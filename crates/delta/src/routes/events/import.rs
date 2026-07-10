use std::collections::HashMap;

use revolt_database::{
    events::client::EventV1, util::permissions::DatabasePermissionQuery,
    util::reference::Reference, CalendarEvent, Database, MessageFilter, MessageQuery,
    MessageTimePeriod, User,
};
use revolt_models::v0;
use revolt_permissions::{
    calculate_channel_permissions, calculate_server_permissions, ChannelPermission,
};
use revolt_result::{create_error, ErrorType, Result};
use rocket::{serde::json::Json, State};
use serde::Deserialize;

/// The tag the legacy client-only calendar prefixed onto chat messages.
const EVENT_PREFIX: &str = "[ACUTEST_EVENT]:";

/// Cap on messages scanned per run — bounds the DB walk on a huge channel. The scan
/// always starts from the newest message; re-running is safe (dedup by
/// `source_message_id`) but cannot reach past the cap.
const MAX_IMPORT_SCAN: usize = 2000;

/// Page size for the scan.
const SCAN_PAGE: i64 = 100;

/// The legacy message payload (the client's `ServerEvent` minus client-only fields).
/// `authorId` is deliberately NOT read — the creator comes from the message's
/// server-side `author` field, so message content cannot spoof it.
#[derive(Deserialize)]
struct LegacyEventPayload {
    title: String,
    start: String,
    #[serde(default)]
    end: Option<String>,
    #[serde(default)]
    desc: Option<String>,
    #[serde(default, rename = "voiceId")]
    voice_id: Option<String>,
    #[serde(default)]
    color: Option<String>,
}

/// Parse a legacy `start`/`end` value: an RFC3339 datetime (the legacy writer used
/// `Date.toISOString()`), or a bare `YYYY-MM-DD` date, which imports as all-day.
/// Returns `(ms epoch, is_date_only)`.
fn parse_legacy_instant(value: &str) -> Option<(i64, bool)> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(value) {
        return Some((dt.timestamp_millis(), false));
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        let midnight = date.and_hms_opt(0, 0, 0)?;
        return Some((midnight.and_utc().timestamp_millis(), true));
    }
    None
}

/// # Import Legacy Events
///
/// One-time, manager-triggered import of legacy `[ACUTEST_EVENT]:`-tagged messages
/// from a channel into real calendar events (design §11). Rows go through the same
/// validation as create (invalid rows are rejected and counted, never stored) and are
/// deduplicated by `source_message_id`, so re-running is safe. The event creator is
/// the tagged message's author. Requires server-wide `ManageChannel` plus
/// `ViewChannel` on the source channel.
#[openapi(tag = "Calendar")]
#[post("/server/<server>/import", data = "<data>")]
pub async fn import_legacy_events(
    db: &State<Database>,
    user: User,
    server: Reference<'_>,
    data: Json<v0::DataImportLegacyEvents>,
) -> Result<Json<v0::ImportResult>> {
    super::require_events_enabled().await?;
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }
    let data = data.into_inner();

    let server = server.as_server(db).await?;
    db.fetch_member(&server.id, &user.id)
        .await
        .map_err(|_| create_error!(NotFound))?;

    // Manager-triggered (design §11): server-wide ManageChannel.
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    calculate_server_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageChannel)?;

    // The source channel must belong to this server AND be viewable by the caller —
    // a manager denied ViewChannel on a private channel must not be able to turn its
    // tagged content into server-visible events.
    let channel = db.fetch_channel(&data.channel).await?;
    if channel.server() != Some(server.id.as_str()) {
        return Err(create_error!(InvalidOperation));
    }
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&channel);
    calculate_channel_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    // Dedup set: everything this server already imported (finding M5), extended with
    // this run's inserts so a duplicate tag within one scan imports once.
    let mut seen = db.fetch_imported_source_ids(&server.id).await?;

    // voiceId → validated channel attachment, cached per id. `None` when the channel
    // is gone, cross-server, or not viewable by the importer — degrade, don't reject:
    // a dead auxiliary channel must not block the import. A kept channel becomes the
    // event's visibility topic (C1), hence the importer view check.
    let mut voice_cache: HashMap<String, Option<String>> = HashMap::new();

    let mut imported = 0usize;
    let mut skipped_duplicates = 0usize;
    let mut skipped_invalid = 0usize;
    let mut scanned = 0usize;
    let mut truncated = false;

    let mut before: Option<String> = None;
    'scan: loop {
        let page = db
            .fetch_messages(MessageQuery {
                limit: Some(SCAN_PAGE),
                filter: MessageFilter {
                    channel: Some(channel.id().to_string()),
                    ..Default::default()
                },
                time_period: MessageTimePeriod::Absolute {
                    before: before.clone(),
                    after: None,
                    sort: Some(v0::MessageSort::Latest),
                },
            })
            .await?;
        let page_len = page.len();
        if page_len == 0 {
            break;
        }
        // Latest-first sort ⇒ the page's last message is its oldest: the next cursor.
        before = page.last().map(|m| m.id.clone());

        for message in page {
            if scanned >= MAX_IMPORT_SCAN {
                truncated = true;
                break 'scan;
            }
            scanned += 1;

            let Some(payload) = message
                .content
                .as_deref()
                .and_then(|c| c.strip_prefix(EVENT_PREFIX))
            else {
                continue;
            };
            if seen.contains(&message.id) {
                skipped_duplicates += 1;
                continue;
            }

            let Ok(legacy) = serde_json::from_str::<LegacyEventPayload>(payload) else {
                skipped_invalid += 1;
                continue;
            };
            let Some((start, date_only)) = parse_legacy_instant(&legacy.start) else {
                skipped_invalid += 1;
                continue;
            };
            // An end only applies to a timed event and must itself be a datetime;
            // `create` below rejects end <= start (§11: invalid rows rejected).
            let end = match &legacy.end {
                Some(value) if !date_only => match parse_legacy_instant(value) {
                    Some((ms, false)) => Some(ms),
                    _ => {
                        skipped_invalid += 1;
                        continue;
                    }
                },
                _ => None,
            };

            let attach = match &legacy.voice_id {
                Some(vid) => match voice_cache.get(vid) {
                    Some(cached) => cached.clone(),
                    None => {
                        let validated = match db.fetch_channel(vid).await {
                            Ok(vc) if vc.server() == Some(server.id.as_str()) => {
                                let mut q =
                                    DatabasePermissionQuery::new(db, &user).channel(&vc);
                                if calculate_channel_permissions(&mut q)
                                    .await
                                    .has_channel_permission(ChannelPermission::ViewChannel)
                                {
                                    Some(vid.clone())
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        };
                        voice_cache.insert(vid.clone(), validated.clone());
                        validated
                    }
                },
                None => None,
            };

            // Same validation as create: timezone is UTC (imports are non-recurring;
            // timed events render viewer-local anyway), creator is the message author.
            match CalendarEvent::create(
                db,
                server.id.clone(),
                message.author.clone(),
                legacy.title,
                legacy.desc,
                None,
                start,
                end,
                date_only,
                "UTC".to_string(),
                None,
                legacy.color,
                attach,
                Some(message.id.clone()),
            )
            .await
            {
                Ok(event) => {
                    seen.insert(message.id.clone());
                    imported += 1;
                    let topic = super::event_topic(&event);
                    EventV1::CalendarEventCreate {
                        event: super::event_to_wire(event),
                    }
                    .p(topic)
                    .await;
                }
                // Validation rejections are counted, never stored (§11); anything
                // else (a DB failure) aborts the run rather than masquerading as
                // "invalid input".
                Err(error) => {
                    if matches!(error.error_type, ErrorType::FailedValidation { .. }) {
                        skipped_invalid += 1;
                    } else {
                        return Err(error);
                    }
                }
            }
        }

        if page_len < SCAN_PAGE as usize {
            break;
        }
    }

    Ok(Json(v0::ImportResult {
        imported,
        skipped_duplicates,
        skipped_invalid,
        scanned,
        truncated,
    }))
}
