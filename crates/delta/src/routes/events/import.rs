use std::collections::HashMap;

use revolt_database::{
    events::client::EventV1,
    util::event_visibility::{
        require_event_channel_view, resolve_event_channel_target, user_can_view_channel,
    },
    util::permissions::DatabasePermissionQuery,
    util::reference::Reference,
    CalendarEvent, Database, MessageFilter, MessageQuery, MessageTimePeriod, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
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
    // tagged content into server-visible events. A thread is judged by its parent;
    // a channel outside the server is InvalidOperation, a hidden one NotFound.
    let channel = db.fetch_channel(&data.channel).await?;
    require_event_channel_view(db, &user, &server.id, &channel).await?;

    // A protected channel's history is ciphertext the server can't read; any
    // plaintext row left in it is a stray that must never be served. Refused
    // after the view check, so a non-viewer gets the same answer either way.
    if channel.is_protected() {
        return Err(create_error!(ChannelProtected));
    }

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
                        // A thread or forum post is judged by its parent; one that
                        // cannot be resolved degrades like any other unusable id.
                        let target = match db.fetch_channel(vid).await {
                            Ok(vc) if vc.server() == Some(server.id.as_str()) => {
                                resolve_event_channel_target(db, &vc).await
                            }
                            _ => None,
                        };
                        let visible = match &target {
                            Some(target) => {
                                user_can_view_channel(db, &user, &server.id, target).await
                            }
                            None => false,
                        };
                        let validated = visible.then(|| vid.clone());
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

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{
        events::client::EventV1, Channel, Database, Message, PartialChannel, PartialMember, Role,
        Server,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::{json, Value};
    use ulid::Ulid;

    /// Mark `channel_id` protected under its stored plaintext rows, raw, as
    /// the R15 compensation window can leave a stray behind
    async fn protect_under_stored_rows(db: &Database, channel_id: &str) {
        match db {
            Database::Reference(reference) => {
                match reference.channels.lock().await.get_mut(channel_id) {
                    Some(Channel::TextChannel { protected, .. }) => *protected = true,
                    other => panic!("expected a text channel, got {:?}", other),
                }
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, Document};

                let result = mongo
                    .col::<Document>("channels")
                    .update_one(
                        doc! { "_id": channel_id },
                        doc! { "$set": { "protected": true } },
                    )
                    .await
                    .expect("raw protect");
                assert_eq!(result.matched_count, 1);
            }
        }

        assert!(db
            .fetch_channel(channel_id)
            .await
            .expect("channel")
            .is_protected());
    }

    /// Store one tagged legacy event row in `channel_id`, returning its id
    async fn insert_tagged(
        harness: &TestHarness,
        channel_id: &str,
        author: &str,
        title: &str,
    ) -> String {
        let id = Ulid::new().to_string();
        harness
            .db
            .insert_message(&Message {
                id: id.clone(),
                channel: channel_id.to_string(),
                author: author.to_string(),
                content: Some(format!(
                    r#"[ACUTEST_EVENT]:{{"title":"{}","start":"2030-03-01T18:00:00.000Z"}}"#,
                    title
                )),
                ..Default::default()
            })
            .await
            .expect("message");
        id
    }

    async fn import(
        harness: &TestHarness,
        token: &str,
        server_id: &str,
        channel_id: &str,
    ) -> (Status, Value) {
        let response = harness
            .client
            .post(format!("/events/server/{}/import", server_id))
            .header(Header::new("x-session-token", token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "channel": channel_id }).to_string())
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_json::<Value>().await.expect("json body");
        (status, body)
    }

    fn is_create_titled(title: &'static str) -> impl Fn(&EventV1) -> bool {
        move |event| matches!(event, EventV1::CalendarEventCreate { event } if event.title == title)
    }

    /// A protected source channel is refused (decision 9, R15): a stray
    /// plaintext `[ACUTEST_EVENT]:` row in it is never turned into a calendar
    /// event, nothing is stored and no event is published. The same row in an
    /// unprotected channel of the same server imports (positive control, and
    /// the marker that proves the refused run published nothing).
    ///
    /// Control: the `is_protected()` refusal dropped.
    #[test]
    fn import_refuses_a_protected_source_channel() {
        crate::util::test::rt().block_on(import_refuses_a_protected_source_channel_case())
    }

    async fn import_refuses_a_protected_source_channel_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        harness.join_server(&server, &owner).await;
        let protected = harness.new_channel(&server).await;
        let server = harness.db.fetch_server(&server.id).await.expect("server");
        let open = harness.new_channel(&server).await;
        let token = session.token.to_string();

        insert_tagged(&harness, protected.id(), &owner.id, "Stray").await;
        protect_under_stored_rows(&harness.db, protected.id()).await;
        let kept = insert_tagged(&harness, open.id(), &owner.id, "Kept").await;

        let (status, body) = import(&harness, &token, &server.id, protected.id()).await;
        assert_eq!(body["type"], "ChannelProtected", "{}", body);
        assert_ne!(status, Status::Ok);
        assert!(
            harness
                .db
                .fetch_imported_source_ids(&server.id)
                .await
                .expect("imported ids")
                .is_empty(),
            "the refused run stored an event"
        );

        // Positive control on the unprotected channel: exactly its one row.
        let (status, body) = import(&harness, &token, &server.id, open.id()).await;
        assert_eq!(status, Status::Ok, "{}", body);
        let result: v0::ImportResult = serde_json::from_value(body).expect("import result");
        assert_eq!(result.imported, 1);
        assert_eq!(result.scanned, 1);

        let stored = harness
            .db
            .fetch_imported_source_ids(&server.id)
            .await
            .expect("imported ids");
        assert_eq!(stored.into_iter().collect::<Vec<_>>(), vec![kept]);

        // Redis pub/sub is FIFO per subscription: once the later "Kept" create
        // is observed, anything the refused run published is buffered too.
        harness
            .wait_for_event(&server.id, is_create_titled("Kept"))
            .await;
        harness.assert_no_buffered_event(&server.id, is_create_titled("Stray"));
    }

    /// Decision 18: a manager without ViewChannel on the source channel gets
    /// the pre-W2 answer, byte-identical for a protected and an unprotected
    /// channel, so the refusal reveals nothing about a hidden channel.
    #[test]
    fn import_non_viewer_answer_is_identical_protected_or_not() {
        crate::util::test::rt()
            .block_on(import_non_viewer_answer_is_identical_protected_or_not_case())
    }

    async fn import_non_viewer_answer_is_identical_protected_or_not_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, manager_session, manager) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        harness.join_server(&server, &owner).await;
        let manager_member = harness.join_server(&server, &manager).await;

        // Server-wide ManageChannel through a role: manager authority.
        let role = Role {
            id: Ulid::new().to_string(),
            name: "Mgr".to_string(),
            permissions: OverrideField {
                a: ChannelPermission::ManageChannel as i64,
                d: 0,
            },
            colour: None,
            hoist: false,
            rank: 1,
            icon: None,
        };
        harness
            .db
            .insert_role(&server.id, &role)
            .await
            .expect("role");
        harness
            .db
            .update_member(
                &manager_member.id,
                &PartialMember {
                    roles: Some(vec![role.id.clone()]),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("assign role");

        // Two channels the manager can't view; one is then protected.
        let mut answers = Vec::new();
        for protect in [true, false] {
            let server: Server = harness.db.fetch_server(&server.id).await.expect("server");
            let mut channel = harness.new_channel(&server).await;
            channel
                .update(
                    &harness.db,
                    PartialChannel {
                        default_permissions: Some(OverrideField {
                            a: 0,
                            d: ChannelPermission::ViewChannel as i64,
                        }),
                        ..Default::default()
                    },
                    vec![],
                )
                .await
                .expect("deny view");
            insert_tagged(&harness, channel.id(), &owner.id, "Hidden").await;
            if protect {
                protect_under_stored_rows(&harness.db, channel.id()).await;
            }

            let (status, body) = import(
                &harness,
                &manager_session.token.to_string(),
                &server.id,
                channel.id(),
            )
            .await;
            // The pre-W2 answer for a hidden source channel (upstream's
            // `require_event_channel_view`)
            assert_eq!(body["type"], "NotFound", "{}", body);
            answers.push((status, body.to_string()));
        }

        assert_eq!(answers[0], answers[1]);
        assert!(harness
            .db
            .fetch_imported_source_ids(&server.id)
            .await
            .expect("imported ids")
            .is_empty());
    }
}
