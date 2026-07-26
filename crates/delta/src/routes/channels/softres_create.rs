use revolt_database::util::idempotency::IdempotencyKey;
use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{Channel, Database, Message, MessageFlagsValue, SoftResSheet, User, AMQP};
use revolt_models::v0::{self, MessageFlags};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission, PermissionQuery};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use ulid::Ulid;
use validator::Validate;

use crate::util::polls::now_ms;
use crate::util::softres_catalog;

/// # Create Soft-Reserve Sheet
///
/// Creates a soft-reserve sheet and sends the message carrying it to the
/// given channel.
///
/// The result message carries the `SoftRes` flag and the embedded
/// immutable definition. The regular message send path rejects
/// client-supplied flag values above 7 and has no `softres` field, so a
/// flagged sheet message is guaranteed to be server-validated and cannot
/// be spoofed.
#[openapi(tag = "Soft Reserves")]
#[post("/<target>/softres", data = "<data>")]
pub async fn softres_create(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataSoftResCreate>,
    idempotency: IdempotencyKey,
) -> Result<Json<v0::Message>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Per-row constraints (the validator version in use cannot combine
    // `length` with nested validation on the same field).
    for hard_reserve in &data.hard_reserves {
        hard_reserve.validate().map_err(|error| {
            create_error!(FailedValidation {
                error: error.to_string()
            })
        })?;
    }

    // Same gate as sending a normal message
    let channel = target.as_channel(db).await?;

    // Forum channels have no message stream of their own — fail closed like
    // message_send.
    if matches!(channel, Channel::Forum { .. }) {
        return Err(create_error!(InvalidOperation));
    }

    // NOTE: E2EE exclusion (sheets are server-validated plaintext) is
    // enforced client-side by the composer, matching message_send — the
    // server cannot reliably know a conversation's encryption state.

    // Threads inherit their parent channel's permission overrides.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    // Archived or locked threads reject sheets exactly like normal messages.
    crate::util::threads::ensure_thread_writable(&channel, &permissions)?;

    crate::util::slowmode::enforce_slowmode(&user, &channel, &permissions).await?;

    // ----- Catalog validation ------------------------------------------------

    if !softres_catalog::editions()
        .iter()
        .any(|edition| edition.id == data.edition)
    {
        return Err(create_error!(UnknownEdition));
    }

    // Deduplicate silently (order-preserving) — a repeated raid id adds
    // nothing.
    let mut raids = data.raids.clone();
    let mut seen = std::collections::HashSet::new();
    raids.retain(|raid| seen.insert(raid.clone()));
    if raids.is_empty() || raids.len() > v0::MAX_SR_RAIDS_PER_SHEET {
        return Err(create_error!(TooManySoftResRaids {
            max: v0::MAX_SR_RAIDS_PER_SHEET
        }));
    }
    for raid in &raids {
        if !softres_catalog::raid_exists(raid) {
            return Err(create_error!(UnknownRaid));
        }
        // Every raid must resolve to the DECLARED edition — a mixed sheet
        // is nonsense and would break the addon export's single
        // `instance` metadata field.
        if softres_catalog::edition_of(raid) != Some(data.edition.as_str()) {
            return Err(create_error!(SoftResMixedEditions));
        }
    }

    // Hard reserves must reference items of the selected raids.
    for hard_reserve in &data.hard_reserves {
        if softres_catalog::item_in_raids(hard_reserve.item_id, &raids).is_none() {
            return Err(create_error!(SoftResInvalidItems));
        }
    }

    // ----- Event linkage -----------------------------------------------------

    let now = now_ms();
    // `lock_at_event_start` is meaningless without a linked event —
    // normalise it away rather than storing a toggle that can never fire.
    let mut lock_at_event_start = data.lock_at_event_start && data.event_id.is_some();
    let mut locks_at = None;
    let mut server_of_event = None;

    if let Some(event_id) = &data.event_id {
        // Linking is an events-feature surface: reject when the flag is
        // off rather than leaving half-alive DB linkage behind it.
        crate::routes::events::require_events_enabled().await?;

        let event = db.fetch_event(event_id).await?;

        // The sheet must live in the event's server.
        let channel_server = match &channel {
            Channel::TextChannel { server, .. } | Channel::Thread { server, .. } => {
                Some(server.clone())
            }
            _ => None,
        };
        if channel_server.as_deref() != Some(event.server.as_str()) {
            return Err(create_error!(NotFound));
        }
        server_of_event = channel_server;

        // Manage rights on the event BEFORE any state checks: view-level
        // linking would let any member permanently claim the one sheet
        // slot of someone else's event, and distinguishable
        // cancelled/recurring errors ahead of this gate would leak event
        // state to members the events routes themselves deny.
        crate::routes::events::authorize_manage(db, &user, &event).await?;

        if event.cancelled {
            return Err(create_error!(InvalidOperation));
        }

        // v1 links non-recurring events only: "next occurrence" is
        // ill-defined for a series and the unique-per-event slot would
        // burn on week one.
        if event.recurrence.is_some() {
            return Err(create_error!(SoftResRecurringEvent));
        }

        // Eager duplicate check for a friendly 409; the unique sparse
        // index (and the Reference driver's in-code check) closes the
        // race for real at insert time.
        if db.fetch_sheet_by_event(&event.id).await?.is_some() {
            return Err(create_error!(SoftResEventAlreadyLinked));
        }

        if lock_at_event_start {
            // A born-locked sheet is useless.
            if event.start <= now {
                return Err(create_error!(InvalidOperation));
            }
            locks_at = Some(event.start);
        }
    } else {
        lock_at_event_start = false;
    }

    let mut idempotency = idempotency;
    idempotency
        .consume_nonce(data.nonce)
        .await
        .map_err(|_| create_error!(InvalidOperation))?;

    let server = match &channel {
        Channel::TextChannel { server, .. }
        | Channel::Thread { server, .. }
        | Channel::Forum { server, .. } => Some(server.clone()),
        _ => None,
    };
    debug_assert!(server_of_event.is_none() || server_of_event == server);

    let sheet = SoftResSheet {
        id: Ulid::new().to_string(),
        message: Ulid::new().to_string(),
        channel: channel.id().to_string(),
        server,
        event: data.event_id.clone(),
        creator: user.id.clone(),
        title: data.title,
        edition: data.edition,
        raids,
        reserves_per_user: data.reserves_per_user.unwrap_or(1),
        per_item_cap: data.per_item_cap,
        allow_duplicates: data.allow_duplicates,
        class_restriction: data.class_restriction,
        hidden: data.hidden,
        lock_at_event_start,
        locks_at,
        note: data.note,
        hard_reserves: data.hard_reserves,
        locked: false,
        created_at: now,
        edited_at: None,
    };

    // Build author objects for the event fan-out
    let author: v0::User = user.clone().into(db, Some(&user)).await;

    // Make sure we have server member (edge case if server owner)
    query.are_we_a_member().await;

    let model_user = user
        .clone()
        .into_known_static(revolt_presence::is_online(&user.id).await)
        .await;

    let model_member: Option<v0::Member> = query
        .member_ref()
        .as_ref()
        .map(|member| member.clone().into_owned().into());

    let mut flags = MessageFlagsValue(0);
    flags.set(MessageFlags::SoftRes, true);

    // The sheet row is inserted BEFORE the message is sent so any client
    // that reacts to the Message event can immediately fetch sheet state.
    // This is also where the one-sheet-per-event race is settled (409).
    db.insert_sheet(&sheet).await?;

    // Cancel-race healing: the event was validated non-cancelled ABOVE,
    // but a cancel can commit in the fetch→insert gap — and its lock hook
    // runs before this row exists, so nothing would ever freeze the
    // sheet (the cancel route's early return skips the hook on retries).
    // Re-check once after the insert and lock the newborn sheet if the
    // race happened; clients see it locked from the first state fetch.
    if let Some(event_id) = &sheet.event {
        if let Ok(event) = db.fetch_event(event_id).await {
            if event.cancelled {
                let _ = db.set_sheet_locked_if_unlocked(&sheet.id).await;
            }
        }
    }

    let mut message = Message {
        id: sheet.message.clone(),
        channel: channel.id().to_string(),
        author: user.id.clone(),
        // Mandatory fallback: legacy clients and the push-notification
        // path render content, so a sheet must never be an empty message.
        content: Some(format!("🛡️ Soft reserves — {}", sheet.title)),
        flags: Some(flags.0),
        softres: Some(sheet.definition()),
        nonce: Some(idempotency.into_key()),
        ..Default::default()
    };

    if let Err(error) = message
        .send(
            db,
            Some(amqp),
            v0::MessageAuthor::User(&author),
            Some(model_user.clone()),
            model_member.clone(),
            &channel,
            false,
        )
        .await
    {
        // Best-effort: never leave a sheet row without its carrying
        // message (it would hold the event's unique sheet slot forever).
        let _ = db
            .delete_softres_for_messages(std::slice::from_ref(&sheet.message))
            .await;
        return Err(error);
    }

    Ok(Json(message.into_model(Some(model_user), model_member)))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::MessageFlagsValue;
    use revolt_models::v0::{self, MessageFlags};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    #[rocket::async_test]
    async fn create_sheet_creates_flagged_message_with_definition() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let response = harness
            .client
            .post(format!("/channels/{}/softres", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "title": "Sunday MC",
                    "edition": "classic",
                    "raids": ["mc", "onyxia"],
                    "reserves_per_user": 2,
                    "hard_reserves": [
                        { "item_id": 17204, "reserved_for": "Guild bank" }
                    ]
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);

        let message: v0::Message = response.into_json().await.expect("`Message`");
        assert_eq!(message.author, user.id);

        // Message carries the SoftRes flag and the embedded definition
        let flags = MessageFlagsValue(message.flags);
        assert!(flags.has(MessageFlags::SoftRes), "SoftRes flag not set");

        let softres = message.softres.expect("softres definition");
        assert_eq!(softres.title, "Sunday MC");
        assert_eq!(softres.edition, "classic");
        assert_eq!(softres.raids, vec!["mc", "onyxia"]);
        assert_eq!(softres.reserves_per_user, 2);
        assert_eq!(softres.hard_reserves.len(), 1);

        // Fallback content for legacy clients / push notifications
        let content = message.content.expect("fallback content");
        assert!(content.contains("Sunday MC"), "unexpected content: {content}");
    }

    #[rocket::async_test]
    async fn create_sheet_rejects_invalid_shapes() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        for body in [
            // Unknown edition
            json!({ "title": "x", "edition": "cata", "raids": ["mc"] }),
            // Unknown raid
            json!({ "title": "x", "edition": "classic", "raids": ["deadmines"] }),
            // Mixed editions (declared classic, raid is TBC)
            json!({ "title": "x", "edition": "classic", "raids": ["mc", "kara"] }),
            // No raids
            json!({ "title": "x", "edition": "classic", "raids": [] }),
            // Too many raids
            json!({
                "title": "x",
                "edition": "classic",
                "raids": ["mc", "onyxia", "bwl", "zg", "aq40"]
            }),
            // Empty title
            json!({ "title": "", "edition": "classic", "raids": ["mc"] }),
            // Hard reserve not in the selected raids (Warglaive in MC)
            json!({
                "title": "x",
                "edition": "classic",
                "raids": ["mc"],
                "hard_reserves": [{ "item_id": 32837, "reserved_for": "nope" }]
            }),
            // reserves_per_user out of range
            json!({
                "title": "x",
                "edition": "classic",
                "raids": ["mc"],
                "reserves_per_user": 11
            }),
        ] {
            let response = harness
                .client
                .post(format!("/channels/{}/softres", channel.id()))
                .header(Header::new("x-session-token", session.token.to_string()))
                .header(ContentType::JSON)
                .body(body.to_string())
                .dispatch()
                .await;

            assert_ne!(response.status(), Status::Ok, "body should be rejected: {body}");
        }
    }

    #[rocket::async_test]
    async fn regular_send_cannot_forge_softres_flag() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        // Attempt to send a normal message carrying the SoftRes flag bit
        let response = harness
            .client
            .post(format!("/channels/{}/messages", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({
                    "content": "🛡️ fake sheet",
                    "flags": 512
                })
                .to_string(),
            )
            .dispatch()
            .await;

        // The send path rejects flags > 7 outright
        assert_ne!(
            response.status(),
            Status::Ok,
            "regular send must not accept the SoftRes flag"
        );
    }
}
