use revolt_config::config;
use revolt_database::util::antispam;
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

    // Threads inherit their parent channel's permission overrides.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    // A sheet is server-validated plaintext, which a protected channel never
    // carries (design 7.3). Refused here, after the SendMessage check, so a
    // caller who cannot view the channel gets the same answer for a
    // protected channel as for any other (decision 18 (W2)), and before
    // slowmode claims its slot and the nonce is consumed. No thread under a
    // protected parent can exist (2.5); its parent is checked anyway.
    if channel.is_protected() || permission_channel.is_protected() {
        return Err(create_error!(ChannelProtected));
    }

    // Archived or locked threads reject sheets exactly like normal messages.
    crate::util::threads::ensure_thread_writable(&channel, &permissions)?;

    // A paused account cannot reach a stranger through a sheet either.
    // Checked before any side effect (slowmode key, nonce, sheet row). No
    // observer: the fallback content is fixed-format, not user text.
    let dm_peer = if let Channel::DirectMessage { recipients, .. } = &channel {
        recipients.iter().find(|id| *id != &user.id).cloned()
    } else {
        None
    };
    if let Some(peer) = &dm_peer {
        let antispam = config().await.features.antispam.clone();
        antispam::dm_send_allowed(db, &antispam, &user, channel.id(), peer).await?;
    }

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
    use crate::{
        rocket,
        util::test::{statement_at, without_comments, without_whitespace, TestHarness},
    };
    use revolt_config::config;
    use revolt_database::{
        iso8601_timestamp::Timestamp, Channel, DmGuard, Member, Message, MessageFilter,
        MessageFlagsValue, MessageQuery, MessageTimePeriod, Session,
    };
    use revolt_models::v0::{self, MessageFlags};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    /// POST a minimal valid sheet into `channel_id` as `session`.
    async fn create_sheet(
        harness: &TestHarness,
        session: &Session,
        channel_id: &str,
    ) -> (Status, serde_json::Value) {
        let response = harness
            .client
            .post(format!("/channels/{channel_id}/softres"))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({ "title": "Sunday MC", "edition": "classic", "raids": ["mc"] }).to_string(),
            )
            .dispatch()
            .await;
        let status = response.status();
        let body = response
            .into_json::<serde_json::Value>()
            .await
            .expect("json body");
        (status, body)
    }

    async fn messages_by(harness: &TestHarness, channel_id: &str, author: &str) -> Vec<Message> {
        harness
            .db
            .fetch_messages(MessageQuery {
                limit: Some(10),
                filter: MessageFilter {
                    channel: Some(channel_id.to_string()),
                    author: Some(author.to_string()),
                    ..Default::default()
                },
                time_period: MessageTimePeriod::Absolute {
                    before: None,
                    after: None,
                    sort: None,
                },
            })
            .await
            .expect("fetch_messages")
    }

    /// A paused sender cannot open a conversation with a silent stranger
    /// through a sheet; once the stranger has written in the DM it can.
    /// Mutation: the `dm_send_allowed` gate removed.
    #[test]
    #[ignore = "needs REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"]
    fn antispam_route_softres_paused_refused() {
        crate::util::test::rt().block_on(antispam_route_softres_paused_refused_case())
    }

    async fn antispam_route_softres_paused_refused_case() {
        assert!(
            config().await.features.antispam.dm_dupe_enabled,
            "run with REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"
        );

        let harness = TestHarness::new().await;
        let (_, session, spammer) = harness.new_user().await;
        let (_, _, stranger) = harness.new_user().await;

        // A mutual server grants SendMessage in the DM, so only the pause can
        // refuse the sheet.
        let (server, _) = harness.new_server(&spammer).await;
        for user in [&spammer, &stranger] {
            Member::create(&harness.db, &server, user, None)
                .await
                .expect("member");
        }
        let dm = Channel::create_dm(&harness.db, &spammer, &stranger)
            .await
            .expect("DM");
        assert!(matches!(dm, Channel::DirectMessage { .. }), "{:?}", dm);

        // Pause the sender the way the detector would; the route loads the
        // caller from the session, so the stored copy is what it sees.
        let guard = DmGuard {
            report_id: ulid::Ulid::new().to_string(),
            flagged_at: Timestamp::now_utc(),
            paused: true,
            cleared_at: None,
            recipients: 3,
            fingerprint: "test".into(),
        };
        assert!(
            harness
                .db
                .claim_dm_guard(&spammer.id, &guard, Timestamp::now_utc())
                .await
                .expect("claim_dm_guard"),
            "the fresh user must take the guard"
        );

        let (status, body) = create_sheet(&harness, &session, dm.id()).await;
        assert_eq!(status, Status::Forbidden, "{body}");
        assert_eq!(body["type"], "DirectMessagesPaused", "{body}");
        assert!(
            messages_by(&harness, dm.id(), &spammer.id).await.is_empty(),
            "a refused sheet must not post its message"
        );

        // Control: once the stranger has written in the DM the same sheet goes
        // through, so the refusal above is the pause and not the permission
        // check.
        harness
            .db
            .insert_message(&Message {
                id: ulid::Ulid::new().to_string(),
                channel: dm.id().to_string(),
                author: stranger.id.clone(),
                content: Some("hello".to_string()),
                ..Default::default()
            })
            .await
            .expect("reply");

        let (status, body) = create_sheet(&harness, &session, dm.id()).await;
        assert_eq!(status, Status::Ok, "{body}");
        assert_eq!(body["author"], spammer.id.as_str(), "{body}");
        assert_eq!(messages_by(&harness, dm.id(), &spammer.id).await.len(), 1);
    }

    /// The DM pause gate runs before every side effect of the route: the
    /// slowmode key, the nonce and the sheet row. Mutation: the gate moved
    /// below any of them.
    #[test]
    fn the_dm_pause_gate_precedes_every_side_effect() {
        let source = include_str!("softres_create.rs");
        let shipping = &source[..source.find("#[cfg(test)]").expect("a test module")];
        let code = without_whitespace(&without_comments(shipping));

        let gate = statement_at(
            &code,
            "antispam::dm_send_allowed(db,&antispam,&user,channel.id(),peer).await?;",
        );
        for side_effect in [
            "crate::util::slowmode::enforce_slowmode(&user,&channel,&permissions).await?;",
            "idempotency.consume_nonce(data.nonce).await.map_err(|_|create_error!(InvalidOperation))?;",
            "db.insert_sheet(&sheet).await?;",
        ] {
            assert!(
                gate < statement_at(&code, side_effect),
                "the DM pause gate must precede `{}`",
                side_effect
            );
        }
    }

    #[test]
    fn create_sheet_creates_flagged_message_with_definition() {
        crate::util::test::rt().block_on(create_sheet_creates_flagged_message_with_definition_case())
    }

    async fn create_sheet_creates_flagged_message_with_definition_case() {
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

    #[test]
    fn create_sheet_rejects_invalid_shapes() {
        crate::util::test::rt().block_on(create_sheet_rejects_invalid_shapes_case())
    }

    async fn create_sheet_rejects_invalid_shapes_case() {
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

    #[test]
    fn regular_send_cannot_forge_softres_flag() {
        crate::util::test::rt().block_on(regular_send_cannot_forge_softres_flag_case())
    }

    async fn regular_send_cannot_forge_softres_flag_case() {
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

    use crate::util::test::ProtectedChannel;
    use revolt_database::events::client::EventV1;
    use revolt_database::PartialChannel;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use serde_json::Value;

    fn sheet_body(nonce: &str) -> serde_json::Value {
        json!({
            "nonce": nonce,
            "title": "Sunday MC",
            "edition": "classic",
            "raids": ["mc"]
        })
    }

    async fn create_sheet_with_body(
        harness: &TestHarness,
        session: &Session,
        channel_id: &str,
        body: &serde_json::Value,
    ) -> (Status, Value) {
        let response = harness
            .client
            .post(format!("/channels/{}/softres", channel_id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(body.to_string())
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_json::<Value>().await.expect("json body");
        (status, body)
    }

    async fn stored_messages(harness: &TestHarness, channel_id: &str) -> usize {
        harness
            .db
            .fetch_messages(MessageQuery {
                limit: Some(10),
                filter: MessageFilter {
                    channel: Some(channel_id.to_string()),
                    ..Default::default()
                },
                time_period: MessageTimePeriod::Absolute {
                    before: None,
                    after: None,
                    sort: None,
                },
            })
            .await
            .expect("the channel's messages")
            .len()
    }

    async fn set_slowmode(harness: &TestHarness, channel: &Channel) {
        channel
            .clone()
            .update(
                &harness.db,
                PartialChannel {
                    slowmode: Some(600),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("slowmode");
    }

    async fn deny_view(harness: &TestHarness, channel: &Channel) {
        channel
            .clone()
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
    }

    /// A seated member's sheet in a protected channel is refused with
    /// `ChannelProtected` before any side effect: no slowmode slot (a second
    /// try is refused the same way, not `InSlowmode`), no consumed nonce (the
    /// same nonce then succeeds in an ordinary channel: the positive control),
    /// no stored message and no `Message` event (the control's event is the
    /// marker that proves nothing earlier reached the protected topic).
    ///
    /// Control: the `is_protected()` refusal dropped.
    #[test]
    fn softres_create_refuses_a_protected_channel() {
        crate::util::test::rt().block_on(softres_create_refuses_a_protected_channel_case())
    }

    async fn softres_create_refuses_a_protected_channel_case() {
        let mut harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let ProtectedChannel {
            server,
            channel: protected,
            ..
        } = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let ordinary = harness.new_channel(&server).await;
        set_slowmode(&harness, &protected).await;
        set_slowmode(&harness, &ordinary).await;
        let protected = harness
            .db
            .fetch_channel(protected.id())
            .await
            .expect("the protected channel");
        assert!(protected.is_protected());

        let nonce = ulid::Ulid::new().to_string();
        let body = sheet_body(&nonce);

        for attempt in ["the first try", "the second try"] {
            let (status, refused) =
                create_sheet_with_body(&harness, &member_session, protected.id(), &body).await;
            assert_eq!(refused["type"], "ChannelProtected", "{attempt}: {refused}");
            assert_eq!(status, Status::BadRequest, "{attempt}: {refused}");
        }
        assert_eq!(stored_messages(&harness, protected.id()).await, 0);

        // Positive control: the same request (same nonce) in an ordinary
        // channel of the same server.
        let (status, sent) =
            create_sheet_with_body(&harness, &member_session, ordinary.id(), &body).await;
        assert_eq!(status, Status::Ok, "{sent}");
        let message: v0::Message = serde_json::from_value(sent).expect("`Message`");
        assert!(MessageFlagsValue(message.flags).has(MessageFlags::SoftRes));
        assert!(message.softres.is_some());
        assert_eq!(stored_messages(&harness, ordinary.id()).await, 1);

        // Redis pub/sub is FIFO per subscription: once the control's event is
        // observed, anything the refused tries published is buffered too.
        harness
            .wait_for_event(ordinary.id(), |event| match event {
                EventV1::Message(sent) => sent.id == message.id,
                _ => false,
            })
            .await;
        harness
            .assert_no_buffered_event(protected.id(), |event| matches!(event, EventV1::Message(_)));
    }

    /// Decision 18 (W2): a member who cannot view the channel gets the
    /// pre-W2 answer, byte-identical (`location` included) for a protected
    /// and an ordinary channel.
    #[test]
    fn softres_create_non_viewer_error_is_unchanged_by_protection() {
        crate::util::test::rt()
            .block_on(softres_create_non_viewer_error_is_unchanged_by_protection_case())
    }

    async fn softres_create_non_viewer_error_is_unchanged_by_protection_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let ProtectedChannel {
            server,
            channel: protected,
            ..
        } = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let ordinary = harness.new_channel(&server).await;
        deny_view(&harness, &protected).await;
        deny_view(&harness, &ordinary).await;
        assert!(harness
            .db
            .fetch_channel(protected.id())
            .await
            .expect("the protected channel")
            .is_protected());

        let (protected_status, protected_body) = create_sheet_with_body(
            &harness,
            &member_session,
            protected.id(),
            &sheet_body(&ulid::Ulid::new().to_string()),
        )
        .await;
        let (ordinary_status, ordinary_body) = create_sheet_with_body(
            &harness,
            &member_session,
            ordinary.id(),
            &sheet_body(&ulid::Ulid::new().to_string()),
        )
        .await;

        assert_eq!(ordinary_status, Status::Forbidden, "{ordinary_body}");
        assert_eq!(
            ordinary_body["type"], "MissingPermission",
            "{ordinary_body}"
        );
        assert_eq!(protected_status, ordinary_status);
        assert_eq!(protected_body, ordinary_body);
        assert_eq!(stored_messages(&harness, protected.id()).await, 0);
        assert_eq!(stored_messages(&harness, ordinary.id()).await, 0);
    }
}
