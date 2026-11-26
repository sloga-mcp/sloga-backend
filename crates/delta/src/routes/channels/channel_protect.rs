use iso8601_timestamp::Timestamp;
use revolt_database::{
    events::client::EventV1, seat_list_channel_server, util::reference::Reference, AuditLogAction,
    AuditLogChange, AuditLogDraft, AuditLogEntry, AuditValue, Channel, Database, Poll,
    ScheduledMessage, SeatListBody, SeatListPreHistory, Session, SoftResSheet, User,
};
use revolt_models::v0;
use revolt_result::{create_error, Error, ErrorType, Result};
use rocket::{serde::json::Json, State};

use super::poll_fetch::poll_is_servable;
use super::protected_seat_validation::{after_seat_list_write, validate_protect};
use crate::routes::mls::{
    require_channel_access, require_protected_available, require_protected_growth,
};
use crate::util::softres::publish_sheet_update;

/// # Protect Channel
///
/// Protect a server text channel with its genesis seat list
/// (protected-channels design 7.2). Only the server owner may protect a
/// channel, and never a privileged (staff) owner.
///
/// S4 (7.2 "S4"): a v2 genesis may carry a history boundary B, so a channel
/// with messages can be protected; `wipe_history`, when present, must agree
/// with the signed `pre_history` line. A `wiped` genesis is refused while
/// the server has a legal hold (2.9). The answer, and the protect
/// `ChannelUpdate`, carry the stored `protected_history`.
///
/// A missing channel, and a channel the caller cannot view, get the same
/// 404 before any other check (decision 18 (W2)), so a non-viewer learns
/// nothing about the channel.
#[openapi(tag = "E2EE")]
#[put("/<target>/protect", data = "<data>")]
pub async fn protect_channel(
    db: &State<Database>,
    user: User,
    session: Session,
    target: Reference<'_>,
    data: Json<v0::DataProtectChannel>,
) -> Result<Json<v0::Channel>> {
    let channel = match target.as_channel(db).await {
        Ok(channel) => channel,
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => return Err(no_channel()),
        Err(error) => return Err(error),
    };
    if require_channel_access(db, &user, &channel).await.is_err() {
        return Err(no_channel());
    }

    require_protected_available().await?;

    let server_id =
        seat_list_channel_server(&channel).ok_or_else(|| create_error!(InvalidOperation))?;
    let server = db.fetch_server(server_id).await?;

    // 4.3 steps 1 to 3 (the signer is the caller and the server owner,
    // signing from a device this session is bound to), then N3: a
    // byte-identical retry of a protect that landed skips steps 5 to 8.
    // S2: a v2 genesis only while `formats_v2` is on and a v1 genesis only
    // while it is off (step 1, #218), and the first authority of a v2
    // genesis is verified under the signer device's directory key (3b).
    let validated = validate_protect(db, &channel, &server, &user, &session, &data).await?;

    // Decision 4 (W2): a retry runs before the staff-owner refusal and the
    // growth gate (#128), so it still gets the stored success after state
    // moved on or the flag was turned off. The driver decides N3 again
    // inside its transaction; a request it does not answer `unchanged`
    // meets every protect rule there.
    if !validated.retry {
        // 2.3 (W0-fix): a privileged account can never be seated, so it can
        // never own a protected channel. A hard check on the caller (the
        // owner, by now), not the permission calculus, which grants
        // privileged accounts everything first.
        if user.privileged {
            return Err(create_error!(InvalidOperation));
        }
        require_protected_growth().await?;

        // 4.3 "S4", 2.9: a `wiped` genesis (the SIGNED line, S4-PA-7) is
        // refused while the server has a legal hold. Read after the owner
        // check, so only the owner learns that a hold is set. A retry is
        // not refused: its wipe is already written, and the job stops on
        // the hold before each batch (7.5 "S4").
        if signs_wiped(&validated.body) && db.fetch_server_legal_hold(&server.id).await?.is_some() {
            return Err(create_error!(InvalidOperation));
        }
    }

    // 7.2 "S4": an absent `wipe_history` takes the signed line; a present
    // one must agree with it (the driver's `FailedValidation`)
    let outcome = db
        .protect_channel_with_wipe(
            channel.id(),
            &validated.submission,
            data.wipe_history,
            Timestamp::now_utc(),
        )
        .await?;
    // Prot (S5b 6.7, BR2): a crowdfunded channel's Launching tank captures
    // its pledges once the protect has committed, a retry (`unchanged`)
    // included. It never fails the protect, which has landed: an error is
    // logged and the goals sweep captures later.
    revolt_payments::engine::tank::on_protect_landed(db, channel.id()).await;
    if !outcome.unchanged {
        log::info!(
            "AUDIT channel_protect: actor={} channel={} server={} seats={}",
            user.id,
            channel.id(),
            server.id,
            outcome.claimed.len()
        );
    }

    // 4.3 "After the claim commits" (S2-D12): the same recheck, event and
    // entry as the seat PUT. A genesis releases nobody, so no reason. Kept
    // and answered after the protect event below, which must go out either
    // way; the protect stays written.
    let after = after_seat_list_write(db, &server, &channel, &user, &outcome, None).await;

    // 7.4 "S4": the state an existing channel carries over. Also on N3: a
    // protect that landed but answered 5xx may have stopped before this,
    // and every step only acts on what is still open.
    close_carried_over_state(db, channel.id()).await;

    // 7.5 "S4" (S4-D19): written only by the write that protected
    if !outcome.unchanged {
        AuditLogEntry::record(
            db,
            protect_audit(&server.id, channel.id(), &user.id, &validated.body),
        )
        .await;
    }

    // Every connected client sets its protected pin (9.4) now, on the
    // SERVER topic, the one `Channel::update` uses (decision 19 (W2)).
    // Re-emitted on N3 (#134): a protect that landed but answered 5xx never
    // emitted it, and a repeated `protected: Some(true)` changes nothing.
    // S4 (2.1 "S4"): it carries the stored `protected_history`, re-read
    // after the commit; a failed read still sends the pin and is answered
    // below.
    let fresh = db.fetch_channel(channel.id()).await;
    EventV1::ChannelUpdate {
        id: channel.id().to_string(),
        data: v0::PartialChannel {
            protected: Some(true),
            protected_history: fresh.as_ref().ok().and_then(wire_protected_history),
            ..Default::default()
        },
        clear: vec![],
    }
    .p(server.id.clone())
    .await;
    after?;

    Ok(Json(fresh?.into()))
}

/// The one `NotFound` for a missing channel and a channel the caller cannot
/// view: one source site, so the body's `location` never tells them apart
fn no_channel() -> Error {
    create_error!(NotFound)
}

/// Whether the signed genesis asks for the wipe (`pre_history:wiped`)
fn signs_wiped(body: &SeatListBody) -> bool {
    body.v2
        .as_ref()
        .is_some_and(|lines| lines.pre_history == SeatListPreHistory::Wiped)
}

/// The stored `protected_history` of `channel`, in its wire form
fn wire_protected_history(channel: &Channel) -> Option<Box<v0::ProtectedHistory>> {
    match channel {
        Channel::TextChannel {
            protected_history: Some(history),
            ..
        } => Some(Box::new((**history).clone().into())),
        _ => None,
    }
}

/// 7.4 "S4", after the protect commit: pending scheduled messages are
/// cancelled, open polls closed (one `PollClose` each) and open softres
/// sheets locked (one sheet update each), except that nothing is published
/// for a row a `wiped` genesis made unservable (S4-D21). Best effort: a
/// failure is reported and the protect stays answered; the routes'
/// `ChannelProtected` refusals (scheduling, voting, ending, reserving) are
/// the backstop.
async fn close_carried_over_state(db: &Database, channel_id: &str) {
    if let Err(error) = ScheduledMessage::cancel_all_for_channel(db, channel_id).await {
        revolt_config::capture_error(&error);
    }

    match Poll::close_open_for_channel(db, channel_id).await {
        Ok(ids) if ids.is_empty() => {}
        Ok(ids) => match db.fetch_polls(&ids).await {
            Ok(polls) => {
                for poll in polls {
                    // S4-D21: no event carries the state of a poll whose
                    // parent message is not servable (after a `wiped`
                    // genesis, every carried-over poll); the close stands
                    match poll_is_publishable(db, &poll).await {
                        Ok(true) => {}
                        Ok(false) => continue,
                        Err(error) => {
                            revolt_config::capture_error(&error);
                            continue;
                        }
                    }
                    EventV1::PollClose {
                        counts: poll.counts_vec(),
                        id: poll.id,
                        channel_id: poll.channel.clone(),
                        message_id: poll.message,
                        total_votes: poll.total_votes,
                    }
                    .p(poll.channel)
                    .await;
                }
            }
            Err(error) => {
                revolt_config::capture_error(&error);
            }
        },
        Err(error) => {
            revolt_config::capture_error(&error);
        }
    }

    match SoftResSheet::close_open_for_channel(db, channel_id).await {
        Ok(ids) => {
            for id in ids {
                let published = match db.fetch_sheet(&id).await {
                    Ok(sheet) => publish_sheet_update(db, sheet).await,
                    Err(error) => Err(error),
                };
                if let Err(error) = published {
                    revolt_config::capture_error(&error);
                }
            }
        }
        Err(error) => {
            revolt_config::capture_error(&error);
        }
    }
}

/// Whether the closed `poll` may be broadcast: its parent message is
/// servable under the read view of its channel (`poll_is_servable`)
async fn poll_is_publishable(db: &Database, poll: &Poll) -> Result<bool> {
    let channel = db.fetch_channel(&poll.channel).await?;
    let permission_channel = channel.permission_target(db).await?.into_owned();
    poll_is_servable(db, &channel, &permission_channel, poll).await
}

/// The `ChannelProtect` entry (7.5 "S4"; the mapping on
/// `AuditLogAction::ChannelProtect`): the owner as the actor, the channel,
/// the signed boundary (no `new` without one) and whether the genesis wipes
fn protect_audit(
    server_id: &str,
    channel_id: &str,
    actor_id: &str,
    body: &SeatListBody,
) -> AuditLogDraft {
    let boundary = body
        .v2
        .as_ref()
        .and_then(|lines| lines.history_boundary.clone());
    AuditLogDraft {
        server: server_id.to_string(),
        actor: Some(actor_id.to_string()),
        action: AuditLogAction::ChannelProtect,
        target: None,
        channel: Some(channel_id.to_string()),
        changes: vec![
            AuditLogChange::new("boundary", None, boundary.map(AuditValue::String)),
            AuditLogChange::new("wiped", None, Some(AuditValue::Bool(signs_wiped(body)))),
        ],
        count: None,
        reason: None,
    }
}

#[cfg(test)]
mod test {
    //! Run under nextest (one process per test; the flag variants call
    //! `overwrite_config`). Every refusal also asserts that nothing was
    //! written.

    use std::collections::{BTreeSet, HashMap};

    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        events::client::EventV1, AuditLogAction, AuditLogEntry, AuditValue, BotInformation,
        Channel, ChannelAuthority, ChannelSeat, Message, PartialChannel, PartialUser, Poll,
        RemovalIntention, ScheduledMessage, ScheduledMessageStatus, SeatList, SeatListBody,
        SeatListHistory, SeatListPreHistory, SeatListSubmission, SeatListV2Lines, ServerLegalHold,
        Session, SoftResSheet, User, PROTECTED_SCOPE_SEATS,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;
    use ulid::Ulid;

    use crate::routes::channels::protected_seat_validation::v2_fixtures::{
        authority, V2List, SALT,
    };
    use crate::routes::mls::require_channel_access;
    use crate::util::test::{
        TestE2EEDevice, TestHarness, FIXTURE_DEVICE_CAP, FIXTURE_SLOT_CAP, MEMBER_DEVICE_SEED,
        NEW_OWNER_DEVICE_SEED, OWNER_DEVICE_SEED,
    };

    #[test]
    fn protect_channel_is_mounted_and_refuses() {
        crate::util::test::rt().block_on(protect_channel_is_mounted_and_refuses_case())
    }

    async fn protect_channel_is_mounted_and_refuses_case() {
        let harness = TestHarness::new().await;
        let (_, session, _) = harness.new_user().await;

        let response = TestHarness::with_session(
            session,
            harness
                .client
                .put(format!("/channels/{}/protect", ulid::Ulid::new()))
                .header(ContentType::JSON)
                .body(
                    json!({
                        "seat_list": {
                            "body": "body",
                            "signature": "signature",
                            "signer_device_id": "device"
                        }
                    })
                    .to_string(),
                ),
        )
        .await;

        // An unmounted route is also a 404, but from Rocket's catcher, which
        // carries no API error body: a JSON body typed `NotFound` is the
        // handler's own. The body never carries the error's `location`.
        assert_eq!(response.status(), Status::NotFound);
        assert_eq!(response.content_type(), Some(ContentType::JSON));
        let error = response
            .into_json::<serde_json::Value>()
            .await
            .expect("API error body");
        assert_eq!(error["type"], "NotFound");
        assert!(
            error.get("location").is_none(),
            "the body must not carry the error location: {}",
            error
        );
    }

    /// A protectable channel: the owner's server and unprotected channel, an
    /// Active entitlement, the owner's device bound to the owner's session,
    /// and a member who can view the channel
    struct Setup {
        harness: TestHarness,
        owner: User,
        owner_session: Session,
        owner_device: TestE2EEDevice,
        member: User,
        member_session: Session,
        server_id: String,
        channel: Channel,
    }

    async fn setup() -> Setup {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (server, channel) = harness.new_protectable_channel(&owner).await;
        harness.join_server(&server, &member).await;
        harness
            .grant_entitlement(&channel, FIXTURE_SLOT_CAP, None)
            .await;
        let owner_device = harness
            .new_e2ee_device(&owner, &owner_session.id, OWNER_DEVICE_SEED)
            .await;

        Setup {
            harness,
            owner,
            owner_session,
            owner_device,
            member,
            member_session,
            server_id: server.id,
            channel,
        }
    }

    impl Setup {
        fn channel_id(&self) -> String {
            self.channel.id().to_string()
        }

        /// The owner device's genesis list seating the owner and the member
        fn genesis(&self) -> v0::DataProtectChannel {
            self.owner_device.protect_request(
                self.channel.id(),
                FIXTURE_DEVICE_CAP,
                &[self.owner.id.clone(), self.member.id.clone()],
            )
        }

        /// The first authority (4.10) of the channel, naming the owner
        /// device under the public half of `listed`, signed with `signing`
        fn first_authority(
            &self,
            listed: &ed25519_dalek::SigningKey,
            signing: &ed25519_dalek::SigningKey,
        ) -> v0::SignedAuthority {
            authority(
                self.channel.id(),
                &self.owner.id,
                &self.owner_device.device_id,
                &[(self.owner_device.device_id.as_str(), listed)],
                None,
                signing,
            )
        }

        /// The owner device's v2 genesis (4.1.1) seating the owner and the
        /// member, carrying `authority`
        fn v2_genesis(&self, authority: &v0::SignedAuthority) -> v0::DataProtectChannel {
            v0::DataProtectChannel {
                seat_list: V2List {
                    channel_id: self.channel.id(),
                    version: 1,
                    signer_user_id: &self.owner.id,
                    signer_device_id: &self.owner_device.device_id,
                    key: &self.owner_device.signing_key,
                    seats: &[self.owner.id.as_str(), self.member.id.as_str()],
                    salt: SALT,
                    authority,
                }
                .signed(),
                wipe_history: None,
            }
        }

        /// The owner device's v2 genesis with the history boundary
        /// `boundary` and `pre_history`, seating the owner alone (4.3 "S4"),
        /// with an honest first authority. Issued now, so `ulid_time(B) <=
        /// issued_at` (4.1.1 "S4").
        fn history_genesis(
            &self,
            boundary: &str,
            pre_history: SeatListPreHistory,
            wipe_history: Option<bool>,
        ) -> v0::DataProtectChannel {
            let key = &self.owner_device.signing_key;
            let authority = self.first_authority(key, key);
            let issued_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("the clock")
                .as_millis() as i64;
            let body = SeatListBody {
                channel_id: self.channel_id(),
                version: 1,
                device_cap: FIXTURE_DEVICE_CAP,
                issued_at,
                signer_user_id: self.owner.id.clone(),
                signer_device_id: self.owner_device.device_id.clone(),
                seats: vec![self.owner.id.clone()],
                v2: Some(SeatListV2Lines {
                    authority_sha256: Some(ChannelAuthority::sha256(&authority.body)),
                    history: SeatListHistory::Hidden,
                    history_boundary: Some(boundary.to_string()),
                    pre_history,
                    group_salt: SALT.to_string(),
                }),
            }
            .build()
            .expect("a canonical v2 genesis body");

            v0::DataProtectChannel {
                seat_list: v0::DataSeatList {
                    signature: self.owner_device.sign(&body),
                    body,
                    signer_device_id: self.owner_device.device_id.clone(),
                    handover: None,
                    authority: Some(authority),
                },
                wipe_history,
            }
        }
    }

    async fn history_setting_on() {
        revolt_config::overwrite_config(|settings| {
            settings.features.protected_channels.formats_v2 = true;
            settings.features.protected_channels.history_setting = true;
        })
        .await;
    }

    /// The stored `protected_history` of `channel_id`, in its wire form
    async fn stored_history(
        harness: &TestHarness,
        channel_id: &str,
    ) -> Option<v0::ProtectedHistory> {
        let channel: v0::Channel = harness
            .db
            .fetch_channel(channel_id)
            .await
            .expect("the channel")
            .into();
        match channel {
            v0::Channel::TextChannel {
                protected_history, ..
            } => protected_history.map(|history| *history),
            _ => None,
        }
    }

    /// The protect event (7.2) carrying `history` (2.1 "S4") and nothing
    /// else. A requested wipe's `at` is compared in milliseconds, the
    /// precision the event keeps over the event bus (the Reference driver
    /// stores nanoseconds); every other field exactly.
    fn protect_update_carrying(
        channel_id: &str,
        history: Option<v0::ProtectedHistory>,
    ) -> impl Fn(&EventV1) -> bool + '_ {
        let expected = at_wire_precision(&v0::PartialChannel {
            protected: Some(true),
            protected_history: history.map(Box::new),
            ..Default::default()
        });
        move |event| {
            matches!(event, EventV1::ChannelUpdate { id, data, clear }
                if id == channel_id && at_wire_precision(data) == expected && clear.is_empty())
        }
    }

    /// `data` with a requested wipe's `at` taken out, and that `at` in
    /// milliseconds since the epoch
    fn at_wire_precision(data: &v0::PartialChannel) -> (v0::PartialChannel, Option<i128>) {
        let mut data = data.clone();
        let mut at_ms = None;
        if let Some(history) = data.protected_history.as_mut() {
            if let v0::HistoryWipe::Requested { at, .. } = &mut history.wipe {
                at_ms = Some(
                    at.duration_since(Timestamp::UNIX_EPOCH)
                        .whole_milliseconds(),
                );
                *at = Timestamp::UNIX_EPOCH;
            }
        }
        (data, at_ms)
    }

    /// Pre-protect state of a busy channel (7.4 "S4"): three plaintext
    /// messages by the owner, oldest first, the last of them B; a closed
    /// poll on the first, an open poll on the second, an open softres sheet
    /// on B, and the member's pending scheduled message
    struct Carried {
        messages: Vec<Message>,
        closed_poll: Poll,
        open_poll: Poll,
        open_sheet: SoftResSheet,
        scheduled: ScheduledMessage,
    }

    impl Carried {
        /// The newest message: the boundary B
        fn boundary(&self) -> &str {
            &self.messages[2].id
        }
    }

    async fn carried(setup: &Setup) -> Carried {
        let db = &setup.harness.db;
        let channel_id = setup.channel_id();

        // A minute ago, a second apart: ids in creation order
        let base = Ulid::new().timestamp_ms() - 60_000;
        let mut messages = Vec::new();
        for k in 0..3 {
            let message = Message {
                id: Ulid::from_parts(base + k * 1_000, 0).to_string(),
                channel: channel_id.clone(),
                author: setup.owner.id.clone(),
                content: Some("Before protect".to_string()),
                ..Default::default()
            };
            db.insert_message(&message).await.expect("a message");
            messages.push(message);
        }

        let poll = |message: &Message, closed: bool| Poll {
            id: Ulid::new().to_string(),
            message: message.id.clone(),
            channel: channel_id.clone(),
            server: Some(setup.server_id.clone()),
            author: setup.owner.id.clone(),
            question: "Raid night?".to_string(),
            answers: vec![
                v0::PollAnswer {
                    id: 0,
                    text: "Friday".to_string(),
                    emoji: None,
                },
                v0::PollAnswer {
                    id: 1,
                    text: "Saturday".to_string(),
                    emoji: None,
                },
            ],
            allow_multiselect: false,
            expires_at: 4_000_000_000_000,
            closed,
            counts: HashMap::new(),
            total_votes: 0,
        };
        let closed_poll = poll(&messages[0], true);
        let open_poll = poll(&messages[1], false);
        for row in [&closed_poll, &open_poll] {
            db.insert_poll(row).await.expect("a poll");
        }

        let open_sheet = SoftResSheet {
            id: Ulid::new().to_string(),
            message: messages[2].id.clone(),
            channel: channel_id.clone(),
            server: Some(setup.server_id.clone()),
            event: None,
            creator: setup.owner.id.clone(),
            title: "Sunday MC".to_string(),
            edition: "classic".to_string(),
            raids: vec!["mc".to_string()],
            reserves_per_user: 2,
            per_item_cap: None,
            allow_duplicates: false,
            class_restriction: false,
            hidden: false,
            lock_at_event_start: false,
            locks_at: None,
            note: None,
            hard_reserves: vec![],
            locked: false,
            created_at: 1_000_000,
            edited_at: None,
        };
        db.insert_sheet(&open_sheet).await.expect("a sheet");

        let scheduled = ScheduledMessage {
            id: Ulid::new().to_string(),
            author: setup.member.id.clone(),
            channel: channel_id.clone(),
            server: Some(setup.server_id.clone()),
            scheduled_at: 4_000_000_000_000,
            data: serde_json::from_value(json!({ "content": "Later" })).expect("a message payload"),
            status: ScheduledMessageStatus::Pending,
            failure_reason: None,
        };
        db.insert_scheduled_message(&scheduled)
            .await
            .expect("a scheduled message");

        Carried {
            messages,
            closed_poll,
            open_poll,
            open_sheet,
            scheduled,
        }
    }

    /// 7.4 "S4", once the protect answered: the open poll is closed with one
    /// `PollClose`, the closed poll publishes nothing, the open sheet is
    /// locked with one sheet update, and the scheduled message is gone.
    /// Every event is published before the protect update, and the
    /// subscription is FIFO, so waiting on `update` first buffers them all.
    async fn assert_carried_over(
        setup: &mut Setup,
        carried: &Carried,
        update: impl Fn(&EventV1) -> bool,
    ) {
        let channel_id = setup.channel_id();
        let server_id = setup.server_id.clone();
        setup.harness.wait_for_event(&server_id, update).await;

        let db = &setup.harness.db;
        assert!(
            db.fetch_poll(&carried.open_poll.id)
                .await
                .expect("the open poll")
                .closed
        );
        assert!(
            db.fetch_sheet(&carried.open_sheet.id)
                .await
                .expect("the open sheet")
                .locked
        );
        assert!(db
            .fetch_scheduled_message(&carried.scheduled.id)
            .await
            .is_err());

        let open_poll = carried.open_poll.clone();
        setup
            .harness
            .wait_for_event(&channel_id, move |event| {
                matches!(event, EventV1::PollClose {
                    id, channel_id, message_id, counts, total_votes
                } if *id == open_poll.id
                    && *channel_id == open_poll.channel
                    && *message_id == open_poll.message
                    && counts.len() == 2
                    && *total_votes == 0)
            })
            .await;
        let open_sheet = carried.open_sheet.id.clone();
        setup
            .harness
            .wait_for_event(&channel_id, move |event| {
                matches!(event, EventV1::SoftresSheetUpdate { id, .. } if *id == open_sheet)
            })
            .await;
        let closed_poll = carried.closed_poll.id.clone();
        setup.harness.assert_no_buffered_event(
            &channel_id,
            |event| matches!(event, EventV1::PollClose { id, .. } if *id == closed_poll),
        );
    }

    /// Every `ProtectedSeatsUpdate` entry of `server_id`
    async fn seats_updates(harness: &TestHarness, server_id: &str) -> Vec<AuditLogEntry> {
        harness
            .db
            .fetch_audit_log(
                server_id,
                None,
                50,
                Some(AuditLogAction::ProtectedSeatsUpdate),
                None,
            )
            .await
            .expect("the audit log")
    }

    /// Every `ChannelProtect` entry of `server_id`
    async fn protect_entries(harness: &TestHarness, server_id: &str) -> Vec<AuditLogEntry> {
        harness
            .db
            .fetch_audit_log(
                server_id,
                None,
                50,
                Some(AuditLogAction::ChannelProtect),
                None,
            )
            .await
            .expect("the audit log")
    }

    /// The one `ChannelProtect` entry of `server_id`, by `owner` on
    /// `channel_id` (7.5 "S4"): its changes as (key, new)
    async fn protect_entry(
        harness: &TestHarness,
        server_id: &str,
        owner: &User,
        channel_id: &str,
    ) -> Vec<(String, Option<AuditValue>)> {
        let entries = protect_entries(harness, server_id).await;
        assert_eq!(entries.len(), 1, "{entries:?}");
        let entry = &entries[0];
        assert_eq!(entry.actor.as_deref(), Some(owner.id.as_str()));
        assert_eq!(entry.channel.as_deref(), Some(channel_id));
        assert_eq!(entry.target, None);
        assert_eq!(entry.reason, None);
        entry
            .changes
            .iter()
            .map(|change| {
                assert_eq!(change.old, None, "{entry:?}");
                (change.key.clone(), change.new.clone())
            })
            .collect()
    }

    /// The 7.5 seat event for `channel_id`
    fn seats_changed(channel_id: &str) -> impl Fn(&EventV1) -> bool + '_ {
        move |event| {
            matches!(event, EventV1::ProtectedChannelChanged { id, scope }
                if id == channel_id && *scope == vec![PROTECTED_SCOPE_SEATS.to_string()])
        }
    }

    async fn formats_v2_on() {
        revolt_config::overwrite_config(|settings| {
            settings.features.protected_channels.formats_v2 = true;
        })
        .await;
    }

    /// `PUT /channels/:id/protect` as `session`: the status and the body
    async fn protect(
        harness: &TestHarness,
        session: &Session,
        channel_id: &str,
        data: &v0::DataProtectChannel,
    ) -> (Status, String) {
        let response = harness
            .client
            .put(format!("/channels/{channel_id}/protect"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.clone()))
            .body(serde_json::to_string(data).expect("JSON"))
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    #[track_caller]
    fn body(answer: &(Status, String)) -> serde_json::Value {
        serde_json::from_str(&answer.1).unwrap_or_else(|_| panic!("not JSON: {:?}", answer))
    }

    /// A refusal: its status, and its whole error body. The body never
    /// carries the error's `location`, so an exact match also proves that.
    #[track_caller]
    fn assert_refused(answer: &(Status, String), status: Status, error: serde_json::Value) {
        assert_eq!(answer.0, status, "{:?}", answer);
        assert_eq!(body(answer), error, "{:?}", answer);
    }

    /// The success answer: the channel as stored now, which is protected
    async fn assert_protected_answer(harness: &TestHarness, answer: &(Status, String), id: &str) {
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        let fresh = harness.db.fetch_channel(id).await.expect("the channel");
        assert!(fresh.is_protected(), "{:?}", fresh);
        let fresh: v0::Channel = fresh.into();
        assert_eq!(body(answer), serde_json::to_value(fresh).expect("JSON"));
    }

    /// What a protect writes: the flag, the seat list and the seats
    #[derive(Debug, PartialEq)]
    struct Written {
        protected: bool,
        list: Option<SeatList>,
        seats: Vec<ChannelSeat>,
    }

    impl Written {
        fn nothing() -> Written {
            Written {
                protected: false,
                list: None,
                seats: vec![],
            }
        }
    }

    async fn written(harness: &TestHarness, channel_id: &str) -> Written {
        let db = &harness.db;
        let mut seats = db.fetch_channel_seats(channel_id).await.expect("seats");
        seats.sort_by(|a, b| a.user_id.cmp(&b.user_id));
        Written {
            protected: db
                .fetch_channel(channel_id)
                .await
                .expect("the channel")
                .is_protected(),
            list: db.fetch_seat_list(channel_id).await.expect("the seat list"),
            seats,
        }
    }

    /// The 7.2 protect event for `channel_id`: `protected: Some(true)` and
    /// nothing else
    fn protect_update(channel_id: &str) -> impl Fn(&EventV1) -> bool + '_ {
        let expected = v0::PartialChannel {
            protected: Some(true),
            ..Default::default()
        };
        move |event| {
            matches!(event, EventV1::ChannelUpdate { id, data, clear }
                if id == channel_id && *data == expected && clear.is_empty())
        }
    }

    async fn make_privileged(harness: &TestHarness, user: &User) {
        harness
            .db
            .update_user(
                &user.id,
                &PartialUser {
                    privileged: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("make the owner privileged");
        assert!(
            harness
                .db
                .fetch_user(&user.id)
                .await
                .expect("user")
                .privileged
        );
    }

    #[test]
    fn the_owner_protects_and_the_server_topic_hears_it() {
        crate::util::test::rt().block_on(Box::pin(the_owner_protects_case()))
    }

    async fn the_owner_protects_case() {
        let mut setup = setup().await;
        let channel_id = setup.channel_id();
        let data = setup.genesis();

        let answer = protect(&setup.harness, &setup.owner_session, &channel_id, &data).await;
        assert_protected_answer(&setup.harness, &answer, &channel_id).await;

        let written = written(&setup.harness, &channel_id).await;
        assert!(written.protected);
        let list = written.list.expect("the genesis list is stored");
        assert_eq!(list.version, 1);
        assert_eq!(list.body, data.seat_list.body);
        assert_eq!(list.signature, data.seat_list.signature);
        let seated: BTreeSet<&str> = written
            .seats
            .iter()
            .filter(|seat| seat.is_active())
            .map(|seat| seat.user_id.as_str())
            .collect();
        assert_eq!(
            seated,
            BTreeSet::from([setup.owner.id.as_str(), setup.member.id.as_str()])
        );

        // Decision 19 (W2): on the SERVER topic
        let server_id = setup.server_id.clone();
        setup
            .harness
            .wait_for_event(&server_id, protect_update(&channel_id))
            .await;

        // S2 (4.3 "After the claim commits", 7.5): the seat event on the
        // CHANNEL topic and the protect's one `ProtectedSeatsUpdate`, with
        // everyone it seated. Control: protect's `after_seat_list_write`
        // call removed.
        setup
            .harness
            .wait_for_event(&channel_id, seats_changed(&channel_id))
            .await;
        let entries = seats_updates(&setup.harness, &server_id).await;
        assert_eq!(entries.len(), 1, "{entries:?}");
        let entry = &entries[0];
        assert_eq!(entry.actor.as_deref(), Some(setup.owner.id.as_str()));
        assert_eq!(entry.channel.as_deref(), Some(channel_id.as_str()));
        assert_eq!(entry.reason, None);
        let mut seated = vec![setup.owner.id.clone(), setup.member.id.clone()];
        seated.sort();
        let changes: Vec<(String, Option<AuditValue>)> = entry
            .changes
            .iter()
            .map(|change| (change.key.clone(), change.new.clone()))
            .collect();
        assert_eq!(
            changes,
            vec![
                ("released".to_string(), Some(AuditValue::StringList(vec![]))),
                ("seated".to_string(), Some(AuditValue::StringList(seated))),
            ]
        );

        // 7.5 "S4": the one `ChannelProtect` entry; a v1 genesis has no
        // boundary and keeps nothing to wipe. Control: the entry dropped.
        assert_eq!(
            protect_entry(&setup.harness, &server_id, &setup.owner, &channel_id).await,
            vec![
                ("boundary".to_string(), None),
                ("wiped".to_string(), Some(AuditValue::Bool(false))),
            ]
        );
    }

    /// N3 (#128, #134): the protect landed through the database, so no event
    /// was ever published (a protect whose answer was lost), and the owner
    /// sends the same bytes again
    async fn an_identical_retry_case() {
        let mut setup = setup().await;
        let channel_id = setup.channel_id();
        let data = setup.genesis();
        setup.harness.protect_with_db(&setup.channel, &data).await;
        let before = written(&setup.harness, &channel_id).await;
        assert!(before.protected);

        let answer = protect(&setup.harness, &setup.owner_session, &channel_id, &data).await;
        assert_protected_answer(&setup.harness, &answer, &channel_id).await;
        assert_eq!(
            written(&setup.harness, &channel_id).await,
            before,
            "N3 writes nothing"
        );

        let server_id = setup.server_id.clone();
        setup
            .harness
            .wait_for_event(&server_id, protect_update(&channel_id))
            .await;

        // S2: the retry changed nothing, so no seat event and no entry. The
        // route publishes the seat event before the protect update and the
        // subscription is FIFO, so one would be buffered by now. Control:
        // the event and the entry emitted on `unchanged` too.
        setup
            .harness
            .assert_no_buffered_event(&channel_id, |event| {
                matches!(event, EventV1::ProtectedChannelChanged { .. })
            });
        let entries = seats_updates(&setup.harness, &server_id).await;
        assert!(entries.is_empty(), "{entries:?}");
        let entries = protect_entries(&setup.harness, &server_id).await;
        assert!(entries.is_empty(), "{:?}", entries);
    }

    #[test]
    fn an_identical_retry_re_emits_the_update_and_writes_nothing() {
        crate::util::test::rt().block_on(Box::pin(an_identical_retry_case()))
    }

    /// Decision 4 (W2): the retry runs before the growth gate
    #[test]
    fn an_identical_retry_succeeds_with_growth_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            Box::pin(an_identical_retry_case()).await
        })
    }

    #[test]
    fn a_new_protect_with_growth_off_is_refused_before_any_write() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            Box::pin(a_new_protect_with_growth_off_case()).await
        })
    }

    async fn a_new_protect_with_growth_off_case() {
        let setup = setup().await;
        let channel_id = setup.channel_id();

        let answer = protect(
            &setup.harness,
            &setup.owner_session,
            &channel_id,
            &setup.genesis(),
        )
        .await;
        assert_refused(
            &answer,
            Status::BadRequest,
            json!({ "type": "FeatureDisabled", "feature": "protected_channels" }),
        );
        assert_eq!(
            written(&setup.harness, &channel_id).await,
            Written::nothing()
        );
    }

    /// 4.3 step 1 (#218) with `formats_v2` off (the test config): a v2
    /// genesis, honest authority and all, is refused 400 and nothing is
    /// written; S1's v1 genesis is what lands (the tests above)
    #[test]
    fn a_v2_genesis_is_refused_while_formats_v2_is_off() {
        crate::util::test::rt().block_on(Box::pin(a_v2_genesis_with_formats_v2_off_case()))
    }

    async fn a_v2_genesis_with_formats_v2_off_case() {
        let setup = setup().await;
        let channel_id = setup.channel_id();
        let key = &setup.owner_device.signing_key;
        let data = setup.v2_genesis(&setup.first_authority(key, key));

        let answer = protect(&setup.harness, &setup.owner_session, &channel_id, &data).await;
        assert_refused(
            &answer,
            Status::BadRequest,
            json!({ "type": "FailedValidation", "error": "a v2 genesis list needs formats_v2" }),
        );
        assert_eq!(
            written(&setup.harness, &channel_id).await,
            Written::nothing()
        );
    }

    /// With `formats_v2` on: a v1 genesis is refused (#218); a v2 genesis
    /// whose first authority lists the owner device under a key that is not
    /// its directory key is refused by 4.3 step 3b, even though the
    /// directory key signed it (so only the key compare stops it); neither
    /// writes anything. The honest v2 genesis lands with its authority, and
    /// the seat event goes out. Control: the route's directory-key compare
    /// removed.
    #[test]
    fn with_formats_v2_on_only_an_honest_v2_genesis_lands() {
        crate::util::test::rt().block_on(Box::pin(async {
            formats_v2_on().await;
            with_formats_v2_on_only_an_honest_v2_genesis_lands_case().await
        }))
    }

    async fn with_formats_v2_on_only_an_honest_v2_genesis_lands_case() {
        let mut setup = setup().await;
        let channel_id = setup.channel_id();
        let key = setup.owner_device.signing_key.clone();
        let foreign = TestE2EEDevice::signing_key_for(MEMBER_DEVICE_SEED);

        let answer = protect(
            &setup.harness,
            &setup.owner_session,
            &channel_id,
            &setup.genesis(),
        )
        .await;
        assert_refused(
            &answer,
            Status::BadRequest,
            json!({
                "type": "FailedValidation",
                "error": "a genesis list must be v2 while formats_v2 is on"
            }),
        );
        assert_eq!(
            written(&setup.harness, &channel_id).await,
            Written::nothing()
        );

        let forged = setup.v2_genesis(&setup.first_authority(&foreign, &key));
        let answer = protect(&setup.harness, &setup.owner_session, &channel_id, &forged).await;
        assert_refused(
            &answer,
            Status::BadRequest,
            json!({
                "type": "FailedValidation",
                "error": "authority signer key is not the signer device key"
            }),
        );
        assert_eq!(
            written(&setup.harness, &channel_id).await,
            Written::nothing()
        );

        let honest_authority = setup.first_authority(&key, &key);
        let honest = setup.v2_genesis(&honest_authority);
        let answer = protect(&setup.harness, &setup.owner_session, &channel_id, &honest).await;
        assert_protected_answer(&setup.harness, &answer, &channel_id).await;
        let list = written(&setup.harness, &channel_id)
            .await
            .list
            .expect("the v2 genesis is stored");
        assert!(list.is_v2());
        let stored_authority = list.authority.expect("its authority");
        assert_eq!(stored_authority.body, honest_authority.body);
        assert_eq!(stored_authority.signature, honest_authority.signature);
        setup
            .harness
            .wait_for_event(&channel_id, seats_changed(&channel_id))
            .await;
    }

    /// MUST CLOSE 5, 2.3 (W0-fix): a privileged owner cannot protect
    #[test]
    fn a_privileged_owner_is_refused() {
        crate::util::test::rt().block_on(Box::pin(a_privileged_owner_is_refused_case()))
    }

    async fn a_privileged_owner_is_refused_case() {
        let setup = setup().await;
        let channel_id = setup.channel_id();
        make_privileged(&setup.harness, &setup.owner).await;

        let answer = protect(
            &setup.harness,
            &setup.owner_session,
            &channel_id,
            &setup.genesis(),
        )
        .await;
        assert_refused(
            &answer,
            Status::BadRequest,
            json!({ "type": "InvalidOperation" }),
        );
        assert_eq!(
            written(&setup.harness, &channel_id).await,
            Written::nothing()
        );
    }

    /// #128 orders N3 BEFORE the staff-owner refusal: an owner who protected,
    /// then became privileged, still gets the stored success for the same
    /// bytes, and nothing is written
    #[test]
    fn a_privileged_owners_identical_retry_is_the_stored_success() {
        crate::util::test::rt().block_on(Box::pin(a_privileged_owners_retry_case()))
    }

    async fn a_privileged_owners_retry_case() {
        let setup = setup().await;
        let channel_id = setup.channel_id();
        let data = setup.genesis();
        setup.harness.protect_with_db(&setup.channel, &data).await;
        let before = written(&setup.harness, &channel_id).await;
        make_privileged(&setup.harness, &setup.owner).await;

        let answer = protect(&setup.harness, &setup.owner_session, &channel_id, &data).await;
        assert_protected_answer(&setup.harness, &answer, &channel_id).await;
        assert_eq!(written(&setup.harness, &channel_id).await, before);
    }

    /// A member who can view the channel replays the owner's signed protect
    /// bytes: the list is valid and its signer owns the server (the driver
    /// would take it), but the caller is not the owner
    #[test]
    fn a_non_owner_replaying_the_owners_list_is_refused() {
        crate::util::test::rt().block_on(Box::pin(a_non_owner_is_refused_case()))
    }

    async fn a_non_owner_is_refused_case() {
        let setup = setup().await;
        let channel_id = setup.channel_id();
        let channel = setup
            .harness
            .db
            .fetch_channel(&channel_id)
            .await
            .expect("the channel");
        require_channel_access(&setup.harness.db, &setup.member, &channel)
            .await
            .expect("the member views the channel");

        let answer = protect(
            &setup.harness,
            &setup.member_session,
            &channel_id,
            &setup.genesis(),
        )
        .await;
        assert_refused(&answer, Status::Forbidden, json!({ "type": "NotOwner" }));
        assert_eq!(
            written(&setup.harness, &channel_id).await,
            Written::nothing()
        );
    }

    #[test]
    fn a_bad_signature_is_refused() {
        crate::util::test::rt().block_on(Box::pin(a_bad_signature_is_refused_case()))
    }

    async fn a_bad_signature_is_refused_case() {
        let setup = setup().await;
        let channel_id = setup.channel_id();
        let mut data = setup.genesis();
        data.seat_list.signature = setup.owner_device.sign("not the seat list");

        let answer = protect(&setup.harness, &setup.owner_session, &channel_id, &data).await;
        assert_refused(
            &answer,
            Status::BadRequest,
            json!({ "type": "FailedValidation", "error": "seat list signature" }),
        );
        assert_eq!(
            written(&setup.harness, &channel_id).await,
            Written::nothing()
        );
    }

    /// The owner signs from a registered device that another session is
    /// bound to
    #[test]
    fn an_unbound_session_is_refused() {
        crate::util::test::rt().block_on(Box::pin(an_unbound_session_is_refused_case()))
    }

    async fn an_unbound_session_is_refused_case() {
        let setup = setup().await;
        let channel_id = setup.channel_id();
        let elsewhere = setup
            .harness
            .new_e2ee_device(
                &setup.owner,
                &Ulid::new().to_string(),
                NEW_OWNER_DEVICE_SEED,
            )
            .await;
        let data = elsewhere.protect_request(
            &channel_id,
            FIXTURE_DEVICE_CAP,
            &[setup.owner.id.clone(), setup.member.id.clone()],
        );

        let answer = protect(&setup.harness, &setup.owner_session, &channel_id, &data).await;
        assert_refused(
            &answer,
            Status::Unauthorized,
            json!({ "type": "NotAuthenticated" }),
        );
        assert_eq!(
            written(&setup.harness, &channel_id).await,
            Written::nothing()
        );
    }

    /// 7.2 and decision 13 (W2), enforced by the driver inside the protect
    /// transaction: history and threads stay plaintext, so a channel with
    /// either is refused
    #[test]
    fn a_channel_with_a_message_or_a_thread_is_refused() {
        crate::util::test::rt().block_on(Box::pin(a_channel_with_history_case()))
    }

    async fn a_channel_with_history_case() {
        let setup = setup().await;
        let db = &setup.harness.db;

        let with_message = setup.channel_id();
        db.insert_message(&Message {
            id: Ulid::new().to_string(),
            channel: with_message.clone(),
            author: setup.owner.id.clone(),
            content: Some("history".to_string()),
            ..Default::default()
        })
        .await
        .expect("a message");

        let server = db.fetch_server(&setup.server_id).await.expect("server");
        let with_thread = setup.harness.new_channel(&server).await;
        setup
            .harness
            .grant_entitlement(&with_thread, FIXTURE_SLOT_CAP, None)
            .await;
        db.insert_channel(&Channel::Thread {
            id: Ulid::new().to_string(),
            server: setup.server_id.clone(),
            parent_channel: with_thread.id().to_string(),
            name: "thread".to_string(),
            creator: setup.owner.id.clone(),
            origin_message_id: None,
            last_message_id: None,
            archived: false,
            archived_timestamp: None,
            auto_archive_minutes: 0,
            locked: false,
            applied_tags: vec![],
        })
        .await
        .expect("a thread");

        for channel_id in [with_message, with_thread.id().to_string()] {
            let data = setup.owner_device.protect_request(
                &channel_id,
                FIXTURE_DEVICE_CAP,
                &[setup.owner.id.clone(), setup.member.id.clone()],
            );
            let answer = protect(&setup.harness, &setup.owner_session, &channel_id, &data).await;
            assert_refused(
                &answer,
                Status::BadRequest,
                json!({ "type": "InvalidOperation" }),
            );
            assert_eq!(
                written(&setup.harness, &channel_id).await,
                Written::nothing()
            );
        }
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

    /// Decision 18 (W2): for every caller class, a channel the caller cannot
    /// view (protectable, or already protected) and a deleted channel answer
    /// EXACTLY as a channel id the server never held, the full body, for a
    /// valid and a garbage request alike, and that answer is not what a
    /// viewer gets
    async fn non_viewers_answer_as_a_missing_channel() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (server, hidden) = harness.new_protectable_channel(&owner).await;
        harness
            .grant_entitlement(&hidden, FIXTURE_SLOT_CAP, None)
            .await;
        let owner_device = harness
            .new_e2ee_device(&owner, &owner_session.id, OWNER_DEVICE_SEED)
            .await;
        let genesis = |channel_id: &str| {
            owner_device.protect_request(channel_id, FIXTURE_DEVICE_CAP, &[owner.id.clone()])
        };
        deny_view(&harness, &hidden).await;

        let hidden_protected = harness.new_channel(&server).await;
        harness
            .grant_entitlement(&hidden_protected, FIXTURE_SLOT_CAP, None)
            .await;
        deny_view(&harness, &hidden_protected).await;
        harness
            .protect_with_db(&hidden_protected, &genesis(hidden_protected.id()))
            .await;

        let deleted = harness.new_channel(&server).await;
        harness
            .grant_entitlement(&deleted, FIXTURE_SLOT_CAP, None)
            .await;
        db.delete_channel(&deleted).await.expect("delete");
        assert!(db.fetch_channel(deleted.id()).await.is_err());

        let (_, member_session, member) = harness.new_user().await;
        let (_, bot_session, bot) = harness.new_user().await;
        let (_, unbound_session, unbound) = harness.new_user().await;
        for user in [&member, &bot, &unbound] {
            harness.join_server(&server, user).await;
        }
        harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        harness
            .new_e2ee_device(&unbound, &Ulid::new().to_string(), MEMBER_DEVICE_SEED + 1)
            .await;
        db.update_user(
            &bot.id,
            &PartialUser {
                bot: Some(BotInformation {
                    owner: owner.id.clone(),
                }),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("make the bot a bot");
        let bot = db.fetch_user(&bot.id).await.expect("the bot");
        assert!(bot.bot.is_some());

        let garbage: v0::DataProtectChannel = serde_json::from_value(json!({
            "seat_list": {
                "body": "garbage",
                "signature": "garbage",
                "signer_device_id": "garbage"
            }
        }))
        .expect("a garbage request");
        let missing_id = Ulid::new().to_string();
        let callers = [
            ("member", &member, &member_session),
            ("bot", &bot, &bot_session),
            ("unbound", &unbound, &unbound_session),
        ];

        for (class, user, session) in callers {
            for channel_id in [hidden.id(), hidden_protected.id()] {
                let channel = db.fetch_channel(channel_id).await.expect("the channel");
                assert!(
                    require_channel_access(db, user, &channel).await.is_err(),
                    "{} views {}",
                    class,
                    channel_id
                );
            }

            for (kind, request) in [
                ("valid", genesis(missing_id.as_str())),
                ("garbage", garbage.clone()),
            ] {
                let missing = protect(&harness, session, &missing_id, &request).await;
                assert_refused(&missing, Status::NotFound, json!({ "type": "NotFound" }));
                assert!(
                    body(&missing).get("location").is_none(),
                    "the body must not carry the error location: {}",
                    missing.1
                );

                for (target, channel_id) in [
                    ("hidden", hidden.id()),
                    ("hidden protected", hidden_protected.id()),
                    ("deleted", deleted.id()),
                ] {
                    let request = match kind {
                        "valid" => genesis(channel_id),
                        _ => garbage.clone(),
                    };
                    let answer = protect(&harness, session, channel_id, &request).await;
                    assert_eq!(answer, missing, "{} {} {}", class, kind, target);
                }
            }
        }

        // The owner views the hidden channel and gets a different answer: a
        // protect, or a gate (the checks the hidden answer must not reach)
        let owner_missing = protect(&harness, &owner_session, &missing_id, &garbage).await;
        let owner_hidden =
            protect(&harness, &owner_session, hidden.id(), &genesis(hidden.id())).await;
        assert_ne!(owner_hidden, owner_missing);
        let config = revolt_config::config().await;
        if !config.features.e2ee_enabled {
            assert_refused(
                &owner_hidden,
                Status::BadRequest,
                json!({ "type": "FeatureDisabled", "feature": "e2ee" }),
            );
        } else if !config.features.protected_channels.enabled {
            assert_refused(
                &owner_hidden,
                Status::BadRequest,
                json!({ "type": "FeatureDisabled", "feature": "protected_channels" }),
            );
        } else {
            assert_protected_answer(&harness, &owner_hidden, hidden.id()).await;
        }
    }

    #[test]
    fn non_viewers_answer_as_a_missing_channel_with_every_flag_on() {
        crate::util::test::rt().block_on(Box::pin(non_viewers_answer_as_a_missing_channel()))
    }

    #[test]
    fn non_viewers_answer_as_a_missing_channel_with_e2ee_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            Box::pin(non_viewers_answer_as_a_missing_channel()).await
        })
    }

    #[test]
    fn non_viewers_answer_as_a_missing_channel_with_growth_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            Box::pin(non_viewers_answer_as_a_missing_channel()).await
        })
    }

    /// A route-level smoke of the decision-13 protect-vs-kick race (the
    /// unpaced races are the database tests, A1): the protect route and the
    /// kick (`Member::remove`, what the kick route calls) start together.
    /// Whichever lands first, neither errors and the kicked member never
    /// ends up holding an active seat. No overlap guard: a smoke, not a race
    /// proof.
    #[test]
    fn protect_racing_a_kick_never_leaves_the_kicked_member_seated() {
        crate::util::test::rt().block_on(Box::pin(protect_racing_a_kick_case()))
    }

    async fn protect_racing_a_kick_case() {
        const ROUNDS: usize = 6;

        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let owner_device = harness
            .new_e2ee_device(&owner, &owner_session.id, OWNER_DEVICE_SEED)
            .await;

        let mut landed = 0;
        for round in 0..ROUNDS {
            let (server, channel) = harness.new_protectable_channel(&owner).await;
            harness
                .grant_entitlement(&channel, FIXTURE_SLOT_CAP, None)
                .await;
            let (_, _, member) = harness.new_user().await;
            let membership = harness.join_server(&server, &member).await;
            let data = owner_device.protect_request(
                channel.id(),
                FIXTURE_DEVICE_CAP,
                &[owner.id.clone(), member.id.clone()],
            );

            let (answer, kicked) = futures::join!(
                protect(&harness, &owner_session, channel.id(), &data),
                membership.remove(db, &server, RemovalIntention::Kick, true),
            );
            kicked.unwrap_or_else(|error| panic!("round {}: kick: {:?}", round, error));

            if answer.0 == Status::Ok {
                landed += 1;
                assert_protected_answer(&harness, &answer, channel.id()).await;
            } else {
                assert_eq!(
                    answer.0,
                    Status::BadRequest,
                    "round {}: {:?}",
                    round,
                    answer
                );
                assert_eq!(
                    body(&answer)["type"],
                    "FailedValidation",
                    "round {}: {:?}",
                    round,
                    answer
                );
                assert_eq!(
                    written(&harness, channel.id()).await,
                    Written::nothing(),
                    "round {}",
                    round
                );
            }

            assert!(
                db.fetch_member(&server.id, &member.id).await.is_err(),
                "round {}: still a member",
                round
            );
            let seats = db.fetch_channel_seats(channel.id()).await.expect("seats");
            assert!(
                !seats
                    .iter()
                    .any(|seat| seat.user_id == member.id && seat.is_active()),
                "round {}: the kicked member holds an active seat: {:?}",
                round,
                seats
            );
        }
        println!("protect vs kick: {}/{} protects landed", landed, ROUNDS);
    }

    /// 7.2 "S4" (S4-PA-7): a present `wipe_history` must agree with the
    /// signed `pre_history` (a v1 genesis keeps). `true` is refused and
    /// writes nothing; `false` lands. Control: the route passes `None`.
    #[test]
    fn a_wipe_history_flag_must_agree_with_the_signed_line() {
        crate::util::test::rt().block_on(Box::pin(a_wipe_history_flag_case()))
    }

    async fn a_wipe_history_flag_case() {
        let setup = setup().await;
        let channel_id = setup.channel_id();

        let mut data = setup.genesis();
        data.wipe_history = Some(true);
        let answer = protect(&setup.harness, &setup.owner_session, &channel_id, &data).await;
        assert_refused(
            &answer,
            Status::BadRequest,
            json!({
                "type": "FailedValidation",
                "error": "wipe_history disagrees with the signed pre_history"
            }),
        );
        assert_eq!(
            written(&setup.harness, &channel_id).await,
            Written::nothing()
        );

        data.wipe_history = Some(false);
        let answer = protect(&setup.harness, &setup.owner_session, &channel_id, &data).await;
        assert_protected_answer(&setup.harness, &answer, &channel_id).await;
        assert_eq!(stored_history(&setup.harness, &channel_id).await, None);
    }

    /// 2.9, 7.1 "S4": a legal hold refuses only a `wiped` genesis; a genesis
    /// that keeps its history (here a v1 one) still lands under a hold
    #[test]
    fn a_legal_hold_does_not_refuse_a_genesis_that_keeps_history() {
        crate::util::test::rt().block_on(Box::pin(a_hold_keeps_case()))
    }

    async fn a_hold_keeps_case() {
        let setup = setup().await;
        let channel_id = setup.channel_id();
        set_hold(&setup).await;

        let answer = protect(
            &setup.harness,
            &setup.owner_session,
            &channel_id,
            &setup.genesis(),
        )
        .await;
        assert_protected_answer(&setup.harness, &answer, &channel_id).await;
    }

    async fn set_hold(setup: &Setup) {
        setup
            .harness
            .db
            .set_server_legal_hold(&ServerLegalHold {
                id: setup.server_id.clone(),
                set_at: Timestamp::now_utc(),
                set_by: Ulid::new().to_string(),
                note: None,
            })
            .await
            .expect("the legal hold");
    }

    /// 4.1.1 "S4" (fix round F1): with `history_setting` off a genesis that
    /// would introduce a boundary is refused 400 and nothing is written
    #[test]
    fn with_history_setting_off_a_boundary_genesis_is_refused() {
        crate::util::test::rt().block_on(Box::pin(async {
            formats_v2_on().await;
            with_history_setting_off_case().await
        }))
    }

    async fn with_history_setting_off_case() {
        let setup = setup().await;
        let channel_id = setup.channel_id();
        let carried = carried(&setup).await;

        let data = setup.history_genesis(carried.boundary(), SeatListPreHistory::Kept, None);
        let answer = protect(&setup.harness, &setup.owner_session, &channel_id, &data).await;
        assert_refused(
            &answer,
            Status::BadRequest,
            json!({
                "type": "FailedValidation",
                "error": "history_boundary is refused until S4"
            }),
        );
        assert_eq!(
            written(&setup.harness, &channel_id).await,
            Written::nothing()
        );
    }

    /// 7.2 "S4", 7.4 "S4": the owner protects a channel with messages, a
    /// poll, a softres sheet and a scheduled message, with B its newest
    /// message. The list seats the owner alone; the answer, the stored
    /// channel and the protect update carry `protected_history { B, none }`;
    /// the carried-over state is closed; the `ChannelProtect` entry names B.
    #[test]
    fn the_owner_protects_a_channel_with_history() {
        crate::util::test::rt().block_on(Box::pin(async {
            history_setting_on().await;
            the_owner_protects_with_history_case().await
        }))
    }

    async fn the_owner_protects_with_history_case() {
        let mut setup = setup().await;
        let channel_id = setup.channel_id();
        let carried = carried(&setup).await;
        let boundary = carried.boundary().to_string();

        let data = setup.history_genesis(&boundary, SeatListPreHistory::Kept, None);
        let answer = protect(&setup.harness, &setup.owner_session, &channel_id, &data).await;
        assert_protected_answer(&setup.harness, &answer, &channel_id).await;

        let history = v0::ProtectedHistory {
            boundary: boundary.clone(),
            wipe: v0::HistoryWipe::None,
        };
        assert_eq!(
            stored_history(&setup.harness, &channel_id).await,
            Some(history.clone())
        );
        let written = written(&setup.harness, &channel_id).await;
        let seated: Vec<&str> = written
            .seats
            .iter()
            .filter(|seat| seat.is_active())
            .map(|seat| seat.user_id.as_str())
            .collect();
        assert_eq!(seated, vec![setup.owner.id.as_str()]);

        assert_carried_over(
            &mut setup,
            &carried,
            protect_update_carrying(&channel_id, Some(history)),
        )
        .await;
        let server_id = setup.server_id.clone();
        assert_eq!(
            protect_entry(&setup.harness, &server_id, &setup.owner, &channel_id).await,
            vec![
                ("boundary".to_string(), Some(AuditValue::String(boundary))),
                ("wiped".to_string(), Some(AuditValue::Bool(false))),
            ]
        );
    }

    /// N3 (#134) with a boundary: the protect landed through the database
    /// and nothing after its commit ran. The same bytes again answer the
    /// stored success carrying `protected_history`, re-emit the update with
    /// it, and close the carried-over state; no second `ChannelProtect`
    /// entry. Controls: the history dropped from the update; the poll close
    /// dropped.
    #[test]
    fn an_identical_retry_with_history_sends_it_and_closes_what_was_carried_over() {
        crate::util::test::rt().block_on(Box::pin(async {
            history_setting_on().await;
            an_identical_retry_with_history_case().await
        }))
    }

    async fn an_identical_retry_with_history_case() {
        let mut setup = setup().await;
        let channel_id = setup.channel_id();
        let carried = carried(&setup).await;
        let boundary = carried.boundary().to_string();
        let data = setup.history_genesis(&boundary, SeatListPreHistory::Kept, None);
        let landed = setup
            .harness
            .db
            .protect_channel_with_wipe(
                &channel_id,
                &SeatListSubmission::from(data.seat_list.clone()),
                None,
                Timestamp::now_utc(),
            )
            .await
            .expect("the protect lands through the database");
        assert!(!landed.unchanged);
        let before = written(&setup.harness, &channel_id).await;

        let answer = protect(&setup.harness, &setup.owner_session, &channel_id, &data).await;
        assert_protected_answer(&setup.harness, &answer, &channel_id).await;
        assert_eq!(written(&setup.harness, &channel_id).await, before);
        let history = v0::ProtectedHistory {
            boundary,
            wipe: v0::HistoryWipe::None,
        };
        assert_eq!(body(&answer)["protected_history"], json!(history));

        assert_carried_over(
            &mut setup,
            &carried,
            protect_update_carrying(&channel_id, Some(history)),
        )
        .await;
        let entries = protect_entries(&setup.harness, &setup.server_id).await;
        assert!(entries.is_empty(), "{:?}", entries);
    }

    /// 4.3 "S4", 2.9: under a legal hold a `wiped` genesis is refused
    /// `InvalidOperation` and nothing is written. With the hold cleared the
    /// same request lands, its wipe `requested` by the owner. Control: the
    /// legal-hold check dropped.
    #[test]
    fn a_wiped_genesis_is_refused_under_a_legal_hold() {
        crate::util::test::rt().block_on(Box::pin(async {
            history_setting_on().await;
            a_wiped_genesis_under_a_hold_case().await
        }))
    }

    async fn a_wiped_genesis_under_a_hold_case() {
        let mut setup = setup().await;
        let channel_id = setup.channel_id();
        let carried = carried(&setup).await;
        let boundary = carried.boundary().to_string();
        let data = setup.history_genesis(&boundary, SeatListPreHistory::Wiped, Some(true));
        set_hold(&setup).await;

        let answer = protect(&setup.harness, &setup.owner_session, &channel_id, &data).await;
        assert_refused(
            &answer,
            Status::BadRequest,
            json!({ "type": "InvalidOperation" }),
        );
        assert_eq!(
            written(&setup.harness, &channel_id).await,
            Written::nothing()
        );

        setup
            .harness
            .db
            .clear_server_legal_hold(&setup.server_id)
            .await
            .expect("clear the hold");
        let answer = protect(&setup.harness, &setup.owner_session, &channel_id, &data).await;
        assert_protected_answer(&setup.harness, &answer, &channel_id).await;
        let history = stored_history(&setup.harness, &channel_id)
            .await
            .expect("the stored history");
        assert_eq!(history.boundary, boundary);
        assert!(
            matches!(&history.wipe, v0::HistoryWipe::Requested { by, .. } if *by == setup.owner.id),
            "{:?}",
            history
        );

        let server_id = setup.server_id.clone();
        setup
            .harness
            .wait_for_event(
                &server_id,
                protect_update_carrying(&channel_id, Some(history)),
            )
            .await;
        assert_eq!(
            protect_entry(&setup.harness, &server_id, &setup.owner, &channel_id).await,
            vec![
                ("boundary".to_string(), Some(AuditValue::String(boundary))),
                ("wiped".to_string(), Some(AuditValue::Bool(true))),
            ]
        );
    }

    /// 7.2 "S4": a message newer than the signed boundary B (here B is the
    /// second of three) answers 409 `ProtectHistoryMoved` and nothing is
    /// written
    #[test]
    fn a_message_above_the_boundary_answers_protect_history_moved() {
        crate::util::test::rt().block_on(Box::pin(async {
            history_setting_on().await;
            protect_history_moved_case().await
        }))
    }

    async fn protect_history_moved_case() {
        let setup = setup().await;
        let channel_id = setup.channel_id();
        let carried = carried(&setup).await;

        let data = setup.history_genesis(&carried.messages[1].id, SeatListPreHistory::Kept, None);
        let answer = protect(&setup.harness, &setup.owner_session, &channel_id, &data).await;
        assert_refused(
            &answer,
            Status::Conflict,
            json!({ "type": "ProtectHistoryMoved" }),
        );
        assert_eq!(
            written(&setup.harness, &channel_id).await,
            Written::nothing()
        );
    }

    /// S4-D21: a `wiped` genesis still closes the open poll and locks the
    /// open sheet, but publishes neither, since both ride pre-boundary rows
    /// that are wipe-pending from the commit on. The protect update is
    /// published after them on the one FIFO subscription, so once it is
    /// observed nothing published before it can be missing from the
    /// buffer. Controls: the `PollClose` gate dropped; the sheet-update gate
    /// dropped.
    #[test]
    fn a_wiped_genesis_publishes_no_state_of_the_carried_over_rows() {
        crate::util::test::rt().block_on(Box::pin(async {
            history_setting_on().await;
            a_wiped_genesis_publishes_nothing_case().await
        }))
    }

    async fn a_wiped_genesis_publishes_nothing_case() {
        let mut setup = setup().await;
        let channel_id = setup.channel_id();
        let carried = carried(&setup).await;
        let boundary = carried.boundary().to_string();

        let data = setup.history_genesis(&boundary, SeatListPreHistory::Wiped, Some(true));
        let answer = protect(&setup.harness, &setup.owner_session, &channel_id, &data).await;
        assert_protected_answer(&setup.harness, &answer, &channel_id).await;
        let history = stored_history(&setup.harness, &channel_id)
            .await
            .expect("the stored history");
        assert!(
            matches!(history.wipe, v0::HistoryWipe::Requested { .. }),
            "{:?}",
            history
        );

        let server_id = setup.server_id.clone();
        setup
            .harness
            .wait_for_event(
                &server_id,
                protect_update_carrying(&channel_id, Some(history)),
            )
            .await;

        let db = &setup.harness.db;
        assert!(
            db.fetch_poll(&carried.open_poll.id)
                .await
                .expect("the open poll")
                .closed
        );
        assert!(
            db.fetch_sheet(&carried.open_sheet.id)
                .await
                .expect("the open sheet")
                .locked
        );

        let open_poll = carried.open_poll.id.clone();
        let open_sheet = carried.open_sheet.id.clone();
        setup
            .harness
            .assert_no_buffered_event(&channel_id, |event| {
                matches!(event, EventV1::PollClose { id, .. } if *id == open_poll)
                    || matches!(event, EventV1::SoftresSheetUpdate { id, .. } if *id == open_sheet)
            });
    }

    /// The pledge that funds [`crowdfunded_setup`]'s launch goal
    const PLEDGED: i64 = 1_200;

    /// [`setup`] without its admin grant: instead the owner funds a launch
    /// goal of the server alone and launches it onto the channel (S5b 8.6),
    /// so the channel holds a Crowdfund entitlement and a Launching tank and
    /// the pledge is still Held. The goal's id and the pledge's id.
    async fn crowdfunded_setup() -> (Setup, String, String) {
        use revolt_config::ProtectionFeatures;
        use revolt_database::{
            prot_key_admin, prot_user_account, ProtAmount, ProtGoal, ProtLaunchInput,
            ProtPledgeInput, ProtPosting, ProtRef, ProtTankRules, PROT_SYS_ADJUST,
        };

        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (server, channel) = harness.new_protectable_channel(&owner).await;
        harness.join_server(&server, &member).await;
        let owner_device = harness
            .new_e2ee_device(&owner, &owner_session.id, OWNER_DEVICE_SEED)
            .await;

        let db = &harness.db;
        let rules = ProtTankRules::from_config(&ProtectionFeatures::default())
            .expect("the default Prot config is valid");
        let now = revolt_database::now_ms();
        let goal = db
            .create_prot_goal(&ProtGoal {
                id: Ulid::new().to_string(),
                kind: v0::ProtGoalKind::Launch,
                server_id: server.id.clone(),
                channel_id: None,
                tank_id: None,
                created_by: owner.id.clone(),
                create_nonce: Ulid::new().to_string(),
                slots: FIXTURE_SLOT_CAP,
                days: Some(30),
                daily_cost: rules.daily_cost(FIXTURE_SLOT_CAP).expect("a slot tier"),
                base_daily_cost: None,
                target_prot: PLEDGED,
                pledged_total: 0,
                state: v0::ProtGoalState::Funding,
                deadline_at: now + 30 * 86_400_000,
                funded_at: None,
                launch_deadline_at: None,
                launched_at: None,
                closed_at: None,
                refund7_done: false,
                open_key: Some(format!("launch:{}", server.id)),
                version: 0,
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("a launch goal");

        // An admin credit, not a purchase, so none of it is held back (D17)
        db.apply_prot_posting(&ProtPosting {
            key: prot_key_admin("01ADMIN0000000000000000000", &Ulid::new().to_string()),
            kind: v0::ProtEntryKind::AdminAdjust,
            debit: PROT_SYS_ADJUST.to_string(),
            credit: prot_user_account(&owner.id),
            amount: ProtAmount::Exact(PLEDGED),
            debit_floor: 0,
            actor: "01ADMIN0000000000000000000".to_string(),
            reference: ProtRef::default(),
            reason: Some("protect hook test".to_string()),
            created_at: now,
        })
        .await
        .expect("the owner's Prot");
        let pledged = db
            .pledge_prot(&ProtPledgeInput {
                user_id: owner.id.clone(),
                goal_id: goal.id.clone(),
                amount: PLEDGED,
                nonce: Ulid::new().to_string(),
                rules: rules.clone(),
                now,
            })
            .await
            .expect("the owner funds the goal");
        assert!(pledged.funded_now);

        let (launched, tank) = db
            .launch_prot_goal(&ProtLaunchInput {
                goal_id: goal.id.clone(),
                channel_id: channel.id().to_string(),
                owner_id: owner.id.clone(),
                rules,
                now,
            })
            .await
            .expect("the goal launches onto the channel");
        assert_eq!(launched.state, v0::ProtGoalState::Launching);
        assert_eq!(tank.stage, v0::ProtTankStage::Launching);

        let setup = Setup {
            harness,
            owner,
            owner_session,
            owner_device,
            member,
            member_session,
            server_id: server.id,
            channel,
        };
        (setup, goal.id, pledged.pledge.id)
    }

    /// Whether the launch has been captured: the goal Launched, the tank
    /// Active and the pledge Captured in full. Anything else (the tank
    /// still Launching) fails the test.
    async fn assert_captured(harness: &TestHarness, channel_id: &str, goal: &str, pledge: &str) {
        let db = &harness.db;
        let tank = db
            .fetch_prot_tank_by_channel(channel_id)
            .await
            .expect("read the tank")
            .expect("the tank");
        assert_eq!(tank.stage, v0::ProtTankStage::Active, "{:?}", tank);
        let goal = db
            .fetch_prot_goal(goal)
            .await
            .expect("read the goal")
            .expect("the goal");
        assert_eq!(goal.state, v0::ProtGoalState::Launched, "{:?}", goal);
        let pledge = db
            .fetch_prot_pledge(pledge)
            .await
            .expect("read the pledge")
            .expect("the pledge");
        assert_eq!(
            (pledge.state, pledge.captured),
            (v0::ProtPledgeState::Captured, PLEDGED),
            "{:?}",
            pledge
        );
    }

    /// S5b 6.7: the protect route captures a crowdfunded channel's launch
    /// pledges right after the protect commits. Control: drop the
    /// `on_protect_landed` call (the tank stays Launching).
    #[test]
    fn protect_captures_the_launch_pledges() {
        crate::util::test::rt().block_on(Box::pin(protect_captures_the_launch_pledges_case()))
    }

    async fn protect_captures_the_launch_pledges_case() {
        let (setup, goal, pledge) = crowdfunded_setup().await;
        let channel_id = setup.channel_id();

        let answer = protect(
            &setup.harness,
            &setup.owner_session,
            &channel_id,
            &setup.genesis(),
        )
        .await;
        assert_protected_answer(&setup.harness, &answer, &channel_id).await;
        assert_captured(&setup.harness, &channel_id, &goal, &pledge).await;
    }

    /// S5b 6.7 on N3: a protect that landed without its answer (through the
    /// database here, so nothing captured) is retried with the same bytes;
    /// the `unchanged` retry captures too. Control: run the hook only when
    /// `!outcome.unchanged` (the tank stays Launching).
    #[test]
    fn an_identical_retry_captures_the_launch_pledges() {
        crate::util::test::rt().block_on(Box::pin(an_identical_retry_captures_case()))
    }

    async fn an_identical_retry_captures_case() {
        let (setup, goal, pledge) = crowdfunded_setup().await;
        let channel_id = setup.channel_id();
        let data = setup.genesis();
        setup.harness.protect_with_db(&setup.channel, &data).await;
        let tank = setup
            .harness
            .db
            .fetch_prot_tank_by_channel(&channel_id)
            .await
            .expect("read the tank")
            .expect("the tank");
        assert_eq!(tank.stage, v0::ProtTankStage::Launching);

        let answer = protect(&setup.harness, &setup.owner_session, &channel_id, &data).await;
        assert_protected_answer(&setup.harness, &answer, &channel_id).await;
        assert_captured(&setup.harness, &channel_id, &goal, &pledge).await;
    }
}
