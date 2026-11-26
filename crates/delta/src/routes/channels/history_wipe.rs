use iso8601_timestamp::Timestamp;
use revolt_database::{
    check_seat_list_authority, events::client::EventV1, seat_list_channel_server,
    util::reference::Reference, AuditLogAction, AuditLogDraft, AuditLogEntry, Channel, Database,
    SeatListBody, SeatListSubmission, Session, User, PROTECTED_SCOPE_SEATS,
};
use revolt_models::v0;
use revolt_result::{create_error, Error, ErrorType, Result};

use rocket::{serde::json::Json, State};

use super::seats_fetch::channel_seats_response;
use crate::routes::mls::{require_channel_access, require_protected_available};

/// # Request History Wipe
///
/// Request the wipe of a protected channel's pre-protect plaintext history
/// (protected-channels design 7.2 "History wipe", S4-D20). The body is the
/// owner's next v2 seat list, identical to the stored one except
/// `pre_history:wiped`. Only the server owner may request it, never a
/// privileged (staff) owner. From the request on the rows at or below the
/// boundary are no longer served; the `history_wipes` job deletes them.
#[openapi(tag = "E2EE")]
#[post("/<target>/history_wipe", data = "<data>")]
pub async fn wipe_history(
    db: &State<Database>,
    user: User,
    session: Session,
    target: Reference<'_>,
    data: Json<v0::DataSeatList>,
) -> Result<Json<v0::ResponseChannelSeats>> {
    // 7.4 refusal placement (decision 18 (W2)): a missing channel and a
    // channel the caller cannot view get the same answer, from one site,
    // before any other check, so a non-viewer learns nothing about it
    let channel = match target.as_channel(db).await {
        Ok(channel) => Some(channel),
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => None,
        Err(error) => return Err(error),
    };
    let channel = match channel {
        Some(channel) if require_channel_access(db, &user, &channel).await.is_ok() => channel,
        _ => return Err(missing_channel()),
    };

    // The hard owner check: the caller owns the channel's server (not the
    // permission calculus, which grants the owner and privileged accounts
    // everything first), and is not privileged (2.3: a privileged account is
    // never seated, so it never signs a list), as protect
    let server_id =
        seat_list_channel_server(&channel).ok_or_else(|| create_error!(InvalidOperation))?;
    let server = db.fetch_server(server_id).await?;
    if user.id != server.owner {
        return Err(create_error!(NotOwner));
    }
    if user.privileged {
        return Err(create_error!(InvalidOperation));
    }

    // 7.1 "S4": the available gate and `history_setting`; never the growth
    // gate (S4-D20: the wipe is allowed in every entitlement state)
    require_protected_available().await?;
    require_history_setting().await?;

    // The channel is protected with a non-empty boundary
    if history_boundary(&channel).is_none() {
        return Err(create_error!(InvalidOperation));
    }

    // 2.9: no legal hold on the server. A hold set after this read is the
    // job's: it reads the hold again before every batch and never marks a
    // wipe `Done` while one is set
    if db.fetch_server_legal_hold(&server.id).await?.is_some() {
        return Err(create_error!(InvalidOperation));
    }

    // 4.3 "S4": the route's steps, then the seat-list write as
    // `SeatListWriteKind::Wipe`, which owns the rest in its transaction
    let submission = validate_wipe_list(db, &channel, &user, &session, &data).await?;
    let outcome = db
        .request_history_wipe(channel.id(), &submission, Timestamp::now_utc())
        .await?;

    // 4.3 "S4", after the commit: the seat event and the audit entry (the
    // design's `count: None`) when the list landed; the byte-identical
    // retry (N3) writes and announces nothing
    if !outcome.unchanged {
        EventV1::ProtectedChannelChanged {
            id: channel.id().to_string(),
            scope: vec![PROTECTED_SCOPE_SEATS.to_string()],
        }
        .p(channel.id().to_string())
        .await;
        AuditLogEntry::record(
            db,
            AuditLogDraft {
                server: server.id.clone(),
                actor: Some(user.id.clone()),
                action: AuditLogAction::ChannelHistoryWipe,
                channel: Some(channel.id().to_string()),
                ..Default::default()
            },
        )
        .await;
    }

    // 7.5 "S4": `ChannelUpdate { protected_history }` on the SERVER topic,
    // as protect (#149); clients purge their cached plaintext rows at or
    // below B on it. Sent on the retry too, as protect does (#134): a wipe
    // that landed but whose answer was lost may never have sent it, and the
    // same state again changes nothing
    let channel = db.fetch_channel(channel.id()).await?;
    if let Channel::TextChannel {
        protected_history: Some(history),
        ..
    } = &channel
    {
        EventV1::ChannelUpdate {
            id: channel.id().to_string(),
            data: v0::PartialChannel {
                protected_history: Some(Box::new((**history).clone().into())),
                ..Default::default()
            },
            clear: vec![],
        }
        .p(server.id.clone())
        .await;
    }

    // The seat state `GET .../seats` serves, as the owner sees it
    channel_seats_response(db, &channel, &user).await.map(Json)
}

/// The one answer for a missing channel and a channel the caller cannot
/// view: one source site, so the body's `location` never tells them apart
fn missing_channel() -> Error {
    create_error!(NotFound)
}

/// 7.1 "S4": a wipe introduces history, so it needs `history_setting`; it
/// is refused as the history-link PUT is (7.6 "S4")
async fn require_history_setting() -> Result<()> {
    let config = revolt_config::config().await;
    if !config.features.protected_channels.history_setting {
        return Err(create_error!(FeatureDisabled {
            feature: "protected_history".to_string()
        }));
    }

    Ok(())
}

/// The boundary B of a protected channel that has one; `None` for an
/// unprotected channel and for one protected without a boundary
fn history_boundary(channel: &Channel) -> Option<&str> {
    match channel {
        Channel::TextChannel {
            protected: true,
            protected_history: Some(history),
            ..
        } if !history.boundary.is_empty() => Some(history.boundary.as_str()),
        _ => None,
    }
}

fn invalid(error: &str) -> Error {
    create_error!(FailedValidation {
        error: error.to_string()
    })
}

/// 4.3 "S4" (S4-PA-6), the route's half of the wipe write: steps 1 to 3 as
/// `protected_seat_validation` runs them for the seat PUT (strict parse, the
/// route channel and the signer device; the signer is the caller, signing
/// from a registered device this session is bound to; the signature verifies
/// under its directory key), plus two refusals only the route can make: a
/// handover (its statement is verified only at the route, and the wipe moves
/// nothing but `pre_history`) and a CHANGED authority (the route would have
/// to verify it; a wipe keeps the stored one).
///
/// Everything else is the driver's, inside its transaction: the version
/// rule with the byte-identical retry first, step 4c turned around
/// (`check_seat_list_wipe_lines`), the removed-users refusal, 5b, no seat
/// claimed or released, and the channel's boundary equal to the list's.
/// Steps 5 and 6 are not run: the list names exactly the stored list's
/// seats and `device_cap`, which passed them when that list landed.
async fn validate_wipe_list(
    db: &Database,
    channel: &Channel,
    user: &User,
    session: &Session,
    data: &v0::DataSeatList,
) -> Result<SeatListSubmission> {
    if data.handover.is_some() {
        return Err(invalid("the history wipe carries no handover"));
    }

    // Step 1: strict parse; the route channel and the declared signer device
    // must match the signed body
    let body = SeatListBody::parse(&data.body)?;
    if body.channel_id != channel.id() {
        return Err(invalid("seat list channel_id does not match the channel"));
    }
    if body.signer_device_id != data.signer_device_id {
        return Err(invalid(
            "signer_device_id does not match the seat list body",
        ));
    }

    // Step 2: the signer is the caller (the owner, checked above), signing
    // from a registered device this session is bound to
    if body.signer_user_id != user.id {
        return Err(create_error!(NotOwner));
    }
    let signer = db
        .fetch_e2ee_identity(&user.id, &body.signer_device_id)
        .await
        .map_err(|error| match error.error_type {
            ErrorType::NotFound => invalid("signer device is not registered"),
            _ => error,
        })?;
    signer.assert_bound_session(&session.id)?;

    // Step 3: the signature verifies under the directory identity key
    if !signer.verify_payload(&data.body, &data.signature) {
        return Err(invalid("seat list signature"));
    }

    // Step 3b: the authority is carried unchanged; only an unchanged one
    // goes unverified (4.4.1 rule 6)
    let submission: SeatListSubmission = data.clone().into();
    let stored = db.fetch_seat_list(channel.id()).await?;
    if check_seat_list_authority(&body, submission.authority.as_ref(), stored.as_ref())?.is_some() {
        return Err(invalid("the history wipe changes only pre_history"));
    }

    Ok(submission)
}

#[cfg(test)]
mod test {
    //! Run under nextest (one process per test): the flag cases overwrite
    //! the config, which panics on a second call in one process. Every
    //! refusal also asserts that nothing was written.

    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        events::client::EventV1, AuditLogAction, AuditLogEntry, BotInformation, Channel,
        HistoryWipe, MemberCompositeKey, Message, PartialChannel, PartialMember, PartialUser,
        ProtectedHistory, SeatList, SeatListBody, SeatListHistory, SeatListPreHistory,
        SeatListSubmission, SeatListV2Lines, Server, ServerLegalHold, Session, User,
        PROTECTED_SCOPE_SEATS,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::Value;
    use ulid::Ulid;

    use crate::routes::mls::require_channel_access;
    use crate::util::test::{
        TestE2EEDevice, TestHarness, FIXTURE_DEVICE_CAP, FIXTURE_ISSUED_AT, FIXTURE_SLOT_CAP,
        MEMBER_DEVICE_SEED, NEW_OWNER_DEVICE_SEED, OWNER_DEVICE_SEED,
    };

    /// A group salt (3.1.1: 64 lowercase hex)
    const SALT: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";

    /// `formats_v2` and `history_setting` on: protect takes a v2 genesis
    /// with a boundary, and the wipe passes its gate
    async fn history_on() {
        revolt_config::overwrite_config(|settings| {
            settings.features.protected_channels.formats_v2 = true;
            settings.features.protected_channels.history_setting = true;
        })
        .await;
    }

    /// A message id ten minutes before the fixtures' `issued_at` (4.1.1:
    /// a boundary is never later than the list's `issued_at`)
    fn boundary_id() -> String {
        Ulid::from_parts(
            FIXTURE_ISSUED_AT as u64 - 600_000,
            rand::random::<u64>() as u128,
        )
        .to_string()
    }

    /// A v2 seat list (no authority, history hidden) signed by `device`
    fn history_list(
        device: &TestE2EEDevice,
        channel_id: &str,
        version: i64,
        seats: &[&str],
        boundary: Option<&str>,
        pre_history: SeatListPreHistory,
    ) -> v0::DataSeatList {
        let body = SeatListBody {
            channel_id: channel_id.to_string(),
            version,
            device_cap: FIXTURE_DEVICE_CAP,
            issued_at: FIXTURE_ISSUED_AT,
            signer_user_id: device.user_id.clone(),
            signer_device_id: device.device_id.clone(),
            seats: seats.iter().map(|seat| seat.to_string()).collect(),
            v2: Some(SeatListV2Lines {
                authority_sha256: None,
                history: SeatListHistory::Hidden,
                history_boundary: boundary.map(str::to_string),
                pre_history,
                group_salt: SALT.to_string(),
            }),
        }
        .build()
        .expect("a canonical v2 seat list body");

        v0::DataSeatList {
            signature: device.sign(&body),
            body,
            signer_device_id: device.device_id.clone(),
            handover: None,
            authority: None,
        }
    }

    /// A list body that does not parse, signed by `device`: a probe whose
    /// only possible answers are an earlier check's refusal or the parse's
    fn garbage(device: &TestE2EEDevice) -> v0::DataSeatList {
        v0::DataSeatList {
            signature: device.sign("garbage"),
            body: "garbage".to_string(),
            signer_device_id: device.device_id.clone(),
            handover: None,
            authority: None,
        }
    }

    fn history_of(channel: &Channel) -> Option<ProtectedHistory> {
        match channel {
            Channel::TextChannel {
                protected_history, ..
            } => protected_history.as_deref().cloned(),
            _ => None,
        }
    }

    /// A v2 protected channel with a boundary (`history_on`): the owner's
    /// device signed the genesis (the owner alone, `pre_history:kept`, B the
    /// last message before protect); a member can view the channel
    struct World {
        harness: TestHarness,
        server: Server,
        channel: Channel,
        owner: User,
        owner_session: Session,
        owner_device: TestE2EEDevice,
        member: User,
        member_session: Session,
        boundary: String,
    }

    async fn world() -> World {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (server, channel) = harness.new_protectable_channel(&owner).await;
        harness
            .grant_entitlement(&channel, FIXTURE_SLOT_CAP, None)
            .await;
        let owner_device = harness
            .new_e2ee_device(&owner, &owner_session.id, OWNER_DEVICE_SEED)
            .await;
        harness.join_server(&server, &member).await;

        let boundary = boundary_id();
        harness
            .insert_raw_message(&Message {
                id: boundary.clone(),
                channel: channel.id().to_string(),
                author: owner.id.clone(),
                content: Some("Before protect".to_string()),
                ..Default::default()
            })
            .await;
        let genesis = history_list(
            &owner_device,
            channel.id(),
            1,
            &[&owner.id],
            Some(&boundary),
            SeatListPreHistory::Kept,
        );
        harness
            .db
            .protect_channel_with_wipe(
                channel.id(),
                &SeatListSubmission::from(genesis),
                None,
                Timestamp::now_utc(),
            )
            .await
            .expect("protect with a boundary");

        let channel = harness
            .db
            .fetch_channel(channel.id())
            .await
            .expect("the channel");
        assert_eq!(
            history_of(&channel),
            Some(ProtectedHistory {
                boundary: boundary.clone(),
                wipe: HistoryWipe::None,
            })
        );
        assert!(require_channel_access(&harness.db, &member, &channel)
            .await
            .is_ok());
        let server = harness
            .db
            .fetch_server(&server.id)
            .await
            .expect("the server");

        World {
            harness,
            server,
            channel,
            owner,
            owner_session,
            owner_device,
            member,
            member_session,
            boundary,
        }
    }

    impl World {
        /// The owner's wipe list: version 2, the genesis but `wiped`
        fn wipe(&self) -> v0::DataSeatList {
            history_list(
                &self.owner_device,
                self.channel.id(),
                2,
                &[&self.owner.id],
                Some(&self.boundary),
                SeatListPreHistory::Wiped,
            )
        }

        async fn stored(&self) -> SeatList {
            self.harness
                .db
                .fetch_seat_list(self.channel.id())
                .await
                .expect("read")
                .expect("a stored list")
        }

        async fn history(&self) -> Option<ProtectedHistory> {
            history_of(
                &self
                    .harness
                    .db
                    .fetch_channel(self.channel.id())
                    .await
                    .expect("the channel"),
            )
        }

        /// Nothing written: the genesis is still the list, the wipe was
        /// never requested and no wipe entry was recorded
        async fn assert_untouched(&self, case: &str) {
            assert_eq!(self.stored().await.version, 1, "{case}: the list");
            assert_eq!(
                self.history().await,
                Some(ProtectedHistory {
                    boundary: self.boundary.clone(),
                    wipe: HistoryWipe::None,
                }),
                "{case}: the wipe state"
            );
            let entries = wipe_entries(&self.harness, &self.server.id).await;
            assert!(entries.is_empty(), "{}: {:?}", case, entries);
        }

        /// The wipe lands for the owner
        async fn assert_wipe_lands(&self, case: &str) {
            let answer = post(
                &self.harness,
                &self.owner_session,
                self.channel.id(),
                &self.wipe(),
            )
            .await;
            let value = assert_ok(&answer, case);
            assert_eq!(value["list"]["version"], 2, "{case}: {}", answer.1);
            assert!(
                matches!(
                    self.history().await,
                    Some(ProtectedHistory {
                        wipe: HistoryWipe::Requested { .. },
                        ..
                    })
                ),
                "{}",
                case
            );
        }
    }

    /// The route's full answer: status and body
    async fn post(
        harness: &TestHarness,
        session: &Session,
        channel_id: &str,
        data: &v0::DataSeatList,
    ) -> (Status, String) {
        let response = harness
            .client
            .post(format!("/channels/{channel_id}/history_wipe"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.clone()))
            .body(serde_json::to_string(data).expect("JSON"))
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    /// Every `ChannelHistoryWipe` entry of `server_id`, newest first
    async fn wipe_entries(harness: &TestHarness, server_id: &str) -> Vec<AuditLogEntry> {
        harness
            .db
            .fetch_audit_log(
                server_id,
                None,
                50,
                Some(AuditLogAction::ChannelHistoryWipe),
                None,
            )
            .await
            .expect("the audit log")
    }

    #[track_caller]
    fn body(answer: &(Status, String)) -> Value {
        serde_json::from_str(&answer.1).unwrap_or_else(|_| panic!("not JSON: {:?}", answer))
    }

    #[track_caller]
    fn assert_ok(answer: &(Status, String), case: &str) -> Value {
        assert_eq!(answer.0, Status::Ok, "{}: {:?}", case, answer);
        body(answer)
    }

    #[track_caller]
    fn assert_answer(answer: &(Status, String), status: Status, expected: Value, case: &str) {
        assert_eq!(answer.0, status, "{}: {:?}", case, answer);
        assert_eq!(body(answer), expected, "{}", case);
    }

    #[track_caller]
    fn assert_invalid_operation(answer: &(Status, String), case: &str) {
        assert_answer(
            answer,
            Status::BadRequest,
            serde_json::json!({ "type": "InvalidOperation" }),
            case,
        );
    }

    #[track_caller]
    fn assert_not_owner(answer: &(Status, String), case: &str) {
        assert_answer(
            answer,
            Status::Forbidden,
            serde_json::json!({ "type": "NotOwner" }),
            case,
        );
    }

    #[track_caller]
    fn assert_feature_disabled(answer: &(Status, String), feature: &str, case: &str) {
        assert_answer(
            answer,
            Status::BadRequest,
            serde_json::json!({ "type": "FeatureDisabled", "feature": feature }),
            case,
        );
    }

    #[track_caller]
    fn assert_failed_validation(answer: &(Status, String), error: &str, case: &str) {
        assert_answer(
            answer,
            Status::BadRequest,
            serde_json::json!({ "type": "FailedValidation", "error": error }),
            case,
        );
    }

    /// The 7.5 seat event for `channel_id`
    fn seats_changed(channel_id: &str) -> impl Fn(&EventV1) -> bool + '_ {
        move |event| {
            matches!(event, EventV1::ProtectedChannelChanged { id, scope }
                if id == channel_id && *scope == vec![PROTECTED_SCOPE_SEATS.to_string()])
        }
    }

    /// A `ChannelUpdate` of `channel_id` carrying `protected_history`
    fn history_update(channel_id: &str) -> impl Fn(&EventV1) -> bool + '_ {
        move |event| {
            matches!(event, EventV1::ChannelUpdate { id, data, .. }
                if id == channel_id && data.protected_history.is_some())
        }
    }

    /// Publish a marker on `user_id`'s private topic and wait for it: the
    /// harness reads every topic through ONE subscription, FIFO, so once it
    /// is seen everything published before it is in the event buffer
    async fn flush_with_marker(harness: &mut TestHarness, user_id: &str) {
        let marker = Ulid::new().to_string();
        EventV1::ChannelAck {
            id: marker.clone(),
            user: user_id.to_string(),
            message_id: marker.clone(),
        }
        .private(user_id.to_string())
        .await;
        harness
            .wait_for_event(&format!("{user_id}!"), |event| match event {
                EventV1::ChannelAck { message_id, .. } => message_id == &marker,
                _ => false,
            })
            .await;
    }

    async fn set_privileged(world: &World, privileged: bool) {
        world
            .harness
            .db
            .update_user(
                &world.owner.id,
                &PartialUser {
                    privileged: Some(privileged),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("the owner's privileged flag");
    }

    async fn set_legal_hold(world: &World) {
        world
            .harness
            .db
            .set_server_legal_hold(&ServerLegalHold {
                id: world.server.id.clone(),
                set_at: Timestamp::now_utc(),
                set_by: Ulid::new().to_string(),
                note: None,
            })
            .await
            .expect("set the hold");
    }

    /// Design 7.2 "History wipe" and 4.3 "S4": the owner's wipe list lands
    /// (the answer is the seat state, the list at version 2), the channel's
    /// wipe is `Requested` by the owner, ONE `ChannelHistoryWipe` entry is
    /// recorded (actor, channel, no count: the design's `count: None`), the
    /// seat event goes to the channel topic and `ChannelUpdate {
    /// protected_history }` to the server topic. The rows stay: the job
    /// deletes them. The byte-identical re-POST is the stored success (N3):
    /// nothing moves, no second entry, no second seat event; the
    /// `ChannelUpdate` is sent again. Controls: the entry removed; the entry
    /// and the seat event on the retry too; each event removed.
    #[test]
    fn the_owner_requests_the_wipe_once() {
        crate::util::test::rt().block_on(Box::pin(async {
            history_on().await;
            the_owner_requests_the_wipe_once_case().await
        }))
    }

    async fn the_owner_requests_the_wipe_once_case() {
        let mut world = Box::pin(world()).await;
        let wipe = world.wipe();
        let channel_id = world.channel.id().to_string();
        let server_id = world.server.id.clone();

        let answer = post(&world.harness, &world.owner_session, &channel_id, &wipe).await;
        let value = assert_ok(&answer, "the wipe");
        assert_eq!(value["list"]["version"], 2, "{}", answer.1);
        assert_eq!(value["list"]["body"], wipe.body.as_str());
        assert_eq!(value["list"]["signature"], wipe.signature.as_str());
        let stored = world.stored().await;
        assert_eq!((stored.version, &stored.body), (2, &wipe.body));

        let history = world.history().await.expect("the protected history");
        assert_eq!(history.boundary, world.boundary);
        match &history.wipe {
            HistoryWipe::Requested { by, .. } => assert_eq!(by, &world.owner.id),
            other => panic!("the wipe is not requested: {:?}", other),
        }

        let entries = wipe_entries(&world.harness, &server_id).await;
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].actor.as_deref(), Some(world.owner.id.as_str()));
        assert_eq!(entries[0].channel.as_deref(), Some(channel_id.as_str()));
        assert_eq!(entries[0].target, None);
        assert!(entries[0].changes.is_empty(), "{:?}", entries[0]);
        assert_eq!(entries[0].count, None);
        assert_eq!(entries[0].reason, None);

        // Published in this order: the seat event, then the update
        world
            .harness
            .wait_for_event(&channel_id, seats_changed(&channel_id))
            .await;
        let update = world
            .harness
            .wait_for_event(&server_id, history_update(&channel_id))
            .await;
        let EventV1::ChannelUpdate { data, clear, .. } = update else {
            unreachable!()
        };
        // Compared as the wire carries them: the event crossed Redis as
        // JSON, where a `Timestamp` keeps milliseconds only
        assert_eq!(
            serde_json::to_value(&data).expect("encode"),
            serde_json::to_value(v0::PartialChannel {
                protected_history: Some(Box::new(history.clone().into())),
                ..Default::default()
            })
            .expect("encode")
        );
        assert!(clear.is_empty());

        // The route deletes nothing
        assert!(world
            .harness
            .db
            .fetch_message(&world.boundary)
            .await
            .is_ok());

        // N3: the same bytes again
        let retry = post(&world.harness, &world.owner_session, &channel_id, &wipe).await;
        let value = assert_ok(&retry, "the identical re-POST");
        assert_eq!(value["list"]["version"], 2, "{}", retry.1);
        assert_eq!(world.stored().await, stored);
        assert_eq!(world.history().await, Some(history));
        assert_eq!(wipe_entries(&world.harness, &server_id).await.len(), 1);
        world
            .harness
            .wait_for_event(&server_id, history_update(&channel_id))
            .await;
        let owner_id = world.owner.id.clone();
        flush_with_marker(&mut world.harness, &owner_id).await;
        world
            .harness
            .assert_no_buffered_event(&channel_id, seats_changed(&channel_id));
    }

    /// 7.2 "History wipe": the hard owner check comes before the list is
    /// read. A member holding ManageMessages, sending their own wipe list,
    /// the owner's list or a list that does not parse, is `NotOwner`; a
    /// privileged (staff) owner is `InvalidOperation` with either list;
    /// nothing is written. Back to an ordinary owner, the wipe lands.
    /// Controls: the owner check replaced by a ManageMessages permission
    /// check; the privileged check removed.
    #[test]
    fn a_caller_who_is_not_the_owner_is_refused() {
        crate::util::test::rt().block_on(Box::pin(async {
            history_on().await;
            a_caller_who_is_not_the_owner_is_refused_case().await
        }))
    }

    async fn a_caller_who_is_not_the_owner_is_refused_case() {
        let world = Box::pin(world()).await;
        let db = &world.harness.db;
        let channel_id = world.channel.id();

        let moderator = world
            .harness
            .new_role(
                &world.server,
                1,
                Some(OverrideField {
                    a: ChannelPermission::ManageMessages as i64,
                    d: 0,
                }),
            )
            .await;
        db.update_member(
            &MemberCompositeKey {
                server: world.server.id.clone(),
                user: world.member.id.clone(),
            },
            &PartialMember {
                roles: Some(vec![moderator.id.clone()]),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("give the moderator role");
        let permissions = require_channel_access(db, &world.member, &world.channel)
            .await
            .expect("the member views the channel");
        assert!(permissions
            .throw_if_lacking_channel_permission(ChannelPermission::ManageMessages)
            .is_ok());

        let member_device = world
            .harness
            .new_e2ee_device(&world.member, &world.member_session.id, MEMBER_DEVICE_SEED)
            .await;
        let own = history_list(
            &member_device,
            channel_id,
            2,
            &[&world.owner.id, &world.member.id],
            Some(&world.boundary),
            SeatListPreHistory::Wiped,
        );
        for (case, data) in [
            ("the member's own list", &own),
            ("the owner's list", &world.wipe()),
            ("a list that does not parse", &garbage(&member_device)),
        ] {
            let answer = post(&world.harness, &world.member_session, channel_id, data).await;
            assert_not_owner(&answer, case);
        }
        world.assert_untouched("a moderator").await;

        set_privileged(&world, true).await;
        for (case, data) in [
            ("privileged owner", world.wipe()),
            ("privileged owner, garbage", garbage(&world.owner_device)),
        ] {
            let answer = post(&world.harness, &world.owner_session, channel_id, &data).await;
            assert_invalid_operation(&answer, case);
        }
        world.assert_untouched("a privileged owner").await;

        set_privileged(&world, false).await;
        world.assert_wipe_lands("the owner").await;
    }

    /// 2.9 and 7.2: while the server has a legal hold the wipe is refused
    /// `InvalidOperation`, before the list is read (a list that does not
    /// parse gets the same answer), and nothing is written; once the hold
    /// is cleared the same list lands. Controls: the hold check removed;
    /// the hold check moved after the list validation.
    #[test]
    fn a_legal_hold_refuses_the_wipe() {
        crate::util::test::rt().block_on(Box::pin(async {
            history_on().await;
            a_legal_hold_refuses_the_wipe_case().await
        }))
    }

    async fn a_legal_hold_refuses_the_wipe_case() {
        let world = Box::pin(world()).await;
        set_legal_hold(&world).await;

        for (case, data) in [
            ("the wipe list", world.wipe()),
            ("a list that does not parse", garbage(&world.owner_device)),
        ] {
            let answer = post(
                &world.harness,
                &world.owner_session,
                world.channel.id(),
                &data,
            )
            .await;
            assert_invalid_operation(&answer, case);
        }
        world.assert_untouched("a legal hold").await;

        world
            .harness
            .db
            .clear_server_legal_hold(&world.server.id)
            .await
            .expect("clear the hold");
        world.assert_wipe_lands("the hold cleared").await;
    }

    /// 7.2: the channel must be protected with a non-empty boundary, else
    /// `InvalidOperation`, before the list is read: an unprotected channel,
    /// a channel protected without a boundary (a v2 genesis with none) and
    /// one whose stored boundary is empty answer it to the owner, for a
    /// list that does not parse too. Nothing is written. Control: the
    /// boundary check removed.
    #[test]
    fn a_channel_without_a_boundary_is_refused() {
        crate::util::test::rt().block_on(Box::pin(async {
            history_on().await;
            a_channel_without_a_boundary_is_refused_case().await
        }))
    }

    async fn a_channel_without_a_boundary_is_refused_case() {
        let world = Box::pin(world()).await;
        let db = &world.harness.db;
        let device = &world.owner_device;
        let owner = world.owner.id.as_str();

        let unprotected = world.harness.new_channel(&world.server).await;

        let bare = world.harness.new_channel(&world.server).await;
        world
            .harness
            .grant_entitlement(&bare, FIXTURE_SLOT_CAP, None)
            .await;
        let genesis = history_list(
            device,
            bare.id(),
            1,
            &[owner],
            None,
            SeatListPreHistory::Kept,
        );
        db.protect_channel(
            bare.id(),
            &SeatListSubmission::from(genesis),
            Timestamp::now_utc(),
        )
        .await
        .expect("protect without a boundary");
        let bare = db.fetch_channel(bare.id()).await.expect("the channel");
        assert!(bare.is_protected());
        assert_eq!(history_of(&bare), None);

        let empty = world.harness.new_channel(&world.server).await;
        world
            .harness
            .grant_entitlement(&empty, FIXTURE_SLOT_CAP, None)
            .await;
        let genesis = history_list(
            device,
            empty.id(),
            1,
            &[owner],
            None,
            SeatListPreHistory::Kept,
        );
        db.protect_channel(
            empty.id(),
            &SeatListSubmission::from(genesis),
            Timestamp::now_utc(),
        )
        .await
        .expect("protect");
        db.update_channel(
            empty.id(),
            &PartialChannel {
                protected_history: Some(Box::new(ProtectedHistory {
                    boundary: String::new(),
                    wipe: HistoryWipe::None,
                })),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("an empty stored boundary");

        for (target, channel) in [
            ("unprotected", &unprotected),
            ("no boundary", &bare),
            ("empty boundary", &empty),
        ] {
            let list = history_list(
                device,
                channel.id(),
                2,
                &[owner],
                Some(&world.boundary),
                SeatListPreHistory::Wiped,
            );
            for (case, data) in [("a wipe list", list), ("garbage", garbage(device))] {
                let answer = post(&world.harness, &world.owner_session, channel.id(), &data).await;
                assert_invalid_operation(&answer, &format!("{target}: {case}"));
            }
            let stored = db.fetch_seat_list(channel.id()).await.expect("read");
            assert!(
                stored.map_or(true, |stored| stored.version == 1),
                "{}: the list",
                target
            );
        }
        assert!(wipe_entries(&world.harness, &world.server.id)
            .await
            .is_empty());
    }

    /// 4.3 steps 1 to 3 at the route, and 4.3 "S4" in the driver: a list
    /// from a device bound to another session (`NotAuthenticated`), a list
    /// signed as another user (`NotOwner`), a bad signature, a list naming
    /// another channel, a handover, a list that changes a seat and a list
    /// that keeps `pre_history` are refused, and nothing is written; the
    /// wipe list then lands. Controls: each route check removed (the
    /// handover, the session binding, the signature, the signer user).
    #[test]
    fn an_invalid_wipe_list_is_refused() {
        crate::util::test::rt().block_on(Box::pin(async {
            history_on().await;
            an_invalid_wipe_list_is_refused_case().await
        }))
    }

    async fn an_invalid_wipe_list_is_refused_case() {
        let world = Box::pin(world()).await;
        let channel_id = world.channel.id();
        let owner = world.owner.id.as_str();
        let boundary = Some(world.boundary.as_str());
        let wiped = SeatListPreHistory::Wiped;

        let unbound = world
            .harness
            .new_e2ee_device(
                &world.owner,
                &Ulid::new().to_string(),
                NEW_OWNER_DEVICE_SEED,
            )
            .await;
        let answer = post(
            &world.harness,
            &world.owner_session,
            channel_id,
            &history_list(&unbound, channel_id, 2, &[owner], boundary, wiped),
        )
        .await;
        assert_answer(
            &answer,
            Status::Unauthorized,
            serde_json::json!({ "type": "NotAuthenticated" }),
            "an unbound device",
        );

        let member_device = world
            .harness
            .new_e2ee_device(&world.member, &world.member_session.id, MEMBER_DEVICE_SEED)
            .await;
        let answer = post(
            &world.harness,
            &world.owner_session,
            channel_id,
            &history_list(
                &member_device,
                channel_id,
                2,
                &[owner, &world.member.id],
                boundary,
                wiped,
            ),
        )
        .await;
        assert_not_owner(&answer, "signed as the member");

        let mut forged = world.wipe();
        forged.signature = world.owner_device.sign("another body");
        let answer = post(&world.harness, &world.owner_session, channel_id, &forged).await;
        assert_failed_validation(&answer, "seat list signature", "a bad signature");

        let other = world.harness.new_channel(&world.server).await;
        let answer = post(
            &world.harness,
            &world.owner_session,
            channel_id,
            &history_list(
                &world.owner_device,
                other.id(),
                2,
                &[owner],
                boundary,
                wiped,
            ),
        )
        .await;
        assert_failed_validation(
            &answer,
            "seat list channel_id does not match the channel",
            "another channel",
        );

        let mut handover = world.wipe();
        handover.handover = Some(world.owner_device.handover_to(channel_id, &member_device));
        let answer = post(&world.harness, &world.owner_session, channel_id, &handover).await;
        assert_failed_validation(
            &answer,
            "the history wipe carries no handover",
            "a handover",
        );

        let answer = post(
            &world.harness,
            &world.owner_session,
            channel_id,
            &history_list(
                &world.owner_device,
                channel_id,
                2,
                &[owner, &world.member.id],
                boundary,
                wiped,
            ),
        )
        .await;
        assert_failed_validation(
            &answer,
            "the history wipe changes only pre_history",
            "a seat added",
        );

        let answer = post(
            &world.harness,
            &world.owner_session,
            channel_id,
            &history_list(
                &world.owner_device,
                channel_id,
                2,
                &[owner],
                boundary,
                SeatListPreHistory::Kept,
            ),
        )
        .await;
        assert_failed_validation(
            &answer,
            "the history wipe must set pre_history wiped",
            "kept",
        );

        world.assert_untouched("invalid lists").await;
        world.assert_wipe_lands("the wipe list").await;
    }

    /// A v1 protected channel given a boundary straight through the driver
    /// (no flag needed), seating the owner and a member who can view it.
    /// The flag tests never reach the list, so it need not be wipeable.
    async fn v1_world() -> World {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let boundary = boundary_id();
        let channel = harness
            .protect_with_history_raw(protected.channel.id(), &boundary, HistoryWipe::None)
            .await;

        World {
            harness,
            server: protected.server,
            channel,
            owner,
            owner_session,
            owner_device: protected.owner_device,
            member,
            member_session,
            boundary,
        }
    }

    /// 7.1 "S4" and 7.6 "S4": with `history_setting` off (the test
    /// configuration's value) the owner is refused `FeatureDisabled {
    /// protected_history }`: after the owner checks (a member is `NotOwner`,
    /// a privileged owner `InvalidOperation`) and before the boundary, the
    /// legal hold and the list (an unprotected channel, a held server and a
    /// list that does not parse get the same answer). Nothing is written.
    /// Controls: the gate removed; the gates moved above the owner check.
    #[test]
    fn history_setting_off_refuses_the_wipe() {
        crate::util::test::rt().block_on(Box::pin(history_setting_off_refuses_the_wipe_case()))
    }

    async fn history_setting_off_refuses_the_wipe_case() {
        assert!(
            !revolt_config::config()
                .await
                .features
                .protected_channels
                .history_setting
        );
        let world = Box::pin(v1_world()).await;
        let harness = &world.harness;
        let channel_id = world.channel.id();
        let device = &world.owner_device;
        let wipe = history_list(
            device,
            channel_id,
            2,
            &[&world.owner.id, &world.member.id],
            Some(&world.boundary),
            SeatListPreHistory::Wiped,
        );

        let answer = post(harness, &world.member_session, channel_id, &wipe).await;
        assert_not_owner(&answer, "the member");

        for (case, data) in [("the wipe list", &wipe), ("garbage", &garbage(device))] {
            let answer = post(harness, &world.owner_session, channel_id, data).await;
            assert_feature_disabled(&answer, "protected_history", case);
        }
        let unprotected = harness.new_channel(&world.server).await;
        let answer = post(
            harness,
            &world.owner_session,
            unprotected.id(),
            &garbage(device),
        )
        .await;
        assert_feature_disabled(&answer, "protected_history", "an unprotected channel");

        set_legal_hold(&world).await;
        let answer = post(harness, &world.owner_session, channel_id, &garbage(device)).await;
        assert_feature_disabled(&answer, "protected_history", "a legal hold");

        set_privileged(&world, true).await;
        let answer = post(harness, &world.owner_session, channel_id, &wipe).await;
        assert_invalid_operation(&answer, "a privileged owner");

        world.assert_untouched("history_setting off").await;
    }

    /// 7.1: with E2EE off the owner is refused `FeatureDisabled { e2ee }`,
    /// the available gate answering before `history_setting` (off too);
    /// a member is still `NotOwner`. Nothing is written. Controls: the
    /// available gate removed; the two gates swapped.
    #[test]
    fn e2ee_off_refuses_the_wipe() {
        crate::util::test::rt().block_on(Box::pin(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            e2ee_off_refuses_the_wipe_case().await
        }))
    }

    async fn e2ee_off_refuses_the_wipe_case() {
        let world = Box::pin(v1_world()).await;
        let harness = &world.harness;
        let channel_id = world.channel.id();
        let device = &world.owner_device;
        let wipe = history_list(
            device,
            channel_id,
            2,
            &[&world.owner.id, &world.member.id],
            Some(&world.boundary),
            SeatListPreHistory::Wiped,
        );

        let answer = post(harness, &world.member_session, channel_id, &wipe).await;
        assert_not_owner(&answer, "the member");
        for (case, data) in [("the wipe list", &wipe), ("garbage", &garbage(device))] {
            let answer = post(harness, &world.owner_session, channel_id, data).await;
            assert_feature_disabled(&answer, "e2ee", case);
        }

        world.assert_untouched("e2ee off").await;
    }

    /// One caller of the decision-18 matrix
    struct Caller {
        class: &'static str,
        session: Session,
    }

    struct Hidden {
        harness: TestHarness,
        /// A member with a bound session, a bot and a member with an
        /// unbound session, all members of the hidden channels' server
        callers: Vec<Caller>,
        /// Owner of the hidden channels, who can view them
        owner_session: Session,
        owner_device: TestE2EEDevice,
        /// Protected with a boundary
        hidden_protected: Channel,
        hidden_unprotected: Channel,
        deleted_id: String,
        missing_id: String,
    }

    async fn deny_view(harness: &TestHarness, channel: &Channel) -> Channel {
        let mut channel = channel.clone();
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
        channel
    }

    async fn hidden() -> Hidden {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, bot_session, bot) = harness.new_user().await;
        let (_, unbound_session, unbound) = harness.new_user().await;

        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[])
            .await;
        harness
            .protect_with_history_raw(protected.channel.id(), &boundary_id(), HistoryWipe::None)
            .await;
        let hidden_protected = deny_view(&harness, &protected.channel).await;
        let hidden_unprotected = harness.new_channel(&protected.server).await;
        let hidden_unprotected = deny_view(&harness, &hidden_unprotected).await;

        for user in [&member, &bot, &unbound] {
            harness.join_server(&protected.server, user).await;
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

        for user in [&member, &bot, &unbound] {
            for channel in [&hidden_protected, &hidden_unprotected] {
                let channel = db.fetch_channel(channel.id()).await.expect("the channel");
                assert!(
                    require_channel_access(db, user, &channel).await.is_err(),
                    "{} views {}",
                    user.id,
                    channel.id()
                );
            }
        }

        let (_, deleted_owner_session, deleted_owner) = harness.new_user().await;
        let deleted = harness
            .new_protected_channel(&deleted_owner, &deleted_owner_session, &[])
            .await;
        db.delete_channel(&deleted.channel)
            .await
            .expect("delete the channel");
        assert!(db.fetch_channel(deleted.channel.id()).await.is_err());

        Hidden {
            callers: vec![
                Caller {
                    class: "member",
                    session: member_session,
                },
                Caller {
                    class: "bot",
                    session: bot_session,
                },
                Caller {
                    class: "unbound",
                    session: unbound_session,
                },
            ],
            owner_session,
            owner_device: protected.owner_device,
            hidden_protected,
            hidden_unprotected,
            deleted_id: deleted.channel.id().to_string(),
            missing_id: Ulid::new().to_string(),
            harness,
        }
    }

    /// Decision 18 (W2), 7.4 refusal placement: for every caller class, a
    /// channel the caller cannot view (protected with a boundary, or not)
    /// and a deleted channel answer EXACTLY as a channel id the server
    /// never held, the full body and status, and that answer is this
    /// route's own 404, for a wipe list and for a list that does not parse.
    /// The hidden channel is real: its owner gets past the access check.
    /// Control: the access check removed.
    async fn non_viewers_answer_as_a_missing_channel() {
        let fixture = Box::pin(hidden()).await;
        let features = revolt_config::config().await.features;
        let device = &fixture.owner_device;
        let list = history_list(
            device,
            fixture.hidden_protected.id(),
            2,
            &[device.user_id.as_str()],
            None,
            SeatListPreHistory::Kept,
        );
        let garbage = garbage(device);

        // The owner passes the access check and meets the next refusal
        let owner = post(
            &fixture.harness,
            &fixture.owner_session,
            fixture.hidden_protected.id(),
            &garbage,
        )
        .await;
        if !features.e2ee_enabled {
            assert_feature_disabled(&owner, "e2ee", "hidden owner");
        } else if !features.protected_channels.history_setting {
            assert_feature_disabled(&owner, "protected_history", "hidden owner");
        } else {
            assert_eq!(owner.0, Status::BadRequest, "hidden owner: {:?}", owner);
            assert_eq!(body(&owner)["type"], "FailedValidation", "{:?}", owner);
        }

        for caller in &fixture.callers {
            for data in [&list, &garbage] {
                let missing =
                    post(&fixture.harness, &caller.session, &fixture.missing_id, data).await;
                assert_answer(
                    &missing,
                    Status::NotFound,
                    serde_json::json!({ "type": "NotFound" }),
                    caller.class,
                );

                for (target, channel_id) in [
                    ("hidden protected", fixture.hidden_protected.id()),
                    ("hidden unprotected", fixture.hidden_unprotected.id()),
                    ("deleted", fixture.deleted_id.as_str()),
                ] {
                    let answer = post(&fixture.harness, &caller.session, channel_id, data).await;
                    assert_eq!(answer, missing, "{} {}", caller.class, target);
                }
            }
        }
    }

    /// `history_setting` on, `formats_v2` left off: the fixture protects
    /// with v1 genesis lists
    #[test]
    fn non_viewers_answer_as_a_missing_channel_with_history_on() {
        crate::util::test::rt().block_on(Box::pin(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.history_setting = true;
            })
            .await;
            non_viewers_answer_as_a_missing_channel().await
        }))
    }

    #[test]
    fn non_viewers_answer_as_a_missing_channel_with_e2ee_off() {
        crate::util::test::rt().block_on(Box::pin(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            non_viewers_answer_as_a_missing_channel().await
        }))
    }
}
