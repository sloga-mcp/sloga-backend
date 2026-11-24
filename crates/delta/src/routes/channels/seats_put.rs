use iso8601_timestamp::Timestamp;
use revolt_database::{
    seat_list_channel_server,
    util::{audit_reason::AuditLogReason, reference::Reference},
    Database, Session, User,
};
use revolt_models::v0;
use revolt_result::{create_error, Error, ErrorType, Result};

use rocket::{serde::json::Json, State};

use super::{
    protected_seat_validation::{after_seat_list_write, validate_seat_list_put},
    seats_fetch::channel_seats_response,
};
use crate::routes::mls::{
    require_channel_access, require_protected_available, require_protected_growth,
};

/// # Publish Seat List
///
/// Publish the next owner-signed seat list of a protected channel. Only the
/// server owner may publish, from the device that signed the list. A list
/// that unseats anyone needs an `X-Audit-Log-Reason`.
#[openapi(tag = "E2EE")]
#[put("/<target>/seats", data = "<data>")]
pub async fn put_seats(
    db: &State<Database>,
    user: User,
    session: Session,
    reason: AuditLogReason,
    target: Reference<'_>,
    data: Json<v0::DataSeatList>,
) -> Result<Json<v0::ResponseChannelSeats>> {
    // Decision 18 (W2): a missing channel and a channel the caller cannot
    // view get the same answer, from one site, before any protected-specific
    // check, so a non-viewer learns nothing about the channel
    let channel = match target.as_channel(db).await {
        Ok(channel) => Some(channel),
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => None,
        Err(error) => return Err(error),
    };
    let channel = match channel {
        Some(channel) if require_channel_access(db, &user, &channel).await.is_ok() => channel,
        _ => return Err(missing_channel()),
    };

    if !channel.is_protected() {
        return Err(create_error!(InvalidOperation));
    }
    let server_id =
        seat_list_channel_server(&channel).ok_or_else(|| create_error!(InvalidOperation))?;
    let server = db.fetch_server(server_id).await?;

    require_protected_available().await?;

    // 4.3 step 4d: the reason header, sanitized (an over-long one is refused
    // here, before anything is written). Whether the list needs one is the
    // planner's call, inside the write, once it knows what the list
    // releases; a retry of a list that landed needs none.
    let reason = reason.validated()?;

    // 4.3 steps 1 to 3, 3b, 4c, 5, 6 and 8; the signer is always seated
    // (4.1), so a privileged (staff) owner is refused at step 5 with
    // `InvalidOperation`
    let validated = validate_seat_list_put(db, &channel, &server, &user, &session, &data).await?;

    // Decisions 4 and 5 (W2): with the growth flag off the driver still
    // answers a byte-identical re-PUT and applies a list that claims nobody
    // (removals, a `device_cap` change); only a claim is refused
    let allow_claims = require_protected_growth().await.is_ok();
    let outcome = db
        .put_seat_list(
            channel.id(),
            &validated.submission,
            allow_claims,
            Timestamp::now_utc(),
            reason.as_deref(),
        )
        .await?;

    // 4.3 "After the claim commits" (S2-D12, 7.5): the access recheck, then
    // the event and the audit entry when the list changed. A failed recheck
    // is answered after them; the list stays written.
    after_seat_list_write(db, &server, &channel, &user, &outcome, reason).await?;

    // The seat state `GET .../seats` serves, as the owner (the validated
    // caller) sees it, after the recheck
    channel_seats_response(db, &channel, &user).await.map(Json)
}

/// The one answer for a missing channel and a channel the caller cannot
/// view: one source site, so the body's `location` never tells them apart
fn missing_channel() -> Error {
    create_error!(NotFound)
}

#[cfg(test)]
mod test {
    //! Run under nextest (one process per test): the flag cases overwrite
    //! the config, which panics on a second call in one process.

    use revolt_database::{
        events::client::EventV1, AuditLogAction, AuditLogEntry, AuditValue, BotInformation,
        Channel, MemberCompositeKey, PartialChannel, PartialMember, PartialUser, RemovalIntention,
        SeatList, SeatReleaseCause, Server, Session, User, PROTECTED_SCOPE_SEATS,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::Value;
    use ulid::Ulid;

    use crate::routes::channels::protected_seat_validation::v2_fixtures::{
        authority, V2List, SALT,
    };
    use crate::routes::mls::require_channel_access;
    use crate::util::test::{
        TestE2EEDevice, TestHarness, FIXTURE_DEVICE_CAP, FIXTURE_SLOT_CAP, MEMBER_DEVICE_SEED,
        NEW_OWNER_DEVICE_SEED, OWNER_DEVICE_SEED,
    };

    /// A protected channel: the owner, a seated member who can view it, a
    /// seated member who lost ViewChannel after being seated, and a server
    /// member who is not seated yet
    struct World {
        harness: TestHarness,
        server: Server,
        channel: Channel,
        owner: User,
        owner_session: Session,
        owner_device: TestE2EEDevice,
        member: User,
        member_session: Session,
        blind: User,
        newcomer: User,
    }

    impl World {
        /// The genesis seats
        fn seated(&self) -> Vec<String> {
            let mut seats = vec![
                self.owner.id.clone(),
                self.member.id.clone(),
                self.blind.id.clone(),
            ];
            seats.sort();
            seats
        }

        /// `seats` signed by the owner device at `version`
        fn list(&self, version: i64, seats: &[&String]) -> v0::DataSeatList {
            self.owner_device
                .seat_list(self.channel.id(), version, FIXTURE_DEVICE_CAP, seats)
        }

        /// Version 2: the genesis seats plus the newcomer (one claim)
        fn growth(&self) -> v0::DataSeatList {
            self.list(
                2,
                &[
                    &self.owner.id,
                    &self.member.id,
                    &self.blind.id,
                    &self.newcomer.id,
                ],
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

        /// Whether `user` holds an active seat
        async fn is_seated(&self, user: &User) -> bool {
            self.harness
                .db
                .fetch_channel_seats(self.channel.id())
                .await
                .expect("read")
                .iter()
                .any(|seat| seat.user_id == user.id && seat.is_active())
        }
    }

    async fn world() -> World {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, _, blind) = harness.new_user().await;
        let (_, _, newcomer) = harness.new_user().await;

        let (server, channel) = harness.new_protectable_channel(&owner).await;
        harness
            .grant_entitlement(&channel, FIXTURE_SLOT_CAP, None)
            .await;
        let owner_device = harness
            .new_e2ee_device(&owner, &owner_session.id, OWNER_DEVICE_SEED)
            .await;
        for user in [&member, &blind, &newcomer] {
            harness.join_server(&server, user).await;
        }
        let genesis = owner_device.protect_request(
            channel.id(),
            FIXTURE_DEVICE_CAP,
            &[&owner.id, &member.id, &blind.id],
        );
        harness.protect_with_db(&channel, &genesis).await;

        // The blind member loses ViewChannel after being seated (6.4)
        let blind_role = harness
            .new_role(
                &server,
                1,
                Some(OverrideField {
                    a: 0,
                    d: ChannelPermission::ViewChannel as i64,
                }),
            )
            .await;
        db.update_member(
            &MemberCompositeKey {
                server: server.id.clone(),
                user: blind.id.clone(),
            },
            &PartialMember {
                roles: Some(vec![blind_role.id.clone()]),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("give the blind role");

        let server = db.fetch_server(&server.id).await.expect("the server");
        let channel = db.fetch_channel(channel.id()).await.expect("the channel");
        assert!(channel.is_protected());
        assert!(require_channel_access(db, &member, &channel).await.is_ok());
        assert!(require_channel_access(db, &newcomer, &channel)
            .await
            .is_ok());
        assert!(require_channel_access(db, &blind, &channel).await.is_err());

        World {
            harness,
            server,
            channel,
            owner,
            owner_session,
            owner_device,
            member,
            member_session,
            blind,
            newcomer,
        }
    }

    /// The route's full answer: status and body (no `X-Audit-Log-Reason`)
    async fn put(
        harness: &TestHarness,
        session: &Session,
        channel_id: &str,
        data: &v0::DataSeatList,
    ) -> (Status, String) {
        put_with_reason(harness, session, channel_id, data, None).await
    }

    /// [`put`] with `reason` as the `X-Audit-Log-Reason` header (4.3 step
    /// 4d), when given
    async fn put_with_reason(
        harness: &TestHarness,
        session: &Session,
        channel_id: &str,
        data: &v0::DataSeatList,
        reason: Option<&str>,
    ) -> (Status, String) {
        let mut request = harness
            .client
            .put(format!("/channels/{channel_id}/seats"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.clone()))
            .body(serde_json::to_string(data).expect("JSON"));
        if let Some(reason) = reason {
            request = request.header(Header::new("X-Audit-Log-Reason", reason.to_string()));
        }
        let response = request.dispatch().await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    /// Every `ProtectedSeatsUpdate` entry of `server_id`, newest first
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

    /// `(key, new)` of each change of an audit entry, in order
    fn changes_of(entry: &AuditLogEntry) -> Vec<(String, Option<AuditValue>)> {
        entry
            .changes
            .iter()
            .map(|change| (change.key.clone(), change.new.clone()))
            .collect()
    }

    fn ids(users: &[&User]) -> Vec<String> {
        let mut ids: Vec<String> = users.iter().map(|user| user.id.clone()).collect();
        ids.sort();
        ids
    }

    /// The 7.5 seat event for `channel_id`
    fn seats_changed(channel_id: &str) -> impl Fn(&EventV1) -> bool + '_ {
        move |event| {
            matches!(event, EventV1::ProtectedChannelChanged { id, scope }
                if id == channel_id && *scope == vec![PROTECTED_SCOPE_SEATS.to_string()])
        }
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
    fn assert_error(answer: &(Status, String), expected: &str, case: &str) -> Value {
        let value = body(answer);
        assert_eq!(value["type"], expected, "{}: {:?}", case, answer);
        value
    }

    #[track_caller]
    fn assert_feature_disabled(answer: &(Status, String), feature: &str, case: &str) {
        assert_eq!(answer.0, Status::BadRequest, "{}: {:?}", case, answer);
        let value = assert_error(answer, "FeatureDisabled", case);
        assert_eq!(value["feature"], feature, "{}: {}", case, answer.1);
    }

    /// `(user_id, seated_without_access)` of every active seat, sorted
    fn seats_of(value: &Value) -> Vec<(String, Value)> {
        let mut seats: Vec<(String, Value)> = value["seats"]
            .as_array()
            .expect("seats")
            .iter()
            .map(|seat| {
                (
                    seat["user_id"].as_str().expect("user_id").to_string(),
                    seat["seated_without_access"].clone(),
                )
            })
            .collect();
        seats.sort_by(|a, b| a.0.cmp(&b.0));
        seats
    }

    fn cooling_of(value: &Value) -> Vec<String> {
        let mut cooling: Vec<String> = value["cooling"]
            .as_array()
            .expect("cooling")
            .iter()
            .map(|seat| seat["user_id"].as_str().expect("user_id").to_string())
            .collect();
        cooling.sort();
        cooling
    }

    /// Publish a marker on `user_id`'s private topic and wait for it. The
    /// harness reads every topic through ONE subscription and redis pub/sub
    /// is FIFO on it, and the route awaits any publish before it answers, so
    /// once the marker is seen everything the route published is in the
    /// event buffer, where `assert_no_buffered_event` sees it
    async fn flush_with_marker(harness: &mut TestHarness, user_id: &str) -> String {
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
        marker
    }

    /// Design 4.3 and 7.2: the owner's next list (version + 1) lands: the
    /// newcomer is claimed and the answer is the new seat state, with
    /// `seated_without_access` on every seat (the caller is the owner).
    ///
    /// S2-D12 (4.3 "After the claim commits"; 6.4 replaced by the
    /// reconciler): the route then rechecks access with fresh reads, so the
    /// blind member, seated before losing ViewChannel, is released as
    /// `AccessLost` (and cools: they had received the keys) and the answer
    /// already shows it. Before S2 that seat stayed, shown as
    /// `seated_without_access: true`; this test asserted that and is changed
    /// for that reason. Control: the `reconcile_channel` call removed from
    /// `after_seat_list_write`.
    #[test]
    fn the_owner_publishes_the_next_list() {
        crate::util::test::rt().block_on(Box::pin(the_owner_publishes_the_next_list_case()))
    }

    async fn the_owner_publishes_the_next_list_case() {
        let world = Box::pin(world()).await;
        let next = world.growth();
        assert!(!world.is_seated(&world.newcomer).await);
        world
            .harness
            .mark_keys_received(world.channel.id(), &world.blind.id)
            .await;

        let answer = put(
            &world.harness,
            &world.owner_session,
            world.channel.id(),
            &next,
        )
        .await;
        let value = assert_ok(&answer, "next list");

        assert_eq!(value["list"]["version"], 2, "{}", answer.1);
        assert_eq!(value["list"]["body"], next.body.as_str());
        assert_eq!(value["list"]["signature"], next.signature.as_str());
        assert_eq!(value["list"]["signer_user_id"], world.owner.id.as_str());
        assert_eq!(
            value["list"]["signer_device_id"],
            next.signer_device_id.as_str()
        );
        let mut expected = vec![
            (world.owner.id.clone(), Value::Bool(false)),
            (world.member.id.clone(), Value::Bool(false)),
            (world.newcomer.id.clone(), Value::Bool(false)),
        ];
        expected.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(seats_of(&value), expected, "{}", answer.1);
        assert_eq!(
            cooling_of(&value),
            vec![world.blind.id.clone()],
            "{}",
            answer.1
        );
        assert_eq!(value["seats_used"], 4, "{}", answer.1);
        assert_eq!(value["slot_cap"], FIXTURE_SLOT_CAP, "{}", answer.1);
        assert_eq!(value["entitlement_device_cap"], 5, "{}", answer.1);
        assert_eq!(value["device_cap"], FIXTURE_DEVICE_CAP, "{}", answer.1);
        assert_eq!(value["as_of_epoch"], Value::Null, "{}", answer.1);
        assert_eq!(value["as_of_group_id"], Value::Null, "{}", answer.1);

        let stored = world.stored().await;
        assert_eq!(stored.version, 2);
        assert_eq!(stored.body, next.body);
        assert!(world.is_seated(&world.newcomer).await);

        // The reconciler released the blind seat, not the list (which still
        // names them): cause `AccessLost`, its own audit entry
        let blind = world
            .harness
            .db
            .fetch_channel_seats(world.channel.id())
            .await
            .expect("read")
            .into_iter()
            .find(|seat| seat.user_id == world.blind.id)
            .expect("the blind seat row");
        assert!(!blind.is_active(), "{blind:?}");
        assert_eq!(
            blind.release_cause,
            Some(SeatReleaseCause::AccessLost),
            "{blind:?}"
        );
        let releases = world
            .harness
            .db
            .fetch_audit_log(
                &world.server.id,
                None,
                50,
                Some(AuditLogAction::ProtectedSeatRelease),
                None,
            )
            .await
            .expect("the audit log");
        assert_eq!(releases.len(), 1, "{releases:?}");
        assert_eq!(releases[0].target.as_deref(), Some(world.blind.id.as_str()));
    }

    /// 4.3 "After the claim commits" and 7.5 (S2-D18): a list that changed
    /// publishes `ProtectedChannelChanged { scope: ["seats"] }` on the
    /// CHANNEL topic and records one `ProtectedSeatsUpdate` per write: the
    /// owner, the channel, who was released and seated, and the reason. A
    /// fixture where everyone keeps access, so the reconciler announces
    /// nothing itself. Before S2 a seat PUT published no event (S1 7.5);
    /// S2 replaced that rule. Controls: the event removed; the entry removed.
    #[test]
    fn a_changed_list_is_announced_and_audited() {
        crate::util::test::rt().block_on(Box::pin(a_changed_list_is_announced_and_audited_case()))
    }

    async fn a_changed_list_is_announced_and_audited_case() {
        let mut harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, _, member) = harness.new_user().await;
        let (_, _, newcomer) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        harness.join_server(&protected.server, &newcomer).await;
        let channel_id = protected.channel.id().to_string();
        let server_id = protected.server.id.clone();
        let device = &protected.owner_device;

        let growth = device.seat_list(
            &channel_id,
            2,
            FIXTURE_DEVICE_CAP,
            &[&owner.id, &member.id, &newcomer.id],
        );
        let answer = put(&harness, &owner_session, &channel_id, &growth).await;
        assert_ok(&answer, "growth");
        harness
            .wait_for_event(&channel_id, seats_changed(&channel_id))
            .await;

        let unseat = device.seat_list(
            &channel_id,
            3,
            FIXTURE_DEVICE_CAP,
            &[&owner.id, &newcomer.id],
        );
        let answer = put_with_reason(
            &harness,
            &owner_session,
            &channel_id,
            &unseat,
            Some("left the team"),
        )
        .await;
        assert_ok(&answer, "unseat");

        let entries = seats_updates(&harness, &server_id).await;
        assert_eq!(entries.len(), 2, "{entries:?}");
        for entry in &entries {
            assert_eq!(entry.actor.as_deref(), Some(owner.id.as_str()));
            assert_eq!(entry.channel.as_deref(), Some(channel_id.as_str()));
            assert_eq!(entry.target, None);
        }
        // Two writes may share a millisecond, so the ids do not order them:
        // each entry is told apart by its reason
        let unseated = entries
            .iter()
            .find(|entry| entry.reason.as_deref() == Some("left the team"))
            .expect("the unseat entry, with its reason");
        assert_eq!(
            changes_of(unseated),
            vec![
                (
                    "released".to_string(),
                    Some(AuditValue::StringList(ids(&[&member])))
                ),
                ("seated".to_string(), Some(AuditValue::StringList(vec![]))),
            ]
        );
        let grown = entries
            .iter()
            .find(|entry| entry.reason.is_none())
            .expect("the growth entry, sent without a reason");
        assert_eq!(
            changes_of(grown),
            vec![
                ("released".to_string(), Some(AuditValue::StringList(vec![]))),
                (
                    "seated".to_string(),
                    Some(AuditValue::StringList(ids(&[&newcomer])))
                ),
            ]
        );
    }

    /// 4.3 "After the claim commits": the byte-identical retry of a list
    /// that landed (here through the database, which announces nothing) is
    /// answered with no `ProtectedChannelChanged` and no
    /// `ProtectedSeatsUpdate`. Control: the event and the entry emitted on
    /// `unchanged` too.
    #[test]
    fn an_unchanged_retry_is_neither_announced_nor_audited() {
        crate::util::test::rt().block_on(Box::pin(
            an_unchanged_retry_is_neither_announced_nor_audited_case(),
        ))
    }

    async fn an_unchanged_retry_is_neither_announced_nor_audited_case() {
        let mut harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, _, member) = harness.new_user().await;
        let (_, _, newcomer) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        harness.join_server(&protected.server, &newcomer).await;
        let channel_id = protected.channel.id().to_string();
        let growth = protected.owner_device.seat_list(
            &channel_id,
            2,
            FIXTURE_DEVICE_CAP,
            &[&owner.id, &member.id, &newcomer.id],
        );
        harness.put_seats_with_db(&protected.channel, &growth).await;

        let answer = put(&harness, &owner_session, &channel_id, &growth).await;
        let value = assert_ok(&answer, "identical retry");
        assert_eq!(value["list"]["version"], 2, "{}", answer.1);

        let owner_id = owner.id.clone();
        flush_with_marker(&mut harness, &owner_id).await;
        harness.assert_no_buffered_event(&channel_id, |event| {
            matches!(event, EventV1::ProtectedChannelChanged { .. })
        });
        let entries = seats_updates(&harness, &protected.server.id).await;
        assert!(entries.is_empty(), "{entries:?}");
    }

    /// 4.3 step 4d (S2-D20): a list that unseats the member is refused 400
    /// `RemovalReasonRequired` without the header and with a blank one,
    /// writing nothing; it lands with a reason; the byte-identical retry of
    /// the landed list without the header is the stored success. Controls:
    /// the planner's reason check removed; the check moved after the write.
    #[test]
    fn a_releasing_put_needs_a_reason() {
        crate::util::test::rt().block_on(Box::pin(a_releasing_put_needs_a_reason_case()))
    }

    /// The stored list version, and whether `user_id` holds an active seat
    async fn list_state(harness: &TestHarness, channel_id: &str, user_id: &str) -> (i64, bool) {
        let version = harness
            .db
            .fetch_seat_list(channel_id)
            .await
            .expect("read")
            .expect("a stored list")
            .version;
        let seated = harness
            .db
            .fetch_channel_seats(channel_id)
            .await
            .expect("read")
            .iter()
            .any(|seat| seat.user_id == user_id && seat.is_active());
        (version, seated)
    }

    async fn a_releasing_put_needs_a_reason_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, _, member) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let channel_id = protected.channel.id().to_string();
        let unseat =
            protected
                .owner_device
                .seat_list(&channel_id, 2, FIXTURE_DEVICE_CAP, &[&owner.id]);

        for reason in [None, Some("   ")] {
            let answer =
                put_with_reason(&harness, &owner_session, &channel_id, &unseat, reason).await;
            assert_eq!(answer.0, Status::BadRequest, "{reason:?}: {answer:?}");
            assert_eq!(
                body(&answer),
                serde_json::json!({ "type": "RemovalReasonRequired" }),
                "{reason:?}"
            );
            assert_eq!(
                list_state(&harness, &channel_id, &member.id).await,
                (1, true),
                "{reason:?}: nothing written"
            );
        }

        let answer = put_with_reason(
            &harness,
            &owner_session,
            &channel_id,
            &unseat,
            Some("left the team"),
        )
        .await;
        assert_ok(&answer, "with a reason");
        assert_eq!(
            list_state(&harness, &channel_id, &member.id).await,
            (2, false)
        );

        let retry = put(&harness, &owner_session, &channel_id, &unseat).await;
        let value = assert_ok(&retry, "retry without the header");
        assert_eq!(value["list"]["version"], 2, "{}", retry.1);
    }

    async fn formats_v2_on() {
        revolt_config::overwrite_config(|settings| {
            settings.features.protected_channels.formats_v2 = true;
        })
        .await;
    }

    /// A v2 protected channel (`formats_v2` on): the owner's device signed
    /// the genesis list (owner and member) and its authority `first`, which
    /// lists the owner device and a second owner device (both bound to the
    /// owner's session); a newcomer has joined
    struct V2World {
        harness: TestHarness,
        channel: Channel,
        owner: User,
        owner_session: Session,
        owner_device: TestE2EEDevice,
        second_device: TestE2EEDevice,
        member: User,
        newcomer: User,
        first: v0::SignedAuthority,
    }

    async fn v2_world() -> V2World {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, _, member) = harness.new_user().await;
        let (_, _, newcomer) = harness.new_user().await;
        let (server, channel) = harness.new_protectable_channel(&owner).await;
        harness
            .grant_entitlement(&channel, FIXTURE_SLOT_CAP, None)
            .await;
        let owner_device = harness
            .new_e2ee_device(&owner, &owner_session.id, OWNER_DEVICE_SEED)
            .await;
        let second_device = harness
            .new_e2ee_device(&owner, &owner_session.id, NEW_OWNER_DEVICE_SEED)
            .await;
        for user in [&member, &newcomer] {
            harness.join_server(&server, user).await;
        }

        let first = authority(
            channel.id(),
            &owner.id,
            &owner_device.device_id,
            &[
                (owner_device.device_id.as_str(), &owner_device.signing_key),
                (second_device.device_id.as_str(), &second_device.signing_key),
            ],
            None,
            &owner_device.signing_key,
        );
        let genesis = V2List {
            channel_id: channel.id(),
            version: 1,
            signer_user_id: &owner.id,
            signer_device_id: &owner_device.device_id,
            key: &owner_device.signing_key,
            seats: &[owner.id.as_str(), member.id.as_str()],
            salt: SALT,
            authority: &first,
        }
        .signed();
        harness
            .protect_with_db(&channel, &v0::DataProtectChannel { seat_list: genesis })
            .await;
        let channel = harness
            .db
            .fetch_channel(channel.id())
            .await
            .expect("the channel");

        V2World {
            harness,
            channel,
            owner,
            owner_session,
            owner_device,
            second_device,
            member,
            newcomer,
            first,
        }
    }

    impl V2World {
        /// Version 2 (the genesis seats plus the newcomer) signed by
        /// `device`, carrying `authority`
        fn growth(
            &self,
            device: &TestE2EEDevice,
            authority: &v0::SignedAuthority,
        ) -> v0::DataSeatList {
            V2List {
                channel_id: self.channel.id(),
                version: 2,
                signer_user_id: &self.owner.id,
                signer_device_id: &device.device_id,
                key: &device.signing_key,
                seats: &[
                    self.owner.id.as_str(),
                    self.member.id.as_str(),
                    self.newcomer.id.as_str(),
                ],
                salt: SALT,
                authority,
            }
            .signed()
        }

        async fn stored(&self) -> SeatList {
            self.harness
                .db
                .fetch_seat_list(self.channel.id())
                .await
                .expect("read")
                .expect("a stored list")
        }
    }

    /// 🔴 4.3 step 3b, route side (BLOCKER for `formats_v2`): the owner
    /// device's next list carries a CHANGED authority (version 2) that is
    /// forged: (a) it lists the owner device under a key that is not its
    /// directory key and is signed with that key, so it verifies under the
    /// key it names; (b) it names the directory key but another key signed
    /// it; (c) it names another key but the directory key signed it. Each
    /// is refused `FailedValidation` and NOTHING is persisted (the list,
    /// the authority, the claim). The honest change lands. Controls: the
    /// directory-key compare removed ((c) lands); the signature check
    /// removed ((b) lands).
    #[test]
    fn a_forged_authority_change_is_refused_and_nothing_is_written() {
        crate::util::test::rt().block_on(Box::pin(async {
            formats_v2_on().await;
            a_forged_authority_change_is_refused_and_nothing_is_written_case().await
        }))
    }

    async fn a_forged_authority_change_is_refused_and_nothing_is_written_case() {
        let world = Box::pin(v2_world()).await;
        let owner_device = &world.owner_device;
        let foreign = TestE2EEDevice::signing_key_for(MEMBER_DEVICE_SEED);
        let change = |listed: &ed25519_dalek::SigningKey, signing: &ed25519_dalek::SigningKey| {
            authority(
                world.channel.id(),
                &world.owner.id,
                &owner_device.device_id,
                &[
                    (owner_device.device_id.as_str(), listed),
                    (
                        world.second_device.device_id.as_str(),
                        &world.second_device.signing_key,
                    ),
                ],
                Some(&world.first),
                signing,
            )
        };
        let before = world.stored().await;

        for (case, message, forged) in [
            (
                "(a) another key, signed by it",
                "authority signer key is not the signer device key",
                change(&foreign, &foreign),
            ),
            (
                "(b) the directory key, signed by another",
                "authority signature",
                change(&owner_device.signing_key, &foreign),
            ),
            (
                "(c) another key, signed by the directory key",
                "authority signer key is not the signer device key",
                change(&foreign, &owner_device.signing_key),
            ),
        ] {
            let answer = put(
                &world.harness,
                &world.owner_session,
                world.channel.id(),
                &world.growth(owner_device, &forged),
            )
            .await;
            assert_eq!(answer.0, Status::BadRequest, "{case}: {answer:?}");
            assert_eq!(
                body(&answer),
                serde_json::json!({ "type": "FailedValidation", "error": message }),
                "{case}"
            );
            assert_eq!(world.stored().await, before, "{case}: nothing written");
            assert!(
                !world
                    .harness
                    .db
                    .fetch_channel_seats(world.channel.id())
                    .await
                    .expect("read")
                    .iter()
                    .any(|seat| seat.user_id == world.newcomer.id),
                "{case}: nothing claimed"
            );
        }

        let honest = change(&owner_device.signing_key, &owner_device.signing_key);
        let answer = put(
            &world.harness,
            &world.owner_session,
            world.channel.id(),
            &world.growth(owner_device, &honest),
        )
        .await;
        assert_ok(&answer, "the honest change");
        let stored = world.stored().await;
        assert_eq!(stored.version, 2);
        let stored_authority = stored.authority.expect("the stored authority");
        assert_eq!(stored_authority.body, honest.body);
        assert_eq!(stored_authority.signature, honest.signature);
    }

    /// 4.3 step 3b (#225; 4.4.1 rule 6): the second owner device publishes
    /// the next list carrying the stored authority UNCHANGED, still signed
    /// by the owner device: it is no change, is not verified again, and
    /// lands. Control: an unchanged authority re-verified under the PUT
    /// signer's key (refused as "authority signature").
    #[test]
    fn an_unchanged_authority_from_another_owner_device_is_accepted() {
        crate::util::test::rt().block_on(Box::pin(async {
            formats_v2_on().await;
            an_unchanged_authority_from_another_owner_device_is_accepted_case().await
        }))
    }

    async fn an_unchanged_authority_from_another_owner_device_is_accepted_case() {
        let world = Box::pin(v2_world()).await;
        let next = world.growth(&world.second_device, &world.first);

        let answer = put(
            &world.harness,
            &world.owner_session,
            world.channel.id(),
            &next,
        )
        .await;
        assert_ok(&answer, "the stored authority from the second device");
        let stored = world.stored().await;
        assert_eq!(stored.version, 2);
        assert_eq!(stored.signer_device_id, world.second_device.device_id);
        let stored_authority = stored.authority.expect("the stored authority");
        assert_eq!(stored_authority.body, world.first.body);
        assert_eq!(stored_authority.signature, world.first.signature);
    }

    /// Design 4.3 step 4 (W0-fix8) and 4.9: a byte-identical re-PUT after a
    /// listed member left (so step 5 would now refuse the list) is the
    /// stored success: 200, nothing written
    #[test]
    fn an_identical_re_put_after_a_member_left_is_unchanged() {
        crate::util::test::rt().block_on(Box::pin(
            an_identical_re_put_after_a_member_left_is_unchanged_case(),
        ))
    }

    async fn an_identical_re_put_after_a_member_left_is_unchanged_case() {
        let world = Box::pin(world()).await;
        let db = &world.harness.db;
        let next = world.growth();
        let first = put(
            &world.harness,
            &world.owner_session,
            world.channel.id(),
            &next,
        )
        .await;
        assert_ok(&first, "first PUT");
        // The member had received the keys, so the leave cools the seat
        world
            .harness
            .mark_keys_received(world.channel.id(), &world.member.id)
            .await;

        let member = db
            .fetch_member(&world.server.id, &world.member.id)
            .await
            .expect("the member");
        member
            .remove(db, &world.server, RemovalIntention::Leave, true)
            .await
            .expect("the member leaves");
        assert!(db
            .fetch_member(&world.server.id, &world.member.id)
            .await
            .is_err());
        let before = world.stored().await;

        let retry = put(
            &world.harness,
            &world.owner_session,
            world.channel.id(),
            &next,
        )
        .await;
        let value = assert_ok(&retry, "identical re-PUT");
        assert_eq!(value["list"]["version"], 2, "{}", retry.1);
        assert_eq!(value["list"]["body"], next.body.as_str());
        assert_eq!(world.stored().await, before);
        // The leave released the seat; the retry did not seat them again
        assert!(!world.is_seated(&world.member).await);
        assert!(cooling_of(&value).contains(&world.member.id), "{}", retry.1);
    }

    /// Decision 4 (W2): the byte-identical re-PUT runs before the growth
    /// flag, so it succeeds with the flag off
    #[test]
    fn an_identical_re_put_with_growth_off_is_unchanged() {
        crate::util::test::rt().block_on(Box::pin(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            an_identical_re_put_with_growth_off_is_unchanged_case().await
        }))
    }

    async fn an_identical_re_put_with_growth_off_is_unchanged_case() {
        let world = Box::pin(world()).await;
        let next = world.growth();
        // It landed while the flag was on
        world.harness.put_seats_with_db(&world.channel, &next).await;
        let before = world.stored().await;

        let retry = put(
            &world.harness,
            &world.owner_session,
            world.channel.id(),
            &next,
        )
        .await;
        let value = assert_ok(&retry, "identical re-PUT, growth off");
        assert_eq!(value["list"]["version"], 2, "{}", retry.1);
        assert_eq!(value["list"]["body"], next.body.as_str());
        assert_eq!(world.stored().await, before);
    }

    /// Decision 5 (W2): with the growth flag off a list that only removes
    /// seats is applied; the removed seat (its user had received the keys)
    /// starts cooling. It carries the reason S2 step 4d requires of a list
    /// that releases anyone (`a_releasing_put_needs_a_reason`).
    #[test]
    fn a_removal_only_put_with_growth_off_lands() {
        crate::util::test::rt().block_on(Box::pin(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            a_removal_only_put_with_growth_off_lands_case().await
        }))
    }

    async fn a_removal_only_put_with_growth_off_lands_case() {
        let world = Box::pin(world()).await;
        let next = world.list(2, &[&world.owner.id, &world.member.id]);
        world
            .harness
            .mark_keys_received(world.channel.id(), &world.blind.id)
            .await;

        let answer = put_with_reason(
            &world.harness,
            &world.owner_session,
            world.channel.id(),
            &next,
            Some("unseat"),
        )
        .await;
        let value = assert_ok(&answer, "removal only, growth off");
        assert_eq!(value["list"]["version"], 2, "{}", answer.1);
        assert_eq!(cooling_of(&value), vec![world.blind.id.clone()]);
        // The cooling seat still counts against the slot cap
        assert_eq!(value["seats_used"], 3, "{}", answer.1);
        assert_eq!(world.stored().await.version, 2);
        assert!(!world.is_seated(&world.blind).await);
    }

    /// 2.3 (S2-D21): the owner unseating a user who never received the keys
    /// frees the slot at once: released as `DeviceNeverJoined` with no
    /// cooldown, so not listed as cooling and not counted. With the reason
    /// step 4d requires.
    #[test]
    fn unseating_a_never_joined_user_frees_the_slot_at_once() {
        crate::util::test::rt().block_on(Box::pin(
            unseating_a_never_joined_user_frees_the_slot_at_once_case(),
        ))
    }

    async fn unseating_a_never_joined_user_frees_the_slot_at_once_case() {
        let world = Box::pin(world()).await;
        let next = world.list(2, &[&world.owner.id, &world.member.id]);

        let answer = put_with_reason(
            &world.harness,
            &world.owner_session,
            world.channel.id(),
            &next,
            Some("unseat"),
        )
        .await;
        let value = assert_ok(&answer, "removal of a never-joined user");
        assert_eq!(value["list"]["version"], 2, "{}", answer.1);
        assert!(cooling_of(&value).is_empty(), "{}", answer.1);
        assert_eq!(value["seats_used"], 2, "{}", answer.1);
        let seat = world
            .harness
            .db
            .fetch_channel_seats(world.channel.id())
            .await
            .expect("read")
            .into_iter()
            .find(|seat| seat.user_id == world.blind.id)
            .expect("the seat row is kept");
        assert!(!seat.is_active(), "{seat:?}");
        assert_eq!(
            seat.release_cause,
            Some(SeatReleaseCause::DeviceNeverJoined),
            "{seat:?}"
        );
        assert_eq!(seat.cooldown_until, None, "{seat:?}");
    }

    /// Decision 5 (W2): with the growth flag off a list that claims a seat
    /// is refused with `FeatureDisabled { protected_channels }` and nothing
    /// is written. Control: `allow_claims` hard-coded to `true`.
    #[test]
    fn a_claim_with_growth_off_is_refused() {
        crate::util::test::rt().block_on(Box::pin(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            a_claim_with_growth_off_is_refused_case().await
        }))
    }

    async fn a_claim_with_growth_off_is_refused_case() {
        let world = Box::pin(world()).await;
        let next = world.growth();

        let answer = put(
            &world.harness,
            &world.owner_session,
            world.channel.id(),
            &next,
        )
        .await;
        assert_feature_disabled(&answer, "protected_channels", "claim, growth off");
        assert_eq!(world.stored().await.version, 1);
        assert!(!world.is_seated(&world.newcomer).await);
    }

    /// C1 (W2 audit; decision 2, confirmed by the user 2026-10-04: a removed
    /// or re-invited member is not re-seated until the owner re-seats them).
    /// The member is kicked (the real `Member::remove`) and rejoins by
    /// invite; the blind member LEAVES of their own accord and does not come
    /// back. The owner's client still lists both, so its next list (adding
    /// the newcomer) is refused 400 `SeatListNamesRemovedUsers` with both ids
    /// and nothing is written: the rejoined member is answered by the driver
    /// as well, the one who has not rejoined by the validator ahead of its
    /// membership rule (else a bare `FailedValidation`). The list without
    /// them lands; a later list naming the member again seats them, as an
    /// ordinary claim. Control: the check removed from the validator and the
    /// planner (the first list lands and seats the kicked member again).
    #[test]
    fn a_list_still_naming_a_removed_member_is_refused() {
        crate::util::test::rt().block_on(Box::pin(
            a_list_still_naming_a_removed_member_is_refused_case(),
        ))
    }

    async fn a_list_still_naming_a_removed_member_is_refused_case() {
        let world = Box::pin(world()).await;
        let db = &world.harness.db;

        db.fetch_member(&world.server.id, &world.member.id)
            .await
            .expect("the member")
            .remove(db, &world.server, RemovalIntention::Kick, true)
            .await
            .expect("the kick");
        world
            .harness
            .join_server(&world.server, &world.member)
            .await;
        db.fetch_member(&world.server.id, &world.blind.id)
            .await
            .expect("the blind member")
            .remove(db, &world.server, RemovalIntention::Leave, true)
            .await
            .expect("the leave");
        assert!(db
            .fetch_member(&world.server.id, &world.member.id)
            .await
            .is_ok());
        assert!(db
            .fetch_member(&world.server.id, &world.blind.id)
            .await
            .is_err());

        let stale = world.growth();
        let answer = put(
            &world.harness,
            &world.owner_session,
            world.channel.id(),
            &stale,
        )
        .await;
        assert_eq!(answer.0, Status::BadRequest, "{:?}", answer);
        let mut removed = vec![world.member.id.clone(), world.blind.id.clone()];
        removed.sort();
        assert_eq!(
            body(&answer),
            serde_json::json!({ "type": "SeatListNamesRemovedUsers", "users": removed }),
            "{:?}",
            answer
        );
        assert_eq!(world.stored().await.version, 1);
        assert!(!world.is_seated(&world.newcomer).await);
        assert!(!world.is_seated(&world.member).await);

        // The rejoined member alone, through the driver as well
        let rejoined = world.list(2, &[&world.owner.id, &world.member.id, &world.newcomer.id]);
        let answer = put(
            &world.harness,
            &world.owner_session,
            world.channel.id(),
            &rejoined,
        )
        .await;
        let value = assert_error(&answer, "SeatListNamesRemovedUsers", "rejoined member");
        assert_eq!(value["users"], serde_json::json!([world.member.id]));
        assert!(!world.is_seated(&world.member).await);

        // The list without them lands
        let without = world.list(2, &[&world.owner.id, &world.newcomer.id]);
        let answer = put(
            &world.harness,
            &world.owner_session,
            world.channel.id(),
            &without,
        )
        .await;
        assert_ok(&answer, "list without the removed members");
        assert!(world.is_seated(&world.newcomer).await);

        // Then the rejoined member is seated again as an ordinary claim
        let again = world.list(3, &[&world.owner.id, &world.member.id, &world.newcomer.id]);
        let answer = put(
            &world.harness,
            &world.owner_session,
            world.channel.id(),
            &again,
        )
        .await;
        assert_ok(&answer, "re-seat after a list without them");
        assert!(world.is_seated(&world.member).await);
    }

    /// Design 7.1: with E2EE off the seat PUT is refused for the owner too,
    /// before the list is looked at
    #[test]
    fn e2ee_off_refuses_the_owner() {
        crate::util::test::rt().block_on(Box::pin(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            e2ee_off_refuses_the_owner_case().await
        }))
    }

    async fn e2ee_off_refuses_the_owner_case() {
        let world = Box::pin(world()).await;
        let mut garbage = world.growth();
        garbage.body = "garbage".to_string();

        for (case, data) in [("valid", world.growth()), ("garbage", garbage)] {
            let answer = put(
                &world.harness,
                &world.owner_session,
                world.channel.id(),
                &data,
            )
            .await;
            assert_feature_disabled(&answer, "e2ee", case);
        }
        assert_eq!(world.stored().await.version, 1);
    }

    /// Design 4.3 steps 2 and 3, 7.2: a caller who is not the owner, a list
    /// signed as another user, a device bound to another session, a bad
    /// signature, a privileged (staff) owner and an unprotected channel are
    /// all refused, and nothing is written
    #[test]
    fn every_unauthorized_put_is_refused() {
        crate::util::test::rt().block_on(Box::pin(every_unauthorized_put_is_refused_case()))
    }

    async fn every_unauthorized_put_is_refused_case() {
        let world = Box::pin(world()).await;
        let db = &world.harness.db;
        let next = world.growth();

        // A member signing a list of their own, from their bound device
        let member_device = world
            .harness
            .new_e2ee_device(&world.member, &world.member_session.id, MEMBER_DEVICE_SEED)
            .await;
        let member_list = member_device.seat_list(
            world.channel.id(),
            2,
            FIXTURE_DEVICE_CAP,
            &[&world.owner.id, &world.member.id, &world.blind.id],
        );
        let answer = put(
            &world.harness,
            &world.member_session,
            world.channel.id(),
            &member_list,
        )
        .await;
        assert_error(&answer, "NotOwner", "member's own list");

        // A member replaying the owner's signed list
        let answer = put(
            &world.harness,
            &world.member_session,
            world.channel.id(),
            &next,
        )
        .await;
        assert_error(&answer, "NotOwner", "member replays the owner's list");

        // The owner, signing from a device bound to another session
        let unbound_device = world
            .harness
            .new_e2ee_device(
                &world.owner,
                &Ulid::new().to_string(),
                NEW_OWNER_DEVICE_SEED,
            )
            .await;
        let unbound_list = unbound_device.seat_list(
            world.channel.id(),
            2,
            FIXTURE_DEVICE_CAP,
            &[
                &world.owner.id,
                &world.member.id,
                &world.blind.id,
                &world.newcomer.id,
            ],
        );
        let answer = put(
            &world.harness,
            &world.owner_session,
            world.channel.id(),
            &unbound_list,
        )
        .await;
        assert_eq!(answer.0, Status::Unauthorized, "{:?}", answer);
        assert_error(&answer, "NotAuthenticated", "unbound session");

        // A signature over another body
        let mut forged = next.clone();
        forged.signature = world
            .owner_device
            .sign(&world.list(2, &[&world.owner.id]).body);
        let answer = put(
            &world.harness,
            &world.owner_session,
            world.channel.id(),
            &forged,
        )
        .await;
        assert_error(&answer, "FailedValidation", "bad signature");

        // An unprotected channel of the same owner
        let unprotected = world.harness.new_channel(&world.server).await;
        let unprotected_list = world.owner_device.seat_list(
            unprotected.id(),
            2,
            FIXTURE_DEVICE_CAP,
            &[&world.owner.id],
        );
        let answer = put(
            &world.harness,
            &world.owner_session,
            unprotected.id(),
            &unprotected_list,
        )
        .await;
        assert_error(&answer, "InvalidOperation", "unprotected channel");

        // A privileged (staff) owner, last: it changes the owner
        db.update_user(
            &world.owner.id,
            &PartialUser {
                privileged: Some(true),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("make the owner staff");
        assert!(
            db.fetch_user(&world.owner.id)
                .await
                .expect("owner")
                .privileged
        );
        let answer = put(
            &world.harness,
            &world.owner_session,
            world.channel.id(),
            &next,
        )
        .await;
        assert_error(&answer, "InvalidOperation", "privileged owner");

        assert_eq!(world.stored().await.version, 1);
        assert!(!world.is_seated(&world.newcomer).await);
    }

    /// Design 4.3 step 4: two different version + 1 lists PUT at once:
    /// exactly one lands, the other is refused, round after round. The
    /// version compare-and-set is the equivocation guard (run on MONGODB,
    /// where the two transactions really overlap).
    ///
    /// S2: the lists leave out the blind member (who lost ViewChannel), so
    /// round 1 unseats them, with the reason step 4d requires. Kept on the
    /// lists, the post-claim reconcile (S2-D12) would release them after
    /// round 1 and every later list would be refused as naming a removed
    /// user (C1), which is not what this test is about.
    #[test]
    fn racing_next_lists_exactly_one_wins() {
        crate::util::test::rt().block_on(Box::pin(racing_next_lists_exactly_one_wins_case()))
    }

    async fn racing_next_lists_exactly_one_wins_case() {
        const ROUNDS: usize = 4;
        let world = Box::pin(world()).await;
        let mut candidates = Vec::new();
        for _ in 0..ROUNDS * 2 {
            let (_, _, user) = world.harness.new_user().await;
            world.harness.join_server(&world.server, &user).await;
            candidates.push(user);
        }

        let mut seated: Vec<String> = world
            .seated()
            .into_iter()
            .filter(|user_id| *user_id != world.blind.id)
            .collect();
        for round in 0..ROUNDS {
            let version = round as i64 + 2;
            let lists: Vec<v0::DataSeatList> = (0..2)
                .map(|side| {
                    let mut seats: Vec<&String> = seated.iter().collect();
                    seats.push(&candidates[round * 2 + side].id);
                    world.list(version, &seats)
                })
                .collect();

            let (first, second) = rocket::tokio::join!(
                put_with_reason(
                    &world.harness,
                    &world.owner_session,
                    world.channel.id(),
                    &lists[0],
                    Some("race"),
                ),
                put_with_reason(
                    &world.harness,
                    &world.owner_session,
                    world.channel.id(),
                    &lists[1],
                    Some("race"),
                ),
            );

            let answers = [&first, &second];
            let winners: Vec<usize> = (0..2)
                .filter(|side| answers[*side].0 == Status::Ok)
                .collect();
            assert_eq!(
                winners.len(),
                1,
                "round {}: {:?} / {:?}",
                round,
                first,
                second
            );
            let winner = winners[0];
            let loser = 1 - winner;
            assert_error(answers[loser], "FailedValidation", "racing loser");

            let stored = world.stored().await;
            assert_eq!(stored.version, version, "round {}", round);
            assert_eq!(stored.body, lists[winner].body, "round {}", round);
            assert!(world.is_seated(&candidates[round * 2 + winner]).await);
            assert!(!world.is_seated(&candidates[round * 2 + loser]).await);

            seated.push(candidates[round * 2 + winner].id.clone());
        }
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
        /// The stored genesis list of `hidden_protected`
        genesis: v0::DataSeatList,
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
            genesis: protected.seat_list,
            hidden_protected,
            hidden_unprotected,
            deleted_id: deleted.channel.id().to_string(),
            missing_id: Ulid::new().to_string(),
            harness,
        }
    }

    /// Decision 18 (W2): for every caller class, a channel the caller
    /// cannot view (protected or not) and a deleted channel answer EXACTLY
    /// as a channel id the server never held, the full body (`location`
    /// included) and status, and that answer is this route's own 404.
    /// Control: the protected check moved above the access check.
    async fn non_viewers_answer_as_a_missing_channel() {
        let fixture = Box::pin(hidden()).await;
        let e2ee = revolt_config::config().await.features.e2ee_enabled;

        // The hidden protected channel is real: its owner's byte-identical
        // re-PUT of the genesis list is served (or gated with E2EE off)
        let owner = put(
            &fixture.harness,
            &fixture.owner_session,
            fixture.hidden_protected.id(),
            &fixture.genesis,
        )
        .await;
        if e2ee {
            let value = assert_ok(&owner, "hidden owner");
            assert_eq!(value["list"]["body"], fixture.genesis.body.as_str());
        } else {
            assert_feature_disabled(&owner, "e2ee", "hidden owner");
        }

        // A malformed list too: the access answer comes before validation
        let mut garbage = fixture.genesis.clone();
        garbage.body = "garbage".to_string();

        for caller in &fixture.callers {
            for data in [&fixture.genesis, &garbage] {
                let missing =
                    put(&fixture.harness, &caller.session, &fixture.missing_id, data).await;
                assert_eq!(
                    missing.0,
                    Status::NotFound,
                    "{}: {:?}",
                    caller.class,
                    missing
                );
                let value = assert_error(&missing, "NotFound", caller.class);
                assert!(
                    value.get("location").is_none(),
                    "{}: the body must not carry the error location: {}",
                    caller.class,
                    missing.1
                );

                for (target, channel_id) in [
                    ("hidden protected", fixture.hidden_protected.id()),
                    ("hidden unprotected", fixture.hidden_unprotected.id()),
                    ("deleted", fixture.deleted_id.as_str()),
                ] {
                    let answer = put(&fixture.harness, &caller.session, channel_id, data).await;
                    assert_eq!(answer, missing, "{} {}", caller.class, target);
                }
            }
        }
    }

    #[test]
    fn non_viewers_answer_as_a_missing_channel_with_every_flag_on() {
        crate::util::test::rt().block_on(Box::pin(non_viewers_answer_as_a_missing_channel()))
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

    #[test]
    fn non_viewers_answer_as_a_missing_channel_with_growth_off() {
        crate::util::test::rt().block_on(Box::pin(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            non_viewers_answer_as_a_missing_channel().await
        }))
    }
}
