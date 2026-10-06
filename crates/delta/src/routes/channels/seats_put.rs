use iso8601_timestamp::Timestamp;
use revolt_database::{
    seat_list_channel_server, util::reference::Reference, Database, Session, User,
};
use revolt_models::v0;
use revolt_result::{create_error, Error, ErrorType, Result};

use rocket::{serde::json::Json, State};

use super::{
    protected_seat_validation::validate_seat_list_put, seats_fetch::channel_seats_response,
};
use crate::routes::mls::{
    require_channel_access, require_protected_available, require_protected_growth,
};

/// # Publish Seat List
///
/// Publish the next owner-signed seat list of a protected channel. Only the
/// server owner may publish, from the device that signed the list.
#[openapi(tag = "E2EE")]
#[put("/<target>/seats", data = "<data>")]
pub async fn put_seats(
    db: &State<Database>,
    user: User,
    session: Session,
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

    // 4.3 steps 1 to 3, 5, 6 and 8; the signer is always seated (4.1), so a
    // privileged (staff) owner is refused at step 5 with `InvalidOperation`
    let validated = validate_seat_list_put(db, &channel, &server, &user, &session, &data).await?;

    // Decisions 4 and 5 (W2): with the growth flag off the driver still
    // answers a byte-identical re-PUT and applies a list that claims nobody
    // (removals, a `device_cap` change); only a claim is refused
    let allow_claims = require_protected_growth().await.is_ok();
    db.put_seat_list(
        channel.id(),
        &validated.submission,
        allow_claims,
        Timestamp::now_utc(),
    )
    .await?;

    // 7.5: a seat PUT publishes no websocket event; clients refresh `GET
    // .../seats` on their own schedule. The answer is the seat state that
    // route serves, as the owner (the validated caller) sees it, with
    // `seated_without_access` on every seat.
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
        events::client::EventV1, BotInformation, Channel, MemberCompositeKey, PartialChannel,
        PartialMember, PartialUser, RemovalIntention, SeatList, Server, Session, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::Value;
    use ulid::Ulid;

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

    /// The route's full answer: status and body
    async fn put(
        harness: &TestHarness,
        session: &Session,
        channel_id: &str,
        data: &v0::DataSeatList,
    ) -> (Status, String) {
        let response = harness
            .client
            .put(format!("/channels/{channel_id}/seats"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.clone()))
            .body(serde_json::to_string(data).expect("JSON"))
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
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
    /// Design 7.5: no websocket event is published.
    #[test]
    fn the_owner_publishes_the_next_list() {
        crate::util::test::rt().block_on(Box::pin(the_owner_publishes_the_next_list_case()))
    }

    async fn the_owner_publishes_the_next_list_case() {
        let mut world = Box::pin(world()).await;
        let next = world.growth();
        assert!(!world.is_seated(&world.newcomer).await);

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
            (world.blind.id.clone(), Value::Bool(true)),
            (world.newcomer.id.clone(), Value::Bool(false)),
        ];
        expected.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(seats_of(&value), expected, "{}", answer.1);
        assert!(cooling_of(&value).is_empty(), "{}", answer.1);
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

        // No event: nothing the PUT could have published reached any topic
        // a client of this channel listens on. The setup publishes only the
        // kinds allowed below (creating the channel also updates the
        // server's channel list).
        let owner_id = world.owner.id.clone();
        let marker = flush_with_marker(&mut world.harness, &owner_id).await;
        let mut topics = vec![world.server.id.clone(), world.channel.id().to_string()];
        for user in [&world.owner, &world.member, &world.blind, &world.newcomer] {
            topics.push(user.id.clone());
            topics.push(format!("{}!", user.id));
        }
        for topic in &topics {
            world
                .harness
                .assert_no_buffered_event(topic, |event| match event {
                    EventV1::ServerCreate { .. }
                    | EventV1::ServerMemberJoin { .. }
                    | EventV1::ServerRoleUpdate { .. }
                    | EventV1::ChannelCreate(_) => false,
                    EventV1::ServerUpdate { data, .. } => data.channels.is_none(),
                    EventV1::ChannelAck { message_id, .. } => message_id != &marker,
                    _ => true,
                });
        }
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
    /// seats is applied; the removed seat starts cooling
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

        let answer = put(
            &world.harness,
            &world.owner_session,
            world.channel.id(),
            &next,
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

        let mut seated = world.seated();
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
                put(
                    &world.harness,
                    &world.owner_session,
                    world.channel.id(),
                    &lists[0],
                ),
                put(
                    &world.harness,
                    &world.owner_session,
                    world.channel.id(),
                    &lists[1],
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
                    value["location"]
                        .as_str()
                        .is_some_and(|location| location.contains("routes/channels/seats_put.rs")),
                    "{}: {}",
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
