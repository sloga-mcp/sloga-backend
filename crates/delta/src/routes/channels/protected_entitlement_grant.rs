use iso8601_timestamp::Timestamp;
use revolt_database::{
    seat_list_channel_server, util::reference::Reference, ChannelEntitlement,
    ChannelEntitlementSource, ChannelEntitlementState, Database, User,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use ulid::Ulid;
use validator::Validate;

use rocket::{serde::json::Json, State};

use crate::routes::mls::require_protected_growth;

/// # Grant Channel Entitlement
///
/// Grant (or update) the entitlement that lets a server channel be
/// protected. Requires a privileged account.
#[openapi(tag = "E2EE")]
#[put("/<target>/protected_entitlement", data = "<data>")]
pub async fn grant_entitlement(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataGrantChannelEntitlement>,
) -> Result<Json<v0::ChannelEntitlement>> {
    // Staff only (design 7.2), checked before anything else is read: every
    // other caller gets this one answer whatever the target and the flags,
    // so the route says nothing about whether a channel exists, is visible
    // or is protected (decision 18). S1 has no non-admin grant.
    if !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    // A grant is growth (decision 5): refused with E2EE or the protected
    // channels flag off
    require_protected_growth().await?;

    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let channel = target.as_channel(db).await?;
    let Some(server_id) = seat_list_channel_server(&channel) else {
        // Only a server TextChannel can be protected (2.1)
        return Err(create_error!(InvalidOperation));
    };

    // An existing row keeps its id, server, source, state and `created_at`
    // and takes the new caps and `granted_by`. The driver re-checks the
    // `1..=100` range (`FailedValidation`) and refuses a `slot_cap` below
    // the seats in use (`SeatCapReached`) under the same lock or
    // transaction as the write, so a racing seat claim cannot slip between
    // the count and the cap.
    let now = Timestamp::now_utc();
    let stored = db
        .upsert_channel_entitlement(
            &ChannelEntitlement {
                id: Ulid::new().to_string(),
                channel_id: channel.id().to_string(),
                server_id: server_id.to_string(),
                source: ChannelEntitlementSource::AdminGrant,
                slot_cap: data.slot_cap,
                device_cap: data.device_cap,
                state: ChannelEntitlementState::Active,
                granted_by: user.id.clone(),
                created_at: now,
            },
            now,
        )
        .await?;

    log::info!(
        "AUDIT protected_entitlement_grant: actor={} channel={} server={} entitlement={} slot_cap={} device_cap={:?}",
        user.id,
        stored.channel_id,
        stored.server_id,
        stored.id,
        stored.slot_cap,
        stored.device_cap
    );

    Ok(Json(stored.into()))
}

#[cfg(test)]
mod test {
    use crate::util::test::{TestHarness, FIXTURE_SLOT_CAP};
    use revolt_database::{BotInformation, Channel, ChannelEntitlement, PartialUser};
    use revolt_database::{Server, Session, User};
    use revolt_models::v0;
    use rocket::http::{ContentType, Status};
    use serde_json::{json, Value};

    struct Caller {
        class: &'static str,
        session: Session,
        user: User,
    }

    struct World {
        harness: TestHarness,
        owner: Caller,
        member: Caller,
        staff: Caller,
        server: Server,
        /// An unprotected server TextChannel with no entitlement
        channel: Channel,
    }

    /// A server owned by a plain user, a plain member, and a privileged
    /// (staff) account that is not a member
    async fn world() -> World {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (server, channel) = harness.new_protectable_channel(&owner).await;
        let (_, member_session, member) = harness.new_user().await;
        harness.join_server(&server, &member).await;
        let (_, staff_session, staff) = harness.new_user().await;
        let staff = make_staff(&harness, &staff).await;

        World {
            harness,
            owner: Caller {
                class: "owner",
                session: owner_session,
                user: owner,
            },
            member: Caller {
                class: "member",
                session: member_session,
                user: member,
            },
            staff: Caller {
                class: "staff",
                session: staff_session,
                user: staff,
            },
            server,
            channel,
        }
    }

    async fn make_staff(harness: &TestHarness, user: &User) -> User {
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
            .expect("make staff");
        let staff = harness.db.fetch_user(&user.id).await.expect("the staff");
        assert!(staff.privileged);
        staff
    }

    /// A member of the world's server that is a bot
    async fn bot(world: &World) -> Caller {
        let (_, session, bot) = world.harness.new_user().await;
        world.harness.join_server(&world.server, &bot).await;
        world
            .harness
            .db
            .update_user(
                &bot.id,
                &PartialUser {
                    bot: Some(BotInformation {
                        owner: world.owner.user.id.clone(),
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("make the bot a bot");
        let bot = world.harness.db.fetch_user(&bot.id).await.expect("the bot");
        assert!(bot.bot.is_some());
        Caller {
            class: "bot",
            session,
            user: bot,
        }
    }

    async fn new_forum(world: &World) -> Channel {
        Channel::create_server_channel(
            &world.harness.db,
            &mut world.server.clone(),
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Forum,
                name: "Forum".to_string(),
                ..Default::default()
            },
            true,
        )
        .await
        .expect("a forum")
    }

    async fn grant(
        harness: &TestHarness,
        session: &Session,
        channel_id: &str,
        body: Value,
    ) -> (Status, Value) {
        let response = TestHarness::with_session(
            session.clone(),
            harness
                .client
                .put(format!("/channels/{channel_id}/protected_entitlement"))
                .header(ContentType::JSON)
                .body(body.to_string()),
        )
        .await;
        let status = response.status();
        let body = response.into_json::<Value>().await.expect("a JSON body");
        (status, body)
    }

    async fn stored(harness: &TestHarness, channel_id: &str) -> Option<ChannelEntitlement> {
        harness
            .db
            .fetch_channel_entitlement(channel_id)
            .await
            .expect("fetch the entitlement")
    }

    /// The stored row as the route serializes it
    async fn stored_json(harness: &TestHarness, channel_id: &str) -> Value {
        let row = stored(harness, channel_id).await.expect("an entitlement");
        serde_json::to_value(v0::ChannelEntitlement::from(row)).expect("serialize")
    }

    fn assert_refused(answer: &(Status, Value), status: Status, error: &str, case: &str) {
        assert_eq!(answer.0, status, "{case}: {:?}", answer);
        assert_eq!(answer.1["type"], error, "{case}: {:?}", answer);
    }

    /// Every caller that is not privileged (the server owner, a member, a
    /// bot, an outsider) gets the same `NotPrivileged`, from this route, for
    /// every target (a missing channel, the visible unprotected channel, a
    /// protected channel, a forum) and every body (valid or out of range).
    /// Nothing is written. Run under each flag state: the answer does not
    /// change with the flags either
    async fn non_privileged_callers_are_refused_identically() {
        let world = Box::pin(world()).await;
        let harness = &world.harness;
        let bot = bot(&world).await;
        let (_, outsider_session, outsider) = harness.new_user().await;
        let outsider = Caller {
            class: "outsider",
            session: outsider_session,
            user: outsider,
        };

        // The owner's own protected channel (seating the member), with its
        // Active entitlement
        let protected = harness
            .new_protected_channel(
                &world.owner.user,
                &world.owner.session,
                &[&world.member.user],
            )
            .await;
        let protected_entitlement = stored_json(harness, protected.channel.id()).await;
        let forum = new_forum(&world).await;
        let missing_id = ulid::Ulid::new().to_string();

        // The plain case first: a member's valid grant on a channel it can
        // see is refused and writes nothing
        let answer = grant(
            harness,
            &world.member.session,
            world.channel.id(),
            json!({ "slot_cap": 5 }),
        )
        .await;
        assert_refused(&answer, Status::Forbidden, "NotPrivileged", "member grant");
        assert!(stored(harness, world.channel.id()).await.is_none());

        for caller in [&world.owner, &world.member, &bot, &outsider] {
            assert!(!caller.user.privileged, "{}", caller.class);
            for body in [
                json!({ "slot_cap": 5 }),
                json!({ "slot_cap": 5, "device_cap": 0 }),
                json!({ "slot_cap": 0 }),
                json!({ "slot_cap": 101 }),
            ] {
                let missing = grant(harness, &caller.session, &missing_id, body.clone()).await;
                assert_refused(&missing, Status::Forbidden, "NotPrivileged", caller.class);
                assert!(
                    missing.1["location"]
                        .as_str()
                        .is_some_and(|location| location
                            .contains("routes/channels/protected_entitlement_grant.rs")),
                    "{}: refused away from this route: {:?}",
                    caller.class,
                    missing
                );
                for (target, channel_id) in [
                    ("unprotected", world.channel.id()),
                    ("protected", protected.channel.id()),
                    ("forum", forum.id()),
                ] {
                    let answer = grant(harness, &caller.session, channel_id, body.clone()).await;
                    assert_eq!(answer, missing, "{} {} {}", caller.class, target, body);
                }
            }
        }

        assert!(stored(harness, world.channel.id()).await.is_none());
        assert!(stored(harness, forum.id()).await.is_none());
        assert_eq!(
            stored_json(harness, protected.channel.id()).await,
            protected_entitlement
        );
    }

    #[test]
    fn non_privileged_callers_are_refused_identically_with_every_flag_on() {
        crate::util::test::rt().block_on(Box::pin(non_privileged_callers_are_refused_identically()))
    }

    #[test]
    fn non_privileged_callers_are_refused_identically_with_growth_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            Box::pin(non_privileged_callers_are_refused_identically()).await
        })
    }

    #[test]
    fn non_privileged_callers_are_refused_identically_with_e2ee_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            Box::pin(non_privileged_callers_are_refused_identically()).await
        })
    }

    #[test]
    fn staff_grant_creates_then_updates_the_entitlement() {
        crate::util::test::rt().block_on(Box::pin(staff_grant_creates_then_updates_case()))
    }

    async fn staff_grant_creates_then_updates_case() {
        let world = Box::pin(world()).await;
        let harness = &world.harness;
        let channel_id = world.channel.id();
        assert!(stored(harness, channel_id).await.is_none());

        // Created: an Active admin grant by this staff account, on the
        // channel's server, with the configured default device cap
        let created = grant(
            harness,
            &world.staff.session,
            channel_id,
            json!({ "slot_cap": 3 }),
        )
        .await;
        assert_eq!(created.0, Status::Ok, "{:?}", created);
        let value = &created.1;
        assert!(value["_id"].as_str().is_some_and(|id| !id.is_empty()));
        assert_eq!(value["channel_id"], channel_id);
        assert_eq!(value["server_id"], world.server.id);
        assert_eq!(value["source"], "AdminGrant");
        assert_eq!(value["slot_cap"], 3);
        assert!(value.get("device_cap").is_none(), "{}", value);
        assert_eq!(value["state"], "Active");
        assert_eq!(value["granted_by"], world.staff.user.id);
        assert!(value["created_at"].is_string());
        assert_eq!(*value, stored_json(harness, channel_id).await);

        // Updated by another staff account: the same row (id, server,
        // source, state, created_at) with the new caps and grantor
        let (_, other_session, other) = harness.new_user().await;
        let other = make_staff(harness, &other).await;
        let updated = grant(
            harness,
            &other_session,
            channel_id,
            json!({ "slot_cap": 100, "device_cap": 0 }),
        )
        .await;
        assert_eq!(updated.0, Status::Ok, "{:?}", updated);
        let mut expected = created.1.clone();
        expected["slot_cap"] = json!(100);
        expected["device_cap"] = json!(0);
        expected["granted_by"] = json!(other.id);
        assert_eq!(updated.1, expected);
        assert_eq!(updated.1, stored_json(harness, channel_id).await);

        // An absent device cap goes back to the configured default
        let reset = grant(
            harness,
            &world.staff.session,
            channel_id,
            json!({ "slot_cap": 1 }),
        )
        .await;
        assert_eq!(reset.0, Status::Ok, "{:?}", reset);
        let mut expected = created.1.clone();
        expected["slot_cap"] = json!(1);
        assert_eq!(reset.1, expected);
        assert_eq!(reset.1, stored_json(harness, channel_id).await);
    }

    #[test]
    fn staff_grant_refuses_a_slot_cap_outside_1_to_100() {
        crate::util::test::rt().block_on(Box::pin(staff_grant_refuses_a_slot_cap_case()))
    }

    async fn staff_grant_refuses_a_slot_cap_case() {
        let world = Box::pin(world()).await;
        let harness = &world.harness;
        let channel_id = world.channel.id();

        for slot_cap in [0, 101, u64::from(u32::MAX)] {
            let answer = grant(
                harness,
                &world.staff.session,
                channel_id,
                json!({ "slot_cap": slot_cap }),
            )
            .await;
            assert_refused(
                &answer,
                Status::BadRequest,
                "FailedValidation",
                &format!("slot_cap {slot_cap}"),
            );
            assert!(stored(harness, channel_id).await.is_none());
        }

        // An existing entitlement is left as it was
        let created = grant(
            harness,
            &world.staff.session,
            channel_id,
            json!({ "slot_cap": 4 }),
        )
        .await;
        assert_eq!(created.0, Status::Ok, "{:?}", created);
        for slot_cap in [0, 101] {
            let answer = grant(
                harness,
                &world.staff.session,
                channel_id,
                json!({ "slot_cap": slot_cap, "device_cap": 2 }),
            )
            .await;
            assert_refused(
                &answer,
                Status::BadRequest,
                "FailedValidation",
                &format!("update to slot_cap {slot_cap}"),
            );
            assert_eq!(stored_json(harness, channel_id).await, created.1);
        }
    }

    #[test]
    fn staff_grant_refuses_a_slot_cap_below_the_seats_in_use() {
        crate::util::test::rt().block_on(Box::pin(staff_grant_refuses_below_seats_case()))
    }

    async fn staff_grant_refuses_below_seats_case() {
        let world = Box::pin(world()).await;
        let harness = &world.harness;

        // Two seats in use: the owner and the member
        let protected = harness
            .new_protected_channel(
                &world.owner.user,
                &world.owner.session,
                &[&world.member.user],
            )
            .await;
        let channel_id = protected.channel.id();
        let before = stored_json(harness, channel_id).await;
        assert_eq!(before["slot_cap"], FIXTURE_SLOT_CAP);

        let answer = grant(
            harness,
            &world.staff.session,
            channel_id,
            json!({ "slot_cap": 1 }),
        )
        .await;
        assert_refused(&answer, Status::BadRequest, "SeatCapReached", "slot_cap 1");
        assert_eq!(answer.1["max"], 1);
        assert_eq!(stored_json(harness, channel_id).await, before);

        // Exactly the seats in use is allowed
        let answer = grant(
            harness,
            &world.staff.session,
            channel_id,
            json!({ "slot_cap": 2 }),
        )
        .await;
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        assert_eq!(answer.1["_id"], before["_id"]);
        assert_eq!(answer.1["slot_cap"], 2);
        assert_eq!(answer.1, stored_json(harness, channel_id).await);
    }

    #[test]
    fn staff_grant_refuses_a_channel_that_is_not_a_server_text_channel() {
        crate::util::test::rt().block_on(Box::pin(staff_grant_refuses_other_channels_case()))
    }

    async fn staff_grant_refuses_other_channels_case() {
        let world = Box::pin(world()).await;
        let harness = &world.harness;

        let forum = new_forum(&world).await;
        let group = Channel::create_group(
            &harness.db,
            v0::DataCreateGroup {
                name: "Group".to_string(),
                users: std::iter::once(world.member.user.id.clone()).collect(),
                ..Default::default()
            },
            world.owner.user.id.clone(),
        )
        .await
        .expect("a group");
        let dm = Channel::create_dm(&harness.db, &world.owner.user, &world.member.user)
            .await
            .expect("a DM");

        for (class, channel) in [("forum", &forum), ("group", &group), ("dm", &dm)] {
            let answer = grant(
                harness,
                &world.staff.session,
                channel.id(),
                json!({ "slot_cap": 5 }),
            )
            .await;
            assert_refused(&answer, Status::BadRequest, "InvalidOperation", class);
            assert!(stored(harness, channel.id()).await.is_none(), "{}", class);
        }

        let missing_id = ulid::Ulid::new().to_string();
        let answer = grant(
            harness,
            &world.staff.session,
            &missing_id,
            json!({ "slot_cap": 5 }),
        )
        .await;
        assert_refused(&answer, Status::NotFound, "NotFound", "missing");
        assert!(stored(harness, &missing_id).await.is_none());
    }

    /// With the growth flag (or E2EE) off, a staff grant is refused before
    /// anything is written, a new grant and an update alike
    async fn staff_grant_is_refused_by_the_growth_gate(feature: &str) {
        let world = Box::pin(world()).await;
        let harness = &world.harness;
        let protected = harness
            .new_protected_channel(&world.owner.user, &world.owner.session, &[])
            .await;
        let before = stored_json(harness, protected.channel.id()).await;

        let answer = grant(
            harness,
            &world.staff.session,
            world.channel.id(),
            json!({ "slot_cap": 5 }),
        )
        .await;
        assert_refused(&answer, Status::BadRequest, "FeatureDisabled", "new grant");
        assert_eq!(answer.1["feature"], feature);
        assert!(stored(harness, world.channel.id()).await.is_none());

        let answer = grant(
            harness,
            &world.staff.session,
            protected.channel.id(),
            json!({ "slot_cap": 20, "device_cap": 1 }),
        )
        .await;
        assert_refused(&answer, Status::BadRequest, "FeatureDisabled", "update");
        assert_eq!(answer.1["feature"], feature);
        assert_eq!(stored_json(harness, protected.channel.id()).await, before);
    }

    #[test]
    fn staff_grant_is_refused_with_growth_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            Box::pin(staff_grant_is_refused_by_the_growth_gate(
                "protected_channels",
            ))
            .await
        })
    }

    #[test]
    fn staff_grant_is_refused_with_e2ee_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            Box::pin(staff_grant_is_refused_by_the_growth_gate("e2ee")).await
        })
    }
}
