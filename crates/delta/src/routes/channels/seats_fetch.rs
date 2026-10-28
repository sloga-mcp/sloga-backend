use std::{collections::BTreeSet, convert::TryFrom};

use revolt_config::ProtectedChannelFeatures;
use revolt_database::{
    iso8601_timestamp::Timestamp,
    mls_text_enforced_device_cap, seat_list_channel_server,
    util::{permissions::perms, reference::Reference},
    Channel, ChannelEntitlement, ChannelSeat, Database, SeatListBody, SeatListSnapshot, Server,
    User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Error, Result};

use rocket::{serde::json::Json, State};

use crate::routes::mls::{
    effective_device_cap, require_channel_access, require_protected_available,
};

/// # Fetch Seats
///
/// The seat state of a channel (protected-channels design 7.2): the newest
/// owner-signed seat list with the open Text group's epoch and id, read in
/// one snapshot, the caps, the active seats and the seats still cooling
/// down. Any user who can view the channel; maintenance gate (E2EE only, so
/// it keeps answering with growth off). A channel that is not protected
/// answers with a `null` list.
///
/// A missing channel, and a channel the caller cannot view, get the same
/// 404 before any other check (decision 18 (W2)), so a non-viewer cannot
/// tell a protected channel from an unprotected one, or from no channel.
#[openapi(tag = "E2EE")]
#[get("/<target>/seats")]
pub async fn fetch_seats(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<v0::ResponseChannelSeats>> {
    // ANY failure to read the channel answers as a missing channel
    let Ok(channel) = target.as_channel(db).await else {
        return Err(no_channel());
    };
    if require_channel_access(db, &user, &channel).await.is_err() {
        return Err(no_channel());
    }

    require_protected_available().await?;

    channel_seats_response(db, &channel, &user).await.map(Json)
}

/// The one `NotFound` this route answers, for a missing channel and a channel
/// the caller cannot view alike: one source site, so the body's `location`
/// never tells them apart
fn no_channel() -> Error {
    create_error!(NotFound)
}

/// `channel`'s seat state as `caller` may see it (7.2), shared with
/// `PUT .../seats`, which answers with the same shape. The caller must
/// already be authorized to view `channel`: this only reads and projects.
///
/// The list and the open Text group come from ONE snapshot read, so
/// `(list.version, as_of_epoch, as_of_group_id)` stays consistent under a
/// racing PUT (W0-fix4). The entitlement and the seat rows are read after
/// it; they are the Delivery Service's own view, which no client verifies.
///
/// `seated_without_access` is computed only when the caller is the server
/// owner, by a hard id check rather than the permission calculus (which
/// grants everything to privileged accounts), and left out for everyone
/// else (7.2, DECISION (W0): other members' permission state is not
/// disclosed).
pub(crate) async fn channel_seats_response(
    db: &Database,
    channel: &Channel,
    caller: &User,
) -> Result<v0::ResponseChannelSeats> {
    let snapshot = db.fetch_seat_list_snapshot(channel.id()).await?;
    let entitlement = db.fetch_channel_entitlement(channel.id()).await?;
    let seats = db.fetch_channel_seats(channel.id()).await?;

    let without_access = match owned_server(db, channel, caller).await? {
        Some(server) => Some(seats_without_access(db, channel, &server, &seats).await?),
        None => None,
    };

    let config = revolt_config::config().await;
    project_seats(
        snapshot,
        entitlement.as_ref(),
        seats,
        without_access.as_ref(),
        &config.features.protected_channels,
        Timestamp::now_utc(),
    )
}

/// The channel's server when `caller` owns it; `None` for anyone else and
/// for a channel outside a server
async fn owned_server(db: &Database, channel: &Channel, caller: &User) -> Result<Option<Server>> {
    let Some(server_id) = seat_list_channel_server(channel) else {
        return Ok(None);
    };
    let server = db.fetch_server(server_id).await?;
    Ok((server.owner == caller.id).then_some(server))
}

/// The users holding an ACTIVE seat who cannot view the channel (6.4). A
/// seat holder who is no longer a server member (a failed second release,
/// 6.3) or whose account is gone counts as without access.
async fn seats_without_access(
    db: &Database,
    channel: &Channel,
    server: &Server,
    seats: &[ChannelSeat],
) -> Result<BTreeSet<String>> {
    let seated: Vec<String> = seats
        .iter()
        .filter(|seat| seat.is_active())
        .map(|seat| seat.user_id.clone())
        .collect();
    if seated.is_empty() {
        return Ok(BTreeSet::new());
    }

    let users = db.fetch_users(&seated).await?;
    let members = db.fetch_members(&server.id, &seated).await?;

    let mut without_access = BTreeSet::new();
    for user_id in seated {
        let user = users.iter().find(|user| user.id == user_id);
        let member = members
            .iter()
            .find(|member| member.id.server == server.id && member.id.user == user_id);
        let can_view = match (user, member) {
            (Some(user), Some(member)) => {
                let mut query = perms(db, user)
                    .channel(channel)
                    .server(server)
                    .member(member);
                calculate_channel_permissions(&mut query)
                    .await
                    .has_channel_permission(ChannelPermission::ViewChannel)
            }
            _ => false,
        };
        if !can_view {
            without_access.insert(user_id);
        }
    }

    Ok(without_access)
}

/// The stored state projected onto the response. Active seats are listed;
/// a released seat only while it is cooling at `now` (`into_cooling_info`
/// does not look at the time). `seats_used` counts what is listed, active +
/// cooling, the slot cap's count (2.3).
///
/// Caps (#152): `entitlement_device_cap` and `slot_cap` are `null` without
/// an entitlement, `device_cap` is `null` without a list. `device_cap` is
/// the ENFORCED cap (2.5): the signed cap against the effective
/// entitlement cap, or the configured default without an entitlement, as
/// the Text commit route enforces it.
fn project_seats(
    snapshot: SeatListSnapshot,
    entitlement: Option<&ChannelEntitlement>,
    seats: Vec<ChannelSeat>,
    without_access: Option<&BTreeSet<String>>,
    config: &ProtectedChannelFeatures,
    now: Timestamp,
) -> Result<v0::ResponseChannelSeats> {
    let entitlement_device_cap =
        entitlement.map(|entitlement| effective_device_cap(entitlement, config));
    let device_cap = match &snapshot.list {
        Some(list) => Some(mls_text_enforced_device_cap(
            SeatListBody::parse(&list.body)?.device_cap,
            entitlement_device_cap.unwrap_or(config.default_device_cap),
        )),
        None => None,
    };

    let mut active = Vec::new();
    let mut cooling = Vec::new();
    for seat in seats {
        if seat.is_active() {
            let lost_access = without_access.map(|users| users.contains(&seat.user_id));
            let mut info = seat.into_seat_info();
            info.seated_without_access = lost_access;
            active.push(info);
        } else if seat.is_cooling(now) {
            cooling.extend(seat.into_cooling_info());
        }
    }
    let seats_used =
        u32::try_from(active.len() + cooling.len()).map_err(|_| create_error!(InternalError))?;

    Ok(v0::ResponseChannelSeats {
        as_of_epoch: snapshot
            .text_group
            .as_ref()
            .map(|group| group.current_epoch),
        as_of_group_id: snapshot.text_group.map(|group| group.id),
        list: snapshot.list.map(Into::into),
        entitlement_device_cap,
        slot_cap: entitlement.map(|entitlement| entitlement.slot_cap),
        device_cap,
        seats_used,
        seats: active,
        cooling,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use revolt_config::ProtectedChannelFeatures;
    use revolt_database::{
        iso8601_timestamp::Timestamp, BotInformation, Channel, ChannelSeat, MemberCompositeKey,
        PartialChannel, PartialMember, PartialUser, SeatListSnapshot, Session, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{Header, Status};
    use serde_json::{json, Value};
    use ulid::Ulid;

    use super::project_seats;
    use crate::routes::mls::{require_channel_access, text::text_group_id};
    use crate::util::test::{
        ProtectedChannel, TestHarness, FIXTURE_DEVICE_CAP, FIXTURE_SLOT_CAP, MEMBER_DEVICE_SEED,
    };

    /// The A7 wire example of a channel that is not protected and has no
    /// open Text group (v0 `protected_dto_tests`)
    const SEATS_UNPROTECTED: &str = r#"{"list":null,"as_of_epoch":null,"as_of_group_id":null,"entitlement_device_cap":null,"slot_cap":null,"device_cap":null,"seats_used":0,"seats":[],"cooling":[]}"#;

    /// The route's full answer: status and body
    async fn get(harness: &TestHarness, session: &Session, channel_id: &str) -> (Status, String) {
        let response = harness
            .client
            .get(format!("/channels/{channel_id}/seats"))
            .header(Header::new("x-session-token", session.token.clone()))
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    #[track_caller]
    fn body(answer: &(Status, String)) -> Value {
        serde_json::from_str(&answer.1).unwrap_or_else(|_| panic!("not JSON: {:?}", answer))
    }

    /// An API 404 (JSON typed `NotFound`, so not an unmatched route's). The
    /// body never carries the error's `location`, so it cannot tell this
    /// route's 404 from another file's.
    #[track_caller]
    fn assert_own_not_found(answer: &(Status, String), case: &str) {
        assert_eq!(answer.0, Status::NotFound, "{}: {:?}", case, answer);
        let value = body(answer);
        assert_eq!(value["type"], "NotFound", "{}: {}", case, answer.1);
        assert!(
            value.get("location").is_none(),
            "{}: the body must not carry the error location: {}",
            case,
            answer.1
        );
    }

    #[track_caller]
    fn assert_e2ee_disabled(answer: &(Status, String), case: &str) {
        assert_eq!(answer.0, Status::BadRequest, "{}: {:?}", case, answer);
        let value = body(answer);
        assert_eq!(value["type"], "FeatureDisabled", "{}: {}", case, answer.1);
        assert_eq!(value["feature"], "e2ee", "{}: {}", case, answer.1);
    }

    fn member_key(server: &str, user: &str) -> MemberCompositeKey {
        MemberCompositeKey {
            server: server.to_string(),
            user: user.to_string(),
        }
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

    async fn make_bot(harness: &TestHarness, bot: &User, owner: &User) -> User {
        harness
            .db
            .update_user(
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
        let bot = harness.db.fetch_user(&bot.id).await.expect("the bot");
        assert!(bot.bot.is_some());
        bot
    }

    /// A protected channel with its generation-0 Text group, whose list is
    /// at version 2, and every kind of seat:
    /// - `member`: seated, can view;
    /// - `blind`: seated, lost ViewChannel through a role override;
    /// - `gone`: seated, no longer a server member (a failed second
    ///   release, 6.3);
    /// - `leaver`: unseated by the v2 list, so cooling.
    ///
    /// Viewers who are NOT the owner: `member`, a staff account (granted
    /// everything by the permission calculus) and a bot.
    struct Fixture {
        harness: TestHarness,
        protected: ProtectedChannel,
        owner_session: Session,
        member_session: Session,
        staff_session: Session,
        bot_session: Session,
        blind: User,
        gone: User,
        leaver: User,
    }

    async fn fixture() -> Fixture {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, _, blind) = harness.new_user().await;
        let (_, _, gone) = harness.new_user().await;
        let (_, _, leaver) = harness.new_user().await;
        let (_, staff_session, staff) = harness.new_user().await;
        let (_, bot_session, bot) = harness.new_user().await;

        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member, &blind, &gone, &leaver])
            .await;
        let server_id = protected.server.id.clone();
        harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let v2 = protected.owner_device.seat_list(
            protected.channel.id(),
            2,
            FIXTURE_DEVICE_CAP,
            &[
                owner.id.as_str(),
                member.id.as_str(),
                blind.id.as_str(),
                gone.id.as_str(),
            ],
        );
        harness.put_seats_with_db(&protected.channel, &v2).await;

        // Through `update`: the Reference driver's `set_channel_role_permission`
        // only replaces an override that already exists
        let role = harness.new_role(&protected.server, 1, None).await;
        let mut channel = protected.channel.clone();
        channel
            .update(
                db,
                PartialChannel {
                    role_permissions: Some(HashMap::from([(
                        role.id.clone(),
                        OverrideField {
                            a: 0,
                            d: ChannelPermission::ViewChannel as i64,
                        },
                    )])),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("deny the role ViewChannel");
        db.update_member(
            &member_key(&server_id, &blind.id),
            &PartialMember {
                roles: Some(vec![role.id.clone()]),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("give blind the role");
        db.force_delete_member(&member_key(&server_id, &gone.id))
            .await
            .expect("drop gone's membership");

        harness.join_server(&protected.server, &bot).await;
        let bot = make_bot(&harness, &bot, &owner).await;
        db.update_user(
            &staff.id,
            &PartialUser {
                privileged: Some(true),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("make staff privileged");
        let staff = db.fetch_user(&staff.id).await.expect("staff");
        assert!(staff.privileged);

        // The fixture really holds what it claims, so no assertion below
        // passes on an empty case
        let channel = db
            .fetch_channel(protected.channel.id())
            .await
            .expect("read");
        for (who, user, views) in [
            ("owner", &owner, true),
            ("member", &member, true),
            ("staff", &staff, true),
            ("bot", &bot, true),
            ("blind", &blind, false),
            ("gone", &gone, false),
        ] {
            let user = db.fetch_user(&user.id).await.expect("the user");
            assert_eq!(
                require_channel_access(db, &user, &channel).await.is_ok(),
                views,
                "{who}"
            );
        }
        let seats = db
            .fetch_channel_seats(protected.channel.id())
            .await
            .expect("seats");
        let active: BTreeSet<&str> = seats
            .iter()
            .filter(|seat| seat.is_active())
            .map(|seat| seat.user_id.as_str())
            .collect();
        assert_eq!(
            active,
            BTreeSet::from([
                owner.id.as_str(),
                member.id.as_str(),
                blind.id.as_str(),
                gone.id.as_str()
            ])
        );
        assert!(seats
            .iter()
            .any(|seat| seat.user_id == leaver.id && seat.is_cooling(Timestamp::now_utc())));
        assert_eq!(
            revolt_config::config()
                .await
                .features
                .protected_channels
                .default_device_cap,
            FIXTURE_DEVICE_CAP
        );

        Fixture {
            harness,
            protected,
            owner_session,
            member_session,
            staff_session,
            bot_session,
            blind,
            gone,
            leaver,
        }
    }

    /// The response the fixture's channel must get, from the stored rows:
    /// `owner_view` adds `seated_without_access` to every seat
    async fn expected_body(fixture: &Fixture, owner_view: bool) -> Value {
        let db = &fixture.harness.db;
        let channel_id = fixture.protected.channel.id();
        let list = db
            .fetch_seat_list(channel_id)
            .await
            .expect("read")
            .expect("a list");
        assert_eq!(list.version, 2);
        let lost = BTreeSet::from([fixture.blind.id.as_str(), fixture.gone.id.as_str()]);

        let mut seats = vec![];
        let mut cooling = vec![];
        for seat in db.fetch_channel_seats(channel_id).await.expect("seats") {
            if seat.released_at.is_none() {
                let mut entry = json!({ "user_id": seat.user_id, "seated_at": seat.seated_at });
                if owner_view {
                    entry["seated_without_access"] = json!(lost.contains(seat.user_id.as_str()));
                }
                seats.push(entry);
            } else {
                assert_eq!(seat.user_id, fixture.leaver.id);
                cooling.push(json!({
                    "user_id": seat.user_id,
                    "released_at": seat.released_at,
                    "cooldown_until": seat.cooldown_until,
                }));
            }
        }
        assert_eq!((seats.len(), cooling.len()), (4, 1));

        json!({
            "list": v0::ChannelSeatListInfo::from(list),
            "as_of_epoch": 0,
            "as_of_group_id": text_group_id(channel_id, 0),
            "entitlement_device_cap": FIXTURE_DEVICE_CAP,
            "slot_cap": FIXTURE_SLOT_CAP,
            "device_cap": FIXTURE_DEVICE_CAP,
            "seats_used": 5,
            "seats": seats,
            "cooling": cooling,
        })
    }

    /// 6.4 / 7.2: the owner gets `seated_without_access` on every active
    /// seat, `true` exactly for the seat holder who lost ViewChannel and the
    /// one who is no longer a member
    async fn the_owner_sees_who_is_seated_without_access_case() {
        let fixture = Box::pin(fixture()).await;
        let answer = get(
            &fixture.harness,
            &fixture.owner_session,
            fixture.protected.channel.id(),
        )
        .await;
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        let value = body(&answer);
        assert_eq!(value, expected_body(&fixture, true).await);

        let flagged: BTreeSet<&str> = value["seats"]
            .as_array()
            .expect("seats")
            .iter()
            .filter(|seat| seat["seated_without_access"] == json!(true))
            .map(|seat| seat["user_id"].as_str().expect("user_id"))
            .collect();
        assert_eq!(
            flagged,
            BTreeSet::from([fixture.blind.id.as_str(), fixture.gone.id.as_str()])
        );
    }

    #[test]
    fn the_owner_sees_who_is_seated_without_access() {
        crate::util::test::rt()
            .block_on(Box::pin(the_owner_sees_who_is_seated_without_access_case()))
    }

    /// DECISION (W0): no other viewer learns anyone's permission state, not
    /// even staff, whom the permission calculus grants everything; the rest
    /// of the answer is the owner's
    async fn only_the_owner_is_told_who_lost_access_case() {
        let fixture = Box::pin(fixture()).await;
        let expected = expected_body(&fixture, false).await;
        for (class, session) in [
            ("member", &fixture.member_session),
            ("staff", &fixture.staff_session),
            ("bot", &fixture.bot_session),
        ] {
            let answer = get(&fixture.harness, session, fixture.protected.channel.id()).await;
            assert_eq!(answer.0, Status::Ok, "{}: {:?}", class, answer);
            assert!(
                !answer.1.contains("seated_without_access"),
                "{}: {}",
                class,
                answer.1
            );
            assert_eq!(body(&answer), expected, "{}", class);
        }
    }

    #[test]
    fn only_the_owner_is_told_who_lost_access() {
        crate::util::test::rt().block_on(Box::pin(only_the_owner_is_told_who_lost_access_case()))
    }

    /// `"2026-10-20T00:00:00.000Z"`-style test instants
    fn at(instant: &str) -> Timestamp {
        serde_json::from_value(json!(instant)).expect("a timestamp")
    }

    fn seat(user_id: &str, released_at: Option<&str>, cooldown_until: Option<&str>) -> ChannelSeat {
        ChannelSeat {
            id: ChannelSeat::composite_id("channel", user_id),
            channel_id: "channel".to_string(),
            user_id: user_id.to_string(),
            seated_at: at("2026-09-01T00:00:00.000Z"),
            released_at: released_at.map(at),
            cooldown_until: cooldown_until.map(at),
        }
    }

    /// 2.3: a released seat is listed (and counted) only while
    /// `now < cooldown_until`; at or past it the seat is free
    #[test]
    fn expired_cooling_seats_are_left_out() {
        let now = at("2026-10-20T00:00:00.000Z");
        let seats = vec![
            seat("active", None, None),
            seat(
                "cooling",
                Some("2026-10-10T00:00:00.000Z"),
                Some("2026-10-24T00:00:00.000Z"),
            ),
            seat(
                "expired",
                Some("2026-10-01T00:00:00.000Z"),
                Some("2026-10-15T00:00:00.000Z"),
            ),
            seat(
                "boundary",
                Some("2026-10-06T00:00:00.000Z"),
                Some("2026-10-20T00:00:00.000Z"),
            ),
        ];
        let without_access = BTreeSet::from(["active".to_string()]);

        for owner_view in [None, Some(&without_access)] {
            let response = project_seats(
                SeatListSnapshot {
                    list: None,
                    text_group: None,
                },
                None,
                seats.clone(),
                owner_view,
                &ProtectedChannelFeatures::default(),
                now,
            )
            .expect("projected");

            let cooling: Vec<&str> = response
                .cooling
                .iter()
                .map(|seat| seat.user_id.as_str())
                .collect();
            assert_eq!(cooling, ["cooling"]);
            assert_eq!(
                response.cooling[0].cooldown_until,
                at("2026-10-24T00:00:00.000Z")
            );
            assert_eq!(response.seats.len(), 1);
            assert_eq!(response.seats[0].user_id, "active");
            assert_eq!(
                response.seats[0].seated_without_access,
                owner_view.map(|_| true)
            );
            assert_eq!(response.seats_used, 2);
        }
    }

    /// Decision 5 (W2): the read keeps working with growth off, unchanged
    async fn served_with_growth_off_case() {
        revolt_config::overwrite_config(|settings| {
            settings.features.protected_channels.enabled = false;
        })
        .await;
        assert!(revolt_config::config().await.features.e2ee_enabled);

        let fixture = Box::pin(fixture()).await;
        let channel_id = fixture.protected.channel.id();
        let owner = get(&fixture.harness, &fixture.owner_session, channel_id).await;
        assert_eq!(owner.0, Status::Ok, "{:?}", owner);
        assert_eq!(body(&owner), expected_body(&fixture, true).await);
        let member = get(&fixture.harness, &fixture.member_session, channel_id).await;
        assert_eq!(member.0, Status::Ok, "{:?}", member);
        assert_eq!(body(&member), expected_body(&fixture, false).await);
    }

    #[test]
    fn served_with_growth_off() {
        crate::util::test::rt().block_on(Box::pin(served_with_growth_off_case()))
    }

    /// 7.1: E2EE off stops the text plane, this read included, for viewers
    async fn refused_with_e2ee_off_case() {
        revolt_config::overwrite_config(|settings| {
            settings.features.e2ee_enabled = false;
        })
        .await;

        let fixture = Box::pin(fixture()).await;
        let channel_id = fixture.protected.channel.id();
        for (class, session) in [
            ("owner", &fixture.owner_session),
            ("member", &fixture.member_session),
            ("bot", &fixture.bot_session),
        ] {
            let answer = get(&fixture.harness, session, channel_id).await;
            assert_e2ee_disabled(&answer, class);
        }
    }

    #[test]
    fn refused_with_e2ee_off() {
        crate::util::test::rt().block_on(Box::pin(refused_with_e2ee_off_case()))
    }

    /// Decision 18 (W2): for every caller class, a channel the caller cannot
    /// view (protected or not) and a deleted channel answer EXACTLY as a
    /// channel id the server never held, the full body included, and that
    /// answer is this route's own 404 under every flag set
    async fn non_viewers_answer_as_a_missing_channel() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let e2ee = revolt_config::config().await.features.e2ee_enabled;
        let (_, member_session, member) = harness.new_user().await;
        let (_, bot_session, bot) = harness.new_user().await;
        let (_, unbound_session, unbound) = harness.new_user().await;

        let (_, hidden_owner_session, hidden_owner) = harness.new_user().await;
        let hidden = harness
            .new_protected_channel(&hidden_owner, &hidden_owner_session, &[])
            .await;
        harness
            .new_text_group(&hidden.channel, &hidden.owner_device, 0, None)
            .await;
        let hidden_protected = deny_view(&harness, &hidden.channel).await;
        let hidden_unprotected = harness.new_channel(&hidden.server).await;
        let hidden_unprotected = deny_view(&harness, &hidden_unprotected).await;

        for user in [&member, &bot, &unbound] {
            harness.join_server(&hidden.server, user).await;
        }
        harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        harness
            .new_e2ee_device(&unbound, &Ulid::new().to_string(), MEMBER_DEVICE_SEED + 1)
            .await;
        let bot = make_bot(&harness, &bot, &hidden_owner).await;

        let (_, deleted_owner_session, deleted_owner) = harness.new_user().await;
        let deleted = harness
            .new_protected_channel(&deleted_owner, &deleted_owner_session, &[])
            .await;
        db.delete_channel(&deleted.channel)
            .await
            .expect("delete the channel");
        assert!(db.fetch_channel(deleted.channel.id()).await.is_err());
        let missing_id = Ulid::new().to_string();

        // The hidden protected channel really is served to a viewer (or
        // gated, with E2EE off), so the comparison is with a live list
        let owner = get(&harness, &hidden_owner_session, hidden_protected.id()).await;
        if e2ee {
            assert_eq!(owner.0, Status::Ok, "{:?}", owner);
            assert_eq!(body(&owner)["list"]["version"], 1);
        } else {
            assert_e2ee_disabled(&owner, "hidden owner");
        }

        for (class, user, session) in [
            ("member", &member, &member_session),
            ("bot", &bot, &bot_session),
            ("unbound", &unbound, &unbound_session),
        ] {
            for channel in [&hidden_protected, &hidden_unprotected] {
                let channel = db.fetch_channel(channel.id()).await.expect("the channel");
                assert!(
                    require_channel_access(db, user, &channel).await.is_err(),
                    "{} views {}",
                    class,
                    channel.id()
                );
            }

            let missing = get(&harness, session, &missing_id).await;
            assert_own_not_found(&missing, class);
            for (target, channel_id) in [
                ("hidden protected", hidden_protected.id()),
                ("hidden unprotected", hidden_unprotected.id()),
                ("deleted", deleted.channel.id()),
            ] {
                let answer = get(&harness, session, channel_id).await;
                assert_eq!(answer, missing, "{} {}", class, target);
            }
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

    /// #152: a channel that is not protected answers with a `null` list and
    /// `null` caps, to the owner and members alike; an entitlement fills
    /// its two caps while `device_cap` stays `null` until a list exists
    async fn an_unprotected_channel_has_a_null_list_and_null_caps_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (server, channel) = harness.new_protectable_channel(&owner).await;
        harness.join_server(&server, &member).await;

        for (class, session) in [("owner", &owner_session), ("member", &member_session)] {
            let answer = get(&harness, session, channel.id()).await;
            assert_eq!(answer.0, Status::Ok, "{}: {:?}", class, answer);
            assert_eq!(answer.1, SEATS_UNPROTECTED, "{}", class);
        }

        harness
            .grant_entitlement(&channel, FIXTURE_SLOT_CAP, Some(3))
            .await;
        let answer = get(&harness, &owner_session, channel.id()).await;
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        assert_eq!(
            body(&answer),
            json!({
                "list": null,
                "as_of_epoch": null,
                "as_of_group_id": null,
                "entitlement_device_cap": 3,
                "slot_cap": FIXTURE_SLOT_CAP,
                "device_cap": null,
                "seats_used": 0,
                "seats": [],
                "cooling": [],
            })
        );
    }

    #[test]
    fn an_unprotected_channel_has_a_null_list_and_null_caps() {
        crate::util::test::rt().block_on(Box::pin(
            an_unprotected_channel_has_a_null_list_and_null_caps_case(),
        ))
    }

    /// 7.2: `device_cap` is the enforced cap, `min(signed, entitlement)`
    /// with `0` unlimited in either operand (2.5), and
    /// `entitlement_device_cap` is the effective entitlement cap
    async fn device_cap_is_the_enforced_cap_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[])
            .await;

        for (entitlement_cap, enforced) in
            [(2, 2), (0, FIXTURE_DEVICE_CAP), (9, FIXTURE_DEVICE_CAP)]
        {
            harness
                .grant_entitlement(&protected.channel, FIXTURE_SLOT_CAP, Some(entitlement_cap))
                .await;
            let answer = get(&harness, &owner_session, protected.channel.id()).await;
            assert_eq!(answer.0, Status::Ok, "{:?}", answer);
            let value = body(&answer);
            assert_eq!(value["list"]["version"], 1);
            assert_eq!(
                value["entitlement_device_cap"], entitlement_cap,
                "{entitlement_cap}"
            );
            assert_eq!(value["device_cap"], enforced, "{entitlement_cap}");
            assert_eq!(value["slot_cap"], FIXTURE_SLOT_CAP);
            assert_eq!(value["seats_used"], 1);
        }
    }

    #[test]
    fn device_cap_is_the_enforced_cap() {
        crate::util::test::rt().block_on(Box::pin(device_cap_is_the_enforced_cap_case()))
    }
}
