use std::{collections::BTreeSet, convert::TryFrom};

use revolt_config::ProtectedChannelFeatures;
use revolt_database::{
    iso8601_timestamp::Timestamp,
    mls_text_enforced_device_cap, seat_list_channel_server,
    util::{protected_access::seat_holder_lacks_access, reference::Reference},
    Channel, ChannelAuthority, ChannelAuthorityBody, ChannelEntitlement, ChannelSeat, Database,
    E2EEIdentity, SeatList, SeatListBody, SeatListSnapshot, Server, User,
};
use revolt_models::v0;
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
/// The owner-only fields (`seated_without_access`, `cooling[].cause` and
/// `revoked_owner_devices`) are computed only when the caller is the server
/// owner, by a hard id check rather than the permission calculus (which
/// grants everything to privileged accounts), and left out for everyone
/// else (7.2, DECISION (W0): other members' permission state is not
/// disclosed). Without a stored authority or an open group, the non-owner
/// answer is the S1 one byte for byte.
pub(crate) async fn channel_seats_response(
    db: &Database,
    channel: &Channel,
    caller: &User,
) -> Result<v0::ResponseChannelSeats> {
    let snapshot = db.fetch_seat_list_snapshot(channel.id()).await?;
    let entitlement = db.fetch_channel_entitlement(channel.id()).await?;
    let seats = db.fetch_channel_seats(channel.id()).await?;

    let owner_view = match owned_server(db, channel, caller).await? {
        Some(server) => Some(OwnerView {
            without_access: seats_without_access(db, channel, &server, &seats).await?,
            revoked_owner_devices: revoked_owner_devices(db, snapshot.list.as_ref()).await?,
        }),
        None => None,
    };

    let config = revolt_config::config().await;
    project_seats(
        snapshot,
        entitlement.as_ref(),
        seats,
        owner_view.as_ref(),
        &config.features.protected_channels,
        Timestamp::now_utc(),
    )
}

/// What only the server owner is told (7.2)
#[derive(Debug, Default)]
struct OwnerView {
    /// Active seat holders who lack access (6.3 "Reconciler", 6.4)
    without_access: BTreeSet<String>,
    /// The stored authority's owner devices revoked or re-keyed since it
    /// was signed (R27, #216, #231)
    revoked_owner_devices: Vec<String>,
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

/// The users holding an ACTIVE seat who lack access to the channel, by the
/// reconciler's own predicate (6.3 "Reconciler", 6.4), so the owner UI and
/// the reconciler never disagree: a missing user, a non-member (a failed
/// second release, 6.3), a bot, a privileged (staff) account, or a member
/// without ViewChannel.
///
/// The list signer is NOT exempted here. The reconciler keeps the signer's
/// seat even when the predicate matches (#222: releasing it would wedge the
/// channel) and reports it; the owner is still told, so a privileged signer
/// shows `seated_without_access: true` on their own seat.
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
        if seat_holder_lacks_access(db, user, member, channel, server).await {
            without_access.insert(user_id);
        }
    }

    Ok(without_access)
}

/// The device ids of the stored authority's `owner_devices` that have no
/// registered identity, or whose listed key differs from the directory key
/// (7.2, R27, #216, #231), read now from the directory. Empty without a
/// list or without an authority (a v1 list has none).
///
/// A stored authority that does not parse is corrupt data: this fails loud
/// rather than report no revoked device.
async fn revoked_owner_devices(db: &Database, list: Option<&SeatList>) -> Result<Vec<String>> {
    let Some(stored) = list.and_then(|list| list.authority.as_ref()) else {
        return Ok(Vec::new());
    };
    let authority = ChannelAuthority::parse(&stored.body).map_err(|error| {
        log::error!("stored channel authority does not parse: {error:?}");
        create_error!(InternalError)
    })?;
    let identities = db.fetch_e2ee_identities(&authority.owner_user_id).await?;
    Ok(owner_devices_not_in_directory(&authority, &identities))
}

/// [`revoked_owner_devices`] against `identities`, in `owner_devices` order:
/// an entry counts as present only for an identity of the authority's owner
/// user with the same device id AND the same Ed25519 key
fn owner_devices_not_in_directory(
    authority: &ChannelAuthorityBody,
    identities: &[E2EEIdentity],
) -> Vec<String> {
    authority
        .owner_devices
        .iter()
        .filter(|listed| {
            !identities.iter().any(|identity| {
                identity.user_id == authority.owner_user_id
                    && identity.device_id == listed.device_id
                    && identity.ed25519_key == listed.identity_key
            })
        })
        .map(|listed| listed.device_id.clone())
        .collect()
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
///
/// `as_of_generation` comes from the same snapshot's group as `as_of_epoch`
/// and `as_of_group_id` (S2-D33). `owner` is `Some` exactly for the server
/// owner: it alone carries `seated_without_access`, the cooling `cause` and
/// `revoked_owner_devices`.
fn project_seats(
    snapshot: SeatListSnapshot,
    entitlement: Option<&ChannelEntitlement>,
    seats: Vec<ChannelSeat>,
    owner: Option<&OwnerView>,
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
            let lost_access = owner.map(|owner| owner.without_access.contains(&seat.user_id));
            let mut info = seat.into_seat_info();
            info.seated_without_access = lost_access;
            active.push(info);
        } else if seat.is_cooling(now) {
            cooling.extend(match owner {
                Some(_) => seat.into_owner_cooling_info(),
                None => seat.into_cooling_info(),
            });
        }
    }
    let seats_used =
        u32::try_from(active.len() + cooling.len()).map_err(|_| create_error!(InternalError))?;

    Ok(v0::ResponseChannelSeats {
        as_of_epoch: snapshot
            .text_group
            .as_ref()
            .map(|group| group.current_epoch),
        as_of_generation: snapshot
            .text_group
            .as_ref()
            .and_then(|group| group.generation),
        as_of_group_id: snapshot.text_group.map(|group| group.id),
        list: snapshot.list.map(Into::into),
        entitlement_device_cap,
        slot_cap: entitlement.map(|entitlement| entitlement.slot_cap),
        device_cap,
        seats_used,
        seats: active,
        cooling,
        revoked_owner_devices: owner
            .map(|owner| owner.revoked_owner_devices.clone())
            .unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use revolt_config::ProtectedChannelFeatures;
    use revolt_database::{
        iso8601_timestamp::Timestamp,
        util::protected_access::{reconcile_channel, seat_holder_lacks_access},
        AuthorityOwnerDevice, BotInformation, Channel, ChannelAuthority, ChannelAuthorityBody,
        ChannelSeat, Database, MemberCompositeKey, PartialChannel, PartialMember, PartialUser,
        SeatList, SeatListBody, SeatListHistory, SeatListPreHistory, SeatListSnapshot,
        SeatListV2Lines, SeatReleaseCause, Server, Session, SignedAuthority, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{Header, Status};
    use serde_json::{json, Value};
    use ulid::Ulid;

    use super::{owner_devices_not_in_directory, project_seats, OwnerView};
    use crate::routes::mls::{require_channel_access, text::text_group_id};
    use crate::util::test::{
        ProtectedChannel, TestE2EEDevice, TestHarness, FIXTURE_DEVICE_CAP, FIXTURE_ISSUED_AT,
        FIXTURE_SLOT_CAP, MEMBER_DEVICE_SEED,
    };

    /// Key seeds of the owner's extra devices in the authority tests, clear
    /// of the harness seeds (0x00 owner, 0x20 member, 0x80 new owner)
    const REKEYED_DEVICE_SEED: u8 = 0x40;
    const LISTED_KEY_SEED: u8 = 0x60;
    const ABSENT_DEVICE_SEED: u8 = 0xa0;
    const ABSENT_DEVICE_ID: &str = "0123456789abcdef0123456789abcdef";

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

    /// Take ViewChannel from `user` on `channel` through a role override
    /// on a new role given to them. Through `update`: the Reference
    /// driver's `set_channel_role_permission` only replaces an override
    /// that already exists.
    async fn deny_view_to(harness: &TestHarness, server: &Server, channel: &Channel, user: &User) {
        let db = &harness.db;
        let role = harness.new_role(server, 1, None).await;
        let mut channel = channel.clone();
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
            &member_key(&server.id, &user.id),
            &PartialMember {
                roles: Some(vec![role.id.clone()]),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("give the user the role");
    }

    async fn make_privileged(harness: &TestHarness, user: &User) -> User {
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
            .expect("make the user privileged");
        let user = harness.db.fetch_user(&user.id).await.expect("the user");
        assert!(user.privileged);
        user
    }

    /// Overwrite `row.id`'s stored seat list straight in the store: no
    /// write rule (nor the `formats_v2` flag) runs, only the read is under
    /// test
    async fn replace_seat_list(harness: &TestHarness, row: &SeatList) {
        match &harness.db {
            Database::Reference(reference) => {
                let mut lists = reference.channel_seat_lists.lock().await;
                assert!(lists.contains_key(&row.id), "the seat list row");
                lists.insert(row.id.clone(), row.clone());
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::doc;

                let result = mongo
                    .col::<SeatList>("channel_seat_lists")
                    .replace_one(doc! { "_id": &row.id }, row)
                    .await
                    .expect("the seat list write");
                assert_eq!(result.matched_count, 1, "the seat list row");
            }
        }
    }

    /// A protected channel with its generation-0 Text group, whose list is
    /// at version 2, and every kind of seat:
    /// - `member`: seated, can view;
    /// - `blind`: seated, lost ViewChannel through a role override;
    /// - `gone`: seated, no longer a server member (a failed second
    ///   release, 6.3);
    /// - `leaver`: had received the keys, unseated by the v2 list, so
    ///   cooling.
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
        harness
            .mark_keys_received(protected.channel.id(), &leaver.id)
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

        deny_view_to(&harness, &protected.server, &protected.channel, &blind).await;
        db.force_delete_member(&member_key(&server_id, &gone.id))
            .await
            .expect("drop gone's membership");

        harness.join_server(&protected.server, &bot).await;
        let bot = make_bot(&harness, &bot, &owner).await;
        let staff = make_privileged(&harness, &staff).await;

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
    /// `owner_view` adds `seated_without_access` to every seat and the
    /// release `cause` to the cooling seat. S2 (7.2, S2-D33):
    /// `as_of_generation` is the open group's generation for every viewer;
    /// the v1 list has no authority, so `revoked_owner_devices` stays absent
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
                assert_eq!(seat.release_cause, Some(SeatReleaseCause::OwnerUnseat));
                let mut entry = json!({
                    "user_id": seat.user_id,
                    "released_at": seat.released_at,
                    "cooldown_until": seat.cooldown_until,
                });
                if owner_view {
                    entry["cause"] = json!("owner_unseat");
                }
                cooling.push(entry);
            }
        }
        assert_eq!((seats.len(), cooling.len()), (4, 1));
        assert!(list.authority.is_none());

        json!({
            "list": v0::ChannelSeatListInfo::from(list),
            "as_of_epoch": 0,
            "as_of_group_id": text_group_id(channel_id, 0),
            "as_of_generation": 0,
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
    /// even staff, whom the permission calculus grants everything, nor
    /// (S2, 7.2) why a seat was released or which owner devices were
    /// revoked; the rest of the answer is the owner's
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
            for owner_only in [
                "seated_without_access",
                "\"cause\"",
                "revoked_owner_devices",
            ] {
                assert!(
                    !answer.1.contains(owner_only),
                    "{}: {} leaked: {}",
                    class,
                    owner_only,
                    answer.1
                );
            }
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
            release_cause: released_at.map(|_| SeatReleaseCause::OwnerUnseat),
            keys_received_at: None,
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
        let owner = OwnerView {
            without_access: BTreeSet::from(["active".to_string()]),
            revoked_owner_devices: vec![],
        };

        for owner_view in [None, Some(&owner)] {
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
            assert_eq!(
                response.cooling[0].cause,
                owner_view.map(|_| v0::SeatReleaseCauseInfo::OwnerUnseat)
            );
            assert_eq!(response.as_of_generation, None);
            assert!(response.revoked_owner_devices.is_empty());
            assert_eq!(response.seats.len(), 1);
            assert_eq!(response.seats[0].user_id, "active");
            assert_eq!(
                response.seats[0].seated_without_access,
                owner_view.map(|_| true)
            );
            assert_eq!(response.seats_used, 2);
        }
    }

    /// 2.3 (S2-D21): a seat released before its user received the keys
    /// (`DeviceNeverJoined`, no cooldown) is free: neither listed as
    /// cooling nor counted
    #[test]
    fn a_never_joined_release_is_not_cooling() {
        let now = at("2026-10-20T00:00:00.000Z");
        let mut never_joined = seat("never_joined", Some("2026-10-19T00:00:00.000Z"), None);
        never_joined.release_cause = Some(SeatReleaseCause::DeviceNeverJoined);
        let response = project_seats(
            SeatListSnapshot {
                list: None,
                text_group: None,
            },
            None,
            vec![seat("active", None, None), never_joined],
            None,
            &ProtectedChannelFeatures::default(),
            now,
        )
        .expect("projected");

        assert!(response.cooling.is_empty(), "{:?}", response.cooling);
        assert_eq!(response.seats.len(), 1);
        assert_eq!(response.seats_used, 1);
    }

    /// 7.2: `revoked_owner_devices` is the owner view's, and serializes
    /// only when non-empty (absent = empty)
    #[test]
    fn revoked_owner_devices_follow_the_owner_view() {
        let now = at("2026-10-20T00:00:00.000Z");
        let owner = OwnerView {
            without_access: BTreeSet::new(),
            revoked_owner_devices: vec!["revoked".to_string()],
        };
        for (owner_view, expected) in [(None, vec![]), (Some(&owner), vec!["revoked"])] {
            let response = project_seats(
                SeatListSnapshot {
                    list: None,
                    text_group: None,
                },
                None,
                vec![],
                owner_view,
                &ProtectedChannelFeatures::default(),
                now,
            )
            .expect("projected");
            assert_eq!(response.revoked_owner_devices, expected);
            let value = serde_json::to_value(&response).expect("serialized");
            assert_eq!(
                value.get("revoked_owner_devices").is_some(),
                owner_view.is_some(),
                "{value}"
            );
        }
    }

    /// An authority over `devices` (device id, listed key) by the first
    fn authority_over(owner_user_id: &str, devices: &[(&str, String)]) -> ChannelAuthorityBody {
        ChannelAuthorityBody {
            channel_id: "01J9Z3K4M5N6P7Q8R9S0T1V2W3".to_string(),
            version: 1,
            owner_user_id: owner_user_id.to_string(),
            signer_device_id: devices[0].0.to_string(),
            issued_at: FIXTURE_ISSUED_AT,
            owner_devices: devices
                .iter()
                .map(|(device_id, identity_key)| AuthorityOwnerDevice {
                    device_id: device_id.to_string(),
                    identity_key: identity_key.clone(),
                })
                .collect(),
            delegates: vec![],
            delegate_max_device_cap: 0,
            successors: vec![],
            prev: None,
        }
    }

    /// R27, #216, #231: an `owner_devices` entry is revoked when the
    /// directory has no identity for it, or one under another key; an
    /// identity of another user with the same device id does not count
    #[test]
    fn owner_devices_missing_or_rekeyed_are_revoked() {
        let owner = "01HZXAAAAAAAAAAAAAAAAAAAAA";
        let other_user = "01HZXBBBBBBBBBBBBBBBBBBBBB";
        let kept = TestE2EEDevice::new(owner, "00112233445566778899aabbccddeeff", 0x00, "s");
        let rekeyed = TestE2EEDevice::new(
            owner,
            "ffeeddccbbaa99887766554433221100",
            REKEYED_DEVICE_SEED,
            "s",
        );
        let listed_key =
            TestE2EEDevice::new(owner, &rekeyed.device_id, LISTED_KEY_SEED, "s").identity_key();
        let absent = TestE2EEDevice::new(owner, ABSENT_DEVICE_ID, ABSENT_DEVICE_SEED, "s");
        let elsewhere = TestE2EEDevice::new(other_user, ABSENT_DEVICE_ID, ABSENT_DEVICE_SEED, "s");
        assert_ne!(rekeyed.identity_key(), listed_key);

        let authority = authority_over(
            owner,
            &[
                (kept.device_id.as_str(), kept.identity_key()),
                (rekeyed.device_id.as_str(), listed_key),
                (absent.device_id.as_str(), absent.identity_key()),
            ],
        );
        let directory = vec![
            kept.identity.clone(),
            rekeyed.identity.clone(),
            elsewhere.identity.clone(),
        ];
        assert_eq!(
            owner_devices_not_in_directory(&authority, &directory),
            vec![rekeyed.device_id.clone(), absent.device_id.clone()]
        );
        assert_eq!(owner_devices_not_in_directory(&authority, &[]).len(), 3);
    }

    /// 7.2 (R27, #216, #231), end to end: the owner is told which devices
    /// of the stored authority are gone from the directory or re-keyed,
    /// computed at read time; a member is not. `list.authority` passes
    /// through to every viewer.
    async fn the_owner_sees_revoked_owner_devices_case() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let channel_id = protected.channel.id();
        let kept = &protected.owner_device;
        let rekeyed = harness
            .new_e2ee_device(&owner, &Ulid::new().to_string(), REKEYED_DEVICE_SEED)
            .await;
        let listed_key =
            TestE2EEDevice::new(&owner.id, &rekeyed.device_id, LISTED_KEY_SEED, "s").identity_key();
        let absent = TestE2EEDevice::new(&owner.id, ABSENT_DEVICE_ID, ABSENT_DEVICE_SEED, "s");
        assert_ne!(rekeyed.identity_key(), listed_key);
        assert!(db
            .fetch_e2ee_identity(&owner.id, ABSENT_DEVICE_ID)
            .await
            .is_err());

        let mut authority = authority_over(
            &owner.id,
            &[
                (kept.device_id.as_str(), kept.identity_key()),
                (rekeyed.device_id.as_str(), listed_key),
                (absent.device_id.as_str(), absent.identity_key()),
            ],
        );
        authority.channel_id = channel_id.to_string();
        let authority_body = ChannelAuthority::build(&authority).expect("a canonical authority");
        let stored_authority = SignedAuthority {
            signature: kept.sign(&authority_body),
            body: authority_body,
        };
        let list_body = SeatListBody {
            channel_id: channel_id.to_string(),
            version: 1,
            device_cap: FIXTURE_DEVICE_CAP,
            issued_at: FIXTURE_ISSUED_AT,
            signer_user_id: owner.id.clone(),
            signer_device_id: kept.device_id.clone(),
            seats: vec![owner.id.clone(), member.id.clone()],
            v2: Some(SeatListV2Lines {
                authority_sha256: Some(ChannelAuthority::sha256(&stored_authority.body)),
                history: SeatListHistory::Visible,
                history_boundary: None,
                pre_history: SeatListPreHistory::Kept,
                group_salt: "5a".repeat(32),
            }),
        }
        .build()
        .expect("a canonical v2 body");
        let mut row = db
            .fetch_seat_list(channel_id)
            .await
            .expect("read")
            .expect("the genesis list");
        row.signature = kept.sign(&list_body);
        row.body = list_body;
        row.authority = Some(stored_authority.clone());
        replace_seat_list(&harness, &row).await;

        let served_authority = json!({
            "body": stored_authority.body,
            "signature": stored_authority.signature,
        });

        let answer = get(&harness, &owner_session, channel_id).await;
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        let value = body(&answer);
        assert_eq!(value["list"]["authority"], served_authority, "{}", answer.1);
        let revoked = value["revoked_owner_devices"]
            .as_array()
            .unwrap_or_else(|| panic!("revoked_owner_devices: {}", answer.1));
        let revoked: BTreeSet<&str> = revoked
            .iter()
            .map(|device| device.as_str().expect("a device id"))
            .collect();
        assert_eq!(
            revoked,
            BTreeSet::from([rekeyed.device_id.as_str(), absent.device_id.as_str()]),
            "{}",
            answer.1
        );

        let answer = get(&harness, &member_session, channel_id).await;
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        assert!(!answer.1.contains("revoked_owner_devices"), "{}", answer.1);
        assert_eq!(body(&answer)["list"]["authority"], served_authority);
    }

    #[test]
    fn the_owner_sees_revoked_owner_devices() {
        crate::util::test::rt().block_on(Box::pin(the_owner_sees_revoked_owner_devices_case()))
    }

    /// 6.3 "Reconciler", 6.4: `seated_without_access` is the reconciler's
    /// predicate, so a bot and a staff account holding a seat are flagged
    /// although the permission calculus lets them view the channel
    async fn seated_without_access_is_the_reconciler_predicate_case() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, _, member) = harness.new_user().await;
        let (_, _, bot) = harness.new_user().await;
        let (_, _, staff) = harness.new_user().await;
        let (_, _, blind) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member, &bot, &staff, &blind])
            .await;
        let channel_id = protected.channel.id();
        let bot = make_bot(&harness, &bot, &owner).await;
        let staff = make_privileged(&harness, &staff).await;
        deny_view_to(&harness, &protected.server, &protected.channel, &blind).await;

        // The bot and staff really can view, so only the predicate's own
        // bot and privileged checks flag them
        let channel = db.fetch_channel(channel_id).await.expect("read");
        let server = db.fetch_server(&protected.server.id).await.expect("read");
        for (who, user, views) in [
            ("owner", &owner, true),
            ("member", &member, true),
            ("bot", &bot, true),
            ("staff", &staff, true),
            ("blind", &blind, false),
        ] {
            let user = db.fetch_user(&user.id).await.expect("the user");
            assert_eq!(
                require_channel_access(db, &user, &channel).await.is_ok(),
                views,
                "{who}"
            );
        }

        let answer = get(&harness, &owner_session, channel_id).await;
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        let value = body(&answer);
        let seats = value["seats"].as_array().expect("seats");
        assert_eq!(seats.len(), 5, "{}", answer.1);

        let mut flagged = BTreeSet::new();
        for seat in seats {
            let user_id = seat["user_id"].as_str().expect("user_id");
            let user = db.fetch_user(user_id).await.ok();
            let member = db.fetch_member(&server.id, user_id).await.ok();
            let lacks =
                seat_holder_lacks_access(db, user.as_ref(), member.as_ref(), &channel, &server)
                    .await;
            assert_eq!(
                seat["seated_without_access"],
                json!(lacks),
                "{user_id}: {}",
                answer.1
            );
            if lacks {
                flagged.insert(user_id.to_string());
            }
        }
        assert_eq!(
            flagged,
            BTreeSet::from([bot.id.clone(), staff.id.clone(), blind.id.clone()])
        );
    }

    #[test]
    fn seated_without_access_is_the_reconciler_predicate() {
        crate::util::test::rt().block_on(Box::pin(
            seated_without_access_is_the_reconciler_predicate_case(),
        ))
    }

    /// #222: the reconciler keeps a privileged list signer's seat; the
    /// owner view still reads the bare predicate and flags it, so the owner
    /// sees the state the reconciler declined to repair
    async fn a_privileged_signer_is_flagged_but_kept_case() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, _, member) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let channel_id = protected.channel.id();
        let owner = make_privileged(&harness, &owner).await;

        let flags = |value: &Value| -> Vec<(String, Value)> {
            let mut flags: Vec<(String, Value)> = value["seats"]
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
            flags.sort_by(|a, b| a.0.cmp(&b.0));
            flags
        };
        let mut expected = vec![
            (owner.id.clone(), json!(true)),
            (member.id.clone(), json!(false)),
        ];
        expected.sort_by(|a, b| a.0.cmp(&b.0));

        let answer = get(&harness, &owner_session, channel_id).await;
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        assert_eq!(flags(&body(&answer)), expected, "{}", answer.1);

        let released = reconcile_channel(db, channel_id).await.expect("reconciled");
        assert!(released.is_empty(), "{released:?}");
        let seats = db.fetch_channel_seats(channel_id).await.expect("seats");
        assert!(seats
            .iter()
            .any(|seat| seat.user_id == owner.id && seat.is_active()));

        let answer = get(&harness, &owner_session, channel_id).await;
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        assert_eq!(flags(&body(&answer)), expected, "{}", answer.1);
    }

    #[test]
    fn a_privileged_signer_is_flagged_but_kept() {
        crate::util::test::rt().block_on(Box::pin(a_privileged_signer_is_flagged_but_kept_case()))
    }

    /// S2-D33: `as_of_generation` is the open Text group's generation, to
    /// every viewer, from the snapshot that gives `as_of_group_id`; absent
    /// without an open group
    async fn as_of_generation_is_the_open_groups_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let channel_id = protected.channel.id();

        for session in [&owner_session, &member_session] {
            let answer = get(&harness, session, channel_id).await;
            assert_eq!(answer.0, Status::Ok, "{:?}", answer);
            let value = body(&answer);
            assert_eq!(value["as_of_group_id"], Value::Null, "{}", answer.1);
            assert!(value.get("as_of_generation").is_none(), "{}", answer.1);
        }

        let first = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let second = harness
            .new_text_group(
                &protected.channel,
                &protected.owner_device,
                1,
                Some(&first.id),
            )
            .await;
        assert_eq!(second.id, text_group_id(channel_id, 1));

        for session in [&owner_session, &member_session] {
            let answer = get(&harness, session, channel_id).await;
            assert_eq!(answer.0, Status::Ok, "{:?}", answer);
            let value = body(&answer);
            assert_eq!(value["as_of_group_id"], second.id.as_str(), "{}", answer.1);
            assert_eq!(value["as_of_epoch"], second.current_epoch, "{}", answer.1);
            assert_eq!(value["as_of_generation"], 1, "{}", answer.1);
        }
    }

    #[test]
    fn as_of_generation_is_the_open_groups() {
        crate::util::test::rt().block_on(Box::pin(as_of_generation_is_the_open_groups_case()))
    }

    /// S1 compatibility (7.2): on a v1 channel without an open group a
    /// non-owner gets the S1 answer byte for byte, although the cooling
    /// seat's row stores a release cause (which the owner is shown)
    async fn a_non_owner_gets_the_s1_answer_on_a_v1_channel_case() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, _, leaver) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member, &leaver])
            .await;
        let channel_id = protected.channel.id();
        harness.mark_keys_received(channel_id, &leaver.id).await;
        let v2 = protected.owner_device.seat_list(
            channel_id,
            2,
            FIXTURE_DEVICE_CAP,
            &[owner.id.as_str(), member.id.as_str()],
        );
        harness.put_seats_with_db(&protected.channel, &v2).await;

        let list = db
            .fetch_seat_list(channel_id)
            .await
            .expect("read")
            .expect("a list");
        assert!(list.authority.is_none());
        let rows = db.fetch_channel_seats(channel_id).await.expect("seats");
        assert!(
            rows.iter()
                .any(|seat| seat.user_id == leaver.id && seat.release_cause.is_some()),
            "the cooling row stores its cause: {rows:?}"
        );

        let text = |value: &str| serde_json::to_string(value).expect("a string");
        let instant = |value: &Timestamp| serde_json::to_string(value).expect("a timestamp");
        let mut seats = vec![];
        let mut cooling = vec![];
        for seat in &rows {
            match (&seat.released_at, &seat.cooldown_until) {
                (None, _) => seats.push(format!(
                    r#"{{"user_id":{},"seated_at":{}}}"#,
                    text(seat.user_id.as_str()),
                    instant(&seat.seated_at)
                )),
                (Some(released_at), Some(cooldown_until)) => cooling.push(format!(
                    r#"{{"user_id":{},"released_at":{},"cooldown_until":{}}}"#,
                    text(seat.user_id.as_str()),
                    instant(released_at),
                    instant(cooldown_until)
                )),
                (Some(_), None) => panic!("a release without a cooldown: {seat:?}"),
            }
        }
        assert_eq!((seats.len(), cooling.len()), (2, 1));
        let s1 = format!(
            r#"{{"list":{{"version":2,"body":{},"signature":{},"signer_user_id":{},"signer_device_id":{},"handovers":[]}},"as_of_epoch":null,"as_of_group_id":null,"entitlement_device_cap":{FIXTURE_DEVICE_CAP},"slot_cap":{FIXTURE_SLOT_CAP},"device_cap":{FIXTURE_DEVICE_CAP},"seats_used":3,"seats":[{}],"cooling":[{}]}}"#,
            text(list.body.as_str()),
            text(list.signature.as_str()),
            text(list.signer_user_id.as_str()),
            text(list.signer_device_id.as_str()),
            seats.join(","),
            cooling.join(",")
        );

        let answer = get(&harness, &member_session, channel_id).await;
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        assert_eq!(answer.1, s1);

        // The owner IS told the cause
        let answer = get(&harness, &owner_session, channel_id).await;
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        assert_eq!(
            body(&answer)["cooling"][0]["cause"],
            "owner_unseat",
            "{}",
            answer.1
        );
    }

    #[test]
    fn a_non_owner_gets_the_s1_answer_on_a_v1_channel() {
        crate::util::test::rt().block_on(Box::pin(
            a_non_owner_gets_the_s1_answer_on_a_v1_channel_case(),
        ))
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
