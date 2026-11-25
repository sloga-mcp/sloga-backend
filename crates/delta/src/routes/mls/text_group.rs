use std::collections::HashSet;

use iso8601_timestamp::{Duration, Timestamp};
use revolt_database::{
    mls_text_rejoin_window_seconds, util::reference::Reference, Database, MlsGroup, MlsGroupKind,
    Session, User,
};
use revolt_models::v0::{self, UserFlags};
use revolt_result::{create_error, Error, ErrorType, Result};
use rocket::{serde::json::Json, State};

use super::TextGate;

/// # Fetch Text Group
///
/// The channel's open protected-channel Text group (protected-channels
/// design §7.2): id, generation, epoch, roster, pending removals and
/// `member_added`. ViewChannel; the MLS caller checks (not a bot, a session
/// bound to one of the caller's devices); maintenance gate. The media flag
/// plays no part. 404 when the channel has no open Text group.
///
/// A SEATED caller also gets `join_requests`, `pending_device_removals` and
/// `signer_lost` (S2, §6.3 "Async Text join", R24, #222, #228). An unseated
/// viewer gets the S1 body, byte for byte.
///
/// A missing channel, and a channel the caller cannot view, get that same
/// 404 before any other check (decision 18 (W2)), so a non-viewer cannot
/// tell a protected channel from an unprotected one, or from no channel.
#[openapi(tag = "MLS")]
#[get("/channels/<channel_id>/text_group")]
pub async fn fetch_text_group(
    db: &State<Database>,
    user: User,
    session: Session,
    channel_id: String,
) -> Result<Json<v0::ResponseTextGroup>> {
    // ANY failure to read the channel answers as a missing channel
    let Ok(channel) = Reference::from_unchecked(&channel_id).as_channel(db).await else {
        return Err(no_text_group());
    };
    if super::require_channel_access(db, &user, &channel)
        .await
        .is_err()
    {
        return Err(no_text_group());
    }

    super::require_mls_caller(db, &user, Some(&session)).await?;
    super::require_text_gate(TextGate::Available).await?;

    // §7.2 makes ViewChannel the whole access rule for this read, with no
    // seat: a seated member's device reads it BEFORE it joins (§6.3 "Seat
    // a member"). An unprotected channel never has a Text group.
    let group = db
        .fetch_open_mls_group_for_channel(channel.id(), MlsGroupKind::Text)
        .await?
        .ok_or_else(no_text_group)?;

    // Seated = an ACTIVE seat in this channel, `require_seated`'s predicate
    // (§2.3: a cooling seat is not a seat), read once for the caller and
    // for the intent filter alike
    let seated: HashSet<String> = db
        .fetch_channel_seats(channel.id())
        .await?
        .into_iter()
        .filter(|seat| seat.channel_id == channel.id() && seat.is_active())
        .map(|seat| seat.user_id)
        .collect();
    let response = if seated.contains(&user.id) {
        seated_response(db, &user, channel.id(), &seated, group).await?
    } else {
        group.into_text_group_response()
    };

    // A stored Text group always carries its generation. One without is
    // corrupt, and a 404 would invite a fresh create over it.
    response
        .map(Json)
        .ok_or_else(|| create_error!(InternalError))
}

/// The seated caller's body (§7.2): the stored join intents of SEATED users
/// still inside the Text window (§6.3 "Async Text join"; the bridge keeps
/// those of this group newer than the device's `member_added.at`), the
/// pending device removals and `signer_lost`, relabelled
/// `account_unavailable` while the signer user's account is unavailable
/// (#222), or derived for the signer user when nothing is stored (#228)
async fn seated_response(
    db: &Database,
    user: &User,
    channel_id: &str,
    seated: &HashSet<String>,
    group: MlsGroup,
) -> Result<Option<v0::ResponseTextGroup>> {
    let window = mls_text_rejoin_window_seconds(
        revolt_config::config()
            .await
            .features
            .protected_channels
            .text_rejoin_window_secs,
    );
    // The driver's rule-6 bound (`created_at >= start`). A window reaching
    // before the epoch has no lower bound.
    let window_start = Timestamp::now_utc().checked_sub(Duration::seconds(window));
    let intents: Vec<_> = db
        .fetch_mls_join_intents_for_group(&group.id)
        .await?
        .into_iter()
        .filter(|intent| seated.contains(&intent.user_id))
        .filter(|intent| window_start.is_none_or(|start| intent.created_at >= start))
        .collect();

    let signer_account_unavailable = match &group.signer_lost {
        Some(lost) => signer_user_unavailable(db, &lost.user_id).await?,
        None => false,
    };

    let Some(mut response) =
        group.into_text_group_response_for_seated(intents, signer_account_unavailable)
    else {
        return Ok(None);
    };
    if response.signer_lost.is_none() {
        response.signer_lost = derived_signer_lost(db, user, channel_id).await?;
    }

    Ok(Some(response))
}

/// Whether `user`'s account is unavailable at `now` (#222): Deleted,
/// Banned, or SuspendedUntil while the suspension is in effect. An elapsed
/// timed suspension keeps its flag until the next login, so its end time
/// decides; one without an end time is indefinite.
fn account_unavailable(user: &User, now: Timestamp) -> bool {
    let flags = user.flags.unwrap_or_default();
    if flags & (UserFlags::Deleted as i32 | UserFlags::Banned as i32) != 0 {
        return true;
    }

    flags & UserFlags::SuspendedUntil as i32 != 0
        && user
            .suspended_until
            .as_ref()
            .is_none_or(|until| *until > now)
}

/// [`account_unavailable`] for the stored `signer_lost`'s user, read now.
/// A signer user with no user row at all is unavailable too.
async fn signer_user_unavailable(db: &Database, user_id: &str) -> Result<bool> {
    match db.fetch_user(user_id).await {
        Ok(signer) => Ok(account_unavailable(&signer, Timestamp::now_utc())),
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => Ok(true),
        Err(error) => Err(error),
    }
}

/// #228: for a caller who is the stored list's signer USER, a `signer_lost`
/// derived at read time when none is stored but the list's signer device
/// has no registered identity (the authority-less solo owner, a revocation
/// with `formats_v2` off), so its UI can offer recovery. Never stored, and
/// send gating still reads the stored flag only (§7.2). The cause follows
/// #222; `at` is the list's `updated_at` (no loss time is recorded, and a
/// fixed value keeps repeated reads equal).
async fn derived_signer_lost(
    db: &Database,
    user: &User,
    channel_id: &str,
) -> Result<Option<v0::MlsSignerLostInfo>> {
    let Some(list) = db.fetch_seat_list(channel_id).await? else {
        return Ok(None);
    };
    if list.signer_user_id != user.id {
        return Ok(None);
    }

    match db
        .fetch_e2ee_identity(&list.signer_user_id, &list.signer_device_id)
        .await
    {
        Ok(_) => return Ok(None),
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => {}
        Err(error) => return Err(error),
    }

    let cause = if account_unavailable(user, Timestamp::now_utc()) {
        v0::MlsSignerLostCause::AccountUnavailable
    } else {
        v0::MlsSignerLostCause::DeviceRevoked
    };
    Ok(Some(v0::MlsSignerLostInfo {
        user_id: list.signer_user_id,
        device_id: list.signer_device_id,
        cause,
        at: list.updated_at,
    }))
}

/// The one `NotFound` this route answers, for a missing channel, a channel
/// the caller cannot view and a channel with no open Text group alike (one
/// source site; error locations no longer serialize, so this is hygiene)
fn no_text_group() -> Error {
    create_error!(NotFound)
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{
        mls_text_rejoin_window_seconds, BotInformation, Channel, ChannelSeat, Database, FieldsUser,
        MlsGroup, MlsJoinIntent, MlsPendingDeviceRemoval, MlsSignerLost, PartialChannel,
        PartialUser, SeatReleaseCause, Session, User,
    };
    use revolt_models::v0::UserFlags;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{Header, Status};
    use ulid::Ulid;

    use super::super::{require_channel_access, text::text_group_id};
    use crate::util::test::{
        TestHarness, FIXTURE_ISSUED_AT, MEMBER_DEVICE_SEED, NEW_OWNER_DEVICE_SEED,
    };

    /// One caller of the matrix, with the session it calls under
    struct Caller {
        class: &'static str,
        user: User,
        session: Session,
    }

    struct Fixture {
        harness: TestHarness,
        /// A member (seated, bound), a bot (a member, no device), a member
        /// with an unbound session, and a bound user who is in neither
        /// server
        callers: Vec<Caller>,
        /// Protected, visible to the members of its server, with its
        /// generation-0 Text group; the member class is seated in it
        protected: Channel,
        /// Unprotected, visible to the members of the same server
        visible_unprotected: Channel,
        /// Protected, with a Text group, that no member may view
        hidden_protected: Channel,
        /// Its owner, who can view it
        hidden_owner_session: Session,
        /// Unprotected, in the same server, that no member may view
        hidden_unprotected: Channel,
        /// A protected channel deleted under its Text group
        deleted_id: String,
        /// A channel id the server never held
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

    async fn fixture() -> Fixture {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, bot_session, bot) = harness.new_user().await;
        let (_, unbound_session, unbound) = harness.new_user().await;
        let (_, outsider_session, outsider) = harness.new_user().await;

        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let visible_unprotected = harness.new_channel(&protected.server).await;

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

        for user in [&bot, &unbound] {
            harness.join_server(&protected.server, user).await;
        }
        for user in [&member, &bot, &unbound] {
            harness.join_server(&hidden.server, user).await;
        }
        harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        harness
            .new_e2ee_device(&unbound, &Ulid::new().to_string(), MEMBER_DEVICE_SEED + 1)
            .await;
        harness
            .new_e2ee_device(&outsider, &outsider_session.id, MEMBER_DEVICE_SEED + 2)
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

        let (_, deleted_owner_session, deleted_owner) = harness.new_user().await;
        let deleted = harness
            .new_protected_channel(&deleted_owner, &deleted_owner_session, &[])
            .await;
        harness
            .new_text_group(&deleted.channel, &deleted.owner_device, 0, None)
            .await;
        db.delete_channel(&deleted.channel)
            .await
            .expect("delete the channel");
        assert!(db.fetch_channel(deleted.channel.id()).await.is_err());

        Fixture {
            callers: vec![
                Caller {
                    class: "member",
                    user: member,
                    session: member_session,
                },
                Caller {
                    class: "bot",
                    user: bot,
                    session: bot_session,
                },
                Caller {
                    class: "unbound",
                    user: unbound,
                    session: unbound_session,
                },
                Caller {
                    class: "outsider",
                    user: outsider,
                    session: outsider_session,
                },
            ],
            protected: protected.channel,
            visible_unprotected,
            hidden_protected,
            hidden_owner_session,
            hidden_unprotected,
            deleted_id: deleted.channel.id().to_string(),
            missing_id: Ulid::new().to_string(),
            harness,
        }
    }

    /// The route's full answer: status and body
    async fn get(harness: &TestHarness, session: &Session, channel_id: &str) -> (Status, String) {
        let response = harness
            .client
            .get(format!("/mls/channels/{channel_id}/text_group"))
            .header(Header::new("x-session-token", session.token.clone()))
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    #[track_caller]
    fn body(answer: &(Status, String)) -> serde_json::Value {
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
    fn assert_type(answer: &(Status, String), expected: &str, case: &str) {
        assert_eq!(body(answer)["type"], expected, "{}: {:?}", case, answer);
    }

    #[track_caller]
    fn assert_e2ee_disabled(answer: &(Status, String), case: &str) {
        assert_eq!(answer.0, Status::BadRequest, "{}: {:?}", case, answer);
        let value = body(answer);
        assert_eq!(value["type"], "FeatureDisabled", "{}: {}", case, answer.1);
        assert_eq!(value["feature"], "e2ee", "{}: {}", case, answer.1);
    }

    /// The stored group as the route must serve it
    async fn expected_response(fixture: &Fixture, channel: &Channel) -> serde_json::Value {
        let group = fixture
            .harness
            .db
            .fetch_open_mls_group_for_channel(channel.id(), revolt_database::MlsGroupKind::Text)
            .await
            .expect("read")
            .expect("an open Text group");
        serde_json::to_value(group.into_text_group_response().expect("a Text group")).expect("JSON")
    }

    /// Decision 18 (W2): for every caller class, a channel the caller cannot
    /// view (protected or not) and a deleted channel answer EXACTLY as a
    /// channel id the server never held, the full body included, and that
    /// answer is this route's own 404 under every flag set
    async fn non_viewers_answer_as_a_missing_channel() {
        let fixture = Box::pin(fixture()).await;
        let db = &fixture.harness.db;
        let e2ee = revolt_config::config().await.features.e2ee_enabled;

        // The hidden protected channel really is served to a viewer (or
        // gated, with E2EE off), so the comparison is with a live group
        let owner = get(
            &fixture.harness,
            &fixture.hidden_owner_session,
            fixture.hidden_protected.id(),
        )
        .await;
        if e2ee {
            assert_eq!(owner.0, Status::Ok, "{:?}", owner);
            assert_eq!(
                body(&owner),
                expected_response(&fixture, &fixture.hidden_protected).await
            );
        } else {
            assert_e2ee_disabled(&owner, "hidden owner");
        }

        for caller in &fixture.callers {
            for channel in [&fixture.hidden_protected, &fixture.hidden_unprotected] {
                let channel = db.fetch_channel(channel.id()).await.expect("the channel");
                assert!(
                    require_channel_access(db, &caller.user, &channel)
                        .await
                        .is_err(),
                    "{} views {}",
                    caller.class,
                    channel.id()
                );
            }

            let missing = get(&fixture.harness, &caller.session, &fixture.missing_id).await;
            assert_own_not_found(&missing, caller.class);
            for (target, channel_id) in [
                ("hidden protected", fixture.hidden_protected.id()),
                ("hidden unprotected", fixture.hidden_unprotected.id()),
                ("deleted", fixture.deleted_id.as_str()),
            ] {
                let answer = get(&fixture.harness, &caller.session, channel_id).await;
                assert_eq!(answer, missing, "{} {}", caller.class, target);
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

    #[test]
    fn non_viewers_answer_as_a_missing_channel_with_media_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            Box::pin(non_viewers_answer_as_a_missing_channel()).await
        })
    }

    #[test]
    fn non_viewers_answer_as_a_missing_channel_with_growth_and_media_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            Box::pin(non_viewers_answer_as_a_missing_channel()).await
        })
    }

    /// For a caller who CAN view the channel: the caller checks, then the
    /// maintenance gate (E2EE only: growth and media play no part), then
    /// the group, or the 404 of a channel with no open Text group
    async fn viewers_get_the_group_after_the_caller_checks_and_the_gate() {
        let fixture = Box::pin(fixture()).await;
        let e2ee = revolt_config::config().await.features.e2ee_enabled;
        let caller = |class: &str| {
            fixture
                .callers
                .iter()
                .find(|caller| caller.class == class)
                .expect("a caller")
        };

        // The seated member with a bound session is served
        let member = caller("member");
        let answer = get(&fixture.harness, &member.session, fixture.protected.id()).await;
        if e2ee {
            assert_eq!(answer.0, Status::Ok, "{:?}", answer);
            let value = body(&answer);
            assert_eq!(value, expected_response(&fixture, &fixture.protected).await);
            assert_eq!(value["group_id"], text_group_id(fixture.protected.id(), 0));
            assert_eq!(value["channel_id"], fixture.protected.id());
            assert_eq!(value["generation"], 0);
        } else {
            assert_e2ee_disabled(&answer, "member");
        }

        // The caller checks answer before the gate, whatever the flags
        let bot = caller("bot");
        let answer = get(&fixture.harness, &bot.session, fixture.protected.id()).await;
        assert_type(&answer, "IsBot", "bot");
        let unbound = caller("unbound");
        let answer = get(&fixture.harness, &unbound.session, fixture.protected.id()).await;
        assert_type(&answer, "NotAuthenticated", "unbound");

        // An unprotected channel has no Text group (§7.2 `NotFound`)
        let answer = get(
            &fixture.harness,
            &member.session,
            fixture.visible_unprotected.id(),
        )
        .await;
        if e2ee {
            assert_own_not_found(&answer, "unprotected");
        } else {
            assert_e2ee_disabled(&answer, "unprotected");
        }

        // The outsider cannot view it, so it gets the missing answer
        let outsider = caller("outsider");
        let missing = get(&fixture.harness, &outsider.session, &fixture.missing_id).await;
        let answer = get(&fixture.harness, &outsider.session, fixture.protected.id()).await;
        assert_eq!(answer, missing, "outsider");
    }

    #[test]
    fn viewers_get_the_group_with_every_flag_on() {
        crate::util::test::rt().block_on(Box::pin(
            viewers_get_the_group_after_the_caller_checks_and_the_gate(),
        ))
    }

    #[test]
    fn viewers_are_refused_with_e2ee_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            Box::pin(viewers_get_the_group_after_the_caller_checks_and_the_gate()).await
        })
    }

    #[test]
    fn viewers_get_the_group_with_growth_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            Box::pin(viewers_get_the_group_after_the_caller_checks_and_the_gate()).await
        })
    }

    /// Decision 3 (W2): the text plane ignores the media flag
    #[test]
    fn viewers_get_the_group_with_media_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            Box::pin(viewers_get_the_group_after_the_caller_checks_and_the_gate()).await
        })
    }

    #[test]
    fn viewers_get_the_group_with_growth_and_media_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            Box::pin(viewers_get_the_group_after_the_caller_checks_and_the_gate()).await
        })
    }

    /// The served group is the channel's OPEN one: none before the first
    /// create, the successor after a supersede
    #[test]
    fn the_open_group_is_served() {
        crate::util::test::rt().block_on(the_open_group_is_served_case())
    }

    async fn the_open_group_is_served_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[])
            .await;
        let channel_id = protected.channel.id();

        let answer = get(&harness, &owner_session, channel_id).await;
        assert_own_not_found(&answer, "no Text group yet");

        let first = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let answer = get(&harness, &owner_session, channel_id).await;
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        assert_eq!(body(&answer)["group_id"], first.id);

        let successor = harness
            .new_text_group(
                &protected.channel,
                &protected.owner_device,
                1,
                Some(&first.id),
            )
            .await;
        let answer = get(&harness, &owner_session, channel_id).await;
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        let value = body(&answer);
        assert_eq!(value["group_id"], successor.id);
        assert_eq!(value["group_id"], text_group_id(channel_id, 1));
        assert_eq!(value["generation"], 1);
    }

    #[test]
    fn the_route_needs_a_session() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let response = harness
                .client
                .get(format!("/mls/channels/{}/text_group", Ulid::new()))
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Unauthorized);
        })
    }

    /// A fresh device id (32 lowercase hex chars)
    fn device_id() -> String {
        format!("{:032x}", Ulid::new().0)
    }

    /// `seconds` ago
    fn ago(seconds: i64) -> Timestamp {
        Timestamp::now_utc()
            .checked_sub(Duration::seconds(seconds))
            .expect("a time")
    }

    /// Apply `edit` to the stored group `id`, straight to the store (the S2
    /// fields have no write path a read test can drive in isolation). On
    /// MongoDB the edited group is `$set`, so a field serialized away
    /// (`None`, empty) keeps its stored value.
    async fn edit_group(harness: &TestHarness, id: &str, edit: impl FnOnce(&mut MlsGroup)) {
        match &harness.db {
            Database::Reference(reference) => {
                edit(
                    reference
                        .mls_groups
                        .lock()
                        .await
                        .get_mut(id)
                        .expect("the group row"),
                );
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, to_document};

                let collection = mongo.col::<MlsGroup>("mls_groups");
                let mut group = collection
                    .find_one(doc! { "_id": id })
                    .await
                    .expect("the group read")
                    .expect("the group row");
                edit(&mut group);
                let mut set = to_document(&group).expect("the group as BSON");
                set.remove("_id");
                let result = collection
                    .update_one(doc! { "_id": id }, doc! { "$set": set })
                    .await
                    .expect("the group write");
                assert_eq!(result.matched_count, 1, "the group row");
            }
        }
    }

    /// Store a join intent by a fresh device of `user_id` for `group_id`,
    /// created `age` seconds ago
    async fn store_intent(
        harness: &TestHarness,
        group_id: &str,
        user_id: &str,
        age: i64,
    ) -> MlsJoinIntent {
        let device_id = device_id();
        let intent = MlsJoinIntent {
            id: MlsJoinIntent::composite_id(group_id, user_id, &device_id),
            group_id: group_id.to_string(),
            user_id: user_id.to_string(),
            device_id: device_id.clone(),
            key_package_ref: format!("kp-{device_id}"),
            signature: format!("sig-{device_id}"),
            created_at: ago(age),
            generation: Some(0),
            issued_at: Some(FIXTURE_ISSUED_AT),
        };
        harness
            .db
            .upsert_mls_join_intent(&intent)
            .await
            .expect("the join intent");
        intent
    }

    /// R24 (#222), §6.3 "Async Text join": a seated caller gets the
    /// outstanding join intents of SEATED users only (inside the Text
    /// window, not the Call one) and the pending device removals; an
    /// unseated viewer gets the S1 body byte for byte; a non-viewer, and a
    /// seated member who cannot view, still get the missing answer
    #[test]
    fn seated_callers_get_the_s2_fields_and_unseated_viewers_the_s1_body() {
        crate::util::test::rt().block_on(Box::pin(seated_and_unseated_case()))
    }

    async fn seated_and_unseated_case() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let window = mls_text_rejoin_window_seconds(
            revolt_config::config()
                .await
                .features
                .protected_channels
                .text_rejoin_window_secs,
        );
        assert!(window > 3600, "the case needs a Text window above an hour");

        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, viewer_session, viewer) = harness.new_user().await;
        let (_, outsider_session, outsider) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        harness.join_server(&protected.server, &viewer).await;
        harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        harness
            .new_e2ee_device(&viewer, &viewer_session.id, MEMBER_DEVICE_SEED + 1)
            .await;
        harness
            .new_e2ee_device(&outsider, &outsider_session.id, MEMBER_DEVICE_SEED + 2)
            .await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let channel_id = protected.channel.id();

        let pending = MlsPendingDeviceRemoval {
            user_id: member.id.clone(),
            device_id: device_id(),
            created_at: Timestamp::now_utc(),
        };
        edit_group(&harness, &group.id, |group| {
            group.pending_device_removals = vec![pending.clone()];
        })
        .await;

        // Seated users: outstanding (an hour old, which a 30 s Call window
        // would drop) and expired. The unseated viewer: outstanding.
        let owner_outstanding = store_intent(&harness, &group.id, &owner.id, 3600).await;
        let member_outstanding = store_intent(&harness, &group.id, &member.id, 60).await;
        let member_expired = store_intent(&harness, &group.id, &member.id, window + 60).await;
        let viewer_outstanding = store_intent(&harness, &group.id, &viewer.id, 60).await;

        let stored = db.fetch_mls_group(&group.id).await.expect("the group");
        assert_eq!(stored.pending_device_removals.len(), 1);
        let intents = db
            .fetch_mls_join_intents_for_group(&group.id)
            .await
            .expect("the intents");
        assert_eq!(intents.len(), 4, "every intent is stored");
        let kept: Vec<MlsJoinIntent> = intents
            .into_iter()
            .filter(|intent| {
                intent.id == owner_outstanding.id || intent.id == member_outstanding.id
            })
            .collect();
        let seated_body = serde_json::to_value(
            stored
                .clone()
                .into_text_group_response_for_seated(kept, false)
                .expect("a Text group"),
        )
        .expect("JSON");
        let s1_body =
            serde_json::to_string(&stored.into_text_group_response().expect("a Text group"))
                .expect("JSON");

        for (class, session) in [("owner", &owner_session), ("member", &member_session)] {
            let answer = get(&harness, session, channel_id).await;
            assert_eq!(answer.0, Status::Ok, "{}: {:?}", class, answer);
            let value = body(&answer);
            assert_eq!(value, seated_body, "{}", class);
            let devices: Vec<&str> = value["join_requests"]
                .as_array()
                .expect("join_requests")
                .iter()
                .map(|request| request["device_id"].as_str().expect("a device id"))
                .collect();
            // Oldest first
            assert_eq!(
                devices,
                vec![
                    owner_outstanding.device_id.as_str(),
                    member_outstanding.device_id.as_str()
                ],
                "{}: neither the unseated ({}) nor the expired ({}) intent",
                class,
                viewer_outstanding.device_id,
                member_expired.device_id
            );
            assert_eq!(
                value["pending_device_removals"][0]["device_id"], pending.device_id,
                "{}",
                class
            );
            assert!(
                value.get("signer_lost").is_none(),
                "{}: {}",
                class,
                answer.1
            );
        }

        let answer = get(&harness, &viewer_session, channel_id).await;
        assert_eq!(answer.0, Status::Ok, "viewer: {:?}", answer);
        assert_eq!(answer.1, s1_body, "the unseated viewer gets the S1 body");
        let value = body(&answer);
        for field in ["join_requests", "pending_device_removals", "signer_lost"] {
            assert!(value.get(field).is_none(), "viewer {}: {}", field, answer.1);
        }

        // Oracle parity (decision 1): the S2 state changes nothing for a
        // non-viewer, nor for a seated member who cannot view
        let missing_id = Ulid::new().to_string();
        let missing = get(&harness, &outsider_session, &missing_id).await;
        assert_own_not_found(&missing, "outsider");
        let answer = get(&harness, &outsider_session, channel_id).await;
        assert_eq!(answer, missing, "outsider");
        deny_view(&harness, &protected.channel).await;
        let missing = get(&harness, &member_session, &missing_id).await;
        assert_own_not_found(&missing, "seated non-viewer");
        let answer = get(&harness, &member_session, channel_id).await;
        assert_eq!(answer, missing, "seated non-viewer");
    }

    /// A released (cooling) seat is not a seat (§2.3, `require_seated`'s
    /// predicate): its holder, still a viewer, gets the S1 body, and its
    /// intents are not served to seated callers
    #[test]
    fn a_cooling_seat_is_not_seated() {
        crate::util::test::rt().block_on(Box::pin(cooling_seat_case()))
    }

    async fn cooling_seat_case() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let channel_id = protected.channel.id();

        let owner_intent = store_intent(&harness, &group.id, &owner.id, 60).await;
        let member_intent = store_intent(&harness, &group.id, &member.id, 60).await;
        harness.mark_keys_received(channel_id, &member.id).await;
        let seat_of = |seats: Vec<ChannelSeat>| {
            seats
                .into_iter()
                .find(|seat| seat.user_id == member.id)
                .expect("the member's seat")
        };
        let seat = seat_of(db.fetch_channel_seats(channel_id).await.expect("seats"));
        assert!(db
            .release_channel_seat(
                channel_id,
                &member.id,
                seat.seated_at,
                SeatReleaseCause::OwnerUnseat,
                Timestamp::now_utc(),
            )
            .await
            .expect("the release"));
        let seat = seat_of(db.fetch_channel_seats(channel_id).await.expect("seats"));
        assert!(!seat.is_active(), "released");
        assert!(seat.is_cooling(Timestamp::now_utc()), "cooling");

        let stored = db.fetch_mls_group(&group.id).await.expect("the group");
        let answer = get(&harness, &member_session, channel_id).await;
        assert_eq!(answer.0, Status::Ok, "cooling member: {:?}", answer);
        assert_eq!(
            answer.1,
            serde_json::to_string(&stored.into_text_group_response().expect("a Text group"))
                .expect("JSON"),
            "the cooling member gets the S1 body"
        );

        let answer = get(&harness, &owner_session, channel_id).await;
        assert_eq!(answer.0, Status::Ok, "owner: {:?}", answer);
        let value = body(&answer);
        let devices: Vec<&str> = value["join_requests"]
            .as_array()
            .expect("join_requests")
            .iter()
            .map(|request| request["device_id"].as_str().expect("a device id"))
            .collect();
        assert_eq!(
            devices,
            vec![owner_intent.device_id.as_str()],
            "not the cooling member's ({})",
            member_intent.device_id
        );
    }

    /// #222: a stored `signer_lost` (cause `device_revoked`) is served as
    /// `account_unavailable` while the signer user's account is suspended
    /// (the suspension in effect), deleted or banned, read per request; an
    /// unseated viewer never sees it
    #[test]
    fn a_stored_signer_lost_reads_account_unavailable_for_an_unavailable_signer() {
        crate::util::test::rt().block_on(Box::pin(account_unavailable_case()))
    }

    async fn account_unavailable_case() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, viewer_session, viewer) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        harness.join_server(&protected.server, &viewer).await;
        harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        harness
            .new_e2ee_device(&viewer, &viewer_session.id, MEMBER_DEVICE_SEED + 1)
            .await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let channel_id = protected.channel.id();
        let signer = &protected.owner_device;

        let lost = MlsSignerLost {
            user_id: owner.id.clone(),
            device_id: signer.device_id.clone(),
            cause: revolt_database::MlsSignerLostCause::DeviceRevoked,
            at: Timestamp::now_utc(),
        };
        edit_group(&harness, &group.id, |group| {
            group.signer_lost = Some(lost.clone());
        })
        .await;
        let stored = db.fetch_mls_group(&group.id).await.expect("the group");
        assert!(stored.signer_lost.is_some(), "the stored signer_lost");

        let (revoked, unavailable) = ("device_revoked", "account_unavailable");
        let suspended = UserFlags::SuspendedUntil as i32;
        let deleted = UserFlags::Deleted as i32;
        let banned = UserFlags::Banned as i32;
        let later = Timestamp::now_utc()
            .checked_add(Duration::days(1))
            .expect("a time");
        for (case, flags, until, cause) in [
            ("no flag", 0, None, revoked),
            ("indefinite suspension", suspended, None, unavailable),
            ("suspension in effect", suspended, Some(later), unavailable),
            ("elapsed suspension", suspended, Some(ago(86400)), revoked),
            ("deleted", deleted, None, unavailable),
            ("banned", banned, None, unavailable),
        ] {
            let remove = if until.is_none() {
                vec![FieldsUser::Suspension]
            } else {
                vec![]
            };
            db.update_user(
                &owner.id,
                &PartialUser {
                    flags: Some(flags),
                    suspended_until: until,
                    ..Default::default()
                },
                remove,
            )
            .await
            .expect("the signer's flags");

            let answer = get(&harness, &member_session, channel_id).await;
            assert_eq!(answer.0, Status::Ok, "{}: {:?}", case, answer);
            let value = body(&answer);
            let served = &value["signer_lost"];
            assert_eq!(served["cause"], cause, "{}: {}", case, answer.1);
            assert_eq!(served["user_id"], owner.id, "{}", case);
            assert_eq!(served["device_id"], signer.device_id, "{}", case);

            let answer = get(&harness, &viewer_session, channel_id).await;
            assert_eq!(answer.0, Status::Ok, "{} viewer: {:?}", case, answer);
            assert!(
                body(&answer).get("signer_lost").is_none(),
                "{} viewer: {}",
                case,
                answer.1
            );
        }
    }

    /// #228: with no `signer_lost` stored, a signer-USER caller gets one
    /// derived when the stored list's signer device has no registered
    /// identity (here a revocation with `formats_v2` off); a seated member
    /// who is not the signer user gets none and an unseated viewer the S1
    /// body. Nothing is stored, and the cause follows the account (#222).
    #[test]
    fn a_signer_user_gets_a_derived_signer_lost_when_the_signer_device_is_gone() {
        crate::util::test::rt().block_on(Box::pin(derived_signer_lost_case()))
    }

    async fn derived_signer_lost_case() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, viewer_session, viewer) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        harness.join_server(&protected.server, &viewer).await;
        harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        harness
            .new_e2ee_device(&viewer, &viewer_session.id, MEMBER_DEVICE_SEED + 1)
            .await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let channel_id = protected.channel.id();
        let signer = &protected.owner_device;

        // The signer device is registered: nothing to derive
        let answer = get(&harness, &owner_session, channel_id).await;
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        assert!(body(&answer).get("signer_lost").is_none(), "{}", answer.1);

        // Its identity goes and nothing is stored; the owner calls from a
        // replacement device bound to the same session
        assert!(db
            .delete_e2ee_device(&owner.id, &signer.device_id)
            .await
            .expect("the identity delete"));
        harness
            .new_e2ee_device(&owner, &owner_session.id, NEW_OWNER_DEVICE_SEED)
            .await;
        let list = db
            .fetch_seat_list(channel_id)
            .await
            .expect("the list read")
            .expect("the stored list");
        assert_eq!(list.signer_user_id, owner.id);
        assert_eq!(list.signer_device_id, signer.device_id);

        let first = get(&harness, &owner_session, channel_id).await;
        assert_eq!(first.0, Status::Ok, "{:?}", first);
        assert_eq!(
            body(&first)["signer_lost"],
            serde_json::json!({
                "user_id": owner.id,
                "device_id": signer.device_id,
                "cause": "device_revoked",
                "at": list.updated_at,
            }),
            "{}",
            first.1
        );
        // Derived per read, never stored, and the same on every read
        let stored = db.fetch_mls_group(&group.id).await.expect("the group");
        assert!(stored.signer_lost.is_none(), "nothing is stored");
        assert_eq!(get(&harness, &owner_session, channel_id).await, first);

        let answer = get(&harness, &member_session, channel_id).await;
        assert_eq!(answer.0, Status::Ok, "member: {:?}", answer);
        assert!(
            body(&answer).get("signer_lost").is_none(),
            "member: {}",
            answer.1
        );

        let answer = get(&harness, &viewer_session, channel_id).await;
        assert_eq!(answer.0, Status::Ok, "viewer: {:?}", answer);
        assert_eq!(
            answer.1,
            serde_json::to_string(&stored.into_text_group_response().expect("a Text group"))
                .expect("JSON"),
            "the unseated viewer gets the S1 body"
        );

        db.update_user(
            &owner.id,
            &PartialUser {
                flags: Some(UserFlags::Banned as i32),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("the ban flag");
        let answer = get(&harness, &owner_session, channel_id).await;
        assert_eq!(answer.0, Status::Ok, "banned: {:?}", answer);
        assert_eq!(
            body(&answer)["signer_lost"]["cause"],
            "account_unavailable",
            "{}",
            answer.1
        );
    }
}
