use revolt_database::{util::reference::Reference, Database, MlsGroupKind, Session, User};
use revolt_models::v0;
use revolt_result::{create_error, Error, Result};
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

    // A stored Text group always carries its generation. One without is
    // corrupt, and a 404 would invite a fresh create over it.
    group
        .into_text_group_response()
        .map(Json)
        .ok_or_else(|| create_error!(InternalError))
}

/// The one `NotFound` this route answers, for a missing channel, a channel
/// the caller cannot view and a channel with no open Text group alike (one
/// source site; error locations no longer serialize, so this is hygiene)
fn no_text_group() -> Error {
    create_error!(NotFound)
}

#[cfg(test)]
mod tests {
    use revolt_database::{BotInformation, Channel, PartialChannel, PartialUser, Session, User};
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{Header, Status};
    use ulid::Ulid;

    use super::super::{require_channel_access, text::text_group_id};
    use crate::util::test::{TestHarness, MEMBER_DEVICE_SEED};

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
}
