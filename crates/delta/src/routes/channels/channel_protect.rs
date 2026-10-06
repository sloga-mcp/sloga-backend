use iso8601_timestamp::Timestamp;
use revolt_database::{
    events::client::EventV1, seat_list_channel_server, util::reference::Reference, Database,
    Session, User,
};
use revolt_models::v0;
use revolt_result::{create_error, Error, ErrorType, Result};
use rocket::{serde::json::Json, State};

use super::protected_seat_validation::validate_protect;
use crate::routes::mls::{
    require_channel_access, require_protected_available, require_protected_growth,
};

/// # Protect Channel
///
/// Protect a server text channel with its genesis seat list
/// (protected-channels design 7.2). Only the server owner may protect a
/// channel, and never a privileged (staff) owner.
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
    // byte-identical retry of a protect that landed skips steps 5 to 8
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
    }

    let outcome = db
        .protect_channel(channel.id(), &validated.submission, Timestamp::now_utc())
        .await?;
    if !outcome.unchanged {
        log::info!(
            "AUDIT channel_protect: actor={} channel={} server={} seats={}",
            user.id,
            channel.id(),
            server.id,
            outcome.claimed.len()
        );
    }

    // Every connected client sets its protected pin (9.4) now, on the
    // SERVER topic, the one `Channel::update` uses (decision 19 (W2)).
    // Re-emitted on N3 (#134): a protect that landed but answered 5xx never
    // emitted it, and a repeated `protected: Some(true)` changes nothing.
    EventV1::ChannelUpdate {
        id: channel.id().to_string(),
        data: v0::PartialChannel {
            protected: Some(true),
            ..Default::default()
        },
        clear: vec![],
    }
    .p(server.id.clone())
    .await;

    let channel = db.fetch_channel(channel.id()).await?;
    Ok(Json(channel.into()))
}

/// The one `NotFound` for a missing channel and a channel the caller cannot
/// view: one source site, so the body's `location` never tells them apart
fn no_channel() -> Error {
    create_error!(NotFound)
}

#[cfg(test)]
mod test {
    //! Run under nextest (one process per test; the flag variants call
    //! `overwrite_config`). Every refusal also asserts that nothing was
    //! written.

    use std::collections::BTreeSet;

    use revolt_database::{
        events::client::EventV1, BotInformation, Channel, ChannelSeat, Message, PartialChannel,
        PartialUser, RemovalIntention, SeatList, Session, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;
    use ulid::Ulid;

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
        // carries no API error body. The location pins it to this handler.
        assert_eq!(response.status(), Status::NotFound);
        let error = response
            .into_json::<serde_json::Value>()
            .await
            .expect("API error body");
        assert_eq!(error["type"], "NotFound");
        assert!(
            error["location"]
                .as_str()
                .is_some_and(|location| location.contains("routes/channels/channel_protect.rs")),
            "unexpected error: {}",
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

    /// A refusal: its status, and its error body apart from `location`
    #[track_caller]
    fn assert_refused(answer: &(Status, String), status: Status, error: serde_json::Value) {
        assert_eq!(answer.0, status, "{:?}", answer);
        let mut value = body(answer);
        value
            .as_object_mut()
            .expect("an error object")
            .remove("location");
        assert_eq!(value, error, "{:?}", answer);
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
    /// EXACTLY as a channel id the server never held, the full body
    /// (`location` included), for a valid and a garbage request alike, and
    /// that answer is not what a viewer gets
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
                    body(&missing)["location"].as_str().is_some_and(
                        |location| location.contains("routes/channels/channel_protect.rs")
                    ),
                    "{}",
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
}
