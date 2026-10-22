use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Channel, Database, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use validator::Validate;

/// # Create Thread
///
/// Create a new thread under a server text channel.
///
/// The target channel must be a `TextChannel`; threads cannot be created under
/// DMs, groups or other threads.
#[openapi(tag = "Threads")]
#[post("/<target>/threads", data = "<data>")]
pub async fn create_thread(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataCreateThread>,
) -> Result<Json<v0::Channel>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let channel = target.as_channel(db).await?;
    // Permissions are always evaluated against the parent text channel.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    // A protected channel takes no plaintext-named thread (decision 18 (W2)):
    // refused after the permission checks, so a non-viewer gets the same
    // answer as for any channel, and before the thread row, the auto-join
    // and the `ChannelCreate`. `create_thread`'s parent hold stays the floor.
    if channel.is_protected() {
        return Err(create_error!(ChannelProtected));
    }

    let thread = Channel::create_thread(db, &channel, &user, None, data).await?;
    Ok(Json(thread.into()))
}

/// # Create Thread From Message
///
/// Create a new thread anchored to an existing message in a server text
/// channel. The message is stamped with the new thread's id.
#[openapi(tag = "Threads")]
#[post("/<target>/messages/<msg>/threads", data = "<data>")]
pub async fn create_thread_from_message(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    msg: Reference<'_>,
    data: Json<v0::DataCreateThread>,
) -> Result<Json<v0::Channel>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let channel = target.as_channel(db).await?;
    // Permissions are always evaluated against the parent text channel.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    // As in `create_thread`, and before the message lookup: a protected
    // channel's messages never anchor a thread.
    if channel.is_protected() {
        return Err(create_error!(ChannelProtected));
    }

    // Ensure the message actually belongs to the target channel.
    let message = msg.as_message_in_channel(db, channel.id()).await?;
    let thread = Channel::create_thread(db, &channel, &user, Some(&message), data).await?;
    Ok(Json(thread.into()))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::{
        events::client::EventV1, util::bulk_permissions::BulkDatabasePermissionQuery, Channel,
        Member, Message, PartialChannel,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use revolt_result::ErrorType;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::{json, Value};
    use ulid::Ulid;

    /// POST `path` (under `/channels`) as `token` with a thread body
    async fn post_thread(
        harness: &TestHarness,
        token: &str,
        path: &str,
        auto_archive_minutes: Option<u32>,
    ) -> (Status, Value) {
        let response = harness
            .client
            .post(format!("/channels/{}", path))
            .header(Header::new("x-session-token", token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!({ "name": "Thread", "auto_archive_minutes": auto_archive_minutes })
                    .to_string(),
            )
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_json::<Value>().await.expect("json body");
        (status, body)
    }

    /// The created thread's id, asserting it hangs off `parent_id`
    #[track_caller]
    fn created_thread(answer: &(Status, Value), parent_id: &str) -> String {
        assert_eq!(answer.0, Status::Ok, "{}", answer.1);
        match serde_json::from_value::<v0::Channel>(answer.1.clone()).expect("a channel") {
            v0::Channel::Thread {
                id, parent_channel, ..
            } if parent_channel == parent_id => id,
            other => panic!("expected a thread under {}, got {:?}", parent_id, other),
        }
    }

    fn is_thread_create_under(parent_id: String) -> impl Fn(&EventV1) -> bool {
        move |event| {
            matches!(
                event,
                EventV1::ChannelCreate(v0::Channel::Thread { parent_channel, .. })
                    if parent_channel == &parent_id
            )
        }
    }

    fn is_thread_create_of(thread_id: String) -> impl Fn(&EventV1) -> bool {
        move |event| {
            matches!(
                event,
                EventV1::ChannelCreate(v0::Channel::Thread { id, .. }) if id == &thread_id
            )
        }
    }

    /// Store a plaintext message in `channel_id`, returning it
    async fn insert_plain(harness: &TestHarness, channel_id: &str, author: &str) -> Message {
        let message = Message {
            id: Ulid::new().to_string(),
            channel: channel_id.to_string(),
            author: author.to_string(),
            content: Some("anchor".to_string()),
            ..Default::default()
        };
        harness.db.insert_message(&message).await.expect("message");
        message
    }

    /// Decision 18 (W2): both thread routes refuse a protected parent with
    /// the ROUTE's `ChannelProtected`, ahead of everything `create_thread`
    /// checks (an invalid auto-archive duration) and ahead of the message
    /// lookup (an unknown message id). No thread row, no membership, no
    /// stamp on the anchor, and no `ChannelCreate` for a thread under the
    /// parent reaches the server topic: a thread created afterwards under
    /// an unprotected channel of the same server is the FIFO marker.
    ///
    /// Control: the route refusals dropped (`db0f44d4`). The parent hold in
    /// `create_thread` still answers `ChannelProtected` with no event, but
    /// from the database crate (`location`), and only after the duration
    /// check (`InvalidProperty`) and the message lookup (`NotFound`).
    #[test]
    fn protected_parent_refuses_both_thread_routes_without_side_effects() {
        crate::util::test::rt()
            .block_on(protected_parent_refuses_both_thread_routes_without_side_effects_case())
    }

    async fn protected_parent_refuses_both_thread_routes_without_side_effects_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let protected = harness.new_protected_channel(&owner, &session, &[]).await;
        let open = harness.new_channel(&protected.server).await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let anchor = harness
            .new_encrypted_message(&protected.channel, &protected.owner_device, &group)
            .await;
        let token = session.token.to_string();
        let parent = protected.channel.id().to_string();
        assert!(protected.channel.is_protected());

        let cases = [
            ("plain", format!("{}/threads", parent), None),
            (
                "bad duration",
                format!("{}/threads", parent),
                Some(u32::MAX),
            ),
            (
                "anchored",
                format!("{}/messages/{}/threads", parent, anchor.id),
                None,
            ),
            (
                "unknown anchor",
                format!("{}/messages/{}/threads", parent, Ulid::new()),
                None,
            ),
        ];
        for (case, path, auto_archive_minutes) in &cases {
            let (status, body) = post_thread(&harness, &token, path, *auto_archive_minutes).await;
            assert_eq!(status, Status::BadRequest, "{}: {}", case, body);
            assert_eq!(body["type"], "ChannelProtected", "{}: {}", case, body);
            let location = body["location"].as_str().unwrap_or_default();
            assert!(
                location.contains("routes/channels/thread_create.rs"),
                "{}: refused outside the route: {}",
                case,
                body
            );
        }

        assert!(harness
            .db
            .fetch_threads_by_parent(&parent)
            .await
            .expect("threads")
            .is_empty());
        assert!(harness
            .db
            .fetch_joined_thread_ids(&owner.id, &protected.server.id)
            .await
            .expect("joined threads")
            .is_empty());
        let anchor = harness.db.fetch_message(&anchor.id).await.expect("anchor");
        assert_eq!(anchor.thread_id, None);

        // Marker: the same request under an unprotected sibling channel
        let marker = created_thread(
            &post_thread(&harness, &token, &format!("{}/threads", open.id()), None).await,
            open.id(),
        );
        harness
            .wait_for_event(&protected.server.id, is_thread_create_of(marker))
            .await;
        harness.assert_no_buffered_event(&protected.server.id, is_thread_create_under(parent));
    }

    /// Positive control: the same requests under an unprotected channel
    /// create threads, and the anchored one stamps its message.
    #[test]
    fn unprotected_parent_creates_threads_through_both_routes() {
        crate::util::test::rt()
            .block_on(unprotected_parent_creates_threads_through_both_routes_case())
    }

    async fn unprotected_parent_creates_threads_through_both_routes_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (server, channel) = harness.new_protectable_channel(&owner).await;
        let anchor = insert_plain(&harness, channel.id(), &owner.id).await;
        let token = session.token.to_string();
        assert!(!channel.is_protected());

        let plain = created_thread(
            &post_thread(&harness, &token, &format!("{}/threads", channel.id()), None).await,
            channel.id(),
        );
        let anchored = created_thread(
            &post_thread(
                &harness,
                &token,
                &format!("{}/messages/{}/threads", channel.id(), anchor.id),
                None,
            )
            .await,
            channel.id(),
        );

        let anchor = harness.db.fetch_message(&anchor.id).await.expect("anchor");
        assert_eq!(anchor.thread_id.as_deref(), Some(anchored.as_str()));
        assert_eq!(
            harness
                .db
                .fetch_threads_by_parent(channel.id())
                .await
                .expect("threads")
                .len(),
            2
        );
        harness
            .wait_for_event(&server.id, is_thread_create_of(plain))
            .await;
        harness
            .wait_for_event(&server.id, is_thread_create_of(anchored))
            .await;
    }

    /// Decision 18 (W2): a member who cannot view the channel gets the
    /// pre-W2 `MissingPermission`, byte-identical (`location` included) for
    /// a protected and an unprotected channel, from both routes.
    ///
    /// Control: the refusal moved above the permission calculation.
    #[test]
    fn non_viewer_answer_is_identical_protected_or_not() {
        crate::util::test::rt().block_on(non_viewer_answer_is_identical_protected_or_not_case())
    }

    async fn non_viewer_answer_is_identical_protected_or_not_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let open = harness.new_channel(&protected.server).await;
        let token = member_session.token.to_string();

        let mut answers: Vec<Vec<(Status, String)>> = vec![];
        for mut channel in [protected.channel.clone(), open] {
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

            let mut per_channel = vec![];
            for path in [
                format!("{}/threads", channel.id()),
                format!("{}/messages/{}/threads", channel.id(), Ulid::new()),
            ] {
                let (status, body) = post_thread(&harness, &token, &path, None).await;
                assert_eq!(body["type"], "MissingPermission", "{}: {}", path, body);
                per_channel.push((status, body.to_string()));
            }
            assert!(harness
                .db
                .fetch_threads_by_parent(channel.id())
                .await
                .expect("threads")
                .is_empty());
            answers.push(per_channel);
        }

        assert!(harness
            .db
            .fetch_channel(protected.channel.id())
            .await
            .expect("channel")
            .is_protected());
        assert_eq!(answers[0], answers[1]);
    }

    #[test]
    fn create_thread_auto_joins_creator_and_delegates_permissions() {
        crate::util::test::rt().block_on(create_thread_auto_joins_creator_and_delegates_permissions_case())
    }

    async fn create_thread_auto_joins_creator_and_delegates_permissions_case() {
        let harness = TestHarness::new().await;
        let (_, _, user) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let thread = Channel::create_thread(
            &harness.db,
            &channel,
            &user,
            None,
            v0::DataCreateThread {
                name: "My Thread".to_string(),
                auto_archive_minutes: None,
            },
        )
        .await
        .expect("thread created");

        // The thread hangs off the parent text channel.
        assert!(
            matches!(&thread, Channel::Thread { parent_channel, .. } if parent_channel == channel.id()),
            "thread should point at its parent channel"
        );

        // The creator is auto-joined.
        let members = harness
            .db
            .fetch_thread_members(thread.id())
            .await
            .expect("fetch members");
        assert!(
            members.iter().any(|member| member.id.user == user.id),
            "creator should be auto-joined to the thread"
        );

        // Permission checks delegate to the parent channel.
        let target = thread
            .permission_target(&harness.db)
            .await
            .expect("permission target");
        assert_eq!(
            target.id(),
            channel.id(),
            "a thread's permission target must be its parent channel"
        );
    }

    /// Exercises the exact bulk-permission path the pushd mass-mention
    /// consumer uses for a role/everyone mention inside a thread: the query is
    /// built from the THREAD's id, must not panic, and must evaluate the
    /// PARENT channel's overrides (a member denied ViewChannel on the parent
    /// must not be pushed for a thread mass mention).
    #[test]
    fn thread_mass_mention_visibility_uses_parent_overrides() {
        crate::util::test::rt().block_on(thread_mass_mention_visibility_uses_parent_overrides_case())
    }

    async fn thread_mass_mention_visibility_uses_parent_overrides_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, _, outsider) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&owner).await;
        let mut channel = harness.new_channel(&server).await;

        // Deny ViewChannel by default on the parent channel.
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
            .expect("deny view on parent");

        let thread = Channel::create_thread(
            &harness.db,
            &channel,
            &owner,
            None,
            v0::DataCreateThread {
                name: "Hidden Thread".to_string(),
                auto_archive_minutes: None,
            },
        )
        .await
        .expect("thread created");

        // A plain member with no roles cannot see the (hidden) parent.
        let (member, _) = Member::create(&harness.db, &server, &outsider, None)
            .await
            .expect("member created");

        // Mirror pushd's mass-mention query shape: built from the thread id.
        let members = [member];
        let visibility = BulkDatabasePermissionQuery::from_server_id(&harness.db, &server.id)
            .await
            .from_channel_id(thread.id().to_string())
            .await
            .members(&members)
            .members_can_see_channel()
            .await;

        assert_eq!(
            visibility.get(&outsider.id),
            Some(&false),
            "member denied ViewChannel on the parent must not see the thread"
        );
    }

    #[test]
    fn thread_cannot_double_anchor_a_message() {
        crate::util::test::rt().block_on(thread_cannot_double_anchor_a_message_case())
    }

    async fn thread_cannot_double_anchor_a_message_case() {
        let harness = TestHarness::new().await;
        let (_, _, user) = harness.new_user().await;
        let (server, channels) = harness.new_server(&user).await;
        let (channel, _member, message) = harness.new_message(&user, &server, channels).await;

        // First thread anchored to the message succeeds.
        Channel::create_thread(
            &harness.db,
            &channel,
            &user,
            Some(&message),
            v0::DataCreateThread {
                name: "First".to_string(),
                auto_archive_minutes: None,
            },
        )
        .await
        .expect("first thread");

        // Re-fetch so the message carries the stamped thread_id.
        let message = harness
            .db
            .fetch_message(&message.id)
            .await
            .expect("refetch message");

        // Anchoring a second thread to the same message is rejected.
        let error = Channel::create_thread(
            &harness.db,
            &channel,
            &user,
            Some(&message),
            v0::DataCreateThread {
                name: "Second".to_string(),
                auto_archive_minutes: None,
            },
        )
        .await
        .expect_err("second thread should be rejected");
        assert!(
            matches!(error.error_type, ErrorType::ThreadAlreadyExists),
            "expected ThreadAlreadyExists, got {:?}",
            error.error_type
        );
    }
}
