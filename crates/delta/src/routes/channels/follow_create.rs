use revolt_config::config;
use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Channel, ChannelFollow, Database, User, Webhook,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use ulid::Ulid;
use validator::Validate;

/// Truncate a string to at most `max` characters (char-safe).
fn truncate_chars(input: &str, max: usize) -> String {
    input.chars().take(max).collect()
}

/// Current time in milliseconds since the Unix epoch.
#[allow(clippy::disallowed_methods)]
fn now_ms() -> i64 {
    use iso8601_timestamp::Timestamp;
    Timestamp::now_utc()
        .duration_since(Timestamp::UNIX_EPOCH)
        .whole_milliseconds() as i64
}

/// # Follow Announcement Channel
///
/// Follows a source announcement channel from a target channel in another
/// server. Creates a real webhook in the target channel; publishing an
/// announcement then fans a webhook-authored copy into every follower.
///
/// The caller needs `ViewChannel` on the source announcement channel and
/// `ManageWebhooks` on the target channel (the same gate as creating a
/// webhook there — the target server keeps full local control).
///
/// A protected (end-to-end encrypted) source or target is refused with
/// `ChannelProtected`, even when the follow already exists.
#[openapi(tag = "Channel Information")]
#[post("/<source>/follow", data = "<data>")]
pub async fn follow_channel(
    db: &State<Database>,
    user: User,
    source: Reference<'_>,
    data: Json<v0::DataFollowChannel>,
) -> Result<Json<v0::ChannelFollow>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Resolve the source — it must be a server text channel flagged as an
    // announcement channel. (E2EE fail-closed: DMs/groups/saved-messages can
    // never be a follow source.)
    let source_channel = source.as_channel(db).await?;
    let (source_channel_id, source_server_id, source_channel_name, is_announcement) =
        match &source_channel {
            Channel::TextChannel {
                id,
                server,
                name,
                announcement,
                ..
            } => (
                id.clone(),
                server.clone(),
                name.clone(),
                *announcement == Some(true),
            ),
            _ => return Err(create_error!(NotAnAnnouncementChannel)),
        };
    if !is_announcement {
        return Err(create_error!(NotAnAnnouncementChannel));
    }

    // Caller must be able to see the source announcement channel.
    let mut source_query = DatabasePermissionQuery::new(db, &user).channel(&source_channel);
    calculate_channel_permissions(&mut source_query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    // Resolve the target — it must be a server text channel in the given
    // server (fail closed for every E2EE-capable / non-server context).
    let target_channel = Reference::from_unchecked(&data.channel).as_channel(db).await?;
    let (target_channel_id, target_server_id) = match &target_channel {
        Channel::TextChannel { id, server, .. } => (id.clone(), server.clone()),
        _ => return Err(create_error!(InvalidOperation)),
    };
    if target_server_id != data.server {
        return Err(create_error!(InvalidOperation));
    }
    // A channel cannot follow itself.
    if target_channel_id == source_channel_id {
        return Err(create_error!(InvalidOperation));
    }

    // Caller must be able to manage webhooks in the TARGET channel — this is
    // exactly the gate for creating a webhook there, so the target server
    // retains full control (rename / delete via normal webhook settings).
    let mut target_query = DatabasePermissionQuery::new(db, &user).channel(&target_channel);
    calculate_channel_permissions(&mut target_query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageWebhooks)?;

    // Decision 18 (W2): a protected channel on either side is refused here,
    // after both permission checks so a caller who fails them learns nothing
    // about it, and before the idempotent return and the webhook so no follow
    // into or out of a protected channel is ever created or served.
    if source_channel.is_protected() || target_channel.is_protected() {
        return Err(create_error!(ChannelProtected));
    }

    // Idempotent: an existing (source, target) follow is returned as-is.
    if let Some(existing) = db
        .fetch_follow_by_source_and_target(&source_channel_id, &target_channel_id)
        .await?
    {
        return Ok(Json(existing.into_model()));
    }

    // Enforce the per-source follower cap.
    let cap = config().await.features.limits.global.followers_per_channel;
    if db.count_follows_by_source(&source_channel_id).await? >= cap {
        return Err(create_error!(TooManyFollowers { max: cap }));
    }

    // Name the webhook after the source: "{server} • #{channel}", truncated
    // to the 32-char webhook name limit so a later PATCH via normal webhook
    // settings still validates.
    let source_server_name = db
        .fetch_server(&source_server_id)
        .await
        .map(|server| server.name)
        .unwrap_or_default();
    let webhook_name = truncate_chars(
        &format!("{source_server_name} • #{source_channel_name}"),
        32,
    );

    // Minimal permission bitfield: only what a crosspost copy needs, so the
    // fan-out still respects the target channel's webhook gating.
    let webhook_permissions: u64 = ChannelPermission::SendMessage
        + ChannelPermission::SendEmbeds
        + ChannelPermission::UploadFiles
        + ChannelPermission::Masquerade;

    let webhook = Webhook {
        id: Ulid::new().to_string(),
        name: webhook_name,
        avatar: None,
        creator_id: user.id.clone(),
        channel_id: target_channel_id.clone(),
        permissions: webhook_permissions,
        token: Some(nanoid::nanoid!(64)),
    };
    webhook.create(db).await?;

    let follow = ChannelFollow {
        id: Ulid::new().to_string(),
        source_channel: source_channel_id,
        source_server: source_server_id,
        target_channel: target_channel_id,
        target_server: target_server_id,
        webhook_id: webhook.id.clone(),
        created_by: user.id.clone(),
        created_at: now_ms(),
    };

    if let Err(error) = db.insert_channel_follow(&follow).await {
        // Never leave a dangling webhook if the follow row failed to insert.
        webhook.delete(db).await.ok();
        return Err(error);
    }

    follow.emit_create().await;

    Ok(Json(follow.into_model()))
}

#[cfg(test)]
mod test {
    use crate::util::test::{rt, TestHarness};
    use revolt_database::{
        events::client::EventV1, Channel, Database, PartialChannel, Server, Session, User,
    };
    use rocket::http::{ContentType, Status};
    use serde_json::{json, Value};

    /// The route's full answer: status and JSON body
    async fn follow(
        harness: &TestHarness,
        session: &Session,
        source: &Channel,
        target: &Channel,
    ) -> (Status, Value) {
        let server = target.server().expect("a server target");
        let response = TestHarness::with_session(
            session.clone(),
            harness
                .client
                .post(format!("/channels/{}/follow", source.id()))
                .header(ContentType::JSON)
                .body(json!({ "server": server, "channel": target.id() }).to_string()),
        )
        .await;
        let status = response.status();
        let body = response.into_json::<Value>().await.expect("a JSON body");
        (status, body)
    }

    #[track_caller]
    fn assert_protected(status: Status, body: &Value) {
        assert_eq!(status, Status::BadRequest, "{}", body);
        assert_eq!(body["type"], "ChannelProtected", "{}", body);
    }

    /// A fresh unprotected announcement channel in `server`
    async fn new_announcement(harness: &TestHarness, server: &Server) -> Channel {
        let mut channel = harness.new_channel(server).await;
        channel
            .update(
                &harness.db,
                PartialChannel {
                    announcement: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("announcement");
        channel
    }

    /// Set `protected` on a stored channel through the driver, bypassing the
    /// protect preconditions: the stray state (an announcement channel, or a
    /// channel that already has a follow) the route must still refuse
    async fn raw_protect(db: &Database, channel_id: &str) -> Channel {
        match db {
            Database::Reference(reference) => {
                match reference.channels.lock().await.get_mut(channel_id) {
                    Some(Channel::TextChannel { protected, .. }) => *protected = true,
                    other => panic!("expected a text channel, got {:?}", other),
                }
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, Document};

                let result = mongo
                    .col::<Document>("channels")
                    .update_one(
                        doc! { "_id": channel_id },
                        doc! { "$set": { "protected": true } },
                    )
                    .await
                    .expect("raw protect");
                assert_eq!(result.matched_count, 1);
            }
        }

        let channel = db.fetch_channel(channel_id).await.expect("channel");
        assert!(channel.is_protected());
        channel
    }

    /// Nothing the route writes exists for `target`: no follow, no webhook
    async fn assert_untouched(harness: &TestHarness, target: &Channel) {
        assert!(harness
            .db
            .fetch_follows_by_target(target.id())
            .await
            .expect("follows")
            .is_empty());
        assert!(harness
            .db
            .fetch_webhooks_for_channel(target.id())
            .await
            .expect("webhooks")
            .is_empty());
    }

    fn is_follow_create(source: &str, target: &str) -> impl Fn(&EventV1) -> bool {
        let (source, target) = (source.to_string(), target.to_string());
        move |event| match event {
            EventV1::ChannelFollowCreate { follow } => {
                follow.source_channel == source && follow.target_channel == target
            }
            _ => false,
        }
    }

    /// An owner with an announcement source in one server
    async fn source_world(harness: &TestHarness) -> (Session, User, Server, Channel) {
        let (_, session, owner) = harness.new_user().await;
        let (server, _) = harness.new_protectable_channel(&owner).await;
        let source = new_announcement(harness, &server).await;
        (session, owner, server, source)
    }

    #[test]
    fn follow_into_protected_target_is_refused_without_side_effect() {
        rt().block_on(follow_into_protected_target_is_refused_without_side_effect_case())
    }

    async fn follow_into_protected_target_is_refused_without_side_effect_case() {
        let mut harness = TestHarness::new().await;
        let (session, owner, _, source) = source_world(&harness).await;
        let protected = harness.new_protected_channel(&owner, &session, &[]).await;

        let (status, body) = follow(&harness, &session, &source, &protected.channel).await;
        assert_protected(status, &body);
        assert_untouched(&harness, &protected.channel).await;

        // Positive control: an unprotected sibling in the same server
        let open = harness.new_channel(&protected.server).await;
        let (status, body) = follow(&harness, &session, &source, &open).await;
        assert_eq!(status, Status::Ok, "{}", body);
        assert_eq!(body["target_channel"], open.id(), "{}", body);
        assert_eq!(
            harness
                .db
                .fetch_webhooks_for_channel(open.id())
                .await
                .expect("webhooks")
                .len(),
            1
        );

        // Redis pub/sub is FIFO per subscription: once the sibling's create
        // is observed, anything the refused call published is buffered too.
        harness
            .wait_for_event(
                &protected.server.id,
                is_follow_create(source.id(), open.id()),
            )
            .await;
        harness.assert_no_buffered_event(
            &protected.server.id,
            is_follow_create(source.id(), protected.channel.id()),
        );
    }

    #[test]
    fn follow_from_protected_source_is_refused_without_side_effect() {
        rt().block_on(follow_from_protected_source_is_refused_without_side_effect_case())
    }

    async fn follow_from_protected_source_is_refused_without_side_effect_case() {
        let mut harness = TestHarness::new().await;
        let (session, owner, source_server, open_source) = source_world(&harness).await;
        let stray = new_announcement(&harness, &source_server).await;
        let stray = raw_protect(&harness.db, stray.id()).await;
        let (target_server, target) = harness.new_protectable_channel(&owner).await;

        let (status, body) = follow(&harness, &session, &stray, &target).await;
        assert_protected(status, &body);
        assert_untouched(&harness, &target).await;

        // Positive control: the same target from an unprotected source
        let (status, body) = follow(&harness, &session, &open_source, &target).await;
        assert_eq!(status, Status::Ok, "{}", body);
        assert_eq!(body["source_channel"], open_source.id(), "{}", body);

        harness
            .wait_for_event(
                &target_server.id,
                is_follow_create(open_source.id(), target.id()),
            )
            .await;
        harness
            .assert_no_buffered_event(&target_server.id, is_follow_create(stray.id(), target.id()));
    }

    #[test]
    fn existing_follow_into_now_protected_target_is_refused() {
        rt().block_on(existing_follow_into_now_protected_target_is_refused_case())
    }

    async fn existing_follow_into_now_protected_target_is_refused_case() {
        // The idempotent return must not serve a follow whose target became
        // protected after it was created.
        let harness = TestHarness::new().await;
        let (session, owner, _, source) = source_world(&harness).await;
        let (_, target) = harness.new_protectable_channel(&owner).await;

        let (status, body) = follow(&harness, &session, &source, &target).await;
        assert_eq!(status, Status::Ok, "{}", body);

        let target = raw_protect(&harness.db, target.id()).await;
        let (status, body) = follow(&harness, &session, &source, &target).await;
        assert_protected(status, &body);
        assert_eq!(
            harness
                .db
                .fetch_follows_by_target(target.id())
                .await
                .expect("follows")
                .len(),
            1,
            "the refusal wrote a second follow"
        );
    }

    #[test]
    fn follow_non_manager_answer_is_identical_protected_or_not() {
        rt().block_on(follow_non_manager_answer_is_identical_protected_or_not_case())
    }

    async fn follow_non_manager_answer_is_identical_protected_or_not_case() {
        // Decision 18: a member without ManageWebhooks on the target gets the
        // pre-W2 answer, byte-identical for a protected and an unprotected
        // target, so the refusal reveals nothing about the target.
        let harness = TestHarness::new().await;
        let (session, owner, source_server, source) = source_world(&harness).await;
        let protected = harness.new_protected_channel(&owner, &session, &[]).await;
        let open = harness.new_channel(&protected.server).await;

        let (_, member_session, member) = harness.new_user().await;
        harness.join_server(&source_server, &member).await;
        harness.join_server(&protected.server, &member).await;

        let refused = follow(&harness, &member_session, &source, &protected.channel).await;
        let control = follow(&harness, &member_session, &source, &open).await;
        assert_ne!(refused.1["type"], "ChannelProtected", "{}", refused.1);
        assert!(refused.0.code >= 400, "{}", refused.1);
        assert_eq!(refused.0, control.0);
        assert_eq!(refused.1.to_string(), control.1.to_string());
        assert_untouched(&harness, &protected.channel).await;
    }

    #[test]
    fn follow_non_viewer_answer_is_identical_protected_or_not() {
        rt().block_on(follow_non_viewer_answer_is_identical_protected_or_not_case())
    }

    async fn follow_non_viewer_answer_is_identical_protected_or_not_case() {
        // Decision 18: a caller who cannot see the source gets the pre-W2
        // answer, byte-identical for a protected and an unprotected source.
        let harness = TestHarness::new().await;
        let (_, _, source_server, open_source) = source_world(&harness).await;
        let stray = new_announcement(&harness, &source_server).await;
        let stray = raw_protect(&harness.db, stray.id()).await;

        let (_, outsider_session, outsider) = harness.new_user().await;
        let (_, target) = harness.new_protectable_channel(&outsider).await;

        let refused = follow(&harness, &outsider_session, &stray, &target).await;
        let control = follow(&harness, &outsider_session, &open_source, &target).await;
        assert_ne!(refused.1["type"], "ChannelProtected", "{}", refused.1);
        assert!(refused.0.code >= 400, "{}", refused.1);
        assert_eq!(refused.0, control.0);
        assert_eq!(refused.1.to_string(), control.1.to_string());
        assert_untouched(&harness, &target).await;
    }
}
