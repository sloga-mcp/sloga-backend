use std::time::{Duration, SystemTime};

use revolt_config::config;
use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Channel, Database, Message, MessageFlagsValue, PartialMessage, User, AMQP,
};
use revolt_models::v0::{self, MessageFlags};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use ulid::Ulid;

/// # Publish (crosspost) an announcement message
///
/// Publishes a message from an announcement channel: flags the origin as
/// `Crossposted` and fans a webhook-authored copy (carrying server-set
/// origin attribution) into every follower channel.
///
/// The caller needs `SendMessage`, plus `ManageMessages` when publishing
/// someone else's message. A message can only be published once, and a
/// delivered crosspost copy can never be re-published (loop prevention).
#[openapi(tag = "Messaging")]
#[post("/<channel>/messages/<msg>/crosspost")]
pub async fn message_crosspost(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    channel: Reference<'_>,
    msg: Reference<'_>,
) -> Result<Json<v0::Message>> {
    // The source must be a server text channel flagged as an announcement
    // channel — this type constraint IS the server-side E2EE fail-closed
    // guarantee (DMs/groups can never be announcement channels).
    let source_channel = channel.as_channel(db).await?;
    let (source_channel_id, source_server_id, is_announcement) = match &source_channel {
        Channel::TextChannel {
            id,
            server,
            announcement,
            ..
        } => (id.clone(), server.clone(), *announcement == Some(true)),
        _ => return Err(create_error!(NotAnAnnouncementChannel)),
    };
    if !is_announcement {
        return Err(create_error!(NotAnAnnouncementChannel));
    }

    let mut origin = msg.as_message_in_channel(db, &source_channel_id).await?;

    // Permission: SendMessage, and ManageMessages when it isn't your message.
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&source_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;
    if origin.author != user.id {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageMessages)?;
    }

    // A protected channel never publishes: every copy is a plaintext,
    // webhook-authored message. Only reachable through a stored channel that
    // breaks the announcement/protected exclusion, so this holds it here too.
    // Refused after the permission check, so a caller who may not publish
    // learns nothing about the channel's protected status.
    if source_channel.is_protected() || origin.encrypted.is_some() {
        return Err(create_error!(ChannelProtected));
    }

    // System messages don't publish.
    if origin.system.is_some() {
        return Err(create_error!(InvalidOperation));
    }

    // Already published, or itself a delivered crosspost copy — reject
    // (loop prevention against A→B→A amplification).
    let origin_flags = MessageFlagsValue(origin.flags.unwrap_or(0));
    if origin_flags.has(MessageFlags::Crossposted) || origin_flags.has(MessageFlags::IsCrosspost) {
        return Err(create_error!(AlreadyCrossposted));
    }

    // Durable per-channel hourly publish cap (counted from Crossposted-flag
    // messages in the last hour — no separate collection needed).
    let cfg = config().await;
    let hourly_cap = cfg.features.limits.global.crossposts_per_hour;
    let hour_ago = Ulid::from_datetime(SystemTime::now() - Duration::from_secs(3600)).to_string();
    if db
        .count_crossposts_since(&source_channel_id, &hour_ago)
        .await?
        >= hourly_cap
    {
        return Err(create_error!(TooManyCrossposts { max: hourly_cap }));
    }

    // 1) Flag the origin as published (fans a MessageUpdate to the source).
    let mut new_flags = origin_flags;
    new_flags.set(MessageFlags::Crossposted, true);
    origin
        .update(
            db,
            PartialMessage {
                flags: Some(new_flags.0),
                ..Default::default()
            },
            vec![],
        )
        .await?;

    // 2) Fan a webhook-authored copy into every follower channel. Bounded by
    //    the follower cap; dead follows are reaped lazily.
    let attribution = v0::CrosspostInfo {
        message_id: origin.id.clone(),
        channel_id: source_channel_id.clone(),
        server_id: source_server_id,
    };

    for follow in db.fetch_follows_by_source(&source_channel_id).await? {
        // Target channel must still exist and be a server text channel.
        let target_channel = match db.fetch_channel(&follow.target_channel).await {
            Ok(target @ Channel::TextChannel { .. }) => target,
            _ => {
                // Dead target — reap the follow (and its now-orphaned webhook).
                db.delete_channel_follow(&follow.id).await.ok();
                db.delete_webhook(&follow.webhook_id).await.ok();
                follow.emit_delete().await;
                continue;
            }
        };

        // A protected follower never receives a plaintext copy. Skipped
        // before any delivery or reaping: the follow and its webhook stay.
        if target_channel.is_protected() {
            log::info!(
                "crosspost {}: skipped protected follower channel {} (follow {})",
                origin.id,
                follow.target_channel,
                follow.id
            );
            continue;
        }

        // Webhook must still exist (it authors + gates the delivered copy).
        let webhook = match db.fetch_webhook(&follow.webhook_id).await {
            Ok(webhook) => webhook,
            Err(_) => {
                db.delete_channel_follow(&follow.id).await.ok();
                follow.emit_delete().await;
                continue;
            }
        };

        // MVP delivers content + embeds only. If the origin carried neither
        // (attachment- or sticker-only announcement — those are stripped),
        // there is nothing to render, so skip this follower rather than
        // deliver a blank message.
        let has_body = origin.content.as_ref().is_some_and(|c| !c.is_empty())
            || origin.embeds.as_ref().is_some_and(|e| !e.is_empty());
        if !has_body {
            continue;
        }

        let v0_webhook: v0::Webhook = webhook.clone().into();

        let mut copy_flags = MessageFlagsValue(0);
        copy_flags.set(MessageFlags::IsCrosspost, true);

        // MVP copies content + embeds only — attachments and stickers are
        // stripped (Autumn file ownership is per-origin-message) alongside
        // mentions / replies / reactions / masquerade.
        let mut copy = Message {
            id: Ulid::new().to_string(),
            channel: follow.target_channel.clone(),
            author: webhook.id.clone(),
            webhook: Some(v0_webhook.clone().into()),
            content: origin.content.clone(),
            embeds: origin.embeds.clone(),
            flags: Some(copy_flags.0),
            crosspost: Some(attribution.clone()),
            ..Default::default()
        };

        // A failed delivery to one follower must not abort the others.
        copy.send(
            db,
            Some(amqp),
            v0::MessageAuthor::Webhook(&v0_webhook),
            None,
            None,
            &target_channel,
            false,
        )
        .await
        .ok();
    }

    Ok(Json(origin.into_model(None, None)))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{
        events::client::EventV1, Channel, ChannelFollow, Database, Message, MessageFilter,
        MessageFlagsValue, MessageQuery, MessageTimePeriod, PartialChannel, Webhook,
    };
    use revolt_models::v0::{self, MessageFlags};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;
    use ulid::Ulid;

    #[test]
    fn crosspost_flags_origin_and_prevents_reposting() {
        crate::util::test::rt().block_on(crosspost_flags_origin_and_prevents_reposting_case())
    }

    async fn crosspost_flags_origin_and_prevents_reposting_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, channels) = harness.new_server(&user).await;
        let (_, _, message) = harness.new_message(&user, &server, channels.clone()).await;
        let channel = &channels[0];

        // Not an announcement channel yet → rejected.
        let response = harness
            .client
            .post(format!(
                "/channels/{}/messages/{}/crosspost",
                channel.id(),
                message.id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_ne!(
            response.status(),
            Status::Ok,
            "publishing from a non-announcement channel must be rejected"
        );

        // Flag the channel as an announcement channel.
        let response = harness
            .client
            .patch(format!("/channels/{}", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "announcement": true }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        // Publish succeeds and flags the origin as Crossposted.
        let response = harness
            .client
            .post(format!(
                "/channels/{}/messages/{}/crosspost",
                channel.id(),
                message.id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let published: v0::Message = response.into_json().await.expect("`Message`");
        assert!(
            MessageFlagsValue(published.flags).has(MessageFlags::Crossposted),
            "origin must carry the Crossposted flag"
        );

        // Publishing the same message again is rejected (loop prevention).
        let response = harness
            .client
            .post(format!(
                "/channels/{}/messages/{}/crosspost",
                channel.id(),
                message.id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_ne!(
            response.status(),
            Status::Ok,
            "an already-published message cannot be published again"
        );
    }

    #[test]
    fn regular_send_cannot_forge_crosspost_flags() {
        crate::util::test::rt().block_on(regular_send_cannot_forge_crosspost_flags_case())
    }

    async fn regular_send_cannot_forge_crosspost_flags_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        // Attempt to send a normal message carrying the Crossposted bit (128).
        let response = harness
            .client
            .post(format!("/channels/{}/messages", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "content": "fake", "flags": 128 }).to_string())
            .dispatch()
            .await;
        assert_ne!(
            response.status(),
            Status::Ok,
            "regular send must reject the Crossposted flag (flags > 7)"
        );
    }

    /// Flag `channel` as an announcement channel through the model
    async fn announce(db: &Database, channel: &Channel) {
        let mut channel = channel.clone();
        channel
            .update(
                db,
                PartialChannel {
                    announcement: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("announce");
    }

    /// Set `protected` on a stored channel directly, past the protect
    /// route's checks: no protected announcement channel or protected
    /// channel holding plaintext can be made any other way
    async fn protect_raw(db: &Database, channel_id: &str) {
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

        assert!(db
            .fetch_channel(channel_id)
            .await
            .expect("channel")
            .is_protected());
    }

    /// A plaintext row by `author` in `channel`, stored through the driver
    async fn insert_plaintext(db: &Database, channel: &Channel, author: &str) -> Message {
        let message = Message {
            id: Ulid::new().to_string(),
            channel: channel.id().to_string(),
            author: author.to_string(),
            content: Some("Announcement".to_string()),
            ..Default::default()
        };
        db.insert_message(&message)
            .await
            .expect("Failed to store test plaintext message");
        message
    }

    /// A follow of `source` from `target`, with its webhook, stored the way
    /// `follow_channel` stores them
    async fn follow(
        db: &Database,
        source: &Channel,
        target: &Channel,
        created_by: &str,
    ) -> ChannelFollow {
        let webhook = Webhook {
            id: Ulid::new().to_string(),
            name: "Follower".to_string(),
            avatar: None,
            creator_id: created_by.to_string(),
            channel_id: target.id().to_string(),
            permissions: 0,
            token: Some(Ulid::new().to_string()),
        };
        webhook.create(db).await.expect("`Webhook`");

        let follow = ChannelFollow {
            id: Ulid::new().to_string(),
            source_channel: source.id().to_string(),
            source_server: source.server().expect("a server channel").to_string(),
            target_channel: target.id().to_string(),
            target_server: target.server().expect("a server channel").to_string(),
            webhook_id: webhook.id,
            created_by: created_by.to_string(),
            created_at: 0,
        };
        db.insert_channel_follow(&follow)
            .await
            .expect("`ChannelFollow`");
        follow
    }

    async fn channel_messages(db: &Database, channel_id: &str) -> Vec<Message> {
        db.fetch_messages(MessageQuery {
            limit: Some(10),
            filter: MessageFilter {
                channel: Some(channel_id.to_string()),
                ..Default::default()
            },
            time_period: MessageTimePeriod::Absolute {
                before: None,
                after: None,
                sort: None,
            },
        })
        .await
        .expect("the channel's messages")
    }

    /// POST the crosspost route; the status and the raw body
    async fn crosspost(
        harness: &TestHarness,
        token: &str,
        channel_id: &str,
        message_id: &str,
    ) -> (Status, String) {
        let response = harness
            .client
            .post(format!(
                "/channels/{}/messages/{}/crosspost",
                channel_id, message_id
            ))
            .header(Header::new("x-session-token", token.to_string()))
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    fn error_type(body: &str) -> String {
        let body: serde_json::Value = serde_json::from_str(body).expect("an error body");
        body["type"].as_str().unwrap_or_default().to_string()
    }

    /// Publish a marker `ChannelAck` on `user`'s private topic and wait for
    /// it. Redis pub/sub is FIFO on the harness's one subscription, so once
    /// the marker is seen everything the request published before it is in
    /// the event buffer, where `assert_no_buffered_event` can see it.
    async fn flush_with_marker(harness: &mut TestHarness, user: &str, channel_id: &str) {
        let marker = Ulid::new().to_string();

        EventV1::ChannelAck {
            id: channel_id.to_string(),
            user: user.to_string(),
            message_id: marker.clone(),
        }
        .private(user.to_string())
        .await;

        harness
            .wait_for_event(&format!("{user}!"), |event| match event {
                EventV1::ChannelAck { message_id, .. } => message_id == &marker,
                _ => false,
            })
            .await;
    }

    #[test]
    fn crosspost_from_a_protected_channel_is_refused_without_side_effects() {
        crate::util::test::rt()
            .block_on(crosspost_from_a_protected_channel_is_refused_without_side_effects_case())
    }

    async fn crosspost_from_a_protected_channel_is_refused_without_side_effects_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (_, source) = harness.new_protectable_channel(&owner).await;
        announce(&harness.db, &source).await;
        let origin = insert_plaintext(&harness.db, &source, &owner.id).await;
        let (_, target) = harness.new_protectable_channel(&owner).await;
        let follow = follow(&harness.db, &source, &target, &owner.id).await;
        protect_raw(&harness.db, source.id()).await;

        let (status, body) = crosspost(&harness, &session.token, source.id(), &origin.id).await;
        assert_eq!(status, Status::BadRequest, "{}", body);
        assert_eq!(error_type(&body), "ChannelProtected", "{}", body);

        // Nothing written: the origin is not flagged, no copy was delivered,
        // and the follow and its webhook are untouched
        assert_eq!(
            harness
                .db
                .fetch_message(&origin.id)
                .await
                .expect("the origin"),
            origin
        );
        assert!(channel_messages(&harness.db, target.id()).await.is_empty());
        harness
            .db
            .fetch_follow(&follow.id)
            .await
            .expect("the follow stays");
        harness
            .db
            .fetch_webhook(&follow.webhook_id)
            .await
            .expect("the webhook stays");

        // Nothing published: no origin update, no delivered copy
        flush_with_marker(&mut harness, &owner.id, source.id()).await;
        harness.assert_no_buffered_event(source.id(), |event| match event {
            EventV1::MessageUpdate { id, .. } => id == &origin.id,
            _ => false,
        });
        harness.assert_no_buffered_event(target.id(), |event| matches!(event, EventV1::Message(_)));
    }

    #[test]
    fn crosspost_skips_protected_followers_and_delivers_to_the_rest() {
        crate::util::test::rt()
            .block_on(crosspost_skips_protected_followers_and_delivers_to_the_rest_case())
    }

    async fn crosspost_skips_protected_followers_and_delivers_to_the_rest_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (_, source) = harness.new_protectable_channel(&owner).await;
        announce(&harness.db, &source).await;
        let origin = insert_plaintext(&harness.db, &source, &owner.id).await;

        let (_, open) = harness.new_protectable_channel(&owner).await;
        let (_, protected) = harness.new_protectable_channel(&owner).await;
        let (_, protected_orphan) = harness.new_protectable_channel(&owner).await;
        let open_follow = follow(&harness.db, &source, &open, &owner.id).await;
        let protected_follow = follow(&harness.db, &source, &protected, &owner.id).await;
        let orphan_follow = follow(&harness.db, &source, &protected_orphan, &owner.id).await;

        // Both followers were protected after they followed; one of them has
        // also lost its webhook, which an unprotected follower gets reaped for
        protect_raw(&harness.db, protected.id()).await;
        protect_raw(&harness.db, protected_orphan.id()).await;
        harness
            .db
            .delete_webhook(&orphan_follow.webhook_id)
            .await
            .expect("delete the webhook");

        // The unprotected source publishes (positive control)
        let (status, body) = crosspost(&harness, &session.token, source.id(), &origin.id).await;
        assert_eq!(status, Status::Ok, "{}", body);
        let published: v0::Message = serde_json::from_str(&body).expect("`Message`");
        assert!(MessageFlagsValue(published.flags).has(MessageFlags::Crossposted));

        // The unprotected follower receives its copy
        let delivered = channel_messages(&harness.db, open.id()).await;
        assert_eq!(delivered.len(), 1, "{:?}", delivered);
        assert_eq!(delivered[0].author, open_follow.webhook_id);
        assert_eq!(
            delivered[0]
                .crosspost
                .as_ref()
                .map(|c| c.message_id.as_str()),
            Some(origin.id.as_str())
        );

        // The protected followers are skipped before any delivery or
        // reaping: no copy, and every follow and webhook still stands
        assert!(channel_messages(&harness.db, protected.id())
            .await
            .is_empty());
        assert!(channel_messages(&harness.db, protected_orphan.id())
            .await
            .is_empty());
        harness
            .db
            .fetch_follow(&protected_follow.id)
            .await
            .expect("the protected follower's follow stays");
        harness
            .db
            .fetch_webhook(&protected_follow.webhook_id)
            .await
            .expect("the protected follower's webhook stays");
        harness
            .db
            .fetch_follow(&orphan_follow.id)
            .await
            .expect("a protected follower is never reaped by a publish");
    }

    #[test]
    fn crosspost_by_a_non_publisher_answers_the_same_on_a_protected_channel() {
        crate::util::test::rt()
            .block_on(crosspost_by_a_non_publisher_answers_the_same_on_a_protected_channel_case())
    }

    async fn crosspost_by_a_non_publisher_answers_the_same_on_a_protected_channel_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (_, outsider_session, _) = harness.new_user().await;
        let (_, open) = harness.new_protectable_channel(&owner).await;
        let (_, protected) = harness.new_protectable_channel(&owner).await;
        announce(&harness.db, &open).await;
        announce(&harness.db, &protected).await;
        let open_origin = insert_plaintext(&harness.db, &open, &owner.id).await;
        let protected_origin = insert_plaintext(&harness.db, &protected, &owner.id).await;
        protect_raw(&harness.db, protected.id()).await;

        // The protected channel does refuse a caller who may publish there
        let (status, body) = crosspost(
            &harness,
            &session.token,
            protected.id(),
            &protected_origin.id,
        )
        .await;
        assert_eq!(status, Status::BadRequest, "{}", body);
        assert_eq!(error_type(&body), "ChannelProtected", "{}", body);

        // A caller who may not publish gets the permission error, byte for
        // byte the same on both channels
        let open_answer = crosspost(
            &harness,
            &outsider_session.token,
            open.id(),
            &open_origin.id,
        )
        .await;
        let protected_answer = crosspost(
            &harness,
            &outsider_session.token,
            protected.id(),
            &protected_origin.id,
        )
        .await;
        assert_ne!(open_answer.0, Status::Ok, "{}", open_answer.1);
        assert_ne!(error_type(&open_answer.1), "ChannelProtected");
        assert_eq!(protected_answer, open_answer);
    }
}
