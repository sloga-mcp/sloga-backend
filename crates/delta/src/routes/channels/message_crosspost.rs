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
    use revolt_database::MessageFlagsValue;
    use revolt_models::v0::{self, MessageFlags};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

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
}
