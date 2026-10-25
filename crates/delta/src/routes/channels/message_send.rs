use std::convert::Infallible;
use std::time::Duration;

use revolt_config::config;
use revolt_database::events::client::EventV1;
use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::{
    util::antispam, util::idempotency::IdempotencyKey, util::reference::Reference, Database, User,
};
use revolt_database::{validate_protected_send, MlsGroupKind, Session};
use revolt_database::{Channel, Interactions, Message, Referral, ReferralActivity, AMQP};
use revolt_models::v0;
use revolt_permissions::PermissionQuery;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Error, ErrorType, Result};
use revolt_rocket_okapi::r#gen::OpenApiGenerator;
use revolt_rocket_okapi::request::{OpenApiFromRequest, RequestHeaderInput};
use rocket::request::{FromRequest, Outcome};
use rocket::serde::json::Json;
use rocket::{Request, State};
use validator::Validate;

use crate::routes::mls::{require_protected_available, require_seated};

/// Whether the request carried an `Idempotency-Key` header at all.
/// [`IdempotencyKey`] mints a key when the header is absent, so its key
/// cannot tell "absent" from "present"; a protected send must (design 7.3,
/// W0-fix2). Never fails.
pub struct IdempotencyHeader {
    present: bool,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for IdempotencyHeader {
    type Error = Infallible;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(IdempotencyHeader {
            present: request.headers().contains("Idempotency-Key"),
        })
    }
}

impl OpenApiFromRequest<'_> for IdempotencyHeader {
    /// Documents nothing: the route's [`IdempotencyKey`] guard already
    /// documents the `Idempotency-Key` header, and a second parameter with
    /// the same name and location is invalid OpenAPI.
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> revolt_rocket_okapi::Result<RequestHeaderInput> {
        Ok(RequestHeaderInput::None)
    }
}

/// # Send Message
///
/// Sends a message to the given channel.
#[openapi(tag = "Messaging")]
#[post("/<target>/messages", data = "<data>")]
#[allow(clippy::too_many_arguments)]
pub async fn message_send(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    session: Option<Session>,
    target: Reference<'_>,
    data: Json<v0::DataMessageSend>,
    idempotency: IdempotencyKey,
    idempotency_header: IdempotencyHeader,
) -> Result<Json<v0::Message>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Ensure we have permissions to send a message
    let channel = target.as_channel(db).await?;

    // Forum channels have no message stream of their own — content lives in
    // posts (threads). Fail closed on direct sends.
    if matches!(channel, Channel::Forum { .. }) {
        return Err(create_error!(InvalidOperation));
    }

    // Threads delegate their permission calculus to the parent text channel;
    // resolve it BEFORE constructing the query so a thread under a private
    // parent inherits the parent's overrides instead of falling through to
    // server-wide defaults.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    // Protected channels (design 7.3). Both refusals run after the
    // SendMessage check, so a caller who cannot view the channel gets the
    // same answer for a protected channel as for any other (decision 18
    // (W2)), and before the thread, masquerade, embed and file checks and
    // slowmode, which claims its slot at check time.
    if matches!(channel, Channel::Thread { .. }) && permission_channel.is_protected() {
        // No such thread can exist (2.5 "Race closure"): defense in depth
        return Err(create_error!(ChannelProtected));
    }

    if channel.is_protected() {
        check_protected_send(
            db,
            &user,
            session.as_ref(),
            &channel,
            &data,
            &idempotency_header,
        )
        .await?;
    }

    // Archived or locked threads reject new messages unless the sender can
    // manage the parent channel (which is also how a thread gets unarchived).
    crate::util::threads::ensure_thread_writable(&channel, &permissions)?;

    // Verify permissions for masquerade
    if let Some(masq) = &data.masquerade {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::Masquerade)?;

        if masq.colour.is_some() {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageRole)?;
        }
    }

    // Check permissions for embeds
    if data.embeds.as_ref().is_some_and(|v| !v.is_empty()) {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::SendEmbeds)?;
    }

    // Check permissions for files
    if data.attachments.as_ref().is_some_and(|v| !v.is_empty()) {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::UploadFiles)?;
    }

    crate::util::slowmode::enforce_slowmode(&user, &channel, &permissions).await?;

    // Ensure interactions information is correct
    if let Some(interactions) = &data.interactions {
        let interactions: Interactions = interactions.clone().into();
        interactions.validate(db, &permissions).await?;
    }

    // Disallow mentions for new users (TRUST-0: <12 hours age) in public servers
    let allow_mentions = if let Some(server) = query.server_ref() {
        if server.discoverable {
            (ulid::Ulid::from_string(&user.id)
                .unwrap()
                .datetime()
                .elapsed()
                .expect("Time went backwards"))
                >= Duration::from_hours(12)
        } else {
            true
        }
    } else {
        true
    };

    // Create the message
    let author: v0::User = user.clone().into(db, Some(&user)).await;

    // Make sure we have server member (edge case if server owner)
    query.are_we_a_member().await;

    // Create model user / members
    let model_user = user
        .clone()
        .into_known_static(revolt_presence::is_online(&user.id).await)
        .await;

    let model_member: Option<v0::Member> = query
        .member_ref()
        .as_ref()
        .map(|member| member.clone().into_owned().into());

    // Capture the thread's identity before `channel` is consumed by the send,
    // so we can auto-join the author once the message lands.
    let thread_info = if let Channel::Thread { server, .. } = &channel {
        Some((channel.id().to_string(), server.clone()))
    } else {
        None
    };

    // Notes to self don't count towards a pending referral.
    let counts_for_referral = !matches!(channel, Channel::SavedMessages { .. });

    // Anti-spam looks at direct messages only (never groups, saved messages
    // or server channels), so capture the DM's id and peer before `channel`
    // is consumed by the send.
    let dm_peer = if let Channel::DirectMessage { id, recipients, .. } = &channel {
        recipients
            .iter()
            .find(|recipient| *recipient != &user.id)
            .map(|peer| (id.clone(), peer.clone()))
    } else {
        None
    };

    // A paused account may keep talking to anyone who has written to it, but
    // may not open conversations with strangers. Checked before anything is
    // stored (message, attachments, embeds).
    let antispam_config = if let Some((channel_id, peer)) = &dm_peer {
        let antispam_config = config().await.features.antispam.clone();
        antispam::dm_send_allowed(db, &antispam_config, &user, channel_id, peer).await?;
        Some(antispam_config)
    } else {
        None
    };

    let message = Message::create_from_api(
        db,
        Some(amqp),
        channel,
        data,
        v0::MessageAuthor::User(&author),
        Some(model_user.clone()),
        model_member.clone(),
        user.limits().await,
        idempotency,
        permissions.has_channel_permission(ChannelPermission::SendEmbeds),
        allow_mentions,
    )
    .await?;

    // Recorded as soon as the message is stored, before the thread join
    // below can fail the request.
    if counts_for_referral {
        Referral::record_activity(db, &user, ReferralActivity::Message).await;
    }

    // Copy-paste DM detection runs on the stored message (it carries the
    // text embeds) off the request path: it never fails or delays the send.
    if let (Some((channel_id, peer)), Some(antispam_config)) = (dm_peer, antispam_config) {
        let (db, user, message) = (db.inner().clone(), user.clone(), message.clone());
        tokio::spawn(async move {
            antispam::observe_dm_message(
                &db,
                &antispam_config,
                &user,
                &channel_id,
                &peer,
                &message,
            )
            .await;
        });
    }

    // Sending in a thread joins you to it (Discord parity), so you start
    // receiving its notifications.
    if let Some((thread_id, server_id)) = thread_info {
        if db.join_thread_if_absent(&thread_id, &user.id).await? {
            EventV1::ThreadMemberJoin {
                id: thread_id,
                user: user.id.clone(),
            }
            .p(server_id)
            .await;
        }
    }

    Ok(Json(message.into_model(Some(model_user), model_member)))
}

fn resecuring(reason: &str) -> Error {
    create_error!(ProtectedChannelResecuring {
        reason: reason.to_string()
    })
}

/// The protected-channel send checks of design 7.3, steps 0 to 7, in that
/// order. Slowmode (step 8) and `create_from_api` follow in the route.
async fn check_protected_send(
    db: &Database,
    user: &User,
    session: Option<&Session>,
    channel: &Channel,
    data: &v0::DataMessageSend,
    idempotency_header: &IdempotencyHeader,
) -> Result<()> {
    // 0. The text plane's kill switch
    require_protected_available().await?;

    // 1. No `Idempotency-Key` (3.10: the message `nonce` is the replay key),
    // then the one allowlist and the payload's structure (2.6)
    if idempotency_header.present {
        return Err(create_error!(ProtectedFieldRefused {
            field: "idempotency-key".to_string()
        }));
    }

    let author: v0::User = user.clone().into(db, Some(user)).await;
    validate_protected_send(true, &v0::MessageAuthor::User(&author), data, false)?;
    let Some(encrypted) = &data.encrypted else {
        // Unreachable: the allowlist refuses a send without a payload
        return Err(create_error!(ChannelProtected));
    };

    // 2. Seated
    require_seated(db, channel.id(), &user.id).await?;

    // 3. The session is bound to the sending device, which is the caller's.
    // A bot has no session; an unknown device is not bound to this one.
    let Some(session) = session else {
        return Err(create_error!(NotAuthenticated));
    };
    match db
        .fetch_e2ee_identity(&user.id, &encrypted.sender_device_id)
        .await
    {
        Ok(identity) => identity.assert_bound_session(&session.id)?,
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => {
            return Err(create_error!(NotAuthenticated))
        }
        Err(error) => return Err(error),
    }

    // 4. The channel's open Text group, and the payload names it
    let group = db
        .fetch_open_mls_group_for_channel(channel.id(), MlsGroupKind::Text)
        .await?
        .filter(|group| group.id == encrypted.group_id)
        .ok_or_else(|| resecuring("stale_group"))?;

    // 5. No removal is pending
    if !group.pending_removals.is_empty() {
        return Err(resecuring("pending_removal"));
    }

    // 6. The current epoch
    if encrypted.epoch != group.current_epoch {
        return Err(resecuring("stale_epoch"));
    }

    // 7. The sending device is a member
    if !group.has_member(&user.id, &encrypted.sender_device_id) {
        return Err(resecuring("not_member"));
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    use crate::{rocket, util::test::TestHarness};
    use revolt_config::config;
    use revolt_database::{events::client::EventV1, Bot};
    use revolt_database::{
        iso8601_timestamp::Timestamp, DmGuard, MessageFilter, MessageQuery, MessageTimePeriod,
        RelationshipStatus, Report, Session, User, SYSTEM_USER_ID,
    };
    use revolt_database::{
        util::{idempotency::IdempotencyKey, reference::Reference},
        Channel, Member, Message, MessageFlagsValue, PartialChannel, PartialMember, Role, Server,
    };
    use revolt_database::{PartialUser, Referral, ReferralSource};
    use revolt_models::v0::{self, DataCreateServerChannel, MessageFlags};
    use revolt_permissions::{ChannelPermission, OverrideField};
    use revolt_result::ErrorType;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    #[test]
    fn message_mention_constraints() {
        crate::util::test::rt().block_on(message_mention_constraints_case())
    }

    async fn message_mention_constraints_case() {
        let harness = TestHarness::new().await;
        let (_, _, user) = harness.new_user().await;
        let (_, _, second_user) = harness.new_user().await;

        let (server, channels) = Server::create(
            &harness.db,
            v0::DataCreateServer {
                name: "Test Server".to_string(),
                ..Default::default()
            },
            &user,
            true,
        )
        .await
        .expect("Failed to create test server");

        let server_mut: &mut Server = &mut server.clone();
        let mut locked_channel = Channel::create_server_channel(
            &harness.db,
            server_mut,
            DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Text,
                name: "Hidden Channel".to_string(),
                description: None,
                nsfw: Some(false),
                spoiler: None,
                voice: None,
                announcement: None,
                ..Default::default()
            },
            true,
        )
        .await
        .expect("Failed to make new channel");

        let role = Role::create(&harness.db, &server, "Show Hidden Channel".to_string())
            .await
            .expect("Failed to create the role");

        let mut overrides = HashMap::new();
        overrides.insert(
            role.id.clone(),
            OverrideField {
                a: (ChannelPermission::ViewChannel) as i64,
                d: 0,
            },
        );

        let partial = PartialChannel {
            name: None,
            owner: None,
            description: None,
            icon: None,
            nsfw: None,
            spoiler: None,
            active: None,
            permissions: None,
            role_permissions: Some(overrides),
            default_permissions: Some(OverrideField {
                a: 0,
                d: ChannelPermission::ViewChannel as i64,
            }),
            last_message_id: None,
            voice: None,
            slowmode: None,
            archived: None,
            archived_timestamp: None,
            tags: None,
            require_tag: None,
            default_sort: None,
            force_sort: None,
            default_layout: None,
            auto_archive_minutes: None,
            default_auto_archive_minutes: None,
            applied_tags: None,
            announcement: None,
            protected: None,
        };
        locked_channel
            .update(&harness.db, partial, vec![])
            .await
            .expect("Failed to update the channel permissions for special role");

        Member::create(&harness.db, &server, &user, Some(channels.clone()))
            .await
            .expect("Failed to create member");
        let member = Reference::from_unchecked(&user.id)
            .as_member(&harness.db, &server.id)
            .await
            .expect("Failed to get member");

        // Second user is not part of the server
        let message = Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            locked_channel.clone(),
            v0::DataMessageSend {
                content: Some(format!("<@{}>", second_user.id)),
                nonce: None,
                attachments: None,
                replies: None,
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                encrypted: None,
                flags: None,
            },
            v0::MessageAuthor::User(&user.clone().into(&harness.db, Some(&user)).await),
            Some(user.clone().into(&harness.db, Some(&user)).await),
            Some(member.clone().into()),
            user.limits().await,
            IdempotencyKey::unchecked_from_string("0".to_string()),
            false,
            true,
        )
        .await
        .expect("Failed to create message");

        // The mention should not go through here
        assert!(
            message.mentions.is_none() || message.mentions.unwrap().is_empty(),
            "Mention failed to be scrubbed when the user is not part of the server"
        );

        Member::create(&harness.db, &server, &second_user, Some(channels.clone()))
            .await
            .expect("Failed to create second member");
        let mut second_member = Reference::from_unchecked(&second_user.id)
            .as_member(&harness.db, &server.id)
            .await
            .expect("Failed to get second member");

        // Second user cannot see the channel
        let message = Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            locked_channel.clone(),
            v0::DataMessageSend {
                content: Some(format!("<@{}>", second_user.id)),
                nonce: None,
                attachments: None,
                replies: None,
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                encrypted: None,
                flags: None,
            },
            v0::MessageAuthor::User(&user.clone().into(&harness.db, Some(&user)).await),
            Some(user.clone().into(&harness.db, Some(&user)).await),
            Some(member.clone().into()),
            user.limits().await,
            IdempotencyKey::unchecked_from_string("1".to_string()),
            false,
            true,
        )
        .await
        .expect("Failed to create message");

        // The mention should not go through here
        assert!(
            message.mentions.is_none() || message.mentions.unwrap().is_empty(),
            "Mention failed to be scrubbed when the user cannot see the channel"
        );

        let second_member_roles = vec![role.id.clone()];
        let partial = PartialMember {
            id: None,
            joined_at: None,
            nickname: None,
            pronouns: None,
            avatar: None,
            timeout: None,
            roles: Some(second_member_roles),
            can_publish: None,
            can_receive: None,
        };
        second_member
            .update(&harness.db, partial, vec![])
            .await
            .expect("Failed to update the second user's roles");

        // This time the mention SHOULD go through
        let message = Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            locked_channel.clone(),
            v0::DataMessageSend {
                content: Some(format!("<@{}>", second_user.id)),
                nonce: None,
                attachments: None,
                replies: None,
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                encrypted: None,
                flags: None,
            },
            v0::MessageAuthor::User(&user.clone().into(&harness.db, Some(&user)).await),
            Some(user.clone().into(&harness.db, Some(&user)).await),
            Some(member.clone().into()),
            user.limits().await,
            IdempotencyKey::unchecked_from_string("2".to_string()),
            false,
            true,
        )
        .await
        .expect("Failed to create message");

        // The mention SHOULD go through here
        assert!(
            message.mentions.is_some() && !message.mentions.unwrap().is_empty(),
            "Mention was scrubbed when the user can see the channel"
        );
    }

    #[test]
    fn message_reply() {
        crate::util::test::rt().block_on(message_reply_case())
    }

    async fn message_reply_case() {
        let harness = TestHarness::new().await;
        let (_, _, user) = harness.new_user().await;
        let (server, channels) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;
        let (_, member, message) = harness.new_message(&user, &server, channels).await;

        // Send a message with a reply
        // Should succeed
        let message_with_reply = Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            channel.clone(),
            v0::DataMessageSend {
                content: Some("Message with reply".to_string()),
                nonce: None,
                attachments: None,
                replies: Some(vec![v0::ReplyIntent {
                    id: message.id.clone(),
                    mention: false,
                    fail_if_not_exists: Some(true),
                }]),
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                encrypted: None,
                flags: None,
            },
            v0::MessageAuthor::User(&user.clone().into(&harness.db, Some(&user)).await),
            Some(user.clone().into(&harness.db, Some(&user)).await),
            Some(member.clone().into()),
            user.limits().await,
            IdempotencyKey::unchecked_from_string("1".to_string()),
            false,
            false,
        )
        .await
        .expect("Failed to create message with reply");

        assert!(
            message_with_reply.replies.is_some(),
            "Message replies is None",
        );

        let replies = message_with_reply.replies.unwrap();

        assert!(!replies.is_empty(), "Message replies is empty",);

        assert_eq!(replies[0], message.id, "Message reply ID does not match",);

        // Delete the message
        message
            .clone()
            .delete(&harness.db)
            .await
            .expect("Failed to delete message");

        // Attempt to create messages with a reply to a deleted message

        // fail_if_not_exists is set to false
        // Should send the message without a reply
        let message_with_missing_reply = Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            channel.clone(),
            v0::DataMessageSend {
                content: Some("Message with missing reply".to_string()),
                nonce: None,
                attachments: None,
                replies: Some(vec![v0::ReplyIntent {
                    id: message.id.clone(),
                    mention: false,
                    fail_if_not_exists: Some(false),
                }]),
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                encrypted: None,
                flags: None,
            },
            v0::MessageAuthor::User(&user.clone().into(&harness.db, Some(&user)).await),
            Some(user.clone().into(&harness.db, Some(&user)).await),
            Some(member.clone().into()),
            user.limits().await,
            IdempotencyKey::unchecked_from_string("3".to_string()),
            false,
            false,
        )
        .await
        .expect("Failed to create message with missing reply");

        assert!(
            message_with_missing_reply.replies.is_none()
                || message_with_missing_reply.replies.unwrap().is_empty(),
            "Message replies exist when they shouldn't",
        );

        // fail_if_not_exists is set to true
        // Should fail to send the message
        Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            channel.clone(),
            v0::DataMessageSend {
                content: Some("Message with missing reply".to_string()),
                nonce: None,
                attachments: None,
                replies: Some(vec![v0::ReplyIntent {
                    id: message.id.clone(),
                    mention: false,
                    fail_if_not_exists: Some(true),
                }]),
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                encrypted: None,
                flags: None,
            },
            v0::MessageAuthor::User(&user.clone().into(&harness.db, Some(&user)).await),
            Some(user.clone().into(&harness.db, Some(&user)).await),
            Some(member.clone().into()),
            user.limits().await,
            IdempotencyKey::unchecked_from_string("4".to_string()),
            false,
            false,
        )
        .await
        .expect_err("Created message with missing reply and true fail");

        // fail_if_not_exists is not set
        // Should fail to send the message
        Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            channel.clone(),
            v0::DataMessageSend {
                content: Some("Message with missing reply".to_string()),
                nonce: None,
                attachments: None,
                replies: Some(vec![v0::ReplyIntent {
                    id: message.id.clone(),
                    mention: false,
                    fail_if_not_exists: None,
                }]),
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                encrypted: None,
                flags: None,
            },
            v0::MessageAuthor::User(&user.clone().into(&harness.db, Some(&user)).await),
            Some(user.clone().into(&harness.db, Some(&user)).await),
            Some(member.clone().into()),
            user.limits().await,
            IdempotencyKey::unchecked_from_string("4".to_string()),
            false,
            false,
        )
        .await
        .expect_err("Created message with missing reply and none fail");
    }

    #[test]
    fn mass_mentions_test() {
        crate::util::test::rt().block_on(mass_mentions_test_case())
    }

    async fn mass_mentions_test_case() {
        let harness = TestHarness::new().await;
        let (_, _, user) = harness.new_user().await;
        let (_, _, other_user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;
        let role = harness
            .new_role(
                &server,
                1,
                Some(OverrideField {
                    a: (ChannelPermission::MentionEveryone as i64)
                        | (ChannelPermission::MentionRoles as i64),
                    d: 0,
                }),
            )
            .await;
        let (mut other_member, _) = Member::create(&harness.db, &server, &other_user, None)
            .await
            .expect("Failed to add test member");

        // Send a message with an everyone and role mention.
        // Should fail
        let bad_message_with_mentions = Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            channel.clone(),
            v0::DataMessageSend {
                content: Some(format!("Mentioning @everyone and role <%{}>", &role.id)),
                nonce: None,
                attachments: None,
                replies: None,
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                encrypted: None,
                flags: None,
            },
            v0::MessageAuthor::User(
                &other_user
                    .clone()
                    .into(&harness.db, Some(&other_user))
                    .await,
            ),
            Some(
                other_user
                    .clone()
                    .into(&harness.db, Some(&other_user))
                    .await,
            ),
            Some(other_member.clone().into()),
            other_user.limits().await,
            IdempotencyKey::unchecked_from_string("1".to_string()),
            false,
            true,
        )
        .await
        .expect_err("Should not have created message with everyone and role pings");

        assert!(
            matches!(
                bad_message_with_mentions.error_type,
                ErrorType::MissingPermission { .. }
            ),
            "Intentional permissions error did not return MissingPermission"
        );

        // Send a mass mention inside a codeblock.
        // Should be undetected and therefor pass
        let message_with_codeblock = Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            channel.clone(),
            v0::DataMessageSend {
                content: Some(format!("Mentioning `@everyone` and role `<%{}>`", &role.id)),
                nonce: None,
                attachments: None,
                replies: None,
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                encrypted: None,
                flags: None,
            },
            v0::MessageAuthor::User(
                &other_user
                    .clone()
                    .into(&harness.db, Some(&other_user))
                    .await,
            ),
            Some(
                other_user
                    .clone()
                    .into(&harness.db, Some(&other_user))
                    .await,
            ),
            Some(other_member.clone().into()),
            other_user.limits().await,
            IdempotencyKey::unchecked_from_string("1".to_string()),
            false,
            true,
        )
        .await
        .expect("Failed to create message with everyone and role pings in codeblocks");

        assert!(
            message_with_codeblock.flags.is_none()
                || !MessageFlagsValue(message_with_codeblock.flags.unwrap())
                    .has(MessageFlags::MentionsEveryone),
            "Message flags mentions everyone when inside codeblock",
        );

        assert!(
            message_with_codeblock.role_mentions.is_none(),
            "Role mentions detected when inside codeblock"
        );

        other_member.roles.push(role.id.clone());
        harness
            .db
            .update_member(
                &other_member.id,
                &PartialMember {
                    avatar: None,
                    id: None,
                    joined_at: None,
                    nickname: None,
                    pronouns: None,
                    roles: Some(vec![role.id.clone()]),
                    timeout: None,
                    can_publish: None,
                    can_receive: None,
                },
                vec![],
            )
            .await
            .expect("Failed to add role to user");

        // Send a message with an everyone and role mention.
        // Should succeed
        let message_with_mentions = Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            channel.clone(),
            v0::DataMessageSend {
                content: Some(format!("Mentioning @everyone and role <%{}>", &role.id)),
                nonce: None,
                attachments: None,
                replies: None,
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                encrypted: None,
                flags: None,
            },
            v0::MessageAuthor::User(
                &other_user
                    .clone()
                    .into(&harness.db, Some(&other_user))
                    .await,
            ),
            Some(
                other_user
                    .clone()
                    .into(&harness.db, Some(&other_user))
                    .await,
            ),
            Some(other_member.clone().into()),
            other_user.limits().await,
            IdempotencyKey::unchecked_from_string("1".to_string()),
            false,
            true,
        )
        .await
        .expect("Failed to create message with everyone and role pings");

        assert!(
            message_with_mentions.flags.is_some(),
            "Message flags is None",
        );

        assert!(
            MessageFlagsValue(message_with_mentions.flags.unwrap())
                .has(MessageFlags::MentionsEveryone),
            "Message flags does not mention everyone. Flag value is {}",
            message_with_mentions.flags.unwrap()
        );

        assert!(
            message_with_mentions.role_mentions.is_some(),
            "Message has no role mentions"
        );
    }

    // Self-ack: sending marks the channel read for a human author.
    //
    // The negative tests below all pass `Some(&harness.amqp)`: the self-ack is
    // gated on `amqp` being present, so `None` would pass them vacuously.

    /// Publish a marker `ChannelAck` on `marker_user`'s private topic and wait
    /// for it. The harness reads every topic through one `psubscribe("*")`
    /// connection and redis pub/sub is FIFO on it, so once the marker is seen,
    /// everything the send published before it (the `Message` fan-out and any
    /// self-ack, both awaited inside `send`) is in the event buffer, where
    /// `assert_no_buffered_event` can see it. Returns the marker's id.
    async fn flush_with_marker(
        harness: &mut TestHarness,
        marker_user: &str,
        channel_id: &str,
    ) -> String {
        let marker = ulid::Ulid::new().to_string();

        EventV1::ChannelAck {
            id: channel_id.to_string(),
            user: marker_user.to_string(),
            message_id: marker.clone(),
        }
        .private(marker_user.to_string())
        .await;

        harness
            .wait_for_event(&format!("{marker_user}!"), |event| match event {
                EventV1::ChannelAck { message_id, .. } => message_id == &marker,
                _ => false,
            })
            .await;

        marker
    }

    /// The send's own `Message` event reached the harness, so its publishes
    /// were observable in this run. Served from the buffer after the marker.
    async fn assert_fanned_out(harness: &mut TestHarness, channel_id: &str, message_id: &str) {
        harness
            .wait_for_event(channel_id, |event| match event {
                EventV1::Message(message) => message.id == message_id,
                _ => false,
            })
            .await;
    }

    /// Any `ChannelAck` other than the marker.
    fn is_stray_ack(event: &EventV1, marker: &str) -> bool {
        match event {
            EventV1::ChannelAck { message_id, .. } => message_id.as_str() != marker,
            _ => false,
        }
    }

    fn plain_send(content: &str) -> v0::DataMessageSend {
        v0::DataMessageSend {
            content: Some(content.to_string()),
            nonce: None,
            attachments: None,
            replies: None,
            embeds: None,
            masquerade: None,
            interactions: None,
            components: None,
            sticker_ids: None,
            encrypted: None,
            flags: None,
        }
    }

    /// A human author is acked on both send paths: the route
    /// (`create_from_api` -> `send_with_ack_author(.., true)`) and the
    /// `Message::send` wrapper that poll, forward, soft-response and `/roll`
    /// use. The second half fails if `send` stops passing `true`.
    #[test]
    fn self_ack_route_acks_author() {
        crate::util::test::rt().block_on(self_ack_route_acks_author_case())
    }

    async fn self_ack_route_acks_author_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let response = harness
            .client
            .post(format!("/channels/{}/messages", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "content": "self ack" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let message: v0::Message = response.into_json().await.expect("`Message`");

        // Times out (and fails) after 30s if the send never acked the author.
        let event = harness
            .wait_for_event(&format!("{}!", user.id), |event| match event {
                EventV1::ChannelAck { message_id, .. } => message_id == &message.id,
                _ => false,
            })
            .await;

        match event {
            EventV1::ChannelAck {
                id,
                user: acked_user,
                message_id,
            } => {
                assert_eq!(id, channel.id());
                assert_eq!(acked_user, user.id);
                assert_eq!(message_id, message.id);
            }
            _ => unreachable!(),
        }

        // The `Message::send` wrapper, as poll/forward/soft-response/roll call it.
        let author: v0::User = user.clone().into(&harness.db, Some(&user)).await;
        assert!(author.bot.is_none(), "precondition: the author is a human");

        let mut sent = Message {
            id: ulid::Ulid::new().to_string(),
            channel: channel.id().to_string(),
            author: user.id.clone(),
            content: Some("self ack via send".to_string()),
            ..Default::default()
        };

        sent.send(
            &harness.db,
            Some(&harness.amqp),
            v0::MessageAuthor::User(&author),
            Some(author.clone()),
            None,
            &channel,
            false,
        )
        .await
        .expect("Failed to send message");

        // Its own ack: the route's ack above carries a different message id.
        let event = harness
            .wait_for_event(&format!("{}!", user.id), |event| match event {
                EventV1::ChannelAck { message_id, .. } => message_id == &sent.id,
                _ => false,
            })
            .await;

        match event {
            EventV1::ChannelAck {
                id,
                user: acked_user,
                message_id,
            } => {
                assert_eq!(id, channel.id());
                assert_eq!(acked_user, user.id);
                assert_eq!(message_id, sent.id);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn self_ack_skipped_when_opted_out() {
        crate::util::test::rt().block_on(self_ack_skipped_when_opted_out_case())
    }

    async fn self_ack_skipped_when_opted_out_case() {
        let mut harness = TestHarness::new().await;
        let (_, _, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let author: v0::User = user.clone().into(&harness.db, Some(&user)).await;
        assert!(author.bot.is_none(), "precondition: the author is a human");

        let message = Message::create_from_api_with_id(
            &harness.db,
            Some(&harness.amqp),
            channel.clone(),
            plain_send("opted out"),
            v0::MessageAuthor::User(&author),
            Some(author.clone()),
            None,
            user.limits().await,
            IdempotencyKey::unchecked_from_string("0".to_string()),
            false,
            true,
            None,
            None,
            false,
        )
        .await
        .expect("Failed to create message");

        let marker = flush_with_marker(&mut harness, &user.id, channel.id()).await;
        assert_fanned_out(&mut harness, channel.id(), &message.id).await;

        harness.assert_no_buffered_event(&format!("{}!", user.id), |event| {
            is_stray_ack(event, &marker)
        });
    }

    #[test]
    fn self_ack_skipped_for_webhook() {
        crate::util::test::rt().block_on(self_ack_skipped_for_webhook_case())
    }

    async fn self_ack_skipped_for_webhook_case() {
        let mut harness = TestHarness::new().await;
        let (_, _, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let webhook = v0::Webhook {
            id: ulid::Ulid::new().to_string(),
            name: "Self-ack webhook".to_string(),
            avatar: None,
            creator_id: user.id.clone(),
            channel_id: channel.id().to_string(),
            permissions: 0,
            token: None,
        };

        // Same shape as a crosspost copy (message_crosspost.rs).
        let mut message = Message {
            id: ulid::Ulid::new().to_string(),
            channel: channel.id().to_string(),
            author: webhook.id.clone(),
            webhook: Some(webhook.clone().into()),
            content: Some("from a webhook".to_string()),
            ..Default::default()
        };

        message
            .send(
                &harness.db,
                Some(&harness.amqp),
                v0::MessageAuthor::Webhook(&webhook),
                None,
                None,
                &channel,
                false,
            )
            .await
            .expect("Failed to send webhook message");

        let marker = flush_with_marker(&mut harness, &user.id, channel.id()).await;
        assert_fanned_out(&mut harness, channel.id(), &message.id).await;

        // Neither the webhook's id nor its creator is acked.
        for topic in [format!("{}!", webhook.id), format!("{}!", user.id)] {
            harness.assert_no_buffered_event(&topic, |event| is_stray_ack(event, &marker));
        }
    }

    #[test]
    fn self_ack_skipped_for_bot() {
        crate::util::test::rt().block_on(self_ack_skipped_for_bot_case())
    }

    async fn self_ack_skipped_for_bot_case() {
        let mut harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        let channel = harness.new_channel(&server).await;

        let (_, bot_user) = Bot::create(&harness.db, TestHarness::rand_string(), &owner, None)
            .await
            .expect("`Bot`");
        let (bot_member, _) = Member::create(&harness.db, &server, &bot_user, None)
            .await
            .expect("bot member");

        let author: v0::User = bot_user.clone().into(&harness.db, Some(&owner)).await;
        assert!(
            author.bot.is_some(),
            "precondition: the author carries bot information"
        );

        let mut message = Message {
            id: ulid::Ulid::new().to_string(),
            channel: channel.id().to_string(),
            author: bot_user.id.clone(),
            content: Some("from a bot".to_string()),
            ..Default::default()
        };

        // The pinned wrapper (always `ack_author = true`), as bot-driven
        // sends like `/roll` and soft responses reach it.
        message
            .send(
                &harness.db,
                Some(&harness.amqp),
                v0::MessageAuthor::User(&author),
                Some(author.clone()),
                Some(bot_member.into()),
                &channel,
                false,
            )
            .await
            .expect("Failed to send bot message");

        let marker = flush_with_marker(&mut harness, &owner.id, channel.id()).await;
        assert_fanned_out(&mut harness, channel.id(), &message.id).await;

        // Neither the bot nor its owner is acked.
        for topic in [format!("{}!", bot_user.id), format!("{}!", owner.id)] {
            harness.assert_no_buffered_event(&topic, |event| is_stray_ack(event, &marker));
        }
    }

    async fn referral_message_count(harness: &TestHarness, invitee_id: &str) -> i32 {
        harness
            .db
            .fetch_referral(invitee_id)
            .await
            .expect("Failed to fetch referral")
            .expect("Referral is missing")
            .message_count
    }

    /// A pending invitee's accepted sends count towards the referral; notes
    /// to self and rejected sends do not.
    #[test]
    fn referral_activity_recorded_on_send() {
        crate::util::test::rt().block_on(referral_activity_recorded_on_send_case())
    }

    async fn referral_activity_recorded_on_send_case() {
        let harness = TestHarness::new().await;
        let (_, _, referrer) = harness.new_user().await;
        let (_, session, mut user) = harness.new_user().await;

        assert!(Referral::create_for_invitee(
            &harness.db,
            &user.id,
            &referrer.id,
            ReferralSource::Code
        )
        .await
        .expect("Failed to create referral"));
        user.update(
            &harness.db,
            PartialUser {
                referral_pending: Some(true),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("Failed to mark the referral pending");

        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;
        let notes = Channel::SavedMessages {
            id: ulid::Ulid::new().to_string(),
            user: user.id.clone(),
        };
        harness.db.insert_channel(&notes).await.expect("notes");

        let send = |channel_id: String, body: serde_json::Value| {
            harness
                .client
                .post(format!("/channels/{channel_id}/messages"))
                .header(Header::new("x-session-token", session.token.to_string()))
                .header(ContentType::JSON)
                .body(body.to_string())
                .dispatch()
        };

        let response = send(notes.id().to_string(), json!({ "content": "note" })).await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(referral_message_count(&harness, &user.id).await, 0);

        let response = send(channel.id().to_string(), json!({})).await;
        assert_ne!(response.status(), Status::Ok);
        assert_eq!(referral_message_count(&harness, &user.id).await, 0);

        let response = send(channel.id().to_string(), json!({ "content": "hello" })).await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(referral_message_count(&harness, &user.id).await, 1);
    }

    // Anti-spam: the same text sent to several strangers in DMs.
    //
    // Delta reads the cached global config, which keeps the detector off in
    // tests, so the `antispam_route_*` tests are ignored by default and run
    // with `REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true` and `--ignored`.
    // The observer is spawned off the request, so they poll for its result.

    /// The scam that prompted the detector: long enough to be fingerprinted
    const SCAM: &str = "Hi! I love your profile picture, can I use it for an art project \
                        for my client? I'll pay you and credit you.";

    /// A message that is only an invite link, as "Invite to server" sends
    const INVITE: &str = "https://app.sloga.gg/invite/abc";

    /// How long the spawned observer gets before a test gives up on it
    const OBSERVE_TIMEOUT: Duration = Duration::from_secs(5);

    /// How long a test watches for a flag that must NOT appear
    const OBSERVE_SETTLE: Duration = Duration::from_millis(1500);

    const OBSERVE_POLL: Duration = Duration::from_millis(100);

    /// Put `members` in one server (owned by someone else), so each pair may
    /// DM through the mutual server without being friends
    async fn share_server(harness: &TestHarness, members: &[&User]) {
        let (_, _, owner) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        for member in members {
            Member::create(&harness.db, &server, member, None)
                .await
                .expect("Failed to add test member");
        }
    }

    /// A DM between `a` and `b`, inserted directly so each test controls
    /// exactly which DMs exist
    async fn new_dm(harness: &TestHarness, a: &User, b: &User) -> String {
        let id = ulid::Ulid::new().to_string();
        harness
            .db
            .insert_channel(&Channel::DirectMessage {
                id: id.clone(),
                active: true,
                recipients: vec![a.id.clone(), b.id.clone()],
                last_message_id: None,
            })
            .await
            .expect("Failed to create test DM");
        id
    }

    /// Send `content` through the route; the status and the JSON body
    async fn send_as(
        harness: &TestHarness,
        session: &Session,
        channel_id: &str,
        content: &str,
    ) -> (Status, serde_json::Value) {
        let response = harness
            .client
            .post(format!("/channels/{channel_id}/messages"))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "content": content }).to_string())
            .dispatch()
            .await;
        let status = response.status();
        let body = response
            .into_json::<serde_json::Value>()
            .await
            .unwrap_or_default();
        (status, body)
    }

    /// Send `content` and expect it to be accepted; the new message's id
    async fn send_ok(
        harness: &TestHarness,
        session: &Session,
        channel_id: &str,
        content: &str,
    ) -> String {
        let (status, body) = send_as(harness, session, channel_id, content).await;
        assert_eq!(status, Status::Ok, "send to {channel_id} refused: {body}");
        body["_id"].as_str().expect("message id").to_string()
    }

    /// The guard the observer set on `user_id`, waiting for it
    async fn wait_for_dm_guard(harness: &TestHarness, user_id: &str) -> DmGuard {
        let deadline = Instant::now() + OBSERVE_TIMEOUT;
        loop {
            let user = harness.db.fetch_user(user_id).await.expect("user");
            if let Some(guard) = user.dm_guard {
                return guard;
            }

            assert!(
                Instant::now() < deadline,
                "no DM guard after {:?}",
                OBSERVE_TIMEOUT
            );
            tokio::time::sleep(OBSERVE_POLL).await;
        }
    }

    /// Watch `user_id` for a while and fail if a guard appears
    async fn assert_no_dm_guard(harness: &TestHarness, user_id: &str, context: &str) {
        let deadline = Instant::now() + OBSERVE_SETTLE;
        loop {
            let user = harness.db.fetch_user(user_id).await.expect("user");
            assert!(
                user.dm_guard.is_none(),
                "{}: the sender was flagged",
                context
            );

            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(OBSERVE_POLL).await;
        }
    }

    /// The report filed under `report_id`, waiting for it (the guard is
    /// claimed before the report is written)
    async fn wait_for_report(harness: &TestHarness, report_id: &str) -> Report {
        let deadline = Instant::now() + OBSERVE_TIMEOUT;
        loop {
            if let Ok(report) = harness.db.fetch_report(report_id).await {
                return report;
            }

            assert!(
                Instant::now() < deadline,
                "no report {} after {:?}",
                report_id,
                OBSERVE_TIMEOUT
            );
            tokio::time::sleep(OBSERVE_POLL).await;
        }
    }

    /// Pause `user` the way the detector does, without running it
    async fn pause_dms(harness: &TestHarness, user: &User) {
        let guard = DmGuard {
            report_id: ulid::Ulid::new().to_string(),
            flagged_at: Timestamp::now_utc(),
            paused: true,
            cleared_at: None,
            recipients: 3,
            fingerprint: "test".into(),
        };
        assert!(
            harness
                .db
                .claim_dm_guard(&user.id, &guard, Timestamp::now_utc())
                .await
                .expect("Failed to claim the DM guard"),
            "precondition: the guard was claimed"
        );
    }

    async fn dm_message_count(harness: &TestHarness, channel_id: &str) -> usize {
        harness
            .db
            .fetch_messages(MessageQuery {
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
            .expect("Failed to fetch DM messages")
            .len()
    }

    /// The third stranger who got the same text and never answered files an
    /// automated report and pauses the sender, whose next new stranger is
    /// then refused.
    #[test]
    #[ignore = "needs REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"]
    fn antispam_route_third_silent_stranger_files_report_and_pauses() {
        crate::util::test::rt()
            .block_on(antispam_route_third_silent_stranger_files_report_and_pauses_case())
    }

    async fn antispam_route_third_silent_stranger_files_report_and_pauses_case() {
        assert!(
            config().await.features.antispam.dm_dupe_enabled,
            "run with REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"
        );

        let harness = TestHarness::new().await;
        let (_, session, sender) = harness.new_user().await;
        let mut strangers = Vec::new();
        for _ in 0..4 {
            strangers.push(harness.new_user().await.2);
        }
        let mut members: Vec<&User> = strangers.iter().collect();
        members.push(&sender);
        share_server(&harness, &members).await;

        let mut sent = Vec::new();
        for stranger in &strangers[..3] {
            let dm = new_dm(&harness, &sender, stranger).await;
            sent.push(send_ok(&harness, &session, &dm, SCAM).await);
        }

        let guard = wait_for_dm_guard(&harness, &sender.id).await;
        assert!(guard.paused, "the default config pauses");
        assert_eq!(guard.recipients, 3);
        assert!(
            harness
                .db
                .fetch_user(&sender.id)
                .await
                .expect("user")
                .is_dm_paused(),
            "the sender is paused"
        );

        let report = wait_for_report(&harness, &guard.report_id).await;
        assert_eq!(report.author_id, SYSTEM_USER_ID);
        match &report.content {
            v0::ReportedContent::User {
                id,
                report_reason,
                message_id,
            } => {
                assert_eq!(id, &sender.id, "the report is about the sender");
                assert_eq!(*report_reason, v0::UserReportReason::SpamAbuse);
                assert!(
                    message_id
                        .as_ref()
                        .is_some_and(|message| sent.contains(message)),
                    "the report points at one of the copies, got {:?}",
                    message_id
                );
            }
            other => panic!("expected a user report, got {:?}", other),
        }

        // A fourth stranger who never wrote is now out of reach
        let dm = new_dm(&harness, &sender, &strangers[3]).await;
        let (status, body) = send_as(&harness, &session, &dm, SCAM).await;
        assert_eq!(status, Status::Forbidden, "{body}");
        assert_eq!(body["type"], "DirectMessagesPaused");
        assert_eq!(dm_message_count(&harness, &dm).await, 0, "nothing stored");
    }

    /// The same text to friends and an invite link to strangers are normal
    /// use, and never flag. Ends with the scam to the same strangers, which
    /// does flag: proof the detector ran in this test at all.
    #[test]
    #[ignore = "needs REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"]
    fn antispam_route_friends_and_invites_not_flagged() {
        crate::util::test::rt().block_on(antispam_route_friends_and_invites_not_flagged_case())
    }

    async fn antispam_route_friends_and_invites_not_flagged_case() {
        assert!(
            config().await.features.antispam.dm_dupe_enabled,
            "run with REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"
        );

        let harness = TestHarness::new().await;
        let (_, session, mut sender) = harness.new_user().await;
        let mut friends = Vec::new();
        let mut strangers = Vec::new();
        for _ in 0..3 {
            friends.push(harness.new_user().await.2);
            strangers.push(harness.new_user().await.2);
        }
        let mut members: Vec<&User> = friends.iter().chain(strangers.iter()).collect();
        members.push(&sender);
        share_server(&harness, &members).await;

        for friend in &mut friends {
            sender
                .apply_relationship(
                    &harness.db,
                    friend,
                    RelationshipStatus::Friend,
                    RelationshipStatus::Friend,
                    None,
                )
                .await
                .expect("friendship");
        }

        for friend in &friends {
            let dm = new_dm(&harness, &sender, friend).await;
            send_ok(&harness, &session, &dm, SCAM).await;
        }

        let mut stranger_dms = Vec::new();
        for stranger in &strangers {
            let dm = new_dm(&harness, &sender, stranger).await;
            send_ok(&harness, &session, &dm, INVITE).await;
            stranger_dms.push(dm);
        }

        assert_no_dm_guard(&harness, &sender.id, "friends and invite links").await;

        // Control: the same strangers, the scam this time
        for dm in &stranger_dms {
            send_ok(&harness, &session, dm, SCAM).await;
        }

        let guard = wait_for_dm_guard(&harness, &sender.id).await;
        assert_eq!(guard.recipients, 3, "only the strangers count");
    }

    /// A stranger who writes back is a conversation, not a target: it drops
    /// out of the count, and the flag needs three others who stayed silent.
    #[test]
    #[ignore = "needs REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"]
    fn antispam_route_reply_removes_that_peer() {
        crate::util::test::rt().block_on(antispam_route_reply_removes_that_peer_case())
    }

    async fn antispam_route_reply_removes_that_peer_case() {
        assert!(
            config().await.features.antispam.dm_dupe_enabled,
            "run with REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"
        );

        let harness = TestHarness::new().await;
        let (_, session, sender) = harness.new_user().await;
        let (_, replier_session, replier) = harness.new_user().await;
        let mut silent = Vec::new();
        for _ in 0..3 {
            silent.push(harness.new_user().await.2);
        }
        let mut members: Vec<&User> = silent.iter().collect();
        members.push(&sender);
        members.push(&replier);
        share_server(&harness, &members).await;

        let replier_dm = new_dm(&harness, &sender, &replier).await;
        send_ok(&harness, &session, &replier_dm, SCAM).await;
        send_ok(
            &harness,
            &replier_session,
            &replier_dm,
            "sure, what is it for?",
        )
        .await;

        let first_dm = new_dm(&harness, &sender, &silent[0]).await;
        send_ok(&harness, &session, &first_dm, SCAM).await;
        let second_dm = new_dm(&harness, &sender, &silent[1]).await;
        send_ok(&harness, &session, &second_dm, SCAM).await;

        assert_no_dm_guard(&harness, &sender.id, "one of three replied").await;

        let third_dm = new_dm(&harness, &sender, &silent[2]).await;
        send_ok(&harness, &session, &third_dm, SCAM).await;

        let guard = wait_for_dm_guard(&harness, &sender.id).await;
        assert_eq!(guard.recipients, 3, "the replier is not counted");
    }

    /// A paused sender cannot reach a stranger who never wrote (and nothing is
    /// stored), but can keep talking to one who did.
    #[test]
    #[ignore = "needs REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"]
    fn antispam_route_paused_sender_refused_but_replied_peer_allowed() {
        crate::util::test::rt()
            .block_on(antispam_route_paused_sender_refused_but_replied_peer_allowed_case())
    }

    async fn antispam_route_paused_sender_refused_but_replied_peer_allowed_case() {
        assert!(
            config().await.features.antispam.dm_dupe_enabled,
            "run with REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"
        );

        let harness = TestHarness::new().await;
        let (_, session, sender) = harness.new_user().await;
        let (_, _, silent) = harness.new_user().await;
        let (_, chatty_session, chatty) = harness.new_user().await;
        share_server(&harness, &[&sender, &silent, &chatty]).await;

        let silent_dm = new_dm(&harness, &sender, &silent).await;
        let chatty_dm = new_dm(&harness, &sender, &chatty).await;
        send_ok(
            &harness,
            &chatty_session,
            &chatty_dm,
            "hey, saw you in the server",
        )
        .await;

        pause_dms(&harness, &sender).await;

        let (status, body) = send_as(&harness, &session, &silent_dm, "hi").await;
        assert_eq!(status, Status::Forbidden, "{body}");
        assert_eq!(body["type"], "DirectMessagesPaused");
        assert_eq!(
            dm_message_count(&harness, &silent_dm).await,
            0,
            "nothing stored"
        );

        send_ok(&harness, &session, &chatty_dm, "hi").await;
    }

    /// `dm_dupe_enabled = false` is the kill switch: it lifts every standing
    /// pause, so a paused sender reaches a silent stranger again.
    #[test]
    fn antispam_kill_switch_lifts_pause_on_send() {
        crate::util::test::rt().block_on(antispam_kill_switch_lifts_pause_on_send_case())
    }

    async fn antispam_kill_switch_lifts_pause_on_send_case() {
        assert!(
            !config().await.features.antispam.dm_dupe_enabled,
            "precondition: the test config keeps the detector off"
        );

        let harness = TestHarness::new().await;
        let (_, session, sender) = harness.new_user().await;
        let (_, _, silent) = harness.new_user().await;
        share_server(&harness, &[&sender, &silent]).await;

        let dm = new_dm(&harness, &sender, &silent).await;
        pause_dms(&harness, &sender).await;
        assert!(
            harness
                .db
                .fetch_user(&sender.id)
                .await
                .expect("user")
                .is_dm_paused(),
            "precondition: the sender is paused"
        );

        send_ok(&harness, &session, &dm, SCAM).await;
        assert_eq!(dm_message_count(&harness, &dm).await, 1);
    }
}

/// The protected-channel send (design 7.3). Every flag case is its own
/// `#[test]`: `overwrite_config` runs once per process (nextest).
#[cfg(test)]
mod protected_tests {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        Bot, Channel, MessageFilter, MessageQuery, MessageTimePeriod, MlsCommit, MlsCommitOutcome,
        MlsGroup, MlsMemberDevice, PartialChannel, Session, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::{json, Value};
    use ulid::Ulid;

    use crate::routes::mls::text::text_group_id;
    use crate::util::test::{ProtectedChannel, TestE2EEDevice, TestHarness, MEMBER_DEVICE_SEED};

    fn session_auth(session: &Session) -> Header<'static> {
        Header::new("x-session-token", session.token.to_string())
    }

    fn bot_auth(bot: &Bot) -> Header<'static> {
        Header::new("x-bot-token", bot.token.to_string())
    }

    /// POST a send, with a fresh `Idempotency-Key` header when `with_key`
    /// (a fresh one, so the existing guard's cache never answers first).
    /// Returns the status and the JSON body (`Null` when there is none).
    async fn send(
        harness: &TestHarness,
        auth: Header<'static>,
        channel_id: &str,
        body: &Value,
        with_key: bool,
    ) -> (Status, Value) {
        let mut request = harness
            .client
            .post(format!("/channels/{channel_id}/messages"))
            .header(auth)
            .header(ContentType::JSON)
            .body(body.to_string());
        if with_key {
            request = request.header(Header::new("Idempotency-Key", Ulid::new().to_string()));
        }
        let response = request.dispatch().await;
        let status = response.status();
        let body = response.into_json::<Value>().await.unwrap_or(Value::Null);
        (status, body)
    }

    fn encrypted_send(payload: v0::EncryptedPayload) -> Value {
        json!({ "nonce": Ulid::new().to_string(), "encrypted": payload })
    }

    fn assert_sent(answer: &(Status, Value), case: &str) {
        assert_eq!(answer.0, Status::Ok, "{case}: {}", answer.1);
    }

    fn assert_refused(answer: &(Status, Value), status: Status, error: &str, case: &str) {
        assert_eq!(answer.0, status, "{case}: {}", answer.1);
        assert_eq!(answer.1["type"], error, "{case}: {}", answer.1);
    }

    fn assert_field(answer: &(Status, Value), field: &str, case: &str) {
        assert_refused(answer, Status::BadRequest, "ProtectedFieldRefused", case);
        assert_eq!(answer.1["field"], field, "{case}: {}", answer.1);
    }

    fn assert_resecuring(answer: &(Status, Value), reason: &str, case: &str) {
        assert_refused(answer, Status::Conflict, "ProtectedChannelResecuring", case);
        assert_eq!(answer.1["reason"], reason, "{case}: {}", answer.1);
    }

    fn random_group_id() -> String {
        format!("{:032x}{:032x}", Ulid::new().0, Ulid::new().0)
    }

    /// `group` after an Add of `device` at the next epoch, committed by
    /// `committer`, through the database primitive
    async fn add_device(
        harness: &TestHarness,
        group: &MlsGroup,
        committer: &TestE2EEDevice,
        device: &TestE2EEDevice,
    ) -> MlsGroup {
        let db = &harness.db;
        let hash = db
            .fetch_seat_list(&group.channel_id)
            .await
            .expect("the seat list")
            .expect("a stored seat list")
            .commit_ad_sha256()
            .expect("its AD hash");
        let epoch = group.current_epoch + 1;
        let commit = MlsCommit {
            id: MlsCommit::composite_id(&group.id, epoch),
            group_id: group.id.clone(),
            epoch,
            committer: MlsMemberDevice {
                user_id: committer.user_id.clone(),
                device_id: committer.device_id.clone(),
            },
            commit: STANDARD_NO_PAD.encode(b"add"),
            size: 3,
            added: vec![MlsMemberDevice {
                user_id: device.user_id.clone(),
                device_id: device.device_id.clone(),
            }],
            removed: vec![],
            created_at: Timestamp::now_utc(),
            rejoin_intents: vec![],
            removed_reasons: vec![],
        };
        let outcome = db
            .insert_mls_text_commit(&commit, &hash, 0)
            .await
            .expect("the add");
        assert!(matches!(outcome, MlsCommitOutcome::Won), "{:?}", outcome);
        db.fetch_mls_group(&group.id)
            .await
            .expect("the grown group")
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

    struct Fixture {
        harness: TestHarness,
        protected: ProtectedChannel,
        /// Epoch 1: the owner's device and `member_device`
        group: MlsGroup,
        /// An unprotected channel of the same server
        ordinary: Channel,
        owner: User,
        owner_session: Session,
        member: User,
        member_session: Session,
        member_device: TestE2EEDevice,
        /// A server member with a bound device, not seated
        outsider_session: Session,
        outsider_device: TestE2EEDevice,
        /// Seated, a bound device that is not in the group
        loner_session: Session,
        loner_device: TestE2EEDevice,
        /// Seated, its device bound to some other session
        unbound_session: Session,
        unbound_device: TestE2EEDevice,
    }

    async fn fixture() -> Fixture {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, outsider_session, outsider) = harness.new_user().await;
        let (_, loner_session, loner) = harness.new_user().await;
        let (_, unbound_session, unbound) = harness.new_user().await;

        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member, &loner, &unbound])
            .await;
        harness.join_server(&protected.server, &outsider).await;
        let ordinary = harness.new_channel(&protected.server).await;

        let member_device = harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        let outsider_device = harness
            .new_e2ee_device(&outsider, &outsider_session.id, 0x40)
            .await;
        let loner_device = harness
            .new_e2ee_device(&loner, &loner_session.id, 0x50)
            .await;
        let unbound_device = harness
            .new_e2ee_device(&unbound, "some-other-session", 0x60)
            .await;

        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let group = add_device(&harness, &group, &protected.owner_device, &member_device).await;
        assert_eq!(group.current_epoch, 1);

        Fixture {
            harness,
            protected,
            group,
            ordinary,
            owner,
            owner_session,
            member,
            member_session,
            member_device,
            outsider_session,
            outsider_device,
            loner_session,
            loner_device,
            unbound_session,
            unbound_device,
        }
    }

    /// Every refusal in its 7.3 position, each case paired with a later
    /// failure so the earlier check is the one that answers
    #[test]
    fn protected_send_checks_run_in_the_design_order() {
        crate::util::test::rt().block_on(Box::pin(
            protected_send_checks_run_in_the_design_order_case(),
        ))
    }

    async fn protected_send_checks_run_in_the_design_order_case() {
        let f = fixture().await;
        let h = &f.harness;
        let channel_id = f.protected.channel.id();
        let member = session_auth(&f.member_session);
        let valid = || encrypted_send(f.member_device.encrypted_payload(&f.group));

        // 1. the raw header, before the allowlist and the seat
        let answer = send(
            h,
            member.clone(),
            channel_id,
            &json!({ "content": "x" }),
            true,
        )
        .await;
        assert_field(&answer, "idempotency-key", "header + plaintext");
        assert_field(
            &send(h, member.clone(), channel_id, &valid(), true).await,
            "idempotency-key",
            "header + valid payload",
        );
        let outsider = session_auth(&f.outsider_session);
        let outsider_send = encrypted_send(f.outsider_device.encrypted_payload(&f.group));
        assert_field(
            &send(h, outsider.clone(), channel_id, &outsider_send, true).await,
            "idempotency-key",
            "header + unseated",
        );

        // 1. the allowlist, before the seat
        assert_field(
            &send(
                h,
                outsider.clone(),
                channel_id,
                &json!({ "content": "x" }),
                false,
            )
            .await,
            "content",
            "unseated + plaintext",
        );
        let mut with_replies = valid();
        with_replies["replies"] = json!([]);
        assert_field(
            &send(h, member.clone(), channel_id, &with_replies, false).await,
            "replies",
            "an empty replies array",
        );

        // 2. seated, before the session
        assert_refused(
            &send(h, outsider.clone(), channel_id, &outsider_send, false).await,
            Status::Forbidden,
            "NotSeated",
            "unseated, no header",
        );
        let outsider_as_owner =
            encrypted_send(f.protected.owner_device.encrypted_payload(&f.group));
        assert_refused(
            &send(h, outsider.clone(), channel_id, &outsider_as_owner, false).await,
            Status::Forbidden,
            "NotSeated",
            "unseated, someone else's device",
        );

        // 3. the bound session, before the group
        let unbound = session_auth(&f.unbound_session);
        let mut unbound_stale = f.unbound_device.encrypted_payload(&f.group);
        assert_refused(
            &send(
                h,
                unbound.clone(),
                channel_id,
                &encrypted_send(unbound_stale.clone()),
                false,
            )
            .await,
            Status::Unauthorized,
            "NotAuthenticated",
            "an unbound session",
        );
        unbound_stale.group_id = random_group_id();
        assert_refused(
            &send(
                h,
                unbound,
                channel_id,
                &encrypted_send(unbound_stale),
                false,
            )
            .await,
            Status::Unauthorized,
            "NotAuthenticated",
            "an unbound session + a stale group",
        );
        let member_as_owner = encrypted_send(f.protected.owner_device.encrypted_payload(&f.group));
        assert_refused(
            &send(h, member.clone(), channel_id, &member_as_owner, false).await,
            Status::Unauthorized,
            "NotAuthenticated",
            "another user's device",
        );

        // 4. the group, before the epoch
        let mut stale_group = f.member_device.encrypted_payload(&f.group);
        stale_group.group_id = random_group_id();
        assert_resecuring(
            &send(
                h,
                member.clone(),
                channel_id,
                &encrypted_send(stale_group.clone()),
                false,
            )
            .await,
            "stale_group",
            "a stale group",
        );
        stale_group.epoch = 0;
        assert_resecuring(
            &send(
                h,
                member.clone(),
                channel_id,
                &encrypted_send(stale_group),
                false,
            )
            .await,
            "stale_group",
            "a stale group + a stale epoch",
        );

        // 6. the epoch, before membership
        let mut stale_epoch = f.member_device.encrypted_payload(&f.group);
        stale_epoch.epoch = 0;
        assert_resecuring(
            &send(
                h,
                member.clone(),
                channel_id,
                &encrypted_send(stale_epoch),
                false,
            )
            .await,
            "stale_epoch",
            "a stale epoch",
        );
        let loner = session_auth(&f.loner_session);
        let mut loner_stale = f.loner_device.encrypted_payload(&f.group);
        loner_stale.epoch = 0;
        assert_resecuring(
            &send(
                h,
                loner.clone(),
                channel_id,
                &encrypted_send(loner_stale),
                false,
            )
            .await,
            "stale_epoch",
            "a stale epoch + not a member",
        );

        // 7. membership
        let loner_send = encrypted_send(f.loner_device.encrypted_payload(&f.group));
        assert_resecuring(
            &send(h, loner, channel_id, &loner_send, false).await,
            "not_member",
            "a device outside the group",
        );

        // No header, every check passed: sent and stored as ciphertext
        let answer = send(h, member, channel_id, &valid(), false).await;
        assert_sent(&answer, "a valid send");
        let message =
            h.db.fetch_message(answer.1["_id"].as_str().expect("an id"))
                .await
                .expect("the stored message");
        assert_eq!(message.author, f.member.id);
        assert!(message.content.is_none());
        let encrypted = message.encrypted.expect("the payload");
        assert_eq!(encrypted.group_id, f.group.id);
        assert_eq!(encrypted.sender_device_id, f.member_device.device_id);
    }

    /// A protected channel with no open Text group: `stale_group`
    #[test]
    fn protected_send_without_a_text_group_is_a_stale_group() {
        crate::util::test::rt().block_on(Box::pin(
            protected_send_without_a_text_group_is_a_stale_group_case(),
        ))
    }

    async fn protected_send_without_a_text_group_is_a_stale_group_case() {
        let f = fixture().await;
        let h = &f.harness;
        let (_, bare_owner_session, bare_owner) = h.new_user().await;
        let bare = h
            .new_protected_channel(&bare_owner, &bare_owner_session, &[&f.member])
            .await;

        let mut payload = f.member_device.encrypted_payload(&f.group);
        payload.group_id = text_group_id(bare.channel.id(), 0);
        payload.epoch = 0;
        assert_resecuring(
            &send(
                h,
                session_auth(&f.member_session),
                bare.channel.id(),
                &encrypted_send(payload),
                false,
            )
            .await,
            "stale_group",
            "no open text group",
        );
    }

    /// 5. A pending removal refuses every send, before the epoch and
    /// membership checks
    #[test]
    fn protected_send_waits_for_pending_removals() {
        crate::util::test::rt().block_on(Box::pin(protected_send_waits_for_pending_removals_case()))
    }

    async fn protected_send_waits_for_pending_removals_case() {
        let f = fixture().await;
        let h = &f.harness;
        let channel_id = f.protected.channel.id();
        let owner = session_auth(&f.owner_session);
        let owner_send = || encrypted_send(f.protected.owner_device.encrypted_payload(&f.group));

        assert_sent(
            &send(h, owner.clone(), channel_id, &owner_send(), false).await,
            "before the removal",
        );

        h.db.release_channel_seats_for_user(
            &f.member.id,
            Some(&f.protected.server.id),
            Timestamp::now_utc(),
        )
        .await
        .expect("release the member's seat");
        let group = h.db.fetch_mls_group(&f.group.id).await.expect("the group");
        assert!(group.has_pending_removal(&f.member.id));

        assert_resecuring(
            &send(h, owner.clone(), channel_id, &owner_send(), false).await,
            "pending_removal",
            "a pending removal",
        );
        let mut stale_epoch = f.protected.owner_device.encrypted_payload(&f.group);
        stale_epoch.epoch = 0;
        assert_resecuring(
            &send(h, owner, channel_id, &encrypted_send(stale_epoch), false).await,
            "pending_removal",
            "a pending removal + a stale epoch",
        );
        let loner_send = encrypted_send(f.loner_device.encrypted_payload(&f.group));
        assert_resecuring(
            &send(
                h,
                session_auth(&f.loner_session),
                channel_id,
                &loner_send,
                false,
            )
            .await,
            "pending_removal",
            "a pending removal + not a member",
        );
        let member_send = encrypted_send(f.member_device.encrypted_payload(&f.group));
        assert_refused(
            &send(
                h,
                session_auth(&f.member_session),
                channel_id,
                &member_send,
                false,
            )
            .await,
            Status::Forbidden,
            "NotSeated",
            "the removed member",
        );
    }

    /// 0. With E2EE off a protected send answers `FeatureDisabled { e2ee }`
    /// before any other check; an ordinary channel still sends
    #[test]
    fn protected_send_with_e2ee_off_is_disabled() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            Box::pin(protected_send_with_e2ee_off_is_disabled_case()).await
        })
    }

    async fn protected_send_with_e2ee_off_is_disabled_case() {
        let f = fixture().await;
        let h = &f.harness;
        let channel_id = f.protected.channel.id();
        let member = session_auth(&f.member_session);
        let valid = encrypted_send(f.member_device.encrypted_payload(&f.group));

        for (body, with_key, case) in [
            (&valid, false, "a valid send"),
            (&valid, true, "a header"),
            (&json!({ "content": "x" }), false, "plaintext"),
        ] {
            let answer = send(h, member.clone(), channel_id, body, with_key).await;
            assert_refused(&answer, Status::BadRequest, "FeatureDisabled", case);
            assert_eq!(answer.1["feature"], "e2ee", "{case}: {}", answer.1);
        }

        assert_sent(
            &send(
                h,
                member,
                f.ordinary.id(),
                &json!({ "content": "x" }),
                false,
            )
            .await,
            "an ordinary channel",
        );
    }

    /// Decision 5 (W2): the growth flag never stops a seated send
    #[test]
    fn protected_send_with_growth_off_still_sends() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            Box::pin(protected_send_with_growth_off_still_sends_case()).await
        })
    }

    async fn protected_send_with_growth_off_still_sends_case() {
        let f = fixture().await;
        let valid = encrypted_send(f.member_device.encrypted_payload(&f.group));
        assert_sent(
            &send(
                &f.harness,
                session_auth(&f.member_session),
                f.protected.channel.id(),
                &valid,
                false,
            )
            .await,
            "growth off",
        );
    }

    /// A bot has no session: it still sends to an ordinary channel, and a
    /// seated bot's protected send is refused at the session step
    #[test]
    fn protected_send_bots() {
        crate::util::test::rt().block_on(Box::pin(protected_send_bots_case()))
    }

    async fn protected_send_bots_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (bot, bot_user) = Bot::create(&harness.db, TestHarness::rand_string(), &owner, None)
            .await
            .expect("`Bot`");
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&bot_user])
            .await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let ordinary = harness.new_channel(&protected.server).await;

        assert_sent(
            &send(
                &harness,
                bot_auth(&bot),
                ordinary.id(),
                &json!({ "content": "from a bot" }),
                false,
            )
            .await,
            "a bot to an ordinary channel",
        );

        assert_field(
            &send(
                &harness,
                bot_auth(&bot),
                protected.channel.id(),
                &json!({ "content": "from a bot" }),
                false,
            )
            .await,
            "content",
            "a bot's plaintext",
        );

        let payload = encrypted_send(protected.owner_device.encrypted_payload(&group));
        assert_refused(
            &send(
                &harness,
                bot_auth(&bot),
                protected.channel.id(),
                &payload,
                false,
            )
            .await,
            Status::Unauthorized,
            "NotAuthenticated",
            "a seated bot, no session",
        );
    }

    /// T5: a silent protected send stores `1` and is silent; any other
    /// flag is refused
    #[test]
    fn protected_send_flags() {
        crate::util::test::rt().block_on(Box::pin(protected_send_flags_case()))
    }

    async fn protected_send_flags_case() {
        let f = fixture().await;
        let h = &f.harness;
        let channel_id = f.protected.channel.id();
        let member = session_auth(&f.member_session);
        let with_flags = |flags: u32| {
            let mut body = encrypted_send(f.member_device.encrypted_payload(&f.group));
            body["flags"] = json!(flags);
            body
        };

        let answer = send(h, member.clone(), channel_id, &with_flags(1), false).await;
        assert_sent(&answer, "flags 1");
        let message =
            h.db.fetch_message(answer.1["_id"].as_str().expect("an id"))
                .await
                .expect("the stored message");
        assert_eq!(message.flags, Some(1));
        assert!(message.has_suppressed_notifications());

        for flags in [2, 4] {
            assert_field(
                &send(h, member.clone(), channel_id, &with_flags(flags), false).await,
                "flags",
                &format!("flags {flags}"),
            );
        }
    }

    /// A resend of the same client message id: `DuplicateNonce`, one row
    #[test]
    fn protected_send_duplicate_nonce() {
        crate::util::test::rt().block_on(Box::pin(protected_send_duplicate_nonce_case()))
    }

    async fn protected_send_duplicate_nonce_case() {
        let f = fixture().await;
        let h = &f.harness;
        let channel_id = f.protected.channel.id();
        let member = session_auth(&f.member_session);
        let nonce = Ulid::new().to_string();
        let body = |payload: v0::EncryptedPayload| json!({ "nonce": nonce, "encrypted": payload });

        let first = body(f.member_device.encrypted_payload(&f.group));
        assert_sent(
            &send(h, member.clone(), channel_id, &first, false).await,
            "the first send",
        );
        let again = body(f.member_device.encrypted_payload(&f.group));
        assert_refused(
            &send(h, member, channel_id, &again, false).await,
            Status::Conflict,
            "DuplicateNonce",
            "the resend",
        );

        let stored =
            h.db.fetch_messages(MessageQuery {
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
            .expect("the channel's messages");
        assert_eq!(stored.len(), 1, "{:?}", stored);
        assert_eq!(stored[0].nonce.as_deref(), Some(nonce.as_str()));
    }

    fn thread_under(parent: &Channel, server_id: &str, creator: &User) -> Channel {
        Channel::Thread {
            id: Ulid::new().to_string(),
            server: server_id.to_string(),
            parent_channel: parent.id().to_string(),
            name: "Thread".to_string(),
            creator: creator.id.clone(),
            origin_message_id: None,
            last_message_id: None,
            archived: false,
            archived_timestamp: None,
            auto_archive_minutes: 0,
            locked: false,
            applied_tags: vec![],
        }
    }

    /// A thread whose parent is protected refuses every send
    #[test]
    fn protected_send_thread_under_a_protected_parent() {
        crate::util::test::rt().block_on(Box::pin(
            protected_send_thread_under_a_protected_parent_case(),
        ))
    }

    async fn protected_send_thread_under_a_protected_parent_case() {
        let f = fixture().await;
        let h = &f.harness;
        let server_id = &f.protected.server.id;
        let member = session_auth(&f.member_session);

        let protected_thread = thread_under(&f.protected.channel, server_id, &f.owner);
        h.db.insert_channel(&protected_thread)
            .await
            .expect("thread");
        let ordinary_thread = thread_under(&f.ordinary, server_id, &f.owner);
        h.db.insert_channel(&ordinary_thread).await.expect("thread");

        let valid = encrypted_send(f.member_device.encrypted_payload(&f.group));
        for (body, case) in [
            (&json!({ "content": "x" }), "plaintext"),
            (&valid, "a payload"),
        ] {
            assert_refused(
                &send(h, member.clone(), protected_thread.id(), body, false).await,
                Status::BadRequest,
                "ChannelProtected",
                case,
            );
        }

        assert_sent(
            &send(
                h,
                member,
                ordinary_thread.id(),
                &json!({ "content": "x" }),
                false,
            )
            .await,
            "a thread under an ordinary channel",
        );
    }

    /// Decision 18 (W2): a caller who cannot view the channel gets the
    /// pre-W2 answer, byte-identical for a protected and an ordinary channel
    async fn protected_send_non_viewer_case() {
        let f = fixture().await;
        let h = &f.harness;
        deny_view(h, &f.protected.channel).await;
        deny_view(h, &f.ordinary).await;
        let outsider = session_auth(&f.outsider_session);
        let payload = encrypted_send(f.outsider_device.encrypted_payload(&f.group));

        for (body, with_key, case) in [
            (&json!({ "content": "x" }), false, "plaintext"),
            (&payload, false, "a payload"),
            (&payload, true, "a payload + a header"),
        ] {
            let protected = send(
                h,
                outsider.clone(),
                f.protected.channel.id(),
                body,
                with_key,
            )
            .await;
            let ordinary = send(h, outsider.clone(), f.ordinary.id(), body, with_key).await;
            assert_refused(&ordinary, Status::Forbidden, "MissingPermission", case);
            assert_eq!(protected, ordinary, "{case}");
        }
    }

    #[test]
    fn protected_send_non_viewer() {
        crate::util::test::rt().block_on(Box::pin(protected_send_non_viewer_case()))
    }

    #[test]
    fn protected_send_non_viewer_with_e2ee_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            Box::pin(protected_send_non_viewer_case()).await
        })
    }

    /// Slowmode is step 8: a refused protected send never claims a slot
    #[test]
    fn protected_send_refusals_claim_no_slowmode_slot() {
        crate::util::test::rt().block_on(Box::pin(
            protected_send_refusals_claim_no_slowmode_slot_case(),
        ))
    }

    async fn protected_send_refusals_claim_no_slowmode_slot_case() {
        let f = fixture().await;
        let h = &f.harness;
        f.protected
            .channel
            .clone()
            .update(
                &h.db,
                PartialChannel {
                    slowmode: Some(600),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("slowmode");
        let channel_id = f.protected.channel.id();
        let member = session_auth(&f.member_session);
        let valid = || encrypted_send(f.member_device.encrypted_payload(&f.group));

        assert_field(
            &send(h, member.clone(), channel_id, &valid(), true).await,
            "idempotency-key",
            "a refused send",
        );
        let mut stale_epoch = f.member_device.encrypted_payload(&f.group);
        stale_epoch.epoch = 0;
        assert_resecuring(
            &send(
                h,
                member.clone(),
                channel_id,
                &encrypted_send(stale_epoch),
                false,
            )
            .await,
            "stale_epoch",
            "a refused send",
        );
        assert_sent(
            &send(h, member.clone(), channel_id, &valid(), false).await,
            "the first accepted send",
        );
        // Slowmode is live: the next send waits
        assert_refused(
            &send(h, member, channel_id, &valid(), false).await,
            Status::TooManyRequests,
            "InSlowmode",
            "the second accepted send",
        );
    }
}
