use redis_kiss::{get_connection as _get_conn, AsyncCommands, Conn};
use regex::Regex;
use revolt_config::config;
use revolt_database::{Channel, Database};
use revolt_models::v0::{self, PushNotification, PROTECTED_PUSH_BODY};
use revolt_parser::parse_message;
use revolt_result::{create_error, Result, ToRevoltError};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};
use tokio::join;

async fn get_connection() -> Result<Conn> {
    _get_conn().await.map_err(|_| create_error!(InternalError))
}

pub async fn render_notification_content(
    notification: &PushNotification,
    db: &Database,
) -> Result<String> {
    // Protected-channel notifications are never rendered (decision 10,
    // defense in depth behind `PushNotification::from`): whatever body
    // arrives, nothing is parsed and nothing is resolved against the
    // database or the cache
    if is_protected(notification) {
        return Ok(PROTECTED_PUSH_BODY.to_string());
    }

    let parsed = parse_message(&notification.body);

    let user_mentions: HashMap<String, String>;
    let channel_mentions: HashMap<String, String>;
    let emojis: HashMap<String, String>;
    let roles: HashMap<String, String>;

    let server_id: Option<String> = get_channel_server_id(notification.channel.id(), db)
        .await
        .map(Some)
        .or(Ok(None))?;

    if server_id.is_some() {
        (user_mentions, channel_mentions, emojis, roles) = join!(
            get_items(
                parsed.user_mentions,
                server_id.as_deref(),
                db,
                get_user_display_name,
                "Unknown User".to_string()
            ),
            get_items(
                parsed.channel_mentions,
                server_id.as_deref(),
                db,
                get_channel_name,
                "Unknown Channel".to_string()
            ),
            get_items(
                parsed.emojis,
                server_id.as_deref(),
                db,
                get_emoji_name,
                "Unknown Emoji".to_string()
            ),
            get_items(
                parsed.role_mentions,
                server_id.as_deref(),
                db,
                get_role_name,
                "Unknown Role".to_string()
            ),
        );
    } else {
        roles = HashMap::default();

        (user_mentions, channel_mentions, emojis) = join!(
            get_items(
                parsed.user_mentions,
                server_id.as_deref(),
                db,
                get_user_display_name,
                "Unknown User".to_string()
            ),
            get_items(
                parsed.channel_mentions,
                server_id.as_deref(),
                db,
                get_channel_name,
                "Unknown Channel".to_string()
            ),
            get_items(
                parsed.emojis,
                server_id.as_deref(),
                db,
                get_emoji_name,
                "Unknown Emoji".to_string()
            ),
        );
    }

    let mut body = Cow::Borrowed(notification.body.as_str());

    for (uid, name) in user_mentions {
        replace_all_in_place(
            Regex::new(format!("<@{uid}>").as_str()).unwrap(),
            &mut body,
            format!("@{name}").as_str(),
        );
    }

    for (uid, name) in channel_mentions {
        replace_all_in_place(
            Regex::new(format!("<#{uid}>").as_str()).unwrap(),
            &mut body,
            format!("#{name}").as_str(),
        );
    }

    for (uid, name) in roles {
        replace_all_in_place(
            Regex::new(format!("<%{uid}>").as_str()).unwrap(),
            &mut body,
            format!("%{name}").as_str(),
        );
    }

    for (uid, name) in emojis {
        replace_all_in_place(
            Regex::new(format!(":{uid}:").as_str()).unwrap(),
            &mut body,
            format!(":{name}:").as_str(),
        );
    }

    Ok(body.to_string())
}

async fn get_items<F>(
    items: HashSet<String>,
    server_id: Option<&str>,
    db: &Database,
    getter: F,
    invalid_string: String,
) -> HashMap<String, String>
where
    F: AsyncFn(&str, Option<&str>, &Database) -> Result<String>,
{
    let mut resp = HashMap::default();

    for obj_id in items {
        resp.insert(
            obj_id.clone(),
            getter(&obj_id, server_id, db)
                .await
                .unwrap_or(invalid_string.clone()),
        );
    }

    resp
}

// Getters

async fn get_user_display_name(id: &str, server: Option<&str>, db: &Database) -> Result<String> {
    let config = config().await;

    let mut conn = get_connection().await?;
    let key = format!("pushd-user-cache:{}:{id}", server.unwrap_or("GLOBAL"));

    if let Ok(name) = conn.get(key.clone()).await {
        return Ok(name);
    }

    if let Some(server) = server {
        let member = db.fetch_member(server, id).await?;
        if let Some(nickname) = member.nickname {
            conn.set_ex::<_, _, ()>(key, nickname.clone(), config.pushd.render_cache_time)
                .await
                .to_internal_error()?;
            return Ok(nickname);
        }
    }

    let user = db.fetch_user(id).await?;
    let name = user.display_name.unwrap_or(user.username);

    conn.set_ex::<_, _, ()>(key, name.clone(), config.pushd.render_cache_time)
        .await
        .to_internal_error()?;

    Ok(name)
}

async fn get_channel_name(id: &str, _server: Option<&str>, db: &Database) -> Result<String> {
    let config = config().await;

    let mut conn = get_connection().await?;
    let key = format!("pushd-channel-cache:{id}");

    if let Ok(name) = conn.get(key.clone()).await {
        return Ok(name);
    }

    let channel = db.fetch_channel(id).await?;
    let name = match channel {
        Channel::DirectMessage { .. } => "DM Channel".to_string(),
        Channel::Group { name, .. }
        | Channel::TextChannel { name, .. }
        | Channel::Thread { name, .. }
        | Channel::Forum { name, .. } => name,
        Channel::SavedMessages { .. } => "Err".to_string(),
    };

    conn.set_ex::<_, _, ()>(key, name.clone(), config.pushd.render_cache_time)
        .await
        .to_internal_error()?;

    Ok(name)
}

async fn get_role_name(id: &str, server: Option<&str>, db: &Database) -> Result<String> {
    let server = server.unwrap(); // Must be passed, but the interface must stay the same as the other getters
    let config: revolt_config::Settings = config().await;

    let mut conn = get_connection().await?;
    let key = format!("pushd-role-cache:{server}:{id}");

    if let Ok(name) = conn.get(key.clone()).await {
        return Ok(name);
    }

    let server = db.fetch_server(server).await?;
    let name = server
        .roles
        .get(id)
        .ok_or_else(|| create_error!(NotFound))?
        .name
        .clone();

    conn.set_ex::<_, _, ()>(key, name.clone(), config.pushd.render_cache_time)
        .await
        .to_internal_error()?;

    Ok(name)
}

async fn get_emoji_name(id: &str, _server: Option<&str>, db: &Database) -> Result<String> {
    let config: revolt_config::Settings = config().await;

    let mut conn = get_connection().await?;
    let key = format!("pushd-emoji-cache:{id}");

    if let Ok(name) = conn.get(key.clone()).await {
        return Ok(name);
    }

    let emoji = db.fetch_emoji(id).await?;
    let name = emoji.name;

    conn.set_ex::<_, _, ()>(key, name.clone(), config.pushd.render_cache_time)
        .await
        .to_internal_error()?;

    Ok(name)
}

// utility

/// An encrypted message, or any message in a protected channel, even if the
/// channel copy is stale and lacks the flag
fn is_protected(notification: &PushNotification) -> bool {
    notification.message.encrypted.is_some()
        || matches!(
            notification.channel,
            v0::Channel::TextChannel {
                protected: true,
                ..
            }
        )
}

async fn get_channel_server_id(channel_id: &str, db: &Database) -> Result<String> {
    match db.fetch_channel(channel_id).await? {
        Channel::DirectMessage { .. } | Channel::Group { .. } | Channel::SavedMessages { .. } => {
            Err(create_error!(NotFound))
        }
        Channel::TextChannel { server, .. }
        | Channel::Thread { server, .. }
        | Channel::Forum { server, .. } => Ok(server),
    }
}

fn replace_all_in_place<R: regex::Replacer>(regex: Regex, s: &mut Cow<'_, str>, replacer: R) {
    let new = regex.replace_all(s, replacer);
    if let Cow::Owned(o) = new {
        *s = Cow::Owned(o);
    }
}

#[cfg(test)]
mod tests {
    use revolt_database::{
        events::rabbit::{MassMessageSentPayload, MessageSentPayload},
        Database, DatabaseInfo,
    };
    use revolt_models::v0::{Channel, Message, PushNotification, PROTECTED_PUSH_BODY};
    use revolt_parser::parse_message;

    use super::render_notification_content;

    const CHANNEL_ID: &str = "01FD58YK5W7QRV5H3D64KTQYX1";
    const SERVER_ID: &str = "01FD58YK5W7QRV5H3D64KTQYX2";

    /// One token of every kind the renderer resolves: user, channel, role, emoji
    const TOKEN_BODY: &str = "hi <@01FD58YK5W7QRV5H3D64KTQYX3> see <#01FD58YK5W7QRV5H3D64KTQYX4> \
                              <%01FD58YK5W7QRV5H3D64KTQYX5> :01FD58YK5W7QRV5H3D64KTQYX6:";

    async fn db() -> Database {
        DatabaseInfo::Reference.connect().await.unwrap()
    }

    fn channel(protected: Option<bool>) -> Channel {
        let mut value = serde_json::json!({
            "channel_type": "TextChannel",
            "_id": CHANNEL_ID,
            "server": SERVER_ID,
            "name": "general",
        });
        if let Some(protected) = protected {
            value["protected"] = protected.into();
        }
        serde_json::from_value(value).unwrap()
    }

    fn encrypted() -> serde_json::Value {
        serde_json::json!({
            "v": 1,
            "group_id": format!("{}1", "0".repeat(63)),
            "epoch": 7,
            "sender_device_id": "a".repeat(32),
            "nonce": "Tk9OQ0VOT05DRU5PTkNFTk9OQ0VOT05D",
            "ciphertext": "Q0lQSEVSVEVYVF9DSVBIRVJURVhUX0NJUEhFUlRFWFQ",
            "sig": "U0lHTkFUVVJFX1NJR05BVFVSRV9TSUdOQVRVUkVfU0lHTkFUVVJFX1NJR05BVFVSRV9TSUdOQVRVUkVfU0lH",
        })
    }

    fn message(content: &str) -> Message {
        serde_json::from_value(serde_json::json!({
            "_id": "01FD58YK5W7QRV5H3D64KTQYX7",
            "nonce": "01FD58YK5W7QRV5H3D64KTQYX8",
            "channel": CHANNEL_ID,
            "author": "01FD58YK5W7QRV5H3D64KTQYX9",
            "content": content,
        }))
        .unwrap()
    }

    /// What `inbound/message.rs` deserializes off the queue
    fn via_message_queue(notification: PushNotification) -> PushNotification {
        let wire = serde_json::to_string(&MessageSentPayload {
            notification,
            users: vec!["01FD58YK5W7QRV5H3D64KTQYXA".to_string()],
        })
        .unwrap();
        serde_json::from_slice::<MessageSentPayload>(wire.as_bytes())
            .unwrap()
            .notification
    }

    /// What `inbound/mass_mention.rs` deserializes off the queue
    fn via_mass_mention_queue(notification: PushNotification) -> Vec<PushNotification> {
        let wire = serde_json::to_string(&MassMessageSentPayload {
            notifications: vec![notification],
            server_id: SERVER_ID.to_string(),
        })
        .unwrap();
        serde_json::from_slice::<MassMessageSentPayload>(wire.as_bytes())
            .unwrap()
            .notifications
    }

    /// Renders through both consumers' inputs
    async fn render_both(notification: PushNotification) -> Vec<String> {
        let db = db().await;
        let direct = via_message_queue(notification.clone());
        let mut rendered = vec![render_notification_content(&direct, &db).await.unwrap()];
        for push in via_mass_mention_queue(notification).iter() {
            rendered.push(render_notification_content(push, &db).await.unwrap());
        }
        rendered
    }

    /// The fixture body must carry every token kind, or the tests below
    /// would pass without the renderer ever being tempted to resolve one
    #[test]
    fn token_body_has_every_token_kind() {
        let parsed = parse_message(TOKEN_BODY);
        assert_eq!(parsed.user_mentions.len(), 1);
        assert_eq!(parsed.channel_mentions.len(), 1);
        assert_eq!(parsed.role_mentions.len(), 1);
        assert_eq!(parsed.emojis.len(), 1);
    }

    /// Decision 10: a protected channel's notification, as the producer
    /// builds it, renders to the generic body even if a body with tokens
    /// reaches pushd
    #[tokio::test]
    async fn protected_channel_notification_is_not_rendered() {
        let mut notification =
            PushNotification::from(message(TOKEN_BODY), None, channel(Some(true))).await;
        notification.body = TOKEN_BODY.to_string();

        let rendered = render_both(notification).await;
        assert_eq!(rendered.len(), 2);
        for body in rendered {
            assert_eq!(body, PROTECTED_PUSH_BODY);
        }
    }

    /// An encrypted message is protected even on a channel copy that lacks
    /// the `protected` flag
    #[tokio::test]
    async fn encrypted_message_on_unflagged_channel_is_not_rendered() {
        let mut message = serde_json::to_value(message(TOKEN_BODY)).unwrap();
        message["encrypted"] = encrypted();
        let notification: PushNotification = serde_json::from_value(serde_json::json!({
            "author": "alice",
            "icon": "https://app.test/assets/logo.png",
            "body": TOKEN_BODY,
            "tag": CHANNEL_ID,
            "timestamp": 0,
            "url": "https://app.test/channel",
            "message": message,
            "channel": channel(None),
        }))
        .unwrap();
        assert!(notification.message.encrypted.is_some());
        assert!(!matches!(
            notification.channel,
            Channel::TextChannel {
                protected: true,
                ..
            }
        ));

        let rendered = render_both(notification).await;
        assert_eq!(rendered.len(), 2);
        for body in rendered {
            assert_eq!(body, PROTECTED_PUSH_BODY);
        }
    }

    /// An ordinary notification still goes through the renderer
    #[tokio::test]
    async fn unprotected_notification_still_renders() {
        let notification =
            PushNotification::from(message("hello there"), None, channel(Some(false))).await;
        assert_eq!(notification.body, "hello there");

        let rendered = render_both(notification).await;
        assert_eq!(rendered, vec!["hello there".to_string(); 2]);
    }
}
