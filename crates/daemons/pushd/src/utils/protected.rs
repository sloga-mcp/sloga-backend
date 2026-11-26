use revolt_models::v0::{Channel, PushNotification};

/// Title of every protected-channel push (S8-O4). The body is
/// `PROTECTED_PUSH_BODY`; neither names the author or the channel
pub const PROTECTED_PUSH_TITLE: &str = "New message";

/// An encrypted message, or any message in a protected channel, even if the
/// channel copy is stale and lacks the flag
pub fn is_protected(notification: &PushNotification) -> bool {
    notification.message.encrypted.is_some()
        || matches!(
            notification.channel,
            Channel::TextChannel {
                protected: true,
                ..
            }
        )
}

/// Notifications as they reach the outbound builders, for the builder tests
#[cfg(test)]
pub mod fixtures {
    use revolt_models::v0::PushNotification;

    pub const CHANNEL_ID: &str = "01FD58YK5W7QRV5H3D64KTQYC1";
    pub const SERVER_ID: &str = "01FD58YK5W7QRV5H3D64KTQYS1";
    pub const MESSAGE_ID: &str = "01FD58YK5W7QRV5H3D64KTQYM1";
    pub const NONCE: &str = "01FD58YK5W7QRV5H3D64KTQYN1";
    pub const AUTHOR_ID: &str = "01FD58YK5W7QRV5H3D64KTQYA1";
    pub const AUTHOR_NAME: &str = "alice-author-name";
    pub const CHANNEL_NAME: &str = "secret-plans-channel";
    pub const AVATAR_URL: &str = "https://autumn.test/avatars/AVATARFILE01";
    pub const ATTACHMENT_URL: &str = "https://autumn.test/attachments/ATTACHFILE01";
    pub const URL: &str =
        "https://app.test/channel/01FD58YK5W7QRV5H3D64KTQYC1/01FD58YK5W7QRV5H3D64KTQYM1";
    /// Text that must never leave pushd for a protected channel
    pub const STRAY_BODY: &str = "stray plaintext body";
    pub const STRAY_CONTENT: &str = "stray plaintext content";

    /// Every value a protected push must not carry
    pub const FORBIDDEN: [&str; 9] = [
        AUTHOR_NAME,
        CHANNEL_NAME,
        AVATAR_URL,
        ATTACHMENT_URL,
        AUTHOR_ID,
        NONCE,
        SERVER_ID,
        STRAY_BODY,
        STRAY_CONTENT,
    ];

    /// A message notification on a server text channel. `protected` sets the
    /// channel flag; every name, avatar, id and stray text is filled in, so a
    /// builder that forwards any of them is caught
    pub fn notification(protected: bool) -> PushNotification {
        serde_json::from_value(serde_json::json!({
            "author": AUTHOR_NAME,
            "icon": AVATAR_URL,
            "image": ATTACHMENT_URL,
            "body": STRAY_BODY,
            "raw_body": STRAY_BODY,
            "tag": CHANNEL_ID,
            "timestamp": 1_700_000_000u64,
            "url": URL,
            "message": {
                "_id": MESSAGE_ID,
                "nonce": NONCE,
                "channel": CHANNEL_ID,
                "author": AUTHOR_ID,
                "content": STRAY_CONTENT,
                "flags": 1,
            },
            "channel": {
                "channel_type": "TextChannel",
                "_id": CHANNEL_ID,
                "server": SERVER_ID,
                "name": CHANNEL_NAME,
                "description": CHANNEL_NAME,
                "protected": protected,
            },
        }))
        .expect("notification fixture")
    }

    /// An encrypted message on a channel copy that lacks the flag
    pub fn encrypted_on_unflagged_channel() -> PushNotification {
        let mut value = serde_json::to_value(notification(false)).unwrap();
        value["message"]["encrypted"] = serde_json::json!({
            "v": 1,
            "group_id": format!("{}1", "0".repeat(63)),
            "epoch": 7,
            "sender_device_id": "a".repeat(32),
            "nonce": "Tk9OQ0VOT05DRU5PTkNFTk9OQ0VOT05D",
            "ciphertext": "Q0lQSEVSVEVYVF9DSVBIRVJURVhUX0NJUEhFUlRFWFQ",
            "sig": "U0lHTkFUVVJFX1NJR05BVFVSRV9TSUdOQVRVUkVfU0lHTkFUVVJFX1NJR05BVFVSRV9TSUdOQVRVUkVfU0lH",
        });
        serde_json::from_value(value).expect("encrypted fixture")
    }

    /// Panics naming the first forbidden value found in `wire`
    pub fn assert_carries_nothing_forbidden(builder: &str, wire: &str) {
        for value in FORBIDDEN {
            assert!(
                !wire.contains(value),
                "{builder}: a protected push carries {value:?}: {wire}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{fixtures, is_protected};

    #[test]
    fn protected_flag_or_ciphertext_marks_a_notification_protected() {
        assert!(is_protected(&fixtures::notification(true)));
        assert!(is_protected(&fixtures::encrypted_on_unflagged_channel()));
        assert!(!is_protected(&fixtures::notification(false)));
    }
}
