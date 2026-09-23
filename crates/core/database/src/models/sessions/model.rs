use iso8601_timestamp::Timestamp;

use crate::{events::client::EventV1, Database, E2EEIdentity};
use revolt_result::Result;

auto_derived_partial!(
    /// Session information
    pub struct Session {
        /// Unique Id
        #[serde(rename = "_id")]
        pub id: String,

        /// User Id
        pub user_id: String,

        /// Session token
        pub token: String,

        /// Display name
        pub name: String,

        /// When the session was last logged in
        pub last_seen: Timestamp,

        /// Where the session originated from
        ///
        /// This could be used to differentiate sessions that come from staging/test vs prod, etc.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub origin: Option<String>,

        /// Web Push subscription
        #[serde(skip_serializing_if = "Option::is_none")]
        pub subscription: Option<WebPushSubscription>,
    },
    "PartialSession"
);

auto_derived!(
    /// Web Push subscription
    pub struct WebPushSubscription {
        pub endpoint: String,
        pub p256dh: String,
        pub auth: String,

        /// Delivery mechanism, absent for browser Web Push subscriptions
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<PushSubscriptionKind>,
    }

    /// Push subscription delivery mechanism
    #[serde(rename_all = "lowercase")]
    pub enum PushSubscriptionKind {
        /// UnifiedPush distributor endpoint
        UnifiedPush,
    }
);

impl Session {
    /// Save model
    pub async fn save(&self, db: &Database) -> Result<()> {
        db.save_session(self).await
    }

    /// Delete session
    pub async fn delete(self, db: &Database) -> Result<()> {
        // Delete from database
        db.delete_session(&self.id).await?;

        // An E2EE device dies with the session it is bound to: remove its
        // keys and queued envelopes and notify peers
        E2EEIdentity::revoke_devices_for_session(db, &self.user_id, &self.id).await?;

        // Create and push event
        EventV1::DeleteSession {
            user_id: self.user_id.clone(),
            session_id: self.id,
        }
        .private(self.user_id)
        .await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{PushSubscriptionKind, WebPushSubscription};

    #[test]
    fn subscription_without_kind_loads_and_saves_without_kind() {
        let sub: WebPushSubscription =
            serde_json::from_str(r#"{"endpoint":"e","p256dh":"p","auth":"a"}"#).unwrap();
        assert_eq!(sub.kind, None);

        let value = serde_json::to_value(&sub).unwrap();
        assert!(value.get("kind").is_none());
    }

    #[test]
    fn unifiedpush_kind_round_trips_as_lowercase() {
        let sub = WebPushSubscription {
            endpoint: "e".to_string(),
            p256dh: "p".to_string(),
            auth: "a".to_string(),
            kind: Some(PushSubscriptionKind::UnifiedPush),
        };

        let value = serde_json::to_value(&sub).unwrap();
        assert_eq!(value["kind"], "unifiedpush");

        let back: WebPushSubscription = serde_json::from_value(value).unwrap();
        assert_eq!(back, sub);
    }
}
