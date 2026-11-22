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

        /// This session wants direct messages, groups, friend requests and calls only
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub chats_only: Option<bool>,

        /// This session must not be rung for incoming calls
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub no_ring: Option<bool>,
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
            chats_only: None,
            no_ring: None,
        };

        let value = serde_json::to_value(&sub).unwrap();
        assert_eq!(value["kind"], "unifiedpush");

        let back: WebPushSubscription = serde_json::from_value(value).unwrap();
        assert_eq!(back, sub);
    }

    fn preferences(chats_only: Option<bool>, no_ring: Option<bool>) -> WebPushSubscription {
        WebPushSubscription {
            endpoint: "e".to_string(),
            p256dh: "p".to_string(),
            auth: "a".to_string(),
            kind: None,
            chats_only,
            no_ring,
        }
    }

    #[test]
    fn subscription_without_preferences_loads_and_saves_without_them() {
        // Every subscription stored before the preferences existed looks like this
        let sub: WebPushSubscription =
            serde_json::from_str(r#"{"endpoint":"e","p256dh":"p","auth":"a"}"#).unwrap();
        assert_eq!(sub.chats_only, None);
        assert_eq!(sub.no_ring, None);

        let value = serde_json::to_value(&sub).unwrap();
        assert!(value.get("chats_only").is_none());
        assert!(value.get("no_ring").is_none());
    }

    #[test]
    fn chats_only_round_trips() {
        let sub = preferences(Some(true), None);

        let value = serde_json::to_value(&sub).unwrap();
        assert_eq!(value["chats_only"], true);
        assert!(value.get("no_ring").is_none());

        let back: WebPushSubscription = serde_json::from_value(value).unwrap();
        assert_eq!(back, sub);
    }

    #[test]
    fn no_ring_round_trips() {
        let sub = preferences(None, Some(true));

        let value = serde_json::to_value(&sub).unwrap();
        assert_eq!(value["no_ring"], true);
        assert!(value.get("chats_only").is_none());

        let back: WebPushSubscription = serde_json::from_value(value).unwrap();
        assert_eq!(back, sub);
    }

    #[test]
    fn false_preference_is_saved_as_false() {
        // Only an unset preference is left out; a session that turned one
        // off keeps that answer
        let sub = preferences(Some(false), Some(false));

        let value = serde_json::to_value(&sub).unwrap();
        assert_eq!(value["chats_only"], false);
        assert_eq!(value["no_ring"], false);

        let back: WebPushSubscription = serde_json::from_value(value).unwrap();
        assert_eq!(back, sub);
    }

    #[test]
    fn preferences_survive_the_api_conversion_both_ways() {
        // The two fields have the same type, so the compiler accepts one
        // copied into the other; different values make that show
        let sub = preferences(Some(true), Some(false));

        let api: revolt_models::v0::WebPushSubscription = sub.clone().into();
        assert_eq!(api.chats_only, Some(true));
        assert_eq!(api.no_ring, Some(false));

        let back: WebPushSubscription = api.into();
        assert_eq!(back, sub);
    }
}

#[cfg(all(test, feature = "mongodb"))]
mod bson_tests {
    use bson::{from_document, from_slice, to_document, to_vec, Document};

    use super::{PushSubscriptionKind, WebPushSubscription};

    fn subscription(kind: Option<PushSubscriptionKind>) -> WebPushSubscription {
        WebPushSubscription {
            endpoint: "e".to_string(),
            p256dh: "p".to_string(),
            auth: "a".to_string(),
            kind,
            chats_only: None,
            no_ring: None,
        }
    }

    fn preferences(chats_only: Option<bool>, no_ring: Option<bool>) -> WebPushSubscription {
        WebPushSubscription {
            chats_only,
            no_ring,
            ..subscription(None)
        }
    }

    /// Decode as a `Document` and as the raw bytes a MongoDB cursor reads
    fn decode(document: Document) -> WebPushSubscription {
        let bytes = to_vec(&document).unwrap();
        let raw: WebPushSubscription = from_slice(&bytes).unwrap();

        let decoded: WebPushSubscription = from_document(document).unwrap();
        assert_eq!(raw, decoded);
        decoded
    }

    #[test]
    fn unifiedpush_kind_round_trips_through_bson() {
        let sub = subscription(Some(PushSubscriptionKind::UnifiedPush));

        let document = to_document(&sub).unwrap();
        assert_eq!(document.get_str("kind"), Ok("unifiedpush"));
        assert_eq!(decode(document), sub);
    }

    #[test]
    fn browser_subscription_has_no_kind_key_in_bson() {
        let sub = subscription(None);

        let document = to_document(&sub).unwrap();
        assert!(!document.contains_key("kind"));
        assert_eq!(decode(document), sub);
    }

    #[test]
    fn stored_subscription_without_kind_loads_from_bson() {
        let document = doc! {
            "endpoint": "e",
            "p256dh": "p",
            "auth": "a"
        };

        assert_eq!(decode(document), subscription(None));
    }

    #[test]
    fn stored_subscription_without_preferences_loads_and_saves_without_them_in_bson() {
        // Every subscription stored before the preferences existed looks like this
        let document = doc! {
            "endpoint": "e",
            "p256dh": "p",
            "auth": "a"
        };

        let sub = decode(document);
        assert_eq!(sub.chats_only, None);
        assert_eq!(sub.no_ring, None);

        let saved = to_document(&sub).unwrap();
        assert!(!saved.contains_key("chats_only"));
        assert!(!saved.contains_key("no_ring"));
    }

    #[test]
    fn chats_only_round_trips_through_bson() {
        let sub = preferences(Some(true), None);

        let document = to_document(&sub).unwrap();
        assert_eq!(document.get_bool("chats_only"), Ok(true));
        assert!(!document.contains_key("no_ring"));
        assert_eq!(decode(document), sub);
    }

    #[test]
    fn no_ring_round_trips_through_bson() {
        let sub = preferences(None, Some(true));

        let document = to_document(&sub).unwrap();
        assert_eq!(document.get_bool("no_ring"), Ok(true));
        assert!(!document.contains_key("chats_only"));
        assert_eq!(decode(document), sub);
    }

    #[test]
    fn false_preference_is_stored_as_false_in_bson() {
        // Only an unset preference is left out; a session that turned one
        // off keeps that answer
        let sub = preferences(Some(false), Some(false));

        let document = to_document(&sub).unwrap();
        assert_eq!(document.get_bool("chats_only"), Ok(false));
        assert_eq!(document.get_bool("no_ring"), Ok(false));
        assert_eq!(decode(document), sub);
    }
}
