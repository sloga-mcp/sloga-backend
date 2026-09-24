use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::Session;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractSessions: Sync + Send {
    /// Find session by id
    async fn fetch_session(&self, id: &str) -> Result<Session>;

    /// Find sessions by user id
    async fn fetch_sessions(&self, user_id: &str) -> Result<Vec<Session>>;

    /// Find sessions by user ids
    async fn fetch_sessions_with_subscription(&self, user_ids: &[String]) -> Result<Vec<Session>>;

    /// Find session by token
    async fn fetch_session_by_token(&self, token: &str) -> Result<Session>;

    /// Save session
    async fn save_session(&self, session: &Session) -> Result<()>;

    /// Delete session
    async fn delete_session(&self, id: &str) -> Result<()>;

    /// Delete session
    async fn delete_all_sessions(&self, user_id: &str, ignore: Option<String>) -> Result<()>;

    /// Remove push subscription for a session by session id
    async fn remove_push_subscription_by_session_id(&self, session_id: &str) -> Result<()>;

    /// Remove push subscription for a session, only if its stored endpoint
    /// equals `endpoint`
    ///
    /// A late failure for a session's old endpoint must not wipe the newer
    /// subscription that replaced it. Zero matches (no such session, no
    /// subscription, or a different endpoint) is `Ok`.
    async fn remove_push_subscription_if_endpoint(
        &self,
        session_id: &str,
        endpoint: &str,
    ) -> Result<()>;

    async fn update_session_last_seen(&self, session_id: &str, when: Timestamp) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::AbstractSessions;
    use crate::{Session, WebPushSubscription};
    use iso8601_timestamp::Timestamp;

    const OLD_ENDPOINT: &str = "https://push.example.test/old";
    const NEW_ENDPOINT: &str = "https://push.example.test/new";

    fn session(id: &str, endpoint: Option<&str>) -> Session {
        Session {
            id: id.to_string(),
            user_id: "01USER000000000000000000000".to_string(),
            token: format!("token-{id}"),
            name: "test".to_string(),
            last_seen: Timestamp::now_utc(),
            origin: None,
            subscription: endpoint.map(|endpoint| WebPushSubscription {
                endpoint: endpoint.to_string(),
                p256dh: "p256dh".to_string(),
                auth: "auth".to_string(),
            }),
        }
    }

    #[tokio::test]
    async fn matching_endpoint_unsets_subscription() {
        database_test!(|db| async move {
            // Saved first, so a driver that drops the session id from its
            // filter is likely to reach it before the target
            let bystander = session("01SESSIONBYSTANDER00000000", Some(OLD_ENDPOINT));
            let target = session("01SESSIONTARGET00000000000", Some(OLD_ENDPOINT));
            db.save_session(&bystander).await.unwrap();
            db.save_session(&target).await.unwrap();

            db.remove_push_subscription_if_endpoint(&target.id, OLD_ENDPOINT)
                .await
                .unwrap();

            let fetched = db.fetch_session(&target.id).await.unwrap();
            assert!(
                fetched.subscription.is_none(),
                "a matching endpoint must unset the subscription"
            );

            let fetched = db.fetch_session(&bystander.id).await.unwrap();
            assert_eq!(
                fetched.subscription, bystander.subscription,
                "another session with the same endpoint must be untouched"
            );
        });
    }

    #[tokio::test]
    async fn different_endpoint_keeps_subscription() {
        database_test!(|db| async move {
            // The session has already moved to a new endpoint when the
            // failure for its old one arrives
            let healed = session("01SESSIONHEALED00000000000", Some(NEW_ENDPOINT));
            db.save_session(&healed).await.unwrap();

            db.remove_push_subscription_if_endpoint(&healed.id, OLD_ENDPOINT)
                .await
                .unwrap();

            let fetched = db.fetch_session(&healed.id).await.unwrap();
            assert_eq!(
                fetched.subscription, healed.subscription,
                "a different endpoint must keep the subscription"
            );
        });
    }

    #[tokio::test]
    async fn no_match_is_ok() {
        database_test!(|db| async move {
            assert!(db
                .remove_push_subscription_if_endpoint("01SESSIONMISSING0000000000", OLD_ENDPOINT)
                .await
                .is_ok());

            let bare = session("01SESSIONBARE0000000000000", None);
            db.save_session(&bare).await.unwrap();

            assert!(db
                .remove_push_subscription_if_endpoint(&bare.id, OLD_ENDPOINT)
                .await
                .is_ok());

            let fetched = db.fetch_session(&bare.id).await.unwrap();
            assert!(fetched.subscription.is_none());
        });
    }
}
