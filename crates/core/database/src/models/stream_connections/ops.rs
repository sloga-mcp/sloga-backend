use revolt_result::Result;

use crate::{ConnectionPlatform, StreamConnection};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractStreamConnections: Sync + Send {
    /// Insert or replace a connection (link / relink — id is
    /// `{user_id}/{platform}` so relinking replaces the old channel).
    async fn upsert_stream_connection(&self, connection: &StreamConnection) -> Result<()>;

    /// Save an existing connection WITHOUT upserting (poller writes:
    /// losing the race against an unlink must not resurrect the row).
    async fn save_stream_connection(&self, connection: &StreamConnection) -> Result<()>;

    /// Fetch one user's connection on a platform.
    async fn fetch_stream_connection(
        &self,
        user_id: &str,
        platform: &ConnectionPlatform,
    ) -> Result<StreamConnection>;

    /// Fetch every connection a user holds.
    async fn fetch_stream_connections_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<StreamConnection>>;

    /// Fetch every connection on a platform (live-status poller scan).
    async fn fetch_stream_connections_by_platform(
        &self,
        platform: &ConnectionPlatform,
    ) -> Result<Vec<StreamConnection>>;

    /// Delete one user's connection on a platform; returns the removed row
    /// (callers revoke tokens) or NotFound.
    async fn delete_stream_connection(
        &self,
        user_id: &str,
        platform: &ConnectionPlatform,
    ) -> Result<StreamConnection>;

    /// Delete every connection a user holds, returning the removed rows
    /// (account-deletion cascade revokes their tokens).
    async fn delete_stream_connections_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<StreamConnection>>;
}

#[cfg(test)]
mod tests {
    use super::AbstractStreamConnections;
    use crate::{ConnectionPlatform, StreamConnection, StreamLiveState};
    use iso8601_timestamp::Timestamp;

    fn row(user_id: &str, platform: ConnectionPlatform, handle: &str) -> StreamConnection {
        StreamConnection {
            id: StreamConnection::compose_id(user_id, &platform),
            user_id: user_id.to_string(),
            platform,
            channel_id: format!("chan-{handle}"),
            handle: handle.to_string(),
            display_name: handle.to_string(),
            refresh_token: None,
            access_token: None,
            token_expiry: None,
            live: None,
            poll_failures: 0,
            last_notified_live_at: None,
        }
    }

    #[tokio::test]
    async fn upsert_fetch_and_relink_replaces() {
        database_test!(|db| async move {
            let user = "01USER000000000000000000000";
            db.upsert_stream_connection(&row(user, ConnectionPlatform::Twitch, "old_handle"))
                .await
                .unwrap();

            // Relink replaces the same platform slot
            db.upsert_stream_connection(&row(user, ConnectionPlatform::Twitch, "new_handle"))
                .await
                .unwrap();

            let fetched = db
                .fetch_stream_connection(user, &ConnectionPlatform::Twitch)
                .await
                .unwrap();
            assert_eq!(fetched.handle, "new_handle");

            db.upsert_stream_connection(&row(user, ConnectionPlatform::YouTube, "yt_handle"))
                .await
                .unwrap();
            assert_eq!(
                db.fetch_stream_connections_for_user(user).await.unwrap().len(),
                2
            );
        });
    }

    #[tokio::test]
    async fn save_does_not_resurrect_deleted_rows() {
        database_test!(|db| async move {
            let user = "01USER000000000000000000001";
            let mut conn = row(user, ConnectionPlatform::Twitch, "streamer");
            db.upsert_stream_connection(&conn).await.unwrap();

            // Unlink wins the race...
            db.delete_stream_connection(user, &ConnectionPlatform::Twitch)
                .await
                .unwrap();

            // ...then a stale poller save must NOT bring the row back
            conn.live = Some(StreamLiveState {
                title: Some("hi".to_string()),
                started_at: Timestamp::now_utc(),
            });
            db.save_stream_connection(&conn).await.unwrap();
            assert!(db
                .fetch_stream_connection(user, &ConnectionPlatform::Twitch)
                .await
                .is_err());
        });
    }

    #[tokio::test]
    async fn platform_scan_and_user_cascade() {
        database_test!(|db| async move {
            let alice = "01USER00000000000000000000A";
            let bob = "01USER00000000000000000000B";
            db.upsert_stream_connection(&row(alice, ConnectionPlatform::Twitch, "alice_ttv"))
                .await
                .unwrap();
            db.upsert_stream_connection(&row(alice, ConnectionPlatform::YouTube, "alice_yt"))
                .await
                .unwrap();
            db.upsert_stream_connection(&row(bob, ConnectionPlatform::Twitch, "bob_ttv"))
                .await
                .unwrap();

            let twitch = db
                .fetch_stream_connections_by_platform(&ConnectionPlatform::Twitch)
                .await
                .unwrap();
            assert_eq!(twitch.len(), 2);

            let removed = db.delete_stream_connections_for_user(alice).await.unwrap();
            assert_eq!(removed.len(), 2);
            assert!(db
                .fetch_stream_connections_for_user(alice)
                .await
                .unwrap()
                .is_empty());
            // Bob untouched
            assert!(db
                .fetch_stream_connection(bob, &ConnectionPlatform::Twitch)
                .await
                .is_ok());
        });
    }
}
