use revolt_result::Result;

use crate::ReferenceDb;
use crate::{ConnectionPlatform, StreamConnection};

use super::AbstractStreamConnections;

#[async_trait]
impl AbstractStreamConnections for ReferenceDb {
    /// Insert or replace a connection (link / relink).
    async fn upsert_stream_connection(&self, connection: &StreamConnection) -> Result<()> {
        let mut rows = self.stream_connections.lock().await;
        rows.insert(connection.id.to_string(), connection.clone());
        Ok(())
    }

    /// Save an existing connection WITHOUT upserting.
    async fn save_stream_connection(&self, connection: &StreamConnection) -> Result<()> {
        let mut rows = self.stream_connections.lock().await;
        if let Some(existing) = rows.get_mut(&connection.id) {
            *existing = connection.clone();
        }
        Ok(())
    }

    /// Fetch one user's connection on a platform.
    async fn fetch_stream_connection(
        &self,
        user_id: &str,
        platform: &ConnectionPlatform,
    ) -> Result<StreamConnection> {
        let rows = self.stream_connections.lock().await;
        rows.get(&StreamConnection::compose_id(user_id, platform))
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch every connection a user holds.
    async fn fetch_stream_connections_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<StreamConnection>> {
        let rows = self.stream_connections.lock().await;
        Ok(rows
            .values()
            .filter(|row| row.user_id == user_id)
            .cloned()
            .collect())
    }

    /// Fetch every connection on a platform (poller scan).
    async fn fetch_stream_connections_by_platform(
        &self,
        platform: &ConnectionPlatform,
    ) -> Result<Vec<StreamConnection>> {
        let rows = self.stream_connections.lock().await;
        Ok(rows
            .values()
            .filter(|row| &row.platform == platform)
            .cloned()
            .collect())
    }

    /// Delete one user's connection on a platform, returning it.
    async fn delete_stream_connection(
        &self,
        user_id: &str,
        platform: &ConnectionPlatform,
    ) -> Result<StreamConnection> {
        let mut rows = self.stream_connections.lock().await;
        rows.remove(&StreamConnection::compose_id(user_id, platform))
            .ok_or_else(|| create_error!(NotFound))
    }

    /// Delete every connection a user holds, returning the removed rows.
    async fn delete_stream_connections_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<StreamConnection>> {
        let mut rows = self.stream_connections.lock().await;
        let ids: Vec<String> = rows
            .values()
            .filter(|row| row.user_id == user_id)
            .map(|row| row.id.clone())
            .collect();

        Ok(ids.into_iter().filter_map(|id| rows.remove(&id)).collect())
    }
}
