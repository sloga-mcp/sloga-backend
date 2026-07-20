use futures::StreamExt;
use revolt_result::Result;

use crate::MongoDb;
use crate::{ConnectionPlatform, StreamConnection};

use super::AbstractStreamConnections;

static COL: &str = "user_stream_connections";

#[async_trait]
impl AbstractStreamConnections for MongoDb {
    /// Insert or replace a connection (link / relink).
    async fn upsert_stream_connection(&self, connection: &StreamConnection) -> Result<()> {
        self.col::<StreamConnection>(COL)
            .replace_one(doc! { "_id": &connection.id }, connection)
            .upsert(true)
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("replace_one", COL))
    }

    /// Save an existing connection WITHOUT upserting.
    async fn save_stream_connection(&self, connection: &StreamConnection) -> Result<()> {
        self.col::<StreamConnection>(COL)
            .replace_one(doc! { "_id": &connection.id }, connection)
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("replace_one", COL))
    }

    /// Fetch one user's connection on a platform.
    async fn fetch_stream_connection(
        &self,
        user_id: &str,
        platform: &ConnectionPlatform,
    ) -> Result<StreamConnection> {
        query!(
            self,
            find_one_by_id,
            COL,
            &StreamConnection::compose_id(user_id, platform)
        )?
        .ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch every connection a user holds.
    async fn fetch_stream_connections_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<StreamConnection>> {
        Ok(self
            .col::<StreamConnection>(COL)
            .find(doc! { "user_id": user_id })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await)
    }

    /// Fetch every connection on a platform (poller scan).
    async fn fetch_stream_connections_by_platform(
        &self,
        platform: &ConnectionPlatform,
    ) -> Result<Vec<StreamConnection>> {
        Ok(self
            .col::<StreamConnection>(COL)
            .find(doc! { "platform": platform.as_variant_str() })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await)
    }

    /// Delete one user's connection on a platform, returning it.
    async fn delete_stream_connection(
        &self,
        user_id: &str,
        platform: &ConnectionPlatform,
    ) -> Result<StreamConnection> {
        self.col::<StreamConnection>(COL)
            .find_one_and_delete(doc! {
                "_id": StreamConnection::compose_id(user_id, platform)
            })
            .await
            .map_err(|_| create_database_error!("find_one_and_delete", COL))?
            .ok_or_else(|| create_error!(NotFound))
    }

    /// Delete every connection a user holds, returning the removed rows.
    async fn delete_stream_connections_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<StreamConnection>> {
        let rows = self.fetch_stream_connections_for_user(user_id).await?;

        self.col::<StreamConnection>(COL)
            .delete_many(doc! { "user_id": user_id })
            .await
            .map_err(|_| create_database_error!("delete_many", COL))?;

        Ok(rows)
    }
}
