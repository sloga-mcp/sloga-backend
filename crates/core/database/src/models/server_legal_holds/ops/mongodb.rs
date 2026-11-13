use revolt_result::Result;

use crate::{MongoDb, ServerLegalHold};

use super::AbstractServerLegalHolds;

static COL: &str = "server_legal_holds";

#[async_trait]
impl AbstractServerLegalHolds for MongoDb {
    /// Fetch the hold on a server, if one is set
    async fn fetch_server_legal_hold(&self, server_id: &str) -> Result<Option<ServerLegalHold>> {
        query!(self, find_one_by_id, COL, server_id)
    }

    /// Set the hold, replacing any stored row whole. A replace, not a `$set`:
    /// a `$set` of a hold without a note would keep a stale stored note.
    async fn set_server_legal_hold(&self, hold: &ServerLegalHold) -> Result<()> {
        self.col::<ServerLegalHold>(COL)
            .replace_one(doc! { "_id": &hold.id }, hold)
            .upsert(true)
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("replace_one", COL))
    }

    /// Clear the hold; no row is not an error
    async fn clear_server_legal_hold(&self, server_id: &str) -> Result<()> {
        query!(self, delete_one_by_id, COL, server_id).map(|_| ())
    }
}
