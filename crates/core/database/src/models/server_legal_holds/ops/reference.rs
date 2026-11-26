use revolt_result::Result;

use crate::{ReferenceDb, ServerLegalHold};

use super::AbstractServerLegalHolds;

/// Each fn takes the `server_legal_holds` lock alone and never holds it
/// together with another (design 2.9).
#[async_trait]
impl AbstractServerLegalHolds for ReferenceDb {
    /// Fetch the hold on a server, if one is set
    async fn fetch_server_legal_hold(&self, server_id: &str) -> Result<Option<ServerLegalHold>> {
        let holds = self.server_legal_holds.lock().await;
        Ok(holds.get(server_id).cloned())
    }

    /// Set the hold, replacing any stored row whole
    async fn set_server_legal_hold(&self, hold: &ServerLegalHold) -> Result<()> {
        let mut holds = self.server_legal_holds.lock().await;
        holds.insert(hold.id.clone(), hold.clone());
        Ok(())
    }

    /// Clear the hold; no row is not an error
    async fn clear_server_legal_hold(&self, server_id: &str) -> Result<()> {
        let mut holds = self.server_legal_holds.lock().await;
        holds.remove(server_id);
        Ok(())
    }
}
