use revolt_result::Result;

use crate::Interaction;
use crate::ReferenceDb;

use super::AbstractInteractions;

#[async_trait]
impl AbstractInteractions for ReferenceDb {
    /// Insert a new interaction row.
    async fn insert_interaction(&self, interaction: &Interaction) -> Result<()> {
        let mut interactions = self.interactions.lock().await;
        if interactions
            .insert(interaction.id.to_string(), interaction.clone())
            .is_some()
        {
            Err(create_database_error!("insert", "interactions"))
        } else {
            Ok(())
        }
    }

    /// Fetch an interaction by its id.
    async fn fetch_interaction(&self, id: &str) -> Result<Interaction> {
        let interactions = self.interactions.lock().await;
        interactions
            .get(id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    /// Atomically claim the single response slot for an interaction.
    /// The mutex makes check-and-set atomic on this driver.
    async fn try_claim_interaction_response(&self, id: &str) -> Result<bool> {
        let mut interactions = self.interactions.lock().await;
        match interactions.get_mut(id) {
            Some(interaction) if !interaction.responded => {
                interaction.responded = true;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Delete all interactions addressed to a bot (bot-deletion cascade).
    async fn delete_interactions_by_bot(&self, bot_id: &str) -> Result<()> {
        let mut interactions = self.interactions.lock().await;
        interactions.retain(|_, interaction| interaction.bot_id != bot_id);
        Ok(())
    }

    /// Delete every interaction with an id strictly below the cutoff ULID.
    async fn delete_interactions_before(&self, cutoff_id: &str) -> Result<()> {
        let mut interactions = self.interactions.lock().await;
        interactions.retain(|id, _| id.as_str() >= cutoff_id);
        Ok(())
    }
}
