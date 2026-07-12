use revolt_result::Result;

use crate::Interaction;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractInteractions: Sync + Send {
    /// Insert a new interaction row.
    async fn insert_interaction(&self, interaction: &Interaction) -> Result<()>;

    /// Fetch an interaction by its id.
    async fn fetch_interaction(&self, id: &str) -> Result<Interaction>;

    /// Atomically claim the single response slot for an interaction.
    ///
    /// Flips `responded` false→true; returns whether THIS caller won the
    /// claim. A second concurrent respond gets `false` — replay defence.
    async fn try_claim_interaction_response(&self, id: &str) -> Result<bool>;

    /// Delete all interactions addressed to a bot (bot-deletion cascade).
    async fn delete_interactions_by_bot(&self, bot_id: &str) -> Result<()>;

    /// Delete every interaction with an id strictly below the cutoff ULID
    /// (storage hygiene; expiry is enforced at respond time regardless).
    async fn delete_interactions_before(&self, cutoff_id: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::AbstractInteractions;
    use crate::{Interaction, InteractionKind};

    fn row(id: &str) -> Interaction {
        Interaction {
            id: id.to_string(),
            kind: InteractionKind::Command,
            token: "token".to_string(),
            bot_id: "01BOT0000000000000000000000".to_string(),
            user_id: "01USER000000000000000000000".to_string(),
            channel_id: "01CHAN000000000000000000000".to_string(),
            message_id: None,
            command_id: Some("01CMD0000000000000000000000".to_string()),
            command_name: Some("ping".to_string()),
            options: Default::default(),
            responded: false,
        }
    }

    #[tokio::test]
    async fn respond_claim_is_single_use() {
        database_test!(|db| async move {
            let interaction = row("01INTERACTION00000000000000");
            db.insert_interaction(&interaction).await.unwrap();

            let fetched = db.fetch_interaction(&interaction.id).await.unwrap();
            assert_eq!(fetched, interaction);

            // First claim wins, second (replay) loses
            assert!(db
                .try_claim_interaction_response(&interaction.id)
                .await
                .unwrap());
            assert!(!db
                .try_claim_interaction_response(&interaction.id)
                .await
                .unwrap());

            // Claiming an unknown id is not an error, just a lost claim
            assert!(!db
                .try_claim_interaction_response("01MISSING000000000000000000")
                .await
                .unwrap());
        });
    }

    #[tokio::test]
    async fn cleanup_paths() {
        database_test!(|db| async move {
            let older = row(&ulid::Ulid::from_parts(1_000, 1).to_string());
            let newer = row(&ulid::Ulid::from_parts(2_000_000, 1).to_string());
            db.insert_interaction(&older).await.unwrap();
            db.insert_interaction(&newer).await.unwrap();

            // Sweep strictly-below the cutoff
            let cutoff = ulid::Ulid::from_parts(1_000_000, 0).to_string();
            db.delete_interactions_before(&cutoff).await.unwrap();
            assert!(db.fetch_interaction(&older.id).await.is_err());
            assert!(db.fetch_interaction(&newer.id).await.is_ok());

            // Bot cascade
            db.delete_interactions_by_bot(&newer.bot_id).await.unwrap();
            assert!(db.fetch_interaction(&newer.id).await.is_err());
        });
    }
}
