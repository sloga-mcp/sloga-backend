use bson::Document;
use revolt_result::Result;

use crate::Interaction;
use crate::InteractionKind;
use crate::ModalValue;
use crate::MongoDb;

use super::AbstractInteractions;

static COL: &str = "interactions";

#[async_trait]
impl AbstractInteractions for MongoDb {
    /// Insert a new interaction row.
    async fn insert_interaction(&self, interaction: &Interaction) -> Result<()> {
        query!(self, insert_one, COL, &interaction).map(|_| ())
    }

    /// Fetch an interaction by its id.
    async fn fetch_interaction(&self, id: &str) -> Result<Interaction> {
        query!(self, find_one_by_id, COL, id)?.ok_or_else(|| create_error!(NotFound))
    }

    /// Atomically claim the single response slot for an interaction.
    async fn try_claim_interaction_response(&self, id: &str) -> Result<bool> {
        // `responded: false` is stored as a MISSING key (skip_serializing_if),
        // so match on "not true" rather than "false".
        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": id,
                    "responded": { "$ne": true }
                },
                doc! {
                    "$set": { "responded": true }
                },
            )
            .await
            .map(|result| result.modified_count == 1)
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Atomically record a modal submission, claiming the single submit slot.
    async fn try_submit_modal(&self, id: &str, values: &[ModalValue]) -> Result<bool> {
        // Same "not true" match as the response claim: `submitted: false` is
        // stored as a MISSING key.
        let values = bson::to_bson(values)
            .map_err(|_| create_database_error!("to_bson", "submitted_values"))?;

        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": id,
                    "submitted": { "$ne": true }
                },
                doc! {
                    "$set": {
                        "submitted": true,
                        "submitted_values": values
                    }
                },
            )
            .await
            .map(|result| result.modified_count == 1)
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Delete all interactions addressed to a bot (bot-deletion cascade).
    async fn delete_interactions_by_bot(&self, bot_id: &str) -> Result<()> {
        self.col::<Document>(COL)
            .delete_many(doc! {
                "bot_id": bot_id
            })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", COL))
    }

    /// Delete every interaction with an id strictly below the cutoff ULID.
    async fn delete_interactions_before(&self, cutoff_id: &str) -> Result<()> {
        self.col::<Document>(COL)
            .delete_many(doc! {
                "_id": { "$lt": cutoff_id }
            })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", COL))
    }

    /// Same, restricted to one kind.
    async fn delete_interactions_of_kind_before(
        &self,
        kind: InteractionKind,
        cutoff_id: &str,
    ) -> Result<()> {
        let kind = bson::to_bson(&kind).map_err(|_| create_database_error!("to_bson", "kind"))?;

        self.col::<Document>(COL)
            .delete_many(doc! {
                "kind": kind,
                "_id": { "$lt": cutoff_id }
            })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", COL))
    }
}
