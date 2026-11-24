use crate::{AbstractAccountInvites, AccountInvite, MongoDb};
use bson::to_document;
use mongodb::options::UpdateOptions;
use revolt_result::Result;

const COL: &str = "account_invites";

#[async_trait]
impl AbstractAccountInvites for MongoDb {
    /// Find invite by id
    async fn fetch_account_invite(&self, id: &str) -> Result<AccountInvite> {
        query!(self, find_one_by_id, COL, id)?.ok_or_else(|| create_error!(InvalidInvite))
    }

    /// Save invite
    async fn save_account_invite(&self, invite: &AccountInvite) -> Result<()> {
        self.col::<AccountInvite>(COL)
            .update_one(
                doc! {
                    "_id": &invite.id
                },
                doc! {
                    "$set": to_document(invite).map_err(|_| create_database_error!("to_document", COL))?,
                },
            )
            .with_options(UpdateOptions::builder().upsert(true).build())
            .await
            .map_err(|_| create_database_error!("upsert_one", COL))
            .map(|_| ())
    }

    /// Use an invite up for `account_id`, but only while it is not used yet
    async fn claim_account_invite_if_unused(
        &self,
        invite_id: &str,
        account_id: &str,
    ) -> Result<bool> {
        // `$ne`, not `false`: an unused invite is stored without the field.
        // No upsert: a missing invite matches nothing and stays missing.
        self.col::<AccountInvite>(COL)
            .update_one(
                doc! {
                    "_id": invite_id,
                    "used": { "$ne": true }
                },
                doc! {
                    "$set": {
                        "used": true,
                        "claimed_by": account_id
                    }
                },
            )
            .await
            .map(|result| result.modified_count > 0)
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Give an invite back, but only while it is claimed by `account_id`
    async fn release_account_invite_if_claimed_by(
        &self,
        invite_id: &str,
        account_id: &str,
    ) -> Result<bool> {
        // `$unset`, not `$set`: an unused invite is stored without either
        // field, and `save_account_invite` cannot remove a field
        self.col::<AccountInvite>(COL)
            .update_one(
                doc! {
                    "_id": invite_id,
                    "claimed_by": account_id
                },
                doc! {
                    "$unset": {
                        "used": "",
                        "claimed_by": ""
                    }
                },
            )
            .await
            .map(|result| result.modified_count > 0)
            .map_err(|_| create_database_error!("update_one", COL))
    }
}
