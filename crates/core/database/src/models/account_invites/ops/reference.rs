use crate::{AbstractAccountInvites, AccountInvite, ReferenceDb};
use revolt_result::Result;

#[async_trait]
impl AbstractAccountInvites for ReferenceDb {
    /// Find invite by id
    async fn fetch_account_invite(&self, id: &str) -> Result<AccountInvite> {
        let invites = self.account_invites.lock().await;
        invites
            .get(id)
            .cloned()
            .ok_or_else(|| create_error!(InvalidInvite))
    }

    /// Save invite
    async fn save_account_invite(&self, invite: &AccountInvite) -> Result<()> {
        let mut invites = self.account_invites.lock().await;
        invites.insert(invite.id.to_string(), invite.clone());
        Ok(())
    }

    /// Use an invite up for `account_id`, but only while it is not used yet
    async fn claim_account_invite_if_unused(
        &self,
        invite_id: &str,
        account_id: &str,
    ) -> Result<bool> {
        let mut invites = self.account_invites.lock().await;
        match invites.get_mut(invite_id) {
            Some(invite) if !invite.used => {
                invite.used = true;
                invite.claimed_by = Some(account_id.to_string());
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Give an invite back, but only while it is claimed by `account_id`
    async fn release_account_invite_if_claimed_by(
        &self,
        invite_id: &str,
        account_id: &str,
    ) -> Result<bool> {
        let mut invites = self.account_invites.lock().await;
        match invites.get_mut(invite_id) {
            Some(invite) if invite.claimed_by.as_deref() == Some(account_id) => {
                invite.used = false;
                invite.claimed_by = None;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}
