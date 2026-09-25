pub mod mongodb;
pub mod reference;

use revolt_result::Result;

use crate::{Referral, ReferralCode, ReferralStatus};

#[async_trait]
pub trait AbstractReferrals: Sync + Send {
    /// Insert a referral unless the invitee already has one; Ok(true) if inserted
    async fn insert_referral_if_absent(&self, referral: &Referral) -> Result<bool>;

    /// Fetch the referral of an invitee
    async fn fetch_referral(&self, invitee_id: &str) -> Result<Option<Referral>>;

    /// Fetch every pending referral (qualification sweep)
    async fn fetch_pending_referrals(&self) -> Result<Vec<Referral>>;

    /// Move a referral to a new status, setting `qualified_at` when given.
    ///
    /// Also clears active_days/message_count when status != Pending.
    async fn update_referral_status(
        &self,
        invitee_id: &str,
        status: ReferralStatus,
        qualified_at: Option<i64>,
    ) -> Result<()>;

    /// Pending rows only. Adds `day` to active_days (set semantics), adds
    /// message_inc to message_count; if invite_creator is Some(c) and
    /// c != referrer, sets joined_via_invite = true.
    async fn record_referral_activity(
        &self,
        invitee_id: &str,
        day: u32,
        message_inc: i32,
        invite_creator: Option<&str>,
    ) -> Result<()>;

    /// Count a referrer's referrals in the given status
    async fn count_referrals_by_referrer(
        &self,
        referrer: &str,
        status: ReferralStatus,
    ) -> Result<u32>;

    /// Count a referrer's referrals that are still Qualified and qualified
    /// at or after `since_ms` (weekly cap)
    async fn count_referrals_qualified_since(&self, referrer: &str, since_ms: i64) -> Result<u32>;

    /// Delete an invitee's referral (no-op if absent)
    async fn delete_referral(&self, invitee_id: &str) -> Result<()>;

    /// Insert a referral code; a duplicate code or a second code for the
    /// same user is an error
    async fn insert_referral_code(&self, code: &ReferralCode) -> Result<()>;

    /// Fetch a referral code by its bare code
    async fn fetch_referral_code(&self, code: &str) -> Result<Option<ReferralCode>>;

    /// Fetch a user's referral code
    async fn fetch_referral_code_by_user(&self, user_id: &str) -> Result<Option<ReferralCode>>;

    /// Account-deletion cascade: delete a user's referral code
    async fn delete_referral_codes_by_user(&self, user_id: &str) -> Result<()>;
}
