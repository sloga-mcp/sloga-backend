pub mod mongodb;
pub mod reference;

use revolt_result::Result;

use crate::{Donation, DonationClaimCode};

#[async_trait]
pub trait AbstractDonations: Sync + Send {
    /// Insert a donation unless a row with the same id OR the same
    /// message_id already exists; Ok(true) if it was inserted
    async fn insert_donation_if_absent(&self, d: &Donation) -> Result<bool>;

    /// Fetch a donation by its Ko-fi transaction id
    async fn fetch_donation(&self, id: &str) -> Result<Option<Donation>>;

    /// Fetch a donation by the Ko-fi webhook message id
    async fn fetch_donation_by_message_id(&self, message_id: &str) -> Result<Option<Donation>>;

    /// Replace a donation row in full
    async fn update_donation(&self, d: &Donation) -> Result<()>;

    /// Fetch every donation attributed to a user
    async fn fetch_donations_by_user(&self, user_id: &str) -> Result<Vec<Donation>>;

    /// Account-deletion cascade: rows owned by the user lose `user` and
    /// `payer_hmac`; rows where the user is only the claimant lose `claimant`
    async fn unlink_donations_by_user(&self, user_id: &str) -> Result<()>;

    /// Unset `payer_hmac` on Unclaimed and NeedsReview rows older than
    /// `before_ms`; returns how many rows were changed
    async fn wipe_stale_payer_hmacs(&self, before_ms: i64) -> Result<u64>;

    /// Insert a claim code (a duplicate code is an error)
    async fn insert_claim_code(&self, c: &DonationClaimCode) -> Result<()>;

    /// Fetch a claim code
    async fn fetch_claim_code(&self, code: &str) -> Result<Option<DonationClaimCode>>;

    /// Fetch a user's claim code, if they have one
    async fn fetch_claim_code_by_user(&self, user_id: &str) -> Result<Option<DonationClaimCode>>;

    /// Delete a claim code; NotFound if it no longer exists, so exactly one
    /// of two concurrent consumers succeeds
    async fn delete_claim_code(&self, code: &str) -> Result<()>;

    /// Account-deletion cascade: delete every claim code a user holds
    async fn delete_claim_codes_by_user(&self, user_id: &str) -> Result<()>;

    /// Delete claim codes created before `before_ms`; returns how many
    async fn delete_expired_claim_codes(&self, before_ms: i64) -> Result<u64>;
}
