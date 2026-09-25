use revolt_result::Result;

use crate::ReferenceDb;
use crate::{Donation, DonationClaimCode, DonationState};

use super::AbstractDonations;

/// Unit tests only: inserting a donation with this id fails, so the error
/// paths around the insert can be exercised
#[cfg(test)]
pub(crate) const FAILING_DONATION_ID: &str = "reference-insert-fails";

#[async_trait]
impl AbstractDonations for ReferenceDb {
    async fn insert_donation_if_absent(&self, d: &Donation) -> Result<bool> {
        #[cfg(test)]
        if d.id == FAILING_DONATION_ID {
            return Err(create_database_error!("insert", "donation"));
        }

        let mut donations = self.donations.lock().await;
        if donations.contains_key(&d.id)
            || donations.values().any(|row| row.message_id == d.message_id)
        {
            Ok(false)
        } else {
            donations.insert(d.id.clone(), d.clone());
            Ok(true)
        }
    }

    async fn fetch_donation(&self, id: &str) -> Result<Option<Donation>> {
        let donations = self.donations.lock().await;
        Ok(donations.get(id).cloned())
    }

    async fn fetch_donation_by_message_id(&self, message_id: &str) -> Result<Option<Donation>> {
        let donations = self.donations.lock().await;
        Ok(donations
            .values()
            .find(|row| row.message_id == message_id)
            .cloned())
    }

    async fn update_donation(&self, d: &Donation) -> Result<()> {
        let mut donations = self.donations.lock().await;
        match donations.get_mut(&d.id) {
            Some(row) => {
                *row = d.clone();
                Ok(())
            }
            None => Err(create_error!(NotFound)),
        }
    }

    async fn fetch_donations_by_user(&self, user_id: &str) -> Result<Vec<Donation>> {
        let donations = self.donations.lock().await;
        Ok(donations
            .values()
            .filter(|row| row.user.as_deref() == Some(user_id))
            .cloned()
            .collect())
    }

    async fn unlink_donations_by_user(&self, user_id: &str) -> Result<()> {
        let mut donations = self.donations.lock().await;
        for row in donations.values_mut() {
            if row.user.as_deref() == Some(user_id) {
                row.user = None;
                row.payer_hmac = None;
            }
            if row.claimant.as_deref() == Some(user_id) {
                row.claimant = None;
            }
        }
        Ok(())
    }

    async fn wipe_stale_payer_hmacs(&self, before_ms: i64) -> Result<u64> {
        let mut donations = self.donations.lock().await;
        let mut wiped = 0;
        for row in donations.values_mut() {
            if matches!(
                row.state,
                DonationState::Unclaimed | DonationState::NeedsReview
            ) && row.timestamp < before_ms
                && row.payer_hmac.is_some()
            {
                row.payer_hmac = None;
                wiped += 1;
            }
        }
        Ok(wiped)
    }

    async fn insert_claim_code(&self, c: &DonationClaimCode) -> Result<()> {
        let mut codes = self.donation_claim_codes.lock().await;
        if codes.contains_key(&c.code) {
            Err(create_database_error!("insert", "donation_claim_code"))
        } else {
            codes.insert(c.code.clone(), c.clone());
            Ok(())
        }
    }

    async fn fetch_claim_code(&self, code: &str) -> Result<Option<DonationClaimCode>> {
        let codes = self.donation_claim_codes.lock().await;
        Ok(codes.get(code).cloned())
    }

    async fn fetch_claim_code_by_user(&self, user_id: &str) -> Result<Option<DonationClaimCode>> {
        let codes = self.donation_claim_codes.lock().await;
        Ok(codes.values().find(|c| c.user == user_id).cloned())
    }

    async fn delete_claim_code(&self, code: &str) -> Result<()> {
        let mut codes = self.donation_claim_codes.lock().await;
        if codes.remove(code).is_some() {
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    async fn delete_claim_codes_by_user(&self, user_id: &str) -> Result<()> {
        let mut codes = self.donation_claim_codes.lock().await;
        codes.retain(|_, c| c.user != user_id);
        Ok(())
    }

    async fn delete_expired_claim_codes(&self, before_ms: i64) -> Result<u64> {
        let mut codes = self.donation_claim_codes.lock().await;
        let before = codes.len();
        codes.retain(|_, c| c.created_at >= before_ms);
        Ok((before - codes.len()) as u64)
    }
}
