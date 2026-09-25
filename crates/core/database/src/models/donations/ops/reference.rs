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
            // Retention runs from when the row was stored, so a backfilled
            // old payment keeps its HMAC for the full window; older rows
            // without `stored_at` fall back to the payment date
            if matches!(
                row.state,
                DonationState::Unclaimed | DonationState::NeedsReview
            ) && row
                .stored_at
                .map_or(row.timestamp < before_ms, |at| at < before_ms)
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

#[cfg(test)]
mod tests {
    use crate::{Database, Donation, DonationState, ReferenceDb, DAY_MS};

    const CUTOFF: i64 = 1_788_264_000_000;

    fn unclaimed(id: &str, timestamp: i64, stored_at: Option<i64>) -> Donation {
        Donation {
            id: id.to_string(),
            message_id: format!("msg_{id}"),
            kind: "Donation".to_string(),
            amount_cents: 1000,
            currency: "USD".to_string(),
            usd_cents_override: None,
            is_subscription: false,
            tier_name: None,
            timestamp,
            stored_at,
            user: None,
            claimed_at: None,
            payer_hmac: Some(format!("hmac_{id}")),
            claimant: None,
            state: DonationState::Unclaimed,
        }
    }

    async fn payer_hmac(db: &Database, id: &str) -> Option<String> {
        db.fetch_donation(id).await.unwrap().unwrap().payer_hmac
    }

    #[tokio::test]
    async fn stale_payer_hmacs_age_from_when_the_row_was_stored() {
        // Always the in-memory driver: this test never touches MongoDB
        let db = Database::Reference(ReferenceDb::default());
        for row in [
            // Imported long after the payment: still inside the window
            unclaimed("backfilled", CUTOFF - 400 * DAY_MS, Some(CUTOFF + DAY_MS)),
            // Stored before the cutoff: `stored_at` decides even though the
            // payment date is inside the window
            unclaimed("stored_early", CUTOFF + DAY_MS, Some(CUTOFF - DAY_MS)),
            // Rows without `stored_at` age from the payment date
            unclaimed("legacy_old", CUTOFF - DAY_MS, None),
            unclaimed("legacy_recent", CUTOFF + DAY_MS, None),
        ] {
            assert!(db.insert_donation_if_absent(&row).await.unwrap());
        }

        assert_eq!(db.wipe_stale_payer_hmacs(CUTOFF).await.unwrap(), 2);

        assert!(payer_hmac(&db, "backfilled").await.is_some());
        assert!(payer_hmac(&db, "stored_early").await.is_none());
        assert!(payer_hmac(&db, "legacy_old").await.is_none());
        assert!(payer_hmac(&db, "legacy_recent").await.is_some());
    }
}
