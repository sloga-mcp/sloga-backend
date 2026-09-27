use revolt_result::Result;

use crate::ReferenceDb;
use crate::{Referral, ReferralCode, ReferralStatus};

use super::AbstractReferrals;

/// Status write shared by the unconditional and Pending-only updates
fn apply_status(referral: &mut Referral, status: ReferralStatus, qualified_at: Option<i64>) {
    if let Some(qualified_at) = qualified_at {
        referral.qualified_at = Some(qualified_at);
    }
    if status != ReferralStatus::Pending {
        referral.active_days.clear();
        referral.message_count = 0;
    }
    referral.status = status;
}

#[async_trait]
impl AbstractReferrals for ReferenceDb {
    async fn insert_referral_if_absent(&self, referral: &Referral) -> Result<bool> {
        let mut referrals = self.referrals.lock().await;
        if referrals.contains_key(&referral.id) {
            Ok(false)
        } else {
            referrals.insert(referral.id.clone(), referral.clone());
            Ok(true)
        }
    }

    async fn fetch_referral(&self, invitee_id: &str) -> Result<Option<Referral>> {
        let referrals = self.referrals.lock().await;
        Ok(referrals.get(invitee_id).cloned())
    }

    async fn fetch_pending_referrals(&self) -> Result<Vec<Referral>> {
        let referrals = self.referrals.lock().await;
        Ok(referrals
            .values()
            .filter(|r| r.status == ReferralStatus::Pending)
            .cloned()
            .collect())
    }

    async fn update_referral_status(
        &self,
        invitee_id: &str,
        status: ReferralStatus,
        qualified_at: Option<i64>,
    ) -> Result<()> {
        let mut referrals = self.referrals.lock().await;
        if let Some(referral) = referrals.get_mut(invitee_id) {
            apply_status(referral, status, qualified_at);
        }
        Ok(())
    }

    async fn update_referral_status_if_pending(
        &self,
        invitee_id: &str,
        status: ReferralStatus,
        qualified_at: Option<i64>,
    ) -> Result<bool> {
        // The lock is held across the check and the write
        let mut referrals = self.referrals.lock().await;
        match referrals.get_mut(invitee_id) {
            Some(referral) if referral.status == ReferralStatus::Pending => {
                apply_status(referral, status, qualified_at);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn record_referral_activity(
        &self,
        invitee_id: &str,
        day: u32,
        message_inc: i32,
        invite_creator: Option<&str>,
    ) -> Result<()> {
        let mut referrals = self.referrals.lock().await;
        if let Some(referral) = referrals.get_mut(invitee_id) {
            if referral.status != ReferralStatus::Pending {
                return Ok(());
            }
            if !referral.active_days.contains(&day) {
                referral.active_days.push(day);
            }
            referral.message_count = referral.message_count.saturating_add(message_inc);
            if invite_creator.is_some_and(|creator| creator != referral.referrer) {
                referral.joined_via_invite = true;
            }
        }
        Ok(())
    }

    async fn count_referrals_by_referrer(
        &self,
        referrer: &str,
        status: ReferralStatus,
    ) -> Result<u32> {
        let referrals = self.referrals.lock().await;
        Ok(referrals
            .values()
            .filter(|r| r.referrer == referrer && r.status == status)
            .count() as u32)
    }

    async fn count_referrals_qualified_since(&self, referrer: &str, since_ms: i64) -> Result<u32> {
        let referrals = self.referrals.lock().await;
        Ok(referrals
            .values()
            .filter(|r| {
                r.referrer == referrer
                    && r.status == ReferralStatus::Qualified
                    && r.qualified_at.is_some_and(|at| at >= since_ms)
            })
            .count() as u32)
    }

    async fn delete_referral(&self, invitee_id: &str) -> Result<()> {
        let mut referrals = self.referrals.lock().await;
        referrals.remove(invitee_id);
        Ok(())
    }

    async fn insert_referral_code(&self, code: &ReferralCode) -> Result<()> {
        // Mirrors the unique indexes on `_id` and `user`
        let mut codes = self.referral_codes.lock().await;
        if codes.contains_key(&code.code) || codes.values().any(|c| c.user == code.user) {
            Err(create_database_error!("insert", "referral_codes"))
        } else {
            codes.insert(code.code.clone(), code.clone());
            Ok(())
        }
    }

    async fn fetch_referral_code(&self, code: &str) -> Result<Option<ReferralCode>> {
        let codes = self.referral_codes.lock().await;
        Ok(codes.get(code).cloned())
    }

    async fn fetch_referral_code_by_user(&self, user_id: &str) -> Result<Option<ReferralCode>> {
        let codes = self.referral_codes.lock().await;
        Ok(codes.values().find(|c| c.user == user_id).cloned())
    }

    async fn delete_referral_codes_by_user(&self, user_id: &str) -> Result<()> {
        let mut codes = self.referral_codes.lock().await;
        codes.retain(|_, c| c.user != user_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Database, ReferenceDb, Referral, ReferralSource, ReferralStatus, DAY_MS};

    const DAY0: u32 = 20_000;

    /// Always the in-memory driver: these tests never touch MongoDB
    async fn db_with_pending(invitee: &str, referrer: &str) -> Database {
        let db = Database::Reference(ReferenceDb::default());
        let inserted = db
            .insert_referral_if_absent(&Referral {
                id: invitee.to_string(),
                referrer: referrer.to_string(),
                source: ReferralSource::Code,
                created_at: DAY0 as i64 * DAY_MS,
                status: ReferralStatus::Pending,
                qualified_at: None,
                active_days: Vec::new(),
                message_count: 0,
                joined_via_invite: false,
            })
            .await
            .unwrap();
        assert!(inserted);
        db
    }

    async fn fetch(db: &Database, invitee: &str) -> Referral {
        db.fetch_referral(invitee).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn activity_days_are_a_set() {
        let db = db_with_pending("invitee", "referrer").await;

        for day in [DAY0, DAY0, DAY0 + 1, DAY0, DAY0 + 1, DAY0 + 5] {
            db.record_referral_activity("invitee", day, 0, None)
                .await
                .unwrap();
        }

        let mut days = fetch(&db, "invitee").await.active_days;
        days.sort_unstable();
        assert_eq!(days, vec![DAY0, DAY0 + 1, DAY0 + 5]);
    }

    #[tokio::test]
    async fn activity_messages_accumulate() {
        let db = db_with_pending("invitee", "referrer").await;

        db.record_referral_activity("invitee", DAY0, 1, None)
            .await
            .unwrap();
        db.record_referral_activity("invitee", DAY0, 1, None)
            .await
            .unwrap();
        // An ack counts the day but no message
        db.record_referral_activity("invitee", DAY0 + 1, 0, None)
            .await
            .unwrap();
        db.record_referral_activity("invitee", DAY0 + 1, 1, None)
            .await
            .unwrap();

        let referral = fetch(&db, "invitee").await;
        assert_eq!(referral.message_count, 3);
        assert_eq!(referral.active_days.len(), 2);
    }

    #[tokio::test]
    async fn activity_leaves_non_pending_rows_alone() {
        for status in [
            ReferralStatus::Qualified,
            ReferralStatus::Expired,
            ReferralStatus::Revoked,
        ] {
            let db = db_with_pending("invitee", "referrer").await;
            db.record_referral_activity("invitee", DAY0, 1, None)
                .await
                .unwrap();
            db.update_referral_status("invitee", status.clone(), Some(1))
                .await
                .unwrap();
            let before = fetch(&db, "invitee").await;

            db.record_referral_activity("invitee", DAY0 + 3, 1, Some("stranger"))
                .await
                .unwrap();

            let after = fetch(&db, "invitee").await;
            assert_eq!(after, before, "status: {status:?}");
            assert!(after.active_days.is_empty(), "status: {status:?}");
            assert_eq!(after.message_count, 0, "status: {status:?}");
            assert!(!after.joined_via_invite, "status: {status:?}");
        }
    }

    #[tokio::test]
    async fn activity_on_a_missing_row_is_a_no_op() {
        let db = db_with_pending("invitee", "referrer").await;

        db.record_referral_activity("somebody_else", DAY0, 1, Some("stranger"))
            .await
            .unwrap();

        assert!(db.fetch_referral("somebody_else").await.unwrap().is_none());
        assert_eq!(fetch(&db, "invitee").await.message_count, 0);
    }

    #[tokio::test]
    async fn invite_from_the_referrer_does_not_count_as_a_join() {
        let db = db_with_pending("invitee", "referrer").await;

        db.record_referral_activity("invitee", DAY0, 0, Some("referrer"))
            .await
            .unwrap();
        let referral = fetch(&db, "invitee").await;
        assert!(!referral.joined_via_invite);
        // The join is still an active day
        assert_eq!(referral.active_days, vec![DAY0]);
    }

    #[tokio::test]
    async fn invite_from_someone_else_counts_as_a_join() {
        let db = db_with_pending("invitee", "referrer").await;

        db.record_referral_activity("invitee", DAY0, 0, Some("stranger"))
            .await
            .unwrap();
        assert!(fetch(&db, "invitee").await.joined_via_invite);

        // Sticky: a later invite from the referrer does not clear it
        db.record_referral_activity("invitee", DAY0 + 1, 0, Some("referrer"))
            .await
            .unwrap();
        assert!(fetch(&db, "invitee").await.joined_via_invite);
    }

    #[tokio::test]
    async fn status_if_pending_updates_a_pending_row() {
        let db = db_with_pending("invitee", "referrer").await;
        db.record_referral_activity("invitee", DAY0, 1, None)
            .await
            .unwrap();

        let updated = db
            .update_referral_status_if_pending("invitee", ReferralStatus::Qualified, Some(123))
            .await
            .unwrap();

        assert!(updated);
        let referral = fetch(&db, "invitee").await;
        assert_eq!(referral.status, ReferralStatus::Qualified);
        assert_eq!(referral.qualified_at, Some(123));
        assert!(referral.active_days.is_empty());
        assert_eq!(referral.message_count, 0);
    }

    #[tokio::test]
    async fn status_if_pending_leaves_a_revoked_row_alone() {
        let db = db_with_pending("invitee", "referrer").await;
        db.update_referral_status("invitee", ReferralStatus::Revoked, None)
            .await
            .unwrap();
        let before = fetch(&db, "invitee").await;

        let updated = db
            .update_referral_status_if_pending("invitee", ReferralStatus::Qualified, Some(123))
            .await
            .unwrap();

        assert!(!updated);
        let after = fetch(&db, "invitee").await;
        assert_eq!(after, before);
        assert_eq!(after.status, ReferralStatus::Revoked);
        assert_eq!(after.qualified_at, None);
    }

    #[tokio::test]
    async fn status_if_pending_on_a_missing_row_is_false() {
        let db = db_with_pending("invitee", "referrer").await;
        let before = fetch(&db, "invitee").await;

        let updated = db
            .update_referral_status_if_pending("somebody_else", ReferralStatus::Qualified, Some(1))
            .await
            .unwrap();

        assert!(!updated);
        assert!(db.fetch_referral("somebody_else").await.unwrap().is_none());
        assert_eq!(fetch(&db, "invitee").await, before);
    }
}
