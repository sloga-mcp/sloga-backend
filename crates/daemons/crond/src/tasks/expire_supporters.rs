use std::time::Duration;

use log::{error, info};
use revolt_database::{Database, CLAIM_CODE_TTL_DAYS, DAY_MS, PAYER_HMAC_RETENTION_DAYS};
use revolt_models::v0::UserFlags;
use revolt_result::Result;
use tokio::time::sleep;

/// How often the sweep runs
const SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// How soon a failed sweep is tried again
const RETRY_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// How far back the first sweep after a start looks, so a subscription that
/// lapsed while crond was down still gets its update
const FIRST_WINDOW_MS: i64 = 2 * DAY_MS;

/// A monthly subscription lapses on its own: nothing is written when
/// `monthly_until` passes, so this sends the badge, name style and perk
/// update the lapse implies. It also drops the payer HMAC from unmatched
/// donations past their retention and deletes expired claim codes.
pub async fn task(db: Database, _: revolt_database::AMQP) -> Result<()> {
    let mut window_from = revolt_database::now_ms() - FIRST_WINDOW_MS;

    loop {
        let now = revolt_database::now_ms();

        match run_once(&db, window_from, now).await {
            Ok(_) => {
                // The lapse window is half-open, so the next one starting
                // where this one ended neither skips nor repeats a lapse
                window_from = now;
                sleep(SWEEP_INTERVAL).await;
            }
            Err(err) => {
                // Keep the window so the retry covers every lapse in it; an
                // update sent twice is harmless
                error!("Supporter expiry sweep failed, retrying in an hour: {err:?}");
                revolt_config::capture_error(&err);
                sleep(RETRY_INTERVAL).await;
            }
        }
    }
}

/// Send the perks update for every monthly supporter whose `monthly_until`
/// is in `[from_ms, now_ms)`, then run the donation retention sweeps.
/// Returns how many supporters were updated.
pub async fn run_once(db: &Database, from_ms: i64, now_ms: i64) -> Result<u32> {
    let users = db
        .fetch_users_monthly_until_between(from_ms, now_ms)
        .await?;

    let mut lapsed = 0;
    for user in users {
        if user.flags.unwrap_or_default() & UserFlags::Deleted as i32 != 0 {
            continue;
        }

        user.publish_perks_update(db).await;
        lapsed += 1;
    }

    if lapsed > 0 {
        info!("Sent perks updates for {lapsed} lapsed monthly supporter(s)");
    }

    let wiped = db
        .wipe_stale_payer_hmacs(now_ms - PAYER_HMAC_RETENTION_DAYS * DAY_MS)
        .await?;
    let expired = db
        .delete_expired_claim_codes(now_ms - CLAIM_CODE_TTL_DAYS * DAY_MS)
        .await?;

    if wiped > 0 || expired > 0 {
        info!("Wiped {wiped} stale payer HMAC(s) and deleted {expired} expired claim code(s)");
    }

    Ok(lapsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use revolt_database::{now_ms, Donation, DonationClaimCode, DonationState, Supporter, User};

    fn reference_db() -> Database {
        Database::Reference(Default::default())
    }

    // `insert_user` is disallowed in favor of `User::create()`, but these
    // tests need bare rows carrying a supporter record
    #[allow(clippy::disallowed_methods)]
    async fn insert_supporter(db: &Database, id: &str, monthly_until: i64, flags: Option<i32>) {
        db.insert_user(&User {
            id: id.to_string(),
            username: id.to_string(),
            discriminator: "0001".to_string(),
            flags,
            supporter: Some(Supporter {
                lifetime_usd_cents: 500,
                monthly_until: Some(monthly_until),
                payer_hmacs: vec![],
                show_badges: true,
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    }

    fn donation(id: &str, state: DonationState, timestamp: i64) -> Donation {
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
            stored_at: None,
            user: None,
            claimed_at: None,
            payer_hmac: Some(format!("hmac_{id}")),
            claimant: None,
            state,
        }
    }

    #[tokio::test]
    async fn lapse_inside_the_window_is_counted() {
        let db = reference_db();
        let now = now_ms();
        let from = now - 2 * DAY_MS;

        insert_supporter(&db, "inside", now - DAY_MS, None).await;
        insert_supporter(&db, "before", now - 3 * DAY_MS, None).await;
        insert_supporter(&db, "active", now + DAY_MS, None).await;
        insert_supporter(
            &db,
            "deleted",
            now - DAY_MS,
            Some(UserFlags::Deleted as i32),
        )
        .await;

        // The deleted account is in the window but gets no update
        assert_eq!(
            db.fetch_users_monthly_until_between(from, now)
                .await
                .unwrap()
                .len(),
            2
        );
        assert_eq!(run_once(&db, from, now).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn consecutive_windows_count_a_lapse_once() {
        let db = reference_db();
        let now = now_ms();
        let first = now - 2 * DAY_MS;
        let second = now - DAY_MS;

        // Exactly on the boundary between the two windows
        insert_supporter(&db, "boundary", second, None).await;
        insert_supporter(&db, "early", second - 1, None).await;
        insert_supporter(&db, "late", now - 1, None).await;

        assert_eq!(run_once(&db, first, second).await.unwrap(), 1);
        assert_eq!(run_once(&db, second, now).await.unwrap(), 2);
        assert_eq!(run_once(&db, now, now + DAY_MS).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn stale_payer_hmacs_and_expired_claim_codes_are_removed() {
        let db = reference_db();
        let now = now_ms();
        let stale = now - (PAYER_HMAC_RETENTION_DAYS + 1) * DAY_MS;

        for row in [
            donation("tx_stale", DonationState::Unclaimed, stale),
            donation("tx_review", DonationState::NeedsReview, stale),
            donation("tx_claimed", DonationState::Claimed, stale),
            donation("tx_fresh", DonationState::Unclaimed, now - DAY_MS),
        ] {
            assert!(db.insert_donation_if_absent(&row).await.unwrap());
        }

        for (code, created_at) in [
            ("KOFI-AAAAAA", now - (CLAIM_CODE_TTL_DAYS + 1) * DAY_MS),
            ("KOFI-BBBBBB", now),
        ] {
            db.insert_claim_code(&DonationClaimCode {
                code: code.to_string(),
                user: "owner".to_string(),
                created_at,
            })
            .await
            .unwrap();
        }

        assert_eq!(run_once(&db, now - 2 * DAY_MS, now).await.unwrap(), 0);

        let payer_hmac = |row: Option<Donation>| row.unwrap().payer_hmac;
        assert!(payer_hmac(db.fetch_donation("tx_stale").await.unwrap()).is_none());
        assert!(payer_hmac(db.fetch_donation("tx_review").await.unwrap()).is_none());
        // Only unmatched rows lose it, and only past the retention
        assert!(payer_hmac(db.fetch_donation("tx_claimed").await.unwrap()).is_some());
        assert!(payer_hmac(db.fetch_donation("tx_fresh").await.unwrap()).is_some());

        assert!(db.fetch_claim_code("KOFI-AAAAAA").await.unwrap().is_none());
        assert!(db.fetch_claim_code("KOFI-BBBBBB").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn payer_hmac_retention_counts_from_when_the_row_was_stored() {
        let db = reference_db();
        let now = now_ms();
        let paid = now - 400 * DAY_MS;

        // A backfill import stores old payments, which stay self-claimable
        // for the full retention after the import
        for (id, stored_at) in [
            ("tx_imported", now - DAY_MS),
            (
                "tx_imported_stale",
                now - (PAYER_HMAC_RETENTION_DAYS + 1) * DAY_MS,
            ),
        ] {
            let row = Donation {
                stored_at: Some(stored_at),
                ..donation(id, DonationState::Unclaimed, paid)
            };
            assert!(db.insert_donation_if_absent(&row).await.unwrap());
        }

        assert_eq!(run_once(&db, now - 2 * DAY_MS, now).await.unwrap(), 0);

        let payer_hmac = |row: Option<Donation>| row.unwrap().payer_hmac;
        assert!(payer_hmac(db.fetch_donation("tx_imported").await.unwrap()).is_some());
        assert!(payer_hmac(db.fetch_donation("tx_imported_stale").await.unwrap()).is_none());
    }
}
