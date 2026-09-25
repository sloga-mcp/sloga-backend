use std::collections::{HashMap, HashSet};
use std::time::Duration;

use log::{error, info, warn};
use revolt_database::{
    now_ms, Database, EmailVerification, FieldsUser, PartialUser, Referral, ReferralStatus,
    ReferralVerdict, User, AMQP, DAY_MS, TIER_CUSTOM_BADGE, WELCOME_TRIAL_DAYS,
};
use revolt_models::v0::UserFlags;
use revolt_result::{ErrorType, Result};
use tokio::time::sleep;

/// How often the sweep runs
const SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Ended trials announced by the first sweep after a restart
const FIRST_WINDOW_MS: i64 = 2 * 60 * 60 * 1000;

/// Age an account must reach before its flag can count as orphaned,
/// measured from the user id's ULID time, which is when the account signed
/// up rather than when it onboarded. Onboarding sets the flag and records
/// the referral milliseconds apart, so this shields users who onboard right
/// after signing up; a later onboarding is only exposed if the hourly sweep
/// lands inside those milliseconds.
const ORPHAN_GRACE_MS: i64 = 10 * 60 * 1000;

/// Rolling window of the per-referrer qualification cap
const CAP_WINDOW_MS: i64 = 7 * DAY_MS;

/// What one sweep changed
#[derive(Debug, Default)]
pub struct QualifySummary {
    pub qualified: u32,
    pub expired: u32,
    pub orphans_cleared: u32,
    pub trials_ended: u32,
}

impl QualifySummary {
    fn is_empty(&self) -> bool {
        self.qualified == 0
            && self.expired == 0
            && self.orphans_cleared == 0
            && self.trials_ended == 0
    }
}

/// State carried across the pending referrals of one sweep
#[derive(Default)]
struct Sweep {
    summary: QualifySummary,
    /// Referrer id -> whether the account exists and is not deleted
    referrer_live: HashMap<String, bool>,
    /// Referrer id -> qualifications inside the cap window before this sweep
    credited_before: HashMap<String, u32>,
    /// Referrer id -> qualifications made by this sweep
    qualified_this_sweep: HashMap<String, u32>,
    /// Referrers whose qualified count may have changed
    touched: HashSet<String>,
}

/// Hourly referral sweep.
///
/// Qualifies or expires pending referrals, recounts the referrers it
/// credited, clears stale `referral_pending` flags and announces welcome
/// trials that ended since the previous run.
pub async fn task(db: Database, _: AMQP) -> Result<()> {
    let mut window_from = now_ms() - FIRST_WINDOW_MS;

    loop {
        let now = now_ms();
        match run_once(&db, now, window_from).await {
            Ok(summary) => {
                window_from = now;

                if !summary.is_empty() {
                    info!(
                        "Referral sweep: {} qualified, {} expired, {} orphaned flag(s) cleared, {} trial(s) ended",
                        summary.qualified,
                        summary.expired,
                        summary.orphans_cleared,
                        summary.trials_ended
                    );
                }
            }
            Err(err) => {
                // Keep the window, so the next run still announces the
                // trials this one never reached
                error!("Referral sweep failed: {err:?}");
                revolt_config::capture_error(&err);
            }
        }

        sleep(SWEEP_INTERVAL).await; // run hourly
    }
}

/// One sweep at `now_ms`; trials that ended in `[window_from_ms, now_ms)`
/// are announced.
pub async fn run_once(db: &Database, now_ms: i64, window_from_ms: i64) -> Result<QualifySummary> {
    let mut sweep = Sweep::default();

    // 1. Pending referrals. One row's failure never stops the others.
    for referral in db.fetch_pending_referrals().await? {
        if let Err(err) = process_referral(db, &referral, now_ms, &mut sweep).await {
            warn!(
                "Failed to evaluate the referral of {}: {err:?}",
                referral.id
            );
            revolt_config::capture_error(&err);
        }
    }

    // 2. Recount every referrer credited above. The update emits the
    //    user events itself.
    for referrer in &sweep.touched {
        if let Err(err) = recount_referrer(db, referrer).await {
            warn!("Failed to recount the referrals of {referrer}: {err:?}");
            revolt_config::capture_error(&err);
        }
    }

    // 3. Flags whose referral is gone or already settled
    for mut user in db.fetch_users_with_referral_pending().await? {
        if !created_before(&user.id, now_ms - ORPHAN_GRACE_MS) {
            continue;
        }

        let referral = match db.fetch_referral(&user.id).await {
            Ok(Some(referral)) if referral.status == ReferralStatus::Pending => continue,
            Ok(referral) => referral,
            Err(err) => {
                warn!("Failed to fetch the referral of {}: {err:?}", user.id);
                continue;
            }
        };

        // A qualification whose welcome write failed still owes the trial
        let owed_welcome = referral
            .filter(|referral| referral.status == ReferralStatus::Qualified)
            .and_then(|referral| referral.qualified_at)
            .filter(|_| user.welcomed_at.is_none());

        let cleared = match owed_welcome {
            Some(qualified_at) => {
                user.update(
                    db,
                    PartialUser {
                        welcomed_at: Some(qualified_at),
                        ..Default::default()
                    },
                    vec![FieldsUser::ReferralPending],
                )
                .await
            }
            None => clear_pending(db, &user).await,
        };

        match cleared {
            Ok(()) => sweep.summary.orphans_cleared += 1,
            Err(err) => warn!("Failed to clear the referral flag of {}: {err:?}", user.id),
        }
    }

    // 4. Welcome trials that ended since the previous run lose their
    //    color without any write, so announce the computed values
    let trial_ms = WELCOME_TRIAL_DAYS * DAY_MS;
    for user in db
        .fetch_users_welcomed_between(window_from_ms - trial_ms, now_ms - trial_ms)
        .await?
    {
        if is_deleted(&user) {
            continue;
        }

        user.publish_perks_update(db).await;
        sweep.summary.trials_ended += 1;
    }

    Ok(sweep.summary)
}

/// Evaluate one pending referral and apply the verdict.
///
/// `referral` was read at the start of the sweep and may be stale, so every
/// write only lands while the stored row is still Pending; a row that
/// settled in the meantime (a staff revoke) is left exactly as it is.
async fn process_referral(
    db: &Database,
    referral: &Referral,
    now_ms: i64,
    sweep: &mut Sweep,
) -> Result<()> {
    let mut invitee = match db.fetch_user(&referral.id).await {
        Ok(user) => user,
        Err(err) if matches!(err.error_type, ErrorType::NotFound) => {
            if db
                .update_referral_status_if_pending(&referral.id, ReferralStatus::Expired, None)
                .await?
            {
                sweep.summary.expired += 1;
            }
            return Ok(());
        }
        Err(err) => return Err(err),
    };

    // A deleted referrer can never be credited
    if !referrer_is_live(db, &referral.referrer, sweep).await? {
        expire(db, &invitee, sweep).await?;
        return Ok(());
    }

    // A missing account (or a failed read) counts as unverified, which
    // only ever delays qualification
    let email_verified = db
        .fetch_account(&invitee.id)
        .await
        .map(|account| !matches!(account.verification, EmailVerification::Pending { .. }))
        .unwrap_or(false);

    // The weekly cap includes what this sweep has already credited
    let credited = credited_before(db, &referral.referrer, now_ms, sweep).await?
        + sweep
            .qualified_this_sweep
            .get(&referral.referrer)
            .copied()
            .unwrap_or(0);

    match referral.evaluate(&invitee, email_verified, now_ms, credited) {
        ReferralVerdict::Qualify => {
            if !db
                .update_referral_status_if_pending(
                    &referral.id,
                    ReferralStatus::Qualified,
                    Some(now_ms),
                )
                .await?
            {
                return Ok(());
            }

            sweep.summary.qualified += 1;
            *sweep
                .qualified_this_sweep
                .entry(referral.referrer.clone())
                .or_default() += 1;
            sweep.touched.insert(referral.referrer.clone());

            // If this fails the orphan pass grants the welcome later
            invitee
                .update(
                    db,
                    PartialUser {
                        welcomed_at: Some(now_ms),
                        ..Default::default()
                    },
                    vec![FieldsUser::ReferralPending],
                )
                .await?;
        }
        // There is no rejected status; a referral that can never qualify expires
        ReferralVerdict::Expire | ReferralVerdict::Reject => expire(db, &invitee, sweep).await?,
        ReferralVerdict::Wait => {}
    }

    Ok(())
}

/// Whether the referrer exists and is not deleted, fetched once per sweep
async fn referrer_is_live(db: &Database, referrer: &str, sweep: &mut Sweep) -> Result<bool> {
    if let Some(live) = sweep.referrer_live.get(referrer) {
        return Ok(*live);
    }

    let live = match db.fetch_user(referrer).await {
        Ok(user) => !is_deleted(&user),
        Err(err) if matches!(err.error_type, ErrorType::NotFound) => false,
        Err(err) => return Err(err),
    };

    sweep.referrer_live.insert(referrer.to_string(), live);
    Ok(live)
}

/// Qualifications credited to the referrer inside the cap window before
/// this sweep started.
///
/// Read once per referrer, before any of its referrals is qualified here,
/// so the sweep's own writes are only counted through `qualified_this_sweep`.
async fn credited_before(
    db: &Database,
    referrer: &str,
    now_ms: i64,
    sweep: &mut Sweep,
) -> Result<u32> {
    if let Some(count) = sweep.credited_before.get(referrer) {
        return Ok(*count);
    }

    let count = db
        .count_referrals_qualified_since(referrer, now_ms - CAP_WINDOW_MS)
        .await?;
    sweep.credited_before.insert(referrer.to_string(), count);
    Ok(count)
}

/// Expire the invitee's referral, if still pending, and stop tracking
/// their activity
async fn expire(db: &Database, invitee: &User, sweep: &mut Sweep) -> Result<()> {
    if !db
        .update_referral_status_if_pending(&invitee.id, ReferralStatus::Expired, None)
        .await?
    {
        return Ok(());
    }

    sweep.summary.expired += 1;
    clear_pending(db, invitee).await
}

/// Remove the activity-tracking flag.
///
/// Written directly: the flag is internal, so there is nothing to tell
/// any client.
async fn clear_pending(db: &Database, user: &User) -> Result<()> {
    if user.referral_pending.is_none() {
        return Ok(());
    }

    db.update_user(
        &user.id,
        &PartialUser::default(),
        vec![FieldsUser::ReferralPending],
    )
    .await
}

/// Store the referrer's qualified count if it changed
async fn recount_referrer(db: &Database, referrer_id: &str) -> Result<()> {
    let mut referrer = db.fetch_user(referrer_id).await?;
    if is_deleted(&referrer) {
        return Ok(());
    }

    let count = db
        .count_referrals_by_referrer(referrer_id, ReferralStatus::Qualified)
        .await?;
    let stored = i32::try_from(count).unwrap_or(i32::MAX);
    let before = referrer.referral_count;
    if before == Some(stored) {
        return Ok(());
    }

    referrer
        .update(
            db,
            PartialUser {
                referral_count: Some(stored),
                ..Default::default()
            },
            vec![],
        )
        .await?;

    // Staff reach out to design the badge
    let before = before.unwrap_or_default().max(0) as u32;
    if before < TIER_CUSTOM_BADGE && count >= TIER_CUSTOM_BADGE {
        info!(
            "AUDIT referral_milestone: user={} count={}",
            referrer_id, count
        );
    }

    Ok(())
}

fn is_deleted(user: &User) -> bool {
    user.flags.unwrap_or_default() & UserFlags::Deleted as i32 != 0
}

/// Whether the user id (a ULID, minted when the account signed up) was
/// minted before `cutoff_ms`; an id that is not a ULID never came from
/// signup and counts as old
fn created_before(user_id: &str, cutoff_ms: i64) -> bool {
    ulid::Ulid::from_string(user_id).map_or(true, |id| (id.timestamp_ms() as i64) < cutoff_ms)
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        day_index, Account, BotInformation, ReferenceDb, ReferralSource, QUALIFY_WEEKLY_CAP,
    };

    use super::*;

    const MINUTE_MS: i64 = 60 * 1000;
    const HOUR_MS: i64 = 60 * MINUTE_MS;

    /// Always the in-memory driver: these tests never touch MongoDB
    fn reference_db() -> Database {
        Database::Reference(ReferenceDb::default())
    }

    /// A ULID minted at `ms`
    fn id_at(ms: i64) -> String {
        ulid::Ulid::from_parts(ms as u64, ulid::Ulid::new().random()).to_string()
    }

    fn user(id: &str) -> User {
        User {
            id: id.to_string(),
            username: id.to_string(),
            discriminator: "0001".to_string(),
            ..Default::default()
        }
    }

    /// A tracked invitee
    fn invitee(id: &str) -> User {
        User {
            referral_pending: Some(true),
            ..user(id)
        }
    }

    // `insert_user` is disallowed in favor of `User::create`, which pulls
    // in username allocation these tests have no use for
    #[allow(clippy::disallowed_methods)]
    async fn insert_user(db: &Database, user: User) {
        db.insert_user(&user).await.unwrap();
    }

    async fn insert_account(db: &Database, id: &str, verified: bool) {
        let verification = if verified {
            EmailVerification::Verified
        } else {
            EmailVerification::Pending {
                token: "token".to_string(),
                expiry: Timestamp::now_utc(),
            }
        };

        db.save_account(&Account {
            id: id.to_string(),
            email: format!("{id}@example.com"),
            email_normalised: format!("{id}@example.com"),
            password: String::new(),
            disabled: false,
            verification,
            password_reset: None,
            deletion: None,
            lockout: None,
            mfa: Default::default(),
            google_id: None,
            apple_id: None,
        })
        .await
        .unwrap();
    }

    /// A pending referral recorded `age_days` ago
    fn pending(invitee: &str, referrer: &str, now: i64, age_days: i64) -> Referral {
        Referral {
            id: invitee.to_string(),
            referrer: referrer.to_string(),
            source: ReferralSource::Code,
            created_at: now - age_days * DAY_MS,
            status: ReferralStatus::Pending,
            qualified_at: None,
            active_days: Vec::new(),
            message_count: 0,
            joined_via_invite: false,
        }
    }

    /// A pending referral that meets every rule at `now`
    fn eligible(invitee: &str, referrer: &str, now: i64) -> Referral {
        let mut referral = pending(invitee, referrer, now, 10);
        let day0 = day_index(referral.created_at);
        referral.active_days = vec![day0, day0 + 2, day0 + 4, day0 + 8];
        referral.message_count = 10;
        referral
    }

    /// A verified, tracked invitee with an eligible referral
    async fn eligible_invitee(db: &Database, referrer: &str, now: i64) -> String {
        let id = ulid::Ulid::new().to_string();
        insert_user(db, invitee(&id)).await;
        insert_account(db, &id, true).await;
        db.insert_referral_if_absent(&eligible(&id, referrer, now))
            .await
            .unwrap();
        id
    }

    async fn status(db: &Database, invitee: &str) -> ReferralStatus {
        db.fetch_referral(invitee).await.unwrap().unwrap().status
    }

    /// How many of the invitees' referrals are in `expected`
    async fn count(db: &Database, invitees: &[String], expected: ReferralStatus) -> usize {
        let mut count = 0;
        for invitee in invitees {
            if status(db, invitee).await == expected {
                count += 1;
            }
        }
        count
    }

    #[tokio::test]
    async fn qualifies_and_recounts_the_referrer() {
        let db = reference_db();
        let now = now_ms();

        insert_user(&db, user("referrer")).await;
        let qualified = eligible_invitee(&db, "referrer", now).await;

        // Meets every rule but the email check
        let unverified = ulid::Ulid::new().to_string();
        insert_user(&db, invitee(&unverified)).await;
        insert_account(&db, &unverified, false).await;
        db.insert_referral_if_absent(&eligible(&unverified, "referrer", now))
            .await
            .unwrap();

        // No account at all
        let no_account = ulid::Ulid::new().to_string();
        insert_user(&db, invitee(&no_account)).await;
        db.insert_referral_if_absent(&eligible(&no_account, "referrer", now))
            .await
            .unwrap();

        let summary = run_once(&db, now, now - HOUR_MS).await.unwrap();
        assert_eq!(summary.qualified, 1);
        assert_eq!(summary.expired, 0);

        let referral = db.fetch_referral(&qualified).await.unwrap().unwrap();
        assert_eq!(referral.status, ReferralStatus::Qualified);
        assert_eq!(referral.qualified_at, Some(now));

        let welcomed = db.fetch_user(&qualified).await.unwrap();
        assert_eq!(welcomed.welcomed_at, Some(now));
        assert_eq!(welcomed.referral_pending, None);

        let referrer = db.fetch_user("referrer").await.unwrap();
        assert_eq!(referrer.referral_count, Some(1));

        // Unverified invitees keep waiting, still tracked
        for waiting in [&unverified, &no_account] {
            assert_eq!(status(&db, waiting).await, ReferralStatus::Pending);
            let user = db.fetch_user(waiting).await.unwrap();
            assert_eq!(user.referral_pending, Some(true));
            assert_eq!(user.welcomed_at, None);
        }

        // A second sweep changes nothing
        let again = run_once(&db, now + HOUR_MS, now).await.unwrap();
        assert_eq!(again.qualified, 0);
        assert_eq!(
            db.fetch_user("referrer").await.unwrap().referral_count,
            Some(1)
        );
    }

    #[tokio::test]
    async fn referrals_that_can_never_qualify_expire() {
        let db = reference_db();
        let now = now_ms();

        insert_user(&db, user("referrer")).await;
        insert_user(
            &db,
            User {
                flags: Some(UserFlags::Deleted as i32),
                ..user("deleted_referrer")
            },
        )
        .await;

        // Referrer deleted after the invitee signed up
        let of_deleted = eligible_invitee(&db, "deleted_referrer", now).await;
        // Referrer gone from the database
        let of_missing = eligible_invitee(&db, "missing_referrer", now).await;

        // Invitee gone from the database
        let missing = ulid::Ulid::new().to_string();
        db.insert_referral_if_absent(&eligible(&missing, "referrer", now))
            .await
            .unwrap();

        // A bot can never qualify (Reject)
        let bot = ulid::Ulid::new().to_string();
        insert_user(
            &db,
            User {
                bot: Some(BotInformation {
                    owner: "owner".to_string(),
                }),
                ..invitee(&bot)
            },
        )
        .await;
        insert_account(&db, &bot, true).await;
        db.insert_referral_if_absent(&eligible(&bot, "referrer", now))
            .await
            .unwrap();

        // Past the 60-day window (Expire)
        let stale = ulid::Ulid::new().to_string();
        insert_user(&db, invitee(&stale)).await;
        insert_account(&db, &stale, true).await;
        db.insert_referral_if_absent(&pending(&stale, "referrer", now, 61))
            .await
            .unwrap();

        let summary = run_once(&db, now, now - HOUR_MS).await.unwrap();
        assert_eq!(summary.qualified, 0);
        assert_eq!(summary.expired, 5);

        for id in [&of_deleted, &of_missing, &missing, &bot, &stale] {
            assert_eq!(status(&db, id).await, ReferralStatus::Expired, "{id}");
        }
        for id in [&of_deleted, &of_missing, &bot, &stale] {
            let user = db.fetch_user(id).await.unwrap();
            assert_eq!(user.referral_pending, None, "{id}");
            assert_eq!(user.welcomed_at, None, "{id}");
        }

        for referrer in ["referrer", "deleted_referrer"] {
            assert_eq!(db.fetch_user(referrer).await.unwrap().referral_count, None);
        }
    }

    #[tokio::test]
    async fn weekly_cap_counts_this_sweep() {
        let db = reference_db();
        let now = now_ms();

        // A referrer with a clean week
        insert_user(&db, user("fresh")).await;
        let mut fresh = Vec::new();
        for _ in 0..12 {
            fresh.push(eligible_invitee(&db, "fresh", now).await);
        }

        // A referrer already credited 3 times this week, and once more
        // long enough ago to fall outside the window
        insert_user(&db, user("busy")).await;
        for qualified_at in [
            now - DAY_MS,
            now - 2 * DAY_MS,
            now - 6 * DAY_MS,
            now - 8 * DAY_MS,
        ] {
            let mut earlier = pending(&ulid::Ulid::new().to_string(), "busy", now, 20);
            earlier.status = ReferralStatus::Qualified;
            earlier.qualified_at = Some(qualified_at);
            db.insert_referral_if_absent(&earlier).await.unwrap();
        }
        let mut busy = Vec::new();
        for _ in 0..12 {
            busy.push(eligible_invitee(&db, "busy", now).await);
        }

        let summary = run_once(&db, now, now - HOUR_MS).await.unwrap();
        assert_eq!(summary.qualified, 10 + 7);

        assert_eq!(QUALIFY_WEEKLY_CAP, 10);
        assert_eq!(count(&db, &fresh, ReferralStatus::Qualified).await, 10);
        assert_eq!(count(&db, &fresh, ReferralStatus::Pending).await, 2);
        assert_eq!(count(&db, &busy, ReferralStatus::Qualified).await, 7);
        assert_eq!(count(&db, &busy, ReferralStatus::Pending).await, 5);

        assert_eq!(
            db.fetch_user("fresh").await.unwrap().referral_count,
            Some(10)
        );
        assert_eq!(
            db.fetch_user("busy").await.unwrap().referral_count,
            Some(11)
        );

        // Over-cap referrals stay tracked and qualify once the window moves
        for id in fresh.iter().chain(&busy) {
            let user = db.fetch_user(id).await.unwrap();
            let pending = status(&db, id).await == ReferralStatus::Pending;
            assert_eq!(user.referral_pending, pending.then_some(true), "{id}");
        }
    }

    #[tokio::test]
    async fn orphaned_flags_are_cleared_after_the_grace_period() {
        let db = reference_db();
        let now = now_ms();

        insert_user(&db, user("referrer")).await;

        // No referral at all
        let orphan = id_at(now - 11 * MINUTE_MS);
        insert_user(&db, invitee(&orphan)).await;

        // Referral already settled
        let settled = id_at(now - DAY_MS);
        insert_user(&db, invitee(&settled)).await;
        let mut referral = pending(&settled, "referrer", now, 30);
        referral.status = ReferralStatus::Expired;
        db.insert_referral_if_absent(&referral).await.unwrap();

        // Onboarding may still be about to record this one
        let fresh = id_at(now - MINUTE_MS);
        insert_user(&db, invitee(&fresh)).await;

        // Still pending, so still tracked
        let waiting = id_at(now - DAY_MS);
        insert_user(&db, invitee(&waiting)).await;
        insert_account(&db, &waiting, true).await;
        db.insert_referral_if_absent(&pending(&waiting, "referrer", now, 1))
            .await
            .unwrap();

        let summary = run_once(&db, now, now - HOUR_MS).await.unwrap();
        assert_eq!(summary.orphans_cleared, 2);

        for id in [&orphan, &settled] {
            assert_eq!(
                db.fetch_user(id).await.unwrap().referral_pending,
                None,
                "{id}"
            );
        }
        for id in [&fresh, &waiting] {
            assert_eq!(
                db.fetch_user(id).await.unwrap().referral_pending,
                Some(true),
                "{id}"
            );
        }
        assert_eq!(status(&db, &waiting).await, ReferralStatus::Pending);
    }

    /// Store `referral` as Revoked and return the Pending copy a sweep
    /// loaded before the revoke landed
    async fn revoked_after_load(db: &Database, referral: Referral) -> Referral {
        db.insert_referral_if_absent(&Referral {
            status: ReferralStatus::Revoked,
            ..referral.clone()
        })
        .await
        .unwrap();
        referral
    }

    #[tokio::test]
    async fn a_revoke_during_the_sweep_is_never_overwritten() {
        let db = reference_db();
        let now = now_ms();

        insert_user(&db, user("referrer")).await;
        insert_user(
            &db,
            User {
                flags: Some(UserFlags::Deleted as i32),
                ..user("deleted_referrer")
            },
        )
        .await;

        // Would qualify
        let qualifying = ulid::Ulid::new().to_string();
        insert_user(&db, invitee(&qualifying)).await;
        insert_account(&db, &qualifying, true).await;
        let stale_qualifying =
            revoked_after_load(&db, eligible(&qualifying, "referrer", now)).await;

        // Would expire: past the 60-day window
        let lapsed = ulid::Ulid::new().to_string();
        insert_user(&db, invitee(&lapsed)).await;
        insert_account(&db, &lapsed, true).await;
        let stale_lapsed = revoked_after_load(&db, pending(&lapsed, "referrer", now, 61)).await;

        // Would expire: the referrer is deleted
        let of_deleted = ulid::Ulid::new().to_string();
        insert_user(&db, invitee(&of_deleted)).await;
        insert_account(&db, &of_deleted, true).await;
        let stale_of_deleted =
            revoked_after_load(&db, eligible(&of_deleted, "deleted_referrer", now)).await;

        // Would expire: the invitee is gone
        let missing = ulid::Ulid::new().to_string();
        let stale_missing = revoked_after_load(&db, eligible(&missing, "referrer", now)).await;

        // The same steps `run_once` takes, fed the stale copies
        let mut sweep = Sweep::default();
        for referral in [
            &stale_qualifying,
            &stale_lapsed,
            &stale_of_deleted,
            &stale_missing,
        ] {
            process_referral(&db, referral, now, &mut sweep)
                .await
                .unwrap();
        }
        for referrer in &sweep.touched {
            recount_referrer(&db, referrer).await.unwrap();
        }

        assert_eq!(sweep.summary.qualified, 0);
        assert_eq!(sweep.summary.expired, 0);
        assert!(sweep.qualified_this_sweep.is_empty());
        assert!(sweep.touched.is_empty());

        for id in [&qualifying, &lapsed, &of_deleted, &missing] {
            let referral = db.fetch_referral(id).await.unwrap().unwrap();
            assert_eq!(referral.status, ReferralStatus::Revoked, "{id}");
            assert_eq!(referral.qualified_at, None, "{id}");
        }

        // No trial, and not even the flag is written; the orphan pass
        // owns that
        for id in [&qualifying, &lapsed, &of_deleted] {
            let user = db.fetch_user(id).await.unwrap();
            assert_eq!(user.welcomed_at, None, "{id}");
            assert_eq!(user.referral_pending, Some(true), "{id}");
        }

        assert_eq!(
            db.fetch_user("referrer").await.unwrap().referral_count,
            None
        );
    }

    #[tokio::test]
    async fn orphan_pass_grants_a_lost_welcome() {
        let db = reference_db();
        let now = now_ms();
        let qualified_at = now - 2 * HOUR_MS;

        insert_user(&db, user("referrer")).await;

        let qualified = |id: &str| {
            let mut referral = pending(id, "referrer", now, 20);
            referral.status = ReferralStatus::Qualified;
            referral.qualified_at = Some(qualified_at);
            referral
        };

        // Qualified, but the welcome write never landed
        let unwelcomed = id_at(now - 20 * DAY_MS);
        insert_user(&db, invitee(&unwelcomed)).await;
        db.insert_referral_if_absent(&qualified(&unwelcomed))
            .await
            .unwrap();

        // Qualified and welcomed, with only the flag left behind
        let welcomed = id_at(now - 20 * DAY_MS);
        insert_user(
            &db,
            User {
                welcomed_at: Some(now - HOUR_MS),
                ..invitee(&welcomed)
            },
        )
        .await;
        db.insert_referral_if_absent(&qualified(&welcomed))
            .await
            .unwrap();

        let summary = run_once(&db, now, now - HOUR_MS).await.unwrap();
        assert_eq!(summary.orphans_cleared, 2);

        let user = db.fetch_user(&unwelcomed).await.unwrap();
        assert_eq!(user.welcomed_at, Some(qualified_at));
        assert_eq!(user.referral_pending, None);

        let user = db.fetch_user(&welcomed).await.unwrap();
        assert_eq!(user.welcomed_at, Some(now - HOUR_MS));
        assert_eq!(user.referral_pending, None);
    }

    #[tokio::test]
    async fn ended_trials_are_announced_once() {
        let db = reference_db();
        let now = now_ms();
        let trial = WELCOME_TRIAL_DAYS * DAY_MS;

        let welcomed = |id: &str, at: i64| User {
            welcomed_at: Some(at),
            ..user(id)
        };

        // Ended an hour ago, inside the 2 h window
        insert_user(&db, welcomed("ended", now - trial - HOUR_MS)).await;
        // Ended before the window
        insert_user(&db, welcomed("earlier", now - trial - 3 * HOUR_MS)).await;
        // Still running
        insert_user(&db, welcomed("running", now - DAY_MS)).await;
        // Deleted accounts hold no perks to lose
        insert_user(
            &db,
            User {
                flags: Some(UserFlags::Deleted as i32),
                ..welcomed("deleted", now - trial - HOUR_MS)
            },
        )
        .await;

        let summary = run_once(&db, now, now - 2 * HOUR_MS).await.unwrap();
        assert_eq!(summary.trials_ended, 1);

        // The next run's window starts where this one stopped
        let next = run_once(&db, now + HOUR_MS, now).await.unwrap();
        assert_eq!(next.trials_ended, 0);
    }

    #[test]
    fn ulid_age() {
        let now = now_ms();
        assert!(created_before(
            &id_at(now - 11 * MINUTE_MS),
            now - ORPHAN_GRACE_MS
        ));
        assert!(!created_before(
            &id_at(now - 9 * MINUTE_MS),
            now - ORPHAN_GRACE_MS
        ));
        assert!(created_before("not-a-ulid", now - ORPHAN_GRACE_MS));
    }
}
