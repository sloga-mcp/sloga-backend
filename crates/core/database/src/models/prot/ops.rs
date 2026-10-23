pub mod mongodb;
pub mod reference;

use std::future::Future;

use revolt_models::v0;
use revolt_result::Result;

use crate::{
    cipher_prot_grant_count, cipher_prot_posted, cipher_prot_target, is_prot_system_account,
    prot_key_cipher_founding, prot_key_cipher_upgrade, prot_key_clawback, prot_key_forfeit,
    prot_user_account, CipherMembership, CipherProtSync, ProtAccount, ProtAmount, ProtApplyOutcome,
    ProtLedgerEntry, ProtPosting, ProtRef, PROT_ACTOR_CIPHER, PROT_ACTOR_DELETION,
    PROT_ACTOR_PAYMENTS, PROT_SYS_CLAWED, PROT_SYS_FORFEITED, PROT_SYS_ISSUED,
};

/// Append-only Prot ledger: inserts and reads only. No method updates or
/// deletes a ledger row.
#[async_trait]
pub trait AbstractProtLedger: Sync + Send {
    /// Apply one posting atomically: insert the ledger row, move the debit side
    /// (conditional on its floor), upsert the credit side. A duplicate key with the
    /// same payload hash is AlreadyApplied; with another payload, ProtIdempotencyConflict.
    /// Exact that the debit can't cover: InsufficientProt { needed, available }.
    async fn apply_prot_posting(&self, posting: &ProtPosting) -> Result<ProtApplyOutcome>;

    async fn fetch_prot_account(&self, account_id: &str) -> Result<Option<ProtAccount>>;

    async fn fetch_prot_entry_by_key(&self, key: &str) -> Result<Option<ProtLedgerEntry>>;

    /// Rows with debit == account OR credit == account, newest first (`_id` descending),
    /// only rows with `_id < before_id` when given; `limit` clamped to 1..=100
    async fn fetch_prot_entries_by_account(
        &self,
        account_id: &str,
        before_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ProtLedgerEntry>>;

    /// Rows with ref.order_id == order_id, oldest first
    async fn fetch_prot_entries_by_order(&self, order_id: &str) -> Result<Vec<ProtLedgerEntry>>;

    /// Rows with ref.membership_order_id == base_order_id, oldest first
    async fn fetch_prot_entries_by_membership(
        &self,
        base_order_id: &str,
    ) -> Result<Vec<ProtLedgerEntry>>;

    /// Sum of `amount` of rows with credit == account, kind in `kinds`, created_at >= since
    /// (D17 held figure: kinds = [Purchase])
    async fn sum_prot_credits_since(
        &self,
        account_id: &str,
        kinds: &[v0::ProtEntryKind],
        since: i64,
    ) -> Result<i64>;

    /// Cipher upward sync for one user, ONE transaction
    async fn sync_cipher_prot(&self, user_id: &str, now: i64) -> Result<CipherProtSync>;

    /// Cipher downward sync after a reversal of `order_id`, ONE transaction.
    /// Ok(None): nothing to claw back and no row for this order.
    async fn clawback_cipher_prot(
        &self,
        user_id: &str,
        order_id: &str,
        now: i64,
    ) -> Result<Option<ProtApplyOutcome>>;

    /// Account deletion: move the whole wallet to sys:forfeited, ONE transaction per pass.
    /// Key forfeit:{user_id}:{n}, n = 1 + number of Forfeit rows already debiting
    /// user:{user_id}, counted inside the transaction. Ok(None) when the wallet is
    /// absent or 0 (checked first, outside any transaction). After an AlreadyApplied
    /// pass (a racing pass took key n), re-read the balance outside any transaction:
    /// still > 0 -> run the next pass (n recounted, so n + 1), at most PROT_STATE_RETRIES
    /// passes in all, then Err(InternalError) logged as `PROT_FORFEIT_UNSETTLED`.
    /// Returns the last pass's outcome.
    async fn forfeit_prot_wallet(
        &self,
        user_id: &str,
        now: i64,
    ) -> Result<Option<ProtApplyOutcome>>;
}

/// Bound on re-running a Cipher sync or clawback whose state moved under it,
/// and on forfeit passes. Shared by both drivers.
const PROT_STATE_RETRIES: usize = 5;

/// Longest key accepted, in bytes
const PROT_KEY_MAX_BYTES: usize = 255;

/// A refused posting is a programming error, never a user error: log the key
/// and refuse it with InternalError
fn invalid_posting(posting: &ProtPosting, why: &str) -> revolt_result::Error {
    log::error!(
        "PROT_POSTING_INVALID key={:?} kind={} debit={:?} credit={:?}: {why}",
        posting.key,
        posting.kind.as_str(),
        posting.debit,
        posting.credit
    );
    create_error!(InternalError)
}

/// Whether an account id names a side a posting may use: `sys:*` or a
/// `user:` / `tank:` / `hold:` account, with something after the prefix
fn is_valid_prot_side(id: &str) -> bool {
    ["sys:", "user:", "tank:", "hold:"]
        .iter()
        .any(|prefix| id.strip_prefix(prefix).is_some_and(|rest| !rest.is_empty()))
}

/// Checks `apply_prot_posting` runs before anything else, identical in both
/// drivers (R10: a zero-amount row can only ever be one of five kinds)
fn validate_prot_posting(posting: &ProtPosting) -> Result<()> {
    if posting.key.is_empty() || posting.key.len() > PROT_KEY_MAX_BYTES {
        return Err(invalid_posting(posting, "key must be 1..=255 bytes"));
    }
    if posting.key.contains('\n') {
        return Err(invalid_posting(posting, "key contains a newline"));
    }
    if posting.debit == posting.credit {
        return Err(invalid_posting(
            posting,
            "debit and credit are the same account",
        ));
    }
    if !is_valid_prot_side(&posting.debit) || !is_valid_prot_side(&posting.credit) {
        return Err(invalid_posting(posting, "unknown account prefix"));
    }

    // The payload hash joins these with newlines; one inside a value could
    // make two different payloads hash alike
    let r = &posting.reference;
    let hashed = [
        Some(posting.debit.as_str()),
        Some(posting.credit.as_str()),
        r.order_id.as_deref(),
        r.tank_id.as_deref(),
        r.goal_id.as_deref(),
        r.pledge_id.as_deref(),
        r.day.as_deref(),
        r.membership_order_id.as_deref(),
    ];
    if hashed.iter().flatten().any(|value| value.contains('\n')) {
        return Err(invalid_posting(
            posting,
            "a hashed field contains a newline",
        ));
    }

    match posting.amount {
        ProtAmount::Exact(n) => {
            if n <= 0 {
                return Err(invalid_posting(posting, "Exact needs n > 0"));
            }
        }
        ProtAmount::UpTo(n) => {
            if n <= 0 {
                return Err(invalid_posting(posting, "UpTo needs n > 0"));
            }
            if !matches!(
                posting.kind,
                v0::ProtEntryKind::Clawback | v0::ProtEntryKind::ClawbackHold
            ) {
                return Err(invalid_posting(posting, "UpTo is for clawbacks only"));
            }
        }
        ProtAmount::All => {
            if !matches!(
                posting.kind,
                v0::ProtEntryKind::Forfeit
                    | v0::ProtEntryKind::ForfeitHold
                    | v0::ProtEntryKind::ForfeitTank
            ) {
                return Err(invalid_posting(posting, "All is for forfeits only"));
            }
        }
    }

    // A system side has no balance, so "up to what it holds" means nothing
    if !matches!(posting.amount, ProtAmount::Exact(_)) && is_prot_system_account(&posting.debit) {
        return Err(invalid_posting(
            posting,
            "UpTo and All need an account debit",
        ));
    }

    Ok(())
}

/// What a posting moves, decided from the debit side's balance
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProtResolved {
    amount: i64,
    requested: Option<i64>,
    shortfall: Option<i64>,
    /// What the debit side holds above its floor (0 for a system debit, which has no limit)
    available: i64,
    /// Lowest balance the debit side needs for this amount (`debit_floor + amount`)
    required: i64,
}

/// Section 4.2 steps 1-2 for a validated posting. `debit_balance` is the debit
/// account's balance (0 when it has no document); ignored for a system debit.
fn resolve_prot_amount(posting: &ProtPosting, debit_balance: i64) -> Result<ProtResolved> {
    let system = is_prot_system_account(&posting.debit);
    let available = if system {
        0
    } else {
        debit_balance.saturating_sub(posting.debit_floor).max(0)
    };

    let (amount, requested, shortfall) = match posting.amount {
        ProtAmount::Exact(n) => {
            if !system && n > available {
                return Err(create_error!(InsufficientProt {
                    needed: n,
                    available
                }));
            }
            (n, None, None)
        }
        ProtAmount::UpTo(n) => {
            let amount = n.min(available);
            (amount, Some(n), Some(n - amount))
        }
        ProtAmount::All => (available, None, None),
    };

    let required = posting
        .debit_floor
        .checked_add(amount)
        .ok_or_else(|| invalid_posting(posting, "debit floor + amount overflows"))?;

    Ok(ProtResolved {
        amount,
        requested,
        shortfall,
        available,
        required,
    })
}

/// The row a posting writes (section 4.2 step 3)
fn build_prot_entry(
    posting: &ProtPosting,
    resolved: &ProtResolved,
    payload_hash: &str,
) -> ProtLedgerEntry {
    ProtLedgerEntry {
        id: ulid::Ulid::new().to_string(),
        key: posting.key.clone(),
        kind: posting.kind,
        currency: v0::ProtCurrency::Prot,
        debit: posting.debit.clone(),
        credit: posting.credit.clone(),
        amount: resolved.amount,
        requested: resolved.requested,
        shortfall: resolved.shortfall,
        actor: posting.actor.clone(),
        reference: posting.reference.clone(),
        payload_hash: payload_hash.to_string(),
        reason: posting.reason.clone(),
        created_at: posting.created_at,
    }
}

/// A duplicate key, read back outside the transaction (section 4.2 step 5)
fn duplicate_outcome(
    key: &str,
    payload_hash: &str,
    stored: Option<ProtLedgerEntry>,
) -> Result<ProtApplyOutcome> {
    match stored {
        Some(stored) if stored.payload_hash == payload_hash => {
            Ok(ProtApplyOutcome::AlreadyApplied(stored))
        }
        Some(_) => {
            log::warn!("PROT_IDEMPOTENCY_CONFLICT key={key:?}");
            Err(create_error!(ProtIdempotencyConflict))
        }
        // The insert reported the key as taken, yet no row has it
        None => {
            log::error!("PROT_DUPLICATE_KEY_WITHOUT_ROW key={key:?}");
            Err(create_database_error!("find_one", "prot_ledger"))
        }
    }
}

/// A Cipher sync or clawback whose state kept moving under it
fn state_retries_exhausted(
    operation: &str,
    user_id: &str,
    last_error: Option<revolt_result::Error>,
) -> revolt_result::Error {
    log::error!(
        "PROT_STATE_RETRIES_EXHAUSTED op={operation} user={user_id} retries={PROT_STATE_RETRIES}"
    );
    last_error.unwrap_or_else(|| create_database_error!("transaction", "prot_ledger"))
}

/// Base order of a membership's current incarnation (`orders[0]`); None,
/// logged, when `orders` is empty
fn cipher_base<'a>(user_id: &str, m: &'a CipherMembership) -> Option<&'a str> {
    let base = m.orders.first().map(String::as_str);
    if base.is_none() {
        log::warn!("PROT_CIPHER_NO_ORDERS user={user_id}");
    }
    base
}

/// Whether a reversed order belongs to an incarnation older than the current
/// one (ULIDs compare in time order). That incarnation's Prot was settled when
/// it was revoked; the current one never pays for it. Logged.
fn is_older_incarnation(user_id: &str, order_id: &str, base: &str) -> bool {
    let older = order_id < base;
    if older {
        log::warn!("PROT_CLAWBACK_OLD_INCARNATION order={order_id} user={user_id}");
    }
    older
}

/// What an upward Cipher sync does with one read of the membership and its rows
#[derive(Debug, Clone, PartialEq, Eq)]
enum CipherSyncPlan {
    Done(CipherProtSync),
    Post(ProtPosting),
}

/// Section 6.1 steps 2-5 for a membership with a base order
fn plan_cipher_sync(
    user_id: &str,
    m: &CipherMembership,
    base: &str,
    rows: &[ProtLedgerEntry],
    now: i64,
) -> CipherSyncPlan {
    let posted = cipher_prot_posted(rows);
    let target = cipher_prot_target(m);

    // No upward posting while inactive or while a dispute is listed (the
    // hourly sweep picks it up once the dispute is won)
    if !m.is_active() || !m.disputed_orders.is_empty() || posted >= target {
        return CipherSyncPlan::Done(if posted > target {
            CipherProtSync::OverPosted { posted, target }
        } else {
            CipherProtSync::Nothing
        });
    }

    let seq = cipher_prot_grant_count(rows);
    let (kind, key) = if seq == 0 {
        (
            v0::ProtEntryKind::CipherFounding,
            prot_key_cipher_founding(user_id, m.number, base),
        )
    } else {
        (
            v0::ProtEntryKind::CipherUpgrade,
            prot_key_cipher_upgrade(user_id, m.number, base, seq),
        )
    };

    CipherSyncPlan::Post(ProtPosting {
        key,
        kind,
        debit: PROT_SYS_ISSUED.to_string(),
        credit: prot_user_account(user_id),
        amount: ProtAmount::Exact(target - posted),
        debit_floor: 0,
        actor: PROT_ACTOR_CIPHER.to_string(),
        reference: ProtRef {
            order_id: m.orders.last().cloned(),
            membership_number: Some(m.number),
            membership_order_id: Some(base.to_string()),
            ..Default::default()
        },
        reason: None,
        created_at: now,
    })
}

/// Section 6.2 steps 1-2: the clawback posting, or None when nothing is
/// posted above the target. The caller has already run the incarnation check.
fn plan_cipher_clawback(
    user_id: &str,
    order_id: &str,
    m: &CipherMembership,
    base: &str,
    rows: &[ProtLedgerEntry],
    now: i64,
) -> Option<ProtPosting> {
    let posted = cipher_prot_posted(rows);
    let target = cipher_prot_target(m);
    if posted <= target {
        return None;
    }

    Some(ProtPosting {
        key: prot_key_clawback(order_id),
        kind: v0::ProtEntryKind::Clawback,
        debit: prot_user_account(user_id),
        credit: PROT_SYS_CLAWED.to_string(),
        amount: ProtAmount::UpTo(posted - target),
        debit_floor: 0,
        actor: PROT_ACTOR_PAYMENTS.to_string(),
        reference: ProtRef {
            order_id: Some(order_id.to_string()),
            membership_number: Some(m.number),
            membership_order_id: Some(base.to_string()),
            ..Default::default()
        },
        reason: None,
        created_at: now,
    })
}

/// Forfeit pass `n` (1-based) of a user's wallet
fn forfeit_posting(user_id: &str, n: u64, now: i64) -> ProtPosting {
    ProtPosting {
        key: prot_key_forfeit(user_id, n),
        kind: v0::ProtEntryKind::Forfeit,
        debit: prot_user_account(user_id),
        credit: PROT_SYS_FORFEITED.to_string(),
        amount: ProtAmount::All,
        debit_floor: 0,
        actor: PROT_ACTOR_DELETION.to_string(),
        reference: ProtRef::default(),
        reason: None,
        created_at: now,
    }
}

/// The forfeit pass loop of `forfeit_prot_wallet`, shared by both drivers.
/// `balance` reads the wallet balance outside any transaction (0 when absent);
/// `pass` runs one forfeit pass in its own transaction.
async fn run_forfeit_passes<P, PF, B, BF>(
    user_id: &str,
    mut pass: P,
    mut balance: B,
) -> Result<Option<ProtApplyOutcome>>
where
    P: FnMut() -> PF,
    PF: Future<Output = Result<ProtApplyOutcome>>,
    B: FnMut() -> BF,
    BF: Future<Output = Result<i64>>,
{
    // An absent or empty wallet never opens a transaction
    if balance().await? <= 0 {
        return Ok(None);
    }

    for _ in 0..PROT_STATE_RETRIES {
        let outcome = pass().await?;
        match outcome {
            ProtApplyOutcome::Applied(_) => return Ok(Some(outcome)),
            // A racing pass took this key: if Prot reached the wallet after
            // it, the next pass (n recounted) moves it
            ProtApplyOutcome::AlreadyApplied(_) => {
                if balance().await? <= 0 {
                    return Ok(Some(outcome));
                }
            }
        }
    }

    log::error!("PROT_FORFEIT_UNSETTLED user={user_id} passes={PROT_STATE_RETRIES}");
    Err(create_error!(InternalError))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use futures::future::join_all;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use revolt_models::v0;
    use revolt_result::ErrorType;

    use crate::{
        cipher_prot_posted, prot_key_admin, prot_key_cipher_founding, prot_key_cipher_upgrade,
        prot_key_clawback, prot_key_forfeit, prot_key_purchase, prot_user_account,
        CipherMembership, CipherProtSync, ProtAmount, ProtApplyOutcome, ProtLedgerEntry,
        ProtPosting, ProtRef, PROT_ACTOR_CIPHER, PROT_ACTOR_PAYMENTS, PROT_SYS_ADJUST,
        PROT_SYS_CLAWED, PROT_SYS_FORFEITED, PROT_SYS_ISSUED,
    };

    use super::{run_forfeit_passes, validate_prot_posting, PROT_STATE_RETRIES};

    const ADMIN: &str = "01ADMIN0000000000000000000";

    /// Install the Prot indexes on MongoDB and create both collections, with
    /// the migration's own helper (revision 76).
    ///
    /// `database_test!` connects to a fresh database with no migrations run.
    /// The collections are created up front as the migration does, so no
    /// transaction has to create one. The reference driver enforces the
    /// unique key in code, so it needs no setup.
    async fn create_prot_test_indexes(db: &crate::Database) {
        match db {
            crate::Database::Reference(_) => {}
            #[cfg(feature = "mongodb")]
            crate::Database::MongoDb(mongo) => {
                for collection in crate::PROT_COLLECTIONS {
                    mongo.db().create_collection(collection).await.ok();
                }

                crate::create_prot_indexes(&mongo.db())
                    .await
                    .expect("failed to create prot_ledger indexes");
            }
        }
    }

    fn admin_posting(user_id: &str, nonce: &str, amount: i64, now: i64) -> ProtPosting {
        let wallet = prot_user_account(user_id);
        let (debit, credit, n) = if amount >= 0 {
            (PROT_SYS_ADJUST.to_string(), wallet, amount)
        } else {
            (wallet, PROT_SYS_ADJUST.to_string(), -amount)
        };
        ProtPosting {
            key: prot_key_admin(ADMIN, nonce),
            kind: v0::ProtEntryKind::AdminAdjust,
            debit,
            credit,
            amount: ProtAmount::Exact(n),
            debit_floor: 0,
            actor: ADMIN.to_string(),
            reference: ProtRef::default(),
            reason: Some("test".to_string()),
            created_at: now,
        }
    }

    fn purchase_posting(user_id: &str, order_id: &str, prot: i64, now: i64) -> ProtPosting {
        ProtPosting {
            key: prot_key_purchase(order_id),
            kind: v0::ProtEntryKind::Purchase,
            debit: PROT_SYS_ISSUED.to_string(),
            credit: prot_user_account(user_id),
            amount: ProtAmount::Exact(prot),
            debit_floor: 0,
            actor: PROT_ACTOR_PAYMENTS.to_string(),
            reference: ProtRef {
                order_id: Some(order_id.to_string()),
                ..Default::default()
            },
            reason: None,
            created_at: now,
        }
    }

    fn clawback_posting(user_id: &str, order_id: &str, n: i64, now: i64) -> ProtPosting {
        ProtPosting {
            key: prot_key_clawback(order_id),
            kind: v0::ProtEntryKind::Clawback,
            debit: prot_user_account(user_id),
            credit: PROT_SYS_CLAWED.to_string(),
            amount: ProtAmount::UpTo(n),
            debit_floor: 0,
            actor: PROT_ACTOR_PAYMENTS.to_string(),
            reference: ProtRef {
                order_id: Some(order_id.to_string()),
                ..Default::default()
            },
            reason: None,
            created_at: now,
        }
    }

    fn cipher_grant_posting(
        user_id: &str,
        key: String,
        kind: v0::ProtEntryKind,
        number: u32,
        base: &str,
        amount: i64,
        now: i64,
    ) -> ProtPosting {
        ProtPosting {
            key,
            kind,
            debit: PROT_SYS_ISSUED.to_string(),
            credit: prot_user_account(user_id),
            amount: ProtAmount::Exact(amount),
            debit_floor: 0,
            actor: PROT_ACTOR_CIPHER.to_string(),
            reference: ProtRef {
                order_id: Some(base.to_string()),
                membership_number: Some(number),
                membership_order_id: Some(base.to_string()),
                ..Default::default()
            },
            reason: None,
            created_at: now,
        }
    }

    fn membership(user_id: &str, number: u32, orders: &[&str]) -> CipherMembership {
        CipherMembership {
            user_id: user_id.to_string(),
            number,
            tier: v0::CipherTier::T99,
            prot_grant: 16_500,
            orders: orders.iter().map(|order| order.to_string()).collect(),
            disputed_orders: vec![],
            granted_at: 1_000,
            revoked_at: None,
            revoke_reason: None,
            prot_posted_at: None,
            version: 0,
        }
    }

    async fn balance(db: &crate::Database, user_id: &str) -> i64 {
        db.fetch_prot_account(&prot_user_account(user_id))
            .await
            .unwrap()
            .map_or(0, |account| account.balance)
    }

    async fn version(db: &crate::Database, user_id: &str) -> u64 {
        db.fetch_prot_account(&prot_user_account(user_id))
            .await
            .unwrap()
            .map_or(0, |account| account.version)
    }

    async fn membership_version(db: &crate::Database, user_id: &str) -> u64 {
        db.fetch_cipher_membership(user_id)
            .await
            .unwrap()
            .expect("membership exists")
            .version
    }

    /// Every row naming the account, read through the paged fetch
    async fn all_entries(db: &crate::Database, account_id: &str) -> Vec<ProtLedgerEntry> {
        let mut rows: Vec<ProtLedgerEntry> = Vec::new();
        loop {
            let before = rows.last().map(|row| row.id.clone());
            let page = db
                .fetch_prot_entries_by_account(account_id, before.as_deref(), 100)
                .await
                .unwrap();
            if page.is_empty() {
                return rows;
            }
            rows.extend(page);
        }
    }

    fn is_error(result: &revolt_result::Result<impl std::fmt::Debug>, expected: &str) -> bool {
        match result {
            Err(error) => format!("{:?}", error.error_type).starts_with(expected),
            Ok(_) => false,
        }
    }

    const ALL_KINDS: [v0::ProtEntryKind; 19] = [
        v0::ProtEntryKind::Purchase,
        v0::ProtEntryKind::CipherFounding,
        v0::ProtEntryKind::CipherUpgrade,
        v0::ProtEntryKind::Contribution,
        v0::ProtEntryKind::TierUpgrade,
        v0::ProtEntryKind::PledgeHold,
        v0::ProtEntryKind::PledgeCapture,
        v0::ProtEntryKind::PledgeReturn,
        v0::ProtEntryKind::PledgeWithdraw,
        v0::ProtEntryKind::LaunchReturn,
        v0::ProtEntryKind::Burn,
        v0::ProtEntryKind::Settlement,
        v0::ProtEntryKind::WriteOff,
        v0::ProtEntryKind::Clawback,
        v0::ProtEntryKind::ClawbackHold,
        v0::ProtEntryKind::Forfeit,
        v0::ProtEntryKind::ForfeitHold,
        v0::ProtEntryKind::ForfeitTank,
        v0::ProtEntryKind::AdminAdjust,
    ];

    #[test]
    fn up_to_and_all_are_only_valid_for_their_kinds() {
        for kind in ALL_KINDS {
            let mut posting = clawback_posting("u1", "o1", 10, 1_000);
            posting.kind = kind;
            let clawback = matches!(
                kind,
                v0::ProtEntryKind::Clawback | v0::ProtEntryKind::ClawbackHold
            );
            assert_eq!(
                validate_prot_posting(&posting).is_ok(),
                clawback,
                "UpTo {kind:?}"
            );

            posting.amount = ProtAmount::All;
            let forfeit = matches!(
                kind,
                v0::ProtEntryKind::Forfeit
                    | v0::ProtEntryKind::ForfeitHold
                    | v0::ProtEntryKind::ForfeitTank
            );
            assert_eq!(
                validate_prot_posting(&posting).is_ok(),
                forfeit,
                "All {kind:?}"
            );

            // Exact is valid for every kind
            posting.amount = ProtAmount::Exact(1);
            assert!(validate_prot_posting(&posting).is_ok(), "Exact {kind:?}");
        }
    }

    #[test]
    fn malformed_postings_are_refused_as_internal_errors() {
        let good = purchase_posting("u1", "o1", 100, 1_000);
        assert!(validate_prot_posting(&good).is_ok());

        let mut cases: Vec<ProtPosting> = Vec::new();
        for amount in [ProtAmount::Exact(0), ProtAmount::Exact(-1)] {
            cases.push(ProtPosting {
                amount,
                ..good.clone()
            });
        }
        for n in [0, -5] {
            cases.push(clawback_posting("u1", "o1", n, 1_000));
        }
        cases.push(ProtPosting {
            key: String::new(),
            ..good.clone()
        });
        cases.push(ProtPosting {
            key: "k".repeat(256),
            ..good.clone()
        });
        cases.push(ProtPosting {
            key: "purchase:o1\nx".to_string(),
            ..good.clone()
        });
        cases.push(ProtPosting {
            credit: PROT_SYS_ISSUED.to_string(),
            ..good.clone()
        });
        cases.push(ProtPosting {
            credit: "wallet:u1".to_string(),
            ..good.clone()
        });
        cases.push(ProtPosting {
            credit: "user:".to_string(),
            ..good.clone()
        });
        cases.push(ProtPosting {
            debit: "issued".to_string(),
            ..good.clone()
        });
        let mut newline = good.clone();
        newline.reference.order_id = Some("o1\nref.tank_id=t1".to_string());
        cases.push(newline);
        // UpTo / All from a system side, which has no balance
        cases.push(ProtPosting {
            debit: PROT_SYS_ISSUED.to_string(),
            credit: prot_user_account("u1"),
            ..clawback_posting("u1", "o1", 10, 1_000)
        });

        for posting in cases {
            let result = validate_prot_posting(&posting);
            assert!(
                is_error(&result, "InternalError"),
                "{posting:?} gave {result:?}"
            );
        }

        // 255 bytes is still a key
        assert!(validate_prot_posting(&ProtPosting {
            key: "k".repeat(255),
            ..good
        })
        .is_ok());
    }

    /// A pass or balance read that completes at once
    fn ready<T>(value: T) -> std::future::Ready<revolt_result::Result<T>> {
        std::future::ready(Ok(value))
    }

    #[tokio::test]
    async fn a_forfeit_pass_that_finds_its_key_taken_runs_the_next_pass() {
        let row = |key: &str| ProtLedgerEntry {
            id: "01ROW".to_string(),
            key: key.to_string(),
            kind: v0::ProtEntryKind::Forfeit,
            currency: v0::ProtCurrency::Prot,
            debit: prot_user_account("u1"),
            credit: PROT_SYS_FORFEITED.to_string(),
            amount: 0,
            requested: None,
            shortfall: None,
            actor: "sys:account-deletion".to_string(),
            reference: ProtRef::default(),
            payload_hash: String::new(),
            reason: None,
            created_at: 1_000,
        };

        // Pass 1 finds key 1 taken by a racing pass, and Prot reached the
        // wallet after it: pass 2 runs and moves it
        let passes = AtomicUsize::new(0);
        let balances = [700_i64, 50, 0];
        let reads = AtomicUsize::new(0);
        let outcome = run_forfeit_passes(
            "u1",
            || {
                let n = passes.fetch_add(1, Ordering::SeqCst) + 1;
                let entry = row(&prot_key_forfeit("u1", n as u64));
                ready(if n == 1 {
                    ProtApplyOutcome::AlreadyApplied(entry)
                } else {
                    ProtApplyOutcome::Applied(entry)
                })
            },
            || {
                let balance = balances[reads.fetch_add(1, Ordering::SeqCst)];
                ready(balance)
            },
        )
        .await
        .unwrap();
        assert_eq!(passes.load(Ordering::SeqCst), 2);
        assert_eq!(
            outcome,
            Some(ProtApplyOutcome::Applied(row("forfeit:u1:2")))
        );

        // A racing pass took key 1 and nothing came in after it: done
        let passes = AtomicUsize::new(0);
        let outcome = run_forfeit_passes(
            "u1",
            || {
                passes.fetch_add(1, Ordering::SeqCst);
                let entry = row("forfeit:u1:1");
                ready(ProtApplyOutcome::AlreadyApplied(entry))
            },
            {
                let reads = AtomicUsize::new(0);
                move || {
                    let first = reads.fetch_add(1, Ordering::SeqCst) == 0;
                    ready(if first { 700 } else { 0 })
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(passes.load(Ordering::SeqCst), 1);
        assert_eq!(
            outcome,
            Some(ProtApplyOutcome::AlreadyApplied(row("forfeit:u1:1")))
        );

        // Never settles: bounded, then an error
        let passes = AtomicUsize::new(0);
        let result = run_forfeit_passes(
            "u1",
            || {
                passes.fetch_add(1, Ordering::SeqCst);
                let entry = row("forfeit:u1:1");
                ready(ProtApplyOutcome::AlreadyApplied(entry))
            },
            || ready(10),
        )
        .await;
        assert!(is_error(&result, "InternalError"));
        assert_eq!(passes.load(Ordering::SeqCst), PROT_STATE_RETRIES);

        // An empty wallet runs no pass at all
        let passes = AtomicUsize::new(0);
        let outcome = run_forfeit_passes(
            "u1",
            || {
                passes.fetch_add(1, Ordering::SeqCst);
                let entry = row("forfeit:u1:1");
                ready(ProtApplyOutcome::Applied(entry))
            },
            || ready(0),
        )
        .await
        .unwrap();
        assert_eq!(outcome, None);
        assert_eq!(passes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn each_key_kind_applied_twice_writes_one_row() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;
            let user = "01USERA0000000000000000000";
            let wallet = prot_user_account(user);

            let postings = vec![
                purchase_posting(user, "01ORDERA000000000000000000", 2_600, 1_000),
                cipher_grant_posting(
                    user,
                    prot_key_cipher_founding(user, 7, "01BASEA0000000000000000000"),
                    v0::ProtEntryKind::CipherFounding,
                    7,
                    "01BASEA0000000000000000000",
                    16_500,
                    1_001,
                ),
                cipher_grant_posting(
                    user,
                    prot_key_cipher_upgrade(user, 7, "01BASEA0000000000000000000", 1),
                    v0::ProtEntryKind::CipherUpgrade,
                    7,
                    "01BASEA0000000000000000000",
                    16_500,
                    1_002,
                ),
                admin_posting(user, "n-credit", 400, 1_003),
                admin_posting(user, "n-debit", -300, 1_004),
                clawback_posting(user, "01ORDERA000000000000000000", 2_600, 1_005),
            ];

            for posting in &postings {
                let written = match db.apply_prot_posting(posting).await.unwrap() {
                    ProtApplyOutcome::Applied(written) => written,
                    other => panic!("{} was not applied: {other:?}", posting.key),
                };
                let after_first = (balance(&db, user).await, version(&db, user).await);

                // Retried with other metadata: the stored row, nothing written
                let mut retry = posting.clone();
                retry.created_at += 50_000;
                retry.reason = Some("retried".to_string());
                assert_eq!(
                    db.apply_prot_posting(&retry).await.unwrap(),
                    ProtApplyOutcome::AlreadyApplied(written.clone())
                );
                assert_eq!(
                    (balance(&db, user).await, version(&db, user).await),
                    after_first,
                    "{}",
                    posting.key
                );
                assert_eq!(
                    db.fetch_prot_entry_by_key(&posting.key).await.unwrap(),
                    Some(written)
                );
            }

            // The forfeit key, through the trait method (its pass count makes
            // a second call a new pass; the key itself is applied once)
            let forfeit = db.forfeit_prot_wallet(user, 2_000).await.unwrap().unwrap();
            assert_eq!(forfeit.entry().key, prot_key_forfeit(user, 1));
            let replay = super::forfeit_posting(user, 1, 2_001);
            assert_eq!(
                db.apply_prot_posting(&replay).await.unwrap(),
                ProtApplyOutcome::AlreadyApplied(forfeit.entry().clone())
            );

            // One row per key
            let rows = all_entries(&db, &wallet).await;
            assert_eq!(rows.len(), postings.len() + 1);
            let mut keys: Vec<&str> = rows.iter().map(|row| row.key.as_str()).collect();
            keys.sort_unstable();
            keys.dedup();
            assert_eq!(keys.len(), rows.len());

            // 2,600 + 16,500 + 16,500 + 400 - 300 - 2,600, then forfeited
            assert_eq!(forfeit.entry().amount, 33_100);
            assert_eq!(balance(&db, user).await, 0);
            assert_eq!(version(&db, user).await, rows.len() as u64);
        });
    }

    #[tokio::test]
    async fn the_same_key_with_another_payload_is_an_idempotency_conflict() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;
            let user = "01USERB0000000000000000000";

            let posting = purchase_posting(user, "01ORDERB000000000000000000", 1_000, 1_000);
            let written = db.apply_prot_posting(&posting).await.unwrap();

            let mut other = posting.clone();
            other.amount = ProtAmount::Exact(1_001);
            let result = db.apply_prot_posting(&other).await;
            assert!(is_error(&result, "ProtIdempotencyConflict"), "{result:?}");

            let mut other = posting.clone();
            other.credit = prot_user_account("01USERZ0000000000000000000");
            let result = db.apply_prot_posting(&other).await;
            assert!(is_error(&result, "ProtIdempotencyConflict"), "{result:?}");

            // Nothing moved
            assert_eq!(
                db.fetch_prot_entry_by_key(&posting.key)
                    .await
                    .unwrap()
                    .as_ref(),
                Some(written.entry())
            );
            assert_eq!(balance(&db, user).await, 1_000);
            assert_eq!(version(&db, user).await, 1);
            assert!(db
                .fetch_prot_account(&prot_user_account("01USERZ0000000000000000000"))
                .await
                .unwrap()
                .is_none());
        });
    }

    #[tokio::test]
    async fn a_replayed_debit_is_already_applied_after_the_wallet_was_spent() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;
            let user = "01USERC0000000000000000000";

            db.apply_prot_posting(&admin_posting(user, "fund", 500, 1_000))
                .await
                .unwrap();
            let debit = admin_posting(user, "take", -400, 1_001);
            let written = db.apply_prot_posting(&debit).await.unwrap();
            assert_eq!(balance(&db, user).await, 100);

            // The replay finds its row before the floor would refuse it
            assert_eq!(
                db.apply_prot_posting(&debit).await.unwrap(),
                ProtApplyOutcome::AlreadyApplied(written.entry().clone())
            );

            // A new debit the wallet can't cover changes nothing
            let result = db
                .apply_prot_posting(&admin_posting(user, "too-much", -101, 1_002))
                .await;
            match result {
                Err(error) => assert!(matches!(
                    error.error_type,
                    ErrorType::InsufficientProt {
                        needed: 101,
                        available: 100
                    }
                )),
                Ok(outcome) => panic!("overspent: {outcome:?}"),
            }
            assert_eq!(balance(&db, user).await, 100);
            assert_eq!(version(&db, user).await, 2);
            assert!(db
                .fetch_prot_entry_by_key(&prot_key_admin(ADMIN, "too-much"))
                .await
                .unwrap()
                .is_none());
        });
    }

    #[tokio::test]
    async fn concurrent_exact_debits_never_overspend() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;
            let user = "01USERD0000000000000000000";
            db.apply_prot_posting(&admin_posting(user, "fund", 100, 1_000))
                .await
                .unwrap();

            let debits: Vec<ProtPosting> = (0..20)
                .map(|i| admin_posting(user, &format!("debit-{i}"), -10, 2_000 + i))
                .collect();
            let results =
                join_all(debits.iter().map(|posting| db.apply_prot_posting(posting))).await;

            let mut applied = 0;
            for result in &results {
                match result {
                    Ok(ProtApplyOutcome::Applied(_)) => applied += 1,
                    Err(error) => assert!(
                        matches!(error.error_type, ErrorType::InsufficientProt { .. }),
                        "{error:?}"
                    ),
                    Ok(other) => panic!("unexpected {other:?}"),
                }
            }
            assert_eq!(applied, 10);
            assert_eq!(balance(&db, user).await, 0);

            let rows = all_entries(&db, &prot_user_account(user)).await;
            assert_eq!(rows.len(), 11);
            assert_eq!(version(&db, user).await, 11);
        });
    }

    #[tokio::test]
    async fn the_ledger_sums_equal_the_balances_after_a_random_sequence() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;
            let users = [
                "01USERE0000000000000000000",
                "01USERF0000000000000000000",
                "01USERG0000000000000000000",
            ];
            let mut rng = StdRng::seed_from_u64(0x5052_4f54);
            let mut applied: Vec<ProtPosting> = Vec::new();

            for step in 0..60_i64 {
                let user = users[rng.gen_range(0..users.len())];
                let now = 10_000 + step;
                let posting = match rng.gen_range(0..5) {
                    0 => purchase_posting(
                        user,
                        &format!("01ORDER{step:019}"),
                        rng.gen_range(1..3_000),
                        now,
                    ),
                    1 => admin_posting(user, &format!("c{step}"), rng.gen_range(1..500), now),
                    2 => admin_posting(user, &format!("d{step}"), -rng.gen_range(1..800), now),
                    3 => clawback_posting(
                        user,
                        &format!("01ORDER{step:019}"),
                        rng.gen_range(1..1_500),
                        now,
                    ),
                    // Replay an earlier posting
                    _ => match applied.len() {
                        0 => continue,
                        n => applied[rng.gen_range(0..n)].clone(),
                    },
                };
                match db.apply_prot_posting(&posting).await {
                    Ok(_) => applied.push(posting),
                    Err(error) => assert!(
                        matches!(error.error_type, ErrorType::InsufficientProt { .. }),
                        "{error:?}"
                    ),
                }
            }
            db.forfeit_prot_wallet(users[0], 20_000).await.unwrap();

            // Every row names at least one wallet here
            let mut rows: Vec<ProtLedgerEntry> = Vec::new();
            for user in users {
                for row in all_entries(&db, &prot_user_account(user)).await {
                    if !rows.iter().any(|seen| seen.id == row.id) {
                        rows.push(row);
                    }
                }
            }
            assert!(rows.len() > 20);

            let signed = |account: &str| -> i64 {
                rows.iter()
                    .map(|row| {
                        (if row.credit == account { row.amount } else { 0 })
                            - (if row.debit == account { row.amount } else { 0 })
                    })
                    .sum()
            };

            let mut wallets = 0;
            for user in users {
                let account = prot_user_account(user);
                let stored = db.fetch_prot_account(&account).await.unwrap();
                let naming = rows
                    .iter()
                    .filter(|row| row.debit == account || row.credit == account)
                    .count() as u64;
                assert_eq!(stored.as_ref().map_or(0, |a| a.balance), signed(&account));
                assert_eq!(stored.as_ref().map_or(0, |a| a.version), naming);
                assert!(stored.as_ref().map_or(0, |a| a.balance) >= 0);
                wallets += signed(&account);
            }
            assert_eq!(balance(&db, users[0]).await, 0);

            // System sides as signed totals: over all accounts the ledger sums to 0
            let system: i64 = [
                PROT_SYS_ISSUED,
                PROT_SYS_ADJUST,
                PROT_SYS_CLAWED,
                PROT_SYS_FORFEITED,
            ]
            .into_iter()
            .map(&signed)
            .sum();
            assert_eq!(wallets + system, 0);

            // UpTo rows record what they could not take
            for row in rows
                .iter()
                .filter(|row| row.kind == v0::ProtEntryKind::Clawback)
            {
                let requested = row.requested.expect("UpTo rows record requested");
                assert_eq!(row.shortfall, Some(requested - row.amount));
                assert!(row.amount >= 0 && row.amount <= requested);
            }
        });
    }

    #[tokio::test]
    async fn a_zero_amount_up_to_still_bumps_the_version() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;
            let user = "01USERH0000000000000000000";

            // No wallet at all: the row records the full shortfall and the
            // wallet document is created at 0
            let first = db
                .apply_prot_posting(&clawback_posting(
                    user,
                    "01ORDERH000000000000000000",
                    500,
                    1_000,
                ))
                .await
                .unwrap();
            let entry = first.entry();
            assert_eq!(entry.amount, 0);
            assert_eq!(entry.requested, Some(500));
            assert_eq!(entry.shortfall, Some(500));
            assert_eq!(balance(&db, user).await, 0);
            assert_eq!(version(&db, user).await, 1);

            // An emptied wallet
            db.apply_prot_posting(&admin_posting(user, "in", 300, 1_001))
                .await
                .unwrap();
            db.apply_prot_posting(&admin_posting(user, "out", -300, 1_002))
                .await
                .unwrap();
            assert_eq!(version(&db, user).await, 3);
            let second = db
                .apply_prot_posting(&clawback_posting(
                    user,
                    "01ORDERI000000000000000000",
                    200,
                    1_003,
                ))
                .await
                .unwrap();
            assert_eq!(second.entry().amount, 0);
            assert_eq!(second.entry().shortfall, Some(200));
            assert_eq!(version(&db, user).await, 4);
            assert_eq!(
                db.fetch_prot_account(&prot_user_account(user))
                    .await
                    .unwrap()
                    .map(|account| account.updated_at),
                Some(1_003)
            );

            // A partial one takes what is there
            db.apply_prot_posting(&admin_posting(user, "in-2", 150, 1_004))
                .await
                .unwrap();
            let third = db
                .apply_prot_posting(&clawback_posting(
                    user,
                    "01ORDERJ000000000000000000",
                    200,
                    1_005,
                ))
                .await
                .unwrap();
            assert_eq!(third.entry().amount, 150);
            assert_eq!(third.entry().shortfall, Some(50));
            assert_eq!(balance(&db, user).await, 0);
            assert_eq!(version(&db, user).await, 6);
        });
    }

    #[tokio::test]
    async fn entries_by_account_page_newest_first() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;
            let user = "01USERI0000000000000000000";
            let other = "01USERJ0000000000000000000";
            let account = prot_user_account(user);

            // Credits and debits both name the account
            for i in 0..5 {
                db.apply_prot_posting(&admin_posting(user, &format!("c{i}"), 100, 1_000 + i))
                    .await
                    .unwrap();
            }
            for i in 0..2 {
                db.apply_prot_posting(&admin_posting(user, &format!("d{i}"), -50, 2_000 + i))
                    .await
                    .unwrap();
            }
            db.apply_prot_posting(&admin_posting(other, "x", 100, 3_000))
                .await
                .unwrap();

            let mut expected: Vec<String> = Vec::new();
            for key in (0..5)
                .map(|i| format!("c{i}"))
                .chain((0..2).map(|i| format!("d{i}")))
            {
                let row = db
                    .fetch_prot_entry_by_key(&prot_key_admin(ADMIN, &key))
                    .await
                    .unwrap()
                    .unwrap();
                expected.push(row.id);
            }
            expected.sort_unstable_by(|a, b| b.cmp(a));

            let mut seen: Vec<String> = Vec::new();
            let mut sizes = Vec::new();
            loop {
                let page = db
                    .fetch_prot_entries_by_account(&account, seen.last().map(String::as_str), 3)
                    .await
                    .unwrap();
                sizes.push(page.len());
                if page.is_empty() {
                    break;
                }
                for row in &page {
                    assert!(row.debit == account || row.credit == account);
                }
                seen.extend(page.into_iter().map(|row| row.id));
            }
            assert_eq!(sizes, vec![3, 3, 1, 0]);
            assert_eq!(seen, expected);

            // limit is clamped to 1..=100
            for limit in [0, -3] {
                assert_eq!(
                    db.fetch_prot_entries_by_account(&account, None, limit)
                        .await
                        .unwrap()
                        .len(),
                    1
                );
            }
            assert_eq!(
                db.fetch_prot_entries_by_account(&account, None, 1_000)
                    .await
                    .unwrap()
                    .len(),
                7
            );
            assert!(db
                .fetch_prot_entries_by_account(&prot_user_account("01NOBODY"), None, 10)
                .await
                .unwrap()
                .is_empty());
        });
    }

    #[tokio::test]
    async fn entries_by_account_return_at_most_100() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;
            let user = "01USERK0000000000000000000";
            for i in 0..101 {
                db.apply_prot_posting(&admin_posting(user, &format!("c{i}"), 1, 1_000 + i))
                    .await
                    .unwrap();
            }
            let account = prot_user_account(user);
            let first = db
                .fetch_prot_entries_by_account(&account, None, 1_000)
                .await
                .unwrap();
            assert_eq!(first.len(), 100);
            let rest = db
                .fetch_prot_entries_by_account(
                    &account,
                    first.last().map(|row| row.id.as_str()),
                    1_000,
                )
                .await
                .unwrap();
            assert_eq!(rest.len(), 1);
            assert!(rest[0].id < first[99].id);
        });
    }

    #[tokio::test]
    async fn entries_by_order_membership_and_credit_sums() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;
            let user = "01USERL0000000000000000000";
            let order = "01ORDERL000000000000000000";
            let base = "01BASEL0000000000000000000";

            db.apply_prot_posting(&purchase_posting(user, order, 1_000, 1_000))
                .await
                .unwrap();
            db.apply_prot_posting(&purchase_posting(
                user,
                "01ORDERM000000000000000000",
                500,
                5_000,
            ))
            .await
            .unwrap();
            db.apply_prot_posting(&cipher_grant_posting(
                user,
                prot_key_cipher_founding(user, 3, base),
                v0::ProtEntryKind::CipherFounding,
                3,
                base,
                16_500,
                6_000,
            ))
            .await
            .unwrap();
            db.apply_prot_posting(&clawback_posting(user, order, 1_000, 7_000))
                .await
                .unwrap();

            let by_order = db.fetch_prot_entries_by_order(order).await.unwrap();
            let mut keys: Vec<&str> = by_order.iter().map(|row| row.key.as_str()).collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                vec![prot_key_clawback(order), prot_key_purchase(order)]
            );
            assert!(by_order.windows(2).all(|pair| pair[0].id < pair[1].id));

            let by_membership = db.fetch_prot_entries_by_membership(base).await.unwrap();
            assert_eq!(by_membership.len(), 1);
            assert_eq!(by_membership[0].kind, v0::ProtEntryKind::CipherFounding);
            assert!(db
                .fetch_prot_entries_by_membership("01NONE")
                .await
                .unwrap()
                .is_empty());

            let account = prot_user_account(user);
            let purchases = [v0::ProtEntryKind::Purchase];
            assert_eq!(
                db.sum_prot_credits_since(&account, &purchases, 0)
                    .await
                    .unwrap(),
                1_500
            );
            assert_eq!(
                db.sum_prot_credits_since(&account, &purchases, 1_001)
                    .await
                    .unwrap(),
                500
            );
            assert_eq!(
                db.sum_prot_credits_since(&account, &purchases, 5_000)
                    .await
                    .unwrap(),
                500
            );
            assert_eq!(
                db.sum_prot_credits_since(&account, &purchases, 5_001)
                    .await
                    .unwrap(),
                0
            );
            assert_eq!(
                db.sum_prot_credits_since(
                    &account,
                    &[
                        v0::ProtEntryKind::Purchase,
                        v0::ProtEntryKind::CipherFounding
                    ],
                    0
                )
                .await
                .unwrap(),
                18_000
            );
            // Debits (the clawback) never count
            assert_eq!(
                db.sum_prot_credits_since(&account, &[v0::ProtEntryKind::Clawback], 0)
                    .await
                    .unwrap(),
                0
            );
            assert_eq!(
                db.sum_prot_credits_since(&account, &[], 0).await.unwrap(),
                0
            );
        });
    }

    #[tokio::test]
    async fn the_apply_trait_refuses_invalid_postings_and_writes_nothing() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;
            let user = "01USERM0000000000000000000";
            db.apply_prot_posting(&admin_posting(user, "fund", 100, 1_000))
                .await
                .unwrap();

            let mut up_to = clawback_posting(user, "01ORDERN000000000000000000", 10, 1_001);
            up_to.kind = v0::ProtEntryKind::Purchase;
            let mut all = clawback_posting(user, "01ORDERO000000000000000000", 10, 1_002);
            all.kind = v0::ProtEntryKind::AdminAdjust;
            all.amount = ProtAmount::All;
            let mut zero = admin_posting(user, "zero", 1, 1_003);
            zero.amount = ProtAmount::Exact(0);

            for posting in [up_to, all, zero] {
                let result = db.apply_prot_posting(&posting).await;
                assert!(is_error(&result, "InternalError"), "{result:?}");
                assert!(db
                    .fetch_prot_entry_by_key(&posting.key)
                    .await
                    .unwrap()
                    .is_none());
            }
            assert_eq!(balance(&db, user).await, 100);
            assert_eq!(version(&db, user).await, 1);
        });
    }

    #[tokio::test]
    async fn forfeit_moves_the_whole_wallet_one_pass_at_a_time() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;
            let user = "01USERN0000000000000000000";

            // No wallet, then an empty one: nothing written
            assert_eq!(db.forfeit_prot_wallet(user, 1_000).await.unwrap(), None);
            db.apply_prot_posting(&admin_posting(user, "in", 700, 1_001))
                .await
                .unwrap();
            db.apply_prot_posting(&admin_posting(user, "out", -700, 1_002))
                .await
                .unwrap();
            assert_eq!(db.forfeit_prot_wallet(user, 1_003).await.unwrap(), None);
            assert!(db
                .fetch_prot_entry_by_key(&prot_key_forfeit(user, 1))
                .await
                .unwrap()
                .is_none());

            db.apply_prot_posting(&admin_posting(user, "in-2", 700, 1_004))
                .await
                .unwrap();
            let first = db.forfeit_prot_wallet(user, 1_005).await.unwrap().unwrap();
            let ProtApplyOutcome::Applied(entry) = &first else {
                panic!("{first:?}");
            };
            assert_eq!(entry.key, prot_key_forfeit(user, 1));
            assert_eq!(entry.amount, 700);
            assert_eq!(entry.debit, prot_user_account(user));
            assert_eq!(entry.credit, PROT_SYS_FORFEITED);
            assert_eq!(entry.actor, "sys:account-deletion");
            assert_eq!(balance(&db, user).await, 0);

            // A credit that lands afterwards: the second pass takes key 2
            db.apply_prot_posting(&purchase_posting(
                user,
                "01ORDERP000000000000000000",
                50,
                1_006,
            ))
            .await
            .unwrap();
            let second = db.forfeit_prot_wallet(user, 1_007).await.unwrap().unwrap();
            assert_eq!(second.entry().key, prot_key_forfeit(user, 2));
            assert_eq!(second.entry().amount, 50);
            assert_eq!(balance(&db, user).await, 0);
        });
    }

    #[tokio::test]
    async fn racing_forfeit_passes_move_the_wallet_once() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;
            let user = "01USERO0000000000000000000";
            db.apply_prot_posting(&admin_posting(user, "in", 900, 1_000))
                .await
                .unwrap();

            let results = join_all((0..4).map(|i| db.forfeit_prot_wallet(user, 2_000 + i))).await;
            for result in &results {
                assert!(result.is_ok(), "{result:?}");
            }

            let rows = all_entries(&db, &prot_user_account(user)).await;
            let forfeited: i64 = rows
                .iter()
                .filter(|row| row.kind == v0::ProtEntryKind::Forfeit)
                .map(|row| row.amount)
                .sum();
            assert_eq!(forfeited, 900);
            assert_eq!(balance(&db, user).await, 0);
        });
    }

    #[tokio::test]
    async fn sync_posts_the_founding_grant_once_and_bumps_the_membership_version() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;
            let user = "01USERP0000000000000000000";
            let base = "01BASEP0000000000000000000";
            assert!(db
                .insert_cipher_membership(&membership(user, 42, &[base]))
                .await
                .unwrap());

            let synced = db.sync_cipher_prot(user, 5_000).await.unwrap();
            let CipherProtSync::Posted(ProtApplyOutcome::Applied(entry)) = &synced else {
                panic!("{synced:?}");
            };
            assert_eq!(entry.key, prot_key_cipher_founding(user, 42, base));
            assert_eq!(entry.kind, v0::ProtEntryKind::CipherFounding);
            assert_eq!(entry.amount, 16_500);
            assert_eq!(entry.debit, PROT_SYS_ISSUED);
            assert_eq!(entry.credit, prot_user_account(user));
            assert_eq!(entry.actor, PROT_ACTOR_CIPHER);
            assert_eq!(
                entry.reference,
                ProtRef {
                    order_id: Some(base.to_string()),
                    membership_number: Some(42),
                    membership_order_id: Some(base.to_string()),
                    ..Default::default()
                }
            );
            assert_eq!(balance(&db, user).await, 16_500);
            assert_eq!(membership_version(&db, user).await, 1);

            // Nothing more to do: no posting, and the version stays put
            assert_eq!(
                db.sync_cipher_prot(user, 5_001).await.unwrap(),
                CipherProtSync::Nothing
            );
            assert_eq!(membership_version(&db, user).await, 1);
            assert_eq!(balance(&db, user).await, 16_500);

            // No membership at all
            assert_eq!(
                db.sync_cipher_prot("01NOMEMBER", 5_002).await.unwrap(),
                CipherProtSync::Nothing
            );
        });
    }

    #[tokio::test]
    async fn sync_posts_an_upgrade_difference_under_the_next_seq() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;
            let user = "01USERQ0000000000000000000";
            let base = "01BASEQ0000000000000000000";
            let upgrade = "01UPGRQ0000000000000000000";
            let mut m = membership(user, 43, &[base]);
            assert!(db.insert_cipher_membership(&m).await.unwrap());
            db.sync_cipher_prot(user, 5_000).await.unwrap();

            m.tier = v0::CipherTier::T149;
            m.prot_grant = 33_000;
            m.orders.push(upgrade.to_string());
            assert!(db.update_cipher_membership_if_version(&m, 1).await.unwrap());

            let synced = db.sync_cipher_prot(user, 6_000).await.unwrap();
            let CipherProtSync::Posted(ProtApplyOutcome::Applied(entry)) = &synced else {
                panic!("{synced:?}");
            };
            assert_eq!(entry.key, prot_key_cipher_upgrade(user, 43, base, 1));
            assert_eq!(entry.kind, v0::ProtEntryKind::CipherUpgrade);
            assert_eq!(entry.amount, 16_500);
            assert_eq!(entry.reference.order_id.as_deref(), Some(upgrade));
            assert_eq!(entry.reference.membership_order_id.as_deref(), Some(base));
            assert_eq!(balance(&db, user).await, 33_000);
            assert_eq!(membership_version(&db, user).await, 3);
        });
    }

    #[tokio::test]
    async fn sync_leaves_an_inactive_or_disputed_membership_untouched() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;

            // Disputed: no upward posting
            let disputed = "01USERR0000000000000000000";
            let mut m = membership(disputed, 44, &["01BASER0000000000000000000"]);
            m.disputed_orders = vec!["01BASER0000000000000000000".to_string()];
            assert!(db.insert_cipher_membership(&m).await.unwrap());
            assert_eq!(
                db.sync_cipher_prot(disputed, 5_000).await.unwrap(),
                CipherProtSync::Nothing
            );
            assert_eq!(membership_version(&db, disputed).await, 0);
            assert_eq!(balance(&db, disputed).await, 0);

            // Empty orders
            let empty = "01USERS0000000000000000000";
            assert!(db
                .insert_cipher_membership(&membership(empty, 45, &[]))
                .await
                .unwrap());
            assert_eq!(
                db.sync_cipher_prot(empty, 5_000).await.unwrap(),
                CipherProtSync::Nothing
            );
            assert_eq!(membership_version(&db, empty).await, 0);

            // Revoked after its grant was posted and before any clawback:
            // reported, never clawed here, version untouched
            let revoked = "01USERT0000000000000000000";
            let mut m = membership(revoked, 46, &["01BASET0000000000000000000"]);
            assert!(db.insert_cipher_membership(&m).await.unwrap());
            db.sync_cipher_prot(revoked, 5_000).await.unwrap();
            m.revoked_at = Some(6_000);
            m.revoke_reason = Some(crate::CipherRevokeReason::Refund);
            assert!(db.update_cipher_membership_if_version(&m, 1).await.unwrap());
            assert_eq!(
                db.sync_cipher_prot(revoked, 6_001).await.unwrap(),
                CipherProtSync::OverPosted {
                    posted: 16_500,
                    target: 0
                }
            );
            assert_eq!(membership_version(&db, revoked).await, 2);
            assert_eq!(balance(&db, revoked).await, 16_500);
        });
    }

    #[tokio::test]
    async fn clawback_takes_what_is_posted_above_the_target_and_records_the_shortfall() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;
            let user = "01USERU0000000000000000000";
            let base = "01BASEU0000000000000000000";
            let mut m = membership(user, 47, &[base]);
            assert!(db.insert_cipher_membership(&m).await.unwrap());
            db.sync_cipher_prot(user, 5_000).await.unwrap();

            // Nothing to claw while the membership still holds its grant
            assert_eq!(
                db.clawback_cipher_prot(user, base, 5_500).await.unwrap(),
                None
            );
            assert_eq!(membership_version(&db, user).await, 1);

            // 1,000 left the wallet; then the membership is revoked
            db.apply_prot_posting(&admin_posting(user, "spend", -1_000, 5_600))
                .await
                .unwrap();
            m.revoked_at = Some(6_000);
            m.revoke_reason = Some(crate::CipherRevokeReason::Refund);
            assert!(db.update_cipher_membership_if_version(&m, 1).await.unwrap());

            let clawed = db
                .clawback_cipher_prot(user, base, 6_001)
                .await
                .unwrap()
                .unwrap();
            let ProtApplyOutcome::Applied(entry) = &clawed else {
                panic!("{clawed:?}");
            };
            assert_eq!(entry.key, prot_key_clawback(base));
            assert_eq!(entry.kind, v0::ProtEntryKind::Clawback);
            assert_eq!(entry.amount, 15_500);
            assert_eq!(entry.requested, Some(16_500));
            assert_eq!(entry.shortfall, Some(1_000));
            assert_eq!(entry.credit, PROT_SYS_CLAWED);
            assert_eq!(entry.reference.membership_order_id.as_deref(), Some(base));
            assert_eq!(entry.reference.membership_number, Some(47));
            assert_eq!(balance(&db, user).await, 0);
            assert_eq!(membership_version(&db, user).await, 3);

            // Settled to its target: posted counts `requested`
            let rows = db.fetch_prot_entries_by_membership(base).await.unwrap();
            assert_eq!(cipher_prot_posted(&rows), 0);

            // The same reversal again: the stored row, nothing written
            assert_eq!(
                db.clawback_cipher_prot(user, base, 6_002).await.unwrap(),
                Some(ProtApplyOutcome::AlreadyApplied(entry.clone()))
            );
            // Another order of the same membership: nothing left to claw
            assert_eq!(
                db.clawback_cipher_prot(user, "01UPGRU0000000000000000000", 6_003)
                    .await
                    .unwrap(),
                None
            );
            assert_eq!(membership_version(&db, user).await, 3);
        });
    }

    #[tokio::test]
    async fn clawback_with_nothing_posted_writes_nothing() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;
            let user = "01USERV0000000000000000000";
            let base = "01BASEV0000000000000000000";
            let mut m = membership(user, 48, &[base]);
            assert!(db.insert_cipher_membership(&m).await.unwrap());
            m.revoked_at = Some(6_000);
            m.revoke_reason = Some(crate::CipherRevokeReason::DisputeLost);
            assert!(db.update_cipher_membership_if_version(&m, 0).await.unwrap());

            assert_eq!(
                db.clawback_cipher_prot(user, base, 6_001).await.unwrap(),
                None
            );
            assert_eq!(membership_version(&db, user).await, 1);
            assert!(db
                .fetch_prot_entry_by_key(&prot_key_clawback(base))
                .await
                .unwrap()
                .is_none());

            // No membership
            assert_eq!(
                db.clawback_cipher_prot("01NOMEMBER", base, 6_002)
                    .await
                    .unwrap(),
                None
            );
        });
    }

    #[tokio::test]
    async fn clawback_of_an_order_from_an_older_incarnation_claws_nothing() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;
            let user = "01USERW0000000000000000000";
            // The current incarnation was bought with 01B...; 01A... is an
            // order of the row a re-purchase replaced
            let old_order = "01AOLDW0000000000000000000";
            let base = "01BNEWW0000000000000000000";
            let mut m = membership(user, 49, &[base]);
            assert!(db.insert_cipher_membership(&m).await.unwrap());
            db.sync_cipher_prot(user, 5_000).await.unwrap();
            // Even with the current incarnation revoked (posted > target)
            m.revoked_at = Some(6_000);
            m.revoke_reason = Some(crate::CipherRevokeReason::Refund);
            assert!(db.update_cipher_membership_if_version(&m, 1).await.unwrap());

            assert_eq!(
                db.clawback_cipher_prot(user, old_order, 6_001)
                    .await
                    .unwrap(),
                None
            );
            assert_eq!(balance(&db, user).await, 16_500);
            assert_eq!(membership_version(&db, user).await, 2);
            assert!(db
                .fetch_prot_entry_by_key(&prot_key_clawback(old_order))
                .await
                .unwrap()
                .is_none());
        });
    }

    #[tokio::test]
    async fn a_window_downgrade_claws_the_difference_and_a_re_upgrade_is_credited_again() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;
            let user = "01USERX0000000000000000000";
            let base = "01BASEX0000000000000000000";
            let first_upgrade = "01UPGRX1000000000000000000";
            let second_upgrade = "01UPGRX2000000000000000000";

            let mut m = membership(user, 50, &[base]);
            assert!(db.insert_cipher_membership(&m).await.unwrap());
            db.sync_cipher_prot(user, 5_000).await.unwrap();
            m.tier = v0::CipherTier::T149;
            m.prot_grant = 33_000;
            m.orders.push(first_upgrade.to_string());
            assert!(db.update_cipher_membership_if_version(&m, 1).await.unwrap());
            db.sync_cipher_prot(user, 5_100).await.unwrap();
            assert_eq!(balance(&db, user).await, 33_000);

            // Window downgrade: back to T99, the upgrade's order removed
            m.tier = v0::CipherTier::T99;
            m.prot_grant = 16_500;
            m.orders = vec![base.to_string()];
            assert!(db.update_cipher_membership_if_version(&m, 3).await.unwrap());
            let clawed = db
                .clawback_cipher_prot(user, first_upgrade, 6_000)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(clawed.entry().amount, 16_500);
            assert_eq!(clawed.entry().shortfall, Some(0));
            assert_eq!(balance(&db, user).await, 16_500);

            // Re-upgrade to the same tier: a new key, credited again
            m.tier = v0::CipherTier::T149;
            m.prot_grant = 33_000;
            m.orders.push(second_upgrade.to_string());
            assert!(db.update_cipher_membership_if_version(&m, 5).await.unwrap());
            let synced = db.sync_cipher_prot(user, 7_000).await.unwrap();
            let CipherProtSync::Posted(ProtApplyOutcome::Applied(entry)) = &synced else {
                panic!("{synced:?}");
            };
            assert_eq!(entry.key, prot_key_cipher_upgrade(user, 50, base, 2));
            assert_eq!(entry.amount, 16_500);
            assert_eq!(balance(&db, user).await, 33_000);
        });
    }

    #[tokio::test]
    async fn postings_and_cipher_syncs_run_concurrently_without_a_hang() {
        database_test!(|db| async move {
            create_prot_test_indexes(&db).await;
            let user = "01USERY0000000000000000000";
            let base = "01BASEY0000000000000000000";
            assert!(db
                .insert_cipher_membership(&membership(user, 51, &[base]))
                .await
                .unwrap());

            // The Reference driver's lock order is what this exercises; the
            // MongoDB leg runs fewer tasks so write conflicts stay cheap
            let tasks = match &db {
                crate::Database::Reference(_) => 50,
                #[cfg(feature = "mongodb")]
                crate::Database::MongoDb(_) => 10,
            };

            let credits: Vec<ProtPosting> = (0..tasks)
                .map(|i| admin_posting(user, &format!("c{i}"), 10, 1_000 + i))
                .collect();
            let postings = join_all(credits.iter().map(|posting| db.apply_prot_posting(posting)));
            let syncs = join_all((0..tasks).map(|i| db.sync_cipher_prot(user, 2_000 + i)));

            let (posted, synced) = tokio::time::timeout(
                std::time::Duration::from_secs(60),
                futures::future::join(postings, syncs),
            )
            .await
            .expect("postings and syncs deadlocked");

            for result in posted {
                assert!(result.is_ok(), "{result:?}");
            }
            for result in synced {
                assert!(result.is_ok(), "{result:?}");
            }

            // One founding grant, posted once
            let rows = db.fetch_prot_entries_by_membership(base).await.unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(cipher_prot_posted(&rows), 16_500);
            assert_eq!(balance(&db, user).await, 16_500 + 10 * tasks);
            assert_eq!(membership_version(&db, user).await, 1);
        });
    }

    /// Start a transaction that writes `user_id`'s membership row and leave
    /// it open: until it is aborted, any transaction writing the row fails
    /// with a write conflict (labelled TransientTransactionError)
    #[cfg(feature = "mongodb")]
    async fn hold_membership_row(
        mongo: &crate::MongoDb,
        user_id: &str,
    ) -> ::mongodb::ClientSession {
        let mut holder = mongo.start_session().await.unwrap();
        holder.start_transaction().await.unwrap();
        let held = mongo
            .col::<bson::Document>("cipher_memberships")
            .update_one(
                bson::doc! { "_id": user_id },
                bson::doc! { "$set": { "held": true } },
            )
            .session(&mut holder)
            .await
            .unwrap();
        assert_eq!(held.modified_count, 1);
        holder
    }

    /// The Cipher sync's and clawback's version bumps hit a write conflict
    /// for as long as another transaction holds the membership row. That is
    /// transient: the transaction is re-run until the row is free, within
    /// the time budget, instead of using up the state retries at once.
    #[tokio::test]
    async fn a_write_conflict_on_the_membership_is_retried_until_it_clears() {
        database_test!(|db| async move {
            match &db {
                // No transactions here: the map lock serializes the writers
                crate::Database::Reference(_) => {}
                #[cfg(feature = "mongodb")]
                crate::Database::MongoDb(mongo) => {
                    create_prot_test_indexes(&db).await;
                    let user = "01USERZ0000000000000000000";
                    let base = "01BASEZ0000000000000000000";
                    let mut m = membership(user, 52, &[base]);
                    assert!(db.insert_cipher_membership(&m).await.unwrap());
                    let hold = std::time::Duration::from_secs(1);

                    // Upward: held for a second, then let go
                    let mut holder = hold_membership_row(mongo, user).await;
                    let (synced, ()) =
                        futures::future::join(db.sync_cipher_prot(user, 5_000), async {
                            tokio::time::sleep(hold).await;
                            holder.abort_transaction().await.unwrap();
                        })
                        .await;
                    let synced = synced.unwrap();
                    let CipherProtSync::Posted(ProtApplyOutcome::Applied(entry)) = &synced else {
                        panic!("{synced:?}");
                    };
                    assert_eq!(entry.amount, 16_500);
                    assert_eq!(balance(&db, user).await, 16_500);
                    assert_eq!(membership_version(&db, user).await, 1);

                    // Downward, the same way
                    m.revoked_at = Some(6_000);
                    m.revoke_reason = Some(crate::CipherRevokeReason::Refund);
                    assert!(db.update_cipher_membership_if_version(&m, 1).await.unwrap());
                    let mut holder = hold_membership_row(mongo, user).await;
                    let (clawed, ()) =
                        futures::future::join(db.clawback_cipher_prot(user, base, 6_001), async {
                            tokio::time::sleep(hold).await;
                            holder.abort_transaction().await.unwrap();
                        })
                        .await;
                    let clawed = clawed.unwrap();
                    let Some(ProtApplyOutcome::Applied(entry)) = &clawed else {
                        panic!("{clawed:?}");
                    };
                    assert_eq!(entry.amount, 16_500);
                    assert_eq!(balance(&db, user).await, 0);
                    assert_eq!(membership_version(&db, user).await, 3);

                    // One grant and one clawback; the held writes never landed
                    let rows = db.fetch_prot_entries_by_membership(base).await.unwrap();
                    assert_eq!(rows.len(), 2);
                    let stored = mongo
                        .col::<bson::Document>("cipher_memberships")
                        .find_one(bson::doc! { "_id": user })
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(!stored.contains_key("held"));
                }
            }
        });
    }
}
