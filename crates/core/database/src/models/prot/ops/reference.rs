use std::collections::HashMap;

use revolt_models::v0;
use revolt_result::Result;

use crate::models::cipher_memberships::bump_cipher_membership_version_locked;
use crate::{
    is_prot_system_account, prot_key_clawback, prot_payload_hash, prot_user_account,
    CipherProtSync, ProtAccount, ProtAmount, ProtApplyOutcome, ProtGoal, ProtLedgerEntry,
    ProtPledge, ProtPosting, ReferenceDb,
};

use super::{
    build_prot_entry, cipher_base, clawback_hold_posting, clawback_total, duplicate_outcome,
    forfeit_hold_posting, forfeit_posting, goal_after_hold_debit, held_purchase_net, hold_short,
    hold_state_broken, invalid_posting, is_older_incarnation, plan_cipher_clawback,
    plan_cipher_sync, plan_pledge_drain, pledge_after_hold_debit, purchase_clawback_posting,
    resolve_prot_amount, run_forfeit_passes, state_retries_exhausted, validate_prot_posting,
    AbstractProtLedger, CipherSyncPlan,
};

// Lock order (every method): cipher_memberships -> prot_ledger -> prot_accounts
// -> prot_pledges -> prot_goals (the complete order is in models/prot/mod.rs).
// A method takes every map it needs at its start, in this order, holds them to
// the end, and never calls another trait method while holding one (the mutex
// is not re-entrant). Every check runs before the first mutation, so a refused
// call changes nothing: that is this driver's transaction.

/// A posting whose checks all passed, ready to write
pub(in crate::models::prot) struct PreparedPosting {
    pub(in crate::models::prot) entry: ProtLedgerEntry,
    /// New balance of the debit side; None for a system debit
    pub(in crate::models::prot) debit_balance: Option<i64>,
    /// New balance of the credit side; None for a system credit
    pub(in crate::models::prot) credit_balance: Option<i64>,
}

/// The checks of a posting against the locked maps
pub(in crate::models::prot) enum Prepared {
    /// A row already has this key (payload not compared yet)
    Duplicate(ProtLedgerEntry),
    New(PreparedPosting),
}

pub(in crate::models::prot) fn balance_of(
    accounts: &HashMap<String, ProtAccount>,
    id: &str,
) -> i64 {
    accounts.get(id).map_or(0, |account| account.balance)
}

/// Section 4.2 steps 1-3 and 5 without writing anything. The posting must
/// already be validated.
pub(in crate::models::prot) fn prepare_locked(
    ledger: &HashMap<String, ProtLedgerEntry>,
    accounts: &HashMap<String, ProtAccount>,
    posting: &ProtPosting,
    payload_hash: &str,
) -> Result<Prepared> {
    if let Some(stored) = ledger.get(&posting.key) {
        return Ok(Prepared::Duplicate(stored.clone()));
    }

    let debit_system = is_prot_system_account(&posting.debit);
    let credit_system = is_prot_system_account(&posting.credit);
    let resolved = resolve_prot_amount(posting, balance_of(accounts, &posting.debit))?;

    // Carry-forward 3 (S5b 10.3): a debit only ever moves Prot out of an
    // account that has a document, as in MongoDB's post_in_session
    if !debit_system && resolved.amount > 0 && !accounts.contains_key(&posting.debit) {
        log::error!(
            "PROT_DEBIT_WITHOUT_ACCOUNT key={:?} debit={:?}",
            posting.key,
            posting.debit
        );
        return Err(create_error!(InternalError));
    }

    let debit_balance = if debit_system {
        None
    } else {
        Some(
            balance_of(accounts, &posting.debit)
                .checked_sub(resolved.amount)
                .ok_or_else(|| invalid_posting(posting, "debit balance overflows"))?,
        )
    };
    let credit_balance = if credit_system {
        None
    } else {
        Some(
            balance_of(accounts, &posting.credit)
                .checked_add(resolved.amount)
                .ok_or_else(|| invalid_posting(posting, "credit balance overflows"))?,
        )
    };

    // Mirrors MongoDB's conditional decrement (amount > 0 only; a zero-amount
    // posting just touches the account): never below the floor
    if resolved.amount > 0 && debit_balance.is_some_and(|balance| balance < posting.debit_floor) {
        return Err(create_error!(InsufficientProt {
            needed: resolved.amount,
            available: resolved.available
        }));
    }

    Ok(Prepared::New(PreparedPosting {
        entry: build_prot_entry(posting, &resolved, payload_hash),
        debit_balance,
        credit_balance,
    }))
}

/// Write a prepared posting: the row, then both non-system sides, each with
/// `version += 1` and `updated_at = created_at`, zero-amount postings included.
/// Cannot fail.
pub(in crate::models::prot) fn commit_locked(
    ledger: &mut HashMap<String, ProtLedgerEntry>,
    accounts: &mut HashMap<String, ProtAccount>,
    prepared: PreparedPosting,
) -> ProtLedgerEntry {
    let PreparedPosting {
        entry,
        debit_balance,
        credit_balance,
    } = prepared;

    for (id, balance) in [
        (&entry.debit, debit_balance),
        (&entry.credit, credit_balance),
    ] {
        if let Some(balance) = balance {
            let account = accounts.entry(id.clone()).or_insert_with(|| ProtAccount {
                id: id.clone(),
                currency: v0::ProtCurrency::Prot,
                balance: 0,
                version: 0,
                updated_at: entry.created_at,
            });
            account.balance = balance;
            account.version = account.version.saturating_add(1);
            account.updated_at = entry.created_at;
        }
    }

    ledger.insert(entry.key.clone(), entry.clone());
    entry
}

/// Rows of one membership incarnation, oldest first
fn membership_rows(
    ledger: &HashMap<String, ProtLedgerEntry>,
    base_order_id: &str,
) -> Vec<ProtLedgerEntry> {
    let mut rows: Vec<ProtLedgerEntry> = ledger
        .values()
        .filter(|row| row.reference.membership_order_id.as_deref() == Some(base_order_id))
        .cloned()
        .collect();
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    rows
}

/// In-transaction twin of `held_purchase_prot` (audit 11), for the
/// contribute and pledge lock sections: the held figure under their locks
pub(in crate::models::prot) fn held_purchase_prot_locked(
    ledger: &HashMap<String, ProtLedgerEntry>,
    user_id: &str,
    since_ms: i64,
) -> i64 {
    held_purchase_net(ledger.values(), user_id, since_ms)
}

/// The maps a clawback or a pledge forfeit reads, locked by the caller
struct HoldMaps<'a> {
    ledger: &'a HashMap<String, ProtLedgerEntry>,
    accounts: &'a HashMap<String, ProtAccount>,
    pledges: &'a HashMap<String, ProtPledge>,
    goals: &'a HashMap<String, ProtGoal>,
}

/// The writes of one lock section that posts more than once (a clawback
/// that drains held pledges, a pledge forfeit). Each posting is checked and
/// applied to this section's copies of the accounts, pledges and goals it
/// touches; nothing reaches the locked maps until `apply`, after every check
/// has passed, so a refusal part way changes nothing.
#[derive(Default)]
struct LockedWrites {
    rows: Vec<ProtLedgerEntry>,
    accounts: HashMap<String, ProtAccount>,
    pledges: HashMap<String, ProtPledge>,
    goals: HashMap<String, ProtGoal>,
}

impl LockedWrites {
    /// A goal as this section sees it: its own copy, else the stored one
    fn goal(&self, maps: &HoldMaps, id: &str) -> Option<ProtGoal> {
        self.goals.get(id).or_else(|| maps.goals.get(id)).cloned()
    }

    /// Check one posting against this section's view of its two sides and
    /// record it; `shortfall` overrides the stored shortfall (10.1 step d).
    /// Every caller reads its own key first, so a key that is already taken
    /// here is a broken invariant: refused.
    fn post(
        &mut self,
        maps: &HoldMaps,
        posting: &ProtPosting,
        shortfall: Option<i64>,
    ) -> Result<ProtLedgerEntry> {
        validate_prot_posting(posting)?;
        if maps.ledger.contains_key(&posting.key)
            || self.rows.iter().any(|row| row.key == posting.key)
        {
            log::error!("PROT_DUPLICATE_KEY_IN_SECTION key={:?}", posting.key);
            return Err(create_error!(InternalError));
        }
        let payload_hash = prot_payload_hash(posting);

        let mut view: HashMap<String, ProtAccount> = HashMap::new();
        for id in [&posting.debit, &posting.credit] {
            if let Some(account) = self.accounts.get(id).or_else(|| maps.accounts.get(id)) {
                view.insert(id.clone(), account.clone());
            }
        }

        // The key was checked above against both the ledger and this section
        let mut prepared = match prepare_locked(&HashMap::new(), &view, posting, &payload_hash)? {
            Prepared::New(prepared) => prepared,
            Prepared::Duplicate(_) => return Err(create_error!(InternalError)),
        };
        if shortfall.is_some() {
            prepared.entry.shortfall = shortfall;
        }

        let entry = commit_locked(&mut HashMap::new(), &mut view, prepared);
        self.accounts.extend(view);
        self.rows.push(entry.clone());
        Ok(entry)
    }

    /// Write everything this section recorded. Cannot fail.
    fn apply(
        self,
        ledger: &mut HashMap<String, ProtLedgerEntry>,
        accounts: &mut HashMap<String, ProtAccount>,
        pledges: &mut HashMap<String, ProtPledge>,
        goals: &mut HashMap<String, ProtGoal>,
    ) {
        for row in self.rows {
            ledger.insert(row.key.clone(), row);
        }
        accounts.extend(self.accounts);
        pledges.extend(self.pledges);
        goals.extend(self.goals);
    }
}

/// One way out of a hold (10.1 step c, 9.6): the posting (None = nothing
/// left to move), the pledge to `emptied` once nothing is left, and the
/// goal's `pledged_total`, in this section's view (a second pledge of the
/// same goal sees the first one's write). A hold that holds less than its
/// pledges, or a pledge without its goal, is a broken invariant: refused.
fn hold_debit_locked(
    maps: &HoldMaps,
    writes: &mut LockedWrites,
    pledge: &ProtPledge,
    posting: Option<&ProtPosting>,
    emptied: v0::ProtPledgeState,
    now: i64,
) -> Result<Option<ProtLedgerEntry>> {
    let x = match posting.map(|posting| posting.amount) {
        None => 0,
        Some(ProtAmount::Exact(x)) => x,
        Some(ProtAmount::UpTo(_) | ProtAmount::All) => {
            return Err(hold_state_broken("pledge", &pledge.id));
        }
    };
    let next_pledge = pledge_after_hold_debit(pledge, x, emptied, now)
        .ok_or_else(|| hold_state_broken("pledge", &pledge.id))?;

    let mut entry = None;
    if let Some(posting) = posting {
        let goal = writes
            .goal(maps, &pledge.goal_id)
            .ok_or_else(|| hold_state_broken("goal", &pledge.goal_id))?;
        let next_goal = goal_after_hold_debit(&goal, x, now)
            .ok_or_else(|| hold_state_broken("goal", &goal.id))?;

        let written = writes
            .post(maps, posting, None)
            .map_err(|error| hold_short(posting, error))?;
        writes.goals.insert(next_goal.id.clone(), next_goal);
        entry = Some(written);
    }

    writes.pledges.insert(next_pledge.id.clone(), next_pledge);
    Ok(entry)
}

/// The pledge drain (10.1 step c, `drain_held_pledges_in` in MongoDB): up
/// to `rest` from the buyer's Held pledges, newest first, each through
/// `clawback-hold:`. Returns the rows recorded; what they moved is the
/// drain's recovery.
fn drain_held_pledges_locked(
    maps: &HoldMaps,
    writes: &mut LockedWrites,
    user_id: &str,
    order_id: &str,
    rest: i64,
    now: i64,
) -> Result<Vec<ProtLedgerEntry>> {
    let held: Vec<ProtPledge> = maps
        .pledges
        .values()
        .filter(|pledge| pledge.user_id == user_id && pledge.state == v0::ProtPledgeState::Held)
        .cloned()
        .collect();

    let mut rows = Vec::new();
    for (pledge, x) in plan_pledge_drain(rest, &held) {
        let posting = clawback_hold_posting(order_id, pledge, x, now);
        rows.extend(hold_debit_locked(
            maps,
            writes,
            pledge,
            Some(&posting),
            v0::ProtPledgeState::ClawedBack,
            now,
        )?);
    }
    Ok(rows)
}

/// A reversal's clawback (10.1, `claw_back_in` in MongoDB): (a) `total` is
/// what the `clawback:` posting asks for; (b) the wallet gives `w =
/// min(total, balance)`; (c) the held pledges give up to `total - w`; (d) the
/// `clawback:` row records `amount = w`, `requested = total` and the FINAL
/// shortfall `total - w - drained`. Never a tank.
fn claw_back_locked(
    maps: &HoldMaps,
    writes: &mut LockedWrites,
    posting: &ProtPosting,
    user_id: &str,
    order_id: &str,
    now: i64,
) -> Result<ProtLedgerEntry> {
    let total = clawback_total(posting)?;
    let from_wallet = total.min(balance_of(maps.accounts, &posting.debit).max(0));

    let drained = if total > from_wallet {
        drain_held_pledges_locked(maps, writes, user_id, order_id, total - from_wallet, now)?
    } else {
        Vec::new()
    };
    let from_pledges = drained
        .iter()
        .fold(0_i64, |sum, row| sum.saturating_add(row.amount));

    let entry = writes.post(maps, posting, Some(total - from_wallet - from_pledges))?;
    if entry.amount != from_wallet {
        log::error!(
            "PROT_CLAWBACK_SPLIT_MISMATCH key={:?} wallet={from_wallet} posted={}",
            posting.key,
            entry.amount
        );
        return Err(create_error!(InternalError));
    }
    Ok(entry)
}

impl ReferenceDb {
    /// One forfeit pass under the locks: n = 1 + Forfeit rows debiting the wallet
    async fn prot_forfeit_pass(&self, user_id: &str, now: i64) -> Result<ProtApplyOutcome> {
        let mut ledger = self.prot_ledger.lock().await;
        let mut accounts = self.prot_accounts.lock().await;

        let wallet = prot_user_account(user_id);
        let passes = ledger
            .values()
            .filter(|row| row.kind == v0::ProtEntryKind::Forfeit && row.debit == wallet)
            .count() as u64;
        let posting = forfeit_posting(user_id, passes + 1, now);
        validate_prot_posting(&posting)?;
        let payload_hash = prot_payload_hash(&posting);

        match prepare_locked(&ledger, &accounts, &posting, &payload_hash)? {
            Prepared::Duplicate(stored) => {
                duplicate_outcome(&posting.key, &payload_hash, Some(stored))
            }
            Prepared::New(prepared) => Ok(ProtApplyOutcome::Applied(commit_locked(
                &mut ledger,
                &mut accounts,
                prepared,
            ))),
        }
    }
}

#[async_trait]
impl AbstractProtLedger for ReferenceDb {
    async fn apply_prot_posting(&self, posting: &ProtPosting) -> Result<ProtApplyOutcome> {
        validate_prot_posting(posting)?;
        let payload_hash = prot_payload_hash(posting);

        let mut ledger = self.prot_ledger.lock().await;
        let mut accounts = self.prot_accounts.lock().await;

        // A duplicate key is decided before the floor: a replay of a posting
        // that was applied is AlreadyApplied whatever the balance is now
        match prepare_locked(&ledger, &accounts, posting, &payload_hash)? {
            Prepared::Duplicate(stored) => {
                duplicate_outcome(&posting.key, &payload_hash, Some(stored))
            }
            Prepared::New(prepared) => Ok(ProtApplyOutcome::Applied(commit_locked(
                &mut ledger,
                &mut accounts,
                prepared,
            ))),
        }
    }

    async fn fetch_prot_account(&self, account_id: &str) -> Result<Option<ProtAccount>> {
        let accounts = self.prot_accounts.lock().await;
        Ok(accounts.get(account_id).cloned())
    }

    async fn fetch_prot_entry_by_key(&self, key: &str) -> Result<Option<ProtLedgerEntry>> {
        let ledger = self.prot_ledger.lock().await;
        Ok(ledger.get(key).cloned())
    }

    async fn fetch_prot_entries_by_account(
        &self,
        account_id: &str,
        before_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ProtLedgerEntry>> {
        let ledger = self.prot_ledger.lock().await;
        let mut rows: Vec<ProtLedgerEntry> = ledger
            .values()
            .filter(|row| row.debit == account_id || row.credit == account_id)
            .filter(|row| before_id.is_none_or(|before| row.id.as_str() < before))
            .cloned()
            .collect();

        // ULIDs sort by time: newest first
        rows.sort_by(|a, b| b.id.cmp(&a.id));
        rows.truncate(limit.clamp(1, 100) as usize);
        Ok(rows)
    }

    async fn fetch_prot_entries_by_order(&self, order_id: &str) -> Result<Vec<ProtLedgerEntry>> {
        let ledger = self.prot_ledger.lock().await;
        let mut rows: Vec<ProtLedgerEntry> = ledger
            .values()
            .filter(|row| row.reference.order_id.as_deref() == Some(order_id))
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(rows)
    }

    async fn fetch_prot_entries_by_membership(
        &self,
        base_order_id: &str,
    ) -> Result<Vec<ProtLedgerEntry>> {
        let ledger = self.prot_ledger.lock().await;
        Ok(membership_rows(&ledger, base_order_id))
    }

    async fn sum_prot_credits_since(
        &self,
        account_id: &str,
        kinds: &[v0::ProtEntryKind],
        since: i64,
    ) -> Result<i64> {
        let ledger = self.prot_ledger.lock().await;
        Ok(ledger
            .values()
            .filter(|row| {
                row.credit == account_id && kinds.contains(&row.kind) && row.created_at >= since
            })
            .fold(0_i64, |total, row| total.saturating_add(row.amount)))
    }

    async fn sync_cipher_prot(&self, user_id: &str, now: i64) -> Result<CipherProtSync> {
        // The whole sync runs under the three locks, so the membership read,
        // the posting and the version bump cannot interleave with an engine
        // write or another sync (no step-0 pre-check is needed here)
        let mut memberships = self.cipher_memberships.lock().await;
        let mut ledger = self.prot_ledger.lock().await;
        let mut accounts = self.prot_accounts.lock().await;

        let Some(m) = memberships.get(user_id).cloned() else {
            return Ok(CipherProtSync::Nothing);
        };
        let Some(base) = cipher_base(user_id, &m) else {
            return Ok(CipherProtSync::Nothing);
        };
        let rows = membership_rows(&ledger, base);

        let posting = match plan_cipher_sync(user_id, &m, base, &rows, now) {
            CipherSyncPlan::Done(sync) => return Ok(sync),
            CipherSyncPlan::Post(posting) => posting,
        };
        validate_prot_posting(&posting)?;
        let payload_hash = prot_payload_hash(&posting);

        let prepared = match prepare_locked(&ledger, &accounts, &posting, &payload_hash)? {
            Prepared::Duplicate(stored) if stored.payload_hash == payload_hash => {
                return Ok(CipherProtSync::Posted(ProtApplyOutcome::AlreadyApplied(
                    stored,
                )));
            }
            // MongoDB re-runs the body here; under these locks a re-run reads
            // the same state, so it could only end the same way
            Prepared::Duplicate(_) => {
                return Err(state_retries_exhausted("sync_cipher_prot", user_id, None));
            }
            Prepared::New(prepared) => prepared,
        };

        // Only a posting bumps the membership version. The version was read
        // under this lock, so the compare-and-swap cannot miss; it runs before
        // the ledger write so a miss would still change nothing.
        if !bump_cipher_membership_version_locked(&mut memberships, user_id, m.version) {
            return Err(state_retries_exhausted("sync_cipher_prot", user_id, None));
        }

        Ok(CipherProtSync::Posted(ProtApplyOutcome::Applied(
            commit_locked(&mut ledger, &mut accounts, prepared),
        )))
    }

    async fn clawback_cipher_prot(
        &self,
        user_id: &str,
        order_id: &str,
        now: i64,
    ) -> Result<Option<ProtApplyOutcome>> {
        let mut memberships = self.cipher_memberships.lock().await;
        let mut ledger = self.prot_ledger.lock().await;
        let mut accounts = self.prot_accounts.lock().await;
        let mut pledges = self.prot_pledges.lock().await;
        let mut goals = self.prot_goals.lock().await;

        // One key per reversal: a row for this order settles it, whatever
        // state it was computed from
        if let Some(stored) = ledger.get(&prot_key_clawback(order_id)) {
            return Ok(Some(ProtApplyOutcome::AlreadyApplied(stored.clone())));
        }

        let Some(m) = memberships.get(user_id).cloned() else {
            return Ok(None);
        };
        let Some(base) = cipher_base(user_id, &m) else {
            return Ok(None);
        };
        if is_older_incarnation(user_id, order_id, base) {
            return Ok(None);
        }

        let rows = membership_rows(&ledger, base);
        let Some(posting) = plan_cipher_clawback(user_id, order_id, &m, base, &rows, now) else {
            return Ok(None);
        };
        validate_prot_posting(&posting)?;

        // S5b: what the wallet no longer holds is drained from the member's
        // held pledges under the same locks (10.1). Checked in full before
        // anything is written.
        let mut writes = LockedWrites::default();
        let entry = claw_back_locked(
            &HoldMaps {
                ledger: &ledger,
                accounts: &accounts,
                pledges: &pledges,
                goals: &goals,
            },
            &mut writes,
            &posting,
            user_id,
            order_id,
            now,
        )?;

        if !bump_cipher_membership_version_locked(&mut memberships, user_id, m.version) {
            return Err(state_retries_exhausted(
                "clawback_cipher_prot",
                user_id,
                None,
            ));
        }

        writes.apply(&mut ledger, &mut accounts, &mut pledges, &mut goals);
        Ok(Some(ProtApplyOutcome::Applied(entry)))
    }

    async fn forfeit_prot_wallet(
        &self,
        user_id: &str,
        now: i64,
    ) -> Result<Option<ProtApplyOutcome>> {
        let wallet = prot_user_account(user_id);
        let wallet = wallet.as_str();
        run_forfeit_passes(
            user_id,
            || self.prot_forfeit_pass(user_id, now),
            || async move {
                let account = self.fetch_prot_account(wallet).await?;
                Ok::<i64, revolt_result::Error>(account.map_or(0, |account| account.balance))
            },
        )
        .await
    }

    async fn clawback_prot_purchase(
        &self,
        user_id: &str,
        order_id: &str,
        amount: i64,
        now: i64,
    ) -> Result<ProtApplyOutcome> {
        let posting = purchase_clawback_posting(user_id, order_id, amount, now);

        let mut ledger = self.prot_ledger.lock().await;
        let mut accounts = self.prot_accounts.lock().await;
        let mut pledges = self.prot_pledges.lock().await;
        let mut goals = self.prot_goals.lock().await;

        // One key per reversal: a settled reversal writes nothing
        if let Some(stored) = ledger.get(&posting.key) {
            return Ok(ProtApplyOutcome::AlreadyApplied(stored.clone()));
        }
        validate_prot_posting(&posting)?;

        let mut writes = LockedWrites::default();
        let entry = claw_back_locked(
            &HoldMaps {
                ledger: &ledger,
                accounts: &accounts,
                pledges: &pledges,
                goals: &goals,
            },
            &mut writes,
            &posting,
            user_id,
            order_id,
            now,
        )?;

        writes.apply(&mut ledger, &mut accounts, &mut pledges, &mut goals);
        Ok(ProtApplyOutcome::Applied(entry))
    }

    async fn held_purchase_prot(&self, user_id: &str, since_ms: i64) -> Result<i64> {
        let ledger = self.prot_ledger.lock().await;
        Ok(held_purchase_prot_locked(&ledger, user_id, since_ms))
    }

    async fn sum_held_prot_pledges(&self, user_id: &str) -> Result<i64> {
        let pledges = self.prot_pledges.lock().await;
        Ok(pledges
            .values()
            .filter(|pledge| pledge.user_id == user_id && pledge.state == v0::ProtPledgeState::Held)
            .fold(0_i64, |sum, pledge| sum.saturating_add(pledge.remaining)))
    }

    async fn forfeit_held_prot_pledges(
        &self,
        user_id: &str,
        now: i64,
    ) -> Result<Vec<ProtLedgerEntry>> {
        let mut written = Vec::new();

        // One lock section per pledge, newest first. Each one takes a pledge
        // out of Held (or refuses), so this ends.
        loop {
            let mut ledger = self.prot_ledger.lock().await;
            let mut accounts = self.prot_accounts.lock().await;
            let mut pledges = self.prot_pledges.lock().await;
            let mut goals = self.prot_goals.lock().await;

            let Some(pledge) = pledges
                .values()
                .filter(|pledge| {
                    pledge.user_id == user_id && pledge.state == v0::ProtPledgeState::Held
                })
                .max_by(|a, b| a.id.cmp(&b.id))
                .cloned()
            else {
                return Ok(written);
            };

            let posting = (pledge.remaining > 0).then(|| forfeit_hold_posting(&pledge, now));
            let mut writes = LockedWrites::default();
            let entry = hold_debit_locked(
                &HoldMaps {
                    ledger: &ledger,
                    accounts: &accounts,
                    pledges: &pledges,
                    goals: &goals,
                },
                &mut writes,
                &pledge,
                posting.as_ref(),
                v0::ProtPledgeState::Forfeited,
                now,
            )?;

            writes.apply(&mut ledger, &mut accounts, &mut pledges, &mut goals);
            written.extend(entry);
        }
    }
}
