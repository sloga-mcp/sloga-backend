use std::collections::HashMap;

use revolt_models::v0;
use revolt_result::Result;

use crate::models::cipher_memberships::bump_cipher_membership_version_locked;
use crate::{
    is_prot_system_account, prot_key_clawback, prot_payload_hash, prot_user_account,
    CipherProtSync, ProtAccount, ProtApplyOutcome, ProtLedgerEntry, ProtPosting, ReferenceDb,
};

use super::{
    build_prot_entry, cipher_base, duplicate_outcome, forfeit_posting, invalid_posting,
    is_older_incarnation, plan_cipher_clawback, plan_cipher_sync, resolve_prot_amount,
    run_forfeit_passes, state_retries_exhausted, validate_prot_posting, AbstractProtLedger,
    CipherSyncPlan,
};

// Lock order (every method): cipher_memberships -> prot_ledger -> prot_accounts.
// A method takes every map it needs at its start, in this order, holds them to
// the end, and never calls another trait method while holding one (the mutex
// is not re-entrant). Every check runs before the first mutation, so a refused
// call changes nothing: that is this driver's transaction.

/// A posting whose checks all passed, ready to write
struct PreparedPosting {
    entry: ProtLedgerEntry,
    /// New balance of the debit side; None for a system debit
    debit_balance: Option<i64>,
    /// New balance of the credit side; None for a system credit
    credit_balance: Option<i64>,
}

/// The checks of a posting against the locked maps
enum Prepared {
    /// A row already has this key (payload not compared yet)
    Duplicate(ProtLedgerEntry),
    New(PreparedPosting),
}

fn balance_of(accounts: &HashMap<String, ProtAccount>, id: &str) -> i64 {
    accounts.get(id).map_or(0, |account| account.balance)
}

/// Section 4.2 steps 1-3 and 5 without writing anything. The posting must
/// already be validated.
fn prepare_locked(
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
fn commit_locked(
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
        let payload_hash = prot_payload_hash(&posting);

        let prepared = match prepare_locked(&ledger, &accounts, &posting, &payload_hash)? {
            // Checked above, under the same lock
            Prepared::Duplicate(stored) => {
                return Ok(Some(ProtApplyOutcome::AlreadyApplied(stored)));
            }
            Prepared::New(prepared) => prepared,
        };

        if !bump_cipher_membership_version_locked(&mut memberships, user_id, m.version) {
            return Err(state_retries_exhausted(
                "clawback_cipher_prot",
                user_id,
                None,
            ));
        }

        Ok(Some(ProtApplyOutcome::Applied(commit_locked(
            &mut ledger,
            &mut accounts,
            prepared,
        ))))
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
}
