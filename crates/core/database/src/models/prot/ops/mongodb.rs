use std::sync::OnceLock;
use std::time::{Duration, Instant};

use bson::Document;
use futures::TryStreamExt;
use mongodb::options::{ReadConcern, WriteConcern};
use mongodb::ClientSession;
use revolt_models::v0;
use revolt_result::{ErrorType, Result};

use crate::{
    is_prot_system_account, prot_key_clawback, prot_payload_hash, prot_user_account,
    AbstractCipherMemberships, CipherProtSync, MongoDb, ProtAccount, ProtAmount, ProtApplyOutcome,
    ProtLedgerEntry, ProtPosting,
};

use super::{
    build_prot_entry, cipher_base, duplicate_outcome, forfeit_posting, is_older_incarnation,
    plan_cipher_clawback, plan_cipher_sync, resolve_prot_amount, run_forfeit_passes,
    state_retries_exhausted, validate_prot_posting, AbstractProtLedger, CipherSyncPlan,
    PROT_STATE_RETRIES,
};

static LEDGER: &str = "prot_ledger";
static ACCOUNTS: &str = "prot_accounts";
static MEMBERSHIPS: &str = "cipher_memberships";

/// Every retry of one transaction (body or commit) stops this long after the
/// first attempt started
const PROT_TXN_BUDGET: Duration = Duration::from_secs(10);

/// The pause before the first re-run of a transaction body; it doubles on
/// each re-run up to PROT_TXN_BACKOFF_MAX
const PROT_TXN_BACKOFF_MIN: Duration = Duration::from_millis(5);
const PROT_TXN_BACKOFF_MAX: Duration = Duration::from_millis(100);

/// Set once a `hello` reply showed a replica set; a negative or failed probe
/// is not cached, so it is asked again on the next write
static PROT_REPLICA_SET_OK: OnceLock<()> = OnceLock::new();

/// Err(ProtReplicaSetRequired) unless `hello` reports a replica set.
/// Prot writes need transactions, which need a replica set; a write never
/// falls back to a non-transactional path. Called lazily by the first Prot
/// write of the process (reads never call it).
async fn ensure_replica_set(db: &MongoDb) -> Result<()> {
    if PROT_REPLICA_SET_OK.get().is_some() {
        return Ok(());
    }

    match db
        .0
        .database("admin")
        .run_command(doc! { "hello": 1_i32 })
        .await
    {
        Ok(reply) if hello_reports_replica_set(&reply) => {
            let _ = PROT_REPLICA_SET_OK.set(());
            Ok(())
        }
        Ok(_) => {
            log::error!("PROT_REPLICA_SET_REQUIRED: MongoDB is not a replica set member; Prot writes are refused");
            Err(create_error!(ProtReplicaSetRequired))
        }
        Err(error) => {
            log::error!("PROT_REPLICA_SET_REQUIRED: the hello probe failed: {error}");
            Err(create_error!(ProtReplicaSetRequired))
        }
    }
}

/// Whether a `hello` reply describes a replica-set member (`setName` is a string)
fn hello_reports_replica_set(reply: &bson::Document) -> bool {
    reply.get_str("setName").is_ok()
}

/// 11000, as a write error or a command error
fn is_duplicate_key(error: &mongodb::error::Error) -> bool {
    match &*error.kind {
        mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(write_error)) => {
            write_error.code == 11000
        }
        mongodb::error::ErrorKind::Command(command_error) => command_error.code == 11000,
        _ => false,
    }
}

/// The whole transaction can be re-run
fn is_transient(error: &mongodb::error::Error) -> bool {
    error.contains_label(mongodb::error::TRANSIENT_TRANSACTION_ERROR)
}

/// The commit may or may not have applied; the commit alone can be re-run
fn is_unknown_commit(error: &mongodb::error::Error) -> bool {
    error.contains_label(mongodb::error::UNKNOWN_TRANSACTION_COMMIT_RESULT)
}

/// The pause before re-run number `rerun` (1 for the first) of a transaction
/// body: PROT_TXN_BACKOFF_MIN doubling up to PROT_TXN_BACKOFF_MAX, of which a
/// random half (`jitter` in 0..1) is kept so racing writers spread out, and
/// never longer than the `remaining` budget
fn prot_txn_backoff(rerun: u32, remaining: Duration, jitter: f64) -> Duration {
    let doubled =
        PROT_TXN_BACKOFF_MIN.saturating_mul(2_u32.saturating_pow(rerun.saturating_sub(1)));
    let ceiling = doubled.min(PROT_TXN_BACKOFF_MAX);
    ceiling
        .mul_f64(0.5 + jitter.clamp(0.0, 1.0) / 2.0)
        .min(remaining)
}

/// Why a transaction body stopped without a result
enum TxnAbort {
    /// A driver error; a transient one re-runs the body, any other is a
    /// database error naming `operation` on `collection`
    Mongo {
        error: Box<mongodb::error::Error>,
        operation: &'static str,
        collection: &'static str,
    },
    /// The snapshot was stale (an UpTo/All debit that matched nothing, an
    /// account upsert that raced its own insert): re-run the body
    Stale,
    /// The ledger insert hit an existing key: never re-run; the caller reads
    /// the stored row OUTSIDE the transaction
    DuplicateKey { key: String, payload_hash: String },
    /// The membership moved under a Cipher posting (its version bump matched
    /// nothing): the caller re-runs up to PROT_STATE_RETRIES times. A driver
    /// error of the bump is `Mongo` (a write conflict is transient).
    StateMoved,
    /// A business refusal, returned as is
    Refused(revolt_result::Error),
}

/// How a transaction ended, for the caller to act on
enum TxnEnd<T> {
    Committed(T),
    DuplicateKey { key: String, payload_hash: String },
    StateMoved,
}

fn mongo_abort(
    operation: &'static str,
    collection: &'static str,
) -> impl FnOnce(mongodb::error::Error) -> TxnAbort {
    move |error| TxnAbort::Mongo {
        error: Box::new(error),
        operation,
        collection,
    }
}

/// The body of one transaction: every read and write uses `session`
#[async_trait]
trait ProtTxnBody: Sync {
    type Output: Send;

    async fn run(
        &self,
        db: &MongoDb,
        session: &mut ClientSession,
    ) -> std::result::Result<Self::Output, TxnAbort>;
}

/// Run `body` in one transaction (snapshot reads, majority writes), each
/// attempt from a fresh session, until PROT_TXN_BUDGET from the first attempt:
/// - a transient body error: abort, re-run the body;
/// - a commit error with UnknownTransactionCommitResult: re-run the commit only;
///   with TransientTransactionError: re-run the body;
/// - a duplicate ledger key or a moved membership: abort, hand it to the caller;
/// - a business refusal: abort, return it;
/// - budget exhausted: a database error.
///
/// Each re-run of the body waits `prot_txn_backoff` first, so writers
/// conflicting on one wallet or membership do not retry in lockstep.
async fn run_prot_transaction<B: ProtTxnBody>(db: &MongoDb, body: &B) -> Result<TxnEnd<B::Output>> {
    let started = Instant::now();
    let mut reruns: u32 = 0;

    'attempt: loop {
        if reruns > 0 {
            let remaining = PROT_TXN_BUDGET.saturating_sub(started.elapsed());
            tokio::time::sleep(prot_txn_backoff(reruns, remaining, rand::random::<f64>())).await;
        }
        reruns = reruns.saturating_add(1);

        if started.elapsed() >= PROT_TXN_BUDGET {
            log::error!("PROT_TXN_BUDGET_EXHAUSTED: the transaction kept conflicting");
            return Err(create_database_error!("transaction", LEDGER));
        }

        let mut session = db
            .start_session()
            .await
            .map_err(|_| create_database_error!("start_session", LEDGER))?;
        session
            .start_transaction()
            .read_concern(ReadConcern::snapshot())
            .write_concern(WriteConcern::majority())
            .await
            .map_err(|_| create_database_error!("start_transaction", LEDGER))?;

        let output = match body.run(db, &mut session).await {
            Ok(output) => output,
            Err(abort) => {
                // Errors ignored: the server may already have aborted it
                let _ = session.abort_transaction().await;
                match abort {
                    TxnAbort::Mongo { error, .. } if is_transient(&error) => continue 'attempt,
                    TxnAbort::Mongo {
                        error,
                        operation,
                        collection,
                    } => {
                        log::error!(
                            "PROT_TXN_FAILED op={operation} collection={collection}: {error}"
                        );
                        return Err(create_database_error!(operation, collection));
                    }
                    TxnAbort::Stale => continue 'attempt,
                    TxnAbort::DuplicateKey { key, payload_hash } => {
                        return Ok(TxnEnd::DuplicateKey { key, payload_hash })
                    }
                    TxnAbort::StateMoved => return Ok(TxnEnd::StateMoved),
                    TxnAbort::Refused(error) => return Err(error),
                }
            }
        };

        loop {
            match session.commit_transaction().await {
                Ok(()) => return Ok(TxnEnd::Committed(output)),
                Err(error) if is_unknown_commit(&error) => {
                    // Retried below. Giving up here leaves the outcome unknown;
                    // the caller's retry finds the row under its key if it applied.
                    if started.elapsed() >= PROT_TXN_BUDGET {
                        log::error!("PROT_TXN_COMMIT_UNKNOWN: {error}");
                        return Err(create_database_error!("commit_transaction", LEDGER));
                    }
                }
                Err(error) if is_transient(&error) => continue 'attempt,
                Err(error) => {
                    log::error!("PROT_TXN_COMMIT_FAILED: {error}");
                    return Err(create_database_error!("commit_transaction", LEDGER));
                }
            }
        }
    }
}

/// Upsert-increment one account: `balance += delta`, `version += 1`,
/// `updated_at = now`
async fn upsert_account(
    db: &MongoDb,
    session: &mut ClientSession,
    account_id: &str,
    delta: i64,
    now: i64,
) -> std::result::Result<(), TxnAbort> {
    db.col::<Document>(ACCOUNTS)
        .update_one(
            doc! { "_id": account_id },
            doc! {
                "$inc": { "balance": delta, "version": 1_i64 },
                "$set": { "updated_at": now },
                "$setOnInsert": { "currency": "Prot" }
            },
        )
        .upsert(true)
        .session(&mut *session)
        .await
        .map(|_| ())
        .map_err(|error| {
            // Two transactions creating the same account: the loser re-runs
            // and finds the document
            if is_duplicate_key(&error) {
                TxnAbort::Stale
            } else {
                TxnAbort::Mongo {
                    error: Box::new(error),
                    operation: "update_one",
                    collection: ACCOUNTS,
                }
            }
        })
}

/// One posting inside `session` (section 4.2 steps 1-4); the posting must
/// already be validated. Returns the row written.
async fn post_in_session(
    db: &MongoDb,
    session: &mut ClientSession,
    posting: &ProtPosting,
    payload_hash: &str,
) -> std::result::Result<ProtLedgerEntry, TxnAbort> {
    let debit_system = is_prot_system_account(&posting.debit);
    let debit_account = if debit_system {
        None
    } else {
        db.col::<ProtAccount>(ACCOUNTS)
            .find_one(doc! { "_id": &posting.debit })
            .session(&mut *session)
            .await
            .map_err(mongo_abort("find_one", ACCOUNTS))?
    };

    let resolved = resolve_prot_amount(
        posting,
        debit_account.as_ref().map_or(0, |account| account.balance),
    )
    .map_err(TxnAbort::Refused)?;
    let entry = build_prot_entry(posting, &resolved, payload_hash);

    // The unique index on `key` is what stops a posting from being applied twice
    if let Err(error) = db
        .col::<ProtLedgerEntry>(LEDGER)
        .insert_one(&entry)
        .session(&mut *session)
        .await
    {
        return Err(if is_duplicate_key(&error) {
            TxnAbort::DuplicateKey {
                key: posting.key.clone(),
                payload_hash: payload_hash.to_string(),
            }
        } else {
            TxnAbort::Mongo {
                error: Box::new(error),
                operation: "insert_one",
                collection: LEDGER,
            }
        });
    }

    let now = posting.created_at;
    if !debit_system {
        if resolved.amount > 0 && debit_account.is_some() {
            // Conditional on the floor, in the same write that moves the balance
            let result = db
                .col::<Document>(ACCOUNTS)
                .update_one(
                    doc! {
                        "_id": &posting.debit,
                        "balance": { "$gte": resolved.required }
                    },
                    doc! {
                        "$inc": { "balance": -resolved.amount, "version": 1_i64 },
                        "$set": { "updated_at": now }
                    },
                )
                .session(&mut *session)
                .await
                .map_err(mongo_abort("update_one", ACCOUNTS))?;

            if result.matched_count == 0 {
                return Err(match posting.amount {
                    ProtAmount::Exact(needed) => {
                        TxnAbort::Refused(create_error!(InsufficientProt {
                            needed,
                            available: resolved.available
                        }))
                    }
                    // UpTo / All were sized from a stale snapshot
                    ProtAmount::UpTo(_) | ProtAmount::All => TxnAbort::Stale,
                });
            }
        } else {
            // Amount 0: touch (version and updated_at only). Amount > 0 with no
            // document is only possible below a negative floor (an S5b tank),
            // which the floor allows by construction
            upsert_account(db, session, &posting.debit, -resolved.amount, now).await?;
        }
    }

    if !is_prot_system_account(&posting.credit) {
        upsert_account(db, session, &posting.credit, resolved.amount, now).await?;
    }

    Ok(entry)
}

/// Rows of one membership incarnation inside `session`, oldest first
async fn membership_rows_in(
    db: &MongoDb,
    session: &mut ClientSession,
    base_order_id: &str,
) -> std::result::Result<Vec<ProtLedgerEntry>, TxnAbort> {
    let mut cursor = db
        .col::<ProtLedgerEntry>(LEDGER)
        .find(doc! { "ref.membership_order_id": base_order_id })
        .sort(doc! { "_id": 1_i32 })
        .session(&mut *session)
        .await
        .map_err(mongo_abort("find", LEDGER))?;

    let mut rows = Vec::new();
    while let Some(row) = cursor.next(&mut *session).await {
        rows.push(row.map_err(mongo_abort("find", LEDGER))?);
    }
    Ok(rows)
}

/// Map the result of a membership version bump in the session
fn bumped(
    result: std::result::Result<bool, mongodb::error::Error>,
) -> std::result::Result<(), TxnAbort> {
    match result {
        Ok(true) => Ok(()),
        // The version moved or the row is gone: re-run on the new state
        Ok(false) => Err(TxnAbort::StateMoved),
        // A write conflict (another writer changed the row after this
        // transaction's snapshot) is transient: the body is re-run within
        // the budget. Any other driver error is a database error.
        Err(error) => Err(mongo_abort("update_one", MEMBERSHIPS)(error)),
    }
}

/// apply_prot_posting
struct PostingBody {
    posting: ProtPosting,
    payload_hash: String,
}

#[async_trait]
impl ProtTxnBody for PostingBody {
    type Output = ProtLedgerEntry;

    async fn run(
        &self,
        db: &MongoDb,
        session: &mut ClientSession,
    ) -> std::result::Result<ProtLedgerEntry, TxnAbort> {
        post_in_session(db, session, &self.posting, &self.payload_hash).await
    }
}

/// sync_cipher_prot, section 6.1 steps 1-6
struct CipherSyncBody {
    user_id: String,
    now: i64,
}

#[async_trait]
impl ProtTxnBody for CipherSyncBody {
    type Output = CipherProtSync;

    async fn run(
        &self,
        db: &MongoDb,
        session: &mut ClientSession,
    ) -> std::result::Result<CipherProtSync, TxnAbort> {
        let m = db
            .fetch_cipher_membership_in(session, &self.user_id)
            .await
            .map_err(mongo_abort("find_one", MEMBERSHIPS))?;
        let Some(m) = m else {
            return Ok(CipherProtSync::Nothing);
        };
        let Some(base) = cipher_base(&self.user_id, &m) else {
            return Ok(CipherProtSync::Nothing);
        };
        let rows = membership_rows_in(db, session, base).await?;

        let posting = match plan_cipher_sync(&self.user_id, &m, base, &rows, self.now) {
            CipherSyncPlan::Done(sync) => return Ok(sync),
            CipherSyncPlan::Post(posting) => posting,
        };
        validate_prot_posting(&posting).map_err(TxnAbort::Refused)?;
        let payload_hash = prot_payload_hash(&posting);
        let entry = post_in_session(db, session, &posting, &payload_hash).await?;

        // Serializes this posting against every engine membership write
        bumped(
            db.bump_cipher_membership_version_in(session, &self.user_id, m.version)
                .await,
        )?;

        Ok(CipherProtSync::Posted(ProtApplyOutcome::Applied(entry)))
    }
}

/// clawback_cipher_prot, section 6.2 steps 1-3
struct CipherClawbackBody {
    user_id: String,
    order_id: String,
    now: i64,
}

#[async_trait]
impl ProtTxnBody for CipherClawbackBody {
    type Output = Option<ProtApplyOutcome>;

    async fn run(
        &self,
        db: &MongoDb,
        session: &mut ClientSession,
    ) -> std::result::Result<Option<ProtApplyOutcome>, TxnAbort> {
        // As in step 0: a row for this order settles it. Read again here so
        // a body re-run after a commit that did land reports that row.
        let stored = db
            .col::<ProtLedgerEntry>(LEDGER)
            .find_one(doc! { "key": prot_key_clawback(&self.order_id) })
            .session(&mut *session)
            .await
            .map_err(mongo_abort("find_one", LEDGER))?;
        if let Some(stored) = stored {
            return Ok(Some(ProtApplyOutcome::AlreadyApplied(stored)));
        }

        let m = db
            .fetch_cipher_membership_in(session, &self.user_id)
            .await
            .map_err(mongo_abort("find_one", MEMBERSHIPS))?;
        let Some(m) = m else {
            return Ok(None);
        };
        let Some(base) = cipher_base(&self.user_id, &m) else {
            return Ok(None);
        };
        if is_older_incarnation(&self.user_id, &self.order_id, base) {
            return Ok(None);
        }

        let rows = membership_rows_in(db, session, base).await?;
        let Some(posting) =
            plan_cipher_clawback(&self.user_id, &self.order_id, &m, base, &rows, self.now)
        else {
            return Ok(None);
        };
        validate_prot_posting(&posting).map_err(TxnAbort::Refused)?;
        let payload_hash = prot_payload_hash(&posting);
        let entry = post_in_session(db, session, &posting, &payload_hash).await?;

        bumped(
            db.bump_cipher_membership_version_in(session, &self.user_id, m.version)
                .await,
        )?;

        Ok(Some(ProtApplyOutcome::Applied(entry)))
    }
}

/// One forfeit pass: n = 1 + Forfeit rows debiting the wallet, counted here
struct ForfeitPassBody {
    user_id: String,
    now: i64,
}

#[async_trait]
impl ProtTxnBody for ForfeitPassBody {
    type Output = ProtLedgerEntry;

    async fn run(
        &self,
        db: &MongoDb,
        session: &mut ClientSession,
    ) -> std::result::Result<ProtLedgerEntry, TxnAbort> {
        let passes = db
            .col::<Document>(LEDGER)
            .count_documents(doc! {
                "debit": prot_user_account(&self.user_id),
                "kind": v0::ProtEntryKind::Forfeit.as_str()
            })
            .session(&mut *session)
            .await
            .map_err(mongo_abort("count_documents", LEDGER))?;

        let posting = forfeit_posting(&self.user_id, passes + 1, self.now);
        validate_prot_posting(&posting).map_err(TxnAbort::Refused)?;
        let payload_hash = prot_payload_hash(&posting);
        post_in_session(db, session, &posting, &payload_hash).await
    }
}

impl MongoDb {
    /// One forfeit pass in its own transaction
    async fn prot_forfeit_pass(&self, user_id: &str, now: i64) -> Result<ProtApplyOutcome> {
        ensure_replica_set(self).await?;

        let body = ForfeitPassBody {
            user_id: user_id.to_string(),
            now,
        };
        match run_prot_transaction(self, &body).await? {
            TxnEnd::Committed(entry) => Ok(ProtApplyOutcome::Applied(entry)),
            TxnEnd::DuplicateKey { key, payload_hash } => {
                let stored = self.fetch_prot_entry_by_key(&key).await?;
                duplicate_outcome(&key, &payload_hash, stored)
            }
            // The body never refers to a membership
            TxnEnd::StateMoved => Err(state_retries_exhausted(
                "forfeit_prot_wallet",
                user_id,
                None,
            )),
        }
    }
}

#[async_trait]
impl AbstractProtLedger for MongoDb {
    async fn apply_prot_posting(&self, posting: &ProtPosting) -> Result<ProtApplyOutcome> {
        validate_prot_posting(posting)?;
        ensure_replica_set(self).await?;

        let payload_hash = prot_payload_hash(posting);
        let body = PostingBody {
            posting: posting.clone(),
            payload_hash: payload_hash.clone(),
        };

        match run_prot_transaction(self, &body).await {
            Ok(TxnEnd::Committed(entry)) => Ok(ProtApplyOutcome::Applied(entry)),
            Ok(TxnEnd::DuplicateKey { key, payload_hash }) => {
                let stored = self.fetch_prot_entry_by_key(&key).await?;
                duplicate_outcome(&key, &payload_hash, stored)
            }
            // The body never refers to a membership
            Ok(TxnEnd::StateMoved) => Err(create_database_error!("transaction", LEDGER)),
            // A replay of a posting that was applied is AlreadyApplied
            // whatever the balance is now, as in the Reference driver (which
            // checks the key before the floor)
            Err(error) if matches!(error.error_type, ErrorType::InsufficientProt { .. }) => {
                match self.fetch_prot_entry_by_key(&posting.key).await? {
                    Some(stored) => duplicate_outcome(&posting.key, &payload_hash, Some(stored)),
                    None => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }

    async fn fetch_prot_account(&self, account_id: &str) -> Result<Option<ProtAccount>> {
        self.col::<ProtAccount>(ACCOUNTS)
            .find_one(doc! { "_id": account_id })
            .await
            .map_err(|_| create_database_error!("find_one", ACCOUNTS))
    }

    async fn fetch_prot_entry_by_key(&self, key: &str) -> Result<Option<ProtLedgerEntry>> {
        self.col::<ProtLedgerEntry>(LEDGER)
            .find_one(doc! { "key": key })
            .await
            .map_err(|_| create_database_error!("find_one", LEDGER))
    }

    async fn fetch_prot_entries_by_account(
        &self,
        account_id: &str,
        before_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ProtLedgerEntry>> {
        let mut filter = doc! {
            "$or": [
                { "debit": account_id },
                { "credit": account_id }
            ]
        };
        if let Some(before_id) = before_id {
            filter.insert("_id", doc! { "$lt": before_id });
        }

        // A row that fails to decode fails the page: a ledger read never
        // silently skips a row
        self.col::<ProtLedgerEntry>(LEDGER)
            .find(filter)
            .sort(doc! { "_id": -1_i32 })
            .limit(limit.clamp(1, 100))
            .await
            .map_err(|_| create_database_error!("find", LEDGER))?
            .try_collect()
            .await
            .map_err(|_| create_database_error!("find", LEDGER))
    }

    async fn fetch_prot_entries_by_order(&self, order_id: &str) -> Result<Vec<ProtLedgerEntry>> {
        self.col::<ProtLedgerEntry>(LEDGER)
            .find(doc! { "ref.order_id": order_id })
            .sort(doc! { "_id": 1_i32 })
            .await
            .map_err(|_| create_database_error!("find", LEDGER))?
            .try_collect()
            .await
            .map_err(|_| create_database_error!("find", LEDGER))
    }

    async fn fetch_prot_entries_by_membership(
        &self,
        base_order_id: &str,
    ) -> Result<Vec<ProtLedgerEntry>> {
        self.col::<ProtLedgerEntry>(LEDGER)
            .find(doc! { "ref.membership_order_id": base_order_id })
            .sort(doc! { "_id": 1_i32 })
            .await
            .map_err(|_| create_database_error!("find", LEDGER))?
            .try_collect()
            .await
            .map_err(|_| create_database_error!("find", LEDGER))
    }

    async fn sum_prot_credits_since(
        &self,
        account_id: &str,
        kinds: &[v0::ProtEntryKind],
        since: i64,
    ) -> Result<i64> {
        if kinds.is_empty() {
            return Ok(0);
        }

        let kinds: Vec<&str> = kinds.iter().map(|kind| kind.as_str()).collect();
        let rows: Vec<ProtLedgerEntry> = self
            .col::<ProtLedgerEntry>(LEDGER)
            .find(doc! {
                "credit": account_id,
                "kind": { "$in": kinds },
                "created_at": { "$gte": since }
            })
            .await
            .map_err(|_| create_database_error!("find", LEDGER))?
            .try_collect()
            .await
            .map_err(|_| create_database_error!("find", LEDGER))?;

        Ok(rows
            .iter()
            .fold(0_i64, |total, row| total.saturating_add(row.amount)))
    }

    async fn sync_cipher_prot(&self, user_id: &str, now: i64) -> Result<CipherProtSync> {
        // Step 0, read-only and outside any transaction: a membership with
        // nothing owed returns here without opening one (and without the
        // replica-set check), so the hourly sweep is a read per membership
        let Some(m) = self.fetch_cipher_membership(user_id).await? else {
            return Ok(CipherProtSync::Nothing);
        };
        let Some(base) = cipher_base(user_id, &m) else {
            return Ok(CipherProtSync::Nothing);
        };
        let rows = self.fetch_prot_entries_by_membership(base).await?;
        if let CipherSyncPlan::Done(sync) = plan_cipher_sync(user_id, &m, base, &rows, now) {
            return Ok(sync);
        }

        ensure_replica_set(self).await?;
        let body = CipherSyncBody {
            user_id: user_id.to_string(),
            now,
        };

        for _ in 0..PROT_STATE_RETRIES {
            match run_prot_transaction(self, &body).await? {
                TxnEnd::Committed(sync) => return Ok(sync),
                TxnEnd::DuplicateKey { key, payload_hash } => {
                    match self.fetch_prot_entry_by_key(&key).await? {
                        Some(stored) if stored.payload_hash == payload_hash => {
                            return Ok(CipherProtSync::Posted(ProtApplyOutcome::AlreadyApplied(
                                stored,
                            )));
                        }
                        // A racing sync posted from an older state: re-run on
                        // the state it left (not ProtIdempotencyConflict)
                        Some(_) => {}
                        None => {
                            log::error!("PROT_DUPLICATE_KEY_WITHOUT_ROW key={key:?}");
                            return Err(create_database_error!("find_one", LEDGER));
                        }
                    }
                }
                TxnEnd::StateMoved => {}
            }
        }

        Err(state_retries_exhausted("sync_cipher_prot", user_id, None))
    }

    async fn clawback_cipher_prot(
        &self,
        user_id: &str,
        order_id: &str,
        now: i64,
    ) -> Result<Option<ProtApplyOutcome>> {
        // Step 0, outside any transaction. A reversal with nothing posted
        // above the target never opens one, so a missing replica set can
        // never strand a Cipher refund while nothing was ever posted.
        let key = prot_key_clawback(order_id);
        if let Some(stored) = self.fetch_prot_entry_by_key(&key).await? {
            return Ok(Some(ProtApplyOutcome::AlreadyApplied(stored)));
        }
        let Some(m) = self.fetch_cipher_membership(user_id).await? else {
            return Ok(None);
        };
        let Some(base) = cipher_base(user_id, &m) else {
            return Ok(None);
        };
        if is_older_incarnation(user_id, order_id, base) {
            return Ok(None);
        }
        let rows = self.fetch_prot_entries_by_membership(base).await?;
        if plan_cipher_clawback(user_id, order_id, &m, base, &rows, now).is_none() {
            return Ok(None);
        }

        ensure_replica_set(self).await?;
        let body = CipherClawbackBody {
            user_id: user_id.to_string(),
            order_id: order_id.to_string(),
            now,
        };

        for _ in 0..PROT_STATE_RETRIES {
            match run_prot_transaction(self, &body).await? {
                TxnEnd::Committed(outcome) => return Ok(outcome),
                // One key per reversal: as in step 0, a row for this order
                // settles it, whatever state it was computed from
                TxnEnd::DuplicateKey { key, .. } => {
                    return match self.fetch_prot_entry_by_key(&key).await? {
                        Some(stored) => Ok(Some(ProtApplyOutcome::AlreadyApplied(stored))),
                        None => {
                            log::error!("PROT_DUPLICATE_KEY_WITHOUT_ROW key={key:?}");
                            Err(create_database_error!("find_one", LEDGER))
                        }
                    };
                }
                TxnEnd::StateMoved => {}
            }
        }

        Err(state_retries_exhausted(
            "clawback_cipher_prot",
            user_id,
            None,
        ))
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use revolt_models::v0;

    use crate::{CipherMembership, CipherProtSync, ProtApplyOutcome};

    use super::{
        hello_reports_replica_set, prot_txn_backoff, run_prot_transaction, CipherClawbackBody,
        TxnEnd,
    };

    /// Whether `duration` is `ms` milliseconds, give or take float rounding
    fn is_ms(duration: Duration, ms: f64) -> bool {
        (duration.as_secs_f64() * 1_000.0 - ms).abs() < 0.001
    }

    #[test]
    fn the_backoff_doubles_up_to_its_cap_and_never_outlasts_the_budget() {
        let plenty = Duration::from_secs(10);

        // Full jitter keeps the whole step, none keeps half of it
        assert!(is_ms(prot_txn_backoff(1, plenty, 1.0), 5.0));
        assert!(is_ms(prot_txn_backoff(1, plenty, 0.0), 2.5));
        assert!(is_ms(prot_txn_backoff(2, plenty, 1.0), 10.0));
        assert!(is_ms(prot_txn_backoff(5, plenty, 1.0), 80.0));
        assert!(is_ms(prot_txn_backoff(6, plenty, 1.0), 100.0));
        assert!(is_ms(prot_txn_backoff(6, plenty, 0.0), 50.0));
        assert!(is_ms(prot_txn_backoff(u32::MAX, plenty, 1.0), 100.0));

        // A jitter out of range is clamped
        assert!(is_ms(prot_txn_backoff(6, plenty, 7.0), 100.0));
        assert!(is_ms(prot_txn_backoff(6, plenty, -7.0), 50.0));

        // Never past the end of the budget
        assert_eq!(
            prot_txn_backoff(6, Duration::from_millis(3), 1.0),
            Duration::from_millis(3)
        );
        assert_eq!(prot_txn_backoff(6, Duration::ZERO, 0.5), Duration::ZERO);
    }

    /// Step 1 of the clawback body reads `clawback:{order_id}` in the session
    /// first: a body re-run after a commit that did land (its result lost)
    /// reports the stored row, as step 0 does, not `None`
    #[tokio::test]
    async fn a_clawback_body_re_run_after_its_commit_reports_the_stored_row() {
        database_test!(|db| async move {
            let crate::Database::MongoDb(mongo) = &db else {
                return;
            };
            for collection in crate::PROT_COLLECTIONS {
                mongo.db().create_collection(collection).await.ok();
            }
            crate::create_prot_indexes(&mongo.db()).await.unwrap();

            let user = "01USERF5000000000000000000";
            let base = "01BASEF5000000000000000000";
            let mut m = CipherMembership {
                user_id: user.to_string(),
                number: 53,
                tier: v0::CipherTier::T99,
                prot_grant: 16_500,
                orders: vec![base.to_string()],
                disputed_orders: vec![],
                granted_at: 1_000,
                revoked_at: None,
                revoke_reason: None,
                prot_posted_at: None,
                version: 0,
            };
            assert!(db.insert_cipher_membership(&m).await.unwrap());
            assert!(matches!(
                db.sync_cipher_prot(user, 5_000).await.unwrap(),
                CipherProtSync::Posted(ProtApplyOutcome::Applied(_))
            ));
            m.revoked_at = Some(6_000);
            m.revoke_reason = Some(crate::CipherRevokeReason::Refund);
            assert!(db.update_cipher_membership_if_version(&m, 1).await.unwrap());

            let clawed = db.clawback_cipher_prot(user, base, 6_001).await.unwrap();
            let Some(ProtApplyOutcome::Applied(entry)) = &clawed else {
                panic!("{clawed:?}");
            };

            // The body again, as the helper re-runs it
            let body = CipherClawbackBody {
                user_id: user.to_string(),
                order_id: base.to_string(),
                now: 6_002,
            };
            match run_prot_transaction(mongo, &body).await.unwrap() {
                TxnEnd::Committed(outcome) => {
                    assert_eq!(
                        outcome,
                        Some(ProtApplyOutcome::AlreadyApplied(entry.clone()))
                    )
                }
                TxnEnd::DuplicateKey { key, .. } => panic!("duplicate key {key}"),
                TxnEnd::StateMoved => panic!("state moved"),
            }

            // Nothing written by the re-run
            assert_eq!(
                db.fetch_prot_entries_by_membership(base)
                    .await
                    .unwrap()
                    .len(),
                2
            );
            assert_eq!(
                db.fetch_cipher_membership(user)
                    .await
                    .unwrap()
                    .unwrap()
                    .version,
                3
            );
        });
    }

    #[test]
    fn hello_reports_replica_set_only_for_a_string_set_name() {
        // A replica-set member: Prot writes go ahead
        assert!(hello_reports_replica_set(&bson::doc! {
            "setName": "rs0",
            "isWritablePrimary": true
        }));

        // A standalone server: refused with ProtReplicaSetRequired
        assert!(!hello_reports_replica_set(&bson::doc! {
            "isWritablePrimary": true,
            "maxWireVersion": 21_i32
        }));

        // Not a string
        assert!(!hello_reports_replica_set(&bson::doc! { "setName": 1_i32 }));
    }
}
