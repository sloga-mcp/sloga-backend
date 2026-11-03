//! MongoDB driver for the Prot fuel tanks, goals and pledges (S5b).
//!
//! Every write is ONE transaction run by S5a's `run_prot_transaction`
//! (snapshot reads, majority writes, the whole body re-run on
//! TransientTransactionError, which covers write conflicts) and every posting
//! goes through `post_in_session`. A state change is a compare-and-set on the
//! document's `version` (a pledge leaving its hold also on `state` and the
//! `remaining` read), and every transaction that moves a tank's Prot writes
//! the tank document, so the tank serializes burns, contributions, tier
//! changes, settlements and terminations.
//!
//! A duplicate ledger key in a body that writes ONE posting has S5a's
//! meaning: the stored row is read outside the transaction. In a body that
//! writes several (capture, returns, settlement) it means a racing run
//! committed: the body is re-run, finds the goal or tank state moved and
//! returns what that state says.
//!
//! The tank-backed entitlement (source Prot or Crowdfund) is written by these
//! transactions (state and `slot_cap`, contracts 6.1, BR1). An `AdminGrant`
//! row is never matched, the `Deleted` tombstone never moves, and nothing here
//! writes `channels.protected`.

use std::collections::{BTreeMap, HashMap, HashSet};

use bson::{Bson, Document};
use futures::TryStreamExt;
use iso8601_timestamp::Timestamp;
use mongodb::ClientSession;
use revolt_models::v0;
use revolt_result::{ErrorType, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::{
    channel_seats_used, check_channel_protectable, plan_prot_settlement, plan_tank_day,
    plan_unseated_returns, prot_burn_amount, prot_day_start_ms, prot_hold_account, prot_hours_left,
    prot_key_burn, prot_key_contrib, prot_key_forfeit_tank, prot_key_launch_return,
    prot_key_pledge, prot_key_pledge_capture, prot_key_pledge_return, prot_key_pledge_withdraw,
    prot_key_settle, prot_key_tier, prot_key_writeoff, prot_next_day, prot_notice_key,
    prot_payload_hash, prot_pro_rata, prot_tank_account, prot_tank_target_key, prot_user_account,
    prot_utc_day, seat_list_channel_server, AbstractProtLedger, Channel, ChannelEntitlement,
    ChannelEntitlementSource, ChannelEntitlementState, ChannelSeat, MongoDb, ProtAccount,
    ProtAmount, ProtBurnOutcome, ProtContributeInput, ProtContributeOutcome, ProtContributorPref,
    ProtDayPlan, ProtGoal, ProtGoalCloseOutcome, ProtLaunchInput, ProtLedgerEntry, ProtLot,
    ProtNotice, ProtNoticeKind, ProtPledge, ProtPledgeInput, ProtPledgeOutcome, ProtPosting,
    ProtPurgeCounts, ProtRef, ProtRuntime, ProtSettleCause, ProtSettlement, ProtTank,
    ProtTankRules, ProtTankTarget, ProtTermination, ProtTierChangeInput, PROT_ACTOR_CLOCK,
    PROT_ACTOR_GOALS, PROT_ACTOR_SETTLEMENT, PROT_OPEN_GOAL_STATES, PROT_RUNTIME_ID,
    PROT_SLOT_TIERS, PROT_SYS_BURNED, PROT_SYS_FORFEITED, PROT_SYS_WRITEOFF,
};

use super::super::ops::mongodb::{
    ensure_replica_set, is_duplicate_key, mongo_abort, post_in_session, run_prot_transaction,
    ProtTxnBody, TxnAbort, TxnEnd, ACCOUNTS, LEDGER,
};
use super::super::ops::{duplicate_outcome, validate_prot_posting, PROT_STATE_RETRIES};
use super::AbstractProtTanks;

static TANKS: &str = "prot_tanks";
static GOALS: &str = "prot_goals";
static PLEDGES: &str = "prot_pledges";
static NOTICES: &str = "prot_notices";
static RUNTIME: &str = "prot_runtime";
static PREFS: &str = "prot_contributor_prefs";
static CHANNELS: &str = "channels";
static SERVERS: &str = "servers";
static USERS: &str = "users";
static ENTITLEMENTS: &str = "channel_entitlements";
static SEATS: &str = "channel_seats";
static MESSAGES: &str = "messages";
static GROUPS: &str = "mls_groups";
static COMMITS: &str = "mls_commits";
static JOIN_INTENTS: &str = "mls_join_intents";
static E2EE_QUEUE: &str = "e2ee_queue";

/// Serialized `MlsGroupKind::Text`
const KIND_TEXT: &str = "Text";

const DAY_MS: i64 = 86_400_000;

/// One step of a transaction body
type Step<T> = std::result::Result<T, TxnAbort>;

/// Serialized `ProtGoalKind` (Mongo filters)
fn goal_kind_name(kind: v0::ProtGoalKind) -> &'static str {
    match kind {
        v0::ProtGoalKind::Launch => "Launch",
        v0::ProtGoalKind::Upgrade => "Upgrade",
    }
}

/// Serialized `ChannelEntitlementState` (Mongo filters and `$set`)
fn entitlement_state_name(state: &ChannelEntitlementState) -> &'static str {
    match state {
        ChannelEntitlementState::Active => "Active",
        ChannelEntitlementState::Grace => "Grace",
        ChannelEntitlementState::Frozen => "Frozen",
        ChannelEntitlementState::Deleted => "Deleted",
    }
}

/// Serialized `ChannelEntitlementSource` (Mongo filters)
fn entitlement_source_name(source: &ChannelEntitlementSource) -> &'static str {
    match source {
        ChannelEntitlementSource::AdminGrant => "AdminGrant",
        ChannelEntitlementSource::Prot => "Prot",
        ChannelEntitlementSource::Crowdfund => "Crowdfund",
    }
}

fn refuse(error: revolt_result::Error) -> TxnAbort {
    TxnAbort::Refused(error)
}

/// A state no S5b write leaves behind: logged, refused with InternalError
fn inconsistent(id: &str, what: &str) -> TxnAbort {
    log::error!("PROT_TANK_INCONSISTENT id={id}: {what}");
    TxnAbort::Refused(create_error!(InternalError))
}

/// Every tank has an account document from its launch (10.3)
fn tank_without_account(tank_id: &str) -> TxnAbort {
    log::error!("PROT_TANK_WITHOUT_ACCOUNT tank={tank_id}");
    TxnAbort::Refused(create_error!(InternalError))
}

/// A body whose state kept moving under it
fn retries_exhausted(operation: &str, id: &str) -> revolt_result::Error {
    log::error!("PROT_STATE_RETRIES_EXHAUSTED op={operation} id={id} retries={PROT_STATE_RETRIES}");
    create_database_error!("transaction", LEDGER)
}

/// The insert reported the key as taken, yet no row has it
fn duplicate_without_row(key: &str) -> revolt_result::Error {
    log::error!("PROT_DUPLICATE_KEY_WITHOUT_ROW key={key:?}");
    create_database_error!("find_one", LEDGER)
}

fn timestamp_at(ms: i64) -> Step<Timestamp> {
    Timestamp::UNIX_EPOCH
        .checked_add(iso8601_timestamp::Duration::milliseconds(ms))
        .ok_or_else(|| refuse(create_error!(InternalError)))
}

fn days_ms(days: u32) -> i64 {
    i64::from(days).saturating_mul(DAY_MS)
}

fn day_start(day: &str) -> Step<i64> {
    prot_day_start_ms(day).map_err(refuse)
}

fn next_day(day: &str) -> Step<String> {
    prot_next_day(day).map_err(refuse)
}

/// Clamp a page size the way the Reference driver does (at least one row)
fn page_size(limit: i64) -> i64 {
    limit.max(1)
}

fn tank_channel(tank: &ProtTank) -> Option<&str> {
    match &tank.target {
        ProtTankTarget::Channel { channel_id } => Some(channel_id.as_str()),
        // S10
        ProtTankTarget::Server { .. } => None,
    }
}

/// `protected: true` on a channel document (a capture needs exactly that)
fn is_protected(channel: &Document) -> bool {
    matches!(channel.get("protected"), Some(Bson::Boolean(true)))
}

/// Anything but an absent, null or false `protected`. An abandon refuses on
/// it, so a malformed flag fails closed (never strands a protected channel).
fn may_be_protected(channel: &Document) -> bool {
    !matches!(
        channel.get("protected"),
        None | Some(Bson::Null) | Some(Bson::Boolean(false))
    )
}

fn open_goal_state_names() -> Vec<&'static str> {
    PROT_OPEN_GOAL_STATES
        .iter()
        .map(|state| state.as_str())
        .collect()
}

/// `_id` of a contributor preference (BR10)
fn pref_id(server_id: &str, user_id: &str) -> String {
    format!("{server_id}:{user_id}")
}

/// A user id from a `user:{id}` account
fn wallet_user(account_id: &str) -> Option<&str> {
    account_id.strip_prefix("user:")
}

/// The tank-backed entitlement of a channel in a live state: an AdminGrant
/// row never matches, and the Deleted tombstone never moves (6.1)
fn tank_entitlement_filter(channel_id: &str) -> Document {
    doc! {
        "channel_id": channel_id,
        "source": {
            "$in": [
                entitlement_source_name(&ChannelEntitlementSource::Prot),
                entitlement_source_name(&ChannelEntitlementSource::Crowdfund),
            ]
        },
        "state": {
            "$in": [
                entitlement_state_name(&ChannelEntitlementState::Active),
                entitlement_state_name(&ChannelEntitlementState::Grace),
                entitlement_state_name(&ChannelEntitlementState::Frozen),
            ]
        }
    }
}

fn version_filter(id: &str, version: u64) -> Document {
    doc! { "_id": id, "version": version as i64 }
}

/// An Exact posting with debit floor 0 and no reason
fn exact_posting(
    key: String,
    kind: v0::ProtEntryKind,
    (debit, credit): (String, String),
    amount: i64,
    actor: &str,
    reference: ProtRef,
    now: i64,
) -> ProtPosting {
    ProtPosting {
        key,
        kind,
        debit,
        credit,
        amount: ProtAmount::Exact(amount),
        debit_floor: 0,
        actor: actor.to_string(),
        reference,
        reason: None,
        created_at: now,
    }
}

fn tank_ref(tank_id: &str) -> ProtRef {
    ProtRef {
        tank_id: Some(tank_id.to_string()),
        ..Default::default()
    }
}

fn pledge_ref(pledge: &ProtPledge, tank_id: Option<&str>) -> ProtRef {
    ProtRef {
        goal_id: Some(pledge.goal_id.clone()),
        pledge_id: Some(pledge.id.clone()),
        tank_id: tank_id.map(str::to_string),
        ..Default::default()
    }
}

/// `burn:{tank}:{day}` (7.2): tank -> sys:burned down to the tank's floor
fn burn_posting(tank_id: &str, day: &str, amount: i64, floor: i64, now: i64) -> ProtPosting {
    ProtPosting {
        debit_floor: floor,
        ..exact_posting(
            prot_key_burn(tank_id, day),
            v0::ProtEntryKind::Burn,
            (prot_tank_account(tank_id), PROT_SYS_BURNED.to_string()),
            amount,
            PROT_ACTOR_CLOCK,
            ProtRef {
                tank_id: Some(tank_id.to_string()),
                day: Some(day.to_string()),
                ..Default::default()
            },
            now,
        )
    }
}

/// `contrib:` (8.8): wallet -> tank, floored at the held figure (D17)
fn contribution_posting(input: &ProtContributeInput, held: i64) -> ProtPosting {
    ProtPosting {
        debit_floor: held,
        ..exact_posting(
            prot_key_contrib(&input.user_id, &input.tank_id, &input.nonce),
            v0::ProtEntryKind::Contribution,
            (
                prot_user_account(&input.user_id),
                prot_tank_account(&input.tank_id),
            ),
            input.amount,
            &input.user_id,
            tank_ref(&input.tank_id),
            input.now,
        )
    }
}

// ---------------------------------------------------------------------------
// Reads and writes inside the session
// ---------------------------------------------------------------------------

async fn find_one_in<T>(
    db: &MongoDb,
    session: &mut ClientSession,
    collection: &'static str,
    filter: Document,
) -> Step<Option<T>>
where
    T: DeserializeOwned + Send + Sync + Unpin,
{
    db.col::<T>(collection)
        .find_one(filter)
        .session(&mut *session)
        .await
        .map_err(mongo_abort("find_one", collection))
}

/// Every row matching `filter`, in `sort` order. A row that fails to decode
/// fails the body: nothing is ever skipped silently.
async fn find_all_in<T>(
    db: &MongoDb,
    session: &mut ClientSession,
    collection: &'static str,
    filter: Document,
    sort: Document,
) -> Step<Vec<T>>
where
    T: DeserializeOwned + Send + Sync + Unpin,
{
    let mut cursor = db
        .col::<T>(collection)
        .find(filter)
        .sort(sort)
        .session(&mut *session)
        .await
        .map_err(mongo_abort("find", collection))?;

    let mut rows = Vec::new();
    while let Some(row) = cursor.next(&mut *session).await {
        rows.push(row.map_err(mongo_abort("find", collection))?);
    }
    Ok(rows)
}

/// Insert one document; a duplicate key is `on_duplicate`
async fn insert_in<T>(
    db: &MongoDb,
    session: &mut ClientSession,
    collection: &'static str,
    row: &T,
    on_duplicate: TxnAbort,
) -> Step<()>
where
    T: Serialize + Send + Sync,
{
    match db
        .col::<T>(collection)
        .insert_one(row)
        .session(&mut *session)
        .await
    {
        Ok(_) => Ok(()),
        Err(error) if is_duplicate_key(&error) => Err(on_duplicate),
        Err(error) => Err(mongo_abort("insert_one", collection)(error)),
    }
}

/// Write `after` over the document read as `before`, conditional on
/// `filter` (its `_id` and the version read, plus whatever state the caller
/// checked): `$set` every field `after` has but `_id` and `version`,
/// `$unset` every field only `before` had, `version += 1`. Fields another
/// binary added are left alone. Matching nothing means a writer moved it
/// since the read: the body is re-run.
async fn cas_write<T>(
    db: &MongoDb,
    session: &mut ClientSession,
    collection: &'static str,
    filter: Document,
    before: &T,
    after: &T,
) -> Step<()>
where
    T: Serialize + Sync,
{
    let encode = |value: &T| {
        bson::to_document(value).map_err(|error| {
            log::error!("PROT_TANK_ENCODE_FAILED collection={collection}: {error}");
            refuse(create_database_error!("to_document", collection))
        })
    };
    let old = encode(before)?;
    let mut new = encode(after)?;
    new.remove("_id");
    new.remove("version");

    let mut unset = Document::new();
    for key in old.keys() {
        if key != "_id" && key != "version" && !new.contains_key(key) {
            unset.insert(key.clone(), "");
        }
    }
    let mut update = doc! {
        "$set": new,
        "$inc": { "version": 1_i64 }
    };
    if !unset.is_empty() {
        update.insert("$unset", unset);
    }

    let result = db
        .col::<Document>(collection)
        .update_one(filter, update)
        .session(&mut *session)
        .await
        .map_err(mongo_abort("update_one", collection))?;
    if result.matched_count == 0 {
        return Err(TxnAbort::StateMoved);
    }
    Ok(())
}

async fn write_tank(
    db: &MongoDb,
    session: &mut ClientSession,
    before: &ProtTank,
    after: &mut ProtTank,
    now: i64,
) -> Step<()> {
    after.version = before.version + 1;
    after.updated_at = now;
    let filter = version_filter(&before.id, before.version);
    cas_write(db, session, TANKS, filter, before, &*after).await
}

async fn write_goal(
    db: &MongoDb,
    session: &mut ClientSession,
    before: &ProtGoal,
    after: &mut ProtGoal,
    now: i64,
) -> Step<()> {
    after.version = before.version + 1;
    after.updated_at = now;
    let mut filter = version_filter(&before.id, before.version);
    filter.insert("state", before.state.as_str());
    cas_write(db, session, GOALS, filter, before, &*after).await
}

/// The pledge-state CAS (audit BLOCKER 1): only the state and `remaining`
/// read may move, in the same transaction as the pledge's ledger row
async fn write_pledge(
    db: &MongoDb,
    session: &mut ClientSession,
    before: &ProtPledge,
    after: &mut ProtPledge,
    now: i64,
) -> Step<()> {
    after.version = before.version + 1;
    after.updated_at = now;
    let mut filter = version_filter(&before.id, before.version);
    filter.insert("state", before.state.as_str());
    filter.insert("remaining", before.remaining);
    cas_write(db, session, PLEDGES, filter, before, &*after).await
}

/// A real write (`$inc` of `txn_serial`, S1's counter) to a document this
/// transaction depends on, so a racing writer of that document
/// write-conflicts with it
async fn touch(
    db: &MongoDb,
    session: &mut ClientSession,
    collection: &'static str,
    filter: Document,
) -> Step<()> {
    let result = db
        .col::<Document>(collection)
        .update_one(filter, doc! { "$inc": { "txn_serial": 1_i64 } })
        .session(&mut *session)
        .await
        .map_err(mongo_abort("update_one", collection))?;
    if result.matched_count == 0 {
        return Err(TxnAbort::StateMoved);
    }
    Ok(())
}

async fn account_in(
    db: &MongoDb,
    session: &mut ClientSession,
    account_id: &str,
) -> Step<Option<ProtAccount>> {
    find_one_in(db, session, ACCOUNTS, doc! { "_id": account_id }).await
}

/// The balance document of a new `tank:` / `hold:` account, at 0 and version
/// 0 as the Reference driver opens it (8.2, 8.6, 10.3). Its id is a fresh
/// ULID's, so a duplicate is only a re-run that already made it.
async fn open_account_in(
    db: &MongoDb,
    session: &mut ClientSession,
    account_id: &str,
    now: i64,
) -> Step<()> {
    let account = ProtAccount {
        id: account_id.to_string(),
        currency: v0::ProtCurrency::Prot,
        balance: 0,
        version: 0,
        updated_at: now,
    };
    insert_in(db, session, ACCOUNTS, &account, TxnAbort::Stale).await
}

async fn tank_balance_in(db: &MongoDb, session: &mut ClientSession, tank_id: &str) -> Step<i64> {
    account_in(db, session, &prot_tank_account(tank_id))
        .await?
        .map(|account| account.balance)
        .ok_or_else(|| tank_without_account(tank_id))
}

async fn row_in(
    db: &MongoDb,
    session: &mut ClientSession,
    key: &str,
) -> Step<Option<ProtLedgerEntry>> {
    find_one_in(db, session, LEDGER, doc! { "key": key }).await
}

/// One validated posting in the session
async fn post(
    db: &MongoDb,
    session: &mut ClientSession,
    posting: &ProtPosting,
) -> Step<ProtLedgerEntry> {
    validate_prot_posting(posting).map_err(refuse)?;
    let payload_hash = prot_payload_hash(posting);
    post_in_session(db, session, posting, &payload_hash).await
}

async fn find_tank_in(
    db: &MongoDb,
    session: &mut ClientSession,
    tank_id: &str,
) -> Step<Option<ProtTank>> {
    find_one_in(db, session, TANKS, doc! { "_id": tank_id }).await
}

async fn find_goal_in(
    db: &MongoDb,
    session: &mut ClientSession,
    goal_id: &str,
) -> Step<Option<ProtGoal>> {
    find_one_in(db, session, GOALS, doc! { "_id": goal_id }).await
}

/// The goal's pledges in `state`, oldest first
async fn pledges_in(
    db: &MongoDb,
    session: &mut ClientSession,
    goal_id: &str,
    state: v0::ProtPledgeState,
) -> Step<Vec<ProtPledge>> {
    find_all_in(
        db,
        session,
        PLEDGES,
        doc! { "goal_id": goal_id, "state": state.as_str() },
        doc! { "_id": 1_i32 },
    )
    .await
}

/// The server's owner; None when the server is gone
async fn server_owner_in(
    db: &MongoDb,
    session: &mut ClientSession,
    server_id: &str,
) -> Step<Option<String>> {
    let server: Option<Document> =
        find_one_in(db, session, SERVERS, doc! { "_id": server_id }).await?;
    Ok(server.and_then(|server| server.get_str("owner").ok().map(str::to_string)))
}

/// Seats in use (active + cooling) of the tank's channel at `now`. The read
/// is in the transaction, and a racing S1 claim writes the entitlement this
/// transaction writes too, so the count cannot go stale before the commit.
async fn seats_used_in(
    db: &MongoDb,
    session: &mut ClientSession,
    tank: &ProtTank,
    now: i64,
) -> Step<usize> {
    let Some(channel_id) = tank_channel(tank) else {
        return Ok(0);
    };
    let seats: Vec<ChannelSeat> = find_all_in(
        db,
        session,
        SEATS,
        doc! { "channel_id": channel_id },
        doc! { "_id": 1_i32 },
    )
    .await?;
    Ok(channel_seats_used(&seats, timestamp_at(now)?))
}

/// The tank-backed entitlement after a stage or tier write (6.1). Matching
/// nothing is fine: no tank-backed row, or the tombstone already.
async fn write_entitlement_in(
    db: &MongoDb,
    session: &mut ClientSession,
    tank: &ProtTank,
    state: Option<ChannelEntitlementState>,
    slot_cap: Option<u32>,
) -> Step<()> {
    let Some(channel_id) = tank_channel(tank) else {
        return Ok(());
    };
    let mut set = Document::new();
    if let Some(state) = &state {
        set.insert("state", entitlement_state_name(state));
    }
    if let Some(slot_cap) = slot_cap {
        set.insert("slot_cap", i64::from(slot_cap));
    }
    if set.is_empty() {
        return Ok(());
    }

    db.col::<Document>(ENTITLEMENTS)
        .update_one(tank_entitlement_filter(channel_id), doc! { "$set": set })
        .session(&mut *session)
        .await
        .map_err(mongo_abort("update_one", ENTITLEMENTS))?;
    Ok(())
}

/// 8.5: every Held pledge of the goal back to its pledger (`pledge-return:`;
/// one with nothing left is Returned without a row)
async fn return_held_in(
    db: &MongoDb,
    session: &mut ClientSession,
    goal: &ProtGoal,
    now: i64,
) -> Step<Vec<ProtLedgerEntry>> {
    let hold = prot_hold_account(&goal.id);
    let mut returned = Vec::new();
    for pledge in pledges_in(db, session, &goal.id, v0::ProtPledgeState::Held).await? {
        if pledge.remaining > 0 {
            returned.push(
                post(
                    db,
                    session,
                    &exact_posting(
                        prot_key_pledge_return(&pledge.id),
                        v0::ProtEntryKind::PledgeReturn,
                        (hold.clone(), prot_user_account(&pledge.user_id)),
                        pledge.remaining,
                        PROT_ACTOR_GOALS,
                        pledge_ref(&pledge, None),
                        now,
                    ),
                )
                .await?,
            );
        }
        let mut after = pledge.clone();
        after.state = v0::ProtPledgeState::Returned;
        after.remaining = 0;
        write_pledge(db, session, &pledge, &mut after, now).await?;
    }
    Ok(returned)
}

/// 8.6 / 8.7: every Held pledge of the goal into the tank (`pledge-capture:`;
/// one with nothing left is Captured without a row)
async fn capture_held_in(
    db: &MongoDb,
    session: &mut ClientSession,
    goal: &ProtGoal,
    tank_id: &str,
    now: i64,
) -> Step<()> {
    let hold = prot_hold_account(&goal.id);
    for pledge in pledges_in(db, session, &goal.id, v0::ProtPledgeState::Held).await? {
        if pledge.remaining > 0 {
            post(
                db,
                session,
                &exact_posting(
                    prot_key_pledge_capture(&pledge.id),
                    v0::ProtEntryKind::PledgeCapture,
                    (hold.clone(), prot_tank_account(tank_id)),
                    pledge.remaining,
                    PROT_ACTOR_GOALS,
                    pledge_ref(&pledge, Some(tank_id)),
                    now,
                ),
            )
            .await?;
        }
        let mut after = pledge.clone();
        after.state = v0::ProtPledgeState::Captured;
        after.captured = pledge.captured.saturating_add(pledge.remaining);
        after.remaining = 0;
        write_pledge(db, session, &pledge, &mut after, now).await?;
    }
    Ok(())
}

/// Today's pro rata from `now` to midnight (capture, D16 resume), through the
/// 7.0 clamp: an Active tank short of a full day enters Grace from today's
/// start. `next_burn_day` becomes tomorrow. Ok(true) when it entered Grace.
async fn burn_rest_of_today_in(
    db: &MongoDb,
    session: &mut ClientSession,
    tank: &mut ProtTank,
    now: i64,
    rules: &ProtTankRules,
) -> Step<bool> {
    let balance = tank_balance_in(db, session, &tank.id).await?;
    let today = prot_utc_day(now);
    let floor = rules.floor(tank.daily_cost);
    let amount = prot_burn_amount(
        prot_pro_rata(tank.daily_cost, prot_hours_left(now)),
        balance,
        floor,
    );
    // A row for today means today is already paid
    let key = prot_key_burn(&tank.id, &today);
    if amount > 0 && row_in(db, session, &key).await?.is_none() {
        post(
            db,
            session,
            &burn_posting(&tank.id, &today, amount, floor, now),
        )
        .await?;
    }

    let grace = tank.stage == v0::ProtTankStage::Active && balance < tank.daily_cost;
    if grace {
        tank.stage = v0::ProtTankStage::Grace;
        tank.exhausted_at = Some(day_start(&today)?);
    }
    tank.next_burn_day = Some(next_day(&today)?);
    Ok(grace)
}

/// 7.3 after a credit (`balance` = the tank's balance now, `tank.daily_cost`
/// its CURRENT cost): Grace or Frozen with at least min_reactivation_days of
/// Prot goes back to Active and re-arms its warnings; from Frozen today is
/// billed pro rata (frozen days never are). Ok(true) when it reactivated.
async fn reactivate_in(
    db: &MongoDb,
    session: &mut ClientSession,
    tank: &mut ProtTank,
    balance: i64,
    now: i64,
    rules: &ProtTankRules,
) -> Step<bool> {
    let from_frozen = match tank.stage {
        v0::ProtTankStage::Grace => false,
        v0::ProtTankStage::Frozen => true,
        _ => return Ok(false),
    };
    let threshold = i64::from(rules.min_reactivation_days).saturating_mul(tank.daily_cost);
    if balance < threshold {
        // Smaller top-ups repay debt only
        return Ok(false);
    }

    tank.stage = v0::ProtTankStage::Active;
    tank.exhausted_at = None;
    tank.final_warning_at = None;
    tank.warnings_epoch = tank.warnings_epoch.saturating_add(1);

    // From Grace nothing more: today was charged at 00:00 and next_burn_day
    // is already tomorrow
    if from_frozen {
        let today = prot_utc_day(now);
        if rules.burning {
            let floor = rules.floor(tank.daily_cost);
            let amount = prot_burn_amount(
                prot_pro_rata(tank.daily_cost, prot_hours_left(now)),
                balance,
                floor,
            );
            let key = prot_key_burn(&tank.id, &today);
            if amount > 0 && row_in(db, session, &key).await?.is_none() {
                post(
                    db,
                    session,
                    &burn_posting(&tank.id, &today, amount, floor, now),
                )
                .await?;
            }
            tank.next_burn_day = Some(next_day(&today)?);
        } else {
            // 7.0: no row while burning is off; the resume pass bills the rest
            tank.next_burn_day = Some(today);
        }
    }
    Ok(true)
}

/// An abandoned launch (8.5, BR2): the never-launched tank, its empty account
/// and the Crowdfund entitlement go. The caller has read the channel as not
/// protected in this transaction. Returns the tank removed, if there was one.
async fn remove_unlaunched_tank_in(
    db: &MongoDb,
    session: &mut ClientSession,
    goal: &ProtGoal,
) -> Step<Option<ProtTank>> {
    let mut removed = None;
    if let Some(tank_id) = goal.tank_id.as_deref() {
        if let Some(tank) = find_tank_in(db, session, tank_id).await? {
            let never_launched = tank.launched_at.is_none()
                && matches!(
                    tank.stage,
                    v0::ProtTankStage::Launching | v0::ProtTankStage::Settling
                );
            let account = prot_tank_account(&tank.id);
            let balance = account_in(db, session, &account)
                .await?
                .map_or(0, |account| account.balance);
            if !never_launched || balance != 0 {
                log::error!(
                    "PROT_ABANDON_REFUSED goal={} tank={} stage={} balance={balance}",
                    goal.id,
                    tank.id,
                    tank.stage.as_str()
                );
                return Err(refuse(create_error!(InternalError)));
            }

            let deleted = db
                .col::<Document>(TANKS)
                .delete_one(version_filter(&tank.id, tank.version))
                .session(&mut *session)
                .await
                .map_err(mongo_abort("delete_one", TANKS))?;
            if deleted.deleted_count == 0 {
                return Err(TxnAbort::StateMoved);
            }
            db.col::<Document>(ACCOUNTS)
                .delete_one(doc! { "_id": &account, "balance": 0_i64 })
                .session(&mut *session)
                .await
                .map_err(mongo_abort("delete_one", ACCOUNTS))?;
            removed = Some(tank);
        }
    }

    if let Some(channel_id) = goal.channel_id.as_deref() {
        db.col::<Document>(ENTITLEMENTS)
            .delete_many(doc! {
                "channel_id": channel_id,
                "source": entitlement_source_name(&ChannelEntitlementSource::Crowdfund)
            })
            .session(&mut *session)
            .await
            .map_err(mongo_abort("delete_many", ENTITLEMENTS))?;
    }
    Ok(removed)
}

/// close_prot_goal's body for a goal read in this session (8.5). Also the
/// full-returns cancel of an upgrade apply that cannot apply (8.7).
async fn close_goal_in(
    db: &MongoDb,
    session: &mut ClientSession,
    goal: &ProtGoal,
    to: v0::ProtGoalState,
    now: i64,
) -> Step<ProtGoalCloseOutcome> {
    let allowed = match (goal.state, to) {
        (v0::ProtGoalState::Funding, v0::ProtGoalState::Expired)
        | (v0::ProtGoalState::Funding, v0::ProtGoalState::Cancelled)
        | (v0::ProtGoalState::Funded, v0::ProtGoalState::Cancelled)
        | (v0::ProtGoalState::Launching, v0::ProtGoalState::Cancelled) => true,
        (_, v0::ProtGoalState::Expired) | (_, v0::ProtGoalState::Cancelled) => false,
        (_, to) => {
            log::error!(
                "PROT_GOAL_CLOSE_INVALID goal={} to={}",
                goal.id,
                to.as_str()
            );
            return Err(refuse(create_error!(InternalError)));
        }
    };
    if !allowed {
        return Err(refuse(create_error!(ProtGoalClosed)));
    }

    let mut removed_tank = None;
    if goal.state == v0::ProtGoalState::Launching {
        if let Some(channel_id) = goal.channel_id.as_deref() {
            let channel: Option<Document> =
                find_one_in(db, session, CHANNELS, doc! { "_id": channel_id }).await?;
            if let Some(channel) = &channel {
                // The in-transaction protected read (8.5, BR2, audit 13):
                // protect landed and the capture has not run yet. Only the
                // capture may end this goal now.
                if may_be_protected(channel) {
                    return Err(refuse(create_error!(InvalidOperation)));
                }
                // Write the channel, so a protect racing this abandon (it
                // sets `protected` on this document) write-conflicts with it
                touch(db, session, CHANNELS, doc! { "_id": channel_id }).await?;
            }
        }
        removed_tank = remove_unlaunched_tank_in(db, session, goal).await?;
    }

    let returned = return_held_in(db, session, goal, now).await?;
    let mut after = goal.clone();
    after.state = to;
    after.open_key = None;
    after.closed_at = Some(now);
    write_goal(db, session, goal, &mut after, now).await?;

    Ok(ProtGoalCloseOutcome {
        goal: after,
        returned,
        removed_tank,
    })
}

// ---------------------------------------------------------------------------
// Transaction bodies
// ---------------------------------------------------------------------------

/// set_prot_contributor_pref
struct PrefBody {
    server_id: String,
    user_id: String,
    hidden: bool,
    now: i64,
}

#[async_trait]
impl ProtTxnBody for PrefBody {
    type Output = ();

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<()> {
        db.col::<Document>(PREFS)
            .update_one(
                doc! { "_id": pref_id(&self.server_id, &self.user_id) },
                doc! { "$set": { "hidden": self.hidden, "updated_at": self.now } },
            )
            .upsert(true)
            .session(&mut *session)
            .await
            .map_err(|error| {
                // Two upserts creating the row: the loser re-runs and finds it
                if is_duplicate_key(&error) {
                    TxnAbort::Stale
                } else {
                    mongo_abort("update_one", PREFS)(error)
                }
            })?;
        Ok(())
    }
}

/// create_prot_goal (8.2, 8.7): the goal and its `hold:` account document
struct CreateGoalBody {
    goal: ProtGoal,
}

#[async_trait]
impl ProtTxnBody for CreateGoalBody {
    type Output = ProtGoal;

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<ProtGoal> {
        let goal = &self.goal;
        // An upgrade goal locks the tier (8.9 reads the tank's open goals):
        // write the tank, so a racing tier change write-conflicts with it.
        // `txn_serial` only, so the tank's version is unchanged.
        if goal.kind == v0::ProtGoalKind::Upgrade {
            if let Some(tank_id) = goal.tank_id.as_deref() {
                if find_tank_in(db, session, tank_id).await?.is_some() {
                    touch(db, session, TANKS, doc! { "_id": tank_id }).await?;
                }
            }
        }

        // The unique open_key (one open launch goal per server, one open
        // upgrade goal per tank, BR14) or the `_id`: the caller looks
        insert_in(
            db,
            session,
            GOALS,
            goal,
            TxnAbort::DuplicateKey {
                key: goal.open_key.clone().unwrap_or_default(),
                payload_hash: String::new(),
            },
        )
        .await?;
        open_account_in(db, session, &prot_hold_account(&goal.id), goal.created_at).await?;
        Ok(goal.clone())
    }
}

/// pledge_prot (8.3)
struct PledgeBody {
    input: ProtPledgeInput,
    /// Fixed for every re-run of this call
    pledge_id: String,
}

#[async_trait]
impl ProtTxnBody for PledgeBody {
    type Output = ProtPledgeOutcome;

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<ProtPledgeOutcome> {
        let input = &self.input;
        let rules = &input.rules;
        let now = input.now;

        let goal = find_goal_in(db, session, &input.goal_id)
            .await?
            .ok_or_else(|| refuse(create_error!(NotFound)))?;
        if goal.state != v0::ProtGoalState::Funding || now >= goal.deadline_at {
            return Err(refuse(create_error!(ProtGoalClosed)));
        }
        let open = goal.target_prot - goal.pledged_total;
        if open <= 0 {
            return Err(refuse(create_error!(ProtGoalClosed)));
        }
        // Capped at the target; a pledge that completes the goal may be
        // below the minimum
        let amount = input.amount.min(open);
        if amount < rules.min_contribution && amount != open {
            return Err(refuse(create_error!(FailedValidation {
                error: "below the minimum".to_string()
            })));
        }

        // D17 (BR8): the held figure in this transaction's snapshot is the
        // debit's floor, so a purchase landing mid-request is never spent
        let wallet = prot_user_account(&input.user_id);
        let wallet_balance = account_in(db, session, &wallet)
            .await?
            .map_or(0, |account| account.balance);
        let held = db
            .held_purchase_prot_in(session, &input.user_id, now - rules.hold_ms())
            .await?
            .min(wallet_balance)
            .max(0);

        let pledge = ProtPledge {
            id: self.pledge_id.clone(),
            goal_id: goal.id.clone(),
            server_id: goal.server_id.clone(),
            user_id: input.user_id.clone(),
            kind: goal.kind,
            amount,
            remaining: amount,
            state: v0::ProtPledgeState::Held,
            captured: 0,
            launch_returned: 0,
            version: 0,
            created_at: now,
            updated_at: now,
        };
        let entry = post(
            db,
            session,
            &ProtPosting {
                debit_floor: held,
                ..exact_posting(
                    prot_key_pledge(&input.user_id, &input.goal_id, &input.nonce),
                    v0::ProtEntryKind::PledgeHold,
                    (wallet, prot_hold_account(&goal.id)),
                    amount,
                    &input.user_id,
                    pledge_ref(&pledge, None),
                    now,
                )
            },
        )
        .await?;
        insert_in(db, session, PLEDGES, &pledge, TxnAbort::Stale).await?;

        let mut after = goal.clone();
        after.pledged_total = goal.pledged_total + amount;
        let funded_now = after.pledged_total >= goal.target_prot;
        if funded_now {
            // For an Upgrade goal this is the apply deadline (8.7)
            after.state = v0::ProtGoalState::Funded;
            after.funded_at = Some(now);
            after.launch_deadline_at = Some(now.saturating_add(days_ms(rules.launch_window_days)));
        }
        write_goal(db, session, &goal, &mut after, now).await?;

        Ok(ProtPledgeOutcome {
            pledge,
            goal: after,
            entry,
            already_applied: false,
            funded_now,
        })
    }
}

/// withdraw_prot_pledge (8.4, D10)
struct WithdrawBody {
    pledge_id: String,
    user_id: String,
    now: i64,
    cutoff_ms: i64,
}

#[async_trait]
impl ProtTxnBody for WithdrawBody {
    type Output = ProtPledge;

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<ProtPledge> {
        let now = self.now;
        let pledge: ProtPledge = find_one_in(db, session, PLEDGES, doc! { "_id": &self.pledge_id })
            .await?
            .filter(|pledge: &ProtPledge| pledge.user_id == self.user_id)
            .ok_or_else(|| refuse(create_error!(NotFound)))?;
        let goal = find_goal_in(db, session, &pledge.goal_id)
            .await?
            .ok_or_else(|| refuse(create_error!(NotFound)))?;
        if goal.state != v0::ProtGoalState::Funding
            || now > goal.deadline_at.saturating_sub(self.cutoff_ms)
        {
            return Err(refuse(create_error!(ProtGoalClosed)));
        }
        // The pledge-state CAS (also in `write_pledge`'s filter): only a
        // pledge still in the hold can leave it
        if pledge.state != v0::ProtPledgeState::Held {
            return Err(refuse(create_error!(InvalidOperation)));
        }

        if pledge.remaining > 0 {
            post(
                db,
                session,
                &exact_posting(
                    prot_key_pledge_withdraw(&pledge.id),
                    v0::ProtEntryKind::PledgeWithdraw,
                    (
                        prot_hold_account(&goal.id),
                        prot_user_account(&self.user_id),
                    ),
                    pledge.remaining,
                    &self.user_id,
                    pledge_ref(&pledge, None),
                    now,
                ),
            )
            .await?;
        }
        let mut after = pledge.clone();
        after.state = v0::ProtPledgeState::Withdrawn;
        after.remaining = 0;
        write_pledge(db, session, &pledge, &mut after, now).await?;

        let mut goal_after = goal.clone();
        goal_after.pledged_total = goal.pledged_total - pledge.remaining;
        write_goal(db, session, &goal, &mut goal_after, now).await?;

        Ok(after)
    }
}

/// close_prot_goal (8.5)
struct CloseBody {
    goal_id: String,
    to: v0::ProtGoalState,
    now: i64,
}

#[async_trait]
impl ProtTxnBody for CloseBody {
    type Output = ProtGoalCloseOutcome;

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<ProtGoalCloseOutcome> {
        let goal = find_goal_in(db, session, &self.goal_id)
            .await?
            .ok_or_else(|| refuse(create_error!(NotFound)))?;
        close_goal_in(db, session, &goal, self.to, self.now).await
    }
}

/// launch_prot_goal (8.6)
struct LaunchBody {
    input: ProtLaunchInput,
    /// Fixed for every re-run of this call
    tank_id: String,
    entitlement_id: String,
}

#[async_trait]
impl ProtTxnBody for LaunchBody {
    type Output = (ProtGoal, ProtTank);

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<(ProtGoal, ProtTank)> {
        let input = &self.input;
        let now = input.now;

        let goal = find_goal_in(db, session, &input.goal_id)
            .await?
            .ok_or_else(|| refuse(create_error!(NotFound)))?;
        if goal.kind != v0::ProtGoalKind::Launch {
            return Err(refuse(create_error!(InvalidOperation)));
        }
        if goal.state != v0::ProtGoalState::Funded
            || goal.launch_deadline_at.is_none_or(|at| now > at)
        {
            return Err(refuse(create_error!(ProtGoalClosed)));
        }
        if !PROT_SLOT_TIERS.contains(&goal.slots) || goal.daily_cost <= 0 {
            return Err(inconsistent(
                &goal.id,
                "a launch goal without a priced tier",
            ));
        }

        // Authority is the server's owner at call time (11.3), held to the
        // commit (S1's owner claim)
        let owner = server_owner_in(db, session, &goal.server_id)
            .await?
            .ok_or_else(|| refuse(create_error!(NotFound)))?;
        if owner != input.owner_id {
            return Err(refuse(create_error!(NotOwner)));
        }

        // Another server's channel looks absent (IDOR)
        let channel: Channel =
            find_one_in(db, session, CHANNELS, doc! { "_id": &input.channel_id })
                .await?
                .filter(|channel: &Channel| {
                    seat_list_channel_server(channel) == Some(goal.server_id.as_str())
                })
                .ok_or_else(|| refuse(create_error!(NotFound)))?;
        check_channel_protectable(Some(&channel)).map_err(refuse)?;
        // `last_message_id` lags stored messages: ask the messages themselves
        let message: Option<Document> =
            find_one_in(db, session, MESSAGES, doc! { "channel": &input.channel_id }).await?;
        if message.is_some() {
            return Err(refuse(create_error!(InvalidOperation)));
        }
        let entitlement: Option<Document> = find_one_in(
            db,
            session,
            ENTITLEMENTS,
            doc! { "channel_id": &input.channel_id },
        )
        .await?;
        if entitlement.is_some() {
            return Err(refuse(create_error!(InvalidOperation)));
        }
        let target_key = prot_tank_target_key(&input.channel_id);
        let tank: Option<Document> =
            find_one_in(db, session, TANKS, doc! { "target_key": &target_key }).await?;
        if tank.is_some() {
            return Err(refuse(create_error!(InvalidOperation)));
        }

        touch(
            db,
            session,
            SERVERS,
            doc! { "_id": &goal.server_id, "owner": &input.owner_id },
        )
        .await?;

        // The unique `channel_id`: a racing admin grant either sees this row
        // (and is refused, 6.6) or makes this insert fail
        let entitlement = ChannelEntitlement {
            id: self.entitlement_id.clone(),
            channel_id: input.channel_id.clone(),
            server_id: goal.server_id.clone(),
            source: ChannelEntitlementSource::Crowdfund,
            slot_cap: goal.slots,
            device_cap: None,
            state: ChannelEntitlementState::Active,
            granted_by: input.owner_id.clone(),
            created_at: timestamp_at(now)?,
        };
        insert_in(
            db,
            session,
            ENTITLEMENTS,
            &entitlement,
            refuse(create_error!(InvalidOperation)),
        )
        .await?;

        let tank = ProtTank {
            id: self.tank_id.clone(),
            target: ProtTankTarget::Channel {
                channel_id: input.channel_id.clone(),
            },
            target_key,
            server_id: goal.server_id.clone(),
            created_by: input.owner_id.clone(),
            plan: v0::ProtPlan::Channel,
            slot_tier: goal.slots,
            pending_slot_tier: None,
            // The goal's snapshot: a config edit never moves a date
            daily_cost: goal.daily_cost,
            rate_card: input.rules.rate_card(),
            stage: v0::ProtTankStage::Launching,
            exhausted_at: None,
            next_burn_day: None,
            launched_at: None,
            final_warning_at: None,
            warnings_epoch: 0,
            pause_shift_for: None,
            settle_cause: None,
            ended_at: None,
            terminated_by: None,
            purged_at: None,
            purge_passes: 0,
            version: 0,
            created_at: now,
            updated_at: now,
        };
        // The unique target_key: one tank per channel
        insert_in(
            db,
            session,
            TANKS,
            &tank,
            refuse(create_error!(InvalidOperation)),
        )
        .await?;
        open_account_in(db, session, &prot_tank_account(&tank.id), now).await?;

        let mut after = goal.clone();
        after.state = v0::ProtGoalState::Launching;
        after.channel_id = Some(input.channel_id.clone());
        after.tank_id = Some(tank.id.clone());
        write_goal(db, session, &goal, &mut after, now).await?;

        Ok((after, tank))
    }
}

/// capture_launch_pledges (8.6). `rules`: the rules of the launch-day burn;
/// None posts none (a termination captures only to forfeit).
struct CaptureBody {
    channel_id: String,
    now: i64,
    rules: Option<ProtTankRules>,
}

#[async_trait]
impl ProtTxnBody for CaptureBody {
    type Output = Option<ProtTank>;

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<Option<ProtTank>> {
        let now = self.now;
        let target_key = prot_tank_target_key(&self.channel_id);
        let Some(tank): Option<ProtTank> =
            find_one_in(db, session, TANKS, doc! { "target_key": &target_key }).await?
        else {
            return Ok(None);
        };
        // A Settling tank that never launched: a delete in progress (9.4)
        let settling = match tank.stage {
            v0::ProtTankStage::Launching => false,
            v0::ProtTankStage::Settling if tank.launched_at.is_none() => true,
            _ => return Ok(None),
        };
        let Some(goal): Option<ProtGoal> = find_one_in(
            db,
            session,
            GOALS,
            doc! {
                "tank_id": &tank.id,
                "kind": goal_kind_name(v0::ProtGoalKind::Launch),
                "state": v0::ProtGoalState::Launching.as_str()
            },
        )
        .await?
        else {
            return Ok(None);
        };
        // Capture only once protect has landed (BR2). An abandon racing this
        // capture deletes this tank (a write), so the two serialize.
        let channel: Option<Document> =
            find_one_in(db, session, CHANNELS, doc! { "_id": &self.channel_id }).await?;
        if !channel.as_ref().is_some_and(is_protected) {
            return Ok(None);
        }

        capture_held_in(db, session, &goal, &tank.id, now).await?;
        let mut goal_after = goal.clone();
        goal_after.state = v0::ProtGoalState::Launched;
        goal_after.launched_at = Some(now);
        goal_after.open_key = None;
        write_goal(db, session, &goal, &mut goal_after, now).await?;

        let mut after = tank.clone();
        after.launched_at = Some(now);
        let mut entered_grace = false;
        // A Settling tank keeps Settling: no launch-day burn and no
        // next_burn_day; the captured Prot goes back FIFO in full (N5)
        if !settling {
            after.stage = v0::ProtTankStage::Active;
            match &self.rules {
                Some(rules) if rules.burning => {
                    entered_grace =
                        burn_rest_of_today_in(db, session, &mut after, now, rules).await?;
                }
                // 7.0: no row while burning is off
                _ => after.next_burn_day = Some(prot_utc_day(now)),
            }
        }
        if entered_grace {
            write_entitlement_in(
                db,
                session,
                &after,
                Some(ChannelEntitlementState::Grace),
                None,
            )
            .await?;
        }
        write_tank(db, session, &tank, &mut after, now).await?;
        Ok(Some(after))
    }
}

/// return_unseated_launch_pledges (8.6, D8)
struct UnseatedBody {
    goal_id: String,
    now: i64,
}

#[async_trait]
impl ProtTxnBody for UnseatedBody {
    type Output = Vec<ProtLedgerEntry>;

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<Vec<ProtLedgerEntry>> {
        let now = self.now;
        let goal = find_goal_in(db, session, &self.goal_id)
            .await?
            .ok_or_else(|| refuse(create_error!(NotFound)))?;
        // Once (the refund7_done CAS), for a launched Launch goal only
        if goal.kind != v0::ProtGoalKind::Launch
            || goal.state != v0::ProtGoalState::Launched
            || goal.refund7_done
        {
            return Ok(Vec::new());
        }
        let mut done = goal.clone();
        done.refund7_done = true;

        let tank = match goal.tank_id.as_deref() {
            Some(tank_id) => find_tank_in(db, session, tank_id).await?,
            None => None,
        }
        .filter(|tank| {
            matches!(
                tank.stage,
                v0::ProtTankStage::Active | v0::ProtTankStage::Grace | v0::ProtTankStage::Frozen
            )
        });
        let Some((tank, channel_id)) = tank.and_then(|tank| {
            let channel_id = tank_channel(&tank)?.to_string();
            Some((tank, channel_id))
        }) else {
            write_goal(db, session, &goal, &mut done, now).await?;
            return Ok(Vec::new());
        };

        // The owner is exempt; everyone else needs an ACTIVE seat now
        let owner = server_owner_in(db, session, &goal.server_id).await?;
        let seats: Vec<ChannelSeat> = find_all_in(
            db,
            session,
            SEATS,
            doc! { "channel_id": &channel_id },
            doc! { "_id": 1_i32 },
        )
        .await?;
        let seated: HashSet<&str> = seats
            .iter()
            .filter(|seat| seat.is_active())
            .map(|seat| seat.user_id.as_str())
            .collect();
        let captured: Vec<ProtPledge> =
            pledges_in(db, session, &goal.id, v0::ProtPledgeState::Captured)
                .await?
                .into_iter()
                .filter(|pledge| {
                    pledge.kind == v0::ProtGoalKind::Launch
                        && pledge.captured > 0
                        && owner.as_deref() != Some(pledge.user_id.as_str())
                        && !seated.contains(pledge.user_id.as_str())
                })
                .collect();
        let due: Vec<(String, i64)> = captured
            .iter()
            .map(|pledge| (pledge.id.clone(), pledge.captured))
            .collect();
        let balance = tank_balance_in(db, session, &tank.id).await?;

        let mut entries = Vec::new();
        for (pledge_id, amount) in plan_unseated_returns(&due, balance) {
            let Some(pledge) = captured.iter().find(|pledge| pledge.id == pledge_id) else {
                continue;
            };
            entries.push(
                post(
                    db,
                    session,
                    &exact_posting(
                        prot_key_launch_return(&pledge.id),
                        v0::ProtEntryKind::LaunchReturn,
                        (
                            prot_tank_account(&tank.id),
                            prot_user_account(&pledge.user_id),
                        ),
                        amount,
                        PROT_ACTOR_GOALS,
                        pledge_ref(pledge, Some(tank.id.as_str())),
                        now,
                    ),
                )
                .await?,
            );
            let mut after = pledge.clone();
            after.launch_returned = amount;
            write_pledge(db, session, pledge, &mut after, now).await?;
        }

        write_goal(db, session, &goal, &mut done, now).await?;
        if !entries.is_empty() {
            let mut after = tank.clone();
            write_tank(db, session, &tank, &mut after, now).await?;
        }
        Ok(entries)
    }
}

/// apply_prot_upgrade_goal (8.7, D13)
struct ApplyBody {
    goal_id: String,
    now: i64,
    rules: ProtTankRules,
}

#[async_trait]
impl ProtTxnBody for ApplyBody {
    type Output = Option<ProtTank>;

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<Option<ProtTank>> {
        let now = self.now;
        let rules = &self.rules;
        let goal = find_goal_in(db, session, &self.goal_id)
            .await?
            .ok_or_else(|| refuse(create_error!(NotFound)))?;
        if goal.kind != v0::ProtGoalKind::Upgrade || goal.state != v0::ProtGoalState::Funded {
            return Ok(None);
        }
        let tank = match goal.tank_id.as_deref() {
            Some(tank_id) => find_tank_in(db, session, tank_id).await?,
            None => None,
        };

        let apply = match &tank {
            // Still launching: the capture comes first
            Some(tank) if tank.stage == v0::ProtTankStage::Launching => return Ok(None),
            // The tier moved anyway: pledgers never pay for an upgrade they
            // don't get
            Some(tank) if goal.slots <= tank.slot_tier => false,
            Some(tank) => matches!(
                tank.stage,
                v0::ProtTankStage::Active | v0::ProtTankStage::Grace | v0::ProtTankStage::Frozen
            ),
            None => false,
        };
        let (Some(tank), true) = (tank, apply) else {
            // Settling / Deleted / Terminated (or no tank): full returns
            close_goal_in(db, session, &goal, v0::ProtGoalState::Cancelled, now).await?;
            return Ok(None);
        };

        capture_held_in(db, session, &goal, &tank.id, now).await?;
        let balance = tank_balance_in(db, session, &tank.id).await?;
        let new_cost = goal.daily_cost;

        if tank.stage == v0::ProtTankStage::Active && rules.burning {
            // The apply clamps at 0 (a manual upgrade refuses instead, N5)
            let charge = prot_burn_amount(
                prot_pro_rata(new_cost - tank.daily_cost, prot_hours_left(now)),
                balance,
                0,
            );
            if charge > 0 {
                post(
                    db,
                    session,
                    &exact_posting(
                        prot_key_tier(&tank.id, &format!("goal-{}", goal.id)),
                        v0::ProtEntryKind::TierUpgrade,
                        (prot_tank_account(&tank.id), PROT_SYS_BURNED.to_string()),
                        charge,
                        PROT_ACTOR_GOALS,
                        tank_ref(&tank.id),
                        now,
                    ),
                )
                .await?;
            }
        }

        let mut after = tank.clone();
        after.slot_tier = goal.slots;
        after.daily_cost = new_cost;
        after.rate_card = rules.rate_card();
        after.pending_slot_tier = None;
        // Grace / Frozen: no tier row (today was charged at the old cost, or
        // not at all while frozen); reactivation at the NEW cost
        let reactivated = reactivate_in(db, session, &mut after, balance, now, rules).await?;
        write_entitlement_in(
            db,
            session,
            &after,
            reactivated.then_some(ChannelEntitlementState::Active),
            Some(goal.slots),
        )
        .await?;

        let mut goal_after = goal.clone();
        goal_after.state = v0::ProtGoalState::Applied;
        goal_after.open_key = None;
        goal_after.closed_at = Some(now);
        write_goal(db, session, &goal, &mut goal_after, now).await?;
        write_tank(db, session, &tank, &mut after, now).await?;
        Ok(Some(after))
    }
}

/// contribute_prot (8.8)
struct ContributeBody {
    input: ProtContributeInput,
}

#[async_trait]
impl ProtTxnBody for ContributeBody {
    type Output = ProtContributeOutcome;

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<ProtContributeOutcome> {
        let input = &self.input;
        let rules = &input.rules;
        let now = input.now;

        let tank = find_tank_in(db, session, &input.tank_id)
            .await?
            .ok_or_else(|| refuse(create_error!(NotFound)))?;
        let burnable = match tank.stage {
            v0::ProtTankStage::Active | v0::ProtTankStage::Grace => true,
            v0::ProtTankStage::Frozen => false,
            // NIT 23: ProtGoalClosed reads "goal"
            _ => return Err(refuse(create_error!(InvalidOperation))),
        };
        // A midnight crossed since the engine's catch-up (8.8), decided on
        // the runtime row in this snapshot. A tank still waiting for its
        // pause shift is not stale: its missed days are paused days (7.4, N4)
        let runtime: Option<ProtRuntime> =
            find_one_in(db, session, RUNTIME, doc! { "_id": PROT_RUNTIME_ID }).await?;
        let paused = runtime.and_then(|runtime| runtime.burn_paused_at);
        let waiting_for_shift = paused.is_some() && tank.pause_shift_for != paused;
        let today = prot_utc_day(now);
        if rules.burning
            && burnable
            && !waiting_for_shift
            && tank
                .next_burn_day
                .as_deref()
                .is_some_and(|day| day < today.as_str())
        {
            log::error!("PROT_TANK_STALE tank={}", tank.id);
            return Err(refuse(create_error!(InternalError)));
        }

        // D17 (BR8), in this transaction's snapshot
        let wallet_balance = account_in(db, session, &prot_user_account(&input.user_id))
            .await?
            .map_or(0, |account| account.balance);
        let held = db
            .held_purchase_prot_in(session, &input.user_id, now - rules.hold_ms())
            .await?
            .min(wallet_balance)
            .max(0);

        let before = tank_balance_in(db, session, &tank.id).await?;
        let entry = post(db, session, &contribution_posting(input, held)).await?;
        let balance = tank_balance_in(db, session, &tank.id).await?;

        let mut after = tank.clone();
        let reactivated = reactivate_in(db, session, &mut after, balance, now, rules).await?;
        // BR13: lifting the days left above the largest warn day re-arms the
        // warnings, so a second dip is warned again
        if !reactivated && after.stage == v0::ProtTankStage::Active && after.daily_cost > 0 {
            if let Some(largest) = rules.warn_days.iter().copied().max() {
                let largest = i64::from(largest);
                if before.div_euclid(after.daily_cost) <= largest
                    && balance.div_euclid(after.daily_cost) > largest
                {
                    after.warnings_epoch = after.warnings_epoch.saturating_add(1);
                }
            }
        }
        if reactivated {
            write_entitlement_in(
                db,
                session,
                &after,
                Some(ChannelEntitlementState::Active),
                None,
            )
            .await?;
        }
        write_tank(db, session, &tank, &mut after, now).await?;

        Ok(ProtContributeOutcome::Applied {
            entry,
            tank: after,
            stage_changed: reactivated,
        })
    }
}

/// change_prot_tier (8.9)
struct TierBody {
    input: ProtTierChangeInput,
}

#[async_trait]
impl ProtTxnBody for TierBody {
    type Output = ProtTank;

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<ProtTank> {
        let input = &self.input;
        let rules = &input.rules;
        let now = input.now;

        let tank = find_tank_in(db, session, &input.tank_id)
            .await?
            .ok_or_else(|| refuse(create_error!(NotFound)))?;
        let Some(cost) = rules.daily_cost(input.slots) else {
            return Err(refuse(create_error!(FailedValidation {
                error: "slots must be 10, 25, 50 or 100".to_string()
            })));
        };
        let key = prot_key_tier(&tank.id, &input.change_id);
        // A replay of an applied upgrade
        if row_in(db, session, &key).await?.is_some() {
            return Ok(tank);
        }
        // 8.7: the tier cannot move under an open upgrade goal
        let open_upgrade: Option<Document> = find_one_in(
            db,
            session,
            GOALS,
            doc! {
                "tank_id": &tank.id,
                "kind": goal_kind_name(v0::ProtGoalKind::Upgrade),
                "state": { "$in": open_goal_state_names() }
            },
        )
        .await?;
        if open_upgrade.is_some() {
            return Err(refuse(create_error!(InvalidOperation)));
        }
        if !matches!(
            tank.stage,
            v0::ProtTankStage::Active | v0::ProtTankStage::Grace | v0::ProtTankStage::Frozen
        ) {
            return Err(refuse(create_error!(InvalidOperation)));
        }

        let mut after = tank.clone();
        let mut slot_cap = None;
        if input.slots == tank.slot_tier {
            // The current tier: a pending downgrade is called off
            if tank.pending_slot_tier.is_none() {
                return Ok(tank);
            }
            after.pending_slot_tier = None;
        } else if input.slots > tank.slot_tier {
            if tank.stage != v0::ProtTankStage::Active {
                return Err(refuse(create_error!(InvalidOperation)));
            }
            let charge = if rules.burning {
                prot_pro_rata(cost - tank.daily_cost, prot_hours_left(now))
            } else {
                0
            };
            let balance = tank_balance_in(db, session, &tank.id).await?;
            // A manual upgrade never borrows: it refuses (N5)
            if balance - charge < 0 {
                return Err(refuse(create_error!(InsufficientProt {
                    needed: charge,
                    available: balance.max(0)
                })));
            }
            if charge > 0 {
                let owner = server_owner_in(db, session, &tank.server_id)
                    .await?
                    .unwrap_or_else(|| tank.created_by.clone());
                post(
                    db,
                    session,
                    &exact_posting(
                        key,
                        v0::ProtEntryKind::TierUpgrade,
                        (prot_tank_account(&tank.id), PROT_SYS_BURNED.to_string()),
                        charge,
                        &owner,
                        tank_ref(&tank.id),
                        now,
                    ),
                )
                .await?;
            }
            after.slot_tier = input.slots;
            after.daily_cost = cost;
            after.rate_card = rules.rate_card();
            after.pending_slot_tier = None;
            slot_cap = Some(input.slots);
        } else if seats_used_in(db, session, &tank, now).await? <= input.slots as usize {
            // The new cost from the next burn; today is not refunded and the
            // lower floor is the 7.0 clamp's
            after.slot_tier = input.slots;
            after.daily_cost = cost;
            after.rate_card = rules.rate_card();
            after.pending_slot_tier = None;
            slot_cap = Some(input.slots);
        } else {
            // Applied by the clock once cooldowns free the seats
            after.pending_slot_tier = Some(input.slots);
        }

        write_entitlement_in(db, session, &after, None, slot_cap).await?;
        write_tank(db, session, &tank, &mut after, now).await?;
        Ok(after)
    }
}

/// apply_pending_prot_tier (8.9)
struct PendingTierBody {
    tank_id: String,
    now: i64,
    rules: ProtTankRules,
}

#[async_trait]
impl ProtTxnBody for PendingTierBody {
    type Output = Option<ProtTank>;

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<Option<ProtTank>> {
        let now = self.now;
        let tank = find_tank_in(db, session, &self.tank_id)
            .await?
            .ok_or_else(|| refuse(create_error!(NotFound)))?;
        let Some(pending) = tank.pending_slot_tier else {
            return Ok(None);
        };
        if !matches!(
            tank.stage,
            v0::ProtTankStage::Active | v0::ProtTankStage::Grace | v0::ProtTankStage::Frozen
        ) {
            return Ok(None);
        }

        let mut after = tank.clone();
        let mut slot_cap = None;
        match self.rules.daily_cost(pending) {
            Some(cost) if pending < tank.slot_tier => {
                // slot_cap is never written below the seats in use
                if seats_used_in(db, session, &tank, now).await? > pending as usize {
                    return Ok(None);
                }
                after.slot_tier = pending;
                after.daily_cost = cost;
                after.rate_card = self.rules.rate_card();
                slot_cap = Some(pending);
            }
            // Not a downgrade (or not a tier) any more: nothing to apply
            _ => log::warn!(
                "PROT_PENDING_TIER_DROPPED tank={} pending={pending} tier={}",
                tank.id,
                tank.slot_tier
            ),
        }
        after.pending_slot_tier = None;

        write_entitlement_in(db, session, &after, None, slot_cap).await?;
        write_tank(db, session, &tank, &mut after, now).await?;
        Ok(Some(after))
    }
}

/// burn_prot_tank_day (7.2)
struct BurnBody {
    tank_id: String,
    day: String,
    paused: Option<i64>,
    now: i64,
    rules: ProtTankRules,
}

#[async_trait]
impl ProtTxnBody for BurnBody {
    type Output = ProtBurnOutcome;

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<ProtBurnOutcome> {
        let rules = &self.rules;
        let now = self.now;
        let day = self.day.as_str();

        let tank = find_tank_in(db, session, &self.tank_id)
            .await?
            .ok_or_else(|| refuse(create_error!(NotFound)))?;
        // 7.0: nothing is billed while burning is off, and while a pause is
        // recorded only a tank already shifted for it is billed
        if !rules.burning
            || !matches!(
                tank.stage,
                v0::ProtTankStage::Active | v0::ProtTankStage::Grace
            )
            || tank.next_burn_day.as_deref() != Some(day)
            || self
                .paused
                .is_some_and(|paused| tank.pause_shift_for != Some(paused))
        {
            return Ok(ProtBurnOutcome::NotDue { tank });
        }

        let balance = tank_balance_in(db, session, &tank.id).await?;
        let floor = rules.floor(tank.daily_cost);
        let plan = plan_tank_day(&tank, balance, day, rules).map_err(refuse)?;

        let amount = match plan {
            ProtDayPlan::Burn { amount } | ProtDayPlan::EnterGrace { amount, .. } => amount,
            ProtDayPlan::Freeze | ProtDayPlan::Advance => 0,
        };
        let entry = if amount > 0 {
            Some(
                post(
                    db,
                    session,
                    &burn_posting(&tank.id, day, amount, floor, now),
                )
                .await?,
            )
        } else {
            None
        };

        let mut after = tank.clone();
        let mut state = None;
        match plan {
            ProtDayPlan::Burn { .. } | ProtDayPlan::Advance => {
                after.next_burn_day = Some(next_day(day)?);
            }
            ProtDayPlan::EnterGrace { exhausted_at, .. } => {
                after.next_burn_day = Some(next_day(day)?);
                after.stage = v0::ProtTankStage::Grace;
                after.exhausted_at = Some(exhausted_at);
                state = Some(ChannelEntitlementState::Grace);
            }
            // Frozen days are never billed: next_burn_day stays
            ProtDayPlan::Freeze => {
                after.stage = v0::ProtTankStage::Frozen;
                state = Some(ChannelEntitlementState::Frozen);
            }
        }
        if state.is_some() {
            write_entitlement_in(db, session, &after, state, None).await?;
        }
        write_tank(db, session, &tank, &mut after, now).await?;

        Ok(match (plan, entry) {
            (ProtDayPlan::Burn { .. }, Some(entry)) => {
                ProtBurnOutcome::Burned { entry, tank: after }
            }
            (ProtDayPlan::Freeze, _) => ProtBurnOutcome::Froze { tank: after },
            // EnterGrace, and a Grace day clamped to 0 at the floor (Advance):
            // the tank is in Grace and the catch-up goes on (tanks.rs)
            (_, entry) => ProtBurnOutcome::EnteredGrace { entry, tank: after },
        })
    }
}

/// record_prot_notice (12.2)
struct NoticeBody {
    tank_id: String,
    epoch: u64,
    kind: ProtNoticeKind,
    delivered: bool,
    now: i64,
}

#[async_trait]
impl ProtTxnBody for NoticeBody {
    type Output = bool;

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<bool> {
        let key = prot_notice_key(&self.tank_id, self.epoch, self.kind);
        let stored: Option<Document> =
            find_one_in(db, session, NOTICES, doc! { "_id": &key }).await?;
        if stored.is_some() {
            return Ok(false);
        }

        // The Final notice dates the deletion guard (7.5): only for the
        // epoch it was computed from (the CAS on warnings_epoch)
        let final_warning = if self.kind == ProtNoticeKind::Final {
            let tank = find_tank_in(db, session, &self.tank_id)
                .await?
                .ok_or_else(|| refuse(create_error!(NotFound)))?;
            if tank.warnings_epoch != self.epoch {
                return Ok(false);
            }
            Some(tank)
        } else {
            None
        };

        insert_in(
            db,
            session,
            NOTICES,
            &ProtNotice {
                id: key.clone(),
                tank_id: self.tank_id.clone(),
                sent_at: self.now,
                delivered: self.delivered,
            },
            TxnAbort::DuplicateKey {
                key,
                payload_hash: String::new(),
            },
        )
        .await?;

        if let Some(tank) = final_warning {
            let mut after = tank.clone();
            after.final_warning_at = Some(self.now);
            write_tank(db, session, &tank, &mut after, self.now).await?;
        }
        Ok(true)
    }
}

/// set_prot_burn_paused: only when absent
struct PauseBody {
    at: i64,
}

#[async_trait]
impl ProtTxnBody for PauseBody {
    type Output = bool;

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<bool> {
        let runtime: Option<ProtRuntime> =
            find_one_in(db, session, RUNTIME, doc! { "_id": PROT_RUNTIME_ID }).await?;
        match runtime {
            Some(runtime) if runtime.burn_paused_at.is_some() => Ok(false),
            Some(runtime) => {
                let mut after = runtime.clone();
                after.burn_paused_at = Some(self.at);
                after.version = runtime.version + 1;
                let filter = version_filter(&runtime.id, runtime.version);
                cas_write(db, session, RUNTIME, filter, &runtime, &after).await?;
                Ok(true)
            }
            None => {
                // Two replicas creating the singleton: the loser re-runs and
                // finds it set
                insert_in(
                    db,
                    session,
                    RUNTIME,
                    &ProtRuntime {
                        id: PROT_RUNTIME_ID.to_string(),
                        burn_paused_at: Some(self.at),
                        version: 1,
                    },
                    TxnAbort::Stale,
                )
                .await?;
                Ok(true)
            }
        }
    }
}

/// clear_prot_burn_paused: CAS on the value
struct ClearPauseBody {
    expected: i64,
}

#[async_trait]
impl ProtTxnBody for ClearPauseBody {
    type Output = bool;

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<bool> {
        let runtime: Option<ProtRuntime> =
            find_one_in(db, session, RUNTIME, doc! { "_id": PROT_RUNTIME_ID }).await?;
        let Some(runtime) = runtime.filter(|runtime| runtime.burn_paused_at == Some(self.expected))
        else {
            return Ok(false);
        };
        let mut after = runtime.clone();
        after.burn_paused_at = None;
        after.version = runtime.version + 1;
        let mut filter = version_filter(&runtime.id, runtime.version);
        filter.insert("burn_paused_at", self.expected);
        cas_write(db, session, RUNTIME, filter, &runtime, &after).await?;
        Ok(true)
    }
}

/// shift_prot_tank_for_pause (7.4, D16)
struct ShiftBody {
    tank_id: String,
    paused_at: i64,
    now: i64,
    rules: ProtTankRules,
}

#[async_trait]
impl ProtTxnBody for ShiftBody {
    type Output = bool;

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<bool> {
        let rules = &self.rules;
        let now = self.now;
        let tank = find_tank_in(db, session, &self.tank_id)
            .await?
            .ok_or_else(|| refuse(create_error!(NotFound)))?;
        // The resume pass runs only while burning is back on (7.1 step 1)
        if !rules.burning
            || tank.pause_shift_for == Some(self.paused_at)
            || !matches!(
                tank.stage,
                v0::ProtTankStage::Active | v0::ProtTankStage::Grace | v0::ProtTankStage::Frozen
            )
        {
            return Ok(false);
        }

        // Grace and Frozen deadlines move with the pause
        let shift = now.saturating_sub(self.paused_at).max(0);
        let mut after = tank.clone();
        after.exhausted_at = tank.exhausted_at.map(|at| at.saturating_add(shift));
        after.final_warning_at = tank.final_warning_at.map(|at| at.saturating_add(shift));
        after.pause_shift_for = Some(self.paused_at);

        let mut entered_grace = false;
        let today = prot_utc_day(now);
        let due = matches!(
            after.stage,
            v0::ProtTankStage::Active | v0::ProtTankStage::Grace
        ) && after
            .next_burn_day
            .as_deref()
            .is_some_and(|day| day <= today.as_str());
        if due {
            let today_start = day_start(&today)?;
            let grace_over = after.stage == v0::ProtTankStage::Grace
                && after
                    .exhausted_at
                    .is_some_and(|at| today_start >= at.saturating_add(days_ms(rules.grace_days)));
            if grace_over {
                // Not billed: today's burn freezes it (7.2 checks Freeze first)
                after.next_burn_day = Some(today);
            } else {
                // BR12: the rest of today only; the days in between are never
                // billed. A clamped 0 writes no row and the shift still lands.
                entered_grace = burn_rest_of_today_in(db, session, &mut after, now, rules).await?;
            }
        }
        if entered_grace {
            write_entitlement_in(
                db,
                session,
                &after,
                Some(ChannelEntitlementState::Grace),
                None,
            )
            .await?;
        }
        write_tank(db, session, &tank, &mut after, now).await?;
        Ok(true)
    }
}

/// begin_prot_settlement (9.1)
struct BeginSettlementBody {
    tank_id: String,
    cause: ProtSettleCause,
    now: i64,
}

#[async_trait]
impl ProtTxnBody for BeginSettlementBody {
    type Output = Option<ProtTank>;

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<Option<ProtTank>> {
        let Some(tank) = find_tank_in(db, session, &self.tank_id).await? else {
            return Ok(None);
        };
        let traffic_stops = match tank.stage {
            v0::ProtTankStage::Active | v0::ProtTankStage::Grace | v0::ProtTankStage::Frozen => {
                true
            }
            // A delete of a never-launched tank: the entitlement is left to
            // the goal close or the capture (9.4)
            v0::ProtTankStage::Launching => false,
            // Resume
            v0::ProtTankStage::Settling => return Ok(Some(tank)),
            v0::ProtTankStage::Deleted | v0::ProtTankStage::Terminated => return Ok(None),
        };

        let mut after = tank.clone();
        after.stage = v0::ProtTankStage::Settling;
        after.settle_cause = Some(self.cause);
        if traffic_stops {
            write_entitlement_in(
                db,
                session,
                &after,
                Some(ChannelEntitlementState::Frozen),
                None,
            )
            .await?;
        }
        write_tank(db, session, &tank, &mut after, self.now).await?;
        Ok(Some(after))
    }
}

/// settle_prot_tank (9.2, D7)
struct SettleBody {
    tank_id: String,
    now: i64,
}

#[async_trait]
impl ProtTxnBody for SettleBody {
    type Output = ProtSettlement;

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<ProtSettlement> {
        let now = self.now;
        let tank_id = self.tank_id.as_str();
        let tank = find_tank_in(db, session, tank_id)
            .await?
            .ok_or_else(|| refuse(create_error!(NotFound)))?;
        let account = prot_tank_account(tank_id);
        match tank.stage {
            v0::ProtTankStage::Settling => {}
            // A racing run settled it: the stored outcome, never a conflict
            v0::ProtTankStage::Deleted => {
                let returns: Vec<ProtLedgerEntry> = find_all_in(
                    db,
                    session,
                    LEDGER,
                    doc! {
                        "ref.tank_id": tank_id,
                        "kind": v0::ProtEntryKind::Settlement.as_str(),
                        "debit": &account
                    },
                    doc! { "_id": 1_i32 },
                )
                .await?;
                let writeoff = row_in(db, session, &prot_key_writeoff(tank_id)).await?;
                return Ok(ProtSettlement {
                    tank,
                    returns,
                    writeoff,
                });
            }
            _ => return Err(refuse(create_error!(InvalidOperation))),
        }
        // Held pledges of an open goal would be stranded by a Deleted tank:
        // the caller closes (or captures) the tank's goals first (7.5, 9.4)
        let open_goal: Option<Document> = find_one_in(
            db,
            session,
            GOALS,
            doc! { "tank_id": tank_id, "state": { "$in": open_goal_state_names() } },
        )
        .await?;
        if open_goal.is_some() {
            log::error!("PROT_SETTLE_WITH_OPEN_GOAL tank={tank_id}");
            return Err(refuse(create_error!(InvalidOperation)));
        }

        // D7: FIFO lots from the tank's rows, in this transaction
        let rows: Vec<ProtLedgerEntry> = find_all_in(
            db,
            session,
            LEDGER,
            doc! { "ref.tank_id": tank_id },
            doc! { "_id": 1_i32 },
        )
        .await?;
        let pledge_ids: Vec<&str> = rows
            .iter()
            .filter(|row| row.kind == v0::ProtEntryKind::PledgeCapture && row.credit == account)
            .filter_map(|row| row.reference.pledge_id.as_deref())
            .collect();
        let pledges: HashMap<String, ProtPledge> = if pledge_ids.is_empty() {
            HashMap::new()
        } else {
            find_all_in::<ProtPledge>(
                db,
                session,
                PLEDGES,
                doc! { "_id": { "$in": &pledge_ids } },
                doc! { "_id": 1_i32 },
            )
            .await?
            .into_iter()
            .map(|pledge| (pledge.id.clone(), pledge))
            .collect()
        };

        let bad_lot = |row: &ProtLedgerEntry| {
            log::error!("PROT_SETTLE_BAD_LOT row={}", row.id);
            refuse(create_error!(InternalError))
        };
        let mut lots: Vec<ProtLot> = Vec::new();
        let mut lot_of_pledge: HashMap<String, usize> = HashMap::new();
        let mut burned: i64 = 0;
        for row in &rows {
            match row.kind {
                v0::ProtEntryKind::Contribution if row.credit == account => {
                    let user_id = wallet_user(&row.debit).ok_or_else(|| bad_lot(row))?;
                    lots.push(ProtLot {
                        key: row.id.clone(),
                        user_id: user_id.to_string(),
                        created_at: row.created_at,
                        amount: row.amount,
                    });
                }
                v0::ProtEntryKind::PledgeCapture if row.credit == account => {
                    let pledge = row
                        .reference
                        .pledge_id
                        .as_deref()
                        .and_then(|pledge_id| pledges.get(pledge_id))
                        .ok_or_else(|| bad_lot(row))?;
                    lot_of_pledge.insert(pledge.id.clone(), lots.len());
                    lots.push(ProtLot {
                        key: row.id.clone(),
                        user_id: pledge.user_id.clone(),
                        created_at: row.created_at,
                        amount: row.amount,
                    });
                }
                v0::ProtEntryKind::Burn | v0::ProtEntryKind::TierUpgrade
                    if row.debit == account =>
                {
                    burned = burned.saturating_add(row.amount);
                }
                _ => {}
            }
        }
        // A launch return reduces the lot of the SAME pledge (C is never
        // paid twice)
        for row in &rows {
            if row.kind != v0::ProtEntryKind::LaunchReturn || row.debit != account {
                continue;
            }
            if let Some(index) = row
                .reference
                .pledge_id
                .as_deref()
                .and_then(|pledge_id| lot_of_pledge.get(pledge_id))
            {
                lots[*index].amount = lots[*index].amount.saturating_sub(row.amount);
            }
        }
        let balance = tank_balance_in(db, session, tank_id).await?;
        let plan = plan_prot_settlement(&lots, burned, balance);
        if plan.mismatch {
            log::error!("PROT_SETTLE_MISMATCH tank={tank_id} balance={balance} burned={burned}");
        }

        let mut returns = Vec::new();
        for (user_id, amount) in &plan.returns {
            returns.push(
                post(
                    db,
                    session,
                    &exact_posting(
                        prot_key_settle(tank_id, user_id),
                        v0::ProtEntryKind::Settlement,
                        (account.clone(), prot_user_account(user_id)),
                        *amount,
                        PROT_ACTOR_SETTLEMENT,
                        tank_ref(tank_id),
                        now,
                    ),
                )
                .await?,
            );
        }
        let writeoff = if plan.writeoff > 0 {
            Some(
                post(
                    db,
                    session,
                    &exact_posting(
                        prot_key_writeoff(tank_id),
                        v0::ProtEntryKind::WriteOff,
                        (PROT_SYS_WRITEOFF.to_string(), account.clone()),
                        plan.writeoff,
                        PROT_ACTOR_SETTLEMENT,
                        tank_ref(tank_id),
                        now,
                    ),
                )
                .await?,
            )
        } else {
            None
        };

        let mut after = tank.clone();
        after.stage = v0::ProtTankStage::Deleted;
        after.ended_at = Some(now);
        write_entitlement_in(
            db,
            session,
            &after,
            Some(ChannelEntitlementState::Deleted),
            None,
        )
        .await?;
        write_tank(db, session, &tank, &mut after, now).await?;

        Ok(ProtSettlement {
            tank: after,
            returns,
            writeoff,
        })
    }
}

/// Transaction 1 of a termination (9.5): Active/Grace/Frozen -> Terminated,
/// entitlement -> Deleted, a negative balance written off and a positive one
/// forfeited. An already Terminated tank returns its stored rows (resume).
struct TerminateBody {
    tank_id: String,
    admin_id: String,
    reason: String,
    now: i64,
}

#[async_trait]
impl ProtTxnBody for TerminateBody {
    type Output = (ProtTank, Option<ProtLedgerEntry>, Option<ProtLedgerEntry>);

    async fn run(
        &self,
        db: &MongoDb,
        session: &mut ClientSession,
    ) -> Step<(ProtTank, Option<ProtLedgerEntry>, Option<ProtLedgerEntry>)> {
        let now = self.now;
        let tank_id = self.tank_id.as_str();
        let tank = find_tank_in(db, session, tank_id)
            .await?
            .ok_or_else(|| refuse(create_error!(NotFound)))?;
        match tank.stage {
            v0::ProtTankStage::Active | v0::ProtTankStage::Grace | v0::ProtTankStage::Frozen => {}
            v0::ProtTankStage::Terminated => {
                let forfeit = row_in(db, session, &prot_key_forfeit_tank(tank_id)).await?;
                let writeoff = row_in(db, session, &prot_key_writeoff(tank_id)).await?;
                return Ok((tank, forfeit, writeoff));
            }
            _ => return Err(refuse(create_error!(InvalidOperation))),
        }

        let balance = tank_balance_in(db, session, tank_id).await?;
        let account = prot_tank_account(tank_id);
        let reason = Some(self.reason.clone()).filter(|reason| !reason.is_empty());
        let mut forfeit = None;
        let mut writeoff = None;
        if balance < 0 {
            writeoff = Some(
                post(
                    db,
                    session,
                    &ProtPosting {
                        reason: reason.clone(),
                        ..exact_posting(
                            prot_key_writeoff(tank_id),
                            v0::ProtEntryKind::WriteOff,
                            (PROT_SYS_WRITEOFF.to_string(), account.clone()),
                            balance.saturating_neg(),
                            &self.admin_id,
                            tank_ref(tank_id),
                            now,
                        )
                    },
                )
                .await?,
            );
        } else if balance > 0 {
            // BR15: Exact(balance), never All (the tank floor is negative)
            forfeit = Some(
                post(
                    db,
                    session,
                    &ProtPosting {
                        reason,
                        ..exact_posting(
                            prot_key_forfeit_tank(tank_id),
                            v0::ProtEntryKind::ForfeitTank,
                            (account, PROT_SYS_FORFEITED.to_string()),
                            balance,
                            &self.admin_id,
                            tank_ref(tank_id),
                            now,
                        )
                    },
                )
                .await?,
            );
        }

        let mut after = tank.clone();
        after.stage = v0::ProtTankStage::Terminated;
        after.settle_cause = Some(ProtSettleCause::Termination);
        after.terminated_by = Some(self.admin_id.clone());
        after.ended_at = Some(now);
        after.purge_passes = 0;
        write_entitlement_in(
            db,
            session,
            &after,
            Some(ChannelEntitlementState::Deleted),
            None,
        )
        .await?;
        write_tank(db, session, &tank, &mut after, now).await?;
        Ok((after, forfeit, writeoff))
    }
}

/// mark_prot_tank_purged: purge_passes += 1
struct MarkPurgedBody {
    tank_id: String,
    now: i64,
}

#[async_trait]
impl ProtTxnBody for MarkPurgedBody {
    type Output = ();

    async fn run(&self, db: &MongoDb, session: &mut ClientSession) -> Step<()> {
        let tank = find_tank_in(db, session, &self.tank_id)
            .await?
            .ok_or_else(|| refuse(create_error!(NotFound)))?;
        if !matches!(
            tank.stage,
            v0::ProtTankStage::Deleted | v0::ProtTankStage::Terminated
        ) {
            return Err(refuse(create_error!(InvalidOperation)));
        }
        let mut after = tank.clone();
        after.purge_passes = tank.purge_passes.saturating_add(1);
        after.purged_at = Some(self.now);
        write_tank(db, session, &tank, &mut after, self.now).await
    }
}

// ---------------------------------------------------------------------------
// Runners and reads outside any transaction
// ---------------------------------------------------------------------------

/// Run a body whose duplicate ledger key or moved state means a racing run
/// committed: re-run it (it then finds the state moved and returns what that
/// state says), at most PROT_STATE_RETRIES times
async fn run_rerunning<B: ProtTxnBody>(
    db: &MongoDb,
    body: &B,
    operation: &str,
    id: &str,
) -> Result<B::Output> {
    ensure_replica_set(db).await?;
    for _ in 0..PROT_STATE_RETRIES {
        match run_prot_transaction(db, body).await? {
            TxnEnd::Committed(output) => return Ok(output),
            TxnEnd::DuplicateKey { key, .. } => {
                log::warn!("PROT_TANK_RACE op={operation} id={id} key={key:?}")
            }
            TxnEnd::StateMoved => {}
        }
    }
    Err(retries_exhausted(operation, id))
}

async fn read_one<T>(db: &MongoDb, collection: &'static str, filter: Document) -> Result<Option<T>>
where
    T: DeserializeOwned + Send + Sync + Unpin,
{
    db.col::<T>(collection)
        .find_one(filter)
        .await
        .map_err(|_| create_database_error!("find_one", collection))
}

/// Every row matching `filter` in `sort` order, at most `limit`. A row that
/// fails to decode fails the read: nothing is ever skipped silently.
async fn read_all<T>(
    db: &MongoDb,
    collection: &'static str,
    filter: Document,
    sort: Document,
    limit: Option<i64>,
) -> Result<Vec<T>>
where
    T: DeserializeOwned + Send + Sync + Unpin,
{
    let rows = db.col::<T>(collection);
    let mut find = rows.find(filter).sort(sort);
    if let Some(limit) = limit {
        find = find.limit(limit);
    }
    find.await
        .map_err(|_| create_database_error!("find", collection))?
        .try_collect()
        .await
        .map_err(|_| create_database_error!("find", collection))
}

/// Per user: (net Prot put into the tank since `since_ms`, (created_at, _id)
/// of the first counted row). Contributions + captures of the user's pledges
/// - launch returns of those captured pledges (19.2).
async fn tank_contributions_since(
    db: &MongoDb,
    tank_id: &str,
    since_ms: i64,
) -> Result<BTreeMap<String, (i64, (i64, String))>> {
    let account = prot_tank_account(tank_id);
    let rows: Vec<ProtLedgerEntry> = read_all(
        db,
        LEDGER,
        doc! {
            "ref.tank_id": tank_id,
            "kind": {
                "$in": [
                    v0::ProtEntryKind::Contribution.as_str(),
                    v0::ProtEntryKind::PledgeCapture.as_str(),
                    v0::ProtEntryKind::LaunchReturn.as_str(),
                ]
            }
        },
        doc! { "_id": 1_i32 },
        None,
    )
    .await?;

    let pledge_ids: Vec<&str> = rows
        .iter()
        .filter(|row| {
            row.kind == v0::ProtEntryKind::PledgeCapture
                && row.credit == account
                && row.created_at >= since_ms
        })
        .filter_map(|row| row.reference.pledge_id.as_deref())
        .collect();
    let pledge_users: HashMap<String, String> = if pledge_ids.is_empty() {
        HashMap::new()
    } else {
        read_all::<ProtPledge>(
            db,
            PLEDGES,
            doc! { "_id": { "$in": &pledge_ids } },
            doc! { "_id": 1_i32 },
            None,
        )
        .await?
        .into_iter()
        .map(|pledge| (pledge.id, pledge.user_id))
        .collect()
    };

    let mut totals: BTreeMap<String, (i64, (i64, String))> = BTreeMap::new();
    let mut counted: HashMap<String, String> = HashMap::new();
    for row in rows.iter().filter(|row| row.created_at >= since_ms) {
        let user_id = match row.kind {
            v0::ProtEntryKind::Contribution if row.credit == account => {
                wallet_user(&row.debit).map(str::to_string)
            }
            v0::ProtEntryKind::PledgeCapture if row.credit == account => {
                row.reference.pledge_id.as_deref().and_then(|pledge_id| {
                    let user_id = pledge_users.get(pledge_id)?;
                    counted.insert(pledge_id.to_string(), user_id.clone());
                    Some(user_id.clone())
                })
            }
            _ => None,
        };
        if let Some(user_id) = user_id {
            let first = (row.created_at, row.id.clone());
            let total = totals.entry(user_id).or_insert((0, first.clone()));
            total.0 = total.0.saturating_add(row.amount);
            if first < total.1 {
                total.1 = first;
            }
        }
    }
    for row in &rows {
        if row.kind != v0::ProtEntryKind::LaunchReturn || row.debit != account {
            continue;
        }
        let user_id = row
            .reference
            .pledge_id
            .as_deref()
            .and_then(|pledge_id| counted.get(pledge_id));
        if let Some(total) = user_id.and_then(|user_id| totals.get_mut(user_id)) {
            total.0 = total.0.saturating_sub(row.amount);
        }
    }
    Ok(totals)
}

/// `flags & Deleted` of a user document; a missing user counts as deleted
fn user_is_deleted(user: Option<&Document>) -> bool {
    let Some(user) = user else {
        return true;
    };
    let flags = match user.get("flags") {
        Some(Bson::Int32(flags)) => i64::from(*flags),
        Some(Bson::Int64(flags)) => *flags,
        _ => 0,
    };
    flags & (v0::UserFlags::Deleted as i64) != 0
}

#[async_trait]
impl AbstractProtTanks for MongoDb {
    async fn fetch_prot_tank(&self, tank_id: &str) -> Result<Option<ProtTank>> {
        read_one(self, TANKS, doc! { "_id": tank_id }).await
    }

    async fn fetch_prot_tank_by_channel(&self, channel_id: &str) -> Result<Option<ProtTank>> {
        read_one(
            self,
            TANKS,
            doc! { "target_key": prot_tank_target_key(channel_id) },
        )
        .await
    }

    async fn fetch_prot_tanks_by_server(&self, server_id: &str) -> Result<Vec<ProtTank>> {
        read_all(
            self,
            TANKS,
            doc! { "server_id": server_id },
            doc! { "_id": 1_i32 },
            None,
        )
        .await
    }

    async fn fetch_prot_goal(&self, goal_id: &str) -> Result<Option<ProtGoal>> {
        read_one(self, GOALS, doc! { "_id": goal_id }).await
    }

    async fn fetch_open_prot_goals_by_server(&self, server_id: &str) -> Result<Vec<ProtGoal>> {
        read_all(
            self,
            GOALS,
            doc! { "server_id": server_id, "state": { "$in": open_goal_state_names() } },
            doc! { "_id": 1_i32 },
            None,
        )
        .await
    }

    async fn fetch_open_prot_goals_by_tank(&self, tank_id: &str) -> Result<Vec<ProtGoal>> {
        read_all(
            self,
            GOALS,
            doc! { "tank_id": tank_id, "state": { "$in": open_goal_state_names() } },
            doc! { "_id": 1_i32 },
            None,
        )
        .await
    }

    async fn fetch_prot_pledge(&self, pledge_id: &str) -> Result<Option<ProtPledge>> {
        read_one(self, PLEDGES, doc! { "_id": pledge_id }).await
    }

    async fn fetch_prot_pledges_by_goal(&self, goal_id: &str) -> Result<Vec<ProtPledge>> {
        read_all(
            self,
            PLEDGES,
            doc! { "goal_id": goal_id },
            doc! { "_id": 1_i32 },
            None,
        )
        .await
    }

    async fn fetch_held_prot_pledges_by_user(&self, user_id: &str) -> Result<Vec<ProtPledge>> {
        read_all(
            self,
            PLEDGES,
            doc! { "user_id": user_id, "state": v0::ProtPledgeState::Held.as_str() },
            doc! { "_id": -1_i32 },
            None,
        )
        .await
    }

    async fn fetch_prot_entries_by_tank(&self, tank_id: &str) -> Result<Vec<ProtLedgerEntry>> {
        read_all(
            self,
            LEDGER,
            doc! { "ref.tank_id": tank_id },
            doc! { "_id": 1_i32 },
            None,
        )
        .await
    }

    async fn fetch_prot_contributor_prefs(
        &self,
        server_id: &str,
        user_ids: &[String],
    ) -> Result<Vec<ProtContributorPref>> {
        if user_ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<String> = user_ids
            .iter()
            .map(|user_id| pref_id(server_id, user_id))
            .collect();
        let found: HashMap<String, ProtContributorPref> = read_all::<ProtContributorPref>(
            self,
            PREFS,
            doc! { "_id": { "$in": &ids } },
            doc! { "_id": 1_i32 },
            None,
        )
        .await?
        .into_iter()
        .map(|pref| (pref.id.clone(), pref))
        .collect();
        // In the order asked for, as the Reference driver returns them
        Ok(ids.iter().filter_map(|id| found.get(id).cloned()).collect())
    }

    async fn fetch_prot_runtime(&self) -> Result<Option<ProtRuntime>> {
        read_one(self, RUNTIME, doc! { "_id": PROT_RUNTIME_ID }).await
    }

    async fn recent_contribution(
        &self,
        user_id: &str,
        tank_id: &str,
        since_ms: i64,
    ) -> Result<i64> {
        Ok(tank_contributions_since(self, tank_id, since_ms)
            .await?
            .get(user_id)
            .map_or(0, |(net, _)| (*net).max(0)))
    }

    async fn top_contributor(&self, tank_id: &str, since_ms: i64) -> Result<Option<String>> {
        let Some(tank) = self.fetch_prot_tank(tank_id).await? else {
            return Ok(None);
        };
        let mut candidates: Vec<(String, i64, (i64, String))> =
            tank_contributions_since(self, tank_id, since_ms)
                .await?
                .into_iter()
                .filter(|(_, (net, _))| *net > 0)
                .map(|(user_id, (net, first))| (user_id, net, first))
                .collect();
        if candidates.is_empty() {
            return Ok(None);
        }

        // Hidden contributors are never named, not even here (BR10)
        let user_ids: Vec<String> = candidates
            .iter()
            .map(|(user_id, _, _)| user_id.clone())
            .collect();
        let hidden: HashSet<String> = self
            .fetch_prot_contributor_prefs(&tank.server_id, &user_ids)
            .await?
            .into_iter()
            .filter(|pref| pref.hidden)
            .map(|pref| pref.id)
            .collect();
        candidates.retain(|(user_id, _, _)| !hidden.contains(&pref_id(&tank.server_id, user_id)));
        candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.2.cmp(&b.2)));

        let ids: Vec<&str> = candidates
            .iter()
            .map(|(user_id, _, _)| user_id.as_str())
            .collect();
        let users: HashMap<String, Document> = read_all::<Document>(
            self,
            USERS,
            doc! { "_id": { "$in": &ids } },
            doc! { "_id": 1_i32 },
            None,
        )
        .await?
        .into_iter()
        .filter_map(|user| Some((user.get_str("_id").ok()?.to_string(), user)))
        .collect();
        Ok(candidates
            .into_iter()
            .map(|(user_id, _, _)| user_id)
            .find(|user_id| !user_is_deleted(users.get(user_id))))
    }

    async fn fetch_prot_tanks_due_burn(&self, today: &str, limit: i64) -> Result<Vec<ProtTank>> {
        read_all(
            self,
            TANKS,
            doc! {
                "stage": {
                    "$in": [
                        v0::ProtTankStage::Active.as_str(),
                        v0::ProtTankStage::Grace.as_str(),
                    ]
                },
                "next_burn_day": { "$lte": today }
            },
            doc! { "next_burn_day": 1_i32, "_id": 1_i32 },
            Some(page_size(limit)),
        )
        .await
    }

    async fn fetch_prot_tanks_by_stage(
        &self,
        stages: &[v0::ProtTankStage],
        after_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ProtTank>> {
        if stages.is_empty() {
            return Ok(Vec::new());
        }
        let stages: Vec<&str> = stages.iter().map(|stage| stage.as_str()).collect();
        let mut filter = doc! { "stage": { "$in": stages } };
        if let Some(after_id) = after_id {
            filter.insert("_id", doc! { "$gt": after_id });
        }
        read_all(
            self,
            TANKS,
            filter,
            doc! { "_id": 1_i32 },
            Some(page_size(limit)),
        )
        .await
    }

    async fn fetch_prot_tanks_to_purge(
        &self,
        after_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ProtTank>> {
        let mut filter = doc! {
            "stage": {
                "$in": [
                    v0::ProtTankStage::Deleted.as_str(),
                    v0::ProtTankStage::Terminated.as_str(),
                ]
            },
            // An absent counter is 0 (`#[serde(default)]`)
            "purge_passes": { "$not": { "$gte": 2_i64 } }
        };
        if let Some(after_id) = after_id {
            filter.insert("_id", doc! { "$gt": after_id });
        }
        read_all(
            self,
            TANKS,
            filter,
            doc! { "_id": 1_i32 },
            Some(page_size(limit)),
        )
        .await
    }

    async fn fetch_prot_goals_due(
        &self,
        now: i64,
        launch_seat_window_ms: i64,
        limit: i64,
    ) -> Result<Vec<ProtGoal>> {
        let funding = v0::ProtGoalState::Funding.as_str();
        let funded = v0::ProtGoalState::Funded.as_str();
        let launching = v0::ProtGoalState::Launching.as_str();
        let launched = v0::ProtGoalState::Launched.as_str();
        read_all(
            self,
            GOALS,
            doc! {
                "$or": [
                    { "state": funding, "deadline_at": { "$lte": now } },
                    { "state": funded, "launch_deadline_at": { "$lte": now } },
                    // The capture backstop: any time
                    { "state": launching },
                    {
                        "state": launched,
                        "kind": goal_kind_name(v0::ProtGoalKind::Launch),
                        "refund7_done": { "$ne": true },
                        "launched_at": { "$lte": now.saturating_sub(launch_seat_window_ms) }
                    },
                    // Apply, or the 8.7 exit past launch_deadline_at
                    { "state": funded, "kind": goal_kind_name(v0::ProtGoalKind::Upgrade) },
                ]
            },
            doc! { "_id": 1_i32 },
            Some(page_size(limit)),
        )
        .await
    }

    async fn set_prot_contributor_pref(
        &self,
        server_id: &str,
        user_id: &str,
        hidden: bool,
        now: i64,
    ) -> Result<()> {
        let body = PrefBody {
            server_id: server_id.to_string(),
            user_id: user_id.to_string(),
            hidden,
            now,
        };
        run_rerunning(self, &body, "set_prot_contributor_pref", server_id).await
    }

    async fn contribute_prot(&self, input: &ProtContributeInput) -> Result<ProtContributeOutcome> {
        // The floor is not hashed, so this is the stored row's payload
        let posting = contribution_posting(input, 0);
        validate_prot_posting(&posting)?;
        let key = posting.key.clone();
        let payload_hash = prot_payload_hash(&posting);

        // A replay is decided before the stage (S5a: a duplicate key is
        // decided before the floor)
        let replay = |stored: Option<ProtLedgerEntry>| async move {
            let outcome = duplicate_outcome(&key, &payload_hash, stored)?;
            let tank = self
                .fetch_prot_tank(&input.tank_id)
                .await?
                .ok_or_else(|| create_error!(NotFound))?;
            Ok::<_, revolt_result::Error>(ProtContributeOutcome::AlreadyApplied {
                entry: outcome.entry().clone(),
                tank,
            })
        };
        if let Some(stored) = self.fetch_prot_entry_by_key(&posting.key).await? {
            return replay(Some(stored)).await;
        }

        ensure_replica_set(self).await?;
        let body = ContributeBody {
            input: input.clone(),
        };
        for _ in 0..PROT_STATE_RETRIES {
            match run_prot_transaction(self, &body).await {
                Ok(TxnEnd::Committed(outcome)) => return Ok(outcome),
                Ok(TxnEnd::DuplicateKey { key, .. }) if key == posting.key => {
                    let stored = self.fetch_prot_entry_by_key(&key).await?;
                    return replay(stored).await;
                }
                // Today's reactivation burn raced the clock: re-run on the
                // state it left
                Ok(TxnEnd::DuplicateKey { .. }) | Ok(TxnEnd::StateMoved) => {}
                // A replay of a contribution that was applied is
                // AlreadyApplied whatever the wallet holds now
                Err(error) if matches!(error.error_type, ErrorType::InsufficientProt { .. }) => {
                    return match self.fetch_prot_entry_by_key(&posting.key).await? {
                        Some(stored) => replay(Some(stored)).await,
                        None => Err(error),
                    };
                }
                Err(error) => return Err(error),
            }
        }
        Err(retries_exhausted("contribute_prot", &input.tank_id))
    }

    async fn create_prot_goal(&self, goal: &ProtGoal) -> Result<ProtGoal> {
        if goal.state != v0::ProtGoalState::Funding
            || goal.pledged_total != 0
            || goal.open_key.is_none()
            || goal.target_prot <= 0
        {
            log::error!("PROT_GOAL_INVALID goal={}", goal.id);
            return Err(create_error!(InternalError));
        }

        ensure_replica_set(self).await?;
        let body = CreateGoalBody { goal: goal.clone() };
        for _ in 0..PROT_STATE_RETRIES {
            match run_prot_transaction(self, &body).await? {
                TxnEnd::Committed(goal) => return Ok(goal),
                TxnEnd::DuplicateKey { .. } => {
                    // The unique open_key: one open launch goal per server,
                    // one open upgrade goal per tank (BR14). A retry of the
                    // same request finds the goal it made.
                    let open: Option<ProtGoal> =
                        read_one(self, GOALS, doc! { "open_key": &goal.open_key }).await?;
                    if let Some(open) = open {
                        return if open.created_by == goal.created_by
                            && open.create_nonce == goal.create_nonce
                        {
                            Ok(open)
                        } else {
                            Err(create_error!(ProtGoalClosed))
                        };
                    }
                    if self.fetch_prot_goal(&goal.id).await?.is_some() {
                        log::error!("PROT_GOAL_ID_TAKEN goal={}", goal.id);
                        return Err(create_error!(InternalError));
                    }
                    // The open goal closed since: insert again
                }
                TxnEnd::StateMoved => {}
            }
        }
        Err(retries_exhausted("create_prot_goal", &goal.id))
    }

    async fn pledge_prot(&self, input: &ProtPledgeInput) -> Result<ProtPledgeOutcome> {
        if input.amount < 1 {
            return Err(create_error!(FailedValidation {
                error: "amount must be at least 1".to_string()
            }));
        }
        let key = prot_key_pledge(&input.user_id, &input.goal_id, &input.nonce);
        let wallet = prot_user_account(&input.user_id);
        let hold = prot_hold_account(&input.goal_id);

        // A replay (also a concurrent request with the same nonce, audit 27)
        // returns the stored pledge. The capped amount may differ, so the
        // payload hash is not compared: debit, credit and goal are.
        let replay = |stored: ProtLedgerEntry| async move {
            if stored.debit != wallet
                || stored.credit != hold
                || stored.reference.goal_id.as_deref() != Some(input.goal_id.as_str())
            {
                log::warn!("PROT_IDEMPOTENCY_CONFLICT key={:?}", stored.key);
                return Err(create_error!(ProtIdempotencyConflict));
            }
            let pledge = match stored.reference.pledge_id.as_deref() {
                Some(pledge_id) => self.fetch_prot_pledge(pledge_id).await?,
                None => None,
            }
            .ok_or_else(|| {
                log::error!("PROT_PLEDGE_ROW_WITHOUT_PLEDGE key={:?}", stored.key);
                create_error!(InternalError)
            })?;
            let goal = self
                .fetch_prot_goal(&input.goal_id)
                .await?
                .ok_or_else(|| create_error!(NotFound))?;
            Ok::<_, revolt_result::Error>(ProtPledgeOutcome {
                pledge,
                goal,
                entry: stored,
                already_applied: true,
                funded_now: false,
            })
        };
        if let Some(stored) = self.fetch_prot_entry_by_key(&key).await? {
            return replay(stored).await;
        }

        ensure_replica_set(self).await?;
        let body = PledgeBody {
            input: input.clone(),
            pledge_id: ulid::Ulid::new().to_string(),
        };
        for _ in 0..PROT_STATE_RETRIES {
            match run_prot_transaction(self, &body).await {
                Ok(TxnEnd::Committed(outcome)) => return Ok(outcome),
                Ok(TxnEnd::DuplicateKey { key, .. }) => {
                    let stored = self
                        .fetch_prot_entry_by_key(&key)
                        .await?
                        .ok_or_else(|| duplicate_without_row(&key))?;
                    return replay(stored).await;
                }
                Ok(TxnEnd::StateMoved) => {}
                Err(error) if matches!(error.error_type, ErrorType::InsufficientProt { .. }) => {
                    return match self.fetch_prot_entry_by_key(&key).await? {
                        Some(stored) => replay(stored).await,
                        None => Err(error),
                    };
                }
                Err(error) => return Err(error),
            }
        }
        Err(retries_exhausted("pledge_prot", &input.goal_id))
    }

    async fn withdraw_prot_pledge(
        &self,
        pledge_id: &str,
        user_id: &str,
        now: i64,
        cutoff_ms: i64,
    ) -> Result<ProtPledge> {
        let body = WithdrawBody {
            pledge_id: pledge_id.to_string(),
            user_id: user_id.to_string(),
            now,
            cutoff_ms,
        };
        // A taken `pledge-withdraw:` key is a racing withdraw that committed:
        // the re-run finds the pledge no longer Held
        run_rerunning(self, &body, "withdraw_prot_pledge", pledge_id).await
    }

    async fn close_prot_goal(
        &self,
        goal_id: &str,
        to: v0::ProtGoalState,
        now: i64,
    ) -> Result<ProtGoalCloseOutcome> {
        let body = CloseBody {
            goal_id: goal_id.to_string(),
            to,
            now,
        };
        run_rerunning(self, &body, "close_prot_goal", goal_id).await
    }

    async fn launch_prot_goal(&self, input: &ProtLaunchInput) -> Result<(ProtGoal, ProtTank)> {
        let body = LaunchBody {
            input: input.clone(),
            tank_id: ulid::Ulid::new().to_string(),
            entitlement_id: ulid::Ulid::new().to_string(),
        };
        run_rerunning(self, &body, "launch_prot_goal", &input.goal_id).await
    }

    async fn capture_launch_pledges(
        &self,
        channel_id: &str,
        now: i64,
        rules: &ProtTankRules,
    ) -> Result<Option<ProtTank>> {
        let body = CaptureBody {
            channel_id: channel_id.to_string(),
            now,
            rules: Some(rules.clone()),
        };
        run_rerunning(self, &body, "capture_launch_pledges", channel_id).await
    }

    async fn return_unseated_launch_pledges(
        &self,
        goal_id: &str,
        now: i64,
    ) -> Result<Vec<ProtLedgerEntry>> {
        let body = UnseatedBody {
            goal_id: goal_id.to_string(),
            now,
        };
        run_rerunning(self, &body, "return_unseated_launch_pledges", goal_id).await
    }

    async fn apply_prot_upgrade_goal(
        &self,
        goal_id: &str,
        now: i64,
        rules: &ProtTankRules,
    ) -> Result<Option<ProtTank>> {
        let body = ApplyBody {
            goal_id: goal_id.to_string(),
            now,
            rules: rules.clone(),
        };
        run_rerunning(self, &body, "apply_prot_upgrade_goal", goal_id).await
    }

    async fn change_prot_tier(&self, input: &ProtTierChangeInput) -> Result<ProtTank> {
        let key = prot_key_tier(&input.tank_id, &input.change_id);
        let current = || async move {
            self.fetch_prot_tank(&input.tank_id)
                .await?
                .ok_or_else(|| create_error!(NotFound))
        };

        ensure_replica_set(self).await?;
        let body = TierBody {
            input: input.clone(),
        };
        for _ in 0..PROT_STATE_RETRIES {
            match run_prot_transaction(self, &body).await {
                Ok(TxnEnd::Committed(tank)) => return Ok(tank),
                // A racing request with the same change id applied it
                Ok(TxnEnd::DuplicateKey { .. }) => return current().await,
                Ok(TxnEnd::StateMoved) => {}
                Err(error) if matches!(error.error_type, ErrorType::InsufficientProt { .. }) => {
                    return match self.fetch_prot_entry_by_key(&key).await? {
                        Some(_) => current().await,
                        None => Err(error),
                    };
                }
                Err(error) => return Err(error),
            }
        }
        Err(retries_exhausted("change_prot_tier", &input.tank_id))
    }

    async fn apply_pending_prot_tier(
        &self,
        tank_id: &str,
        now: i64,
        rules: &ProtTankRules,
    ) -> Result<Option<ProtTank>> {
        let body = PendingTierBody {
            tank_id: tank_id.to_string(),
            now,
            rules: rules.clone(),
        };
        run_rerunning(self, &body, "apply_pending_prot_tier", tank_id).await
    }

    async fn burn_prot_tank_day(
        &self,
        tank_id: &str,
        day: &str,
        paused: Option<i64>,
        now: i64,
        rules: &ProtTankRules,
    ) -> Result<ProtBurnOutcome> {
        ensure_replica_set(self).await?;
        let body = BurnBody {
            tank_id: tank_id.to_string(),
            day: day.to_string(),
            paused,
            now,
            rules: rules.clone(),
        };
        for _ in 0..PROT_STATE_RETRIES {
            match run_prot_transaction(self, &body).await? {
                TxnEnd::Committed(outcome) => return Ok(outcome),
                // `burn:{tank}:{day}` is the clock's lock: a racing replica
                // billed the day. S5a semantics, then the tank as it left it.
                TxnEnd::DuplicateKey { key, payload_hash } => {
                    let stored = self.fetch_prot_entry_by_key(&key).await?;
                    duplicate_outcome(&key, &payload_hash, stored)?;
                    let tank = self
                        .fetch_prot_tank(tank_id)
                        .await?
                        .ok_or_else(|| create_error!(NotFound))?;
                    return Ok(ProtBurnOutcome::NotDue { tank });
                }
                TxnEnd::StateMoved => {}
            }
        }
        Err(retries_exhausted("burn_prot_tank_day", tank_id))
    }

    async fn record_prot_notice(
        &self,
        tank_id: &str,
        epoch: u64,
        kind: ProtNoticeKind,
        delivered: bool,
        now: i64,
    ) -> Result<bool> {
        ensure_replica_set(self).await?;
        let body = NoticeBody {
            tank_id: tank_id.to_string(),
            epoch,
            kind,
            delivered,
            now,
        };
        for _ in 0..PROT_STATE_RETRIES {
            match run_prot_transaction(self, &body).await? {
                TxnEnd::Committed(recorded) => return Ok(recorded),
                // A racing replica recorded it first
                TxnEnd::DuplicateKey { .. } => return Ok(false),
                TxnEnd::StateMoved => {}
            }
        }
        Err(retries_exhausted("record_prot_notice", tank_id))
    }

    async fn set_prot_burn_paused(&self, at: i64) -> Result<bool> {
        run_rerunning(
            self,
            &PauseBody { at },
            "set_prot_burn_paused",
            PROT_RUNTIME_ID,
        )
        .await
    }

    async fn clear_prot_burn_paused(&self, expected: i64) -> Result<bool> {
        run_rerunning(
            self,
            &ClearPauseBody { expected },
            "clear_prot_burn_paused",
            PROT_RUNTIME_ID,
        )
        .await
    }

    async fn shift_prot_tank_for_pause(
        &self,
        tank_id: &str,
        paused_at: i64,
        now: i64,
        rules: &ProtTankRules,
    ) -> Result<bool> {
        let body = ShiftBody {
            tank_id: tank_id.to_string(),
            paused_at,
            now,
            rules: rules.clone(),
        };
        run_rerunning(self, &body, "shift_prot_tank_for_pause", tank_id).await
    }

    async fn begin_prot_settlement(
        &self,
        tank_id: &str,
        cause: ProtSettleCause,
        now: i64,
    ) -> Result<Option<ProtTank>> {
        let body = BeginSettlementBody {
            tank_id: tank_id.to_string(),
            cause,
            now,
        };
        run_rerunning(self, &body, "begin_prot_settlement", tank_id).await
    }

    async fn settle_prot_tank(&self, tank_id: &str, now: i64) -> Result<ProtSettlement> {
        let body = SettleBody {
            tank_id: tank_id.to_string(),
            now,
        };
        run_rerunning(self, &body, "settle_prot_tank", tank_id).await
    }

    async fn terminate_prot_tank(
        &self,
        tank_id: &str,
        admin_id: &str,
        reason: &str,
        now: i64,
    ) -> Result<ProtTermination> {
        // A tank that never launched (audit 8): protect landed -> capture
        // first (no launch-day burn: the Prot is forfeited next); not
        // protected -> the launch is abandoned with full returns, and the tank
        // no longer exists
        let tank = self
            .fetch_prot_tank(tank_id)
            .await?
            .ok_or_else(|| create_error!(NotFound))?;
        if tank.launched_at.is_none()
            && matches!(
                tank.stage,
                v0::ProtTankStage::Launching | v0::ProtTankStage::Settling
            )
        {
            let channel_id = tank_channel(&tank).map(str::to_string);
            let protected = match channel_id.as_deref() {
                Some(channel_id) => {
                    read_one::<Document>(self, CHANNELS, doc! { "_id": channel_id })
                        .await?
                        .is_some_and(|channel| is_protected(&channel))
                }
                None => false,
            };
            match (protected, channel_id) {
                (true, Some(channel_id)) => {
                    let body = CaptureBody {
                        channel_id: channel_id.clone(),
                        now,
                        rules: None,
                    };
                    run_rerunning(self, &body, "capture_launch_pledges", &channel_id).await?;
                }
                _ => {
                    for goal in self.fetch_open_prot_goals_by_tank(tank_id).await? {
                        if goal.state == v0::ProtGoalState::Launching {
                            self.close_prot_goal(&goal.id, v0::ProtGoalState::Cancelled, now)
                                .await?;
                        }
                    }
                    log::info!("AUDIT prot_terminate_unlaunched: actor={admin_id} tank={tank_id}");
                    return Err(create_error!(NotFound));
                }
            }
        }

        let body = TerminateBody {
            tank_id: tank_id.to_string(),
            admin_id: admin_id.to_string(),
            reason: reason.to_string(),
            now,
        };
        let (tank, forfeit, writeoff) =
            run_rerunning(self, &body, "terminate_prot_tank", tank_id).await?;

        // Held pledges of the tank's open goals go back (D11), each close its
        // own transaction; a crash here is finished by the clock (7.1 step 7)
        let mut closed_goals = Vec::new();
        for goal in self.fetch_open_prot_goals_by_tank(tank_id).await? {
            closed_goals.push(
                self.close_prot_goal(&goal.id, v0::ProtGoalState::Cancelled, now)
                    .await?,
            );
        }
        Ok(ProtTermination {
            tank,
            forfeit,
            writeoff,
            closed_goals,
        })
    }

    async fn purge_protected_channel_content(&self, channel_id: &str) -> Result<ProtPurgeCounts> {
        // NOT a transaction (a channel can hold 10^5 messages); idempotent.
        // Only behind a Deleted tombstone: a purge never touches a channel
        // that can still carry traffic.
        let tombstone: Option<Document> = read_one(
            self,
            ENTITLEMENTS,
            doc! {
                "channel_id": channel_id,
                "state": entitlement_state_name(&ChannelEntitlementState::Deleted)
            },
        )
        .await?;
        if tombstone.is_none() {
            log::error!("PROT_PURGE_REFUSED channel={channel_id} (no Deleted entitlement)");
            return Err(create_error!(InvalidOperation));
        }

        let messages = self
            .col::<Document>(MESSAGES)
            .delete_many(doc! { "channel": channel_id })
            .await
            .map_err(|_| create_database_error!("delete_many", MESSAGES))?
            .deleted_count;

        // The Text plane only; the entitlement tombstone, the seats, the seat
        // list and `channel.protected` all stay. The group rows go last, so a
        // purge cut short finds them again on its next pass.
        let group_ids: Vec<Bson> = read_all::<Document>(
            self,
            GROUPS,
            doc! { "channel_id": channel_id, "kind": KIND_TEXT },
            doc! { "_id": 1_i32 },
            None,
        )
        .await?
        .into_iter()
        .filter_map(|mut group| group.remove("_id"))
        .collect();
        if group_ids.is_empty() {
            return Ok(ProtPurgeCounts {
                messages,
                groups: 0,
                commits: 0,
                join_intents: 0,
                envelopes: 0,
            });
        }

        let by_group = doc! { "group_id": { "$in": &group_ids } };
        let commits = self
            .col::<Document>(COMMITS)
            .delete_many(by_group.clone())
            .await
            .map_err(|_| create_database_error!("delete_many", COMMITS))?
            .deleted_count;
        let join_intents = self
            .col::<Document>(JOIN_INTENTS)
            .delete_many(by_group.clone())
            .await
            .map_err(|_| create_database_error!("delete_many", JOIN_INTENTS))?
            .deleted_count;
        let envelopes = self
            .col::<Document>(E2EE_QUEUE)
            .delete_many(by_group)
            .await
            .map_err(|_| create_database_error!("delete_many", E2EE_QUEUE))?
            .deleted_count;
        let groups = self
            .col::<Document>(GROUPS)
            .delete_many(doc! { "_id": { "$in": &group_ids }, "kind": KIND_TEXT })
            .await
            .map_err(|_| create_database_error!("delete_many", GROUPS))?
            .deleted_count;

        Ok(ProtPurgeCounts {
            messages,
            groups,
            commits,
            join_intents,
            envelopes,
        })
    }

    async fn mark_prot_tank_purged(&self, tank_id: &str, now: i64) -> Result<()> {
        let body = MarkPurgedBody {
            tank_id: tank_id.to_string(),
            now,
        };
        run_rerunning(self, &body, "mark_prot_tank_purged", tank_id).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bson::Document;
    use iso8601_timestamp::Timestamp;
    use revolt_models::v0;
    use revolt_result::ErrorType;

    use crate::{
        prot_hours_left, prot_key_admin, prot_pro_rata, prot_tank_account, prot_tank_target_key,
        prot_user_account, Channel, ChannelEntitlement, ChannelEntitlementSource,
        ChannelEntitlementState, Database, Member, MemberCompositeKey, MongoDb, ProtAmount,
        ProtGoal, ProtLaunchInput, ProtPledgeInput, ProtPosting, ProtPurgeCounts, ProtRef,
        ProtTank, ProtTankRules, ProtTankTarget, SeatListBody, SeatListSubmission, Server,
        PROT_SYS_ADJUST,
    };

    use super::{
        entitlement_source_name, entitlement_state_name, goal_kind_name, run_prot_transaction,
        CaptureBody, TxnEnd,
    };

    const DAY: i64 = 86_400_000;
    /// 2026-10-01T13:00:00Z (11 hours left in the UTC day)
    const NOW: i64 = 1_790_812_800_000 + 13 * 3_600_000;
    const OWNER_DEVICE: &str = "00112233445566778899aabbccddeeff";
    const ADMIN: &str = "01ADMIN0000000000000000000";
    /// Protect-vs-abandon races after the sequential case
    const RACES: usize = 10;

    fn rules() -> ProtTankRules {
        ProtTankRules {
            self_serve: true,
            burning: true,
            deletion_enabled: true,
            ..ProtTankRules::from_config(&revolt_config::ProtectionFeatures::default())
                .expect("the default Prot config is valid")
        }
    }

    fn ulid() -> String {
        ulid::Ulid::new().to_string()
    }

    fn timestamp(ms: i64) -> Timestamp {
        Timestamp::UNIX_EPOCH
            .checked_add(iso8601_timestamp::Duration::milliseconds(ms))
            .unwrap()
    }

    /// The collections the bodies touch and every index they rely on, as the
    /// migration installs them (`database_test!` hands out an unmigrated DB)
    async fn install(mongo: &MongoDb) {
        for collection in crate::PROT_COLLECTIONS
            .into_iter()
            .chain(crate::PROT_TANK_COLLECTIONS)
        {
            mongo.db().create_collection(collection).await.ok();
        }
        for collection in [
            "channels",
            "servers",
            "server_members",
            "channel_entitlements",
            "channel_seats",
            "channel_seat_lists",
            "mls_groups",
            "mls_commits",
            "mls_join_intents",
            "messages",
            "e2ee_queue",
            "users",
        ] {
            mongo.db().create_collection(collection).await.ok();
        }
        crate::create_prot_indexes(&mongo.db()).await.unwrap();
        crate::create_prot_tank_indexes(&mongo.db()).await.unwrap();
    }

    #[test]
    fn the_hand_written_names_match_serde() {
        for kind in [v0::ProtGoalKind::Launch, v0::ProtGoalKind::Upgrade] {
            assert_eq!(
                serde_json::to_value(kind).unwrap(),
                serde_json::json!(goal_kind_name(kind))
            );
        }
        for state in [
            ChannelEntitlementState::Active,
            ChannelEntitlementState::Grace,
            ChannelEntitlementState::Frozen,
            ChannelEntitlementState::Deleted,
        ] {
            assert_eq!(
                serde_json::to_value(&state).unwrap(),
                serde_json::json!(entitlement_state_name(&state))
            );
        }
        for source in [
            ChannelEntitlementSource::AdminGrant,
            ChannelEntitlementSource::Prot,
            ChannelEntitlementSource::Crowdfund,
        ] {
            assert_eq!(
                serde_json::to_value(&source).unwrap(),
                serde_json::json!(entitlement_source_name(&source))
            );
        }
    }

    fn tank(
        id: &str,
        stage: v0::ProtTankStage,
        next_burn_day: Option<&str>,
        passes: u32,
    ) -> ProtTank {
        let channel_id = format!("CH{id}");
        ProtTank {
            id: id.to_string(),
            target_key: prot_tank_target_key(&channel_id),
            target: ProtTankTarget::Channel { channel_id },
            server_id: "01SERVER".to_string(),
            created_by: "01OWNER".to_string(),
            plan: v0::ProtPlan::Channel,
            slot_tier: 10,
            pending_slot_tier: None,
            daily_cost: 40,
            rate_card: "40/90/160/280".to_string(),
            stage,
            exhausted_at: None,
            next_burn_day: next_burn_day.map(str::to_string),
            launched_at: None,
            final_warning_at: None,
            warnings_epoch: 0,
            pause_shift_for: None,
            settle_cause: None,
            ended_at: None,
            terminated_by: None,
            purged_at: None,
            purge_passes: passes,
            version: 0,
            created_at: NOW,
            updated_at: NOW,
        }
    }

    fn goal(
        id: &str,
        kind: v0::ProtGoalKind,
        state: v0::ProtGoalState,
        deadline_at: i64,
        launch_deadline_at: Option<i64>,
        launched_at: Option<i64>,
        refund7_done: bool,
    ) -> ProtGoal {
        ProtGoal {
            id: id.to_string(),
            kind,
            server_id: "01SERVER".to_string(),
            channel_id: None,
            tank_id: None,
            created_by: "01OWNER".to_string(),
            create_nonce: id.to_string(),
            slots: 10,
            days: Some(30),
            daily_cost: 40,
            base_daily_cost: None,
            target_prot: 1_200,
            pledged_total: 0,
            state,
            deadline_at,
            funded_at: None,
            launch_deadline_at,
            launched_at,
            closed_at: None,
            refund7_done,
            open_key: None,
            version: 0,
            created_at: NOW,
            updated_at: NOW,
        }
    }

    fn tank_ids(rows: Vec<ProtTank>) -> Vec<String> {
        rows.into_iter().map(|tank| tank.id).collect()
    }

    fn goal_ids(rows: Vec<ProtGoal>) -> Vec<String> {
        rows.into_iter().map(|goal| goal.id).collect()
    }

    /// The clock's and the sweep's queries are this driver's own filters
    /// (string-ordered days, `$or` of the due goal states, the purge counter)
    #[tokio::test]
    async fn the_sweep_queries_select_exactly_the_due_rows() {
        database_test!(|db| async move {
            let Database::MongoDb(mongo) = &db else {
                return;
            };
            install(mongo).await;

            use v0::ProtTankStage as S;
            let tanks = mongo.col::<ProtTank>("prot_tanks");
            for row in [
                tank("01T01", S::Active, Some("2026-10-31"), 0),
                tank("01T02", S::Grace, Some("2026-11-01"), 0),
                tank("01T03", S::Active, Some("2026-11-02"), 0),
                tank("01T04", S::Frozen, Some("2026-10-01"), 0),
                tank("01T05", S::Launching, None, 0),
                tank("01T06", S::Active, Some("2026-10-30"), 0),
                tank("01T07", S::Deleted, None, 0),
                tank("01T08", S::Terminated, None, 1),
                tank("01T09", S::Deleted, None, 2),
            ] {
                tanks.insert_one(&row).await.unwrap();
            }

            // By (next_burn_day, _id); Frozen and Launching never burn
            assert_eq!(
                tank_ids(
                    db.fetch_prot_tanks_due_burn("2026-11-01", 10)
                        .await
                        .unwrap()
                ),
                ["01T06", "01T01", "01T02"]
            );
            assert_eq!(
                tank_ids(db.fetch_prot_tanks_due_burn("2026-11-01", 2).await.unwrap()),
                ["01T06", "01T01"]
            );
            assert_eq!(
                tank_ids(
                    db.fetch_prot_tanks_by_stage(&[S::Active], None, 10)
                        .await
                        .unwrap()
                ),
                ["01T01", "01T03", "01T06"]
            );
            assert_eq!(
                tank_ids(
                    db.fetch_prot_tanks_by_stage(&[S::Active, S::Frozen], Some("01T01"), 2)
                        .await
                        .unwrap()
                ),
                ["01T03", "01T04"]
            );
            // purge_passes < 2 only
            assert_eq!(
                tank_ids(db.fetch_prot_tanks_to_purge(None, 10).await.unwrap()),
                ["01T07", "01T08"]
            );
            assert_eq!(
                tank_ids(
                    db.fetch_prot_tanks_to_purge(Some("01T07"), 10)
                        .await
                        .unwrap()
                ),
                ["01T08"]
            );

            use v0::ProtGoalKind::{Launch, Upgrade};
            use v0::ProtGoalState as G;
            let window = 7 * DAY;
            let goals = mongo.col::<ProtGoal>("prot_goals");
            for row in [
                goal("01G01", Launch, G::Funding, NOW - 1, None, None, false),
                goal("01G02", Launch, G::Funding, NOW + 1, None, None, false),
                goal(
                    "01G03",
                    Launch,
                    G::Funded,
                    NOW + DAY,
                    Some(NOW - 1),
                    None,
                    false,
                ),
                goal(
                    "01G04",
                    Launch,
                    G::Funded,
                    NOW + DAY,
                    Some(NOW + 1),
                    None,
                    false,
                ),
                goal(
                    "01G05",
                    Launch,
                    G::Launching,
                    NOW + DAY,
                    Some(NOW + DAY),
                    None,
                    false,
                ),
                goal(
                    "01G06",
                    Launch,
                    G::Launched,
                    NOW,
                    None,
                    Some(NOW - 8 * DAY),
                    false,
                ),
                goal(
                    "01G07",
                    Launch,
                    G::Launched,
                    NOW,
                    None,
                    Some(NOW - 8 * DAY),
                    true,
                ),
                goal(
                    "01G08",
                    Launch,
                    G::Launched,
                    NOW,
                    None,
                    Some(NOW - DAY),
                    false,
                ),
                goal(
                    "01G09",
                    Upgrade,
                    G::Funded,
                    NOW + DAY,
                    Some(NOW + DAY),
                    None,
                    false,
                ),
                goal("01G10", Upgrade, G::Applied, NOW - DAY, None, None, false),
                goal("01G11", Launch, G::Cancelled, NOW - DAY, None, None, false),
                goal(
                    "01G12",
                    Upgrade,
                    G::Launched,
                    NOW,
                    None,
                    Some(NOW - 8 * DAY),
                    false,
                ),
            ] {
                goals.insert_one(&row).await.unwrap();
            }
            assert_eq!(
                goal_ids(db.fetch_prot_goals_due(NOW, window, 10).await.unwrap()),
                ["01G01", "01G03", "01G05", "01G06", "01G09"]
            );
            assert_eq!(
                goal_ids(db.fetch_prot_goals_due(NOW, window, 2).await.unwrap()),
                ["01G01", "01G03"]
            );
        });
    }

    /// A canonical unpadded b64 encoding of 64 bytes (the DB layer only
    /// checks the encoding; signatures are verified by the route)
    fn signature() -> String {
        format!("B{}", "A".repeat(85))
    }

    /// The genesis list: only the owner, signed by the owner's device
    fn genesis(channel_id: &str, owner_id: &str) -> SeatListSubmission {
        SeatListSubmission {
            body: SeatListBody {
                channel_id: channel_id.to_string(),
                version: 1,
                device_cap: 5,
                issued_at: NOW,
                signer_user_id: owner_id.to_string(),
                signer_device_id: OWNER_DEVICE.to_string(),
                seats: vec![owner_id.to_string()],
            }
            .build()
            .unwrap(),
            signature: signature(),
            signer_device_id: OWNER_DEVICE.to_string(),
            handover: None,
        }
    }

    async fn balance_of(db: &Database, account_id: &str) -> i64 {
        db.fetch_prot_account(account_id)
            .await
            .unwrap()
            .map_or(0, |account| account.balance)
    }

    /// One channel whose launch goal is Launching (funded by one backer,
    /// tank created, protect not landed yet)
    struct Launching {
        channel: String,
        owner: String,
        backer: String,
        goal_id: String,
        target: i64,
    }

    #[allow(clippy::disallowed_methods)]
    async fn launching_channel(db: &Database, rules: &ProtTankRules) -> Launching {
        let server = ulid();
        let channel = ulid();
        let owner = ulid();
        let backer = ulid();

        let row: Server = serde_json::from_value(serde_json::json!({
            "_id": server,
            "owner": owner,
            "name": "abandon",
            "channels": [channel],
            "default_permissions": 0,
        }))
        .unwrap();
        db.insert_server(&row).await.unwrap();
        for user in [&owner, &backer] {
            db.insert_or_merge_member(&Member {
                id: MemberCompositeKey {
                    server: server.clone(),
                    user: user.clone(),
                },
                ..Default::default()
            })
            .await
            .unwrap();
        }
        db.insert_channel(&Channel::TextChannel {
            id: channel.clone(),
            server: server.clone(),
            name: "abandon".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: HashMap::new(),
            nsfw: false,
            spoiler: false,
            voice: None,
            slowmode: None,
            announcement: None,
            protected: false,
        })
        .await
        .unwrap();

        let daily_cost = rules.daily_cost(10).expect("10 is a slot tier");
        let goal = db
            .create_prot_goal(&ProtGoal {
                id: ulid(),
                kind: v0::ProtGoalKind::Launch,
                server_id: server.clone(),
                channel_id: None,
                tank_id: None,
                created_by: owner.clone(),
                create_nonce: "abandon".to_string(),
                slots: 10,
                days: Some(30),
                daily_cost,
                base_daily_cost: None,
                target_prot: 30 * daily_cost,
                pledged_total: 0,
                state: v0::ProtGoalState::Funding,
                deadline_at: NOW + 30 * DAY,
                funded_at: None,
                launch_deadline_at: None,
                launched_at: None,
                closed_at: None,
                refund7_done: false,
                open_key: Some(format!("launch:{server}")),
                version: 0,
                created_at: NOW - 5_000,
                updated_at: NOW - 5_000,
            })
            .await
            .unwrap();

        db.apply_prot_posting(&ProtPosting {
            key: prot_key_admin(ADMIN, &format!("seed-{backer}")),
            kind: v0::ProtEntryKind::AdminAdjust,
            debit: PROT_SYS_ADJUST.to_string(),
            credit: prot_user_account(&backer),
            amount: ProtAmount::Exact(goal.target_prot),
            debit_floor: 0,
            actor: ADMIN.to_string(),
            reference: ProtRef::default(),
            reason: Some("abandon test".to_string()),
            created_at: NOW - 4_000,
        })
        .await
        .unwrap();
        let funded = db
            .pledge_prot(&ProtPledgeInput {
                user_id: backer.clone(),
                goal_id: goal.id.clone(),
                amount: goal.target_prot,
                nonce: "fund".to_string(),
                rules: rules.clone(),
                now: NOW - 3_000,
            })
            .await
            .unwrap();
        assert!(funded.funded_now);

        let (goal, tank) = db
            .launch_prot_goal(&ProtLaunchInput {
                goal_id: goal.id.clone(),
                channel_id: channel.clone(),
                owner_id: owner.clone(),
                rules: rules.clone(),
                now: NOW,
            })
            .await
            .unwrap();
        assert_eq!(goal.state, v0::ProtGoalState::Launching);
        assert_eq!(tank.stage, v0::ProtTankStage::Launching);

        Launching {
            channel,
            owner,
            backer,
            target: goal.target_prot,
            goal_id: goal.id,
        }
    }

    /// Every order of protect and abandon ends either "protected, entitlement
    /// kept, the capture lands" or "not protected, entitlement and tank gone,
    /// the backer refunded". Returns whether the channel ended protected.
    async fn assert_never_stranded(
        db: &Database,
        launching: &Launching,
        rules: &ProtTankRules,
    ) -> bool {
        let protected = matches!(
            db.fetch_channel(&launching.channel).await.unwrap(),
            Channel::TextChannel {
                protected: true,
                ..
            }
        );
        let entitlement = db
            .fetch_channel_entitlement(&launching.channel)
            .await
            .unwrap();
        let tank = db
            .fetch_prot_tank_by_channel(&launching.channel)
            .await
            .unwrap();
        let goal = db
            .fetch_prot_goal(&launching.goal_id)
            .await
            .unwrap()
            .expect("the goal");
        let wallet = balance_of(db, &prot_user_account(&launching.backer)).await;

        if protected {
            let entitlement = entitlement.expect("a protected channel keeps its entitlement");
            assert_eq!(entitlement.state, ChannelEntitlementState::Active);
            assert_eq!(entitlement.source, ChannelEntitlementSource::Crowdfund);
            assert_eq!(
                tank.expect("a protected channel keeps its tank").stage,
                v0::ProtTankStage::Launching
            );
            assert_eq!(goal.state, v0::ProtGoalState::Launching);
            assert_eq!(wallet, 0);

            // Only the capture ends the goal now
            let captured = db
                .capture_launch_pledges(&launching.channel, NOW, rules)
                .await
                .unwrap()
                .expect("the capture lands");
            assert_eq!(captured.stage, v0::ProtTankStage::Active);
            let launch_day = prot_pro_rata(captured.daily_cost, prot_hours_left(NOW));
            assert_eq!(
                balance_of(db, &prot_tank_account(&captured.id)).await,
                launching.target - launch_day
            );
        } else {
            assert!(entitlement.is_none(), "{entitlement:?}");
            assert!(tank.is_none(), "{tank:?}");
            assert_eq!(goal.state, v0::ProtGoalState::Cancelled);
            assert_eq!(wallet, launching.target);
        }
        protected
    }

    /// 8.5 / BR2 on this driver: the abandon reads `protected` inside its
    /// transaction and writes the channel, so it serializes with protect.
    /// First the sequential order (protect landed, then the abandon is
    /// refused: a deterministic pin of the in-transaction read, which the
    /// shared `abandon_racing_protect_never_strands` exercises by racing),
    /// then the two racing on fresh channels.
    #[tokio::test]
    async fn an_abandon_after_protect_landed_is_refused_in_its_transaction() {
        database_test!(|db| async move {
            let Database::MongoDb(mongo) = &db else {
                return;
            };
            install(mongo).await;
            let rules = rules();

            let launching = launching_channel(&db, &rules).await;
            db.protect_channel(
                &launching.channel,
                &genesis(&launching.channel, &launching.owner),
                timestamp(NOW),
            )
            .await
            .unwrap();
            let refused = db
                .close_prot_goal(&launching.goal_id, v0::ProtGoalState::Cancelled, NOW)
                .await;
            assert!(
                matches!(
                    &refused,
                    Err(error) if matches!(error.error_type, ErrorType::InvalidOperation)
                ),
                "an abandon after protect must be refused, got {refused:?}"
            );
            assert!(assert_never_stranded(&db, &launching, &rules).await);

            let mut endings = [0_usize; 2];
            for _ in 0..RACES {
                let launching = launching_channel(&db, &rules).await;
                let submission = genesis(&launching.channel, &launching.owner);
                let (protected, closed) = tokio::join!(
                    db.protect_channel(&launching.channel, &submission, timestamp(NOW)),
                    db.close_prot_goal(&launching.goal_id, v0::ProtGoalState::Cancelled, NOW),
                );
                let ended_protected = assert_never_stranded(&db, &launching, &rules).await;
                assert_eq!(protected.is_ok(), ended_protected, "{protected:?}");
                assert_eq!(closed.is_ok(), !ended_protected, "{closed:?}");
                endings[usize::from(ended_protected)] += 1;
            }
            assert_eq!(endings.iter().sum::<usize>(), RACES);
        });
    }

    /// A capture body re-run after its commit landed (its result lost, 5.3)
    /// finds the tank launched and writes nothing
    #[tokio::test]
    async fn a_capture_body_re_run_after_its_commit_writes_nothing() {
        database_test!(|db| async move {
            let Database::MongoDb(mongo) = &db else {
                return;
            };
            install(mongo).await;
            let rules = rules();

            let launching = launching_channel(&db, &rules).await;
            db.protect_channel(
                &launching.channel,
                &genesis(&launching.channel, &launching.owner),
                timestamp(NOW),
            )
            .await
            .unwrap();
            let tank = db
                .capture_launch_pledges(&launching.channel, NOW, &rules)
                .await
                .unwrap()
                .expect("the capture lands");
            let rows = db.fetch_prot_entries_by_tank(&tank.id).await.unwrap();
            // The capture and the launch-day burn
            assert_eq!(rows.len(), 2, "{rows:?}");

            let body = CaptureBody {
                channel_id: launching.channel.clone(),
                now: NOW + 1,
                rules: Some(rules.clone()),
            };
            match run_prot_transaction(mongo, &body).await.unwrap() {
                TxnEnd::Committed(None) => {}
                TxnEnd::Committed(Some(tank)) => panic!("captured twice: {tank:?}"),
                TxnEnd::DuplicateKey { key, .. } => panic!("duplicate key {key}"),
                TxnEnd::StateMoved => panic!("state moved"),
            }

            assert_eq!(db.fetch_prot_entries_by_tank(&tank.id).await.unwrap(), rows);
            assert_eq!(db.fetch_prot_tank(&tank.id).await.unwrap(), Some(tank));
            assert!(db
                .capture_launch_pledges(&launching.channel, NOW, &rules)
                .await
                .unwrap()
                .is_none());
        });
    }

    async fn count(mongo: &MongoDb, collection: &str, filter: Document) -> u64 {
        mongo
            .col::<Document>(collection)
            .count_documents(filter)
            .await
            .unwrap()
    }

    /// 6.5 on this driver: refused while the entitlement is live; behind the
    /// tombstone it removes the channel's messages and its TEXT groups'
    /// commits, join intents and envelopes by group id (a Call group and its
    /// rows stay), keeps the tombstone, and a second pass finds nothing
    #[tokio::test]
    async fn purge_refuses_a_live_entitlement_and_removes_only_the_text_plane() {
        database_test!(|db| async move {
            let Database::MongoDb(mongo) = &db else {
                return;
            };
            install(mongo).await;

            let channel = ulid();
            let other = ulid();
            mongo
                .col::<ChannelEntitlement>("channel_entitlements")
                .insert_one(&ChannelEntitlement {
                    id: ulid(),
                    channel_id: channel.clone(),
                    server_id: ulid(),
                    source: ChannelEntitlementSource::Crowdfund,
                    slot_cap: 10,
                    device_cap: None,
                    state: ChannelEntitlementState::Frozen,
                    granted_by: ulid(),
                    created_at: timestamp(NOW),
                })
                .await
                .unwrap();
            mongo
                .col::<Document>("messages")
                .insert_many([
                    doc! { "_id": "m1", "channel": &channel },
                    doc! { "_id": "m2", "channel": &channel },
                    doc! { "_id": "m3", "channel": &other },
                ])
                .await
                .unwrap();
            mongo
                .col::<Document>("mls_groups")
                .insert_many([
                    doc! { "_id": "g-text", "channel_id": &channel, "kind": "Text" },
                    doc! { "_id": "g-call", "channel_id": &channel, "kind": "Call" },
                ])
                .await
                .unwrap();
            mongo
                .col::<Document>("mls_commits")
                .insert_many([
                    doc! { "_id": "c1", "group_id": "g-text" },
                    doc! { "_id": "c2", "group_id": "g-call" },
                ])
                .await
                .unwrap();
            mongo
                .col::<Document>("mls_join_intents")
                .insert_one(doc! { "_id": "j1", "group_id": "g-text" })
                .await
                .unwrap();
            mongo
                .col::<Document>("e2ee_queue")
                .insert_many([
                    doc! { "_id": "q1", "group_id": "g-text" },
                    doc! { "_id": "q2", "group_id": "g-call" },
                ])
                .await
                .unwrap();

            let refused = db.purge_protected_channel_content(&channel).await;
            assert!(
                matches!(
                    &refused,
                    Err(error) if matches!(error.error_type, ErrorType::InvalidOperation)
                ),
                "{refused:?}"
            );
            assert_eq!(count(mongo, "messages", doc! {}).await, 3);

            mongo
                .col::<Document>("channel_entitlements")
                .update_one(
                    doc! { "channel_id": &channel },
                    doc! { "$set": { "state": "Deleted" } },
                )
                .await
                .unwrap();
            assert_eq!(
                db.purge_protected_channel_content(&channel).await.unwrap(),
                ProtPurgeCounts {
                    messages: 2,
                    groups: 1,
                    commits: 1,
                    join_intents: 1,
                    envelopes: 1,
                }
            );
            assert_eq!(count(mongo, "messages", doc! { "_id": "m3" }).await, 1);
            assert_eq!(count(mongo, "messages", doc! {}).await, 1);
            assert_eq!(
                count(mongo, "mls_groups", doc! { "_id": "g-call" }).await,
                1
            );
            assert_eq!(count(mongo, "mls_groups", doc! {}).await, 1);
            assert_eq!(count(mongo, "mls_commits", doc! { "_id": "c2" }).await, 1);
            assert_eq!(count(mongo, "mls_commits", doc! {}).await, 1);
            assert_eq!(count(mongo, "e2ee_queue", doc! { "_id": "q2" }).await, 1);
            assert_eq!(count(mongo, "e2ee_queue", doc! {}).await, 1);
            assert_eq!(
                db.fetch_channel_entitlement(&channel)
                    .await
                    .unwrap()
                    .expect("the tombstone stays")
                    .state,
                ChannelEntitlementState::Deleted
            );

            assert_eq!(
                db.purge_protected_channel_content(&channel).await.unwrap(),
                ProtPurgeCounts {
                    messages: 0,
                    groups: 0,
                    commits: 0,
                    join_intents: 0,
                    envelopes: 0,
                }
            );
        });
    }
}
