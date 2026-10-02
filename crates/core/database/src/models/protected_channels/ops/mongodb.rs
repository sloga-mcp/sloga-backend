//! MongoDB driver for protected-channel data.
//!
//! Every multi-document write is ONE multi-document transaction (design
//! 2.5 (c)): read concern `snapshot`, write concern `majority`, retried as a
//! whole on `TransientTransactionError` (which covers write conflicts with a
//! concurrent seat PUT or Text commit on the same group document), the
//! commit step retried on `UnknownTransactionCommitResult`, at most
//! `MAX_TRANSACTION_ATTEMPTS` attempts, after which the existing database
//! error is returned. The deployment runs a replica set (`rs0`), which
//! transactions require.
//!
//! Seat claims are never check-then-act across transactions: the cap count
//! and the claims happen in one transaction that also writes the channel's
//! `channel_seat_lists` document (version compare-and-set), so two racing
//! claims always write a common document and one of them is retried, and
//! then sees the other's result.

use std::collections::BTreeSet;

use bson::{Bson, Document};
use iso8601_timestamp::Timestamp;
use mongodb::error::{TRANSIENT_TRANSACTION_ERROR, UNKNOWN_TRANSACTION_COMMIT_RESULT};
use mongodb::options::{ReadConcern, WriteConcern};
use mongodb::ClientSession;
use revolt_result::Result;
use serde::de::DeserializeOwned;

use crate::{
    channel_seats_used, check_channel_protectable, check_text_first_generation,
    check_text_successor, plan_seat_list_write, prepare_text_group, seat_cooldown_until, Channel,
    ChannelEntitlement, ChannelSeat, MlsGroup, MlsGroupCreateOutcome, MongoDb, SeatList,
    SeatListSnapshot, SeatListSubmission, SeatListWriteDecision, SeatListWriteInput,
    SeatListWriteKind, SeatListWriteOutcome, MAX_CHANNEL_SLOT_CAP,
};

use super::AbstractProtectedChannels;

const COL_CHANNELS: &str = "channels";
const COL_ENTITLEMENTS: &str = "channel_entitlements";
const COL_SEATS: &str = "channel_seats";
const COL_SEAT_LISTS: &str = "channel_seat_lists";
const COL_GROUPS: &str = "mls_groups";
const COL_COMMITS: &str = "mls_commits";
const COL_JOIN_INTENTS: &str = "mls_join_intents";
const COL_MESSAGES: &str = "messages";

// `txn_serial` is a serialization counter written by `MongoDb::touch`. It
// exists only so a transaction that merely READS a document can still write
// it: two Mongo transactions conflict only when both write a common document,
// so a read-only dependency would allow write skew. Never read; typed
// replacements of the row drop it, which is harmless.

/// Serialized `MlsGroupKind::Text` (design 2.5)
const KIND_TEXT: &str = "Text";

/// Whole-transaction attempts (design 2.5 (a): at most 5)
const MAX_TRANSACTION_ATTEMPTS: u32 = 5;

/// Why one transaction attempt stopped
enum TxnFail {
    /// A driver error. Retried when it carries `TransientTransactionError`.
    Mongo {
        error: mongodb::error::Error,
        operation: &'static str,
        collection: &'static str,
    },
    /// A conflict this code detected itself (a compare-and-set matched
    /// nothing, a duplicate key): retry the whole transaction, which then
    /// reads the winner's result
    Retry {
        operation: &'static str,
        collection: &'static str,
    },
    /// A refusal: abort and return it as-is
    Refuse(revolt_result::Error),
}

impl From<revolt_result::Error> for TxnFail {
    fn from(error: revolt_result::Error) -> Self {
        TxnFail::Refuse(error)
    }
}

type Attempt<T> = std::result::Result<T, TxnFail>;

fn db_err(
    operation: &'static str,
    collection: &'static str,
) -> impl FnOnce(mongodb::error::Error) -> TxnFail {
    move |error| TxnFail::Mongo {
        error,
        operation,
        collection,
    }
}

/// A duplicate-key write error (code 11000) is a lost race on a unique
/// index; inside a transaction it is retried as a conflict
fn dup_or_db_err(
    operation: &'static str,
    collection: &'static str,
) -> impl FnOnce(mongodb::error::Error) -> TxnFail {
    move |error| {
        if is_duplicate_key(&error) {
            TxnFail::Retry {
                operation,
                collection,
            }
        } else {
            TxnFail::Mongo {
                error,
                operation,
                collection,
            }
        }
    }
}

fn is_duplicate_key(error: &mongodb::error::Error) -> bool {
    matches!(
        *error.kind,
        mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(
            ref write_error,
        )) if write_error.code == 11000
    )
}

fn is_transient(error: &mongodb::error::Error) -> bool {
    error.contains_label(TRANSIENT_TRANSACTION_ERROR)
}

/// Typed writes serialize `Timestamp` as Int64 unix milliseconds; every
/// hand-built document must use the same encoding (see `mls/ops/mongodb.rs`)
fn timestamp_bson(at: &Timestamp) -> Bson {
    Bson::Int64(
        at.duration_since(Timestamp::UNIX_EPOCH)
            .whole_milliseconds() as i64,
    )
}

/// Back off before retrying a whole transaction. A write conflict fails
/// fast while the winning transaction is still open, so an immediate retry
/// would re-read the same snapshot and conflict again; spacing the attempts
/// out (20, 40, 80, 160 ms plus jitter) lets the winner commit first.
async fn retry_backoff(attempt_no: u32) {
    let base = 20u64 << attempt_no.saturating_sub(1).min(4);
    let jitter = {
        use rand::Rng;
        rand::thread_rng().gen_range(0..=20u64)
    };
    tokio::time::sleep(std::time::Duration::from_millis(base + jitter)).await;
}

async fn commit_with_retry(session: &mut ClientSession) -> mongodb::error::Result<()> {
    let mut tries = 0;
    loop {
        tries += 1;
        match session.commit_transaction().await {
            Ok(()) => return Ok(()),
            Err(error)
                if error.contains_label(UNKNOWN_TRANSACTION_COMMIT_RESULT)
                    && tries < MAX_TRANSACTION_ATTEMPTS =>
            {
                continue
            }
            Err(error) => return Err(error),
        }
    }
}

async fn find_all<T>(
    collection: &mongodb::Collection<T>,
    filter: Document,
    session: &mut ClientSession,
    name: &'static str,
) -> Attempt<Vec<T>>
where
    T: DeserializeOwned + Send + Sync + Unpin,
{
    let mut cursor = collection
        .find(filter)
        .session(&mut *session)
        .await
        .map_err(db_err("find", name))?;

    let mut rows = Vec::new();
    while let Some(row) = cursor.next(&mut *session).await {
        rows.push(row.map_err(db_err("find", name))?);
    }
    Ok(rows)
}

/// Run `$attempt` (an expression using the session ident) as one
/// transaction, with the retry rules in the module docs
macro_rules! run_transaction {
    ($self:ident, |$session:ident| $attempt:expr) => {{
        let mut attempt_no: u32 = 0;
        loop {
            attempt_no += 1;

            let mut $session = match $self.start_session().await {
                Ok(session) => session,
                Err(_) => break Err(create_database_error!("start_session", COL_SEAT_LISTS)),
            };
            if $session
                .start_transaction()
                .read_concern(ReadConcern::snapshot())
                .write_concern(WriteConcern::majority())
                .await
                .is_err()
            {
                break Err(create_database_error!("start_transaction", COL_SEAT_LISTS));
            }

            let outcome: Attempt<_> = $attempt.await;
            match outcome {
                Ok(value) => match commit_with_retry(&mut $session).await {
                    Ok(()) => break Ok(value),
                    Err(error) if is_transient(&error) && attempt_no < MAX_TRANSACTION_ATTEMPTS => {
                        retry_backoff(attempt_no).await;
                        continue;
                    }
                    Err(_) => {
                        break Err(create_database_error!("commit_transaction", COL_SEAT_LISTS))
                    }
                },
                Err(fail) => {
                    // The server may already have aborted it; nothing to do
                    // if this fails too
                    let _ = $session.abort_transaction().await;
                    match fail {
                        TxnFail::Refuse(error) => break Err(error),
                        TxnFail::Retry {
                            operation,
                            collection,
                        } => {
                            if attempt_no < MAX_TRANSACTION_ATTEMPTS {
                                retry_backoff(attempt_no).await;
                                continue;
                            }
                            break Err(create_database_error!(operation, collection));
                        }
                        TxnFail::Mongo {
                            error,
                            operation,
                            collection,
                        } => {
                            if is_transient(&error) && attempt_no < MAX_TRANSACTION_ATTEMPTS {
                                retry_backoff(attempt_no).await;
                                continue;
                            }
                            break Err(create_database_error!(operation, collection));
                        }
                    }
                }
            }
        }
    }};
}

impl MongoDb {
    /// A real write (`$inc` of `txn_serial`) to a document this
    /// transaction read, filtered on the values it read. Any concurrent
    /// transaction that writes the same document then write-conflicts with
    /// this one, and `matched_count == 0` (the document moved on) retries.
    async fn touch(
        &self,
        session: &mut ClientSession,
        collection: &'static str,
        filter: Document,
    ) -> Attempt<()> {
        let result = self
            .col::<Document>(collection)
            .update_one(filter, doc! { "$inc": { "txn_serial": 1_i64 } })
            .session(&mut *session)
            .await
            .map_err(db_err("update_one", collection))?;
        if result.matched_count == 0 {
            return Err(TxnFail::Retry {
                operation: "update_one",
                collection,
            });
        }
        Ok(())
    }

    /// Liveness: write the `mls_groups` documents this transaction will
    /// update as its FIRST operation (`$inc` of `txn_serial`). The first
    /// operation also fixes the transaction's snapshot, so from then on this
    /// transaction holds the documents' write intent and a racing Text commit
    /// takes the write conflict and retries. Written LAST instead, every
    /// commit that lands in between conflicts THIS transaction, and a busy
    /// channel starves it. Matching nothing is fine (no such group).
    async fn claim_groups_first(
        &self,
        session: &mut ClientSession,
        filter: Document,
    ) -> Attempt<()> {
        self.col::<Document>(COL_GROUPS)
            .update_many(filter, doc! { "$inc": { "txn_serial": 1_i64 } })
            .session(&mut *session)
            .await
            .map_err(db_err("update_many", COL_GROUPS))?;
        Ok(())
    }

    async fn find_open_text_group(
        &self,
        session: &mut ClientSession,
        channel_id: &str,
    ) -> Attempt<Option<MlsGroup>> {
        self.col::<MlsGroup>(COL_GROUPS)
            .find_one(doc! {
                "channel_id": channel_id,
                "open": true,
                "kind": KIND_TEXT
            })
            .session(&mut *session)
            .await
            .map_err(db_err("find_one", COL_GROUPS))
    }

    async fn find_entitlement(
        &self,
        session: &mut ClientSession,
        channel_id: &str,
    ) -> Attempt<Option<ChannelEntitlement>> {
        self.col::<ChannelEntitlement>(COL_ENTITLEMENTS)
            .find_one(doc! { "channel_id": channel_id })
            .session(&mut *session)
            .await
            .map_err(db_err("find_one", COL_ENTITLEMENTS))
    }

    async fn find_stored_seat_list(
        &self,
        session: &mut ClientSession,
        channel_id: &str,
    ) -> Attempt<Option<SeatList>> {
        self.col::<SeatList>(COL_SEAT_LISTS)
            .find_one(doc! { "_id": channel_id })
            .session(&mut *session)
            .await
            .map_err(db_err("find_one", COL_SEAT_LISTS))
    }

    /// Write a planned seat-list change: the list row (insert at genesis,
    /// version compare-and-set otherwise), the changed seat rows, and the
    /// open Text group's AD hash and new pending removals (field-level, never
    /// a `replace_one` of the group)
    async fn apply_decision(
        &self,
        session: &mut ClientSession,
        decision: &SeatListWriteDecision,
        stored_version: Option<i64>,
        text_group: Option<&MlsGroup>,
    ) -> Attempt<()> {
        let SeatListWriteDecision::Apply(plan) = decision else {
            return Ok(());
        };

        match stored_version {
            None => {
                self.col::<SeatList>(COL_SEAT_LISTS)
                    .insert_one(&plan.row)
                    .session(&mut *session)
                    .await
                    .map_err(dup_or_db_err("insert_one", COL_SEAT_LISTS))?;
            }
            Some(version) => {
                let result = self
                    .col::<SeatList>(COL_SEAT_LISTS)
                    .replace_one(doc! { "_id": &plan.row.id, "version": version }, &plan.row)
                    .session(&mut *session)
                    .await
                    .map_err(db_err("replace_one", COL_SEAT_LISTS))?;
                if result.matched_count == 0 {
                    return Err(TxnFail::Retry {
                        operation: "replace_one",
                        collection: COL_SEAT_LISTS,
                    });
                }
            }
        }

        for seat in &plan.seat_rows {
            self.col::<ChannelSeat>(COL_SEATS)
                .replace_one(doc! { "_id": &seat.id }, seat)
                .upsert(true)
                .session(&mut *session)
                .await
                .map_err(dup_or_db_err("replace_one", COL_SEATS))?;
        }

        if let Some(group) = text_group {
            let mut update = doc! {
                "$set": { "seat_list_ad_sha256": &plan.seat_list_ad_sha256 }
            };
            if !plan.pending_added.is_empty() {
                let entries: Vec<Document> = plan
                    .pending_added
                    .iter()
                    .map(|pending| {
                        doc! {
                            "user_id": &pending.user_id,
                            "created_at": timestamp_bson(&pending.created_at)
                        }
                    })
                    .collect();
                update.insert("$push", doc! { "pending_removals": { "$each": entries } });
            }

            let result = self
                .col::<Document>(COL_GROUPS)
                .update_one(
                    doc! { "_id": &group.id, "open": true, "kind": KIND_TEXT },
                    update,
                )
                .session(&mut *session)
                .await
                .map_err(db_err("update_one", COL_GROUPS))?;
            if result.matched_count == 0 {
                return Err(TxnFail::Retry {
                    operation: "update_one",
                    collection: COL_GROUPS,
                });
            }
        }

        Ok(())
    }

    async fn upsert_entitlement_attempt(
        &self,
        session: &mut ClientSession,
        entitlement: &ChannelEntitlement,
        now: Timestamp,
    ) -> Attempt<ChannelEntitlement> {
        let existing = self
            .find_entitlement(session, &entitlement.channel_id)
            .await?;
        let seats: Vec<ChannelSeat> = find_all(
            &self.col(COL_SEATS),
            doc! { "channel_id": &entitlement.channel_id },
            session,
            COL_SEATS,
        )
        .await?;

        if channel_seats_used(&seats, now) > entitlement.slot_cap as usize {
            return Err(TxnFail::Refuse(create_error!(SeatCapReached {
                max: entitlement.slot_cap as usize
            })));
        }

        match existing {
            Some(existing) => {
                let stored = ChannelEntitlement {
                    slot_cap: entitlement.slot_cap,
                    device_cap: entitlement.device_cap,
                    granted_by: entitlement.granted_by.clone(),
                    ..existing
                };
                self.col::<ChannelEntitlement>(COL_ENTITLEMENTS)
                    .replace_one(doc! { "_id": &stored.id }, &stored)
                    .session(&mut *session)
                    .await
                    .map_err(db_err("replace_one", COL_ENTITLEMENTS))?;
                Ok(stored)
            }
            None => {
                self.col::<ChannelEntitlement>(COL_ENTITLEMENTS)
                    .insert_one(entitlement)
                    .session(&mut *session)
                    .await
                    .map_err(dup_or_db_err("insert_one", COL_ENTITLEMENTS))?;
                Ok(entitlement.clone())
            }
        }
    }

    async fn snapshot_attempt(
        &self,
        session: &mut ClientSession,
        channel_id: &str,
    ) -> Attempt<SeatListSnapshot> {
        let list = self.find_stored_seat_list(session, channel_id).await?;
        let text_group = self.find_open_text_group(session, channel_id).await?;
        Ok(SeatListSnapshot { list, text_group })
    }

    async fn seat_list_write_attempt(
        &self,
        session: &mut ClientSession,
        kind: SeatListWriteKind,
        channel_id: &str,
        submission: &SeatListSubmission,
        now: Timestamp,
    ) -> Attempt<SeatListWriteOutcome> {
        // FIRST operation: the open Text group whose hash and pending
        // removals this write updates (see `claim_groups_first`)
        self.claim_groups_first(
            session,
            doc! { "channel_id": channel_id, "open": true, "kind": KIND_TEXT },
        )
        .await?;

        if kind == SeatListWriteKind::Protect {
            let channel: Option<Channel> = self
                .col::<Channel>(COL_CHANNELS)
                .find_one(doc! { "_id": channel_id })
                .session(&mut *session)
                .await
                .map_err(db_err("find_one", COL_CHANNELS))?;
            check_channel_protectable(channel.as_ref())?;

            // `last_message_id` is written asynchronously (batched), so it
            // can lag a stored message: ask the messages collection itself
            let message: Option<Document> = self
                .col::<Document>(COL_MESSAGES)
                .find_one(doc! { "channel": channel_id })
                .session(&mut *session)
                .await
                .map_err(db_err("find_one", COL_MESSAGES))?;
            if message.is_some() {
                return Err(TxnFail::Refuse(create_error!(InvalidOperation)));
            }
        }

        let entitlement = self.find_entitlement(session, channel_id).await?;
        if kind == SeatListWriteKind::Protect
            && !entitlement
                .as_ref()
                .is_some_and(ChannelEntitlement::is_active)
        {
            return Err(TxnFail::Refuse(create_error!(InvalidOperation)));
        }

        let stored = self.find_stored_seat_list(session, channel_id).await?;
        let seats: Vec<ChannelSeat> = find_all(
            &self.col(COL_SEATS),
            doc! { "channel_id": channel_id },
            session,
            COL_SEATS,
        )
        .await?;
        let text_group = self.find_open_text_group(session, channel_id).await?;

        let decision = plan_seat_list_write(&SeatListWriteInput {
            kind,
            channel_id,
            submission,
            stored: stored.as_ref(),
            entitlement: entitlement.as_ref(),
            seats: &seats,
            text_group: text_group.as_ref(),
            now,
        })?;

        // The cap check above read the entitlement; claiming seats writes
        // it too, so an admin grant that lowers `slot_cap` (which reads the
        // seats and writes the entitlement) conflicts instead of skewing
        if let (SeatListWriteDecision::Apply(plan), Some(entitlement)) = (&decision, &entitlement) {
            if !plan.claimed.is_empty() {
                self.touch(
                    session,
                    COL_ENTITLEMENTS,
                    doc! { "_id": &entitlement.id, "slot_cap": entitlement.slot_cap as i64 },
                )
                .await?;
            }
        }

        self.apply_decision(
            session,
            &decision,
            stored.as_ref().map(|stored| stored.version),
            text_group.as_ref(),
        )
        .await?;

        if kind == SeatListWriteKind::Protect {
            let result = self
                .col::<Document>(COL_CHANNELS)
                .update_one(
                    doc! {
                        "_id": channel_id,
                        "channel_type": "TextChannel",
                        "protected": { "$ne": true },
                        "last_message_id": null
                    },
                    doc! { "$set": { "protected": true } },
                )
                .session(&mut *session)
                .await
                .map_err(db_err("update_one", COL_CHANNELS))?;
            if result.matched_count == 0 {
                return Err(TxnFail::Retry {
                    operation: "update_one",
                    collection: COL_CHANNELS,
                });
            }
        }

        Ok(decision.outcome())
    }

    async fn create_text_group_attempt(
        &self,
        session: &mut ClientSession,
        group: &MlsGroup,
        supersedes: Option<&str>,
    ) -> Attempt<MlsGroupCreateOutcome> {
        // FIRST operation: the superseded group this create closes (a first
        // create writes no existing group: its insert and the seat-list
        // touch below cannot collide with a Text commit)
        if let Some(superseded_id) = supersedes {
            self.claim_groups_first(
                session,
                doc! { "_id": superseded_id, "open": true, "kind": KIND_TEXT },
            )
            .await?;
        }

        let list = self
            .find_stored_seat_list(session, &group.channel_id)
            .await?
            .ok_or_else(|| {
                TxnFail::Refuse(create_error!(FailedValidation {
                    error: "channel has no seat list".to_string()
                }))
            })?;
        let open = self
            .find_open_text_group(session, &group.channel_id)
            .await?;

        match supersedes {
            Some(superseded_id) => {
                let superseded: MlsGroup = self
                    .col::<MlsGroup>(COL_GROUPS)
                    .find_one(doc! { "_id": superseded_id })
                    .session(&mut *session)
                    .await
                    .map_err(db_err("find_one", COL_GROUPS))?
                    .ok_or_else(|| TxnFail::Refuse(create_error!(NotFound)))?;
                check_text_successor(&superseded, group)?;
                if let Some(open) = open.filter(|open| open.id != superseded_id) {
                    return Ok(MlsGroupCreateOutcome::Conflict {
                        open_group_id: open.id,
                        channel_id: open.channel_id,
                    });
                }
            }
            None => {
                check_text_first_generation(group)?;
                if let Some(open) = open {
                    return Ok(MlsGroupCreateOutcome::Conflict {
                        open_group_id: open.id,
                        channel_id: open.channel_id,
                    });
                }
            }
        }

        let prepared = prepare_text_group(group, &list)?;

        // The group binds this list's AD hash, so the create must serialize
        // with every seat-list write (2.5 (c)): write the list row, filtered
        // on the version read. A racing PUT then conflicts with this
        // transaction and one side retries against the other's result.
        self.touch(
            session,
            COL_SEAT_LISTS,
            doc! { "_id": &list.id, "version": list.version },
        )
        .await?;

        let taken: Option<Document> = self
            .col::<Document>(COL_GROUPS)
            .find_one(doc! { "_id": &prepared.id })
            .session(&mut *session)
            .await
            .map_err(db_err("find_one", COL_GROUPS))?;
        if taken.is_some() {
            return Err(TxnFail::Refuse(create_error!(InvalidOperation)));
        }

        if let Some(superseded_id) = supersedes {
            // Matches nothing when a racing successor already closed it;
            // the insert below then conflicts on the open-group index
            self.col::<Document>(COL_GROUPS)
                .update_one(
                    doc! { "_id": superseded_id, "open": true, "kind": KIND_TEXT },
                    doc! {
                        "$set": {
                            "open": false,
                            "closed_at": timestamp_bson(&group.created_at),
                            "superseded_by": &group.id
                        }
                    },
                )
                .session(&mut *session)
                .await
                .map_err(db_err("update_one", COL_GROUPS))?;
        }

        // The (channel_id, kind) partial unique index on open groups (rev
        // 73) arbitrates racing creators; a duplicate retries and the retry
        // reads the winner as `Conflict`
        self.col::<MlsGroup>(COL_GROUPS)
            .insert_one(&prepared)
            .session(&mut *session)
            .await
            .map_err(dup_or_db_err("insert_one", COL_GROUPS))?;

        Ok(MlsGroupCreateOutcome::Created)
    }

    async fn release_attempt(
        &self,
        session: &mut ClientSession,
        user_id: &str,
        server_id: Option<&str>,
        now: Timestamp,
    ) -> Attempt<Vec<String>> {
        let cooldown_until = seat_cooldown_until(now)?;

        // Groups this release may append a pending removal to, written
        // first (see `claim_groups_first`). Unscoped, this is the very
        // first operation; scoped, it follows the one entitlement read.
        let mut claim = doc! { "open": true, "kind": KIND_TEXT, "members.user_id": user_id };

        let scope: Option<Vec<String>> = match server_id {
            Some(server_id) => Some(
                find_all::<ChannelEntitlement>(
                    &self.col(COL_ENTITLEMENTS),
                    doc! { "server_id": server_id },
                    session,
                    COL_ENTITLEMENTS,
                )
                .await?
                .into_iter()
                .map(|entitlement| entitlement.channel_id)
                .collect(),
            ),
            None => None,
        };
        if let Some(scope) = &scope {
            claim.insert("channel_id", doc! { "$in": scope });
        }
        self.claim_groups_first(session, claim).await?;

        let mut affected = BTreeSet::new();

        let mut seat_filter = doc! { "user_id": user_id, "released_at": null };
        if let Some(scope) = &scope {
            seat_filter.insert("channel_id", doc! { "$in": scope });
        }
        let seats: Vec<ChannelSeat> =
            find_all(&self.col(COL_SEATS), seat_filter, session, COL_SEATS).await?;
        for seat in seats {
            self.col::<Document>(COL_SEATS)
                .update_one(
                    doc! { "_id": &seat.id, "released_at": null },
                    doc! {
                        "$set": {
                            "released_at": timestamp_bson(&now),
                            "cooldown_until": timestamp_bson(&cooldown_until)
                        }
                    },
                )
                .session(&mut *session)
                .await
                .map_err(db_err("update_one", COL_SEATS))?;
            affected.insert(seat.channel_id);
        }

        let mut group_filter = doc! {
            "open": true,
            "kind": KIND_TEXT,
            "members.user_id": user_id
        };
        if let Some(scope) = &scope {
            group_filter.insert("channel_id", doc! { "$in": scope });
        }
        let groups: Vec<MlsGroup> =
            find_all(&self.col(COL_GROUPS), group_filter, session, COL_GROUPS).await?;
        for group in groups {
            if group
                .pending_removals
                .iter()
                .any(|pending| pending.user_id == user_id)
            {
                continue;
            }
            self.col::<Document>(COL_GROUPS)
                .update_one(
                    doc! { "_id": &group.id, "open": true, "kind": KIND_TEXT },
                    doc! {
                        "$push": {
                            "pending_removals": {
                                "user_id": user_id,
                                "created_at": timestamp_bson(&now)
                            }
                        }
                    },
                )
                .session(&mut *session)
                .await
                .map_err(db_err("update_one", COL_GROUPS))?;
            affected.insert(group.channel_id);
        }

        Ok(affected.into_iter().collect())
    }

    async fn delete_attempt(&self, session: &mut ClientSession, channel_id: &str) -> Attempt<()> {
        // FIRST operation: the Text groups this cascade closes
        self.claim_groups_first(
            session,
            doc! { "channel_id": channel_id, "kind": KIND_TEXT },
        )
        .await?;

        self.col::<Document>(COL_ENTITLEMENTS)
            .delete_many(doc! { "channel_id": channel_id })
            .session(&mut *session)
            .await
            .map_err(db_err("delete_many", COL_ENTITLEMENTS))?;
        self.col::<Document>(COL_SEATS)
            .delete_many(doc! { "channel_id": channel_id })
            .session(&mut *session)
            .await
            .map_err(db_err("delete_many", COL_SEATS))?;
        self.col::<Document>(COL_SEAT_LISTS)
            .delete_one(doc! { "_id": channel_id })
            .session(&mut *session)
            .await
            .map_err(db_err("delete_one", COL_SEAT_LISTS))?;

        let groups: Vec<MlsGroup> = find_all(
            &self.col(COL_GROUPS),
            doc! { "channel_id": channel_id, "kind": KIND_TEXT },
            session,
            COL_GROUPS,
        )
        .await?;
        let group_ids: Vec<String> = groups.into_iter().map(|group| group.id).collect();

        self.col::<Document>(COL_GROUPS)
            .update_many(
                doc! { "channel_id": channel_id, "kind": KIND_TEXT, "open": true },
                doc! {
                    "$set": {
                        "open": false,
                        "closed_at": timestamp_bson(&Timestamp::now_utc())
                    }
                },
            )
            .session(&mut *session)
            .await
            .map_err(db_err("update_many", COL_GROUPS))?;

        if !group_ids.is_empty() {
            self.col::<Document>(COL_COMMITS)
                .delete_many(doc! { "group_id": { "$in": &group_ids } })
                .session(&mut *session)
                .await
                .map_err(db_err("delete_many", COL_COMMITS))?;
            self.col::<Document>(COL_JOIN_INTENTS)
                .delete_many(doc! { "group_id": { "$in": &group_ids } })
                .session(&mut *session)
                .await
                .map_err(db_err("delete_many", COL_JOIN_INTENTS))?;
        }

        Ok(())
    }
}

#[async_trait]
impl AbstractProtectedChannels for MongoDb {
    async fn upsert_channel_entitlement(
        &self,
        entitlement: &ChannelEntitlement,
        now: Timestamp,
    ) -> Result<ChannelEntitlement> {
        if !(1..=MAX_CHANNEL_SLOT_CAP).contains(&entitlement.slot_cap) {
            return Err(create_error!(FailedValidation {
                error: "slot_cap must be 1..=100".to_string()
            }));
        }
        run_transaction!(self, |session| self.upsert_entitlement_attempt(
            &mut session,
            entitlement,
            now
        ))
    }

    async fn fetch_channel_entitlement(
        &self,
        channel_id: &str,
    ) -> Result<Option<ChannelEntitlement>> {
        query!(
            self,
            find_one,
            COL_ENTITLEMENTS,
            doc! { "channel_id": channel_id }
        )
    }

    async fn fetch_channel_seats(&self, channel_id: &str) -> Result<Vec<ChannelSeat>> {
        let mut rows: Vec<ChannelSeat> =
            query!(self, find, COL_SEATS, doc! { "channel_id": channel_id })?;
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(rows)
    }

    async fn fetch_channel_seats_for_user(&self, user_id: &str) -> Result<Vec<ChannelSeat>> {
        let mut rows: Vec<ChannelSeat> =
            query!(self, find, COL_SEATS, doc! { "user_id": user_id })?;
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(rows)
    }

    async fn fetch_seat_list(&self, channel_id: &str) -> Result<Option<SeatList>> {
        query!(self, find_one, COL_SEAT_LISTS, doc! { "_id": channel_id })
    }

    async fn fetch_seat_list_snapshot(&self, channel_id: &str) -> Result<SeatListSnapshot> {
        run_transaction!(self, |session| self
            .snapshot_attempt(&mut session, channel_id))
    }

    async fn protect_channel(
        &self,
        channel_id: &str,
        submission: &SeatListSubmission,
        now: Timestamp,
    ) -> Result<SeatListWriteOutcome> {
        run_transaction!(self, |session| self.seat_list_write_attempt(
            &mut session,
            SeatListWriteKind::Protect,
            channel_id,
            submission,
            now
        ))
    }

    async fn put_seat_list(
        &self,
        channel_id: &str,
        submission: &SeatListSubmission,
        now: Timestamp,
    ) -> Result<SeatListWriteOutcome> {
        run_transaction!(self, |session| self.seat_list_write_attempt(
            &mut session,
            SeatListWriteKind::Put,
            channel_id,
            submission,
            now
        ))
    }

    async fn create_text_mls_group(
        &self,
        group: &MlsGroup,
        supersedes: Option<&str>,
    ) -> Result<MlsGroupCreateOutcome> {
        run_transaction!(self, |session| self.create_text_group_attempt(
            &mut session,
            group,
            supersedes
        ))
    }

    async fn release_channel_seats_for_user(
        &self,
        user_id: &str,
        server_id: Option<&str>,
        now: Timestamp,
    ) -> Result<Vec<String>> {
        run_transaction!(self, |session| self.release_attempt(
            &mut session,
            user_id,
            server_id,
            now
        ))
    }

    async fn delete_protected_channel_data(&self, channel_id: &str) -> Result<()> {
        run_transaction!(self, |session| self
            .delete_attempt(&mut session, channel_id))
    }
}
