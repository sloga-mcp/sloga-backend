use std::collections::HashSet;

use bson::{Bson, Document};
use iso8601_timestamp::Timestamp;
use mongodb::{
    error::{TRANSIENT_TRANSACTION_ERROR, UNKNOWN_TRANSACTION_COMMIT_RESULT},
    options::{FindOptions, ReadConcern, WriteConcern},
    ClientSession,
};
use revolt_result::Result;

use futures::StreamExt;

use crate::{
    AbstractMls, ChannelSeat, E2EEIdentity, MlsCommit, MlsCommitOutcome, MlsGroup,
    MlsGroupCreateOutcome, MlsGroupKind, MlsJoinIntent, MlsKeyPackage, MlsMemberAdded, MongoDb,
    SeatList, MAX_MLS_GROUP_MEMBERS,
};

use super::plan_mls_text_commit;

const COL_KEY_PACKAGES: &str = "mls_key_packages";
const COL_GROUPS: &str = "mls_groups";
const COL_COMMITS: &str = "mls_commits";
const COL_JOIN_INTENTS: &str = "mls_join_intents";
/// Owned by the protected-channels models (design §2.4); read here, inside
/// the Text commit transaction, never written
const COL_SEAT_LISTS: &str = "channel_seat_lists";
/// Owned by the protected-channels models (design §2.3). The Text commit
/// transaction only bumps a `txn_serial` counter on an ADDED user's ACTIVE
/// seat row (conflict marker; no seat field is changed)
const COL_SEATS: &str = "channel_seats";
/// Owned by the E2EE models (`e2ee/ops/mongodb.rs`, `COL_IDENTITY`); the
/// collection name is SINGULAR. Read here for the revoked-identity lookup
const COL_E2EE_IDENTITY: &str = "e2ee_identity";

/// Whole-transaction attempts for a Text commit (design §2.5 (a))
const TEXT_COMMIT_ATTEMPTS: usize = 5;

/// How many times a Text commit transaction was retried as a whole, in this
/// process. Test-only evidence that the retry branch actually ran.
#[cfg(test)]
pub(crate) static TEXT_COMMIT_RETRIES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Back off before retrying a whole Text commit transaction (same shape as
/// the protected-channels `retry_backoff`): a write conflict fails fast
/// while the winning transaction is still open, so an immediate retry would
/// mostly conflict again. Exponential from 20 ms (capped at 320 ms) plus
/// 0 to 20 ms of jitter so racing committers do not retry in lockstep.
async fn text_commit_backoff(retry_no: usize) {
    let base = 20u64 << retry_no.saturating_sub(1).min(4);
    let jitter = {
        use rand::Rng;
        rand::thread_rng().gen_range(0..=20u64)
    };
    tokio::time::sleep(std::time::Duration::from_millis(base + jitter)).await;
}

/// Filter value for a group's `kind`. A Call lookup also matches a stored
/// group with no `kind` field (written before the field existed), so Call
/// callers keep their exact behavior whether or not the revision-73
/// backfill has run.
fn kind_filter(kind: MlsGroupKind) -> Bson {
    match kind {
        MlsGroupKind::Call => Bson::Document(doc! { "$ne": "Text" }),
        MlsGroupKind::Text => Bson::String("Text".to_string()),
    }
}

/// Why one attempt of the Text commit transaction did not commit
enum TextAttemptError {
    /// A definitive refusal or result error: abort and return it
    Refused(revolt_result::Error),
    /// A driver error: abort, retry if it carries
    /// `TransientTransactionError`, else a database error
    Mongo(mongodb::error::Error, &'static str, &'static str),
    /// A concurrent writer won (duplicate commit id, or the group update
    /// matched nothing): abort and retry; the next attempt's step 0 or
    /// validity checks give the definitive answer
    Retry,
}

/// What one attempt of the Text commit transaction decided
enum TextAttemptOutcome {
    /// Step 0 found a row: abort (nothing was written) and return it
    Existing(MlsCommit),
    /// Every write is staged: commit the transaction, then report `Won`
    Staged,
}

fn mongo_error(
    operation: &'static str,
    collection: &'static str,
) -> impl FnOnce(mongodb::error::Error) -> TextAttemptError {
    move |error| TextAttemptError::Mongo(error, operation, collection)
}

/// Whether a MongoDB error is a duplicate-key write rejection (the CAS
/// primitive: unique-index insert arbitration, `insert_e2ee_identity`
/// precedent)
fn is_duplicate_key(error: &mongodb::error::Error) -> bool {
    matches!(
        *error.kind,
        mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(
            ref write_error,
        )) if write_error.code == 11000
    )
}

/// Typed collection writes (insert_one/replace_one) serialize `Timestamp`
/// through bson's NON-human-readable serde path: Int64 unix-milliseconds.
/// Every hand-built document ($set updates, range-query thresholds) MUST use
/// the same encoding — `bson::to_bson` would emit an ISO STRING, and a `$lt`
/// across BSON types silently matches nothing (verified empirically; the
/// sweep tests cover it).
fn timestamp_bson(at: &Timestamp) -> Bson {
    Bson::Int64(
        at.duration_since(Timestamp::UNIX_EPOCH)
            .whole_milliseconds() as i64,
    )
}

impl MongoDb {
    /// Apply a winning CALL commit's effects to the group document — epoch
    /// bump + asserted roster delta — as a CAS conditioned on
    /// `current_epoch == commit.epoch - 1`. Idempotent: a second applier (or
    /// the loser-side repair after a winner crashed between commit insert
    /// and group update) simply matches nothing. Returns whether this call
    /// applied it.
    ///
    /// FIELD-LEVEL (design §2.5 (b)): only `current_epoch` and `members`
    /// are written, never a `replace_one` of a clone, so no other field
    /// (`kind`, `generation`, `pending_removals`, `seat_list_ad_sha256`,
    /// `member_added`, a concurrent close) can be reverted. The filter
    /// excludes Text groups, so neither this nor the repair loop can ever
    /// apply effects to one.
    async fn apply_mls_commit_effects(&self, group: &MlsGroup, commit: &MlsCommit) -> Result<bool> {
        let mut members = group.members.clone();
        members.retain(|member| !commit.removed.iter().any(|removed| removed == member));
        members.extend(commit.added.iter().cloned());
        let members =
            bson::to_bson(&members).map_err(|_| create_database_error!("to_bson", COL_GROUPS))?;

        let applied = self
            .col::<MlsGroup>(COL_GROUPS)
            .update_one(
                doc! {
                    "_id": &group.id,
                    "current_epoch": commit.epoch - 1,
                    "open": true,
                    "kind": kind_filter(MlsGroupKind::Call)
                },
                doc! {
                    "$set": {
                        "current_epoch": commit.epoch,
                        "members": members
                    }
                },
            )
            .await
            .map_err(|_| create_database_error!("update_one", COL_GROUPS))
            .map(|result| result.matched_count > 0)?;

        // Admission consumes the joiner's intent row: without this, every
        // member would retain its original pre-admit intent and the
        // dual-reload close (rejoin plan §5) could misread a freshly
        // admitted member as "still rejoining". Idempotent, so safe under
        // the repair path; a delayed repair deleting a device's NEWER
        // rejoin intent only defers the close check one re-broadcast.
        if applied && !commit.added.is_empty() {
            let added_ids: Vec<String> = commit
                .added
                .iter()
                .map(|added| {
                    MlsJoinIntent::composite_id(&group.id, &added.user_id, &added.device_id)
                })
                .collect();
            self.col::<MlsJoinIntent>(COL_JOIN_INTENTS)
                .delete_many(doc! { "_id": { "$in": added_ids } })
                .await
                .map_err(|_| create_database_error!("delete_many", COL_JOIN_INTENTS))?;
        }

        Ok(applied)
    }

    /// Fetch a group and lazily repair its `current_epoch`/roster mirror
    /// from any stored winning commit it has not yet absorbed (crash
    /// recovery between the commit CAS and the group update — the Reference
    /// driver's single Mutex has no such window)
    ///
    /// CALL GROUPS ONLY: a Text group is returned as read. Its insert and
    /// effects are one transaction, so there is never anything to repair,
    /// and re-applying a Text commit here would skip every Text rule
    /// (design §2.5, W0-fix5).
    async fn fetch_mls_group_repaired(&self, group_id: &str) -> Result<MlsGroup> {
        // Bounded: each iteration absorbs one already-arbitrated epoch
        for _ in 0..64 {
            let group: MlsGroup = query!(self, find_one, COL_GROUPS, doc! { "_id": group_id })?
                .ok_or_else(|| create_error!(NotFound))?;

            if group.kind != MlsGroupKind::Call {
                return Ok(group);
            }

            let next: Option<MlsCommit> = query!(
                self,
                find_one,
                COL_COMMITS,
                doc! { "_id": MlsCommit::composite_id(group_id, group.current_epoch + 1) }
            )?;

            match next {
                Some(commit) if group.open => {
                    self.apply_mls_commit_effects(&group, &commit).await?;
                }
                _ => return Ok(group),
            }
        }

        Err(create_database_error!("repair_loop", COL_GROUPS))
    }

    /// One attempt of the Text commit transaction (design §2.5 (a), steps 0
    /// to 5). Every read and write runs in `session`'s transaction; the
    /// caller commits or aborts.
    async fn text_commit_attempt(
        &self,
        session: &mut ClientSession,
        commit: &MlsCommit,
        ad_sha256: &str,
        entitlement_device_cap: u32,
    ) -> std::result::Result<TextAttemptOutcome, TextAttemptError> {
        let id = MlsCommit::composite_id(&commit.group_id, commit.epoch);

        // Step 0: an existing row at {group}:{epoch} is returned before any
        // validity check (idempotent resubmit, W0-fix7/8)
        let existing = self
            .col::<MlsCommit>(COL_COMMITS)
            .find_one(doc! { "_id": &id })
            .session(&mut *session)
            .await
            .map_err(mongo_error("find_one", COL_COMMITS))?;
        if let Some(winning) = existing {
            return Ok(TextAttemptOutcome::Existing(winning));
        }

        // Step 1: the group, then the channel's newest seat list
        let group = self
            .col::<MlsGroup>(COL_GROUPS)
            .find_one(doc! { "_id": &commit.group_id })
            .session(&mut *session)
            .await
            .map_err(mongo_error("find_one", COL_GROUPS))?
            .ok_or_else(|| TextAttemptError::Refused(create_error!(NotFound)))?;

        let seat_list = self
            .col::<SeatList>(COL_SEAT_LISTS)
            .find_one(doc! { "_id": &group.channel_id })
            .session(&mut *session)
            .await
            .map_err(mongo_error("find_one", COL_SEAT_LISTS))?;

        // The removed devices' stored join intents (rule 6) and identity
        // rows (rule 4), read in the same snapshot
        let mut stored_intents: Vec<MlsJoinIntent> = Vec::new();
        let mut revoked_identities: HashSet<String> = HashSet::new();
        for removed in &commit.removed {
            let intent = self
                .col::<MlsJoinIntent>(COL_JOIN_INTENTS)
                .find_one(doc! {
                    "_id": MlsJoinIntent::composite_id(
                        &group.id,
                        &removed.user_id,
                        &removed.device_id
                    )
                })
                .session(&mut *session)
                .await
                .map_err(mongo_error("find_one", COL_JOIN_INTENTS))?;
            stored_intents.extend(intent);

            let identity_id = E2EEIdentity::composite_id(&removed.user_id, &removed.device_id);
            let identity = self
                .col::<Document>(COL_E2EE_IDENTITY)
                .find_one(doc! { "_id": &identity_id })
                .projection(doc! { "_id": 1 })
                .session(&mut *session)
                .await
                .map_err(mongo_error("find_one", COL_E2EE_IDENTITY))?;
            if identity.is_none() {
                revoked_identities.insert(identity_id);
            }
        }

        // Each ADDED user's seat row must be active. This is a conditional
        // WRITE, not a read: a forced release (kick, ban, leave) writes the
        // seat row and nothing else this transaction writes, so only a
        // write here makes a racing release write-conflict (one side
        // retries and then sees the other's result). Filter encoding matches
        // the seat writers: `released_at: null` = absent or null (active).
        let mut active_seat_users: HashSet<String> = HashSet::new();
        for added in &commit.added {
            if active_seat_users.contains(&added.user_id) {
                continue;
            }
            let matched = self
                .col::<Document>(COL_SEATS)
                .update_one(
                    doc! {
                        "_id": ChannelSeat::composite_id(&group.channel_id, &added.user_id),
                        "released_at": Bson::Null
                    },
                    doc! { "$inc": { "txn_serial": 1_i64 } },
                )
                .session(&mut *session)
                .await
                .map_err(mongo_error("update_one", COL_SEATS))?
                .matched_count;
            if matched > 0 {
                active_seat_users.insert(added.user_id.clone());
            }
        }

        // Step 2: every validity check
        let plan = plan_mls_text_commit(
            &group,
            commit,
            ad_sha256,
            seat_list.as_ref(),
            entitlement_device_cap,
            &stored_intents,
            &revoked_identities,
            &active_seat_users,
        )
        .map_err(TextAttemptError::Refused)?;

        // Hand-built BSON before any write: `member_added.at` must use the
        // typed path's Int64 unix-ms encoding (`timestamp_bson`)
        let members = bson::to_bson(&plan.members).map_err(|_| {
            TextAttemptError::Refused(create_database_error!("to_bson", COL_GROUPS))
        })?;
        let member_added: Vec<Bson> = plan
            .member_added
            .iter()
            .map(|entry: &MlsMemberAdded| {
                Bson::Document(doc! {
                    "user_id": &entry.user_id,
                    "device_id": &entry.device_id,
                    "epoch": entry.epoch,
                    "at": timestamp_bson(&entry.at)
                })
            })
            .collect();

        // Step 3: the commit row. Its unique _id still arbitrates a racing
        // same-epoch insert
        match self
            .col::<MlsCommit>(COL_COMMITS)
            .insert_one(&plan.stored)
            .session(&mut *session)
            .await
        {
            Ok(_) => {}
            Err(error) if is_duplicate_key(&error) => return Err(TextAttemptError::Retry),
            Err(error) => return Err(TextAttemptError::Mongo(error, "insert_one", COL_COMMITS)),
        }

        // Step 4: field-level effects, filtered on the state just validated
        let mut update = doc! {
            "$set": {
                "current_epoch": commit.epoch,
                "members": members,
                "member_added": member_added
            }
        };
        if !plan.cleared_pending.is_empty() {
            update.insert(
                "$pull",
                doc! {
                    "pending_removals": {
                        "user_id": { "$in": &plan.cleared_pending }
                    }
                },
            );
        }

        let matched = self
            .col::<MlsGroup>(COL_GROUPS)
            .update_one(
                doc! {
                    "_id": &group.id,
                    "open": true,
                    "kind": kind_filter(MlsGroupKind::Text),
                    "current_epoch": commit.epoch - 1,
                    "seat_list_ad_sha256": ad_sha256
                },
                update,
            )
            .session(&mut *session)
            .await
            .map_err(mongo_error("update_one", COL_GROUPS))?
            .matched_count;
        if matched == 0 {
            return Err(TextAttemptError::Retry);
        }

        // Step 5: consume the added devices' intents and every rule-6 intent
        if !plan.consumed_intent_ids.is_empty() {
            self.col::<Document>(COL_JOIN_INTENTS)
                .delete_many(doc! { "_id": { "$in": &plan.consumed_intent_ids } })
                .session(&mut *session)
                .await
                .map_err(mongo_error("delete_many", COL_JOIN_INTENTS))?;
        }

        Ok(TextAttemptOutcome::Staged)
    }
}

#[async_trait]
impl AbstractMls for MongoDb {
    async fn insert_mls_key_packages(&self, packages: &[MlsKeyPackage]) -> Result<()> {
        for package in packages {
            // Typed replace-upsert (NOT `to_document` + $set): the typed
            // path encodes `expires_at` as Int64 unix-ms, matching the
            // expiry sweep's range query — see `timestamp_bson`
            self.col::<MlsKeyPackage>(COL_KEY_PACKAGES)
                .replace_one(doc! { "_id": &package.id }, package)
                .with_options(
                    mongodb::options::ReplaceOptions::builder()
                        .upsert(true)
                        .build(),
                )
                .await
                .map_err(|_| create_database_error!("upsert_one", COL_KEY_PACKAGES))?;
        }

        Ok(())
    }

    async fn count_mls_key_packages(&self, user_id: &str, device_id: &str) -> Result<u64> {
        self.col::<MlsKeyPackage>(COL_KEY_PACKAGES)
            .count_documents(doc! {
                "user_id": user_id,
                "device_id": device_id,
                "last_resort": false
            })
            .await
            .map_err(|_| create_database_error!("count_documents", COL_KEY_PACKAGES))
    }

    async fn insert_mls_key_packages_capped(
        &self,
        user_id: &str,
        device_id: &str,
        packages: &[MlsKeyPackage],
        max: usize,
    ) -> Result<u64> {
        self.insert_mls_key_packages(packages).await?;

        let batch_ids: Vec<String> = packages.iter().map(|package| package.id.clone()).collect();

        // No sort/limit on delete_many, so prune is find-oldest-ids →
        // delete-by-id, re-checked in a bounded loop: a publish racing the
        // find/delete window converges on a later round, and concurrent
        // claims only ever DECREASE the count (their find_one_and_delete is
        // atomic), so a transient over-`max` between rounds is the accepted
        // worst case (plan-audit HIGH-1)
        for _ in 0..3 {
            let count = self.count_mls_key_packages(user_id, device_id).await?;
            if count <= max as u64 {
                return Ok(count);
            }

            // Oldest first: created_at ascending (Int64 unix-ms — see
            // `timestamp_bson`), tie-broken by _id ascending; never the
            // last-resort row, never the batch's own refs
            let mut cursor = self
                .col::<Document>(COL_KEY_PACKAGES)
                .find(doc! {
                    "user_id": user_id,
                    "device_id": device_id,
                    "last_resort": false,
                    "_id": { "$nin": batch_ids.clone() }
                })
                .with_options(
                    FindOptions::builder()
                        .sort(doc! { "created_at": 1, "_id": 1 })
                        .projection(doc! { "_id": 1 })
                        .limit((count - max as u64) as i64)
                        .build(),
                )
                .await
                .map_err(|_| create_database_error!("find", COL_KEY_PACKAGES))?;

            let mut ids: Vec<String> = vec![];
            while let Some(document) = cursor.next().await {
                let document =
                    document.map_err(|_| create_database_error!("find", COL_KEY_PACKAGES))?;
                if let Ok(id) = document.get_str("_id") {
                    ids.push(id.to_string());
                }
            }

            if ids.is_empty() {
                // Nothing prunable (everything stored is the batch itself /
                // last-resort) — the count stands
                break;
            }

            self.col::<Document>(COL_KEY_PACKAGES)
                .delete_many(doc! { "_id": { "$in": ids } })
                .await
                .map_err(|_| create_database_error!("delete_many", COL_KEY_PACKAGES))?;
        }

        self.count_mls_key_packages(user_id, device_id).await
    }

    async fn consume_mls_key_package(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<MlsKeyPackage>> {
        // Atomic take: two concurrent claimers can never get the same
        // one-time package (mirrors consume_e2ee_one_time_key)
        self.col::<MlsKeyPackage>(COL_KEY_PACKAGES)
            .find_one_and_delete(doc! {
                "user_id": user_id,
                "device_id": device_id,
                "last_resort": false
            })
            .await
            .map_err(|_| create_database_error!("find_one_and_delete", COL_KEY_PACKAGES))
    }

    async fn fetch_one_mls_key_package(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<MlsKeyPackage>> {
        query!(
            self,
            find_one,
            COL_KEY_PACKAGES,
            doc! {
                "user_id": user_id,
                "device_id": device_id
            }
        )
    }

    async fn fetch_mls_last_resort_key_package(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<MlsKeyPackage>> {
        // An expired last-resort package must not be served during the
        // window before the hourly sweep removes it (crypto gate finding)
        query!(
            self,
            find_one,
            COL_KEY_PACKAGES,
            doc! {
                "user_id": user_id,
                "device_id": device_id,
                "last_resort": true,
                "expires_at": { "$gt": timestamp_bson(&Timestamp::now_utc()) }
            }
        )
    }

    async fn replace_mls_last_resort_key_package(&self, package: &MlsKeyPackage) -> Result<()> {
        self.col::<Document>(COL_KEY_PACKAGES)
            .delete_many(doc! {
                "user_id": &package.user_id,
                "device_id": &package.device_id,
                "last_resort": true
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL_KEY_PACKAGES))?;

        self.col::<MlsKeyPackage>(COL_KEY_PACKAGES)
            .insert_one(package)
            .await
            .map_err(|_| create_database_error!("insert_one", COL_KEY_PACKAGES))
            .map(|_| ())
    }

    async fn delete_mls_key_packages(&self, user_id: &str, device_id: &str) -> Result<usize> {
        self.col::<Document>(COL_KEY_PACKAGES)
            .delete_many(doc! {
                "user_id": user_id,
                "device_id": device_id
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL_KEY_PACKAGES))
            .map(|result| result.deleted_count as usize)
    }

    async fn delete_expired_mls_key_packages(&self, now: Timestamp) -> Result<usize> {
        self.col::<Document>(COL_KEY_PACKAGES)
            .delete_many(doc! {
                "expires_at": { "$lt": timestamp_bson(&now) }
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL_KEY_PACKAGES))
            .map(|result| result.deleted_count as usize)
    }

    async fn create_mls_group(
        &self,
        group: &MlsGroup,
        supersedes: Option<&str>,
    ) -> Result<MlsGroupCreateOutcome> {
        // Call groups only: Text groups are created by
        // `create_text_mls_group` (protected-channels models)
        if group.kind != MlsGroupKind::Call {
            return Err(create_error!(InvalidOperation));
        }

        if let Some(superseded_id) = supersedes {
            // CAS-close the predecessor: only one successor's update matches
            // the open document; the loser falls through to the conflict
            // path and joins whatever group is (or becomes) open
            let closed = self
                .col::<MlsGroup>(COL_GROUPS)
                .update_one(
                    doc! {
                        "_id": superseded_id,
                        "channel_id": &group.channel_id,
                        "kind": kind_filter(group.kind),
                        "open": true
                    },
                    doc! {
                        "$set": {
                            "open": false,
                            "closed_at": timestamp_bson(&group.created_at),
                            "superseded_by": &group.id
                        }
                    },
                )
                .await
                .map_err(|_| create_database_error!("update_one", COL_GROUPS))?
                .matched_count
                > 0;

            if !closed {
                let exists: Option<MlsGroup> =
                    query!(self, find_one, COL_GROUPS, doc! { "_id": superseded_id })?;

                match exists {
                    None => return Err(create_error!(NotFound)),
                    Some(old) if old.channel_id != group.channel_id => {
                        return Err(create_error!(FailedValidation {
                            error: "superseded group belongs to another channel".to_string()
                        }));
                    }
                    Some(old) if old.kind != group.kind => {
                        return Err(create_error!(FailedValidation {
                            error: "superseded group is of another kind".to_string()
                        }));
                    }
                    // Already closed by a racing successor — fall through to
                    // the normal create/conflict path below
                    Some(_) => {}
                }
            }
        }

        // The partial unique index on (channel_id, kind WHERE open) is the
        // arbitration: exactly one insert per open-group slot succeeds.
        // NOTE: if the supersedes branch above closed the predecessor and
        // this insert then fails (crash/duplicate), the channel briefly has
        // no open group — the next create simply succeeds; the flow
        // converges rather than deadlocks (plan §1.4).
        match self.col::<MlsGroup>(COL_GROUPS).insert_one(group).await {
            Ok(_) => Ok(MlsGroupCreateOutcome::Created),
            Err(error) if is_duplicate_key(&error) => {
                let open = self
                    .fetch_open_mls_group_for_channel(&group.channel_id, group.kind)
                    .await?;

                match open {
                    Some(existing) => Ok(MlsGroupCreateOutcome::Conflict {
                        open_group_id: existing.id,
                        channel_id: existing.channel_id,
                    }),
                    // The winner closed again between our insert and this
                    // fetch (or the duplicate was the group id itself);
                    // surface as a retryable conflict-shaped error
                    None => Err(create_error!(InvalidOperation)),
                }
            }
            Err(_) => Err(create_database_error!("insert_one", COL_GROUPS)),
        }
    }

    async fn fetch_mls_group(&self, group_id: &str) -> Result<MlsGroup> {
        self.fetch_mls_group_repaired(group_id).await
    }

    async fn fetch_open_mls_group_for_channel(
        &self,
        channel_id: &str,
        kind: MlsGroupKind,
    ) -> Result<Option<MlsGroup>> {
        query!(
            self,
            find_one,
            COL_GROUPS,
            doc! {
                "channel_id": channel_id,
                "kind": kind_filter(kind),
                "open": true
            }
        )
    }

    async fn close_mls_group(&self, group_id: &str) -> Result<bool> {
        // Call groups only: the kind filter makes the write itself unable
        // to touch a Text group; the follow-up read turns that into a loud
        // refusal
        let result = self
            .col::<MlsGroup>(COL_GROUPS)
            .update_one(
                doc! {
                    "_id": group_id,
                    "open": true,
                    "kind": kind_filter(MlsGroupKind::Call)
                },
                doc! {
                    "$set": {
                        "open": false,
                        "closed_at": timestamp_bson(&Timestamp::now_utc())
                    }
                },
            )
            .await
            .map_err(|_| create_database_error!("update_one", COL_GROUPS))?;

        if result.matched_count > 0 {
            return Ok(true);
        }

        // Idempotence vs missing group vs Text group
        let exists: Option<MlsGroup> =
            query!(self, find_one, COL_GROUPS, doc! { "_id": group_id })?;
        match exists {
            None => Err(create_error!(NotFound)),
            Some(group) if group.kind != MlsGroupKind::Call => Err(create_error!(InvalidOperation)),
            Some(_) => Ok(false),
        }
    }

    async fn insert_mls_commit(&self, commit: &MlsCommit) -> Result<MlsCommitOutcome> {
        // Repair-then-validate: absorbs any arbitrated-but-unapplied epoch
        // first, so validation runs against the latest winning state. The
        // check→insert window is not transactional — a commit racing at the
        // same epoch is settled by the unique-index CAS below, and a stale
        // read merely produces a retryable validation error.
        let group = self.fetch_mls_group_repaired(&commit.group_id).await?;

        // Call path only: Text commits go through insert_mls_text_commit
        if group.kind != MlsGroupKind::Call {
            return Err(create_error!(InvalidOperation));
        }

        if !group.open {
            return Err(create_error!(FailedValidation {
                error: "group is closed".to_string()
            }));
        }

        if !group.has_member(&commit.committer.user_id, &commit.committer.device_id) {
            return Err(create_error!(NotFound));
        }

        if commit.epoch <= group.current_epoch {
            let winning: Option<MlsCommit> = query!(
                self,
                find_one,
                COL_COMMITS,
                doc! { "_id": MlsCommit::composite_id(&commit.group_id, commit.epoch) }
            )?;
            let winning = winning.ok_or_else(|| create_error!(NotFound))?;
            return Ok(MlsCommitOutcome::Lost { winning });
        }

        if commit.epoch != group.current_epoch + 1 {
            return Err(create_error!(FailedValidation {
                error: "commit epoch must be exactly current_epoch + 1".to_string()
            }));
        }

        for added in &commit.added {
            if let Some(existing) = group.member_device_of(&added.user_id) {
                let error = if existing.device_id == added.device_id {
                    "added device is already a member"
                } else {
                    "user already has a live leaf from another device"
                };
                return Err(create_error!(FailedValidation {
                    error: error.to_string()
                }));
            }
        }

        let real_removals = commit
            .removed
            .iter()
            .filter(|removed| group.has_member(&removed.user_id, &removed.device_id))
            .count();
        if group.members.len() + commit.added.len() - real_removals > MAX_MLS_GROUP_MEMBERS {
            return Err(create_error!(FailedValidation {
                error: "group is at the E2EE roster ceiling".to_string()
            }));
        }

        // The CAS: exactly one insert per {group_id}:{epoch} succeeds
        match self.col::<MlsCommit>(COL_COMMITS).insert_one(commit).await {
            Ok(_) => {
                // Win: apply effects. If this crashes, the next reader's
                // repair loop applies them instead — never lost, never
                // double-applied (the effects update is epoch-CAS'd).
                self.apply_mls_commit_effects(&group, commit).await?;
                Ok(MlsCommitOutcome::Won)
            }
            Err(error) if is_duplicate_key(&error) => {
                let winning: Option<MlsCommit> = query!(
                    self,
                    find_one,
                    COL_COMMITS,
                    doc! { "_id": &commit.id }
                )?;
                let winning = winning.ok_or_else(|| create_error!(NotFound))?;

                // Loser-side repair: make sure the winner's effects land
                // even if the winner crashed right after its insert
                self.apply_mls_commit_effects(&group, &winning).await?;

                Ok(MlsCommitOutcome::Lost { winning })
            }
            Err(_) => Err(create_database_error!("insert_one", COL_COMMITS)),
        }
    }

    async fn insert_mls_text_commit(
        &self,
        commit: &MlsCommit,
        ad_sha256: &str,
        entitlement_device_cap: u32,
    ) -> Result<MlsCommitOutcome> {
        // ONE multi-document transaction, retried as a whole (design §2.5
        // (a)). No repair loop: insert, effects and intent consumption are
        // atomic. A seat-list write touches the same group document, so
        // write-conflict detection serializes the two; the loser retries
        // and sees the other's result.
        for attempt in 0..TEXT_COMMIT_ATTEMPTS {
            if attempt > 0 {
                #[cfg(test)]
                TEXT_COMMIT_RETRIES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                text_commit_backoff(attempt).await;
            }

            let mut session = self
                .start_session()
                .await
                .map_err(|_| create_database_error!("start_session", COL_COMMITS))?;

            session
                .start_transaction()
                .read_concern(ReadConcern::snapshot())
                .write_concern(WriteConcern::majority())
                .await
                .map_err(|_| create_database_error!("start_transaction", COL_COMMITS))?;

            let attempt = self
                .text_commit_attempt(&mut session, commit, ad_sha256, entitlement_device_cap)
                .await;

            match attempt {
                Ok(TextAttemptOutcome::Existing(winning)) => {
                    // Nothing was written; the abort result does not matter
                    let _ = session.abort_transaction().await;
                    return Ok(MlsCommitOutcome::Lost { winning });
                }
                Ok(TextAttemptOutcome::Staged) => {
                    // Commit, retrying the commit itself on
                    // UnknownTransactionCommitResult (commitTransaction is
                    // idempotent). A transient error retries the whole
                    // transaction; anything else is the database error, and
                    // the committer runs its outcome recovery (W0-fix5).
                    let mut retry_whole = false;
                    for _ in 0..TEXT_COMMIT_ATTEMPTS {
                        match session.commit_transaction().await {
                            Ok(()) => return Ok(MlsCommitOutcome::Won),
                            Err(error)
                                if error.contains_label(UNKNOWN_TRANSACTION_COMMIT_RESULT) =>
                            {
                                continue;
                            }
                            Err(error) if error.contains_label(TRANSIENT_TRANSACTION_ERROR) => {
                                retry_whole = true;
                                break;
                            }
                            Err(_) => {
                                return Err(create_database_error!(
                                    "commit_transaction",
                                    COL_COMMITS
                                ))
                            }
                        }
                    }

                    if !retry_whole {
                        return Err(create_database_error!("commit_transaction", COL_COMMITS));
                    }
                }
                Err(TextAttemptError::Refused(error)) => {
                    let _ = session.abort_transaction().await;
                    return Err(error);
                }
                Err(TextAttemptError::Retry) => {
                    let _ = session.abort_transaction().await;
                }
                Err(TextAttemptError::Mongo(error, operation, collection)) => {
                    let _ = session.abort_transaction().await;
                    if !error.contains_label(TRANSIENT_TRANSACTION_ERROR) {
                        return Err(create_database_error!(operation, collection));
                    }
                }
            }
        }

        Err(create_database_error!("transaction", COL_COMMITS))
    }

    async fn fetch_mls_commits_from(
        &self,
        group_id: &str,
        from_epoch: i64,
        limit: i64,
    ) -> Result<Vec<MlsCommit>> {
        Ok(self
            .col::<MlsCommit>(COL_COMMITS)
            .find(doc! {
                "group_id": group_id,
                "epoch": { "$gte": from_epoch }
            })
            .with_options(
                FindOptions::builder()
                    .sort(doc! { "epoch": 1 })
                    .limit(limit)
                    .build(),
            )
            .await
            .map_err(|_| create_database_error!("find", COL_COMMITS))?
            .filter_map(|s| async { s.ok() })
            .collect::<Vec<MlsCommit>>()
            .await)
    }

    async fn upsert_mls_join_intent(
        &self,
        intent: &MlsJoinIntent,
    ) -> Result<Option<MlsJoinIntent>> {
        self.col::<MlsJoinIntent>(COL_JOIN_INTENTS)
            .find_one_and_replace(doc! { "_id": &intent.id }, intent)
            .with_options(
                mongodb::options::FindOneAndReplaceOptions::builder()
                    .upsert(true)
                    .return_document(mongodb::options::ReturnDocument::Before)
                    .build(),
            )
            .await
            .map_err(|_| create_database_error!("find_one_and_replace", COL_JOIN_INTENTS))
    }

    async fn fetch_mls_join_intents_for_group(
        &self,
        group_id: &str,
    ) -> Result<Vec<MlsJoinIntent>> {
        Ok(self
            .col::<MlsJoinIntent>(COL_JOIN_INTENTS)
            .find(doc! { "group_id": group_id })
            .await
            .map_err(|_| create_database_error!("find", COL_JOIN_INTENTS))?
            .filter_map(|s| async { s.ok() })
            .collect::<Vec<MlsJoinIntent>>()
            .await)
    }

    async fn sweep_mls_groups(
        &self,
        closed_threshold: Timestamp,
        created_threshold: Timestamp,
    ) -> Result<usize> {
        // Text groups are never swept (design §2.5): their commits age out
        // through prune_mls_text_commits instead
        let swept: Vec<MlsGroup> = self
            .col::<MlsGroup>(COL_GROUPS)
            .find(doc! {
                "kind": kind_filter(MlsGroupKind::Call),
                "$or": [
                    { "closed_at": { "$lt": timestamp_bson(&closed_threshold) } },
                    { "created_at": { "$lt": timestamp_bson(&created_threshold) } }
                ]
            })
            .await
            .map_err(|_| create_database_error!("find", COL_GROUPS))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await;

        if swept.is_empty() {
            return Ok(0);
        }

        let ids: Vec<&str> = swept.iter().map(|group| group.id.as_str()).collect();

        self.col::<Document>(COL_COMMITS)
            .delete_many(doc! { "group_id": { "$in": &ids } })
            .await
            .map_err(|_| create_database_error!("delete_many", COL_COMMITS))?;

        self.col::<Document>(COL_JOIN_INTENTS)
            .delete_many(doc! { "group_id": { "$in": &ids } })
            .await
            .map_err(|_| create_database_error!("delete_many", COL_JOIN_INTENTS))?;

        self.col::<Document>(COL_GROUPS)
            .delete_many(doc! { "_id": { "$in": &ids } })
            .await
            .map_err(|_| create_database_error!("delete_many", COL_GROUPS))
            .map(|result| result.deleted_count as usize)
    }

    async fn prune_mls_text_commits(&self, older_than: Timestamp) -> Result<u64> {
        let mut cursor = self
            .col::<Document>(COL_GROUPS)
            .find(doc! { "kind": kind_filter(MlsGroupKind::Text) })
            .with_options(FindOptions::builder().projection(doc! { "_id": 1 }).build())
            .await
            .map_err(|_| create_database_error!("find", COL_GROUPS))?;

        let mut ids: Vec<String> = vec![];
        while let Some(document) = cursor.next().await {
            let document = document.map_err(|_| create_database_error!("find", COL_GROUPS))?;
            if let Ok(id) = document.get_str("_id") {
                ids.push(id.to_string());
            }
        }

        if ids.is_empty() {
            return Ok(0);
        }

        // created_at is Int64 unix-ms on typed writes (`timestamp_bson`)
        self.col::<Document>(COL_COMMITS)
            .delete_many(doc! {
                "group_id": { "$in": ids },
                "created_at": { "$lt": timestamp_bson(&older_than) }
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL_COMMITS))
            .map(|result| result.deleted_count)
    }
}
