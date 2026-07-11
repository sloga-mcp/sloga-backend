use bson::{Bson, Document};
use iso8601_timestamp::Timestamp;
use mongodb::options::FindOptions;
use revolt_result::Result;

use futures::StreamExt;

use crate::{
    AbstractMls, MlsCommit, MlsCommitOutcome, MlsGroup, MlsGroupCreateOutcome, MlsJoinIntent,
    MlsKeyPackage, MongoDb, MAX_MLS_GROUP_MEMBERS,
};

const COL_KEY_PACKAGES: &str = "mls_key_packages";
const COL_GROUPS: &str = "mls_groups";
const COL_COMMITS: &str = "mls_commits";
const COL_JOIN_INTENTS: &str = "mls_join_intents";

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
    /// Apply a winning commit's effects to the group document — epoch bump +
    /// asserted roster delta — as a CAS conditioned on `current_epoch ==
    /// commit.epoch - 1`. Idempotent: a second applier (or the loser-side
    /// repair after a winner crashed between commit insert and group update)
    /// simply matches nothing. Returns whether this call applied it.
    async fn apply_mls_commit_effects(&self, group: &MlsGroup, commit: &MlsCommit) -> Result<bool> {
        let mut updated = group.clone();
        updated.current_epoch = commit.epoch;
        updated
            .members
            .retain(|member| !commit.removed.iter().any(|removed| removed == member));
        updated.members.extend(commit.added.iter().cloned());

        self.col::<MlsGroup>(COL_GROUPS)
            .replace_one(
                doc! {
                    "_id": &group.id,
                    "current_epoch": commit.epoch - 1,
                    "open": true
                },
                &updated,
            )
            .await
            .map_err(|_| create_database_error!("replace_one", COL_GROUPS))
            .map(|result| result.matched_count > 0)
    }

    /// Fetch a group and lazily repair its `current_epoch`/roster mirror
    /// from any stored winning commit it has not yet absorbed (crash
    /// recovery between the commit CAS and the group update — the Reference
    /// driver's single Mutex has no such window)
    async fn fetch_mls_group_repaired(&self, group_id: &str) -> Result<MlsGroup> {
        // Bounded: each iteration absorbs one already-arbitrated epoch
        for _ in 0..64 {
            let group: MlsGroup = query!(self, find_one, COL_GROUPS, doc! { "_id": group_id })?
                .ok_or_else(|| create_error!(NotFound))?;

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

    async fn count_mls_key_packages_among(
        &self,
        user_id: &str,
        device_id: &str,
        refs: &[String],
    ) -> Result<u64> {
        let ids: Vec<String> = refs
            .iter()
            .map(|reference| MlsKeyPackage::composite_id(user_id, device_id, reference))
            .collect();

        self.col::<MlsKeyPackage>(COL_KEY_PACKAGES)
            .count_documents(doc! {
                "_id": { "$in": ids }
            })
            .await
            .map_err(|_| create_database_error!("count_documents", COL_KEY_PACKAGES))
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
                    // Already closed by a racing successor — fall through to
                    // the normal create/conflict path below
                    Some(_) => {}
                }
            }
        }

        // The partial unique index on (channel_id WHERE open) is the
        // arbitration: exactly one insert per open-group slot succeeds.
        // NOTE: if the supersedes branch above closed the predecessor and
        // this insert then fails (crash/duplicate), the channel briefly has
        // no open group — the next create simply succeeds; the flow
        // converges rather than deadlocks (plan §1.4).
        match self.col::<MlsGroup>(COL_GROUPS).insert_one(group).await {
            Ok(_) => Ok(MlsGroupCreateOutcome::Created),
            Err(error) if is_duplicate_key(&error) => {
                let open = self
                    .fetch_open_mls_group_for_channel(&group.channel_id)
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
    ) -> Result<Option<MlsGroup>> {
        query!(
            self,
            find_one,
            COL_GROUPS,
            doc! {
                "channel_id": channel_id,
                "open": true
            }
        )
    }

    async fn close_mls_group(&self, group_id: &str) -> Result<bool> {
        let result = self
            .col::<MlsGroup>(COL_GROUPS)
            .update_one(
                doc! { "_id": group_id, "open": true },
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

        // Idempotence vs missing group
        let exists: Option<MlsGroup> =
            query!(self, find_one, COL_GROUPS, doc! { "_id": group_id })?;
        exists.map(|_| false).ok_or_else(|| create_error!(NotFound))
    }

    async fn insert_mls_commit(&self, commit: &MlsCommit) -> Result<MlsCommitOutcome> {
        // Repair-then-validate: absorbs any arbitrated-but-unapplied epoch
        // first, so validation runs against the latest winning state. The
        // check→insert window is not transactional — a commit racing at the
        // same epoch is settled by the unique-index CAS below, and a stale
        // read merely produces a retryable validation error.
        let group = self.fetch_mls_group_repaired(&commit.group_id).await?;

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

    async fn sweep_mls_groups(
        &self,
        closed_threshold: Timestamp,
        created_threshold: Timestamp,
    ) -> Result<usize> {
        let swept: Vec<MlsGroup> = self
            .col::<MlsGroup>(COL_GROUPS)
            .find(doc! {
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
}
