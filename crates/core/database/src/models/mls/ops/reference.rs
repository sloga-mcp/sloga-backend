use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::{
    MlsCommit, MlsCommitOutcome, MlsGroup, MlsGroupCreateOutcome, MlsJoinIntent, MlsKeyPackage,
    ReferenceDb, MAX_MLS_GROUP_MEMBERS,
};

#[async_trait]
impl crate::AbstractMls for ReferenceDb {
    async fn insert_mls_key_packages(&self, packages: &[MlsKeyPackage]) -> Result<()> {
        let mut stored = self.mls_key_packages.lock().await;
        for package in packages {
            stored.insert(package.id.clone(), package.clone());
        }
        Ok(())
    }

    async fn count_mls_key_packages(&self, user_id: &str, device_id: &str) -> Result<u64> {
        let stored = self.mls_key_packages.lock().await;
        Ok(stored
            .values()
            .filter(|package| {
                package.user_id == user_id
                    && package.device_id == device_id
                    && !package.last_resort
            })
            .count() as u64)
    }

    async fn insert_mls_key_packages_capped(
        &self,
        user_id: &str,
        device_id: &str,
        packages: &[MlsKeyPackage],
        max: usize,
    ) -> Result<u64> {
        // One Mutex hold makes upsert + prune atomic outright — the
        // stronger of the two drivers (Mongo converges via a bounded loop)
        let mut stored = self.mls_key_packages.lock().await;
        for package in packages {
            stored.insert(package.id.clone(), package.clone());
        }

        let batch_ids: std::collections::HashSet<&str> =
            packages.iter().map(|package| package.id.as_str()).collect();

        let count = stored
            .values()
            .filter(|package| {
                package.user_id == user_id
                    && package.device_id == device_id
                    && !package.last_resort
            })
            .count();

        if count <= max {
            return Ok(count as u64);
        }

        // Oldest first: created_at ascending, tie-broken by id ascending
        // (an intra-batch publish shares one `now`) — never the last-resort
        // row, never the batch's own refs
        let mut prunable: Vec<(Timestamp, String)> = stored
            .values()
            .filter(|package| {
                package.user_id == user_id
                    && package.device_id == device_id
                    && !package.last_resort
                    && !batch_ids.contains(package.id.as_str())
            })
            .map(|package| (package.created_at, package.id.clone()))
            .collect();
        prunable.sort();

        let mut pruned = 0;
        for (_, id) in prunable.into_iter().take(count - max) {
            stored.remove(&id);
            pruned += 1;
        }

        Ok((count - pruned) as u64)
    }

    async fn consume_mls_key_package(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<MlsKeyPackage>> {
        // The mutex makes take-and-remove atomic, matching Mongo's
        // find_one_and_delete: two concurrent claimers never get the same
        // one-time package
        let mut stored = self.mls_key_packages.lock().await;
        let id = stored
            .values()
            .filter(|package| {
                package.user_id == user_id
                    && package.device_id == device_id
                    && !package.last_resort
            })
            .map(|package| package.id.clone())
            .min();

        Ok(id.and_then(|id| stored.remove(&id)))
    }

    async fn fetch_one_mls_key_package(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<MlsKeyPackage>> {
        let stored = self.mls_key_packages.lock().await;
        Ok(stored
            .values()
            .find(|package| package.user_id == user_id && package.device_id == device_id)
            .cloned())
    }

    async fn fetch_mls_last_resort_key_package(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Result<Option<MlsKeyPackage>> {
        // Expired last-resort packages are never served, even before the
        // hourly sweep removes them (crypto gate finding)
        let now = Timestamp::now_utc();
        let stored = self.mls_key_packages.lock().await;
        Ok(stored
            .values()
            .find(|package| {
                package.user_id == user_id
                    && package.device_id == device_id
                    && package.last_resort
                    && package.expires_at > now
            })
            .cloned())
    }

    async fn replace_mls_last_resort_key_package(&self, package: &MlsKeyPackage) -> Result<()> {
        let mut stored = self.mls_key_packages.lock().await;
        stored.retain(|_, existing| {
            !(existing.user_id == package.user_id
                && existing.device_id == package.device_id
                && existing.last_resort)
        });
        stored.insert(package.id.clone(), package.clone());
        Ok(())
    }

    async fn delete_mls_key_packages(&self, user_id: &str, device_id: &str) -> Result<usize> {
        let mut stored = self.mls_key_packages.lock().await;
        let before = stored.len();
        stored.retain(|_, package| {
            !(package.user_id == user_id && package.device_id == device_id)
        });
        Ok(before - stored.len())
    }

    async fn delete_expired_mls_key_packages(&self, now: Timestamp) -> Result<usize> {
        let mut stored = self.mls_key_packages.lock().await;
        let before = stored.len();
        stored.retain(|_, package| package.expires_at > now);
        Ok(before - stored.len())
    }

    async fn create_mls_group(
        &self,
        group: &MlsGroup,
        supersedes: Option<&str>,
    ) -> Result<MlsGroupCreateOutcome> {
        // Single Mutex = the whole arbitration is atomic (the Reference
        // equivalent of the Mongo partial unique index, plan §1.2)
        let mut groups = self.mls_groups.lock().await;

        if let Some(superseded_id) = supersedes {
            match groups.get(superseded_id) {
                Some(old) if old.channel_id != group.channel_id => {
                    return Err(create_error!(FailedValidation {
                        error: "superseded group belongs to another channel".to_string()
                    }));
                }
                Some(old) if !old.open => {
                    // Someone else already superseded it — conflict with the
                    // channel's actual open group, if any
                }
                Some(_) => {
                    let old = groups
                        .get_mut(superseded_id)
                        .expect("checked present above");
                    old.open = false;
                    old.closed_at = Some(group.created_at);
                    old.superseded_by = Some(group.id.clone());

                    groups.insert(group.id.clone(), group.clone());
                    return Ok(MlsGroupCreateOutcome::Created);
                }
                None => {
                    return Err(create_error!(NotFound));
                }
            }
        }

        if let Some(open) = groups
            .values()
            .find(|existing| existing.channel_id == group.channel_id && existing.open)
        {
            return Ok(MlsGroupCreateOutcome::Conflict {
                open_group_id: open.id.clone(),
                channel_id: open.channel_id.clone(),
            });
        }

        groups.insert(group.id.clone(), group.clone());
        Ok(MlsGroupCreateOutcome::Created)
    }

    async fn fetch_mls_group(&self, group_id: &str) -> Result<MlsGroup> {
        let groups = self.mls_groups.lock().await;
        groups
            .get(group_id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    async fn fetch_open_mls_group_for_channel(
        &self,
        channel_id: &str,
    ) -> Result<Option<MlsGroup>> {
        let groups = self.mls_groups.lock().await;
        Ok(groups
            .values()
            .find(|group| group.channel_id == channel_id && group.open)
            .cloned())
    }

    async fn close_mls_group(&self, group_id: &str) -> Result<bool> {
        let mut groups = self.mls_groups.lock().await;
        let group = groups
            .get_mut(group_id)
            .ok_or_else(|| create_error!(NotFound))?;

        if !group.open {
            return Ok(false);
        }

        group.open = false;
        group.closed_at = Some(Timestamp::now_utc());
        Ok(true)
    }

    async fn insert_mls_commit(&self, commit: &MlsCommit) -> Result<MlsCommitOutcome> {
        // Lock order: groups then commits (matched everywhere in this impl)
        let mut groups = self.mls_groups.lock().await;
        let mut commits = self.mls_commits.lock().await;

        let group = groups
            .get_mut(&commit.group_id)
            .ok_or_else(|| create_error!(NotFound))?;

        if !group.open {
            return Err(create_error!(FailedValidation {
                error: "group is closed".to_string()
            }));
        }

        // Only current members commit (Welcome-based join: the joiner never
        // commits, an existing member admits it — plan §1.6)
        if !group.has_member(&commit.committer.user_id, &commit.committer.device_id) {
            return Err(create_error!(NotFound));
        }

        // Stale epoch: hand the loser the winner it must rebase onto
        if commit.epoch <= group.current_epoch {
            let winning = commits
                .get(&MlsCommit::composite_id(&commit.group_id, commit.epoch))
                .cloned()
                .ok_or_else(|| create_error!(NotFound))?;
            return Ok(MlsCommitOutcome::Lost { winning });
        }

        // Epoch monotonicity (invariant 10): no skip-ahead
        if commit.epoch != group.current_epoch + 1 {
            return Err(create_error!(FailedValidation {
                error: "commit epoch must be exactly current_epoch + 1".to_string()
            }));
        }

        // One-device-per-user (plan §1.5) + roster sanity for added devices
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

        // Roster ceiling (plan A3/Q5) — removed entries not in the roster
        // are tolerated (availability-lenient), so count real removals only
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

        // The CAS itself (single Mutex = atomic contains-check-then-insert)
        let id = MlsCommit::composite_id(&commit.group_id, commit.epoch);
        if let Some(winning) = commits.get(&id) {
            return Ok(MlsCommitOutcome::Lost {
                winning: winning.clone(),
            });
        }
        commits.insert(id, commit.clone());

        // Win: bump the epoch and apply the asserted roster delta
        group.current_epoch = commit.epoch;
        group.members.retain(|member| {
            !commit
                .removed
                .iter()
                .any(|removed| removed == member)
        });
        group.members.extend(commit.added.iter().cloned());

        Ok(MlsCommitOutcome::Won)
    }

    async fn fetch_mls_commits_from(
        &self,
        group_id: &str,
        from_epoch: i64,
        limit: i64,
    ) -> Result<Vec<MlsCommit>> {
        let commits = self.mls_commits.lock().await;
        let mut result: Vec<MlsCommit> = commits
            .values()
            .filter(|commit| commit.group_id == group_id && commit.epoch >= from_epoch)
            .cloned()
            .collect();

        result.sort_by_key(|commit| commit.epoch);
        result.truncate(limit.max(0) as usize);
        Ok(result)
    }

    async fn upsert_mls_join_intent(
        &self,
        intent: &MlsJoinIntent,
    ) -> Result<Option<MlsJoinIntent>> {
        let mut intents = self.mls_join_intents.lock().await;
        Ok(intents.insert(intent.id.clone(), intent.clone()))
    }

    async fn sweep_mls_groups(
        &self,
        closed_threshold: Timestamp,
        created_threshold: Timestamp,
    ) -> Result<usize> {
        let mut groups = self.mls_groups.lock().await;
        let mut commits = self.mls_commits.lock().await;
        let mut intents = self.mls_join_intents.lock().await;

        let swept: Vec<String> = groups
            .values()
            .filter(|group| {
                group
                    .closed_at
                    .is_some_and(|closed_at| closed_at < closed_threshold)
                    || group.created_at < created_threshold
            })
            .map(|group| group.id.clone())
            .collect();

        for group_id in &swept {
            groups.remove(group_id);
        }
        commits.retain(|_, commit| !swept.contains(&commit.group_id));
        intents.retain(|_, intent| !swept.contains(&intent.group_id));

        Ok(swept.len())
    }
}
