use std::collections::HashSet;

use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::{
    ChannelSeat, E2EEIdentity, MlsCommit, MlsCommitOutcome, MlsGroup, MlsGroupCreateOutcome,
    MlsGroupKind, MlsJoinIntent, MlsKeyPackage, ReferenceDb, MAX_MLS_GROUP_MEMBERS,
};

use super::plan_mls_text_commit;

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
        // Call groups only: Text groups are created by
        // `create_text_mls_group` (protected-channels models)
        if group.kind != MlsGroupKind::Call {
            return Err(create_error!(InvalidOperation));
        }

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
                Some(old) if old.kind != group.kind => {
                    return Err(create_error!(FailedValidation {
                        error: "superseded group is of another kind".to_string()
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

        // Keyed by (channel_id, kind): a channel's Call and Text groups
        // coexist (design §2.7)
        if let Some(open) = groups.values().find(|existing| {
            existing.channel_id == group.channel_id && existing.kind == group.kind && existing.open
        }) {
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
        kind: MlsGroupKind,
    ) -> Result<Option<MlsGroup>> {
        let groups = self.mls_groups.lock().await;
        Ok(groups
            .values()
            .find(|group| group.channel_id == channel_id && group.kind == kind && group.open)
            .cloned())
    }

    async fn close_mls_group(&self, group_id: &str) -> Result<bool> {
        let mut groups = self.mls_groups.lock().await;
        let group = groups
            .get_mut(group_id)
            .ok_or_else(|| create_error!(NotFound))?;

        // Call groups only: a Text group is refused and left untouched
        if group.kind != MlsGroupKind::Call {
            return Err(create_error!(InvalidOperation));
        }

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

        // Call path only: Text commits go through insert_mls_text_commit
        if group.kind != MlsGroupKind::Call {
            return Err(create_error!(InvalidOperation));
        }

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

        // Admission consumes the joiner's intent row (dual-reload close,
        // rejoin plan §5) — lock order groups → commits → intents matches
        // the sweep
        if !commit.added.is_empty() {
            let mut intents = self.mls_join_intents.lock().await;
            for added in &commit.added {
                intents.remove(&MlsJoinIntent::composite_id(
                    &commit.group_id,
                    &added.user_id,
                    &added.device_id,
                ));
            }
        }

        Ok(MlsCommitOutcome::Won)
    }

    async fn insert_mls_text_commit(
        &self,
        commit: &MlsCommit,
        ad_sha256: &str,
        entitlement_device_cap: u32,
    ) -> Result<MlsCommitOutcome> {
        // Lock order (design §2.5 (d)): channel_seat_lists -> channel_seats
        // -> mls_groups -> mls_commits -> mls_join_intents -> e2ee_identities,
        // every lock held for the whole operation, so the read, the checks
        // and the writes are one atomic unit (the Reference form of the
        // Mongo transaction). channel_seats is held so a seat release
        // (which takes it) can never interleave with the added users' seat
        // check.
        let seat_lists = self.channel_seat_lists.lock().await;
        let seats = self.channel_seats.lock().await;
        let mut groups = self.mls_groups.lock().await;
        let mut commits = self.mls_commits.lock().await;
        let mut intents = self.mls_join_intents.lock().await;
        let identities = self.e2ee_identities.lock().await;

        // Step 0: an existing row wins before any validity check
        let id = MlsCommit::composite_id(&commit.group_id, commit.epoch);
        if let Some(winning) = commits.get(&id) {
            return Ok(MlsCommitOutcome::Lost {
                winning: winning.clone(),
            });
        }

        // Step 1: one consistent read
        let group = groups
            .get_mut(&commit.group_id)
            .ok_or_else(|| create_error!(NotFound))?;
        let seat_list = seat_lists.get(&group.channel_id);
        let stored_intents: Vec<MlsJoinIntent> = commit
            .removed
            .iter()
            .filter_map(|removed| {
                intents
                    .get(&MlsJoinIntent::composite_id(
                        &group.id,
                        &removed.user_id,
                        &removed.device_id,
                    ))
                    .cloned()
            })
            .collect();
        let revoked_identities: HashSet<String> = commit
            .removed
            .iter()
            .map(|removed| E2EEIdentity::composite_id(&removed.user_id, &removed.device_id))
            .filter(|identity_id| !identities.contains_key(identity_id))
            .collect();
        let active_seat_users: HashSet<String> = commit
            .added
            .iter()
            .filter(|added| {
                seats
                    .get(&ChannelSeat::composite_id(
                        &group.channel_id,
                        &added.user_id,
                    ))
                    .is_some_and(|seat| seat.is_active())
            })
            .map(|added| added.user_id.clone())
            .collect();

        // Step 2: every validity check
        let plan = plan_mls_text_commit(
            group,
            commit,
            ad_sha256,
            seat_list,
            entitlement_device_cap,
            &stored_intents,
            &revoked_identities,
            &active_seat_users,
        )?;

        // Steps 3 to 5 (the filter of step 4 is the state just validated
        // under the same locks)
        commits.insert(id, plan.stored);

        group.current_epoch = commit.epoch;
        group.members = plan.members;
        group.member_added = plan.member_added;
        group
            .pending_removals
            .retain(|pending| !plan.cleared_pending.contains(&pending.user_id));

        for intent_id in &plan.consumed_intent_ids {
            intents.remove(intent_id);
        }

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

    async fn fetch_mls_join_intents_for_group(
        &self,
        group_id: &str,
    ) -> Result<Vec<MlsJoinIntent>> {
        let intents = self.mls_join_intents.lock().await;
        Ok(intents
            .values()
            .filter(|intent| intent.group_id == group_id)
            .cloned()
            .collect())
    }

    async fn sweep_mls_groups(
        &self,
        closed_threshold: Timestamp,
        created_threshold: Timestamp,
    ) -> Result<usize> {
        let mut groups = self.mls_groups.lock().await;
        let mut commits = self.mls_commits.lock().await;
        let mut intents = self.mls_join_intents.lock().await;

        // Text groups are never swept (design §2.5): their commits age out
        // through prune_mls_text_commits instead
        let swept: Vec<String> = groups
            .values()
            .filter(|group| {
                group.kind == MlsGroupKind::Call
                    && (group
                        .closed_at
                        .is_some_and(|closed_at| closed_at < closed_threshold)
                        || group.created_at < created_threshold)
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

    async fn prune_mls_text_commits(&self, older_than: Timestamp) -> Result<u64> {
        // Lock order: groups then commits
        let groups = self.mls_groups.lock().await;
        let mut commits = self.mls_commits.lock().await;

        let text_groups: HashSet<&str> = groups
            .values()
            .filter(|group| group.kind == MlsGroupKind::Text)
            .map(|group| group.id.as_str())
            .collect();

        let before = commits.len();
        commits.retain(|_, commit| {
            !(text_groups.contains(commit.group_id.as_str()) && commit.created_at < older_than)
        });
        Ok((before - commits.len()) as u64)
    }
}
