//! Reference driver for protected-channel data.
//!
//! LOCK ORDER (design 2.5 (d), extended by this lane): every path that holds
//! more than one of these collection locks takes them in this order and
//! holds them for the whole operation:
//!
//! `channels -> messages -> channel_entitlements -> servers ->
//!  server_members -> channel_seat_lists -> channel_seats -> mls_groups
//!  -> mls_commits -> mls_join_intents -> e2ee_identities`
//!
//! The doc's order starts at `channel_seat_lists`. `channels` (protect sets
//! the flag atomically with the genesis list, and refuses a channel with
//! threads), `messages` (protect refuses a channel that already holds a
//! message), `channel_entitlements` (the slot cap read together with the
//! seat claims, and the admin grant's seats-in-use check), `servers`
//! (protect's owner check, decision 13 (W2)) and `server_members` (the
//! membership of every newly seated user, decision 13 (W2)) are PREFIXED,
//! so the doc's order is a suffix of this one and every path it pins stays
//! valid. No other Reference path holds `servers` or `server_members`
//! together with another lock (`delete_role` takes them one at a time).
//!
//! Decision 13's claim order `groups -> servers -> server_members -> seats`
//! is the Mongo write order (a liveness rule: the first write fixes the
//! snapshot). Here every lock is taken up front and held for the whole
//! operation, so the 2.5 (d) order, which puts `mls_groups` after
//! `channel_seats`, is kept; the release and Text commit paths rely on it.

use std::collections::{BTreeSet, HashMap};

use iso8601_timestamp::Timestamp;
use revolt_result::Result;
use sha2::{Digest, Sha256};

use crate::{
    channel_seats_used, check_channel_protectable, check_text_first_generation,
    check_text_successor, is_genesis_reprotect, plan_seat_list_write, prepare_text_group,
    seat_cooldown_until, seat_list_channel_server, Channel, ChannelEntitlement, ChannelSeat,
    Member, MemberCompositeKey, MlsGroup, MlsGroupCreateOutcome, MlsGroupKind, MlsPendingRemoval,
    ReferenceDb, SeatList, SeatListBody, SeatListSnapshot, SeatListSubmission,
    SeatListWriteDecision, SeatListWriteInput, SeatListWriteKind, SeatListWriteOutcome,
    MAX_CHANNEL_SLOT_CAP,
};

use super::AbstractProtectedChannels;

fn is_open_text_group_of(group: &MlsGroup, channel_id: &str) -> bool {
    group.channel_id == channel_id && group.open && group.kind == MlsGroupKind::Text
}

/// Text group id derivation context (design 0.4, WIRE FORMAT, never rename)
const CONTEXT_TEXT_GROUP: &str = "sloga-text-group-v1";

/// M9 (W3a audit), shared by both drivers: whether a Text create's id
/// really derives from its channel and generation (design 3.1).
///
/// Text group ids are public and deterministic, while a Call create takes
/// any 64-hex id on any channel its caller can call in. A Call row at the
/// id a Text create derives is therefore a squat by construction (a random
/// Call id equals a derived one with probability 2^-256), and
/// `create_text_mls_group` evicts it in the same atomic unit as its insert.
/// The database cannot see that the route checked the derivation, so the
/// eviction is bounded here: a create naming any other id (another call's
/// random id) keeps the `InvalidOperation` refusal and deletes nothing.
/// This is the design 3.1 equation; delta's `routes/mls/text.rs`
/// `text_group_id` is the route's copy, and the tests pin this one to the
/// 5.5 vectors.
pub(super) fn is_derived_text_group_id(group: &MlsGroup) -> bool {
    let Some(generation) = group.generation else {
        return false;
    };
    let digest = Sha256::digest(format!(
        "{CONTEXT_TEXT_GROUP}\n{}\n{generation}",
        group.channel_id
    ));
    let derived: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    derived == group.id
}

/// The audit line of an M9 eviction (ids only): the Text group, its
/// channel, and the evicted Call row's channel and creator
pub(super) fn log_call_squat_evicted(group: &MlsGroup, call_channel_id: &str, call_creator: &str) {
    log::warn!(
        "AUDIT mls_text_squat_evicted group={} channel={} call_channel={} call_creator={}",
        group.id,
        group.channel_id,
        call_channel_id,
        call_creator
    );
}

/// Decision 13 (W2): every newly seated user is a member of the server
/// (Reference has no soft deletion: a removed member is gone from the map)
fn check_members(
    members: &HashMap<MemberCompositeKey, Member>,
    server_id: &str,
    decision: &SeatListWriteDecision,
) -> Result<()> {
    let SeatListWriteDecision::Apply(plan) = decision else {
        return Ok(());
    };
    for user_id in &plan.claimed {
        let key = MemberCompositeKey {
            server: server_id.to_string(),
            user: user_id.clone(),
        };
        if !members.contains_key(&key) {
            return Err(create_error!(FailedValidation {
                error: "seated user is not a member of the server".to_string()
            }));
        }
    }
    Ok(())
}

/// Apply a seat-list plan to the locked maps. Infallible: every check ran
/// in the planner, so nothing here can fail half-way.
fn apply_decision(
    decision: &SeatListWriteDecision,
    seat_lists: &mut HashMap<String, SeatList>,
    seats: &mut HashMap<String, ChannelSeat>,
    groups: &mut HashMap<String, MlsGroup>,
    text_group_id: Option<&str>,
) {
    let SeatListWriteDecision::Apply(plan) = decision else {
        return;
    };

    seat_lists.insert(plan.row.id.clone(), plan.row.clone());
    for seat in &plan.seat_rows {
        seats.insert(seat.id.clone(), seat.clone());
    }
    if let Some(group) = text_group_id.and_then(|id| groups.get_mut(id)) {
        group.seat_list_ad_sha256 = Some(plan.seat_list_ad_sha256.clone());
        group
            .pending_removals
            .extend(plan.pending_added.iter().cloned());
    }
}

#[async_trait]
impl AbstractProtectedChannels for ReferenceDb {
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

        let mut entitlements = self.channel_entitlements.lock().await;
        let seats = self.channel_seats.lock().await;

        let channel_seats: Vec<ChannelSeat> = seats
            .values()
            .filter(|seat| seat.channel_id == entitlement.channel_id)
            .cloned()
            .collect();
        if channel_seats_used(&channel_seats, now) > entitlement.slot_cap as usize {
            return Err(create_error!(SeatCapReached {
                max: entitlement.slot_cap as usize
            }));
        }

        let stored = match entitlements
            .values()
            .find(|existing| existing.channel_id == entitlement.channel_id)
        {
            Some(existing) => ChannelEntitlement {
                slot_cap: entitlement.slot_cap,
                device_cap: entitlement.device_cap,
                granted_by: entitlement.granted_by.clone(),
                ..existing.clone()
            },
            None => entitlement.clone(),
        };

        entitlements.insert(stored.id.clone(), stored.clone());
        Ok(stored)
    }

    async fn fetch_channel_entitlement(
        &self,
        channel_id: &str,
    ) -> Result<Option<ChannelEntitlement>> {
        let entitlements = self.channel_entitlements.lock().await;
        Ok(entitlements
            .values()
            .find(|entitlement| entitlement.channel_id == channel_id)
            .cloned())
    }

    async fn fetch_channel_seats(&self, channel_id: &str) -> Result<Vec<ChannelSeat>> {
        let seats = self.channel_seats.lock().await;
        let mut rows: Vec<ChannelSeat> = seats
            .values()
            .filter(|seat| seat.channel_id == channel_id)
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(rows)
    }

    async fn fetch_channel_seats_for_user(&self, user_id: &str) -> Result<Vec<ChannelSeat>> {
        let seats = self.channel_seats.lock().await;
        let mut rows: Vec<ChannelSeat> = seats
            .values()
            .filter(|seat| seat.user_id == user_id)
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(rows)
    }

    async fn fetch_seat_list(&self, channel_id: &str) -> Result<Option<SeatList>> {
        let seat_lists = self.channel_seat_lists.lock().await;
        Ok(seat_lists.get(channel_id).cloned())
    }

    async fn fetch_seat_list_snapshot(&self, channel_id: &str) -> Result<SeatListSnapshot> {
        let seat_lists = self.channel_seat_lists.lock().await;
        let groups = self.mls_groups.lock().await;

        Ok(SeatListSnapshot {
            list: seat_lists.get(channel_id).cloned(),
            text_group: groups
                .values()
                .find(|group| is_open_text_group_of(group, channel_id))
                .cloned(),
        })
    }

    async fn protect_channel(
        &self,
        channel_id: &str,
        submission: &SeatListSubmission,
        now: Timestamp,
    ) -> Result<SeatListWriteOutcome> {
        let mut channels = self.channels.lock().await;
        let messages = self.messages.lock().await;
        let entitlements = self.channel_entitlements.lock().await;
        let servers = self.servers.lock().await;
        let members = self.server_members.lock().await;
        let mut seat_lists = self.channel_seat_lists.lock().await;
        let mut seats = self.channel_seats.lock().await;
        let mut groups = self.mls_groups.lock().await;

        let server_id = channels
            .get(channel_id)
            .and_then(seat_list_channel_server)
            .map(str::to_string);
        let owned_by = |user_id: &str| {
            server_id
                .as_deref()
                .and_then(|server_id| servers.get(server_id))
                .is_some_and(|server| server.owner == user_id)
        };

        // N3 (#128, decision 4 (W2)): the byte-identical retry of a protect
        // that landed is the stored success, decided before the protect
        // preconditions (which that protect made false); nothing is written
        if let Some(stored) = seat_lists.get(channel_id) {
            if is_genesis_reprotect(submission, stored) && owned_by(&stored.signer_user_id) {
                return Ok(SeatListWriteDecision::Unchanged(stored.clone()).outcome());
            }
        }

        check_channel_protectable(channels.get(channel_id))?;

        // Decision 13 (W2): the list's signer owns the server
        let body = SeatListBody::parse(&submission.body)?;
        if !owned_by(&body.signer_user_id) {
            return Err(create_error!(NotOwner));
        }
        let server_id = server_id.ok_or_else(|| create_error!(InvalidOperation))?;

        // Decision 13 (W2): a channel with threads is refused
        if channels.values().any(|channel| {
            matches!(channel, Channel::Thread { parent_channel, .. } if parent_channel == channel_id)
        }) {
            return Err(create_error!(InvalidOperation));
        }

        // `last_message_id` is written asynchronously (batched), so it can
        // lag a stored message: ask the messages themselves
        if messages
            .values()
            .any(|message| message.channel == channel_id)
        {
            return Err(create_error!(InvalidOperation));
        }

        let entitlement = entitlements
            .values()
            .find(|entitlement| entitlement.channel_id == channel_id)
            .cloned();
        if !entitlement.as_ref().is_some_and(|entitlement| {
            entitlement.is_active() && entitlement.server_id == server_id
        }) {
            return Err(create_error!(InvalidOperation));
        }

        let channel_seats: Vec<ChannelSeat> = seats
            .values()
            .filter(|seat| seat.channel_id == channel_id)
            .cloned()
            .collect();
        let text_group = groups
            .values()
            .find(|group| is_open_text_group_of(group, channel_id))
            .cloned();

        let decision = plan_seat_list_write(&SeatListWriteInput {
            kind: SeatListWriteKind::Protect,
            channel_id,
            submission,
            stored: seat_lists.get(channel_id),
            entitlement: entitlement.as_ref(),
            seats: &channel_seats,
            text_group: text_group.as_ref(),
            allow_claims: true,
            now,
        })?;
        check_members(&members, &server_id, &decision)?;

        apply_decision(
            &decision,
            &mut seat_lists,
            &mut seats,
            &mut groups,
            text_group.as_ref().map(|group| group.id.as_str()),
        );
        if let Some(Channel::TextChannel { protected, .. }) = channels.get_mut(channel_id) {
            *protected = true;
        }

        Ok(decision.outcome())
    }

    async fn put_seat_list(
        &self,
        channel_id: &str,
        submission: &SeatListSubmission,
        allow_claims: bool,
        now: Timestamp,
    ) -> Result<SeatListWriteOutcome> {
        let entitlements = self.channel_entitlements.lock().await;
        let members = self.server_members.lock().await;
        let mut seat_lists = self.channel_seat_lists.lock().await;
        let mut seats = self.channel_seats.lock().await;
        let mut groups = self.mls_groups.lock().await;

        let entitlement = entitlements
            .values()
            .find(|entitlement| entitlement.channel_id == channel_id)
            .cloned();
        let channel_seats: Vec<ChannelSeat> = seats
            .values()
            .filter(|seat| seat.channel_id == channel_id)
            .cloned()
            .collect();
        let text_group = groups
            .values()
            .find(|group| is_open_text_group_of(group, channel_id))
            .cloned();

        let decision = plan_seat_list_write(&SeatListWriteInput {
            kind: SeatListWriteKind::Put,
            channel_id,
            submission,
            stored: seat_lists.get(channel_id),
            entitlement: entitlement.as_ref(),
            seats: &channel_seats,
            text_group: text_group.as_ref(),
            allow_claims,
            now,
        })?;
        // Claims need an active entitlement (the planner refused
        // otherwise), whose server it is; without one nobody is a member
        let server_id = entitlement
            .as_ref()
            .map(|entitlement| entitlement.server_id.as_str())
            .unwrap_or_default();
        check_members(&members, server_id, &decision)?;

        apply_decision(
            &decision,
            &mut seat_lists,
            &mut seats,
            &mut groups,
            text_group.as_ref().map(|group| group.id.as_str()),
        );

        Ok(decision.outcome())
    }

    async fn create_text_mls_group(
        &self,
        group: &MlsGroup,
        supersedes: Option<&str>,
    ) -> Result<MlsGroupCreateOutcome> {
        let seat_lists = self.channel_seat_lists.lock().await;
        let mut groups = self.mls_groups.lock().await;
        // M9: a Call squat at this id goes with its commits and join intents
        let mut commits = self.mls_commits.lock().await;
        let mut intents = self.mls_join_intents.lock().await;

        let list = seat_lists.get(&group.channel_id).ok_or_else(|| {
            create_error!(FailedValidation {
                error: "channel has no seat list".to_string()
            })
        })?;

        let open = groups
            .values()
            .find(|existing| is_open_text_group_of(existing, &group.channel_id))
            .cloned();

        match supersedes {
            Some(superseded_id) => {
                let superseded = groups
                    .get(superseded_id)
                    .ok_or_else(|| create_error!(NotFound))?;
                check_text_successor(superseded, group)?;
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

        let prepared = prepare_text_group(group, list)?;

        // A row already at the id: a Call squat at a derived id is evicted
        // (M9, see `is_derived_text_group_id`) with its Call-plane
        // dependents (the `sweep_mls_groups` cascade; KeyPackages are keyed
        // by device, not group); any other row is refused as before
        let evicted = match groups.get(&prepared.id) {
            None => None,
            Some(taken)
                if taken.kind == MlsGroupKind::Call && is_derived_text_group_id(&prepared) =>
            {
                Some((taken.channel_id.clone(), taken.created_by.user_id.clone()))
            }
            Some(_) => return Err(create_error!(InvalidOperation)),
        };
        if evicted.is_some() {
            groups.remove(&prepared.id);
            commits.retain(|_, commit| commit.group_id != prepared.id);
            intents.retain(|_, intent| intent.group_id != prepared.id);
        }

        if let Some(superseded) = supersedes.and_then(|id| groups.get_mut(id)) {
            if superseded.open {
                superseded.open = false;
                superseded.closed_at = Some(group.created_at);
                superseded.superseded_by = Some(group.id.clone());
            }
        }
        groups.insert(prepared.id.clone(), prepared);

        if let Some((call_channel_id, call_creator)) = evicted {
            log_call_squat_evicted(group, &call_channel_id, &call_creator);
        }

        Ok(MlsGroupCreateOutcome::Created)
    }

    async fn release_channel_seats_for_user(
        &self,
        user_id: &str,
        server_id: Option<&str>,
        now: Timestamp,
    ) -> Result<Vec<String>> {
        let cooldown_until = seat_cooldown_until(now)?;

        let entitlements = self.channel_entitlements.lock().await;
        let mut seats = self.channel_seats.lock().await;
        let mut groups = self.mls_groups.lock().await;

        let scope: Option<BTreeSet<String>> = server_id.map(|server_id| {
            entitlements
                .values()
                .filter(|entitlement| entitlement.server_id == server_id)
                .map(|entitlement| entitlement.channel_id.clone())
                .collect()
        });
        let in_scope = |channel_id: &str| {
            scope
                .as_ref()
                .is_none_or(|scope| scope.contains(channel_id))
        };

        let mut affected = BTreeSet::new();

        for seat in seats.values_mut() {
            if seat.user_id == user_id && seat.is_active() && in_scope(&seat.channel_id) {
                seat.released_at = Some(now);
                seat.cooldown_until = Some(cooldown_until);
                affected.insert(seat.channel_id.clone());
            }
        }

        for group in groups.values_mut() {
            if group.open
                && group.kind == MlsGroupKind::Text
                && in_scope(&group.channel_id)
                && group.members.iter().any(|member| member.user_id == user_id)
                && !group
                    .pending_removals
                    .iter()
                    .any(|pending| pending.user_id == user_id)
            {
                group.pending_removals.push(MlsPendingRemoval {
                    user_id: user_id.to_string(),
                    created_at: now,
                });
                affected.insert(group.channel_id.clone());
            }
        }

        Ok(affected.into_iter().collect())
    }

    async fn delete_protected_channel_data(&self, channel_id: &str) -> Result<()> {
        let mut entitlements = self.channel_entitlements.lock().await;
        let mut seat_lists = self.channel_seat_lists.lock().await;
        let mut seats = self.channel_seats.lock().await;
        let mut groups = self.mls_groups.lock().await;
        let mut commits = self.mls_commits.lock().await;
        let mut intents = self.mls_join_intents.lock().await;

        entitlements.retain(|_, entitlement| entitlement.channel_id != channel_id);
        seat_lists.remove(channel_id);
        seats.retain(|_, seat| seat.channel_id != channel_id);

        let now = Timestamp::now_utc();
        let mut text_group_ids = BTreeSet::new();
        for group in groups.values_mut() {
            if group.channel_id == channel_id && group.kind == MlsGroupKind::Text {
                text_group_ids.insert(group.id.clone());
                if group.open {
                    group.open = false;
                    group.closed_at = Some(now);
                }
            }
        }

        commits.retain(|_, commit| !text_group_ids.contains(&commit.group_id));
        intents.retain(|_, intent| !text_group_ids.contains(&intent.group_id));
        Ok(())
    }
}
