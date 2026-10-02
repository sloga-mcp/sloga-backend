//! Reference driver for protected-channel data.
//!
//! LOCK ORDER (design 2.5 (d), extended by this lane): every path that holds
//! more than one of these collection locks takes them in this order and
//! holds them for the whole operation:
//!
//! `channels -> messages -> channel_entitlements -> channel_seat_lists
//!  -> channel_seats -> mls_groups -> mls_commits -> mls_join_intents
//!  -> e2ee_identities`
//!
//! The doc's order starts at `channel_seat_lists`. `channels` (protect sets
//! the flag atomically with the genesis list), `messages` (protect refuses a
//! channel that already holds a message) and `channel_entitlements`
//! (the slot cap read together with the seat claims, and the admin grant's
//! seats-in-use check) are PREFIXED, so the doc's order is a suffix of this
//! one and every path it pins stays valid.

use std::collections::{BTreeSet, HashMap};

use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::{
    channel_seats_used, check_channel_protectable, check_text_first_generation,
    check_text_successor, plan_seat_list_write, prepare_text_group, seat_cooldown_until, Channel,
    ChannelEntitlement, ChannelSeat, MlsGroup, MlsGroupCreateOutcome, MlsGroupKind,
    MlsPendingRemoval, ReferenceDb, SeatList, SeatListSnapshot, SeatListSubmission,
    SeatListWriteDecision, SeatListWriteInput, SeatListWriteKind, SeatListWriteOutcome,
    MAX_CHANNEL_SLOT_CAP,
};

use super::AbstractProtectedChannels;

fn is_open_text_group_of(group: &MlsGroup, channel_id: &str) -> bool {
    group.channel_id == channel_id && group.open && group.kind == MlsGroupKind::Text
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
        let mut seat_lists = self.channel_seat_lists.lock().await;
        let mut seats = self.channel_seats.lock().await;
        let mut groups = self.mls_groups.lock().await;

        check_channel_protectable(channels.get(channel_id))?;
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
        if !entitlement
            .as_ref()
            .is_some_and(ChannelEntitlement::is_active)
        {
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
            now,
        })?;

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
        now: Timestamp,
    ) -> Result<SeatListWriteOutcome> {
        let entitlements = self.channel_entitlements.lock().await;
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
            now,
        })?;

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
        if groups.contains_key(&prepared.id) {
            return Err(create_error!(InvalidOperation));
        }

        if let Some(superseded) = supersedes.and_then(|id| groups.get_mut(id)) {
            if superseded.open {
                superseded.open = false;
                superseded.closed_at = Some(group.created_at);
                superseded.superseded_by = Some(group.id.clone());
            }
        }
        groups.insert(prepared.id.clone(), prepared);

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
