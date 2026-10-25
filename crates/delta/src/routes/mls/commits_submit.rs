use std::collections::HashSet;

use iso8601_timestamp::{Duration, Timestamp};
use revolt_database::{
    events::client::EventV1, is_valid_device_id, mls_text_enforced_device_cap, Channel, Database,
    E2EEContentType, E2EEEnvelope, MlsCommit, MlsCommitOutcome, MlsEnvelopeRejoinIntent, MlsGroup,
    MlsJoinIntent, MlsMemberDevice, MlsRemovalReason, MlsRemovedReason, SeatListBody, Session,
    User, E2EE_PROTOCOL_VERSION, MAX_MLS_GROUP_MEMBERS, MAX_MLS_TEXT_GROUP_MEMBERS,
};
use revolt_models::v0;
use revolt_result::{create_error, ErrorType, Result};
use rocket::{serde::json::Json, State};
use ulid::Ulid;

use crate::routes::e2ee::{require_e2ee_deliver_eligible, MAX_QUEUE_BYTES, MAX_QUEUE_DEPTH};

use super::{
    encoded_len, text, Arbitrated, GroupDispatch, TextGate, MAX_MLS_COMMIT_RAW_SIZE,
    MAX_MLS_WELCOME_RAW_SIZE, REJOIN_OUTSTANDING_WINDOW_SECONDS,
};

/// # Submit MLS Commit
///
/// Submit the commit for the group's next epoch. **The unique-index insert
/// on `{group_id}:{epoch}` IS the arbitration** (plan §2.2.3): exactly one
/// submission per epoch wins (200); the loser receives **409** with the
/// winning commit and rebases onto it.
///
/// On win, the commit is fanned out as an envelope to every member device
/// (queue-first, then live push) and the Welcome to each added device. The
/// added/removed lists are committer-asserted and the server cannot validate
/// them against the ciphertext — a malicious MEMBER can under-fan-out to
/// desync targets. This is availability-only (victims gap-refetch or
/// rejoin; no secrecy impact — plan T-19).
///
/// A protected channel's Text group takes its own path (protected-channels
/// design §6.1, §3.12.2): the caller must view the channel, be seated and
/// commit from the device its session is bound to; a commit row already at
/// the epoch answers before any validity check; the commit's
/// `authenticated_data` must be the channel's newest stored seat list;
/// Adds need the growth flag, an Active entitlement and eligible, seated
/// targets within the device and leaf caps; Removes follow the Remove rule.
/// Its commit envelopes carry the declarations (`committer`, `added`,
/// `removed`, `rejoin_intents`) receivers bind the commit to.
#[openapi(tag = "MLS")]
#[post("/groups/<group_id>/commits", data = "<data>")]
pub async fn submit_commit(
    db: &State<Database>,
    user: User,
    session: Session,
    group_id: String,
    data: Json<v0::DataSubmitMlsCommit>,
) -> Result<Arbitrated<v0::ResponseSubmitMlsCommit>> {
    // Kind dispatch first (decision 1 (W2)). Request validation runs only
    // inside a branch: placed here, a hidden Text group would answer a
    // malformed body differently from an unknown id with the media flag off
    match super::dispatch_group(db, &group_id).await? {
        GroupDispatch::CallOrUnknown(None) => {
            super::as_unknown_group(db, &user, Some(&session)).await
        }
        GroupDispatch::CallOrUnknown(Some(_)) => {
            submit_call_commit(db, user, session, group_id, data.into_inner()).await
        }
        GroupDispatch::Text(group) => {
            submit_text_commit(db, user, session, group, data.into_inner()).await
        }
    }
}

/// The request checks both paths share: the Call path runs them at their
/// existing position, the Text path right after the caller checks (design
/// §6.1 step 5). They read the request only, so the identical resubmit of a
/// commit that won always passes them again (§2.5 step 0 stays idempotent).
fn validate_submission(data: &v0::DataSubmitMlsCommit) -> Result<()> {
    if !is_valid_device_id(&data.device_id) {
        return Err(create_error!(FailedValidation {
            error: "device_id must be 128 bits of lowercase hex".to_string()
        }));
    }

    if data.epoch < 1 {
        return Err(create_error!(FailedValidation {
            error: "epoch must be at least 1".to_string()
        }));
    }

    // Per-content_type size caps (plan §2.2.4) — stated raw, enforced on
    // the encoded field
    if data.commit.is_empty() || data.commit.len() > encoded_len(MAX_MLS_COMMIT_RAW_SIZE) {
        return Err(create_error!(PayloadTooLarge));
    }

    match (&data.welcome, data.added.is_empty()) {
        (Some(welcome), false) => {
            if welcome.is_empty() || welcome.len() > encoded_len(MAX_MLS_WELCOME_RAW_SIZE) {
                return Err(create_error!(PayloadTooLarge));
            }
        }
        (None, true) => {}
        (Some(_), true) => {
            return Err(create_error!(FailedValidation {
                error: "welcome without added devices".to_string()
            }));
        }
        (None, false) => {
            return Err(create_error!(FailedValidation {
                error: "added devices require a welcome".to_string()
            }));
        }
    }

    if data.added.len() > MAX_MLS_GROUP_MEMBERS || data.removed.len() > MAX_MLS_GROUP_MEMBERS {
        return Err(create_error!(FailedValidation {
            error: "fan-out list too large".to_string()
        }));
    }

    let mut seen = HashSet::new();
    for member in data.added.iter().chain(data.removed.iter()) {
        if !is_valid_device_id(&member.device_id) {
            return Err(create_error!(FailedValidation {
                error: "invalid device id in fan-out list".to_string()
            }));
        }
        if !seen.insert((member.user_id.as_str(), member.device_id.as_str())) {
            return Err(create_error!(FailedValidation {
                error: "duplicate device in fan-out lists".to_string()
            }));
        }
    }

    Ok(())
}

/// A Call group's commit: the pre-W2 route, unchanged
async fn submit_call_commit(
    db: &Database,
    user: User,
    session: Session,
    group_id: String,
    data: v0::DataSubmitMlsCommit,
) -> Result<Arbitrated<v0::ResponseSubmitMlsCommit>> {
    super::require_media_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    validate_submission(&data)?;

    let v0::DataSubmitMlsCommit {
        device_id,
        epoch,
        commit: commit_ciphertext,
        welcome,
        added,
        removed,
    } = data;

    // The committing session must be bound to the registered device
    let identity = db
        .fetch_e2ee_identity(&user.id, &device_id)
        .await
        .map_err(|_| {
            create_error!(FailedValidation {
                error: "committing device is not registered".to_string()
            })
        })?;
    identity.assert_bound_session(&session.id)?;

    let (group, channel) = super::fetch_authorized_group(db, &user, &group_id).await?;
    if !group.open {
        return Err(create_error!(FailedValidation {
            error: "group is closed".to_string()
        }));
    }

    // Every ADDED device must be a real device whose user may receive MLS
    // envelopes for this group: call co-presence (channel access) or the
    // text-E2EE deliver gates. Rejecting here (not skipping) keeps the
    // roster mirror clean and closes the welcome-spam/queue-fill vector —
    // an honest committer only adds devices that sent verified join
    // intents, which required channel access.
    for added in &added {
        if db
            .fetch_e2ee_identity(&added.user_id, &added.device_id)
            .await
            .is_err()
        {
            return Err(create_error!(FailedValidation {
                error: "added device is not registered".to_string()
            }));
        }

        if added.user_id != user.id {
            let target_user = db.fetch_user(&added.user_id).await.map_err(|_| {
                create_error!(FailedValidation {
                    error: "added device is not registered".to_string()
                })
            })?;

            // Deliver-eligibility (blocked co-members allowed — E2EE
            // delivery is neither weaker nor stronger than plaintext
            // channel behaviour, slice-5 asymmetry)
            let eligible = super::require_channel_access(db, &target_user, &channel)
                .await
                .is_ok()
                || require_e2ee_deliver_eligible(db, &user, &target_user)
                    .await
                    .is_ok();

            if !eligible {
                return Err(create_error!(FailedValidation {
                    error: "added device is not eligible for this call".to_string()
                }));
            }
        }
    }

    let committer = MlsMemberDevice {
        user_id: user.id.clone(),
        device_id: device_id.clone(),
    };

    // Raw (decoded) size from the unpadded-base64 length
    let commit_raw_size = (commit_ciphertext.len() * 3) / 4;

    let commit = MlsCommit {
        id: MlsCommit::composite_id(&group.id, epoch),
        group_id: group.id.clone(),
        epoch,
        committer: committer.clone(),
        commit: commit_ciphertext,
        size: commit_raw_size as i64,
        added: added
            .iter()
            .map(|member| MlsMemberDevice {
                user_id: member.user_id.clone(),
                device_id: member.device_id.clone(),
            })
            .collect(),
        removed: removed
            .iter()
            .map(|member| MlsMemberDevice {
                user_id: member.user_id.clone(),
                device_id: member.device_id.clone(),
            })
            .collect(),
        created_at: Timestamp::now_utc(),
        // Call commits never carry rejoin intents (Text-only, design §2.5)
        rejoin_intents: vec![],
        // Nor removal reasons (Text-only, B48): never serialized for Call
        removed_reasons: vec![],
    };

    // The CAS — one winner per epoch; membership, epoch monotonicity, the
    // one-device-per-user rule and the roster ceiling are enforced inside
    // (per driver, under its atomicity primitive)
    match db.insert_mls_commit(&commit).await? {
        MlsCommitOutcome::Lost { winning } => Ok(Arbitrated {
            conflict: true,
            body: Json(v0::ResponseSubmitMlsCommit::Lost {
                winning: winning.into_commit_info(&group.channel_id),
            }),
        }),
        MlsCommitOutcome::Won => {
            // Fan out. Commit envelopes go to the PRE-commit roster minus
            // the committer's own device (added devices get the Welcome —
            // they cannot read a commit for a group they are not in yet;
            // removed devices still receive the commit that removes them).
            let commit_recipients: Vec<&MlsMemberDevice> = group
                .members
                .iter()
                .filter(|member| **member != committer)
                .collect();

            let mut envelopes = Vec::new();

            // Call envelopes carry no declarations (design §6.1 errors)
            let build =
                |recipient: &MlsMemberDevice, content_type: E2EEContentType, ciphertext: String| {
                    envelope(
                        &user,
                        &device_id,
                        &group.id,
                        epoch,
                        recipient,
                        content_type,
                        ciphertext,
                    )
                };

            for recipient in commit_recipients {
                envelopes.push(build(
                    recipient,
                    E2EEContentType::MlsCommit,
                    commit.commit.clone(),
                ));
            }

            if let Some(welcome) = &welcome {
                for added in &added {
                    envelopes.push(build(
                        &MlsMemberDevice {
                            user_id: added.user_id.clone(),
                            device_id: added.device_id.clone(),
                        },
                        E2EEContentType::MlsWelcome,
                        welcome.clone(),
                    ));
                }
            }

            deliver(db, envelopes).await?;

            Ok(Arbitrated {
                conflict: false,
                body: Json(v0::ResponseSubmitMlsCommit::Won),
            })
        }
    }
}

/// A protected channel's Text group commit (design §6.1, §2.5 "Commit
/// transaction", §3.12.2). Checks, in order:
///
/// 1. the channel and ViewChannel (any failure answers exactly as an unknown
///    group, the §6.1 invariant);
/// 2. the caller checks, then request validation;
/// 3. the maintenance gate, seated, and the session bound to the committing
///    device: with ViewChannel, the commit-fetch authorization;
/// 4. a row already at `{group}:{epoch}` answers `Lost` with that row,
///    BEFORE every validity check, so an identical resubmit stays
///    idempotent after the group, the seat list or the growth flag moved on
///    (W0-fix8, §11);
/// 5. validity: open; the AD binding; for Adds the growth gate, an Active
///    entitlement and no pending removal; the Remove rule; the Add targets
///    and caps. The commit transaction checks them again on its own read,
///    and that check is the one that binds.
async fn submit_text_commit(
    db: &Database,
    user: User,
    session: Session,
    group: MlsGroup,
    data: v0::DataSubmitMlsCommit,
) -> Result<Arbitrated<v0::ResponseSubmitMlsCommit>> {
    let Ok(channel) = db.fetch_channel(&group.channel_id).await else {
        return super::as_unknown_group(db, &user, Some(&session)).await;
    };
    if super::require_channel_access(db, &user, &channel)
        .await
        .is_err()
    {
        return super::as_unknown_group(db, &user, Some(&session)).await;
    }

    super::require_mls_caller(db, &user, Some(&session)).await?;
    validate_submission(&data)?;
    super::require_text_gate(TextGate::Available).await?;
    super::require_seated(db, &group.channel_id, &user.id).await?;

    // The committing session must be bound to the registered device
    let identity = db
        .fetch_e2ee_identity(&user.id, &data.device_id)
        .await
        .map_err(|_| failed("committing device is not registered"))?;
    identity.assert_bound_session(&session.id)?;

    let v0::DataSubmitMlsCommit {
        device_id,
        epoch,
        commit: commit_ciphertext,
        welcome,
        added,
        removed,
    } = data;

    // Existing-row check: after access, before every validity check
    if let Some(winning) = db
        .fetch_mls_commits_from(&group.id, epoch, 1)
        .await?
        .into_iter()
        .find(|row| row.epoch == epoch)
    {
        return Ok(Arbitrated {
            conflict: true,
            body: Json(v0::ResponseSubmitMlsCommit::Lost {
                winning: winning.into_commit_info(&group.channel_id),
            }),
        });
    }

    if !group.open {
        return Err(failed("group is closed"));
    }

    // AD binding (decision 2 (W2)): the AD parsed from the received commit
    // must be byte-identical to the stored newest list's `commit_ad`, and
    // the transaction then filters on the hash of THAT row. Never the
    // group's own `seat_list_ad_sha256`, which may already describe a newer
    // list than the row compared here.
    let received_ad = text::parse_commit_ad(&commit_ciphertext, &group.id, epoch)?;
    let stored = db
        .fetch_seat_list(&group.channel_id)
        .await?
        .ok_or_else(|| failed("channel has no seat list"))?;
    if received_ad != stored.commit_ad()? {
        return Err(resecuring("stale_seat_list"));
    }
    let ad_sha256 = stored.commit_ad_sha256()?;
    let signed = SeatListBody::parse(&stored.body)?;

    let config = revolt_config::config().await;
    let entitlement = db.fetch_channel_entitlement(&group.channel_id).await?;
    let entitlement_device_cap = match &entitlement {
        Some(entitlement) => {
            super::effective_device_cap(entitlement, &config.features.protected_channels)
        }
        // Only a commit without Adds goes on from here (refused below), and
        // the cap binds Adds only
        None => config.features.protected_channels.default_device_cap,
    };

    let committer = MlsMemberDevice {
        user_id: user.id.clone(),
        device_id: device_id.clone(),
    };
    let added: Vec<MlsMemberDevice> = added
        .into_iter()
        .map(|member| MlsMemberDevice {
            user_id: member.user_id,
            device_id: member.device_id,
        })
        .collect();
    let removed: Vec<MlsMemberDevice> = removed
        .into_iter()
        .map(|member| MlsMemberDevice {
            user_id: member.user_id,
            device_id: member.device_id,
        })
        .collect();

    // Growth is Adds only: Remove and Update commits go on with the flag
    // off (decision 5 (W2)). Adds also need an Active entitlement
    // (decision 7) and no pending removal (W0-fix3).
    if !added.is_empty() {
        super::require_text_gate(TextGate::Growth).await?;
        if !entitlement
            .as_ref()
            .is_some_and(|entitlement| entitlement.is_active())
        {
            return Err(create_error!(InvalidOperation));
        }
        if !group.pending_removals.is_empty() {
            return Err(resecuring("pending_removal"));
        }
    }

    let now = Timestamp::now_utc();
    // Advisory only (B48): stored on the row and fanned out, never read
    // for admission
    let removed_reasons = check_removals(db, &group, &signed, &committer, &removed, now).await?;

    if !added.is_empty() {
        for target in &added {
            check_add_target(db, &channel, target).await?;
        }

        let roster: Vec<&MlsMemberDevice> = group
            .members
            .iter()
            .filter(|member| !removed.contains(member))
            .chain(added.iter())
            .collect();
        if roster.len() > MAX_MLS_TEXT_GROUP_MEMBERS {
            return Err(create_error!(MlsCallFull {
                max: MAX_MLS_TEXT_GROUP_MEMBERS
            }));
        }

        let cap = mls_text_enforced_device_cap(signed.device_cap, entitlement_device_cap);
        if cap != 0
            && added.iter().any(|target| {
                roster
                    .iter()
                    .filter(|member| member.user_id == target.user_id)
                    .count()
                    > cap as usize
            })
        {
            return Err(create_error!(DeviceCapReached { max: cap as usize }));
        }
    }

    // Raw (decoded) size from the unpadded-base64 length
    let commit_raw_size = (commit_ciphertext.len() * 3) / 4;

    let commit = MlsCommit {
        id: MlsCommit::composite_id(&group.id, epoch),
        group_id: group.id.clone(),
        epoch,
        committer: committer.clone(),
        commit: commit_ciphertext,
        size: commit_raw_size as i64,
        added,
        removed,
        created_at: now,
        // Filled by the commit transaction from the stored intents
        rejoin_intents: vec![],
        removed_reasons,
    };

    match db
        .insert_mls_text_commit(&commit, &ad_sha256, entitlement_device_cap)
        .await?
    {
        MlsCommitOutcome::Lost { winning } => Ok(Arbitrated {
            conflict: true,
            body: Json(v0::ResponseSubmitMlsCommit::Lost {
                winning: winning.into_commit_info(&group.channel_id),
            }),
        }),
        MlsCommitOutcome::Won => {
            // The declarations come from the STORED row: the transaction
            // filled its `rejoin_intents`. Receivers treat a Text commit
            // envelope without them as a mismatch, so nothing goes out
            // without them; an error here sends the committer down the
            // outcome recovery (§2.5) and members gap-refetch.
            let stored_commit = db
                .fetch_mls_commits_from(&group.id, epoch, 1)
                .await?
                .into_iter()
                .find(|row| {
                    row.epoch == epoch && row.committer == committer && row.commit == commit.commit
                })
                .ok_or_else(|| create_error!(InternalError))?;
            let rejoin_intents: Vec<MlsEnvelopeRejoinIntent> = stored_commit
                .rejoin_intents
                .iter()
                .map(|intent| MlsEnvelopeRejoinIntent::from_join_intent(intent, &group.channel_id))
                .collect();

            let build =
                |recipient: &MlsMemberDevice, content_type: E2EEContentType, ciphertext: String| {
                    envelope(
                        &user,
                        &device_id,
                        &group.id,
                        epoch,
                        recipient,
                        content_type,
                        ciphertext,
                    )
                };

            let mut envelopes = Vec::new();

            // Commit envelopes go to the PRE-commit roster minus the
            // committer (removed devices included). The group read is that
            // roster when it was at `epoch - 1`. The transaction accepted
            // `epoch`, so a read at any other epoch raced the rows, and the
            // members gap-refetch instead of getting a guessed fan-out.
            if group.current_epoch + 1 == epoch {
                for recipient in group.members.iter().filter(|member| **member != committer) {
                    envelopes.push(E2EEEnvelope {
                        committer: Some(stored_commit.committer.clone()),
                        added: stored_commit.added.clone(),
                        removed: stored_commit.removed.clone(),
                        rejoin_intents: rejoin_intents.clone(),
                        removed_reasons: stored_commit.removed_reasons.clone(),
                        ..build(
                            recipient,
                            E2EEContentType::MlsCommit,
                            stored_commit.commit.clone(),
                        )
                    });
                }
            } else {
                log::warn!(
                    "text commit {}:{} won over a group read at epoch {}; commit fan-out skipped",
                    group.id,
                    epoch,
                    group.current_epoch
                );
            }

            // Welcomes carry no declarations (design §8.1)
            if let Some(welcome) = &welcome {
                for added in &stored_commit.added {
                    envelopes.push(build(added, E2EEContentType::MlsWelcome, welcome.clone()));
                }
            }

            deliver(db, envelopes).await?;

            Ok(Arbitrated {
                conflict: false,
                body: Json(v0::ResponseSubmitMlsCommit::Won),
            })
        }
    }
}

/// Rank of a Remove rule for the advisory `removed_reasons` (B48): the
/// strongest admitting rule is stamped, `pending_removal` > `off_list` >
/// `revoked` > `own_user` > `rejoin`
fn removal_priority(reason: MlsRemovalReason) -> u8 {
    match reason {
        MlsRemovalReason::PendingRemoval => 5,
        MlsRemovalReason::OffList => 4,
        MlsRemovalReason::Revoked => 3,
        MlsRemovalReason::OwnUser => 2,
        MlsRemovalReason::Rejoin => 1,
    }
}

/// The Remove rule (design §3.12.2), checked by the route on the group and
/// seat list it read; the commit transaction checks it again on its own
/// read. `signed` is the newest stored list, `now` the commit's time.
///
/// The current list signer's device may be removed only in the rejoin case.
/// Any other device may be removed when it belongs to the committer's own
/// user, its user is pending removal, its identity is revoked, its user is
/// off the list and the committer is the signer's device, or in the rejoin
/// case.
///
/// Returns one advisory reason per removed device, in `removed` order: the
/// strongest rule that admits it (B48). The reasons never change admission:
/// a device is admitted exactly when some rule admits it. Every rule but
/// rejoin is evaluated for every device. Rejoin is the weakest, so it can
/// never be the strongest when another rule admits; it is evaluated only
/// when none does, as before, so its intent read never runs, and never
/// fails, for a device another rule already admits. An identity read error
/// is no evidence of revocation: it refuses only when no other rule admits
/// the device, as before.
async fn check_removals(
    db: &Database,
    group: &MlsGroup,
    signed: &SeatListBody,
    committer: &MlsMemberDevice,
    removed: &[MlsMemberDevice],
    now: Timestamp,
) -> Result<Vec<MlsRemovedReason>> {
    if removed.is_empty() {
        return Ok(vec![]);
    }

    let committer_is_signer = committer.user_id == signed.signer_user_id
        && committer.device_id == signed.signer_device_id;
    let window_start = now
        .checked_sub(Duration::seconds(REJOIN_OUTSTANDING_WINDOW_SECONDS))
        .ok_or_else(|| failed("invalid commit time"))?;
    let mut intents: Option<Vec<MlsJoinIntent>> = None;
    let mut reasons = Vec::with_capacity(removed.len());

    for device in removed {
        if !group.has_member(&device.user_id, &device.device_id) {
            return Err(failed("removed device is not a member"));
        }

        if device == committer {
            return Err(failed("a device cannot remove itself"));
        }

        let is_signer_device =
            device.user_id == signed.signer_user_id && device.device_id == signed.signer_device_id;

        // Rules 2 to 5, all of them; none applies to the signer's device
        let mut admitting: Vec<MlsRemovalReason> = Vec::new();
        if !is_signer_device {
            if group.has_pending_removal(&device.user_id) {
                admitting.push(MlsRemovalReason::PendingRemoval);
            }
            if committer_is_signer && !signed.seats.iter().any(|seat| *seat == device.user_id) {
                admitting.push(MlsRemovalReason::OffList);
            }
            if device.user_id == committer.user_id {
                admitting.push(MlsRemovalReason::OwnUser);
            }

            // Revoked = no identity row; a read error is no evidence
            match db
                .fetch_e2ee_identity(&device.user_id, &device.device_id)
                .await
            {
                Ok(_) => {}
                Err(error) if matches!(error.error_type, ErrorType::NotFound) => {
                    admitting.push(MlsRemovalReason::Revoked)
                }
                Err(error) if admitting.is_empty() => return Err(error),
                Err(_) => {}
            }
        }

        if let Some(reason) = admitting
            .into_iter()
            .max_by_key(|reason| removal_priority(*reason))
        {
            reasons.push(MlsRemovedReason {
                user_id: device.user_id.clone(),
                device_id: device.device_id.clone(),
                reason,
            });
            continue;
        }

        // Rejoin case: a stored intent of this device, outstanding and
        // newer than the device's latest Add (no `member_added` entry =
        // refused, never "added at time zero")
        if intents.is_none() {
            intents = Some(db.fetch_mls_join_intents_for_group(&group.id).await?);
        }
        let intent_id = MlsJoinIntent::composite_id(&group.id, &device.user_id, &device.device_id);
        let added_at = group
            .member_added
            .iter()
            .find(|entry| entry.user_id == device.user_id && entry.device_id == device.device_id)
            .map(|entry| entry.at);
        let outstanding = intents.iter().flatten().any(|intent| {
            intent.id == intent_id
                && intent.group_id == group.id
                && intent.user_id == device.user_id
                && intent.device_id == device.device_id
                && added_at
                    .is_some_and(|at| intent.created_at >= window_start && intent.created_at > at)
        });
        if !outstanding {
            return Err(failed("removal not permitted"));
        }
        reasons.push(MlsRemovedReason {
            user_id: device.user_id.clone(),
            device_id: device.device_id.clone(),
            reason: MlsRemovalReason::Rejoin,
        });
    }

    Ok(reasons)
}

/// One ADDED device (design §6.1 "Commit with `added`", decision 7 (W2)): a
/// registered E2EE device (else `FailedValidation`) of a user who is not a
/// bot or staff, is a member of the channel's server, can view the channel
/// and holds an active seat (else `NotSeated`). The Call path's friend/DM
/// eligibility does not apply, and blocked pairs are not checked.
async fn check_add_target(
    db: &Database,
    channel: &Channel,
    target: &MlsMemberDevice,
) -> Result<()> {
    if db
        .fetch_e2ee_identity(&target.user_id, &target.device_id)
        .await
        .is_err()
    {
        return Err(failed("added device is not registered"));
    }

    let user = match db.fetch_user(&target.user_id).await {
        Ok(user) => user,
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => {
            return Err(create_error!(NotSeated))
        }
        Err(error) => return Err(error),
    };
    if user.bot.is_some() || user.privileged {
        return Err(create_error!(NotSeated));
    }

    let server_id = channel.server().ok_or_else(|| create_error!(NotSeated))?;
    match db.fetch_member(server_id, &user.id).await {
        Ok(_) => {}
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => {
            return Err(create_error!(NotSeated))
        }
        Err(error) => return Err(error),
    }

    if super::require_channel_access(db, &user, channel)
        .await
        .is_err()
    {
        return Err(create_error!(NotSeated));
    }

    super::require_seated(db, channel.id(), &user.id).await
}

/// An MLS envelope from the committing device, with no declarations (the
/// Text path sets them on its commit envelopes)
fn envelope(
    user: &User,
    device_id: &str,
    group_id: &str,
    epoch: i64,
    recipient: &MlsMemberDevice,
    content_type: E2EEContentType,
    ciphertext: String,
) -> E2EEEnvelope {
    E2EEEnvelope {
        id: Ulid::new().to_string(),
        recipient_user_id: recipient.user_id.clone(),
        recipient_device_id: recipient.device_id.clone(),
        // Sender stamped from the session, never from the payload
        sender_user_id: user.id.clone(),
        sender_device_id: device_id.to_string(),
        protocol_version: E2EE_PROTOCOL_VERSION,
        // MLS envelopes are ordered by (group_id, epoch), not by the olm
        // per-session sequence
        sequence: 0,
        ciphertext,
        timestamp: Timestamp::now_utc(),
        content_type,
        group_id: Some(group_id.to_string()),
        epoch: Some(epoch),
        committer: None,
        added: vec![],
        removed: vec![],
        rejoin_intents: vec![],
        removed_reasons: vec![],
    }
}

/// Queue the envelopes, then push them live
async fn deliver(db: &Database, envelopes: Vec<E2EEEnvelope>) -> Result<()> {
    // Per-device queue depth + BYTE budget (plan §2.2.4). A recipient over
    // budget is skipped, not failed: under-delivery is availability-only
    // and the gap-refetch path recovers it.
    let mut accepted = Vec::with_capacity(envelopes.len());
    for envelope in envelopes {
        let depth = db
            .count_e2ee_envelopes(&envelope.recipient_user_id, &envelope.recipient_device_id)
            .await?;
        let bytes = db
            .sum_e2ee_envelope_bytes(&envelope.recipient_user_id, &envelope.recipient_device_id)
            .await?;

        if depth >= MAX_QUEUE_DEPTH || bytes + envelope.ciphertext.len() as u64 > MAX_QUEUE_BYTES {
            log::debug!(
                "mls fan-out skipped for {}:{} (queue depth {depth}, bytes {bytes})",
                envelope.recipient_user_id,
                envelope.recipient_device_id
            );
            continue;
        }

        accepted.push(envelope);
    }

    // Queue first, then push live: an envelope is never push-only; clients
    // dedup the drain-vs-live-push race by envelope ULID
    db.insert_e2ee_envelopes(&accepted).await?;

    for envelope in accepted {
        let recipient_user_id = envelope.recipient_user_id.clone();
        let event = match envelope.content_type {
            E2EEContentType::MlsWelcome => EventV1::MlsWelcome(envelope.into()),
            _ => EventV1::MlsCommit(envelope.into()),
        };
        event.private(recipient_user_id).await;
    }

    Ok(())
}

fn failed(error: &str) -> revolt_result::Error {
    create_error!(FailedValidation {
        error: error.to_string()
    })
}

fn resecuring(reason: &str) -> revolt_result::Error {
    create_error!(ProtectedChannelResecuring {
        reason: reason.to_string()
    })
}

/// Text commit submission (protected-channels design §6.1, §2.5, §3.12.2,
/// W2 decisions 1, 2, 5 and 7). The route is called directly, so a bot is
/// a user with `bot` set and every refusal is the exact error a client
/// would get. Each flag case is its own `#[test]` (nextest: one process per
/// test, `overwrite_config` before the harness). The test config has every
/// flag on.
#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{
        Account, BotInformation, ChannelEntitlementState, Database, E2EEContentType, E2EEEnvelope,
        MemberCompositeKey, MlsCommit, MlsCommitOutcome, MlsEnvelopeRejoinIntent, MlsGroup,
        MlsGroupCreateOutcome, MlsGroupKind, MlsJoinIntent, MlsMemberDevice, MlsRemovalReason,
        MlsRemovedReason, PartialChannel, PartialMember, PartialUser, RelationshipStatus, SeatList,
        Session, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use revolt_result::{Error, ErrorType, Result};
    use rocket::{serde::json::Json, State};
    use ulid::Ulid;

    use super::super::{dispatch_group, require_channel_access, Arbitrated, GroupDispatch};
    use super::submit_commit;
    use crate::util::test::{
        ProtectedChannel, TestHarness, FIXTURE_DEVICE_CAP, MEMBER_DEVICE_SEED,
    };

    type Submitted = Result<Arbitrated<v0::ResponseSubmitMlsCommit>>;

    /// A user, one of their sessions and a device bound to it
    struct Party {
        user: User,
        session: Session,
        device_id: String,
    }

    impl Party {
        fn device(&self) -> v0::MlsMemberDevice {
            v0::MlsMemberDevice {
                user_id: self.user.id.clone(),
                device_id: self.device_id.clone(),
            }
        }
    }

    fn device_of(user: &User, device_id: &str) -> v0::MlsMemberDevice {
        v0::MlsMemberDevice {
            user_id: user.id.clone(),
            device_id: device_id.to_string(),
        }
    }

    struct Setup {
        harness: TestHarness,
        protected: ProtectedChannel,
        group_id: String,
        owner_account: Account,
        owner: Party,
        members: Vec<Party>,
    }

    impl Setup {
        fn db(&self) -> &Database {
            &self.harness.db
        }

        fn channel_id(&self) -> &str {
            self.protected.channel.id()
        }
    }

    /// A protected channel seating the owner and `count` members (each with
    /// a device bound to their session), and its generation-0 Text group,
    /// whose only member is the owner's device, the list signer
    async fn setup(count: usize) -> Setup {
        let harness = TestHarness::new().await;
        let (owner_account, owner_session, owner) = harness.new_user().await;
        let mut users = Vec::new();
        for _ in 0..count {
            let (_, session, user) = harness.new_user().await;
            users.push((user, session));
        }
        let seated: Vec<&User> = users.iter().map(|(user, _)| user).collect();
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &seated)
            .await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;

        let mut members = Vec::new();
        for (index, (user, session)) in users.into_iter().enumerate() {
            let device = harness
                .new_e2ee_device(&user, &session.id, MEMBER_DEVICE_SEED + index as u8)
                .await;
            members.push(Party {
                user,
                session,
                device_id: device.device_id,
            });
        }

        Setup {
            owner: Party {
                device_id: protected.owner_device.device_id.clone(),
                user: owner,
                session: owner_session,
            },
            harness,
            protected,
            group_id: group.id,
            owner_account,
            members,
        }
    }

    /// The route, called directly
    async fn submit(
        harness: &TestHarness,
        user: &User,
        session: &Session,
        group_id: &str,
        data: v0::DataSubmitMlsCommit,
    ) -> Submitted {
        let db = State::<Database>::get(harness.client.rocket()).expect("the managed `Database`");
        submit_commit(
            db,
            user.clone(),
            session.clone(),
            group_id.to_string(),
            Json(data),
        )
        .await
    }

    /// A Text commit framed as a client frames it (design §3.12.2): the MLS
    /// prefix for `group_id` at `epoch - 1`, the AD, then opaque bytes
    fn framed_commit(group_id: &str, epoch: i64, ad: &[u8]) -> String {
        let mut bytes = vec![0x00, 0x01, 0x00, 0x02, 0x20];
        for index in 0..32 {
            bytes.push(u8::from_str_radix(&group_id[index * 2..index * 2 + 2], 16).expect("hex"));
        }
        bytes.extend_from_slice(&((epoch - 1) as u64).to_be_bytes());
        bytes.push(0x03);
        if ad.len() < 0x40 {
            bytes.push(ad.len() as u8);
        } else {
            bytes.push(0x40 | (ad.len() >> 8) as u8);
            bytes.push((ad.len() & 0xff) as u8);
        }
        bytes.extend_from_slice(ad);
        bytes.extend_from_slice(b"opaque private message content");
        STANDARD_NO_PAD.encode(bytes)
    }

    /// The channel's newest stored seat list's commit AD
    async fn current_ad(harness: &TestHarness, channel_id: &str) -> Vec<u8> {
        harness
            .db
            .fetch_seat_list(channel_id)
            .await
            .expect("seat list read")
            .expect("a seat list")
            .commit_ad()
            .expect("commit ad")
    }

    fn request(
        device_id: &str,
        group_id: &str,
        epoch: i64,
        ad: &[u8],
        added: Vec<v0::MlsMemberDevice>,
        removed: Vec<v0::MlsMemberDevice>,
    ) -> v0::DataSubmitMlsCommit {
        v0::DataSubmitMlsCommit {
            device_id: device_id.to_string(),
            epoch,
            commit: framed_commit(group_id, epoch, ad),
            welcome: (!added.is_empty()).then(|| STANDARD_NO_PAD.encode(b"opaque welcome")),
            added,
            removed,
        }
    }

    /// `committer`'s commit for the group's next epoch with the current AD
    async fn commit_next(
        setup: &Setup,
        committer: &Party,
        added: Vec<v0::MlsMemberDevice>,
        removed: Vec<v0::MlsMemberDevice>,
    ) -> Submitted {
        let group = setup
            .db()
            .fetch_mls_group(&setup.group_id)
            .await
            .expect("the group");
        let ad = current_ad(&setup.harness, setup.channel_id()).await;
        submit(
            &setup.harness,
            &committer.user,
            &committer.session,
            &setup.group_id,
            request(
                &committer.device_id,
                &setup.group_id,
                group.current_epoch + 1,
                &ad,
                added,
                removed,
            ),
        )
        .await
    }

    #[track_caller]
    fn assert_won(result: Submitted, case: &str) {
        match result {
            Ok(Arbitrated {
                conflict: false,
                body,
            }) => assert!(
                matches!(body.into_inner(), v0::ResponseSubmitMlsCommit::Won),
                "{}",
                case
            ),
            Ok(Arbitrated { body, .. }) => panic!("{}: lost {:?}", case, body.into_inner()),
            Err(error) => panic!("{}: refused {:?}", case, error),
        }
    }

    #[track_caller]
    fn assert_lost(result: Submitted, case: &str) -> v0::MlsCommitInfo {
        match result {
            Ok(Arbitrated {
                conflict: true,
                body,
            }) => match body.into_inner() {
                v0::ResponseSubmitMlsCommit::Lost { winning } => winning,
                other => panic!("{}: a 409 without a winner {:?}", case, other),
            },
            Ok(Arbitrated { body, .. }) => panic!("{}: won {:?}", case, body.into_inner()),
            Err(error) => panic!("{}: refused {:?}", case, error),
        }
    }

    #[track_caller]
    fn refusal(result: Submitted, case: &str) -> Error {
        match result {
            Err(error) => error,
            Ok(Arbitrated { conflict, body }) => panic!(
                "{}: served (409: {}) {:?}",
                case,
                conflict,
                body.into_inner()
            ),
        }
    }

    /// A refusal the delta route raised itself, not the commit transaction
    /// in the database crate
    #[track_caller]
    fn assert_route_refusal(error: &Error, case: &str) {
        assert!(
            error.location.contains("delta/src/routes/mls/"),
            "{}: raised at {}: {:?}",
            case,
            error.location,
            error
        );
    }

    #[track_caller]
    fn assert_failed_validation(error: &Error, case: &str) {
        assert!(
            matches!(error.error_type, ErrorType::FailedValidation { .. }),
            "{}: {:?}",
            case,
            error
        );
    }

    #[track_caller]
    fn assert_not_seated(error: &Error, case: &str) {
        assert!(
            matches!(error.error_type, ErrorType::NotSeated),
            "{}: {:?}",
            case,
            error
        );
    }

    #[track_caller]
    fn assert_resecuring(error: &Error, reason: &str, case: &str) {
        match &error.error_type {
            ErrorType::ProtectedChannelResecuring { reason: actual } => {
                assert_eq!(actual, reason, "{}", case)
            }
            _ => panic!(
                "{}: expected ProtectedChannelResecuring {{ {} }}, got {:?}",
                case, reason, error
            ),
        }
    }

    #[track_caller]
    fn assert_disabled(error: &Error, feature: &str, case: &str) {
        match &error.error_type {
            ErrorType::FeatureDisabled { feature: actual } => {
                assert_eq!(actual, feature, "{}", case)
            }
            _ => panic!(
                "{}: expected FeatureDisabled {{ {} }}, got {:?}",
                case, feature, error
            ),
        }
    }

    /// The envelopes queued for a device, oldest first
    async fn envelopes_of(
        harness: &TestHarness,
        user_id: &str,
        device_id: &str,
    ) -> Vec<E2EEEnvelope> {
        harness
            .db
            .fetch_e2ee_envelopes(user_id, device_id, 100)
            .await
            .expect("envelopes")
    }

    fn member_device(user_id: &str, device_id: &str) -> MlsMemberDevice {
        MlsMemberDevice {
            user_id: user_id.to_string(),
            device_id: device_id.to_string(),
        }
    }

    /// Overwrite the group's `seat_list_ad_sha256`. The route meets this
    /// state only in a race (a seat PUT between its seat-list read and the
    /// commit transaction); written directly, the race is deterministic.
    async fn set_group_ad_hash(db: &Database, group_id: &str, hash: &str) {
        match db {
            Database::Reference(reference) => {
                reference
                    .mls_groups
                    .lock()
                    .await
                    .get_mut(group_id)
                    .expect("the group")
                    .seat_list_ad_sha256 = Some(hash.to_string());
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, Document};
                let result = mongo
                    .col::<Document>("mls_groups")
                    .update_one(
                        doc! { "_id": group_id },
                        doc! { "$set": { "seat_list_ad_sha256": hash } },
                    )
                    .await
                    .expect("write the group hash");
                assert_eq!(result.matched_count, 1);
            }
        }
    }

    /// Take ViewChannel from `user` alone (a role of theirs is denied it on
    /// the channel); the owner and every other member still view it
    async fn deny_view(setup: &Setup, user: &User) {
        let db = setup.db();
        let role = setup
            .harness
            .new_role(&setup.protected.server, 10, None)
            .await;
        db.update_member(
            &MemberCompositeKey {
                server: setup.protected.server.id.clone(),
                user: user.id.clone(),
            },
            &PartialMember {
                roles: Some(vec![role.id.clone()]),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("assign the role");
        let mut channel = db
            .fetch_channel(setup.channel_id())
            .await
            .expect("the channel");
        channel
            .update(
                db,
                PartialChannel {
                    role_permissions: Some(HashMap::from([(
                        role.id.clone(),
                        OverrideField {
                            a: 0,
                            d: ChannelPermission::ViewChannel as i64,
                        },
                    )])),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("deny view to the role");
        let channel = db
            .fetch_channel(setup.channel_id())
            .await
            .expect("the channel");
        assert!(require_channel_access(db, user, &channel).await.is_err());
        assert!(require_channel_access(db, &setup.owner.user, &channel)
            .await
            .is_ok());
    }

    /// Set the channel's entitlement state, or delete the entitlement
    /// (`None`). S1 has no primitive for either (states other than Active
    /// are S5), so the row is written directly.
    async fn set_entitlement(
        db: &Database,
        channel_id: &str,
        state: Option<ChannelEntitlementState>,
    ) {
        let expected = state.clone();
        match db {
            Database::Reference(reference) => {
                let mut entitlements = reference.channel_entitlements.lock().await;
                match state {
                    Some(state) => {
                        let mut found = 0;
                        for entitlement in entitlements
                            .values_mut()
                            .filter(|entitlement| entitlement.channel_id == channel_id)
                        {
                            entitlement.state = state.clone();
                            found += 1;
                        }
                        assert_eq!(found, 1);
                    }
                    None => {
                        entitlements.retain(|_, entitlement| entitlement.channel_id != channel_id)
                    }
                }
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, to_bson, Document};
                let collection = mongo.col::<Document>("channel_entitlements");
                match state {
                    Some(state) => {
                        let result = collection
                            .update_one(
                                doc! { "channel_id": channel_id },
                                doc! { "$set": { "state": to_bson(&state).expect("bson") } },
                            )
                            .await
                            .expect("write the entitlement state");
                        assert_eq!(result.matched_count, 1);
                    }
                    None => {
                        let result = collection
                            .delete_one(doc! { "channel_id": channel_id })
                            .await
                            .expect("delete the entitlement");
                        assert_eq!(result.deleted_count, 1);
                    }
                }
            }
        }
        let stored = db
            .fetch_channel_entitlement(channel_id)
            .await
            .expect("entitlement read");
        assert_eq!(stored.map(|entitlement| entitlement.state), expected);
    }

    // ---------------------------------------------------------------------
    // The oracle (decision 1 (W2), design §6.1 invariant)
    // ---------------------------------------------------------------------

    /// For every caller class (a seated member who cannot view the channel,
    /// a bot, a member whose session is bound to none of its devices) and
    /// for a valid and a malformed request, a Text group whose channel is
    /// hidden and one whose channel was deleted answer EXACTLY as an unknown
    /// group id: the same error body, `location` included. The owner commits
    /// epoch 1 first, so a caller who reached the existing-row check would
    /// get `Lost` instead.
    async fn hidden_and_deleted_text_groups_answer_as_unknown() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, bot_session, mut bot) = harness.new_user().await;
        let (_, unbound_session, unbound) = harness.new_user().await;

        // Every caller is seated: only ViewChannel keeps them out
        let hidden = harness
            .new_protected_channel(&owner, &owner_session, &[&member, &bot, &unbound])
            .await;
        bot.bot = Some(BotInformation {
            owner: owner.id.clone(),
        });
        let member_device = harness
            .new_e2ee_device(&member, &member_session.id, 0x41)
            .await;
        let unbound_device = harness
            .new_e2ee_device(&unbound, &Ulid::new().to_string(), 0x42)
            .await;
        let mut hidden_channel = hidden.channel.clone();
        hidden_channel
            .update(
                db,
                PartialChannel {
                    default_permissions: Some(OverrideField {
                        a: 0,
                        d: ChannelPermission::ViewChannel as i64,
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("deny view");
        let hidden_group = harness
            .new_text_group(&hidden.channel, &hidden.owner_device, 0, None)
            .await;
        let hidden_ad = current_ad(&harness, hidden.channel.id()).await;

        let (_, other_session, other_owner) = harness.new_user().await;
        let deleted = harness
            .new_protected_channel(&other_owner, &other_session, &[])
            .await;
        let deleted_group = harness
            .new_text_group(&deleted.channel, &deleted.owner_device, 0, None)
            .await;
        let deleted_ad = current_ad(&harness, deleted.channel.id()).await;
        db.delete_channel(&deleted.channel)
            .await
            .expect("delete the channel");
        assert!(db.fetch_channel(deleted.channel.id()).await.is_err());

        let unknown_group_id = format!("{:032x}{:032x}", Ulid::new().0, Ulid::new().0);
        let media = revolt_database::voice::media_e2ee_enabled().await;
        let e2ee = revolt_config::config().await.features.e2ee_enabled;

        // Both groups are stored Text groups, so the oracle compares a real
        // Text path with the unknown path
        for group_id in [&hidden_group.id, &deleted_group.id] {
            assert!(matches!(
                dispatch_group(db, group_id).await,
                Ok(GroupDispatch::Text(_))
            ));
        }
        let hidden_channel = db
            .fetch_channel(hidden.channel.id())
            .await
            .expect("the hidden channel");
        assert!(require_channel_access(db, &owner, &hidden_channel)
            .await
            .is_ok());

        // The owner (seated, a viewer, bound) is served
        let served = submit(
            &harness,
            &owner,
            &owner_session,
            &hidden_group.id,
            request(
                &hidden.owner_device.device_id,
                &hidden_group.id,
                1,
                &hidden_ad,
                vec![],
                vec![],
            ),
        )
        .await;
        if e2ee {
            assert_won(served, "the owner");
        } else {
            assert_disabled(&refusal(served, "the owner"), "e2ee", "the owner");
        }

        let callers = [
            (
                "member",
                &member,
                &member_session,
                member_device.device_id.clone(),
            ),
            ("bot", &bot, &bot_session, "ab".repeat(16)),
            (
                "unbound",
                &unbound,
                &unbound_session,
                unbound_device.device_id.clone(),
            ),
        ];
        for (class, user, session, device_id) in &callers {
            assert!(
                require_channel_access(db, user, &hidden_channel)
                    .await
                    .is_err(),
                "{} views the hidden channel",
                class
            );

            for malformed in [false, true] {
                let case = format!("{class}, malformed {malformed}");
                let body = |group_id: &str, ad: &[u8]| {
                    let mut data = request(device_id, group_id, 1, ad, vec![], vec![]);
                    if malformed {
                        data.device_id = "not a device".to_string();
                        data.epoch = 0;
                    }
                    data
                };

                let unknown = serde_json::to_string(&refusal(
                    submit(
                        &harness,
                        user,
                        session,
                        &unknown_group_id,
                        body(&unknown_group_id, &hidden_ad),
                    )
                    .await,
                    &format!("unknown, {case}"),
                ))
                .expect("an error body");

                // Each class gets its own answer, so the classes are real
                let value: serde_json::Value = serde_json::from_str(&unknown).expect("JSON");
                let expected = match (media, *class) {
                    (false, _) => "FeatureDisabled",
                    (true, "bot") => "IsBot",
                    (true, "unbound") => "NotAuthenticated",
                    (true, _) => "NotFound",
                };
                assert_eq!(value["type"], expected, "{case}: {unknown}");

                for (target, group_id, ad) in [
                    ("hidden", &hidden_group.id, &hidden_ad),
                    ("deleted", &deleted_group.id, &deleted_ad),
                ] {
                    let answer = serde_json::to_string(&refusal(
                        submit(&harness, user, session, group_id, body(group_id, ad)).await,
                        &format!("{target}, {case}"),
                    ))
                    .expect("an error body");
                    assert_eq!(answer, unknown, "{target}, {case}");
                }
            }
        }
    }

    #[test]
    fn hidden_and_deleted_text_groups_answer_as_unknown_with_every_flag_on() {
        crate::util::test::rt().block_on(hidden_and_deleted_text_groups_answer_as_unknown())
    }

    #[test]
    fn hidden_and_deleted_text_groups_answer_as_unknown_with_e2ee_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
            })
            .await;
            hidden_and_deleted_text_groups_answer_as_unknown().await
        })
    }

    #[test]
    fn hidden_and_deleted_text_groups_answer_as_unknown_with_growth_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            hidden_and_deleted_text_groups_answer_as_unknown().await
        })
    }

    #[test]
    fn hidden_and_deleted_text_groups_answer_as_unknown_with_media_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            hidden_and_deleted_text_groups_answer_as_unknown().await
        })
    }

    #[test]
    fn hidden_and_deleted_text_groups_answer_as_unknown_with_growth_and_media_off() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
                settings.features.media_e2ee_enabled = false;
            })
            .await;
            hidden_and_deleted_text_groups_answer_as_unknown().await
        })
    }

    // ---------------------------------------------------------------------
    // Access, the existing row, the AD binding
    // ---------------------------------------------------------------------

    /// §11, W0-fix7/8: an Add that won is resubmitted with the growth flag
    /// OFF. The resubmit gets its own row back (`Lost { winning: self }`),
    /// before the growth gate and the AD check, and still does after the
    /// seat list moved on (its AD is then stale).
    #[test]
    fn an_identical_resubmit_with_growth_off_gets_its_own_row() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.protected_channels.enabled = false;
            })
            .await;
            an_identical_resubmit_with_growth_off_gets_its_own_row_case().await
        })
    }

    async fn an_identical_resubmit_with_growth_off_gets_its_own_row_case() {
        let setup = setup(1).await;
        let db = setup.db();
        let member = &setup.members[0];
        let ad = current_ad(&setup.harness, setup.channel_id()).await;
        let add = || {
            request(
                &setup.owner.device_id,
                &setup.group_id,
                1,
                &ad,
                vec![member.device()],
                vec![],
            )
        };

        // The Add won while growth was on: stored through the commit
        // transaction, which reads no flag
        let won = add();
        let stored = db
            .fetch_seat_list(setup.channel_id())
            .await
            .expect("seat list read")
            .expect("a seat list");
        let outcome = db
            .insert_mls_text_commit(
                &MlsCommit {
                    id: MlsCommit::composite_id(&setup.group_id, 1),
                    group_id: setup.group_id.clone(),
                    epoch: 1,
                    committer: member_device(&setup.owner.user.id, &setup.owner.device_id),
                    commit: won.commit.clone(),
                    size: (won.commit.len() * 3 / 4) as i64,
                    added: vec![member_device(&member.user.id, &member.device_id)],
                    removed: vec![],
                    created_at: Timestamp::now_utc(),
                    rejoin_intents: vec![],
                    removed_reasons: vec![],
                },
                &stored.commit_ad_sha256().expect("hash"),
                FIXTURE_DEVICE_CAP,
            )
            .await
            .expect("the Add");
        assert!(matches!(outcome, MlsCommitOutcome::Won));

        let assert_own_row = |winning: v0::MlsCommitInfo, case: &str| {
            assert_eq!(winning.epoch, 1, "{case}");
            assert_eq!(winning.committer.user_id, setup.owner.user.id, "{case}");
            assert_eq!(winning.committer.device_id, setup.owner.device_id, "{case}");
            assert_eq!(winning.commit, won.commit, "{case}");
            assert_eq!(winning.added.len(), 1, "{case}");
        };

        let resubmit = submit(
            &setup.harness,
            &setup.owner.user,
            &setup.owner.session,
            &setup.group_id,
            add(),
        )
        .await;
        assert_own_row(
            assert_lost(resubmit, "identical resubmit"),
            "identical resubmit",
        );

        // The seat list moves on; the resubmit's AD is stale now
        setup
            .harness
            .put_seats_with_db(
                &setup.protected.channel,
                &setup.protected.owner_device.seat_list(
                    setup.channel_id(),
                    2,
                    FIXTURE_DEVICE_CAP,
                    &[&setup.owner.user.id, &member.user.id],
                ),
            )
            .await;
        assert_ne!(current_ad(&setup.harness, setup.channel_id()).await, ad);
        let resubmit = submit(
            &setup.harness,
            &setup.owner.user,
            &setup.owner.session,
            &setup.group_id,
            add(),
        )
        .await;
        assert_own_row(
            assert_lost(resubmit, "resubmit after the seat list moved"),
            "resubmit after the seat list moved",
        );

        // Non-vacuity: growth is really off for a NEW Add, while an Update
        // goes through
        let second = setup
            .harness
            .new_e2ee_device(&member.user, &Ulid::new().to_string(), 0x60)
            .await;
        let error = refusal(
            commit_next(
                &setup,
                &setup.owner,
                vec![device_of(&member.user, &second.device_id)],
                vec![],
            )
            .await,
            "a new Add",
        );
        assert_disabled(&error, "protected_channels", "a new Add");
        assert_won(
            commit_next(&setup, &setup.owner, vec![], vec![]).await,
            "an Update with growth off",
        );
    }

    /// W0-fix8: every caller who fails an access check gets that refusal and
    /// never the `Lost { winning }` body of the existing row; a seated
    /// viewer with a bound device gets the row
    #[test]
    fn access_runs_before_the_existing_row() {
        crate::util::test::rt().block_on(access_runs_before_the_existing_row_case())
    }

    async fn access_runs_before_the_existing_row_case() {
        let setup = setup(5).await;
        let ad = current_ad(&setup.harness, setup.channel_id()).await;
        let owner_commit = request(
            &setup.owner.device_id,
            &setup.group_id,
            1,
            &ad,
            vec![],
            vec![],
        );
        let winning_commit = owner_commit.commit.clone();
        assert_won(
            submit(
                &setup.harness,
                &setup.owner.user,
                &setup.owner.session,
                &setup.group_id,
                owner_commit,
            )
            .await,
            "the owner's epoch 1",
        );
        let at_epoch_one =
            |device_id: &str| request(device_id, &setup.group_id, 1, &ad, vec![], vec![]);

        // A seated viewer with a bound device is authorized: it gets the row
        let viewer = &setup.members[0];
        let winning = assert_lost(
            submit(
                &setup.harness,
                &viewer.user,
                &viewer.session,
                &setup.group_id,
                at_epoch_one(&viewer.device_id),
            )
            .await,
            "a seated viewer",
        );
        assert_eq!(winning.commit, winning_commit);

        // A bot
        let mut bot = setup.members[1].user.clone();
        bot.bot = Some(BotInformation {
            owner: setup.owner.user.id.clone(),
        });
        let error = refusal(
            submit(
                &setup.harness,
                &bot,
                &setup.members[1].session,
                &setup.group_id,
                at_epoch_one(&setup.members[1].device_id),
            )
            .await,
            "a bot",
        );
        assert!(matches!(error.error_type, ErrorType::IsBot), "{:?}", error);

        // A session bound to none of the caller's devices
        let unbound = &setup.members[2];
        let (_, other_session) = setup
            .harness
            .account_from_user(unbound.user.id.clone())
            .await;
        let error = refusal(
            submit(
                &setup.harness,
                &unbound.user,
                &other_session,
                &setup.group_id,
                at_epoch_one(&unbound.device_id),
            )
            .await,
            "an unbound session",
        );
        assert!(
            matches!(error.error_type, ErrorType::NotAuthenticated),
            "{:?}",
            error
        );

        // A session bound to one device, committing for another of the
        // caller's devices
        let switching = &setup.members[3];
        let other_device = setup
            .harness
            .new_e2ee_device(&switching.user, &Ulid::new().to_string(), 0x61)
            .await;
        let error = refusal(
            submit(
                &setup.harness,
                &switching.user,
                &switching.session,
                &setup.group_id,
                at_epoch_one(&other_device.device_id),
            )
            .await,
            "another device's commit",
        );
        assert!(
            matches!(error.error_type, ErrorType::NotAuthenticated),
            "{:?}",
            error
        );

        // A seated member who cannot view the channel answers as an unknown
        // group would
        let hidden = &setup.members[4];
        deny_view(&setup, &hidden.user).await;
        let error = refusal(
            submit(
                &setup.harness,
                &hidden.user,
                &hidden.session,
                &setup.group_id,
                at_epoch_one(&hidden.device_id),
            )
            .await,
            "a seated non-viewer",
        );
        assert!(
            matches!(error.error_type, ErrorType::NotFound),
            "{:?}",
            error
        );

        // A viewer who is not seated
        let (_, session, outsider) = setup.harness.new_user().await;
        setup
            .harness
            .join_server(&setup.protected.server, &outsider)
            .await;
        let outsider_device = setup
            .harness
            .new_e2ee_device(&outsider, &session.id, 0x62)
            .await;
        let error = refusal(
            submit(
                &setup.harness,
                &outsider,
                &session,
                &setup.group_id,
                at_epoch_one(&outsider_device.device_id),
            )
            .await,
            "an unseated viewer",
        );
        assert_not_seated(&error, "an unseated viewer");
    }

    /// Decision 2 (W2): a commit whose AD embeds an older list than the
    /// newest stored one is refused by the route's byte compare; the newest
    /// list's AD goes through. A prefix that does not frame this epoch is
    /// `FailedValidation`.
    #[test]
    fn a_stale_seat_list_is_refused() {
        crate::util::test::rt().block_on(a_stale_seat_list_is_refused_case())
    }

    async fn a_stale_seat_list_is_refused_case() {
        let setup = setup(1).await;
        let member = &setup.members[0];
        let old_ad = current_ad(&setup.harness, setup.channel_id()).await;
        setup
            .harness
            .put_seats_with_db(
                &setup.protected.channel,
                &setup.protected.owner_device.seat_list(
                    setup.channel_id(),
                    2,
                    FIXTURE_DEVICE_CAP,
                    &[&setup.owner.user.id, &member.user.id],
                ),
            )
            .await;
        let new_ad = current_ad(&setup.harness, setup.channel_id()).await;
        assert_ne!(old_ad, new_ad);

        let error = refusal(
            submit(
                &setup.harness,
                &setup.owner.user,
                &setup.owner.session,
                &setup.group_id,
                request(
                    &setup.owner.device_id,
                    &setup.group_id,
                    1,
                    &old_ad,
                    vec![],
                    vec![],
                ),
            )
            .await,
            "the old list",
        );
        assert_resecuring(&error, "stale_seat_list", "the old list");
        assert_route_refusal(&error, "the old list");

        let mut misframed = request(
            &setup.owner.device_id,
            &setup.group_id,
            1,
            &new_ad,
            vec![],
            vec![],
        );
        misframed.commit = framed_commit(&setup.group_id, 2, &new_ad);
        let error = refusal(
            submit(
                &setup.harness,
                &setup.owner.user,
                &setup.owner.session,
                &setup.group_id,
                misframed,
            )
            .await,
            "framed for another epoch",
        );
        assert_failed_validation(&error, "framed for another epoch");
        assert_route_refusal(&error, "framed for another epoch");

        assert_won(
            submit(
                &setup.harness,
                &setup.owner.user,
                &setup.owner.session,
                &setup.group_id,
                request(
                    &setup.owner.device_id,
                    &setup.group_id,
                    1,
                    &new_ad,
                    vec![],
                    vec![],
                ),
            )
            .await,
            "the newest list",
        );
    }

    /// Decision 2 (W2): the hash the transaction filters on is that of the
    /// seat-list ROW the route compared, never the group's own
    /// `seat_list_ad_sha256`. Here the group already names a newer list (a
    /// seat PUT that landed after the route read the row): the commit
    /// embedding the compared, older list must be refused by the
    /// transaction. Passing the group's hash would accept it.
    #[test]
    fn the_transaction_filters_on_the_compared_rows_hash() {
        crate::util::test::rt().block_on(the_transaction_filters_on_the_compared_rows_hash_case())
    }

    async fn the_transaction_filters_on_the_compared_rows_hash_case() {
        let setup = setup(0).await;
        let ad = current_ad(&setup.harness, setup.channel_id()).await;
        let next = setup.protected.owner_device.seat_list(
            setup.channel_id(),
            2,
            FIXTURE_DEVICE_CAP,
            &[&setup.owner.user.id],
        );
        let next_hash = SeatList {
            id: setup.channel_id().to_string(),
            version: 2,
            body: next.body,
            signer_user_id: setup.owner.user.id.clone(),
            signer_device_id: setup.owner.device_id.clone(),
            signature: next.signature,
            handovers: vec![],
            updated_at: Timestamp::now_utc(),
        }
        .commit_ad_sha256()
        .expect("hash");
        set_group_ad_hash(setup.db(), &setup.group_id, &next_hash).await;

        let error = refusal(
            submit(
                &setup.harness,
                &setup.owner.user,
                &setup.owner.session,
                &setup.group_id,
                request(
                    &setup.owner.device_id,
                    &setup.group_id,
                    1,
                    &ad,
                    vec![],
                    vec![],
                ),
            )
            .await,
            "the compared list after a racing PUT",
        );
        assert_resecuring(&error, "stale_seat_list", "the racing PUT");
        // The route's byte compare passed (the AD IS the stored row's); the
        // transaction refused
        assert!(
            error.location.contains("database"),
            "raised at {}",
            error.location
        );
    }

    // ---------------------------------------------------------------------
    // Add targets (decision 7 (W2))
    // ---------------------------------------------------------------------

    /// A friend of the committer who is not a member and not seated: the
    /// Call path's friend/DM eligibility does not apply to Text
    #[test]
    fn a_friend_only_add_target_is_not_seated() {
        crate::util::test::rt().block_on(a_friend_only_add_target_is_not_seated_case())
    }

    async fn a_friend_only_add_target_is_not_seated_case() {
        let setup = setup(1).await;
        let db = setup.db();
        let (_, session, friend) = setup.harness.new_user().await;
        let device = setup
            .harness
            .new_e2ee_device(&friend, &session.id, 0x63)
            .await;
        for (user, other) in [(&setup.owner.user, &friend), (&friend, &setup.owner.user)] {
            db.set_relationship(&user.id, &other.id, &RelationshipStatus::Friend, None)
                .await
                .expect("friends");
        }

        let error = refusal(
            commit_next(
                &setup,
                &setup.owner,
                vec![device_of(&friend, &device.device_id)],
                vec![],
            )
            .await,
            "a friend",
        );
        assert_not_seated(&error, "a friend");
        assert_route_refusal(&error, "a friend");

        assert_won(
            commit_next(
                &setup,
                &setup.owner,
                vec![setup.members[0].device()],
                vec![],
            )
            .await,
            "a seated member",
        );
    }

    /// A server member who can view the channel but holds no seat
    #[test]
    fn an_unseated_add_target_is_not_seated() {
        crate::util::test::rt().block_on(an_unseated_add_target_is_not_seated_case())
    }

    async fn an_unseated_add_target_is_not_seated_case() {
        let setup = setup(1).await;
        let (_, session, viewer) = setup.harness.new_user().await;
        setup
            .harness
            .join_server(&setup.protected.server, &viewer)
            .await;
        let device = setup
            .harness
            .new_e2ee_device(&viewer, &session.id, 0x63)
            .await;
        let channel = setup
            .db()
            .fetch_channel(setup.channel_id())
            .await
            .expect("the channel");
        assert!(require_channel_access(setup.db(), &viewer, &channel)
            .await
            .is_ok());

        let error = refusal(
            commit_next(
                &setup,
                &setup.owner,
                vec![device_of(&viewer, &device.device_id)],
                vec![],
            )
            .await,
            "an unseated viewer",
        );
        assert_not_seated(&error, "an unseated viewer");
        assert_route_refusal(&error, "an unseated viewer");

        assert_won(
            commit_next(
                &setup,
                &setup.owner,
                vec![setup.members[0].device()],
                vec![],
            )
            .await,
            "a seated member",
        );
    }

    /// A seated member flagged `privileged` (staff)
    #[test]
    fn a_privileged_add_target_is_not_seated() {
        crate::util::test::rt().block_on(a_privileged_add_target_is_not_seated_case())
    }

    async fn a_privileged_add_target_is_not_seated_case() {
        let setup = setup(2).await;
        let staff = &setup.members[0];
        setup
            .db()
            .update_user(
                &staff.user.id,
                &PartialUser {
                    privileged: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("make staff");

        let error = refusal(
            commit_next(&setup, &setup.owner, vec![staff.device()], vec![]).await,
            "staff",
        );
        assert_not_seated(&error, "staff");
        assert_route_refusal(&error, "staff");

        assert_won(
            commit_next(
                &setup,
                &setup.owner,
                vec![setup.members[1].device()],
                vec![],
            )
            .await,
            "a seated member",
        );
    }

    /// A seated member that is a bot
    #[test]
    fn a_bot_add_target_is_not_seated() {
        crate::util::test::rt().block_on(a_bot_add_target_is_not_seated_case())
    }

    async fn a_bot_add_target_is_not_seated_case() {
        let setup = setup(2).await;
        let bot = &setup.members[0];
        setup
            .db()
            .update_user(
                &bot.user.id,
                &PartialUser {
                    bot: Some(BotInformation {
                        owner: setup.owner.user.id.clone(),
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("make a bot");

        let error = refusal(
            commit_next(&setup, &setup.owner, vec![bot.device()], vec![]).await,
            "a bot",
        );
        assert_not_seated(&error, "a bot");
        assert_route_refusal(&error, "a bot");

        assert_won(
            commit_next(
                &setup,
                &setup.owner,
                vec![setup.members[1].device()],
                vec![],
            )
            .await,
            "a seated member",
        );
    }

    /// A seated user whose membership is gone while the seat stayed (a
    /// failed second release, decision 11)
    #[test]
    fn a_non_member_add_target_is_not_seated() {
        crate::util::test::rt().block_on(a_non_member_add_target_is_not_seated_case())
    }

    async fn a_non_member_add_target_is_not_seated_case() {
        let setup = setup(2).await;
        let db = setup.db();
        let gone = &setup.members[0];
        db.soft_delete_member(&MemberCompositeKey {
            server: setup.protected.server.id.clone(),
            user: gone.user.id.clone(),
        })
        .await
        .expect("drop the membership");
        assert!(db
            .fetch_channel_seats_for_user(&gone.user.id)
            .await
            .expect("seats")
            .iter()
            .any(|seat| seat.channel_id == setup.channel_id() && seat.is_active()));

        let error = refusal(
            commit_next(&setup, &setup.owner, vec![gone.device()], vec![]).await,
            "a non-member",
        );
        assert_not_seated(&error, "a non-member");
        assert_route_refusal(&error, "a non-member");

        assert_won(
            commit_next(
                &setup,
                &setup.owner,
                vec![setup.members[1].device()],
                vec![],
            )
            .await,
            "a seated member",
        );
    }

    /// A seated member who cannot view the channel
    #[test]
    fn an_add_target_without_view_is_not_seated() {
        crate::util::test::rt().block_on(an_add_target_without_view_is_not_seated_case())
    }

    async fn an_add_target_without_view_is_not_seated_case() {
        let setup = setup(2).await;
        let hidden = &setup.members[0];
        deny_view(&setup, &hidden.user).await;

        let error = refusal(
            commit_next(&setup, &setup.owner, vec![hidden.device()], vec![]).await,
            "a non-viewer",
        );
        assert_not_seated(&error, "a non-viewer");
        assert_route_refusal(&error, "a non-viewer");

        assert_won(
            commit_next(
                &setup,
                &setup.owner,
                vec![setup.members[1].device()],
                vec![],
            )
            .await,
            "a seated member",
        );
    }

    /// An added device with no E2EE identity is `FailedValidation`
    #[test]
    fn an_unregistered_add_target_fails_validation() {
        crate::util::test::rt().block_on(an_unregistered_add_target_fails_validation_case())
    }

    async fn an_unregistered_add_target_fails_validation_case() {
        let setup = setup(1).await;
        let member = &setup.members[0];

        let error = refusal(
            commit_next(
                &setup,
                &setup.owner,
                vec![device_of(&member.user, &"cd".repeat(16))],
                vec![],
            )
            .await,
            "an unregistered device",
        );
        assert_failed_validation(&error, "an unregistered device");
        assert_route_refusal(&error, "an unregistered device");

        assert_won(
            commit_next(&setup, &setup.owner, vec![member.device()], vec![]).await,
            "the registered device",
        );
    }

    /// The enforced cap is `min(signed, effective entitlement cap)`: with the
    /// signed list unlimited (0) and the entitlement on the configured
    /// default (5), a user's sixth device is `DeviceCapReached { max: 5 }`
    #[test]
    fn the_sixth_device_is_refused_at_the_default_cap() {
        crate::util::test::rt().block_on(the_sixth_device_is_refused_at_the_default_cap_case())
    }

    async fn the_sixth_device_is_refused_at_the_default_cap_case() {
        let setup = setup(1).await;
        let member = &setup.members[0];
        assert_eq!(setup.protected.entitlement.device_cap, None);
        assert_eq!(
            revolt_config::config()
                .await
                .features
                .protected_channels
                .default_device_cap,
            5
        );
        setup
            .harness
            .put_seats_with_db(
                &setup.protected.channel,
                &setup.protected.owner_device.seat_list(
                    setup.channel_id(),
                    2,
                    0,
                    &[&setup.owner.user.id, &member.user.id],
                ),
            )
            .await;

        let mut devices = vec![member.device()];
        for seed in 0x60..0x65u8 {
            let device = setup
                .harness
                .new_e2ee_device(&member.user, &Ulid::new().to_string(), seed)
                .await;
            devices.push(device_of(&member.user, &device.device_id));
        }
        assert_eq!(devices.len(), 6);
        let sixth = devices.pop().expect("six devices");

        assert_won(
            commit_next(&setup, &setup.owner, devices, vec![]).await,
            "five devices",
        );
        let error = refusal(
            commit_next(&setup, &setup.owner, vec![sixth], vec![]).await,
            "the sixth device",
        );
        assert!(
            matches!(error.error_type, ErrorType::DeviceCapReached { max: 5 }),
            "{:?}",
            error
        );
        assert_route_refusal(&error, "the sixth device");
    }

    /// A Text group holds at most 100 leaves: the 101st is
    /// `MlsCallFull { max: 100 }` (both device caps unlimited here)
    #[test]
    fn the_hundred_and_first_leaf_is_refused() {
        crate::util::test::rt().block_on(the_hundred_and_first_leaf_is_refused_case())
    }

    async fn the_hundred_and_first_leaf_is_refused_case() {
        let setup = setup(1).await;
        let member = &setup.members[0];
        setup
            .harness
            .grant_entitlement(&setup.protected.channel, 10, Some(0))
            .await;
        setup
            .harness
            .put_seats_with_db(
                &setup.protected.channel,
                &setup.protected.owner_device.seat_list(
                    setup.channel_id(),
                    2,
                    0,
                    &[&setup.owner.user.id, &member.user.id],
                ),
            )
            .await;

        let mut devices = Vec::new();
        for seed in 0x80..0xE3u8 {
            let device = setup
                .harness
                .new_e2ee_device(&member.user, &Ulid::new().to_string(), seed)
                .await;
            devices.push(device_of(&member.user, &device.device_id));
        }
        assert_eq!(devices.len(), 99);
        assert_won(
            commit_next(&setup, &setup.owner, devices, vec![]).await,
            "the 100th leaf",
        );
        assert_eq!(
            setup
                .db()
                .fetch_mls_group(&setup.group_id)
                .await
                .expect("the group")
                .members
                .len(),
            100
        );

        let error = refusal(
            commit_next(&setup, &setup.owner, vec![member.device()], vec![]).await,
            "the 101st leaf",
        );
        assert!(
            matches!(error.error_type, ErrorType::MlsCallFull { max: 100 }),
            "{:?}",
            error
        );
        assert_route_refusal(&error, "the 101st leaf");
    }

    /// Decision 7 (W2): without an Active entitlement Adds are
    /// `InvalidOperation`; Remove and Update commits still go through
    #[test]
    fn adds_need_an_active_entitlement() {
        crate::util::test::rt().block_on(adds_need_an_active_entitlement_case())
    }

    async fn adds_need_an_active_entitlement_case() {
        let setup = setup(3).await;
        let db = setup.db();
        assert_won(
            commit_next(
                &setup,
                &setup.owner,
                vec![setup.members[0].device(), setup.members[1].device()],
                vec![],
            )
            .await,
            "two Adds",
        );

        for (case, state) in [
            (
                "a frozen entitlement",
                Some(ChannelEntitlementState::Frozen),
            ),
            ("no entitlement", None),
        ] {
            set_entitlement(db, setup.channel_id(), state).await;

            let error = refusal(
                commit_next(
                    &setup,
                    &setup.owner,
                    vec![setup.members[2].device()],
                    vec![],
                )
                .await,
                case,
            );
            assert!(
                matches!(error.error_type, ErrorType::InvalidOperation),
                "{}: {:?}",
                case,
                error
            );
            assert_route_refusal(&error, case);
            assert_won(
                commit_next(&setup, &setup.owner, vec![], vec![]).await,
                &format!("an Update, {case}"),
            );
        }

        // A Remove (a revoked device, rule 4) without an entitlement
        let revoked = &setup.members[1];
        assert!(db
            .delete_e2ee_device(&revoked.user.id, &revoked.device_id)
            .await
            .expect("revoke"));
        assert_won(
            commit_next(&setup, &setup.owner, vec![], vec![revoked.device()]).await,
            "a Remove without an entitlement",
        );
    }

    // ---------------------------------------------------------------------
    // The Remove rule (design §3.12.2), route side
    // ---------------------------------------------------------------------

    /// The current list signer's device goes only in the rejoin case, even
    /// by another device of the owner (which rule 2 would otherwise allow);
    /// the intent then rides on the commit envelope and is consumed
    #[test]
    fn the_signer_device_goes_only_on_its_rejoin_intent() {
        crate::util::test::rt().block_on(the_signer_device_goes_only_on_its_rejoin_intent_case())
    }

    async fn the_signer_device_goes_only_on_its_rejoin_intent_case() {
        let setup = setup(0).await;
        let db = setup.db();
        let second_session = setup
            .owner_account
            .create_session(db, String::new())
            .await
            .expect("a second session");
        let second = setup
            .harness
            .new_e2ee_device(&setup.owner.user, &second_session.id, 0x50)
            .await;
        let second = Party {
            user: setup.owner.user.clone(),
            session: second_session,
            device_id: second.device_id,
        };
        assert_won(
            commit_next(&setup, &setup.owner, vec![second.device()], vec![]).await,
            "the owner's second device",
        );

        let error = refusal(
            commit_next(&setup, &second, vec![], vec![setup.owner.device()]).await,
            "the signer device without an intent",
        );
        assert_failed_validation(&error, "the signer device without an intent");
        assert_route_refusal(&error, "the signer device without an intent");

        let intent = MlsJoinIntent {
            id: MlsJoinIntent::composite_id(
                &setup.group_id,
                &setup.owner.user.id,
                &setup.owner.device_id,
            ),
            group_id: setup.group_id.clone(),
            user_id: setup.owner.user.id.clone(),
            device_id: setup.owner.device_id.clone(),
            key_package_ref: "rejoin-key-package".to_string(),
            signature: "rejoin-signature".to_string(),
            created_at: Timestamp::now_utc(),
        };
        db.upsert_mls_join_intent(&intent)
            .await
            .expect("the rejoin intent");
        assert_won(
            commit_next(&setup, &second, vec![], vec![setup.owner.device()]).await,
            "the signer device on its rejoin intent",
        );
        assert!(db
            .fetch_mls_join_intents_for_group(&setup.group_id)
            .await
            .expect("intents")
            .is_empty());

        // The removed device gets the commit that removes it, with the
        // declarations and the consumed intent
        let envelopes =
            envelopes_of(&setup.harness, &setup.owner.user.id, &setup.owner.device_id).await;
        let commit = envelopes
            .iter()
            .find(|envelope| {
                envelope.content_type == E2EEContentType::MlsCommit && envelope.epoch == Some(2)
            })
            .expect("the commit envelope");
        assert_eq!(
            commit.committer,
            Some(member_device(&setup.owner.user.id, &second.device_id))
        );
        assert!(commit.added.is_empty());
        assert_eq!(
            commit.removed,
            vec![member_device(&setup.owner.user.id, &setup.owner.device_id)]
        );
        assert_eq!(
            commit.rejoin_intents,
            vec![MlsEnvelopeRejoinIntent {
                group_id: setup.group_id.clone(),
                channel_id: setup.channel_id().to_string(),
                user_id: setup.owner.user.id.clone(),
                device_id: setup.owner.device_id.clone(),
                key_package_ref: intent.key_package_ref.clone(),
                signature: intent.signature.clone(),
            }]
        );
    }

    /// Rules 2 (the committer's own other device), 3 (a pending-removal
    /// user, by a non-signer) and 4 (a revoked device)
    #[test]
    fn permitted_removals_go_through() {
        crate::util::test::rt().block_on(permitted_removals_go_through_case())
    }

    async fn permitted_removals_go_through_case() {
        let setup = setup(3).await;
        let db = setup.db();
        let committer = &setup.members[0];
        let own_other = setup
            .harness
            .new_e2ee_device(&committer.user, &Ulid::new().to_string(), 0x60)
            .await;
        let pending = &setup.members[1];
        let revoked = &setup.members[2];
        assert_won(
            commit_next(
                &setup,
                &setup.owner,
                vec![
                    committer.device(),
                    device_of(&committer.user, &own_other.device_id),
                    pending.device(),
                    revoked.device(),
                ],
                vec![],
            )
            .await,
            "four Adds",
        );

        // Rule 2
        assert_won(
            commit_next(
                &setup,
                committer,
                vec![],
                vec![device_of(&committer.user, &own_other.device_id)],
            )
            .await,
            "the committer's own other device",
        );

        // Rule 3: the owner unseats a user who still has a device
        setup
            .harness
            .put_seats_with_db(
                &setup.protected.channel,
                &setup.protected.owner_device.seat_list(
                    setup.channel_id(),
                    2,
                    FIXTURE_DEVICE_CAP,
                    &[&setup.owner.user.id, &committer.user.id, &revoked.user.id],
                ),
            )
            .await;
        assert!(db
            .fetch_mls_group(&setup.group_id)
            .await
            .expect("the group")
            .has_pending_removal(&pending.user.id));
        assert_won(
            commit_next(&setup, committer, vec![], vec![pending.device()]).await,
            "a pending-removal user, by a non-signer",
        );

        // Rule 4
        assert!(db
            .delete_e2ee_device(&revoked.user.id, &revoked.device_id)
            .await
            .expect("revoke"));
        assert_won(
            commit_next(&setup, committer, vec![], vec![revoked.device()]).await,
            "a revoked device",
        );
    }

    /// Removals no rule allows are refused by the route: a seated member's
    /// live device by another member or by the signer, a rejoin intent older
    /// than the device's latest Add, the committer itself, a non-member
    /// device. A fresh intent then allows the removal.
    #[test]
    fn forbidden_removals_are_refused_by_the_route() {
        crate::util::test::rt().block_on(forbidden_removals_are_refused_by_the_route_case())
    }

    async fn forbidden_removals_are_refused_by_the_route_case() {
        let setup = setup(2).await;
        let db = setup.db();
        let committer = &setup.members[0];
        let target = &setup.members[1];
        let before_add = Timestamp::now_utc()
            .checked_sub(Duration::seconds(5))
            .expect("a time");
        assert_won(
            commit_next(
                &setup,
                &setup.owner,
                vec![committer.device(), target.device()],
                vec![],
            )
            .await,
            "two Adds",
        );

        let refused = |error: Error, case: &str| {
            assert_failed_validation(&error, case);
            assert_route_refusal(&error, case);
        };

        refused(
            refusal(
                commit_next(&setup, committer, vec![], vec![target.device()]).await,
                "a member's device by another member",
            ),
            "a member's device by another member",
        );
        refused(
            refusal(
                commit_next(&setup, &setup.owner, vec![], vec![target.device()]).await,
                "a seated member's device by the signer",
            ),
            "a seated member's device by the signer",
        );

        let intent = |created_at: Timestamp| MlsJoinIntent {
            id: MlsJoinIntent::composite_id(&setup.group_id, &target.user.id, &target.device_id),
            group_id: setup.group_id.clone(),
            user_id: target.user.id.clone(),
            device_id: target.device_id.clone(),
            key_package_ref: "rejoin-key-package".to_string(),
            signature: "rejoin-signature".to_string(),
            created_at,
        };
        db.upsert_mls_join_intent(&intent(before_add))
            .await
            .expect("an intent from before the Add");
        refused(
            refusal(
                commit_next(&setup, committer, vec![], vec![target.device()]).await,
                "an intent older than the Add",
            ),
            "an intent older than the Add",
        );

        refused(
            refusal(
                commit_next(&setup, committer, vec![], vec![committer.device()]).await,
                "the committer itself",
            ),
            "the committer itself",
        );
        refused(
            refusal(
                commit_next(
                    &setup,
                    committer,
                    vec![],
                    vec![device_of(&target.user, &"ef".repeat(16))],
                )
                .await,
                "a device that is not a member",
            ),
            "a device that is not a member",
        );

        db.upsert_mls_join_intent(&intent(Timestamp::now_utc()))
            .await
            .expect("a fresh intent");
        assert_won(
            commit_next(&setup, committer, vec![], vec![target.device()]).await,
            "a fresh rejoin intent",
        );
    }

    // ---------------------------------------------------------------------
    // Advisory `removed_reasons` (B48)
    // ---------------------------------------------------------------------

    fn removed_reason(party: &Party, reason: MlsRemovalReason) -> MlsRemovedReason {
        MlsRemovedReason {
            user_id: party.user.id.clone(),
            device_id: party.device_id.clone(),
            reason,
        }
    }

    /// The stored commit row at `epoch`
    async fn stored_commit(setup: &Setup, epoch: i64) -> MlsCommit {
        setup
            .db()
            .fetch_mls_commits_from(&setup.group_id, epoch, 1)
            .await
            .expect("commit read")
            .into_iter()
            .find(|row| row.epoch == epoch)
            .expect("the stored commit")
    }

    /// The commit envelope at `epoch` queued for `recipient`
    async fn commit_envelope(setup: &Setup, recipient: &Party, epoch: i64) -> E2EEEnvelope {
        envelopes_of(&setup.harness, &recipient.user.id, &recipient.device_id)
            .await
            .into_iter()
            .find(|envelope| {
                envelope.content_type == E2EEContentType::MlsCommit && envelope.epoch == Some(epoch)
            })
            .expect("the commit envelope")
    }

    /// `committer` removes `removed`; the stored row and the commit envelope
    /// to `witness` carry exactly `expected`
    async fn assert_removal_stamped(
        setup: &Setup,
        committer: &Party,
        witness: &Party,
        removed: &Party,
        expected: MlsRemovalReason,
        case: &str,
    ) {
        let epoch = setup
            .db()
            .fetch_mls_group(&setup.group_id)
            .await
            .expect("the group")
            .current_epoch
            + 1;
        assert_won(
            commit_next(setup, committer, vec![], vec![removed.device()]).await,
            case,
        );
        let want = vec![removed_reason(removed, expected)];
        assert_eq!(
            stored_commit(setup, epoch).await.removed_reasons,
            want,
            "{}: row",
            case
        );
        assert_eq!(
            commit_envelope(setup, witness, epoch).await.removed_reasons,
            want,
            "{}: envelope",
            case
        );
    }

    /// Drop every pending removal of the group, leaving a user off the
    /// newest list without one (only rule 5 then applies to them). No route
    /// reaches that state; written directly
    async fn clear_pending_removals(db: &Database, group_id: &str) {
        match db {
            Database::Reference(reference) => {
                reference
                    .mls_groups
                    .lock()
                    .await
                    .get_mut(group_id)
                    .expect("the group")
                    .pending_removals
                    .clear();
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, Document};
                let result = mongo
                    .col::<Document>("mls_groups")
                    .update_one(
                        doc! { "_id": group_id },
                        doc! { "$set": { "pending_removals": [] } },
                    )
                    .await
                    .expect("clear the pending removals");
                assert_eq!(result.matched_count, 1);
            }
        }
        assert!(db
            .fetch_mls_group(group_id)
            .await
            .expect("the group")
            .pending_removals
            .is_empty());
    }

    /// B48: each Remove rule, alone, stamps its own reason on the stored row
    /// and on the commit envelope; the 409 body serves it snake_case
    #[test]
    fn every_removal_reason_is_stamped() {
        crate::util::test::rt().block_on(every_removal_reason_is_stamped_case())
    }

    async fn every_removal_reason_is_stamped_case() {
        let setup = setup(5).await;
        let db = setup.db();
        let owner = &setup.owner;
        let committer = &setup.members[0];
        let own_other = setup
            .harness
            .new_e2ee_device(&committer.user, &Ulid::new().to_string(), 0x61)
            .await;
        let own_other = Party {
            user: committer.user.clone(),
            session: committer.session.clone(),
            device_id: own_other.device_id,
        };
        let pending = &setup.members[1];
        let revoked = &setup.members[2];
        let rejoining = &setup.members[3];
        let off_list = &setup.members[4];
        assert_won(
            commit_next(
                &setup,
                owner,
                vec![
                    committer.device(),
                    own_other.device(),
                    pending.device(),
                    revoked.device(),
                    rejoining.device(),
                    off_list.device(),
                ],
                vec![],
            )
            .await,
            "six Adds",
        );

        // Rule 2 alone: the identity is live, the user seated
        assert_removal_stamped(
            &setup,
            committer,
            owner,
            &own_other,
            MlsRemovalReason::OwnUser,
            "own_user",
        )
        .await;

        // Rule 3 alone: unseated by the owner, removed by a non-signer. The
        // same list also takes `off_list` off it (its pending entry is
        // cleared below)
        setup
            .harness
            .put_seats_with_db(
                &setup.protected.channel,
                &setup.protected.owner_device.seat_list(
                    setup.channel_id(),
                    2,
                    FIXTURE_DEVICE_CAP,
                    &[
                        &owner.user.id,
                        &committer.user.id,
                        &revoked.user.id,
                        &rejoining.user.id,
                    ],
                ),
            )
            .await;
        assert_removal_stamped(
            &setup,
            committer,
            owner,
            pending,
            MlsRemovalReason::PendingRemoval,
            "pending_removal",
        )
        .await;

        // Rule 4 alone: a seated user's revoked device, by a non-signer
        assert!(db
            .delete_e2ee_device(&revoked.user.id, &revoked.device_id)
            .await
            .expect("revoke"));
        assert_removal_stamped(
            &setup,
            committer,
            owner,
            revoked,
            MlsRemovalReason::Revoked,
            "revoked",
        )
        .await;

        // Rule 6 alone: a seated user's live device on its fresh intent
        db.upsert_mls_join_intent(&MlsJoinIntent {
            id: MlsJoinIntent::composite_id(
                &setup.group_id,
                &rejoining.user.id,
                &rejoining.device_id,
            ),
            group_id: setup.group_id.clone(),
            user_id: rejoining.user.id.clone(),
            device_id: rejoining.device_id.clone(),
            key_package_ref: "rejoin-key-package".to_string(),
            signature: "rejoin-signature".to_string(),
            created_at: Timestamp::now_utc(),
        })
        .await
        .expect("the rejoin intent");
        assert_removal_stamped(
            &setup,
            committer,
            owner,
            rejoining,
            MlsRemovalReason::Rejoin,
            "rejoin",
        )
        .await;

        // Rule 5 alone: off the list with no pending entry, removed by the
        // signer's device
        clear_pending_removals(db, &setup.group_id).await;
        assert_removal_stamped(
            &setup,
            owner,
            committer,
            off_list,
            MlsRemovalReason::OffList,
            "off_list",
        )
        .await;

        // The 409 body carries the winner's reasons, snake_case
        let group = db
            .fetch_mls_group(&setup.group_id)
            .await
            .expect("the group");
        let ad = current_ad(&setup.harness, setup.channel_id()).await;
        let winning = assert_lost(
            submit(
                &setup.harness,
                &committer.user,
                &committer.session,
                &setup.group_id,
                request(
                    &committer.device_id,
                    &setup.group_id,
                    group.current_epoch,
                    &ad,
                    vec![],
                    vec![],
                ),
            )
            .await,
            "a commit at the off_list epoch",
        );
        let wire = serde_json::to_value(&winning).expect("JSON");
        assert_eq!(
            wire["removed_reasons"],
            serde_json::json!([{
                "user_id": off_list.user.id,
                "device_id": off_list.device_id,
                "reason": "off_list"
            }])
        );
    }

    /// B48: when several rules admit one device the strongest is stamped,
    /// `pending_removal` > `off_list` > `revoked` > `own_user` > `rejoin`.
    /// Admission is unchanged: every one of these commits wins
    #[test]
    fn the_strongest_admitting_rule_is_stamped() {
        crate::util::test::rt().block_on(the_strongest_admitting_rule_is_stamped_case())
    }

    async fn the_strongest_admitting_rule_is_stamped_case() {
        let setup = setup(4).await;
        let db = setup.db();
        let owner = &setup.owner;
        let committer = &setup.members[0];
        let own_other = setup
            .harness
            .new_e2ee_device(&committer.user, &Ulid::new().to_string(), 0x62)
            .await;
        let own_other = Party {
            user: committer.user.clone(),
            session: committer.session.clone(),
            device_id: own_other.device_id,
        };
        let pending_revoked = &setup.members[1];
        let pending_off_list = &setup.members[2];
        let off_list_revoked = &setup.members[3];
        assert_won(
            commit_next(
                &setup,
                owner,
                vec![
                    committer.device(),
                    own_other.device(),
                    pending_revoked.device(),
                    pending_off_list.device(),
                    off_list_revoked.device(),
                ],
                vec![],
            )
            .await,
            "five Adds",
        );

        // revoked + own_user: the committer's own revoked device
        assert!(db
            .delete_e2ee_device(&committer.user.id, &own_other.device_id)
            .await
            .expect("revoke"));
        assert_removal_stamped(
            &setup,
            committer,
            owner,
            &own_other,
            MlsRemovalReason::Revoked,
            "revoked over own_user",
        )
        .await;

        // Two users unseated: both pending removal
        setup
            .harness
            .put_seats_with_db(
                &setup.protected.channel,
                &setup.protected.owner_device.seat_list(
                    setup.channel_id(),
                    2,
                    FIXTURE_DEVICE_CAP,
                    &[
                        &owner.user.id,
                        &committer.user.id,
                        &off_list_revoked.user.id,
                    ],
                ),
            )
            .await;

        // pending_removal + revoked, by a non-signer
        assert!(db
            .delete_e2ee_device(&pending_revoked.user.id, &pending_revoked.device_id)
            .await
            .expect("revoke"));
        assert_removal_stamped(
            &setup,
            committer,
            owner,
            pending_revoked,
            MlsRemovalReason::PendingRemoval,
            "pending_removal over revoked",
        )
        .await;

        // pending_removal + off_list, by the signer's device
        assert_removal_stamped(
            &setup,
            owner,
            committer,
            pending_off_list,
            MlsRemovalReason::PendingRemoval,
            "pending_removal over off_list",
        )
        .await;

        // off_list + revoked, by the signer's device, no pending entry
        setup
            .harness
            .put_seats_with_db(
                &setup.protected.channel,
                &setup.protected.owner_device.seat_list(
                    setup.channel_id(),
                    3,
                    FIXTURE_DEVICE_CAP,
                    &[&owner.user.id, &committer.user.id],
                ),
            )
            .await;
        clear_pending_removals(db, &setup.group_id).await;
        assert!(db
            .delete_e2ee_device(&off_list_revoked.user.id, &off_list_revoked.device_id)
            .await
            .expect("revoke"));
        assert_removal_stamped(
            &setup,
            owner,
            committer,
            off_list_revoked,
            MlsRemovalReason::OffList,
            "off_list over revoked",
        )
        .await;
    }

    /// B48: a Call commit never carries `removed_reasons`, even with a
    /// Remove: not on the stored row, not on its envelopes, not on the wire
    /// of the 409 body
    #[test]
    fn call_commits_carry_no_removed_reasons() {
        crate::util::test::rt().block_on(call_commits_carry_no_removed_reasons_case())
    }

    async fn call_commits_carry_no_removed_reasons_case() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, session_a, user_a) = harness.new_user().await;
        let (_, session_b, user_b) = harness.new_user().await;
        let (_, session_c, user_c) = harness.new_user().await;
        let (server, channel) = harness.new_protectable_channel(&user_a).await;
        harness.join_server(&server, &user_b).await;
        harness.join_server(&server, &user_c).await;
        let device_a = harness.new_e2ee_device(&user_a, &session_a.id, 0x72).await;
        let device_b = harness.new_e2ee_device(&user_b, &session_b.id, 0x73).await;
        let device_c = harness.new_e2ee_device(&user_c, &session_c.id, 0x74).await;
        let leaf_b = member_device(&user_b.id, &device_b.device_id);
        let members = vec![
            member_device(&user_a.id, &device_a.device_id),
            leaf_b.clone(),
            member_device(&user_c.id, &device_c.device_id),
        ];
        let group = MlsGroup {
            id: format!("{:032x}{:032x}", Ulid::new().0, Ulid::new().0),
            channel_id: channel.id().to_string(),
            open: true,
            created_by: members[0].clone(),
            created_at: Timestamp::now_utc(),
            current_epoch: 0,
            members,
            closed_at: None,
            superseded_by: None,
            kind: MlsGroupKind::Call,
            generation: None,
            seat_list_ad_sha256: None,
            pending_removals: vec![],
            member_added: vec![],
        };
        assert!(matches!(
            db.create_mls_group(&group, None).await.expect("call group"),
            MlsGroupCreateOutcome::Created
        ));

        let call_commit =
            |device_id: &str, removed: Vec<v0::MlsMemberDevice>| v0::DataSubmitMlsCommit {
                device_id: device_id.to_string(),
                epoch: 1,
                commit: STANDARD_NO_PAD.encode(format!("opaque call commit {device_id}")),
                welcome: None,
                added: vec![],
                removed,
            };
        assert_won(
            submit(
                &harness,
                &user_a,
                &session_a,
                &group.id,
                call_commit(
                    &device_a.device_id,
                    vec![device_of(&user_b, &device_b.device_id)],
                ),
            )
            .await,
            "a Call commit removing B",
        );

        let stored = db
            .fetch_mls_commits_from(&group.id, 1, 1)
            .await
            .expect("commit read");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].removed, vec![leaf_b]);
        assert!(stored[0].removed_reasons.is_empty(), "{:?}", stored[0]);

        for (user, device) in [(&user_b, &device_b), (&user_c, &device_c)] {
            let envelopes = envelopes_of(&harness, &user.id, &device.device_id).await;
            assert_eq!(envelopes.len(), 1);
            assert!(
                envelopes[0].removed_reasons.is_empty(),
                "{:?}",
                envelopes[0]
            );
        }

        let winning = assert_lost(
            submit(
                &harness,
                &user_c,
                &session_c,
                &group.id,
                call_commit(&device_c.device_id, vec![]),
            )
            .await,
            "a racing Call commit",
        );
        assert_eq!(winning.removed.len(), 1);
        assert!(winning.removed_reasons.is_empty());
        let wire = serde_json::to_value(&winning).expect("JSON");
        assert!(wire.get("removed_reasons").is_none(), "{}", wire);
    }

    // ---------------------------------------------------------------------
    // Envelopes
    // ---------------------------------------------------------------------

    /// Text commit envelopes carry the declarations from the stored row;
    /// Welcomes carry none; the committer gets nothing
    #[test]
    fn text_commit_envelopes_carry_the_declarations() {
        crate::util::test::rt().block_on(text_commit_envelopes_carry_the_declarations_case())
    }

    async fn text_commit_envelopes_carry_the_declarations_case() {
        let setup = setup(2).await;
        let first = &setup.members[0];
        let second = &setup.members[1];
        let no_declarations = |envelope: &E2EEEnvelope| {
            envelope.committer.is_none()
                && envelope.added.is_empty()
                && envelope.removed.is_empty()
                && envelope.rejoin_intents.is_empty()
        };

        assert_won(
            commit_next(&setup, &setup.owner, vec![first.device()], vec![]).await,
            "the first Add",
        );
        let envelopes = envelopes_of(&setup.harness, &first.user.id, &first.device_id).await;
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].content_type, E2EEContentType::MlsWelcome);
        assert!(no_declarations(&envelopes[0]), "{:?}", envelopes[0]);

        assert_won(
            commit_next(&setup, &setup.owner, vec![second.device()], vec![]).await,
            "the second Add",
        );
        let envelopes = envelopes_of(&setup.harness, &first.user.id, &first.device_id).await;
        let commit = envelopes
            .iter()
            .find(|envelope| envelope.content_type == E2EEContentType::MlsCommit)
            .expect("the commit envelope");
        assert_eq!(commit.epoch, Some(2));
        assert_eq!(commit.group_id.as_deref(), Some(setup.group_id.as_str()));
        assert_eq!(commit.sender_user_id, setup.owner.user.id);
        assert_eq!(commit.sender_device_id, setup.owner.device_id);
        assert_eq!(
            commit.committer,
            Some(member_device(&setup.owner.user.id, &setup.owner.device_id))
        );
        assert_eq!(
            commit.added,
            vec![member_device(&second.user.id, &second.device_id)]
        );
        assert!(commit.removed.is_empty());
        assert!(commit.rejoin_intents.is_empty());

        let envelopes = envelopes_of(&setup.harness, &second.user.id, &second.device_id).await;
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].content_type, E2EEContentType::MlsWelcome);
        assert!(no_declarations(&envelopes[0]), "{:?}", envelopes[0]);

        assert!(
            envelopes_of(&setup.harness, &setup.owner.user.id, &setup.owner.device_id)
                .await
                .is_empty()
        );
    }

    /// The Call path keeps its envelopes: no declarations on a Call commit
    #[test]
    fn call_commit_envelopes_carry_no_declarations() {
        crate::util::test::rt().block_on(call_commit_envelopes_carry_no_declarations_case())
    }

    async fn call_commit_envelopes_carry_no_declarations_case() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, session_a, user_a) = harness.new_user().await;
        let (_, session_b, user_b) = harness.new_user().await;
        let (server, channel) = harness.new_protectable_channel(&user_a).await;
        harness.join_server(&server, &user_b).await;
        let device_a = harness.new_e2ee_device(&user_a, &session_a.id, 0x70).await;
        let device_b = harness.new_e2ee_device(&user_b, &session_b.id, 0x71).await;
        let members = vec![
            member_device(&user_a.id, &device_a.device_id),
            member_device(&user_b.id, &device_b.device_id),
        ];
        let group = MlsGroup {
            id: format!("{:032x}{:032x}", Ulid::new().0, Ulid::new().0),
            channel_id: channel.id().to_string(),
            open: true,
            created_by: members[0].clone(),
            created_at: Timestamp::now_utc(),
            current_epoch: 0,
            members,
            closed_at: None,
            superseded_by: None,
            kind: MlsGroupKind::Call,
            generation: None,
            seat_list_ad_sha256: None,
            pending_removals: vec![],
            member_added: vec![],
        };
        assert!(matches!(
            db.create_mls_group(&group, None).await.expect("call group"),
            MlsGroupCreateOutcome::Created
        ));
        assert!(matches!(
            dispatch_group(db, &group.id).await,
            Ok(GroupDispatch::CallOrUnknown(Some(_)))
        ));

        assert_won(
            submit(
                &harness,
                &user_a,
                &session_a,
                &group.id,
                v0::DataSubmitMlsCommit {
                    device_id: device_a.device_id.clone(),
                    epoch: 1,
                    commit: STANDARD_NO_PAD.encode(b"opaque call commit"),
                    welcome: None,
                    added: vec![],
                    removed: vec![],
                },
            )
            .await,
            "a Call commit",
        );

        let envelopes = envelopes_of(&harness, &user_b.id, &device_b.device_id).await;
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].content_type, E2EEContentType::MlsCommit);
        assert!(envelopes[0].committer.is_none());
        assert!(envelopes[0].added.is_empty());
        assert!(envelopes[0].removed.is_empty());
        assert!(envelopes[0].rejoin_intents.is_empty());
    }
}
