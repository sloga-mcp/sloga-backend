use std::collections::HashSet;

use iso8601_timestamp::Timestamp;
use revolt_database::{
    events::client::EventV1, is_valid_device_id, Database, E2EEContentType, E2EEEnvelope,
    MlsCommit, MlsCommitOutcome, MlsMemberDevice, Session, User, E2EE_PROTOCOL_VERSION,
    MAX_MLS_GROUP_MEMBERS,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use ulid::Ulid;

use crate::routes::e2ee::{require_e2ee_deliver_eligible, MAX_QUEUE_BYTES, MAX_QUEUE_DEPTH};

use super::{encoded_len, Arbitrated, MAX_MLS_COMMIT_RAW_SIZE, MAX_MLS_WELCOME_RAW_SIZE};

fn commit_info(commit: MlsCommit) -> v0::MlsCommitInfo {
    v0::MlsCommitInfo {
        group_id: commit.group_id,
        epoch: commit.epoch,
        committer: v0::MlsMemberDevice {
            user_id: commit.committer.user_id,
            device_id: commit.committer.device_id,
        },
        commit: commit.commit,
        added: commit
            .added
            .into_iter()
            .map(|member| v0::MlsMemberDevice {
                user_id: member.user_id,
                device_id: member.device_id,
            })
            .collect(),
        removed: commit
            .removed
            .into_iter()
            .map(|member| v0::MlsMemberDevice {
                user_id: member.user_id,
                device_id: member.device_id,
            })
            .collect(),
    }
}

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
#[openapi(tag = "MLS")]
#[post("/groups/<group_id>/commits", data = "<data>")]
pub async fn submit_commit(
    db: &State<Database>,
    user: User,
    session: Session,
    group_id: String,
    data: Json<v0::DataSubmitMlsCommit>,
) -> Result<Arbitrated<v0::ResponseSubmitMlsCommit>> {
    super::require_media_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let v0::DataSubmitMlsCommit {
        device_id,
        epoch,
        commit: commit_ciphertext,
        welcome,
        added,
        removed,
    } = data.into_inner();

    if !is_valid_device_id(&device_id) {
        return Err(create_error!(FailedValidation {
            error: "device_id must be 128 bits of lowercase hex".to_string()
        }));
    }

    if epoch < 1 {
        return Err(create_error!(FailedValidation {
            error: "epoch must be at least 1".to_string()
        }));
    }

    // Per-content_type size caps (plan §2.2.4) — stated raw, enforced on
    // the encoded field
    if commit_ciphertext.is_empty() || commit_ciphertext.len() > encoded_len(MAX_MLS_COMMIT_RAW_SIZE) {
        return Err(create_error!(PayloadTooLarge));
    }

    match (&welcome, added.is_empty()) {
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

    if added.len() > MAX_MLS_GROUP_MEMBERS || removed.len() > MAX_MLS_GROUP_MEMBERS {
        return Err(create_error!(FailedValidation {
            error: "fan-out list too large".to_string()
        }));
    }

    let mut seen = HashSet::new();
    for member in added.iter().chain(removed.iter()) {
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
    };

    // The CAS — one winner per epoch; membership, epoch monotonicity, the
    // one-device-per-user rule and the roster ceiling are enforced inside
    // (per driver, under its atomicity primitive)
    match db.insert_mls_commit(&commit).await? {
        MlsCommitOutcome::Lost { winning } => Ok(Arbitrated {
            conflict: true,
            body: Json(v0::ResponseSubmitMlsCommit::Lost {
                winning: commit_info(winning),
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

            let build = |recipient: &MlsMemberDevice,
                         content_type: E2EEContentType,
                         ciphertext: String| {
                E2EEEnvelope {
                    id: Ulid::new().to_string(),
                    recipient_user_id: recipient.user_id.clone(),
                    recipient_device_id: recipient.device_id.clone(),
                    // Sender stamped from the session, never from the payload
                    sender_user_id: user.id.clone(),
                    sender_device_id: device_id.clone(),
                    protocol_version: E2EE_PROTOCOL_VERSION,
                    // MLS envelopes are ordered by (group_id, epoch), not by
                    // the olm per-session sequence
                    sequence: 0,
                    ciphertext,
                    timestamp: Timestamp::now_utc(),
                    content_type,
                    group_id: Some(group.id.clone()),
                    epoch: Some(epoch),
                }
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

            // Per-device queue depth + BYTE budget (plan §2.2.4). A
            // recipient over budget is skipped, not failed: under-delivery
            // is availability-only and the gap-refetch path recovers it.
            let mut accepted = Vec::with_capacity(envelopes.len());
            for envelope in envelopes {
                let depth = db
                    .count_e2ee_envelopes(
                        &envelope.recipient_user_id,
                        &envelope.recipient_device_id,
                    )
                    .await?;
                let bytes = db
                    .sum_e2ee_envelope_bytes(
                        &envelope.recipient_user_id,
                        &envelope.recipient_device_id,
                    )
                    .await?;

                if depth >= MAX_QUEUE_DEPTH
                    || bytes + envelope.ciphertext.len() as u64 > MAX_QUEUE_BYTES
                {
                    log::debug!(
                        "mls fan-out skipped for {}:{} (queue depth {depth}, bytes {bytes})",
                        envelope.recipient_user_id,
                        envelope.recipient_device_id
                    );
                    continue;
                }

                accepted.push(envelope);
            }

            // Queue first, then push live: an envelope is never push-only;
            // clients dedup the drain-vs-live-push race by envelope ULID
            db.insert_e2ee_envelopes(&accepted).await?;

            for envelope in accepted {
                let recipient_user_id = envelope.recipient_user_id.clone();
                let event = match envelope.content_type {
                    E2EEContentType::MlsWelcome => EventV1::MlsWelcome(envelope.into()),
                    _ => EventV1::MlsCommit(envelope.into()),
                };
                event.private(recipient_user_id).await;
            }

            Ok(Arbitrated {
                conflict: false,
                body: Json(v0::ResponseSubmitMlsCommit::Won),
            })
        }
    }
}
