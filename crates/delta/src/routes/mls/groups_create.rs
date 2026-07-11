use iso8601_timestamp::Timestamp;
use revolt_database::{
    is_valid_device_id, is_valid_group_id,
    util::reference::Reference,
    voice::{get_voice_state, UserVoiceChannel},
    Database, MlsGroup, MlsGroupCreateOutcome, MlsMemberDevice, Session, User,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

use super::Arbitrated;

/// # Create MLS Group
///
/// Register a per-call MLS group (epoch 0, creator only) for a channel the
/// caller can access and whose call they are in.
///
/// **Create-race arbitration is channel-scoped (plan §1.2):** at most one
/// OPEN group exists per channel; a racing second creator receives **409**
/// with the existing open group id and falls into the join path for THAT
/// group. `supersedes` runs the poisoned-epoch successor flow (plan §1.4):
/// the named group is atomically closed and this one registered in its
/// place.
#[openapi(tag = "MLS")]
#[post("/groups", data = "<data>")]
pub async fn create_group(
    db: &State<Database>,
    user: User,
    session: Session,
    data: Json<v0::DataCreateMlsGroup>,
) -> Result<Arbitrated<v0::ResponseCreateMlsGroup>> {
    super::require_media_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let data = data.into_inner();

    if !is_valid_group_id(&data.group_id) {
        return Err(create_error!(FailedValidation {
            error: "invalid group id".to_string()
        }));
    }

    if let Some(supersedes) = &data.supersedes {
        if !is_valid_group_id(supersedes) {
            return Err(create_error!(FailedValidation {
                error: "invalid superseded group id".to_string()
            }));
        }
        if supersedes == &data.group_id {
            return Err(create_error!(FailedValidation {
                error: "a group cannot supersede itself".to_string()
            }));
        }
    }

    if !is_valid_device_id(&data.device_id) {
        return Err(create_error!(FailedValidation {
            error: "device_id must be 128 bits of lowercase hex".to_string()
        }));
    }

    // The creating session must be bound to a registered device
    let identity = db
        .fetch_e2ee_identity(&user.id, &data.device_id)
        .await
        .map_err(|_| {
            create_error!(FailedValidation {
                error: "creating device is not registered".to_string()
            })
        })?;
    identity.assert_bound_session(&session.id)?;

    // Channel authorization: existing permission machinery (plan §1.2)
    let channel = Reference::from_unchecked(&data.channel_id)
        .as_channel(db)
        .await?;
    super::require_channel_access(db, &user, &channel).await?;

    if channel.voice().is_none() {
        return Err(create_error!(NotAVoiceChannel));
    }

    // The creator must actually be in the channel's call. Voice presence
    // lives in Redis and is only populated when a LiveKit backend is
    // configured — without one (unit tests / voice-less deployments) there
    // is no call to be in, so the check is vacuous and skipped.
    if !revolt_config::config().await.api.livekit.nodes.is_empty() {
        let user_voice_channel = UserVoiceChannel::from_channel(&channel);
        if get_voice_state(&user_voice_channel, &user.id)
            .await?
            .is_none()
        {
            return Err(create_error!(NotConnected));
        }
    }

    let group = MlsGroup {
        id: data.group_id,
        channel_id: channel.id().to_string(),
        open: true,
        created_by: MlsMemberDevice {
            user_id: user.id.clone(),
            device_id: data.device_id.clone(),
        },
        created_at: Timestamp::now_utc(),
        current_epoch: 0,
        members: vec![MlsMemberDevice {
            user_id: user.id.clone(),
            device_id: data.device_id,
        }],
        closed_at: None,
        superseded_by: None,
    };

    match db.create_mls_group(&group, data.supersedes.as_deref()).await? {
        MlsGroupCreateOutcome::Created => Ok(Arbitrated {
            conflict: false,
            body: Json(v0::ResponseCreateMlsGroup::Created),
        }),
        MlsGroupCreateOutcome::Conflict { open_group_id } => Ok(Arbitrated {
            conflict: true,
            body: Json(v0::ResponseCreateMlsGroup::Conflict { open_group_id }),
        }),
    }
}
