//! Live call captions — server relay.
//!
//! Replaces the original design, in which a speaker broadcast captions over a
//! LiveKit data channel. That never worked and could not: the voice join token
//! is minted with `can_publish_data: false` (`voice/voice_client.rs`), so the
//! SFU silently discarded every caption packet — `publishData()` resolves
//! without error on the sender and nothing arrives at the peer. Only the
//! speaker's own local self-mirror rendered, which is why one-person tests
//! looked green for months.
//!
//! Flipping that grant was the wrong fix: `can_publish_data` is what stops any
//! speaker injecting arbitrary data packets at every other participant, and
//! E2EE slice 6.1 already closed a regrant-on-permission-sync hole in it
//! (`permission_sync_never_regrants_data_publishing`). So captions take the
//! soundboard shape instead — REST validates, the server fans an event — with
//! one deliberate divergence noted on the fan-out below.

use revolt_database::{
    events::client::EventV1,
    util::{permissions::perms, reference::Reference},
    voice::{
        get_voice_channel_members, get_voice_participant_identity, is_in_voice_channel,
        UserVoiceChannel,
    },
    Database, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use validator::Validate;

use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;

/// Display cap the client renders captions at (`liveCaptions.ts`
/// MAX_CAPTION_CHARS). Clamped here too so an over-length line is truncated
/// rather than dropped, and so the fan-out payload is bounded regardless of
/// what the sender claims.
const MAX_CAPTION_CHARS: usize = 240;

/// Truncate on a character boundary — `text` is arbitrary UTF-8 and a byte
/// slice would panic mid-codepoint on the first non-ASCII caption.
fn clamp_caption(text: &str) -> String {
    text.chars().take(MAX_CAPTION_CHARS).collect()
}

/// # Send Live Caption
///
/// Relay one finalized caption line to the other participants of a voice call.
/// The caller must be a current participant holding `Connect` + `Speak`.
/// Nothing is stored: the server validates, fans a `CallCaption` event to the
/// call's members, and forgets it.
#[openapi(tag = "Voice")]
#[post("/<target>/captions", data = "<data>")]
pub async fn send_caption(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataSendCaption>,
) -> Result<EmptyResponse> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let channel = target.as_channel(db).await?;

    if channel.voice().is_none() {
        return Err(create_error!(NotAVoiceChannel));
    }

    let mut query = perms(db, &user).channel(&channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::Connect)?;
    // Speak, not just Connect: a caption is a transcript of speech, so anyone
    // barred from speaking has nothing legitimate to caption. This also stops
    // a listen-only participant putting words on a tile.
    permissions.throw_if_lacking_channel_permission(ChannelPermission::Speak)?;

    let voice_channel = UserVoiceChannel::from_channel(&channel);
    if !is_in_voice_channel(&user.id, &voice_channel).await? {
        return Err(create_error!(NotInVoiceChannel));
    }

    let text = clamp_caption(&data.text);
    // `min = 1` validation passes on whitespace; an all-blank line would clear
    // nothing and cost a fan-out.
    if text.trim().is_empty() {
        return Ok(EmptyResponse);
    }

    // The identity the SFU knows this speaker by — device-qualified on an
    // E2EE-capable call. Resolved SERVER-side, never taken from the request:
    // the client keys caption overlays by identity, so a caller-supplied one
    // would let anyone paint a caption onto another participant's tile.
    let identity = get_voice_participant_identity(channel.id(), &user.id).await?;

    let Some(members) = get_voice_channel_members(&voice_channel).await? else {
        return Ok(EmptyResponse);
    };

    // DIVERGENCE FROM THE SOUNDBOARD PATTERN, deliberate: soundboard uses
    // `.p(channel_id)`, whose authorization boundary is ViewChannel. A caption
    // is speech, so that would hand a live transcript of the call to every
    // text-channel lurker who never joined it. Fan to the CALL's members over
    // their private topics instead (the remote-control offer/decline shape).
    //
    // The speaker is skipped: their own client already renders its recognizer
    // output locally the moment it finalizes, so echoing it back would only
    // re-set an identical entry and reset its linger timer.
    for member_id in members {
        if member_id == user.id {
            continue;
        }

        EventV1::CallCaption {
            channel_id: channel.id().to_string(),
            identity: identity.clone(),
            user_id: user.id.clone(),
            text: text.clone(),
            lang: data.lang.clone(),
        }
        .private(member_id)
        .await;
    }

    Ok(EmptyResponse)
}
