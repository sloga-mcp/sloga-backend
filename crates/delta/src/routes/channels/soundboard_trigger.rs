use revolt_database::{
    events::client::EventV1,
    util::{permissions::perms, reference::Reference},
    voice::{is_in_voice_channel, UserVoiceChannel},
    Database, User,
};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};

use rocket::State;
use rocket_empty::EmptyResponse;

/// # Trigger Soundboard Sound
///
/// Play a server soundboard sound in a voice call. Carries no audio — the
/// server fans a `SoundboardSound` event to the voice-channel topic and each
/// client already in the call plays the clip locally. The caller must be a
/// current participant of the call and hold `UseSoundboard` + `Connect`.
#[openapi(tag = "Soundboard")]
#[post("/<target>/soundboard/<sound_id>")]
pub async fn trigger_sound(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    sound_id: String,
) -> Result<EmptyResponse> {
    let channel = target.as_channel(db).await?;

    if channel.voice().is_none() {
        return Err(create_error!(NotAVoiceChannel));
    }

    // The sound must belong to THIS channel's server (a group/DM voice call
    // has no server → no soundboard). Fetch first so a non-existent or
    // cross-server sound is refused before any fan-out.
    let sound = db.fetch_soundboard_sound(&sound_id).await?;
    if channel.server() != Some(sound.server_id.as_str()) {
        return Err(create_error!(NotFound));
    }

    let mut query = perms(db, &user).channel(&channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::Connect)?;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::UseSoundboard)?;

    // Only a current call participant may trigger — a lurker with ViewChannel
    // (who still receives the channel-topic event) cannot blast the call.
    let user_voice_channel = UserVoiceChannel::from_channel(&channel);
    if !is_in_voice_channel(&user.id, &user_voice_channel).await? {
        return Err(create_error!(NotInVoiceChannel));
    }

    EventV1::SoundboardSound {
        id: sound.id,
        channel_id: channel.id().to_string(),
        server_id: sound.server_id,
        emoji: sound.emoji,
    }
    .p(channel.id().to_string())
    .await;

    Ok(EmptyResponse)
}
