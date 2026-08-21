use crate::{
    models::{Channel, User},
    voice::RoomMetadata,
    Database,
};
use livekit_api::{
    access_token::{AccessToken, VideoGrants},
    services::room::{CreateRoomOptions, RoomClient as InnerRoomClient, UpdateParticipantOptions},
};
use livekit_protocol::{ParticipantInfo, ParticipantPermission, Room, TrackSource};
use revolt_config::{config, LiveKitNode};
use revolt_permissions::{ChannelPermission, PermissionValue};
use revolt_result::{create_error, Result, ToRevoltError};
use std::{collections::HashMap, time::Duration};

use super::{get_allowed_sources, track_source_grant_name};

#[derive(Debug)]
pub struct RoomClient {
    pub client: InnerRoomClient,
    pub node: LiveKitNode,
}

#[derive(Debug)]
pub struct VoiceClient {
    pub rooms: HashMap<String, RoomClient>,
}

impl VoiceClient {
    pub fn new(nodes: HashMap<String, LiveKitNode>) -> Self {
        Self {
            rooms: nodes
                .into_iter()
                .map(|(name, node)| {
                    (
                        name,
                        RoomClient {
                            client: InnerRoomClient::with_api_key(
                                &node.url,
                                &node.key,
                                &node.secret,
                            ),
                            node,
                        },
                    )
                })
                .collect(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        !self.rooms.is_empty()
    }

    pub async fn from_revolt_config() -> Self {
        let config = config().await;

        Self::new(config.api.livekit.nodes.clone())
    }

    pub fn get_node(&self, name: &str) -> Result<&RoomClient> {
        self.rooms
            .get(name)
            .ok_or_else(|| create_error!(UnknownNode))
    }

    pub async fn create_token(
        &self,
        node: &str,
        db: &Database,
        user: &User,
        permissions: PermissionValue,
        channel: &Channel,
        device_id: Option<&str>,
    ) -> Result<String> {
        let room = self.get_node(node)?;

        let limits = user.limits().await;
        let allowed_sources = get_allowed_sources(&limits, permissions);

        // Device-qualified identity (media E2EE, plan Q4): per-device frame
        // keys require an injective identity → (user, device) mapping, and
        // distinct identities stop the SFU kicking a user's first device the
        // moment a second one connects (the one-device-per-call rule is
        // enforced at the MLS delivery service instead).
        let identity = match device_id {
            Some(device_id) => format!("{}:{}", user.id, device_id),
            None => user.id.clone(),
        };

        AccessToken::with_api_key(&room.node.key, &room.node.secret)
            .with_name(&format!("{}#{}", user.username, user.discriminator))
            .with_identity(&identity)
            .with_metadata(
                &serde_json::to_string(&user.clone().into(db, None).await).to_internal_error()?,
            )
            .with_ttl(Duration::from_secs(10))
            .with_grants(VideoGrants {
                room_join: true,
                // An EMPTY canPublishSources claim means "no restriction" to
                // LiveKit (auth/grants.go), so a source-less member (Connect
                // without Speak/Video) must be denied publishing outright
                can_publish: !allowed_sources.is_empty(),
                can_publish_data: false,
                can_publish_sources: allowed_sources
                    .into_iter()
                    .map(|source| track_source_grant_name(source).to_string())
                    .collect(),
                can_subscribe: permissions.has_channel_permission(ChannelPermission::Listen),
                room: channel.id().to_string(),
                ..Default::default()
            })
            .to_jwt()
            .to_internal_error()
    }

    /// Mint a publish-only token for a user's SCREEN LEG — the second SFU
    /// participant a native Android publisher connects as
    /// (android-screen-share plan §2.1).
    ///
    /// `identity` is derived by the route from the CURRENT primary mapping
    /// (`screen_leg_identity`), never built from the request body: a phone
    /// that is not the primary in the call must not be able to mint a leg
    /// under the user's desktop identity, which every viewer would then
    /// canonicalize onto a non-leaf (rev-2 review §0-R.2).
    ///
    /// The grant is the whole security story of a leg, so it is spelled out
    /// here rather than derived from `get_allowed_sources`: exactly the two
    /// screen sources, `can_subscribe: false` (a phone must not pull the
    /// whole grid down a second WebRTC stack, and a leg holds no receive
    /// keys — compromise of the native process exposes one send key per
    /// epoch) and `can_publish_data: false` (the data channel is an
    /// untrusted injection surface for the E2EE call machinery). Name and
    /// metadata match the primary so a viewer resolving either way sees the
    /// same user.
    pub async fn create_screen_leg_token(
        &self,
        node: &str,
        db: &Database,
        user: &User,
        identity: &str,
        channel: &Channel,
    ) -> Result<String> {
        let room = self.get_node(node)?;

        AccessToken::with_api_key(&room.node.key, &room.node.secret)
            .with_name(&format!("{}#{}", user.username, user.discriminator))
            .with_identity(identity)
            .with_metadata(
                &serde_json::to_string(&user.clone().into(db, None).await).to_internal_error()?,
            )
            // Lets a viewer tell a phone leg from a desktop share without
            // parsing identities (the RC "Request control" button is hidden
            // on one). Accepted metadata: these reveal "user X is sharing
            // from a phone" to everyone in the call (plan §5.4).
            .with_attributes([("leg", "screen"), ("platform", "android")])
            // Same 10 s as the primary. The plugin mints BETWEEN the
            // MediaProjection consent dialog and connect (plan §4.2), so a
            // user-paced dialog never eats the TTL.
            .with_ttl(Duration::from_secs(10))
            .with_grants(VideoGrants {
                room_join: true,
                can_publish: true,
                can_publish_data: false,
                can_publish_sources: vec![
                    track_source_grant_name(TrackSource::ScreenShare).to_string(),
                    track_source_grant_name(TrackSource::ScreenShareAudio).to_string(),
                ],
                can_subscribe: false,
                hidden: false,
                room: channel.id().to_string(),
                ..Default::default()
            })
            .to_jwt()
            .to_internal_error()
    }

    pub async fn create_room(&self, node: &str, channel: &Channel) -> Result<Room> {
        let room = self.get_node(node)?;

        let metadata = RoomMetadata {
            server: channel.server().map(|id| id.to_string()),
        };

        room.client
            .create_room(
                channel.id(),
                CreateRoomOptions {
                    empty_timeout: 5 * 60, // 5 minutes,
                    metadata: serde_json::to_string(&metadata).to_internal_error()?,
                    ..Default::default()
                },
            )
            .await
            .to_internal_error()
    }

    pub async fn update_permissions(
        &self,
        node: &str,
        user: &User,
        channel_id: &str,
        new_permissions: ParticipantPermission,
    ) -> Result<ParticipantInfo> {
        // LiveKit addresses participants by identity, which may be
        // device-qualified — resolve through the ingress-maintained mapping
        let identity = super::get_voice_participant_identity(channel_id, &user.id).await?;

        // ...and the user's screen leg, with a LEG-SPECIFIC set. Best-effort:
        // most users have no leg and the SFU simply reports no such
        // participant. Security-relevant, not cosmetic — a moderator
        // revoking `Video` mid-call must stop the phone that is already
        // streaming, not merely the WebView's ability to start (plan §2.4).
        let _ = self
            .update_permissions_identity(
                node,
                &super::screen_leg_identity(&identity),
                channel_id,
                screen_leg_participant_permissions(&new_permissions),
            )
            .await;

        self.update_permissions_identity(node, &identity, channel_id, new_permissions)
            .await
    }

    /// Update a participant addressed by an EXACT SFU identity the caller
    /// already holds. The remote-control revoke path uses this with the
    /// identity captured at accept time: re-resolving through
    /// `get_voice_participant_identity` at revoke time could fall back to
    /// the bare user id (its documented failure mode is a silent no-op for
    /// device-qualified participants), and a revoke that silently no-ops is
    /// exactly what the plan forbids.
    pub async fn update_permissions_identity(
        &self,
        node: &str,
        identity: &str,
        channel_id: &str,
        new_permissions: ParticipantPermission,
    ) -> Result<ParticipantInfo> {
        let room = self.get_node(node)?;

        room.client
            .update_participant(
                channel_id,
                identity,
                UpdateParticipantOptions {
                    permission: Some(new_permissions),
                    ..Default::default()
                },
            )
            .await
            .to_internal_error()
    }

    /// Remove a participant addressed by an EXACT SFU identity (the
    /// remote-control eject-on-revoke-failure escalation)
    pub async fn remove_identity(
        &self,
        node: &str,
        identity: &str,
        channel_id: &str,
    ) -> Result<()> {
        let room = self.get_node(node)?;

        room.client
            .remove_participant(channel_id, identity)
            .await
            .to_internal_error()
    }

    pub async fn remove_user(&self, node: &str, user_id: &str, channel_id: &str) -> Result<()> {
        let room = self.get_node(node)?;

        // Resolve the (possibly device-qualified) identity the SFU knows
        let identity = super::get_voice_participant_identity(channel_id, user_id).await?;

        // A screen leg is a helper of the primary, so EVERY removal path takes
        // it too: moderator kick, voice move, ban, member/server/channel
        // delete, the join-time `force_disconnect`, the ingress admission
        // backstop and the forbidden-track eject all land here. Without this a
        // kicked user's phone keeps streaming into the call it was removed
        // from. Best-effort — most users have no leg (plan §2.4).
        let _ = room
            .client
            .remove_participant(channel_id, &super::screen_leg_identity(&identity))
            .await;

        room.client
            .remove_participant(channel_id, &identity)
            .await
            .to_internal_error()
    }

    /// Server-side mute one published track (media E2EE plan D12 video-cap
    /// enable-leg): refuse an over-cap video track without kicking the member
    /// from the whole call — they stay connected audio-only, matching the
    /// client's "video is full, you're still connected" toast.
    pub async fn mute_track(
        &self,
        node: &str,
        user_id: &str,
        channel_id: &str,
        track_sid: &str,
    ) -> Result<()> {
        let room = self.get_node(node)?;

        let identity = super::get_voice_participant_identity(channel_id, user_id).await?;

        room.client
            .mute_published_track(channel_id, &identity, track_sid, true)
            .await
            .map(|_| ())
            .to_internal_error()
    }

    /// Server-side mute one published track of a participant addressed by an
    /// EXACT SFU identity — the leg-facing twin of [`Self::mute_track`]
    /// (android-screen-share plan §2.4).
    ///
    /// [`Self::mute_track`] resolves the PRIMARY through the identity
    /// mapping, and a leg is deliberately absent from that mapping. Pointed
    /// at a leg's track it would ask the SFU to mute a sid that belongs to a
    /// different participant: LiveKit refuses, and the offending track stays
    /// live.
    pub async fn mute_track_identity(
        &self,
        node: &str,
        identity: &str,
        channel_id: &str,
        track_sid: &str,
    ) -> Result<()> {
        let room = self.get_node(node)?;

        room.client
            .mute_published_track(channel_id, identity, track_sid, true)
            .await
            .map(|_| ())
            .to_internal_error()
    }

    pub async fn delete_room(&self, node: &str, channel_id: &str) -> Result<()> {
        let room = self.get_node(node)?;

        room.client
            .delete_room(channel_id)
            .await
            .to_internal_error()
    }
}

/// The LiveKit participant permissions a permission sync pushes for a SCREEN
/// LEG (android-screen-share plan §2.4).
///
/// NEVER the primary's set. `UpdateParticipant` REPLACES the grant rather
/// than intersecting it with the token (see
/// [`VoiceClient::update_permissions_identity`]), and the sync path grants
/// `can_subscribe = can_listen` plus microphone and camera to anyone holding
/// Listen/Video — pushed at a leg, that would have the phone pulling every
/// track in the call down a second WebRTC stack the instant a moderator
/// edited a role (rev-2 review §0-R.1).
///
/// So: intersect the primary's sources with the two screen ones and drop
/// everything else, unconditionally. An empty intersection means a moderator
/// just revoked `Video` mid-share, and `can_publish: false` is what actually
/// stops the phone — the empty list may only ever travel alongside it, since
/// LiveKit reads an empty `can_publish_sources` as "no restriction".
///
/// Lives in this transport file on purpose: the
/// `remote_control_teardown_restores_the_sync_permission_set` contract test
/// panics on an `update_permissions_identity` call in `voice/mod.rs` built
/// from a constructor it does not inventory.
pub fn screen_leg_participant_permissions(
    primary: &ParticipantPermission,
) -> ParticipantPermission {
    let sources: Vec<i32> = primary
        .can_publish_sources
        .iter()
        .copied()
        .filter(|source| {
            *source == TrackSource::ScreenShare as i32
                || *source == TrackSource::ScreenShareAudio as i32
        })
        .collect();

    ParticipantPermission {
        can_subscribe: false,
        can_publish: !sources.is_empty(),
        can_publish_data: false,
        can_publish_sources: sources,
        ..Default::default()
    }
}

#[cfg(test)]
mod screen_leg_permission_tests {
    use super::screen_leg_participant_permissions;
    use livekit_protocol::{ParticipantPermission, TrackSource};

    /// Whatever the primary holds, the leg never gains subscribe, data, mic
    /// or camera — and an empty intersection travels with `can_publish:
    /// false`, never as LiveKit's "no restriction" empty list.
    #[test]
    fn screen_leg_set_never_carries_subscribe_data_mic_or_camera() {
        let all_sources = [
            TrackSource::Microphone,
            TrackSource::Camera,
            TrackSource::ScreenShare,
            TrackSource::ScreenShareAudio,
            TrackSource::Unknown,
        ];

        for can_listen in [false, true] {
            for can_publish_data in [false, true] {
                for mask in 0u8..1 << all_sources.len() {
                    let sources: Vec<i32> = all_sources
                        .iter()
                        .enumerate()
                        .filter(|(bit, _)| mask & 1 << bit != 0)
                        .map(|(_, source)| *source as i32)
                        .collect();

                    let primary = ParticipantPermission {
                        can_subscribe: can_listen,
                        can_publish: !sources.is_empty(),
                        can_publish_data,
                        can_publish_sources: sources.clone(),
                        ..Default::default()
                    };

                    let leg = screen_leg_participant_permissions(&primary);

                    assert!(!leg.can_subscribe, "a leg never subscribes ({sources:?})");
                    assert!(
                        !leg.can_publish_data,
                        "a leg never publishes data ({sources:?})"
                    );
                    assert!(
                        !leg.can_publish_sources
                            .contains(&(TrackSource::Microphone as i32)),
                        "a leg never gets the microphone ({sources:?})"
                    );
                    assert!(
                        !leg.can_publish_sources
                            .contains(&(TrackSource::Camera as i32)),
                        "a leg never gets the camera ({sources:?})"
                    );
                    assert!(
                        !leg.can_publish_sources
                            .contains(&(TrackSource::Unknown as i32)),
                        "a leg never gets the whisper source ({sources:?})"
                    );

                    let expected: Vec<i32> = sources
                        .iter()
                        .copied()
                        .filter(|source| {
                            *source == TrackSource::ScreenShare as i32
                                || *source == TrackSource::ScreenShareAudio as i32
                        })
                        .collect();
                    assert_eq!(leg.can_publish_sources, expected);
                    assert_eq!(
                        leg.can_publish,
                        !expected.is_empty(),
                        "an empty intersection must carry can_publish:false, never \
                         LiveKit's no-restriction empty list ({sources:?})"
                    );
                }
            }
        }
    }
}
