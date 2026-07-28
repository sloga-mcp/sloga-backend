use crate::{
    models::{Channel, User},
    voice::RoomMetadata,
    Database,
};
use livekit_api::{
    access_token::{AccessToken, VideoGrants},
    services::room::{CreateRoomOptions, RoomClient as InnerRoomClient, UpdateParticipantOptions},
};
use livekit_protocol::{ParticipantInfo, ParticipantPermission, Room};
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

    pub async fn delete_room(&self, node: &str, channel_id: &str) -> Result<()> {
        let room = self.get_node(node)?;

        room.client
            .delete_room(channel_id)
            .await
            .to_internal_error()
    }
}
