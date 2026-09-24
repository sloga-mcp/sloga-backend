use crate::{
    models::{Channel, User},
    voice::RoomMetadata,
    Database,
};
use livekit_api::{
    access_token::{AccessToken, VideoGrants},
    services::{
        room::{CreateRoomOptions, RoomClient as InnerRoomClient, UpdateParticipantOptions},
        ServiceError, TwirpError, TwirpErrorCode,
    },
};
use livekit_protocol::{ParticipantInfo, ParticipantPermission, Room, TrackSource};
use revolt_config::{config, LiveKitNode};
use revolt_permissions::{ChannelPermission, PermissionValue};
use revolt_result::{create_error, Result, ToRevoltError};
use std::{collections::HashMap, time::Duration};

use super::{get_allowed_sources, track_source_grant_name, AfkGate};

/// Token attribute carrying a per-CONNECTION nonce, minted fresh by
/// [`VoiceClient::create_token`] on every call.
///
/// It is an addressing label for server-ordered moves: the SFU reports it
/// back through [`VoiceClient::list_participants_if_present`], so a move can
/// name exactly the connection it is moving, and the client compares it
/// against its own `localParticipant.attributes` to tell "this move is for
/// me" from "this move is for my other seat".
///
/// Token attributes are broadcast to every co-participant in the room, which
/// is why the value is an opaque random id (no timestamp, no device detail).
/// It is an addressing label, NEVER a capability: nothing may be granted or
/// authorized on the strength of it, and it is never accepted from a client
/// body — only ever minted here, server-side.
///
/// It must NEVER be folded into the identity string. Identities are parsed
/// by segment count (`participant_leg`'s `splitn(3, ':')`, `is_screen_leg`,
/// the client's `isDeviceQualified`), and a third segment would turn every
/// primary into something those parsers read as a screen leg.
pub const CONN_NONCE_ATTRIBUTE: &str = "conn";

/// Whether a LiveKit service error is the SFU's structured "not found" reply
/// (for `RemoveParticipant`: that identity is not in the room).
///
/// Deliberately narrow. Only a decoded Twirp error body whose code is
/// `not_found` qualifies; every other Twirp code is a real failure, and so is
/// a 404 whose body is NOT a Twirp JSON error (a proxy's HTML page, say) —
/// that one surfaces as `TwirpError::Request` from the failed JSON decode and
/// must stay an error, or an unreachable SFU would read as "already gone".
pub fn is_twirp_not_found(err: &ServiceError) -> bool {
    matches!(
        err,
        ServiceError::Twirp(TwirpError::Twirp(TwirpErrorCode { code, .. }))
            if code == TwirpErrorCode::NOT_FOUND
    )
}

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
        // No `Server` is in hand here — `create_token` is called only from
        // the `voice_join` route (`call`) and the server-ordered move
        // (`move_user_to_voice_channel_expecting`, which
        // `move_user_to_voice_channel` delegates to); the remote-control
        // paths never mint, they act on existing participants through
        // `update_permissions_identity`, and the Android screen leg mints
        // through `create_screen_leg_token` with its own gate — so the gate
        // resolves the designation itself. One `fetch_server` per token mint
        // (a join or a move), never per participant of a call.
        let allowed_sources = get_allowed_sources(
            &limits,
            permissions,
            AfkGate::resolve(db, channel, None).await?,
        );

        // Device-qualified identity (media E2EE, plan Q4): per-device frame
        // keys require an injective identity → (user, device) mapping, and
        // distinct identities stop the SFU kicking a user's first device the
        // moment a second one connects (the one-device-per-call rule is
        // enforced at the MLS delivery service instead).
        let identity = match device_id {
            Some(device_id) => format!("{}:{}", user.id, device_id),
            None => user.id.clone(),
        };

        // Fresh per-connection nonce on EVERY mint — see
        // `CONN_NONCE_ATTRIBUTE`. Carried as an attribute, never in the
        // identity.
        let conn_nonce = nanoid::nanoid!();

        AccessToken::with_api_key(&room.node.key, &room.node.secret)
            .with_name(&format!("{}#{}", user.username, user.discriminator))
            .with_identity(&identity)
            .with_metadata(
                &serde_json::to_string(&user.clone().into(db, None).await).to_internal_error()?,
            )
            // `with_attributes` REPLACES the whole attribute map, so this must
            // stay the ONLY call on this builder; any future attribute joins
            // this array rather than getting a second call.
            .with_attributes([(CONN_NONCE_ATTRIBUTE, conn_nonce.as_str())])
            .with_ttl(Duration::from_secs(10))
            .with_grants(VideoGrants {
                room_join: true,
                // An EMPTY canPublishSources claim means "no restriction" to
                // LiveKit (auth/grants.go), so a source-less member (Connect
                // without Speak/Video, or anyone in the AFK channel) must be
                // denied publishing outright. Pinned on the minted token by
                // `afk_mint_tests`.
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
    ///
    /// Because the grant is spelled out rather than derived, this is the FIFTH
    /// publish-rights path and the AFK gate does NOT reach it through
    /// `get_allowed_sources` (AFK-channel plan D2). It is gated here, on its
    /// own, or a phone screen-shares into the AFK channel while every WebView
    /// in the room is refused. Refusing outright rather than minting an empty
    /// grant: a leg exists only to publish, and an empty `canPublishSources`
    /// means "no restriction" to LiveKit — minting one would invert the
    /// meaning of the token (the same reasoning the route applies to the
    /// video feature limit).
    pub async fn create_screen_leg_token(
        &self,
        node: &str,
        db: &Database,
        user: &User,
        identity: &str,
        channel: &Channel,
    ) -> Result<String> {
        if AfkGate::resolve(db, channel, None)
            .await?
            .denies_publishing()
        {
            return Err(create_error!(MissingPermission {
                permission: ChannelPermission::Video.to_string()
            }));
        }

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

    /// [`Self::update_permissions`], treating "that participant is not in the
    /// room" as an answer rather than a failure (AFK Stage 6 F-A1).
    ///
    /// `Ok(true)`: the SFU applied the new permissions to a primary connection
    /// of the user. `Ok(false)`: the user has NO connection in the room, as
    /// far as we can be sure (below). `Err`: anything else, including a
    /// non-JSON 404, an unknown node, a failed identity lookup, and a failed
    /// roster read.
    ///
    /// "Not found" is only an answer when the identity we addressed is the
    /// participant's real one (AFK Stage 6 re-audit RA-1). voice-ingress
    /// records every participant's identity, bare or device-qualified, on
    /// `participant_joined`, before it creates the voice state, and deletes
    /// it only with the voice state; so a sync that finds voice state
    /// normally finds the mapping too. When the mapping is missing anyway
    /// (evicted, or dropped by a teardown path that left the voice state),
    /// the bare user id is only a GUESS, and a device-qualified participant
    /// still publishing would answer not_found to it. So on that path the
    /// SFU's own roster decides ([`not_found_answer`]): every primary
    /// connection of the user it lists is pushed to, none listed is
    /// `Ok(false)`, and a roster that cannot be read is an error.
    ///
    /// The screen leg gets the leg-specific set, best-effort, before its
    /// primary, through the classifying push so that a user with no leg (the
    /// common case) is not an ERROR log and a Sentry event on every sync
    /// (RA-6); a real failure there still reports, from inside that push.
    pub async fn update_permissions_if_present(
        &self,
        node: &str,
        user: &User,
        channel_id: &str,
        new_permissions: ParticipantPermission,
    ) -> Result<bool> {
        let stored = super::stored_voice_participant_identity(channel_id, &user.id).await?;
        let mapped = stored.is_some();
        let identity = stored.unwrap_or_else(|| user.id.clone());

        if self
            .push_primary_and_leg(node, &identity, channel_id, &new_permissions)
            .await?
        {
            return Ok(true);
        }

        let answer = match not_found_answer(&user.id, mapped, None) {
            NotFoundAnswer::ReadRoster => {
                let roster = self
                    .list_participants_if_present(node, channel_id)
                    .await
                    .map(|listed| {
                        listed.map(|participants| {
                            participants
                                .into_iter()
                                .map(|participant| participant.identity)
                                .collect::<Vec<_>>()
                        })
                    });
                not_found_answer(&user.id, mapped, Some(roster))
            }
            answer => answer,
        };

        match answer {
            NotFoundAnswer::Gone => Ok(false),
            NotFoundAnswer::Failed(error) => Err(error),
            NotFoundAnswer::PushTo(identities) => {
                log::warn!(
                    "voice identity mapping missing for {} in {channel_id}; the SFU lists \
                     {identities:?}, pushing the permission sync there",
                    user.id
                );
                let mut pushes = Vec::with_capacity(identities.len());
                for identity in &identities {
                    pushes.push(
                        self.push_primary_and_leg(node, identity, channel_id, &new_permissions)
                            .await,
                    );
                }
                pushes_answer(pushes)
            }
            // `not_found_answer` never asks twice; fail closed if it ever does.
            NotFoundAnswer::ReadRoster => {
                log::error!(
                    "permission sync of {} in {channel_id}: the roster was asked for twice",
                    user.id
                );
                Err(create_error!(InternalError))
            }
        }
    }

    /// The leg-specific set to `identity`'s screen leg (best-effort, result
    /// discarded), then `new_permissions` to `identity` itself, both through
    /// the classifying push. The primary's answer is returned.
    async fn push_primary_and_leg(
        &self,
        node: &str,
        identity: &str,
        channel_id: &str,
        new_permissions: &ParticipantPermission,
    ) -> Result<bool> {
        let _ = self
            .update_permissions_identity_if_present(
                node,
                &super::screen_leg_identity(identity),
                channel_id,
                screen_leg_participant_permissions(new_permissions),
            )
            .await;

        self.update_permissions_identity_if_present(
            node,
            identity,
            channel_id,
            new_permissions.clone(),
        )
        .await
    }

    /// [`Self::update_permissions_identity`], treating "that participant is
    /// not in the room" as an answer rather than a failure: `Ok(true)` the SFU
    /// applied it, `Ok(false)` a Twirp `not_found` (see
    /// [`is_twirp_not_found`]), `Err` anything else, including a non-JSON 404
    /// and an unknown node.
    ///
    /// Goes through the raw room client so that the classification happens
    /// BEFORE any reporting: `to_internal_error()` logs at ERROR and reports
    /// to Sentry, and a participant that has already left is not an incident.
    /// So only the not-found answer is quiet. A real failure goes through
    /// `to_internal_error()` exactly as [`Self::update_permissions_identity`]
    /// reports it: ERROR log, Sentry event, `InternalError` (AFK Stage 6
    /// FU-2). A failed grant push is a security-relevant event (a member may
    /// be left publishing where they should not), and must not be quieter
    /// than it was before this function existed.
    pub async fn update_permissions_identity_if_present(
        &self,
        node: &str,
        identity: &str,
        channel_id: &str,
        new_permissions: ParticipantPermission,
    ) -> Result<bool> {
        let livekit = self.get_node(node)?;

        match livekit
            .client
            .update_participant(
                channel_id,
                identity,
                UpdateParticipantOptions {
                    permission: Some(new_permissions),
                    ..Default::default()
                },
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(error) if is_twirp_not_found(&error) => Ok(false),
            // A real failure: ERROR log + Sentry (see the doc comment).
            Err(error) => Err::<bool, _>(error).to_internal_error(),
        }
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

    /// Remove a participant addressed by an EXACT SFU identity, treating
    /// "not in the room" as an answer rather than a failure.
    ///
    /// `Ok(true)`: the SFU removed it. `Ok(false)`: the SFU says no such
    /// participant (see [`is_twirp_not_found`]) — for an eviction that is the
    /// outcome wanted, e.g. a moved connection that already left on the move
    /// event. `Err`: anything else, including a non-JSON 404.
    ///
    /// Goes through the raw room client (the voice-ingress `participant_left`
    /// precedent) rather than [`Self::remove_identity`], whose
    /// `to_internal_error()` logs at ERROR and reports to Sentry before the
    /// caller can classify the result — one event per evicted connection per
    /// move. A real failure is logged here at WARN only; the caller decides
    /// what it means for its operation.
    pub async fn remove_identity_if_present(
        &self,
        node: &str,
        identity: &str,
        room: &str,
    ) -> Result<bool> {
        let livekit = self.get_node(node)?;

        match livekit.client.remove_participant(room, identity).await {
            Ok(()) => Ok(true),
            Err(error) if is_twirp_not_found(&error) => Ok(false),
            Err(error) => {
                log::warn!("failed to remove SFU participant {identity} from room {room}: {error}");
                Err(create_error!(InternalError))
            }
        }
    }

    /// Every participant the SFU currently reports in a room, identities and
    /// all, treating "the SFU has no such room" as an answer rather than a
    /// failure.
    ///
    /// The SFU's own list is the only authority on how many connections an
    /// account actually holds in a call. The server-side records are not:
    /// `voice_identity:{channel_id}` is a hash keyed by BARE user id, so it can
    /// represent at most one connection per account, and `vc_members` is a set
    /// of user ids with the same limitation. Where a decision has to be correct
    /// for a user sitting in a room TWICE — the voice-move eviction, and any
    /// future multi-connection eviction (kick, ban) — it has to be made against
    /// this, not against Redis.
    ///
    /// `Ok(Some(list))`: the SFU's participants. `Ok(None)`: the SFU says the
    /// room does not exist (a Twirp `not_found`, see [`is_twirp_not_found`]),
    /// so nobody is connected to it. `Err`: anything else, including a
    /// non-JSON 404; an unknown node is `get_node`'s `UnknownNode`. Read-only,
    /// so unlike [`Self::remove_user`], whose screen-leg removal is
    /// best-effort, it has no best-effort half: the caller decides what an
    /// unanswered SFU means for its own operation.
    ///
    /// This is deliberately the ONLY participant listing on `VoiceClient`.
    /// A room the SFU no longer has must read as "not connected", not as a
    /// 500 plus a Sentry event on every sweep tick. Like
    /// [`Self::remove_identity_if_present`] it goes through the raw room
    /// client, because `to_internal_error()` logs at ERROR and reports to
    /// Sentry before the caller can classify the result; a real failure is
    /// logged here at WARN only. Do not add a plain `to_internal_error()`
    /// listing beside it.
    pub async fn list_participants_if_present(
        &self,
        node: &str,
        room: &str,
    ) -> Result<Option<Vec<ParticipantInfo>>> {
        let livekit = self.get_node(node)?;

        match livekit.client.list_participants(room).await {
            Ok(participants) => Ok(Some(participants)),
            Err(error) if is_twirp_not_found(&error) => Ok(None),
            Err(error) => {
                log::warn!("failed to list SFU participants of room {room}: {error}");
                Err(create_error!(InternalError))
            }
        }
    }

    /// Remove ONE connection of `user_id` — the one the identity mapping names
    /// — plus its screen leg.
    ///
    /// Exactly one, and that is a real limitation rather than a turn of phrase.
    /// `get_voice_participant_identity` reads a hash field keyed by bare user
    /// id, so an account holding two connections in the same room (which the
    /// SFU permits: `{user}` and `{user}:{device}` are not duplicate
    /// identities) has only one of them represented there, and this leaves the
    /// other connected. Callers that must clear an account out of a room
    /// COMPLETELY have to enumerate [`Self::list_participants_if_present`]
    /// instead, and evict each listed connection with
    /// [`Self::remove_identity_if_present`]; see the eviction leg of
    /// `move_user_to_voice_channel`. Use the `_if_present` listing, never a
    /// raw `to_internal_error()` one: it reads a room the SFU no longer has
    /// as "not connected" (`Ok(None)`), where a plain listing turns it into a
    /// 500 plus a Sentry event.
    pub async fn remove_user(&self, node: &str, user_id: &str, channel_id: &str) -> Result<()> {
        let room = self.get_node(node)?;

        // Resolve the (possibly device-qualified) identity the SFU knows
        let identity = super::get_voice_participant_identity(channel_id, user_id).await?;

        // A screen leg is a helper of the primary, so EVERY removal path that
        // lands here takes it too: the moderator voice disconnect
        // (`member_edit`); through `remove_user_from_voice_channel(s)` the
        // ban, member kick, `server_delete`, `channel_delete`, group member
        // removal and bot deletion; the join-time `force_disconnect`; the
        // ingress admission backstop and the forbidden-track eject. The voice
        // move does NOT come through here — it evicts each connection the SFU
        // lists via `remove_identity_if_present`. Without this a kicked
        // user's phone keeps streaming into the call it was removed from.
        // Best-effort — most users have no leg (plan §2.4).
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

/// What a permission push that the SFU answered `not_found` amounts to (AFK
/// Stage 6 re-audit RA-1). See [`not_found_answer`].
#[derive(Debug, PartialEq, Eq)]
enum NotFoundAnswer<E> {
    /// The user has no connection in the room: skip them.
    Gone,
    /// The addressed identity was a guess; read the SFU's roster, then ask
    /// again with it.
    ReadRoster,
    /// The roster lists these primary connections of the user: push to them.
    PushTo(Vec<String>),
    /// The roster could not be read: no answer, so an error.
    Failed(E),
}

/// Decide what a `not_found` from the SFU means for `user_id`.
///
/// - `mapped`: the identity addressed was the one voice-ingress recorded for
///   this user, i.e. the participant's real identity, so `not_found` is the
///   truth: [`NotFoundAnswer::Gone`].
/// - not `mapped`: the addressed identity was the bare-id FALLBACK, a guess.
///   A device-qualified connection would answer `not_found` to it while
///   still publishing, so only the SFU's roster can say. `roster: None`
///   (not read yet) asks for it; a roster that failed to read is
///   [`NotFoundAnswer::Failed`]; a room the SFU does not have
///   (`Ok(None)`) or a roster listing no primary of the user is
///   [`NotFoundAnswer::Gone`]; otherwise every listed primary of the user,
///   bare or `{user}:{device}`, screen legs excluded, is
///   [`NotFoundAnswer::PushTo`].
///
/// Pure, so each branch is pinned by value.
fn not_found_answer<E>(
    user_id: &str,
    mapped: bool,
    roster: Option<std::result::Result<Option<Vec<String>>, E>>,
) -> NotFoundAnswer<E> {
    if mapped {
        return NotFoundAnswer::Gone;
    }

    match roster {
        None => NotFoundAnswer::ReadRoster,
        Some(Err(error)) => NotFoundAnswer::Failed(error),
        Some(Ok(None)) => NotFoundAnswer::Gone,
        Some(Ok(Some(identities))) => {
            let primaries: Vec<String> = identities
                .into_iter()
                .filter(|identity| {
                    super::user_id_from_participant_identity(identity) == user_id
                        && !super::is_screen_leg(identity)
                })
                .collect();

            if primaries.is_empty() {
                NotFoundAnswer::Gone
            } else {
                NotFoundAnswer::PushTo(primaries)
            }
        }
    }
}

/// What the pushes to the connections the roster listed amount to: the FIRST
/// error when any failed (after all were tried), else `Ok(true)` if any
/// landed, else `Ok(false)` (every listed connection left in the meantime).
/// Pure.
fn pushes_answer<E>(
    pushes: impl IntoIterator<Item = std::result::Result<bool, E>>,
) -> std::result::Result<bool, E> {
    let mut failure = None;
    let mut landed = false;

    for push in pushes {
        match push {
            Ok(pushed) => landed |= pushed,
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
    }

    match failure {
        Some(error) => Err(error),
        None => Ok(landed),
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

/// The per-connection nonce and the classifying removal (AFK Wave 5b-1).
///
/// No Redis, Mongo or real SFU: the tokens are minted by the real
/// `create_token` / `create_screen_leg_token` against a saved-messages channel
/// (no server, so the AFK gate never reads the database) and the Reference
/// driver, and the removal is driven against a one-shot loopback HTTP stub
/// that answers the way a LiveKit Twirp endpoint (or a proxy in front of one)
/// would.
#[cfg(test)]
mod conn_nonce_and_removal_tests {
    use super::{is_twirp_not_found, VoiceClient};
    use crate::{
        models::{Channel, User},
        Database,
    };
    use livekit_api::{
        access_token::{AccessTokenError, Claims},
        services::{ServiceError, TwirpError, TwirpErrorCode},
    };
    use livekit_protocol::ParticipantInfo;
    use revolt_config::LiveKitNode;
    use revolt_permissions::{ChannelPermission, PermissionValue};
    use revolt_result::ErrorType;
    use std::{
        collections::{BTreeMap, HashMap, HashSet},
        io::{Read, Write},
        net::TcpListener,
        thread::JoinHandle,
    };

    const NODE: &str = "test-node";

    fn voice_client(url: &str) -> VoiceClient {
        VoiceClient::new(HashMap::from([(
            NODE.to_string(),
            LiveKitNode {
                url: url.to_string(),
                lat: 0.0,
                lon: 0.0,
                key: "testkey".to_string(),
                secret: "testsecret-testsecret-testsecret".to_string(),
                private: true,
                remote: false,
            },
        )]))
    }

    fn fixture() -> (Database, User, Channel) {
        let user = User {
            id: ulid::Ulid::new().to_string(),
            username: "mover".to_string(),
            discriminator: "0001".to_string(),
            ..Default::default()
        };
        let channel = Channel::SavedMessages {
            id: ulid::Ulid::new().to_string(),
            user: user.id.clone(),
        };

        (Database::Reference(Default::default()), user, channel)
    }

    /// Accept ONE connection on a loopback port, read the whole request
    /// (head plus `content-length` body, so closing never resets an unread
    /// request), answer with the given status / content type / body, and hand
    /// back the request head for inspection.
    fn serve_once(
        status_line: &'static str,
        content_type: &'static str,
        body: impl Into<Vec<u8>>,
    ) -> (String, JoinHandle<String>) {
        let body: Vec<u8> = body.into();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            let head = loop {
                let read = stream.read(&mut chunk).expect("read request");
                assert!(read > 0, "client closed before sending a full request");
                request.extend_from_slice(&chunk[..read]);

                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&request[..end]).to_string();
                    let length = head
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|value| value.trim().to_string())
                        })
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or(0);

                    if request.len() >= end + 4 + length {
                        break head;
                    }
                }
            };

            let mut response = format!(
                "{status_line}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n\
                 connection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            response.extend_from_slice(&body);
            stream.write_all(&response).expect("write response");
            head
        });

        (format!("http://{addr}"), handle)
    }

    fn twirp(code: &str) -> ServiceError {
        ServiceError::Twirp(TwirpError::Twirp(TwirpErrorCode {
            code: code.to_string(),
            msg: "stub".to_string(),
        }))
    }

    /// Every `create_token` call carries its OWN non-empty nonce under the
    /// `conn` attribute, as the only attribute, and never in the identity:
    /// the identity keeps at most two `:` segments and is exactly what it was
    /// before the nonce existed.
    ///
    /// The attribute is read by the string LITERAL `"conn"`, not through
    /// `CONN_NONCE_ATTRIBUTE`, so drifting the constant reddens here instead
    /// of silently moving both sides together (the client matches `"conn"`).
    #[tokio::test]
    async fn create_token_mints_a_fresh_nonce_per_call_outside_the_identity() {
        let (db, user, channel) = fixture();
        let voice = voice_client("http://127.0.0.1:1");
        let permissions = PermissionValue::from_raw(
            ChannelPermission::Connect as u64
                | ChannelPermission::Speak as u64
                | ChannelPermission::Listen as u64,
        );

        let mut nonces = HashSet::new();
        let mints = [
            (None, user.id.clone()),
            (Some("DEVICE"), format!("{}:DEVICE", user.id)),
            (Some("DEVICE"), format!("{}:DEVICE", user.id)),
        ];

        for (device_id, expected_identity) in mints {
            let token = voice
                .create_token(NODE, &db, &user, permissions, &channel, device_id)
                .await
                .expect("create_token");
            let claims = Claims::from_unverified(&token).expect("decode token");

            let nonce = claims
                .attributes
                .get("conn")
                .unwrap_or_else(|| panic!("no `conn` attribute: {:?}", claims.attributes));
            assert!(!nonce.is_empty(), "the nonce must never be empty");
            assert!(
                !nonce.contains(':'),
                "the nonce must not look like an identity segment: {nonce}"
            );
            assert_eq!(
                claims.attributes.keys().collect::<Vec<_>>(),
                vec!["conn"],
                "the primary token carries exactly one attribute"
            );
            assert!(
                nonces.insert(nonce.clone()),
                "two mints produced the same nonce {nonce}"
            );

            assert_eq!(claims.sub, expected_identity, "identity is unchanged");
            assert!(
                claims.sub.split(':').count() <= 2,
                "the identity grew a third segment: {}",
                claims.sub
            );
        }

        assert_eq!(nonces.len(), 3);
    }

    /// The screen-leg token is untouched by the nonce: its attributes are
    /// exactly `{leg: screen, platform: android}` — no `conn`, nothing else.
    #[tokio::test]
    async fn screen_leg_token_attributes_are_exactly_leg_and_platform() {
        let (db, user, channel) = fixture();
        let voice = voice_client("http://127.0.0.1:1");
        let identity = super::super::screen_leg_identity(&format!("{}:DEVICE", user.id));

        let token = voice
            .create_screen_leg_token(NODE, &db, &user, &identity, &channel)
            .await
            .expect("create_screen_leg_token");
        let claims = Claims::from_unverified(&token).expect("decode token");

        let attributes: BTreeMap<&str, &str> = claims
            .attributes
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        assert_eq!(
            attributes,
            BTreeMap::from([("leg", "screen"), ("platform", "android")])
        );
    }

    /// Only a decoded Twirp `not_found` counts as "not in the room".
    #[test]
    fn is_twirp_not_found_accepts_only_the_not_found_code() {
        assert!(is_twirp_not_found(&twirp(TwirpErrorCode::NOT_FOUND)));

        for code in [
            TwirpErrorCode::INTERNAL,
            TwirpErrorCode::PERMISSION_DENIED,
            TwirpErrorCode::UNAVAILABLE,
            TwirpErrorCode::BAD_ROUTE,
            TwirpErrorCode::UNKNOWN,
        ] {
            assert!(!is_twirp_not_found(&twirp(code)), "{code} is not not_found");
        }

        assert!(!is_twirp_not_found(&ServiceError::AccessToken(
            AccessTokenError::InvalidKeys
        )));
        assert!(!is_twirp_not_found(&ServiceError::Env(
            std::env::VarError::NotPresent
        )));
    }

    /// A 404 whose body is not a Twirp JSON error (a proxy page) surfaces from
    /// the real client as `TwirpError::Request` — and is NOT "not found".
    #[tokio::test]
    async fn non_json_404_is_a_request_error_not_not_found() {
        let (url, server) =
            serve_once("HTTP/1.1 404 Not Found", "text/plain", "404 page not found");
        let voice = voice_client(&url);

        let error = voice
            .get_node(NODE)
            .expect("node")
            .client
            .remove_participant("room", "user")
            .await
            .expect_err("a 404 is never success");
        server.join().expect("stub server");

        assert!(
            matches!(error, ServiceError::Twirp(TwirpError::Request(_))),
            "expected TwirpError::Request, got {error:?}"
        );
        assert!(!is_twirp_not_found(&error));
    }

    /// Success -> `Ok(true)`, a Twirp `not_found` -> `Ok(false)`, every other
    /// failure -> `Err(InternalError)`, and an unknown node -> the same
    /// `UnknownNode` that `get_node` returns. Each request goes to the SFU's
    /// `RemoveParticipant` endpoint.
    #[tokio::test]
    async fn remove_identity_if_present_classifies_the_sfu_answer() {
        async fn remove(
            status_line: &'static str,
            content_type: &'static str,
            body: &'static str,
        ) -> revolt_result::Result<bool> {
            let (url, server) = serve_once(status_line, content_type, body);
            let result = voice_client(&url)
                .remove_identity_if_present(NODE, "user:DEVICE", "room")
                .await;
            let head = server.join().expect("stub server");
            assert!(
                head.starts_with("POST /twirp/livekit.RoomService/RemoveParticipant "),
                "unexpected request: {head}"
            );
            result
        }

        assert!(matches!(
            remove("HTTP/1.1 200 OK", "application/protobuf", "").await,
            Ok(true)
        ));

        assert!(matches!(
            remove(
                "HTTP/1.1 404 Not Found",
                "application/json",
                r#"{"code":"not_found","msg":"participant not found"}"#,
            )
            .await,
            Ok(false)
        ));

        for (status_line, content_type, body) in [
            (
                "HTTP/1.1 500 Internal Server Error",
                "application/json",
                r#"{"code":"internal","msg":"boom"}"#,
            ),
            (
                "HTTP/1.1 403 Forbidden",
                "application/json",
                r#"{"code":"permission_denied","msg":"no"}"#,
            ),
            ("HTTP/1.1 404 Not Found", "text/plain", "404 page not found"),
        ] {
            match remove(status_line, content_type, body).await {
                Err(error) => assert!(
                    matches!(error.error_type, ErrorType::InternalError),
                    "{status_line}: {error:?}"
                ),
                Ok(removed) => panic!("{status_line} {body} must be an error, got Ok({removed})"),
            }
        }

        match voice_client("http://127.0.0.1:1")
            .remove_identity_if_present("no-such-node", "user", "room")
            .await
        {
            Err(error) => assert!(
                matches!(error.error_type, ErrorType::UnknownNode),
                "{error:?}"
            ),
            Ok(removed) => panic!("an unknown node must be an error, got Ok({removed})"),
        }
    }

    /// Protobuf wire bytes of a `ListParticipantsResponse` holding one
    /// participant with `identity` and the single attribute `conn`.
    ///
    /// A Twirp 200 is protobuf, not JSON: the client decodes it with prost
    /// (livekit-api `TwirpClient::request`), so a JSON body would be a decode
    /// error. `prost` is not a dependency of this crate, so the bytes are
    /// spelled out here; the test that decodes them through the real client
    /// and checks every field is what proves they are right.
    fn list_participants_response(identity: &str, conn: &str) -> Vec<u8> {
        // Length-delimited field: key byte (tag << 3 | wire type 2), a
        // one-byte varint length, then the payload.
        fn field(tag: u8, payload: &[u8]) -> Vec<u8> {
            assert!(tag < 16 && payload.len() < 0x80, "single-byte varints only");
            let mut out = vec![(tag << 3) | 2, payload.len() as u8];
            out.extend_from_slice(payload);
            out
        }

        // map<string, string> entry: key = 1, value = 2
        let entry = [field(1, b"conn"), field(2, conn.as_bytes())].concat();
        // ParticipantInfo: identity = 2, attributes = 15
        let participant = [field(2, identity.as_bytes()), field(15, &entry)].concat();
        // ListParticipantsResponse: participants = 1
        field(1, &participant)
    }

    /// Success -> `Ok(Some(list))` carrying what the SFU reported (identity
    /// and `conn` attribute included), an empty 200 -> `Ok(Some([]))` (the
    /// room exists, nobody is in it), a Twirp `not_found` -> `Ok(None)` (no
    /// such room), every other failure -> `Err(InternalError)`, and an
    /// unknown node -> `get_node`'s `UnknownNode`. Each request goes to the
    /// SFU's `ListParticipants` endpoint.
    #[tokio::test]
    async fn list_participants_if_present_classifies_the_sfu_answer() {
        async fn list(
            status_line: &'static str,
            content_type: &'static str,
            body: impl Into<Vec<u8>>,
        ) -> revolt_result::Result<Option<Vec<ParticipantInfo>>> {
            let (url, server) = serve_once(status_line, content_type, body);
            let result = voice_client(&url)
                .list_participants_if_present(NODE, "room")
                .await;
            let head = server.join().expect("stub server");
            assert!(
                head.starts_with("POST /twirp/livekit.RoomService/ListParticipants "),
                "unexpected request: {head}"
            );
            result
        }

        match list(
            "HTTP/1.1 200 OK",
            "application/protobuf",
            list_participants_response("user:DEVICE", "n1"),
        )
        .await
        {
            Ok(Some(participants)) => {
                assert_eq!(participants.len(), 1, "{participants:?}");
                assert_eq!(participants[0].identity, "user:DEVICE");
                assert_eq!(
                    participants[0].attributes,
                    HashMap::from([("conn".to_string(), "n1".to_string())])
                );
            }
            other => panic!("a 200 must be Ok(Some(..)), got {other:?}"),
        }

        match list("HTTP/1.1 200 OK", "application/protobuf", Vec::new()).await {
            Ok(Some(participants)) => assert!(participants.is_empty(), "{participants:?}"),
            other => panic!("an empty 200 must be Ok(Some([])), got {other:?}"),
        }

        match list(
            "HTTP/1.1 404 Not Found",
            "application/json",
            r#"{"code":"not_found","msg":"requested room does not exist"}"#,
        )
        .await
        {
            Ok(None) => {}
            other => panic!("a Twirp not_found must be Ok(None), got {other:?}"),
        }

        for (status_line, content_type, body) in [
            (
                "HTTP/1.1 500 Internal Server Error",
                "application/json",
                r#"{"code":"internal","msg":"boom"}"#,
            ),
            (
                "HTTP/1.1 403 Forbidden",
                "application/json",
                r#"{"code":"permission_denied","msg":"no"}"#,
            ),
            ("HTTP/1.1 404 Not Found", "text/plain", "404 page not found"),
        ] {
            match list(status_line, content_type, body).await {
                Err(error) => assert!(
                    matches!(error.error_type, ErrorType::InternalError),
                    "{status_line}: {error:?}"
                ),
                Ok(listed) => panic!("{status_line} {body} must be an error, got Ok({listed:?})"),
            }
        }

        match voice_client("http://127.0.0.1:1")
            .list_participants_if_present("no-such-node", "room")
            .await
        {
            Err(error) => assert!(
                matches!(error.error_type, ErrorType::UnknownNode),
                "{error:?}"
            ),
            Ok(listed) => panic!("an unknown node must be an error, got Ok({listed:?})"),
        }
    }

    /// A shipping `VoiceClient` method of this file, from its definition to
    /// the end of its body, comment lines dropped and whitespace collapsed.
    fn shipping_method(definition: &str) -> String {
        const SOURCE: &str = include_str!("voice_client.rs");
        let shipping = &SOURCE[..SOURCE
            .find("#[cfg(test)]\nmod screen_leg_permission_tests")
            .expect("the first test module")];
        let at = shipping
            .find(definition)
            .unwrap_or_else(|| panic!("`{definition}` is not defined"));
        let end = at
            + shipping[at..]
                .find("\n    }\n")
                .expect("the end of its body");

        shipping[at..end]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// RA-1 (Stage 6 re-audit): `update_permissions_if_present` reads the
    /// mapping WITHOUT the bare-id fallback, pushes to it, and on a miss
    /// asks `not_found_answer` whether that miss is an answer: first with no
    /// roster, then, if asked, with the SFU's roster. Its Redis lookup makes
    /// it untestable by value here, so it is pinned on its text; the decision
    /// itself is pinned by value below. Mutations: the lookup swapped for the
    /// falling-back `get_voice_participant_identity`, `mapped` forced, the
    /// roster never read, or a verdict mapped to the wrong result.
    #[test]
    fn update_permissions_if_present_consults_the_roster_on_a_guess() {
        let body = shipping_method("pub async fn update_permissions_if_present(");
        let at = |needle: &str| {
            body.find(needle).unwrap_or_else(|| {
                panic!("`update_permissions_if_present` lost `{needle}`: {body}")
            })
        };

        assert!(
            !body.contains("get_voice_participant_identity("),
            "the falling-back lookup hides whether the identity is a guess: {body}"
        );
        let order = [
            "let stored = super::stored_voice_participant_identity(channel_id, &user.id).await?;",
            "let mapped = stored.is_some();",
            ".push_primary_and_leg(node, &identity, channel_id, &new_permissions)",
            "not_found_answer(&user.id, mapped, None)",
            ".list_participants_if_present(node, channel_id)",
            "not_found_answer(&user.id, mapped, Some(roster))",
        ];
        for pair in order.windows(2) {
            assert!(
                at(pair[0]) < at(pair[1]),
                "`{}` must precede `{}`: {body}",
                pair[0],
                pair[1]
            );
        }
        for verdict in [
            "NotFoundAnswer::Gone => Ok(false),",
            "NotFoundAnswer::Failed(error) => Err(error),",
            "pushes_answer(pushes)",
        ] {
            at(verdict);
        }
    }

    /// RA-6 (Stage 6 re-audit): the best-effort screen-leg push goes through
    /// the CLASSIFYING push, so a member with no leg (almost everyone) is not
    /// an ERROR log and a Sentry event on every sync. The primary goes
    /// through it too. Mutation: either push routed back through the
    /// collapsing `update_permissions_identity`.
    #[test]
    fn the_leg_and_the_primary_use_the_classifying_push() {
        let body = shipping_method("async fn push_primary_and_leg(");

        assert!(
            body.contains(
                "let _ = self .update_permissions_identity_if_present( node, \
                 &super::screen_leg_identity(identity), channel_id, \
                 screen_leg_participant_permissions(new_permissions), ) .await;"
            ),
            "the leg push must be the classifying one, its result discarded: {body}"
        );
        assert_eq!(
            body.matches(".update_permissions_identity_if_present(")
                .count(),
            2,
            "leg and primary: {body}"
        );
        assert!(
            !body.contains(".update_permissions_identity("),
            "no push here may go through the collapsing variant: {body}"
        );
    }

    /// AFK Stage 6 FU-2: in `update_permissions_identity_if_present` only the
    /// not-found answer is quiet. The real-failure arm goes through
    /// `to_internal_error()` (ERROR log + Sentry, `#[track_caller]`), never a
    /// bare `create_error!(InternalError)`, which reports nothing. The
    /// reporting itself is not observable from a unit test, so it is pinned
    /// on the text. Mutation: the arm turned back into a WARN log plus
    /// `create_error!(InternalError)`, or reduced to the bare error.
    #[test]
    fn update_permissions_identity_if_present_reports_real_failures() {
        const SOURCE: &str = include_str!("voice_client.rs");
        let shipping = &SOURCE[..SOURCE
            .find("#[cfg(test)]\nmod screen_leg_permission_tests")
            .expect("the first test module")];
        let at = shipping
            .find("pub async fn update_permissions_identity_if_present(")
            .expect("`update_permissions_identity_if_present` is defined");
        let end = at
            + shipping[at..]
                .find("\n    }\n")
                .expect("the end of its body");
        let body = shipping[at..end]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        const QUIET: &str = "Err(error) if is_twirp_not_found(&error) => Ok(false),";
        const REPORTED: &str = "Err(error) => Err::<bool, _>(error).to_internal_error(),";
        let quiet = body
            .find(QUIET)
            .unwrap_or_else(|| panic!("the not-found arm is gone: {body}"));
        let reported = body
            .find(REPORTED)
            .unwrap_or_else(|| panic!("the real-failure arm must use to_internal_error(): {body}"));
        assert!(
            quiet < reported,
            "not-found must be classified first: {body}"
        );
        assert!(
            !body.contains("create_error!(InternalError)"),
            "a bare InternalError reaches neither the ERROR log nor Sentry: {body}"
        );
    }

    /// AFK Stage 6 F-A1: success -> `Ok(true)`, a Twirp `not_found` ->
    /// `Ok(false)` (the connection is gone, the room-wide permission sync
    /// skips it), every other failure -> `Err(InternalError)`, an unknown node
    /// -> `UnknownNode`. Each request goes to the SFU's `UpdateParticipant`
    /// endpoint.
    #[tokio::test]
    async fn update_permissions_identity_if_present_classifies_the_sfu_answer() {
        async fn update(
            status_line: &'static str,
            content_type: &'static str,
            body: &'static str,
        ) -> revolt_result::Result<bool> {
            let (url, server) = serve_once(status_line, content_type, body);
            let result = voice_client(&url)
                .update_permissions_identity_if_present(
                    NODE,
                    "user:DEVICE",
                    "room",
                    Default::default(),
                )
                .await;
            let head = server.join().expect("stub server");
            assert!(
                head.starts_with("POST /twirp/livekit.RoomService/UpdateParticipant "),
                "unexpected request: {head}"
            );
            result
        }

        assert!(matches!(
            update("HTTP/1.1 200 OK", "application/protobuf", "").await,
            Ok(true)
        ));

        assert!(matches!(
            update(
                "HTTP/1.1 404 Not Found",
                "application/json",
                r#"{"code":"not_found","msg":"participant not found"}"#,
            )
            .await,
            Ok(false)
        ));

        for (status_line, content_type, body) in [
            (
                "HTTP/1.1 500 Internal Server Error",
                "application/json",
                r#"{"code":"internal","msg":"boom"}"#,
            ),
            (
                "HTTP/1.1 403 Forbidden",
                "application/json",
                r#"{"code":"permission_denied","msg":"no"}"#,
            ),
            ("HTTP/1.1 404 Not Found", "text/plain", "404 page not found"),
        ] {
            match update(status_line, content_type, body).await {
                Err(error) => assert!(
                    matches!(error.error_type, ErrorType::InternalError),
                    "{status_line}: {error:?}"
                ),
                Ok(updated) => panic!("{status_line} {body} must be an error, got Ok({updated})"),
            }
        }

        match voice_client("http://127.0.0.1:1")
            .update_permissions_identity_if_present(
                "no-such-node",
                "user",
                "room",
                Default::default(),
            )
            .await
        {
            Err(error) => assert!(
                matches!(error.error_type, ErrorType::UnknownNode),
                "{error:?}"
            ),
            Ok(updated) => panic!("an unknown node must be an error, got Ok({updated})"),
        }
    }
}

/// AFK Stage 6 F-B2: the Phase A gate on the JOIN/MOVE TOKEN itself.
///
/// `create_token` derives `can_publish` from the gated source list, and an
/// empty `can_publish_sources` means "no restriction" to LiveKit
/// (auth/grants.go). So the one line that turns the gate's empty list into a
/// refusal is `can_publish: !allowed_sources.is_empty()`: `can_publish: true`
/// there hands every member of the AFK channel a token that publishes
/// EVERYTHING. The test in `voice/mod.rs` that checks the gate's source list
/// cannot see that line, so it is pinned here, on the token the real
/// `create_token` mints and signs.
///
/// Reference driver and a fake node: no SFU is ever contacted. Minting a
/// token is local (the node's key and secret sign it), and the only database
/// reads are the server fetch inside `AfkGate::resolve` and the user's
/// metadata. The fixture's server and channel writes publish events, which
/// reach Redis when one is up, so the test runs on the shared Redis-test
/// runtime (`voice::tests::rt`) rather than a runtime of its own.
#[cfg(test)]
mod afk_mint_tests {
    use super::VoiceClient;
    use crate::{Channel, Database, PartialServer, Server, User};
    use livekit_api::access_token::Claims;
    use revolt_config::LiveKitNode;
    use revolt_models::v0::{DataCreateServer, DataCreateServerChannel, LegacyServerChannelType};
    use revolt_permissions::{ChannelPermission, PermissionValue};
    use std::collections::HashMap;

    const NODE: &str = "afk-mint-node";

    #[test]
    fn create_token_in_the_afk_channel_denies_publishing_outright() {
        crate::voice::tests::rt()
            .block_on(create_token_in_the_afk_channel_denies_publishing_outright_case())
    }

    async fn create_token_in_the_afk_channel_denies_publishing_outright_case() {
        let db = Database::Reference(Default::default());

        let owner = User::create(&db, "AfkMintOwner".to_string(), None, None)
            .await
            .expect("`User`");
        let mut server = Server::create(
            &db,
            DataCreateServer {
                name: "AfkMintServer".to_string(),
                description: None,
                nsfw: None,
            },
            &owner,
            false,
        )
        .await
        .expect("`Server`")
        .0;

        let voice_channel = |name: &str| DataCreateServerChannel {
            channel_type: LegacyServerChannelType::Voice,
            name: name.to_string(),
            ..Default::default()
        };
        let afk_channel =
            Channel::create_server_channel(&db, &mut server, voice_channel("AFK"), true)
                .await
                .expect("`Channel`");
        let normal_channel =
            Channel::create_server_channel(&db, &mut server, voice_channel("General"), true)
                .await
                .expect("`Channel`");

        server
            .update(
                &db,
                PartialServer {
                    afk_channel_id: Some(afk_channel.id().to_string()),
                    afk_timeout: Some(300),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("designation");

        let voice = VoiceClient::new(HashMap::from([(
            NODE.to_string(),
            LiveKitNode {
                url: "http://127.0.0.1:1".to_string(),
                lat: 0.0,
                lon: 0.0,
                key: "afkmintkey".to_string(),
                secret: "afkmintsecret-afkmintsecret-afkmint".to_string(),
                private: true,
                remote: false,
            },
        )]));

        // The same member with the same permissions in both channels: Speak
        // and Video (plus Connect and Listen), so the only difference between
        // the two mints is the designation.
        let permissions = PermissionValue::from_raw(
            ChannelPermission::Connect as u64
                | ChannelPermission::Speak as u64
                | ChannelPermission::Video as u64
                | ChannelPermission::Listen as u64,
        );

        let mut grants = Vec::new();
        for channel in [&afk_channel, &normal_channel] {
            let token = voice
                .create_token(NODE, &db, &owner, permissions, channel, None)
                .await
                .expect("create_token");
            let claims = Claims::from_unverified(&token).expect("decode token");
            assert_eq!(claims.video.room, channel.id(), "the token names its room");
            grants.push(claims.video);
        }
        let [afk, control]: [_; 2] = grants.try_into().expect("two mints");

        assert!(
            !afk.can_publish,
            "Phase A regression: a token minted for the designated AFK channel \
             must carry can_publish: false"
        );
        assert!(
            afk.can_publish_sources.is_empty(),
            "the AFK token must list no sources: {:?}",
            afk.can_publish_sources
        );
        assert!(afk.can_subscribe, "AFK revokes publishing, never listening");

        // Control: the undesignated channel, same member, same permissions.
        assert!(
            control.can_publish,
            "control: an undesignated voice channel lets the member publish"
        );
        assert!(
            control
                .can_publish_sources
                .iter()
                .any(|source| source == "microphone"),
            "control: Speak puts the microphone in the grant: {:?}",
            control.can_publish_sources
        );
    }
}

/// AFK Stage 6 re-audit RA-1: when a `not_found` from the SFU is an answer.
#[cfg(test)]
mod not_found_answer_tests {
    use super::{not_found_answer, pushes_answer, NotFoundAnswer};

    const USER: &str = "01KX7HASD9FHBYA3XGKA5YACYX";

    fn roster(identities: &[&str]) -> Option<Result<Option<Vec<String>>, &'static str>> {
        Some(Ok(Some(
            identities
                .iter()
                .map(|identity| identity.to_string())
                .collect(),
        )))
    }

    /// The addressed identity was the recorded one: `not_found` is the
    /// truth, and no roster is needed or read.
    #[test]
    fn a_miss_on_the_recorded_identity_is_gone() {
        assert_eq!(
            not_found_answer::<&str>(USER, true, None),
            NotFoundAnswer::Gone
        );
        assert_eq!(
            not_found_answer(USER, true, roster(&[&format!("{USER}:DEVICE")])),
            NotFoundAnswer::Gone,
            "with a recorded identity the roster is not consulted"
        );
    }

    /// The addressed identity was the bare-id guess: the roster decides.
    #[test]
    fn a_miss_on_the_guess_asks_the_roster() {
        assert_eq!(
            not_found_answer::<&str>(USER, false, None),
            NotFoundAnswer::ReadRoster
        );

        // The user's device-qualified connection is still there: NOT gone.
        let device = format!("{USER}:DEVICE");
        assert_eq!(
            not_found_answer(USER, false, roster(&["OTHERUSER", &device])),
            NotFoundAnswer::PushTo(vec![device.clone()]),
            "a device-qualified participant still publishing must be pushed to"
        );

        // Every primary of the user, in roster order; never a screen leg,
        // never another user.
        assert_eq!(
            not_found_answer(
                USER,
                false,
                roster(&[
                    &format!("{USER}:DEVICE:screen"),
                    &device,
                    "OTHERUSER:DEVICE",
                    USER,
                ])
            ),
            NotFoundAnswer::PushTo(vec![device.clone(), USER.to_string()])
        );

        // Nobody of the user's: gone. Only their leg: gone too (a leg is a
        // helper of a primary, and the primary is what the sync addresses).
        assert_eq!(
            not_found_answer(USER, false, roster(&["OTHERUSER", "OTHERUSER:D"])),
            NotFoundAnswer::Gone
        );
        assert_eq!(
            not_found_answer(USER, false, roster(&[&format!("{USER}::screen")])),
            NotFoundAnswer::Gone
        );
        assert_eq!(
            not_found_answer(USER, false, roster(&[])),
            NotFoundAnswer::Gone
        );

        // The SFU has no such room: nobody is in it.
        assert_eq!(
            not_found_answer::<&str>(USER, false, Some(Ok(None))),
            NotFoundAnswer::Gone
        );

        // The roster could not be read: no answer, so a failure.
        assert_eq!(
            not_found_answer(USER, false, Some(Err("list 500"))),
            NotFoundAnswer::Failed("list 500")
        );
    }

    /// The pushes to the listed connections: the first error wins, else any
    /// landed push is `true`, else `false`.
    #[test]
    fn pushes_answer_returns_the_first_error_else_whether_any_landed() {
        assert_eq!(pushes_answer::<&str>([]), Ok(false));
        assert_eq!(pushes_answer::<&str>([Ok(false), Ok(false)]), Ok(false));
        assert_eq!(pushes_answer::<&str>([Ok(false), Ok(true)]), Ok(true));
        assert_eq!(pushes_answer::<&str>([Ok(true), Ok(false)]), Ok(true));
        assert_eq!(
            pushes_answer([Ok(true), Err("first"), Err("second")]),
            Err("first")
        );
    }
}
