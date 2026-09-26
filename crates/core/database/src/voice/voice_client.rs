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
use std::{
    collections::HashMap,
    future::Future,
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

use super::{get_allowed_sources, track_source_grant_name, AfkGate};

/// The client-side bound on ONE SFU (LiveKit Twirp) call (AFK S-3 D-5,
/// RA-3).
///
/// livekit-api 0.4.23 builds its HTTP client with a bare
/// `reqwest::Client::new()` (`twirp_client.rs`), which has no timeout and no
/// way to inject one: a node that accepts a connection and never answers
/// hangs the caller for as long as the socket lives, and a blackholed SYN
/// costs about two minutes. Every SFU call on [`VoiceClient`] therefore goes
/// through `VoiceClient::sfu`, which gives up after this long with a
/// synthetic `deadline_exceeded` Twirp error — a real failure to every
/// classifier here, never `not_found`, so a timeout can never read as
/// "already gone" / `Ok(false)` / `Ok(None)`.
///
/// `pub`, not `pub(crate)`: crond's move-budget pins must read the real
/// value, and a retyped `3` would make them vacuous.
pub const SFU_CALL_TIMEOUT: Duration = Duration::from_secs(3);

/// How long the per-node breaker stays OPEN once it has tripped (AFK S-3
/// D-5, SR-4, DS-4).
///
/// The breaker trips after [`SFU_BREAKER_TRIP`] CONSECUTIVE timeouts on one
/// node. While it is open, every call to that node fails fast with the same
/// synthetic `deadline_exceeded` error, without touching the network. After
/// the window ONE half-open probe is let through (the window is re-armed for
/// everyone else while it is in flight): an answer closes the breaker, a
/// timeout re-opens it. Stated blast radius: while it is open, joins on that
/// node fail (`create_room`), for at most this long.
pub const SFU_BREAKER_WINDOW: Duration = Duration::from_secs(10);

/// Consecutive timeouts on one node that trip its breaker. Two, not one
/// (DS-4): a single slow answer must not take a node out for a whole window.
const SFU_BREAKER_TRIP: u32 = 2;

/// Lifetime of every token [`VoiceClient::create_token`] mints: the join
/// token and the server-ordered move's token alike. A token must be redeemed
/// within it, so the SFU calls a move makes between the mint and the event
/// that hands the token over must fit inside it (the D-5 budget pins).
pub const MOVE_TOKEN_TTL: Duration = Duration::from_secs(10);

/// Lifetime of the Android SCREEN-LEG token
/// [`VoiceClient::create_screen_leg_token`] mints. Not a move token and not
/// part of the D-5 move budget: the plugin mints it after the
/// MediaProjection consent dialog and connects straight away. Its own
/// constant so it can move independently of [`MOVE_TOKEN_TTL`].
pub const SCREEN_LEG_TOKEN_TTL: Duration = Duration::from_secs(10);

/// The synthetic error an SFU call that ran out of time (or was refused by an
/// open breaker) answers with. Its code is `deadline_exceeded`, so
/// [`is_twirp_not_found`] is false for it, and every classifier on
/// [`VoiceClient`] treats it as a real failure.
fn sfu_deadline_error(msg: &str) -> ServiceError {
    ServiceError::Twirp(TwirpError::Twirp(TwirpErrorCode {
        code: TwirpErrorCode::DEADLINE_EXCEEDED.to_string(),
        msg: msg.to_string(),
    }))
}

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

/// What `VoiceClient::evict_user_connections` did in a room that exists,
/// once every eviction succeeded or had already gone.
struct UserEviction {
    /// Whether the SFU listed anything of the user (a primary or a leg): the
    /// `bool` of `VoiceClient::remove_user_if_present`.
    any: bool,
    /// The `ParticipantInfo.sid` of every PRIMARY connection of the user in
    /// the listing (legs excluded, empty sids skipped): the answer of
    /// `VoiceClient::remove_user_if_present_sids`.
    sids: Vec<String>,
}

#[derive(Debug)]
pub struct RoomClient {
    /// The raw LiveKit room client. PRIVATE (AFK S-3 D-5): every SFU call
    /// goes through a [`VoiceClient`] method, and every one of those runs
    /// under `VoiceClient::sfu`'s deadline and breaker. A caller outside this
    /// file holding the raw client could issue a call with neither, so the
    /// compiler refuses it.
    client: InnerRoomClient,
    pub node: LiveKitNode,
}

#[derive(Debug)]
pub struct VoiceClient {
    pub rooms: HashMap<String, RoomClient>,
    /// Per-call bound, [`SFU_CALL_TIMEOUT`] outside tests.
    sfu_timeout: Duration,
    /// Breaker window, [`SFU_BREAKER_WINDOW`] outside tests.
    sfu_breaker_window: Duration,
    /// Per-node breaker: node name -> (consecutive timeouts, opened at).
    /// A `std` mutex, locked only in the synchronous `breaker_*` helpers and
    /// NEVER held across an `.await`.
    sfu_breaker: Mutex<HashMap<String, (u32, Option<Instant>)>>,
}

impl VoiceClient {
    pub fn new(nodes: HashMap<String, LiveKitNode>) -> Self {
        Self {
            sfu_timeout: SFU_CALL_TIMEOUT,
            sfu_breaker_window: SFU_BREAKER_WINDOW,
            sfu_breaker: Mutex::new(HashMap::new()),
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

    /// Test-only: shrink the per-call bound and the breaker window so the
    /// timeout and breaker tests run in milliseconds. `new` keeps the
    /// production values and its signature.
    #[cfg(test)]
    pub(crate) fn with_sfu_bounds(mut self, timeout: Duration, breaker_window: Duration) -> Self {
        self.sfu_timeout = timeout;
        self.sfu_breaker_window = breaker_window;
        self
    }

    /// Run ONE SFU call on `node` under the client-side deadline and the
    /// node's breaker (AFK S-3 D-5). Every SFU call on this type goes through
    /// here; see [`SFU_CALL_TIMEOUT`] and [`SFU_BREAKER_WINDOW`].
    ///
    /// The call is a future that has not been polled yet, so a call refused
    /// by an open breaker never reaches the network. A timeout and a refusal
    /// both answer the synthetic `deadline_exceeded` Twirp error, which no
    /// classifier here reads as `not_found`. Any answer from the SFU,
    /// success or error, proves the node is reachable and resets its count
    /// of consecutive timeouts.
    async fn sfu<T>(
        &self,
        node: &str,
        call: impl Future<Output = std::result::Result<T, ServiceError>>,
    ) -> std::result::Result<T, ServiceError> {
        if !self.breaker_admits(node) {
            return Err(sfu_deadline_error(
                "client-side SFU deadline: breaker open for this node",
            ));
        }

        match tokio::time::timeout(self.sfu_timeout, call).await {
            Ok(answer) => {
                self.breaker_record(node, false);
                answer
            }
            Err(_elapsed) => {
                self.breaker_record(node, true);
                Err(sfu_deadline_error("client-side SFU deadline"))
            }
        }
    }

    /// Whether the breaker lets a call to `node` through right now. Closed:
    /// yes. Open and inside the window: no. Open and past the window: yes,
    /// as the ONE half-open probe, and the window is re-armed so that calls
    /// racing the probe keep failing fast until it answers.
    fn breaker_admits(&self, node: &str) -> bool {
        let mut breaker = self
            .sfu_breaker
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        match breaker.get_mut(node) {
            Some((_, Some(opened_at))) if opened_at.elapsed() < self.sfu_breaker_window => false,
            Some((_, Some(opened_at))) => {
                *opened_at = Instant::now();
                true
            }
            _ => true,
        }
    }

    /// Record how an admitted call to `node` ended. An answer clears the
    /// node's entry; a timeout counts, and the [`SFU_BREAKER_TRIP`]th
    /// consecutive one opens (or re-opens) the breaker.
    fn breaker_record(&self, node: &str, timed_out: bool) {
        let mut breaker = self
            .sfu_breaker
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        if !timed_out {
            breaker.remove(node);
            return;
        }

        let (timeouts, opened_at) = breaker.entry(node.to_string()).or_insert((0, None));
        *timeouts = timeouts.saturating_add(1);
        if *timeouts >= SFU_BREAKER_TRIP {
            if opened_at.is_none() {
                log::warn!(
                    "SFU node {node} timed out {timeouts} times in a row; failing its calls \
                     fast for {:?}",
                    self.sfu_breaker_window
                );
            }
            *opened_at = Some(Instant::now());
        }
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
        // (`move_user_to_voice_channel_expecting`, the only move entry
        // point); the remote-control paths never mint, they act on existing
        // participants through `update_permissions_identity`, and the
        // Android screen leg mints
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
            .with_ttl(MOVE_TOKEN_TTL)
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
            .with_ttl(SCREEN_LEG_TOKEN_TTL)
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
        let metadata = serde_json::to_string(&metadata).to_internal_error()?;

        self.sfu(
            node,
            room.client.create_room(
                channel.id(),
                CreateRoomOptions {
                    empty_timeout: 5 * 60, // 5 minutes,
                    metadata,
                    ..Default::default()
                },
            ),
        )
        .await
        .to_internal_error()
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

        self.sfu(
            node,
            room.client.update_participant(
                channel_id,
                identity,
                UpdateParticipantOptions {
                    permission: Some(new_permissions),
                    ..Default::default()
                },
            ),
        )
        .await
        .to_internal_error()
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

        match self
            .sfu(
                node,
                livekit.client.update_participant(
                    channel_id,
                    identity,
                    UpdateParticipantOptions {
                        permission: Some(new_permissions),
                        ..Default::default()
                    },
                ),
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(error) if is_twirp_not_found(&error) => Ok(false),
            // A real failure: ERROR log + Sentry (see the doc comment).
            Err(error) => Err::<bool, _>(error).to_internal_error(),
        }
    }

    /// Push a permission set to EVERY connection in `identities`, each
    /// addressed by its exact SFU identity (AFK S-3 D-4). The caller passes
    /// the connections the SFU LISTED for one user; nothing is resolved
    /// through the identity mapping and no leg is derived.
    ///
    /// A primary gets `primary`. A listed screen leg (`is_screen_leg`) gets
    /// [`screen_leg_participant_permissions`]`(&primary)`, NEVER the primary's
    /// set (no subscribe, no microphone, no camera, no data).
    ///
    /// Every push goes through [`Self::update_permissions_identity_if_present`]
    /// (a connection that has left meanwhile is an answer, a real failure is
    /// ERROR + Sentry there), every one is tried, and [`pushes_answer`]
    /// aggregates: the FIRST error after all were tried, else `Ok(true)` if
    /// any landed, else `Ok(false)` (every connection had already left).
    pub async fn update_permissions_connections(
        &self,
        node: &str,
        channel_id: &str,
        identities: &[String],
        primary: ParticipantPermission,
    ) -> Result<bool> {
        let leg = screen_leg_participant_permissions(&primary);

        let mut pushes = Vec::with_capacity(identities.len());
        for identity in identities {
            let permissions = if super::is_screen_leg(identity) {
                leg.clone()
            } else {
                primary.clone()
            };

            pushes.push(
                self.update_permissions_identity_if_present(
                    node,
                    identity,
                    channel_id,
                    permissions,
                )
                .await,
            );
        }

        pushes_answer(pushes)
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

        self.sfu(node, room.client.remove_participant(channel_id, identity))
            .await
            .to_internal_error()
    }

    /// The raw classification every "remove, not-found is an answer" path
    /// shares: `Ok(true)` removed, `Ok(false)` a Twirp `not_found` (see
    /// [`is_twirp_not_found`]), `Err` the SFU's own error, UNREPORTED, so
    /// each caller decides how loudly it counts. Under the D-5 deadline.
    async fn remove_participant_classified(
        &self,
        node: &str,
        livekit: &RoomClient,
        room: &str,
        identity: &str,
    ) -> std::result::Result<bool, ServiceError> {
        match self
            .sfu(node, livekit.client.remove_participant(room, identity))
            .await
        {
            Ok(()) => Ok(true),
            Err(error) if is_twirp_not_found(&error) => Ok(false),
            Err(error) => Err(error),
        }
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

        match self
            .remove_participant_classified(node, livekit, room, identity)
            .await
        {
            Ok(removed) => Ok(removed),
            Err(error) => {
                log::warn!("failed to remove SFU participant {identity} from room {room}: {error}");
                Err(create_error!(InternalError))
            }
        }
    }

    /// Remove EVERY connection of `user_id` the SFU lists in the room (AFK
    /// S-3 D-2): each primary, bare `{user}` or `{user}:{device}`, each
    /// listed screen leg, and the leg derived from each primary (best-effort,
    /// in case it joined after the listing), legs BEFORE their primary. The
    /// selection is `super::eviction_targets`, the same one the voice move
    /// uses, so `{user}` never matches another account whose id merely
    /// extends it.
    ///
    /// ONE listing, through the reporting [`Self::list_participants_reported`]
    /// (a failed read is ERROR + Sentry there and returned). Then every
    /// removal is issued, with NO early exit, before the outcome is judged by
    /// `super::eviction_result`.
    ///
    /// - `Ok(false)`: the SFU has no such room, or lists nothing of the user.
    /// - `Ok(true)`: every listed connection was removed or had already gone
    ///   (a `not_found` is success for an eviction).
    /// - `Err`: the FIRST real failure on a LISTED connection (a derived leg's
    ///   failure is logged and discarded), reported through
    ///   `to_internal_error()` with the SFU's own error, so ERROR + Sentry;
    ///   returned only after every removal was attempted. An unknown node is
    ///   `get_node`'s `UnknownNode`.
    ///
    /// Never resolves through the identity mapping: the mapping holds at most
    /// one connection per user, and this must reach all of them.
    ///
    /// The body is [`Self::evict_user_connections`], shared with
    /// [`Self::remove_user_if_present_sids`]: one listing, one eviction
    /// pass, whichever of the two answers the caller needs.
    pub async fn remove_user_if_present(
        &self,
        node: &str,
        user_id: &str,
        channel_id: &str,
    ) -> Result<bool> {
        Ok(self
            .evict_user_connections(node, user_id, channel_id)
            .await?
            .is_some_and(|evicted| evicted.any))
    }

    /// [`Self::remove_user_if_present`], answering WHICH connections it
    /// evicted (AFK S-3 WA-R, WA-1): the same single listing and the same
    /// eviction pass, with the same error semantics.
    ///
    /// - `Ok(None)`: the SFU has no such room.
    /// - `Ok(Some(sids))`: every listed connection of the user was removed
    ///   or had already gone, and `sids` is the LiveKit `ParticipantInfo.sid`
    ///   of every PRIMARY connection of the user in that ONE listing, in
    ///   listed order. Screen legs are excluded: they are never recorded in
    ///   `vc_conns:{channel}`. Empty when nothing of the user was listed, or
    ///   only a leg was. A listed primary with an empty sid is still evicted
    ///   but cannot be named, so it is left out of `sids` with a WARN.
    /// - `Err`: the first real failure, returned only after every removal was
    ///   attempted, exactly as [`Self::remove_user_if_present`]. No sids are
    ///   returned then: a caller must not tear down the record of a
    ///   connection that may still be live.
    ///
    /// The sids are what a set-mode teardown may delete: a connection that
    /// joined AFTER the listing is not among them, so its record, and the
    /// voice state it keeps alive, survive the teardown.
    pub async fn remove_user_if_present_sids(
        &self,
        node: &str,
        user_id: &str,
        channel_id: &str,
    ) -> Result<Option<Vec<String>>> {
        Ok(self
            .evict_user_connections(node, user_id, channel_id)
            .await?
            .map(|evicted| evicted.sids))
    }

    /// The shared body of [`Self::remove_user_if_present`] and
    /// [`Self::remove_user_if_present_sids`]: `Ok(None)` for no such room,
    /// else what was evicted (see [`UserEviction`]).
    async fn evict_user_connections(
        &self,
        node: &str,
        user_id: &str,
        channel_id: &str,
    ) -> Result<Option<UserEviction>> {
        let livekit = self.get_node(node)?;

        let Some(participants) = self.list_participants_reported(node, channel_id).await? else {
            return Ok(None);
        };

        let mut sids = Vec::new();
        for participant in &participants {
            if super::user_id_from_participant_identity(&participant.identity) != user_id
                || super::is_screen_leg(&participant.identity)
            {
                continue;
            }
            if participant.sid.is_empty() {
                log::warn!(
                    "the SFU listed {} in room {channel_id} with no sid; evicting it, but it \
                     cannot be named to the connection teardown",
                    participant.identity
                );
                continue;
            }
            sids.push(participant.sid.clone());
        }

        let targets = super::eviction_targets(
            participants
                .into_iter()
                .map(|participant| participant.identity),
            user_id,
        );
        if targets.is_empty() {
            return Ok(Some(UserEviction {
                any: false,
                sids: Vec::new(),
            }));
        }

        let mut outcomes = Vec::with_capacity(targets.len());
        for target in targets {
            let outcome = self
                .remove_participant_classified(node, livekit, channel_id, &target.identity)
                .await;
            if let Err(error) = &outcome {
                log::warn!(
                    "failed to remove SFU participant {} from room {channel_id}: {error}",
                    target.identity
                );
            }
            outcomes.push((target, outcome));
        }

        match super::eviction_result(outcomes) {
            Ok(()) => Ok(Some(UserEviction { any: true, sids })),
            Err(error) => Err::<Option<UserEviction>, _>(error).to_internal_error(),
        }
    }

    /// Remove exactly ONE connection, addressed by its exact SFU `identity`
    /// (the event identity at the voice-ingress enforcement sites, AFK S-3
    /// D-2/SR-2), plus the screen leg derived from it, best-effort and first.
    /// Never another connection of the same user, and no listing.
    ///
    /// A leg (three segments) gets no derived leg of its own: that would be
    /// a fourth segment the SFU has never heard of.
    ///
    /// `Ok(true)`: the SFU removed `identity`. `Ok(false)`: it was not in the
    /// room. `Err`: a real failure removing `identity`, reported through
    /// `to_internal_error()` with the SFU's own error (ERROR + Sentry). A
    /// real failure on the derived leg is logged at WARN and discarded; its
    /// `not_found` (almost everyone) is silent.
    pub async fn remove_connection_if_present(
        &self,
        node: &str,
        identity: &str,
        channel_id: &str,
    ) -> Result<bool> {
        let livekit = self.get_node(node)?;

        if super::participant_leg(identity).is_none() {
            let leg = super::screen_leg_identity(identity);
            if let Err(error) = self
                .remove_participant_classified(node, livekit, channel_id, &leg)
                .await
            {
                log::warn!(
                    "failed to remove SFU participant {leg} from room {channel_id}: {error}"
                );
            }
        }

        match self
            .remove_participant_classified(node, livekit, channel_id, identity)
            .await
        {
            Ok(removed) => Ok(removed),
            Err(error) => Err::<bool, _>(error).to_internal_error(),
        }
    }

    /// The raw classification both listings share: `Ok(Some(list))`,
    /// `Ok(None)` for a Twirp `not_found` (no such room), or the SFU's own
    /// error UNREPORTED, so each listing decides how loudly it counts. The
    /// outer `Err` is `get_node`'s `UnknownNode`. Under the D-5 deadline.
    async fn list_participants_classified(
        &self,
        node: &str,
        room: &str,
    ) -> Result<std::result::Result<Option<Vec<ParticipantInfo>>, ServiceError>> {
        let livekit = self.get_node(node)?;

        Ok(
            match self.sfu(node, livekit.client.list_participants(room)).await {
                Ok(participants) => Ok(Some(participants)),
                Err(error) if is_twirp_not_found(&error) => Ok(None),
                Err(error) => Err(error),
            },
        )
    }

    /// [`Self::list_participants_if_present`] for callers whose failed read
    /// is an INCIDENT, not a routine miss (AFK S-3 D-4, RB-2): the roster
    /// that drives a permission sync or a removal. Same classification
    /// (`Ok(None)` = no such room), but a real failure goes through
    /// `to_internal_error()` with the SFU's own error: exactly one ERROR log
    /// and one Sentry event, carrying the cause, and no WARN beside it.
    pub async fn list_participants_reported(
        &self,
        node: &str,
        room: &str,
    ) -> Result<Option<Vec<ParticipantInfo>>> {
        match self.list_participants_classified(node, room).await? {
            Ok(listed) => Ok(listed),
            Err(error) => Err::<_, _>(error).to_internal_error(),
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
    /// for a user sitting in a room TWICE — the voice-move eviction, and the
    /// moderation removals through [`Self::remove_user_if_present_sids`]
    /// (kick, ban, disconnect) — it has to be made against this, not against
    /// Redis.
    ///
    /// `Ok(Some(list))`: the SFU's participants. `Ok(None)`: the SFU says the
    /// room does not exist (a Twirp `not_found`, see [`is_twirp_not_found`]),
    /// so nobody is connected to it. `Err`: anything else, including a
    /// non-JSON 404; an unknown node is `get_node`'s `UnknownNode`. Read-only,
    /// so unlike [`Self::remove_connection_if_present`], whose screen-leg
    /// removal is best-effort, it has no best-effort half: the caller decides
    /// what an unanswered SFU means for its own operation.
    ///
    /// A room the SFU no longer has must read as "not connected", not as a
    /// 500 plus a Sentry event on every sweep tick. Like
    /// [`Self::remove_identity_if_present`] it classifies the raw answer
    /// first, because `to_internal_error()` logs at ERROR and reports to
    /// Sentry before the caller can classify the result; a real failure is
    /// logged here at WARN only (the move and the AFK sweep). Its one twin,
    /// [`Self::list_participants_reported`], shares the classification and
    /// reports a real failure instead. Do not add a plain
    /// `to_internal_error()` listing beside them: that would turn "no such
    /// room" into a 500.
    pub async fn list_participants_if_present(
        &self,
        node: &str,
        room: &str,
    ) -> Result<Option<Vec<ParticipantInfo>>> {
        match self.list_participants_classified(node, room).await? {
            Ok(listed) => Ok(listed),
            Err(error) => {
                log::warn!("failed to list SFU participants of room {room}: {error}");
                Err(create_error!(InternalError))
            }
        }
    }

    /// Server-side mute one published track of a participant addressed by an
    /// EXACT SFU identity (media E2EE plan D12 video-cap enable leg,
    /// android-screen-share plan §2.4): an over-cap or forbidden track is
    /// refused without kicking the connection from the whole call.
    ///
    /// The only track mute there is. Its mapping-resolving twin
    /// (`mute_track`, which resolved the PRIMARY through the identity
    /// mapping) was deleted in the S-3 cleanup: a leg is deliberately absent
    /// from that mapping, so pointed at a leg's track it asked the SFU to
    /// mute a sid that belonged to a different participant, LiveKit refused,
    /// and the offending track stayed live. The caller passes the identity of
    /// the connection that published the track (the event identity).
    pub async fn mute_track_identity(
        &self,
        node: &str,
        identity: &str,
        channel_id: &str,
        track_sid: &str,
    ) -> Result<()> {
        let room = self.get_node(node)?;

        self.sfu(
            node,
            room.client
                .mute_published_track(channel_id, identity, track_sid, true),
        )
        .await
        .map(|_| ())
        .to_internal_error()
    }

    pub async fn delete_room(&self, node: &str, channel_id: &str) -> Result<()> {
        let room = self.get_node(node)?;

        self.sfu(node, room.client.delete_room(channel_id))
            .await
            .to_internal_error()
    }
}

/// What [`VoiceClient::update_permissions_connections`]'s pushes to the
/// listed connections amount to: the FIRST error when any failed (after all
/// were tried), else `Ok(true)` if any landed, else `Ok(false)` (every listed
/// connection left in the meantime). Pure.
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

/// A loopback mock of the LiveKit Twirp room service, for tests that call the
/// REAL `VoiceClient` methods (AFK S-3). Shared with the sibling voice test
/// modules as `super::voice_client::sfu_stub`.
///
/// - [`Stub::serve`] accepts any number of connections, one request each
///   (every reply says `connection: close`), and answers each through the
///   responder `Fn(path, body) -> (status line, content type, body)`.
///   [`routes`] builds a responder from a path table; a path it does not
///   list gets a Twirp 500 (`internal`).
/// - [`Stub::silent`] accepts and reads every request and never answers, so
///   a call without the client-side deadline hangs. [`Stub::set_silent`]
///   flips an existing stub either way.
/// - [`Stub::finish`] stops the stub and returns every request it read, in
///   order, as `(path, identity)`. The identity is protobuf field 2 of the
///   request body (`RoomParticipantIdentity`, `UpdateParticipantRequest`,
///   `MuteRoomTrackRequest`), empty when the request has none (a listing).
///   [`Stub::seen`] is the same list, read without stopping.
/// - [`permission`] decodes the permission an `UpdateParticipant` request
///   carries; [`list_participants_response`] encodes a multi-participant
///   `ListParticipants` answer; [`mute_track_response`] is the body a
///   `MutePublishedTrack` 200 needs (an empty 200 panics livekit-api).
///
/// No `prost` in this crate, so the wire format is spelled out by hand;
/// `stub_decodes_what_the_real_client_sends` proves it against requests the
/// real client encodes. Keep braces balanced in strings here (the workspace
/// scans strip test-gated items by brace matching).
#[cfg(test)]
pub(crate) mod sfu_stub {
    use super::VoiceClient;
    use livekit_protocol::ParticipantPermission;
    use revolt_config::LiveKitNode;
    use std::{
        collections::HashMap,
        io::{Read, Write},
        net::{SocketAddr, TcpListener, TcpStream},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex, PoisonError,
        },
        thread::JoinHandle,
        time::Duration,
    };

    /// The node name [`voice_client`] registers the stub under.
    pub(crate) const NODE: &str = "sfu-stub-node";

    pub(crate) const CREATE_ROOM: &str = "/twirp/livekit.RoomService/CreateRoom";
    pub(crate) const DELETE_ROOM: &str = "/twirp/livekit.RoomService/DeleteRoom";
    pub(crate) const LIST: &str = "/twirp/livekit.RoomService/ListParticipants";
    pub(crate) const REMOVE: &str = "/twirp/livekit.RoomService/RemoveParticipant";
    pub(crate) const UPDATE: &str = "/twirp/livekit.RoomService/UpdateParticipant";
    pub(crate) const MUTE: &str = "/twirp/livekit.RoomService/MutePublishedTrack";

    /// (status line, content type, body)
    pub(crate) type Reply = (&'static str, &'static str, Vec<u8>);

    /// A Twirp 200 with a protobuf body (empty decodes as the default
    /// message, which is what every mutation's answer is here).
    pub(crate) fn ok(body: impl Into<Vec<u8>>) -> Reply {
        ("HTTP/1.1 200 OK", "application/protobuf", body.into())
    }

    /// The SFU's structured "no such participant / room".
    pub(crate) fn not_found() -> Reply {
        (
            "HTTP/1.1 404 Not Found",
            "application/json",
            br#"{"code":"not_found","msg":"stub: not found"}"#.to_vec(),
        )
    }

    /// A real SFU failure (and the answer to any path [`routes`] lacks).
    pub(crate) fn internal() -> Reply {
        (
            "HTTP/1.1 500 Internal Server Error",
            "application/json",
            br#"{"code":"internal","msg":"stub: boom"}"#.to_vec(),
        )
    }

    /// A responder answering each listed path with its reply, and every
    /// other path with [`internal`].
    pub(crate) fn routes(
        table: Vec<(&'static str, Reply)>,
    ) -> impl Fn(&str, &[u8]) -> Reply + Send + 'static {
        move |path, _| {
            table
                .iter()
                .find(|(listed, _)| *listed == path)
                .map(|(_, reply)| reply.clone())
                .unwrap_or_else(internal)
        }
    }

    fn node(url: &str) -> LiveKitNode {
        LiveKitNode {
            url: url.to_string(),
            lat: 0.0,
            lon: 0.0,
            key: "stubkey".to_string(),
            secret: "stubsecret-stubsecret-stubsecret".to_string(),
            private: true,
            remote: false,
        }
    }

    /// A `VoiceClient` with one node, [`NODE`], pointing at `url`, with the
    /// production bounds.
    pub(crate) fn voice_client(url: &str) -> VoiceClient {
        VoiceClient::new(HashMap::from([(NODE.to_string(), node(url))]))
    }

    /// [`voice_client`] with an injected per-call bound and breaker window.
    pub(crate) fn voice_client_with_bounds(
        url: &str,
        timeout: Duration,
        breaker_window: Duration,
    ) -> VoiceClient {
        voice_client(url).with_sfu_bounds(timeout, breaker_window)
    }

    /// A `VoiceClient` whose nodes are `(name, url)` pairs.
    pub(crate) fn voice_client_nodes(
        nodes: &[(&str, &str)],
        timeout: Duration,
        breaker_window: Duration,
    ) -> VoiceClient {
        VoiceClient::new(
            nodes
                .iter()
                .map(|(name, url)| (name.to_string(), node(url)))
                .collect(),
        )
        .with_sfu_bounds(timeout, breaker_window)
    }

    pub(crate) struct Stub {
        url: String,
        addr: SocketAddr,
        silent: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
        seen: Arc<Mutex<Vec<(String, String)>>>,
        thread: Option<JoinHandle<()>>,
    }

    impl Stub {
        /// Answer every request through `responder`.
        pub(crate) fn serve(responder: impl Fn(&str, &[u8]) -> Reply + Send + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
            let addr = listener.local_addr().expect("local addr");
            let silent = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));
            let seen = Arc::new(Mutex::new(Vec::new()));

            let thread = {
                let (silent, stop, seen) = (silent.clone(), stop.clone(), seen.clone());
                std::thread::spawn(move || {
                    // Unanswered connections stay open until the stub stops.
                    let mut held = Vec::new();
                    for stream in listener.incoming() {
                        if stop.load(Ordering::SeqCst) {
                            break;
                        }
                        let Ok(mut stream) = stream else { continue };
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let Some((head, body)) = read_request(&mut stream) else {
                            continue;
                        };
                        let path = head
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or_default()
                            .to_string();
                        seen.lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push((path.clone(), identity(&body).unwrap_or_default()));

                        if silent.load(Ordering::SeqCst) {
                            held.push(stream);
                            continue;
                        }
                        let reply = responder(&path, &body);
                        let _ = write_response(&mut stream, &reply);
                    }
                })
            };

            Stub {
                url: format!("http://{addr}"),
                addr,
                silent,
                stop,
                seen,
                thread: Some(thread),
            }
        }

        /// Read every request, answer none.
        pub(crate) fn silent() -> Self {
            let stub = Self::serve(|_, _| internal());
            stub.set_silent(true);
            stub
        }

        pub(crate) fn url(&self) -> &str {
            &self.url
        }

        pub(crate) fn set_silent(&self, silent: bool) {
            self.silent.store(silent, Ordering::SeqCst);
        }

        /// Every request read so far, in order, as `(path, identity)`.
        pub(crate) fn seen(&self) -> Vec<(String, String)> {
            self.seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        /// Stop the stub (after it has read every request already made) and
        /// return every request it read, in order, as `(path, identity)`.
        pub(crate) fn finish(mut self) -> Vec<(String, String)> {
            if let Some(thread) = self.stop_thread() {
                thread.join().expect("the SFU stub thread panicked");
            }
            self.seen()
        }

        fn stop_thread(&mut self) -> Option<JoinHandle<()>> {
            let thread = self.thread.take()?;
            self.stop.store(true, Ordering::SeqCst);
            // Wake the blocking accept; the loop sees `stop` and ends.
            let _ = TcpStream::connect(self.addr);
            Some(thread)
        }
    }

    impl Drop for Stub {
        fn drop(&mut self) {
            if let Some(thread) = self.stop_thread() {
                let _ = thread.join();
            }
        }
    }

    /// Read one whole HTTP request (head plus `content-length` body, so
    /// closing never resets an unread request). `None` if the peer closed
    /// or stalled first.
    pub(crate) fn read_request(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
        let mut request = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = stream.read(&mut chunk).ok()?;
            if read == 0 {
                return None;
            }
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
                    let body = request[end + 4..end + 4 + length].to_vec();
                    return Some((head, body));
                }
            }
        }
    }

    /// Write one reply and let the connection close.
    pub(crate) fn write_response(stream: &mut TcpStream, reply: &Reply) -> std::io::Result<()> {
        let (status_line, content_type, body) = reply;
        let mut response = format!(
            "{status_line}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        stream.write_all(&response)
    }

    /// One decoded top-level protobuf field.
    pub(crate) enum Field<'a> {
        Varint(u64),
        Bytes(&'a [u8]),
        Fixed,
    }

    fn varint(buf: &mut &[u8]) -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let (&byte, rest) = buf.split_first()?;
            *buf = rest;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    /// The top-level fields of a protobuf message, as (tag, value). Stops at
    /// the first malformed byte.
    pub(crate) fn fields(mut buf: &[u8]) -> Vec<(u64, Field<'_>)> {
        let mut out = Vec::new();
        while !buf.is_empty() {
            let Some(key) = varint(&mut buf) else { break };
            let field = match key & 7 {
                0 => match varint(&mut buf) {
                    Some(value) => Field::Varint(value),
                    None => break,
                },
                2 => {
                    let Some(length) = varint(&mut buf) else {
                        break;
                    };
                    let length = length as usize;
                    if buf.len() < length {
                        break;
                    }
                    let (bytes, rest) = buf.split_at(length);
                    buf = rest;
                    Field::Bytes(bytes)
                }
                1 if buf.len() >= 8 => {
                    buf = &buf[8..];
                    Field::Fixed
                }
                5 if buf.len() >= 4 => {
                    buf = &buf[4..];
                    Field::Fixed
                }
                _ => break,
            };
            out.push((key >> 3, field));
        }
        out
    }

    /// Protobuf field 2 of a request body as a string: the participant
    /// identity of `RemoveParticipant`, `UpdateParticipant` and
    /// `MutePublishedTrack`.
    pub(crate) fn identity(body: &[u8]) -> Option<String> {
        fields(body)
            .into_iter()
            .find_map(|(tag, field)| match field {
                Field::Bytes(bytes) if tag == 2 => Some(String::from_utf8_lossy(bytes).to_string()),
                _ => None,
            })
    }

    /// The `permission` (field 4) of an `UpdateParticipantRequest` body.
    pub(crate) fn permission(body: &[u8]) -> Option<ParticipantPermission> {
        let bytes = fields(body)
            .into_iter()
            .find_map(|(tag, field)| match field {
                Field::Bytes(bytes) if tag == 4 => Some(bytes),
                _ => None,
            })?;

        let mut permission = ParticipantPermission::default();
        for (tag, field) in fields(bytes) {
            match (tag, field) {
                (1, Field::Varint(value)) => permission.can_subscribe = value != 0,
                (2, Field::Varint(value)) => permission.can_publish = value != 0,
                (3, Field::Varint(value)) => permission.can_publish_data = value != 0,
                (9, Field::Varint(value)) => permission.can_publish_sources.push(value as i32),
                (9, Field::Bytes(mut packed)) => {
                    while let Some(value) = varint(&mut packed) {
                        permission.can_publish_sources.push(value as i32);
                    }
                }
                _ => {}
            }
        }
        Some(permission)
    }

    fn encode_varint(mut value: usize, out: &mut Vec<u8>) {
        while value >= 0x80 {
            out.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }

    fn length_delimited(tag: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![(tag << 3) | 2];
        encode_varint(payload.len(), &mut out);
        out.extend_from_slice(payload);
        out
    }

    /// Protobuf wire bytes of a `MuteRoomTrackResponse` carrying an empty
    /// `track` (field 1). livekit-api unwraps that field, so a
    /// `MutePublishedTrack` 200 must carry it or the CLIENT panics.
    pub(crate) fn mute_track_response() -> Vec<u8> {
        length_delimited(1, &[])
    }

    /// Protobuf wire bytes of a `ListParticipantsResponse` listing each
    /// `(identity, conn)` in order: `identity` = ParticipantInfo field 2,
    /// and a `conn` attribute (field 15, map entry key 1 / value 2) when
    /// `conn` is non-empty.
    pub(crate) fn list_participants_response(participants: &[(&str, &str)]) -> Vec<u8> {
        let with_no_sid: Vec<(&str, &str, &str)> = participants
            .iter()
            .map(|(identity, conn)| ("", *identity, *conn))
            .collect();
        list_participants_response_sids(&with_no_sid)
    }

    /// [`list_participants_response`] listing each `(sid, identity, conn)`:
    /// `sid` = ParticipantInfo field 1, omitted when empty (so it decodes as
    /// the empty string, as proto3 does for a missing field).
    pub(crate) fn list_participants_response_sids(participants: &[(&str, &str, &str)]) -> Vec<u8> {
        participants
            .iter()
            .flat_map(|(sid, identity, conn)| {
                let mut participant = if sid.is_empty() {
                    Vec::new()
                } else {
                    length_delimited(1, sid.as_bytes())
                };
                participant.extend(length_delimited(2, identity.as_bytes()));
                if !conn.is_empty() {
                    let entry = [
                        length_delimited(1, b"conn"),
                        length_delimited(2, conn.as_bytes()),
                    ]
                    .concat();
                    participant.extend(length_delimited(15, &entry));
                }
                length_delimited(1, &participant)
            })
            .collect()
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
    /// back the request head for inspection. The request reading and the
    /// reply writing are `sfu_stub`'s, shared with the multi-connection stub.
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
            let (head, _) = super::sfu_stub::read_request(&mut stream)
                .expect("client closed before sending a full request");
            super::sfu_stub::write_response(&mut stream, &(status_line, content_type, body))
                .expect("write response");
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
    /// spelled out (by `sfu_stub`, which also encodes multi-participant
    /// lists); the test that decodes them through the real client and checks
    /// every field is what proves they are right.
    fn list_participants_response(identity: &str, conn: &str) -> Vec<u8> {
        super::sfu_stub::list_participants_response(&[(identity, conn)])
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
    pub(super) fn shipping_method(definition: &str) -> String {
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

/// `pushes_answer`, by value. (The RA-1 `not_found_answer` decision that
/// shared this module was deleted with `update_permissions_if_present` in
/// the S-3 cleanup: nothing resolves a push through the mapping any more.)
#[cfg(test)]
mod pushes_answer_tests {
    use super::pushes_answer;

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

/// AFK S-3 Wave A1: removal of every connection, the roster-driven push, the
/// reporting listing (RB-2), the SFU call deadline and the per-node breaker
/// (D-2, D-4, D-5). Every behavioural test calls the REAL `VoiceClient`
/// method against `sfu_stub`. No method resolves the identity mapping any
/// more (S-3 cleanup), so none needs Redis.
#[cfg(test)]
mod sfu_s3_tests {
    use super::{
        conn_nonce_and_removal_tests::shipping_method,
        is_twirp_not_found, sfu_deadline_error,
        sfu_stub::{
            self, internal, list_participants_response, list_participants_response_sids,
            not_found, ok, routes, Reply, Stub, CREATE_ROOM, DELETE_ROOM, LIST, MUTE, NODE,
            REMOVE, UPDATE,
        },
        VoiceClient, MOVE_TOKEN_TTL, SCREEN_LEG_TOKEN_TTL, SFU_BREAKER_WINDOW, SFU_CALL_TIMEOUT,
    };
    use crate::{
        models::{Channel, User},
        Database,
    };
    use livekit_api::access_token::Claims;
    use livekit_protocol::{ParticipantInfo, ParticipantPermission, TrackSource};
    use revolt_permissions::{ChannelPermission, PermissionValue};
    use revolt_result::{ErrorType, Result};
    use std::{
        fmt::Debug,
        future::Future,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    const U: &str = "01KUSERAAAAAAAAAAAAAAAAAAA";
    const V: &str = "01KUSERBBBBBBBBBBBBBBBBBBB";
    /// Another account whose id EXTENDS `U`: never one of `U`'s connections.
    const UX: &str = "01KUSERAAAAAAAAAAAAAAAAAAAX";
    const ROOM: &str = "room";
    /// The injected per-call bound.
    const BOUND: Duration = Duration::from_millis(150);
    /// The outer bound every deadline case runs under, so a call with no
    /// client-side deadline FAILS instead of hanging the suite.
    const OUTER: Duration = Duration::from_secs(2);

    fn requests(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(path, identity)| (path.to_string(), identity.to_string()))
            .collect()
    }

    fn is_internal<T>(result: &Result<T>) -> bool {
        matches!(result, Err(error) if matches!(error.error_type, ErrorType::InternalError))
    }

    /// A stub listing `roster` and answering each `RemoveParticipant` with
    /// `remove(identity)`.
    fn removal_stub(roster: &[&str], remove: impl Fn(&str) -> Reply + Send + 'static) -> Stub {
        let pairs: Vec<(&str, &str)> = roster.iter().map(|identity| (*identity, "")).collect();
        let listing = list_participants_response(&pairs);
        Stub::serve(move |path, body| match path {
            LIST => ok(listing.clone()),
            REMOVE => remove(&sfu_stub::identity(body).unwrap_or_default()),
            _ => internal(),
        })
    }

    // ---- the stub itself ----

    /// Baseline for every stub-driven test: what the stub records is what the
    /// REAL client encoded (identity = protobuf field 2, the pushed
    /// permission), a multi-participant listing it encodes decodes through
    /// the real client, and a path the responder does not know is a 500.
    #[tokio::test]
    async fn stub_decodes_what_the_real_client_sends() {
        let ud = format!("{U}:D");
        let pushed = Arc::new(Mutex::new(Vec::new()));
        let listing = list_participants_response(&[(U, "n1"), (&ud, "n2")]);
        let stub = {
            let pushed = pushed.clone();
            Stub::serve(move |path, body| match path {
                UPDATE => {
                    pushed.lock().unwrap().push(sfu_stub::permission(body));
                    ok(Vec::new())
                }
                REMOVE => ok(Vec::new()),
                MUTE => ok(sfu_stub::mute_track_response()),
                LIST => ok(listing.clone()),
                _ => internal(),
            })
        };
        let voice = sfu_stub::voice_client(stub.url());
        let permission = ParticipantPermission {
            can_subscribe: true,
            can_publish: true,
            can_publish_sources: vec![
                TrackSource::Microphone as i32,
                TrackSource::ScreenShare as i32,
            ],
            ..Default::default()
        };

        assert!(matches!(
            voice
                .remove_identity_if_present(NODE, "user:DEVICE", ROOM)
                .await,
            Ok(true)
        ));
        assert!(matches!(
            voice
                .update_permissions_identity_if_present(NODE, "user:D2", ROOM, permission.clone())
                .await,
            Ok(true)
        ));
        assert!(voice
            .mute_track_identity(NODE, "user:D3", ROOM, "TR_1")
            .await
            .is_ok());
        match voice.list_participants_if_present(NODE, ROOM).await {
            Ok(Some(participants)) => {
                let listed: Vec<(&str, Option<&str>)> = participants
                    .iter()
                    .map(|p| {
                        (
                            p.identity.as_str(),
                            p.attributes.get("conn").map(String::as_str),
                        )
                    })
                    .collect();
                assert_eq!(listed, vec![(U, Some("n1")), (ud.as_str(), Some("n2"))]);
            }
            other => panic!("a 200 listing must be Ok(Some(..)), got {other:?}"),
        }
        let unknown = voice.delete_room(NODE, ROOM).await;
        assert!(
            is_internal(&unknown),
            "an unknown path is a 500: {unknown:?}"
        );

        assert_eq!(
            stub.finish(),
            requests(&[
                (REMOVE, "user:DEVICE"),
                (UPDATE, "user:D2"),
                (MUTE, "user:D3"),
                (LIST, ""),
                (DELETE_ROOM, ""),
            ])
        );
        assert_eq!(*pushed.lock().unwrap(), vec![Some(permission)]);
    }

    // ---- D-2: remove_user_if_present ----

    /// `[U, U:D, V, UX:B]` evicts exactly U's connections, each with its
    /// derived leg first, and never V or the account whose id extends U's.
    #[tokio::test]
    async fn remove_user_if_present_evicts_every_connection_of_the_user_legs_first() {
        let ud = format!("{U}:D");
        let uxb = format!("{UX}:B");
        let stub = removal_stub(&[U, &ud, V, &uxb], |_| ok(Vec::new()));

        let result = sfu_stub::voice_client(stub.url())
            .remove_user_if_present(NODE, U, ROOM)
            .await;
        let seen = stub.finish();

        assert!(matches!(result, Ok(true)), "{result:?}");
        assert_eq!(
            seen,
            requests(&[
                (LIST, ""),
                (REMOVE, &format!("{U}::screen")),
                (REMOVE, U),
                (REMOVE, &format!("{ud}:screen")),
                (REMOVE, &ud),
            ])
        );
    }

    /// A listed connection that is already gone (not_found) is success, and
    /// every other connection is still evicted.
    #[tokio::test]
    async fn remove_user_if_present_counts_not_found_as_evicted() {
        let ud = format!("{U}:D");
        let gone = ud.clone();
        let stub = removal_stub(&[U, &ud], move |identity| {
            if identity == gone {
                not_found()
            } else {
                ok(Vec::new())
            }
        });

        let result = sfu_stub::voice_client(stub.url())
            .remove_user_if_present(NODE, U, ROOM)
            .await;
        let seen = stub.finish();

        assert!(matches!(result, Ok(true)), "{result:?}");
        assert_eq!(seen.len(), 5, "a list and four removals: {seen:?}");
    }

    /// A real failure on a LISTED connection is an error, returned only
    /// after every eviction was attempted; a real failure on a DERIVED leg
    /// is discarded.
    #[tokio::test]
    async fn remove_user_if_present_fails_after_attempting_every_eviction() {
        let ud = format!("{U}:D");
        let every = requests(&[
            (LIST, ""),
            (REMOVE, &format!("{U}::screen")),
            (REMOVE, U),
            (REMOVE, &format!("{ud}:screen")),
            (REMOVE, &ud),
        ]);

        let stub = removal_stub(&[U, &ud], |identity| {
            if identity == U {
                internal()
            } else {
                ok(Vec::new())
            }
        });
        let result = sfu_stub::voice_client(stub.url())
            .remove_user_if_present(NODE, U, ROOM)
            .await;
        assert!(is_internal(&result), "{result:?}");
        assert_eq!(stub.finish(), every, "no early exit after the failure");

        let leg = format!("{U}::screen");
        let stub = removal_stub(&[U, &ud], move |identity| {
            if identity == leg {
                internal()
            } else {
                ok(Vec::new())
            }
        });
        let result = sfu_stub::voice_client(stub.url())
            .remove_user_if_present(NODE, U, ROOM)
            .await;
        assert!(matches!(result, Ok(true)), "{result:?}");
        assert_eq!(stub.finish(), every);
    }

    /// `Ok(false)`, after ONE request: the room is gone, or nothing of the
    /// user is listed. A failed listing is an error, after one request.
    #[tokio::test]
    async fn remove_user_if_present_answers_false_when_nothing_of_the_user_is_listed() {
        let stub = Stub::serve(routes(vec![(LIST, not_found())]));
        let result = sfu_stub::voice_client(stub.url())
            .remove_user_if_present(NODE, U, ROOM)
            .await;
        assert!(matches!(result, Ok(false)), "room gone: {result:?}");
        assert_eq!(stub.finish(), requests(&[(LIST, "")]));

        let uxb = format!("{UX}:B");
        for roster in [vec![V, uxb.as_str()], vec![]] {
            let stub = removal_stub(&roster, |_| ok(Vec::new()));
            let result = sfu_stub::voice_client(stub.url())
                .remove_user_if_present(NODE, U, ROOM)
                .await;
            assert!(matches!(result, Ok(false)), "{roster:?}: {result:?}");
            assert_eq!(stub.finish(), requests(&[(LIST, "")]), "{roster:?}");
        }

        let stub = Stub::serve(routes(vec![(LIST, internal())]));
        let result = sfu_stub::voice_client(stub.url())
            .remove_user_if_present(NODE, U, ROOM)
            .await;
        assert!(is_internal(&result), "a failed listing: {result:?}");
        assert_eq!(stub.finish(), requests(&[(LIST, "")]));
    }

    /// Only a leg of the user is listed: that leg is evicted, and no leg is
    /// derived from a leg.
    #[tokio::test]
    async fn remove_user_if_present_evicts_a_lone_listed_leg() {
        let leg = format!("{U}:D:screen");
        let stub = removal_stub(&[&leg, V], |_| ok(Vec::new()));
        let result = sfu_stub::voice_client(stub.url())
            .remove_user_if_present(NODE, U, ROOM)
            .await;
        assert!(matches!(result, Ok(true)), "{result:?}");
        assert_eq!(stub.finish(), requests(&[(LIST, ""), (REMOVE, &leg)]));
    }

    // ---- D-2: remove_connection_if_present ----

    /// Exactly the addressed connection plus its derived leg, leg first,
    /// never another connection of the same user, and no listing.
    #[tokio::test]
    async fn remove_connection_if_present_addresses_only_that_connection() {
        let ud = format!("{U}:D");
        let leg = format!("{ud}:screen");
        let bare_leg = format!("{U}::screen");
        for (identity, expected) in [
            (
                ud.as_str(),
                vec![(REMOVE, leg.as_str()), (REMOVE, ud.as_str())],
            ),
            (U, vec![(REMOVE, bare_leg.as_str()), (REMOVE, U)]),
            (leg.as_str(), vec![(REMOVE, leg.as_str())]),
        ] {
            let stub = removal_stub(&[U, &ud, &leg], |_| ok(Vec::new()));
            let result = sfu_stub::voice_client(stub.url())
                .remove_connection_if_present(NODE, identity, ROOM)
                .await;
            let seen = stub.finish();
            assert!(matches!(result, Ok(true)), "{identity}: {result:?}");
            assert_eq!(seen, requests(&expected), "{identity}");
        }
    }

    /// `Ok(false)` when the connection is not there; a real failure on it
    /// is an error, a real failure on its derived leg is not.
    #[tokio::test]
    async fn remove_connection_if_present_classifies_the_answer() {
        let ud = format!("{U}:D");
        let leg = format!("{ud}:screen");

        let stub = Stub::serve(routes(vec![(REMOVE, not_found())]));
        let result = sfu_stub::voice_client(stub.url())
            .remove_connection_if_present(NODE, &ud, ROOM)
            .await;
        assert!(matches!(result, Ok(false)), "{result:?}");
        assert_eq!(stub.finish().len(), 2);

        let primary = ud.clone();
        let stub = removal_stub(&[], move |identity| {
            if identity == primary {
                internal()
            } else {
                ok(Vec::new())
            }
        });
        let result = sfu_stub::voice_client(stub.url())
            .remove_connection_if_present(NODE, &ud, ROOM)
            .await;
        assert!(is_internal(&result), "{result:?}");
        assert_eq!(stub.finish().len(), 2);

        let failing_leg = leg.clone();
        let stub = removal_stub(&[], move |identity| {
            if identity == failing_leg {
                internal()
            } else {
                ok(Vec::new())
            }
        });
        let result = sfu_stub::voice_client(stub.url())
            .remove_connection_if_present(NODE, &ud, ROOM)
            .await;
        assert!(matches!(result, Ok(true)), "{result:?}");
        assert_eq!(stub.finish(), requests(&[(REMOVE, &leg), (REMOVE, &ud)]));
    }

    // ---- D-4: update_permissions_connections ----

    /// The roster `[u, u:A, u:A:screen, v]`, grouped to u's connections by
    /// the real `user_id_from_participant_identity`: exactly three pushes,
    /// the primaries get the primary set, the LISTED leg gets the leg set
    /// (no subscribe, no microphone), and nothing is derived or sent to v.
    #[tokio::test]
    async fn update_permissions_connections_pushes_each_listed_connection_its_own_set() {
        let roster = [
            U.to_string(),
            format!("{U}:A"),
            format!("{U}:A:screen"),
            V.to_string(),
        ];
        let connections: Vec<String> = roster
            .iter()
            .filter(|identity| super::super::user_id_from_participant_identity(identity) == U)
            .cloned()
            .collect();

        let pushed = Arc::new(Mutex::new(Vec::new()));
        let stub = {
            let pushed = pushed.clone();
            Stub::serve(move |path, body| {
                if path != UPDATE {
                    return internal();
                }
                pushed.lock().unwrap().push((
                    sfu_stub::identity(body).unwrap_or_default(),
                    sfu_stub::permission(body).expect("an UpdateParticipant carries a permission"),
                ));
                ok(Vec::new())
            })
        };
        let primary = ParticipantPermission {
            can_subscribe: true,
            can_publish: true,
            can_publish_sources: vec![
                TrackSource::Microphone as i32,
                TrackSource::Camera as i32,
                TrackSource::ScreenShare as i32,
            ],
            ..Default::default()
        };

        let result = sfu_stub::voice_client(stub.url())
            .update_permissions_connections(NODE, ROOM, &connections, primary.clone())
            .await;
        let seen = stub.finish();

        assert!(matches!(result, Ok(true)), "{result:?}");
        assert_eq!(
            seen,
            requests(&[
                (UPDATE, U),
                (UPDATE, &format!("{U}:A")),
                (UPDATE, &format!("{U}:A:screen")),
            ]),
            "exactly the three listed connections of u"
        );

        let pushed = pushed.lock().unwrap();
        assert_eq!(pushed.len(), 3);
        for (identity, permission) in pushed.iter() {
            if identity.ends_with(":screen") {
                assert!(!permission.can_subscribe, "the leg never subscribes");
                assert!(
                    !permission
                        .can_publish_sources
                        .contains(&(TrackSource::Microphone as i32)),
                    "the leg never gets the microphone: {permission:?}"
                );
                assert_eq!(
                    permission.can_publish_sources,
                    vec![TrackSource::ScreenShare as i32]
                );
                assert!(permission.can_publish);
            } else {
                assert_eq!(permission, &primary, "{identity} gets the primary set");
            }
        }
    }

    /// Every push is tried: the first real failure is returned after all;
    /// all gone is `Ok(false)`; any landed is `Ok(true)`.
    #[tokio::test]
    async fn update_permissions_connections_tries_every_push_before_answering() {
        let connections = vec![U.to_string(), format!("{U}:A"), format!("{U}:A:screen")];

        for (answer, expected) in [
            ("first fails", None),
            ("all gone", Some(false)),
            ("one gone", Some(true)),
        ] {
            let stub = Stub::serve(move |_, body| {
                let identity = sfu_stub::identity(body).unwrap_or_default();
                match answer {
                    "first fails" if identity == U => internal(),
                    "all gone" => not_found(),
                    "one gone" if identity == U => not_found(),
                    _ => ok(Vec::new()),
                }
            });
            let result = sfu_stub::voice_client(stub.url())
                .update_permissions_connections(NODE, ROOM, &connections, Default::default())
                .await;
            assert_eq!(stub.finish().len(), 3, "{answer}: every push is tried");
            match expected {
                None => assert!(is_internal(&result), "{answer}: {result:?}"),
                Some(expected) => assert!(
                    matches!(result, Ok(landed) if landed == expected),
                    "{answer}: {result:?}"
                ),
            }
        }
    }

    // ---- D-5: the deadline ----

    /// Run one call against a silent stub under [`OUTER`]: it must come back
    /// on its own, as `Err(InternalError)` (never an `Ok` "gone" answer), no
    /// sooner than the injected bound, and after the stub saw its request.
    async fn expect_deadline<T: Debug>(
        name: &str,
        path: &str,
        stub: Stub,
        call: impl Future<Output = Result<T>>,
    ) {
        let started = Instant::now();
        let outcome = tokio::time::timeout(OUTER, call).await;
        let elapsed = started.elapsed();
        let seen = stub.finish();

        let result = outcome.unwrap_or_else(|_| {
            panic!("{name}: still waiting after {OUTER:?}, so it has no client-side deadline")
        });
        match &result {
            Err(error) => assert!(
                matches!(error.error_type, ErrorType::InternalError),
                "{name}: {error:?}"
            ),
            Ok(value) => panic!("{name}: a timed-out call must be an error, never Ok({value:?})"),
        }
        assert!(
            elapsed >= BOUND,
            "{name}: answered after {elapsed:?}, before the {BOUND:?} deadline"
        );
        assert!(
            seen.iter().any(|(seen_path, _)| seen_path == path),
            "{name}: the stub never saw {path}: {seen:?}"
        );
    }

    macro_rules! deadline_case {
        ($name:expr, $path:expr, $voice:ident => $call:expr) => {{
            let stub = Stub::silent();
            let $voice = sfu_stub::voice_client_with_bounds(stub.url(), BOUND, SFU_BREAKER_WINDOW);
            expect_deadline($name, $path, stub, $call).await;
        }};
    }

    /// Every SFU method (none needs Redis since the S-3 cleanup: see
    /// `no_sfu_method_resolves_the_identity_mapping`), against a node that
    /// accepts and never answers.
    #[tokio::test]
    async fn every_sfu_call_is_bounded_and_a_timeout_is_an_error() {
        let channel = Channel::SavedMessages {
            id: ROOM.to_string(),
            user: U.to_string(),
        };
        let connections = vec![U.to_string()];

        deadline_case!("create_room", CREATE_ROOM, voice => voice.create_room(NODE, &channel));
        deadline_case!("update_permissions_identity", UPDATE, voice =>
            voice.update_permissions_identity(NODE, U, ROOM, Default::default()));
        deadline_case!("update_permissions_identity_if_present", UPDATE, voice =>
            voice.update_permissions_identity_if_present(NODE, U, ROOM, Default::default()));
        deadline_case!("update_permissions_connections", UPDATE, voice =>
            voice.update_permissions_connections(NODE, ROOM, &connections, Default::default()));
        deadline_case!("remove_identity", REMOVE, voice => voice.remove_identity(NODE, U, ROOM));
        deadline_case!("remove_identity_if_present", REMOVE, voice =>
            voice.remove_identity_if_present(NODE, U, ROOM));
        deadline_case!("remove_connection_if_present", REMOVE, voice =>
            voice.remove_connection_if_present(NODE, U, ROOM));
        deadline_case!("remove_user_if_present", LIST, voice =>
            voice.remove_user_if_present(NODE, U, ROOM));
        deadline_case!("remove_user_if_present_sids", LIST, voice =>
            voice.remove_user_if_present_sids(NODE, U, ROOM));
        deadline_case!("list_participants_if_present", LIST, voice =>
            voice.list_participants_if_present(NODE, ROOM));
        deadline_case!("list_participants_reported", LIST, voice =>
            voice.list_participants_reported(NODE, ROOM));
        deadline_case!("mute_track_identity", MUTE, voice =>
            voice.mute_track_identity(NODE, U, ROOM, "TR_1"));
        deadline_case!("delete_room", DELETE_ROOM, voice => voice.delete_room(NODE, ROOM));
    }

    /// WA-7 / RA2-7, retargeted by the S-3 cleanup. This used to drive the
    /// three methods that resolved the identity mapping before their SFU call
    /// (`remove_user`, `mute_track`, `update_permissions_if_present`) through
    /// the deadline on Redis. All three are deleted, so NO surviving method
    /// resolves the mapping, and every SFU method is driven through the
    /// deadline by `every_sfu_call_is_bounded_and_a_timeout_is_an_error`
    /// above with no Redis at all. This pins that premise on the shipping
    /// text: a method that reads the mapping (or the per-connection record)
    /// before its SFU call is a method the Redis-free deadline test cannot
    /// reach, and must come with a bounded test of its own. The floor on the
    /// public async methods keeps the scan from passing over nothing.
    #[test]
    fn no_sfu_method_resolves_the_identity_mapping() {
        const SOURCE: &str = include_str!("voice_client.rs");
        let shipping = &SOURCE[..SOURCE
            .find("#[cfg(test)]\nmod screen_leg_permission_tests")
            .expect("the first test module")];
        let code: String = shipping
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            code.matches("pub async fn ").count() >= 15,
            "expected at least 15 public async methods: {}",
            code.matches("pub async fn ").count()
        );
        for mapping in [
            "voice_participant_identity(",
            "recorded_voice_connections(",
            "get_connection(",
        ] {
            assert!(
                !code.contains(mapping),
                "a `VoiceClient` method reads `{mapping}` before an SFU call: give it a \
                 bounded test of its own, as the deleted mapping-resolving methods had"
            );
        }
    }

    // ---- D-5: the breaker ----

    async fn timed_list(
        voice: &VoiceClient,
        node: &str,
    ) -> (Duration, Result<Option<Vec<ParticipantInfo>>>) {
        let started = Instant::now();
        let result = tokio::time::timeout(OUTER, voice.list_participants_if_present(node, ROOM))
            .await
            .expect("bounded");
        (started.elapsed(), result)
    }

    /// Two consecutive timeouts open node N's breaker: the next call fails
    /// fast (< 50 ms) with no request reaching N, while another node is
    /// unaffected. After the window ONE half-open probe reaches N; a timeout
    /// re-opens it, an answer closes it and resets the count.
    #[tokio::test]
    async fn the_breaker_trips_after_two_timeouts_and_probes_after_the_window() {
        const WINDOW: Duration = Duration::from_millis(400);
        const FAST: Duration = Duration::from_millis(50);

        let stub = Stub::serve(routes(vec![(
            LIST,
            ok(list_participants_response(&[(U, "")])),
        )]));
        stub.set_silent(true);
        let healthy = Stub::serve(routes(vec![(LIST, ok(Vec::new()))]));
        let voice = sfu_stub::voice_client_nodes(
            &[(NODE, stub.url()), ("healthy", healthy.url())],
            BOUND,
            WINDOW,
        );

        let slow = |step: &str,
                    (elapsed, result): (Duration, Result<Option<Vec<ParticipantInfo>>>),
                    reached: usize| {
            assert!(is_internal(&result), "{step}: {result:?}");
            assert!(elapsed >= BOUND, "{step}: {elapsed:?}");
            assert_eq!(
                stub.seen().len(),
                reached,
                "{step}: the call reached the node"
            );
        };
        let fast =
            |step: &str, (elapsed, result): (Duration, Result<Option<Vec<ParticipantInfo>>>)| {
                assert!(is_internal(&result), "{step}: {result:?}");
                assert!(
                    elapsed < FAST,
                    "{step}: an open breaker fails fast, took {elapsed:?}"
                );
            };

        slow("1st timeout", timed_list(&voice, NODE).await, 1);
        slow("2nd timeout", timed_list(&voice, NODE).await, 2);
        fast("open", timed_list(&voice, NODE).await);
        let (_, other) = timed_list(&voice, "healthy").await;
        assert!(
            matches!(other, Ok(Some(_))),
            "another node is unaffected: {other:?}"
        );
        tokio::time::sleep(FAST).await;
        assert_eq!(
            stub.seen().len(),
            2,
            "an open breaker never touches the network"
        );

        tokio::time::sleep(WINDOW).await;
        slow(
            "half-open probe, timed out",
            timed_list(&voice, NODE).await,
            3,
        );
        fast("re-opened", timed_list(&voice, NODE).await);

        tokio::time::sleep(WINDOW).await;
        stub.set_silent(false);
        let (_, probe) = timed_list(&voice, NODE).await;
        assert!(
            matches!(probe, Ok(Some(_))),
            "half-open probe, answered: {probe:?}"
        );
        assert_eq!(stub.seen().len(), 4);

        // Closed and reset: ONE timeout no longer trips it, so the next call
        // reaches the node again. Without the reset it would fail fast.
        stub.set_silent(true);
        slow("closed, 1st timeout", timed_list(&voice, NODE).await, 5);
        slow("closed, 2nd timeout", timed_list(&voice, NODE).await, 6);
        fast("open again", timed_list(&voice, NODE).await);

        let seen = stub.finish();
        assert_eq!(seen.len(), 6, "{seen:?}");
        assert!(seen.iter().all(|(path, _)| path == LIST), "{seen:?}");
        assert_eq!(healthy.finish().len(), 1);
    }

    // ---- pins ----

    /// The contract values (crond's budget pins read the real constants),
    /// the defaults `new` installs, and the synthetic error's code.
    #[test]
    fn the_sfu_bounds_are_the_contract_values() {
        assert_eq!(SFU_CALL_TIMEOUT, Duration::from_secs(3));
        assert_eq!(SFU_BREAKER_WINDOW, Duration::from_secs(10));
        assert_eq!(MOVE_TOKEN_TTL, Duration::from_secs(10));
        assert_eq!(SCREEN_LEG_TOKEN_TTL, Duration::from_secs(10));

        let voice = VoiceClient::new(Default::default());
        assert_eq!(voice.sfu_timeout, SFU_CALL_TIMEOUT);
        assert_eq!(voice.sfu_breaker_window, SFU_BREAKER_WINDOW);

        let synthetic = sfu_deadline_error("client-side SFU deadline");
        assert!(!is_twirp_not_found(&synthetic));
        assert!(
            matches!(
                &synthetic,
                livekit_api::services::ServiceError::Twirp(
                    livekit_api::services::TwirpError::Twirp(code)
                ) if code.code == livekit_api::services::TwirpErrorCode::DEADLINE_EXCEEDED
            ),
            "{synthetic:?}"
        );
    }

    /// `create_token` mints with `MOVE_TOKEN_TTL` (exp - nbf is the TTL,
    /// give or take the second boundary).
    #[tokio::test]
    async fn create_token_lives_for_the_move_token_ttl() {
        let user = User {
            id: ulid::Ulid::new().to_string(),
            username: "ttl".to_string(),
            discriminator: "0001".to_string(),
            ..Default::default()
        };
        let channel = Channel::SavedMessages {
            id: ulid::Ulid::new().to_string(),
            user: user.id.clone(),
        };
        let db = Database::Reference(Default::default());
        let token = sfu_stub::voice_client("http://127.0.0.1:1")
            .create_token(
                NODE,
                &db,
                &user,
                PermissionValue::from_raw(ChannelPermission::Connect as u64),
                &channel,
                None,
            )
            .await
            .expect("create_token");
        let claims = Claims::from_unverified(&token).expect("decode token");
        let lifetime = (claims.exp - claims.nbf) as u64;
        let ttl = MOVE_TOKEN_TTL.as_secs();
        assert!(
            (ttl..=ttl + 1).contains(&lifetime),
            "token lives {lifetime}s, MOVE_TOKEN_TTL is {ttl}s"
        );
    }

    /// Every room-client call in the shipping code sits inside the
    /// arguments of a `.sfu(` call. Textual, so it also covers any call the
    /// behavioural tests above do not drive; the count floor keeps it from
    /// passing over nothing. The floor is today's count, 8, since the S-3
    /// cleanup deleted `remove_user` (two calls) and `mute_track` (one).
    #[test]
    fn every_room_client_call_goes_through_sfu() {
        const SOURCE: &str = include_str!("voice_client.rs");
        let shipping = &SOURCE[..SOURCE
            .find("#[cfg(test)]\nmod screen_leg_permission_tests")
            .expect("the first test module")];
        let flat = shipping
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ");

        let spans: Vec<(usize, usize)> = flat
            .match_indices(".sfu(")
            .map(|(at, needle)| {
                let open = at + needle.len() - 1;
                let mut depth = 0i64;
                for (i, ch) in flat[open..].char_indices() {
                    match ch {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                return (open, open + i);
                            }
                        }
                        _ => {}
                    }
                }
                panic!("unbalanced parens after .sfu( at {at}");
            })
            .collect();

        let calls: Vec<usize> = flat
            .match_indices(".client")
            .map(|(at, needle)| (at, flat[at + needle.len()..].trim_start()))
            .filter(|(_, rest)| rest.starts_with('.'))
            .map(|(at, _)| at)
            .collect();

        assert!(
            calls.len() >= 8,
            "expected at least 8 room-client calls, found {}",
            calls.len()
        );
        for at in calls {
            let context = &flat[at.saturating_sub(80)..(at + 80).min(flat.len())];
            assert!(
                spans.iter().any(|(open, close)| *open < at && at < *close),
                "a room-client call outside `.sfu(`, so with no deadline and no \
                 breaker: ...{context}..."
            );
        }
    }

    /// RB-2: the reporting listing's real-failure arm is exactly one
    /// `to_internal_error()` on the SFU's own error (ERROR + Sentry with the
    /// cause), with no WARN beside it and no bare `InternalError`; and both
    /// listings share one classification.
    #[test]
    fn list_participants_reported_reports_the_sfu_cause_once() {
        let reported = shipping_method("pub async fn list_participants_reported(");
        assert!(
            reported.contains("self.list_participants_classified(node, room).await?"),
            "{reported}"
        );
        assert!(
            reported.contains("Err(error) => Err::<_, _>(error).to_internal_error(),"),
            "the real-failure arm must report the SFU error itself: {reported}"
        );
        assert!(!reported.contains("log::warn!"), "{reported}");
        assert!(
            !reported.contains("create_error!(InternalError)"),
            "{reported}"
        );

        let quiet = shipping_method("pub async fn list_participants_if_present(");
        assert!(
            quiet.contains("self.list_participants_classified(node, room).await?"),
            "{quiet}"
        );

        let classified = shipping_method("async fn list_participants_classified(");
        assert!(
            classified.contains("Err(error) if is_twirp_not_found(&error) => Ok(None),"),
            "{classified}"
        );
    }

    /// D-2: the whole-user removal reads the SFU's roster through the
    /// REPORTING listing, never the mapping, and reports its first failure
    /// with the SFU's own error. The body lives in `evict_user_connections`
    /// (WA-R); both public entry points only delegate to it, so neither can
    /// grow a second listing or its own eviction loop.
    #[test]
    fn remove_user_if_present_lists_reported_and_never_reads_the_mapping() {
        let body = shipping_method("async fn evict_user_connections(");
        for needle in [
            "self.list_participants_reported(node, channel_id).await?",
            "super::eviction_targets(",
            "super::eviction_result(outcomes)",
            "Err(error) => Err::<Option<UserEviction>, _>(error).to_internal_error(),",
        ] {
            assert!(body.contains(needle), "lost `{needle}`: {body}");
        }
        for banned in [
            "voice_participant_identity(",
            ".list_participants_if_present(",
            "return Err",
        ] {
            assert!(!body.contains(banned), "`{banned}` in: {body}");
        }

        for entry in [
            "pub async fn remove_user_if_present(",
            "pub async fn remove_user_if_present_sids(",
        ] {
            let wrapper = shipping_method(entry);
            assert!(
                wrapper.contains(".evict_user_connections(node, user_id, channel_id)"),
                "{entry} must delegate: {wrapper}"
            );
            for banned in ["list_participants", "remove_participant", "eviction_"] {
                assert!(!wrapper.contains(banned), "`{banned}` in {entry}: {wrapper}");
            }
        }
    }

    // ---- WA-R (WA-1): remove_user_if_present_sids ----

    /// A stub listing `(sid, identity)` pairs and answering each
    /// `RemoveParticipant` with `remove(identity)`.
    fn sid_removal_stub(
        roster: &[(&str, &str)],
        remove: impl Fn(&str) -> Reply + Send + 'static,
    ) -> Stub {
        let triples: Vec<(&str, &str, &str)> = roster
            .iter()
            .map(|(sid, identity)| (*sid, *identity, ""))
            .collect();
        let listing = list_participants_response_sids(&triples);
        Stub::serve(move |path, body| match path {
            LIST => ok(listing.clone()),
            REMOVE => remove(&sfu_stub::identity(body).unwrap_or_default()),
            _ => internal(),
        })
    }

    /// The stub's sid field decodes through the real client as
    /// `ParticipantInfo.sid`, and an omitted one as the empty string.
    #[tokio::test]
    async fn the_stub_listing_carries_each_participants_sid() {
        let ud = format!("{U}:D");
        let stub = sid_removal_stub(&[("PA_u", U), ("", &ud)], |_| ok(Vec::new()));
        let listed = sfu_stub::voice_client(stub.url())
            .list_participants_reported(NODE, ROOM)
            .await;
        stub.finish();
        match listed {
            Ok(Some(participants)) => assert_eq!(
                participants
                    .iter()
                    .map(|p| (p.sid.as_str(), p.identity.as_str()))
                    .collect::<Vec<_>>(),
                vec![("PA_u", U), ("", ud.as_str())]
            ),
            other => panic!("{other:?}"),
        }
    }

    /// `[U, U:D, U:D:screen, V, UX:B]`, all removals landing: the answer is
    /// the sids of U's two PRIMARIES, in listed order, never the leg's (legs
    /// are never recorded in `vc_conns`), never V's, never the account whose
    /// id extends U's; and the evictions are exactly those of
    /// `remove_user_if_present`.
    #[tokio::test]
    async fn remove_user_if_present_sids_names_every_evicted_primary_and_no_leg() {
        let ud = format!("{U}:D");
        let leg = format!("{ud}:screen");
        let uxb = format!("{UX}:B");
        let roster = [
            ("PA_u", U),
            ("PA_ud", ud.as_str()),
            ("PA_leg", leg.as_str()),
            ("PA_v", V),
            ("PA_uxb", uxb.as_str()),
        ];

        let stub = sid_removal_stub(&roster, |_| ok(Vec::new()));
        let result = sfu_stub::voice_client(stub.url())
            .remove_user_if_present_sids(NODE, U, ROOM)
            .await;
        let seen = stub.finish();

        assert_eq!(
            result.as_ref().ok(),
            Some(&Some(vec!["PA_u".to_string(), "PA_ud".to_string()])),
            "{result:?}"
        );
        assert_eq!(
            seen,
            requests(&[
                (LIST, ""),
                (REMOVE, &format!("{U}::screen")),
                (REMOVE, U),
                (REMOVE, &leg),
                (REMOVE, &ud),
            ])
        );

        // The bool wrapper, over the same stub shape, is still `Ok(true)`.
        let stub = sid_removal_stub(&roster, |_| ok(Vec::new()));
        let wrapped = sfu_stub::voice_client(stub.url())
            .remove_user_if_present(NODE, U, ROOM)
            .await;
        assert_eq!(stub.finish(), seen, "one body, one request sequence");
        assert!(matches!(wrapped, Ok(true)), "{wrapped:?}");
    }

    /// A listed primary that answers not_found had already gone: success,
    /// and its sid IS named (its record is stale either way).
    #[tokio::test]
    async fn remove_user_if_present_sids_names_an_already_gone_primary() {
        let ud = format!("{U}:D");
        let gone = ud.clone();
        let stub = sid_removal_stub(&[("PA_u", U), ("PA_ud", &ud)], move |identity| {
            if identity == gone {
                not_found()
            } else {
                ok(Vec::new())
            }
        });
        let result = sfu_stub::voice_client(stub.url())
            .remove_user_if_present_sids(NODE, U, ROOM)
            .await;
        assert_eq!(stub.finish().len(), 5);
        assert_eq!(
            result.as_ref().ok(),
            Some(&Some(vec!["PA_u".to_string(), "PA_ud".to_string()])),
            "{result:?}"
        );
    }

    /// A real failure evicting a LISTED connection: `Err` after every
    /// removal was attempted, and NO sids, so no caller tears down the
    /// record of a connection that may still be live. A real failure on a
    /// DERIVED leg is discarded and the sids are returned.
    #[tokio::test]
    async fn remove_user_if_present_sids_names_nothing_when_an_eviction_failed() {
        let ud = format!("{U}:D");
        let every = requests(&[
            (LIST, ""),
            (REMOVE, &format!("{U}::screen")),
            (REMOVE, U),
            (REMOVE, &format!("{ud}:screen")),
            (REMOVE, &ud),
        ]);

        let failing = ud.clone();
        let stub = sid_removal_stub(&[("PA_u", U), ("PA_ud", &ud)], move |identity| {
            if identity == failing {
                internal()
            } else {
                ok(Vec::new())
            }
        });
        let result = sfu_stub::voice_client(stub.url())
            .remove_user_if_present_sids(NODE, U, ROOM)
            .await;
        assert_eq!(stub.finish(), every, "no early exit after the failure");
        assert!(is_internal(&result), "{result:?}");

        let derived = format!("{U}::screen");
        let stub = sid_removal_stub(&[("PA_u", U), ("PA_ud", &ud)], move |identity| {
            if identity == derived {
                internal()
            } else {
                ok(Vec::new())
            }
        });
        let result = sfu_stub::voice_client(stub.url())
            .remove_user_if_present_sids(NODE, U, ROOM)
            .await;
        assert_eq!(stub.finish(), every);
        assert_eq!(
            result.as_ref().ok(),
            Some(&Some(vec!["PA_u".to_string(), "PA_ud".to_string()])),
            "{result:?}"
        );
    }

    /// Room gone: `Ok(None)` after ONE request. Nothing of the user listed:
    /// `Ok(Some([]))`. Only a leg listed: it is evicted, `Ok(Some([]))`. A
    /// primary listed with no sid: evicted, but left out of the answer. A
    /// failed listing: `Err`, after one request.
    #[tokio::test]
    async fn remove_user_if_present_sids_separates_a_gone_room_from_an_empty_answer() {
        let stub = Stub::serve(routes(vec![(LIST, not_found())]));
        let result = sfu_stub::voice_client(stub.url())
            .remove_user_if_present_sids(NODE, U, ROOM)
            .await;
        assert!(matches!(result, Ok(None)), "room gone: {result:?}");
        assert_eq!(stub.finish(), requests(&[(LIST, "")]));

        let stub = sid_removal_stub(&[("PA_v", V)], |_| ok(Vec::new()));
        let result = sfu_stub::voice_client(stub.url())
            .remove_user_if_present_sids(NODE, U, ROOM)
            .await;
        assert_eq!(stub.finish(), requests(&[(LIST, "")]));
        assert!(
            matches!(&result, Ok(Some(sids)) if sids.is_empty()),
            "nothing listed: {result:?}"
        );

        let leg = format!("{U}:D:screen");
        let stub = sid_removal_stub(&[("PA_leg", &leg), ("PA_v", V)], |_| ok(Vec::new()));
        let result = sfu_stub::voice_client(stub.url())
            .remove_user_if_present_sids(NODE, U, ROOM)
            .await;
        assert_eq!(stub.finish(), requests(&[(LIST, ""), (REMOVE, &leg)]));
        assert!(
            matches!(&result, Ok(Some(sids)) if sids.is_empty()),
            "a lone leg: {result:?}"
        );

        let ud = format!("{U}:D");
        let stub = sid_removal_stub(&[("", U), ("PA_ud", &ud)], |_| ok(Vec::new()));
        let result = sfu_stub::voice_client(stub.url())
            .remove_user_if_present_sids(NODE, U, ROOM)
            .await;
        assert_eq!(stub.finish().len(), 5, "the sid-less primary is still evicted");
        assert_eq!(
            result.as_ref().ok(),
            Some(&Some(vec!["PA_ud".to_string()])),
            "{result:?}"
        );

        let stub = Stub::serve(routes(vec![(LIST, internal())]));
        let result = sfu_stub::voice_client(stub.url())
            .remove_user_if_present_sids(NODE, U, ROOM)
            .await;
        assert!(is_internal(&result), "a failed listing: {result:?}");
        assert_eq!(stub.finish(), requests(&[(LIST, "")]));
    }

    // ---- WA-R: the breaker's half-open probe under concurrency ----

    /// After the breaker opens and its window passes, EIGHT calls issued
    /// concurrently let exactly ONE through to the node (the half-open
    /// probe); the other seven fail fast with the synthetic error and never
    /// touch the network. The probe re-arms the window as it is admitted, so
    /// the calls racing it see an open breaker. Without that re-arm every
    /// racing call is a "probe" and a sick node takes the whole burst.
    #[tokio::test]
    async fn only_one_concurrent_call_probes_a_half_open_breaker() {
        const WINDOW: Duration = Duration::from_millis(400);
        const FAST: Duration = Duration::from_millis(50);
        const BURST: usize = 8;

        let stub = Stub::serve(routes(vec![(
            LIST,
            ok(list_participants_response(&[(U, "")])),
        )]));
        stub.set_silent(true);
        let voice = sfu_stub::voice_client_with_bounds(stub.url(), BOUND, WINDOW);

        for step in ["1st timeout", "2nd timeout"] {
            let (_, result) = timed_list(&voice, NODE).await;
            assert!(is_internal(&result), "{step}: {result:?}");
        }
        let (elapsed, open) = timed_list(&voice, NODE).await;
        assert!(
            is_internal(&open) && elapsed < FAST,
            "the breaker is open: {elapsed:?} {open:?}"
        );
        assert_eq!(stub.seen().len(), 2, "tripped after exactly two calls");

        tokio::time::sleep(WINDOW + FAST).await;
        stub.set_silent(false);

        let burst = futures::future::join_all((0..BURST).map(|_| timed_list(&voice, NODE))).await;

        let answered: Vec<_> = burst
            .iter()
            .filter(|(_, result)| matches!(result, Ok(Some(_))))
            .collect();
        let refused: Vec<_> = burst
            .iter()
            .filter(|(elapsed, result)| is_internal(result) && *elapsed < FAST)
            .collect();
        assert_eq!(answered.len(), 1, "exactly one probe answered: {burst:?}");
        assert_eq!(
            refused.len(),
            BURST - 1,
            "every other call failed fast: {burst:?}"
        );

        let seen = stub.finish();
        assert_eq!(
            seen.len(),
            3,
            "two timeouts, then ONE half-open probe reached the node: {seen:?}"
        );
    }

    // ---- WA-8: the screen-leg token lifetime ----

    /// `create_screen_leg_token` mints with `SCREEN_LEG_TOKEN_TTL`.
    #[tokio::test]
    async fn create_screen_leg_token_lives_for_its_named_ttl() {
        let user = User {
            id: ulid::Ulid::new().to_string(),
            username: "leg".to_string(),
            discriminator: "0001".to_string(),
            ..Default::default()
        };
        let channel = Channel::SavedMessages {
            id: ulid::Ulid::new().to_string(),
            user: user.id.clone(),
        };
        let db = Database::Reference(Default::default());
        let identity = super::super::screen_leg_identity(&format!("{}:DEVICE", user.id));
        let token = sfu_stub::voice_client("http://127.0.0.1:1")
            .create_screen_leg_token(NODE, &db, &user, &identity, &channel)
            .await
            .expect("create_screen_leg_token");
        let claims = Claims::from_unverified(&token).expect("decode token");
        let lifetime = (claims.exp - claims.nbf) as u64;
        let ttl = SCREEN_LEG_TOKEN_TTL.as_secs();
        assert!(
            (ttl..=ttl + 1).contains(&lifetime),
            "token lives {lifetime}s, SCREEN_LEG_TOKEN_TTL is {ttl}s"
        );
    }
}
