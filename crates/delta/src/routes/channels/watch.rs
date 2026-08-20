//! Watch-together session routes (watch-together plan §1.1).
//!
//! Sloga carries ONLY the control state of a synced playback session —
//! "item X, position P, playing, host H" — over these routes and the
//! private bonfire fan-out. The media itself (a YouTube embed, an item on a
//! viewer's own Jellyfin) is fetched by every viewer from the provider on
//! their own machine; nothing is hosted, proxied or relayed here, ever.
//!
//! Authority: the HOST (the user who started the session) is the only user
//! whose control writes are accepted, plus `ManageChannel` as the moderation
//! override. Starting requires the `UseWatchTogether` bit in server
//! channels; VIEWING (the GET, and receiving the events) needs only
//! `Connect` + being in the call, like annotations — a listen-only
//! participant is exactly who watches. DMs / group DMs do not consult the
//! bit (the remote-control table's reasoning: non-owners of existing groups
//! hold only ViewChannel + ReadMessageHistory).
//!
//! Every route requires the caller to be IN the call right now — you cannot
//! drive, or read, a call you are not in.

use revolt_database::{
    events::client::EventV1,
    util::{permissions::perms, reference::Reference},
    voice::{
        get_voice_state, is_in_voice_channel, update_voice_state,
        watch::{
            clear_watching_flags, create_watch_session, delete_watch_session, fan_watch_end,
            fan_watch_update, fetch_watch_session, now_ms, update_watch_session,
        },
        UserVoiceChannel,
    },
    Channel, Database, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission, PermissionValue};
use revolt_result::{create_error, Result};

use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;
use validator::Validate;

/// Shared guard: voice channel, `Connect`, caller currently in the call.
/// Returns the permission set too, so callers can layer the start/control
/// checks without a second calculation.
async fn require_call_participant(
    db: &Database,
    user: &User,
    channel: &Channel,
) -> Result<(UserVoiceChannel, PermissionValue)> {
    if channel.voice().is_none() {
        return Err(create_error!(NotAVoiceChannel));
    }

    let mut query = perms(db, user).channel(channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::Connect)?;

    let voice_channel = UserVoiceChannel::from_channel(channel);
    if !is_in_voice_channel(&user.id, &voice_channel).await? {
        return Err(create_error!(NotInVoiceChannel));
    }
    Ok((voice_channel, permissions))
}

/// `UseWatchTogether` gates STARTING in server channels only; DMs and group
/// DMs are Connect-only (see module docs).
fn require_start_permission(channel: &Channel, permissions: &PermissionValue) -> Result<()> {
    match channel {
        Channel::DirectMessage { .. } | Channel::Group { .. } => Ok(()),
        _ => permissions.throw_if_lacking_channel_permission(ChannelPermission::UseWatchTogether),
    }
}

/// Host, or a channel manager (the moderation override).
fn require_control(
    user: &User,
    session: &v0::WatchSession,
    permissions: &PermissionValue,
) -> Result<()> {
    if session.host_id == user.id
        || permissions.has_channel_permission(ChannelPermission::ManageChannel)
    {
        Ok(())
    } else {
        Err(create_error!(NotWatchHost))
    }
}

fn respond(session: v0::WatchSession) -> Json<v0::WatchSessionResponse> {
    Json(v0::WatchSessionResponse {
        session,
        server_now: now_ms(),
    })
}

/// # Start Watching Together
///
/// Create this voice channel's watch-together session with the caller as
/// host, paused at position 0. One session per channel: 409 if one exists
/// (end it, or have the host swap the item with a PATCH). Requires being in
/// the call and, in server channels, `UseWatchTogether`.
#[openapi(tag = "Voice")]
#[post("/<target>/watch", data = "<data>")]
pub async fn watch_create(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataWatchCreate>,
) -> Result<Json<v0::WatchSessionResponse>> {
    let data = data.into_inner();
    let channel = target.as_channel(db).await?;
    let (voice_channel, permissions) = require_call_participant(db, &user, &channel).await?;
    require_start_permission(&channel, &permissions)?;
    validate_media(&data.media)?;

    let session = create_watch_session(channel.id(), &user.id, data.media)
        .await?
        .ok_or_else(|| create_error!(WatchSessionExists))?;

    fan_watch_update(&voice_channel, &session).await;
    Ok(respond(session))
}

/// # Update Watch Session
///
/// Host control write AND heartbeat: the FULL host-owned state (`playing`,
/// `position_ms`, `rate_permille`, optionally a new `media`). The server
/// stamps `position_at` with its own clock, mints a fresh monotonic `seq`,
/// refreshes the session TTL and fans the complete session to the call.
/// Returns the stamped session so the host adopts `seq`/`position_at`
/// without waiting for its own event. Host or `ManageChannel` only.
#[openapi(tag = "Voice")]
#[patch("/<target>/watch", data = "<data>")]
pub async fn watch_update(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataWatchUpdate>,
) -> Result<Json<v0::WatchSessionResponse>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;
    if let Some(media) = &data.media {
        validate_media(media)?;
    }

    let channel = target.as_channel(db).await?;
    let (voice_channel, permissions) = require_call_participant(db, &user, &channel).await?;

    let existing = fetch_watch_session(channel.id())
        .await?
        .ok_or_else(|| create_error!(NotFound))?;
    require_control(&user, &existing, &permissions)?;

    let session = update_watch_session(channel.id(), |session| {
        session.playing = data.playing;
        session.position_ms = data.position_ms;
        session.rate_permille = data.rate_permille;
        if let Some(media) = data.media {
            session.media = media;
        }
    })
    .await?
    // Raced with an end between the fetch and the write — report it as
    // gone rather than resurrecting a session nobody is hosting.
    .ok_or_else(|| create_error!(NotFound))?;

    fan_watch_update(&voice_channel, &session).await;
    Ok(respond(session))
}

/// # Hand Off Watch Session Host
///
/// Give the session to a new host. Caller must be the current host or hold
/// `ManageChannel`. The target must be in the call RIGHT NOW (a host outside
/// the call would orphan the leave-teardown) and, in server channels, hold
/// `UseWatchTogether` themselves — a handoff must not launder the control
/// permission (DMs / group DMs stay exempt, the start-permission table).
/// The playing timeline is advanced to the server clock before the swap so
/// the write rewinds nothing. Same-host handoff is an idempotent no-op.
#[openapi(tag = "Voice")]
#[put("/<target>/watch/host", data = "<data>")]
pub async fn watch_host(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataWatchHost>,
) -> Result<Json<v0::WatchSessionResponse>> {
    let data = data.into_inner();
    let channel = target.as_channel(db).await?;
    let (voice_channel, permissions) = require_call_participant(db, &user, &channel).await?;

    let existing = fetch_watch_session(channel.id())
        .await?
        .ok_or_else(|| create_error!(NotFound))?;
    require_control(&user, &existing, &permissions)?;

    if existing.host_id == data.user {
        // Nothing to write — and no seq minted for a no-op.
        return Ok(respond(existing));
    }

    let new_host = Reference::from_unchecked(&data.user).as_user(db).await?;
    // A bot can hold voice state in two channels of one server under ONE
    // colliding key, and could never drive the session anyway.
    if new_host.bot.is_some() {
        return Err(create_error!(IsBot));
    }
    if !is_in_voice_channel(&new_host.id, &voice_channel).await? {
        return Err(create_error!(NotInVoiceChannel));
    }
    // The TARGET's permission set, not the caller's.
    let mut target_query = perms(db, &new_host).channel(&channel);
    let target_permissions = calculate_channel_permissions(&mut target_query).await;
    require_start_permission(&channel, &target_permissions)?;

    let new_host_id = new_host.id.clone();
    let swap = |session: &mut v0::WatchSession| {
        // update_watch_session re-stamps position_at AFTER this closure
        // runs; a playing timeline must be advanced first or the re-stamp
        // rewinds it by the gap since the last write.
        session.advance_to(now_ms());
        session.host_id = new_host_id.clone();
    };

    let mut session = update_watch_session(channel.id(), swap.clone())
        .await?
        .ok_or_else(|| create_error!(NotFound))?;

    // GET→mutate→SETEX is not atomic: a stale in-flight heartbeat from the
    // OLD host can overwrite this write, and unlike playing/position nothing
    // ever re-writes host_id — a silently reverted handoff would persist.
    // Verify against the store and retry once (bounded; no WATCH/Lua, the
    // house rule). The inverse interleaving — this write clobbering a
    // just-written pause — self-heals within one heartbeat from the new host.
    let stored = fetch_watch_session(channel.id())
        .await?
        .ok_or_else(|| create_error!(NotFound))?;
    if stored.host_id != new_host.id {
        update_watch_session(channel.id(), swap)
            .await?
            .ok_or_else(|| create_error!(NotFound))?;
        let stored = fetch_watch_session(channel.id())
            .await?
            .ok_or_else(|| create_error!(NotFound))?;
        if stored.host_id != new_host.id {
            return Err(create_error!(InternalError));
        }
        session = stored;
    }

    fan_watch_update(&voice_channel, &session).await;
    Ok(respond(session))
}

/// # Set Watching Flag
///
/// Set or clear the caller's `watching` roster flag — "this participant has
/// the channel's watch session attached". A bare boolean on the CHANNEL
/// topic (the `screensharing`/`recording` visibility class): people outside
/// the call learn that a watch party exists, never what it plays — the
/// session itself stays on the private fan-out. Client-claimed both ways
/// (attach and detach); a true claim is refused while the channel has no
/// session, and session teardown clears the flag for every member, so the
/// hint cannot outlive the party. Idempotent.
#[openapi(tag = "Voice")]
#[put("/<target>/watching", data = "<data>")]
pub async fn watching_set(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataSetWatching>,
) -> Result<EmptyResponse> {
    let data = data.into_inner();
    let channel = target.as_channel(db).await?;

    // The rc_capable rule: per-member voice flags key `{user}:{server}`,
    // which COLLIDES for a bot in two voice channels of one server.
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let (voice_channel, _permissions) = require_call_participant(db, &user, &channel).await?;

    // Server-authoritative floor: a client can never advertise a party that
    // does not exist (§7.3 rev-2 review). Clearing is always allowed.
    if data.watching && fetch_watch_session(channel.id()).await?.is_none() {
        return Err(create_error!(NotFound));
    }

    // Idempotent against the DESIRED value — a retrying client must not fan
    // a duplicate roster update at the channel.
    let already = get_voice_state(&voice_channel, &user.id)
        .await?
        .is_some_and(|state| state.watching == data.watching);
    if already {
        return Ok(EmptyResponse);
    }

    // State before event (the recording/rc_capable discipline): the event is
    // the fast path, the voice state is what a late joiner's roster read
    // must already agree with.
    update_voice_state(
        &voice_channel,
        &user.id,
        &v0::PartialUserVoiceState {
            watching: Some(data.watching),
            ..Default::default()
        },
    )
    .await?;

    EventV1::UserVoiceStateUpdate {
        id: user.id.clone(),
        channel_id: channel.id().to_string(),
        data: v0::PartialUserVoiceState {
            id: Some(user.id.clone()),
            watching: Some(data.watching),
            ..Default::default()
        },
    }
    .p(channel.id().to_string())
    .await;

    Ok(EmptyResponse)
}

/// # End Watch Session
///
/// End this channel's session and tell the call. Host or `ManageChannel`.
/// Idempotent: 204 even when nothing was running.
#[openapi(tag = "Voice")]
#[delete("/<target>/watch")]
pub async fn watch_end(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<EmptyResponse> {
    let channel = target.as_channel(db).await?;
    let (voice_channel, permissions) = require_call_participant(db, &user, &channel).await?;

    if let Some(existing) = fetch_watch_session(channel.id()).await? {
        require_control(&user, &existing, &permissions)?;
        if let Some(session) = delete_watch_session(channel.id()).await? {
            fan_watch_end(&voice_channel, &session.id).await;
            // The party is over → nobody in the channel is "watching" any
            // more (the leave-teardown helpers do the same).
            clear_watching_flags(&voice_channel).await;
        }
    }

    Ok(EmptyResponse)
}

/// # Fetch Watch Session
///
/// The channel's current session, for late joiners and reconnects (a WS
/// reconnect fires no join event for self). 404 when none. Any current
/// call participant with `Connect` — viewing is not gated on the bit.
#[openapi(tag = "Voice")]
#[get("/<target>/watch")]
pub async fn watch_fetch(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<v0::WatchSessionResponse>> {
    let channel = target.as_channel(db).await?;
    require_call_participant(db, &user, &channel).await?;

    let session = fetch_watch_session(channel.id())
        .await?
        .ok_or_else(|| create_error!(NotFound))?;
    Ok(respond(session))
}

/// Provider-reference sanity the derive can't express. Rejected, not
/// clamped: a client sending junk is a bug to surface.
fn validate_media(media: &v0::WatchMedia) -> Result<()> {
    let fail = |error: &str| {
        Err(create_error!(FailedValidation {
            error: error.to_string()
        }))
    };
    match media {
        v0::WatchMedia::YouTube { video_id, title } => {
            // Video ids are 11 chars of [A-Za-z0-9_-]; anything else is not
            // an id and would be fanned to the whole call as one.
            if video_id.len() != 11
                || !video_id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return fail("invalid YouTube video id");
            }
            if title.as_ref().is_some_and(|t| t.chars().count() > 200) {
                return fail("title too long");
            }
            Ok(())
        }
        v0::WatchMedia::Jellyfin {
            server_url,
            server_id,
            item_id,
            item_name,
            item_kind,
            ..
        } => {
            // Slice 2 fills in the provider; the reference shape is bounded
            // now so a slice-1 backend never fans unbounded strings.
            if !(server_url.starts_with("http://") || server_url.starts_with("https://"))
                || server_url.len() > 512
            {
                return fail("invalid Jellyfin server url");
            }
            if server_id.is_empty()
                || server_id.len() > 64
                || item_id.is_empty()
                || item_id.len() > 64
                || item_name.chars().count() > 200
                || item_kind.len() > 32
            {
                return fail("invalid Jellyfin item reference");
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        voice::{
            create_voice_state, delete_channel_voice_state, delete_voice_state,
            watch::fetch_watch_session, UserVoiceChannel,
        },
        Channel, Member, User,
    };
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};

    async fn voice_channel(
        harness: &TestHarness,
        server: &revolt_database::Server,
        name: &str,
    ) -> Channel {
        Channel::create_server_channel(
            &harness.db,
            &mut server.clone(),
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Text,
                name: name.to_string(),
                description: None,
                nsfw: Some(false),
                spoiler: None,
                voice: Some(v0::VoiceInformation {
                    max_users: None,
                    disabled: false,
                }),
                announcement: None,
            },
            true,
        )
        .await
        .expect("voice channel")
    }

    /// Host A (owner) + viewer B (plain member), both in the call; C is a
    /// member who is NOT in the call.
    async fn setup() -> (
        TestHarness,
        Channel,
        UserVoiceChannel,
        User,
        String,
        User,
        String,
        User,
        String,
    ) {
        let harness = TestHarness::new().await;
        let (_, session_a, user_a) = harness.new_user().await; // host / owner
        let (_, session_b, user_b) = harness.new_user().await; // viewer
        let (_, session_c, user_c) = harness.new_user().await; // not in call
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member b");
        Member::create(&harness.db, &server, &user_c, None)
            .await
            .expect("member c");
        let channel = voice_channel(&harness, &server, "Voice").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        create_voice_state(&uvc, &user_a.id, Timestamp::now_utc())
            .await
            .expect("voice state a");
        create_voice_state(&uvc, &user_b.id, Timestamp::now_utc())
            .await
            .expect("voice state b");
        (
            harness,
            channel,
            uvc,
            user_a,
            session_a.token,
            user_b,
            session_b.token,
            user_c,
            session_c.token,
        )
    }

    fn yt(id: &str) -> serde_json::Value {
        serde_json::json!({ "media": { "provider": "youtube", "video_id": id } })
    }

    /// create → 409 on a second create → host PATCH bumps seq and stamps
    /// position_at → viewer GET sees it → non-host PATCH 403 → viewer
    /// DELETE 403 → host DELETE 204 → GET 404.
    // These tests run on the shared runtime from `util::test::rt` (see its
    // doc comment): they drive live Redis voice state through the global
    // `redis_kiss` pool, and per-test runtimes intermittently poison that
    // pool with connections whose I/O driver has died.
    #[test]
    fn watch_session_lifecycle() {
        crate::util::test::rt().block_on(watch_session_lifecycle_case())
    }

    async fn watch_session_lifecycle_case() {
        let (harness, channel, uvc, user_a, token_a, user_b, token_b, _user_c, _token_c) =
            setup().await;

        // Start.
        let response = harness
            .client
            .post(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(yt("YE7VzlLtp-4").to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let created: v0::WatchSessionResponse =
            response.into_json().await.expect("create response");
        assert_eq!(created.session.host_id, user_a.id);
        assert!(!created.session.playing);
        assert_eq!(created.session.position_ms, 0);
        assert_eq!(created.session.rate_permille, 1000);
        assert!(created.server_now >= created.session.started_at);
        let first_seq = created.session.seq;

        // Second start: 409.
        let response = harness
            .client
            .post(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_b.clone()))
            .body(yt("YE7VzlLtp-4").to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Conflict);

        // Host play + seek.
        let response = harness
            .client
            .patch(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(
                serde_json::json!({ "playing": true, "position_ms": 120000, "rate_permille": 1000 })
                    .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let updated: v0::WatchSessionResponse =
            response.into_json().await.expect("update response");
        assert!(updated.session.playing);
        assert_eq!(updated.session.position_ms, 120000);
        assert!(updated.session.seq > first_seq, "seq must be monotonic");
        assert!(updated.session.position_at >= created.session.position_at);
        assert_eq!(updated.session.id, created.session.id);

        // Viewer GET sees the same state.
        let response = harness
            .client
            .get(format!("/channels/{}/watch", channel.id()))
            .header(Header::new("x-session-token", token_b.clone()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let fetched: v0::WatchSessionResponse =
            response.into_json().await.expect("fetch response");
        assert_eq!(fetched.session, updated.session);

        // Viewer (plain member, not host, no ManageChannel) cannot drive.
        let response = harness
            .client
            .patch(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_b.clone()))
            .body(
                serde_json::json!({ "playing": false, "position_ms": 0, "rate_permille": 1000 })
                    .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);

        // …nor end.
        let response = harness
            .client
            .delete(format!("/channels/{}/watch", channel.id()))
            .header(Header::new("x-session-token", token_b.clone()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
        assert!(fetch_watch_session(channel.id())
            .await
            .expect("session read")
            .is_some());

        // Host ends.
        let response = harness
            .client
            .delete(format!("/channels/{}/watch", channel.id()))
            .header(Header::new("x-session-token", token_a.clone()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);

        let response = harness
            .client
            .get(format!("/channels/{}/watch", channel.id()))
            .header(Header::new("x-session-token", token_b.clone()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);

        delete_channel_voice_state(&uvc, &[user_a.id.clone(), user_b.id.clone()])
            .await
            .expect("teardown");
    }

    /// Guards: a member not in the call can neither start nor read; a bad
    /// video id is rejected; an out-of-range rate is rejected.
    #[test]
    fn watch_session_guards() {
        crate::util::test::rt().block_on(watch_session_guards_case())
    }

    async fn watch_session_guards_case() {
        let (harness, channel, uvc, user_a, token_a, user_b, _token_b, _user_c, token_c) =
            setup().await;

        // Not in the call: cannot start.
        let response = harness
            .client
            .post(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_c.clone()))
            .body(yt("YE7VzlLtp-4").to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // Bad id.
        let response = harness
            .client
            .post(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(yt("not an id").to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // Good start.
        let response = harness
            .client
            .post(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(yt("YE7VzlLtp-4").to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        // Not in the call: cannot read either.
        let response = harness
            .client
            .get(format!("/channels/{}/watch", channel.id()))
            .header(Header::new("x-session-token", token_c.clone()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // Rate out of range.
        let response = harness
            .client
            .patch(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(
                serde_json::json!({ "playing": true, "position_ms": 0, "rate_permille": 5000 })
                    .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        delete_channel_voice_state(&uvc, &[user_a.id.clone(), user_b.id.clone()])
            .await
            .expect("teardown");
    }

    /// `ManageChannel` override: a plain member (B, default permissions —
    /// which now carry `UseWatchTogether`) hosts; the owner (A, GrantAllSafe)
    /// may drive and end it without being host.
    #[test]
    fn watch_session_manager_override() {
        crate::util::test::rt().block_on(watch_session_manager_override_case())
    }

    async fn watch_session_manager_override_case() {
        let (harness, channel, uvc, user_a, token_a, user_b, token_b, _user_c, _token_c) =
            setup().await;

        let response = harness
            .client
            .post(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_b.clone()))
            .body(yt("YE7VzlLtp-4").to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let created: v0::WatchSessionResponse =
            response.into_json().await.expect("create response");
        assert_eq!(created.session.host_id, user_b.id);

        // Owner pauses at 30 s: allowed.
        let response = harness
            .client
            .patch(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(
                serde_json::json!({ "playing": false, "position_ms": 30000, "rate_permille": 1000 })
                    .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let updated: v0::WatchSessionResponse =
            response.into_json().await.expect("update response");
        assert_eq!(updated.session.host_id, user_b.id, "override must not steal host");
        assert_eq!(updated.session.position_ms, 30000);

        // Owner ends: allowed.
        let response = harness
            .client
            .delete(format!("/channels/{}/watch", channel.id()))
            .header(Header::new("x-session-token", token_a.clone()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);
        assert!(fetch_watch_session(channel.id())
            .await
            .expect("session read")
            .is_none());

        delete_channel_voice_state(&uvc, &[user_a.id.clone(), user_b.id.clone()])
            .await
            .expect("teardown");
    }

    /// The load-bearing teardown: the host's voice state going away (any
    /// leave path — they all pass through `delete_voice_state`) ends the
    /// session; a VIEWER leaving does not.
    #[test]
    fn watch_session_ends_when_host_leaves() {
        crate::util::test::rt().block_on(watch_session_ends_when_host_leaves_case())
    }

    async fn watch_session_ends_when_host_leaves_case() {
        let (harness, channel, uvc, user_a, token_a, user_b, _token_b, _user_c, _token_c) =
            setup().await;

        let response = harness
            .client
            .post(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(yt("YE7VzlLtp-4").to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        // Viewer leaves: session survives.
        delete_voice_state(&uvc, &user_b.id)
            .await
            .expect("viewer leave");
        assert!(fetch_watch_session(channel.id())
            .await
            .expect("session read")
            .is_some());

        // Host leaves: session gone.
        delete_voice_state(&uvc, &user_a.id)
            .await
            .expect("host leave");
        assert!(fetch_watch_session(channel.id())
            .await
            .expect("session read")
            .is_none());
    }

    /// Fan-out boundary (plan §1.2): watch events ride the PRIVATE topics of
    /// the call's members, never the channel topic — a member of the same
    /// server who is not in the call (a text-channel-only account) must see
    /// nothing at all, while a call member sees update AND end.
    #[test]
    fn watch_events_fan_to_call_members_only() {
        crate::util::test::rt().block_on(watch_events_fan_to_call_members_only_case())
    }

    async fn watch_events_fan_to_call_members_only_case() {
        use revolt_database::events::client::EventV1;
        use rocket::futures::StreamExt;

        let (harness, channel, uvc, user_a, token_a, user_b, _token_b, user_c, _token_c) =
            setup().await;
        let topic_b = format!("{}!", user_b.id);
        let topic_c = format!("{}!", user_c.id);

        // Subscribe BEFORE any watch traffic so nothing is missed.
        let mut pubsub = redis_kiss::open_pubsub_connection()
            .await
            .expect("pubsub connection");
        pubsub.subscribe(&topic_b).await.expect("subscribe b");
        pubsub.subscribe(&topic_c).await.expect("subscribe c");

        // create → fans an update; host PATCH → fans an update; host
        // DELETE → fans an end.
        let response = harness
            .client
            .post(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(yt("YE7VzlLtp-4").to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let created: v0::WatchSessionResponse =
            response.into_json().await.expect("create response");
        let response = harness
            .client
            .patch(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(
                serde_json::json!({ "playing": true, "position_ms": 1000, "rate_permille": 1000 })
                    .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let response = harness
            .client
            .delete(format!("/channels/{}/watch", channel.id()))
            .header(Header::new("x-session-token", token_a.clone()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);

        // Drain until quiet. ANY message on C's topic is the leak this test
        // exists to catch; on B's topic, count the watch events for this
        // session (unrelated traffic on the shared Redis is ignored). The
        // final 2 s quiet window after the last expected event doubles as
        // the chance for a trailing leak to C to surface.
        let mut b_updates = 0u32;
        let mut b_ends = 0u32;
        {
            let mut stream = pubsub.on_message();
            while let Ok(Some(msg)) =
                tokio::time::timeout(std::time::Duration::from_secs(2), stream.next()).await
            {
                let topic = msg.get_channel_name().to_string();
                assert_ne!(
                    topic, topic_c,
                    "watch event leaked to a server member who is not in the call"
                );
                if topic != topic_b {
                    continue;
                }
                match redis_kiss::decode_payload::<EventV1>(&msg) {
                    Ok(EventV1::WatchSessionUpdate { session, .. })
                        if session.id == created.session.id =>
                    {
                        b_updates += 1;
                    }
                    Ok(EventV1::WatchSessionEnd { id, .. }) if id == created.session.id => {
                        b_ends += 1;
                    }
                    _ => {}
                }
            }
        }
        assert!(
            b_updates >= 2,
            "call member must receive the create and PATCH updates, got {b_updates}"
        );
        assert_eq!(b_ends, 1, "call member must receive the end event");

        delete_channel_voice_state(&uvc, &[user_a.id.clone(), user_b.id.clone()])
            .await
            .expect("teardown");
    }

    fn host_body(user: &str) -> String {
        serde_json::json!({ "user": user }).to_string()
    }

    /// Handoff lifecycle: host hands to a viewer → control follows, the
    /// PLAYING timeline advances (never rewinds), leave-teardown follows the
    /// NEW host, same-host handoff is a no-op, and a manager can hand off
    /// without being host.
    #[test]
    fn watch_host_handoff_lifecycle() {
        crate::util::test::rt().block_on(watch_host_handoff_lifecycle_case())
    }

    async fn watch_host_handoff_lifecycle_case() {
        let (harness, channel, uvc, user_a, token_a, user_b, token_b, _user_c, _token_c) =
            setup().await;

        let response = harness
            .client
            .post(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(yt("YE7VzlLtp-4").to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        // Play from 60 s so the handoff has a moving timeline to preserve.
        let response = harness
            .client
            .patch(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(
                serde_json::json!({ "playing": true, "position_ms": 60000, "rate_permille": 1000 })
                    .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let playing: v0::WatchSessionResponse =
            response.into_json().await.expect("update response");

        // Host hands to the viewer.
        let response = harness
            .client
            .put(format!("/channels/{}/watch/host", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(host_body(&user_b.id))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let handed: v0::WatchSessionResponse =
            response.into_json().await.expect("handoff response");
        assert_eq!(handed.session.host_id, user_b.id);
        assert_eq!(handed.session.id, playing.session.id);
        assert!(handed.session.seq > playing.session.seq);
        assert!(handed.session.playing, "handoff must not pause");
        assert!(
            handed.session.position_ms >= playing.session.position_ms,
            "a playing timeline must advance across handoff, never rewind"
        );
        assert!(handed.session.position_at >= playing.session.position_at);

        // The old host may no longer drive…
        let response = harness
            .client
            .patch(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(
                serde_json::json!({ "playing": false, "position_ms": 0, "rate_permille": 1000 })
                    .to_string(),
            )
            .dispatch()
            .await;
        // …except A is the server owner (ManageChannel), so drive via the
        // override is still allowed — the HOST though must be B now.
        assert_eq!(response.status(), Status::Ok);
        let driven: v0::WatchSessionResponse =
            response.into_json().await.expect("override response");
        assert_eq!(driven.session.host_id, user_b.id, "override must not steal host");

        // The new host drives.
        let response = harness
            .client
            .patch(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_b.clone()))
            .body(
                serde_json::json!({ "playing": true, "position_ms": 5000, "rate_permille": 1000 })
                    .to_string(),
            )
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        // Same-host handoff: idempotent, no seq minted.
        let before = fetch_watch_session(channel.id())
            .await
            .expect("session read")
            .expect("session");
        let response = harness
            .client
            .put(format!("/channels/{}/watch/host", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_b.clone()))
            .body(host_body(&user_b.id))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let same: v0::WatchSessionResponse =
            response.into_json().await.expect("idempotent response");
        assert_eq!(same.session.seq, before.seq, "no-op must not mint seq");

        // Leave semantics follow the CURRENT host: the old host leaving no
        // longer ends the session; the new host leaving does.
        delete_voice_state(&uvc, &user_a.id)
            .await
            .expect("old host leave");
        assert!(
            fetch_watch_session(channel.id())
                .await
                .expect("session read")
                .is_some(),
            "old host's leave must not end a handed-off session"
        );
        delete_voice_state(&uvc, &user_b.id)
            .await
            .expect("new host leave");
        assert!(fetch_watch_session(channel.id())
            .await
            .expect("session read")
            .is_none());
    }

    /// Handoff guards: target not in the call; caller neither host nor
    /// manager; and the permission-laundering case — a target IN the call
    /// but WITHOUT `UseWatchTogether` must be refused in a server channel,
    /// while a group DM (no voice bits at all) accepts handoff.
    #[test]
    fn watch_host_handoff_guards() {
        crate::util::test::rt().block_on(watch_host_handoff_guards_case())
    }

    async fn watch_host_handoff_guards_case() {
        use revolt_database::PartialServer;
        use revolt_permissions::ChannelPermission;

        let harness = TestHarness::new().await;
        let (_, session_a, user_a) = harness.new_user().await;
        let (_, session_b, user_b) = harness.new_user().await;
        let (_, _session_c, user_c) = harness.new_user().await;
        let (mut server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member b");
        Member::create(&harness.db, &server, &user_c, None)
            .await
            .expect("member c");
        let channel = voice_channel(&harness, &server, "Voice").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        create_voice_state(&uvc, &user_a.id, Timestamp::now_utc())
            .await
            .expect("voice state a");
        create_voice_state(&uvc, &user_b.id, Timestamp::now_utc())
            .await
            .expect("voice state b");
        let token_a = session_a.token;
        let token_b = session_b.token;

        let response = harness
            .client
            .post(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(yt("YE7VzlLtp-4").to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        // Target not in the call.
        let response = harness
            .client
            .put(format!("/channels/{}/watch/host", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(host_body(&user_c.id))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        // Caller is neither host nor manager.
        let response = harness
            .client
            .put(format!("/channels/{}/watch/host", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_b.clone()))
            .body(host_body(&user_b.id))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);

        // Strip `UseWatchTogether` from the default role: the target is in
        // the call but the permission table would refuse them control —
        // handoff must refuse too (the laundering test).
        let stripped =
            (server.default_permissions as u64) & !(ChannelPermission::UseWatchTogether as u64);
        server
            .update(
                &harness.db,
                PartialServer {
                    default_permissions: Some(stripped as i64),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("strip permission");
        let response = harness
            .client
            .put(format!("/channels/{}/watch/host", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(host_body(&user_b.id))
            .dispatch()
            .await;
        assert_eq!(
            response.status(),
            Status::Forbidden,
            "handoff must not launder UseWatchTogether"
        );

        delete_channel_voice_state(&uvc, &[user_a.id.clone(), user_b.id.clone()])
            .await
            .expect("teardown");

        // Group DM: no voice bits exist — handoff succeeds on Connect alone.
        // Groups create with calling off; the owner turns it on.
        let mut group = Channel::create_group(
            &harness.db,
            v0::DataCreateGroup {
                name: "watch group".to_string(),
                description: None,
                icon: None,
                users: std::collections::HashSet::from([user_b.id.clone()]),
                nsfw: None,
                spoiler: None,
            },
            user_a.id.clone(),
        )
        .await
        .expect("group");
        group
            .update(
                &harness.db,
                revolt_database::PartialChannel {
                    voice: Some(revolt_database::VoiceInformation {
                        max_users: None,
                        disabled: false,
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("enable group calling");
        let guvc = UserVoiceChannel::from_channel(&group);
        create_voice_state(&guvc, &user_a.id, Timestamp::now_utc())
            .await
            .expect("group voice a");
        create_voice_state(&guvc, &user_b.id, Timestamp::now_utc())
            .await
            .expect("group voice b");
        let response = harness
            .client
            .post(format!("/channels/{}/watch", group.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(yt("YE7VzlLtp-4").to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let response = harness
            .client
            .put(format!("/channels/{}/watch/host", group.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(host_body(&user_b.id))
            .dispatch()
            .await;
        assert_eq!(
            response.status(),
            Status::Ok,
            "group members hold no voice bits — handoff must stay Connect-only there"
        );

        delete_channel_voice_state(&guvc, &[user_a.id.clone(), user_b.id.clone()])
            .await
            .expect("group teardown");
    }

    /// The `watching` roster flag: refused while no session exists, set and
    /// cleared by the claim route, cleared for EVERY member when the session
    /// ends (host DELETE and host-leave both).
    #[test]
    fn watching_flag_roundtrip() {
        crate::util::test::rt().block_on(watching_flag_roundtrip_case())
    }

    async fn watching_flag_roundtrip_case() {
        use revolt_database::voice::get_voice_state;

        let (harness, channel, uvc, user_a, token_a, user_b, token_b, _user_c, _token_c) =
            setup().await;
        let watching = |value: bool| serde_json::json!({ "watching": value }).to_string();

        // No session yet: a true claim is refused, a clear is fine.
        let response = harness
            .client
            .put(format!("/channels/{}/watching", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_b.clone()))
            .body(watching(true))
            .dispatch()
            .await;
        assert_eq!(
            response.status(),
            Status::NotFound,
            "cannot advertise a party that does not exist"
        );
        let response = harness
            .client
            .put(format!("/channels/{}/watching", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_b.clone()))
            .body(watching(false))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);

        // Start a session; the viewer claims, clears, claims again.
        let response = harness
            .client
            .post(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(yt("YE7VzlLtp-4").to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        for (value, expect) in [(true, true), (true, true), (false, false), (true, true)] {
            let response = harness
                .client
                .put(format!("/channels/{}/watching", channel.id()))
                .header(ContentType::JSON)
                .header(Header::new("x-session-token", token_b.clone()))
                .body(watching(value))
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::NoContent);
            let state = get_voice_state(&uvc, &user_b.id)
                .await
                .expect("state read")
                .expect("state");
            assert_eq!(state.watching, expect);
        }

        // Host DELETE ends the session → every member's flag clears.
        let response = harness
            .client
            .delete(format!("/channels/{}/watch", channel.id()))
            .header(Header::new("x-session-token", token_a.clone()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);
        // NB: the route DELETE path does not enumerate members itself — the
        // clearing rides the database end-helpers, which the route calls
        // through delete_watch_session + fan; assert the flag is gone.
        let state = get_voice_state(&uvc, &user_b.id)
            .await
            .expect("state read")
            .expect("state");
        assert!(
            !state.watching,
            "session end must clear every member's watching flag"
        );

        // Same through the host-LEAVE teardown.
        let response = harness
            .client
            .post(format!("/channels/{}/watch", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_a.clone()))
            .body(yt("YE7VzlLtp-4").to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let response = harness
            .client
            .put(format!("/channels/{}/watching", channel.id()))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token_b.clone()))
            .body(watching(true))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);
        delete_voice_state(&uvc, &user_a.id)
            .await
            .expect("host leave");
        let state = get_voice_state(&uvc, &user_b.id)
            .await
            .expect("state read")
            .expect("state");
        assert!(
            !state.watching,
            "host-leave teardown must clear the watching flags too"
        );

        delete_channel_voice_state(&uvc, &[user_b.id.clone()])
            .await
            .expect("teardown");
    }
}
