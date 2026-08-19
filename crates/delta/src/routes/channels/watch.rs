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
    util::{permissions::perms, reference::Reference},
    voice::{
        is_in_voice_channel,
        watch::{
            create_watch_session, delete_watch_session, fan_watch_end, fan_watch_update,
            fetch_watch_session, now_ms, update_watch_session,
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
    #[rocket::async_test]
    async fn watch_session_lifecycle() {
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
    #[rocket::async_test]
    async fn watch_session_guards() {
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
    #[rocket::async_test]
    async fn watch_session_manager_override() {
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
    #[rocket::async_test]
    async fn watch_session_ends_when_host_leaves() {
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
}
