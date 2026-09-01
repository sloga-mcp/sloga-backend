//! Live-status poller for linked streaming channels (Twitch / YouTube /
//! Kick).
//!
//! On every live↔offline flip (or title change) the denormalized
//! `User.connections` field is rebuilt via `StreamConnection::
//! sync_user_field`, whose `UserUpdate` rides the existing fan-out to
//! friends + mutual-server members (LIVE badge). On an offline→live
//! transition friends additionally get a push notification, throttled by
//! a per-connection hysteresis so flapping streams don't spam.
//!
//! Twitch: one app access token (client credentials, cached in Redis),
//! `helix/streams` batched 100 ids per call, checked every tick.
//! YouTube: the user's own refresh token drives `liveBroadcasts.list`
//! (1 quota unit vs 100 for search.list), checked every 5th tick —
//! ~288 units/user/day against the default 10k/day quota (~30 linked
//! users; WebSub is the upgrade path beyond that).
//! Kick: same shape as Twitch — one app access token (client credentials,
//! cached in Redis), `public/v1/channels` batched 50 ids per call, checked
//! every tick. No user tokens, so no failure/auto-unlink accounting.

use std::collections::HashMap;
use std::time::Duration;

use iso8601_timestamp::Timestamp;
use redis_kiss::{get_connection, redis, AsyncCommands};
use revolt_database::{
    ConnectionPlatform, Database, RelationshipStatus, StreamConnection, StreamLiveState, User,
    AMQP,
};
use revolt_result::Result;
use tokio::time::sleep;

const TICK: Duration = Duration::from_secs(60);
/// YouTube checked every Nth tick (quota, see module doc)
const YOUTUBE_TICK_DIVISOR: u64 = 5;
/// Stream titles are user-generated remote content — bound them
const MAX_TITLE_CHARS: usize = 128;
/// Consecutive YouTube failures (revoked consent, dead refresh token)
/// before the connection is auto-unlinked
const MAX_POLL_FAILURES: u32 = 12;
/// Minimum gap between go-live push notifications per connection
const NOTIFY_HYSTERESIS_MINS: i64 = 30;

const TWITCH_APP_TOKEN_KEY: &str = "oauth:twitch:app_token";
const KICK_APP_TOKEN_KEY: &str = "oauth:kick:app_token";

pub async fn task(db: Database, amqp: AMQP) -> Result<()> {
    let mut tick: u64 = 0;

    loop {
        let config = revolt_config::config().await;

        if config.api.oauth.twitch.enabled {
            if let Err(error) = poll_twitch(&db, &amqp).await {
                log::error!("twitch live poll failed: {error:?}");
            }
        }

        if config.api.oauth.kick.enabled {
            if let Err(error) = poll_kick(&db, &amqp).await {
                log::error!("kick live poll failed: {error:?}");
            }
        }

        if config.api.oauth.youtube.enabled && tick % YOUTUBE_TICK_DIVISOR == 0 {
            if let Err(error) = poll_youtube(&db, &amqp).await {
                log::error!("youtube live poll failed: {error:?}");
            }
        }

        tick = tick.wrapping_add(1);
        sleep(TICK).await
    }
}

fn truncate_title(title: String) -> String {
    if title.chars().count() > MAX_TITLE_CHARS {
        title.chars().take(MAX_TITLE_CHARS).collect()
    } else {
        title
    }
}

/// Apply a freshly observed live state to a connection; returns whether
/// anything changed (and therefore was saved + synced).
async fn apply_live_state(
    db: &Database,
    amqp: &AMQP,
    connection: &mut StreamConnection,
    observed: Option<StreamLiveState>,
) {
    let was_live = connection.live.is_some();
    let is_live = observed.is_some();
    let changed = match (&connection.live, &observed) {
        (None, None) => false,
        (Some(old), Some(new)) => old.title != new.title || old.started_at != new.started_at,
        _ => true,
    };

    if !changed {
        return;
    }

    connection.live = observed;

    // Push BEFORE the hysteresis stamp is decided so the stamp reflects
    // what we actually did this transition
    let should_notify = !was_live
        && is_live
        && connection
            .last_notified_live_at
            .and_then(|last| last.checked_add(iso8601_timestamp::Duration::minutes(NOTIFY_HYSTERESIS_MINS)))
            .map(|until| until < Timestamp::now_utc())
            .unwrap_or(true);

    if should_notify {
        connection.last_notified_live_at = Some(Timestamp::now_utc());
    }

    if db.save_stream_connection(connection).await.is_err() {
        return;
    }

    // Badge fan-out (friends + mutual servers) via the standard path
    if let Err(error) = StreamConnection::sync_user_field(db, &connection.user_id).await {
        log::error!("failed to sync connections for {}: {error:?}", connection.user_id);
    }

    if should_notify {
        notify_friends(db, amqp, connection).await;
    }
}

/// Push "X is live" to the streamer's FRIENDS only — server members get
/// the badge, not a push (spam control, per design doc §4)
async fn notify_friends(db: &Database, amqp: &AMQP, connection: &StreamConnection) {
    let Ok(streamer) = db.fetch_user(&connection.user_id).await else {
        return;
    };

    let platform_label = match connection.platform {
        ConnectionPlatform::Twitch => "Twitch",
        ConnectionPlatform::YouTube => "YouTube",
        ConnectionPlatform::Kick => "Kick",
    };
    let streamer_name = streamer
        .display_name
        .clone()
        .unwrap_or_else(|| streamer.username.clone());
    let title = format!("{} is live on {}", streamer_name, platform_label);
    let body = connection
        .live
        .as_ref()
        .and_then(|live| live.title.clone())
        .unwrap_or_else(|| connection.display_name.clone());

    for relation in streamer.relations.iter().flatten() {
        if !matches!(relation.status, RelationshipStatus::Friend) {
            continue;
        }

        if let Ok(friend) = db.fetch_user(&relation.id).await {
            if let Err(error) = amqp
                .generic_message(&friend, title.clone(), body.clone(), None)
                .await
            {
                log::warn!("go-live push to {} failed: {error:?}", friend.id);
            }
        }
    }
}

// -------------------------------------------------------------------------
// Twitch
// -------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct TwitchTokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(serde::Deserialize)]
struct TwitchStreamsResponse {
    data: Vec<TwitchStream>,
}

#[derive(serde::Deserialize)]
struct TwitchStream {
    user_id: String,
    title: String,
    started_at: String,
    #[serde(rename = "type")]
    stream_type: String,
}

/// Client-credentials app token, cached in Redis with an early-expiry margin
async fn twitch_app_token(force_refresh: bool) -> Option<String> {
    let mut conn = get_connection().await.ok()?.into_inner();

    if !force_refresh {
        if let Ok(Some(token)) = conn.get::<_, Option<String>>(TWITCH_APP_TOKEN_KEY).await {
            return Some(token);
        }
    }

    let config = revolt_config::config().await;
    let twitch = &config.api.oauth.twitch;

    let response = reqwest::Client::new()
        .post("https://id.twitch.tv/oauth2/token")
        .form(&[
            ("client_id", twitch.client_id.as_str()),
            ("client_secret", twitch.client_secret.as_str()),
            ("grant_type", "client_credentials"),
        ])
        .send()
        .await
        .ok()?;

    if !response.status().is_success() {
        return None;
    }

    let tokens: TwitchTokenResponse = response.json().await.ok()?;

    let _: Option<String> = conn
        .set_options(
            TWITCH_APP_TOKEN_KEY,
            &tokens.access_token,
            redis::SetOptions::default()
                .with_expiration(redis::SetExpiry::EX(tokens.expires_in.saturating_sub(300) as usize)),
        )
        .await
        .ok();

    Some(tokens.access_token)
}

async fn poll_twitch(db: &Database, amqp: &AMQP) -> Result<()> {
    let rows = db
        .fetch_stream_connections_by_platform(&ConnectionPlatform::Twitch)
        .await?;
    if rows.is_empty() {
        return Ok(());
    }

    let config = revolt_config::config().await;
    let Some(mut token) = twitch_app_token(false).await else {
        log::warn!("could not obtain twitch app token");
        return Ok(());
    };

    for chunk in rows.chunks(100) {
        let ids: Vec<(&str, &str)> = chunk
            .iter()
            .map(|row| ("user_id", row.channel_id.as_str()))
            .collect();

        let mut response = reqwest::Client::new()
            .get("https://api.twitch.tv/helix/streams")
            .query(&ids)
            .bearer_auth(&token)
            .header("Client-Id", config.api.oauth.twitch.client_id.as_str())
            .send()
            .await
            .map_err(|_| revolt_result::create_error!(InternalError))?;

        // Expired app token — refresh once and retry the batch
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            let Some(fresh) = twitch_app_token(true).await else {
                return Ok(());
            };
            token = fresh;
            response = reqwest::Client::new()
                .get("https://api.twitch.tv/helix/streams")
                .query(&ids)
                .bearer_auth(&token)
                .header("Client-Id", config.api.oauth.twitch.client_id.as_str())
                .send()
                .await
                .map_err(|_| revolt_result::create_error!(InternalError))?;
        }

        if !response.status().is_success() {
            log::warn!("twitch helix/streams returned {}", response.status());
            continue;
        }

        let streams: TwitchStreamsResponse = response
            .json()
            .await
            .map_err(|_| revolt_result::create_error!(InternalError))?;

        let live_by_channel: HashMap<String, StreamLiveState> = streams
            .data
            .into_iter()
            .filter(|stream| stream.stream_type == "live")
            .map(|stream| {
                (
                    stream.user_id,
                    StreamLiveState {
                        title: Some(truncate_title(stream.title)),
                        started_at: Timestamp::parse(&stream.started_at)
                            .unwrap_or_else(Timestamp::now_utc),
                    },
                )
            })
            .collect();

        for row in chunk {
            let mut connection = row.clone();
            let observed = live_by_channel.get(&connection.channel_id).cloned();
            apply_live_state(db, amqp, &mut connection, observed).await;
        }
    }

    Ok(())
}

// -------------------------------------------------------------------------
// Kick
// -------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct KickTokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(serde::Deserialize)]
struct KickChannelsResponse {
    #[serde(default)]
    data: Vec<KickChannel>,
}

#[derive(serde::Deserialize)]
struct KickChannel {
    broadcaster_user_id: u64,
    #[serde(default)]
    stream_title: Option<String>,
    #[serde(default)]
    stream: Option<KickStream>,
}

#[derive(serde::Deserialize)]
struct KickStream {
    #[serde(default)]
    is_live: bool,
    #[serde(default)]
    start_time: Option<String>,
}

/// Client-credentials app token, cached in Redis with an early-expiry margin
async fn kick_app_token(force_refresh: bool) -> Option<String> {
    let mut conn = get_connection().await.ok()?.into_inner();

    if !force_refresh {
        if let Ok(Some(token)) = conn.get::<_, Option<String>>(KICK_APP_TOKEN_KEY).await {
            return Some(token);
        }
    }

    let config = revolt_config::config().await;
    let kick = &config.api.oauth.kick;

    let response = reqwest::Client::new()
        .post("https://id.kick.com/oauth/token")
        .form(&[
            ("client_id", kick.client_id.as_str()),
            ("client_secret", kick.client_secret.as_str()),
            ("grant_type", "client_credentials"),
        ])
        .send()
        .await
        .ok()?;

    if !response.status().is_success() {
        return None;
    }

    let tokens: KickTokenResponse = response.json().await.ok()?;

    let _: Option<String> = conn
        .set_options(
            KICK_APP_TOKEN_KEY,
            &tokens.access_token,
            redis::SetOptions::default()
                .with_expiration(redis::SetExpiry::EX(tokens.expires_in.saturating_sub(300) as usize)),
        )
        .await
        .ok();

    Some(tokens.access_token)
}

async fn poll_kick(db: &Database, amqp: &AMQP) -> Result<()> {
    let rows = db
        .fetch_stream_connections_by_platform(&ConnectionPlatform::Kick)
        .await?;
    if rows.is_empty() {
        return Ok(());
    }

    let Some(mut token) = kick_app_token(false).await else {
        log::warn!("could not obtain kick app token");
        return Ok(());
    };

    for chunk in rows.chunks(50) {
        let ids: Vec<(&str, &str)> = chunk
            .iter()
            .map(|row| ("broadcaster_user_id", row.channel_id.as_str()))
            .collect();

        let mut response = reqwest::Client::new()
            .get("https://api.kick.com/public/v1/channels")
            .query(&ids)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|_| revolt_result::create_error!(InternalError))?;

        // Expired app token — refresh once and retry the batch
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            let Some(fresh) = kick_app_token(true).await else {
                return Ok(());
            };
            token = fresh;
            response = reqwest::Client::new()
                .get("https://api.kick.com/public/v1/channels")
                .query(&ids)
                .bearer_auth(&token)
                .send()
                .await
                .map_err(|_| revolt_result::create_error!(InternalError))?;
        }

        if !response.status().is_success() {
            log::warn!("kick channels returned {}", response.status());
            continue;
        }

        let channels: KickChannelsResponse = response
            .json()
            .await
            .map_err(|_| revolt_result::create_error!(InternalError))?;

        // title + parsed start (None = missing/unparseable), keyed by id
        let live_by_channel: HashMap<String, (Option<String>, Option<Timestamp>)> = channels
            .data
            .into_iter()
            .filter(|channel| channel.stream.as_ref().is_some_and(|s| s.is_live))
            .map(|channel| {
                let started_at = channel
                    .stream
                    .as_ref()
                    .and_then(|s| s.start_time.as_deref())
                    .and_then(Timestamp::parse);
                (
                    channel.broadcaster_user_id.to_string(),
                    (
                        channel
                            .stream_title
                            .filter(|title| !title.is_empty())
                            .map(truncate_title),
                        started_at,
                    ),
                )
            })
            .collect();

        for row in chunk {
            let mut connection = row.clone();
            let observed = live_by_channel
                .get(&connection.channel_id)
                .map(|(title, started_at)| StreamLiveState {
                    title: title.clone(),
                    // If Kick's start_time didn't parse, keep the timestamp
                    // we already have for an ongoing stream — a fresh
                    // now_utc() every tick would trip apply_live_state's
                    // change gate (save + fan-out) once a minute for nothing
                    started_at: started_at
                        .or_else(|| connection.live.as_ref().map(|live| live.started_at))
                        .unwrap_or_else(Timestamp::now_utc),
                });
            apply_live_state(db, amqp, &mut connection, observed).await;
        }
    }

    Ok(())
}

// -------------------------------------------------------------------------
// YouTube
// -------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct YoutubeTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(serde::Deserialize)]
struct YoutubeBroadcastsResponse {
    #[serde(default)]
    items: Vec<YoutubeBroadcast>,
}

#[derive(serde::Deserialize)]
struct YoutubeBroadcast {
    snippet: YoutubeBroadcastSnippet,
    status: YoutubeBroadcastStatus,
}

#[derive(serde::Deserialize)]
struct YoutubeBroadcastSnippet {
    title: String,
    #[serde(rename = "actualStartTime")]
    #[serde(default)]
    actual_start_time: Option<String>,
}

#[derive(serde::Deserialize)]
struct YoutubeBroadcastStatus {
    #[serde(rename = "lifeCycleStatus")]
    life_cycle_status: String,
}

/// Ensure a usable access token, refreshing (and persisting) if needed.
/// `None` = refresh failed — caller counts it toward auto-unlink.
async fn youtube_access_token(
    db: &Database,
    connection: &mut StreamConnection,
) -> Option<String> {
    let needs_refresh = match (&connection.access_token, &connection.token_expiry) {
        (Some(_), Some(expiry)) => {
            expiry
                .checked_sub(iso8601_timestamp::Duration::seconds(60))
                .map(|margin| margin < Timestamp::now_utc())
                .unwrap_or(true)
        }
        _ => true,
    };

    if !needs_refresh {
        return connection.access_token.clone();
    }

    let refresh_token = connection.refresh_token.clone()?;
    let config = revolt_config::config().await;
    let youtube = &config.api.oauth.youtube;

    let response = reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", youtube.client_id.as_str()),
            ("client_secret", youtube.client_secret.as_str()),
            ("refresh_token", refresh_token.as_str()),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .await
        .ok()?;

    if !response.status().is_success() {
        return None;
    }

    let tokens: YoutubeTokenResponse = response.json().await.ok()?;

    connection.access_token = Some(tokens.access_token.clone());
    connection.token_expiry = tokens.expires_in.and_then(|secs| {
        Timestamp::now_utc().checked_add(iso8601_timestamp::Duration::seconds(secs as i64))
    });
    let _ = db.save_stream_connection(connection).await;

    Some(tokens.access_token)
}

async fn poll_youtube(db: &Database, amqp: &AMQP) -> Result<()> {
    let rows = db
        .fetch_stream_connections_by_platform(&ConnectionPlatform::YouTube)
        .await?;

    for row in rows {
        let mut connection = row;

        let Some(token) = youtube_access_token(db, &mut connection).await else {
            connection.poll_failures += 1;

            if connection.poll_failures >= MAX_POLL_FAILURES {
                // Consent revoked or refresh token dead — stop polling a
                // corpse: auto-unlink and update the public field
                log::warn!(
                    "auto-unlinking youtube connection for {} after {} failures",
                    connection.user_id,
                    connection.poll_failures
                );
                let _ = db
                    .delete_stream_connection(&connection.user_id, &ConnectionPlatform::YouTube)
                    .await;
                let _ = StreamConnection::sync_user_field(db, &connection.user_id).await;
            } else {
                let _ = db.save_stream_connection(&connection).await;
            }
            continue;
        };

        let response = reqwest::Client::new()
            .get("https://www.googleapis.com/youtube/v3/liveBroadcasts")
            .query(&[
                ("part", "id,snippet,status"),
                ("broadcastStatus", "active"),
                ("maxResults", "5"),
            ])
            .bearer_auth(&token)
            .send()
            .await;

        let response = match response {
            Ok(response) if response.status().is_success() => response,
            Ok(response) => {
                log::warn!("youtube liveBroadcasts returned {}", response.status());
                connection.poll_failures += 1;
                // API failures count toward the same auto-unlink cap as
                // refresh failures — a permanently-403ing connection is
                // just as dead as one with a revoked refresh token
                if connection.poll_failures >= MAX_POLL_FAILURES {
                    log::warn!(
                        "auto-unlinking youtube connection for {} after {} failures",
                        connection.user_id,
                        connection.poll_failures
                    );
                    let _ = db
                        .delete_stream_connection(
                            &connection.user_id,
                            &ConnectionPlatform::YouTube,
                        )
                        .await;
                    let _ = StreamConnection::sync_user_field(db, &connection.user_id).await;
                } else {
                    let _ = db.save_stream_connection(&connection).await;
                }
                continue;
            }
            Err(_) => continue,
        };

        let Ok(broadcasts) = response.json::<YoutubeBroadcastsResponse>().await else {
            continue;
        };

        // Persist the reset: apply_live_state's change gate skips its save
        // in the common nothing-changed case, and an unpersisted reset
        // makes the DB counter CUMULATIVE — 12 transient blips over weeks
        // would auto-unlink a healthy connection
        if connection.poll_failures != 0 {
            connection.poll_failures = 0;
            let _ = db.save_stream_connection(&connection).await;
        }

        // `broadcastStatus=active` still includes ready/testing persistent
        // broadcasts — only lifeCycleStatus "live" counts
        let observed = broadcasts
            .items
            .into_iter()
            .find(|broadcast| broadcast.status.life_cycle_status == "live")
            .map(|broadcast| StreamLiveState {
                title: Some(truncate_title(broadcast.snippet.title)),
                started_at: broadcast
                    .snippet
                    .actual_start_time
                    .as_deref()
                    .and_then(Timestamp::parse)
                    .unwrap_or_else(Timestamp::now_utc),
            });

        apply_live_state(db, amqp, &mut connection, observed).await;
    }

    Ok(())
}
