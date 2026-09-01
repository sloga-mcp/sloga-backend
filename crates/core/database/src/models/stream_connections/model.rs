use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::{ConnectionPlatform, Database, FieldsUser, PartialUser, UserConnection};

auto_derived!(
    /// Live-stream state of a linked channel, written by the crond poller.
    pub struct StreamLiveState {
        /// Title of the current stream (truncated server-side)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub title: Option<String>,
        /// When the stream started
        pub started_at: Timestamp,
    }

    /// A streaming channel a user linked via OAuth.
    ///
    /// PRIVATE collection (`user_stream_connections`) — this is the ONLY
    /// place provider tokens may live. The public, token-free projection
    /// is denormalized onto `User.connections` by [`StreamConnection::
    /// sync_user_field`]; tokens must never ride `User`/`PartialUser`
    /// (those fan out over WebSocket).
    pub struct StreamConnection {
        /// `{user_id}/{platform}` — one connection per platform per user
        #[serde(rename = "_id")]
        pub id: String,
        /// Owning user
        pub user_id: String,
        /// Which platform the channel is on
        pub platform: ConnectionPlatform,
        /// Provider channel id (Twitch user id / YouTube channel id /
        /// Kick broadcaster user id)
        pub channel_id: String,
        /// Channel handle (Twitch login / YouTube @handle / Kick slug) for URLs
        pub handle: String,
        /// Channel display name
        pub display_name: String,
        /// OAuth refresh token (YouTube only; Twitch and Kick store NO
        /// user tokens)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub refresh_token: Option<String>,
        /// Cached short-lived access token (YouTube only)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub access_token: Option<String>,
        /// When `access_token` expires
        #[serde(skip_serializing_if = "Option::is_none")]
        pub token_expiry: Option<Timestamp>,
        /// Current live state, present while the channel is live
        #[serde(skip_serializing_if = "Option::is_none")]
        pub live: Option<StreamLiveState>,
        /// Consecutive poller failures (token refresh / API); connections
        /// past the failure cap are auto-unlinked
        #[serde(skip_serializing_if = "crate::if_zero_u32", default)]
        pub poll_failures: u32,
        /// Last time friends were push-notified of a go-live (flap hysteresis)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub last_notified_live_at: Option<Timestamp>,
    }
);

impl ConnectionPlatform {
    /// Stable lowercase key used in document ids and route params
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionPlatform::Twitch => "twitch",
            ConnectionPlatform::YouTube => "youtube",
            ConnectionPlatform::Kick => "kick",
        }
    }

    /// The serde-serialized variant name as stored in the `platform`
    /// field of documents (Mongo query filters must use THIS, not the
    /// lowercase key).
    pub fn as_variant_str(&self) -> &'static str {
        match self {
            ConnectionPlatform::Twitch => "Twitch",
            ConnectionPlatform::YouTube => "YouTube",
            ConnectionPlatform::Kick => "Kick",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "twitch" => Some(ConnectionPlatform::Twitch),
            "youtube" => Some(ConnectionPlatform::YouTube),
            "kick" => Some(ConnectionPlatform::Kick),
            _ => None,
        }
    }
}

impl StreamConnection {
    /// Composite document id
    pub fn compose_id(user_id: &str, platform: &ConnectionPlatform) -> String {
        format!("{}/{}", user_id, platform.as_str())
    }

    /// Token-free public projection for `User.connections`
    pub fn to_public(&self) -> UserConnection {
        UserConnection {
            platform: self.platform.clone(),
            handle: self.handle.clone(),
            display_name: self.display_name.clone(),
            live: self.live.is_some(),
            live_title: self.live.as_ref().and_then(|l| l.title.clone()),
            live_since: self.live.as_ref().map(|l| l.started_at),
        }
    }

    /// Rebuild the denormalized `User.connections` field from this
    /// collection and broadcast the change (standard `User::update` path →
    /// `UserUpdate` fan-out to friends + mutual-server members).
    ///
    /// Call after every mutation: link, unlink, live flip, account cascade.
    pub async fn sync_user_field(db: &Database, user_id: &str) -> Result<()> {
        let rows = db.fetch_stream_connections_for_user(user_id).await?;
        let mut user = db.fetch_user(user_id).await?;

        let mut connections: Vec<UserConnection> =
            rows.iter().map(StreamConnection::to_public).collect();
        connections.sort_by_key(|c| c.platform.as_str());

        if connections.is_empty() {
            user.update(db, PartialUser::default(), vec![FieldsUser::Connections])
                .await
        } else {
            user.update(
                db,
                PartialUser {
                    connections: Some(connections),
                    ..Default::default()
                },
                vec![],
            )
            .await
        }
    }

    /// Best-effort revocation of the provider refresh token (YouTube only;
    /// Twitch connections hold no user tokens). Errors are swallowed — the
    /// row is going away regardless.
    pub async fn revoke_tokens(&self) {
        if matches!(self.platform, ConnectionPlatform::YouTube) {
            if let Some(token) = self.refresh_token.as_ref().or(self.access_token.as_ref()) {
                let _ = reqwest::Client::new()
                    .post("https://oauth2.googleapis.com/revoke")
                    .form(&[("token", token.as_str())])
                    .send()
                    .await;
            }
        }
    }

    /// Delete every connection a user holds, optionally revoking provider
    /// tokens, WITHOUT touching the user document (account-deletion
    /// cascade — the user is being marked deleted anyway).
    pub async fn delete_all_for_user(db: &Database, user_id: &str, revoke: bool) -> Result<()> {
        let rows = db.delete_stream_connections_for_user(user_id).await?;

        if revoke {
            for row in rows {
                row.revoke_tokens().await;
            }
        }

        Ok(())
    }
}
