#[cfg(feature = "validator")]
use validator::Validate;

/// Playback rate carried as thousandths (1000 = 1.0×) so the wire model has
/// no floats: every other `v0` type is integer-only and derives `Eq`.
pub const WATCH_RATE_NORMAL_PERMILLE: u32 = 1000;

/// Slowest / fastest host-selectable rate (0.25× … 2×, the YouTube embed's
/// range; HLS accepts more but the UI offers the same steps).
pub const WATCH_RATE_MIN_PERMILLE: u32 = 250;
pub const WATCH_RATE_MAX_PERMILLE: u32 = 2000;

auto_derived!(
    /// What a watch-together session is playing (watch-together plan §1).
    /// Provider-specific reference only — Sloga never hosts, proxies or
    /// relays the media; each viewer's client fetches it from the provider
    /// itself.
    #[serde(tag = "provider")]
    pub enum WatchMedia {
        /// A YouTube video played through the official embed
        #[serde(rename = "youtube")]
        YouTube {
            /// 11-character YouTube video id
            video_id: String,
            /// Title as reported by the embed once the host has loaded it
            /// (informational; late joiners show it before their own embed
            /// is ready)
            #[serde(skip_serializing_if = "Option::is_none")]
            title: Option<String>,
        },
        /// An item on a Jellyfin server the viewers each sign in to (slice 2)
        #[serde(rename = "jellyfin")]
        Jellyfin {
            /// Normalized base URL of the Jellyfin server (visible to every
            /// member of the voice channel — the private fan-out — never to
            /// text-channel lurkers)
            server_url: String,
            /// Jellyfin `System/Info/Public` server id
            server_id: String,
            /// Jellyfin item id
            item_id: String,
            /// Display name
            item_name: String,
            /// Jellyfin item kind (Movie, Episode, …)
            item_kind: String,
            /// Runtime in milliseconds (ticks ÷ 10 000 at the API boundary)
            runtime_ms: u64,
        },
    }

    /// The complete control state of a voice channel's watch-together
    /// session. Ephemeral (Redis, TTL-refreshed) — it dies with the host's
    /// voice state. The whole sync contract is
    /// `expected_position(now) = position_ms + (playing ? (now − position_at) × rate : 0)`.
    pub struct WatchSession {
        /// Session id (ulid) — clients key `last_seen_seq` by it
        pub id: String,
        /// Voice channel this session belongs to
        pub channel_id: String,
        /// The only user whose control writes are accepted (plus channel
        /// managers)
        pub host_id: String,
        /// What is being watched
        pub media: WatchMedia,
        /// Whether the host's timeline is advancing
        pub playing: bool,
        /// Host position (ms into the item) that was true at `position_at`
        pub position_ms: u64,
        /// SERVER unix-ms when `position_ms` was stamped — never the client's
        /// clock
        pub position_at: u64,
        /// Playback rate in thousandths (1000 = 1.0×)
        pub rate_permille: u32,
        /// Monotonic per channel (Redis INCR); receivers drop anything ≤ the
        /// last value they applied for this `id`
        pub seq: u64,
        /// Server unix-ms the session was created
        pub started_at: u64,
    }

    /// Session plus the server clock, so clients derive their offset from
    /// the HTTP round trip (`offset = server_now − (t_send + rtt/2)`).
    pub struct WatchSessionResponse {
        pub session: WatchSession,
        /// Server unix-ms at response time
        pub server_now: u64,
    }

    /// Start a watch-together session (the caller becomes host). Playback
    /// starts paused at 0.
    pub struct DataWatchCreate {
        pub media: WatchMedia,
    }

    /// Host control write AND heartbeat — always the FULL host-owned state,
    /// so an interleaved heartbeat can never roll back a control change.
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataWatchUpdate {
        pub playing: bool,
        pub position_ms: u64,
        /// Thousandths, 250..=2000
        #[cfg_attr(feature = "validator", validate(range(min = 250, max = 2000)))]
        pub rate_permille: u32,
        /// Swap the item without ending the session (resets nothing else —
        /// the host sends `position_ms: 0` alongside)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub media: Option<WatchMedia>,
    }
);
