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

    /// Hand the session to a new host (watch-together plan §7.3, 4a). The
    /// target must be in the call and, in server channels, hold
    /// `UseWatchTogether` — handoff must not launder the control permission.
    pub struct DataWatchHost {
        /// User id of the new host
        pub user: String,
    }

    /// Set the caller's `watching` roster flag (watch-together plan §7.3,
    /// 4b). Unlike `rc_capable` this claim goes BOTH ways — a client
    /// announces attach AND detach — so the body carries the desired value.
    pub struct DataSetWatching {
        pub watching: bool,
    }
);

impl WatchSession {
    /// Advance the stored timeline to `now` — the server-side twin of the
    /// client's `expected_position` formula. Used by writes that mutate
    /// NON-timeline fields (host handoff): `update_watch_session` re-stamps
    /// `position_at` after the closure runs, which silently REWINDS a
    /// playing session unless `position_ms` is advanced to match first.
    /// Paused sessions are untouched.
    pub fn advance_to(&mut self, now_ms: u64) {
        if self.playing {
            let elapsed = now_ms.saturating_sub(self.position_at) as u128;
            let advance = elapsed * self.rate_permille as u128 / 1000;
            self.position_ms = self.position_ms.saturating_add(advance as u64);
            self.position_at = now_ms;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(playing: bool) -> WatchSession {
        WatchSession {
            id: "01H0000000000000000000TEST".to_string(),
            channel_id: "channel".to_string(),
            host_id: "host".to_string(),
            media: WatchMedia::YouTube {
                video_id: "dQw4w9WgXcQ".to_string(),
                title: None,
            },
            playing,
            position_ms: 60_000,
            position_at: 1_000_000,
            rate_permille: 1500,
            seq: 7,
            started_at: 900_000,
        }
    }

    #[test]
    fn advance_to_moves_a_playing_timeline_at_rate() {
        let mut s = session(true);
        // 10 s of wall clock at 1.5× = 15 s of content.
        s.advance_to(1_010_000);
        assert_eq!(s.position_ms, 75_000);
        assert_eq!(s.position_at, 1_010_000);
    }

    #[test]
    fn advance_to_is_a_noop_while_paused() {
        let mut s = session(false);
        s.advance_to(1_010_000);
        assert_eq!(s.position_ms, 60_000);
        assert_eq!(s.position_at, 1_000_000);
    }

    #[test]
    fn advance_to_never_rewinds_on_a_clock_step() {
        let mut s = session(true);
        // A server clock that reads BEFORE position_at (an NTP step) must
        // not underflow or rewind.
        s.advance_to(999_000);
        assert_eq!(s.position_ms, 60_000);
    }
}
