//! Pure helpers for audio link embeds and the `/audio` relay.
//!
//! Everything here is side-effect free: no I/O, no config, no logging.
//! Classification (`generate_embed`) and the `/audio` route both use
//! [`canonical_type`], so the embed's `content_type` and the relayed
//! `Content-Type` can never disagree.

/// Minimum number of leading bytes [`sniff_ok`] needs to check a format's magic.
///
/// Callers with fewer bytes available (e.g. a `bytes=0-1` probe) skip the
/// magic check rather than calling [`sniff_ok`] with a short head.
pub const SNIFF_MIN_BYTES: usize = 16;

/// Upper bound on how many body bytes classification reads from upstream.
///
/// `fetch_audio_metadata` never reads more than this, whatever the file size.
pub const METADATA_READ_BYTES: usize = 64 * 1024;

/// Canonical Content-Type for an allowlisted upstream type, else `None`.
///
/// Decided by the upstream type alone (parameters ignored), per the plan's
/// table: `audio/mpeg|mp3|x-mpeg` -> `audio/mpeg`, `audio/mp4|x-m4a|m4a` ->
/// `audio/mp4`, `audio/aac|x-aac` -> `audio/aac`,
/// `audio/wav|x-wav|wave|vnd.wave` -> `audio/wav`,
/// `audio/ogg|opus` + `application/ogg` -> `audio/ogg`,
/// `audio/flac|x-flac` -> `audio/flac`, `audio/webm` -> `audio/webm`.
/// Anything else (including `application/octet-stream` and `video/*`) -> `None`.
pub fn canonical_type(mime: &mime::Mime) -> Option<&'static str> {
    let _ = mime;
    todo!("wave 3")
}

/// True when `head` (at least [`SNIFF_MIN_BYTES`] long) carries the magic for
/// `canonical` (a value returned by [`canonical_type`]); false otherwise,
/// including when `head` is shorter than [`SNIFF_MIN_BYTES`] or `canonical`
/// is not a known canonical type.
///
/// Magic can only reject: it never changes which canonical type is used.
pub fn sniff_ok(canonical: &str, head: &[u8]) -> bool {
    let _ = (canonical, head);
    todo!("wave 3")
}

/// Last path segment of `url`, percent-decoded, truncated to at most 128
/// characters via `chars().take(128)` (never `String::truncate`, which panics
/// off a char boundary). `None` if the segment is empty.
pub fn filename_from_url(url: &url::Url) -> Option<String> {
    let _ = url;
    todo!("wave 3")
}

/// Parse a single `bytes=start-[end]` range into `(start, end)`.
///
/// Multi-range (`bytes=0-1,5-6`), suffix (`bytes=-500`), non-`bytes` units,
/// `end < start` and otherwise malformed values -> `None`.
pub fn parse_range(value: &str) -> Option<(u64, Option<u64>)> {
    let _ = value;
    todo!("wave 3")
}

/// Full resource size of an upstream response.
///
/// `206` -> the total from `Content-Range: bytes a-b/TOTAL` (`None` when the
/// total is `*` or unparsable); `200` -> `Content-Length`; any other status
/// -> `None`.
pub fn total_size(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Option<u64> {
    let _ = (status, headers);
    todo!("wave 3")
}
