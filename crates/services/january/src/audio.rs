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
    // `essence_str` is `type/subtype[+suffix]` without parameters, so a
    // suffixed type (`audio/mpeg+xml`) matches no row.
    match mime.essence_str().to_ascii_lowercase().as_str() {
        "audio/mpeg" | "audio/mp3" | "audio/x-mpeg" => Some("audio/mpeg"),
        "audio/mp4" | "audio/x-m4a" | "audio/m4a" => Some("audio/mp4"),
        "audio/aac" | "audio/x-aac" => Some("audio/aac"),
        "audio/wav" | "audio/x-wav" | "audio/wave" | "audio/vnd.wave" => Some("audio/wav"),
        "audio/ogg" | "audio/opus" | "application/ogg" => Some("audio/ogg"),
        "audio/flac" | "audio/x-flac" => Some("audio/flac"),
        "audio/webm" => Some("audio/webm"),
        _ => None,
    }
}

/// True when `head` (at least [`SNIFF_MIN_BYTES`] long) carries the magic for
/// `canonical` (a value returned by [`canonical_type`]); false otherwise,
/// including when `head` is shorter than [`SNIFF_MIN_BYTES`] or `canonical`
/// is not a known canonical type.
///
/// Magic can only reject: it never changes which canonical type is used.
pub fn sniff_ok(canonical: &str, head: &[u8]) -> bool {
    if head.len() < SNIFF_MIN_BYTES {
        return false;
    }

    match canonical {
        "audio/mpeg" => head.starts_with(b"ID3") || mpeg_frames_ok(head),
        "audio/mp4" => &head[4..8] == b"ftyp",
        // ADTS: 12-bit sync, layer bits zero.
        "audio/aac" => head[0] == 0xFF && (head[1] & 0xF6) == 0xF0,
        "audio/wav" => head.starts_with(b"RIFF") && &head[8..12] == b"WAVE",
        "audio/ogg" => head.starts_with(b"OggS"),
        "audio/flac" => head.starts_with(b"fLaC"),
        "audio/webm" => head.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]),
        _ => false,
    }
}

/// A valid MPEG audio frame header at 0 and, when `head` reaches it, another
/// valid header where that frame says the next one starts.
fn mpeg_frames_ok(head: &[u8]) -> bool {
    let Some(len) = mpeg_frame_len(head) else {
        return false;
    };

    match head.get(len..) {
        Some(next) if next.len() >= 4 => mpeg_frame_len(next).is_some(),
        // The next frame lies beyond what was read; the first header decides.
        _ => true,
    }
}

/// Bitrates in kbps by bitrate index (0 = free format, 15 = invalid; both are
/// rejected before lookup). Rows: MPEG-1 layer I, II, III; MPEG-2/2.5 layer I,
/// II and III.
#[rustfmt::skip]
const MPEG_KBPS: [[usize; 15]; 5] = [
    [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448],
    [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384],
    [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320],
    [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256],
    [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
];

/// Length in bytes of the MPEG audio frame whose header starts `bytes`, or
/// `None` when there is no valid header there (no 11-bit sync, a reserved
/// version or layer, a free-format or invalid bitrate, a reserved sample rate).
fn mpeg_frame_len(bytes: &[u8]) -> Option<usize> {
    let header = bytes.get(..4)?;
    if header[0] != 0xFF || header[1] & 0xE0 != 0xE0 {
        return None;
    }

    // Version: 0 = MPEG-2.5, 1 = reserved, 2 = MPEG-2, 3 = MPEG-1.
    let version = (header[1] >> 3) & 0b11;
    // Layer: 0 = reserved, 1 = III, 2 = II, 3 = I.
    let layer = (header[1] >> 1) & 0b11;
    let bitrate_index = (header[2] >> 4) as usize;
    let rate_index = ((header[2] >> 2) & 0b11) as usize;
    let padding = ((header[2] >> 1) & 1) as usize;
    if version == 1 || layer == 0 || bitrate_index == 0 || bitrate_index == 15 {
        return None;
    }
    if rate_index == 3 {
        return None;
    }

    let mpeg1 = version == 3;
    let table = match (mpeg1, layer) {
        (true, 3) => 0,
        (true, 2) => 1,
        (true, _) => 2,
        (false, 3) => 3,
        (false, _) => 4,
    };
    let bitrate = MPEG_KBPS[table][bitrate_index] * 1000;

    // MPEG-2 halves the MPEG-1 sample rates, MPEG-2.5 quarters them.
    let shift = match version {
        3 => 0,
        2 => 1,
        _ => 2,
    };
    let sample_rate = [44_100, 48_000, 32_000][rate_index] >> shift;

    Some(match (layer, mpeg1) {
        (3, _) => (12 * bitrate / sample_rate + padding) * 4,
        (1, false) => 72 * bitrate / sample_rate + padding,
        _ => 144 * bitrate / sample_rate + padding,
    })
}

/// Last path segment of `url`, percent-decoded, with control characters and
/// bidi controls removed (so `song\u{202E}3pm.exe` cannot display as
/// `songexe.mp3`), then truncated to at most 128 characters via
/// `chars().take(128)` (never `String::truncate`, which panics off a char
/// boundary). `None` if nothing is left.
pub fn filename_from_url(url: &url::Url) -> Option<String> {
    let segment = url.path_segments()?.next_back()?;
    let decoded = percent_decode(segment);
    let name: String = String::from_utf8_lossy(&decoded)
        .chars()
        .filter(|&c| !c.is_control() && !is_bidi_control(c))
        .take(128)
        .collect();

    (!name.is_empty()).then_some(name)
}

/// Unicode bidi formatting characters (ALM, LRM, RLM, the embeddings and
/// overrides, and the isolates). They are format (Cf), not control (Cc), so
/// `char::is_control` misses them.
fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// Decode `%XX` escapes to bytes; a `%` not followed by two hex digits is kept
/// as-is.
fn percent_decode(input: &str) -> Vec<u8> {
    fn hex(byte: u8) -> Option<u8> {
        (byte as char).to_digit(16).map(|digit| digit as u8)
    }

    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((high << 4) | low);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// A non-empty run of ASCII digits as a `u64` (no sign, no whitespace, no
/// overflow).
fn parse_digits(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

/// Parse a single `bytes=start-[end]` range into `(start, end)`.
///
/// Multi-range (`bytes=0-1,5-6`), suffix (`bytes=-500`), non-`bytes` units,
/// `end < start` and otherwise malformed values -> `None`.
pub fn parse_range(value: &str) -> Option<(u64, Option<u64>)> {
    let (unit, spec) = value.split_once('=')?;
    if !unit.trim().eq_ignore_ascii_case("bytes") || spec.contains(',') {
        return None;
    }

    let (start, end) = spec.split_once('-')?;
    let start = parse_digits(start.trim())?;
    let end = match end.trim() {
        "" => None,
        end => Some(parse_digits(end)?),
    };

    match end {
        Some(end) if end < start => None,
        _ => Some((start, end)),
    }
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
    use reqwest::header::{CONTENT_LENGTH, CONTENT_RANGE};
    use reqwest::StatusCode;

    let header = |name| headers.get(name)?.to_str().ok().map(str::trim);
    match status {
        StatusCode::OK => parse_digits(header(CONTENT_LENGTH)?),
        StatusCode::PARTIAL_CONTENT => {
            let range = header(CONTENT_RANGE)?;
            let (unit, rest) = range.split_once(' ')?;
            if !unit.eq_ignore_ascii_case("bytes") {
                return None;
            }
            // `*` (unknown total) fails the digit check.
            let (_, total) = rest.rsplit_once('/')?;
            parse_digits(total.trim())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue, CONTENT_LENGTH, CONTENT_RANGE};
    use reqwest::StatusCode;

    fn mime(value: &str) -> mime::Mime {
        value.parse().expect("test mime parses")
    }

    fn url(value: &str) -> url::Url {
        url::Url::parse(value).expect("test url parses")
    }

    /// `head` padded with zeros to `len` bytes.
    fn padded(head: &[u8], len: usize) -> Vec<u8> {
        let mut out = head.to_vec();
        out.resize(len.max(head.len()), 0);
        out
    }

    /// MPEG-1 Layer III, no CRC, 128 kbps, 44.1 kHz, no padding.
    const MP3_HEADER: [u8; 4] = [0xFF, 0xFB, 0x90, 0x00];
    /// floor(144 * 128_000 / 44_100) + 0 padding.
    const MP3_FRAME_LEN: usize = 417;

    /// Two consecutive frames: a header at 0 and another at the computed offset.
    fn mp3_two_frames() -> Vec<u8> {
        assert_eq!(144 * 128_000 / 44_100, MP3_FRAME_LEN);
        let mut out = padded(&MP3_HEADER, MP3_FRAME_LEN + 64);
        out[MP3_FRAME_LEN..MP3_FRAME_LEN + 4].copy_from_slice(&MP3_HEADER);
        out
    }

    /// One positive fixture per canonical type.
    fn positives() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("audio/mpeg", padded(b"ID3\x04\x00\x00\x00\x00\x00\x00", 32)),
            ("audio/mpeg", mp3_two_frames()),
            (
                "audio/mp4",
                padded(b"\x00\x00\x00\x20ftypM4A \x00\x00\x02\x00", 32),
            ),
            (
                "audio/aac",
                padded(&[0xFF, 0xF1, 0x50, 0x80, 0x02, 0x1F, 0xFC], 32),
            ),
            ("audio/wav", padded(b"RIFF\x24\x08\x00\x00WAVEfmt ", 32)),
            ("audio/ogg", padded(b"OggS\x00\x02", 32)),
            ("audio/flac", padded(b"fLaC\x00\x00\x00\x22", 32)),
            (
                "audio/webm",
                padded(&[0x1A, 0x45, 0xDF, 0xA3, 0x9F, 0x42, 0x86], 32),
            ),
        ]
    }

    #[test]
    fn canonical_type_maps_every_row() {
        let rows = [
            ("audio/mpeg", "audio/mpeg"),
            ("audio/mp3", "audio/mpeg"),
            ("audio/x-mpeg", "audio/mpeg"),
            ("audio/mp4", "audio/mp4"),
            ("audio/x-m4a", "audio/mp4"),
            ("audio/m4a", "audio/mp4"),
            ("audio/aac", "audio/aac"),
            ("audio/x-aac", "audio/aac"),
            ("audio/wav", "audio/wav"),
            ("audio/x-wav", "audio/wav"),
            ("audio/wave", "audio/wav"),
            ("audio/vnd.wave", "audio/wav"),
            ("audio/ogg", "audio/ogg"),
            ("audio/opus", "audio/ogg"),
            ("application/ogg", "audio/ogg"),
            ("audio/flac", "audio/flac"),
            ("audio/x-flac", "audio/flac"),
            ("audio/webm", "audio/webm"),
        ];
        for (upstream, canonical) in rows {
            assert_eq!(
                canonical_type(&mime(upstream)),
                Some(canonical),
                "{upstream}"
            );
        }
    }

    #[test]
    fn canonical_type_ignores_parameters_and_case() {
        assert_eq!(
            canonical_type(&mime("audio/mpeg; charset=x")),
            Some("audio/mpeg")
        );
        assert_eq!(
            canonical_type(&mime("audio/ogg; codecs=opus")),
            Some("audio/ogg")
        );
        assert_eq!(canonical_type(&mime("AUDIO/MPEG")), Some("audio/mpeg"));
        assert_eq!(canonical_type(&mime("Audio/X-M4A")), Some("audio/mp4"));
        assert_eq!(canonical_type(&mime("Application/Ogg")), Some("audio/ogg"));
    }

    #[test]
    fn canonical_type_rejects_everything_else() {
        for upstream in [
            "video/webm",
            "video/mp4",
            "application/octet-stream",
            "audio/x-aiff",
            "audio/midi",
            "text/html",
            "image/png",
            "audio/mpeg+xml",
        ] {
            assert_eq!(canonical_type(&mime(upstream)), None, "{upstream}");
        }
    }

    #[test]
    fn sniff_ok_accepts_each_format() {
        for (canonical, head) in positives() {
            assert!(sniff_ok(canonical, &head), "{canonical}");
        }
    }

    #[test]
    fn sniff_ok_rejects_each_format() {
        let negatives: Vec<(&str, Vec<u8>)> = vec![
            ("audio/mpeg", padded(b"ID4\x04", 32)),
            ("audio/mp4", padded(b"ftypM4A \x00\x00\x02\x00", 32)),
            ("audio/aac", padded(&MP3_HEADER, 32)),
            ("audio/wav", padded(b"RIFF\x24\x08\x00\x00AVI LIST", 32)),
            ("audio/ogg", padded(b"OggT\x00\x02", 32)),
            ("audio/flac", padded(b"FLAC\x00\x00\x00\x22", 32)),
            ("audio/webm", padded(&[0x1A, 0x45, 0xDF, 0xA4], 32)),
        ];
        for (canonical, head) in negatives {
            assert!(!sniff_ok(canonical, &head), "{canonical}");
        }
    }

    #[test]
    fn sniff_ok_mp3_needs_a_second_valid_frame_when_reachable() {
        let mut head = mp3_two_frames();
        assert!(sniff_ok("audio/mpeg", &head));

        // Bitrate index 15 is invalid.
        head[MP3_FRAME_LEN + 2] = 0xF0;
        assert!(!sniff_ok("audio/mpeg", &head));

        // No sync at the computed offset.
        let mut head = mp3_two_frames();
        head[MP3_FRAME_LEN..MP3_FRAME_LEN + 4].copy_from_slice(&[0, 0, 0, 0]);
        assert!(!sniff_ok("audio/mpeg", &head));

        // A header one byte off the computed offset does not count.
        let mut head = padded(&MP3_HEADER, MP3_FRAME_LEN + 64);
        head[MP3_FRAME_LEN + 1..MP3_FRAME_LEN + 5].copy_from_slice(&MP3_HEADER);
        assert!(!sniff_ok("audio/mpeg", &head));
    }

    #[test]
    fn sniff_ok_mp3_single_header_is_enough_when_next_frame_is_out_of_reach() {
        assert!(sniff_ok("audio/mpeg", &padded(&MP3_HEADER, 64)));
        assert!(sniff_ok("audio/mpeg", &padded(&MP3_HEADER, MP3_FRAME_LEN)));
    }

    #[test]
    fn sniff_ok_mp3_rejects_invalid_first_headers() {
        for header in [
            [0xFF, 0xEB, 0x90, 0x00], // reserved version
            [0xFF, 0xF9, 0x90, 0x00], // reserved layer
            [0xFF, 0xFB, 0x00, 0x00], // free-format bitrate (index 0)
            [0xFF, 0xFB, 0xF0, 0x00], // bitrate index 15
            [0xFF, 0xFB, 0x9C, 0x00], // sample rate index 3
            [0xFF, 0x1B, 0x90, 0x00], // only 8 sync bits
        ] {
            assert!(
                !sniff_ok("audio/mpeg", &padded(&header, 64)),
                "{header:02X?}"
            );
        }
    }

    #[test]
    fn sniff_ok_rejects_short_heads_for_every_format() {
        for (canonical, head) in positives() {
            assert!(
                !sniff_ok(canonical, &head[..SNIFF_MIN_BYTES - 1]),
                "{canonical}"
            );
            assert!(!sniff_ok(canonical, &[]), "{canonical}");
        }
    }

    #[test]
    fn sniff_ok_rejects_other_content_labelled_audio() {
        let png = padded(b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR", 64);
        let html = b"<!DOCTYPE html><html><head><title>x</title></head></html>".to_vec();
        for canonical in [
            "audio/mpeg",
            "audio/mp4",
            "audio/aac",
            "audio/wav",
            "audio/ogg",
            "audio/flac",
            "audio/webm",
        ] {
            assert!(!sniff_ok(canonical, &png), "png as {canonical}");
            assert!(!sniff_ok(canonical, &html), "html as {canonical}");
        }
    }

    #[test]
    fn sniff_ok_rejects_unknown_canonical_types() {
        let head = padded(b"ID3\x04", 32);
        for canonical in ["audio/mp3", "audio/x-aiff", "video/webm", ""] {
            assert!(!sniff_ok(canonical, &head), "{canonical}");
        }
    }

    #[test]
    fn filename_from_url_plain() {
        assert_eq!(
            filename_from_url(&url("https://example.com/music/song.mp3?x=1#frag")),
            Some("song.mp3".to_string())
        );
    }

    #[test]
    fn filename_from_url_percent_decodes() {
        assert_eq!(
            filename_from_url(&url("https://example.com/m/%C3%A9t%C3%A9%20song.mp3")),
            Some("\u{e9}t\u{e9} song.mp3".to_string())
        );
        // Malformed escapes stay literal; invalid UTF-8 becomes U+FFFD.
        assert_eq!(
            filename_from_url(&url("https://example.com/a%ZZb%4.mp3")),
            Some("a%ZZb%4.mp3".to_string())
        );
        assert_eq!(
            filename_from_url(&url("https://example.com/a%FFb.mp3")),
            Some("a\u{fffd}b.mp3".to_string())
        );
    }

    #[test]
    fn filename_from_url_empty_segment_is_none() {
        assert_eq!(filename_from_url(&url("https://example.com/music/")), None);
        assert_eq!(filename_from_url(&url("https://example.com/")), None);
        assert_eq!(filename_from_url(&url("https://example.com")), None);
        // Nothing left once control characters are gone.
        assert_eq!(filename_from_url(&url("https://example.com/%00%0A")), None);
    }

    #[test]
    fn filename_from_url_removes_control_chars() {
        assert_eq!(
            filename_from_url(&url("https://example.com/a%00b%0Ac%7Fd%1B.mp3")),
            Some("abcd.mp3".to_string())
        );
    }

    /// Every bidi control `filename_from_url` must strip.
    const BIDI_CONTROLS: [char; 12] = [
        '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}',
        '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
    ];

    /// `c` as `%XX` escapes of its UTF-8 bytes.
    fn percent_encoded(c: char) -> String {
        let mut buf = [0; 4];
        c.encode_utf8(&mut buf)
            .bytes()
            .map(|b| format!("%{b:02X}"))
            .collect()
    }

    #[test]
    fn filename_from_url_strips_percent_encoded_rlo() {
        assert_eq!(
            filename_from_url(&url("https://example.com/song%E2%80%AE3pm.exe")),
            Some("song3pm.exe".to_string())
        );
    }

    #[test]
    fn filename_from_url_strips_each_bidi_control() {
        for c in BIDI_CONTROLS {
            let encoded = percent_encoded(c);
            assert_eq!(
                filename_from_url(&url(&format!("https://example.com/a{encoded}b.mp3"))),
                Some("ab.mp3".to_string()),
                "U+{:04X}",
                c as u32
            );
        }
    }

    #[test]
    fn filename_from_url_only_bidi_controls_is_none() {
        let name: String = BIDI_CONTROLS.into_iter().map(percent_encoded).collect();
        assert_eq!(
            filename_from_url(&url(&format!("https://example.com/{name}"))),
            None
        );
    }

    #[test]
    fn filename_from_url_cap_counts_chars_after_stripping() {
        // 130 visible chars, each preceded by an RLO: the RLOs must not use up
        // the 128-char budget.
        let name = "%E2%80%AEa".repeat(130);
        assert_eq!(
            filename_from_url(&url(&format!("https://example.com/{name}"))),
            Some("a".repeat(128))
        );
    }

    #[test]
    fn filename_from_url_caps_multibyte_names_at_128_chars() {
        let name = "%C3%A9".repeat(100) + &"%F0%9F%8E%B5".repeat(100);
        let result = filename_from_url(&url(&format!("https://example.com/{name}")))
            .expect("non-empty name");
        assert_eq!(result.chars().count(), 128);
        let expected: String = "\u{e9}"
            .repeat(100)
            .chars()
            .chain("\u{1f3b5}".repeat(28).chars())
            .collect();
        assert_eq!(result, expected);
    }

    #[test]
    fn parse_range_accepts_single_ranges() {
        assert_eq!(parse_range("bytes=0-"), Some((0, None)));
        assert_eq!(parse_range("bytes=0-1"), Some((0, Some(1))));
        assert_eq!(parse_range("bytes=100-199"), Some((100, Some(199))));
        assert_eq!(parse_range("bytes=5-5"), Some((5, Some(5))));
        assert_eq!(parse_range("  bytes = 100 - 199  "), Some((100, Some(199))));
        assert_eq!(parse_range("bytes= 7 -"), Some((7, None)));
    }

    #[test]
    fn parse_range_rejects_everything_else() {
        for value in [
            "bytes=-500",
            "bytes=0-1,5-6",
            "bytes=0-,5-",
            "items=0-1",
            "bytes=5-1",
            "bytes=",
            "bytes=-",
            "bytes=a-b",
            "bytes=+5-",
            "bytes=0-+9",
            "bytes 0-1",
            "bytes=0",
            "bytes=0-1-2",
            "bytes=18446744073709551616-",
            "",
            "garbage",
        ] {
            assert_eq!(parse_range(value), None, "{value:?}");
        }
    }

    fn headers(pairs: &[(reqwest::header::HeaderName, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(name.clone(), HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn total_size_200_uses_content_length() {
        let map = headers(&[(CONTENT_LENGTH, "8997375")]);
        assert_eq!(total_size(StatusCode::OK, &map), Some(8_997_375));
    }

    #[test]
    fn total_size_206_uses_content_range_total() {
        let map = headers(&[(CONTENT_LENGTH, "2"), (CONTENT_RANGE, "bytes 0-1/8997375")]);
        assert_eq!(
            total_size(StatusCode::PARTIAL_CONTENT, &map),
            Some(8_997_375)
        );
    }

    #[test]
    fn total_size_206_unknown_total_is_none() {
        let map = headers(&[(CONTENT_LENGTH, "2"), (CONTENT_RANGE, "bytes 0-1/*")]);
        assert_eq!(total_size(StatusCode::PARTIAL_CONTENT, &map), None);
    }

    #[test]
    fn total_size_other_statuses_are_none() {
        let map = headers(&[(CONTENT_LENGTH, "10"), (CONTENT_RANGE, "bytes */10")]);
        assert_eq!(total_size(StatusCode::NOT_FOUND, &map), None);
        assert_eq!(total_size(StatusCode::RANGE_NOT_SATISFIABLE, &map), None);
        assert_eq!(total_size(StatusCode::NO_CONTENT, &map), None);
    }

    #[test]
    fn total_size_missing_or_bad_headers_are_none() {
        let empty = HeaderMap::new();
        assert_eq!(total_size(StatusCode::OK, &empty), None);
        assert_eq!(total_size(StatusCode::PARTIAL_CONTENT, &empty), None);
        // A 206 never falls back to Content-Length.
        let length_only = headers(&[(CONTENT_LENGTH, "10")]);
        assert_eq!(total_size(StatusCode::PARTIAL_CONTENT, &length_only), None);
        let bad_length = headers(&[(CONTENT_LENGTH, "ten")]);
        assert_eq!(total_size(StatusCode::OK, &bad_length), None);
        let bad_unit = headers(&[(CONTENT_RANGE, "items 0-1/10")]);
        assert_eq!(total_size(StatusCode::PARTIAL_CONTENT, &bad_unit), None);
    }
}
