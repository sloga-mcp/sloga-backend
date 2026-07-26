//! Download dispatch: legacy whole-file objects buffer (bounded ≤ ~100 MB by
//! the historical upload wall); v2 segmented objects stream at ~one segment
//! resident with real HTTP Range support (seek is O(range), not O(file)).

use axum::{
    body::Body,
    http::{header, StatusCode},
    response::Response,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use revolt_config::report_internal_error;
use revolt_database::FileHash;
use revolt_result::{create_error, Result};

use crate::api::CACHE_CONTROL;

/// Outcome of parsing a `Range` header against a resource size
#[derive(Debug, PartialEq, Eq)]
pub enum RangeOutcome {
    /// No (usable) range — serve the whole resource with a 200
    Full,
    /// Inclusive byte range to serve with a 206
    Partial(u64, u64),
    /// Syntactically valid but unsatisfiable — 416
    Unsatisfiable,
}

/// Parse a single-range `bytes=` header. Multi-range requests fall back to
/// `Full` (a 200 is always a legal response to a Range request); garbage
/// likewise. Only a well-formed but out-of-bounds range is `Unsatisfiable`.
pub fn parse_range(header: Option<&str>, size: u64) -> RangeOutcome {
    let Some(header) = header else {
        return RangeOutcome::Full;
    };
    let Some(spec) = header.strip_prefix("bytes=") else {
        return RangeOutcome::Full;
    };
    if spec.contains(',') || size == 0 {
        return RangeOutcome::Full;
    }
    let Some((start, end)) = spec.split_once('-') else {
        return RangeOutcome::Full;
    };

    match (start.is_empty(), end.is_empty()) {
        // bytes=a-b
        (false, false) => match (start.parse::<u64>(), end.parse::<u64>()) {
            // Inverted bounds are an invalid spec — RFC 7233 says ignore
            (Ok(a), Ok(b)) if a > b => RangeOutcome::Full,
            (Ok(a), Ok(b)) if a < size => RangeOutcome::Partial(a, u64::min(b, size - 1)),
            (Ok(_), Ok(_)) => RangeOutcome::Unsatisfiable,
            _ => RangeOutcome::Full,
        },
        // bytes=a-
        (false, true) => match start.parse::<u64>() {
            Ok(a) if a < size => RangeOutcome::Partial(a, size - 1),
            Ok(_) => RangeOutcome::Unsatisfiable,
            _ => RangeOutcome::Full,
        },
        // bytes=-n (final n bytes)
        (true, false) => match end.parse::<u64>() {
            Ok(0) => RangeOutcome::Unsatisfiable,
            Ok(n) => RangeOutcome::Partial(size.saturating_sub(n), size - 1),
            _ => RangeOutcome::Full,
        },
        (true, true) => RangeOutcome::Full,
    }
}

fn base_builder(hash: &FileHash) -> axum::http::response::Builder {
    Response::builder()
        .header(header::CONTENT_TYPE, hash.content_type.clone())
        .header(header::CONTENT_DISPOSITION, "attachment")
        .header(header::CACHE_CONTROL, CACHE_CONTROL)
        .header(header::ACCEPT_RANGES, "bytes")
}

fn range_unsatisfiable(hash: &FileHash, size: u64) -> Result<Response> {
    report_internal_error!(base_builder(hash)
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .header(header::CONTENT_RANGE, format!("bytes */{size}"))
        .body(Body::empty()))
}

/// Serve an already-decrypted legacy buffer, honouring single ranges by
/// slicing (bounded: legacy objects predate chunked uploads, ≤ ~100 MB)
pub fn serve_legacy_buffer(hash: &FileHash, data: Vec<u8>, range: Option<&str>) -> Result<Response> {
    // Legacy `hash.size` records the CIPHERTEXT length (plaintext + tag);
    // ranges are over what the client actually receives, so use the
    // decrypted length
    let size = data.len() as u64;

    match parse_range(range, size) {
        RangeOutcome::Full => report_internal_error!(base_builder(hash).body(Body::from(data))),
        RangeOutcome::Partial(start, end) => {
            let slice = data[start as usize..=end as usize].to_vec();
            report_internal_error!(base_builder(hash)
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{size}"))
                .body(Body::from(slice)))
        }
        RangeOutcome::Unsatisfiable => range_unsatisfiable(hash, size),
    }
}

/// Serve a v2 object by streaming: decrypt segment-by-segment straight into
/// the response body. Never enters the in-memory cache.
pub async fn serve_v2(hash: &FileHash, range: Option<&str>) -> Result<Response> {
    // v2 `hash.size` is the PLAINTEXT length
    let size = hash.size as u64;

    let prefix_bytes = report_internal_error!(BASE64_STANDARD.decode(&hash.iv))?;
    let mut prefix = [0u8; revolt_files::STREAM_NONCE_PREFIX_SIZE];
    if prefix_bytes.len() != prefix.len() {
        return Err(create_error!(InternalError));
    }
    prefix.copy_from_slice(&prefix_bytes);

    let cipher = revolt_files::SegmentedStreamCipher::from_config(prefix).await;

    let (status, start, end) = match parse_range(range, size) {
        RangeOutcome::Full => (StatusCode::OK, 0, size - 1),
        RangeOutcome::Partial(start, end) => (StatusCode::PARTIAL_CONTENT, start, end),
        RangeOutcome::Unsatisfiable => return range_unsatisfiable(hash, size),
    };

    let (ct_start, ct_end, first_segment, includes_final, skip) =
        report_internal_error!(cipher.plaintext_range_to_ciphertext(start, end, size))?;

    let stream = report_internal_error!(
        revolt_files::open_v2_plaintext_stream(
            &hash.bucket_id,
            &hash.path,
            prefix,
            ct_start,
            ct_end,
            revolt_files::PlaintextWindow {
                first_segment,
                includes_final_segment: includes_final,
                skip,
                take: end - start + 1,
            },
        )
        .await
    )?;

    let mut builder = base_builder(hash)
        .status(status)
        .header(header::CONTENT_LENGTH, end - start + 1);
    if status == StatusCode::PARTIAL_CONTENT {
        builder = builder.header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{size}"));
    }
    report_internal_error!(builder.body(Body::from_stream(stream)))
}

#[cfg(test)]
mod tests {
    use super::{parse_range, serve_legacy_buffer, RangeOutcome};
    use revolt_database::{iso8601_timestamp::Timestamp, FileHash, Metadata};

    fn legacy_hash(data_len: usize) -> FileHash {
        FileHash {
            id: "test-hash".into(),
            processed_hash: "test-hash".into(),
            created_at: Timestamp::now_utc(),
            bucket_id: "bucket".into(),
            path: "test-hash".into(),
            iv: "iv".into(),
            format_version: None,
            metadata: Metadata::File,
            content_type: "application/octet-stream".into(),
            // Legacy size records ciphertext length (plaintext + 16-byte tag)
            size: (data_len + 16) as isize,
        }
    }

    #[tokio::test]
    async fn legacy_buffer_slicing() {
        let data: Vec<u8> = (0..100u8).collect();
        let hash = legacy_hash(data.len());

        let response = serve_legacy_buffer(&hash, data.clone(), None).unwrap();
        assert_eq!(response.status(), 200);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], &data[..]);

        // Ranges are over the DECRYPTED length, not the stored size
        let response = serve_legacy_buffer(&hash, data.clone(), Some("bytes=10-19")).unwrap();
        assert_eq!(response.status(), 206);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], &data[10..=19]);

        let response = serve_legacy_buffer(&hash, data, Some("bytes=200-")).unwrap();
        assert_eq!(response.status(), 416);
    }

    #[test]
    fn range_parsing() {
        assert_eq!(parse_range(None, 100), RangeOutcome::Full);
        assert_eq!(parse_range(Some("bytes=0-49"), 100), RangeOutcome::Partial(0, 49));
        // End clamps to the resource
        assert_eq!(parse_range(Some("bytes=50-500"), 100), RangeOutcome::Partial(50, 99));
        // Open-ended and suffix forms
        assert_eq!(parse_range(Some("bytes=30-"), 100), RangeOutcome::Partial(30, 99));
        assert_eq!(parse_range(Some("bytes=-20"), 100), RangeOutcome::Partial(80, 99));
        // Suffix longer than the resource means the whole thing
        assert_eq!(parse_range(Some("bytes=-500"), 100), RangeOutcome::Partial(0, 99));
        // Unsatisfiable: start past the end, or an empty suffix
        assert_eq!(parse_range(Some("bytes=100-"), 100), RangeOutcome::Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=200-300"), 100), RangeOutcome::Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=-0"), 100), RangeOutcome::Unsatisfiable);
        // Multi-range and garbage fall back to a 200
        assert_eq!(parse_range(Some("bytes=0-1,5-9"), 100), RangeOutcome::Full);
        assert_eq!(parse_range(Some("bytes=b-a"), 100), RangeOutcome::Full);
        assert_eq!(parse_range(Some("chapters=1-2"), 100), RangeOutcome::Full);
        // Inverted bounds are an invalid spec — RFC 7233 says ignore
        assert_eq!(parse_range(Some("bytes=9-5"), 100), RangeOutcome::Full);
    }
}
