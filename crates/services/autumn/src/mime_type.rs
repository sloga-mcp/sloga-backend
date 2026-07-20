use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use tempfile::NamedTempFile;

/// Size of the chunk used when scanning a file off disk
const SCAN_CHUNK_SIZE: usize = 64 * 1024;

/// Check whether a file is valid UTF-8 without loading it into memory
///
/// A multi-byte sequence can straddle a chunk boundary, so an incomplete tail is
/// carried into the next chunk instead of being treated as invalid.
fn is_valid_utf8(f: &mut File) -> std::io::Result<bool> {
    f.seek(SeekFrom::Start(0))?;

    let mut carry = Vec::new();
    let mut chunk = vec![0u8; SCAN_CHUNK_SIZE];

    loop {
        let read = f.read(&mut chunk)?;
        if read == 0 {
            break;
        }

        carry.extend_from_slice(&chunk[..read]);

        // `compat` rather than `basic`: it reports how far the input was valid,
        // which is what lets a truncated tail be carried into the next chunk
        match simdutf8::compat::from_utf8(&carry) {
            Ok(_) => carry.clear(),
            // `error_len() == None` means the sequence was merely truncated by
            // the chunk boundary; keep the tail and try again with more bytes
            Err(err) if err.error_len().is_none() => {
                carry.drain(..err.valid_up_to());
            }
            Err(_) => return Ok(false),
        }
    }

    // Anything left over is a trailing incomplete sequence
    Ok(carry.is_empty())
}

/// Determine the mime type of the given temporary file and filename
///
/// Leaves the file cursor at an unspecified position — callers that read `f`
/// afterwards must seek first.
pub fn determine_mime_type(f: &mut NamedTempFile, file_name: &str) -> &'static str {
    // Force certain extensions into particular mime types
    if file_name.to_lowercase().ends_with(".apk") {
        return "application/vnd.android.package-archive";
    } else if file_name.to_lowercase().ends_with(".exe") {
        return "application/vnd.microsoft.portable-executable";
    } else if file_name.to_lowercase().ends_with(".weba") {
        // Audio-only WebM (voice messages): magic signatures only see the
        // WebM container and report video/webm, which then fails video
        // probing and degrades to a generic file
        return "audio/webm";
    }

    // Use magic signatures to determine mime type
    let kind = infer::get_from_path(f.path()).expect("file read successfully");
    let mime_type = if let Some(kind) = kind {
        kind.mime_type()
    } else {
        "application/octet-stream"
    };

    // See if the file is actually just plain Unicode/ASCII text
    // Only worth scanning when the magic bytes told us nothing — this reads the
    // whole file, so it must stay behind the mime check
    let looks_like_text = mime_type == "application/octet-stream"
        && match is_valid_utf8(f.as_file_mut()) {
            Ok(valid) => valid,
            Err(err) => {
                // Don't silently downgrade a text file to octet-stream on an IO
                // error — the read further up the upload path will fail anyway,
                // but this is where the cause is visible
                tracing::warn!("failed to scan {file_name} for UTF-8 content: {err}");
                false
            }
        };

    if looks_like_text {
        if file_name.to_lowercase().ends_with(".svg") {
            return "image/svg+xml";
        } else {
            return "plain/text";
        }
    }

    mime_type
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn weba_extension_forces_audio_webm() {
        let mut f = NamedTempFile::new().unwrap();
        // EBML magic — sniffs as video/webm without the extension force
        let bytes: &[u8] = &[0x1A, 0x45, 0xDF, 0xA3, 0x00, 0x00, 0x00, 0x00];
        f.write_all(bytes).unwrap();
        f.flush().unwrap();

        assert_eq!(
            determine_mime_type(&mut f, "Voice Message.weba"),
            "audio/webm"
        );
        assert_eq!(determine_mime_type(&mut f, "VOICE.WEBA"), "audio/webm");
    }

    fn temp_file_with(bytes: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn utf8_detection_matches_whole_buffer_check() {
        for bytes in [
            b"".as_slice(),
            b"plain ascii".as_slice(),
            "unicode \u{00e9}\u{4e16}\u{1f600}".as_bytes(),
            &[0xff, 0xfe, 0x00],
            &[0xe4, 0xb8], // truncated 3-byte sequence
        ] {
            let mut f = temp_file_with(bytes);
            assert_eq!(
                is_valid_utf8(f.as_file_mut()).unwrap(),
                std::str::from_utf8(bytes).is_ok(),
                "mismatch for {bytes:?}"
            );
        }
    }

    #[test]
    fn utf8_detection_handles_chunk_boundary() {
        // A multi-byte character straddling the chunk boundary must not be
        // mistaken for invalid UTF-8
        let mut bytes = vec![b'a'; SCAN_CHUNK_SIZE - 1];
        bytes.extend_from_slice("\u{4e16}".as_bytes());
        bytes.extend_from_slice(&[b'b'; 16]);

        assert!(std::str::from_utf8(&bytes).is_ok());

        let mut f = temp_file_with(&bytes);
        assert!(is_valid_utf8(f.as_file_mut()).unwrap());
    }
}
