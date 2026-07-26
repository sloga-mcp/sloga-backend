//! Streaming decrypt for v2 (segmented STREAM) objects.
//!
//! Downloads hold ~one segment (1 MiB + tag) resident regardless of object
//! size — the property that makes multi-GB attachments servable on a small
//! box. Range requests map plaintext offsets to segment-aligned ciphertext
//! ranges (O(range), not O(file)) and trim the head/tail here.

use std::io;

use futures::{Stream, StreamExt};

use crate::implementation::stream_cipher::SegmentedStreamCipher;
use crate::implementation::EncryptionKey;
use crate::S3Storage;

/// What to emit from a fetched ciphertext run
pub struct PlaintextWindow {
    /// First segment index covered by the ciphertext
    pub first_segment: u32,
    /// Whether the run includes the object's final segment
    pub includes_final_segment: bool,
    /// Decrypted bytes to drop before emitting (range head trim)
    pub skip: u64,
    /// Plaintext bytes to emit after the skip (range length)
    pub take: u64,
}

/// Open a decrypting stream over an inclusive ciphertext byte range of a v2
/// object.
///
/// The returned stream yields plaintext chunks and holds at most one
/// segment plus one network chunk in memory.
pub async fn open_v2_plaintext_stream(
    bucket_id: &str,
    path: &str,
    prefix: [u8; crate::STREAM_NONCE_PREFIX_SIZE],
    ciphertext_start: u64,
    ciphertext_end_inclusive: u64,
    window: PlaintextWindow,
) -> anyhow::Result<impl Stream<Item = Result<Vec<u8>, io::Error>>> {
    let cipher = SegmentedStreamCipher::from_config(prefix).await;
    let storage = S3Storage::from_config(EncryptionKey::from_config().await).await;
    let body = storage
        .fetch_range(bucket_id, path, ciphertext_start, ciphertext_end_inclusive)
        .await?;

    let stride = cipher.segment_stride();
    let ciphertext_len = ciphertext_end_inclusive - ciphertext_start + 1;
    let segment_count = ciphertext_len.div_ceil(stride);

    struct State {
        body: aws_sdk_s3::primitives::ByteStream,
        cipher: SegmentedStreamCipher,
        buf: Vec<u8>,
        body_done: bool,
        emitted_segments: u64,
        segment_count: u64,
        first_segment: u32,
        includes_final_segment: bool,
        skip: u64,
        take: u64,
    }

    let state = State {
        body,
        cipher,
        buf: Vec::new(),
        body_done: false,
        emitted_segments: 0,
        segment_count,
        first_segment: window.first_segment,
        includes_final_segment: window.includes_final_segment,
        skip: window.skip,
        take: window.take,
    };

    Ok(futures::stream::try_unfold(state, |mut st| async move {
        loop {
            if st.emitted_segments == st.segment_count || st.take == 0 {
                return Ok(None);
            }

            let stride = st.cipher.segment_stride() as usize;
            let is_last = st.emitted_segments == st.segment_count - 1;

            // Fill the buffer up to one sealed segment (the last may be short)
            while !st.body_done && st.buf.len() < stride {
                match st.body.next().await {
                    Some(chunk) => st
                        .buf
                        .extend_from_slice(&chunk.map_err(io::Error::other)?),
                    None => st.body_done = true,
                }
            }

            let block: Vec<u8> = if st.buf.len() >= stride && !is_last {
                st.buf.drain(..stride).collect()
            } else if is_last && st.body_done && !st.buf.is_empty() {
                std::mem::take(&mut st.buf)
            } else if st.buf.len() >= stride {
                st.buf.drain(..stride).collect()
            } else {
                return Err(io::Error::other("truncated ciphertext stream"));
            };

            let segment_index = st
                .first_segment
                .checked_add(st.emitted_segments as u32)
                .ok_or_else(|| io::Error::other("segment counter overflow"))?;
            let mut plaintext = st
                .cipher
                .decrypt_segments(
                    segment_index,
                    st.includes_final_segment && is_last,
                    &block,
                )
                .map_err(io::Error::other)?;
            st.emitted_segments += 1;

            // Head trim for mid-segment range starts
            if st.skip > 0 {
                let drop = usize::min(st.skip as usize, plaintext.len());
                plaintext.drain(..drop);
                st.skip -= drop as u64;
            }
            // Tail trim for mid-segment range ends
            if (plaintext.len() as u64) > st.take {
                plaintext.truncate(st.take as usize);
            }

            if plaintext.is_empty() {
                continue;
            }
            st.take -= plaintext.len() as u64;
            return Ok(Some((plaintext, st)));
        }
    }))
}
