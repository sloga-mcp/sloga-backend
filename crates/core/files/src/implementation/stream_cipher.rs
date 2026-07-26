use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce,
};
use anyhow::Context;
use base64::{prelude::BASE64_STANDARD, Engine};

use crate::AUTHENTICATION_TAG_SIZE_BYTES;

/// Plaintext bytes per AEAD segment of a v2 (`format_version = 2`) object
pub const STREAM_SEGMENT_SIZE: usize = 1024 * 1024;

/// Plaintext bytes per client-uploaded chunk (one S3 part)
///
/// Must stay under Cloudflare's ~100 MB edge body limit and over S3's 5 MiB
/// minimum part size. Must remain an exact multiple of [`STREAM_SEGMENT_SIZE`]:
/// part boundaries have to fall on segment boundaries for part encryption to be
/// a pure function of the part index (see [`SegmentedStreamCipher`]).
pub const CHUNK_SIZE: usize = 32 * 1024 * 1024;

/// Bytes of random per-file nonce prefix; the remaining 5 nonce bytes are the
/// BE32 segment counter and the last-segment flag
pub const STREAM_NONCE_PREFIX_SIZE: usize = 7;

const _: () = assert!(CHUNK_SIZE % STREAM_SEGMENT_SIZE == 0);

/// Segment-at-a-time AES-256-GCM matching the `aead::stream` STREAM (BE32)
/// construction byte-for-byte.
///
/// Each 1 MiB plaintext segment `i` is sealed one-shot under the nonce
/// `prefix(7) ‖ BE32(i) ‖ last_flag(1)` — exactly the nonce schedule
/// `aead::stream::EncryptorBE32` uses internally (verified by differential
/// test below). Doing it segment-at-a-time instead of through the sequential
/// `EncryptorBE32` object is what lets chunked uploads encrypt parts out of
/// order and across process restarts: because part boundaries align with
/// segment boundaries, encrypting part `p` depends only on
/// `(key, prefix, p, is_final_part, part bytes)`.
///
/// Consequently encryption is deterministic. That is safe *only* while a given
/// `(prefix, segment index)` never covers two different plaintexts — callers
/// must reject divergent re-uploads of an already-recorded part rather than
/// overwrite (AES-GCM nonce reuse would otherwise leak the GHASH subkey of the
/// shared server key).
pub struct SegmentedStreamCipher {
    cipher: Aes256Gcm,
    prefix: [u8; STREAM_NONCE_PREFIX_SIZE],
    segment_size: usize,
    segments_per_part: usize,
}

impl SegmentedStreamCipher {
    /// Cipher for the server key in `files.encryption_key`
    pub async fn from_config(prefix: [u8; STREAM_NONCE_PREFIX_SIZE]) -> SegmentedStreamCipher {
        SegmentedStreamCipher::new(
            &revolt_config::config().await.files.encryption_key,
            prefix,
        )
    }

    pub fn new(key_b64: &str, prefix: [u8; STREAM_NONCE_PREFIX_SIZE]) -> SegmentedStreamCipher {
        Self::with_layout(key_b64, prefix, STREAM_SEGMENT_SIZE, CHUNK_SIZE)
    }

    /// Layout-parameterised constructor so tests can exercise the construction
    /// with small segments (debug-build AES is ~200x slower than release)
    fn with_layout(
        key_b64: &str,
        prefix: [u8; STREAM_NONCE_PREFIX_SIZE],
        segment_size: usize,
        part_size: usize,
    ) -> SegmentedStreamCipher {
        assert!(segment_size > 0 && part_size % segment_size == 0);
        let key = BASE64_STANDARD
            .decode(key_b64)
            .expect("valid base64 encryption key");
        let key: &Key<Aes256Gcm> = key[..].into();

        SegmentedStreamCipher {
            cipher: Aes256Gcm::new(key),
            prefix,
            segment_size,
            segments_per_part: part_size / segment_size,
        }
    }

    /// Fresh random per-file nonce prefix
    pub fn generate_prefix() -> [u8; STREAM_NONCE_PREFIX_SIZE] {
        // Reuse the AEAD's own nonce generator (as encryption_impl does) and
        // keep the first 7 of its 12 random bytes
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let mut prefix = [0u8; STREAM_NONCE_PREFIX_SIZE];
        prefix.copy_from_slice(&nonce[..STREAM_NONCE_PREFIX_SIZE]);
        prefix
    }

    fn nonce(&self, segment_index: u32, is_last: bool) -> Nonce<<Aes256Gcm as AeadCore>::NonceSize> {
        let mut nonce = [0u8; 12];
        nonce[..STREAM_NONCE_PREFIX_SIZE].copy_from_slice(&self.prefix);
        nonce[STREAM_NONCE_PREFIX_SIZE..11].copy_from_slice(&segment_index.to_be_bytes());
        nonce[11] = is_last as u8;
        nonce.into()
    }

    /// Ciphertext bytes occupied by one full segment
    pub fn segment_stride(&self) -> u64 {
        (self.segment_size + AUTHENTICATION_TAG_SIZE_BYTES) as u64
    }

    /// Number of segments a plaintext of `len` bytes occupies
    pub fn segment_count(&self, len: u64) -> u64 {
        len.div_ceil(self.segment_size as u64)
    }

    /// Total stored (ciphertext) size for a plaintext of `len` bytes
    pub fn ciphertext_len(&self, len: u64) -> u64 {
        len + self.segment_count(len) * AUTHENTICATION_TAG_SIZE_BYTES as u64
    }

    /// Seal one segment at an explicit index (the primitive under
    /// [`Self::encrypt_part`]).
    ///
    /// A non-final segment must be exactly the segment size; the final segment
    /// must be non-empty and no larger.
    pub fn encrypt_segment(
        &self,
        segment_index: u32,
        is_final_segment: bool,
        plaintext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        if is_final_segment {
            anyhow::ensure!(
                !plaintext.is_empty() && plaintext.len() <= self.segment_size,
                "final segment must be 1..={} bytes, got {}",
                self.segment_size,
                plaintext.len()
            );
        } else {
            anyhow::ensure!(
                plaintext.len() == self.segment_size,
                "non-final segment must be exactly {} bytes, got {}",
                self.segment_size,
                plaintext.len()
            );
        }

        let nonce = self.nonce(segment_index, is_final_segment);
        self.cipher
            .encrypt(&nonce, plaintext)
            .map_err(|error| anyhow::anyhow!("segment encryption failed: {error}"))
    }

    /// Encrypt one upload part.
    ///
    /// `part_number` is 1-based (S3 convention). Every part except the final
    /// one must be exactly the part size; the final part must be non-empty and
    /// no larger. The output is the concatenation of the part's sealed
    /// segments and is byte-identical however many times it is re-run.
    pub fn encrypt_part(
        &self,
        part_number: u32,
        is_final_part: bool,
        plaintext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let part_size = self.segment_size * self.segments_per_part;
        if is_final_part {
            anyhow::ensure!(
                !plaintext.is_empty() && plaintext.len() <= part_size,
                "final part must be 1..={part_size} bytes, got {}",
                plaintext.len()
            );
        } else {
            anyhow::ensure!(
                plaintext.len() == part_size,
                "non-final part must be exactly {part_size} bytes, got {}",
                plaintext.len()
            );
        }

        let first_segment = (part_number as u64 - 1)
            .checked_mul(self.segments_per_part as u64)
            .context("part number overflow")?;
        anyhow::ensure!(
            first_segment + self.segment_count(plaintext.len() as u64) <= u32::MAX as u64 + 1,
            "segment counter overflow"
        );

        let segments: Vec<&[u8]> = plaintext.chunks(self.segment_size).collect();
        let mut out =
            Vec::with_capacity(plaintext.len() + segments.len() * AUTHENTICATION_TAG_SIZE_BYTES);

        for (offset, segment) in segments.iter().enumerate() {
            let last = is_final_part && offset == segments.len() - 1;
            let sealed =
                self.encrypt_segment(first_segment as u32 + offset as u32, last, segment)?;
            out.extend_from_slice(&sealed);
        }

        Ok(out)
    }

    /// Decrypt a run of whole segments starting at `first_segment` (0-based).
    ///
    /// `ciphertext` must contain complete sealed segments (each full segment
    /// is `segment_stride` bytes; a trailing short segment is permitted only
    /// when `includes_final_segment` is set).
    pub fn decrypt_segments(
        &self,
        first_segment: u32,
        includes_final_segment: bool,
        ciphertext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(!ciphertext.is_empty(), "empty ciphertext");
        let stride = self.segment_stride() as usize;

        let blocks: Vec<&[u8]> = ciphertext.chunks(stride).collect();
        let mut out = Vec::with_capacity(ciphertext.len());

        for (offset, block) in blocks.iter().enumerate() {
            let last = offset == blocks.len() - 1;
            anyhow::ensure!(
                block.len() > AUTHENTICATION_TAG_SIZE_BYTES,
                "truncated segment at offset {offset}"
            );
            anyhow::ensure!(
                block.len() == stride || (last && includes_final_segment),
                "short segment at offset {offset} not marked final"
            );

            let nonce = self.nonce(
                first_segment
                    .checked_add(offset as u32)
                    .context("segment counter overflow")?,
                last && includes_final_segment,
            );
            let opened = self
                .cipher
                .decrypt(&nonce, *block)
                .map_err(|error| anyhow::anyhow!("segment decryption failed: {error}"))?;
            out.extend_from_slice(&opened);
        }

        Ok(out)
    }

    /// Map an inclusive plaintext byte range to the segment-aligned ciphertext
    /// range that covers it.
    ///
    /// Returns `(ct_start, ct_end_inclusive, first_segment, includes_final_segment,
    /// skip_head)` where `skip_head` is how many decrypted bytes precede the
    /// requested `start`.
    pub fn plaintext_range_to_ciphertext(
        &self,
        start: u64,
        end_inclusive: u64,
        plaintext_len: u64,
    ) -> anyhow::Result<(u64, u64, u32, bool, u64)> {
        anyhow::ensure!(
            start <= end_inclusive && end_inclusive < plaintext_len,
            "range {start}..={end_inclusive} out of bounds for {plaintext_len}"
        );

        let stride = self.segment_stride();
        let segment_size = self.segment_size as u64;
        let total_segments = self.segment_count(plaintext_len);

        let first_segment = start / segment_size;
        let last_segment = end_inclusive / segment_size;
        let includes_final = last_segment == total_segments - 1;

        let ct_start = first_segment * stride;
        let ct_end = if includes_final {
            self.ciphertext_len(plaintext_len) - 1
        } else {
            (last_segment + 1) * stride - 1
        };

        Ok((
            ct_start,
            ct_end,
            u32::try_from(first_segment).context("segment counter overflow")?,
            includes_final,
            start - first_segment * segment_size,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::stream::EncryptorBE32;
    use aes_gcm::aead::generic_array::GenericArray;

    const KEY: &str = "XkbJ8gBzrouQ+15Ri23xCC81+aZE26Z6+gXzglFxOD4=";
    const PREFIX: [u8; 7] = [1, 2, 3, 4, 5, 6, 7];

    /// Small layout so debug-build AES stays fast; the nonce schedule is
    /// independent of segment size, so equivalence at 1 KiB proves it at 1 MiB
    const SEG: usize = 1024;
    const PART: usize = 4 * SEG;

    fn cipher() -> SegmentedStreamCipher {
        SegmentedStreamCipher::with_layout(KEY, PREFIX, SEG, PART)
    }

    fn pseudo_random(len: usize) -> Vec<u8> {
        // Deterministic filler; content is irrelevant to the construction
        let mut state = 0x2545F4914F6CDD1Du64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    /// Reference: the sequential aead::stream encryptor fed the same segments
    fn reference_encrypt(plaintext: &[u8]) -> Vec<u8> {
        let key = base64::prelude::BASE64_STANDARD.decode(KEY).unwrap();
        let key: &Key<Aes256Gcm> = key[..].into();
        let mut enc = EncryptorBE32::from_aead(
            Aes256Gcm::new(key),
            GenericArray::from_slice(&PREFIX),
        );

        let segments: Vec<&[u8]> = plaintext.chunks(SEG).collect();
        let mut out = vec![];
        for segment in &segments[..segments.len() - 1] {
            out.extend(enc.encrypt_next(*segment).unwrap());
        }
        out.extend(enc.encrypt_last(*segments.last().unwrap()).unwrap());
        out
    }

    fn encrypt_via_parts(c: &SegmentedStreamCipher, plaintext: &[u8]) -> Vec<u8> {
        let part_count = plaintext.len().div_ceil(PART);
        // Encrypt parts in reverse order to prove order-independence
        let mut parts: Vec<(usize, Vec<u8>)> = (0..part_count)
            .rev()
            .map(|index| {
                let start = index * PART;
                let end = usize::min(start + PART, plaintext.len());
                (
                    index,
                    c.encrypt_part(
                        index as u32 + 1,
                        index == part_count - 1,
                        &plaintext[start..end],
                    )
                    .unwrap(),
                )
            })
            .collect();
        parts.sort_by_key(|(index, _)| *index);
        parts.into_iter().flat_map(|(_, ct)| ct).collect()
    }

    #[test]
    fn differential_vs_aead_stream() {
        let c = cipher();
        for len in [
            1,                  // sub-segment
            SEG,                // exactly one segment
            SEG + 1,            // just over a segment
            PART - 1,           // just under one part
            PART,               // exactly one part
            PART + 1,           // just over one part
            3 * PART + 1000,    // multi-part, short tail
            5 * PART,           // exact multiple of part size
            5 * PART + SEG,     // tail of exactly one segment
        ] {
            let plaintext = pseudo_random(len);
            assert_eq!(
                encrypt_via_parts(&c, &plaintext),
                reference_encrypt(&plaintext),
                "mismatch at len {len}"
            );
        }
    }

    #[test]
    fn round_trip_in_odd_groupings() {
        let c = cipher();
        let plaintext = pseudo_random(3 * PART + 1000);
        let ciphertext = encrypt_via_parts(&c, &plaintext);
        let total_segments = c.segment_count(plaintext.len() as u64) as usize;
        let stride = c.segment_stride() as usize;

        // Decrypt in windows of 3 segments — misaligned with the 4-segment parts
        let mut out = vec![];
        let mut segment = 0usize;
        while segment < total_segments {
            let take = usize::min(3, total_segments - segment);
            let start = segment * stride;
            let end = usize::min(start + take * stride, ciphertext.len());
            let includes_final = segment + take == total_segments;
            out.extend(
                c.decrypt_segments(segment as u32, includes_final, &ciphertext[start..end])
                    .unwrap(),
            );
            segment += take;
        }
        assert_eq!(out, plaintext);
    }

    #[test]
    fn tampering_is_detected() {
        let c = cipher();
        let plaintext = pseudo_random(PART + 100);
        let mut ciphertext = encrypt_via_parts(&c, &plaintext);

        // Flip a bit mid-segment
        ciphertext[SEG / 2] ^= 1;
        assert!(c.decrypt_segments(0, false, &ciphertext[..c.segment_stride() as usize]).is_err());

        // Segment presented at the wrong index
        let good = encrypt_via_parts(&c, &plaintext);
        assert!(c.decrypt_segments(1, false, &good[..c.segment_stride() as usize]).is_err());

        // Final segment without its flag
        let stride = c.segment_stride() as usize;
        let tail_start = (c.segment_count(plaintext.len() as u64) as usize - 1) * stride;
        assert!(c.decrypt_segments(
            (c.segment_count(plaintext.len() as u64) - 1) as u32,
            false,
            &good[tail_start..]
        )
        .is_err());
    }

    #[test]
    fn divergent_part_sizes_rejected() {
        let c = cipher();
        assert!(c.encrypt_part(1, false, &pseudo_random(PART - 1)).is_err());
        assert!(c.encrypt_part(1, true, &[]).is_err());
        assert!(c.encrypt_part(1, true, &pseudo_random(PART + 1)).is_err());
    }

    #[test]
    fn range_math() {
        let c = cipher();
        let len = (3 * PART + 1000) as u64;
        let stride = c.segment_stride();

        // Range fully inside segment 5
        let (cs, ce, first, last, skip) = c
            .plaintext_range_to_ciphertext(5 * SEG as u64 + 10, 5 * SEG as u64 + 20, len)
            .unwrap();
        assert_eq!((cs, ce, first, last, skip), (5 * stride, 6 * stride - 1, 5, false, 10));

        // Range touching the final byte
        let (_, ce, _, last, _) = c.plaintext_range_to_ciphertext(0, len - 1, len).unwrap();
        assert_eq!(ce, c.ciphertext_len(len) - 1);
        assert!(last);

        // Out of bounds
        assert!(c.plaintext_range_to_ciphertext(0, len, len).is_err());
    }
}
