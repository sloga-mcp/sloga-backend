//! Protected-channel Text groups: the server's copies of the two client
//! formats the Delivery Service checks itself (protected-channels design
//! §3.1 group id derivation, §3.12.2 commit framing prefix).
//!
//! Pure functions, no database. A commit and its `authenticated_data` are
//! never logged or echoed in an error: errors name the field that failed,
//! never its bytes.

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use revolt_database::{is_valid_group_id, MAX_CANONICAL_INT, MAX_COMMIT_AD_LEN};
use revolt_result::{create_error, Result};
use sha2::{Digest, Sha256};

use super::{encoded_len, MAX_MLS_COMMIT_RAW_SIZE};

/// Text group id derivation context (design §0.4, WIRE FORMAT, never rename)
pub(crate) const CONTEXT_TEXT_GROUP: &str = "sloga-text-group-v1";

/// MLS `ProtocolVersion` mls10 (RFC 9420 §6)
const MLS_VERSION_MLS10: u16 = 0x0001;

/// MLS `WireFormat` mls_private_message (RFC 9420 §6)
const MLS_WIRE_FORMAT_PRIVATE_MESSAGE: u16 = 0x0002;

/// MLS `ContentType` commit (RFC 9420 §6)
const MLS_CONTENT_TYPE_COMMIT: u8 = 0x03;

/// Raw length of a group id (64 lowercase hex chars on the route)
const GROUP_ID_RAW_LEN: usize = 32;

/// The channel's Text group id for `generation` (design §3.1):
/// `lowercase_hex(SHA-256("sloga-text-group-v1" LF channel_id LF decimal(g)))`.
///
/// A pure derivation: it does not check the channel id charset or the
/// generation cap (63); callers compare its output with an id they hold.
pub(crate) fn text_group_id(channel_id: &str, generation: u32) -> String {
    let digest = Sha256::digest(format!("{CONTEXT_TEXT_GROUP}\n{channel_id}\n{generation}"));
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Parse the plaintext framing prefix of a submitted Text commit (design
/// §3.12.2) and return its MLS `authenticated_data` bytes, for the caller
/// to byte-compare with the stored seat list's `commit_ad`.
///
/// - `commit_b64`: the submitted `commit`, canonical unpadded b64 (§0.1);
/// - `group_id`: the route group id (64 lowercase hex chars);
/// - `epoch`: the SUBMITTED epoch, `DataSubmitMlsCommit.epoch`, i.e. the
///   epoch the commit establishes. A commit is framed in the epoch it was
///   created in, so the prefix must carry `epoch - 1`. Pass the request
///   field as is, never a value already decremented.
///
/// The prefix is `version` (mls10), `wire_format` (private message),
/// `group_id<V>` (32 bytes, equal to the route id), `epoch` (u64),
/// `content_type` (commit), `authenticated_data<V>` (a 1- or 2-byte
/// minimal varint, at most 16383 bytes). Everything after the AD is opaque
/// and not read. Any failure is `FailedValidation`.
pub(crate) fn parse_commit_ad(commit_b64: &str, group_id: &str, epoch: i64) -> Result<Vec<u8>> {
    if !(1..=MAX_CANONICAL_INT).contains(&epoch) {
        return Err(refused("epoch"));
    }
    let framed_epoch = (epoch - 1) as u64;
    let group_id = decode_group_id(group_id).ok_or_else(|| refused("group id"))?;

    if commit_b64.len() > encoded_len(MAX_MLS_COMMIT_RAW_SIZE) {
        return Err(refused("commit size"));
    }
    let commit = STANDARD_NO_PAD
        .decode(commit_b64)
        .map_err(|_| refused("commit encoding"))?;

    let mut prefix = Prefix { rest: &commit };
    if prefix.u16().ok_or_else(|| refused("version"))? != MLS_VERSION_MLS10 {
        return Err(refused("version"));
    }
    if prefix.u16().ok_or_else(|| refused("wire format"))? != MLS_WIRE_FORMAT_PRIVATE_MESSAGE {
        return Err(refused("wire format"));
    }
    if prefix.varint().ok_or_else(|| refused("group id length"))? != GROUP_ID_RAW_LEN {
        return Err(refused("group id length"));
    }
    if prefix
        .take(GROUP_ID_RAW_LEN)
        .ok_or_else(|| refused("group id"))?
        != group_id.as_slice()
    {
        return Err(refused("group id"));
    }
    if prefix.u64().ok_or_else(|| refused("epoch"))? != framed_epoch {
        return Err(refused("epoch"));
    }
    if prefix.u8().ok_or_else(|| refused("content type"))? != MLS_CONTENT_TYPE_COMMIT {
        return Err(refused("content type"));
    }
    let ad_len = prefix
        .varint()
        .filter(|len| *len <= MAX_COMMIT_AD_LEN)
        .ok_or_else(|| refused("authenticated data length"))?;
    let ad = prefix
        .take(ad_len)
        .ok_or_else(|| refused("authenticated data"))?;

    Ok(ad.to_vec())
}

/// `FailedValidation` naming the prefix field that failed (never its bytes)
fn refused(field: &str) -> revolt_result::Error {
    create_error!(FailedValidation {
        error: format!("commit framing: {field}")
    })
}

/// The raw 32 bytes of a route group id; `None` unless it is exactly 64
/// lowercase hex chars
fn decode_group_id(group_id: &str) -> Option<[u8; GROUP_ID_RAW_LEN]> {
    if !is_valid_group_id(group_id) {
        return None;
    }
    let mut raw = [0u8; GROUP_ID_RAW_LEN];
    for (index, byte) in raw.iter_mut().enumerate() {
        *byte = u8::from_str_radix(group_id.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(raw)
}

/// Forward-only reader over the commit prefix; every read is bounds-checked
struct Prefix<'a> {
    rest: &'a [u8],
}

impl<'a> Prefix<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        if len > self.rest.len() {
            return None;
        }
        let (head, rest) = self.rest.split_at(len);
        self.rest = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(self.take(2)?);
        Some(u16::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Option<u64> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.take(8)?);
        Some(u64::from_be_bytes(bytes))
    }

    /// RFC 9420 §2.1.2 variable-length integer, 1- or 2-byte form only, and
    /// minimal. The 4-byte form is refused outright: the AD length is at
    /// most 16383 (design §3.12.1, W0-fix3), and the group id length (32)
    /// has a 1-byte minimal form, so a 4-byte form here is never valid.
    fn varint(&mut self) -> Option<usize> {
        let first = self.u8()?;
        match first >> 6 {
            0b00 => Some(usize::from(first & 0x3f)),
            0b01 => {
                let value = (usize::from(first & 0x3f) << 8) | usize::from(self.u8()?);
                (value >= 0x40).then_some(value)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::{
        engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
        Engine as _,
    };
    use revolt_database::{MAX_CANONICAL_INT, MAX_COMMIT_AD_LEN};
    use revolt_result::{Error, ErrorType};
    use sha2::{Digest, Sha256};

    use super::{parse_commit_ad, text_group_id};

    // Section 5.1 input
    const CHANNEL: &str = "01J9Z3K4M5N6P7Q8R9S0T1V2W3";

    // Section 5.5 vectors
    const GROUP_ID_G0: &str = "4a4ba4afc6e6ea1c9f4a271f7eded44ea860fdb814e4e1377121e02635a715b5";
    const GROUP_ID_G1: &str = "b4989a8d9b082e1668a726aa3303d3eb8b52688d340ca4dc1e0184f61fc67000";

    // Section 5.7 vectors: the AD, one row per element, and its SHA-256
    const COMMIT_AD_HEX: [&str; 6] = [
        "0017736c6f67612d746578742d636f6d6d69742d61642d7631",
        "011e736c6f67612d736561742d6c6973742d76310a763a310a6368616e6e656c5f69643a30314a395a334b344d354e3650375138523953305431563257330a76657273696f6e3a330a6465766963655f6361703a350a6973737565645f61743a313739303831323830303030300a7369676e65725f757365725f69643a3031485a584141414141414141414141414141414141414141410a7369676e65725f6465766963655f69643a30303131323233333434353536363737383839396161626263636464656566660a73656174733a3031485a584141414141414141414141414141414141414141412c3031485a584242424242424242424242424242424242424242422c3031485a58434343434343434343434343434343434343434343",
        "00401ed6d2ea36cbbf0499c407b88b66b897098a86fe2133edcd90c63512ec1168fcaff64237c7fdedd52b1a96d7aec68c661b86057335d403bef5df81d32702d108",
        "0001",
        "017f736c6f67612d6f776e65722d68616e646f7665722d76310a763a310a6368616e6e656c5f69643a30314a395a334b344d354e3650375138523953305431563257330a66726f6d5f757365725f69643a3031485a584141414141414141414141414141414141414141410a66726f6d5f6465766963655f69643a30303131323233333434353536363737383839396161626263636464656566660a66726f6d5f6964656e746974795f6b65793a41364548762f504f454c3464634e3059353076416d57666b316a436270513166486479475a424a564d62670a746f5f757365725f69643a3031485a584141414141414141414141414141414141414141410a746f5f6465766963655f69643a30313233343536373839616263646566303132333435363738396162636465660a746f5f6964656e746974795f6b65793a7a52537a663556756c5447552f332b334f7a3242334d5668316870314f416c4c664434615a44376c38366f0a6973737565645f61743a31373930383132383030303030",
        "004024a9d8b5a88afe2ded612c55ef55e85f2cfd9745da0ec588873a02bbcb3d22e4dd9859965f904db68121a6dfaff604af844fa7a92dbf919100d025fa82247a04",
    ];
    const COMMIT_AD_SHA256: &str =
        "9cc01bfe85923de2a68126c90f891806c0ced23191dc1b44c0d02edb0a4b0ea4";

    // Section 5.7 framing prefix, one element per row: version,
    // wire_format, group_id length, (group_id = GROUP_ID_G0), epoch (7),
    // content_type, authenticated_data length (0x4000 | 832)
    const PREFIX_VERSION: &str = "0001";
    const PREFIX_WIRE_FORMAT: &str = "0002";
    const PREFIX_GROUP_ID_LEN: &str = "20";
    const PREFIX_EPOCH: &str = "0000000000000007";
    const PREFIX_CONTENT_TYPE: &str = "03";
    const PREFIX_AD_LEN: &str = "4340";

    /// The submitted epoch of the 5.7 commit (created in epoch 7)
    const SUBMITTED_EPOCH: i64 = 8;

    /// Opaque bytes after the AD (`encrypted_sender_data<V>`,
    /// `ciphertext<V>`), never read by the parser. Four bytes, so the whole
    /// commit (884 bytes) is not a multiple of 3 and its padded b64 form
    /// differs from the unpadded one.
    const OPAQUE_TAIL: &str = "01aa02bb";

    // Field positions in `vector_fields`
    const VERSION: usize = 0;
    const WIRE_FORMAT: usize = 1;
    const GROUP_ID_LEN: usize = 2;
    const GROUP_ID: usize = 3;
    const EPOCH: usize = 4;
    const CONTENT_TYPE: usize = 5;
    const AD_LEN: usize = 6;
    const AD: usize = 7;
    const TAIL: usize = 8;

    fn unhex(hex: &str) -> Vec<u8> {
        assert!(hex.len() % 2 == 0, "odd hex length");
        (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("hex"))
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn vector_ad() -> Vec<u8> {
        unhex(&COMMIT_AD_HEX.concat())
    }

    /// The 5.7 commit, one field per entry, so a test can replace exactly
    /// one field
    fn vector_fields() -> Vec<Vec<u8>> {
        vec![
            unhex(PREFIX_VERSION),
            unhex(PREFIX_WIRE_FORMAT),
            unhex(PREFIX_GROUP_ID_LEN),
            unhex(GROUP_ID_G0),
            unhex(PREFIX_EPOCH),
            unhex(PREFIX_CONTENT_TYPE),
            unhex(PREFIX_AD_LEN),
            vector_ad(),
            unhex(OPAQUE_TAIL),
        ]
    }

    fn encode(fields: &[Vec<u8>]) -> String {
        STANDARD_NO_PAD.encode(fields.concat())
    }

    fn with_field(index: usize, value: &str) -> String {
        let mut fields = vector_fields();
        fields[index] = unhex(value);
        encode(&fields)
    }

    #[track_caller]
    fn assert_refused(commit_b64: &str, group_id: &str, epoch: i64, case: &str) {
        let result = parse_commit_ad(commit_b64, group_id, epoch);
        assert!(
            matches!(
                result,
                Err(Error {
                    error_type: ErrorType::FailedValidation { .. },
                    ..
                })
            ),
            "{case}: expected FailedValidation, got {:?}",
            result.map(|ad| ad.len())
        );
    }

    #[test]
    fn text_group_id_matches_the_5_5_vectors() {
        assert_eq!(text_group_id(CHANNEL, 0), GROUP_ID_G0);
        assert_eq!(text_group_id(CHANNEL, 1), GROUP_ID_G1);
    }

    #[test]
    fn the_5_7_vector_constants_are_self_consistent() {
        let ad = vector_ad();
        assert_eq!(ad.len(), 832);
        assert_eq!(hex(&Sha256::digest(&ad)), COMMIT_AD_SHA256);
        // The prefix's AD length is the 2-byte varint 0x4000 | 832
        assert_eq!(
            unhex(PREFIX_AD_LEN),
            vec![0x40 | (832 >> 8) as u8, (832 & 0xff) as u8]
        );
    }

    #[test]
    fn parse_commit_ad_matches_the_5_7_vector() {
        let ad = parse_commit_ad(&encode(&vector_fields()), GROUP_ID_G0, SUBMITTED_EPOCH)
            .expect("the 5.7 commit parses");
        assert_eq!(hex(&ad), COMMIT_AD_HEX.concat());
        assert_eq!(hex(&Sha256::digest(&ad)), COMMIT_AD_SHA256);
        // The 5.7 prefix names the 5.5 generation-0 group of the 5.1 channel
        assert_eq!(text_group_id(CHANNEL, 0), GROUP_ID_G0);
    }

    #[test]
    fn parse_commit_ad_stops_after_the_ad() {
        // The rest of the message is opaque (3.12.2): nothing after the AD
        // is read, so a commit cut right after it still yields the AD; the
        // byte-compare and the MLS receivers judge the rest
        let mut fields = vector_fields();
        fields[TAIL] = vec![];
        let ad = parse_commit_ad(&encode(&fields), GROUP_ID_G0, SUBMITTED_EPOCH)
            .expect("prefix and AD only");
        assert_eq!(ad, vector_ad());
    }

    #[test]
    fn parse_commit_ad_refuses_every_single_field_corruption() {
        let mut flipped_first = unhex(GROUP_ID_G0);
        flipped_first[0] ^= 0x01;
        let mut flipped_last = unhex(GROUP_ID_G0);
        flipped_last[31] ^= 0x80;

        let cases: Vec<(&str, usize, String)> = vec![
            ("version 0", VERSION, "0000".into()),
            ("version 2", VERSION, "0002".into()),
            ("version byte-swapped", VERSION, "0100".into()),
            ("public message", WIRE_FORMAT, "0001".into()),
            ("welcome", WIRE_FORMAT, "0003".into()),
            ("wire format byte-swapped", WIRE_FORMAT, "0200".into()),
            ("group id length 31", GROUP_ID_LEN, "1f".into()),
            ("group id length 33", GROUP_ID_LEN, "21".into()),
            (
                "group id length non-minimal 2-byte",
                GROUP_ID_LEN,
                "4020".into(),
            ),
            ("group id length 4-byte", GROUP_ID_LEN, "80000020".into()),
            ("group id length invalid prefix", GROUP_ID_LEN, "c0".into()),
            ("generation-1 group id", GROUP_ID, GROUP_ID_G1.into()),
            ("group id first byte flipped", GROUP_ID, hex(&flipped_first)),
            ("group id last byte flipped", GROUP_ID, hex(&flipped_last)),
            ("framed epoch 6", EPOCH, "0000000000000006".into()),
            (
                "framed epoch 8 (the submitted one)",
                EPOCH,
                "0000000000000008".into(),
            ),
            ("framed epoch high bit", EPOCH, "8000000000000007".into()),
            ("application message", CONTENT_TYPE, "01".into()),
            ("proposal", CONTENT_TYPE, "02".into()),
            ("content type 0", CONTENT_TYPE, "00".into()),
            ("AD length 4-byte form", AD_LEN, "80000340".into()),
            ("AD length invalid prefix", AD_LEN, "c340".into()),
            ("AD length far past the end", AD_LEN, "7fff".into()),
            ("AD length one past the end", AD_LEN, "4345".into()),
        ];
        for (case, index, value) in &cases {
            assert_refused(
                &with_field(*index, value),
                GROUP_ID_G0,
                SUBMITTED_EPOCH,
                case,
            );
        }

        // Non-minimal AD length: a 5-byte AD behind a 2-byte varint
        let mut fields = vector_fields();
        fields[AD_LEN] = unhex("4005");
        fields[AD] = vec![0x55; 5];
        fields[TAIL] = vec![];
        assert_refused(
            &encode(&fields),
            GROUP_ID_G0,
            SUBMITTED_EPOCH,
            "AD length non-minimal",
        );
        // The same AD behind the minimal form is accepted
        fields[AD_LEN] = unhex("05");
        assert_eq!(
            parse_commit_ad(&encode(&fields), GROUP_ID_G0, SUBMITTED_EPOCH).expect("minimal"),
            vec![0x55; 5]
        );
    }

    #[test]
    fn parse_commit_ad_refuses_a_mismatched_route_group_or_epoch() {
        let commit = encode(&vector_fields());
        // The route's group id and epoch must match the framing
        assert_refused(
            &commit,
            GROUP_ID_G1,
            SUBMITTED_EPOCH,
            "other generation's group",
        );
        assert_refused(
            &commit,
            &GROUP_ID_G0.to_uppercase(),
            SUBMITTED_EPOCH,
            "uppercase group id",
        );
        assert_refused(
            &commit,
            &GROUP_ID_G0[..63],
            SUBMITTED_EPOCH,
            "63-char group id",
        );
        assert_refused(
            &commit,
            &format!("{GROUP_ID_G0}0"),
            SUBMITTED_EPOCH,
            "65-char group id",
        );
        assert_refused(
            &commit,
            &format!("{}g", &GROUP_ID_G0[..63]),
            SUBMITTED_EPOCH,
            "non-hex group id",
        );
        assert_refused(&commit, "", SUBMITTED_EPOCH, "empty group id");
        // The submitted epoch is the framed epoch + 1, never the framed one
        assert_refused(
            &commit,
            GROUP_ID_G0,
            7,
            "framed epoch passed as the submitted one",
        );
        assert_refused(&commit, GROUP_ID_G0, 9, "submitted epoch + 1");
        for epoch in [0, -1, i64::MIN, MAX_CANONICAL_INT + 1, i64::MAX] {
            assert_refused(&commit, GROUP_ID_G0, epoch, &format!("epoch {epoch}"));
        }
    }

    #[test]
    fn parse_commit_ad_refuses_every_truncation_of_the_prefix_and_ad() {
        let mut fields = vector_fields();
        fields[TAIL] = vec![];
        let bytes = fields.concat();
        for cut in 0..bytes.len() {
            assert_refused(
                &STANDARD_NO_PAD.encode(&bytes[..cut]),
                GROUP_ID_G0,
                SUBMITTED_EPOCH,
                &format!("truncated to {cut} bytes"),
            );
        }
    }

    #[test]
    fn parse_commit_ad_refuses_non_canonical_b64() {
        let canonical = encode(&vector_fields());
        let padded = STANDARD.encode(vector_fields().concat());
        assert_ne!(padded, canonical, "the vector commit must need padding");
        assert_refused(&padded, GROUP_ID_G0, SUBMITTED_EPOCH, "padded");

        let mut url_safe = canonical.clone();
        url_safe.replace_range(10..11, "-");
        assert_refused(&url_safe, GROUP_ID_G0, SUBMITTED_EPOCH, "URL-safe alphabet");

        let mut spaced = canonical.clone();
        spaced.insert(40, '\n');
        assert_refused(&spaced, GROUP_ID_G0, SUBMITTED_EPOCH, "embedded newline");
        assert_refused(
            &format!(" {canonical}"),
            GROUP_ID_G0,
            SUBMITTED_EPOCH,
            "leading space",
        );

        // 884 bytes = 2 mod 3: the last symbol carries 2 unused low bits,
        // which must be zero
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let last = *canonical.as_bytes().last().expect("non-empty");
        let index = ALPHABET
            .iter()
            .position(|symbol| *symbol == last)
            .expect("b64");
        assert_eq!(index & 0b11, 0, "canonical trailing bits are zero");
        let mut trailing = canonical.clone();
        trailing.pop();
        trailing.push(ALPHABET[index | 0b01] as char);
        assert_refused(
            &trailing,
            GROUP_ID_G0,
            SUBMITTED_EPOCH,
            "non-zero trailing bits",
        );

        assert_refused("", GROUP_ID_G0, SUBMITTED_EPOCH, "empty commit");
    }

    #[test]
    fn parse_commit_ad_takes_an_ad_up_to_16383_bytes() {
        let mut fields = vector_fields();
        fields[AD_LEN] = unhex("7fff");
        fields[AD] = vec![0x5a; MAX_COMMIT_AD_LEN];
        let ad =
            parse_commit_ad(&encode(&fields), GROUP_ID_G0, SUBMITTED_EPOCH).expect("16383-byte AD");
        assert_eq!(ad.len(), MAX_COMMIT_AD_LEN);

        // 16384 needs the 4-byte form, which is refused
        fields[AD_LEN] = unhex("80004000");
        fields[AD] = vec![0x5a; MAX_COMMIT_AD_LEN + 1];
        assert_refused(
            &encode(&fields),
            GROUP_ID_G0,
            SUBMITTED_EPOCH,
            "16384-byte AD",
        );
    }
}
