//! Stripe webhook signature verification
//!
//! Stripe signs every webhook delivery with the endpoint's signing secret
//! and sends the result in the `Stripe-Signature` header:
//!
//! ```text
//! t=1700000000,v1=<hex>,v1=<hex>,v0=<hex>
//! ```
//!
//! `v1` is HMAC-SHA256 keyed with the secret over `"{t}.{payload}"`, hex
//! encoded in lowercase. Several `v1` entries appear while a secret is being
//! rolled; any one of them matching is enough. `v0` is a legacy test scheme
//! and is never accepted.
//!
//! The webhook route is unauthenticated, so this check is the only thing
//! standing between the internet and the payment engine. Everything here
//! fails closed.
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};

/// Why a delivery was rejected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// No signing secret is configured, so nothing can verify
    EmptySecret,
    /// The header is missing `t`, has no `v1`, or `t` is not an integer
    Malformed,
    /// `t` is further from now than the tolerance (a replay, or a bad clock)
    Stale,
    /// No `v1` entry matches the expected signature
    NoMatch,
}

/// Verify a `Stripe-Signature` header against the raw request body.
///
/// Checks run in this order, and the first failure is returned:
///
/// 1. An empty secret is `EmptySecret` before anything is parsed or hashed,
///    so an unconfigured endpoint can never accept a delivery (an HMAC keyed
///    with an empty string is trivially forgeable).
/// 2. The header is split on `,` into `key=value` pairs, whitespace around
///    either side is ignored, as are unknown keys and pairs without `=`.
///    Exactly one `t` made of ASCII digits that fits an `i64` and at least
///    one `v1` are required, otherwise `Malformed`. A repeated `t` is
///    `Malformed` too, since it is ambiguous which one was signed.
/// 3. `|now_secs - t| > tolerance_secs` is `Stale`, in either direction. This
///    is checked before hashing so replays cost nothing. The difference is
///    taken with `abs_diff`, so a hostile `t` cannot overflow.
/// 4. The expected signature is computed over `t` exactly as sent (not
///    re-formatted), then compared in constant time with EVERY `v1`, without
///    stopping at the first match. Only the length of a candidate can show
///    up in timing. Hex is compared byte for byte: Stripe sends lowercase,
///    so an uppercase signature is `NoMatch`.
pub fn verify(
    header: &str,
    payload: &[u8],
    secret: &str,
    now_secs: i64,
    tolerance_secs: u64,
) -> Result<(), SignatureError> {
    if secret.is_empty() {
        return Err(SignatureError::EmptySecret);
    }

    let parsed = parse_header(header)?;

    if now_secs.abs_diff(parsed.t) > tolerance_secs {
        return Err(SignatureError::Stale);
    }

    let expected = compute_v1(secret, parsed.t_raw, payload);
    let expected = expected.as_bytes();

    // Fold every comparison so the position of a match is not observable
    let mut matched = Choice::from(0u8);
    for candidate in &parsed.v1 {
        let candidate = candidate.as_bytes();
        if candidate.len() == expected.len() {
            matched |= candidate.ct_eq(expected);
        }
    }

    if bool::from(matched) {
        Ok(())
    } else {
        Err(SignatureError::NoMatch)
    }
}

/// Build a valid `Stripe-Signature` header for `payload` signed with
/// `secret` at time `t`. Used by route tests to post deliveries that pass
/// `verify`; it holds no secret of its own.
pub fn sign_for_tests(payload: &[u8], secret: &str, t: i64) -> String {
    let t_raw = t.to_string();
    let v1 = compute_v1(secret, &t_raw, payload);
    format!("t={t_raw},v1={v1}")
}

/// The fields of a header that `verify` uses
struct ParsedHeader<'a> {
    /// `t` exactly as sent, which is what Stripe signed
    t_raw: &'a str,
    /// `t` as a number, for the tolerance check
    t: i64,
    /// Every `v1` value, in header order
    v1: Vec<&'a str>,
}

fn parse_header(header: &str) -> Result<ParsedHeader<'_>, SignatureError> {
    let mut t_raw: Option<&str> = None;
    let mut v1 = Vec::new();

    for part in header.split(',') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };

        match key.trim() {
            "t" => {
                if t_raw.is_some() {
                    return Err(SignatureError::Malformed);
                }
                t_raw = Some(value.trim());
            }
            "v1" => v1.push(value.trim()),
            _ => {}
        }
    }

    let t_raw = t_raw.ok_or(SignatureError::Malformed)?;
    if v1.is_empty() {
        return Err(SignatureError::Malformed);
    }

    // Digits only: `i64::from_str` would also take a leading `+` or `-`
    if t_raw.is_empty() || !t_raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(SignatureError::Malformed);
    }
    let t = t_raw
        .parse::<i64>()
        .map_err(|_| SignatureError::Malformed)?;

    Ok(ParsedHeader { t_raw, t, v1 })
}

/// Lowercase hex HMAC-SHA256(secret, "{t_raw}.{payload}")
fn compute_v1(secret: &str, t_raw: &str, payload: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(t_raw.as_bytes());
    mac.update(b".");
    mac.update(payload);
    to_lower_hex(&mac.finalize().into_bytes())
}

fn to_lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod test {
    use super::{compute_v1, sign_for_tests, to_lower_hex, verify, SignatureError};

    const SECRET: &str = "whsec_test_secret";
    const PAYLOAD: &[u8] = br#"{"id":"evt_1"}"#;
    const T: i64 = 1_700_000_000;
    const TOLERANCE: u64 = 300;

    /// HMAC-SHA256(key "whsec_test_secret", msg `1700000000.{"id":"evt_1"}`),
    /// computed outside this crate with
    /// `printf '%s' '1700000000.{"id":"evt_1"}' | openssl dgst -sha256 -hmac 'whsec_test_secret'`
    const KAT_V1: &str = "248a374f50f943a28b0f6ab50faf9a7e7e29b710fa26df9fb1618b9bf8ea9c9a";

    fn v1_of(header: &str) -> &str {
        header
            .split(',')
            .find_map(|part| part.strip_prefix("v1="))
            .expect("test header has a v1")
    }

    #[test]
    fn known_answer_vector() {
        assert_eq!(compute_v1(SECRET, "1700000000", PAYLOAD), KAT_V1);
        assert_eq!(
            sign_for_tests(PAYLOAD, SECRET, T),
            format!("t=1700000000,v1={KAT_V1}")
        );

        let header = format!("t=1700000000,v1={KAT_V1}");
        assert_eq!(verify(&header, PAYLOAD, SECRET, T, TOLERANCE), Ok(()));
    }

    #[test]
    fn hex_is_lowercase_and_complete() {
        assert_eq!(to_lower_hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        assert_eq!(to_lower_hex(&[]), "");
    }

    #[test]
    fn valid_signature_verifies() {
        let header = sign_for_tests(PAYLOAD, SECRET, T);
        assert_eq!(verify(&header, PAYLOAD, SECRET, T, TOLERANCE), Ok(()));
        assert_eq!(verify(&header, PAYLOAD, SECRET, T + 10, TOLERANCE), Ok(()));
    }

    #[test]
    fn wrong_secret_is_no_match() {
        let header = sign_for_tests(PAYLOAD, "whsec_other_secret", T);
        assert_eq!(
            verify(&header, PAYLOAD, SECRET, T, TOLERANCE),
            Err(SignatureError::NoMatch)
        );
    }

    #[test]
    fn tampered_payload_is_no_match() {
        let header = sign_for_tests(PAYLOAD, SECRET, T);
        assert_eq!(
            verify(&header, br#"{"id":"evt_2"}"#, SECRET, T, TOLERANCE),
            Err(SignatureError::NoMatch)
        );
        assert_eq!(
            verify(&header, br#"{"id":"evt_1"} "#, SECRET, T, TOLERANCE),
            Err(SignatureError::NoMatch)
        );
        assert_eq!(
            verify(&header, b"", SECRET, T, TOLERANCE),
            Err(SignatureError::NoMatch)
        );
    }

    #[test]
    fn shifted_timestamp_is_no_match() {
        // A captured signature re-sent with a fresh `t` to dodge the tolerance
        let header = sign_for_tests(PAYLOAD, SECRET, T);
        let shifted = format!("t={},v1={}", T + 1000, v1_of(&header));
        assert_eq!(
            verify(&shifted, PAYLOAD, SECRET, T + 1000, TOLERANCE),
            Err(SignatureError::NoMatch)
        );
    }

    #[test]
    fn timestamp_is_signed_as_sent() {
        // Same number, different text: Stripe signed "1700000000", not "01700000000"
        let header = sign_for_tests(PAYLOAD, SECRET, T);
        let padded = format!("t=0{T},v1={}", v1_of(&header));
        assert_eq!(
            verify(&padded, PAYLOAD, SECRET, T, TOLERANCE),
            Err(SignatureError::NoMatch)
        );
    }

    #[test]
    fn stale_in_both_directions() {
        let header = sign_for_tests(PAYLOAD, SECRET, T);
        let tolerance = TOLERANCE as i64;

        // Delivered too long ago (replay)
        assert_eq!(
            verify(&header, PAYLOAD, SECRET, T + tolerance + 1, TOLERANCE),
            Err(SignatureError::Stale)
        );
        // Stamped too far in the future
        assert_eq!(
            verify(&header, PAYLOAD, SECRET, T - tolerance - 1, TOLERANCE),
            Err(SignatureError::Stale)
        );
    }

    #[test]
    fn exactly_at_tolerance_passes() {
        let header = sign_for_tests(PAYLOAD, SECRET, T);
        let tolerance = TOLERANCE as i64;

        assert_eq!(
            verify(&header, PAYLOAD, SECRET, T + tolerance, TOLERANCE),
            Ok(())
        );
        assert_eq!(
            verify(&header, PAYLOAD, SECRET, T - tolerance, TOLERANCE),
            Ok(())
        );
    }

    #[test]
    fn hostile_timestamps_do_not_overflow() {
        let max = sign_for_tests(PAYLOAD, SECRET, i64::MAX);
        assert_eq!(
            verify(&max, PAYLOAD, SECRET, i64::MIN, TOLERANCE),
            Err(SignatureError::Stale)
        );
        assert_eq!(verify(&max, PAYLOAD, SECRET, 0, u64::MAX - 1), Ok(()));

        let zero = sign_for_tests(PAYLOAD, SECRET, 0);
        assert_eq!(
            verify(&zero, PAYLOAD, SECRET, i64::MAX, TOLERANCE),
            Err(SignatureError::Stale)
        );

        // Does not fit an i64
        assert_eq!(
            verify(
                "t=99999999999999999999,v1=00",
                PAYLOAD,
                SECRET,
                T,
                TOLERANCE
            ),
            Err(SignatureError::Malformed)
        );
    }

    #[test]
    fn one_valid_v1_among_several_verifies() {
        let good = v1_of(&sign_for_tests(PAYLOAD, SECRET, T)).to_string();
        let bad = v1_of(&sign_for_tests(PAYLOAD, "whsec_old_secret", T)).to_string();

        for header in [
            format!("t={T},v1={bad},v1={good}"),
            format!("t={T},v1={good},v1={bad}"),
            format!("t={T},v1={bad},v1=short,v1={good},v0={bad}"),
        ] {
            assert_eq!(verify(&header, PAYLOAD, SECRET, T, TOLERANCE), Ok(()));
        }

        let none_valid = format!("t={T},v1={bad},v1=short");
        assert_eq!(
            verify(&none_valid, PAYLOAD, SECRET, T, TOLERANCE),
            Err(SignatureError::NoMatch)
        );
    }

    #[test]
    fn only_v0_is_malformed() {
        // v0 is never accepted, even when it carries a valid signature
        let good = v1_of(&sign_for_tests(PAYLOAD, SECRET, T)).to_string();
        let header = format!("t={T},v0={good}");
        assert_eq!(
            verify(&header, PAYLOAD, SECRET, T, TOLERANCE),
            Err(SignatureError::Malformed)
        );
    }

    #[test]
    fn empty_header_is_malformed() {
        assert_eq!(
            verify("", PAYLOAD, SECRET, T, TOLERANCE),
            Err(SignatureError::Malformed)
        );
    }

    #[test]
    fn garbage_is_malformed() {
        let good = v1_of(&sign_for_tests(PAYLOAD, SECRET, T)).to_string();

        for header in [
            "garbage".to_string(),
            ",,,".to_string(),
            "=,=,=".to_string(),
            format!("v1={good}"),
            format!("t={T}"),
            format!("t=,v1={good}"),
            format!("t=abc,v1={good}"),
            format!("t=+{T},v1={good}"),
            format!("t=-{T},v1={good}"),
            format!("t=1.5,v1={good}"),
            format!("t={T},t={T},v1={good}"),
        ] {
            assert_eq!(
                verify(&header, PAYLOAD, SECRET, T, TOLERANCE),
                Err(SignatureError::Malformed),
                "{header}"
            );
        }
    }

    #[test]
    fn whitespace_and_unknown_keys_are_tolerated() {
        let good = v1_of(&sign_for_tests(PAYLOAD, SECRET, T)).to_string();
        let header = format!(" t = {T} , scheme=x, v1= {good} ,stray, v0=abc ");
        assert_eq!(verify(&header, PAYLOAD, SECRET, T, TOLERANCE), Ok(()));
    }

    #[test]
    fn empty_secret_never_verifies() {
        // Even a header that really was made with an empty key
        let header = sign_for_tests(PAYLOAD, "", T);
        assert_eq!(
            verify(&header, PAYLOAD, "", T, TOLERANCE),
            Err(SignatureError::EmptySecret)
        );

        // Checked before the header, so garbage gets the same answer
        assert_eq!(
            verify("garbage", PAYLOAD, "", T, TOLERANCE),
            Err(SignatureError::EmptySecret)
        );
    }

    #[test]
    fn uppercase_hex_is_no_match() {
        // Stripe sends lowercase; hex is compared byte for byte, not decoded
        let good = v1_of(&sign_for_tests(PAYLOAD, SECRET, T)).to_uppercase();
        assert_ne!(good, good.to_lowercase());
        let header = format!("t={T},v1={good}");
        assert_eq!(
            verify(&header, PAYLOAD, SECRET, T, TOLERANCE),
            Err(SignatureError::NoMatch)
        );
    }

    #[test]
    fn truncated_or_extended_signature_is_no_match() {
        let good = v1_of(&sign_for_tests(PAYLOAD, SECRET, T)).to_string();
        let extended = format!("{good}0");

        for candidate in [&good[..63], &good[..32], "", extended.as_str()] {
            let header = format!("t={T},v1={candidate}");
            assert_eq!(
                verify(&header, PAYLOAD, SECRET, T, TOLERANCE),
                Err(SignatureError::NoMatch),
                "{candidate}"
            );
        }
    }
}
