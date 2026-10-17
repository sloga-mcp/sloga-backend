//! Ownership challenge codes for importing a server from another platform.
//!
//! Before an import starts, the user proves they manage the source server by
//! placing a short code there (a server description, a role name, a room
//! topic). The code is an HMAC over the source, the Sloga user and the UTC
//! day, so it cannot be guessed, cannot be replayed by another account, and a
//! code minted for one source (Stoat) does not verify against another
//! (Matrix). Keyed by the shared `[api.import] challenge_secret`. The code that
//! matched at verification is stored on the job (`challenge_code`); later
//! checks compare against that stored value and never recompute it, so a UTC
//! day roll-over mid-import cannot invalidate it.

use chrono::{DateTime, NaiveDate, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Every challenge code starts with this, so users can tell what it is for
pub const CODE_PREFIX: &str = "sloga-import-";

/// Characters of the base32 digest kept after the prefix (40 bits)
const CODE_DIGEST_LEN: usize = 8;

/// Challenge code for `user_id` importing from `source_tag` on UTC `day`.
///
/// `CODE_PREFIX` followed by the first eight characters of the RFC 4648
/// base32 (uppercase, unpadded) encoding of
/// HMAC-SHA256(key, `"{source_tag}:{user_id}:{yyyy-mm-dd}"`).
pub fn code(key: &[u8], source_tag: &str, user_id: &str, day: NaiveDate) -> String {
    // Config readiness refuses an empty secret, so this never happens in a
    // running service; HMAC still accepts it, so release builds produce a value
    debug_assert!(!key.is_empty(), "import challenge key must not be empty");

    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(format!("{source_tag}:{user_id}:{}", day.format("%Y-%m-%d")).as_bytes());
    let digest = mac.finalize().into_bytes();

    let encoded = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &digest);
    format!("{CODE_PREFIX}{}", &encoded[..CODE_DIGEST_LEN])
}

/// The codes accepted at `now`: today's and yesterday's (UTC), so a code
/// shown just before midnight still verifies a little after it
pub fn accepted_codes(
    key: &[u8],
    source_tag: &str,
    user_id: &str,
    now: DateTime<Utc>,
) -> [String; 2] {
    let today = now.date_naive();
    // Only `NaiveDate::MIN` has no predecessor; fall back to today there
    let yesterday = today.pred_opt().unwrap_or(today);

    [
        code(key, source_tag, user_id, today),
        code(key, source_tag, user_id, yesterday),
    ]
}

/// Find an accepted code inside text the user controls on the source
/// platform (a description, topic or name), returning the code that matched.
///
/// Users paste the code among other text, so it may appear anywhere. The
/// match is exact (case-sensitive), and the character after the code must
/// be absent or non-alphanumeric: a longer token that merely starts with a
/// valid code (`sloga-import-ABCDEFGHX`) is a different string the user did
/// not get from us, and accepting it would make the check depend on where
/// the surrounding text happens to break rather than on the code itself.
pub fn find_accepted_code(
    haystack: &str,
    key: &[u8],
    source_tag: &str,
    user_id: &str,
    now: DateTime<Utc>,
) -> Option<String> {
    accepted_codes(key, source_tag, user_id, now)
        .into_iter()
        .find(|candidate| {
            haystack
                .match_indices(candidate.as_str())
                .any(|(start, _)| {
                    haystack[start + candidate.len()..]
                        .chars()
                        .next()
                        .map_or(true, |next| !next.is_alphanumeric())
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    const KEY: &[u8] = b"test-challenge-secret";
    const USER: &str = "01J9ZQ4V6X7B8C9D0E1F2G3H4J";
    const OTHER_USER: &str = "01J9ZQ4V6X7B8C9D0E1F2G3H4K";

    fn day(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    fn at(y: i32, m: u32, d: u32, h: u32, min: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, min, s).unwrap()
    }

    #[test]
    fn known_answer_vector() {
        // Computed independently with Python's hmac + base64.b32encode; a
        // change to the message format or encoding breaks every issued code
        assert_eq!(
            code(KEY, "stoat", USER, day(2026, 10, 15)),
            "sloga-import-AKY7V2QD"
        );
        assert_eq!(
            code(KEY, "fluxer", USER, day(2026, 10, 15)),
            "sloga-import-Y7G2E4X2"
        );
    }

    #[test]
    fn deterministic() {
        let d = day(2026, 10, 15);
        assert_eq!(code(KEY, "stoat", USER, d), code(KEY, "stoat", USER, d));
    }

    #[test]
    fn length_and_alphabet() {
        let c = code(KEY, "matrix", USER, day(2026, 1, 2));
        assert_eq!(c.len(), CODE_PREFIX.len() + 8);
        let suffix = c
            .strip_prefix(CODE_PREFIX)
            .expect("code carries the prefix");
        assert!(suffix
            .bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)));
    }

    #[test]
    fn differs_per_user_source_day_and_key() {
        let d = day(2026, 10, 15);
        let base = code(KEY, "stoat", USER, d);
        assert_ne!(base, code(KEY, "stoat", OTHER_USER, d));
        assert_ne!(base, code(KEY, "fluxer", USER, d));
        assert_ne!(base, code(KEY, "stoat", USER, day(2026, 10, 16)));
        assert_ne!(base, code(b"another-secret", "stoat", USER, d));
    }

    #[test]
    fn accepted_codes_today_and_yesterday_across_midnight() {
        let just_before = at(2026, 10, 15, 23, 59, 59);
        let just_after = at(2026, 10, 16, 0, 0, 1);

        assert_eq!(
            accepted_codes(KEY, "stoat", USER, just_before),
            [
                code(KEY, "stoat", USER, day(2026, 10, 15)),
                code(KEY, "stoat", USER, day(2026, 10, 14)),
            ]
        );

        // A code shown at 23:59:59 still verifies two seconds later
        let shown = code(KEY, "stoat", USER, just_before.date_naive());
        assert_eq!(
            accepted_codes(KEY, "stoat", USER, just_after),
            [code(KEY, "stoat", USER, day(2026, 10, 16)), shown]
        );
    }

    #[test]
    fn day_before_yesterday_rejected() {
        let now = at(2026, 10, 16, 12, 0, 0);
        let stale = code(KEY, "stoat", USER, day(2026, 10, 14));
        assert!(!accepted_codes(KEY, "stoat", USER, now).contains(&stale));
        assert_eq!(
            find_accepted_code(&format!("code: {stale}"), KEY, "stoat", USER, now),
            None
        );
    }

    #[test]
    fn finds_code_embedded_in_surrounding_text() {
        let now = at(2026, 10, 15, 8, 30, 0);
        let today = code(KEY, "stoat", USER, day(2026, 10, 15));
        let yesterday = code(KEY, "stoat", USER, day(2026, 10, 14));

        let description = format!("Welcome to the server!\n\nVerify: {today}.\nRules below");
        assert_eq!(
            find_accepted_code(&description, KEY, "stoat", USER, now),
            Some(today.clone())
        );

        // At the very end of the text, with nothing after it
        assert_eq!(
            find_accepted_code(&format!("about us\n{yesterday}"), KEY, "stoat", USER, now),
            Some(yesterday)
        );

        // Bare code
        assert_eq!(
            find_accepted_code(&today, KEY, "stoat", USER, now),
            Some(today.clone())
        );
    }

    #[test]
    fn rejects_longer_token() {
        let now = at(2026, 10, 15, 8, 30, 0);
        let today = code(KEY, "stoat", USER, day(2026, 10, 15));

        for haystack in [
            format!("{today}X"),
            format!("{today}2"),
            format!("{today}é"),
        ] {
            assert_eq!(
                find_accepted_code(&haystack, KEY, "stoat", USER, now),
                None,
                "{haystack}"
            );
        }

        // A longer token earlier does not hide a valid occurrence later
        assert_eq!(
            find_accepted_code(&format!("{today}X then {today}"), KEY, "stoat", USER, now),
            Some(today)
        );
    }

    #[test]
    fn rejects_lowercased_code() {
        let now = at(2026, 10, 15, 8, 30, 0);
        let today = code(KEY, "stoat", USER, day(2026, 10, 15));
        assert_eq!(
            find_accepted_code(&today.to_lowercase(), KEY, "stoat", USER, now),
            None
        );
    }

    #[test]
    fn rejects_other_users_code() {
        let now = at(2026, 10, 15, 8, 30, 0);
        let theirs = code(KEY, "stoat", OTHER_USER, day(2026, 10, 15));
        assert_eq!(
            find_accepted_code(&format!("verify {theirs}"), KEY, "stoat", USER, now),
            None
        );
    }

    #[test]
    fn rejects_other_source_tags_code() {
        let now = at(2026, 10, 15, 8, 30, 0);
        let matrix = code(KEY, "matrix", USER, day(2026, 10, 15));
        assert_eq!(
            find_accepted_code(&format!("verify {matrix}"), KEY, "stoat", USER, now),
            None
        );
    }
}
