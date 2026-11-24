//! Email confirmation codes: the only way an address reaches a
//! passkey-created account is a code typed into the app.
//!
//! * a code is 8 decimal digits drawn uniformly from the OS generator and is
//!   only ever stored as its SHA-256;
//! * it lives 15 minutes, takes at most five tries (the fifth wrong one
//!   deletes it) and a new one may be sent once a minute;
//! * the tries are counted in Redis BEFORE a guess is compared, so parallel
//!   guesses cannot share a try;
//! * wrong, expired, used and exhausted all look the same to the caller's
//!   client: `InvalidCredentials`;
//! * every Redis failure is an error: nothing is confirmed without Redis;
//! * one mailbox is sent at most 3 mails in 15 minutes and 10 in a day,
//!   whoever asks ([`reserve_address`]); without Redis it is sent none.
//!
//! Two callers, one set of rules, told apart by the Redis key they bring:
//!
//! * add-email keeps the whole state under its key: [`issue`] and [`check`];
//! * the pending sign-up keeps a [`CodeState`] inside its own blob and uses
//!   [`new_state`], [`begin_issue`], [`try_code`] and [`forget`] with the
//!   blob's key.
//!
//! A resend asks [`cooling_down`] with its key first, and [`reserve_address`]
//! only when the minute is over.
//!
//! Either way two more keys hang off the caller's key: `<key>:tries` and
//! `<key>:resend`.
//!
//! Nothing here logs or prints a code, a hash or an address.

use std::fmt;
use std::sync::LazyLock;

use rand::Rng;
use redis_kiss::redis::Script;
use redis_kiss::{get_connection, redis};
use revolt_database::util::email::normalise_email;
use revolt_result::{create_error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// How long a code can be used
pub const CODE_TTL_SECS: u64 = 900;

/// How long after a code was sent before another may be
pub const RESEND_COOLDOWN_SECS: u64 = 60;

/// Tries one code gets. The last wrong one deletes it.
pub const MAX_TRIES: i64 = 5;

/// Digits in a code
pub const CODE_DIGITS: usize = 8;

/// One more than the largest code
const CODE_SPACE: u32 = 100_000_000;

/// Count one try. The expiry is set by the same script that creates the key,
/// so a counter can never be left without one. It outlives the code it
/// counts for: the code was issued before its first try.
const COUNT_TRY_LUA: &str = r"
local tries = redis.call('INCR', KEYS[1])
if tries == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return tries
";

static COUNT_TRY: LazyLock<Script> = LazyLock::new(|| Script::new(COUNT_TRY_LUA));

/// Mails one address may be sent in one 15-minute window
pub const ADDRESS_MAILS_PER_WINDOW: u32 = 3;

/// Length of that window. It starts with the first mail counted in it.
pub const ADDRESS_WINDOW_SECS: u64 = 900;

/// Mails one address may be sent in a day
pub const ADDRESS_MAILS_PER_DAY: u32 = 10;

/// Length of the day. It starts with the first mail counted in it.
pub const ADDRESS_DAY_SECS: u64 = 86_400;

/// Take one mail from an address's 15 minutes (`KEYS[1]`, cap `ARGV[1]`,
/// expiry `ARGV[3]`) and its day (`KEYS[2]`, cap `ARGV[2]`, expiry
/// `ARGV[4]`).
///
/// Returns 1 after raising both, 0 when either is at its cap (nothing is
/// raised, so mails refused in a full window do not eat into the day), -1
/// when a counter does not hold a number. A key gets its expiry when it is
/// created, in the same script, and again if it is ever found without one.
const RESERVE_ADDRESS_LUA: &str = r"
local window = tonumber(redis.call('GET', KEYS[1]) or '0')
local day = tonumber(redis.call('GET', KEYS[2]) or '0')
if not window or not day then
  return -1
end
if window >= tonumber(ARGV[1]) or day >= tonumber(ARGV[2]) then
  return 0
end
if redis.call('INCR', KEYS[1]) == 1 or redis.call('TTL', KEYS[1]) < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[3])
end
if redis.call('INCR', KEYS[2]) == 1 or redis.call('TTL', KEYS[2]) < 0 then
  redis.call('EXPIRE', KEYS[2], ARGV[4])
end
return 1
";

static RESERVE_ADDRESS: LazyLock<Script> = LazyLock::new(|| Script::new(RESERVE_ADDRESS_LUA));

/// What is kept of a sent code: where it went and its SHA-256.
///
/// Serialised into Redis only. `Debug` prints neither field.
#[derive(Clone, Serialize, Deserialize)]
pub struct CodeState {
    email: String,
    hash: String,
}

impl fmt::Debug for CodeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CodeState(..)")
    }
}

impl CodeState {
    /// The address the code was sent to
    pub fn email(&self) -> &str {
        &self.email
    }
}

/// How one try ended
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The code is the one that was sent. The caller deletes the state.
    Correct,
    /// Not the code; tries remain
    Wrong,
    /// Out of tries, on this try or an earlier one. The caller MUST delete
    /// the state.
    Exhausted,
}

fn tries_key(key: &str) -> String {
    format!("{key}:tries")
}

fn cooldown_key(key: &str) -> String {
    format!("{key}:resend")
}

/// SHA-256 of the code's digits, lower-case hex
fn hash_code(code: &str) -> String {
    Sha256::digest(code.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The digits of something typed as a code, or None when it cannot be one
fn typed_code(code: &str) -> Option<&str> {
    let code = code.trim();

    (code.len() == CODE_DIGITS && code.bytes().all(|byte| byte.is_ascii_digit())).then_some(code)
}

/// The two counter keys of an address: its 15 minutes and its day. Named by
/// the SHA-256 of the address as the account model normalises it, so every
/// spelling of one mailbox (case, dots, a `+tag`) shares one pair and no
/// address is ever written into a key.
pub(crate) fn address_keys(email: &str) -> (String, String) {
    let normalised = normalise_email(email.to_string());
    let hash: String = Sha256::digest(normalised.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    (
        format!("passkey:email-rate:{hash}:window"),
        format!("passkey:email-rate:{hash}:day"),
    )
}

/// Claim the right to send one mail to `email`: at most 3 in 15 minutes and
/// 10 in a day, counted per mailbox whoever asks and whatever the mail is (a
/// code, or the "you already have an account" note).
///
/// Call before ANY mail to an address a client typed. False means send
/// nothing and issue no new code; the caller answers as if it had. Any Redis
/// failure is false too: no mail leaves without the counter.
pub async fn reserve_address(email: &str) -> Result<bool> {
    let (window_key, day_key) = address_keys(email);

    let Ok(conn) = get_connection().await else {
        log::error!("passkeys: no mail sent: the per-address counter has no Redis connection");
        return Ok(false);
    };
    let mut conn = conn.into_inner();

    let reserved = RESERVE_ADDRESS
        .key(window_key)
        .key(day_key)
        .arg(ADDRESS_MAILS_PER_WINDOW)
        .arg(ADDRESS_MAILS_PER_DAY)
        .arg(ADDRESS_WINDOW_SECS)
        .arg(ADDRESS_DAY_SECS)
        .invoke_async::<_, i64>(&mut conn)
        .await;

    match reserved {
        Ok(1) => Ok(true),
        Ok(0) => Ok(false),
        _ => {
            log::error!("passkeys: no mail sent: the per-address counter could not be read");
            Ok(false)
        }
    }
}

/// A fresh code for `email`: the state to keep and the code to mail.
///
/// Touches nothing: call [`begin_issue`] first, store the state, then mail.
pub fn new_state(email: &str) -> (CodeState, String) {
    // `gen_range` rejects the draws that would skew the low codes
    let number: u32 = rand::rngs::OsRng.gen_range(0..CODE_SPACE);
    let code = format!("{number:08}");

    let state = CodeState {
        email: email.to_string(),
        hash: hash_code(&code),
    };

    (state, code)
}

/// Claim the right to send a code under `key`: false when one was sent in
/// the last minute, and then nothing has changed. True also gives the new
/// code a fresh set of tries.
pub async fn begin_issue(key: &str) -> Result<bool> {
    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();

    let claimed: Option<String> = redis::cmd("SET")
        .arg(cooldown_key(key))
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(RESEND_COOLDOWN_SECS)
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    if claimed.is_none() {
        return Ok(false);
    }

    let _: i64 = redis::cmd("DEL")
        .arg(tries_key(key))
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    Ok(true)
}

/// Whether a code was sent under `key` in the last minute, so that
/// [`begin_issue`] would refuse. A look only: nothing is written.
///
/// Ask before [`reserve_address`] on a resend: a request inside the minute
/// sends nothing, so it must not take a mail from the address either. A
/// Redis failure is true: treated as still waiting, nothing is sent.
pub async fn cooling_down(key: &str) -> Result<bool> {
    let Ok(conn) = get_connection().await else {
        log::error!("passkeys: no mail sent: the resend wait has no Redis connection");
        return Ok(true);
    };
    let mut conn = conn.into_inner();

    let marked: std::result::Result<i64, _> = redis::cmd("EXISTS")
        .arg(cooldown_key(key))
        .query_async(&mut conn)
        .await;

    match marked {
        Ok(0) => Ok(false),
        Ok(_) => Ok(true),
        Err(_) => {
            log::error!("passkeys: no mail sent: the resend wait could not be read");
            Ok(true)
        }
    }
}

/// One try of `code` against `state`, counted under `key`.
///
/// Something that cannot be a code (not 8 digits) is `Wrong` and costs no
/// try. Anything else is counted first and compared after, in constant time.
pub async fn try_code(key: &str, state: &CodeState, code: &str) -> Result<Verdict> {
    let Some(code) = typed_code(code) else {
        return Ok(Verdict::Wrong);
    };

    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();

    let tries = COUNT_TRY
        .key(tries_key(key))
        .arg(CODE_TTL_SECS)
        .invoke_async::<_, i64>(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    if !(1..=MAX_TRIES).contains(&tries) {
        return Ok(Verdict::Exhausted);
    }

    let typed = hash_code(code);
    if bool::from(typed.as_bytes().ct_eq(state.hash.as_bytes())) {
        return Ok(Verdict::Correct);
    }

    Ok(if tries == MAX_TRIES {
        Verdict::Exhausted
    } else {
        Verdict::Wrong
    })
}

/// Drop the try counter of `key`, once its code is used up or gone. The
/// resend marker is left to run out: deleting it would allow another mail
/// straight away.
pub async fn forget(key: &str) -> Result<()> {
    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();

    let _: i64 = redis::cmd("DEL")
        .arg(tries_key(key))
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    Ok(())
}

/// Start a code for `email` under `key` and return it for mailing. The state
/// is the whole value of `key`, for 15 minutes; a code issued earlier under
/// the same key stops working.
///
/// `Ok(None)` when a code was sent under this key in the last minute:
/// nothing changed, send nothing.
pub async fn issue(key: &str, email: &str) -> Result<Option<String>> {
    if !begin_issue(key).await? {
        return Ok(None);
    }

    let (state, code) = new_state(email);
    let text = serde_json::to_string(&state).map_err(|_| create_error!(InternalError))?;

    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();

    let set: Option<String> = redis::cmd("SET")
        .arg(key)
        .arg(text)
        .arg("EX")
        .arg(CODE_TTL_SECS)
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    if set.is_none() {
        return Err(create_error!(InternalError));
    }

    Ok(Some(code))
}

/// Check `code` against the state under `key`; the address the code was sent
/// to when it is right. A right code deletes the state: it works once.
///
/// `InvalidCredentials` for a wrong code, no code, an expired one, one that
/// ran out of tries (which deletes the state) and one already used.
pub async fn check(key: &str, code: &str) -> Result<String> {
    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();

    let text: Option<String> = redis::cmd("GET")
        .arg(key)
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    let Some(text) = text else {
        return Err(create_error!(InvalidCredentials));
    };
    let Ok(state) = serde_json::from_str::<CodeState>(&text) else {
        return Err(create_error!(InvalidCredentials));
    };

    match try_code(key, &state, code).await? {
        Verdict::Wrong => Err(create_error!(InvalidCredentials)),
        Verdict::Exhausted => {
            let _: i64 = redis::cmd("DEL")
                .arg(key)
                .arg(tries_key(key))
                .query_async(&mut conn)
                .await
                .map_err(|_| create_error!(InternalError))?;

            Err(create_error!(InvalidCredentials))
        }
        Verdict::Correct => {
            // Only one of two requests with the right code gets the state,
            // and only while it is still the state that was compared
            let taken: Option<String> = redis::cmd("GETDEL")
                .arg(key)
                .query_async(&mut conn)
                .await
                .map_err(|_| create_error!(InternalError))?;

            if taken.as_deref() != Some(text.as_str()) {
                return Err(create_error!(InvalidCredentials));
            }

            // The code is spent either way; a counter left behind expires
            let _ = forget(key).await;

            Ok(state.email)
        }
    }
}

#[cfg(test)]
mod tests {
    //! These need Redis. Every test works under a key of its own.
    //!
    //! Each test says, under "Fails if", the one change to the code above that
    //! turns it red.

    use redis_kiss::{get_connection, redis};
    use revolt_result::Result;
    use ulid::Ulid;

    use super::*;
    use crate::util::test::{rt, TestHarness};

    const EMAIL: &str = "someone@example.test";

    /// What every refusal looks like
    const REFUSED: &str = "InvalidCredentials";

    fn fresh_key() -> String {
        format!("passkey:email-code-test:{}", Ulid::new())
    }

    fn outcome<T>(result: Result<T>) -> String {
        match result {
            Ok(_) => "Ok".to_string(),
            Err(error) => format!("{:?}", error.error_type),
        }
    }

    /// A well-formed code that is not `code`
    fn another_code(code: &str) -> String {
        let number: u32 = code.parse().expect("digits");
        format!("{:08}", (number + 1) % CODE_SPACE)
    }

    async fn ttl(key: &str) -> i64 {
        let mut conn = get_connection().await.expect("redis").into_inner();
        redis::cmd("TTL")
            .arg(key)
            .query_async(&mut conn)
            .await
            .expect("TTL")
    }

    async fn get(key: &str) -> Option<String> {
        let mut conn = get_connection().await.expect("redis").into_inner();
        redis::cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await
            .expect("GET")
    }

    async fn del(key: &str) {
        let mut conn = get_connection().await.expect("redis").into_inner();
        let _: i64 = redis::cmd("DEL")
            .arg(key)
            .query_async(&mut conn)
            .await
            .expect("DEL");
    }

    /// Fails if: a code is not exactly 8 digits (the zero padding is lost),
    /// the hash stops being the SHA-256 of the digits, or `Debug` prints a
    /// field.
    #[test]
    fn a_code_is_eight_digits_and_its_state_holds_only_the_hash() {
        // SHA-256("00000000"), from the definition and not from `hash_code`
        assert_eq!(
            hash_code("00000000"),
            "7e071fd9b023ed8f18458a73613a0834f6220bd5cc50357ba3493c6040a9ea8c"
        );

        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let (state, code) = new_state(EMAIL);
            assert_eq!(code.len(), CODE_DIGITS, "{code}");
            assert!(code.bytes().all(|byte| byte.is_ascii_digit()), "{code}");
            assert_eq!(state.email(), EMAIL);
            assert_eq!(state.hash, hash_code(&code));
            assert_eq!(state.hash.len(), 64);

            let stored = serde_json::to_string(&state).expect("json");
            assert!(!stored.contains(&code), "the stored state holds the code");

            let printed = format!("{state:?}");
            assert!(!printed.contains(&code) && !printed.contains(&state.hash));
            assert!(!printed.contains(EMAIL));

            seen.insert(code);
        }
        // 200 draws from 10^8: a repeat means the generator is not one
        assert!(seen.len() >= 199, "{} distinct codes", seen.len());

        // What can and cannot be a code
        assert_eq!(typed_code(" 01234567 "), Some("01234567"));
        for not_a_code in ["", "1234567", "123456789", "1234 567", "1234567a", "-1234567"] {
            assert_eq!(typed_code(not_a_code), None, "{not_a_code:?}");
        }
    }

    /// Fails if: `issue` stores the code itself, drops the expiry, or `check`
    /// accepts a wrong code, returns another address, or leaves the state in
    /// place after the right code.
    #[test]
    fn the_right_code_works_once_and_the_stored_value_is_not_the_code() {
        rt().block_on(async {
            let _harness = TestHarness::new().await;
            let key = fresh_key();

            assert_eq!(outcome(check(&key, "00000000").await), REFUSED, "no code");

            let code = issue(&key, EMAIL).await.expect("issue").expect("a code");
            assert_eq!(code.len(), CODE_DIGITS);

            // The value under the key: the address and a hash, never the code
            let stored = get(&key).await.expect("state");
            assert!(!stored.contains(&code), "the code is stored");
            assert!(stored.contains(&hash_code(&code)));
            assert!(stored.contains(EMAIL));

            // 15 minutes, and the resend marker one
            let left = ttl(&key).await;
            assert!((1..=900).contains(&left), "ttl {left}");
            let left = ttl(&cooldown_key(&key)).await;
            assert!((1..=60).contains(&left), "cooldown ttl {left}");

            assert_eq!(
                outcome(check(&key, &another_code(&code)).await),
                REFUSED,
                "a wrong code"
            );
            let left = ttl(&tries_key(&key)).await;
            assert!((1..=900).contains(&left), "tries ttl {left}");

            // Padded with spaces as a paste would be
            let email = check(&key, &format!(" {code} ")).await.expect("check");
            assert_eq!(email, EMAIL);

            assert_eq!(get(&key).await, None, "the state survived its use");
            assert_eq!(get(&tries_key(&key)).await, None);
            assert_eq!(outcome(check(&key, &code).await), REFUSED, "used twice");
        })
    }

    /// Fails if: the tries are not counted, the limit is off by one, or the
    /// fifth wrong try leaves the state in place.
    #[test]
    fn five_wrong_tries_then_the_right_code_fails() {
        rt().block_on(async {
            let _harness = TestHarness::new().await;

            // Four wrong tries leave the fifth for the right code
            let key = fresh_key();
            let code = issue(&key, EMAIL).await.expect("issue").expect("a code");
            let wrong = another_code(&code);
            for _ in 0..(MAX_TRIES - 1) {
                assert_eq!(outcome(check(&key, &wrong).await), REFUSED);
            }
            assert_eq!(check(&key, &code).await.expect("the fifth try"), EMAIL);

            // Five wrong tries use it up
            let key = fresh_key();
            let code = issue(&key, EMAIL).await.expect("issue").expect("a code");
            let wrong = another_code(&code);
            for _ in 0..MAX_TRIES {
                assert_eq!(outcome(check(&key, &wrong).await), REFUSED);
            }
            assert_eq!(get(&key).await, None, "the state survived five tries");
            assert_eq!(
                outcome(check(&key, &code).await),
                REFUSED,
                "the right code after five wrong ones"
            );

            // Something that cannot be a code costs no try
            let key = fresh_key();
            let code = issue(&key, EMAIL).await.expect("issue").expect("a code");
            for _ in 0..(MAX_TRIES * 2) {
                assert_eq!(outcome(check(&key, "1234").await), REFUSED);
            }
            assert_eq!(check(&key, &code).await.expect("still usable"), EMAIL);
        })
    }

    /// Fails if: `try_code` compares before it counts or stops at the wrong
    /// count: with the counter already at the limit, the right code must not
    /// pass (this is what parallel guesses run into).
    #[test]
    fn a_try_past_the_limit_is_refused_even_with_the_right_code() {
        rt().block_on(async {
            let _harness = TestHarness::new().await;
            let key = fresh_key();
            let (state, code) = new_state(EMAIL);

            let mut conn = get_connection().await.expect("redis").into_inner();
            let _: () = redis::cmd("SET")
                .arg(tries_key(&key))
                .arg(MAX_TRIES)
                .arg("EX")
                .arg(60)
                .query_async(&mut conn)
                .await
                .expect("SET");

            assert_eq!(
                try_code(&key, &state, &code).await.expect("try"),
                Verdict::Exhausted
            );

            // The verdicts below the limit, on a key of its own
            let key = fresh_key();
            let wrong = another_code(&code);
            for _ in 0..(MAX_TRIES - 1) {
                assert_eq!(
                    try_code(&key, &state, &wrong).await.expect("try"),
                    Verdict::Wrong
                );
            }
            assert_eq!(
                try_code(&key, &state, &wrong).await.expect("try"),
                Verdict::Exhausted,
                "the fifth wrong try"
            );
            del(&tries_key(&key)).await;
            assert_eq!(
                try_code(&key, &state, &code).await.expect("try"),
                Verdict::Correct
            );
            forget(&key).await.expect("forget");
            assert_eq!(get(&tries_key(&key)).await, None);
        })
    }

    /// Fails if: `begin_issue` stops using `SET NX` (a second code within the
    /// minute), drops the marker's expiry, or a refused issue replaces the
    /// first code.
    #[test]
    fn a_second_code_within_the_cooldown_is_refused() {
        rt().block_on(async {
            let _harness = TestHarness::new().await;
            let key = fresh_key();

            let first = issue(&key, EMAIL).await.expect("issue").expect("a code");
            let stored = get(&key).await;
            assert_eq!(
                issue(&key, "other@example.test").await.expect("issue"),
                None,
                "a second code within the minute"
            );
            assert_eq!(get(&key).await, stored, "the refused issue changed the state");

            // Another key has its own cooldown
            let other = fresh_key();
            assert!(issue(&other, EMAIL).await.expect("issue").is_some());

            // Once the marker is gone a new code replaces the old one and
            // gets its own tries
            assert_eq!(outcome(check(&key, &another_code(&first)).await), REFUSED);
            del(&cooldown_key(&key)).await;
            let second = issue(&key, "other@example.test")
                .await
                .expect("issue")
                .expect("a code after the cooldown");
            assert_eq!(get(&tries_key(&key)).await, None, "the tries carried over");
            if second != first {
                assert_eq!(outcome(check(&key, &first).await), REFUSED, "the old code");
            }
            assert_eq!(
                check(&key, &second).await.expect("check"),
                "other@example.test"
            );
        })
    }

    /// Fails if: `cooling_down` reads another key than the marker
    /// `begin_issue` sets, says false while the marker is there or true
    /// once it is gone, or writes anything (the marker, its expiry or the
    /// try counter).
    #[test]
    fn the_cooldown_can_be_looked_at_without_changing_it() {
        rt().block_on(async {
            let _harness = TestHarness::new().await;
            let key = fresh_key();
            let marker = cooldown_key(&key);

            // Nothing sent yet, and the look creates nothing
            for _ in 0..3 {
                assert!(!cooling_down(&key).await.expect("look"), "before a code");
            }
            assert_eq!(get(&marker).await, None, "the look set the marker");
            assert_eq!(get(&key).await, None);
            assert_eq!(get(&tries_key(&key)).await, None);

            assert!(begin_issue(&key).await.expect("issue"));
            let mut conn = get_connection().await.expect("redis").into_inner();
            let _: i64 = redis::cmd("EXPIRE")
                .arg(&marker)
                .arg(30)
                .query_async(&mut conn)
                .await
                .expect("EXPIRE");

            for _ in 0..3 {
                assert!(cooling_down(&key).await.expect("look"), "within the minute");
            }
            let left = ttl(&marker).await;
            assert!((1..=30).contains(&left), "the look renewed the marker: {left}");
            assert_eq!(get(&marker).await.as_deref(), Some("1"));
            assert_eq!(get(&tries_key(&key)).await, None);

            // The look took nothing: the next issue is still refused
            assert!(!begin_issue(&key).await.expect("issue"));

            // Another key is not waiting
            assert!(!cooling_down(&fresh_key()).await.expect("look"));

            // The minute is over
            del(&marker).await;
            assert!(!cooling_down(&key).await.expect("look"), "after the minute");
            assert_eq!(get(&marker).await, None);
        })
    }

    /// An address nothing else uses, so its counters start empty
    fn fresh_address() -> String {
        format!("rate{}@example.test", Ulid::new().to_string().to_lowercase())
    }

    /// Fails if: the keys hold the address itself, stop being named by the
    /// SHA-256 of the normalised address, or two spellings of one mailbox
    /// get two pairs of counters.
    #[test]
    fn the_address_counters_are_named_by_the_hash_of_the_normalised_address() {
        // SHA-256("someone@example.test"), from the definition
        let (window, day) = address_keys(EMAIL);
        let hash: String = Sha256::digest(b"someone@example.test")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(window, format!("passkey:email-rate:{hash}:window"));
        assert_eq!(day, format!("passkey:email-rate:{hash}:day"));
        assert!(!window.contains("someone") && !day.contains("example"));

        // One mailbox, however it is spelled
        for spelling in [
            "Someone@Example.Test",
            "some.one@example.test",
            "someone+signup@example.test",
            "S.o.m.e.o.n.e+a.b@EXAMPLE.test",
        ] {
            assert_eq!(address_keys(spelling), (window.clone(), day.clone()), "{spelling}");
        }

        // Another mailbox
        assert_ne!(address_keys("someone@example.org").0, window);
        assert_ne!(address_keys("someone2@example.test").1, day);
    }

    /// Fails if: the window allows a fourth mail, a refused mail is counted,
    /// a key is created without an expiry or has it renewed by a later mail,
    /// another spelling of the mailbox gets a budget of its own, or one
    /// address spends another's.
    #[test]
    fn the_fourth_mail_to_an_address_in_the_window_is_refused() {
        rt().block_on(async {
            let _harness = TestHarness::new().await;
            let address = fresh_address();
            let other = fresh_address();
            let (window, day) = address_keys(&address);

            assert!(reserve_address(&address).await.expect("the first"));

            let left = ttl(&window).await;
            assert!((1..=900).contains(&left), "window ttl {left}");
            let left = ttl(&day).await;
            assert!((1..=86_400).contains(&left), "day ttl {left}");

            // A later mail does not push the expiry out. The second goes to
            // another spelling of the same mailbox.
            let mut conn = get_connection().await.expect("redis").into_inner();
            for key in [&window, &day] {
                let _: i64 = redis::cmd("EXPIRE")
                    .arg(key)
                    .arg(100)
                    .query_async(&mut conn)
                    .await
                    .expect("EXPIRE");
            }
            let respelled = address.replacen('@', "+again@", 1).to_uppercase();
            assert!(reserve_address(&respelled).await.expect("the second"));
            assert!(reserve_address(&address).await.expect("the third"));
            assert!((1..=100).contains(&ttl(&window).await), "window ttl was renewed");
            assert!((1..=100).contains(&ttl(&day).await), "day ttl was renewed");

            for _ in 0..3 {
                assert!(
                    !reserve_address(&address).await.expect("refused"),
                    "the fourth in the window"
                );
                assert!(!reserve_address(&respelled).await.expect("refused"));
            }
            assert_eq!(get(&window).await.as_deref(), Some("3"));
            assert_eq!(get(&day).await.as_deref(), Some("3"), "refusals were counted");

            // Another address is not held back, and has its own counters
            assert!(reserve_address(&other).await.expect("another address"));
            let (other_window, other_day) = address_keys(&other);
            assert_eq!(get(&other_window).await.as_deref(), Some("1"));
            assert_eq!(get(&window).await.as_deref(), Some("3"));

            for key in [window, day, other_window, other_day] {
                del(&key).await;
            }
        })
    }

    /// Fails if: the day cap is dropped or off by one, a full day still
    /// raises the window counter, or a counter that is not a number or has
    /// no expiry is trusted as it is.
    #[test]
    fn the_eleventh_mail_to_an_address_in_a_day_is_refused() {
        rt().block_on(async {
            let _harness = TestHarness::new().await;
            let address = fresh_address();
            let (window, day) = address_keys(&address);

            // Ten mails over several windows: the window key is gone each
            // time it fills, as it would be after 15 minutes
            let mut sent = 0;
            while sent < ADDRESS_MAILS_PER_DAY {
                if reserve_address(&address).await.expect("reserve") {
                    sent += 1;
                } else {
                    assert_eq!(get(&window).await.as_deref(), Some("3"));
                    del(&window).await;
                }
            }
            assert_eq!(get(&day).await.as_deref(), Some("10"));

            // A new window, the same day: the day cap is what stops it
            del(&window).await;
            for _ in 0..3 {
                assert!(
                    !reserve_address(&address).await.expect("refused"),
                    "the eleventh in the day"
                );
            }
            assert_eq!(get(&window).await, None, "a full day raised the window");
            assert_eq!(get(&day).await.as_deref(), Some("10"));

            // A counter that is not a number refuses
            let mut conn = get_connection().await.expect("redis").into_inner();
            del(&day).await;
            let _: () = redis::cmd("SET")
                .arg(&window)
                .arg("many")
                .arg("EX")
                .arg(60)
                .query_async(&mut conn)
                .await
                .expect("SET");
            assert!(!reserve_address(&address).await.expect("refused"));
            assert_eq!(get(&day).await, None);

            // A key found without an expiry gets one
            let _: () = redis::cmd("SET")
                .arg(&window)
                .arg("1")
                .query_async(&mut conn)
                .await
                .expect("SET");
            assert!(reserve_address(&address).await.expect("reserve"));
            assert!((1..=900).contains(&ttl(&window).await), "no expiry");

            for key in [window, day] {
                del(&key).await;
            }
        })
    }
}
