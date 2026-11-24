//! Redis state for passkey sign-up and passkey recovery. No account exists
//! (sign-up) or no session exists (recovery) while any of it is alive, so
//! all of it is short-lived, single use and made here, never by a client.
//!
//! * the pending sign-up: `passkey:signup:<64 hex>`, 15 minutes. Holds the
//!   fields the start route validated, the user handle of the passkey to be
//!   and, when an email was given, the state of its code
//!   (`util/email_code.rs`). Read by `load`, consumed by `take`;
//! * the no-email counter: one key per clock hour and one per day, checked
//!   and raised by one script. Over a cap, a cap of 0 and any Redis failure
//!   all refuse;
//! * the recovery token: 32 random bytes handed out as base64url and kept
//!   only as `passkey:recover:<SHA-256 hex>`, 30 minutes, one per account
//!   at a time, at most one new one per account every 10 minutes.
//!
//! Nothing here logs or prints a code, a token, a hash or an address.

use std::fmt;
use std::sync::LazyLock;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use rand::RngCore;
use redis_kiss::redis::Script;
use redis_kiss::{get_connection, redis};
use revolt_config::config;
use revolt_result::{create_error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use webauthn_rs::prelude::Uuid;

use super::email_code::{self, CodeState, Verdict};

/// How long a pending sign-up lives, from start to finish
pub const SIGNUP_TTL_SECS: u64 = 900;

/// How long a recovery token can be used
pub const RECOVER_TOKEN_TTL_SECS: u64 = 1800;

/// How long after a recovery token was issued before the same account may
/// get another
pub const RECOVER_COOLDOWN_SECS: u64 = 600;

/// Bytes in a recovery token
const RECOVER_TOKEN_BYTES: usize = 32;

/// Lifetime of an hourly counter key. Its name carries the clock hour, so
/// it only has to outlive that hour.
const HOUR_KEY_TTL_SECS: u64 = 2 * 60 * 60;

/// Lifetime of a daily counter key
const DAY_KEY_TTL_SECS: u64 = 2 * 24 * 60 * 60;

/// Replace the value of a key only while it still holds what was read, and
/// leave its expiry alone
const SWAP_LUA: &str = r"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('SET', KEYS[1], ARGV[2], 'KEEPTTL')
  return 1
end
return 0
";

/// Take one no-email sign-up from the hour (`KEYS[1]`, cap `ARGV[1]`, expiry
/// `ARGV[3]`) and the day (`KEYS[2]`, cap `ARGV[2]`, expiry `ARGV[4]`).
///
/// Returns 1 after raising both, 0 when either is at its cap (nothing is
/// raised, so a refusal in a full hour does not eat into the day), -1 when a
/// counter does not hold a number. A key gets its expiry when it is created,
/// in the same script, and again if it is ever found without one.
const RESERVE_LUA: &str = r"
local hour = tonumber(redis.call('GET', KEYS[1]) or '0')
local day = tonumber(redis.call('GET', KEYS[2]) or '0')
if not hour or not day then
  return -1
end
if hour >= tonumber(ARGV[1]) or day >= tonumber(ARGV[2]) then
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

static SWAP: LazyLock<Script> = LazyLock::new(|| Script::new(SWAP_LUA));
static RESERVE: LazyLock<Script> = LazyLock::new(|| Script::new(RESERVE_LUA));

/// 32 bytes from the OS generator, lower-case hex
fn random_hex_id() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// 64 lower-case hex characters: the shape of a sign-up id and of a hash
fn is_hex_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Err unless passkey sign-up is switched on (`[features.passkeys].signup`).
/// The sign-up, recovery and add-an-email routes ask
/// `passkey::assert_available` first, then this.
pub async fn assert_signup_on() -> Result<()> {
    if config().await.features.passkeys.signup {
        Ok(())
    } else {
        Err(create_error!(FeatureDisabled {
            feature: "passkey_signup".to_string()
        }))
    }
}

// ---------------------------------------------------------------------------
// Pending sign-up
// ---------------------------------------------------------------------------

/// What the start route validated, as it will be used at finish
#[derive(Clone)]
pub struct SignupFields {
    pub username: String,
    /// The address to confirm, or None for a sign-up with no email
    pub email: Option<String>,
    pub invite: Option<String>,
    pub referral_code: Option<String>,
    pub invite_code: Option<String>,
}

/// A sign-up between its start and its finish.
///
/// `Debug` prints no field value.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingSignup {
    pub username: String,
    /// The address given at start. Confirmed only when `email_confirmed`.
    pub email: Option<String>,
    pub invite: Option<String>,
    pub referral_code: Option<String>,
    pub invite_code: Option<String>,
    /// The user handle of the passkey to be (a UUID), random per sign-up
    pub user_handle: String,
    /// Set by `mark_email_confirmed` and by nothing else
    pub email_confirmed: bool,
    /// The code that was mailed, until it is used
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code: Option<CodeState>,
}

impl fmt::Debug for PendingSignup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingSignup")
            .field("has_email", &self.email.is_some())
            .field("email_confirmed", &self.email_confirmed)
            .finish_non_exhaustive()
    }
}

impl PendingSignup {
    /// Whether the passkey may be created: no email was given, or the one
    /// given has been confirmed
    pub fn ready_for_passkey(&self) -> bool {
        self.email.is_none() || self.email_confirmed
    }

    /// The address to put on the account: None unless one was given AND
    /// confirmed. Check `ready_for_passkey` first; None alone does not mean
    /// "a sign-up with no email".
    pub fn confirmed_email(&self) -> Option<&str> {
        if self.email_confirmed {
            self.email.as_deref()
        } else {
            None
        }
    }
}

fn signup_key(signup_id: &str) -> String {
    format!("passkey:signup:{signup_id}")
}

/// What every refusal about a pending sign-up looks like
fn refused() -> revolt_result::Error {
    create_error!(InvalidCredentials)
}

/// The stored text of a pending sign-up and its parsed form. None when the
/// id is malformed, unknown, expired or used.
async fn read_signup(signup_id: &str) -> Result<Option<(String, PendingSignup)>> {
    if !is_hex_id(signup_id) {
        return Ok(None);
    }

    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();

    let text: Option<String> = redis::cmd("GET")
        .arg(signup_key(signup_id))
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    Ok(text.and_then(|text| {
        let pending = serde_json::from_str(&text).ok()?;
        Some((text, pending))
    }))
}

/// Write `pending` over the text that was read, keeping the expiry. False
/// when the blob changed or went away in between.
async fn swap_signup(signup_id: &str, was: &str, pending: &PendingSignup) -> Result<bool> {
    let text = serde_json::to_string(pending).map_err(|_| create_error!(InternalError))?;

    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();

    let swapped = SWAP
        .key(signup_key(signup_id))
        .arg(was)
        .arg(text)
        .invoke_async::<_, i64>(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    Ok(swapped == 1)
}

async fn delete_signup(signup_id: &str) -> Result<()> {
    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();

    let _: i64 = redis::cmd("DEL")
        .arg(signup_key(signup_id))
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    Ok(())
}

/// Store a pending sign-up for 15 minutes.
///
/// Returns its id and, when `fields.email` is set, the code to mail to that
/// address. The user handle is drawn here.
pub async fn create(fields: SignupFields) -> Result<(String, Option<String>)> {
    let signup_id = random_hex_id();
    let key = signup_key(&signup_id);

    let (code_state, code) = match fields.email.as_deref() {
        Some(email) => {
            let (state, code) = email_code::new_state(email);
            (Some(state), Some(code))
        }
        None => (None, None),
    };

    let pending = PendingSignup {
        username: fields.username,
        email: fields.email,
        invite: fields.invite,
        referral_code: fields.referral_code,
        invite_code: fields.invite_code,
        user_handle: Uuid::new_v4().to_string(),
        email_confirmed: false,
        code: code_state,
    };
    let text = serde_json::to_string(&pending).map_err(|_| create_error!(InternalError))?;

    // The first code counts as a send: another may follow in a minute
    if code.is_some() && !email_code::begin_issue(&key).await? {
        return Err(create_error!(InternalError));
    }

    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();

    let set: Option<String> = redis::cmd("SET")
        .arg(&key)
        .arg(text)
        .arg("NX")
        .arg("EX")
        .arg(SIGNUP_TTL_SECS)
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    if set.is_none() {
        return Err(create_error!(InternalError));
    }

    Ok((signup_id, code))
}

/// Read a pending sign-up without consuming it.
///
/// `InvalidCredentials` when the id is malformed, unknown, expired or used.
pub async fn load(signup_id: &str) -> Result<PendingSignup> {
    read_signup(signup_id)
        .await?
        .map(|(_, pending)| pending)
        .ok_or_else(refused)
}

/// A new code for a pending sign-up that is still waiting for one: the
/// address and the code to mail. The code sent before stops working.
///
/// `Ok(None)` when a code was sent in the last minute: send nothing.
/// `InvalidCredentials` when there is no such sign-up, it has no email, or
/// its email is already confirmed.
pub async fn reissue_code(signup_id: &str) -> Result<Option<(String, String)>> {
    let (was, mut pending) = read_signup(signup_id).await?.ok_or_else(refused)?;

    let email = match (&pending.email, pending.email_confirmed) {
        (Some(email), false) => email.clone(),
        _ => return Err(refused()),
    };

    if !email_code::begin_issue(&signup_key(signup_id)).await? {
        return Ok(None);
    }

    let (state, code) = email_code::new_state(&email);
    pending.code = Some(state);

    if !swap_signup(signup_id, &was, &pending).await? {
        return Err(refused());
    }

    Ok(Some((email, code)))
}

/// Check the mailed code and mark the sign-up's email confirmed; the sign-up
/// as it now is.
///
/// `InvalidCredentials` for everything else: no such sign-up, no code
/// waiting, a wrong code, and the fifth wrong code, which deletes the whole
/// pending sign-up.
pub async fn mark_email_confirmed(signup_id: &str, code: &str) -> Result<PendingSignup> {
    let (was, mut pending) = read_signup(signup_id).await?.ok_or_else(refused)?;
    let key = signup_key(signup_id);

    let Some(state) = pending.code.take() else {
        return Err(refused());
    };

    match email_code::try_code(&key, &state, code).await? {
        Verdict::Wrong => Err(refused()),
        Verdict::Exhausted => {
            delete_signup(signup_id).await?;
            let _ = email_code::forget(&key).await;

            Err(refused())
        }
        Verdict::Correct => {
            // The confirmed address is the one the code went to
            pending.email = Some(state.email().to_string());
            pending.email_confirmed = true;

            // Lost when the blob changed since it was read (a new code was
            // sent, or the sign-up finished): nothing is confirmed
            if !swap_signup(signup_id, &was, &pending).await? {
                return Err(refused());
            }

            let _ = email_code::forget(&key).await;

            Ok(pending)
        }
    }
}

/// Consume a pending sign-up (`GETDEL`): whatever happens next, this id is
/// spent.
///
/// `InvalidCredentials` when the id is malformed, unknown, expired or used.
pub async fn take(signup_id: &str) -> Result<PendingSignup> {
    if !is_hex_id(signup_id) {
        return Err(refused());
    }

    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();

    let text: Option<String> = redis::cmd("GETDEL")
        .arg(signup_key(signup_id))
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    let pending = text
        .and_then(|text| serde_json::from_str::<PendingSignup>(&text).ok())
        .ok_or_else(refused)?;

    // A counter left behind expires on its own
    let _ = email_code::forget(&signup_key(signup_id)).await;

    Ok(pending)
}

// ---------------------------------------------------------------------------
// No-email counter
// ---------------------------------------------------------------------------

/// The one answer for "this sign-up needs an email": no-email sign-up is
/// off, a cap is 0 or reached, or the counter cannot be read.
pub fn email_required() -> revolt_result::Error {
    create_error!(InvalidOperation)
}

/// The counter keys for the clock hour and the day `now` falls in (UTC)
fn counter_keys(now: DateTime<Utc>) -> (String, String) {
    (
        format!("passkey:signup-noemail:hour:{}", now.format("%Y%m%d%H")),
        format!("passkey:signup-noemail:day:{}", now.format("%Y%m%d")),
    )
}

/// The script's answer, or None when Redis could not give one
async fn run_reserve(hour_key: &str, day_key: &str, per_hour: u32, per_day: u32) -> Option<i64> {
    let mut conn = get_connection().await.ok()?.into_inner();

    let reserved = RESERVE
        .key(hour_key)
        .key(day_key)
        .arg(per_hour)
        .arg(per_day)
        .arg(HOUR_KEY_TTL_SECS)
        .arg(DAY_KEY_TTL_SECS)
        .invoke_async::<_, i64>(&mut conn)
        .await;

    reserved.ok()
}

async fn reserve_in(hour_key: &str, day_key: &str, per_hour: u32, per_day: u32) -> Result<()> {
    if per_hour == 0 || per_day == 0 {
        return Err(email_required());
    }

    match run_reserve(hour_key, day_key, per_hour, per_day).await {
        Some(1) => Ok(()),
        Some(0) => {
            log::warn!(
                "passkeys: sign-up without an email refused: the hourly or daily cap is reached"
            );
            Err(email_required())
        }
        _ => {
            log::error!(
                "passkeys: sign-up without an email refused: the counter could not be read"
            );
            Err(email_required())
        }
    }
}

/// Take one no-email sign-up out of this hour's and this day's allowance
/// (`signup_without_email_per_hour`, `signup_without_email_per_day`). Call
/// at finish, before anything is written.
///
/// `InvalidOperation` (`email_required`) when either cap is 0 or reached and
/// on any Redis failure. A reservation is not given back if the sign-up
/// fails afterwards.
pub async fn reserve_no_email_signup() -> Result<()> {
    let config = config().await;
    let features = &config.features.passkeys;
    let (hour_key, day_key) = counter_keys(Utc::now());

    reserve_in(
        &hour_key,
        &day_key,
        features.signup_without_email_per_hour,
        features.signup_without_email_per_day,
    )
    .await
}

/// A counter as it stands: 0 when the key is absent, None when it does not
/// hold a whole number
fn counter_value(stored: Option<&String>) -> Option<u64> {
    match stored {
        None => Some(0),
        Some(text) => text.parse().ok(),
    }
}

/// Whether both counters are below their caps. Reads only: nothing is
/// raised and no key is created. False for a cap of 0, a counter at its cap
/// or not a number, and any Redis failure.
async fn room_in(hour_key: &str, day_key: &str, per_hour: u32, per_day: u32) -> bool {
    if per_hour == 0 || per_day == 0 {
        return false;
    }

    let counters: Option<Vec<Option<String>>> = match get_connection().await {
        Ok(conn) => {
            let mut conn = conn.into_inner();
            redis::cmd("MGET")
                .arg(hour_key)
                .arg(day_key)
                .query_async(&mut conn)
                .await
                .ok()
        }
        Err(_) => None,
    };

    let read = counters.filter(|values| values.len() == 2).and_then(|values| {
        Some((
            counter_value(values[0].as_ref())?,
            counter_value(values[1].as_ref())?,
        ))
    });

    match read {
        Some((hour, day)) => {
            let room = hour < u64::from(per_hour) && day < u64::from(per_day);
            if !room {
                // The same line the reservation writes: whichever of the two
                // refuses, the alert sees it
                log::warn!(
                    "passkeys: sign-up without an email refused: the hourly or daily cap is reached"
                );
            }

            room
        }
        None => {
            log::error!(
                "passkeys: sign-up without an email refused: the counter could not be read"
            );
            false
        }
    }
}

/// Whether a no-email sign-up would fit this hour's and this day's allowance
/// right now. A look only: nothing is taken, and `reserve_no_email_signup`
/// at finish still decides. Ask at start and at options, so a full cap
/// refuses before the device makes a passkey.
///
/// `Ok(false)` when either cap is 0 or reached and on any Redis failure: the
/// same cases `reserve_no_email_signup` refuses. Answer it with
/// `email_required`.
pub async fn no_email_room() -> Result<bool> {
    let config = config().await;
    let features = &config.features.passkeys;
    let (hour_key, day_key) = counter_keys(Utc::now());

    Ok(room_in(
        &hour_key,
        &day_key,
        features.signup_without_email_per_hour,
        features.signup_without_email_per_day,
    )
    .await)
}

// ---------------------------------------------------------------------------
// Recovery token
// ---------------------------------------------------------------------------

fn recover_key(token_hash: &str) -> String {
    format!("passkey:recover:{token_hash}")
}

fn recover_cooldown_key(account_id: &str) -> String {
    format!("passkey:recover-cooldown:{account_id}")
}

/// Holds the hash of the account's live token, so the next one replaces it
fn recover_latest_key(account_id: &str) -> String {
    format!("passkey:recover-latest:{account_id}")
}

fn invalid_token() -> revolt_result::Error {
    create_error!(InvalidToken)
}

fn hash_token_bytes(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// SHA-256 hex of a recovery token, the value the recovery ceremony is bound
/// to (`start_recover_registration`). `InvalidToken` when `token` is not 32
/// bytes of unpadded base64url. Says nothing about whether the token is live.
pub fn recover_token_hash(token: &str) -> Result<String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| invalid_token())?;

    if bytes.len() != RECOVER_TOKEN_BYTES {
        return Err(invalid_token());
    }

    Ok(hash_token_bytes(&bytes))
}

/// A recovery token for `account_id`, to mail as part of the link. Lives 30
/// minutes; the account's earlier token, if any, stops working.
///
/// `Ok(None)` when the account got one in the last 10 minutes: send nothing.
pub async fn issue_recover_token(account_id: &str) -> Result<Option<String>> {
    if account_id.is_empty() {
        return Err(create_error!(InternalError));
    }

    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();

    let claimed: Option<String> = redis::cmd("SET")
        .arg(recover_cooldown_key(account_id))
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(RECOVER_COOLDOWN_SECS)
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    if claimed.is_none() {
        return Ok(None);
    }

    // Withdraw the token issued before, if it is still around
    let latest_key = recover_latest_key(account_id);
    let earlier: Option<String> = redis::cmd("GETDEL")
        .arg(&latest_key)
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    if let Some(earlier) = earlier.filter(|hash| is_hex_id(hash)) {
        let _: i64 = redis::cmd("DEL")
            .arg(recover_key(&earlier))
            .query_async(&mut conn)
            .await
            .map_err(|_| create_error!(InternalError))?;
    }

    let mut bytes = [0u8; RECOVER_TOKEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let token_hash = hash_token_bytes(&bytes);

    let set: Option<String> = redis::cmd("SET")
        .arg(recover_key(&token_hash))
        .arg(account_id)
        .arg("NX")
        .arg("EX")
        .arg(RECOVER_TOKEN_TTL_SECS)
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    if set.is_none() {
        return Err(create_error!(InternalError));
    }

    let noted: Option<String> = redis::cmd("SET")
        .arg(&latest_key)
        .arg(&token_hash)
        .arg("EX")
        .arg(RECOVER_TOKEN_TTL_SECS)
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    if noted.is_none() {
        return Err(create_error!(InternalError));
    }

    Ok(Some(URL_SAFE_NO_PAD.encode(bytes)))
}

/// The account a live recovery token belongs to, without consuming it.
///
/// `InvalidToken` when the token is malformed, unknown, expired or used.
pub async fn peek_recover_token(token: &str) -> Result<String> {
    let token_hash = recover_token_hash(token)?;

    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();

    let account_id: Option<String> = redis::cmd("GET")
        .arg(recover_key(&token_hash))
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    account_id
        .filter(|account_id| !account_id.is_empty())
        .ok_or_else(invalid_token)
}

/// Consume a recovery token (`GETDEL`) and return its account: of any
/// number of requests with one token, one gets it.
///
/// `InvalidToken` when the token is malformed, unknown, expired or used.
pub async fn claim_recover_token(token: &str) -> Result<String> {
    let token_hash = recover_token_hash(token)?;

    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();

    let account_id: Option<String> = redis::cmd("GETDEL")
        .arg(recover_key(&token_hash))
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    let account_id = account_id
        .filter(|account_id| !account_id.is_empty())
        .ok_or_else(invalid_token)?;

    // The token is spent whatever happens to its pointer, which expires on
    // its own
    let latest_key = recover_latest_key(&account_id);
    let latest: std::result::Result<Option<String>, _> = redis::cmd("GET")
        .arg(&latest_key)
        .query_async(&mut conn)
        .await;
    if matches!(latest, Ok(Some(hash)) if hash == token_hash) {
        let _: std::result::Result<i64, _> = redis::cmd("DEL")
            .arg(&latest_key)
            .query_async(&mut conn)
            .await;
    }

    Ok(account_id)
}

/// Withdraw the live recovery token of `account_id`, if it has one: the
/// link already mailed stops working. Call when the account's email moves,
/// so a link sent to the old mailbox dies with it.
///
/// The cooldown is left to run out. Ok when there was no token; an error
/// means the token may still be live.
pub async fn revoke_recover_tokens(account_id: &str) -> Result<()> {
    if account_id.is_empty() {
        return Err(create_error!(InternalError));
    }

    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?
        .into_inner();

    // An account has one live token at a time, and this names it
    let latest_key = recover_latest_key(account_id);
    let latest: Option<String> = redis::cmd("GET")
        .arg(&latest_key)
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    let Some(token_hash) = latest else {
        return Ok(());
    };

    // The token first: if this fails the pointer is still there for a retry
    if is_hex_id(&token_hash) {
        let _: i64 = redis::cmd("DEL")
            .arg(recover_key(&token_hash))
            .query_async(&mut conn)
            .await
            .map_err(|_| create_error!(InternalError))?;
    }

    let _: i64 = redis::cmd("DEL")
        .arg(&latest_key)
        .query_async(&mut conn)
        .await
        .map_err(|_| create_error!(InternalError))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    //! These need Redis. Every test works under ids and keys of its own.
    //! The cap-0 test sets config with `overwrite_config`, which works once
    //! per process: run these under nextest (one process per test).
    //!
    //! Each test says, under "Fails if", the one change to the code above that
    //! turns it red.

    use redis_kiss::{get_connection, redis};
    use revolt_result::Result;
    use ulid::Ulid;

    use super::*;
    use crate::util::test::{rt, TestHarness};

    const EMAIL: &str = "someone@example.test";

    /// What every refusal about a pending sign-up looks like
    const REFUSED: &str = "InvalidCredentials";

    fn outcome<T>(result: Result<T>) -> String {
        match result {
            Ok(_) => "Ok".to_string(),
            Err(error) => format!("{:?}", error.error_type),
        }
    }

    fn fields(email: Option<&str>) -> SignupFields {
        SignupFields {
            username: "newcomer".to_string(),
            email: email.map(str::to_string),
            invite: Some("invite-1".to_string()),
            referral_code: Some("REF123".to_string()),
            invite_code: None,
        }
    }

    /// A well-formed code that is not `code`
    fn another_code(code: &str) -> String {
        let number: u32 = code.parse().expect("digits");
        format!("{:08}", (number + 1) % 100_000_000)
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

    async fn expire(key: &str, seconds: i64) {
        let mut conn = get_connection().await.expect("redis").into_inner();
        let _: i64 = redis::cmd("EXPIRE")
            .arg(key)
            .arg(seconds)
            .query_async(&mut conn)
            .await
            .expect("EXPIRE");
    }

    // -----------------------------------------------------------------------
    // Pending sign-up
    // -----------------------------------------------------------------------

    /// Fails if: `create` drops the expiry or stores the code, `load`
    /// consumes, `mark_email_confirmed` confirms on a wrong code, resets the
    /// expiry or leaves the code state behind, or `take` reads with GET.
    #[test]
    fn a_signup_with_an_email_is_confirmed_by_its_code_and_taken_once() {
        rt().block_on(async {
            let _harness = TestHarness::new().await;

            let (signup_id, code) = create(fields(Some(EMAIL))).await.expect("create");
            let code = code.expect("a code for the email");
            assert!(is_hex_id(&signup_id));
            let key = signup_key(&signup_id);
            assert_eq!(key, format!("passkey:signup:{signup_id}"));

            let left = ttl(&key).await;
            assert!((1..=900).contains(&left), "ttl {left}");
            let stored = get(&key).await.expect("blob");
            assert!(!stored.contains(&code), "the blob holds the code");

            // Loading does not consume
            for _ in 0..2 {
                let pending = load(&signup_id).await.expect("load");
                assert_eq!(pending.username, "newcomer");
                assert_eq!(pending.email.as_deref(), Some(EMAIL));
                assert_eq!(pending.invite.as_deref(), Some("invite-1"));
                assert_eq!(pending.referral_code.as_deref(), Some("REF123"));
                assert_eq!(pending.invite_code, None);
                assert!(Uuid::parse_str(&pending.user_handle).is_ok());
                assert!(!pending.email_confirmed);
                assert!(!pending.ready_for_passkey(), "ready before the code");
                assert_eq!(pending.confirmed_email(), None);
            }

            // A wrong code confirms nothing
            assert_eq!(
                outcome(mark_email_confirmed(&signup_id, &another_code(&code)).await),
                REFUSED
            );
            assert!(!load(&signup_id).await.expect("load").email_confirmed);

            // The right one does, and the blob keeps its expiry
            expire(&key, 300).await;
            let confirmed = mark_email_confirmed(&signup_id, &code)
                .await
                .expect("confirm");
            assert!(confirmed.email_confirmed);
            assert!(confirmed.ready_for_passkey());
            assert_eq!(confirmed.confirmed_email(), Some(EMAIL));
            let left = ttl(&key).await;
            assert!((1..=300).contains(&left), "ttl after confirm {left}");
            let stored = get(&key).await.expect("blob");
            assert!(!stored.contains("\"code\""), "the code state stayed");

            let loaded = load(&signup_id).await.expect("load");
            assert!(loaded.email_confirmed);
            assert_eq!(loaded.user_handle, confirmed.user_handle);

            // The code is spent
            assert_eq!(
                outcome(mark_email_confirmed(&signup_id, &code).await),
                REFUSED,
                "the code a second time"
            );
            assert!(load(&signup_id).await.expect("load").email_confirmed);

            // Taken once
            let taken = take(&signup_id).await.expect("take");
            assert!(taken.email_confirmed);
            assert_eq!(taken.confirmed_email(), Some(EMAIL));
            assert_eq!(get(&key).await, None);
            assert_eq!(outcome(take(&signup_id).await), REFUSED, "taken twice");
            assert_eq!(outcome(load(&signup_id).await), REFUSED, "loaded after take");

            // Two sign-ups never share an id or a handle
            let (other_id, _) = create(fields(Some(EMAIL))).await.expect("create");
            assert_ne!(other_id, signup_id);
            assert_ne!(
                load(&other_id).await.expect("load").user_handle,
                taken.user_handle
            );
        })
    }

    /// Fails if: a sign-up with no email gets a code, is not ready for its
    /// passkey, or can be marked confirmed by any code at all.
    #[test]
    fn a_signup_without_an_email_has_no_code_and_cannot_be_confirmed() {
        rt().block_on(async {
            let _harness = TestHarness::new().await;

            let (signup_id, code) = create(fields(None)).await.expect("create");
            assert_eq!(code, None);

            let pending = load(&signup_id).await.expect("load");
            assert_eq!(pending.email, None);
            assert!(!pending.email_confirmed);
            assert!(pending.ready_for_passkey());
            assert_eq!(pending.confirmed_email(), None);

            for guess in ["00000000", "12345678", ""] {
                assert_eq!(
                    outcome(mark_email_confirmed(&signup_id, guess).await),
                    REFUSED
                );
            }
            assert_eq!(outcome(reissue_code(&signup_id).await), REFUSED);

            let taken = take(&signup_id).await.expect("still there");
            assert!(!taken.email_confirmed);
            assert_eq!(taken.email, None);

            // Malformed and unknown ids
            for id in [
                String::new(),
                "x".to_string(),
                "F".repeat(64),
                "f".repeat(64),
            ] {
                assert_eq!(outcome(load(&id).await), REFUSED, "load {id:?}");
                assert_eq!(outcome(take(&id).await), REFUSED, "take {id:?}");
                assert_eq!(
                    outcome(mark_email_confirmed(&id, "00000000").await),
                    REFUSED,
                    "confirm {id:?}"
                );
            }
        })
    }

    /// Fails if: the tries of a sign-up's code are not counted, or the fifth
    /// wrong one leaves the pending sign-up in place.
    #[test]
    fn five_wrong_codes_delete_the_pending_signup() {
        rt().block_on(async {
            let _harness = TestHarness::new().await;

            let (signup_id, code) = create(fields(Some(EMAIL))).await.expect("create");
            let code = code.expect("a code");
            let wrong = another_code(&code);

            for attempt in 1..=email_code::MAX_TRIES {
                assert_eq!(
                    outcome(mark_email_confirmed(&signup_id, &wrong).await),
                    REFUSED,
                    "attempt {attempt}"
                );
            }

            assert_eq!(get(&signup_key(&signup_id)).await, None);
            assert_eq!(
                outcome(mark_email_confirmed(&signup_id, &code).await),
                REFUSED,
                "the right code after five wrong ones"
            );
            assert_eq!(outcome(load(&signup_id).await), REFUSED);

            // Four wrong ones leave it usable
            let (signup_id, code) = create(fields(Some(EMAIL))).await.expect("create");
            let code = code.expect("a code");
            let wrong = another_code(&code);
            for _ in 1..email_code::MAX_TRIES {
                assert_eq!(
                    outcome(mark_email_confirmed(&signup_id, &wrong).await),
                    REFUSED
                );
            }
            assert!(
                mark_email_confirmed(&signup_id, &code)
                    .await
                    .expect("the fifth try")
                    .email_confirmed
            );
        })
    }

    /// Fails if: `create` does not start the resend cooldown, `reissue_code`
    /// ignores it, a new code leaves the old one working, or a reissue
    /// resets the sign-up's expiry.
    #[test]
    fn a_new_signup_code_waits_for_the_cooldown_and_replaces_the_old_one() {
        rt().block_on(async {
            let _harness = TestHarness::new().await;

            let (signup_id, first) = create(fields(Some(EMAIL))).await.expect("create");
            let first = first.expect("a code");
            let key = signup_key(&signup_id);

            assert_eq!(
                reissue_code(&signup_id).await.expect("reissue"),
                None,
                "a second code within the minute"
            );
            let cooldown = format!("{key}:resend");
            let left = ttl(&cooldown).await;
            assert!((1..=60).contains(&left), "cooldown ttl {left}");

            // After the cooldown
            del(&cooldown).await;
            expire(&key, 300).await;
            let (email, second) = reissue_code(&signup_id)
                .await
                .expect("reissue")
                .expect("a code after the cooldown");
            assert_eq!(email, EMAIL);
            let left = ttl(&key).await;
            assert!((1..=300).contains(&left), "ttl after reissue {left}");
            assert!(!get(&key).await.expect("blob").contains(&second));

            if second != first {
                assert_eq!(
                    outcome(mark_email_confirmed(&signup_id, &first).await),
                    REFUSED,
                    "the old code"
                );
            }
            assert!(
                mark_email_confirmed(&signup_id, &second)
                    .await
                    .expect("the new code")
                    .email_confirmed
            );

            // Confirmed: no more codes
            del(&cooldown).await;
            assert_eq!(outcome(reissue_code(&signup_id).await), REFUSED);
        })
    }

    /// Fails if: `Debug` for `PendingSignup` prints a field value.
    #[test]
    fn a_pending_signup_prints_no_field_value() {
        let (state, code) = email_code::new_state(EMAIL);
        let pending = PendingSignup {
            username: "newcomer".to_string(),
            email: Some(EMAIL.to_string()),
            invite: Some("invite-1".to_string()),
            referral_code: Some("REF123".to_string()),
            invite_code: Some("CODE9".to_string()),
            user_handle: "6f1e0c0a-0000-4000-8000-000000000001".to_string(),
            email_confirmed: false,
            code: Some(state),
        };

        let printed = format!("{pending:?}");
        for secret in [
            "newcomer",
            EMAIL,
            "invite-1",
            "REF123",
            "CODE9",
            "6f1e0c0a",
            code.as_str(),
        ] {
            assert!(!printed.contains(secret), "{printed}");
        }
        assert!(printed.contains("has_email: true"), "{printed}");
    }

    // -----------------------------------------------------------------------
    // No-email counter
    // -----------------------------------------------------------------------

    /// Fails if: `assert_signup_on` stops reading `signup`, or refuses with
    /// anything but `FeatureDisabled` naming "passkey_signup". Having
    /// passkeys themselves available does not switch sign-up on.
    #[test]
    fn signup_is_refused_while_its_switch_is_off() {
        rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.passkeys.available = true;
                settings.features.passkeys.signup = false;
                settings.features.passkeys.signup_without_email = true;
            })
            .await;

            let refusal = outcome(assert_signup_on().await);
            assert!(refusal.starts_with("FeatureDisabled"), "{refusal}");
            assert!(refusal.contains("\"passkey_signup\""), "{refusal}");
        })
    }

    /// Fails if: `assert_signup_on` refuses with `signup` on, or needs any
    /// other switch.
    #[test]
    fn signup_is_allowed_once_its_switch_is_on() {
        rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.passkeys.signup = true;
                settings.features.passkeys.signup_without_email = false;
            })
            .await;

            assert_eq!(outcome(assert_signup_on().await), "Ok");
        })
    }

    fn test_counter_keys() -> (String, String) {
        let run = Ulid::new();
        (
            format!("passkey:signup-noemail-test:{run}:hour"),
            format!("passkey:signup-noemail-test:{run}:day"),
        )
    }

    /// Fails if: `reserve_no_email_signup` stops reading the caps from
    /// config, or a cap of 0 stops meaning "none allowed".
    #[test]
    fn a_cap_of_zero_refuses_every_no_email_signup() {
        rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.passkeys.signup_without_email = true;
                settings.features.passkeys.signup_without_email_per_hour = 0;
                settings.features.passkeys.signup_without_email_per_day = 0;
            })
            .await;
            let _harness = TestHarness::new().await;

            assert_eq!(
                outcome(reserve_no_email_signup().await),
                "InvalidOperation"
            );
            assert_eq!(
                format!("{:?}", email_required().error_type),
                "InvalidOperation"
            );
            // The look reads the same caps
            assert!(!no_email_room().await.expect("look"), "room under a cap of 0");

            // Either cap alone at 0 refuses, and nothing is counted
            let (hour, day) = test_counter_keys();
            for (per_hour, per_day) in [(0, 0), (0, 5), (5, 0)] {
                assert_eq!(
                    outcome(reserve_in(&hour, &day, per_hour, per_day).await),
                    "InvalidOperation",
                    "caps {per_hour}/{per_day}"
                );
                assert!(
                    !room_in(&hour, &day, per_hour, per_day).await,
                    "room under caps {per_hour}/{per_day}"
                );
            }
            assert_eq!(get(&hour).await, None);
            assert_eq!(get(&day).await, None);
        })
    }

    /// Fails if: the script compares with `>` (one too many), counts only
    /// one of the two keys, lets a full hour eat into the day, or a key is
    /// created without an expiry / has it renewed by a later sign-up.
    #[test]
    fn a_cap_allows_exactly_that_many_and_the_keys_expire() {
        rt().block_on(async {
            let _harness = TestHarness::new().await;

            // The hour fills first
            let (hour, day) = test_counter_keys();
            reserve_in(&hour, &day, 3, 10).await.expect("the first");

            let left = ttl(&hour).await;
            assert!((1..=7200).contains(&left), "hour ttl {left}");
            let left = ttl(&day).await;
            assert!((1..=172_800).contains(&left), "day ttl {left}");

            // A later sign-up does not push the expiry out
            expire(&hour, 100).await;
            expire(&day, 100).await;
            reserve_in(&hour, &day, 3, 10).await.expect("the second");
            reserve_in(&hour, &day, 3, 10).await.expect("the third");
            assert!((1..=100).contains(&ttl(&hour).await), "hour ttl was renewed");
            assert!((1..=100).contains(&ttl(&day).await), "day ttl was renewed");

            for _ in 0..3 {
                assert_eq!(
                    outcome(reserve_in(&hour, &day, 3, 10).await),
                    "InvalidOperation",
                    "the fourth in the hour"
                );
            }
            assert_eq!(get(&hour).await.as_deref(), Some("3"));
            assert_eq!(get(&day).await.as_deref(), Some("3"), "refusals were counted");

            // A new hour, the same day: the day cap is what stops it
            let (next_hour, _) = test_counter_keys();
            for _ in 0..2 {
                reserve_in(&next_hour, &day, 3, 5).await.expect("day 4 and 5");
            }
            assert_eq!(
                outcome(reserve_in(&next_hour, &day, 3, 5).await),
                "InvalidOperation",
                "the sixth in the day"
            );
            assert_eq!(get(&next_hour).await.as_deref(), Some("2"));
            assert_eq!(get(&day).await.as_deref(), Some("5"));

            // A counter that is not a number refuses
            let (hour, day) = test_counter_keys();
            let mut conn = get_connection().await.expect("redis").into_inner();
            let _: () = redis::cmd("SET")
                .arg(&hour)
                .arg("many")
                .arg("EX")
                .arg(60)
                .query_async(&mut conn)
                .await
                .expect("SET");
            assert_eq!(
                outcome(reserve_in(&hour, &day, 3, 5).await),
                "InvalidOperation"
            );
            assert_eq!(get(&day).await, None);

            // A key found without an expiry gets one
            let (hour, day) = test_counter_keys();
            let _: () = redis::cmd("SET")
                .arg(&hour)
                .arg("1")
                .query_async(&mut conn)
                .await
                .expect("SET");
            reserve_in(&hour, &day, 3, 5).await.expect("reserve");
            assert!((1..=7200).contains(&ttl(&hour).await), "no expiry");

            for key in [hour, day, next_hour] {
                del(&key).await;
            }
        })
    }

    /// Fails if: the look raises a counter or creates a key, reports room at
    /// a cap (`<=` for `<`), looks at only one of the two counters, or
    /// trusts a counter that is not a number.
    #[test]
    fn a_look_at_the_no_email_counter_takes_nothing() {
        rt().block_on(async {
            let _harness = TestHarness::new().await;

            // Nothing counted yet: room, and still no keys after looking
            let (hour, day) = test_counter_keys();
            for _ in 0..5 {
                assert!(room_in(&hour, &day, 2, 3).await, "an empty counter");
            }
            assert_eq!(get(&hour).await, None, "the look created the hour key");
            assert_eq!(get(&day).await, None, "the look created the day key");

            // One below the hourly cap: room. At it: none, as often as asked
            reserve_in(&hour, &day, 2, 3).await.expect("the first");
            assert!(room_in(&hour, &day, 2, 3).await, "one of two used");
            reserve_in(&hour, &day, 2, 3).await.expect("the second");
            for _ in 0..5 {
                assert!(!room_in(&hour, &day, 2, 3).await, "the hour is full");
            }
            assert_eq!(get(&hour).await.as_deref(), Some("2"), "the look counted");
            assert_eq!(get(&day).await.as_deref(), Some("2"), "the look counted");

            // The look and the reservation agree
            assert_eq!(
                outcome(reserve_in(&hour, &day, 2, 3).await),
                "InvalidOperation"
            );

            // A new hour, the same day: one more fits, then the day is full
            let (next_hour, _) = test_counter_keys();
            assert!(room_in(&next_hour, &day, 2, 3).await, "day 3 of 3");
            reserve_in(&next_hour, &day, 2, 3).await.expect("the third");
            assert!(!room_in(&next_hour, &day, 2, 3).await, "the day is full");
            assert_eq!(get(&next_hour).await.as_deref(), Some("1"));
            assert_eq!(get(&day).await.as_deref(), Some("3"));

            // A counter that is not a number: no room, and it is left alone
            let (odd_hour, odd_day) = test_counter_keys();
            let mut conn = get_connection().await.expect("redis").into_inner();
            for unreadable in ["many", "-1", ""] {
                let _: () = redis::cmd("SET")
                    .arg(&odd_day)
                    .arg(unreadable)
                    .arg("EX")
                    .arg(60)
                    .query_async(&mut conn)
                    .await
                    .expect("SET");
                assert!(
                    !room_in(&odd_hour, &odd_day, 2, 3).await,
                    "value {unreadable:?}"
                );
                assert_eq!(get(&odd_day).await.as_deref(), Some(unreadable));
            }
            assert_eq!(get(&odd_hour).await, None);

            for key in [hour, day, next_hour, odd_day] {
                del(&key).await;
            }
        })
    }

    /// Fails if: the live key names stop carrying the clock hour and day.
    #[test]
    fn the_counter_keys_carry_the_clock_hour_and_day() {
        let at = |text: &str| {
            DateTime::parse_from_rfc3339(text)
                .expect("time")
                .with_timezone(&Utc)
        };

        assert_eq!(
            counter_keys(at("2026-11-23T09:59:59Z")),
            (
                "passkey:signup-noemail:hour:2026112309".to_string(),
                "passkey:signup-noemail:day:20261123".to_string()
            )
        );
        // The next hour, and the next day in UTC whatever the offset
        assert_eq!(
            counter_keys(at("2026-11-23T10:00:00Z")).0,
            "passkey:signup-noemail:hour:2026112310"
        );
        assert_eq!(
            counter_keys(at("2026-11-23T20:30:00-05:00")),
            (
                "passkey:signup-noemail:hour:2026112401".to_string(),
                "passkey:signup-noemail:day:20261124".to_string()
            )
        );
    }

    // -----------------------------------------------------------------------
    // Recovery token
    // -----------------------------------------------------------------------

    /// Fails if: the token is stored as itself, the key has no expiry,
    /// `peek_recover_token` consumes, or `claim_recover_token` reads with
    /// GET (a token used twice).
    #[test]
    fn a_recovery_token_is_stored_hashed_and_claimed_once() {
        rt().block_on(async {
            let _harness = TestHarness::new().await;
            let account_id = Ulid::new().to_string();

            let token = issue_recover_token(&account_id)
                .await
                .expect("issue")
                .expect("a token");
            assert_eq!(token.len(), 43, "32 bytes of unpadded base64url");

            // Stored under its hash, holding the account id, for 30 minutes
            let token_hash = recover_token_hash(&token).expect("hash");
            assert!(is_hex_id(&token_hash));
            assert_ne!(token_hash, token);
            let key = recover_key(&token_hash);
            assert_eq!(key, format!("passkey:recover:{token_hash}"));
            assert_eq!(get(&key).await.as_deref(), Some(account_id.as_str()));
            assert_eq!(get(&format!("passkey:recover:{token}")).await, None);
            let left = ttl(&key).await;
            assert!((1..=1800).contains(&left), "ttl {left}");

            // Peeking does not consume
            for _ in 0..2 {
                assert_eq!(peek_recover_token(&token).await.expect("peek"), account_id);
            }

            assert_eq!(
                claim_recover_token(&token).await.expect("claim"),
                account_id
            );
            assert_eq!(get(&key).await, None);
            assert_eq!(
                outcome(claim_recover_token(&token).await),
                "InvalidToken",
                "claimed twice"
            );
            assert_eq!(
                outcome(peek_recover_token(&token).await),
                "InvalidToken",
                "peeked after the claim"
            );
        })
    }

    /// Fails if: `issue_recover_token` drops the per-account cooldown or its
    /// expiry, shares it between accounts, or leaves the earlier token of
    /// the account alive beside a new one.
    #[test]
    fn a_second_recovery_token_waits_for_the_cooldown_and_replaces_the_first() {
        rt().block_on(async {
            let _harness = TestHarness::new().await;
            let account_id = Ulid::new().to_string();
            let other_id = Ulid::new().to_string();

            let first = issue_recover_token(&account_id)
                .await
                .expect("issue")
                .expect("a token");
            assert_eq!(
                issue_recover_token(&account_id).await.expect("issue"),
                None,
                "a second token within ten minutes"
            );
            let cooldown = recover_cooldown_key(&account_id);
            assert_eq!(cooldown, format!("passkey:recover-cooldown:{account_id}"));
            let left = ttl(&cooldown).await;
            assert!((1..=600).contains(&left), "cooldown ttl {left}");

            // The refused issue left the first token alone
            assert_eq!(peek_recover_token(&first).await.expect("peek"), account_id);

            // Another account is not held back
            let theirs = issue_recover_token(&other_id)
                .await
                .expect("issue")
                .expect("a token for another account");
            assert_eq!(peek_recover_token(&theirs).await.expect("peek"), other_id);

            // After the cooldown: a new token, and the first one is dead
            del(&cooldown).await;
            let second = issue_recover_token(&account_id)
                .await
                .expect("issue")
                .expect("a token after the cooldown");
            assert_ne!(second, first);
            assert_eq!(
                outcome(peek_recover_token(&first).await),
                "InvalidToken",
                "the earlier token"
            );
            assert_eq!(
                claim_recover_token(&second).await.expect("claim"),
                account_id
            );
            assert_eq!(get(&recover_latest_key(&account_id)).await, None);
            assert_eq!(peek_recover_token(&theirs).await.expect("peek"), other_id);

            for key in [
                cooldown,
                recover_cooldown_key(&other_id),
                recover_latest_key(&other_id),
                recover_key(&recover_token_hash(&theirs).expect("hash")),
            ] {
                del(&key).await;
            }
        })
    }

    /// Fails if: `revoke_recover_tokens` leaves the mailed token usable or
    /// its pointer behind, drops the cooldown (another mail straight away),
    /// touches another account's token, or errors when there is nothing to
    /// withdraw.
    #[test]
    fn a_revoked_recovery_token_stops_working() {
        rt().block_on(async {
            let _harness = TestHarness::new().await;
            let account_id = Ulid::new().to_string();
            let other_id = Ulid::new().to_string();

            // Nothing issued yet: nothing to do
            revoke_recover_tokens(&account_id).await.expect("no token");

            let token = issue_recover_token(&account_id)
                .await
                .expect("issue")
                .expect("a token");
            let theirs = issue_recover_token(&other_id)
                .await
                .expect("issue")
                .expect("a token for another account");
            let key = recover_key(&recover_token_hash(&token).expect("hash"));
            let latest = recover_latest_key(&account_id);
            assert_eq!(latest, format!("passkey:recover-latest:{account_id}"));
            assert_eq!(get(&key).await.as_deref(), Some(account_id.as_str()));
            assert!(get(&latest).await.is_some());

            revoke_recover_tokens(&account_id).await.expect("revoke");

            assert_eq!(get(&key).await, None, "the token key survived");
            assert_eq!(get(&latest).await, None, "the pointer survived");
            assert_eq!(outcome(peek_recover_token(&token).await), "InvalidToken");
            assert_eq!(outcome(claim_recover_token(&token).await), "InvalidToken");

            // The cooldown still holds: no new mail straight away
            let cooldown = recover_cooldown_key(&account_id);
            assert!((1..=600).contains(&ttl(&cooldown).await), "the cooldown went");
            assert_eq!(
                issue_recover_token(&account_id).await.expect("issue"),
                None
            );

            // Another account keeps its token
            assert_eq!(peek_recover_token(&theirs).await.expect("peek"), other_id);

            // A second revoke, and one after a claim, find nothing and say Ok
            revoke_recover_tokens(&account_id).await.expect("again");
            assert_eq!(
                claim_recover_token(&theirs).await.expect("claim"),
                other_id
            );
            revoke_recover_tokens(&other_id).await.expect("after a claim");

            // After the cooldown the account can get a working token again
            del(&cooldown).await;
            let second = issue_recover_token(&account_id)
                .await
                .expect("issue")
                .expect("a token after the cooldown");
            assert_eq!(peek_recover_token(&second).await.expect("peek"), account_id);
            revoke_recover_tokens(&account_id).await.expect("revoke");
            assert_eq!(outcome(peek_recover_token(&second).await), "InvalidToken");

            // No account, nothing to withdraw
            assert_eq!(outcome(revoke_recover_tokens("").await), "InternalError");

            for key in [cooldown, recover_cooldown_key(&other_id)] {
                del(&key).await;
            }
        })
    }

    /// Fails if: a token that was never issued, or something that is not 32
    /// bytes of unpadded base64url, is answered with anything but
    /// `InvalidToken`.
    #[test]
    fn an_unknown_or_malformed_recovery_token_is_refused() {
        rt().block_on(async {
            let _harness = TestHarness::new().await;

            // Well-formed, never issued
            let unknown = URL_SAFE_NO_PAD.encode([7u8; 32]);
            assert!(recover_token_hash(&unknown).is_ok());
            assert_eq!(outcome(peek_recover_token(&unknown).await), "InvalidToken");
            assert_eq!(outcome(claim_recover_token(&unknown).await), "InvalidToken");

            for malformed in [
                String::new(),
                "x".to_string(),
                URL_SAFE_NO_PAD.encode([7u8; 31]),
                URL_SAFE_NO_PAD.encode([7u8; 33]),
                format!("{unknown}="),
                format!("{}*", &unknown[..42]),
                "f".repeat(64),
            ] {
                assert_eq!(
                    outcome(recover_token_hash(&malformed)),
                    "InvalidToken",
                    "{malformed:?}"
                );
                assert_eq!(
                    outcome(peek_recover_token(&malformed).await),
                    "InvalidToken"
                );
                assert_eq!(
                    outcome(claim_recover_token(&malformed).await),
                    "InvalidToken"
                );
            }

            // No account, no token
            assert_eq!(outcome(issue_recover_token("").await), "InternalError");
        })
    }
}
