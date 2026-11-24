//! Copy-paste DM detection.
//!
//! Catches one account sending the same text to several strangers in direct
//! messages, the pattern of the "can I use your profile picture" scam: a
//! plaintext DM from a human, non-privileged account to a peer who is not a
//! friend is reduced to a fingerprint (see [`fingerprint`]), and once the
//! same fingerprint has reached `threshold` strangers within the window with
//! no reply from any of them, the account gets a [`DmGuard`] (pausing its DMs
//! to strangers when configured to) and staff get an automated report.
//!
//! Only server-readable messages are ever looked at. End-to-end encrypted DMs
//! never reach [`observe_dm_message`]; the routes that deliver them only ask
//! [`dm_send_allowed`]-style metadata questions.
//!
//! The window lives in Redis and holds fingerprints and ids, never text:
//!
//! - `antispam:dm:{author}:{fingerprint}`: ZSET of peer ids, scored by the
//!   time (ms) of the latest send to that peer
//! - `antispam:dmref:{author}:{fingerprint}`: HASH of peer id to
//!   `{channel_id}:{message_id}` of that latest send
//!
//! Both expire with the window. Every Redis failure fails OPEN (nothing is
//! flagged), like slowmode.
//!
//! Encrypted DMs have their own signal, [`observe_e2ee_fanout`]: it counts
//! the distinct strangers an account writes to with no reply, from recipient
//! ids and time alone (it never sees content). Off unless
//! `e2ee_fanout_enabled`; see that function for its keys.

use std::{collections::HashSet, ops::RangeInclusive};

use iso8601_timestamp::{Duration, Timestamp};
use once_cell::sync::Lazy;
use redis_kiss::{
    get_connection,
    redis::{cmd, Pipeline, RedisError},
};
use regex::Regex;
use revolt_config::AntispamFeatures;
use revolt_models::v0::Embed;
use revolt_result::{ErrorType, Result};
use sha2::{Digest, Sha256};
use ulid::Ulid;

use crate::{
    Channel, Database, DmGuard, Message, MessageFilter, MessageQuery, MessageTimePeriod,
    RelationshipStatus, Report, User,
};

/// Peers looked at (newest first) when a fingerprint reaches the threshold
const MAX_PEERS_CHECKED: usize = 10;

/// Message ids handed to the report (it snapshots the first few that exist)
const MAX_REPORT_MESSAGES: usize = 10;

/// Upper bound on the re-arm period, so the cutoff can never underflow
const MAX_REARM_DAYS: u64 = 3650;

/// Upper bound on the window, so the window arithmetic can never overflow
const MAX_WINDOW_HOURS: u64 = 24 * 365;

/// URLs, with or without a scheme. Removed entirely: a message that is only
/// a link (an invite, a video) must normalize to (nearly) nothing.
static URL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"https?://\S+|\S+\.\S+/\S*").expect("valid URL pattern"));

/// Characters that render as nothing (or nearly nothing) and would otherwise
/// split words or pad the text: Unicode format characters (Cf), zero-width
/// and bidi controls, fillers, variation selectors and combining marks.
/// Never matches whitespace, which must separate words instead.
fn is_invisible(character: char) -> bool {
    if character.is_whitespace() {
        return false;
    }

    matches!(
        character,
        '\u{00AD}'
            | '\u{0300}'..='\u{036F}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{08E2}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{1AB0}'..='\u{1AFF}'
            | '\u{1DC0}'..='\u{1DFF}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{20D0}'..='\u{20FF}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FE20}'..='\u{FE2F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// Map every whitespace character to an ASCII space, then delete invisible
/// characters.
///
/// The whitespace mapping comes first and must run before `decancer`, which
/// DELETES some whitespace (a tab, for one): `art\tproject` would otherwise
/// fold to `artproject` and dodge the fingerprint of `art project`.
fn strip_invisible(text: &str) -> String {
    text.chars()
        .filter_map(|character| {
            if character.is_whitespace() {
                Some(' ')
            } else if is_invisible(character) {
                None
            } else {
                Some(character)
            }
        })
        .collect()
}

/// Reduce a message to the form two copies of the same text share.
///
/// Turns all whitespace into spaces and deletes invisible characters, folds
/// case and confusables (`decancer`, falling back to lowercasing if it
/// errors), repeats the whitespace and invisible pass (so neither a forced
/// fallback nor a fold into an odd character lets them split words), removes
/// URLs, then turns everything that is not a letter or digit into single
/// spaces.
pub fn normalize(text: &str) -> String {
    let visible = strip_invisible(text);
    let cured = decancer::cure(&visible, decancer::Options::default())
        .map(|cured| cured.to_string())
        .unwrap_or_else(|_| visible.to_lowercase());
    let cured = strip_invisible(&cured);
    let without_urls = URL.replace_all(&cured, " ");

    without_urls
        .split(|character: char| !character.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Fingerprint of a message's text, or `None` when the text is exempt
/// (shorter than `min_chars` once normalized: links, invites, greetings).
///
/// The first 32 hex characters of the SHA-256 of [`normalize`]d text. The
/// text itself is never stored.
pub fn fingerprint(text: &str, min_chars: usize) -> Option<String> {
    let normalized = normalize(text);
    if normalized.chars().count() < min_chars {
        return None;
    }

    let digest = Sha256::digest(normalized.as_bytes());
    Some(digest.iter().take(16).map(|b| format!("{b:02x}")).collect())
}

/// The sender-controlled text of a message: its content, the title and
/// description of its text embeds (only ever built from the sender's own
/// `SendableEmbed`s; link previews are other variants and are skipped), and
/// the content of a forwarded message. Non-empty parts joined by newlines.
pub fn dm_text(message: &Message) -> String {
    let mut parts: Vec<&str> = Vec::new();

    if let Some(content) = &message.content {
        parts.push(content);
    }

    for embed in message.embeds.iter().flatten() {
        if let Embed::Text(text) = embed {
            parts.extend(text.title.as_deref());
            parts.extend(text.description.as_deref());
        }
    }

    if let Some(forwarded) = &message.forwarded {
        parts.extend(forwarded.content.as_deref());
    }

    parts
        .into_iter()
        .filter(|part| !part.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_friend(author: &User, peer_id: &str) -> bool {
    matches!(
        author.relationship_with(peer_id),
        RelationshipStatus::Friend
    )
}

/// Guards cleared before this may be replaced by a new one
fn rearm_cutoff(cfg: &AntispamFeatures) -> Timestamp {
    let days = cfg.dm_dupe_rearm_days.min(MAX_REARM_DAYS) as i64;
    Timestamp::now_utc()
        .checked_sub(Duration::days(days))
        .unwrap_or(Timestamp::UNIX_EPOCH)
}

/// Whether the detector may flag a user holding `guard` again: never while a
/// guard stands, and only once staff cleared it before `rearm_before`
fn can_rearm(guard: Option<&DmGuard>, rearm_before: Timestamp) -> bool {
    match guard {
        None => true,
        Some(guard) => guard
            .cleared_at
            .is_some_and(|cleared_at| cleared_at < rearm_before),
    }
}

/// Whether `peer_id` has ever sent a message in `channel_id`
async fn peer_has_written(db: &Database, channel_id: &str, peer_id: &str) -> Result<bool> {
    let messages = db
        .fetch_messages(MessageQuery {
            limit: Some(1),
            filter: MessageFilter {
                channel: Some(channel_id.to_string()),
                author: Some(peer_id.to_string()),
                ..Default::default()
            },
            time_period: MessageTimePeriod::Absolute {
                before: None,
                after: None,
                sort: None,
            },
        })
        .await?;

    Ok(!messages.is_empty())
}

fn now_ms() -> i64 {
    Timestamp::now_utc()
        .duration_since(Timestamp::UNIX_EPOCH)
        .whole_milliseconds() as i64
}

/// Why an observation stopped early. Logged (database failures also
/// captured), never returned.
enum ObserveFailure {
    Redis(RedisError),
    Database(revolt_result::Error),
}

impl From<RedisError> for ObserveFailure {
    fn from(err: RedisError) -> Self {
        ObserveFailure::Redis(err)
    }
}

impl From<revolt_result::Error> for ObserveFailure {
    fn from(err: revolt_result::Error) -> Self {
        ObserveFailure::Database(err)
    }
}

fn capture(context: String) {
    error!("{context}");
    revolt_config::capture_message(&context, revolt_config::Level::Error);
}

/// Record a plaintext DM from `author` to `peer_id` and flag the author once
/// the same text has reached enough strangers who never replied.
///
/// Call it after the message is stored, off the request path (spawned).
/// It never fails: every Redis failure fails open with a warning (like
/// slowmode, so a Redis outage does not flood Sentry), and database failures
/// are logged and captured. Skips bots, privileged accounts, friends, exempt
/// (short or link-only) texts, replies in a DM the peer has written in, and
/// authors whose guard cannot re-arm yet.
pub async fn observe_dm_message(
    db: &Database,
    cfg: &AntispamFeatures,
    author: &User,
    channel_id: &str,
    peer_id: &str,
    message: &Message,
) {
    if !cfg.dm_dupe_enabled
        || author.bot.is_some()
        || author.privileged
        || peer_id == author.id
        || is_friend(author, peer_id)
    {
        return;
    }

    // A flagged author is not re-checked on every send: the guard stands
    // until staff clear it, and a cleared one only re-arms after the period
    let rearm_before = rearm_cutoff(cfg);
    if !can_rearm(author.dm_guard.as_ref(), rearm_before) {
        return;
    }

    let Some(fingerprint) = fingerprint(&dm_text(message), cfg.min_chars()) else {
        return;
    };

    // A message in a DM the peer has already written in is part of a
    // conversation and never counts. Checked on every send, not only at the
    // threshold: otherwise strangers could each open a DM, draw the same
    // polite reply, delete their own messages, and get the victim flagged.
    // On a database error nothing is counted (fail open).
    match peer_has_written(db, channel_id, peer_id).await {
        Ok(false) => {}
        Ok(true) => return,
        Err(err) => {
            capture(format!(
                "Anti-spam DM observation for {} in {channel_id} skipped, reply check failed: {err:?}",
                author.id
            ));
            return;
        }
    }

    if let Err(failure) = observe_fingerprint(
        db,
        cfg,
        author,
        channel_id,
        peer_id,
        &message.id,
        &fingerprint,
        rearm_before,
    )
    .await
    {
        match failure {
            ObserveFailure::Redis(err) => warn!(
                "Anti-spam DM observation for {} in {channel_id} skipped, Redis failed: {err}",
                author.id
            ),
            ObserveFailure::Database(err) => capture(format!(
                "Anti-spam DM observation for {} in {channel_id} failed: {err:?}",
                author.id
            )),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn observe_fingerprint(
    db: &Database,
    cfg: &AntispamFeatures,
    author: &User,
    channel_id: &str,
    peer_id: &str,
    message_id: &str,
    fingerprint: &str,
    rearm_before: Timestamp,
) -> std::result::Result<(), ObserveFailure> {
    let Ok(mut conn) = get_connection().await else {
        warn!("Anti-spam DM observation skipped: no Redis connection");
        return Ok(());
    };

    let threshold = cfg.threshold();
    let window_hours = cfg.dm_dupe_window_hours.clamp(1, MAX_WINDOW_HOURS);
    let window_secs = window_hours * 3600;
    let window_ms = window_secs as i64 * 1000;
    let now = now_ms();

    let window_key = format!("antispam:dm:{}:{fingerprint}", author.id);
    let refs_key = format!("antispam:dmref:{}:{fingerprint}", author.id);

    // Record this send, drop sends older than the window, count what is left
    let mut pipeline = Pipeline::new();
    pipeline
        .atomic()
        .cmd("ZADD")
        .arg(&window_key)
        .arg(now)
        .arg(peer_id)
        .ignore()
        .cmd("HSET")
        .arg(&refs_key)
        .arg(peer_id)
        .arg(format!("{channel_id}:{message_id}"))
        .ignore()
        .cmd("ZREMRANGEBYSCORE")
        .arg(&window_key)
        .arg("-inf")
        .arg(format!("({}", now - window_ms))
        .ignore()
        .cmd("ZCARD")
        .arg(&window_key)
        .cmd("EXPIRE")
        .arg(&window_key)
        .arg(window_secs)
        .ignore()
        .cmd("EXPIRE")
        .arg(&refs_key)
        .arg(window_secs)
        .ignore();

    let (count,): (usize,) = pipeline.query_async(&mut *conn).await?;
    if count < threshold {
        return Ok(());
    }

    // Newest peers first; never fewer than the threshold, or a high
    // threshold could never be reached
    let peers_checked = threshold.max(MAX_PEERS_CHECKED);
    let peers: Vec<String> = cmd("ZREVRANGE")
        .arg(&window_key)
        .arg(0)
        .arg(peers_checked - 1)
        .query_async(&mut *conn)
        .await?;
    if peers.is_empty() {
        return Ok(());
    }

    let refs: Vec<Option<String>> = cmd("HMGET")
        .arg(&refs_key)
        .arg(&peers[..])
        .query_async(&mut *conn)
        .await?;

    // A peer who wrote back (or has become a friend since) is a
    // conversation, not a target: forget them
    let mut answered: Vec<String> = Vec::new();
    let mut unanswered: Vec<String> = Vec::new();
    for (peer, reference) in peers.into_iter().zip(refs) {
        let Some((dm_channel, dm_message)) = reference
            .as_deref()
            .and_then(|reference| reference.split_once(':'))
        else {
            continue;
        };

        if is_friend(author, &peer) || peer_has_written(db, dm_channel, &peer).await? {
            answered.push(peer);
        } else {
            unanswered.push(dm_message.to_string());
        }
    }

    if !answered.is_empty() {
        let mut pipeline = Pipeline::new();
        pipeline
            .cmd("ZREM")
            .arg(&window_key)
            .arg(&answered[..])
            .ignore()
            .cmd("HDEL")
            .arg(&refs_key)
            .arg(&answered[..])
            .ignore();
        let _: () = pipeline.query_async(&mut *conn).await?;
    }

    if unanswered.len() < threshold {
        return Ok(());
    }

    let report_id = Ulid::new().to_string();
    let guard = DmGuard {
        report_id: report_id.clone(),
        flagged_at: Timestamp::now_utc(),
        paused: cfg.dm_dupe_pause,
        cleared_at: None,
        recipients: unanswered.len() as u32,
        fingerprint: fingerprint.to_string(),
    };

    // Only the winner of the claim files the report, so concurrent sends
    // (or a stale author) can never file two
    if !db.claim_dm_guard(&author.id, &guard, rearm_before).await? {
        return Ok(());
    }

    let message_ids: Vec<String> = unanswered
        .iter()
        .take(MAX_REPORT_MESSAGES)
        .cloned()
        .collect();
    let additional_context = format!(
        "Automated: identical DM text sent to {} non-friends in {window_hours}h with no replies.",
        unanswered.len()
    );

    if let Err(err) = Report::create_system(
        db,
        report_id.clone(),
        author,
        &message_ids,
        additional_context,
    )
    .await
    {
        // A guard with no report behind it would be a pause nobody can see
        // or lift
        if let Err(release_err) = db.release_dm_guard(&author.id, &report_id).await {
            capture(format!(
                "Anti-spam could not release the DM guard {report_id} of {}: {release_err:?}",
                author.id
            ));
        }

        return Err(err.into());
    }

    // The report stands; forget the window so this text does not re-fire
    let _: () = cmd("DEL")
        .arg(&window_key)
        .arg(&refs_key)
        .query_async(&mut *conn)
        .await?;

    Ok(())
}

/// Whether an existing DM pause on `author` is enforced right now.
///
/// The single source of truth for every gate: `dm_dupe_enabled = false` is
/// the kill switch that lifts enforcement for everyone at once, while
/// `dm_dupe_pause` only decides whether NEW flags pause (it is read when a
/// guard is created, never here).
pub fn dm_pause_enforced(cfg: &AntispamFeatures, author: &User) -> bool {
    cfg.dm_dupe_enabled && author.is_dm_paused()
}

/// Whether `author` may write a new message into the DM `channel_id` with
/// `peer_id`.
///
/// Refused with `DirectMessagesPaused` only while the author's pause is
/// enforced ([`dm_pause_enforced`]), the peer is not a friend, and the peer
/// has never written in that channel; a real conversation stays usable.
/// Always allowed while the detector is switched off (the kill switch lifts
/// enforcement too).
pub async fn dm_send_allowed(
    db: &Database,
    cfg: &AntispamFeatures,
    author: &User,
    channel_id: &str,
    peer_id: &str,
) -> Result<()> {
    if !dm_pause_enforced(cfg, author) || peer_id == author.id || is_friend(author, peer_id) {
        return Ok(());
    }

    if peer_has_written(db, channel_id, peer_id).await? {
        return Ok(());
    }

    Err(create_error!(DirectMessagesPaused))
}

// ---- E2EE fan-out signal ----
//
// Recipient ids and time only. Nothing here reads an envelope, its
// ciphertext, its size or a hash of it, and no id is ever written to a log
// line or to Sentry.
//
// Deviations from S7 of the Slim M3 plan:
//
// - Automatic envelopes (a downgrade notice resent on connect, a late-device
//   downgrade notice, group controls) are counted like typed ones: the
//   request carries no content-free way to tell them apart. Repeats to the
//   same peer count once, and group controls go to co-members, who never
//   count. But the client resends every pending downgrade control on each
//   connect, so a user with pending downgrades to N stranger peers who never
//   wrote back counts N strangers, and N alone can reach the threshold.
// - A plaintext reply is a reply: a peer who has written a server-readable
//   message in their DM with the author never counts. Only whether such a
//   message exists is read, and once found the peer is remembered as a
//   writer for the full reply memory, so deleting the message later does
//   not turn them back into a stranger.
// - A reply is applied lazily: the replier goes into the author's reply
//   memory, and the candidate filter and the threshold re-check drop them
//   from the author's window there (no per-bucket removal on every send).
// - An author holding a copy-paste guard that cannot re-arm yet is not
//   counted by this signal either, until that guard can re-arm.
// - Report only (`e2ee_fanout_pause = false`) never takes the shared DM
//   guard, so the copy-paste detector stays live. Its reports are
//   de-duplicated by their own key instead.
// - Only recipients with at least one queued envelope are passed in.
// - `e2ee_fanout_pause` defaults to false (D14: report only at first).
// - The keys are bucketed (`antispam:e2ee:in:{user}:{day}`,
//   `antispam:e2ee:out:{author}:{hour}`), each bucket with a fixed expiry, so
//   nothing outlives its period by more than one bucket.

/// The guard's `fingerprint` (and so the mark on its report) when the
/// fan-out signal pauses an account
pub const E2EE_FANOUT_FINGERPRINT: &str = "e2ee-fanout";

/// Accounts younger than this are held to `e2ee_fanout_new_account_threshold`
const NEW_ACCOUNT_DAYS: i64 = 14;

/// Upper bounds on the configured spans: they bound the buckets read per send
const MAX_FANOUT_WINDOW_HOURS: u64 = 48;
const MAX_REPLY_MEMORY_DAYS: u64 = 90;

/// Above this many strangers in one send, the author's writers are read with
/// one union instead of one membership test per stranger and day
const UNION_ABOVE: usize = 4;

/// Writers of a deleted account whose counts are cleaned of its id
const MAX_FORGET_WRITERS: usize = 200;

const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 86_400_000;

/// `antispam:e2ee:out:{author}:{hour}`: SET of the strangers `author_id`
/// wrote to in that hour (hours since the epoch). Expires when the last
/// window that reads it ends.
pub fn e2ee_fanout_out_key(author_id: &str, hour: i64) -> String {
    format!("antispam:e2ee:out:{author_id}:{hour}")
}

/// `antispam:e2ee:in:{user}:{day}`: SET of the strangers who wrote to
/// `user_id` that day (days since the epoch). Expires when the last reply
/// memory that reads it ends.
pub fn e2ee_fanout_in_key(user_id: &str, day: i64) -> String {
    format!("antispam:e2ee:in:{user_id}:{day}")
}

/// `antispam:e2ee:reported:{author}`: set when a report-only flag is filed,
/// for one window, so the same author is reported once per window
pub fn e2ee_fanout_reported_key(author_id: &str) -> String {
    format!("antispam:e2ee:reported:{author_id}")
}

/// The hour bucket of `now_ms`
pub fn e2ee_fanout_hour(now_ms: i64) -> i64 {
    now_ms.div_euclid(HOUR_MS)
}

/// The day bucket of `now_ms`
pub fn e2ee_fanout_day(now_ms: i64) -> i64 {
    now_ms.div_euclid(DAY_MS)
}

/// The window and the reply memory, clamped
#[derive(Clone, Copy)]
struct Spans {
    window_hours: u64,
    memory_days: u64,
}

impl Spans {
    /// The widest spans the config allows
    const WIDEST: Spans = Spans {
        window_hours: MAX_FANOUT_WINDOW_HOURS,
        memory_days: MAX_REPLY_MEMORY_DAYS,
    };

    fn of(cfg: &AntispamFeatures) -> Spans {
        Spans {
            window_hours: cfg
                .e2ee_fanout_window_hours
                .clamp(1, MAX_FANOUT_WINDOW_HOURS),
            memory_days: cfg
                .e2ee_fanout_reply_memory_days
                .clamp(1, MAX_REPLY_MEMORY_DAYS),
        }
    }

    /// The hour buckets the window reads at `hour`
    fn out_hours(self, hour: i64) -> RangeInclusive<i64> {
        hour - self.window_hours as i64..=hour
    }

    /// The day buckets the reply memory reads at `day`
    fn in_days(self, day: i64) -> RangeInclusive<i64> {
        day - self.memory_days as i64..=day
    }

    /// When the bucket of `hour` expires (seconds since the epoch): as the
    /// last window that reads it ends, so a member outlives the window by at
    /// most the hour it was written in
    fn out_expire_at(self, hour: i64) -> i64 {
        (hour + 1 + self.window_hours as i64) * 3600
    }

    /// When the bucket of `day` expires (seconds since the epoch): as the
    /// last reply memory that reads it ends, so a member outlives the memory
    /// by at most the day it was written in
    fn in_expire_at(self, day: i64) -> i64 {
        (day + 1 + self.memory_days as i64) * 86_400
    }
}

/// Every key of the signal for `user_id` that can exist at `now_ms`, for the
/// widest spans the config allows (a narrower config later must not strand
/// keys)
pub fn e2ee_fanout_keys(user_id: &str, now_ms: i64) -> Vec<String> {
    let mut keys: Vec<String> = Spans::WIDEST
        .out_hours(e2ee_fanout_hour(now_ms))
        .map(|hour| e2ee_fanout_out_key(user_id, hour))
        .collect();
    keys.extend(
        Spans::WIDEST
            .in_days(e2ee_fanout_day(now_ms))
            .map(|day| e2ee_fanout_in_key(user_id, day)),
    );
    keys.push(e2ee_fanout_reported_key(user_id));
    keys
}

/// Whether `author` was created less than [`NEW_ACCOUNT_DAYS`] before
/// `now_ms`, read from the time in its id. An id that is not a ULID counts as
/// new (the lower threshold).
fn is_new_account(author: &User, now_ms: i64) -> bool {
    match Ulid::from_string(&author.id) {
        Ok(id) => (id.timestamp_ms() as i64) > now_ms - NEW_ACCOUNT_DAYS * DAY_MS,
        Err(_) => true,
    }
}

/// Everyone who shares a Group with `user_id` (both current recipients),
/// from the server's own channel data
async fn co_members(db: &Database, user_id: &str) -> Result<HashSet<String>> {
    let mut members = HashSet::new();
    let mut generator = db.find_group_message_channels(user_id).await?;
    while let Some(groups) = generator.next_n(100).await? {
        for channel in groups {
            if let Channel::Group { recipients, .. } = channel {
                if recipients.iter().any(|id| id == user_id) {
                    members.extend(recipients);
                }
            }
        }
    }

    members.remove(user_id);
    Ok(members)
}

/// Whether `peer_id` has written a server-readable message in a DM with
/// `author_id`. Reads only whether one exists.
async fn wrote_plaintext_to(db: &Database, author_id: &str, peer_id: &str) -> Result<bool> {
    match db.find_direct_message_channel(author_id, peer_id).await {
        Ok(channel) => peer_has_written(db, channel.id(), peer_id).await,
        Err(err) if matches!(err.error_type, ErrorType::NotFound) => Ok(false),
        Err(err) => Err(err),
    }
}

/// `ids` without staff and bots. An id with no account behind it stays.
async fn without_staff<'a>(db: &Database, ids: &[&'a str]) -> Result<Vec<&'a str>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let owned: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
    let staff: HashSet<String> = db
        .fetch_users(&owned)
        .await?
        .into_iter()
        .filter(|user| user.privileged || user.bot.is_some())
        .map(|user| user.id)
        .collect();

    Ok(ids
        .iter()
        .copied()
        .filter(|id| !staff.contains(*id))
        .collect())
}

/// Record one `POST /e2ee/messages` from `author` to `recipient_ids` and flag
/// the author once they have written to enough strangers who never wrote
/// back.
///
/// Call it after the envelopes are stored, off the request path (spawned),
/// with the recipients that got at least one queued envelope. It takes
/// recipient ids only: never an envelope, its ciphertext, its size or a hash.
/// It never fails: every Redis failure fails open with a warning, database
/// failures are logged and captured, and no id is ever logged. O(recipients)
/// Redis work, one read of the author's groups, and bounded reads of
/// accounts and DMs.
///
/// Runs only while `e2ee_fanout_enabled` AND `dm_dupe_enabled`. Friends and
/// shared-group co-members are dropped first and never recorded. Then, for
/// the strangers left:
///
/// - The send is a write to each of them: the author goes into their
///   `antispam:e2ee:in:{stranger}:{day}` (two commands each). That is how a
///   reply answers their fan-out: their candidate filter and re-check read it.
/// - Unless the author is staff, or holds a DM guard that cannot re-arm yet,
///   each stranger who has not written to the author (encrypted within the
///   reply memory, or in plaintext in their DM) and is not staff goes into
///   `antispam:e2ee:out:{author}:{hour}`. A plaintext writer found is
///   remembered in the author's reply memory.
/// - At `e2ee_fanout_threshold` distinct strangers in the window
///   (`e2ee_fanout_new_account_threshold` for accounts younger than 14 days;
///   at most 50) up to `max(threshold, 10)` of them are re-checked. If enough
///   still stand, staff get a system report holding counts only (no message,
///   no recipient). With `e2ee_fanout_pause` the author also gets a [`DmGuard`]
///   (`fingerprint` [`E2EE_FANOUT_FINGERPRINT`]) that closing the report
///   lifts; without it no guard is taken and the report is filed once per
///   window (`antispam:e2ee:reported:{author}`).
///
/// See the deviations listed at the top of this section.
pub async fn observe_e2ee_fanout(
    db: &Database,
    cfg: &AntispamFeatures,
    author: &User,
    recipient_ids: &HashSet<String>,
) {
    if !cfg.e2ee_fanout_active() || author.bot.is_some() {
        return;
    }

    // The author's own other devices are never a recipient
    let recipients: Vec<&str> = recipient_ids
        .iter()
        .map(String::as_str)
        .filter(|id| *id != author.id.as_str())
        .collect();
    if recipients.is_empty() {
        return;
    }

    if let Err(failure) = observe_fanout(db, cfg, author, &recipients, now_ms()).await {
        match failure {
            ObserveFailure::Redis(err) => warn!(
                "Anti-spam E2EE fan-out observation skipped, Redis failed: {:?}",
                err.kind()
            ),
            ObserveFailure::Database(err) => capture(format!(
                "Anti-spam E2EE fan-out observation failed: {:?}",
                err.error_type
            )),
        }
    }
}

async fn observe_fanout(
    db: &Database,
    cfg: &AntispamFeatures,
    author: &User,
    recipients: &[&str],
    now: i64,
) -> std::result::Result<(), ObserveFailure> {
    // Friends and co-members are never recorded, in either direction
    let non_friends: Vec<&str> = recipients
        .iter()
        .copied()
        .filter(|id| !is_friend(author, id))
        .collect();
    if non_friends.is_empty() {
        return Ok(());
    }

    let co_members = co_members(db, &author.id).await?;
    let strangers: Vec<&str> = non_friends
        .into_iter()
        .filter(|id| !co_members.contains(*id))
        .collect();
    if strangers.is_empty() {
        return Ok(());
    }

    let Ok(mut conn) = get_connection().await else {
        warn!("Anti-spam E2EE fan-out observation skipped: no Redis connection");
        return Ok(());
    };

    let spans = Spans::of(cfg);
    let hour = e2ee_fanout_hour(now);
    let day = e2ee_fanout_day(now);

    // This send is a write to each stranger: remember it on their side for
    // the reply memory (their candidate filter and re-check treat it as a
    // reply). Two commands per stranger. MULTI because a SADD that landed
    // without its EXPIREAT (a connection lost mid-pipeline) would leave a
    // bucket that never expires; it adds two commands per send, not per
    // stranger.
    let mut pipeline = Pipeline::new();
    pipeline.atomic();
    for stranger in &strangers {
        let their_in_key = e2ee_fanout_in_key(stranger, day);
        pipeline
            .cmd("SADD")
            .arg(&their_in_key)
            .arg(&author.id)
            .ignore()
            .cmd("EXPIREAT")
            .arg(&their_in_key)
            .arg(spans.in_expire_at(day))
            .ignore();
    }
    let _: () = pipeline.query_async(&mut *conn).await?;

    // Staff are never counted, and an author whose guard cannot re-arm yet is
    // not counted again (the bookkeeping above still runs for both)
    if author.privileged {
        return Ok(());
    }

    let rearm_before = rearm_cutoff(cfg);
    if !can_rearm(author.dm_guard.as_ref(), rearm_before) {
        return Ok(());
    }

    // Nobody who wrote to the author within the reply memory counts
    let in_keys: Vec<String> = spans
        .in_days(day)
        .map(|bucket| e2ee_fanout_in_key(&author.id, bucket))
        .collect();
    let writers: HashSet<String> = if strangers.len() > UNION_ABOVE {
        cmd("SUNION")
            .arg(&in_keys[..])
            .query_async(&mut *conn)
            .await?
    } else {
        let mut pipeline = Pipeline::new();
        for stranger in &strangers {
            for key in &in_keys {
                pipeline.cmd("SISMEMBER").arg(key).arg(*stranger);
            }
        }
        let found: Vec<bool> = pipeline.query_async(&mut *conn).await?;
        strangers
            .iter()
            .zip(found.chunks(in_keys.len()))
            .filter(|(_, hits)| hits.iter().any(|hit| *hit))
            .map(|(stranger, _)| stranger.to_string())
            .collect()
    };

    // Nor anyone who wrote back in plaintext: checked here for the first few,
    // the threshold re-check covers the rest. A plaintext writer found is
    // remembered as a writer, so deleting the message later changes nothing.
    let mut candidates: Vec<&str> = Vec::new();
    let mut plaintext_writers: Vec<&str> = Vec::new();
    let mut plaintext_checks = 0;
    for stranger in strangers {
        if writers.contains(stranger) {
            continue;
        }
        if plaintext_checks < MAX_PEERS_CHECKED {
            plaintext_checks += 1;
            if wrote_plaintext_to(db, &author.id, stranger).await? {
                plaintext_writers.push(stranger);
                continue;
            }
        }
        candidates.push(stranger);
    }

    let today_in_key = e2ee_fanout_in_key(&author.id, day);
    if !plaintext_writers.is_empty() {
        let mut pipeline = Pipeline::new();
        pipeline
            .atomic()
            .cmd("SADD")
            .arg(&today_in_key)
            .arg(&plaintext_writers[..])
            .ignore()
            .cmd("EXPIREAT")
            .arg(&today_in_key)
            .arg(spans.in_expire_at(day))
            .ignore();
        let _: () = pipeline.query_async(&mut *conn).await?;
    }

    // Nor staff
    let candidates = without_staff(db, &candidates).await?;
    if candidates.is_empty() {
        return Ok(());
    }

    // Record them in this hour's bucket and count the window
    let out_key = e2ee_fanout_out_key(&author.id, hour);
    let out_keys: Vec<String> = spans
        .out_hours(hour)
        .map(|bucket| e2ee_fanout_out_key(&author.id, bucket))
        .collect();
    let mut pipeline = Pipeline::new();
    pipeline
        .atomic()
        .cmd("SADD")
        .arg(&out_key)
        .arg(&candidates[..])
        .ignore()
        .cmd("EXPIREAT")
        .arg(&out_key)
        .arg(spans.out_expire_at(hour))
        .ignore()
        .cmd("SUNION")
        .arg(&out_keys[..]);

    let (counted,): (HashSet<String>,) = pipeline.query_async(&mut *conn).await?;
    let threshold = cfg.e2ee_fanout_threshold_for(is_new_account(author, now));
    if counted.len() < threshold {
        return Ok(());
    }

    // At the threshold, re-check them: one who has since become a friend, a
    // co-member or staff, or written back in either form, is a conversation,
    // not a target. The in-memory checks run over every counted peer; one
    // union reads the author's reply memory (replies that arrived after a
    // peer was counted are applied here, lazily).
    let writers: HashSet<String> = cmd("SUNION")
        .arg(&in_keys[..])
        .query_async(&mut *conn)
        .await?;
    let peers_checked = threshold.max(MAX_PEERS_CHECKED);

    let mut answered: Vec<&str> = Vec::new();
    let mut remaining: Vec<&str> = Vec::new();
    for peer in counted.iter().map(String::as_str) {
        if is_friend(author, peer) || co_members.contains(peer) || writers.contains(peer) {
            answered.push(peer);
        } else {
            remaining.push(peer);
        }
    }

    // The account and DM reads only for up to `max(threshold, 10)` of the rest
    let peers: Vec<&str> = remaining.iter().copied().take(peers_checked).collect();
    let unchecked = remaining.len() - peers.len();
    let not_staff = without_staff(db, &peers).await?;

    let mut plaintext_writers: Vec<&str> = Vec::new();
    let mut silent = 0;
    for peer in peers.iter().copied() {
        if !not_staff.contains(&peer) {
            answered.push(peer);
        } else if wrote_plaintext_to(db, &author.id, peer).await? {
            answered.push(peer);
            plaintext_writers.push(peer);
        } else {
            silent += 1;
        }
    }

    if !plaintext_writers.is_empty() {
        let mut pipeline = Pipeline::new();
        pipeline
            .atomic()
            .cmd("SADD")
            .arg(&today_in_key)
            .arg(&plaintext_writers[..])
            .ignore()
            .cmd("EXPIREAT")
            .arg(&today_in_key)
            .arg(spans.in_expire_at(day))
            .ignore();
        let _: () = pipeline.query_async(&mut *conn).await?;
    }

    if !answered.is_empty() {
        let mut pipeline = Pipeline::new();
        for key in &out_keys {
            pipeline.cmd("SREM").arg(key).arg(&answered[..]).ignore();
        }
        let _: () = pipeline.query_async(&mut *conn).await?;
    }

    // Only peers checked and found silent count, here and in the report
    if silent < threshold {
        return Ok(());
    }

    let strangers_count = silent;
    let counted_text = if unchecked > 0 {
        format!("at least {strangers_count}")
    } else {
        strangers_count.to_string()
    };
    let report_id = Ulid::new().to_string();
    let window_hours = spans.window_hours;
    let reported_key = e2ee_fanout_reported_key(&author.id);

    if cfg.e2ee_fanout_pause {
        let guard = DmGuard {
            report_id: report_id.clone(),
            flagged_at: Timestamp::now_utc(),
            paused: true,
            cleared_at: None,
            recipients: strangers_count as u32,
            fingerprint: E2EE_FANOUT_FINGERPRINT.to_string(),
        };

        // Only the winner of the claim files the report, so concurrent sends
        // (or a stale author) can never file two
        if !db.claim_dm_guard(&author.id, &guard, rearm_before).await? {
            return Ok(());
        }
    } else {
        // Report only: no guard, so the copy-paste detector stays live. One
        // report per author per window; a later crossing just starts over.
        let claimed: Option<String> = cmd("SET")
            .arg(&reported_key)
            .arg(1)
            .arg("NX")
            .arg("EX")
            .arg(window_hours * 3600)
            .query_async(&mut *conn)
            .await?;
        if claimed.is_none() {
            let _: () = cmd("DEL")
                .arg(&out_keys[..])
                .query_async(&mut *conn)
                .await?;
            return Ok(());
        }
    }

    // Counts only: the server holds no message to attach, and no recipient
    // is named
    let outcome = if cfg.e2ee_fanout_pause {
        "Their DMs to strangers are paused until this report is closed."
    } else {
        "Report only: nothing was paused."
    };
    let additional_context = format!(
        "Automated: end-to-end encrypted DMs to {counted_text} distinct non-friends in \
         {window_hours}h, none of whom wrote back (threshold {threshold}). Counts only: the \
         content is encrypted and no recipients are listed. {outcome}"
    );

    if let Err(err) =
        Report::create_system(db, report_id.clone(), author, &[], additional_context).await
    {
        if cfg.e2ee_fanout_pause {
            // A guard with no report behind it would be a pause nobody can
            // see or lift
            if let Err(release_err) = db.release_dm_guard(&author.id, &report_id).await {
                capture(format!(
                    "Anti-spam could not release an E2EE fan-out guard after its report failed: {:?}",
                    release_err.error_type
                ));
            }
        } else {
            // Let a later crossing file it
            let _: () = cmd("DEL")
                .arg(&reported_key)
                .query_async(&mut *conn)
                .await?;
        }

        return Err(err.into());
    }

    // The report stands; forget the window so the same strangers do not
    // re-fire
    let _: () = cmd("DEL")
        .arg(&out_keys[..])
        .query_async(&mut *conn)
        .await?;

    Ok(())
}

/// Delete the signal's own keys for `user_id` (every bucket that can exist,
/// and the report-only mark), whatever the config says, after removing the
/// id from the window of each stranger who wrote to it (at most
/// [`MAX_FORGET_WRITERS`]). Called by the account deletion cascade.
///
/// Best-effort: on a Redis failure every bucket still expires on its own.
/// The id can also sit in other users' reply memory (as someone it wrote to)
/// until those buckets expire.
pub async fn forget_e2ee_fanout(cfg: &AntispamFeatures, user_id: &str) {
    if let Err(err) = forget_fanout(cfg, user_id, now_ms()).await {
        warn!(
            "Anti-spam E2EE fan-out keys not deleted, Redis failed: {:?}",
            err.kind()
        );
    }
}

async fn forget_fanout(
    cfg: &AntispamFeatures,
    user_id: &str,
    now: i64,
) -> std::result::Result<(), RedisError> {
    let Ok(mut conn) = get_connection().await else {
        warn!("Anti-spam E2EE fan-out keys not deleted: no Redis connection");
        return Ok(());
    };

    let in_keys: Vec<String> = Spans::WIDEST
        .in_days(e2ee_fanout_day(now))
        .map(|day| e2ee_fanout_in_key(user_id, day))
        .collect();
    let writers: Vec<String> = cmd("SUNION")
        .arg(&in_keys[..])
        .query_async(&mut *conn)
        .await?;

    let mut pipeline = Pipeline::new();
    for writer in writers.iter().take(MAX_FORGET_WRITERS) {
        for hour in Spans::of(cfg).out_hours(e2ee_fanout_hour(now)) {
            pipeline
                .cmd("SREM")
                .arg(e2ee_fanout_out_key(writer, hour))
                .arg(user_id)
                .ignore();
        }
    }
    pipeline
        .cmd("DEL")
        .arg(&e2ee_fanout_keys(user_id, now)[..])
        .ignore();

    pipeline.query_async(&mut *conn).await
}

// ---- end of the E2EE fan-out signal ----

#[cfg(test)]
mod tests {
    use revolt_models::v0::{ReportedContent, Text, WebsiteMetadata};
    use revolt_result::ErrorType;

    use super::*;
    use crate::{ForwardedSnapshot, Relationship, SYSTEM_USER_ID};

    const TIFFANY: &str = "Hi! I love your profile picture, can I use it for an art project for my client? I'll pay you and credit you.";

    /// One runtime for every Redis-backed test here: `redis_kiss` pools
    /// connections globally, and a connection made on one per-test runtime
    /// dies with it (same rationale as the voice tests)
    fn rt() -> &'static tokio::runtime::Runtime {
        static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
        RT.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap()
        })
    }

    fn enabled() -> AntispamFeatures {
        AntispamFeatures {
            dm_dupe_enabled: true,
            ..Default::default()
        }
    }

    fn user(friends: &[&str]) -> User {
        let id = Ulid::new().to_string();
        User {
            username: format!("u{}", &id[16..]),
            discriminator: "0001".to_string(),
            id,
            relations: Some(
                friends
                    .iter()
                    .map(|friend| Relationship {
                        id: friend.to_string(),
                        status: RelationshipStatus::Friend,
                        note: None,
                    })
                    .collect(),
            ),
            ..Default::default()
        }
    }

    fn message(channel: &str, author: &str, content: &str) -> Message {
        Message {
            id: Ulid::new().to_string(),
            channel: channel.to_string(),
            author: author.to_string(),
            content: Some(content.to_string()),
            ..Default::default()
        }
    }

    fn paused_guard() -> DmGuard {
        DmGuard {
            report_id: Ulid::new().to_string(),
            flagged_at: Timestamp::now_utc(),
            paused: true,
            cleared_at: None,
            recipients: 3,
            fingerprint: "f".repeat(32),
        }
    }

    fn fp(text: &str) -> Option<String> {
        fingerprint(text, AntispamFeatures::default().min_chars())
    }

    #[test]
    fn tiffany_variants_share_one_fingerprint() {
        let original = fp(TIFFANY).expect("the scam text is long enough to count");

        let variants = [
            TIFFANY.to_uppercase(),
            TIFFANY.to_lowercase(),
            "  Hi!   I love your profile\n\npicture,   can I use it for an art project\tfor my client?  I'll pay you and credit you.  ".to_string(),
            // Zero-width, bidi, soft hyphen, BOM, variation selector and
            // combining mark inserted inside words
            "Hi! I lo\u{200B}ve your pro\u{200D}file pic\u{2060}ture, can I use it for an a\u{FEFF}rt pro\u{FE0F}ject for my cli\u{00AD}ent? I'll p\u{0301}ay you and cre\u{202E}dit\u{202C} you.\u{2066}".to_string(),
            // Fullwidth letters fold back to ASCII
            TIFFANY.replace(
                "profile",
                "\u{FF50}\u{FF52}\u{FF4F}\u{FF46}\u{FF49}\u{FF4C}\u{FF45}",
            ),
            format!("{TIFFANY} https://example.com/a"),
            format!("{TIFFANY} https://other.example/b?x=1 sloga.gg/x"),
        ];

        for variant in &variants {
            assert_eq!(
                fp(variant).as_deref(),
                Some(original.as_str()),
                "variant {variant:?} normalized to {:?}",
                normalize(variant)
            );
        }
    }

    /// Pinned directly, because `decancer` may already drop some of these on
    /// its own path; the fallback path relies on this alone
    #[test]
    fn invisible_characters_are_deleted() {
        assert_eq!(
            strip_invisible(
                "a\u{200B}b\u{200D}c\u{2060}d\u{FEFF}e\u{00AD}f\u{202E}g\u{2066}h\u{FE0F}i\u{0301}j"
            ),
            "abcdefghij"
        );
        assert_eq!(
            normalize("pro\u{200B}ject  \u{200C}PRO\u{2064}JECT"),
            "project project"
        );
    }

    /// Every whitespace character separates words; `decancer` alone would
    /// delete a tab and join the words around it
    #[test]
    fn every_whitespace_character_separates_words() {
        for text in [
            "a\tb",
            "a\u{00A0}b",
            "a\u{2003}b",
            "a\r\nb",
            "a\u{000B}b",
            "a\u{000C}b",
            "a\u{0085}b",
            "a\u{1680}b",
            "a\u{2028}b",
            "a\u{2029}b",
            "a\u{202F}b",
            "a\u{205F}b",
            "a\u{3000}b",
        ] {
            assert_eq!(normalize(text), "a b", "{text:?}");
        }

        for character in (0..=0x10FFFF).filter_map(char::from_u32) {
            assert!(
                !(character.is_whitespace() && is_invisible(character)),
                "{character:?} is whitespace and must not be deleted"
            );
        }
    }

    #[test]
    fn link_only_messages_are_exempt() {
        for text in [
            "https://app.sloga.gg/invite/abc123",
            "check this https://youtu.be/xyz",
            "join us! https://app.sloga.gg/invite/abc",
            "app.sloga.gg/invite/abc123",
            "\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}\u{200B}hi",
            "",
        ] {
            assert_eq!(fingerprint(text, 30), None, "{text:?} must be exempt");
        }
    }

    #[test]
    fn distinct_texts_have_distinct_fingerprints() {
        let a = fp("Hey, are you coming to the meetup on Saturday afternoon?").unwrap();
        let b = fp("Thanks for the help with the server settings yesterday!").unwrap();
        assert_ne!(a, b);
        assert_ne!(a, fp(TIFFANY).unwrap());
    }

    #[test]
    fn fingerprint_is_32_lowercase_hex_chars() {
        for text in [
            TIFFANY,
            "\u{0428}\u{0442}\u{043E} \u{044D}\u{0442}\u{043E} \u{0437}\u{0430} \u{0441}\u{043E}\u{043E}\u{0431}\u{0449}\u{0435}\u{043D}\u{0438}\u{0435} \u{0442}\u{0430}\u{043A}\u{043E}\u{0435} \u{0434}\u{043B}\u{0438}\u{043D}\u{043D}\u{043E}\u{0435}",
        ] {
            let fingerprint = fingerprint(text, 10).expect("long enough");
            assert_eq!(fingerprint.len(), 32);
            assert!(fingerprint.is_ascii());
            assert!(fingerprint
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        }
    }

    #[test]
    fn dm_text_reads_sender_text_only() {
        let mut message = message("C", "A", "hello");
        message.embeds = Some(vec![
            Embed::Text(Text {
                icon_url: None,
                url: None,
                title: Some("embed title".to_string()),
                description: Some("embed description".to_string()),
                media: None,
                colour: None,
            }),
            // A link preview is fetched by the server, not written by the sender
            Embed::Website(WebsiteMetadata {
                url: None,
                original_url: None,
                special: None,
                title: Some("preview title".to_string()),
                description: Some("preview description".to_string()),
                image: None,
                video: None,
                site_name: None,
                icon_url: None,
                colour: None,
            }),
        ]);
        message.forwarded = Some(ForwardedSnapshot {
            message_id: "M".to_string(),
            channel_id: "C2".to_string(),
            server_id: None,
            author_id: None,
            content: Some("forwarded text".to_string()),
            attachments: vec![],
            original_sent_at: 0,
        });

        assert_eq!(
            dm_text(&message),
            "hello\nembed title\nembed description\nforwarded text"
        );

        let empty = Message {
            content: Some("  ".to_string()),
            ..Default::default()
        };
        assert_eq!(dm_text(&empty), "");
    }

    #[test]
    fn dm_send_allowed_gates_only_paused_authors_writing_to_silent_strangers() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = enabled();
            let friend = Ulid::new().to_string();
            let stranger = Ulid::new().to_string();
            let replier = Ulid::new().to_string();
            let channel = Ulid::new().to_string();
            let other_channel = Ulid::new().to_string();

            let mut author = user(&[&friend]);

            // Not paused: anything goes
            dm_send_allowed(&db, &cfg, &author, &channel, &stranger)
                .await
                .expect("an unpaused author may DM a stranger");

            author.dm_guard = Some(paused_guard());
            assert!(author.is_dm_paused());

            dm_send_allowed(&db, &cfg, &author, &channel, &friend)
                .await
                .expect("a paused author may still DM a friend");

            // The stranger wrote, but in another channel: still refused here
            db.insert_message(&message(&other_channel, &stranger, "hello"))
                .await
                .unwrap();
            let err = dm_send_allowed(&db, &cfg, &author, &channel, &stranger)
                .await
                .expect_err("a paused author may not DM a stranger who never wrote");
            assert!(
                matches!(err.error_type, ErrorType::DirectMessagesPaused),
                "{err:?}"
            );

            db.insert_message(&message(&channel, &replier, "sure, what is it?"))
                .await
                .unwrap();
            dm_send_allowed(&db, &cfg, &author, &channel, &replier)
                .await
                .expect("a stranger who replied keeps the conversation open");

            // The kill switch lifts enforcement
            dm_send_allowed(
                &db,
                &AntispamFeatures::default(),
                &author,
                &channel,
                &stranger,
            )
            .await
            .expect("a disabled detector never refuses");

            // A cleared guard no longer pauses
            if let Some(guard) = author.dm_guard.as_mut() {
                guard.paused = false;
                guard.cleared_at = Some(Timestamp::now_utc());
            }
            dm_send_allowed(&db, &cfg, &author, &channel, &stranger)
                .await
                .expect("a cleared guard does not pause");
        })
    }

    /// Send `text` from `author` to a fresh DM with each peer, observing each
    async fn send_to_all(
        db: &Database,
        cfg: &AntispamFeatures,
        author: &User,
        peers: &[String],
        text: &str,
    ) {
        for peer in peers {
            let channel = Ulid::new().to_string();
            // A real DM has its channel row; the report snapshot reads it
            db.insert_channel(&crate::Channel::DirectMessage {
                id: channel.clone(),
                active: true,
                recipients: vec![author.id.clone(), peer.clone()],
                last_message_id: None,
            })
            .await
            .unwrap();
            let sent = message(&channel, &author.id, text);
            db.insert_message(&sent).await.unwrap();
            observe_dm_message(db, cfg, author, &channel, peer, &sent).await;
        }
    }

    async fn system_reports_about(db: &Database, user_id: &str) -> usize {
        db.fetch_reports(None)
            .await
            .unwrap()
            .into_iter()
            .filter(|report| {
                report.author_id == SYSTEM_USER_ID
                    && matches!(&report.content, ReportedContent::User { id, .. } if id == user_id)
            })
            .count()
    }

    fn strangers(count: usize) -> Vec<String> {
        (0..count).map(|_| Ulid::new().to_string()).collect()
    }

    /// Requires Redis (local default URI)
    #[test]
    fn observe_flags_three_silent_strangers_once() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = enabled();
            let author = user(&[]);
            db.insert_user(&author).await.unwrap();

            let peers = strangers(3);
            send_to_all(&db, &cfg, &author, &peers[..2], TIFFANY).await;
            assert!(
                db.fetch_user(&author.id).await.unwrap().dm_guard.is_none(),
                "two strangers are below the threshold"
            );
            assert_eq!(system_reports_about(&db, &author.id).await, 0);

            send_to_all(&db, &cfg, &author, &peers[2..], TIFFANY).await;

            let flagged = db.fetch_user(&author.id).await.unwrap();
            let guard = flagged.dm_guard.clone().expect("the third stranger flags");
            assert!(guard.paused);
            assert!(guard.cleared_at.is_none());
            assert_eq!(guard.recipients, 3);
            assert_eq!(guard.fingerprint, fp(TIFFANY).unwrap());
            assert!(flagged.is_dm_paused());

            assert_eq!(system_reports_about(&db, &author.id).await, 1);
            let report = db.fetch_report(&guard.report_id).await.unwrap();
            assert_eq!(report.author_id, SYSTEM_USER_ID);
            assert!(
                report.additional_context.contains("3 non-friends"),
                "{}",
                report.additional_context
            );
            match &report.content {
                ReportedContent::User { message_id, .. } => {
                    assert!(message_id.is_some(), "a sent message is the evidence")
                }
                content => panic!("expected a user report, got {content:?}"),
            }

            // The flagged author (as the routes load it) is not re-checked
            send_to_all(
                &db,
                &cfg,
                &author_reloaded(&db, &author).await,
                &strangers(1),
                TIFFANY,
            )
            .await;

            // A stale copy of the author passes the short-circuit, but the
            // claim refuses a second guard, so no second report
            send_to_all(&db, &cfg, &author, &strangers(3), TIFFANY).await;

            assert_eq!(system_reports_about(&db, &author.id).await, 1);
            assert_eq!(
                db.fetch_user(&author.id).await.unwrap().dm_guard,
                Some(guard)
            );
        })
    }

    async fn author_reloaded(db: &Database, author: &User) -> User {
        db.fetch_user(&author.id).await.unwrap()
    }

    /// Requires Redis (local default URI)
    #[test]
    fn observe_never_counts_friends() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = enabled();
            let friend = Ulid::new().to_string();
            let author = user(&[&friend]);
            db.insert_user(&author).await.unwrap();

            // Two strangers and a friend: only two count
            let mut peers = strangers(2);
            peers.push(friend);
            send_to_all(&db, &cfg, &author, &peers, TIFFANY).await;

            assert!(db.fetch_user(&author.id).await.unwrap().dm_guard.is_none());
            assert_eq!(system_reports_about(&db, &author.id).await, 0);
        })
    }

    /// Requires Redis (local default URI). A peer already in the window who
    /// has become a friend since no longer counts toward the flag.
    #[test]
    fn observe_drops_peers_who_became_friends() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = enabled();
            let author = user(&[]);
            db.insert_user(&author).await.unwrap();

            let peers = strangers(3);
            send_to_all(&db, &cfg, &author, &peers[..2], TIFFANY).await;

            // The second stranger and the author become friends before the
            // third send; the routes would load the author with that relation
            let mut befriended = author.clone();
            befriended.relations = Some(vec![Relationship {
                id: peers[1].clone(),
                status: RelationshipStatus::Friend,
                note: None,
            }]);
            send_to_all(&db, &cfg, &befriended, &peers[2..], TIFFANY).await;

            assert!(
                db.fetch_user(&author.id).await.unwrap().dm_guard.is_none(),
                "only two non-friends received the text"
            );
            assert_eq!(system_reports_about(&db, &author.id).await, 0);
        })
    }

    #[test]
    fn pause_is_enforced_only_while_enabled_and_paused() {
        let mut paused = user(&[]);
        paused.dm_guard = Some(paused_guard());
        let unpaused = user(&[]);

        let mut cleared = user(&[]);
        let mut guard = paused_guard();
        guard.paused = false;
        guard.cleared_at = Some(Timestamp::now_utc());
        cleared.dm_guard = Some(guard);

        // `dm_dupe_pause` only shapes new flags; it never lifts an existing
        // pause
        let report_only = AntispamFeatures {
            dm_dupe_enabled: true,
            dm_dupe_pause: false,
            ..Default::default()
        };

        assert!(dm_pause_enforced(&enabled(), &paused));
        assert!(dm_pause_enforced(&report_only, &paused));
        assert!(!dm_pause_enforced(&enabled(), &unpaused));
        assert!(!dm_pause_enforced(&enabled(), &cleared));
        assert!(!dm_pause_enforced(&AntispamFeatures::default(), &paused));
        assert!(!dm_pause_enforced(&AntispamFeatures::default(), &unpaused));
    }

    /// Requires Redis (local default URI)
    #[test]
    fn observe_skips_strangers_who_replied() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = enabled();
            let author = user(&[]);
            db.insert_user(&author).await.unwrap();

            // The second stranger answers in their DM AFTER the author's send
            // was counted, so only the re-check at the threshold catches it
            let peers = strangers(3);
            for (index, peer) in peers.iter().enumerate() {
                let channel = Ulid::new().to_string();
                let sent = message(&channel, &author.id, TIFFANY);
                db.insert_message(&sent).await.unwrap();
                observe_dm_message(&db, &cfg, &author, &channel, peer, &sent).await;
                if index == 1 {
                    db.insert_message(&message(&channel, peer, "who are you?"))
                        .await
                        .unwrap();
                }
            }

            assert!(
                db.fetch_user(&author.id).await.unwrap().dm_guard.is_none(),
                "only two strangers stayed silent"
            );
            assert_eq!(system_reports_about(&db, &author.id).await, 0);

            // A third silent stranger completes the set
            send_to_all(&db, &cfg, &author, &strangers(1), TIFFANY).await;

            let guard = db
                .fetch_user(&author.id)
                .await
                .unwrap()
                .dm_guard
                .expect("three silent strangers flag");
            assert_eq!(guard.recipients, 3);
            assert_eq!(system_reports_about(&db, &author.id).await, 1);
        })
    }

    const POLITE_REPLY: &str =
        "Thank you so much for reaching out, I will think about it and get back to you!";

    /// Each stranger writes first; the author's identical replies never
    /// count. Requires Redis (local default URI).
    #[test]
    fn observe_never_counts_replies_in_conversations_the_peer_started() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = enabled();
            let author = user(&[]);
            db.insert_user(&author).await.unwrap();
            assert!(fp(POLITE_REPLY).is_some(), "the reply must be long enough");

            for peer in strangers(3) {
                let channel = Ulid::new().to_string();
                db.insert_message(&message(&channel, &peer, "hey, love your art!"))
                    .await
                    .unwrap();

                let sent = message(&channel, &author.id, POLITE_REPLY);
                db.insert_message(&sent).await.unwrap();
                observe_dm_message(&db, &cfg, &author, &channel, &peer, &sent).await;
            }

            assert!(db.fetch_user(&author.id).await.unwrap().dm_guard.is_none());
            assert_eq!(system_reports_about(&db, &author.id).await, 0);
        })
    }

    /// Framing attempt: strangers open DMs, draw the same polite reply, then
    /// delete their own messages. Those replies were never counted, so one
    /// more identical message to a silent stranger cannot reach the
    /// threshold. Requires Redis (local default URI).
    #[test]
    fn observe_cannot_be_framed_by_strangers_deleting_their_openers() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = enabled();
            let author = user(&[]);
            db.insert_user(&author).await.unwrap();

            let mut openers = Vec::new();
            for peer in strangers(2) {
                let channel = Ulid::new().to_string();
                let opener = message(&channel, &peer, "hey, love your art!");
                db.insert_message(&opener).await.unwrap();

                let sent = message(&channel, &author.id, POLITE_REPLY);
                db.insert_message(&sent).await.unwrap();
                observe_dm_message(&db, &cfg, &author, &channel, &peer, &sent).await;
                openers.push(opener.id);
            }

            for opener in &openers {
                db.delete_message(opener).await.unwrap();
            }

            send_to_all(&db, &cfg, &author, &strangers(1), POLITE_REPLY).await;

            assert!(
                db.fetch_user(&author.id).await.unwrap().dm_guard.is_none(),
                "replies inside conversations the peers started must not count"
            );
            assert_eq!(system_reports_about(&db, &author.id).await, 0);
        })
    }

    /// No Redis needed: exempt texts return before the window
    #[test]
    fn observe_ignores_invites_and_disabled_config() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let author = user(&[]);
            db.insert_user(&author).await.unwrap();

            send_to_all(
                &db,
                &enabled(),
                &author,
                &strangers(4),
                "join us! https://app.sloga.gg/invite/abc",
            )
            .await;
            send_to_all(
                &db,
                &AntispamFeatures::default(),
                &author,
                &strangers(4),
                TIFFANY,
            )
            .await;

            assert!(db.fetch_user(&author.id).await.unwrap().dm_guard.is_none());
            assert_eq!(system_reports_about(&db, &author.id).await, 0);
        })
    }

    // ---- E2EE fan-out signal ----

    /// Switched on, report only (the default pause setting)
    fn fanout_on() -> AntispamFeatures {
        AntispamFeatures {
            dm_dupe_enabled: true,
            e2ee_fanout_enabled: true,
            ..Default::default()
        }
    }

    /// Switched on, pausing
    fn fanout_pausing() -> AntispamFeatures {
        AntispamFeatures {
            e2ee_fanout_pause: true,
            ..fanout_on()
        }
    }

    /// A stored user created `days` ago (account age is read from the id)
    async fn stored_user_aged(db: &Database, days: u64) -> User {
        let mut author = user(&[]);
        let created_ms = now_ms() as u64 - days * DAY_MS as u64;
        author.id = Ulid::from_parts(created_ms, Ulid::new().random()).to_string();
        db.insert_user(&author).await.unwrap();
        author
    }

    /// One `POST /e2ee/messages` from `author` to `recipients`, observed
    async fn fan_out(db: &Database, cfg: &AntispamFeatures, author: &User, recipients: &[String]) {
        let recipient_ids: HashSet<String> = recipients.iter().cloned().collect();
        observe_e2ee_fanout(db, cfg, author, &recipient_ids).await;
    }

    /// The same at a chosen instant, through the inner observer
    async fn fan_out_at(
        db: &Database,
        cfg: &AntispamFeatures,
        author: &User,
        recipients: &[String],
        now: i64,
    ) {
        let recipients: Vec<&str> = recipients.iter().map(String::as_str).collect();
        if observe_fanout(db, cfg, author, &recipients, now)
            .await
            .is_err()
        {
            panic!("the observation failed");
        }
    }

    /// A group owned by `owner_id` with `member_ids` in it
    async fn group_with(db: &Database, owner_id: &str, member_ids: &[String]) {
        Channel::create_group(
            db,
            revolt_models::v0::DataCreateGroup {
                name: "g".to_string(),
                description: None,
                icon: None,
                users: member_ids.iter().cloned().collect(),
                nsfw: None,
                spoiler: None,
            },
            owner_id.to_string(),
        )
        .await
        .expect("group");
    }

    /// A DM between `author_id` and `peer_id` in which the peer wrote a
    /// plaintext message; the message id
    async fn plaintext_reply(db: &Database, author_id: &str, peer_id: &str) -> String {
        let channel = Ulid::new().to_string();
        db.insert_channel(&crate::Channel::DirectMessage {
            id: channel.clone(),
            active: true,
            recipients: vec![author_id.to_string(), peer_id.to_string()],
            last_message_id: None,
        })
        .await
        .unwrap();
        let reply = message(&channel, peer_id, "hi, who is this?");
        db.insert_message(&reply).await.unwrap();
        reply.id
    }

    async fn union(keys: Vec<String>) -> HashSet<String> {
        let mut conn = get_connection().await.expect("redis");
        cmd("SUNION")
            .arg(&keys[..])
            .query_async(&mut *conn)
            .await
            .expect("SUNION")
    }

    /// The strangers in `author_id`'s window at `now` (default spans)
    async fn out_members(author_id: &str, now: i64) -> HashSet<String> {
        let spans = Spans::of(&AntispamFeatures::default());
        union(
            spans
                .out_hours(e2ee_fanout_hour(now))
                .map(|hour| e2ee_fanout_out_key(author_id, hour))
                .collect(),
        )
        .await
    }

    async fn out_count(author_id: &str) -> usize {
        out_members(author_id, now_ms()).await.len()
    }

    /// Whether `writer` is in `user_id`'s reply memory now (default spans)
    async fn in_contains(user_id: &str, writer: &str) -> bool {
        let spans = Spans::of(&AntispamFeatures::default());
        union(
            spans
                .in_days(e2ee_fanout_day(now_ms()))
                .map(|day| e2ee_fanout_in_key(user_id, day))
                .collect(),
        )
        .await
        .contains(writer)
    }

    /// Whether any key of the signal exists for `user_id`
    async fn any_key(user_id: &str) -> bool {
        let mut conn = get_connection().await.expect("redis");
        let existing: i64 = cmd("EXISTS")
            .arg(&e2ee_fanout_keys(user_id, now_ms())[..])
            .query_async(&mut *conn)
            .await
            .expect("EXISTS");
        existing > 0
    }

    async fn sadd_for_a_minute(key: &str, member: &str) {
        let mut conn = get_connection().await.expect("redis");
        let _: () = cmd("SADD")
            .arg(key)
            .arg(member)
            .query_async(&mut *conn)
            .await
            .expect("SADD");
        let _: () = cmd("EXPIRE")
            .arg(key)
            .arg(60)
            .query_async(&mut *conn)
            .await
            .expect("EXPIRE");
    }

    /// Seconds left on `key`: -2 when it does not exist, -1 when it never
    /// expires
    async fn ttl(key: &str) -> i64 {
        let mut conn = get_connection().await.expect("redis");
        cmd("TTL")
            .arg(key)
            .query_async(&mut *conn)
            .await
            .expect("TTL")
    }

    async fn assert_not_flagged(db: &Database, author: &User, why: &str) {
        assert!(
            db.fetch_user(&author.id).await.unwrap().dm_guard.is_none(),
            "{why}"
        );
        assert_eq!(system_reports_about(db, &author.id).await, 0, "{why}");
    }

    async fn fanout_guard(db: &Database, author: &User, why: &str) -> DmGuard {
        db.fetch_user(&author.id)
            .await
            .unwrap()
            .dm_guard
            .unwrap_or_else(|| panic!("{why}"))
    }

    /// Requires Redis (local default URI)
    #[test]
    fn e2ee_fanout_under_threshold_does_not_flag() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = fanout_on();
            let author = stored_user_aged(&db, 30).await;

            let peers = strangers(9);
            fan_out(&db, &cfg, &author, &peers[..5]).await;
            fan_out(&db, &cfg, &author, &peers[5..]).await;

            assert_eq!(out_count(&author.id).await, 9);
            assert_not_flagged(&db, &author, "nine strangers are below ten").await;
        })
    }

    /// Requires Redis (local default URI)
    #[test]
    fn e2ee_fanout_flags_at_threshold_once_with_counts_only() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = fanout_pausing();
            let author = stored_user_aged(&db, 30).await;

            let peers = strangers(10);
            fan_out(&db, &cfg, &author, &peers[..9]).await;
            assert_not_flagged(&db, &author, "nine strangers are below the threshold").await;

            fan_out(&db, &cfg, &author, &peers[9..]).await;

            let flagged = db.fetch_user(&author.id).await.unwrap();
            let guard = flagged.dm_guard.clone().expect("the tenth stranger flags");
            assert!(guard.paused);
            assert!(guard.cleared_at.is_none());
            assert_eq!(guard.recipients, 10);
            assert_eq!(guard.fingerprint, "e2ee-fanout");
            assert_eq!(guard.fingerprint, E2EE_FANOUT_FINGERPRINT);
            assert!(flagged.is_dm_paused());

            assert_eq!(system_reports_about(&db, &author.id).await, 1);
            let report = db.fetch_report(&guard.report_id).await.unwrap();
            assert_eq!(report.author_id, SYSTEM_USER_ID);
            match &report.content {
                ReportedContent::User { message_id, .. } => {
                    assert!(message_id.is_none(), "no message is attached")
                }
                content => panic!("expected a user report, got {content:?}"),
            }
            assert!(
                report
                    .additional_context
                    .contains("10 distinct non-friends"),
                "{}",
                report.additional_context
            );
            for peer in &peers {
                assert!(
                    !report.additional_context.contains(peer.as_str()),
                    "no recipient is named: {}",
                    report.additional_context
                );
            }
            assert_eq!(out_count(&author.id).await, 0, "the window is forgotten");

            // The flagged author (as the route loads it) is not counted again
            fan_out(
                &db,
                &cfg,
                &author_reloaded(&db, &author).await,
                &strangers(10),
            )
            .await;
            assert_eq!(out_count(&author.id).await, 0);

            // A stale copy of the author passes the short-circuit, but the
            // claim refuses a second guard, so no second report
            fan_out(&db, &cfg, &author, &strangers(10)).await;

            assert_eq!(system_reports_about(&db, &author.id).await, 1);
            assert_eq!(
                db.fetch_user(&author.id).await.unwrap().dm_guard,
                Some(guard)
            );
        })
    }

    /// Requires Redis (local default URI)
    #[test]
    fn e2ee_fanout_new_account_threshold_is_five() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = fanout_pausing();

            // Thirteen days old: still new
            let new = stored_user_aged(&db, 13).await;
            let peers = strangers(5);
            fan_out(&db, &cfg, &new, &peers[..4]).await;
            assert_not_flagged(&db, &new, "four strangers are below five").await;

            fan_out(&db, &cfg, &new, &peers[4..]).await;
            let guard = fanout_guard(&db, &new, "the fifth stranger flags a new account").await;
            assert_eq!(guard.recipients, 5);
            assert_eq!(guard.fingerprint, E2EE_FANOUT_FINGERPRINT);
            assert_eq!(system_reports_about(&db, &new.id).await, 1);

            // Fifteen days old: the threshold of ten applies
            let older = stored_user_aged(&db, 15).await;
            fan_out(&db, &cfg, &older, &strangers(5)).await;
            assert_eq!(out_count(&older.id).await, 5);
            assert_not_flagged(&db, &older, "an older account needs ten").await;
        })
    }

    /// Requires Redis (local default URI)
    #[test]
    fn e2ee_fanout_skips_friends_co_members_staff_self_and_prior_writers() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = fanout_pausing();

            let friend = Ulid::new().to_string();
            let author = user(&[&friend]);
            db.insert_user(&author).await.unwrap();

            let co_member = Ulid::new().to_string();
            group_with(&db, &author.id, std::slice::from_ref(&co_member)).await;

            let mut staff = user(&[]);
            staff.privileged = true;
            db.insert_user(&staff).await.unwrap();

            // Someone who wrote to the author first
            let writer = stored_user_aged(&db, 0).await;
            fan_out(&db, &cfg, &writer, std::slice::from_ref(&author.id)).await;

            let peers = strangers(4);
            let mut recipients = peers.clone();
            recipients.extend([
                friend.clone(),
                co_member.clone(),
                staff.id.clone(),
                author.id.clone(),
                writer.id.clone(),
            ]);
            fan_out(&db, &cfg, &author, &recipients).await;

            assert_eq!(out_count(&author.id).await, 4, "only the strangers count");
            assert_not_flagged(&db, &author, "four strangers are below five").await;

            // Friend and co-member pairs are never recorded, the author never
            // records itself, and a stranger is recorded
            assert!(!in_contains(&friend, &author.id).await);
            assert!(!in_contains(&co_member, &author.id).await);
            assert!(!in_contains(&author.id, &author.id).await);
            assert!(!out_members(&author.id, now_ms()).await.contains(&author.id));
            assert!(in_contains(&peers[0], &author.id).await);

            // One more stranger reaches the new-account threshold
            fan_out(&db, &cfg, &author, &strangers(1)).await;
            let guard = fanout_guard(&db, &author, "five strangers flag").await;
            assert_eq!(guard.recipients, 5);
        })
    }

    /// Requires Redis (local default URI)
    #[test]
    fn e2ee_fanout_never_counts_a_staff_author() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let mut staff = user(&[]);
            staff.privileged = true;
            db.insert_user(&staff).await.unwrap();

            let peers = strangers(12);
            fan_out(&db, &fanout_pausing(), &staff, &peers).await;

            assert_eq!(out_count(&staff.id).await, 0);
            assert_not_flagged(&db, &staff, "staff are never counted").await;

            // Their writes are still remembered: a reply to staff is a reply
            assert!(in_contains(&peers[0], &staff.id).await);
        })
    }

    /// Requires Redis (local default URI)
    #[test]
    fn e2ee_fanout_reply_removes_the_peer() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = fanout_pausing();
            let author = stored_user_aged(&db, 0).await;

            let peers = strangers(4);
            fan_out(&db, &cfg, &author, &peers).await;
            assert_eq!(out_count(&author.id).await, 4);

            // The first stranger writes back
            let replier = User {
                id: peers[0].clone(),
                ..user(&[])
            };
            fan_out(&db, &cfg, &replier, std::slice::from_ref(&author.id)).await;

            // The reply is remembered on the author's side (applied lazily,
            // at the author's next count), and is not fan-out of its own
            assert!(in_contains(&author.id, &replier.id).await);
            assert_eq!(
                out_count(&replier.id).await,
                0,
                "writing back to someone who wrote first is not fan-out"
            );

            // Writing to the replier again never counts. One new stranger
            // makes five in the window, and the re-check drops the replier:
            // four, below five
            let mut recipients = vec![replier.id.clone()];
            recipients.extend(strangers(1));
            fan_out(&db, &cfg, &author, &recipients).await;

            let counted = out_members(&author.id, now_ms()).await;
            assert!(
                !counted.contains(&replier.id),
                "the reply removed that peer"
            );
            assert_eq!(counted.len(), 4);
            assert_not_flagged(&db, &author, "the replier no longer counts").await;
        })
    }

    /// Five puppets write to the victim in plaintext; the victim answers each
    /// with an encrypted DM, and writes to one silent stranger. Requires Redis
    /// (local default URI).
    #[test]
    fn e2ee_fanout_plaintext_replies_count() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = fanout_pausing();
            let victim = stored_user_aged(&db, 0).await;

            let puppets = strangers(5);
            for puppet in &puppets {
                plaintext_reply(&db, &victim.id, puppet).await;
            }
            let mut recipients = puppets.clone();
            recipients.extend(strangers(1));
            fan_out(&db, &cfg, &victim, &recipients).await;

            // Exactly the silent stranger: a swallowed failure would count 0
            assert_eq!(out_count(&victim.id).await, 1);
            assert_not_flagged(&db, &victim, "answering people who wrote first").await;
        })
    }

    /// The puppets delete their plaintext messages after the victim answered;
    /// the victim writes to them again. Their replies were remembered, so
    /// they still never count. Requires Redis (local default URI).
    #[test]
    fn e2ee_fanout_deleted_plaintext_is_still_a_reply() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = fanout_pausing();
            let victim = stored_user_aged(&db, 0).await;

            let puppets = strangers(5);
            let mut replies = Vec::new();
            for puppet in &puppets {
                replies.push(plaintext_reply(&db, &victim.id, puppet).await);
            }
            let mut recipients = puppets.clone();
            recipients.extend(strangers(1));
            fan_out(&db, &cfg, &victim, &recipients).await;
            assert_eq!(out_count(&victim.id).await, 1);
            for puppet in &puppets {
                assert!(in_contains(&victim.id, puppet).await, "remembered");
            }

            for reply in &replies {
                db.delete_message(reply).await.unwrap();
            }
            fan_out(&db, &cfg, &victim, &puppets).await;

            assert_eq!(out_count(&victim.id).await, 1);
            assert_not_flagged(&db, &victim, "deleted replies are still replies").await;
        })
    }

    /// Twelve strangers, the last three of whom wrote in plaintext: only the
    /// first ten are checked on the send, so two plaintext writers are
    /// counted and the re-check at the threshold has to catch them. Through
    /// the inner observer, so the order is fixed. Requires Redis (local
    /// default URI).
    #[test]
    fn e2ee_fanout_recheck_catches_plaintext_writers_past_the_first_ten() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = fanout_pausing();
            // Threshold ten
            let author = stored_user_aged(&db, 30).await;

            let silent = strangers(9);
            let writers = strangers(3);
            for writer in &writers {
                plaintext_reply(&db, &author.id, writer).await;
            }
            let mut recipients = silent.clone();
            recipients.extend(writers.iter().cloned());
            fan_out_at(&db, &cfg, &author, &recipients, now_ms()).await;

            assert_not_flagged(&db, &author, "only nine stayed silent").await;
            let counted = out_members(&author.id, now_ms()).await;
            assert!(
                counted.len() <= 10,
                "the re-check dropped at least one: {}",
                counted.len()
            );
            assert!(silent.iter().all(|peer| counted.contains(peer)));
        })
    }

    /// Two report-only crossings at the same time file one report. Requires
    /// Redis (local default URI).
    #[test]
    fn e2ee_fanout_concurrent_report_only_crossings_file_one_report() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = fanout_on();
            let author = stored_user_aged(&db, 0).await;

            // Each batch alone reaches the new-account threshold of five
            let (first, second) = (strangers(5), strangers(5));
            futures::join!(
                fan_out(&db, &cfg, &author, &first),
                fan_out(&db, &cfg, &author, &second)
            );

            assert_eq!(system_reports_about(&db, &author.id).await, 1);
            assert!(db.fetch_user(&author.id).await.unwrap().dm_guard.is_none());
        })
    }

    /// A plaintext reply that arrives after the stranger was counted is
    /// caught by the re-check at the threshold. Requires Redis (local default
    /// URI).
    #[test]
    fn e2ee_fanout_recheck_catches_a_later_plaintext_reply() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = fanout_pausing();
            let author = stored_user_aged(&db, 0).await;

            let peers = strangers(5);
            fan_out(&db, &cfg, &author, &peers[..4]).await;
            assert_eq!(out_count(&author.id).await, 4);

            plaintext_reply(&db, &author.id, &peers[0]).await;
            fan_out(&db, &cfg, &author, &peers[4..]).await;

            assert_eq!(out_count(&author.id).await, 4, "the replier was dropped");
            assert_not_flagged(&db, &author, "only four strangers stayed silent").await;
            assert!(
                in_contains(&author.id, &peers[0]).await,
                "the re-check remembers the plaintext writer"
            );
        })
    }

    /// Five strangers reply after being counted, then ten silent ones make
    /// fifteen in the window: the in-memory checks drop all five repliers
    /// before the bounded checks, so this crossing flags, counting ten.
    /// Requires Redis (local default URI).
    #[test]
    fn e2ee_fanout_recheck_drops_every_replier_before_the_bounded_checks() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = fanout_pausing();
            // Threshold ten
            let author = stored_user_aged(&db, 30).await;

            let repliers = strangers(5);
            let silent = strangers(10);
            fan_out(&db, &cfg, &author, &repliers).await;
            fan_out(&db, &cfg, &author, &silent[..4]).await;
            assert_not_flagged(&db, &author, "nine strangers are below ten").await;

            for replier in &repliers {
                let replier = User {
                    id: replier.clone(),
                    ..user(&[])
                };
                fan_out(&db, &cfg, &replier, std::slice::from_ref(&author.id)).await;
            }

            // Fifteen in the window, five of whom replied
            fan_out(&db, &cfg, &author, &silent[4..]).await;

            let guard = fanout_guard(&db, &author, "ten silent strangers flag").await;
            assert_eq!(guard.recipients, 10);
            let report = db.fetch_report(&guard.report_id).await.unwrap();
            assert!(
                report.additional_context.contains("DMs to 10 distinct"),
                "{}",
                report.additional_context
            );
            assert!(!report.additional_context.contains("at least"));
        })
    }

    /// The request carries nothing that tells an automatic envelope (a
    /// downgrade notice resent on every connect, a group control) from a
    /// typed one without reading content, so the bound is structural:
    /// repeats to one recipient count once, and group controls go to
    /// co-members, who never count. Requires Redis (local default URI).
    #[test]
    fn e2ee_fanout_automatic_envelopes_add_nothing() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = fanout_pausing();
            let author = stored_user_aged(&db, 0).await;

            let peer = strangers(1);
            for _ in 0..10 {
                fan_out(&db, &cfg, &author, &peer).await;
            }
            assert_eq!(
                out_count(&author.id).await,
                1,
                "one recipient, counted once"
            );

            let members = strangers(6);
            group_with(&db, &author.id, &members).await;
            for _ in 0..5 {
                fan_out(&db, &cfg, &author, &members).await;
            }
            assert_eq!(out_count(&author.id).await, 1, "co-members never count");

            assert_not_flagged(&db, &author, "automatic envelopes add nothing").await;
        })
    }

    /// Requires Redis (local default URI), to prove nothing was written
    #[test]
    fn e2ee_fanout_disabled_by_default_writes_nothing() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let author = stored_user_aged(&db, 0).await;
            let peers = strangers(12);

            assert!(!AntispamFeatures::default().e2ee_fanout_enabled);
            fan_out(&db, &AntispamFeatures::default(), &author, &peers).await;
            // The copy-paste detector on does not switch the signal on
            fan_out(&db, &enabled(), &author, &peers).await;

            assert!(!any_key(&author.id).await);
            for peer in &peers {
                assert!(!any_key(peer).await);
            }
            assert_not_flagged(&db, &author, "the signal is off by default").await;
        })
    }

    /// Requires Redis (local default URI), to prove nothing was written
    #[test]
    fn e2ee_fanout_needs_dm_dupe_enabled() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let author = stored_user_aged(&db, 0).await;
            let peers = strangers(12);

            let cfg = AntispamFeatures {
                dm_dupe_enabled: false,
                ..fanout_pausing()
            };
            fan_out(&db, &cfg, &author, &peers).await;

            assert!(!any_key(&author.id).await);
            for peer in &peers {
                assert!(!any_key(peer).await);
            }
            assert_not_flagged(&db, &author, "the kill switch holds the signal off").await;
        })
    }

    /// Report only takes no DM guard, so a later copy-paste flag still
    /// pauses. Requires Redis (local default URI).
    #[test]
    fn e2ee_fanout_report_only_leaves_the_copy_paste_detector_live() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = fanout_on();
            assert!(!cfg.e2ee_fanout_pause, "report only by default");
            let author = stored_user_aged(&db, 0).await;

            fan_out(&db, &cfg, &author, &strangers(5)).await;

            assert_eq!(system_reports_about(&db, &author.id).await, 1);
            assert!(
                db.fetch_user(&author.id).await.unwrap().dm_guard.is_none(),
                "report only takes no guard"
            );
            let reports = db.fetch_reports(None).await.unwrap();
            let report = reports
                .iter()
                .find(|report| {
                    matches!(&report.content, ReportedContent::User { id, .. } if id == &author.id)
                })
                .expect("the report");
            assert!(
                report.additional_context.contains("nothing was paused"),
                "{}",
                report.additional_context
            );

            // The copy-paste detector still flags and pauses the author
            send_to_all(&db, &cfg, &author, &strangers(3), TIFFANY).await;
            let guard = db
                .fetch_user(&author.id)
                .await
                .unwrap()
                .dm_guard
                .expect("the copy-paste detector flags");
            assert!(guard.paused);
            assert_eq!(Some(guard.fingerprint), fp(TIFFANY));
            assert_eq!(system_reports_about(&db, &author.id).await, 2);
        })
    }

    /// Requires Redis (local default URI)
    #[test]
    fn e2ee_fanout_report_only_files_once_per_window() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = fanout_on();
            let author = stored_user_aged(&db, 0).await;

            fan_out(&db, &cfg, &author, &strangers(5)).await;
            assert_eq!(system_reports_about(&db, &author.id).await, 1);

            let reported_ttl = ttl(&e2ee_fanout_reported_key(&author.id)).await;
            assert!(
                reported_ttl > 0 && reported_ttl <= 24 * 3600,
                "{reported_ttl}"
            );

            // A second crossing inside the window files nothing more
            fan_out(&db, &cfg, &author, &strangers(5)).await;
            assert_eq!(system_reports_about(&db, &author.id).await, 1);
            assert_eq!(out_count(&author.id).await, 0, "and starts over");
        })
    }

    /// The bucket arithmetic: a bucket is read exactly as long as its period
    /// lasts and expires as the last reader passes, so a member outlives the
    /// window by at most an hour and the reply memory by at most a day
    #[test]
    fn e2ee_fanout_buckets_bound_retention() {
        let spans = Spans::of(&AntispamFeatures::default());
        assert_eq!((spans.window_hours, spans.memory_days), (24, 30));

        let start = 1_800_000_000_000_i64;
        for offset in [
            0,
            1,
            59 * 60_000,
            HOUR_MS - 1,
            DAY_MS - 1,
            7 * DAY_MS + 12_345,
        ] {
            let now = start + offset;
            let now_secs = now / 1000;

            let hour = e2ee_fanout_hour(now);
            assert!(spans.out_hours(hour + 24).contains(&hour));
            assert!(!spans.out_hours(hour + 25).contains(&hour));
            assert_eq!(spans.out_expire_at(hour), (hour + 25) * 3600);
            let out_life = spans.out_expire_at(hour) - now_secs;
            assert!(out_life > 24 * 3600 && out_life <= 25 * 3600, "{out_life}");

            let day = e2ee_fanout_day(now);
            assert!(spans.in_days(day + 30).contains(&day));
            assert!(!spans.in_days(day + 31).contains(&day));
            assert_eq!(spans.in_expire_at(day), (day + 31) * 86_400);
            let in_life = spans.in_expire_at(day) - now_secs;
            assert!(in_life > 30 * 86_400 && in_life <= 31 * 86_400, "{in_life}");
        }

        // Misconfigured spans are clamped
        let clamped = Spans::of(&AntispamFeatures {
            e2ee_fanout_window_hours: 0,
            e2ee_fanout_reply_memory_days: 100_000,
            ..Default::default()
        });
        assert_eq!((clamped.window_hours, clamped.memory_days), (1, 90));
        let clamped = Spans::of(&AntispamFeatures {
            e2ee_fanout_window_hours: 100_000,
            e2ee_fanout_reply_memory_days: 0,
            ..Default::default()
        });
        assert_eq!((clamped.window_hours, clamped.memory_days), (48, 1));
    }

    /// Requires Redis (local default URI)
    #[test]
    fn e2ee_fanout_keys_expire_within_the_bound() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            for (hours, days) in [(24, 30), (2, 3), (0, 0), (100_000, 100_000)] {
                let cfg = AntispamFeatures {
                    e2ee_fanout_window_hours: hours,
                    e2ee_fanout_reply_memory_days: days,
                    ..fanout_on()
                };
                let spans = Spans::of(&cfg);
                let window = spans.window_hours as i64 * 3600;
                let memory = spans.memory_days as i64 * 86_400;

                let author = stored_user_aged(&db, 0).await;
                let peer = strangers(1);
                let now = now_ms();
                fan_out_at(&db, &cfg, &author, &peer, now).await;

                let out_ttl = ttl(&e2ee_fanout_out_key(&author.id, e2ee_fanout_hour(now))).await;
                assert!(
                    out_ttl >= window - 2 && out_ttl <= window + 3600,
                    "{hours}h: {out_ttl}"
                );
                let in_ttl = ttl(&e2ee_fanout_in_key(&peer[0], e2ee_fanout_day(now))).await;
                assert!(
                    in_ttl >= memory - 2 && in_ttl <= memory + 86_400,
                    "{days}d: {in_ttl}"
                );
            }
        })
    }

    /// A writer recorded exactly `memory` days ago still counts as a reply;
    /// one day older does not. Both lookups: a membership test per stranger
    /// (few strangers) and one union (more than `UNION_ABOVE`). Requires
    /// Redis (local default URI).
    #[test]
    fn e2ee_fanout_reply_memory_edge() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = fanout_on();
            for fillers in [0, UNION_ABOVE] {
                // Old enough for the threshold of ten, so nothing is flagged
                let author = stored_user_aged(&db, 30).await;
                let now = now_ms();
                let day = e2ee_fanout_day(now);

                let peers = strangers(2);
                sadd_for_a_minute(&e2ee_fanout_in_key(&author.id, day - 30), &peers[0]).await;
                sadd_for_a_minute(&e2ee_fanout_in_key(&author.id, day - 31), &peers[1]).await;

                let mut recipients = peers.clone();
                recipients.extend(strangers(fillers));
                fan_out_at(&db, &cfg, &author, &recipients, now).await;

                let counted = out_members(&author.id, now).await;
                assert!(!counted.contains(&peers[0]), "inside the memory");
                assert!(counted.contains(&peers[1]), "past the memory");
                assert_eq!(counted.len(), 1 + fillers);
            }
        })
    }

    /// A stranger written to exactly `window` hours ago still counts; one
    /// hour older does not. Requires Redis (local default URI).
    #[test]
    fn e2ee_fanout_window_edge() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = fanout_pausing();
            let author = stored_user_aged(&db, 0).await;
            let now = now_ms();
            let hour = e2ee_fanout_hour(now);

            let old = strangers(2);
            sadd_for_a_minute(&e2ee_fanout_out_key(&author.id, hour - 24), &old[0]).await;
            sadd_for_a_minute(&e2ee_fanout_out_key(&author.id, hour - 25), &old[1]).await;

            // Three new strangers plus the one inside the window: four
            fan_out_at(&db, &cfg, &author, &strangers(3), now).await;
            assert_not_flagged(&db, &author, "the older stranger is past the window").await;

            fan_out_at(&db, &cfg, &author, &strangers(1), now).await;
            let guard = fanout_guard(&db, &author, "five inside the window").await;
            assert_eq!(guard.recipients, 5);
        })
    }

    /// Requires Redis (local default URI)
    #[test]
    fn forget_e2ee_fanout_deletes_every_key_and_cleans_writers() {
        rt().block_on(async {
            let db = Database::Reference(Default::default());
            let cfg = fanout_on();
            let author = stored_user_aged(&db, 0).await;
            let writer = stored_user_aged(&db, 0).await;
            let peer = strangers(1);

            fan_out(&db, &cfg, &author, &peer).await;
            fan_out(&db, &cfg, &writer, std::slice::from_ref(&author.id)).await;
            sadd_for_a_minute(&e2ee_fanout_reported_key(&author.id), "1").await;
            assert_eq!(out_count(&author.id).await, 1);
            assert!(in_contains(&author.id, &writer.id).await);
            assert!(out_members(&writer.id, now_ms()).await.contains(&author.id));

            forget_e2ee_fanout(&cfg, &author.id).await;

            assert!(!any_key(&author.id).await, "every key of the account");
            assert!(
                !out_members(&writer.id, now_ms()).await.contains(&author.id),
                "the id is gone from its writers' windows"
            );
            // Other users' reply memory is left to its own expiry
            assert!(in_contains(&peer[0], &author.id).await);
        })
    }

    /// The call at the start of `code`, up to its matching closing parenthesis
    fn balanced_call(code: &str) -> &str {
        let open = code.find('(').expect("an opening parenthesis");
        let mut depth = 0;
        for (at, character) in code[open..].char_indices() {
            match character {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return &code[..open + at + 1];
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced call: {code}")
    }

    /// E10 at the source: the observer takes recipient ids (no envelope
    /// type), the signal reads no envelope field, no log line or Sentry
    /// message in it formats an id, and no name in it reads as the
    /// Encrypted-only setting
    #[test]
    fn e2ee_fanout_reads_recipient_ids_only_and_logs_no_id() {
        let source = include_str!("antispam.rs");
        let start = source
            .find("// ---- E2EE fan-out signal ----")
            .expect("section start");
        let end = start
            + source[start..]
                .find("// ---- end of the E2EE fan-out signal ----")
                .expect("section end");
        let section = &source[start..end];

        let setting_name = concat!("e2ee", "_only");
        let before_tests = &source[..source.find("#[cfg(test)]").expect("tests")];
        assert!(!before_tests.contains(setting_name));

        let signature_at = section
            .find("pub async fn observe_e2ee_fanout(")
            .expect("the observer");
        let signature_len = section[signature_at..].find('{').expect("its body");
        let signature: String = section[signature_at..signature_at + signature_len]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        assert_eq!(
            signature,
            "pubasyncfnobserve_e2ee_fanout(db:&Database,cfg:&AntispamFeatures,author:&User,recipient_ids:&HashSet<String>,)"
        );

        // Code only: the comments above describe what is NOT read
        let code = section
            .lines()
            .map(|line| line.split("//").next().unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in ["Envelope", "envelope", "ciphertext", "sequence"] {
            assert!(
                !code.contains(forbidden),
                "the fan-out signal names `{forbidden}`"
            );
        }

        let mut calls = 0;
        for log_call in ["warn!(", "error!(", "info!(", "debug!(", "capture("] {
            let mut rest = code.as_str();
            while let Some(at) = rest.find(log_call) {
                let call = balanced_call(&rest[at..]);
                for forbidden in [".id", "author", "recipient", "peer", "stranger", "user_id"] {
                    assert!(!call.contains(forbidden), "`{call}` logs `{forbidden}`");
                }
                calls += 1;
                rest = &rest[at + log_call.len()..];
            }
        }
        assert!(calls >= 5, "every log call was looked at ({calls})");
    }
}
