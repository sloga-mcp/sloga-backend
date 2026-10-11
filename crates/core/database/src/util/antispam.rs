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

use iso8601_timestamp::{Duration, Timestamp};
use once_cell::sync::Lazy;
use redis_kiss::{
    get_connection,
    redis::{cmd, Pipeline, RedisError},
};
use regex::Regex;
use revolt_config::AntispamFeatures;
use revolt_models::v0::Embed;
use revolt_result::Result;
use sha2::{Digest, Sha256};
use ulid::Ulid;

use crate::{
    Database, DmGuard, Message, MessageFilter, MessageQuery, MessageTimePeriod, RelationshipStatus,
    Report, User,
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
}
