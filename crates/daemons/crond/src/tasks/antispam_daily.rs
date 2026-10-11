//! Daily anti-spam scan: the staff alert for new accounts that DM strangers
//! the same text.
//!
//! The live detector (`revolt_database::util::antispam`) watches a 24 hour
//! window per send. This scan looks back over a new account's whole life
//! (`daily_account_age_days`) instead, and catches a spammer who stays under
//! the live threshold on any one day. An account is flagged when it has
//! opened enough DMs with non-friends, sent one text into several of them,
//! got almost no replies and posted next to nothing anywhere else. Each
//! suspect gets one automated staff report (`Report::create_system`). Nothing
//! is paused: the scan only tells staff.
//!
//! Only server-readable messages are read, fingerprinted exactly as the live
//! detector does. End-to-end encrypted DMs never reach the messages
//! collection, so an account that only sends E2EE DMs is invisible here (a
//! known gap, listed in the followups).
//!
//! crond has no leader election. The day's run is claimed with
//! `SET antispam_daily:{day} 1 NX EX 129600`, and every report with
//! `SET antispam_reported:{user} 1 NX EX {cooldown}`, so two replicas never
//! report the same account twice.
//!
//! Kill switch: `features.antispam.daily_enabled`, read on every hourly
//! tick. The config is frozen into the process at first access, so flipping
//! it takes a crond restart.

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use log::{error, info, warn};
use redis_kiss::{
    get_connection,
    redis::{ExistenceCheck, SetExpiry, SetOptions},
    AsyncCommands,
};
use revolt_config::{capture_error, AntispamFeatures};
use revolt_database::{
    util::antispam::{dm_text, fingerprint},
    Channel, Database, MessageFilter, MessageQuery, MessageTimePeriod, RelationshipStatus, Report,
    User, AMQP, SYSTEM_USER_ID,
};
use revolt_models::v0::{MessageSort, ReportedContent};
use revolt_result::{create_error, Result, ToRevoltError};
use tokio::time::sleep;
use ulid::Ulid;

/// Time between ticks: the scan runs within an hour of its configured hour
const TICK: Duration = Duration::from_secs(60 * 60);

const DAY_MS: u64 = 86_400_000;
const HOUR_MS: u64 = 3_600_000;

/// Lifetime of the day claim: longer than a day, so it outlives the day it
/// names and no replica runs that day again
const DAY_CLAIM_TTL_SECS: usize = 129_600;

/// Bounds on the configured look-back and cooldown, so the arithmetic can
/// never overflow and a typo cannot scan every account ever created
const MAX_ACCOUNT_AGE_DAYS: u64 = 365;
const MAX_COOLDOWN_DAYS: u64 = 3650;

/// Non-friend DMs read per account (the newest ones)
const MAX_DMS_SCANNED: usize = 50;

/// Messages read per DM (the newest ones)
const MAX_MESSAGES_PER_DM: i64 = 50;

/// Message ids handed to the report (it snapshots the first few that exist)
const MAX_SAMPLE_MESSAGES: usize = 10;

/// Run the scan once a day, at or after `daily_run_hour_utc`.
pub async fn task(db: Database, _: AMQP) -> Result<()> {
    loop {
        let cfg = revolt_config::config().await.features.antispam.clone();
        if cfg.daily_enabled {
            tick(&db, now_ms(), &cfg).await;
        }

        sleep(TICK).await;
    }
}

fn now_ms() -> u64 {
    revolt_database::now_ms().max(0) as u64
}

/// The UTC day (days since the epoch) whose scan is due at `now_ms`, or
/// `None` before the run hour. Hours past 23 mean 23.
fn due_day(now_ms: u64, run_hour_utc: u64) -> Option<u64> {
    let hour = (now_ms % DAY_MS) / HOUR_MS;
    (hour >= run_hour_utc.min(23)).then_some(now_ms / DAY_MS)
}

/// One hourly tick: claim today's scan and run it if this replica won
async fn tick(db: &Database, now_ms: u64, cfg: &AntispamFeatures) {
    let Some(day) = due_day(now_ms, cfg.daily_run_hour_utc) else {
        return;
    };

    match claim(&day_claim_key(day), DAY_CLAIM_TTL_SECS).await {
        Ok(true) => {}
        // Already run today, here or on another replica
        Ok(false) => return,
        Err(err) => {
            warn!("Daily anti-spam scan skipped this hour, could not claim day {day}: {err:?}");
            return;
        }
    }

    match run_once(db, now_ms, cfg).await {
        Ok(filed) => info!("Daily anti-spam scan filed {filed} report(s)"),
        Err(err) => {
            error!("Daily anti-spam scan failed, retrying next hour: {err:?}");
            capture_error(&err);

            // Free the day so a later tick runs it again; reports already
            // filed are not repeated (see the dedup in `run_once`)
            if let Err(err) = release(&day_claim_key(day)).await {
                warn!("Daily anti-spam scan could not release day {day}: {err:?}");
            }
        }
    }
}

fn day_claim_key(day: u64) -> String {
    format!("antispam_daily:{day}")
}

fn reported_claim_key(user_id: &str) -> String {
    format!("antispam_reported:{user_id}")
}

/// `SET {key} 1 NX EX {ttl_secs}`: `true` if this call set it
async fn claim(key: &str, ttl_secs: usize) -> Result<bool> {
    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?;

    conn.set_options(
        key,
        1,
        SetOptions::default()
            .conditional_set(ExistenceCheck::NX)
            .with_expiration(SetExpiry::EX(ttl_secs)),
    )
    .await
    .to_internal_error()
}

async fn release(key: &str) -> Result<()> {
    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?;

    conn.del(key).await.to_internal_error()
}

/// What the scan found on one account
struct Finding {
    /// Non-friend DMs the account has (since the cutoff)
    nonfriend: usize,
    /// How many of them were read (the newest, at most `MAX_DMS_SCANNED`)
    scanned: usize,
    /// How many of those got a reply
    replied: usize,
    /// Most read DMs that received one same text
    top: usize,
    /// Messages sent outside the account's DMs
    public: u64,
    /// Ids of the account's messages carrying that text, newest first
    sample_ids: Vec<String>,
}

/// Scan accounts created within `daily_account_age_days` of `now_ms` and
/// file one automated report per suspect, at most
/// `daily_max_reports_per_run`. Returns how many reports were filed.
///
/// Skips an account that already has a system-authored report about it,
/// that holds a DM guard (the live detector already reported it), or whose
/// `antispam_reported:{user}` cooldown is taken or cannot be checked. Never
/// pauses anything.
pub async fn run_once(db: &Database, now_ms: u64, cfg: &AntispamFeatures) -> Result<usize> {
    let age_days = cfg.daily_account_age_days.clamp(1, MAX_ACCOUNT_AGE_DAYS);
    let cutoff = Ulid::from_parts(now_ms.saturating_sub(age_days * DAY_MS), 0).to_string();

    // Not bots, not privileged, no flags, no DM guard
    let mut users = db.fetch_users_created_since(&cutoff).await?;
    if users.is_empty() {
        return Ok(0);
    }

    // Oldest accounts first, so the per-run cap is applied in a stable order
    users.sort_by(|a, b| a.id.cmp(&b.id));

    // Every DM of a new account is newer than the account, so the DMs
    // created since the cutoff are all of them: (channel, peer) per member
    let candidates: HashSet<&str> = users.iter().map(|user| user.id.as_str()).collect();
    let mut dms_by_user: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for channel in db.fetch_direct_messages_created_since(&cutoff).await? {
        let Channel::DirectMessage { id, recipients, .. } = channel else {
            continue;
        };

        for member in &recipients {
            if !candidates.contains(member.as_str()) {
                continue;
            }

            if let Some(peer) = recipients.iter().find(|recipient| *recipient != member) {
                dms_by_user
                    .entry(member.clone())
                    .or_default()
                    .push((id.clone(), peer.clone()));
            }
        }
    }

    // One read of the queue per run: anyone the server already reported
    let already_reported: HashSet<String> = db
        .fetch_reports(None)
        .await?
        .into_iter()
        .filter(|report| report.author_id == SYSTEM_USER_ID)
        .filter_map(|report| match report.content {
            ReportedContent::User { id, .. } => Some(id),
            _ => None,
        })
        .collect();

    let cooldown_days = cfg.daily_report_cooldown_days.clamp(1, MAX_COOLDOWN_DAYS);
    let cooldown_secs = (cooldown_days * 86_400) as usize;

    let mut filed = 0;
    for user in &users {
        if filed >= cfg.daily_max_reports_per_run {
            info!(
                "Daily anti-spam scan stopped at its cap of {} report(s)",
                cfg.daily_max_reports_per_run
            );
            break;
        }

        if already_reported.contains(&user.id) {
            continue;
        }

        let Some(dms) = dms_by_user.get(&user.id) else {
            continue;
        };

        let finding = match assess(db, cfg, user, dms, &cutoff).await {
            Ok(Some(finding)) => finding,
            Ok(None) => continue,
            Err(err) => {
                error!("Daily anti-spam scan could not assess {}: {err:?}", user.id);
                capture_error(&err);
                continue;
            }
        };

        // The cooldown claim also stops a second replica (or a retried run)
        // reporting the same account. If it cannot be checked, skip rather
        // than risk a duplicate: the account is looked at again tomorrow.
        let cooldown_key = reported_claim_key(&user.id);
        match claim(&cooldown_key, cooldown_secs).await {
            Ok(true) => {}
            Ok(false) => continue,
            Err(err) => {
                warn!(
                    "Daily anti-spam scan skipped {}, could not claim its cooldown: {err:?}",
                    user.id
                );
                continue;
            }
        }

        let additional_context = format!(
            "Daily scan: {} non-friend DMs in {age_days}d, same text to {}, replies {}/{}, public msgs {}.",
            finding.nonfriend, finding.top, finding.replied, finding.scanned, finding.public
        );

        match Report::create_system(
            db,
            Ulid::new().to_string(),
            user,
            &finding.sample_ids,
            additional_context,
        )
        .await
        {
            Ok(report) => {
                info!(
                    "Daily anti-spam scan reported {} (report {})",
                    user.id, report.id
                );
                filed += 1;
            }
            Err(err) => {
                error!("Daily anti-spam scan could not report {}: {err:?}", user.id);
                capture_error(&err);

                // No report stands, so let tomorrow's scan try again
                if let Err(err) = release(&cooldown_key).await {
                    warn!(
                        "Daily anti-spam scan could not release the cooldown of {}: {err:?}",
                        user.id
                    );
                }
            }
        }
    }

    Ok(filed)
}

/// Whether `peer_id` ever wrote in `channel_id`
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

/// Ids of `user_id`'s own Saved Messages channel (none until it is opened).
///
/// Read through `find_direct_messages`, which answers "none" with an empty
/// list on both drivers. `find_saved_messages_channel` cannot tell "none"
/// from a failure (Mongo answers a miss with `InternalError`, and the
/// Reference driver looks the channel up by the user's id, which is never
/// its id), so it would skip every account that never opened its notes.
async fn saved_messages_channels(db: &Database, user_id: &str) -> Result<Vec<String>> {
    Ok(db
        .find_direct_messages(user_id)
        .await?
        .into_iter()
        .filter_map(|channel| match channel {
            Channel::SavedMessages { id, user } if user == user_id => Some(id),
            _ => None,
        })
        .collect())
}

/// Read one account's non-friend DMs and return a finding if it matches the
/// copy-paste pattern: the same text in at least `threshold()` DMs, at most
/// `daily_max_reply_ratio` of the DMs read answered, and at most
/// `daily_max_public_messages` messages anywhere else.
async fn assess(
    db: &Database,
    cfg: &AntispamFeatures,
    user: &User,
    dms: &[(String, String)],
    cutoff: &str,
) -> Result<Option<Finding>> {
    let mut nonfriend: Vec<&(String, String)> = dms
        .iter()
        .filter(|(_, peer)| !matches!(user.relationship_with(peer), RelationshipStatus::Friend))
        .collect();

    if nonfriend.is_empty() || nonfriend.len() < cfg.daily_min_nonfriend_dms {
        return Ok(None);
    }

    // Newest DMs first
    nonfriend.sort_by(|a, b| b.0.cmp(&a.0));
    let scanned = nonfriend.len().min(MAX_DMS_SCANNED);

    // Fingerprint -> (DMs it was sent into, the messages carrying it)
    let mut texts: HashMap<String, (HashSet<&str>, Vec<String>)> = HashMap::new();
    let mut replied = 0;

    for (channel_id, peer_id) in nonfriend.iter().take(MAX_DMS_SCANNED) {
        let messages = db
            .fetch_messages(MessageQuery {
                limit: Some(MAX_MESSAGES_PER_DM),
                filter: MessageFilter {
                    channel: Some(channel_id.clone()),
                    ..Default::default()
                },
                time_period: MessageTimePeriod::Absolute {
                    before: None,
                    after: Some(cutoff.to_string()),
                    sort: Some(MessageSort::Latest),
                },
            })
            .await?;

        let mut peer_wrote = false;
        for message in &messages {
            if &message.author == peer_id {
                peer_wrote = true;
            } else if message.author == user.id {
                // Same fingerprint as the live detector; exempt (short or
                // link-only) texts are ignored
                if let Some(text) = fingerprint(&dm_text(message), cfg.min_chars()) {
                    let (channels, ids) = texts.entry(text).or_default();
                    channels.insert(channel_id.as_str());
                    ids.push(message.id.clone());
                }
            }
        }

        // A reply older than the messages read still counts
        if !peer_wrote && messages.len() as i64 >= MAX_MESSAGES_PER_DM {
            peer_wrote = peer_has_written(db, channel_id, peer_id).await?;
        }

        if peer_wrote {
            replied += 1;
        }
    }

    // The text sent into the most DMs (ties broken by fingerprint, so the
    // pick is stable)
    let Some((_, (channels, mut sample_ids))) = texts.into_iter().max_by(
        |(fingerprint_a, (channels_a, _)), (fingerprint_b, (channels_b, _))| {
            channels_a
                .len()
                .cmp(&channels_b.len())
                .then_with(|| fingerprint_b.cmp(fingerprint_a))
        },
    ) else {
        return Ok(None);
    };

    let top = channels.len();
    if top < cfg.threshold() {
        return Ok(None);
    }

    // `top >= threshold() >= 2`, so at least two DMs were read
    if replied as f64 / scanned as f64 > cfg.daily_max_reply_ratio {
        return Ok(None);
    }

    // Public activity: everything outside the account's DMs and its own
    // Saved Messages (notes to self would otherwise buy a spammer the
    // allowance). Group messages still count; a group needs a friend.
    let mut private_channels: Vec<String> =
        dms.iter().map(|(channel, _)| channel.clone()).collect();
    private_channels.extend(saved_messages_channels(db, &user.id).await?);
    let public = db
        .count_author_messages_since(&user.id, cutoff, &private_channels)
        .await?;
    if public > cfg.daily_max_public_messages {
        return Ok(None);
    }

    sample_ids.sort_by(|a, b| b.cmp(a));
    sample_ids.dedup();
    sample_ids.truncate(MAX_SAMPLE_MESSAGES);

    Ok(Some(Finding {
        nonfriend: nonfriend.len(),
        scanned,
        replied,
        top,
        public,
        sample_ids,
    }))
}

#[cfg(test)]
mod tests {
    use revolt_database::{Message, Relationship};
    use revolt_models::v0::{ReportStatus, UserReportReason};

    use super::*;

    const TIFFANY: &str = "Hi! I love your profile picture, can I use it for an art project for my client? I'll pay you and credit you.";

    /// One runtime for every test here: `redis_kiss` pools connections
    /// globally, and a connection made on one per-test runtime dies with it
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

    fn reference_db() -> Database {
        Database::Reference(Default::default())
    }

    fn enabled() -> AntispamFeatures {
        AntispamFeatures {
            daily_enabled: true,
            ..Default::default()
        }
    }

    fn new_id() -> String {
        Ulid::new().to_string()
    }

    /// An account created `age_days` ago with the given friends
    // `insert_user` is disallowed in favor of `User::create()`, but these
    // tests need bare rows with a chosen id and relations
    #[allow(clippy::disallowed_methods)]
    async fn account(db: &Database, age_days: u64, friends: &[String]) -> User {
        let created = now_ms() - age_days * DAY_MS;
        let id = Ulid::from_parts(created, rand_bits()).to_string();
        let user = User {
            username: format!("u{}", &id[16..]),
            discriminator: "0001".to_string(),
            id,
            relations: Some(
                friends
                    .iter()
                    .map(|friend| Relationship {
                        id: friend.clone(),
                        status: RelationshipStatus::Friend,
                        note: None,
                    })
                    .collect(),
            ),
            ..Default::default()
        };

        db.insert_user(&user).await.unwrap();
        user
    }

    fn rand_bits() -> u128 {
        Ulid::new().random()
    }

    #[allow(clippy::disallowed_methods)]
    async fn dm(db: &Database, a: &str, b: &str) -> String {
        let id = new_id();
        db.insert_channel(&Channel::DirectMessage {
            id: id.clone(),
            active: true,
            recipients: vec![a.to_string(), b.to_string()],
            last_message_id: None,
        })
        .await
        .unwrap();
        id
    }

    #[allow(clippy::disallowed_methods)]
    async fn say(db: &Database, channel: &str, author: &str, content: &str) -> String {
        let id = new_id();
        db.insert_message(&Message {
            id: id.clone(),
            channel: channel.to_string(),
            author: author.to_string(),
            content: Some(content.to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
        id
    }

    /// `count` strangers, each sent `text` by `author` in a new DM; returns
    /// (peer, channel) pairs
    async fn spam(db: &Database, author: &str, text: &str, count: usize) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for _ in 0..count {
            let peer = new_id();
            let channel = dm(db, author, &peer).await;
            say(db, &channel, author, text).await;
            out.push((peer, channel));
        }
        out
    }

    async fn system_reports_about(db: &Database, user_id: &str) -> Vec<Report> {
        db.fetch_reports(None)
            .await
            .unwrap()
            .into_iter()
            .filter(|report| {
                report.author_id == SYSTEM_USER_ID
                    && matches!(&report.content, ReportedContent::User { id, .. } if id == user_id)
            })
            .collect()
    }

    /// Drop a cooldown key a test may have set, so reruns start clean
    async fn forget_cooldown(user_id: &str) {
        let _ = release(&reported_claim_key(user_id)).await;
    }

    #[test]
    fn due_day_waits_for_the_run_hour() {
        let day = 20_000;
        let at = |hour: u64, minute: u64| day * DAY_MS + hour * HOUR_MS + minute * 60_000;

        assert_eq!(due_day(at(13, 59), 14), None);
        assert_eq!(due_day(at(14, 0), 14), Some(day));
        assert_eq!(due_day(at(23, 59), 14), Some(day));
        assert_eq!(due_day(at(0, 0), 0), Some(day));
        // An hour past 23 means 23, so the scan still runs every day
        assert_eq!(due_day(at(22, 59), 99), None);
        assert_eq!(due_day(at(23, 0), 99), Some(day));
    }

    /// The Tiffany pattern: a new account, six strangers, one text, no
    /// replies, nothing public. Reported once, never paused, and a second
    /// run files nothing.
    #[test]
    fn tiffany_pattern_is_reported_once() {
        rt().block_on(async {
            let db = reference_db();
            let tiffany = account(&db, 2, &[]).await;

            // Case, spacing and a zero-width space do not change the text
            let variants = [
                TIFFANY.to_string(),
                TIFFANY.to_uppercase(),
                TIFFANY.replace(' ', "  "),
                TIFFANY.replacen("art", "a\u{200B}rt", 1),
                TIFFANY.to_string(),
                TIFFANY.to_string(),
            ];
            for text in &variants {
                spam(&db, &tiffany.id, text, 1).await;
            }

            assert_eq!(
                run_once(&db, now_ms(), &enabled()).await.unwrap(),
                1,
                "the Tiffany pattern must be reported (needs local Redis)"
            );

            let reports = system_reports_about(&db, &tiffany.id).await;
            assert_eq!(reports.len(), 1);
            let report = &reports[0];
            assert!(matches!(report.status, ReportStatus::Created {}));
            assert!(matches!(
                &report.content,
                ReportedContent::User {
                    report_reason: UserReportReason::SpamAbuse,
                    message_id: Some(_),
                    ..
                }
            ));
            assert_eq!(
                report.additional_context,
                "Daily scan: 6 non-friend DMs in 14d, same text to 6, replies 0/6, public msgs 0."
            );

            // Staff are told; the account is not paused
            assert!(db.fetch_user(&tiffany.id).await.unwrap().dm_guard.is_none());

            assert_eq!(run_once(&db, now_ms(), &enabled()).await.unwrap(), 0);
            assert_eq!(system_reports_about(&db, &tiffany.id).await.len(), 1);

            forget_cooldown(&tiffany.id).await;
        });
    }

    /// The Charity Aviation census pattern: the same long text to friends,
    /// invite and YouTube links to strangers, distinct texts otherwise,
    /// replies coming back, and public activity. Nothing is reported.
    #[test]
    fn charity_aviation_pattern_is_not_reported() {
        rt().block_on(async {
            let db = reference_db();
            let friends: Vec<String> = (0..4).map(|_| new_id()).collect();
            let charity = account(&db, 3, &friends).await;
            let pitch = "Hey! We are planning the next Charity Aviation fundraiser flight, come and help us out this weekend";

            for friend in &friends {
                let channel = dm(&db, &charity.id, friend).await;
                say(&db, &channel, &charity.id, pitch).await;
                say(&db, &channel, friend, "count me in").await;
            }

            let to_strangers = [
                "https://sloga.gg/invite/charityav",
                "join us! https://sloga.gg/invite/charityav",
                "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
                pitch,
                pitch,
                "Thanks for the kind words about the last flight, it really meant a lot to the whole crew",
            ];
            for (index, text) in to_strangers.iter().enumerate() {
                let stranger = new_id();
                let channel = dm(&db, &charity.id, &stranger).await;
                say(&db, &channel, &charity.id, text).await;
                if index % 2 == 0 {
                    say(&db, &channel, &stranger, "sounds great, see you there").await;
                }
            }

            let server_channel = new_id();
            for index in 0..5 {
                say(&db, &server_channel, &charity.id, &format!("update {index}")).await;
            }

            assert_eq!(run_once(&db, now_ms(), &enabled()).await.unwrap(), 0);
            assert!(system_reports_about(&db, &charity.id).await.is_empty());
        });
    }

    /// Friends are never counted: the same text to six friends plus five
    /// strangers sent distinct texts is not a copy-paste pattern
    #[test]
    fn same_text_to_friends_is_not_reported() {
        rt().block_on(async {
            let db = reference_db();
            let friends: Vec<String> = (0..6).map(|_| new_id()).collect();
            let user = account(&db, 1, &friends).await;

            for friend in &friends {
                let channel = dm(&db, &user.id, friend).await;
                say(&db, &channel, &user.id, TIFFANY).await;
            }

            for index in 0..5 {
                spam(
                    &db,
                    &user.id,
                    &format!("{index}: a completely different message for this one person {index}"),
                    1,
                )
                .await;
            }

            assert_eq!(run_once(&db, now_ms(), &enabled()).await.unwrap(), 0);
        });
    }

    /// Two of six strangers wrote back (a third, above the 0.25 ratio)
    #[test]
    fn replies_above_the_ratio_are_not_reported() {
        rt().block_on(async {
            let db = reference_db();
            let user = account(&db, 1, &[]).await;

            let sent = spam(&db, &user.id, TIFFANY, 6).await;
            for (peer, channel) in sent.iter().take(2) {
                say(&db, channel, peer, "who are you?").await;
            }

            assert_eq!(run_once(&db, now_ms(), &enabled()).await.unwrap(), 0);
        });
    }

    /// Public activity above the limit means a participating account
    #[test]
    fn public_activity_above_the_limit_is_not_reported() {
        rt().block_on(async {
            let db = reference_db();
            let user = account(&db, 1, &[]).await;
            spam(&db, &user.id, TIFFANY, 6).await;

            let server_channel = new_id();
            for index in 0..4 {
                say(&db, &server_channel, &user.id, &format!("hello {index}")).await;
            }

            assert_eq!(run_once(&db, now_ms(), &enabled()).await.unwrap(), 0);
        });
    }

    /// Notes to self are not public activity: the Tiffany pattern plus five
    /// messages in the account's own Saved Messages is still reported
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn saved_messages_do_not_count_as_public_activity() {
        rt().block_on(async {
            let db = reference_db();
            let user = account(&db, 1, &[]).await;
            spam(&db, &user.id, TIFFANY, 6).await;

            let saved = new_id();
            db.insert_channel(&Channel::SavedMessages {
                id: saved.clone(),
                user: user.id.clone(),
            })
            .await
            .unwrap();
            for index in 0..5 {
                say(&db, &saved, &user.id, &format!("note to self {index}")).await;
            }

            assert_eq!(
                run_once(&db, now_ms(), &enabled()).await.unwrap(),
                1,
                "Saved Messages must not count as public (needs local Redis)"
            );
            let reports = system_reports_about(&db, &user.id).await;
            assert_eq!(reports.len(), 1);
            assert_eq!(
                reports[0].additional_context,
                "Daily scan: 6 non-friend DMs in 14d, same text to 6, replies 0/6, public msgs 0."
            );

            forget_cooldown(&user.id).await;
        });
    }

    /// The same invite to every stranger is exempt, like `InviteToServer`
    #[test]
    fn link_only_messages_are_not_reported() {
        rt().block_on(async {
            let db = reference_db();
            let user = account(&db, 1, &[]).await;
            spam(&db, &user.id, "join us! https://sloga.gg/invite/abcdef", 8).await;

            assert_eq!(run_once(&db, now_ms(), &enabled()).await.unwrap(), 0);
        });
    }

    /// E2EE DMs leave no messages behind: many stranger DMs with nothing
    /// readable in them are not reported (and never read)
    #[test]
    fn e2ee_only_account_is_not_reported() {
        rt().block_on(async {
            let db = reference_db();
            let user = account(&db, 1, &[]).await;
            for _ in 0..8 {
                dm(&db, &user.id, &new_id()).await;
            }

            assert_eq!(run_once(&db, now_ms(), &enabled()).await.unwrap(), 0);
        });
    }

    /// An account older than the look-back is never scanned
    #[test]
    fn old_account_is_not_reported() {
        rt().block_on(async {
            let db = reference_db();
            let user = account(&db, 30, &[]).await;
            spam(&db, &user.id, TIFFANY, 6).await;

            assert_eq!(run_once(&db, now_ms(), &enabled()).await.unwrap(), 0);
        });
    }

    /// Too few stranger DMs to say anything
    #[test]
    fn below_the_minimum_dms_is_not_reported() {
        rt().block_on(async {
            let db = reference_db();
            let user = account(&db, 1, &[]).await;
            spam(&db, &user.id, TIFFANY, 4).await;

            assert_eq!(run_once(&db, now_ms(), &enabled()).await.unwrap(), 0);
        });
    }

    /// An earlier system report (the live detector's, or any past scan's)
    /// suppresses a new one even with no cooldown key
    #[test]
    fn existing_system_report_suppresses_the_scan() {
        rt().block_on(async {
            let db = reference_db();
            let user = account(&db, 1, &[]).await;
            spam(&db, &user.id, TIFFANY, 6).await;

            db.insert_report(&Report {
                id: new_id(),
                author_id: SYSTEM_USER_ID.to_string(),
                content: ReportedContent::User {
                    id: user.id.clone(),
                    report_reason: UserReportReason::SpamAbuse,
                    message_id: None,
                },
                additional_context: "Automated: earlier".to_string(),
                status: ReportStatus::Rejected {
                    rejection_reason: "false positive".to_string(),
                    closed_at: None,
                },
                notes: String::new(),
            })
            .await
            .unwrap();

            assert_eq!(run_once(&db, now_ms(), &enabled()).await.unwrap(), 0);
            assert_eq!(system_reports_about(&db, &user.id).await.len(), 1);
        });
    }

    /// A held cooldown (another replica, or a recent report on another
    /// database) suppresses the report
    #[test]
    fn held_cooldown_suppresses_the_scan() {
        rt().block_on(async {
            let db = reference_db();
            let user = account(&db, 1, &[]).await;
            spam(&db, &user.id, TIFFANY, 6).await;

            assert!(
                claim(&reported_claim_key(&user.id), 60).await.unwrap(),
                "needs local Redis"
            );

            assert_eq!(run_once(&db, now_ms(), &enabled()).await.unwrap(), 0);
            assert!(system_reports_about(&db, &user.id).await.is_empty());

            forget_cooldown(&user.id).await;
        });
    }

    /// No more than `daily_max_reports_per_run` reports per run
    #[test]
    fn reports_per_run_are_capped() {
        rt().block_on(async {
            let db = reference_db();
            let first = account(&db, 2, &[]).await;
            let second = account(&db, 1, &[]).await;
            spam(&db, &first.id, TIFFANY, 6).await;
            spam(&db, &second.id, TIFFANY, 6).await;

            let cfg = AntispamFeatures {
                daily_max_reports_per_run: 1,
                ..enabled()
            };
            assert_eq!(run_once(&db, now_ms(), &cfg).await.unwrap(), 1);
            // Oldest account first
            assert_eq!(system_reports_about(&db, &first.id).await.len(), 1);
            assert!(system_reports_about(&db, &second.id).await.is_empty());

            forget_cooldown(&first.id).await;
            forget_cooldown(&second.id).await;
        });
    }
}
