use std::collections::{HashMap, HashSet};
use std::time::Duration;

use revolt_database::{iso8601_timestamp::Timestamp, now_ms, Database, PERK_RETENTION_DAYS};
use revolt_models::v0::UserPerks;
use revolt_result::{ErrorType, Result};
use tokio::time::sleep;

use log::info;

/// Message attachments larger than this many bytes are pruned once older than `MAX_AGE`.
const SIZE_THRESHOLD: usize = 20_000_000; // 20 MB
/// How long a large message attachment is retained before it is pruned.
const MAX_AGE: Duration = Duration::from_secs(60 * 60 * 24); // 24 hours
/// Retention for a large attachment whose uploader currently has the upload perk.
const PERK_MAX_AGE: Duration = Duration::from_secs(60 * 60 * 24 * PERK_RETENTION_DAYS as u64);

/// Servers whose message attachments are exempt from pruning (kept indefinitely).
/// - `01KX3JTSZETQ5MQDGEJ3PVAZGJ` = "Sloga Official"
const EXEMPT_SERVER_IDS: &[&str] = &["01KX3JTSZETQ5MQDGEJ3PVAZGJ"];

/// Whether a large attachment of this age has outlived its retention window.
fn past_retention(age: Duration, uploader_has_perk: bool) -> bool {
    if uploader_has_perk {
        age > PERK_MAX_AGE
    } else {
        age > MAX_AGE
    }
}

/// Channel ids whose message attachments are never pruned: every channel of
/// each exempt server, threads and forum posts included. A server that no
/// longer exists is skipped; any other lookup error fails the run, so a
/// transient database error can never prune an exempt server's files.
async fn exempt_channel_ids(db: &Database, server_ids: &[&str]) -> Result<HashSet<String>> {
    let mut channels = HashSet::new();
    for server_id in server_ids {
        match db.fetch_server(server_id).await {
            Ok(server) => channels.extend(server.message_channel_ids(db).await?),
            Err(error) if matches!(error.error_type, ErrorType::NotFound) => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(channels)
}

pub async fn task(db: Database, _: revolt_database::AMQP) -> Result<()> {
    loop {
        // Candidate set is already narrowed by size + type + not-deleted in the query.
        let files = db.fetch_large_message_attachments(SIZE_THRESHOLD).await?;

        // Age is filtered here, not in the query: uploaded_at timestamps are
        // inconsistently serialised in the DB (same reason as prune_dangling_files).
        let expired: Vec<_> = files
            .into_iter()
            .filter(|file| {
                file.uploaded_at.is_some_and(|uploaded_at| {
                    Timestamp::now_utc().duration_since(uploaded_at) > MAX_AGE
                })
            })
            .collect();

        if expired.is_empty() {
            sleep(Duration::from_secs(60 * 60)).await;
            continue;
        }

        // Uploaders who currently hold the upload perk keep their large
        // attachments for `PERK_MAX_AGE` instead. A missing or deleted
        // uploader has no perks and falls back to `MAX_AGE`.
        let uploader_ids: Vec<String> = expired
            .iter()
            .filter_map(|file| file.uploader_id.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let now = now_ms();
        let perk_uploaders: HashSet<String> = db
            .fetch_users(&uploader_ids)
            .await?
            .into_iter()
            .filter(|user| user.perks(now) & UserPerks::UploadPerk as u32 != 0)
            .map(|user| user.id)
            .collect();

        let expired: Vec<_> = expired
            .into_iter()
            .filter(|file| {
                let age = file
                    .uploaded_at
                    .and_then(|uploaded_at| {
                        Duration::try_from(Timestamp::now_utc().duration_since(uploaded_at)).ok()
                    })
                    .unwrap_or_default();
                let has_perk = file
                    .uploader_id
                    .as_ref()
                    .is_some_and(|id| perk_uploaders.contains(id));
                past_retention(age, has_perk)
            })
            .collect();

        // Build the set of channel ids belonging to exempt servers, threads
        // and forum posts included. Message attachments in these channels are
        // kept regardless of size/age. A lookup error aborts the run before
        // anything is pruned; `cron_task_wrapper` retries it after 60s.
        let exempt_channels = exempt_channel_ids(&db, EXEMPT_SERVER_IDS).await?;

        // Resolve each candidate's parent message → channel, in one query.
        let message_ids: Vec<String> = expired
            .iter()
            .filter_map(|file| file.used_for.as_ref().map(|used_for| used_for.id.clone()))
            .collect();
        let message_channel: HashMap<String, String> = db
            .fetch_messages_by_id(&message_ids)
            .await?
            .into_iter()
            .map(|message| (message.id, message.channel))
            .collect();

        let mut file_ids: Vec<String> = Vec::new();
        for file in expired {
            if let Some(used_for) = &file.used_for {
                // Skip if the message still exists and lives in an exempt channel.
                // (A missing message means the attachment is orphaned → prune it.)
                if let Some(channel) = message_channel.get(&used_for.id) {
                    if exempt_channels.contains(channel) {
                        continue;
                    }
                } else {
                    // No message owns this file — it may instead be claimed
                    // against a PENDING scheduled-message row (attachments
                    // are claimed at schedule time and only retargeted to a
                    // real message at fire time). Pruning it would guarantee
                    // a failed send, so leave it until the row fires or is
                    // cancelled (which releases it into the normal sweep).
                    if db.fetch_scheduled_message(&used_for.id).await.is_ok() {
                        continue;
                    }
                }

                // 1. Strip the attachment from its parent message so clients stop
                //    referencing a blob that is about to disappear. The message (and
                //    its text) is left intact.
                db.remove_message_attachment(&used_for.id, &file.id).await?;
            }

            file_ids.push(file.id);
        }

        if !file_ids.is_empty() {
            // 2. Mark the files deleted; the file_deletion task removes the S3 blob,
            //    respecting hash de-duplication and the `reported` (moderation) hold.
            db.mark_attachments_as_deleted(&file_ids).await?;
            info!(
                "Pruned {} large message attachment(s) past retention (24h, {}d with the upload perk)",
                file_ids.len(),
                PERK_RETENTION_DAYS
            );
        }

        sleep(Duration::from_secs(60 * 60)).await; // run hourly
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_secs(60 * 60);
    const DAY: Duration = Duration::from_secs(60 * 60 * 24);

    #[test]
    fn perk_uploader_kept_at_three_days() {
        assert!(!past_retention(DAY * 3, true));
    }

    #[test]
    fn non_perk_uploader_pruned_at_25_hours() {
        assert!(past_retention(HOUR * 25, false));
    }

    #[test]
    fn perk_uploader_pruned_at_eight_days() {
        assert!(past_retention(DAY * 8, true));
    }

    #[test]
    fn perk_window_matches_retention_days() {
        assert_eq!(PERK_MAX_AGE, DAY * PERK_RETENTION_DAYS as u32);
        assert!(!past_retention(PERK_MAX_AGE, true));
        assert!(!past_retention(MAX_AGE, false));
    }

    // ---- Exempt servers -----------------------------------------------------
    //
    // `Server.channels` lists top-level channels only, so an exemption built
    // from it pruned the exempt server's thread and forum-post attachments.
    // Control: `exempt_channel_ids` extending with `server.channels`.

    use revolt_database::{Channel, DatabaseInfo, Server};

    const EX_SERVER: &str = "01W3BEXEMPTSERVER";
    const EX_CHANNEL: &str = "01W3BEXEMPTCHANNEL";
    const EX_THREAD: &str = "01W3BEXEMPTTHREAD";
    const EX_OTHER_SERVER: &str = "01W3BOTHERSERVER";
    const EX_OTHER_CHANNEL: &str = "01W3BOTHERCHANNEL";
    const EX_OTHER_THREAD: &str = "01W3BOTHERTHREAD";
    const EX_MISSING_SERVER: &str = "01W3BMISSINGSERVER";

    fn ex_server(id: &str, channel: &str) -> Server {
        Server {
            id: id.to_string(),
            owner: "01W3BOWNER".to_string(),
            name: "server".to_string(),
            description: None,
            channels: vec![channel.to_string()],
            categories: None,
            system_messages: None,
            roles: HashMap::new(),
            default_permissions: 0,
            icon: None,
            banner: None,
            flags: None,
            nsfw: false,
            analytics: false,
            discoverable: false,
            discovery_requested: false,
            boost_count: None,
            boost_tier: None,
            voice_region: None,
            afk_channel_id: None,
            afk_timeout: None,
        }
    }

    fn ex_text_channel(id: &str, server: &str) -> Channel {
        Channel::TextChannel {
            id: id.to_string(),
            server: server.to_string(),
            name: "text".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: Default::default(),
            nsfw: false,
            spoiler: false,
            voice: None,
            slowmode: None,
            announcement: None,
            protected: false,
        }
    }

    fn ex_thread(id: &str, server: &str, parent: &str) -> Channel {
        Channel::Thread {
            id: id.to_string(),
            server: server.to_string(),
            parent_channel: parent.to_string(),
            name: "thread".to_string(),
            creator: "01W3BOWNER".to_string(),
            origin_message_id: None,
            last_message_id: None,
            archived: false,
            archived_timestamp: None,
            auto_archive_minutes: Channel::default_auto_archive_minutes(),
            locked: false,
            applied_tags: vec![],
        }
    }

    /// The exempt server's channel AND its thread are exempt; a server that
    /// does not exist is skipped rather than failing the run; another
    /// server's thread never leaks in.
    ///
    /// The fixture inserts raw documents: `Server::create` and
    /// `Channel::create_server_channel` mint their own ids, and fixed ids keep
    /// the expected set literal.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn exempt_channel_ids_include_threads_and_skip_missing_servers() {
        let db = DatabaseInfo::Reference.connect().await.expect("database");

        for (server, channel, thread) in [
            (EX_SERVER, EX_CHANNEL, EX_THREAD),
            (EX_OTHER_SERVER, EX_OTHER_CHANNEL, EX_OTHER_THREAD),
        ] {
            db.insert_server(&ex_server(server, channel))
                .await
                .expect("server");
            db.insert_channel(&ex_text_channel(channel, server))
                .await
                .expect("channel");
            db.insert_channel(&ex_thread(thread, server, channel))
                .await
                .expect("thread");
        }

        // The skip branch is only exercised if the lookup really is NotFound.
        let missing = db
            .fetch_server(EX_MISSING_SERVER)
            .await
            .expect_err("missing server must not resolve");
        assert!(
            matches!(missing.error_type, ErrorType::NotFound),
            "{missing:?}"
        );

        let exempt = exempt_channel_ids(&db, &[EX_SERVER, EX_MISSING_SERVER])
            .await
            .expect("a missing exempt server is skipped, not an error");

        assert_eq!(
            exempt,
            HashSet::from([EX_CHANNEL.to_string(), EX_THREAD.to_string()]),
            "W3B: the exempt set must hold the exempt server's channel and its thread, and nothing else"
        );
    }

    // ---- Fail-closed exemption, pinned on its text --------------------------
    //
    // Reference can only fail `fetch_server` with NotFound, so no behavioral
    // test can reach the "any other error" arm. Swallowing that error would
    // silently prune the exempt server's files again; these pin the text.

    /// The body of the function whose definition starts with `signature`,
    /// comment lines dropped and whitespace collapsed.
    fn fn_body(signature: &str) -> String {
        const SOURCE: &str = include_str!("prune_large_attachments.rs");
        let at = SOURCE.find(signature).expect("the function is defined");
        let open = at + SOURCE[at..].find('\u{7b}').expect("a body");
        let mut depth = 0usize;
        let mut close = None;
        for (i, ch) in SOURCE[open..].char_indices() {
            match ch {
                '\u{7b}' => depth += 1,
                '\u{7d}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        SOURCE[open..=close.expect("a closed body")]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Only NotFound is skipped; every other lookup error is returned.
    #[test]
    fn exempt_channel_ids_fails_closed_on_lookup_errors() {
        let body = fn_body("async fn exempt_channel_ids(");

        assert_eq!(
            body.matches("ErrorType::NotFound) => continue").count(),
            1,
            "W3B-text: exactly one NotFound skip arm: {body}"
        );
        assert_eq!(
            body.matches("Err(error) => return Err(error)").count(),
            1,
            "W3B-text: every other lookup error must be returned: {body}"
        );
        assert!(
            !body.contains("Err(_)"),
            "W3B-text: no catch-all error arm: {body}"
        );
        assert!(
            !body.contains(".ok()"),
            "W3B-text: no `.ok()` in the exemption lookup: {body}"
        );
        assert!(
            !body.contains("if let Ok("),
            "W3B-text: no `if let Ok(` in the exemption lookup: {body}"
        );
    }

    /// The task propagates an exemption failure before it prunes anything.
    #[test]
    fn task_propagates_exemption_errors_before_pruning() {
        let body = fn_body("pub async fn task(");
        let call = "exempt_channel_ids(&db, EXEMPT_SERVER_IDS).await?;";

        assert_eq!(
            body.matches(call).count(),
            1,
            "W3B-text: the task must build the exempt set exactly once, with `?`: {body}"
        );
        let built = body.find(call).expect("counted above");
        let pruned = body
            .find("remove_message_attachment(")
            .expect("W3B-text: the task strips attachments");
        assert!(
            built < pruned,
            "W3B-text: the exempt set must be built before anything is pruned: {body}"
        );
    }
}
