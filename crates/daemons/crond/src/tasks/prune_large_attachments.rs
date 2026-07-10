use std::collections::{HashMap, HashSet};
use std::time::Duration;

use revolt_database::{iso8601_timestamp::Timestamp, Database};
use revolt_result::Result;
use tokio::time::sleep;

use log::info;

/// Message attachments larger than this many bytes are pruned once older than `MAX_AGE`.
const SIZE_THRESHOLD: usize = 20_000_000; // 20 MB
/// How long a large message attachment is retained before it is pruned.
const MAX_AGE: Duration = Duration::from_secs(60 * 60 * 24); // 24 hours

/// Servers whose message attachments are exempt from pruning (kept indefinitely).
/// - `01KX3JTSZETQ5MQDGEJ3PVAZGJ` = "Sloga Official"
const EXEMPT_SERVER_IDS: &[&str] = &["01KX3JTSZETQ5MQDGEJ3PVAZGJ"];

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

        // Build the set of channel ids belonging to exempt servers. Message
        // attachments in these channels are kept regardless of size/age.
        let mut exempt_channels: HashSet<String> = HashSet::new();
        for server_id in EXEMPT_SERVER_IDS {
            if let Ok(server) = db.fetch_server(server_id).await {
                exempt_channels.extend(server.channels);
            }
        }

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
                "Pruned {} large message attachment(s) older than 24h",
                file_ids.len()
            );
        }

        sleep(Duration::from_secs(60 * 60)).await; // run hourly
    }
}
