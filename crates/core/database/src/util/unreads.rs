use futures::stream::{self, StreamExt};
use revolt_models::v0;
use revolt_result::Result;

use crate::Database;

/// How many channels are summarised at once. The work is capped per channel,
/// so this only exists to keep a user with a hundred stale channels from
/// opening a hundred simultaneous queries on connect.
const CONCURRENCY: usize = 16;

/// Fetch a user's channel unreads, each stamped with a summary of its unread
/// tail: how many messages sit after the read pointer and whether any of them
/// carries an attachment.
///
/// Every summary is capped at `UNREAD_COUNT_CAP`, so an account that has been
/// away for a month costs the same as one that has been away for an hour.
pub async fn fetch_unreads_with_summary(
    db: &Database,
    user_id: &str,
) -> Result<Vec<v0::ChannelUnread>> {
    let unreads = db.fetch_unreads(user_id).await?;

    // Collect owned targets first: mapping straight off `unreads.iter()` makes
    // each future borrow its element, which the higher-ranked lifetime check
    // cannot prove `Send` for the callers' spawned tasks.
    let targets = unreads
        .iter()
        .map(|unread| (unread.id.channel.clone(), unread.last_id.clone()))
        .collect::<Vec<_>>();

    let summaries = stream::iter(targets.into_iter().map(|(channel, last_id)| async move {
        db.summarise_unread(&channel, last_id.as_deref()).await
    }))
    .buffered(CONCURRENCY)
    .collect::<Vec<_>>()
    .await;

    Ok(unreads
        .into_iter()
        .zip(summaries)
        .map(|(unread, summary)| {
            let mut unread: v0::ChannelUnread = unread.into();

            // A summary that failed degrades to "no number" — the client falls
            // back to the plain unread dot rather than showing a wrong count.
            if let Ok(summary) = summary {
                unread.count = summary.count;
                unread.attachments = summary.attachments;
            }

            unread
        })
        .collect())
}
