//! Draw-consent allowlists for screen-share annotation (tech-support-mode
//! plan §2.4).
//!
//! One Redis SET per (channel, sharer): the user ids that sharer currently
//! allows to draw on their shared screen. This is the ENFORCEMENT state for
//! the annotation route — consent checked server-side on every send, never a
//! client toggle — and it is the only thing the annotation feature stores;
//! strokes themselves are relayed and forgotten, like captions.
//!
//! Unlike remote-control grants (`remote_control.rs`), passive Redis TTL is
//! the right expiry here: a consent entry going stale fails CLOSED (the next
//! send is refused), whereas a grant record vanishing fails OPEN (nothing
//! left to revoke). No reaper, no expiry index — the TTL is garbage
//! collection, not enforcement. Enforcement also re-checks on every send
//! that the target is publishing screen video RIGHT NOW, so an allowlist
//! outliving a share grants nothing.

use redis_kiss::AsyncCommands;
use revolt_result::{Result, ToRevoltError};

use super::get_connection;

/// Garbage-collection horizon for an allowlist nobody cleared. Generous on
/// purpose: correctness never depends on it (see module docs), it only
/// bounds abandoned keys. (`usize` because this redis fork's `expire`
/// takes one.)
const ANNOTATION_ALLOW_TTL_SECS: usize = 12 * 60 * 60;

/// Fixed-point coordinate scale: stroke points are integers in
/// `0..=ANNOTATION_COORD_SCALE` over the shared surface's unit square.
pub const ANNOTATION_COORD_SCALE: u16 = 10_000;

/// Fixed branded ink palette size — color indexes must be `<` this. The
/// client's palette table must stay the same length (its specs assert it).
pub const ANNOTATION_PALETTE_SIZE: u8 = 5;

/// Stroke width classes — width indexes must be `<` this.
pub const ANNOTATION_WIDTH_CLASSES: u8 = 3;

fn allow_key(channel_id: &str, sharer_id: &str) -> String {
    format!("annotations_allow:{channel_id}:{sharer_id}")
}

/// Allow `annotator_id` to draw on `sharer_id`'s shared screen in this
/// channel. Refreshes the GC TTL on the whole set.
pub async fn add_allowed_annotator(
    channel_id: &str,
    sharer_id: &str,
    annotator_id: &str,
) -> Result<()> {
    let mut conn = get_connection().await?;
    let key = allow_key(channel_id, sharer_id);
    let _: () = conn
        .sadd(&key, annotator_id)
        .await
        .to_internal_error()?;
    let _: () = conn
        .expire(&key, ANNOTATION_ALLOW_TTL_SECS)
        .await
        .to_internal_error()?;
    Ok(())
}

/// The one-action revoke (plan §2.4): drop the sharer's WHOLE allowlist.
/// Deliberately not per-user — the backstop against a live phishing overlay
/// must be a single act, not list management.
pub async fn clear_allowed_annotators(channel_id: &str, sharer_id: &str) -> Result<()> {
    let mut conn = get_connection().await?;
    let _: () = conn
        .del(allow_key(channel_id, sharer_id))
        .await
        .to_internal_error()?;
    Ok(())
}

/// Is `annotator_id` currently allowed to draw on `sharer_id`'s screen?
/// Checked by the send route on EVERY batch.
pub async fn is_annotator_allowed(
    channel_id: &str,
    sharer_id: &str,
    annotator_id: &str,
) -> Result<bool> {
    let mut conn = get_connection().await?;
    conn.sismember(allow_key(channel_id, sharer_id), annotator_id)
        .await
        .to_internal_error()
}

/// Current allowlist for one sharer (empty if none).
pub async fn get_allowed_annotators(channel_id: &str, sharer_id: &str) -> Result<Vec<String>> {
    let mut conn = get_connection().await?;
    conn.smembers(allow_key(channel_id, sharer_id))
        .await
        .to_internal_error()
}
