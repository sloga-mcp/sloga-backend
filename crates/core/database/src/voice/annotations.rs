//! Draw-consent allowlists for screen-share annotation (tech-support-mode
//! plan §2.4).
//!
//! One Redis SET per (channel, sharer): the user ids that sharer currently
//! allows to draw on their shared screen. This is the ENFORCEMENT state for
//! the annotation route — consent checked server-side on every send, never a
//! client toggle — and it is the only thing the annotation feature stores;
//! strokes themselves are relayed and forgotten, like captions.
//!
//! CONSENT IS SCOPED TO THE SHARE IT WAS GRANTED ON (review finding, rev 3):
//! the allowlist is cleared when the sharer's `screen_video` goes false, when
//! their voice state is deleted (leave/call end), and on a fresh join —
//! the same stale-key discipline `recording:`/`rc_capable:` follow. Without
//! those clears, re-sharing hours later in the same channel would silently
//! resurrect every old grant the sharer no longer remembers making.
//!
//! Unlike remote-control grants (`remote_control.rs`), passive Redis TTL is
//! the right LAST-RESORT expiry here: a consent entry going stale fails
//! CLOSED (the next send is refused), whereas a grant record vanishing fails
//! OPEN (nothing left to revoke). No reaper, no expiry index — the TTL is
//! garbage collection behind the lifecycle clears above, not enforcement.
//! Enforcement also re-checks on every send that the target is publishing
//! screen video RIGHT NOW.

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

/// Most annotators one sharer may allowlist at once. §2.4's spirit is "a
/// named participant" — helpers, not an audience — and the review promoted
/// this to a security control: the allowlist size is the only server-side
/// bound on the aggregate stroke fan-out (N annotators × 18 req/s ×
/// members-1 publishes), so it must not scale with channel population.
pub const MAX_ALLOWED_ANNOTATORS: usize = 8;

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
/// must be a single act, not list management. Returns whether a list
/// existed, so lifecycle callers can skip fanning a consent event nobody
/// needs.
pub async fn clear_allowed_annotators(channel_id: &str, sharer_id: &str) -> Result<bool> {
    let mut conn = get_connection().await?;
    let removed: i64 = conn
        .del(allow_key(channel_id, sharer_id))
        .await
        .to_internal_error()?;
    Ok(removed > 0)
}

/// Current allowlist size (0 if none) — the PUT route's cap input.
pub async fn count_allowed_annotators(channel_id: &str, sharer_id: &str) -> Result<usize> {
    let mut conn = get_connection().await?;
    let count: i64 = conn
        .scard(allow_key(channel_id, sharer_id))
        .await
        .to_internal_error()?;
    Ok(count.max(0) as usize)
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
