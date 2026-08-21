use std::time::{Duration, SystemTime, UNIX_EPOCH};

use revolt_database::{
    Database, InteractionKind, AUTOCOMPLETE_TTL_MS, INTERACTION_TTL_MS,
};
use revolt_result::Result;
use tokio::time::sleep;

/// Storage hygiene for the transient `interactions` collection.
///
/// Expiry is enforced authoritatively at respond time (the route checks the
/// ULID clock); this sweep only stops expired rows from accumulating. Cutoffs
/// are ULIDs synthesised from (now - TTL), so deletion is a pure
/// `_id < cutoff` range scan on the primary index.
///
/// Autocomplete is swept on its own, much shorter clock: it is the one kind a
/// user creates by typing, so it is by far the most numerous, and a row that
/// stopped being answerable after a minute has no reason to sit around for
/// fifteen.
pub async fn task(db: Database, _: revolt_database::AMQP) -> Result<()> {
    loop {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);

        let autocomplete_cutoff =
            ulid::Ulid::from_parts(now_ms.saturating_sub(AUTOCOMPLETE_TTL_MS), 0);
        db.delete_interactions_of_kind_before(
            InteractionKind::Autocomplete,
            &autocomplete_cutoff.to_string(),
        )
        .await?;

        let cutoff = ulid::Ulid::from_parts(now_ms.saturating_sub(INTERACTION_TTL_MS), 0);
        db.delete_interactions_before(&cutoff.to_string()).await?;

        log::info!(
            "Pruned expired interactions below {cutoff} (autocomplete below {autocomplete_cutoff})"
        );

        // Paced to the SHORTER of the two windows, so autocomplete rows live
        // at most about twice their answerable life rather than up to thirty
        // minutes. Both sweeps are indexed range deletes over an already
        // small collection.
        sleep(Duration::from_secs(60)).await
    }
}
