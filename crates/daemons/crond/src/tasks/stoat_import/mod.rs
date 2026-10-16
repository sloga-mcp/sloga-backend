//! Stoat server importer.
//!
//! The user added the operator bot to their Stoat server and put their
//! verification code in its description; delta checked that and queued a
//! `StoatServer` job with the matched code. This worker, run from the shared
//! import claim loop:
//!
//! 1. fetches the server and every channel the bot can see (ONE request),
//! 2. checks the stored code is still in the description,
//! 3. fetches the server's emoji,
//! 4. maps it all into an `ImportPlan` and hands that to the shared
//!    `execute_plan`, with a fetcher for the icon, banner and emoji files.
//!
//! The bot leaves the Stoat server once the job is terminal (completed,
//! failed or reaped), through the worker's `on_terminal` and its leave
//! retry. Upstream calls per import: server + emojis + leave, plus the CDN
//! downloads on another host.
//!
//! A server where no job was ever created (the bot was added, then nobody
//! finished verifying) is left by the hourly `reconcile` instead.

pub(crate) mod mapper;
pub(crate) mod reconcile;
pub(crate) mod source;

use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};

use revolt_config::Settings;
use revolt_database::{Database, DiscordImportJob, ImportStage};

use super::discord_import::worker::{execute_plan, generic_failure, progress, ImportAbort};
use mapper::plan_stoat_import;
use source::{is_server_id, AssetLimits, StoatApi, StoatAssets};

/// The job's verification code is no longer in the Stoat server's
/// description (or the job has none).
pub(crate) const VERIFICATION_MISSING: &str =
    "Your verification code is no longer in your Stoat server's description. Paste the code \
     back into the description, then start the import again.";

/// Whether `code` appears in `haystack` the way delta accepted it: an exact
/// match whose next character is absent or not alphanumeric.
///
/// The same right-boundary rule as `import_challenge::find_accepted_code`,
/// which delta used; that helper recomputes today's and yesterday's codes,
/// while this compares against the one code stored on the job.
pub(crate) fn contains_code(haystack: &str, code: &str) -> bool {
    !code.is_empty()
        && haystack.match_indices(code).any(|(start, _)| {
            haystack[start + code.len()..]
                .chars()
                .next()
                .is_none_or(|next| !next.is_alphanumeric())
        })
}

/// Import the Stoat server a `StoatServer` job names. The claim loop has
/// already checked the Stoat source is ready.
pub(crate) async fn run(
    db: &Database,
    job: &mut DiscordImportJob,
    config: &Settings,
) -> Result<(), ImportAbort> {
    let stoat = &config.api.import.stoat;
    let Some(api) = StoatApi::new(stoat) else {
        log::error!("stoat import job {}: no usable Stoat API config", job.id);
        return Err(ImportAbort::Failed(generic_failure()));
    };
    let assets = StoatAssets::new(
        &stoat.cdn_url,
        AssetLimits::from_upload_limits(&config.features.limits.default.file_upload_size_limit),
    );

    // Checked before anything leaves the process.
    db.fetch_user(&job.user_id)
        .await
        .map_err(|_| ImportAbort::Failed(generic_failure()))?;

    let Some(server_id) = job.source_server_id.clone().filter(|id| is_server_id(id)) else {
        log::error!(
            "stoat import job {}: missing or invalid source server id",
            job.id
        );
        return Err(ImportAbort::Failed(generic_failure()));
    };
    let Some(code) = job.challenge_code.clone().filter(|code| !code.is_empty()) else {
        return Err(ImportAbort::Failed(VERIFICATION_MISSING.to_string()));
    };

    // 1. The server and its visible channels, in one request.
    if !progress(db, job, ImportStage::Fetching, 0, 0).await {
        return Err(ImportAbort::Superseded);
    }
    let fetched = api.fetch_server(&server_id).await.map_err(|error| {
        log::warn!(
            "stoat import job {}: server fetch failed: {error:?}",
            job.id
        );
        ImportAbort::Failed(error.user_message())
    })?;

    // 2. The code delta matched must still be there: whoever removed it may
    // no longer want the server copied. No request; the fetch above has
    // the description.
    if !progress(db, job, ImportStage::Verifying, 0, 0).await {
        return Err(ImportAbort::Superseded);
    }
    if !contains_code(fetched.server.description.as_deref().unwrap_or(""), &code) {
        return Err(ImportAbort::Failed(VERIFICATION_MISSING.to_string()));
    }

    // 3. Emoji, only once verified.
    let emojis = api.fetch_emojis(&server_id).await.map_err(|error| {
        log::warn!("stoat import job {}: emoji fetch failed: {error:?}", job.id);
        ImportAbort::Failed(error.user_message())
    })?;

    // 4. Map and build. A brand-new server has no boosts, so its emoji cap
    // is the tier-0 one (the worker applies the same cap again).
    let emoji_cap = config
        .features
        .boosts
        .effective_server_emoji(config.features.limits.global.server_emoji, 0);
    let plan = plan_stoat_import(
        &fetched.server,
        &fetched.channels,
        &emojis,
        emoji_cap,
        &code,
    )
    .map_err(|error| ImportAbort::Failed(error.user_message_for(&job.kind)))?;

    execute_plan(db, job, plan, &assets).await
}

/// Make the bot leave the job's Stoat server. Returns whether it is out
/// (see `StoatApi::leave_server`).
///
/// Needs only the bot token and API URL, not `enabled`: a source switched
/// off still has bots to remove. Without a token nothing can be sent; the
/// row stays un-left, and the leave retry gives up loudly after its cap.
pub(crate) async fn leave(job: &DiscordImportJob, config: &Settings) -> bool {
    let Some(server_id) = job
        .source_server_id
        .as_deref()
        .filter(|id| is_server_id(id))
    else {
        log::error!(
            "stoat import job {}: no usable source server id; the bot cannot leave it",
            job.id
        );
        return false;
    };

    let Some(api) = StoatApi::new(&config.api.import.stoat) else {
        // The leave retry calls this every sweep for days; say it once.
        if first_no_token_warning(&job.id) {
            log::warn!(
                "stoat import job {}: no Stoat bot token configured; the bot stays in \
                 {server_id} until one is (the leave retry keeps trying, and logs again if it \
                 gives up)",
                job.id
            );
        }
        return false;
    };

    api.leave_server(server_id).await
}

/// Jobs the no-token leave warning has been logged for in this process.
static NO_TOKEN_WARNED: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Past this many ids the set starts over, so it stays bounded; each job
/// then warns once more at most.
const NO_TOKEN_WARNED_CAP: usize = 10_000;

/// Whether this is the first no-token leave for `job_id` (in this process).
fn first_no_token_warning(job_id: &str) -> bool {
    let mut warned = NO_TOKEN_WARNED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if warned.contains(job_id) {
        return false;
    }
    if warned.len() >= NO_TOKEN_WARNED_CAP {
        warned.clear();
    }
    warned.insert(job_id.to_string());
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODE: &str = "sloga-import-ABCDEFGH";

    /// The cases `import_challenge`'s own tests pin for its matcher.
    #[test]
    fn contains_code_uses_the_same_right_boundary_as_delta() {
        for haystack in [
            CODE.to_string(),
            format!("Welcome!\n\nVerify: {CODE}.\nRules below"),
            format!("about us\n{CODE}"),
            format!("{CODE}X then {CODE}"),
            format!("({CODE})"),
        ] {
            assert!(contains_code(&haystack, CODE), "{haystack}");
        }

        for haystack in [
            format!("{CODE}X"),
            format!("{CODE}2"),
            format!("{CODE}é"),
            CODE.to_lowercase(),
            "sloga-import-ZZZZZZZZ".to_string(),
            String::new(),
        ] {
            assert!(!contains_code(&haystack, CODE), "{haystack}");
        }

        assert!(!contains_code("anything", ""));
    }

    /// The leave retry runs every sweep; without a token the warning is
    /// logged once per job, not on every one of them.
    #[test]
    fn the_no_token_warning_is_once_per_job() {
        let job = "01WARNONCE0000000000000001";
        let other = "01WARNONCE0000000000000002";
        assert!(first_no_token_warning(job));
        assert!(!first_no_token_warning(job));
        assert!(!first_no_token_warning(job));
        assert!(first_no_token_warning(other));
    }
}
