//! Wire shape for import jobs.
//!
//! The stored `DiscordImportJob` is a database model without `JsonSchema`, and
//! it carries fields the client has no business seeing (`user_id`). This is the
//! deliberate public projection.
//!
//! `status`, `stage` and `kind` are emitted as plain strings on purpose: later
//! slices add stages/kinds and a client with a closed enum would break on an
//! unknown value. Treat them as opaque labels.

use revolt_database::DiscordImportJob;
use serde::Serialize;

/// # Import Summary
#[derive(Serialize, JsonSchema, Debug)]
pub struct ImportSummaryResponse {
    pub channels_created: u32,
    pub categories_created: u32,
    pub channels_skipped: u32,
    /// Roles recreated. The Discord `@everyone` role is **not** counted — it
    /// is not a Sloga role; its permissions become the server's defaults.
    pub roles_created: u32,
    /// Roles in the template that were not recreated (cap, or failed insert)
    pub roles_skipped: u32,
    /// Stickers recreated — present only on sticker-import jobs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stickers_created: Option<u32>,
    /// Stickers not recreated (unsupported format, over the cap, oversize,
    /// name collision, or failed download) — present only on sticker jobs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stickers_skipped: Option<u32>,
    /// Human-readable notes about anything deliberately not imported
    pub notes: Vec<String>,
}

/// # Import Job
#[derive(Serialize, JsonSchema, Debug)]
pub struct ImportJobResponse {
    pub job_id: String,
    /// One of `Queued`, `Running`, `Completed`, `Failed`
    pub status: String,
    /// Current phase; treat as an opaque label
    pub stage: String,
    /// What kind of import this is (`Template`, `Stickers`, …); treat as an
    /// opaque label like `stage`
    pub kind: String,
    pub done: u32,
    pub total: u32,
    /// Discord guild the template came from — what the client builds the
    /// bot-invite URL from when offering the sticker step
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_guild_id: Option<String>,
    /// For a sticker job, the Completed template job it was spawned from
    /// (what a client-side "Try again" re-POSTs against)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_job_id: Option<String>,
    /// Present once the server exists
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    /// Present once the welcome invite has been minted
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_code: Option<String>,
    /// User-safe failure message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<ImportSummaryResponse>,
}

impl From<DiscordImportJob> for ImportJobResponse {
    fn from(job: DiscordImportJob) -> Self {
        ImportJobResponse {
            job_id: job.id,
            status: job.status.as_variant_str().to_string(),
            stage: job.stage.as_variant_str().to_string(),
            kind: job.kind.as_variant_str().to_string(),
            done: job.done,
            total: job.total,
            source_guild_id: job.source_guild_id,
            parent_job_id: job.parent_job_id,
            server_id: job.server_id,
            invite_code: job.invite_code,
            error: job.error,
            summary: job.summary.map(|summary| ImportSummaryResponse {
                channels_created: summary.channels_created,
                categories_created: summary.categories_created,
                channels_skipped: summary.channels_skipped,
                roles_created: summary.roles_created,
                roles_skipped: summary.roles_skipped,
                stickers_created: summary.stickers_created,
                stickers_skipped: summary.stickers_skipped,
                notes: summary.notes,
            }),
        }
    }
}
