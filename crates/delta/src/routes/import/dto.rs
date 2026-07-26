//! Wire shape for import jobs.
//!
//! The stored `DiscordImportJob` is a database model without `JsonSchema`, and
//! it carries fields the client has no business seeing (`user_id`). This is the
//! deliberate public projection.
//!
//! `status` and `stage` are emitted as plain strings on purpose: later slices
//! add stages (roles, emojis, …) and a client with a closed enum would break on
//! an unknown value. Treat them as opaque labels.

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
    pub done: u32,
    pub total: u32,
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
            done: job.done,
            total: job.total,
            server_id: job.server_id,
            invite_code: job.invite_code,
            error: job.error,
            summary: job.summary.map(|summary| ImportSummaryResponse {
                channels_created: summary.channels_created,
                categories_created: summary.categories_created,
                channels_skipped: summary.channels_skipped,
                roles_created: summary.roles_created,
                roles_skipped: summary.roles_skipped,
                notes: summary.notes,
            }),
        }
    }
}
