use iso8601_timestamp::Timestamp;

auto_derived!(
    /// Lifecycle state of a Discord import job.
    ///
    /// `Queued` rows are picked up by the crond claim worker, which flips
    /// them to `Running` ATOMICALLY (see
    /// `claim_next_queued_discord_import_job`) so multiple crond instances
    /// can never work the same import. Terminal states are `Completed` and
    /// `Failed`; nothing ever moves out of them — enforced at the storage
    /// layer by `save_discord_import_job_if_active`, not merely by
    /// convention in the worker.
    pub enum ImportStatus {
        Queued,
        Running,
        Completed,
        Failed,
    }

    /// Coarse progress stage, surfaced to the user as a progress label.
    ///
    /// Ordered as the worker walks them: fetch the Discord template, create
    /// the server, recreate categories/channels, join the owner, mint the
    /// invite, done.
    pub enum ImportStage {
        Fetching,
        Server,
        Channels,
        Membership,
        Invite,
        Done,
    }

    /// What the import actually did — shown once on completion.
    ///
    /// `notes` are human-readable "we skipped X because Y" lines; they are
    /// the honest record of everything a Discord template carries that
    /// Sloga has no equivalent for.
    pub struct DiscordImportSummary {
        /// Text/voice channels recreated
        pub channels_created: u32,
        /// Categories recreated
        pub categories_created: u32,
        /// Channels present in the template that were not recreated
        pub channels_skipped: u32,
        /// Human-readable "what we skipped" lines
        pub notes: Vec<String>,
    }

    /// A queued/running/finished "import a Discord server template" job.
    ///
    /// One row per import attempt. Owned by the requesting user; the crond
    /// worker claims it, drives it through the stages, and stamps the
    /// terminal state. Progress is pushed to the owner's private WebSocket
    /// topic (`DiscordImportProgress` / `DiscordImportComplete` /
    /// `DiscordImportFailed`) — clients never poll and never author state.
    pub struct DiscordImportJob {
        /// Unique Id — a ULID, so it doubles as the creation clock and
        /// gives the claim scan a stable oldest-first ordering
        #[serde(rename = "_id")]
        pub id: String,
        /// User who requested the import (and who will own the new server)
        pub user_id: String,
        /// Discord guild-template code being imported
        pub template_code: String,
        /// Lifecycle state
        pub status: ImportStatus,
        /// Coarse progress stage
        pub stage: ImportStage,
        /// Units of work finished within the current stage
        pub done: u32,
        /// Total units of work in the current stage (0 = indeterminate)
        pub total: u32,
        /// HEARTBEAT — set at creation, stamped again at claim time, and
        /// bumped by the worker on EVERY stage transition and progress tick.
        ///
        /// The sweeper fails a NON-TERMINAL job (`Queued` or `Running`)
        /// ONLY when this goes stale (`updated_at < cutoff`), NEVER on the
        /// job's creation age. A large server can legitimately take far
        /// longer than any fixed deadline; false-failing a live import
        /// mid-run would orphan a half-built server. Staleness here means
        /// one of two things: the worker that held this job died, or
        /// nothing ever claimed it.
        pub updated_at: Timestamp,
        /// Server created by the import, once it exists
        #[serde(skip_serializing_if = "Option::is_none")]
        pub server_id: Option<String>,
        /// Invite minted for the finished server
        #[serde(skip_serializing_if = "Option::is_none")]
        pub invite_code: Option<String>,
        /// User-safe failure message (never raw provider/internal errors)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        /// What the import did, populated on completion
        #[serde(skip_serializing_if = "Option::is_none")]
        pub summary: Option<DiscordImportSummary>,
    }
);

impl ImportStatus {
    /// The serde-serialized variant name as stored in the `status` field of
    /// documents.
    ///
    /// Mongo query filters MUST use THIS — `auto_derived!` gives these
    /// enums plain external tagging, so a unit variant lands in BSON as the
    /// bare string "Queued"/"Running"/…, not a lowercase key and not a
    /// document. Same trap as `ConnectionPlatform::as_variant_str`.
    pub fn as_variant_str(&self) -> &'static str {
        match self {
            ImportStatus::Queued => "Queued",
            ImportStatus::Running => "Running",
            ImportStatus::Completed => "Completed",
            ImportStatus::Failed => "Failed",
        }
    }
}

impl ImportStage {
    /// The serde-serialized variant name as stored in the `stage` field of
    /// documents (also the wire value carried by
    /// `EventV1::DiscordImportProgress`).
    pub fn as_variant_str(&self) -> &'static str {
        match self {
            ImportStage::Fetching => "Fetching",
            ImportStage::Server => "Server",
            ImportStage::Channels => "Channels",
            ImportStage::Membership => "Membership",
            ImportStage::Invite => "Invite",
            ImportStage::Done => "Done",
        }
    }
}

impl DiscordImportJob {
    /// Create a fresh queued job for a user.
    ///
    /// The id is a ULID (creation clock + claim ordering) and `updated_at`
    /// starts at now so a job that is never claimed still ages into the
    /// sweeper's view through the normal heartbeat rule.
    pub fn new(user_id: String, template_code: String) -> DiscordImportJob {
        DiscordImportJob {
            id: ulid::Ulid::new().to_string(),
            user_id,
            template_code,
            status: ImportStatus::Queued,
            stage: ImportStage::Fetching,
            done: 0,
            total: 0,
            updated_at: Timestamp::now_utc(),
            server_id: None,
            invite_code: None,
            error: None,
            summary: None,
        }
    }

    /// Bump the heartbeat. Call before every save the worker performs — a
    /// non-terminal job that stops heartbeating is what the sweeper reaps.
    pub fn touch(&mut self) {
        self.updated_at = Timestamp::now_utc();
    }

    /// Whether this job is in flight — the state that blocks a second
    /// concurrent import for the same user, that both save-if-active
    /// guards test, and that the sweeper reaps when the heartbeat stales.
    ///
    /// Mirrors the Mongo `active_user_id` partial filter
    /// (`status $in [Queued, Running]`); the two must stay in lockstep.
    pub fn is_active(&self) -> bool {
        matches!(self.status, ImportStatus::Queued | ImportStatus::Running)
    }
}
