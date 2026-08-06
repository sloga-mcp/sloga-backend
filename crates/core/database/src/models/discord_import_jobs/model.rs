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
    /// the server, recreate roles, recreate categories/channels, join the
    /// owner, mint the invite, done.
    ///
    /// Variants are ADDITIVE — clients treat the wire value as an opaque
    /// label precisely so a stage introduced by a later slice cannot break a
    /// deployed build. Never rename one: a stored job would stop
    /// deserializing.
    pub enum ImportStage {
        Fetching,
        Server,
        /// Roles are created before channels because per-channel permission
        /// overwrites are keyed by role id.
        Roles,
        Channels,
        Membership,
        Invite,
        /// The whole life of a sticker-import job. DELIBERATELY set at
        /// insert time, not first progress: a sticker job row must be
        /// UNDESERIALIZABLE by pre-slice-2 binaries, whose `ImportStage`
        /// lacks this variant. That is what stops an old crond from
        /// claiming the row, misreading it as a template job and minting a
        /// duplicate server — and what keeps an old sweeper (which has no
        /// kind gate) from ever considering it for server rollback. Do not
        /// "fix" a sticker job to start at `Fetching`.
        Stickers,
        Done,
    }

    /// What kind of work an import job is.
    ///
    /// `#[serde(default)]` on the field means every pre-slice-2 row reads
    /// as `Template`, which is what they all are.
    #[derive(Default)]
    pub enum ImportJobKind {
        #[default]
        Template,
        Stickers,
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
        /// Roles recreated (the Discord `@everyone` role is NOT one of these
        /// — it becomes the server's `default_permissions`)
        ///
        /// `#[serde(default)]` because slice 0 rows predate this field and
        /// `auto_derived!` adds no defaults of its own: without it, reading
        /// any job written before slice 1 would fail outright.
        #[serde(default)]
        pub roles_created: u32,
        /// Roles present in the template that were not recreated (over the
        /// per-server cap, or failed to insert)
        ///
        /// Exists so the count and the prose note beside it cannot disagree —
        /// the same rule `channels_skipped` follows.
        #[serde(default)]
        pub roles_skipped: u32,
        /// Stickers recreated (sticker-kind jobs only; `None` on template
        /// jobs so their summaries don't sprout a meaningless zero)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stickers_created: Option<u32>,
        /// Stickers in the guild that were not recreated (Lottie/unavailable,
        /// over the cap, oversize, name collision, or a failed download) —
        /// `created + skipped` must reconcile with what the user sees on
        /// Discord, per the counts-match-notes rule.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub stickers_skipped: Option<u32>,
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
        /// Discord guild-template code being imported.
        ///
        /// EMPTY on sticker-kind jobs, on purpose — copying the parent's
        /// code here would hand any code path that reads it something to
        /// re-import, and the mixed-binary hazard this slice closes was
        /// precisely an old worker running a template import off a sticker
        /// row.
        pub template_code: String,
        /// What kind of work this is. Pre-slice-2 rows deserialize as
        /// `Template`, which is what they all are.
        #[serde(default)]
        pub kind: ImportJobKind,
        /// Discord guild the template was created from — captured (u64-
        /// snowflake-validated) at template-fetch time by the template
        /// worker; the sticker worker reads it back. Also what the client
        /// builds the bot-invite URL from.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub source_guild_id: Option<String>,
        /// For a sticker-kind job: the Completed template job it was
        /// spawned from. Provenance for client-side retry and ops queries.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub parent_job_id: Option<String>,
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
            ImportStage::Roles => "Roles",
            ImportStage::Channels => "Channels",
            ImportStage::Membership => "Membership",
            ImportStage::Invite => "Invite",
            ImportStage::Stickers => "Stickers",
            ImportStage::Done => "Done",
        }
    }
}

impl ImportJobKind {
    /// The serde-serialized variant name (external tagging, bare string) —
    /// also the wire value on the job DTO, treated by clients as an opaque
    /// label like `stage`.
    pub fn as_variant_str(&self) -> &'static str {
        match self {
            ImportJobKind::Template => "Template",
            ImportJobKind::Stickers => "Stickers",
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
            kind: ImportJobKind::Template,
            source_guild_id: None,
            parent_job_id: None,
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

    /// Create a queued sticker-import job from a Completed template job.
    ///
    /// Born at `stage: Stickers` with an EMPTY `template_code` — both are
    /// load-bearing (see the field and variant docs): together they make
    /// the row illegible and inert to pre-slice-2 binaries, converting the
    /// mixed-deploy window from a silent duplicate-server import into a
    /// fail-closed parse error.
    ///
    /// The caller has already validated that `parent` is Completed and
    /// carries `server_id` + `source_guild_id`.
    pub fn new_stickers(parent: &DiscordImportJob) -> DiscordImportJob {
        DiscordImportJob {
            id: ulid::Ulid::new().to_string(),
            user_id: parent.user_id.clone(),
            template_code: String::new(),
            kind: ImportJobKind::Stickers,
            source_guild_id: parent.source_guild_id.clone(),
            parent_job_id: Some(parent.id.clone()),
            status: ImportStatus::Queued,
            stage: ImportStage::Stickers,
            done: 0,
            total: 0,
            updated_at: Timestamp::now_utc(),
            server_id: parent.server_id.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every job row written before slice 2 lacks `kind`,
    /// `source_guild_id`, `parent_job_id` and the sticker summary fields.
    /// They must all read back as their defaults — a deploy must never make
    /// existing rows unreadable.
    #[test]
    fn pre_slice_2_rows_deserialize_with_defaults() {
        let stored = r#"{
            "_id": "01JOB0000000000000000000000",
            "user_id": "01USER000000000000000000000",
            "template_code": "abc123",
            "status": "Completed",
            "stage": "Done",
            "done": 4,
            "total": 4,
            "updated_at": "2026-07-26T00:00:00Z",
            "server_id": "01SERVER0000000000000000000",
            "summary": {
                "channels_created": 4,
                "categories_created": 1,
                "channels_skipped": 0,
                "notes": []
            }
        }"#;

        let job: DiscordImportJob = serde_json::from_str(stored).unwrap();
        assert_eq!(job.kind, ImportJobKind::Template);
        assert_eq!(job.source_guild_id, None);
        assert_eq!(job.parent_job_id, None);
        let summary = job.summary.unwrap();
        assert_eq!(summary.stickers_created, None);
        assert_eq!(summary.stickers_skipped, None);
    }

    /// The inverse direction of the mixed-binary guarantee: a sticker job
    /// SERIALIZES with `stage: "Stickers"` — the variant a pre-slice-2
    /// binary cannot parse — and an empty `template_code`. Together these
    /// are what turn the mixed-deploy window into a parse error instead of
    /// a silent duplicate template import.
    #[test]
    fn sticker_jobs_are_born_illegible_to_old_binaries() {
        let mut parent = DiscordImportJob::new(
            "01USER000000000000000000000".to_string(),
            "abc123".to_string(),
        );
        parent.status = ImportStatus::Completed;
        parent.server_id = Some("01SERVER0000000000000000000".to_string());
        parent.source_guild_id = Some("1530784817975660565".to_string());

        let job = DiscordImportJob::new_stickers(&parent);
        assert_eq!(job.stage, ImportStage::Stickers);
        assert_eq!(job.template_code, "");
        assert_eq!(job.kind, ImportJobKind::Stickers);

        let wire = serde_json::to_value(&job).unwrap();
        assert_eq!(wire["stage"], "Stickers");
        assert_eq!(wire["template_code"], "");
    }
}
