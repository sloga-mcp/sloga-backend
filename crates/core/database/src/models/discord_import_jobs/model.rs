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
    /// Ordered as the worker walks them: fetch the source (Discord template,
    /// or a Stoat/Fluxer/Matrix server), verify ownership (source kinds
    /// only), create the server, recreate roles, recreate
    /// categories/channels, attach icon/banner/emojis (source kinds only),
    /// join the owner, mint the invite, done. Declaration order is
    /// documentation only — nothing derives `Ord` or maps a stage to a
    /// percentage server-side.
    ///
    /// Variants are ADDITIVE — clients treat the wire value as an opaque
    /// label precisely so a stage introduced by a later slice cannot break a
    /// deployed build. Never rename one: a stored job would stop
    /// deserializing.
    pub enum ImportStage {
        Fetching,
        /// Source kinds only: the fetched source is checked against the
        /// job's stored `challenge_code` (a comparison, not a second
        /// request).
        ///
        /// Also the stage a source-kind job is BORN at — see
        /// `DiscordImportJob::new_source` for why it is not `Fetching`.
        Verifying,
        Server,
        /// Roles are created before channels because per-channel permission
        /// overwrites are keyed by role id.
        Roles,
        Channels,
        /// Source kinds only: icon, banner and emojis. Runs before
        /// `Membership` because `ServerCreate` snapshots the in-memory
        /// server when the owner joins.
        Assets,
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
    ///
    /// The three source kinds were added together (one schema change, so
    /// old binaries break on new rows once, not once per source). Any
    /// binary built before them — slice 2 or later — fails to decode a
    /// source-kind row on its `kind` alone (unknown variant), so it can
    /// never misread one as a template import. Pre-slice-2 binaries ignore
    /// `kind` entirely; for them the guard is the birth stage
    /// (`ImportStage::Verifying`), exactly as `Stickers` relies on its
    /// stage. Decoding failing is NOT a clean refusal on MongoDB, though:
    /// an old crond's claim flips the row to `Running` BEFORE decoding it,
    /// and an old sweeper silently skips rows it cannot decode, so the row
    /// sits `Running` until a current crond's sweeper reaps it. Before
    /// rolling crond back below these kinds, fail or delete every
    /// source-kind row.
    #[derive(Default)]
    pub enum ImportJobKind {
        #[default]
        Template,
        Stickers,
        /// A Stoat server, read by the operator bot the user added to it
        StoatServer,
        /// A Fluxer guild, read by the operator bot the user added to it
        FluxerServer,
        /// A Matrix space, read by the operator account the user invited
        MatrixSpace,
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
        ///
        /// On source-kind jobs (`StoatServer`, `FluxerServer`,
        /// `MatrixSpace`) this holds the source string the user pasted
        /// (invite link, server id, space alias), kept for display and
        /// support. Workers act on `source_server_id`, never on this.
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
        /// Source-kind jobs: the id of the server/guild/space being
        /// imported (resolved by delta at request time for Stoat and Fluxer;
        /// by crond for Matrix, where delta never contacts the homeserver).
        /// `None` on template and sticker jobs (they use
        /// `source_guild_id`). Keys the "is another job still using this
        /// source" check that decides whether the bot may leave.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source_server_id: Option<String>,
        /// Source-kind jobs: the ownership-challenge code delta matched at
        /// request time. The worker compares the source against THIS,
        /// never against a recomputation (the day may have rolled over).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub challenge_code: Option<String>,
        /// Source-kind jobs: whether the operator bot has left the source
        /// after the job reached a terminal state. Persist it with
        /// `mark_source_left` (a targeted write — `save_*_if_active` refuses
        /// terminal rows by design); the sweeper retries the leave while
        /// this is false. Absent on every older row, which reads as `false`.
        #[serde(default, skip_serializing_if = "crate::if_false")]
        pub source_left: bool,
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
            ImportStage::Verifying => "Verifying",
            ImportStage::Server => "Server",
            ImportStage::Roles => "Roles",
            ImportStage::Channels => "Channels",
            ImportStage::Assets => "Assets",
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
            ImportJobKind::StoatServer => "StoatServer",
            ImportJobKind::FluxerServer => "FluxerServer",
            ImportJobKind::MatrixSpace => "MatrixSpace",
        }
    }

    /// The kinds that read a third-party source through an operator bot
    /// account — the ones with `source_server_id` / `challenge_code`, and
    /// whose bot must leave the source once the job is terminal.
    ///
    /// Must agree with `is_source`; a test pins it.
    pub const SOURCE_KINDS: [ImportJobKind; 3] = [
        ImportJobKind::StoatServer,
        ImportJobKind::FluxerServer,
        ImportJobKind::MatrixSpace,
    ];

    /// Whether this kind reads a third-party source through an operator
    /// bot account (see `SOURCE_KINDS`).
    pub fn is_source(&self) -> bool {
        match self {
            ImportJobKind::Template | ImportJobKind::Stickers => false,
            ImportJobKind::StoatServer
            | ImportJobKind::FluxerServer
            | ImportJobKind::MatrixSpace => true,
        }
    }

    /// Whether this kind CREATES a server — and therefore owns it, so a
    /// failed or reaped job may roll it back.
    ///
    /// `Stickers` is false on purpose: its `server_id` is a live server the
    /// user already had, which it must never delete.
    pub fn builds_server(&self) -> bool {
        match self {
            ImportJobKind::Template
            | ImportJobKind::StoatServer
            | ImportJobKind::FluxerServer
            | ImportJobKind::MatrixSpace => true,
            ImportJobKind::Stickers => false,
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
            source_server_id: None,
            challenge_code: None,
            source_left: false,
        }
    }

    /// Create a fresh queued source-kind job (`StoatServer`,
    /// `FluxerServer`, `MatrixSpace`).
    ///
    /// `source` is the string the user pasted, stored in `template_code`
    /// for display; `source_server_id` and `challenge_code` are what delta
    /// resolved and verified, and what the worker acts on.
    ///
    /// Born at `stage: Verifying`, NOT `Fetching` — the `Stickers`
    /// precedent. Binaries from slice 2 on already refuse the row on its
    /// unknown `kind`, but pre-slice-2 binaries ignore `kind` and would
    /// read a `Fetching` row as a template import of the pasted string; a
    /// bare invite code can be a syntactically valid Discord template
    /// code. A stage they cannot parse makes the row illegible to them
    /// too. The worker moves the stage on from its first progress write.
    ///
    /// PANICS on `Template` or `Stickers`: building one of those through
    /// this constructor would mint a mis-kinded row (a template job born
    /// at a stage its worker never expects, or a sticker job with no
    /// parent), and refusing loudly is the fail-closed outcome. Callers
    /// derive `kind` from the route, never from the request body.
    pub fn new_source(
        user_id: String,
        kind: ImportJobKind,
        source: String,
        source_server_id: Option<String>,
        challenge_code: Option<String>,
    ) -> DiscordImportJob {
        assert!(
            kind.is_source(),
            "DiscordImportJob::new_source called with non-source kind {kind:?}"
        );

        DiscordImportJob {
            id: ulid::Ulid::new().to_string(),
            user_id,
            template_code: source,
            kind,
            source_guild_id: None,
            parent_job_id: None,
            status: ImportStatus::Queued,
            stage: ImportStage::Verifying,
            done: 0,
            total: 0,
            updated_at: Timestamp::now_utc(),
            server_id: None,
            invite_code: None,
            error: None,
            summary: None,
            source_server_id,
            challenge_code,
            source_left: false,
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
            source_server_id: None,
            challenge_code: None,
            source_left: false,
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

    /// Every row written before the source kinds lacks `source_server_id`,
    /// `challenge_code` and `source_left`; they must read back as their
    /// defaults (`source_left: false` is what puts nothing old into the
    /// leave-retry scan — that scan also filters on kind).
    #[test]
    fn pre_source_rows_deserialize_with_defaults() {
        let stored = r#"{
            "_id": "01JOB0000000000000000000000",
            "user_id": "01USER000000000000000000000",
            "template_code": "abc123",
            "kind": "Stickers",
            "parent_job_id": "01JOB0000000000000000000001",
            "status": "Failed",
            "stage": "Stickers",
            "done": 0,
            "total": 0,
            "updated_at": "2026-09-26T00:00:00Z"
        }"#;

        let job: DiscordImportJob = serde_json::from_str(stored).unwrap();
        assert_eq!(job.source_server_id, None);
        assert_eq!(job.challenge_code, None);
        assert!(!job.source_left);
    }

    /// Wire strings are the variant names — the contract the crond
    /// dispatch, delta's DTO and the client `stageLabel` all key on — and
    /// `as_variant_str` (used in Mongo filters) agrees with serde for every
    /// new variant, both directions.
    #[test]
    fn new_kinds_and_stages_round_trip_as_variant_names() {
        for (kind, name) in [
            (ImportJobKind::StoatServer, "StoatServer"),
            (ImportJobKind::FluxerServer, "FluxerServer"),
            (ImportJobKind::MatrixSpace, "MatrixSpace"),
        ] {
            assert_eq!(kind.as_variant_str(), name);
            assert_eq!(serde_json::to_value(&kind).unwrap(), name);
            let back: ImportJobKind = serde_json::from_value(name.into()).unwrap();
            assert_eq!(back, kind);
        }

        for (stage, name) in [
            (ImportStage::Verifying, "Verifying"),
            (ImportStage::Assets, "Assets"),
        ] {
            assert_eq!(stage.as_variant_str(), name);
            assert_eq!(serde_json::to_value(&stage).unwrap(), name);
            let back: ImportStage = serde_json::from_value(name.into()).unwrap();
            assert_eq!(back, stage);
        }
    }

    /// `builds_server` gates server rollback: true for every kind that
    /// creates a server, false for `Stickers` (its server is a live one the
    /// user already owned). `SOURCE_KINDS` and `is_source` must agree.
    #[test]
    fn kind_classification() {
        assert!(ImportJobKind::Template.builds_server());
        assert!(!ImportJobKind::Stickers.builds_server());
        assert!(!ImportJobKind::Template.is_source());
        assert!(!ImportJobKind::Stickers.is_source());

        for kind in ImportJobKind::SOURCE_KINDS {
            assert!(kind.is_source(), "{kind:?} listed but not is_source");
            assert!(kind.builds_server(), "{kind:?} must own its server");
        }
        assert_eq!(
            ImportJobKind::SOURCE_KINDS
                .iter()
                .filter(|kind| kind.is_source())
                .count(),
            3
        );
    }

    /// Birth invariants of a source job, and the wire shape: `source_left`
    /// is omitted while false (so a fresh row looks exactly like an old
    /// one to the `$ne: true` filter) and written once true.
    #[test]
    fn source_jobs_are_born_at_verifying() {
        let mut job = DiscordImportJob::new_source(
            "01USER000000000000000000000".to_string(),
            ImportJobKind::StoatServer,
            "https://stoat.chat/invite/AbCdEf12".to_string(),
            Some("01SRCSERVER0000000000000000".to_string()),
            Some("sloga-import-ABCDEFGH".to_string()),
        );
        assert_eq!(job.kind, ImportJobKind::StoatServer);
        assert_eq!(job.status, ImportStatus::Queued);
        assert_eq!(job.stage, ImportStage::Verifying);
        assert_eq!(job.template_code, "https://stoat.chat/invite/AbCdEf12");
        assert_eq!(job.source_guild_id, None);
        assert_eq!(job.parent_job_id, None);
        assert!(!job.source_left);

        let wire = serde_json::to_value(&job).unwrap();
        assert_eq!(wire["kind"], "StoatServer");
        assert_eq!(wire["stage"], "Verifying");
        assert_eq!(wire["source_server_id"], "01SRCSERVER0000000000000000");
        assert_eq!(wire["challenge_code"], "sloga-import-ABCDEFGH");
        assert!(wire.get("source_left").is_none());

        job.source_left = true;
        let wire = serde_json::to_value(&job).unwrap();
        assert_eq!(wire["source_left"], true);
    }

    #[test]
    #[should_panic(expected = "non-source kind")]
    fn new_source_refuses_template_kind() {
        DiscordImportJob::new_source(
            "01USER000000000000000000000".to_string(),
            ImportJobKind::Template,
            "abc123".to_string(),
            None,
            None,
        );
    }

    #[test]
    #[should_panic(expected = "non-source kind")]
    fn new_source_refuses_stickers_kind() {
        DiscordImportJob::new_source(
            "01USER000000000000000000000".to_string(),
            ImportJobKind::Stickers,
            String::new(),
            None,
            None,
        );
    }
}
