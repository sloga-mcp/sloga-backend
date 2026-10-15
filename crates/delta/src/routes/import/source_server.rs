//! Start a server import from another platform.
//! POST /import/<source>/server
//!
//! Stoat (release 1) verifies synchronously before anything is queued: the
//! pasted link or id is whitelisted, resolved, fetched as the operator bot,
//! and the requester's challenge code must be in the server description.
//! The job then carries the resolved server id and the code that matched;
//! crond acts on those, never on the pasted string.

use chrono::{DateTime, Utc};
use revolt_config::{config, ApiImport, ApiImportBotSource, Settings};
use revolt_database::{Database, DiscordImportJob, ImportJobKind, User};
use revolt_result::{create_error, Result};
use rocket::request::FromParam;
use rocket::serde::json::Json;
use rocket::State;
use validator::Validate;

use super::discord_template::ResponseImportStarted;
use super::dto::DataImportSourceServer;
use super::stoat_source::{self, parse_stoat_source, verify_stoat_source, StoatApi};

/// A platform servers can be imported from: the `<source>` path segment
#[derive(Clone, Copy, Debug, PartialEq, Eq, JsonSchema)]
#[schemars(rename_all = "lowercase")]
pub enum ImportSource {
    Stoat,
    Fluxer,
    Matrix,
}

impl ImportSource {
    /// Challenge source tag (`import_challenge`); also the path segment
    pub fn tag(self) -> &'static str {
        match self {
            ImportSource::Stoat => stoat_source::SOURCE_TAG,
            ImportSource::Fluxer => "fluxer",
            ImportSource::Matrix => "matrix",
        }
    }

    /// Job kind for an import from this source. Derived from the route,
    /// never from the request body.
    pub fn kind(self) -> ImportJobKind {
        match self {
            ImportSource::Stoat => ImportJobKind::StoatServer,
            ImportSource::Fluxer => ImportJobKind::FluxerServer,
            ImportSource::Matrix => ImportJobKind::MatrixSpace,
        }
    }

    /// Whether this build can import from the source at all. Release 1 is
    /// Stoat only; Fluxer and Matrix stay unavailable here even with their
    /// config filled in, until their own releases flip this.
    pub fn implemented(self) -> bool {
        matches!(self, ImportSource::Stoat)
    }

    /// Implemented AND configured (`ready()`, which includes the shared
    /// challenge secret)
    pub fn ready(self, import: &ApiImport) -> bool {
        self.implemented()
            && match self {
                ImportSource::Stoat => import.stoat_ready(),
                ImportSource::Fluxer => import.fluxer_ready(),
                ImportSource::Matrix => import.matrix_ready(),
            }
    }
}

impl<'r> FromParam<'r> for ImportSource {
    type Error = &'r str;

    /// Exact lowercase names only. Anything else (including `discord`, whose
    /// routes are static paths) fails to parse, Rocket forwards, and the
    /// rank-2 catch-alls below answer 404.
    fn from_param(param: &'r str) -> std::result::Result<Self, Self::Error> {
        match param {
            "stoat" => Ok(ImportSource::Stoat),
            "fluxer" => Ok(ImportSource::Fluxer),
            "matrix" => Ok(ImportSource::Matrix),
            _ => Err(param),
        }
    }
}

/// # Import a Server From Another Platform
///
/// Verifies that you manage the source server (your challenge code from
/// `GET /import/<source>/challenge` must be in its description), then queues
/// the import. Returns immediately with a job id; progress streams over your
/// private WebSocket topic, and the job is followed with the same routes as
/// a Discord import.
#[openapi(tag = "Import")]
#[post("/<source>/server", data = "<data>")]
pub async fn import_source_server(
    db: &State<Database>,
    user: User,
    source: ImportSource,
    data: Json<DataImportSourceServer>,
) -> Result<Json<ResponseImportStarted>> {
    let config = config().await;
    start_source_import(
        db,
        &user,
        source,
        data.into_inner(),
        &config,
        Utc::now(),
        StoatApi::new,
    )
    .await
    .map(Json)
}

/// Any other `<source>` on the POST route.
///
/// A typed path parameter that fails to parse makes Rocket forward with 422,
/// which would reach the client as a bare 422. This catch-all ranks below
/// the typed route (explicit rank 2 vs the default negative rank) and turns
/// every unknown source into the API's 404.
#[openapi(skip)]
#[post("/<_>/server", rank = 2)]
pub async fn import_unknown_source_server() -> Result<()> {
    Err(create_error!(NotFound))
}

/// The guards and the upstream check, with the config, clock and Stoat
/// client passed in so tests can point them at a fake upstream.
async fn start_source_import(
    db: &Database,
    user: &User,
    source: ImportSource,
    data: DataImportSourceServer,
    config: &Settings,
    now: DateTime<Utc>,
    stoat_api: fn(&ApiImportBotSource) -> Result<StoatApi>,
) -> Result<ResponseImportStarted> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    // Not built in this release, or not configured: nothing below runs and
    // no upstream is contacted
    if !source.ready(&config.api.import) {
        return Err(create_error!(ImportSourceUnavailable));
    }

    // This route creates a server, so it honors the same operator gate as
    // `POST /servers/create` (see `discord_template.rs`). The worker
    // re-checks it immediately before `Server::create`.
    let restrict = &config.features.limits.global.restrict_server_creation;
    if !restrict.is_empty() && !restrict.contains(&user.id) {
        return Err(create_error!(CantCreateServers));
    }

    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Only Stoat passes `ready` in this release; the match keeps a future
    // source from falling through to Stoat's parser and client
    let parsed = match source {
        ImportSource::Stoat => {
            parse_stoat_source(&data.source).ok_or_else(|| create_error!(InvalidOperation))?
        }
        ImportSource::Fluxer | ImportSource::Matrix => {
            return Err(create_error!(ImportSourceUnavailable))
        }
    };

    // Cheap local refusals before spending upstream calls
    user.can_acquire_server(db).await?;

    if db
        .fetch_active_discord_import_job_for_user(&user.id)
        .await?
        .is_some()
    {
        return Err(create_error!(ImportAlreadyInProgress));
    }

    let api = stoat_api(&config.api.import.stoat)?;
    let verified = verify_stoat_source(
        &api,
        &parsed,
        config.api.import.challenge_secret.as_bytes(),
        &user.id,
        now,
    )
    .await?;

    let job = DiscordImportJob::new_source(
        user.id.clone(),
        source.kind(),
        data.source,
        Some(verified.server_id),
        Some(verified.challenge_code),
    );
    // A concurrent request that also passed the check above is refused here
    // with the same 409 (unique active-job index / reference mutex)
    db.insert_discord_import_job(&job).await?;

    Ok(ResponseImportStarted { job_id: job.id })
}

#[cfg(test)]
mod tests {
    use super::super::stoat_source::fake_upstream::{FakeStoat, BOT_TOKEN};
    use super::*;
    use crate::util::test::TestHarness;
    use chrono::TimeZone;
    use revolt_config::ApiImportMatrix;
    use revolt_database::util::import_challenge::code;
    use revolt_database::{BotInformation, ImportStage, ImportStatus};
    use rocket::http::{ContentType, Header, Status};

    const SECRET: &str = "r1-route-test-secret";
    const SERVER: &str = "01HSERVER00000000000000000";
    const INVITE: &str = "AbC123xy";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 15, 12, 0, 0).unwrap()
    }

    /// Settings with Stoat ready and pointed at `fake`
    async fn ready_settings(fake: &FakeStoat) -> Settings {
        let mut settings = config().await;
        settings.api.import.challenge_secret = SECRET.to_string();
        settings.api.import.stoat = fake.source_config();
        settings.features.limits.global.restrict_server_creation = vec![];
        assert!(settings.api.import.stoat_ready());
        settings
    }

    fn body(source: &str) -> DataImportSourceServer {
        DataImportSourceServer {
            source: source.to_string(),
        }
    }

    async fn start(
        harness: &TestHarness,
        user: &User,
        source: ImportSource,
        pasted: &str,
        settings: &Settings,
    ) -> Result<ResponseImportStarted> {
        start_source_import(
            &harness.db,
            user,
            source,
            body(pasted),
            settings,
            now(),
            StoatApi::loopback_for_tests,
        )
        .await
    }

    fn assert_error(result: Result<ResponseImportStarted>, expected: &str) {
        match result {
            Ok(started) => panic!("expected {expected}, got job {}", started.job_id),
            Err(error) => assert_eq!(format!("{:?}", error.error_type), expected),
        }
    }

    /// A fake whose invite resolves to `SERVER` and whose description holds
    /// `user_id`'s code for today
    async fn verifying_fake(user_id: &str) -> FakeStoat {
        let mine = code(SECRET.as_bytes(), "stoat", user_id, now().date_naive());
        FakeStoat::new()
            .reply(
                &format!("/invites/{INVITE}"),
                200,
                json!({ "type": "Server", "code": INVITE, "server_id": SERVER }),
            )
            .reply(
                &format!("/servers/{SERVER}"),
                200,
                json!({ "_id": SERVER, "name": "S", "description": format!("hi {mine}") }),
            )
            .start()
            .await
    }

    #[test]
    fn from_param_accepts_exact_names_only() {
        assert_eq!(ImportSource::from_param("stoat"), Ok(ImportSource::Stoat));
        assert_eq!(ImportSource::from_param("fluxer"), Ok(ImportSource::Fluxer));
        assert_eq!(ImportSource::from_param("matrix"), Ok(ImportSource::Matrix));
        for other in ["discord", "Stoat", "STOAT", "stoat ", "", "revolt"] {
            assert_eq!(ImportSource::from_param(other), Err(other));
        }
        for source in [
            ImportSource::Stoat,
            ImportSource::Fluxer,
            ImportSource::Matrix,
        ] {
            assert_eq!(ImportSource::from_param(source.tag()), Ok(source));
        }
    }

    #[test]
    fn happy_path_stores_a_verified_stoat_job() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, user) = harness.new_user().await;
            let fake = verifying_fake(&user.id).await;
            let settings = ready_settings(&fake).await;

            let pasted = format!("https://stoat.chat/invite/{INVITE}");
            let started = start(&harness, &user, ImportSource::Stoat, &pasted, &settings)
                .await
                .expect("import queued");

            let job = harness
                .db
                .fetch_discord_import_job(&started.job_id)
                .await
                .expect("job stored");
            let expected_code = code(SECRET.as_bytes(), "stoat", &user.id, now().date_naive());
            assert_eq!(job.user_id, user.id);
            assert_eq!(job.kind, ImportJobKind::StoatServer);
            assert_eq!(job.status, ImportStatus::Queued);
            assert_eq!(job.stage, ImportStage::Verifying);
            assert_eq!(job.template_code, pasted);
            assert_eq!(job.source_server_id.as_deref(), Some(SERVER));
            assert_eq!(job.challenge_code, Some(expected_code));
            assert!(!job.source_left);

            let seen = fake.seen();
            assert_eq!(seen.len(), 2, "{seen:?}");
            assert_eq!(seen[0].bot_token, None);
            assert_eq!(seen[1].bot_token.as_deref(), Some(BOT_TOKEN));
        })
    }

    #[test]
    fn failed_verification_stores_nothing() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, user) = harness.new_user().await;
            let (_, _, someone_else) = harness.new_user().await;
            // The description holds a code, but for a different Sloga user
            let fake = verifying_fake(&someone_else.id).await;
            let settings = ready_settings(&fake).await;

            assert_error(
                start(&harness, &user, ImportSource::Stoat, INVITE, &settings).await,
                "ImportVerificationMissing",
            );
            assert!(harness
                .db
                .fetch_active_discord_import_job_for_user(&user.id)
                .await
                .unwrap()
                .is_none());
        })
    }

    #[test]
    fn fluxer_and_matrix_are_unavailable_even_when_configured() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, user) = harness.new_user().await;
            let fake = verifying_fake(&user.id).await;
            let mut settings = ready_settings(&fake).await;
            settings.api.import.fluxer = fake.source_config();
            settings.api.import.matrix = ApiImportMatrix {
                enabled: true,
                homeserver_url: fake.api_url.clone(),
                bot_user_id: "@sloga-import:example".to_string(),
                access_token: "token".to_string(),
                max_joins: 8,
            };
            assert!(settings.api.import.fluxer_ready());
            assert!(settings.api.import.matrix_ready());

            for source in [ImportSource::Fluxer, ImportSource::Matrix] {
                assert_error(
                    start(&harness, &user, source, INVITE, &settings).await,
                    "ImportSourceUnavailable",
                );
            }
            assert!(fake.seen().is_empty(), "{:?}", fake.seen());
        })
    }

    #[test]
    fn stoat_not_ready_is_unavailable() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, user) = harness.new_user().await;
            let fake = verifying_fake(&user.id).await;

            let mut disabled = ready_settings(&fake).await;
            disabled.api.import.stoat.enabled = false;
            let mut no_secret = ready_settings(&fake).await;
            no_secret.api.import.challenge_secret = String::new();

            for settings in [disabled, no_secret] {
                assert_error(
                    start(&harness, &user, ImportSource::Stoat, INVITE, &settings).await,
                    "ImportSourceUnavailable",
                );
            }
            assert!(fake.seen().is_empty());
        })
    }

    #[test]
    fn local_refusals_happen_before_any_upstream_call() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, user) = harness.new_user().await;
            let fake = verifying_fake(&user.id).await;
            let settings = ready_settings(&fake).await;

            // Bot accounts
            let mut bot = user.clone();
            bot.bot = Some(BotInformation {
                owner: user.id.clone(),
            });
            assert_error(
                start(&harness, &bot, ImportSource::Stoat, INVITE, &settings).await,
                "IsBot",
            );

            // Server-creation allowlist that excludes the caller
            let mut restricted = settings.clone();
            restricted.features.limits.global.restrict_server_creation =
                vec!["01SOMEONEELSE0000000000000".to_string()];
            assert_error(
                start(&harness, &user, ImportSource::Stoat, INVITE, &restricted).await,
                "CantCreateServers",
            );

            // Unparseable source
            assert_error(
                start(
                    &harness,
                    &user,
                    ImportSource::Stoat,
                    "https://evil.example/x",
                    &settings,
                )
                .await,
                "InvalidOperation",
            );

            // Over the DTO length bound
            let result = start(
                &harness,
                &user,
                ImportSource::Stoat,
                &"a".repeat(257),
                &settings,
            )
            .await;
            assert!(
                matches!(
                    &result,
                    Err(error) if format!("{:?}", error.error_type).starts_with("FailedValidation")
                ),
                "{:?}",
                result.err()
            );

            // One active import at a time
            harness
                .db
                .insert_discord_import_job(&DiscordImportJob::new(
                    user.id.clone(),
                    "abc".to_string(),
                ))
                .await
                .unwrap();
            assert_error(
                start(&harness, &user, ImportSource::Stoat, INVITE, &settings).await,
                "ImportAlreadyInProgress",
            );

            assert!(fake.seen().is_empty(), "{:?}", fake.seen());
        })
    }

    // ---- through Rocket: path parsing, ranking, default config ----

    /// POST and return the status plus the error `type` (or the raw body)
    async fn post_error(
        harness: &TestHarness,
        token: &str,
        path: &str,
        body: &str,
    ) -> (Status, String) {
        let response = harness
            .client
            .post(path.to_string())
            .header(ContentType::JSON)
            .header(Header::new("X-Session-Token", token.to_string()))
            .body(body.to_string())
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        let kind = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| value["type"].as_str().map(str::to_string))
            .unwrap_or(body);
        (status, kind)
    }

    #[test]
    fn unknown_sources_are_404_and_discord_routes_are_not_shadowed() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, session, _) = harness.new_user().await;
            let body = r#"{"source":"AbC123"}"#;

            // Four POSTs in all: import POSTs share a 5-per-window bucket
            for path in [
                "/import/discord/server",
                "/import/bogus/server",
                "/import/Stoat/server",
            ] {
                assert_eq!(
                    post_error(&harness, &session.token, path, body).await,
                    (Status::NotFound, "NotFound".to_string()),
                    "{path}"
                );
            }

            // The static Discord template route still wins its own path: it
            // reaches its handler, which never answers 404 or 422 (disabled
            // config gives OperationFailed; enabled queues a job)
            let (status, kind) = post_error(
                &harness,
                &session.token,
                "/import/discord/template",
                r#"{"template":"abc123"}"#,
            )
            .await;
            assert!(
                status != Status::NotFound && status != Status::UnprocessableEntity,
                "/import/discord/template was shadowed or unrouted: {} {}",
                status,
                kind
            );
        })
    }

    /// The shipped config keeps every source dark: the route answers
    /// `ImportSourceUnavailable` and never reaches an upstream
    #[test]
    fn default_config_keeps_every_source_unavailable() {
        crate::util::test::rt().block_on(async {
            let import = config().await.api.import;
            assert!(
                !import.stoat_ready() && !import.fluxer_ready() && !import.matrix_ready(),
                "test config unexpectedly enables an import source"
            );

            let harness = TestHarness::new().await;
            let (_, session, _) = harness.new_user().await;
            for source in ["stoat", "fluxer", "matrix"] {
                assert_eq!(
                    post_error(
                        &harness,
                        &session.token,
                        &format!("/import/{source}/server"),
                        r#"{"source":"AbC123"}"#
                    )
                    .await,
                    (Status::BadRequest, "ImportSourceUnavailable".to_string()),
                    "{source}"
                );
            }

            // Unauthenticated: refused by the session guard
            let status = harness
                .client
                .post("/import/stoat/server")
                .header(ContentType::JSON)
                .body(r#"{"source":"AbC123"}"#)
                .dispatch()
                .await
                .status();
            assert_eq!(status, Status::Unauthorized);
        })
    }
}
