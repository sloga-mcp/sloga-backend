//! Start a server import from another platform.
//! POST /import/<source>/server
//!
//! Every source verifies synchronously before anything is queued: the pasted
//! link or id is whitelisted by that source's parser, resolved, and checked
//! as the operator bot for the requester's challenge code. Stoat looks for
//! it in the server description; Fluxer looks for a role named exactly the
//! code, holding Manage Server, whose history the guild audit log confirms.
//! The job then carries the resolved server id and the code that matched;
//! crond acts on those, never on the pasted string.

use chrono::{DateTime, Utc};
use revolt_config::{config, ApiImport, Settings};
use revolt_database::{Database, DiscordImportJob, ImportJobKind, User};
use revolt_result::{create_error, Result};
use rocket::request::FromParam;
use rocket::serde::json::Json;
use rocket::State;
use validator::Validate;

use super::discord_template::ResponseImportStarted;
use super::dto::DataImportSourceServer;
use super::fluxer_source::{
    self, parse_fluxer_source, verify_fluxer_source, FluxerApi, FluxerSource,
};
use super::stoat_source::{
    self, api_url_is_https, parse_stoat_source, verify_stoat_source, StoatApi, StoatSource,
    Transport,
};
use super::upstream_throttle::UpstreamThrottle;

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
            ImportSource::Fluxer => fluxer_source::SOURCE_TAG,
            ImportSource::Matrix => "matrix",
        }
    }

    /// The outbound budgets for this source's verification calls, shared by
    /// every delta process. Each source has its own: spending one never
    /// refuses another.
    pub fn throttle(self) -> UpstreamThrottle {
        UpstreamThrottle::for_source(self.tag())
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

    /// Whether this build can import from the source at all: Stoat and
    /// Fluxer. Matrix stays unavailable here even with its config filled in,
    /// until its own release flips this.
    pub fn implemented(self) -> bool {
        matches!(self, ImportSource::Stoat | ImportSource::Fluxer)
    }

    /// Implemented AND configured (the config's `ready()`, which includes
    /// the shared challenge secret), with no check on the API URL's scheme
    fn configured(self, import: &ApiImport) -> bool {
        self.implemented()
            && match self {
                ImportSource::Stoat => import.stoat_ready(),
                ImportSource::Fluxer => import.fluxer_ready(),
                ImportSource::Matrix => import.matrix_ready(),
            }
    }

    /// The configured base URL delta would call
    fn api_url(self, import: &ApiImport) -> &str {
        match self {
            ImportSource::Stoat => &import.stoat.api_url,
            ImportSource::Fluxer => &import.fluxer.api_url,
            ImportSource::Matrix => &import.matrix.homeserver_url,
        }
    }

    /// Implemented, configured, and its API URL is `https://`: the client
    /// refuses plain HTTP, so a source configured with one could never
    /// verify. The one readiness test for the POST and challenge routes and
    /// for what `GET /` advertises.
    pub fn ready(self, import: &ApiImport) -> bool {
        self.configured(import) && api_url_is_https(self.api_url(import))
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
/// `GET /import/<source>/challenge` must be placed on it as that source's
/// instructions say), then queues the import. Returns immediately with a
/// job id; progress streams over your private WebSocket topic, and the job
/// is followed with the same routes as a Discord import.
#[openapi(tag = "Import")]
#[post("/<source>/server", data = "<data>")]
pub async fn import_source_server(
    db: &State<Database>,
    user: User,
    source: ImportSource,
    data: Json<DataImportSourceServer>,
) -> Result<Json<ResponseImportStarted>> {
    // A test driving this handler through Rocket points it at a fake
    // upstream for its own user only; release builds have no such path
    #[cfg(test)]
    {
        if let Some((settings, throttle)) = routed_test_upstream::lookup(&user.id) {
            return start_source_import(
                db,
                &user,
                source,
                data.into_inner(),
                &settings,
                Utc::now(),
                Transport::LoopbackTest,
                &throttle,
            )
            .await
            .map(Json);
        }
    }

    let config = config().await;
    start_source_import(
        db,
        &user,
        source,
        data.into_inner(),
        &config,
        Utc::now(),
        Transport::Production,
        &source.throttle(),
    )
    .await
    .map(Json)
}

/// Per-user overrides for tests that go through the routed handler: the
/// settings to use (pointing at a fake upstream) and isolated budgets.
/// Keyed by user so tests running alongside are unaffected.
#[cfg(test)]
pub(super) mod routed_test_upstream {
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};

    use revolt_config::Settings;

    use super::UpstreamThrottle;

    static ROUTES: LazyLock<Mutex<HashMap<String, (Settings, UpstreamThrottle)>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    pub fn route(user_id: &str, settings: Settings, throttle: UpstreamThrottle) {
        ROUTES
            .lock()
            .unwrap()
            .insert(user_id.to_string(), (settings, throttle));
    }

    pub fn lookup(user_id: &str) -> Option<(Settings, UpstreamThrottle)> {
        ROUTES.lock().unwrap().get(user_id).cloned()
    }
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

/// What the user pasted, parsed by its own source's rules
enum ParsedSource {
    Stoat(StoatSource),
    Fluxer(FluxerSource),
}

/// The guards and the upstream check, with the config, clock, transport and
/// outbound budgets passed in so tests can point them at a fake upstream.
/// `throttle` must be `source`'s own budgets (`ImportSource::throttle`).
///
/// Order matters: every local refusal comes first, so a refused request
/// spends no outbound budget; the throttle is checked inside the source's
/// verify function before each upstream call.
#[allow(clippy::too_many_arguments)]
async fn start_source_import(
    db: &Database,
    user: &User,
    source: ImportSource,
    data: DataImportSourceServer,
    config: &Settings,
    now: DateTime<Utc>,
    transport: Transport,
    throttle: &UpstreamThrottle,
) -> Result<ResponseImportStarted> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    // Not built in this release, not configured, or not reachable over
    // `transport`: nothing below runs and no upstream is contacted. Under
    // `Production` this is exactly `source.ready()`.
    let import = &config.api.import;
    if !(source.configured(import) && transport.accepts_api_url(source.api_url(import))) {
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

    // Each source parses with its own rules and verifies with its own
    // client; a source without an arm here never falls through to another's
    let parsed = match source {
        ImportSource::Stoat => ParsedSource::Stoat(
            parse_stoat_source(&data.source).ok_or_else(|| create_error!(InvalidOperation))?,
        ),
        ImportSource::Fluxer => ParsedSource::Fluxer(
            parse_fluxer_source(&data.source).ok_or_else(|| create_error!(InvalidOperation))?,
        ),
        ImportSource::Matrix => return Err(create_error!(ImportSourceUnavailable)),
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

    let challenge_secret = config.api.import.challenge_secret.as_bytes();
    let (server_id, challenge_code) = match parsed {
        ParsedSource::Stoat(parsed) => {
            let api = StoatApi::connect(&config.api.import.stoat, transport)?;
            let verified =
                verify_stoat_source(&api, throttle, &parsed, challenge_secret, &user.id, now)
                    .await?;
            (verified.server_id, verified.challenge_code)
        }
        ParsedSource::Fluxer(parsed) => {
            let api = FluxerApi::connect(&config.api.import.fluxer, transport)?;
            let verified =
                verify_fluxer_source(&api, throttle, &parsed, challenge_secret, &user.id, now)
                    .await?;
            (verified.guild_id, verified.challenge_code)
        }
    };

    let job = DiscordImportJob::new_source(
        user.id.clone(),
        source.kind(),
        data.source,
        Some(server_id),
        Some(challenge_code),
    );
    // A concurrent request that also passed the check above is refused here
    // with the same 409 (unique active-job index / reference mutex)
    db.insert_discord_import_job(&job).await?;

    Ok(ResponseImportStarted { job_id: job.id })
}

#[cfg(test)]
mod tests {
    use super::super::fluxer_source::fixtures as fluxer_fx;
    use super::super::stoat_source::fake_upstream::{FakeStoat, BOT_TOKEN};
    use super::super::upstream_throttle::UpstreamTarget;
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

    /// One request, with `source`'s outbound budgets on keys of its own
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
            Transport::LoopbackTest,
            &UpstreamThrottle::isolated_for_source_tests(source.tag()),
        )
        .await
    }

    /// A request for any source against shared `throttle` budgets
    async fn start_source_with(
        harness: &TestHarness,
        user: &User,
        source: ImportSource,
        pasted: &str,
        settings: &Settings,
        throttle: &UpstreamThrottle,
        at: DateTime<Utc>,
    ) -> Result<ResponseImportStarted> {
        start_source_import(
            &harness.db,
            user,
            source,
            body(pasted),
            settings,
            at,
            Transport::LoopbackTest,
            throttle,
        )
        .await
    }

    /// A Stoat request against shared `throttle` budgets, as every request
    /// to one delta shares them
    async fn start_with(
        harness: &TestHarness,
        user: &User,
        pasted: &str,
        settings: &Settings,
        throttle: &UpstreamThrottle,
        at: DateTime<Utc>,
    ) -> Result<ResponseImportStarted> {
        start_source_import(
            &harness.db,
            user,
            ImportSource::Stoat,
            body(pasted),
            settings,
            at,
            Transport::LoopbackTest,
            throttle,
        )
        .await
    }

    /// A fake whose server `SERVER` has a description holding today's code
    /// for each of `user_ids` (none: no code at all)
    async fn server_fake(user_ids: &[&str]) -> FakeStoat {
        let codes: Vec<String> = user_ids
            .iter()
            .map(|id| code(SECRET.as_bytes(), "stoat", id, now().date_naive()))
            .collect();
        FakeStoat::new()
            .reply(
                &format!("/servers/{SERVER}"),
                200,
                json!({ "_id": SERVER, "name": "S", "description": codes.join(" ") }),
            )
            .start()
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
    fn matrix_is_unavailable_even_when_configured() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, user) = harness.new_user().await;
            let fake = verifying_fake(&user.id).await;
            let mut settings = ready_settings(&fake).await;
            settings.api.import.matrix = ApiImportMatrix {
                enabled: true,
                homeserver_url: fake.api_url.clone(),
                bot_user_id: "@sloga-import:example".to_string(),
                access_token: "token".to_string(),
                max_joins: 8,
            };
            assert!(settings.api.import.matrix_ready());

            assert_error(
                start(&harness, &user, ImportSource::Matrix, INVITE, &settings).await,
                "ImportSourceUnavailable",
            );
            assert!(fake.seen().is_empty(), "{:?}", fake.seen());
        })
    }

    #[test]
    fn stoat_and_fluxer_are_implemented_matrix_is_not() {
        assert!(ImportSource::Stoat.implemented());
        assert!(ImportSource::Fluxer.implemented());
        assert!(!ImportSource::Matrix.implemented());
        assert_eq!(ImportSource::Fluxer.tag(), "fluxer");
        assert_eq!(ImportSource::Fluxer.kind(), ImportJobKind::FluxerServer);
    }

    /// The live route spends each source's own budgets: `throttle()` is
    /// `for_source(tag)`, and Stoat's is release 1's Stoat throttle
    #[test]
    fn each_source_verifies_against_its_own_budgets() {
        let debug = |throttle: UpstreamThrottle| format!("{throttle:?}");
        for source in [
            ImportSource::Stoat,
            ImportSource::Fluxer,
            ImportSource::Matrix,
        ] {
            assert_eq!(
                debug(source.throttle()),
                debug(UpstreamThrottle::for_source(source.tag()))
            );
        }
        assert_eq!(
            debug(ImportSource::Stoat.throttle()),
            debug(UpstreamThrottle::stoat())
        );
        let fluxer = debug(ImportSource::Fluxer.throttle());
        assert!(fluxer.contains(r#""import_upstream:fluxer""#), "{}", fluxer);
        assert_ne!(fluxer, debug(UpstreamThrottle::stoat()));
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

    /// The route guard and `GET /` agree: a plain-HTTP `api_url` is not
    /// ready, and the production transport refuses it before any call
    #[test]
    fn production_transport_refuses_a_plain_http_api_url() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, user) = harness.new_user().await;
            let fake = verifying_fake(&user.id).await;
            let settings = ready_settings(&fake).await;
            assert!(settings.api.import.stoat.api_url.starts_with("http://"));
            assert!(!ImportSource::Stoat.ready(&settings.api.import));

            let result = start_source_import(
                &harness.db,
                &user,
                ImportSource::Stoat,
                body(INVITE),
                &settings,
                now(),
                Transport::Production,
                &UpstreamThrottle::isolated_for_tests(),
            )
            .await;
            assert_error(result, "ImportSourceUnavailable");
            assert!(fake.seen().is_empty(), "{:?}", fake.seen());
        })
    }

    // ---- outbound budgets ----

    #[test]
    fn a_second_verification_by_one_user_within_30s_makes_no_upstream_call() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, user) = harness.new_user().await;
            // No code in the description: the first attempt fails, so
            // the one-active-job check cannot be what stops the second
            let fake = server_fake(&[]).await;
            let settings = ready_settings(&fake).await;
            let throttle = UpstreamThrottle::isolated_for_tests();

            assert_error(
                start_with(&harness, &user, SERVER, &settings, &throttle, now()).await,
                "ImportVerificationMissing",
            );
            assert_eq!(fake.seen().len(), 1);

            for at in [now(), now() + chrono::Duration::seconds(29)] {
                assert_error(
                    start_with(&harness, &user, SERVER, &settings, &throttle, at).await,
                    "ImportUpstreamUnavailable",
                );
            }
            assert_eq!(fake.seen().len(), 1, "{:?}", fake.seen());

            // After 30 s the user may try again
            assert_error(
                start_with(
                    &harness,
                    &user,
                    SERVER,
                    &settings,
                    &throttle,
                    now() + chrono::Duration::milliseconds(30_001),
                )
                .await,
                "ImportVerificationMissing",
            );
            assert_eq!(fake.seen().len(), 2);
        })
    }

    #[test]
    fn a_third_verification_of_one_server_within_10s_makes_no_upstream_call() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, first) = harness.new_user().await;
            let (_, _, second) = harness.new_user().await;
            let (_, _, third) = harness.new_user().await;
            let fake = server_fake(&[]).await;
            let settings = ready_settings(&fake).await;
            let throttle = UpstreamThrottle::isolated_for_tests();

            for user in [&first, &second] {
                assert_error(
                    start_with(&harness, user, SERVER, &settings, &throttle, now()).await,
                    "ImportVerificationMissing",
                );
            }
            assert_eq!(fake.seen().len(), 2);

            // Lowercase is the same server
            assert_error(
                start_with(
                    &harness,
                    &third,
                    &SERVER.to_lowercase(),
                    &settings,
                    &throttle,
                    now(),
                )
                .await,
                "ImportUpstreamUnavailable",
            );
            assert_eq!(fake.seen().len(), 2, "{:?}", fake.seen());
        })
    }

    #[test]
    fn the_global_cap_refuses_without_an_upstream_call() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, user) = harness.new_user().await;
            let fake = verifying_fake(&user.id).await;
            let settings = ready_settings(&fake).await;
            let throttle = UpstreamThrottle::isolated_for_tests();

            // Ten calls on other servers in this window
            for i in 0..10 {
                throttle
                    .next_call(UpstreamTarget::Server(&format!("FILL{i}")), now())
                    .await
                    .unwrap();
            }

            assert_error(
                start_with(&harness, &user, INVITE, &settings, &throttle, now()).await,
                "ImportUpstreamUnavailable",
            );
            assert!(fake.seen().is_empty(), "{:?}", fake.seen());
        })
    }

    /// Requests refused by a local guard spend no budget: not the user's,
    /// not the target's, not the global one
    #[test]
    fn local_refusals_spend_no_outbound_budget() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, first) = harness.new_user().await;
            let (_, _, second) = harness.new_user().await;
            let (_, _, busy) = harness.new_user().await;
            let (_, _, late) = harness.new_user().await;
            let fake = server_fake(&[&first.id, &second.id]).await;
            let settings = ready_settings(&fake).await;
            let throttle = UpstreamThrottle::isolated_for_tests();

            // Leave room for exactly two calls in the global budget
            for i in 0..8 {
                throttle
                    .next_call(UpstreamTarget::Server(&format!("FILL{i}")), now())
                    .await
                    .unwrap();
            }

            let mut restricted = settings.clone();
            restricted.features.limits.global.restrict_server_creation =
                vec!["01SOMEONEELSE0000000000000".to_string()];
            let mut dark = settings.clone();
            dark.api.import.stoat.enabled = false;
            let mut bot = first.clone();
            bot.bot = Some(BotInformation {
                owner: first.id.clone(),
            });
            harness
                .db
                .insert_discord_import_job(&DiscordImportJob::new(
                    busy.id.clone(),
                    "abc".to_string(),
                ))
                .await
                .unwrap();

            // Every refusal names SERVER, the target the real requests use
            for _ in 0..3 {
                for (user, settings, expected) in [
                    (&first, &restricted, "CantCreateServers"),
                    (&first, &dark, "ImportSourceUnavailable"),
                    (&bot, &settings, "IsBot"),
                    (&busy, &settings, "ImportAlreadyInProgress"),
                ] {
                    assert_error(
                        start_with(&harness, user, SERVER, settings, &throttle, now()).await,
                        expected,
                    );
                }
                assert_error(
                    start_with(
                        &harness,
                        &first,
                        &format!("{SERVER}?x"),
                        &settings,
                        &throttle,
                        now(),
                    )
                    .await,
                    "InvalidOperation",
                );
            }
            assert!(fake.seen().is_empty(), "{:?}", fake.seen());

            // Both real requests still fit every budget
            for user in [&first, &second] {
                start_with(&harness, user, SERVER, &settings, &throttle, now())
                    .await
                    .expect("budget untouched by refusals");
            }
            assert_eq!(fake.seen().len(), 2);

            // ...and the budgets were live: the next one is refused
            assert_error(
                start_with(&harness, &late, SERVER, &settings, &throttle, now()).await,
                "ImportUpstreamUnavailable",
            );
            assert_eq!(fake.seen().len(), 2);
        })
    }

    /// Parallel POSTs from one user all pass the one-active-job check
    /// before any of them inserts; the user budget lets one verify
    #[test]
    fn parallel_requests_from_one_user_verify_once() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, user) = harness.new_user().await;
            let fake = verifying_fake(&user.id).await;
            let settings = ready_settings(&fake).await;
            let throttle = UpstreamThrottle::isolated_for_tests();

            let results = futures::future::join_all(
                (0..5).map(|_| start_with(&harness, &user, INVITE, &settings, &throttle, now())),
            )
            .await;

            let mut started = 0;
            for result in results {
                match result {
                    Ok(_) => started += 1,
                    Err(error) => {
                        let kind = format!("{:?}", error.error_type);
                        assert!(
                            kind == "ImportUpstreamUnavailable"
                                || kind == "ImportAlreadyInProgress",
                            "{}",
                            kind
                        );
                    }
                }
            }
            assert_eq!(started, 1);
            // One verification: the invite, then the server
            assert_eq!(fake.seen().len(), 2, "{:?}", fake.seen());
        })
    }

    // ---- Fluxer ----

    /// Settings with Fluxer ready and pointed at `fake`
    async fn fluxer_settings(fake: &FakeStoat) -> Settings {
        let mut settings = config().await;
        settings.api.import.challenge_secret = SECRET.to_string();
        settings.api.import.fluxer = fluxer_fx::fluxer_config(fake);
        settings.features.limits.global.restrict_server_creation = vec![];
        assert!(settings.api.import.fluxer_ready());
        settings
    }

    fn fluxer_code(user_id: &str, at: DateTime<Utc>) -> String {
        code(SECRET.as_bytes(), "fluxer", user_id, at.date_naive())
    }

    /// A Fluxer guild where `user_id` made today's code role through the
    /// web UI an hour before `now()`
    async fn fluxer_fake(user_id: &str) -> FakeStoat {
        let made = now() - chrono::Duration::hours(1);
        fluxer_fx::Guild::ui_flow(
            &fluxer_code(user_id, now()),
            fluxer_fx::snowflake_at(made, 7),
            made,
        )
        .fake(now())
        .start()
        .await
    }

    #[test]
    fn happy_path_stores_a_verified_fluxer_job() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, user) = harness.new_user().await;
            let fake = fluxer_fake(&user.id).await;
            let settings = fluxer_settings(&fake).await;

            let pasted = format!("https://fluxer.gg/{}", fluxer_fx::INVITE);
            let started = start(&harness, &user, ImportSource::Fluxer, &pasted, &settings)
                .await
                .expect("import queued");

            let job = harness
                .db
                .fetch_discord_import_job(&started.job_id)
                .await
                .expect("job stored");
            assert_eq!(job.user_id, user.id);
            assert_eq!(job.kind, ImportJobKind::FluxerServer);
            assert_eq!(job.status, ImportStatus::Queued);
            assert_eq!(job.stage, ImportStage::Verifying);
            assert_eq!(job.template_code, pasted);
            assert_eq!(job.source_server_id, Some(fluxer_fx::GUILD.to_string()));
            assert_eq!(job.challenge_code, Some(fluxer_code(&user.id, now())));
            assert!(!job.source_left);

            // The invite is public; the four guild calls are the bot's
            let seen = fake.seen();
            assert_eq!(seen.len(), 5, "{seen:?}");
            assert_eq!(seen[0].header("authorization"), None);
            let bot = format!("Bot {}", fluxer_fx::BOT_TOKEN);
            for call in &seen[1..] {
                assert_eq!(
                    call.header("authorization"),
                    Some(bot.as_str()),
                    "{}",
                    call.path
                );
            }
        })
    }

    #[test]
    fn fluxer_job_by_guild_id_stores_the_canonical_id() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, user) = harness.new_user().await;
            let fake = fluxer_fake(&user.id).await;
            let settings = fluxer_settings(&fake).await;

            let pasted = format!(" 0{} ", fluxer_fx::GUILD);
            let started = start(&harness, &user, ImportSource::Fluxer, &pasted, &settings)
                .await
                .expect("import queued");
            let job = harness
                .db
                .fetch_discord_import_job(&started.job_id)
                .await
                .unwrap();
            assert_eq!(job.source_server_id, Some(fluxer_fx::GUILD.to_string()));
            assert_eq!(fake.seen().len(), 4, "{:?}", fake.seen());
        })
    }

    #[test]
    fn failed_fluxer_verification_stores_nothing() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, user) = harness.new_user().await;
            let (_, _, someone_else) = harness.new_user().await;
            // The role carries a code, but another Sloga user's
            let fake = fluxer_fake(&someone_else.id).await;
            let settings = fluxer_settings(&fake).await;

            assert_error(
                start(
                    &harness,
                    &user,
                    ImportSource::Fluxer,
                    fluxer_fx::INVITE,
                    &settings,
                )
                .await,
                "ImportVerificationMissing",
            );
            // ...and a Stoat code on the role is not a Fluxer code
            let stoat_code = code(SECRET.as_bytes(), "stoat", &user.id, now().date_naive());
            let made = now() - chrono::Duration::hours(1);
            let stoat_tagged =
                fluxer_fx::Guild::ui_flow(&stoat_code, fluxer_fx::snowflake_at(made, 7), made)
                    .fake(now())
                    .start()
                    .await;
            assert_error(
                start(
                    &harness,
                    &user,
                    ImportSource::Fluxer,
                    fluxer_fx::INVITE,
                    &fluxer_settings(&stoat_tagged).await,
                )
                .await,
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
    fn unparseable_fluxer_sources_make_no_upstream_call() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, user) = harness.new_user().await;
            let fake = fluxer_fake(&user.id).await;
            let settings = fluxer_settings(&fake).await;

            for pasted in [
                "",
                "  ",
                "a",
                "../../admin",
                "fluxer.gg/AbC123",
                "Ab C123",
                "https://fluxer.gg/%2e%2e",
                "https://fluxer.gg/AbC123?x=1",
                "1234",
                "123456789012345678901",
            ] {
                let result = start(&harness, &user, ImportSource::Fluxer, pasted, &settings).await;
                let expected = if pasted.is_empty() {
                    "FailedValidation"
                } else {
                    "InvalidOperation"
                };
                assert!(
                    matches!(
                        &result,
                        Err(error) if format!("{:?}", error.error_type).starts_with(expected)
                    ),
                    "{pasted:?}: {:?}",
                    result.as_ref().err()
                );
            }
            assert!(fake.seen().is_empty(), "{:?}", fake.seen());
        })
    }

    /// The route guard holds for Fluxer as for Stoat: not ready, or a
    /// plain-HTTP `api_url` under the production transport, makes no call
    #[test]
    fn fluxer_not_ready_is_unavailable() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, user) = harness.new_user().await;
            let fake = fluxer_fake(&user.id).await;

            let mut disabled = fluxer_settings(&fake).await;
            disabled.api.import.fluxer.enabled = false;
            let mut no_token = fluxer_settings(&fake).await;
            no_token.api.import.fluxer.bot_token = String::new();
            // Stoat's readiness says nothing about Fluxer
            let mut only_stoat = ready_settings(&fake).await;
            only_stoat.api.import.fluxer = Default::default();
            for settings in [disabled, no_token, only_stoat] {
                assert_error(
                    start(
                        &harness,
                        &user,
                        ImportSource::Fluxer,
                        fluxer_fx::INVITE,
                        &settings,
                    )
                    .await,
                    "ImportSourceUnavailable",
                );
            }

            let settings = fluxer_settings(&fake).await;
            assert!(!ImportSource::Fluxer.ready(&settings.api.import));
            assert_error(
                start_source_import(
                    &harness.db,
                    &user,
                    ImportSource::Fluxer,
                    body(fluxer_fx::INVITE),
                    &settings,
                    now(),
                    Transport::Production,
                    &UpstreamThrottle::isolated_for_source_tests("fluxer"),
                )
                .await,
                "ImportSourceUnavailable",
            );
            assert!(fake.seen().is_empty(), "{:?}", fake.seen());
        })
    }

    /// Through the route, with every key in one namespace as the live
    /// throttles share Redis: a user whose Stoat budget is spent can still
    /// verify on Fluxer, and Fluxer budgets spent to the global cap never
    /// refuse a Stoat verification
    #[test]
    fn fluxer_and_stoat_budgets_never_refuse_each_other() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, _, first) = harness.new_user().await;
            let (_, _, second) = harness.new_user().await;
            // Stoat verifies only `second`; Fluxer only `first`
            let stoat_fake = verifying_fake(&second.id).await;
            let fluxer_fake = fluxer_fake(&first.id).await;
            let mut settings = ready_settings(&stoat_fake).await;
            settings.api.import.fluxer = fluxer_fx::fluxer_config(&fluxer_fake);
            assert!(settings.api.import.fluxer_ready());

            let namespace = format!("import_upstream_test:{}", ulid::Ulid::new());
            let stoat = UpstreamThrottle::in_test_namespace(&namespace, "stoat");
            let fluxer = UpstreamThrottle::in_test_namespace(&namespace, "fluxer");
            let guild = fluxer_fx::GUILD.to_string();

            // `first` spends their Stoat verification...
            assert_error(
                start_source_with(
                    &harness,
                    &first,
                    ImportSource::Stoat,
                    SERVER,
                    &settings,
                    &stoat,
                    now(),
                )
                .await,
                "ImportVerificationMissing",
            );
            assert_error(
                start_source_with(
                    &harness,
                    &first,
                    ImportSource::Stoat,
                    SERVER,
                    &settings,
                    &stoat,
                    now(),
                )
                .await,
                "ImportUpstreamUnavailable",
            );
            // ...and still verifies on Fluxer
            start_source_with(
                &harness,
                &first,
                ImportSource::Fluxer,
                &guild,
                &settings,
                &fluxer,
                now(),
            )
            .await
            .expect("Fluxer unaffected by Stoat's spent budget");

            // `second` spends both Fluxer verifications, then Fluxer's global
            // budget is filled (after the guild's 10 s window has passed)
            let later = now() + chrono::Duration::seconds(11);
            for _ in 0..2 {
                assert_error(
                    start_source_with(
                        &harness,
                        &second,
                        ImportSource::Fluxer,
                        &guild,
                        &settings,
                        &fluxer,
                        later,
                    )
                    .await,
                    "ImportVerificationMissing",
                );
            }
            assert_error(
                start_source_with(
                    &harness,
                    &second,
                    ImportSource::Fluxer,
                    &guild,
                    &settings,
                    &fluxer,
                    later,
                )
                .await,
                "ImportUpstreamUnavailable",
            );
            for i in 0..10 {
                let _ = fluxer
                    .next_call(UpstreamTarget::Server(&format!("FILL{i}")), later)
                    .await;
            }
            assert!(fluxer
                .next_call(UpstreamTarget::Server("FILL10"), later)
                .await
                .is_err());

            // Stoat still verifies `second`
            let fluxer_calls = fluxer_fake.seen().len();
            start_source_with(
                &harness,
                &second,
                ImportSource::Stoat,
                INVITE,
                &settings,
                &stoat,
                later,
            )
            .await
            .expect("Stoat unaffected by Fluxer's spent budgets");
            assert_eq!(fluxer_fake.seen().len(), fluxer_calls);
        })
    }

    // ---- through Rocket: path parsing, ranking, default config ----

    /// The routed handler end to end: session guard, JSON body, the guards,
    /// verification against the fake upstream, the stored job, and the
    /// response body
    #[test]
    fn routed_post_queues_a_verified_import() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, session, user) = harness.new_user().await;

            // The handler reads the real clock
            let today = Utc::now();
            let mine = code(SECRET.as_bytes(), "stoat", &user.id, today.date_naive());
            let fake = FakeStoat::new()
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
                .await;
            routed_test_upstream::route(
                &user.id,
                ready_settings(&fake).await,
                UpstreamThrottle::isolated_for_tests(),
            );

            let pasted = format!("https://stoat.chat/invite/{INVITE}");
            let response = harness
                .client
                .post("/import/stoat/server")
                .header(ContentType::JSON)
                .header(Header::new("X-Session-Token", session.token.clone()))
                .body(json!({ "source": pasted }).to_string())
                .dispatch()
                .await;
            let status = response.status();
            let text = response.into_string().await.unwrap_or_default();
            assert_eq!(status, Status::Ok, "{text}");

            let started: serde_json::Value = serde_json::from_str(&text).unwrap();
            let fields: Vec<&String> = started.as_object().unwrap().keys().collect();
            assert_eq!(fields, ["job_id"], "{text}");
            let job_id = started["job_id"].as_str().unwrap();

            let job = harness
                .db
                .fetch_discord_import_job(job_id)
                .await
                .expect("job stored");
            assert_eq!(job.user_id, user.id);
            assert_eq!(job.kind, ImportJobKind::StoatServer);
            assert_eq!(job.status, ImportStatus::Queued);
            assert_eq!(job.stage, ImportStage::Verifying);
            assert_eq!(job.template_code, pasted);
            assert_eq!(job.source_server_id.as_deref(), Some(SERVER));
            assert_eq!(job.challenge_code, Some(mine));

            let seen = fake.seen();
            assert_eq!(seen.len(), 2, "{seen:?}");
            assert_eq!(seen[0].path, format!("/invites/{INVITE}"));
            assert_eq!(seen[1].bot_token.as_deref(), Some(BOT_TOKEN));

            // Followed with the Discord job route, as the docs say
            let response = harness
                .client
                .get(format!("/import/discord/jobs/{job_id}"))
                .header(Header::new("X-Session-Token", session.token.clone()))
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Ok);
        })
    }

    /// `POST /import/fluxer/server` end to end: the path picks Fluxer's
    /// parser and client, and the job is a Fluxer one
    #[test]
    fn routed_post_queues_a_verified_fluxer_import() {
        crate::util::test::rt().block_on(async {
            let harness = TestHarness::new().await;
            let (_, session, user) = harness.new_user().await;

            // The handler reads the real clock: the role is made "now"
            let today = Utc::now();
            let mine = fluxer_code(&user.id, today);
            let fake = fluxer_fx::Guild::ui_flow(&mine, fluxer_fx::snowflake_at(today, 7), today)
                .fake(today)
                .start()
                .await;
            routed_test_upstream::route(
                &user.id,
                fluxer_settings(&fake).await,
                UpstreamThrottle::isolated_for_source_tests("fluxer"),
            );

            let pasted = format!("https://web.fluxer.app/invite/{}", fluxer_fx::INVITE);
            let response = harness
                .client
                .post("/import/fluxer/server")
                .header(ContentType::JSON)
                .header(Header::new("X-Session-Token", session.token.clone()))
                .body(json!({ "source": pasted }).to_string())
                .dispatch()
                .await;
            let status = response.status();
            let text = response.into_string().await.unwrap_or_default();
            assert_eq!(status, Status::Ok, "{text}");

            let started: serde_json::Value = serde_json::from_str(&text).unwrap();
            let job = harness
                .db
                .fetch_discord_import_job(started["job_id"].as_str().unwrap())
                .await
                .expect("job stored");
            assert_eq!(job.kind, ImportJobKind::FluxerServer);
            assert_eq!(job.template_code, pasted);
            assert_eq!(job.source_server_id, Some(fluxer_fx::GUILD.to_string()));
            assert_eq!(job.challenge_code, Some(mine));
            assert_eq!(fake.seen().len(), 5, "{:?}", fake.seen());
        })
    }

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
