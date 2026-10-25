#[cfg(feature = "test")]
use std::sync::OnceLock;
use std::{collections::HashMap, path::Path, sync::LazyLock};

use cached::proc_macro::cached;
use config::{Config, Environment, File, FileFormat};
use futures_locks::RwLock;
use serde::Deserialize;

#[cfg(feature = "sentry")]
pub use sentry::{capture_error, capture_message, Level};
#[cfg(feature = "anyhow")]
pub use sentry::integrations::anyhow::capture_anyhow;

#[cfg(all(feature = "report-macros", feature = "sentry"))]
#[macro_export]
macro_rules! report_error {
    ( $expr: expr, $error: ident $( $tt:tt )? ) => {
        $expr
            .inspect_err(|err| {
                $crate::capture_message(
                    &format!("{err:?} ({}:{}:{})", file!(), line!(), column!()),
                    $crate::Level::Error,
                );
            })
            .map_err(|_| ::revolt_result::create_error!($error))
    };
}

#[cfg(all(feature = "report-macros", feature = "sentry"))]
#[macro_export]
macro_rules! capture_internal_error {
    ( $expr: expr ) => {
        $crate::capture_message(
            &format!("{:?} ({}:{}:{})", $expr, file!(), line!(), column!()),
            $crate::Level::Error,
        );
    };
}

#[cfg(all(feature = "report-macros", feature = "sentry"))]
#[macro_export]
macro_rules! report_internal_error {
    ( $expr: expr ) => {
        $expr
            .inspect_err(|err| {
                $crate::capture_message(
                    &format!("{err:?} ({}:{}:{})", file!(), line!(), column!()),
                    $crate::Level::Error,
                );
            })
            .map_err(|_| ::revolt_result::create_error!(InternalError))
    };
}

/// Paths to search for configuration
static CONFIG_SEARCH_PATHS: [&str; 3] = [
    // current working directory
    "Revolt.toml",
    // current working directory - overrides file
    "Revolt.overrides.toml",
    // root directory, for Docker containers
    "/Revolt.toml",
];

/// Path to search for test overrides
static TEST_OVERRIDE_PATH: &str = "Revolt.test-overrides.toml";

/// Configuration builder
static CONFIG_BUILDER: LazyLock<RwLock<Config>> = LazyLock::new(|| {
    RwLock::new({
        let mut builder = Config::builder().add_source(File::from_str(
            include_str!("../Revolt.toml"),
            FileFormat::Toml,
        ));

        let cwd = std::env::current_dir().unwrap();
        let mut cwd: Option<&Path> = Some(&cwd);

        while let Some(path) = cwd {
            for config_path in CONFIG_SEARCH_PATHS {
                let config_path = path.join(config_path);
                if config_path.exists() {
                    builder = builder
                        .add_source(File::new(config_path.to_str().unwrap(), FileFormat::Toml));
                }
            }

            cwd = path.parent();
        }

        if std::env::var("TEST_DB").is_ok() {
            builder = builder.add_source(File::from_str(
                include_str!("../Revolt.test.toml"),
                FileFormat::Toml,
            ));

            // recursively search upwards for an overrides file (if there is one)
            if let Ok(cwd) = std::env::current_dir() {
                let mut path = Some(cwd.as_path());
                while let Some(current_path) = path {
                    let target_path = current_path.join(TEST_OVERRIDE_PATH);
                    if target_path.exists() {
                        builder = builder
                            .add_source(File::new(target_path.to_str().unwrap(), FileFormat::Toml));
                    }

                    path = current_path.parent();
                }
            }
        }

        builder = builder.add_source(Environment::with_prefix("REVOLT").separator("__"));

        builder.build().unwrap()
    })
});

#[derive(Deserialize, Debug, Clone)]
pub struct Database {
    pub mongodb: String,
    pub redis: String,
    pub redis_pubsub: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RabbitQueues {
    pub acks: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Rabbit {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub default_exchange: String,
    pub queues: RabbitQueues,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Hosts {
    pub app: String,
    pub api: String,
    pub events: String,
    pub autumn: String,
    pub january: String,
    pub livekit: HashMap<String, String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ApiRegistration {
    pub invite_only: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ApiSmtp {
    pub host: String,
    pub username: String,
    pub password: String,
    pub from_address: String,
    pub reply_to: Option<String>,
    pub port: Option<i32>,
    pub use_tls: Option<bool>,
    pub use_starttls: Option<bool>,
    pub expiry: EmailExpiry,
}

/// Email expiration config
#[derive(Deserialize, Debug, Clone)]
pub struct EmailExpiry {
    /// How long email verification codes should last for (in seconds)
    pub expire_verification: i64,
    /// How long password reset codes should last for (in seconds)
    pub expire_password_reset: i64,
    /// How long account deletion codes should last for (in seconds)
    pub expire_account_deletion: i64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct PushVapid {
    pub queue: String,
    pub private_key: String,
    pub public_key: String,
    /// Previous private key, tried once when a push service rejects the
    /// primary (401/403) so dormant subscriptions survive a rotation.
    /// Empty = fallback disabled. Defaulted so a config without it still boots.
    #[serde(default)]
    pub legacy_private_key: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct PushUnifiedPush {
    pub queue: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct PushFcm {
    pub queue: String,
    pub key_type: String,
    pub project_id: String,
    pub private_key_id: String,
    pub private_key: String,
    pub client_email: String,
    pub client_id: String,
    pub auth_uri: String,
    pub token_uri: String,
    pub auth_provider_x509_cert_url: String,
    pub client_x509_cert_url: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct PushApn {
    pub queue: String,
    pub sandbox: bool,
    pub pkcs8: String,
    pub key_id: String,
    pub team_id: String,
    /// APNs topic — must equal the iOS app's bundle identifier, or Apple
    /// rejects every push with `TopicDisallowed` and nothing is delivered.
    pub topic: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ApiSecurityCaptcha {
    pub hcaptcha_key: String,
    pub hcaptcha_sitekey: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ApiSecurityShield {
    pub host: String,
    pub key: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ApiSecurity {
    pub shield: ApiSecurityShield,
    pub voso_legacy_token: String,
    pub captcha: ApiSecurityCaptcha,
    pub trust_cloudflare: bool,
    pub easypwned: String,
    pub tenor_key: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ApiWorkers {
    pub max_concurrent_connections: usize,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ApiLiveKit {
    pub call_ring_duration: usize,
    pub nodes: HashMap<String, LiveKitNode>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct LiveKitNode {
    pub url: String,
    pub lat: f64,
    pub lon: f64,
    pub key: String,
    pub secret: String,

    // whether to hide the node in the nodes list
    #[serde(default)]
    pub private: bool,

    // The node runs against its own Redis (a different region), so this
    // deployment's LiveKit `nodes` / `room_node_map` hashes never describe
    // it. The voice-ingress ghost sweep must not judge channels pinned to
    // such a node: to the local Redis they always look unrouted.
    #[serde(default)]
    pub remote: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ApiUsers {
    pub early_adopter_cutoff: Option<u64>,
    pub min_username_length: usize,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct ApiOauthGoogle {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub redirect_uri: String,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct ApiOauthApple {
    #[serde(default)]
    pub enabled: bool,
    /// Services ID acting as the OAuth client id (e.g. "gg.sloga.signin")
    #[serde(default)]
    pub client_id: String,
    /// Apple Developer Team ID
    #[serde(default)]
    pub team_id: String,
    /// Key ID of the Sign in with Apple private key
    #[serde(default)]
    pub key_id: String,
    /// Contents of the .p8 private key (PKCS#8 PEM)
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub redirect_uri: String,
}

/// Twitch OAuth app used for CHANNEL LINKING (not login). No user tokens
/// are stored; live checks use a client-credentials app token.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct ApiOauthTwitch {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub redirect_uri: String,
}

/// YouTube channel linking. May reuse the Google login OAuth client
/// (same client_id/secret) with an extra redirect URI; youtube.readonly is
/// a Google "sensitive" scope — consent-screen verification required or
/// grants cap at 100 users.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct ApiOauthYoutube {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub redirect_uri: String,
}

/// Kick channel linking (not login). Same posture as Twitch: no user
/// tokens are stored — the one-shot token is revoked after the identity
/// fetch and live checks use a client-credentials app token. Kick's OAuth
/// 2.1 endpoints require PKCE even for confidential clients.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct ApiOauthKick {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub redirect_uri: String,
}

/// Import an existing community into Sloga.
///
/// The primary path (server templates) hits a PUBLIC, unauthenticated
/// Discord endpoint (`GET /guilds/templates/{code}`), so it needs no
/// credentials at all — `enabled` gates it alone. The sticker step is the
/// bot upgrade: it needs a Discord application whose bot the importing
/// user adds to their guild. Both keys belong in Revolt.overrides.toml,
/// never in the baked config.
#[derive(Deserialize, Clone, Default)]
pub struct ApiImportDiscord {
    #[serde(default)]
    pub enabled: bool,
    /// Discord application id of the importer bot. Public by nature — it
    /// appears verbatim in the bot-invite URL shown to users. Empty =
    /// sticker import off.
    #[serde(default)]
    pub client_id: String,
    /// Bot token. SECRET: read only where the outbound Discord API call is
    /// made, never logged, never surfaced in any response body.
    #[serde(default)]
    pub bot_token: String,
}

impl ApiImportDiscord {
    /// Whether the optional sticker-import step is available. The template
    /// import can be on while this is off; never the reverse.
    pub fn stickers_enabled(&self) -> bool {
        self.enabled && !self.client_id.is_empty() && !self.bot_token.is_empty()
    }
}

impl std::fmt::Debug for ApiImportDiscord {
    /// Same output as the derive, except `bot_token` is never printed
    /// (`init()` prints the whole config at boot)
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Exhaustive destructure: a new field fails to compile until it is
        // either printed or deliberately redacted here
        let ApiImportDiscord {
            enabled,
            client_id,
            bot_token: _,
        } = self;

        f.debug_struct("ApiImportDiscord")
            .field("enabled", enabled)
            .field("client_id", client_id)
            .field("bot_token", &"<redacted>")
            .finish()
    }
}

/// An import source read through an operator-run bot account on a
/// Revolt-style platform (`stoat`, `fluxer`). The user adds the bot to the
/// server they want to import. Base URLs are operator config only, never
/// user input or job data. `bot_token` belongs in Revolt.overrides.toml,
/// never in the baked config.
///
/// Fields left out of a table come out empty, and an empty URL keeps the
/// source not `ready()`; the baked Revolt.toml supplies the public URLs.
#[derive(Deserialize, Clone, Default)]
pub struct ApiImportBotSource {
    #[serde(default)]
    pub enabled: bool,
    /// API base, e.g. `https://api.stoat.chat`
    #[serde(default)]
    pub api_url: String,
    /// Web app base, used to build the add-bot link shown to users
    #[serde(default)]
    pub app_url: String,
    /// CDN base for icons, banners and emoji
    #[serde(default)]
    pub cdn_url: String,
    /// Bot / application id. Public by nature: it appears in the add-bot link
    #[serde(default)]
    pub bot_id: String,
    /// Bot token. SECRET: read only where the outbound API call is made,
    /// never logged, never surfaced in any response body.
    #[serde(default)]
    pub bot_token: String,
    /// crond makes the bot leave any server it joined more than this many
    /// hours ago that no import job is using (a user who added the bot and
    /// never finished verifying). `0`, the default, turns that reconcile off.
    /// Stoat and Fluxer read it; Matrix does not yet.
    ///
    /// Opt-in, and on exactly ONE deployment: each crond judges "no job is
    /// using it" by its own database, so a second deployment holding the
    /// same bot token would evict the bot from servers the first one is
    /// importing.
    #[serde(default)]
    pub reconcile_after_hours: u32,
}

impl ApiImportBotSource {
    fn with_urls(api_url: &str, app_url: &str, cdn_url: &str) -> Self {
        Self {
            enabled: false,
            api_url: api_url.to_string(),
            app_url: app_url.to_string(),
            cdn_url: cdn_url.to_string(),
            bot_id: String::new(),
            bot_token: String::new(),
            reconcile_after_hours: 0,
        }
    }

    fn stoat_default() -> Self {
        Self::with_urls(
            "https://api.stoat.chat",
            "https://stoat.chat",
            "https://cdn.stoatusercontent.com",
        )
    }

    fn fluxer_default() -> Self {
        Self::with_urls(
            "https://api.fluxer.app",
            "https://fluxer.app",
            "https://fluxerusercontent.com",
        )
    }

    /// Whether imports from this source may run. Fails closed: switched on,
    /// every key the read path needs set, and the shared challenge secret
    /// set (there is no fallback key).
    pub fn ready(&self, challenge_secret: &str) -> bool {
        self.enabled
            && !self.bot_id.is_empty()
            && !self.bot_token.is_empty()
            && !self.api_url.is_empty()
            && !self.cdn_url.is_empty()
            && !challenge_secret.is_empty()
    }
}

impl std::fmt::Debug for ApiImportBotSource {
    /// Same output as a derive, except `bot_token` is never printed
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Exhaustive destructure: a new field fails to compile until it is
        // either printed or deliberately redacted here
        let ApiImportBotSource {
            enabled,
            api_url,
            app_url,
            cdn_url,
            bot_id,
            bot_token: _,
            reconcile_after_hours,
        } = self;

        f.debug_struct("ApiImportBotSource")
            .field("enabled", enabled)
            .field("api_url", api_url)
            .field("app_url", app_url)
            .field("cdn_url", cdn_url)
            .field("bot_id", bot_id)
            .field("bot_token", &"<redacted>")
            .field("reconcile_after_hours", reconcile_after_hours)
            .finish()
    }
}

fn default_matrix_max_joins() -> u32 {
    8
}

/// Import a Matrix space through an operator-run bot account the user
/// invites to the space. `access_token` belongs in Revolt.overrides.toml,
/// never in the baked config.
#[derive(Deserialize, Clone)]
pub struct ApiImportMatrix {
    #[serde(default)]
    pub enabled: bool,
    /// Client-server API base of the bot's homeserver
    #[serde(default)]
    pub homeserver_url: String,
    /// Full user id of the bot, e.g. `@sloga-import:<homeserver>`
    #[serde(default)]
    pub bot_user_id: String,
    /// Bot access token. SECRET: read only where the outbound call is made,
    /// never logged, never surfaced in any response body.
    #[serde(default)]
    pub access_token: String,
    /// Child-room join budget per import
    #[serde(default = "default_matrix_max_joins")]
    pub max_joins: u32,
}

impl Default for ApiImportMatrix {
    fn default() -> Self {
        Self {
            enabled: false,
            homeserver_url: String::new(),
            bot_user_id: String::new(),
            access_token: String::new(),
            max_joins: default_matrix_max_joins(),
        }
    }
}

impl ApiImportMatrix {
    /// Whether Matrix imports may run. Same fail-closed rule as
    /// [`ApiImportBotSource::ready`].
    pub fn ready(&self, challenge_secret: &str) -> bool {
        self.enabled
            && !self.homeserver_url.is_empty()
            && !self.bot_user_id.is_empty()
            && !self.access_token.is_empty()
            && !challenge_secret.is_empty()
    }
}

impl std::fmt::Debug for ApiImportMatrix {
    /// Same output as a derive, except `access_token` is never printed
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Exhaustive destructure: a new field fails to compile until it is
        // either printed or deliberately redacted here
        let ApiImportMatrix {
            enabled,
            homeserver_url,
            bot_user_id,
            access_token: _,
            max_joins,
        } = self;

        f.debug_struct("ApiImportMatrix")
            .field("enabled", enabled)
            .field("homeserver_url", homeserver_url)
            .field("bot_user_id", bot_user_id)
            .field("access_token", &"<redacted>")
            .field("max_joins", max_joins)
            .finish()
    }
}

#[derive(Deserialize, Clone)]
pub struct ApiImport {
    /// Key for the ownership-challenge codes of every bot source. SECRET,
    /// overrides only. Empty = no bot source is ready.
    #[serde(default)]
    pub challenge_secret: String,
    #[serde(default)]
    pub discord: ApiImportDiscord,
    #[serde(default = "ApiImportBotSource::stoat_default")]
    pub stoat: ApiImportBotSource,
    #[serde(default = "ApiImportBotSource::fluxer_default")]
    pub fluxer: ApiImportBotSource,
    #[serde(default)]
    pub matrix: ApiImportMatrix,
}

impl Default for ApiImport {
    fn default() -> Self {
        Self {
            challenge_secret: String::new(),
            discord: ApiImportDiscord::default(),
            stoat: ApiImportBotSource::stoat_default(),
            fluxer: ApiImportBotSource::fluxer_default(),
            matrix: ApiImportMatrix::default(),
        }
    }
}

impl ApiImport {
    pub fn stoat_ready(&self) -> bool {
        self.stoat.ready(&self.challenge_secret)
    }

    pub fn fluxer_ready(&self) -> bool {
        self.fluxer.ready(&self.challenge_secret)
    }

    pub fn matrix_ready(&self) -> bool {
        self.matrix.ready(&self.challenge_secret)
    }

    /// Whether any import source is switched on (enabled flags only). Gates
    /// the import job claim loop; each job's own source is re-checked when
    /// it runs.
    pub fn any_enabled(&self) -> bool {
        self.discord.enabled || self.stoat.enabled || self.fluxer.enabled || self.matrix.enabled
    }
}

impl std::fmt::Debug for ApiImport {
    /// Same output as a derive, except `challenge_secret` is never printed
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Exhaustive destructure: a new field fails to compile until it is
        // either printed or deliberately redacted here
        let ApiImport {
            challenge_secret: _,
            discord,
            stoat,
            fluxer,
            matrix,
        } = self;

        f.debug_struct("ApiImport")
            .field("challenge_secret", &"<redacted>")
            .field("discord", discord)
            .field("stoat", stoat)
            .field("fluxer", fluxer)
            .field("matrix", matrix)
            .finish()
    }
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct ApiOauth {
    #[serde(default)]
    pub google: ApiOauthGoogle,
    #[serde(default)]
    pub apple: ApiOauthApple,
    #[serde(default)]
    pub twitch: ApiOauthTwitch,
    #[serde(default)]
    pub youtube: ApiOauthYoutube,
    #[serde(default)]
    pub kick: ApiOauthKick,
}

/// A preconfigured global soundboard sound ("Sloga Sounds"), playable in any
/// server voice channel. `id` is an Autumn file id in the `soundboard` bucket;
/// the file must be uploaded and marked used out-of-band.
#[derive(Deserialize, Debug, Clone)]
pub struct ApiSoundboardDefaultSound {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub emoji: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct ApiSoundboard {
    #[serde(default)]
    pub default_sounds: Vec<ApiSoundboardDefaultSound>,
}

/// A curated first-party app-catalog entry ("Add apps" panel). `bot_id`
/// must reference an existing PUBLIC bot; entries that fail to resolve or
/// are not public are skipped fail-soft at serve time (a misconfigured id
/// must never 500 the whole catalog).
#[derive(Deserialize, Debug, Clone)]
pub struct ApiAppCatalogEntry {
    pub bot_id: String,
    #[serde(default)]
    pub tagline: Option<String>,
}

// `Default` + `serde(default)` are load-bearing here (as on every optional
// config table): a non-defaulted key panics EVERY service at boot when
// parsing configs that lack it.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct ApiApps {
    #[serde(default)]
    pub catalog: Vec<ApiAppCatalogEntry>,
}

/// Server-side GIF search proxy (fills the client's GIF picker). The client
/// only ever talks to delta; delta queries the provider with this key, so
/// user session tokens and IPs never reach the third party. Empty key =
/// picker returns no results (feature off).
#[derive(Deserialize, Debug, Clone, Default)]
pub struct ApiGifs {
    #[serde(default)]
    pub giphy_key: String,
}

/// Ko-fi donation webhook. Both secrets belong in Revolt.overrides.toml,
/// never in the baked config. An empty `verification_token` means every
/// webhook call is refused.
#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct ApiKofi {
    /// Shared token Ko-fi sends with each webhook, compared in constant time
    pub verification_token: String,
    /// Server secret keying the HMAC of payer emails (never a plain hash)
    pub email_hmac_key: String,
    /// Public Ko-fi page linked from the client
    pub page_url: String,
}

impl Default for ApiKofi {
    fn default() -> Self {
        Self {
            verification_token: String::new(),
            email_hmac_key: String::new(),
            page_url: "https://ko-fi.com/slogatech".to_string(),
        }
    }
}

/// Game data sources (Steam, Blizzard, Riot) used for game cards and
/// lookups. The Blizzard client secret and `internal_key` belong in
/// Revolt.overrides.toml or the environment, never in the baked config.
/// Empty Blizzard credentials turn WoW cards off.
#[derive(Deserialize, Clone)]
#[serde(default)]
pub struct ApiGamedata {
    /// Battle.net OAuth client id
    pub blizzard_client_id: String,
    /// Battle.net OAuth client secret
    pub blizzard_client_secret: String,
    /// Shared key that lets an internal caller ask January for game cards
    pub internal_key: String,
    /// January base URL the embed worker uses when it sends `internal_key`.
    /// Must be http(s) on localhost, a loopback or an RFC 1918 address (e.g.
    /// `http://127.0.0.1:14705`); otherwise the key is never sent. Not a
    /// secret.
    pub internal_january: String,
    /// Length of the Steam store budget window, in seconds
    pub steam_store_window_secs: u64,
    /// Steam store calls per window for embeds
    pub steam_store_embed_budget: u32,
    /// Steam store calls per window for interactive lookups
    pub steam_store_interactive_budget: u32,
    /// Steam news calls per Steam store window
    pub steam_news_per_window: u32,
    /// Blizzard API calls per second, shared by every pool
    pub blizzard_per_second: u32,
}

impl Default for ApiGamedata {
    fn default() -> Self {
        Self {
            blizzard_client_id: String::new(),
            blizzard_client_secret: String::new(),
            internal_key: String::new(),
            internal_january: String::new(),
            steam_store_window_secs: 300,
            steam_store_embed_budget: 100,
            steam_store_interactive_budget: 50,
            steam_news_per_window: 60,
            blizzard_per_second: 20,
        }
    }
}

/// Stripe Checkout (the Cipher sale). Both secrets belong in
/// Revolt.overrides.toml under an explicit `[api.stripe]` header (env form
/// `REVOLT__API__STRIPE__...`, double underscores), never in the baked
/// config. An empty `webhook_secret` means every webhook call is refused.
///
/// `Default` is hand-written for the URLs and the tolerance, and `Debug` is
/// hand-written so `init()`'s config dump never prints a secret.
#[derive(Deserialize, Clone)]
#[serde(default)]
pub struct ApiStripe {
    /// Stripe API secret key (`sk_live_...` / `sk_test_...`)
    pub secret_key: String,
    /// Signing secret of the webhook endpoint (`whsec_...`)
    pub webhook_secret: String,
    /// Events and sessions whose `livemode` differs are ignored
    pub expect_livemode: bool,
    /// Where Checkout sends the buyer back, per `return_to`
    pub success_url_web: String,
    pub cancel_url_web: String,
    pub success_url_shell: String,
    pub cancel_url_shell: String,
    /// Maximum age, in seconds, of a webhook signature timestamp
    pub tolerance_secs: u64,
    /// Stripe Tax on Checkout, with tax-inclusive prices: the buyer pays the
    /// list price and Stripe carves out the tax where we are registered.
    /// Stripe refuses every checkout while Stripe Tax is not active in the
    /// account, so turn this on only once it is
    pub automatic_tax: bool,
}

impl Default for ApiStripe {
    fn default() -> Self {
        Self {
            secret_key: String::new(),
            webhook_secret: String::new(),
            expect_livemode: false,
            success_url_web: "https://app.sloga.gg/settings?cipher=success".to_string(),
            cancel_url_web: "https://app.sloga.gg/settings?cipher=cancel".to_string(),
            success_url_shell: "https://sloga.gg/cipher/thanks/".to_string(),
            cancel_url_shell: "https://sloga.gg/cipher/".to_string(),
            tolerance_secs: 300,
            automatic_tax: false,
        }
    }
}

impl std::fmt::Debug for ApiGamedata {
    /// Same output as the derive, except `blizzard_client_secret` and
    /// `internal_key` are never printed
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Exhaustive destructure: a new field fails to compile until it is
        // either printed or deliberately redacted here
        let ApiGamedata {
            blizzard_client_id,
            blizzard_client_secret: _,
            internal_key: _,
            internal_january,
            steam_store_window_secs,
            steam_store_embed_budget,
            steam_store_interactive_budget,
            steam_news_per_window,
            blizzard_per_second,
        } = self;

        f.debug_struct("ApiGamedata")
            .field("blizzard_client_id", blizzard_client_id)
            .field("blizzard_client_secret", &"<redacted>")
            .field("internal_key", &"<redacted>")
            .field("internal_january", internal_january)
            .field("steam_store_window_secs", steam_store_window_secs)
            .field("steam_store_embed_budget", steam_store_embed_budget)
            .field("steam_store_interactive_budget", steam_store_interactive_budget)
            .field("steam_news_per_window", steam_news_per_window)
            .field("blizzard_per_second", blizzard_per_second)
            .finish()
    }
}

impl std::fmt::Debug for ApiStripe {
    /// Same output as the derive, except the two secrets print as
    /// `"<redacted>"` (or `"<unset>"` when empty)
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn redact(secret: &str) -> &'static str {
            if secret.is_empty() {
                "<unset>"
            } else {
                "<redacted>"
            }
        }

        // Exhaustive destructure: a new field fails to compile until it is
        // either printed or deliberately redacted here
        let ApiStripe {
            secret_key,
            webhook_secret,
            expect_livemode,
            success_url_web,
            cancel_url_web,
            success_url_shell,
            cancel_url_shell,
            tolerance_secs,
            automatic_tax,
        } = self;

        f.debug_struct("ApiStripe")
            .field("secret_key", &redact(secret_key))
            .field("webhook_secret", &redact(webhook_secret))
            .field("expect_livemode", expect_livemode)
            .field("success_url_web", success_url_web)
            .field("cancel_url_web", cancel_url_web)
            .field("success_url_shell", success_url_shell)
            .field("cancel_url_shell", cancel_url_shell)
            .field("tolerance_secs", tolerance_secs)
            .field("automatic_tax", automatic_tax)
            .finish()
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct Api {
    pub registration: ApiRegistration,
    pub smtp: ApiSmtp,
    pub security: ApiSecurity,
    pub workers: ApiWorkers,
    pub livekit: ApiLiveKit,
    pub users: ApiUsers,
    #[serde(default)]
    pub oauth: ApiOauth,
    #[serde(default)]
    pub soundboard: ApiSoundboard,
    #[serde(default)]
    pub gifs: ApiGifs,
    #[serde(default)]
    pub apps: ApiApps,
    #[serde(default)]
    pub import: ApiImport,
    #[serde(default)]
    pub kofi: ApiKofi,
    #[serde(default)]
    pub gamedata: ApiGamedata,
    #[serde(default)]
    pub stripe: ApiStripe,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Pushd {
    pub production: bool,
    pub exchange: String,
    pub mass_mention_chunk_size: usize,
    pub render_cache_time: usize,

    // Queues
    pub message_queue: String,
    pub mass_mention_queue: String,
    pub dm_call_queue: String,
    pub fr_accepted_queue: String,
    pub fr_received_queue: String,
    pub generic_queue: String,
    pub calendar_event_queue: String,
    pub ack_queue: String,

    pub vapid: PushVapid,
    pub unifiedpush: PushUnifiedPush,
    pub fcm: PushFcm,
    pub apn: PushApn,
}

impl Pushd {
    fn get_routing_key(&self, key: String) -> String {
        match self.production {
            true => key + "-prd",
            false => key + "-tst",
        }
    }

    pub fn get_ack_routing_key(&self) -> String {
        self.get_routing_key(self.ack_queue.clone())
    }

    pub fn get_message_routing_key(&self) -> String {
        self.get_routing_key(self.message_queue.clone())
    }

    pub fn get_mass_mention_routing_key(&self) -> String {
        self.get_routing_key(self.mass_mention_queue.clone())
    }

    pub fn get_dm_call_routing_key(&self) -> String {
        self.get_routing_key(self.dm_call_queue.clone())
    }

    pub fn get_fr_accepted_routing_key(&self) -> String {
        self.get_routing_key(self.fr_accepted_queue.clone())
    }

    pub fn get_fr_received_routing_key(&self) -> String {
        self.get_routing_key(self.fr_received_queue.clone())
    }

    pub fn get_generic_routing_key(&self) -> String {
        self.get_routing_key(self.generic_queue.clone())
    }

    pub fn get_calendar_event_routing_key(&self) -> String {
        self.get_routing_key(self.calendar_event_queue.clone())
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct January {
    pub blocked_domains: Vec<String>,
    /// Emit Audio embeds for direct audio links and serve `GET /audio`
    pub audio_embeds: bool,
    /// Largest audio file (in bytes) that is embedded or relayed
    pub max_audio_bytes: usize,
    /// Maximum number of concurrent `/audio` streams
    pub max_audio_streams: usize,
    /// Wall-clock limit (in seconds) for a single `/audio` stream
    pub max_audio_stream_secs: u64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct FilesLimit {
    pub min_file_size: usize,
    pub min_resolution: [usize; 2],
    pub max_mega_pixels: usize,
    pub max_pixel_side: usize,
}

#[derive(Deserialize, Clone)]
pub struct FilesS3 {
    pub endpoint: String,
    pub path_style_buckets: bool,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub default_bucket: String,
}

impl std::fmt::Debug for FilesS3 {
    /// Same output as the derive, except `secret_access_key` is never printed
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Exhaustive destructure: a new field fails to compile until it is
        // either printed or deliberately redacted here
        let FilesS3 {
            endpoint,
            path_style_buckets,
            region,
            access_key_id,
            secret_access_key: _,
            default_bucket,
        } = self;

        f.debug_struct("FilesS3")
            .field("endpoint", endpoint)
            .field("path_style_buckets", path_style_buckets)
            .field("region", region)
            .field("access_key_id", access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("default_bucket", default_bucket)
            .finish()
    }
}

/// Secret map whose Debug never prints values.
#[derive(Clone, Default)]
pub struct RedactedKeys(pub HashMap<String, String>);

impl std::fmt::Debug for RedactedKeys {
    /// Prints the ids only, sorted, e.g. `RedactedKeys(["legacy"])`
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ids: Vec<&String> = self.0.keys().collect();
        ids.sort();
        f.debug_tuple("RedactedKeys").field(&ids).finish()
    }
}

/// Hand-written instead of derived: serde's stock type errors quote the value
/// they were given (`invalid type: string "<key>"`), and a config error ends
/// up in a boot panic. Accepts a table of strings only; no error built here
/// contains any part of the value.
impl<'de> Deserialize<'de> for RedactedKeys {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // `deserialize_any` hands the value's real kind to the visitor, so no
        // format-level conversion error (which may quote it) fires first
        deserializer.deserialize_any(RedactedKeysVisitor)
    }
}

struct RedactedKeysVisitor;

impl RedactedKeysVisitor {
    fn reject<E: serde::de::Error>(found: &str) -> E {
        E::custom(format!(
            "files.decrypt_keys must be a table of `id = \"base64 key\"`, not {found}"
        ))
    }
}

impl<'de> serde::de::Visitor<'de> for RedactedKeysVisitor {
    type Value = RedactedKeys;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a table of `id = \"base64 key\"`")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut keys = HashMap::new();
        while let Some((id, value)) = map.next_entry::<String, RedactedKeyValue>()? {
            keys.insert(id, value.0);
        }
        Ok(RedactedKeys(keys))
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Err(Self::reject("a string"))
    }

    fn visit_borrowed_str<E: serde::de::Error>(self, _: &'de str) -> Result<Self::Value, E> {
        Err(Self::reject("a string"))
    }

    fn visit_string<E: serde::de::Error>(self, _: String) -> Result<Self::Value, E> {
        Err(Self::reject("a string"))
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Err(Self::reject("a boolean"))
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Err(Self::reject("a number"))
    }

    fn visit_i128<E: serde::de::Error>(self, _: i128) -> Result<Self::Value, E> {
        Err(Self::reject("a number"))
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Err(Self::reject("a number"))
    }

    fn visit_u128<E: serde::de::Error>(self, _: u128) -> Result<Self::Value, E> {
        Err(Self::reject("a number"))
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Err(Self::reject("a number"))
    }

    fn visit_bytes<E: serde::de::Error>(self, _: &[u8]) -> Result<Self::Value, E> {
        Err(Self::reject("bytes"))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Err(Self::reject("an empty value"))
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, _: A) -> Result<Self::Value, A::Error> {
        Err(Self::reject("an array"))
    }
}

/// One `decrypt_keys` value: a string, taken as is. Any other kind is rejected
/// without echoing it.
struct RedactedKeyValue(String);

impl<'de> Deserialize<'de> for RedactedKeyValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Not `deserialize_string`: config-rs would quietly turn `k1 = 5` into "5"
        deserializer.deserialize_any(RedactedKeyValueVisitor)
    }
}

struct RedactedKeyValueVisitor;

impl RedactedKeyValueVisitor {
    fn reject<E: serde::de::Error>(found: &str) -> E {
        E::custom(format!(
            "each files.decrypt_keys value must be a base64 key string, not {found}"
        ))
    }
}

impl<'de> serde::de::Visitor<'de> for RedactedKeyValueVisitor {
    type Value = RedactedKeyValue;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a base64 key string")
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(RedactedKeyValue(value.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(RedactedKeyValue(value))
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Err(Self::reject("a boolean"))
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Err(Self::reject("a number"))
    }

    fn visit_i128<E: serde::de::Error>(self, _: i128) -> Result<Self::Value, E> {
        Err(Self::reject("a number"))
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Err(Self::reject("a number"))
    }

    fn visit_u128<E: serde::de::Error>(self, _: u128) -> Result<Self::Value, E> {
        Err(Self::reject("a number"))
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Err(Self::reject("a number"))
    }

    fn visit_bytes<E: serde::de::Error>(self, _: &[u8]) -> Result<Self::Value, E> {
        Err(Self::reject("bytes"))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Err(Self::reject("an empty value"))
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, _: A) -> Result<Self::Value, A::Error> {
        Err(Self::reject("an array"))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, _: A) -> Result<Self::Value, A::Error> {
        Err(Self::reject("a table"))
    }
}

#[derive(Deserialize, Clone)]
pub struct Files {
    /// Primary (write) key, base64
    pub encryption_key: String,
    /// Id the primary key is registered under; "legacy" means rows with no `key_id`
    #[serde(default = "default_encryption_key_id")]
    pub encryption_key_id: String,
    /// Extra keys (id = base64 key) kept for reads and in-flight sessions
    #[serde(default)]
    pub decrypt_keys: RedactedKeys,
    /// Refuse to boot on the "legacy" id or the committed default key
    #[serde(default)]
    pub require_rotated_key: bool,
    pub webp_quality: f32,
    pub blocked_mime_types: Vec<String>,
    pub clamd_host: String,
    pub scan_mime_types: Vec<String>,

    pub limit: FilesLimit,
    pub preview: HashMap<String, [usize; 2]>,
    pub s3: FilesS3,
}

fn default_encryption_key_id() -> String {
    "legacy".to_string()
}

impl std::fmt::Debug for Files {
    /// Same output as the derive, except `encryption_key` is never printed and
    /// `decrypt_keys` shows ids only
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Exhaustive destructure: a new field fails to compile until it is
        // either printed or deliberately redacted here
        let Files {
            encryption_key: _,
            encryption_key_id,
            decrypt_keys,
            require_rotated_key,
            webp_quality,
            blocked_mime_types,
            clamd_host,
            scan_mime_types,
            limit,
            preview,
            s3,
        } = self;

        f.debug_struct("Files")
            .field("encryption_key", &"<redacted>")
            .field("encryption_key_id", encryption_key_id)
            .field("decrypt_keys", decrypt_keys)
            .field("require_rotated_key", require_rotated_key)
            .field("webp_quality", webp_quality)
            .field("blocked_mime_types", blocked_mime_types)
            .field("clamd_host", clamd_host)
            .field("scan_mime_types", scan_mime_types)
            .field("limit", limit)
            .field("preview", preview)
            .field("s3", s3)
            .finish()
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct GlobalLimits {
    pub group_size: usize,
    pub message_embeds: usize,
    pub message_replies: usize,
    pub message_reactions: usize,
    pub server_emoji: usize,
    pub server_stickers: usize,
    pub server_sounds: usize,
    pub server_roles: usize,
    pub server_channels: usize,
    pub threads_per_channel: usize,
    pub scheduled_messages_per_channel: usize,
    pub scheduled_messages_per_user: usize,
    pub followers_per_channel: usize,
    pub crossposts_per_hour: usize,

    pub new_user_hours: usize,

    pub body_limit_size: usize,

    pub restrict_server_creation: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct FeaturesLimits {
    pub outgoing_friend_requests: usize,

    pub bots: usize,
    pub message_length: usize,
    pub message_attachments: usize,
    pub servers: usize,
    pub voice_quality: u32,
    pub video: bool,
    pub video_resolution: [u32; 2],
    pub video_aspect_ratio: [f32; 2],

    pub file_upload_size_limit: HashMap<String, usize>,
}

/// Upload-perk overlay. Not a full limits block: only these upload sizes
/// are laid over `default` for a user holding the upload perk.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct PerkLimits {
    #[serde(default)]
    pub file_upload_size_limit: HashMap<String, usize>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct FeaturesLimitsCollection {
    pub global: GlobalLimits,

    pub new_user: FeaturesLimits,
    pub default: FeaturesLimits,

    // Must stay a named field: serde matches named keys before `roles`
    // collects the rest, and a partial `perk` table would not parse as a
    // full `FeaturesLimits` role. Absent = the perk is off.
    #[serde(default)]
    pub perk: Option<PerkLimits>,

    #[serde(flatten)]
    pub roles: HashMap<String, FeaturesLimits>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct LegalLinks {
    /// Terms of Service URL
    pub terms_of_service: String,
    /// Privacy Policy URL
    pub privacy_policy: String,
    /// Guidelines URL
    pub guidelines: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct FeaturesAdvanced {
    #[serde(default)]
    pub process_message_delay_limit: u16,
}

impl Default for FeaturesAdvanced {
    fn default() -> Self {
        Self {
            process_message_delay_limit: 5,
        }
    }
}

/// Per-tier boost perk overrides. Every field is optional — `None` means
/// "no change from the global limit". Effective limits are
/// `max(global, override)` so an operator-raised global limit is never
/// LOWERED by boosting.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct BoostTierPerks {
    #[serde(default)]
    pub server_emoji: Option<usize>,
    #[serde(default)]
    pub server_sounds: Option<usize>,
}

/// Server-boost feature configuration.
///
/// Ships fully OFF (`enabled = false` compiled into the defaults; absent
/// config keys cannot turn it on). NOTE: the config file sources are frozen
/// into the process at first access — flipping `[features.boosts] enabled`
/// in Revolt.overrides.toml requires RESTARTING delta AND crond (no rebuild,
/// no migration). Do not stage the edit ahead of time: it will silently
/// activate on the next incidental restart.
#[derive(Deserialize, Debug, Clone)]
pub struct BoostFeatures {
    /// Master switch for the whole feature (routes, perks, crond pruning)
    #[serde(default)]
    pub enabled: bool,
    /// Future billing seam: advertised to clients via the root route so
    /// they know whether a purchase flow exists. NO server code path
    /// consumes this in v1.
    #[serde(default)]
    pub purchases_enabled: bool,
    /// Boosts required for tiers 1/2/3 (Discord parity defaults: 2/7/14)
    #[serde(default = "BoostFeatures::default_tier_thresholds")]
    pub tier_thresholds: [u32; 3],
    /// Sanity cap on how many boosts one user may apply to one server
    #[serde(default = "BoostFeatures::default_max_per_user_per_server")]
    pub max_per_user_per_server: u32,
    #[serde(default = "BoostFeatures::default_tier1")]
    pub tier1: BoostTierPerks,
    #[serde(default = "BoostFeatures::default_tier2")]
    pub tier2: BoostTierPerks,
    #[serde(default = "BoostFeatures::default_tier3")]
    pub tier3: BoostTierPerks,
    /// Protected servers and channels (S5): its OWN flags, so turning Boosts on never turns Prot on
    #[serde(default)]
    pub protection: ProtectionFeatures,
}

impl Default for BoostFeatures {
    fn default() -> Self {
        Self {
            enabled: false,
            purchases_enabled: false,
            tier_thresholds: Self::default_tier_thresholds(),
            max_per_user_per_server: Self::default_max_per_user_per_server(),
            tier1: Self::default_tier1(),
            tier2: Self::default_tier2(),
            tier3: Self::default_tier3(),
            protection: ProtectionFeatures::default(),
        }
    }
}

/// `[features.boosts.protection]`. Ships dark; flips need a delta AND crond
/// restart (config is frozen per process).
///
/// Every key is optional and takes the default below. A cost table that is
/// set must name all four tiers: a partial one fails the whole config at
/// startup rather than pricing a tier at zero.
#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct ProtectionFeatures {
    /// Master switch for ledger reads and writes and the tank routes
    pub enabled: bool,
    /// Non-admin tank creation and goals
    pub self_serve_enabled: bool,
    /// The daily burn clock
    pub burn_enabled: bool,
    /// The day-30 purge (dry-run logging while off)
    pub deletion_enabled: bool,
    /// Founding Prot for Cipher members
    pub cipher_grants_enabled: bool,
    /// Prot per day for a protected channel, per slot tier
    pub channel_daily_cost: ProtTierCosts,
    /// Prot per day for a protected server, per slot tier
    pub server_daily_cost: ProtTierCosts,
    pub grace_days: u32,
    pub freeze_days: u32,
    pub final_warning_day: u32,
    /// Days before the tank runs dry that the owner is warned
    pub warn_days: Vec<u32>,
    pub min_reactivation_days: u32,
    pub launch_goal_deadline_days: u32,
    pub launch_window_days: u32,
    pub launch_seat_window_days: u32,
    /// Smallest contribution, in Prot
    pub min_contribution: i64,
    pub min_launch_goal_days: u32,
    pub withdraw_cutoff_hours: u32,
    /// Prot bought in the last this many hours can't go into a tank or a
    /// pledge (0 disables the hold)
    pub contribute_hold_hours: u32,
    /// Most Prot one wallet may hold
    pub wallet_cap: i64,
}

impl Default for ProtectionFeatures {
    fn default() -> Self {
        Self {
            enabled: false,
            self_serve_enabled: false,
            burn_enabled: false,
            deletion_enabled: false,
            cipher_grants_enabled: false,
            channel_daily_cost: ProtTierCosts {
                t10: 40,
                t25: 90,
                t50: 160,
                t100: 280,
            },
            server_daily_cost: ProtTierCosts {
                t10: 60,
                t25: 135,
                t50: 240,
                t100: 420,
            },
            grace_days: 5,
            freeze_days: 25,
            final_warning_day: 20,
            warn_days: vec![7, 3, 1],
            min_reactivation_days: 1,
            launch_goal_deadline_days: 30,
            launch_window_days: 7,
            launch_seat_window_days: 7,
            min_contribution: 50,
            min_launch_goal_days: 30,
            withdraw_cutoff_hours: 48,
            contribute_hold_hours: 72,
            wallet_cap: 100000,
        }
    }
}

/// TOML `channel_daily_cost = { 10 = 40, 25 = 90, 50 = 160, 100 = 280 }`
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtTierCosts {
    #[serde(rename = "10")]
    pub t10: i64,
    #[serde(rename = "25")]
    pub t25: i64,
    #[serde(rename = "50")]
    pub t50: i64,
    #[serde(rename = "100")]
    pub t100: i64,
}

impl BoostFeatures {
    fn default_tier_thresholds() -> [u32; 3] {
        [2, 7, 14]
    }

    fn default_max_per_user_per_server() -> u32 {
        100
    }

    fn default_tier1() -> BoostTierPerks {
        BoostTierPerks {
            server_emoji: Some(200),
            server_sounds: Some(48),
        }
    }

    fn default_tier2() -> BoostTierPerks {
        BoostTierPerks {
            server_emoji: Some(300),
            server_sounds: Some(72),
        }
    }

    fn default_tier3() -> BoostTierPerks {
        BoostTierPerks {
            server_emoji: Some(500),
            server_sounds: Some(96),
        }
    }

    /// Tier (0-3) for a given active boost count. Thresholds are read in
    /// ascending order; a misconfigured non-ascending array is clamped by
    /// taking the highest tier whose threshold is met.
    pub fn tier_for(&self, count: u32) -> u32 {
        let mut tier = 0;
        for (index, threshold) in self.tier_thresholds.iter().enumerate() {
            if count >= *threshold {
                tier = index as u32 + 1;
            }
        }
        tier
    }

    /// Boosts required for the tier after `tier`, if any
    pub fn next_tier_at(&self, tier: u32) -> Option<u32> {
        self.tier_thresholds.get(tier as usize).copied()
    }

    fn perks_up_to(&self, tier: u32) -> impl Iterator<Item = &BoostTierPerks> {
        [&self.tier1, &self.tier2, &self.tier3]
            .into_iter()
            .take(tier.min(3) as usize)
    }

    /// Effective per-server emoji cap for a tier: max(global, cumulative
    /// tier overrides). Returns the global limit unchanged when the feature
    /// is disabled.
    pub fn effective_server_emoji(&self, global: usize, tier: u32) -> usize {
        if !self.enabled {
            return global;
        }
        self.perks_up_to(tier)
            .filter_map(|perks| perks.server_emoji)
            .fold(global, usize::max)
    }

    /// Effective per-server soundboard cap for a tier (same semantics)
    pub fn effective_server_sounds(&self, global: usize, tier: u32) -> usize {
        if !self.enabled {
            return global;
        }
        self.perks_up_to(tier)
            .filter_map(|perks| perks.server_sounds)
            .fold(global, usize::max)
    }
}

/// Anti-spam: the copy-paste DM detector (with its pause on DMs to
/// strangers) and the daily staff alert.
///
/// Ships OFF. Prod turns it on in Revolt.overrides.toml under an explicit
/// `[features.antispam]` header (env form `REVOLT__FEATURES__ANTISPAM__...`,
/// double underscores), then RESTARTS delta AND crond: config sources are
/// frozen into each process at first access.
///
/// `Default` is hand-written on purpose: a derived one would give
/// `dm_dupe_pause = false` and `dm_dupe_threshold = 0`. Read the threshold
/// and minimum length through `threshold()` / `min_chars()`, which clamp.
#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct AntispamFeatures {
    /// Master switch for the copy-paste DM detector
    pub dm_dupe_enabled: bool,
    /// Pause the flagged account's DMs to strangers until staff review the
    /// report (false = report only)
    pub dm_dupe_pause: bool,
    /// Distinct non-friend DMs with the same text that trigger a flag
    pub dm_dupe_threshold: usize,
    /// How long a fingerprint is remembered per author
    pub dm_dupe_window_hours: u64,
    /// Normalized texts shorter than this are exempt (invite / link only)
    pub dm_dupe_min_chars: usize,
    /// Days after staff clear a flag before the detector may flag again
    pub dm_dupe_rearm_days: u64,
    /// Master switch for the daily staff alert (crond)
    pub daily_enabled: bool,
    /// UTC hour at or after which the daily scan runs
    pub daily_run_hour_utc: u64,
    /// Only accounts created within this many days are scanned
    pub daily_account_age_days: u64,
    /// Minimum non-friend DMs before an account is considered
    pub daily_min_nonfriend_dms: usize,
    /// Flag only when at most this share of those DMs got a reply
    pub daily_max_reply_ratio: f64,
    /// Flag only when the account sent at most this many non-DM messages
    pub daily_max_public_messages: u64,
    /// Days before the same account may be reported by the scan again
    pub daily_report_cooldown_days: u64,
    /// Cap on reports filed per daily run
    pub daily_max_reports_per_run: usize,
}

impl Default for AntispamFeatures {
    fn default() -> Self {
        Self {
            dm_dupe_enabled: false,
            dm_dupe_pause: true,
            dm_dupe_threshold: 3,
            dm_dupe_window_hours: 24,
            dm_dupe_min_chars: 30,
            dm_dupe_rearm_days: 30,
            daily_enabled: false,
            daily_run_hour_utc: 14,
            daily_account_age_days: 14,
            daily_min_nonfriend_dms: 5,
            daily_max_reply_ratio: 0.25,
            daily_max_public_messages: 3,
            daily_report_cooldown_days: 30,
            daily_max_reports_per_run: 10,
        }
    }
}

impl AntispamFeatures {
    /// Flag threshold, never below 2 (1 would flag every stranger DM)
    pub fn threshold(&self) -> usize {
        self.dm_dupe_threshold.max(2)
    }

    /// Minimum normalized length, never below 10
    pub fn min_chars(&self) -> usize {
        self.dm_dupe_min_chars.max(10)
    }
}

/// Payments: the Cipher sale and the Stripe Checkout it runs on (provider
/// keys live in `[api.stripe]`).
///
/// Ships OFF. Prod turns it on in Revolt.overrides.toml under an explicit
/// `[features.payments]` header (env form `REVOLT__FEATURES__PAYMENTS__...`,
/// double underscores), then RESTARTS delta AND crond: config sources are
/// frozen into each process at first access.
///
/// `Default` is hand-written on purpose: a derived one would give
/// `cipher_cap = 0`, which reads as "sold out".
#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct FeaturePayments {
    /// Switch for new checkouts only: while off, `POST
    /// /payments/cipher/checkout` answers `PaymentsDisabled` and `GET
    /// /payments/cipher/stats` reports `open: false`. It does NOT gate the
    /// Stripe webhook, `GET /payments/cipher/@me`, the stats route itself or
    /// the crond reconcile sweep: those only read, or settle money already
    /// taken (fulfil a paid order, refund, apply a dispute). The sweep runs
    /// whenever `[api.stripe] secret_key` is set.
    pub enabled: bool,
    /// Whether new Cipher checkouts (and upgrades) may start
    pub cipher_sales_open: bool,
    /// Size of the pre-seeded Cipher number table
    pub cipher_cap: u32,
    /// RFC 3339 instant after which the sale is closed; empty = no close date
    pub cipher_sales_close_at: String,
    /// Countries (ISO 3166-1 alpha-2, uppercase) Cipher is not sold to:
    /// checkout refuses a request Cloudflare places there
    /// (`CipherRegionUnavailable`, only with `[api.security]
    /// trust_cloudflare`), and fulfilment voids and refunds a payment whose
    /// billing address, or the issuing country of the card that paid it, is
    /// there. Defaults to the 27 EU member states and the UK (no VAT
    /// registrations yet). A TOML list, or one comma-separated string (the
    /// environment form, `REVOLT__FEATURES__PAYMENTS__CIPHER_BLOCKED_COUNTRIES=DE,FR`;
    /// see `country_list`). An entry that is not two uppercase letters
    /// fails the payments config (checkouts refused).
    #[serde(deserialize_with = "country_list")]
    pub cipher_blocked_countries: Vec<String>,
    /// Kill switch for NEW Prot checkouts only (fulfilling a paid one never reads it)
    pub prot_sales_open: bool,
    /// Packs on sale; ids are unique "p" + digits
    pub prot_packs: Vec<ProtPackConfig>,
    /// Smallest pay-exact purchase, in cents (Stripe's USD minimum)
    pub prot_exact_min_cents: i64,
    /// Largest pay-exact purchase, in cents
    pub prot_exact_max_cents: i64,
    /// Same format and env form as cipher_blocked_countries. The default is
    /// wider than Cipher's: Norway, Iceland and Liechtenstein are added
    /// (`PROT_BLOCKED_COUNTRIES_DEFAULT`), because Prot is sold
    /// non-refundable and buyers there keep a statutory right of withdrawal
    /// that the Prot checkout terms do not waive
    #[serde(deserialize_with = "country_list")]
    pub prot_blocked_countries: Vec<String>,
    /// Where Checkout returns a web buyer of Prot
    pub prot_success_url: String,
    pub prot_cancel_url: String,
    /// Where Checkout returns a shell buyer of Prot, on success AND cancel
    pub prot_shell_return_url: String,
}

/// One Prot pack in `[features.payments] prot_packs`: `cents` is the price,
/// `prot` what it credits (bonus included)
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProtPackConfig {
    pub id: String,
    pub cents: i64,
    pub prot: i64,
}

impl ProtPackConfig {
    fn new(id: &str, cents: i64, prot: i64) -> Self {
        Self {
            id: id.to_string(),
            cents,
            prot,
        }
    }
}

/// `cipher_blocked_countries` and `prot_blocked_countries` from a list, or
/// from one comma-separated string (an environment variable cannot carry a
/// list). Each entry of the string is trimmed; an empty one (`""`, `"DE,"`)
/// is kept, so the payments config refuses it instead of blocking nothing.
/// To block nothing, set the key to `[]` in Revolt.overrides.toml.
fn country_list<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum CountryList {
        List(Vec<String>),
        Joined(String),
    }

    Ok(match CountryList::deserialize(deserializer)? {
        CountryList::List(codes) => codes,
        CountryList::Joined(joined) => joined
            .split(',')
            .map(|code| code.trim().to_string())
            .collect(),
    })
}

/// The 27 EU member states and the United Kingdom: the default of
/// `[features.payments] cipher_blocked_countries`
pub const CIPHER_BLOCKED_COUNTRIES_DEFAULT: [&str; 28] = [
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV",
    "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "GB",
];

/// The Cipher list plus Norway, Iceland and Liechtenstein (the rest of the
/// EEA): the default of `[features.payments] prot_blocked_countries`
pub const PROT_BLOCKED_COUNTRIES_DEFAULT: [&str; 31] = [
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV",
    "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "GB", "NO", "IS", "LI",
];

impl Default for FeaturePayments {
    fn default() -> Self {
        Self {
            enabled: false,
            cipher_sales_open: false,
            cipher_cap: 1000,
            cipher_sales_close_at: String::new(),
            cipher_blocked_countries: CIPHER_BLOCKED_COUNTRIES_DEFAULT
                .map(str::to_string)
                .to_vec(),
            prot_sales_open: false,
            prot_packs: vec![
                ProtPackConfig::new("p5", 500, 500),
                ProtPackConfig::new("p10", 1000, 1000),
                ProtPackConfig::new("p25", 2500, 2600),
                ProtPackConfig::new("p50", 5000, 5300),
                ProtPackConfig::new("p100", 10000, 11000),
            ],
            prot_exact_min_cents: 50,
            prot_exact_max_cents: 50000,
            prot_blocked_countries: PROT_BLOCKED_COUNTRIES_DEFAULT.map(str::to_string).to_vec(),
            prot_success_url: "https://app.sloga.gg/settings?prot=success".to_string(),
            prot_cancel_url: "https://app.sloga.gg/settings?prot=cancel".to_string(),
            prot_shell_return_url: "https://sloga.gg/prot/thanks/".to_string(),
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct Features {
    pub limits: FeaturesLimitsCollection,
    pub legal_links: LegalLinks,
    pub webhooks_enabled: bool,
    pub mass_mentions_send_notifications: bool,
    pub mass_mentions_enabled: bool,

    /// Operator flag for the E2EE key directory + envelope relay routes
    #[serde(default)]
    pub e2ee_enabled: bool,

    /// Operator flag for the MLS delivery service + KeyPackage directory
    /// backing media E2EE (calls). Requires `e2ee_enabled`.
    #[serde(default)]
    pub media_e2ee_enabled: bool,

    /// Operator flag for the server calendar/events routes
    #[serde(default)]
    pub events_enabled: bool,

    /// Operator flag for remote desktop control during screen share
    /// (remote-control plan §1). Ships dark: defaults false. NOT a kill
    /// switch — `config()` is cached per process, so flipping it false
    /// makes the routes refuse (`FeatureDisabled`, 400) on restart but
    /// revokes nothing by itself; the crond reaper
    /// (`prune_remote_control_grants`) additionally mass-revokes every
    /// live grant when it observes the flag off.
    #[serde(default)]
    pub remote_control: bool,

    /// Operator flag for the native Android screen-share leg
    /// (`POST /channels/{id}/screen_leg`, android-screen-share plan §0.8).
    /// Ships DARK: an un-updated viewer has no frame key for the leg's
    /// `{user}:{device}:screen` identity and latches NOT-ENCRYPTED for the
    /// rest of the call, so the flag stays false until the viewer-side
    /// changes are live on every surface (plan §0.1). `config()` is cached
    /// per process, so flipping it requires a delta restart. voice-ingress
    /// is deliberately NOT gated on it — a hand-minted probe leg still
    /// needs its webhook branches.
    #[serde(default)]
    pub screen_leg: bool,

    /// Kill switch for AFK auto-move (AFK-channel plan, D-5b2-3). ON by
    /// default, and the default lives in the embedded `Revolt.toml`:
    /// `#[serde(default)]` alone would make it `false`. Turn it off with
    /// `REVOLT__FEATURES__AFK_AUTO_MOVE=false` (double underscores) or under
    /// `[features]` in `Revolt.overrides.toml`, then RESTART delta AND crond:
    /// config sources are frozen into each process at first access, so
    /// neither the route nor the sweep's per-tick read ever sees a value
    /// other than the one it started with. Off stops both halves: delta
    /// refuses new idle claims (`PUT /channels/<id>/afk_idle` answers
    /// `InvalidOperation`; withdrawing one still works), and the crond sweep
    /// reads, claims and moves nothing. Claims already stored expire with
    /// their TTL; the index entries they leave are dropped once the sweep is
    /// back on.
    #[serde(default)]
    pub afk_auto_move: bool,

    /// Optional server id that every newly-onboarded user is automatically
    /// added to (a "Welcome" / landing-spot server). Empty/unset disables the
    /// behaviour. Existing users are unaffected (backfill separately).
    #[serde(default)]
    pub welcome_server: Option<String>,

    /// Server-boost feature (ships dark; see BoostFeatures docs for the
    /// flip-requires-restart caveat)
    #[serde(default)]
    pub boosts: BoostFeatures,

    /// Anti-spam (ships off; see AntispamFeatures docs)
    #[serde(default)]
    pub antispam: AntispamFeatures,

    /// Payments and the Cipher sale (ships off; see FeaturePayments docs)
    #[serde(default)]
    pub payments: FeaturePayments,

    #[serde(default)]
    pub advanced: FeaturesAdvanced,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Sentry {
    pub api: String,
    pub events: String,
    pub voice_ingress: String,
    pub files: String,
    pub proxy: String,
    pub pushd: String,
    pub crond: String,
    pub gifbox: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Settings {
    pub database: Database,
    pub rabbit: Rabbit,
    pub hosts: Hosts,
    pub api: Api,
    pub pushd: Pushd,
    pub january: January,
    pub files: Files,
    pub features: Features,
    pub sentry: Sentry,
    pub production: bool,
    pub environment: String,
    pub disable_events_dont_use: bool,
}

impl Settings {
    pub fn preflight_checks(&self) {
        if self.api.smtp.host.is_empty() {
            log::warn!("No SMTP settings specified! Remember to configure email.");
        }

        if self.api.security.captcha.hcaptcha_key.is_empty() {
            log::warn!("No Captcha key specified! Remember to add hCaptcha key.");
        }
    }
}

pub async fn init() {
    println!(
        ":: Revolt Configuration ::\n\x1b[32m{:?}\x1b[0m",
        config().await
    );
}

pub async fn read() -> Config {
    CONFIG_BUILDER.read().await.clone()
}

pub async fn config_no_cache() -> Settings {
    let mut config = read().await.try_deserialize::<Settings>().unwrap();

    // inject REDIS_URI for redis-kiss library
    if std::env::var("REDIS_URI").is_err() {
        std::env::set_var("REDIS_URI", config.database.redis.clone());
    }

    // auto-detect production nodes
    if config.hosts.api.contains("https")
        && (config.hosts.api.contains("revolt.chat") || config.hosts.api.contains("stoat.chat"))
    {
        config.production = true;
    }

    config
}

#[cached(time = 30)]
pub async fn config() -> Settings {
    #[cfg(feature = "test")]
    if let Some(overwrites) = CONFIG_OVERWRITES.get() {
        return overwrites.clone();
    }

    config_no_cache().await
}

#[cfg(feature = "test")]
static CONFIG_OVERWRITES: OnceLock<Settings> = OnceLock::new();

/// Modify the config values for a test, this can only be called once
///
/// This will also fail if two or more tests are running in the same process and both try to modify the config,
/// This could happen if tests where run under `cargo test` instead of `nextest`.
#[cfg(feature = "test")]
pub async fn overwrite_config(f: impl FnOnce(&mut Settings)) {
    let mut config = config_no_cache().await;

    f(&mut config);

    CONFIG_OVERWRITES.set(config).expect(
        "Cannot overwrite config multiple times, make sure you are running tests through nextest.",
    );
}

/// Configure logging and common Rust variables
#[cfg(feature = "sentry")]
pub async fn setup_logging(release: &'static str, dsn: String) -> Option<sentry::ClientInitGuard> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    if std::env::var("ROCKET_ADDRESS").is_err() {
        std::env::set_var("ROCKET_ADDRESS", "0.0.0.0");
    }

    pretty_env_logger::init();
    log::info!("Starting {release}");

    if dsn.is_empty() {
        None
    } else {
        Some(sentry::init((
            dsn,
            sentry::ClientOptions {
                release: Some(release.into()),
                ..Default::default()
            },
        )))
    }
}

#[cfg(feature = "sentry")]
#[macro_export]
macro_rules! configure {
    ($application: ident) => {
        let config = $crate::config().await;
        let _sentry = $crate::setup_logging(
            concat!(env!("CARGO_PKG_NAME"), "@", env!("CARGO_PKG_VERSION")),
            config.sentry.$application,
        )
        .await;
    };
}

#[cfg(feature = "test")]
#[cfg(test)]
mod tests {
    use crate::init;

    #[tokio::test]
    async fn it_works() {
        init().await;
    }
}

#[cfg(test)]
mod boost_tests {
    use super::{BoostFeatures, BoostTierPerks};

    #[test]
    fn tier_thresholds() {
        let boosts = BoostFeatures::default();
        assert_eq!(boosts.tier_for(0), 0);
        assert_eq!(boosts.tier_for(1), 0);
        assert_eq!(boosts.tier_for(2), 1);
        assert_eq!(boosts.tier_for(6), 1);
        assert_eq!(boosts.tier_for(7), 2);
        assert_eq!(boosts.tier_for(13), 2);
        assert_eq!(boosts.tier_for(14), 3);
        assert_eq!(boosts.tier_for(500), 3);

        assert_eq!(boosts.next_tier_at(0), Some(2));
        assert_eq!(boosts.next_tier_at(1), Some(7));
        assert_eq!(boosts.next_tier_at(2), Some(14));
        assert_eq!(boosts.next_tier_at(3), None);
    }

    #[test]
    fn effective_limits_max_semantics() {
        let mut boosts = BoostFeatures {
            enabled: true,
            ..Default::default()
        };

        // Tier override raises a low global cap...
        assert_eq!(boosts.effective_server_emoji(100, 1), 200);
        assert_eq!(boosts.effective_server_emoji(100, 3), 500);
        // ...but never LOWERS an operator-raised one (max, not replace)
        assert_eq!(boosts.effective_server_emoji(10_000, 3), 10_000);
        // Tier 0 = global
        assert_eq!(boosts.effective_server_emoji(100, 0), 100);

        // A higher tier with no override inherits lower tiers' overrides
        boosts.tier3 = BoostTierPerks::default();
        assert_eq!(boosts.effective_server_emoji(100, 3), 300);

        // Disabled => always global, stored tiers notwithstanding
        boosts.enabled = false;
        assert_eq!(boosts.effective_server_emoji(100, 3), 100);
    }
}

// Built from in-process sources only, never the cached `config()`, so no
// local Revolt.overrides.toml or environment variable can skew the result.
#[cfg(test)]
mod antispam_config_tests {
    use std::collections::HashMap;

    use config::{Config, Environment, File, FileFormat};

    use super::{AntispamFeatures, Settings};

    /// The embedded Revolt.toml with its `[features.antispam]` table removed,
    /// standing in for a config that never mentions the feature
    fn embedded_without_antispam() -> String {
        include_str!("../Revolt.toml")
            .lines()
            .filter(|line| {
                let line = line.trim_start();
                line != "[features.antispam]"
                    && !line.starts_with("dm_dupe_")
                    && !line.starts_with("daily_")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Every field except `dm_dupe_enabled` at the planned default
    fn assert_defaults_except_enabled(antispam: &AntispamFeatures) {
        assert!(antispam.dm_dupe_pause);
        assert_eq!(antispam.dm_dupe_threshold, 3);
        assert_eq!(antispam.dm_dupe_window_hours, 24);
        assert_eq!(antispam.dm_dupe_min_chars, 30);
        assert_eq!(antispam.dm_dupe_rearm_days, 30);
        assert!(!antispam.daily_enabled);
        assert_eq!(antispam.daily_run_hour_utc, 14);
        assert_eq!(antispam.daily_account_age_days, 14);
        assert_eq!(antispam.daily_min_nonfriend_dms, 5);
        assert_eq!(antispam.daily_max_reply_ratio, 0.25);
        assert_eq!(antispam.daily_max_public_messages, 3);
        assert_eq!(antispam.daily_report_cooldown_days, 30);
        assert_eq!(antispam.daily_max_reports_per_run, 10);
    }

    fn assert_defaults(antispam: &AntispamFeatures) {
        assert!(!antispam.dm_dupe_enabled);
        assert_defaults_except_enabled(antispam);
    }

    #[test]
    fn hand_written_default_has_the_planned_values() {
        assert_defaults(&AntispamFeatures::default());
    }

    /// The embedded table must not drift from the code default
    #[test]
    fn embedded_table_matches_the_code_default() {
        let settings: Settings = Config::builder()
            .add_source(File::from_str(
                include_str!("../Revolt.toml"),
                FileFormat::Toml,
            ))
            .build()
            .expect("the embedded Revolt.toml builds")
            .try_deserialize()
            .expect("the embedded Revolt.toml deserializes");

        assert_defaults(&settings.features.antispam);
    }

    #[test]
    fn missing_table_takes_the_defaults() {
        let config = Config::builder()
            .add_source(File::from_str(
                &embedded_without_antispam(),
                FileFormat::Toml,
            ))
            .build()
            .expect("the stripped config builds");

        // The table must really be gone, or this test proves nothing
        assert!(config.get_table("features.antispam").is_err());

        let settings: Settings = config
            .try_deserialize()
            .expect("a config without [features.antispam] must deserialize");

        assert_defaults(&settings.features.antispam);
    }

    /// A partial table (what an overrides file holds) keeps every other default
    #[test]
    fn partial_table_keeps_the_other_defaults() {
        let config = Config::builder()
            .add_source(File::from_str(
                &embedded_without_antispam(),
                FileFormat::Toml,
            ))
            .add_source(File::from_str(
                "[features.antispam]\ndm_dupe_enabled = true\n",
                FileFormat::Toml,
            ))
            .build()
            .expect("the partial config builds");

        // Only the one key is present, so every other value is serde's default
        assert!(config
            .get_string("features.antispam.dm_dupe_threshold")
            .is_err());

        let settings: Settings = config
            .try_deserialize()
            .expect("a partial [features.antispam] table must deserialize");

        assert!(settings.features.antispam.dm_dupe_enabled);
        assert_defaults_except_enabled(&settings.features.antispam);
    }

    /// The documented env form (double underscores) reaches the nested keys,
    /// including the float. Supplied in-process, as CONFIG_BUILDER reads it.
    #[test]
    fn environment_override_reaches_the_table() {
        let vars = HashMap::from([
            (
                "REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED".to_owned(),
                "true".to_owned(),
            ),
            (
                "REVOLT__FEATURES__ANTISPAM__DM_DUPE_THRESHOLD".to_owned(),
                "4".to_owned(),
            ),
            (
                "REVOLT__FEATURES__ANTISPAM__DAILY_MAX_REPLY_RATIO".to_owned(),
                "0.5".to_owned(),
            ),
        ]);

        let settings: Settings = Config::builder()
            .add_source(File::from_str(
                include_str!("../Revolt.toml"),
                FileFormat::Toml,
            ))
            .add_source(
                Environment::with_prefix("REVOLT")
                    .separator("__")
                    .source(Some(vars)),
            )
            .build()
            .expect("the config builds")
            .try_deserialize()
            .expect("the config deserializes");

        let antispam = &settings.features.antispam;
        assert!(antispam.dm_dupe_enabled);
        assert_eq!(antispam.dm_dupe_threshold, 4);
        assert_eq!(antispam.daily_max_reply_ratio, 0.5);
        assert!(antispam.dm_dupe_pause);
        assert_eq!(antispam.dm_dupe_min_chars, 30);
    }

    #[test]
    fn helpers_clamp_misconfigured_values() {
        let mut antispam = AntispamFeatures {
            dm_dupe_threshold: 0,
            dm_dupe_min_chars: 1,
            ..Default::default()
        };
        assert_eq!(antispam.threshold(), 2);
        assert_eq!(antispam.min_chars(), 10);

        antispam.dm_dupe_threshold = 1;
        antispam.dm_dupe_min_chars = 0;
        assert_eq!(antispam.threshold(), 2);
        assert_eq!(antispam.min_chars(), 10);

        // Sane values pass through untouched
        let antispam = AntispamFeatures::default();
        assert_eq!(antispam.threshold(), 3);
        assert_eq!(antispam.min_chars(), 30);
    }
}

#[cfg(test)]
mod afk_auto_move_tests {
    use config::{Config, Environment, File, FileFormat};

    use super::Settings;

    fn embedded() -> File<config::FileSourceString, FileFormat> {
        File::from_str(include_str!("../Revolt.toml"), FileFormat::Toml)
    }

    /// The AFK sweep's kill switch is ON unless an operator turns it off.
    /// `#[serde(default)]` on a `bool` is `false`, so the `true` has to come
    /// from the embedded `Revolt.toml`, the first source every process loads.
    #[test]
    fn the_embedded_default_turns_the_sweep_on() {
        let settings: Settings = Config::builder()
            .add_source(embedded())
            .build()
            .expect("the embedded Revolt.toml builds")
            .try_deserialize()
            .expect("the embedded Revolt.toml deserializes");

        assert!(settings.features.afk_auto_move);
    }

    /// And the documented override turns it off (double underscores). The
    /// environment source is configured exactly as `CONFIG_BUILDER` does,
    /// with the variable supplied in-process rather than set on the test
    /// process.
    #[test]
    fn the_environment_override_turns_the_sweep_off() {
        let settings: Settings = Config::builder()
            .add_source(embedded())
            .add_source(
                Environment::with_prefix("REVOLT")
                    .separator("__")
                    .source(Some(
                        [(
                            "REVOLT__FEATURES__AFK_AUTO_MOVE".to_string(),
                            "false".to_string(),
                        )]
                        .into(),
                    )),
            )
            .build()
            .expect("the config builds")
            .try_deserialize()
            .expect("the config deserializes");

        assert!(!settings.features.afk_auto_move);
    }
}

// Built the way CONFIG_BUILDER builds it: the embedded Revolt.toml first, then
// a later TOML source standing in for Revolt.overrides.toml. Key fields are
// compared with `assert!`, never `assert_eq!`, so a failure prints no values.
#[cfg(test)]
mod vapid_config_tests {
    use super::Settings;
    use config::{Config, File, FileFormat};

    const DEFAULT_VAPID_QUEUE: &str = "notifications.outbound.vapid";

    // Obviously fake placeholders; the merge does not care what they hold.
    const OVERRIDES: &str = r#"
[pushd.vapid]
private_key = "fake-primary-private-key-placeholder"
public_key = "fake-primary-public-key-placeholder"
legacy_private_key = "fake-legacy-private-key-placeholder"
"#;

    #[test]
    fn overrides_vapid_table_keeps_default_queue() {
        let settings = Config::builder()
            .add_source(File::from_str(
                include_str!("../Revolt.toml"),
                FileFormat::Toml,
            ))
            .add_source(File::from_str(OVERRIDES, FileFormat::Toml))
            .build()
            .expect("embedded defaults plus overrides must build")
            .try_deserialize::<Settings>()
            .expect("merged config must deserialize");

        let vapid = &settings.pushd.vapid;
        assert_eq!(vapid.queue, DEFAULT_VAPID_QUEUE);
        assert!(
            vapid.private_key == "fake-primary-private-key-placeholder",
            "private_key did not take the override"
        );
        assert!(
            vapid.public_key == "fake-primary-public-key-placeholder",
            "public_key did not take the override"
        );
        assert!(
            vapid.legacy_private_key == "fake-legacy-private-key-placeholder",
            "legacy_private_key did not take the override"
        );
    }

    #[test]
    fn missing_legacy_private_key_defaults_to_empty() {
        let without_legacy = include_str!("../Revolt.toml")
            .lines()
            .filter(|line| !line.trim_start().starts_with("legacy_private_key"))
            .collect::<Vec<_>>()
            .join("\n");

        let config = Config::builder()
            .add_source(File::from_str(&without_legacy, FileFormat::Toml))
            .build()
            .expect("embedded defaults must build");

        // The key must really be gone, or this test proves nothing.
        assert!(config.get_string("pushd.vapid.legacy_private_key").is_err());

        let settings = config
            .try_deserialize::<Settings>()
            .expect("a config without pushd.vapid.legacy_private_key must deserialize");

        assert!(
            settings.pushd.vapid.legacy_private_key.is_empty(),
            "legacy_private_key must default to empty"
        );
        assert_eq!(settings.pushd.vapid.queue, DEFAULT_VAPID_QUEUE);
    }
}

#[cfg(test)]
mod january_tests {
    use std::collections::HashMap;

    use config::{builder::DefaultState, Config, ConfigBuilder, Environment, File, FileFormat};

    use super::{January, Settings};

    /// Only the bundled defaults, so no local override file can skew the result
    fn bundled() -> ConfigBuilder<DefaultState> {
        Config::builder().add_source(File::from_str(
            include_str!("../Revolt.toml"),
            FileFormat::Toml,
        ))
    }

    #[test]
    fn audio_embed_defaults() {
        let settings: Settings = bundled().build().unwrap().try_deserialize().unwrap();

        assert!(!settings.january.audio_embeds);
        assert_eq!(settings.january.max_audio_bytes, 52_428_800);
        assert_eq!(settings.january.max_audio_streams, 32);
        assert_eq!(settings.january.max_audio_stream_secs, 600);
    }

    #[test]
    fn audio_embeds_env_override() {
        // Same environment source as CONFIG_BUILDER, fed from a map instead of
        // the process environment so tests cannot race on global state
        let vars = HashMap::from([(
            "REVOLT__JANUARY__AUDIO_EMBEDS".to_owned(),
            "true".to_owned(),
        )]);

        let january: January = bundled()
            .add_source(
                Environment::with_prefix("REVOLT")
                    .separator("__")
                    .source(Some(vars)),
            )
            .build()
            .unwrap()
            .get("january")
            .unwrap();

        assert!(january.audio_embeds);
        assert_eq!(january.max_audio_bytes, 52_428_800);
    }
}

// Key material must never reach a Debug string (logs, panics, Sentry). The keys
// here are fake, but failures still print no formatted output, by convention.
#[cfg(test)]
mod files_debug_tests {
    use config::{Config, ConfigError, Environment, File, FileFormat};

    use super::{Files, FilesS3, RedactedKeys, Settings};

    const PRIMARY: &str = "w1aFakePrimaryKeyNotARealKeyAAAAAAAAAAAAAAA=";
    const EXTRA: &str = "w1aFakeDecryptKeyNotARealKeyBBBBBBBBBBBBBBB=";
    const MISPLACED: &str = "w1fixFakeStringKeyNotARealKeyCCCCCCCCCCCCCC=";
    const S3_SECRET: &str = "w1fixFakeS3SecretNotARealSecretDDDDDDDDDDDD";

    /// A self-contained `[files]` table, so the test does not depend on the
    /// bundled Revolt.toml
    fn files_toml(extra: &str) -> String {
        format!(
            r#"
[files]
encryption_key = "{PRIMARY}"
webp_quality = 80.0
blocked_mime_types = []
clamd_host = ""
scan_mime_types = []

[files.limit]
min_file_size = 1
min_resolution = [1, 1]
max_mega_pixels = 40
max_pixel_side = 10000

[files.preview]
attachments = [1280, 1280]

[files.s3]
endpoint = "http://minio:9000"
path_style_buckets = false
region = "minio"
access_key_id = "minioautumn"
secret_access_key = "minioautumn"
default_bucket = "revolt-uploads"
{extra}"#
        )
    }

    fn parse(toml: &str) -> Files {
        Config::builder()
            .add_source(File::from_str(toml, FileFormat::Toml))
            .build()
            .expect("the test config builds")
            .get::<Files>("files")
            .expect("the test config deserializes")
    }

    #[test]
    fn new_fields_default_when_absent() {
        let files = parse(&files_toml(""));

        assert_eq!(files.encryption_key_id, "legacy");
        assert!(files.decrypt_keys.0.is_empty());
        assert!(!files.require_rotated_key);
    }

    #[test]
    fn files_debug_never_prints_a_key() {
        let files = parse(&files_toml(&format!(
            r#"
[files.decrypt_keys]
k2025 = "{EXTRA}"
"#
        )));

        // The keys really did deserialize, or the assertions below prove nothing
        assert!(files.encryption_key == PRIMARY, "primary key not loaded");
        assert!(
            files.decrypt_keys.0.get("k2025").map(String::as_str) == Some(EXTRA),
            "decrypt key not loaded"
        );

        let debug = format!("{files:?}");
        assert!(!debug.contains(PRIMARY), "Files Debug leaks encryption_key");
        assert!(!debug.contains(EXTRA), "Files Debug leaks a decrypt key");
        assert!(debug.contains(r#"encryption_key: "<redacted>""#));
        assert!(debug.contains(r#"decrypt_keys: RedactedKeys(["k2025"])"#));
        assert!(debug.contains(r#"encryption_key_id: "legacy""#));
        assert!(debug.contains("require_rotated_key: false"));
        assert!(debug.contains(r#"clamd_host: """#));
    }

    #[test]
    fn redacted_keys_debug_prints_sorted_ids_only() {
        let keys = RedactedKeys(
            [
                ("legacy".to_string(), PRIMARY.to_string()),
                ("k2025".to_string(), EXTRA.to_string()),
            ]
            .into(),
        );

        let debug = format!("{keys:?}");
        assert!(!debug.contains(PRIMARY), "RedactedKeys Debug leaks a value");
        assert!(!debug.contains(EXTRA), "RedactedKeys Debug leaks a value");
        assert_eq!(debug, r#"RedactedKeys(["k2025", "legacy"])"#);
        assert_eq!(format!("{:?}", RedactedKeys::default()), "RedactedKeys([])");
    }

    /// `files_toml("")` with a second TOML source layered on top, the way
    /// Revolt.overrides.toml is; returns the error instead of panicking
    fn try_parse_with(overlay: &str) -> Result<Files, ConfigError> {
        Config::builder()
            .add_source(File::from_str(&files_toml(""), FileFormat::Toml))
            .add_source(File::from_str(overlay, FileFormat::Toml))
            .build()?
            .get::<Files>("files")
    }

    /// The whole Settings, built as CONFIG_BUILDER builds it: the embedded
    /// Revolt.toml, then the environment (supplied in-process)
    fn try_settings_with_env(name: &str, value: &str) -> Result<Settings, ConfigError> {
        Config::builder()
            .add_source(File::from_str(
                include_str!("../Revolt.toml"),
                FileFormat::Toml,
            ))
            .add_source(
                Environment::with_prefix("REVOLT")
                    .separator("__")
                    .source(Some([(name.to_string(), value.to_string())].into())),
            )
            .build()?
            .try_deserialize::<Settings>()
    }

    /// Both renderings of a config error: Display reaches logs, and Debug
    /// (which config-rs forwards to Display) reaches the boot `unwrap` panic
    fn rendered(error: &ConfigError) -> String {
        format!("{error} {error:?}")
    }

    const NOT_A_TABLE: &str =
        "files.decrypt_keys must be a table of `id = \"base64 key\"`, not a string";

    /// A key written where the table belongs fails with an error that names
    /// the mistake, never the key. The leak check runs first, so the wording
    /// check may print the error.
    #[test]
    fn decrypt_keys_as_a_string_fails_without_echoing_it() {
        let Err(error) = try_parse_with(&format!("[files]\ndecrypt_keys = \"{MISPLACED}\"\n"))
        else {
            panic!("a string decrypt_keys deserialized");
        };
        assert!(
            !rendered(&error).contains(MISPLACED),
            "the TOML error echoes the key"
        );
        assert_eq!(format!("{error}"), NOT_A_TABLE);

        let Err(error) = try_settings_with_env("REVOLT__FILES__DECRYPT_KEYS", MISPLACED) else {
            panic!("a string REVOLT__FILES__DECRYPT_KEYS deserialized");
        };
        assert!(
            !rendered(&error).contains(MISPLACED),
            "the env error echoes the key"
        );
        assert_eq!(format!("{error}"), NOT_A_TABLE);
    }

    /// A table value of any other kind fails cleanly, and a nested table that
    /// holds a key does not echo it either
    #[test]
    fn decrypt_keys_with_a_non_string_value_fails_cleanly() {
        let cases = [
            ("legacy = 987654321".to_string(), "a number"),
            ("legacy = 1.5".to_string(), "a number"),
            ("legacy = true".to_string(), "a boolean"),
            ("legacy = []".to_string(), "an array"),
            (format!("legacy = {{ key = \"{MISPLACED}\" }}"), "a table"),
        ];

        for (entry, found) in cases {
            let Err(error) = try_parse_with(&format!("[files.decrypt_keys]\n{entry}\n")) else {
                panic!("a non-string decrypt key deserialized ({found})");
            };
            let text = rendered(&error);
            assert!(
                !text.contains(MISPLACED),
                "the error echoes a key ({found})"
            );
            assert!(
                !text.contains("987654321"),
                "the error echoes the value ({found})"
            );
            assert_eq!(
                format!("{error}"),
                format!("each files.decrypt_keys value must be a base64 key string, not {found}")
            );
        }
    }

    /// The normal shapes still load: a TOML table, and per-id environment
    /// variables (config-rs lowercases the id)
    #[test]
    fn decrypt_keys_table_parses_from_toml_and_environment() {
        let Ok(files) = try_parse_with(&format!(
            "[files.decrypt_keys]\nk2025 = \"{EXTRA}\"\nlegacy = \"{PRIMARY}\"\n"
        )) else {
            panic!("a valid decrypt_keys table failed to deserialize");
        };
        let keys = &files.decrypt_keys.0;
        assert!(keys.len() == 2, "wrong number of decrypt keys");
        assert!(
            keys.get("k2025").map(String::as_str) == Some(EXTRA),
            "k2025 not loaded"
        );
        assert!(
            keys.get("legacy").map(String::as_str) == Some(PRIMARY),
            "legacy not loaded"
        );

        let Ok(settings) = try_settings_with_env("REVOLT__FILES__DECRYPT_KEYS__K1", EXTRA) else {
            panic!("REVOLT__FILES__DECRYPT_KEYS__K1 failed to deserialize");
        };
        let keys = &settings.files.decrypt_keys.0;
        assert!(
            keys.len() == 1,
            "wrong number of decrypt keys from the environment"
        );
        assert!(
            keys.get("k1").map(String::as_str) == Some(EXTRA),
            "k1 not loaded"
        );
    }

    #[test]
    fn files_s3_debug_redacts_the_secret_only() {
        let s3 = FilesS3 {
            endpoint: "http://minio:9000".to_string(),
            path_style_buckets: false,
            region: "minio".to_string(),
            access_key_id: "w1fixAccessKeyId".to_string(),
            secret_access_key: S3_SECRET.to_string(),
            default_bucket: "revolt-uploads".to_string(),
        };

        let debug = format!("{s3:?}");
        assert!(
            !debug.contains(S3_SECRET),
            "FilesS3 Debug leaks secret_access_key"
        );
        assert_eq!(
            debug,
            r#"FilesS3 { endpoint: "http://minio:9000", path_style_buckets: false, region: "minio", access_key_id: "w1fixAccessKeyId", secret_access_key: "<redacted>", default_bucket: "revolt-uploads" }"#
        );

        // And nested in Files, the way a Settings dump prints it
        let Ok(files) = try_parse_with(&format!(
            "[files.s3]\nsecret_access_key = \"{S3_SECRET}\"\n"
        )) else {
            panic!("the s3 overlay failed to deserialize");
        };
        assert!(
            files.s3.secret_access_key == S3_SECRET,
            "s3 secret not loaded"
        );

        let debug = format!("{files:?}");
        assert!(
            !debug.contains(S3_SECRET),
            "Files Debug leaks secret_access_key"
        );
        assert!(debug.contains(r#"secret_access_key: "<redacted>""#));
        assert!(debug.contains(r#"access_key_id: "minioautumn""#));
    }
}

// Built from in-process sources only, never the cached `config()`, so no
// local Revolt.overrides.toml or environment variable can skew the result.
// Secrets are compared with `assert!`, never `assert_eq!`, so a failure
// prints no values.
#[cfg(test)]
mod import_config_tests {
    use std::collections::HashMap;

    use config::{builder::DefaultState, Config, ConfigBuilder, Environment, File, FileFormat};

    use super::{ApiImport, ApiImportBotSource, ApiImportMatrix, Settings};

    const SECRET: &str = "fake-challenge-secret-placeholder";
    const DISCORD_TOKEN: &str = "fake-discord-bot-token-placeholder";
    const STOAT_TOKEN: &str = "fake-stoat-bot-token-placeholder";
    const FLUXER_TOKEN: &str = "fake-fluxer-bot-token-placeholder";
    const MATRIX_TOKEN: &str = "fake-matrix-access-token-placeholder";

    /// Only the bundled defaults, so no local override file can skew the result
    fn bundled() -> ConfigBuilder<DefaultState> {
        Config::builder().add_source(File::from_str(
            include_str!("../Revolt.toml"),
            FileFormat::Toml,
        ))
    }

    fn settings(builder: ConfigBuilder<DefaultState>) -> Settings {
        builder
            .build()
            .expect("the config builds")
            .try_deserialize()
            .expect("the config deserializes")
    }

    fn full_bot_source() -> ApiImportBotSource {
        ApiImportBotSource {
            enabled: true,
            api_url: "https://api.example.test".to_string(),
            app_url: "https://example.test".to_string(),
            cdn_url: "https://cdn.example.test".to_string(),
            bot_id: "01BOTID".to_string(),
            bot_token: STOAT_TOKEN.to_string(),
            reconcile_after_hours: 24,
        }
    }

    fn full_matrix() -> ApiImportMatrix {
        ApiImportMatrix {
            enabled: true,
            homeserver_url: "https://matrix.example.test".to_string(),
            bot_user_id: "@sloga-import:example.test".to_string(),
            access_token: MATRIX_TOKEN.to_string(),
            max_joins: 8,
        }
    }

    fn assert_stoat_defaults(stoat: &ApiImportBotSource) {
        assert!(!stoat.enabled);
        assert_eq!(stoat.api_url, "https://api.stoat.chat");
        assert_eq!(stoat.app_url, "https://stoat.chat");
        assert_eq!(stoat.cdn_url, "https://cdn.stoatusercontent.com");
        assert!(stoat.bot_id.is_empty());
        assert!(stoat.bot_token.is_empty());
        assert_eq!(stoat.reconcile_after_hours, 0);
    }

    fn assert_fluxer_defaults(fluxer: &ApiImportBotSource) {
        assert!(!fluxer.enabled);
        assert_eq!(fluxer.api_url, "https://api.fluxer.app");
        assert_eq!(fluxer.app_url, "https://fluxer.app");
        assert_eq!(fluxer.cdn_url, "https://fluxerusercontent.com");
        assert!(fluxer.bot_id.is_empty());
        assert!(fluxer.bot_token.is_empty());
    }

    fn assert_matrix_defaults(matrix: &ApiImportMatrix) {
        assert!(!matrix.enabled);
        assert!(matrix.homeserver_url.is_empty());
        assert!(matrix.bot_user_id.is_empty());
        assert!(matrix.access_token.is_empty());
        assert_eq!(matrix.max_joins, 8);
    }

    fn assert_import_defaults(import: &ApiImport) {
        assert!(import.challenge_secret.is_empty());
        assert!(!import.discord.enabled);
        assert_stoat_defaults(&import.stoat);
        assert_fluxer_defaults(&import.fluxer);
        assert_matrix_defaults(&import.matrix);
        assert!(!import.stoat_ready());
        assert!(!import.fluxer_ready());
        assert!(!import.matrix_ready());
        assert!(!import.any_enabled());
    }

    #[test]
    fn bot_source_ready_truth_table() {
        assert!(full_bot_source().ready(SECRET));

        // An empty challenge secret alone keeps a fully configured source off
        assert!(!full_bot_source().ready(""));

        type Clear = fn(&mut ApiImportBotSource);
        let required: [(&str, Clear); 5] = [
            ("enabled", |s| s.enabled = false),
            ("bot_id", |s| s.bot_id.clear()),
            ("bot_token", |s| s.bot_token.clear()),
            ("api_url", |s| s.api_url.clear()),
            ("cdn_url", |s| s.cdn_url.clear()),
        ];
        for (name, clear) in required {
            let mut source = full_bot_source();
            clear(&mut source);
            assert!(!source.ready(SECRET), "ready() without {name}");
        }

        // app_url only builds the add-bot link; the read path never uses it
        let mut source = full_bot_source();
        source.app_url.clear();
        assert!(source.ready(SECRET));

        assert!(!ApiImportBotSource::default().ready(SECRET));
    }

    #[test]
    fn matrix_ready_truth_table() {
        assert!(full_matrix().ready(SECRET));
        assert!(!full_matrix().ready(""));

        type Clear = fn(&mut ApiImportMatrix);
        let required: [(&str, Clear); 4] = [
            ("enabled", |m| m.enabled = false),
            ("homeserver_url", |m| m.homeserver_url.clear()),
            ("bot_user_id", |m| m.bot_user_id.clear()),
            ("access_token", |m| m.access_token.clear()),
        ];
        for (name, clear) in required {
            let mut matrix = full_matrix();
            clear(&mut matrix);
            assert!(!matrix.ready(SECRET), "ready() without {name}");
        }

        // The join budget is not a readiness key
        let mut matrix = full_matrix();
        matrix.max_joins = 0;
        assert!(matrix.ready(SECRET));

        assert!(!ApiImportMatrix::default().ready(SECRET));
    }

    /// The per-source helpers pass the shared secret, and only their own source
    #[test]
    fn source_helpers_use_the_shared_secret() {
        let mut import = ApiImport {
            stoat: full_bot_source(),
            fluxer: full_bot_source(),
            matrix: full_matrix(),
            ..Default::default()
        };
        assert!(!import.stoat_ready());
        assert!(!import.fluxer_ready());
        assert!(!import.matrix_ready());

        import.challenge_secret = SECRET.to_string();
        assert!(import.stoat_ready());
        assert!(import.fluxer_ready());
        assert!(import.matrix_ready());

        import.stoat.enabled = false;
        assert!(!import.stoat_ready());
        assert!(import.fluxer_ready());
        assert!(import.matrix_ready());

        import.fluxer.bot_token.clear();
        assert!(!import.fluxer_ready());
        assert!(import.matrix_ready());

        import.matrix.access_token.clear();
        assert!(!import.matrix_ready());
    }

    /// Enabled flags only: readiness is re-checked per job kind in crond
    #[test]
    fn any_enabled_reads_the_flags_only() {
        assert!(!ApiImport::default().any_enabled());

        type Enable = fn(&mut ApiImport);
        let flags: [(&str, Enable); 4] = [
            ("discord", |i| i.discord.enabled = true),
            ("stoat", |i| i.stoat.enabled = true),
            ("fluxer", |i| i.fluxer.enabled = true),
            ("matrix", |i| i.matrix.enabled = true),
        ];
        for (name, enable) in flags {
            let mut import = ApiImport::default();
            enable(&mut import);
            assert!(import.any_enabled(), "any_enabled() missed {name}");
            // No keys and no secret: on, but not ready
            assert!(!import.stoat_ready());
            assert!(!import.fluxer_ready());
            assert!(!import.matrix_ready());
        }
    }

    #[test]
    fn hand_written_default_has_the_planned_values() {
        assert_import_defaults(&ApiImport::default());
    }

    /// The embedded tables must not drift from the code defaults
    #[test]
    fn embedded_tables_match_the_code_defaults() {
        let settings = settings(bundled());
        assert_import_defaults(&settings.api.import);
    }

    /// A config with no import tables at all, and partial tables (what an
    /// overrides file holds), still deserialize with the planned defaults
    #[test]
    fn missing_and_partial_tables_take_the_defaults() {
        let empty: ApiImport = Config::builder()
            .build()
            .expect("an empty config builds")
            .try_deserialize()
            .expect("an empty table must deserialize");
        assert_import_defaults(&empty);

        let partial: ApiImport = Config::builder()
            .add_source(File::from_str(
                "[matrix]\nenabled = true\n[stoat]\nbot_id = \"x\"\n",
                FileFormat::Toml,
            ))
            .build()
            .expect("a partial config builds")
            .try_deserialize()
            .expect("partial tables must deserialize");
        assert!(partial.matrix.enabled);
        assert_eq!(partial.matrix.max_joins, 8);
        // A partial table without the baked file has no URLs, so the source
        // can never be ready from it alone
        assert_eq!(partial.stoat.bot_id, "x");
        assert!(partial.stoat.api_url.is_empty());
        // A table that leaves the reconcile out (heart1's today) gets it off
        assert_eq!(partial.stoat.reconcile_after_hours, 0);
        assert_fluxer_defaults(&partial.fluxer);
    }

    /// The operator turns the bot reconcile on (and picks its grace) in the
    /// overrides of the one deployment that owns the bot
    #[test]
    fn overrides_set_the_reconcile_grace() {
        for (value, expected) in [(0, 0), (24, 24), (6, 6)] {
            let overrides = format!("[api.import.stoat]\nreconcile_after_hours = {value}\n");
            let settings =
                settings(bundled().add_source(File::from_str(&overrides, FileFormat::Toml)));
            assert_eq!(settings.api.import.stoat.reconcile_after_hours, expected);
            assert_eq!(settings.api.import.fluxer.reconcile_after_hours, 0);
        }
    }

    /// Overrides on top of the baked file: the operator sets only the secrets
    /// and ids, and the baked public URLs survive the merge
    #[test]
    fn overrides_make_a_source_ready_and_keep_the_baked_urls() {
        let overrides = format!(
            "[api.import]\nchallenge_secret = \"{SECRET}\"\n\
             [api.import.stoat]\nenabled = true\nbot_id = \"01BOTID\"\nbot_token = \"{STOAT_TOKEN}\"\n"
        );
        let settings = settings(bundled().add_source(File::from_str(&overrides, FileFormat::Toml)));
        let import = &settings.api.import;

        assert!(import.stoat_ready());
        assert_eq!(import.stoat.api_url, "https://api.stoat.chat");
        assert_eq!(import.stoat.cdn_url, "https://cdn.stoatusercontent.com");
        assert_eq!(import.stoat.reconcile_after_hours, 0);
        assert!(!import.fluxer_ready());
        assert!(!import.matrix_ready());
        assert!(import.any_enabled());
    }

    /// The documented env form (double underscores) reaches the nested keys.
    /// Supplied in-process, as CONFIG_BUILDER reads it.
    #[test]
    fn environment_override_reaches_the_tables() {
        let vars = HashMap::from([
            (
                "REVOLT__API__IMPORT__CHALLENGE_SECRET".to_owned(),
                SECRET.to_owned(),
            ),
            (
                "REVOLT__API__IMPORT__MATRIX__ENABLED".to_owned(),
                "true".to_owned(),
            ),
            (
                "REVOLT__API__IMPORT__MATRIX__MAX_JOINS".to_owned(),
                "3".to_owned(),
            ),
        ]);

        let settings = settings(
            bundled().add_source(
                Environment::with_prefix("REVOLT")
                    .separator("__")
                    .source(Some(vars)),
            ),
        );
        let import = &settings.api.import;

        assert!(
            import.challenge_secret == SECRET,
            "challenge_secret not loaded"
        );
        assert!(import.matrix.enabled);
        assert_eq!(import.matrix.max_joins, 3);
        // Enabled with no bot keys is still not ready
        assert!(!import.matrix_ready());
    }

    #[test]
    fn debug_never_prints_the_import_secrets() {
        let overrides = format!(
            "[api.import]\nchallenge_secret = \"{SECRET}\"\n\
             [api.import.discord]\nbot_token = \"{DISCORD_TOKEN}\"\n\
             [api.import.stoat]\nbot_token = \"{STOAT_TOKEN}\"\n\
             [api.import.fluxer]\nbot_token = \"{FLUXER_TOKEN}\"\n\
             [api.import.matrix]\naccess_token = \"{MATRIX_TOKEN}\"\n"
        );
        let settings = settings(bundled().add_source(File::from_str(&overrides, FileFormat::Toml)));

        // The values really loaded, or the absence below proves nothing
        let import = &settings.api.import;
        assert!(
            import.challenge_secret == SECRET,
            "challenge_secret not loaded"
        );
        assert!(
            import.discord.bot_token == DISCORD_TOKEN,
            "discord token not loaded"
        );
        assert!(
            import.stoat.bot_token == STOAT_TOKEN,
            "stoat token not loaded"
        );
        assert!(
            import.fluxer.bot_token == FLUXER_TOKEN,
            "fluxer token not loaded"
        );
        assert!(
            import.matrix.access_token == MATRIX_TOKEN,
            "matrix token not loaded"
        );

        // `init()` prints the whole Settings at boot
        let debug = format!("{settings:?}");
        for (name, secret) in [
            ("challenge_secret", SECRET),
            ("discord bot_token", DISCORD_TOKEN),
            ("stoat bot_token", STOAT_TOKEN),
            ("fluxer bot_token", FLUXER_TOKEN),
            ("matrix access_token", MATRIX_TOKEN),
        ] {
            assert!(!debug.contains(secret), "Settings Debug leaks {name}");
        }

        let debug = format!("{import:?}");
        assert!(debug.contains(r#"challenge_secret: "<redacted>""#));
        assert_eq!(debug.matches(r#"bot_token: "<redacted>""#).count(), 3);
        assert!(debug.contains(r#"access_token: "<redacted>""#));
        // Non-secret fields still print
        assert!(debug.contains(r#"api_url: "https://api.stoat.chat""#));
        assert!(debug.contains("max_joins: 8"));
    }
}

// The Blizzard secret and the internal key must never reach a Debug string.
// Failures print no formatted output, by convention.
#[cfg(test)]
mod gamedata_debug_tests {
    use config::{Config, File, FileFormat};

    use super::{ApiGamedata, Settings};

    const SECRET: &str = "la1FakeBlizzardSecretNotARealOne";
    const INTERNAL: &str = "la1FakeInternalKeyNotARealOne";

    #[test]
    fn debug_redacts_secret_and_internal_key() {
        let gamedata = ApiGamedata {
            blizzard_client_id: "la1-client-id".into(),
            blizzard_client_secret: SECRET.into(),
            internal_key: INTERNAL.into(),
            internal_january: "http://127.0.0.1:14705".into(),
            ..ApiGamedata::default()
        };
        let printed = format!("{gamedata:?}");
        let pretty = format!("{gamedata:#?}");
        assert!(!printed.contains(SECRET), "blizzard_client_secret printed");
        assert!(!printed.contains(INTERNAL), "internal_key printed");
        assert!(!pretty.contains(SECRET), "blizzard_client_secret printed (pretty)");
        assert!(!pretty.contains(INTERNAL), "internal_key printed (pretty)");
        assert!(printed.contains("la1-client-id"), "non-secret field missing");
        assert!(
            printed.contains(r#"internal_january: "http://127.0.0.1:14705""#),
            "internal_january missing"
        );
        assert_eq!(printed.matches("<redacted>").count(), 2);
    }

    #[test]
    fn bundled_defaults_match_default_impl() {
        let settings: Settings = Config::builder()
            .add_source(File::from_str(include_str!("../Revolt.toml"), FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();
        let bundled = settings.api.gamedata;
        let default = ApiGamedata::default();
        assert!(bundled.blizzard_client_id.is_empty());
        assert!(bundled.blizzard_client_secret.is_empty());
        assert!(bundled.internal_key.is_empty());
        assert!(bundled.internal_january.is_empty());
        assert_eq!(bundled.steam_store_window_secs, default.steam_store_window_secs);
        assert_eq!(bundled.steam_store_embed_budget, default.steam_store_embed_budget);
        assert_eq!(
            bundled.steam_store_interactive_budget,
            default.steam_store_interactive_budget
        );
        assert_eq!(bundled.steam_news_per_window, default.steam_news_per_window);
        assert_eq!(bundled.blizzard_per_second, default.blizzard_per_second);
    }
}

// Built from in-process sources only, never the cached `config()`. Secrets are
// fake, and leak checks use `assert!` so a failure prints no values.
#[cfg(test)]
mod payments_config_tests {
    use std::collections::HashMap;

    use config::{Config, Environment, File, FileFormat};

    use super::{ApiStripe, FeaturePayments, Settings, CIPHER_BLOCKED_COUNTRIES_DEFAULT};

    const SECRET_KEY: &str = "sk_test_w1cfgFakeSecretKeyNotARealKey";
    const WEBHOOK_SECRET: &str = "whsec_w1cfgFakeWebhookSecretNotReal";

    /// The embedded Revolt.toml with `[features.payments]` and `[api.stripe]`
    /// removed, standing in for a config that never mentions either
    fn embedded_without_payments() -> String {
        let mut skipping = false;
        include_str!("../Revolt.toml")
            .lines()
            .filter(|line| {
                let line = line.trim_start();
                if line.starts_with('[') {
                    skipping = line == "[features.payments]" || line == "[api.stripe]";
                }
                !skipping
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn assert_payments_defaults(payments: &FeaturePayments) {
        assert!(!payments.enabled);
        assert!(!payments.cipher_sales_open);
        assert_eq!(payments.cipher_cap, 1000);
        assert_eq!(payments.cipher_sales_close_at, "");
        assert_eq!(
            payments.cipher_blocked_countries,
            CIPHER_BLOCKED_COUNTRIES_DEFAULT
                .map(str::to_string)
                .to_vec()
        );
    }

    /// The default list is the 27 EU member states plus the UK, each once
    #[test]
    fn blocked_countries_default_is_the_eu_and_the_uk() {
        let mut codes = CIPHER_BLOCKED_COUNTRIES_DEFAULT.to_vec();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), 28);
        assert!(codes
            .iter()
            .all(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase())));
        for code in ["DE", "FR", "IE", "NL", "GB"] {
            assert!(codes.contains(&code), "{code} is missing");
        }
        // Not EU members, or not ISO 3166-1 alpha-2 (UK, EL)
        for code in ["US", "CH", "NO", "IS", "UK", "EL"] {
            assert!(!codes.contains(&code), "{code} must not be listed");
        }
    }

    fn assert_stripe_defaults(stripe: &ApiStripe) {
        assert!(stripe.secret_key.is_empty());
        assert!(stripe.webhook_secret.is_empty());
        assert!(!stripe.expect_livemode);
        assert_eq!(
            stripe.success_url_web,
            "https://app.sloga.gg/settings?cipher=success"
        );
        assert_eq!(
            stripe.cancel_url_web,
            "https://app.sloga.gg/settings?cipher=cancel"
        );
        assert_eq!(stripe.success_url_shell, "https://sloga.gg/cipher/thanks/");
        assert_eq!(stripe.cancel_url_shell, "https://sloga.gg/cipher/");
        assert_eq!(stripe.tolerance_secs, 300);
    }

    #[test]
    fn hand_written_defaults_have_the_planned_values() {
        assert_payments_defaults(&FeaturePayments::default());
        assert_stripe_defaults(&ApiStripe::default());
    }

    /// The embedded tables must not drift from the code defaults
    #[test]
    fn embedded_tables_match_the_code_defaults() {
        let settings: Settings = Config::builder()
            .add_source(File::from_str(
                include_str!("../Revolt.toml"),
                FileFormat::Toml,
            ))
            .build()
            .expect("the embedded Revolt.toml builds")
            .try_deserialize()
            .expect("the embedded Revolt.toml deserializes");

        assert_payments_defaults(&settings.features.payments);
        assert_stripe_defaults(&settings.api.stripe);
    }

    #[test]
    fn missing_tables_take_the_defaults() {
        let config = Config::builder()
            .add_source(File::from_str(
                &embedded_without_payments(),
                FileFormat::Toml,
            ))
            .build()
            .expect("the stripped config builds");

        // The tables must really be gone, or this test proves nothing
        assert!(config.get_table("features.payments").is_err());
        assert!(config.get_table("api.stripe").is_err());
        // ...and nothing else went with them
        assert!(config.get_table("features.antispam").is_ok());
        assert!(config.get_table("api.kofi").is_ok());

        let settings: Settings = config
            .try_deserialize()
            .expect("a config without the payments tables must deserialize");

        assert_payments_defaults(&settings.features.payments);
        assert_stripe_defaults(&settings.api.stripe);
    }

    /// An overrides-less install whose Revolt.toml predates `[api.stripe]`:
    /// the section is optional (`#[serde(default)]` on `Api.stripe`), so the
    /// whole config still loads, with the Stripe defaults. Without the
    /// attribute every process fails to start on "missing field `stripe`".
    #[test]
    fn missing_stripe_table_alone_takes_the_defaults() {
        let mut skipping = false;
        let stripped = include_str!("../Revolt.toml")
            .lines()
            .filter(|line| {
                let line = line.trim_start();
                if line.starts_with('[') {
                    skipping = line == "[api.stripe]";
                }
                !skipping
            })
            .collect::<Vec<_>>()
            .join("\n");

        let config = Config::builder()
            .add_source(File::from_str(&stripped, FileFormat::Toml))
            .build()
            .expect("the stripped config builds");

        // Only [api.stripe] is gone, or this test proves nothing
        assert!(config.get_table("api.stripe").is_err());
        assert!(config.get_table("features.payments").is_ok());
        assert!(config.get_table("api.gamedata").is_ok());

        let settings: Settings = config
            .try_deserialize()
            .expect("a config without [api.stripe] must deserialize");

        let stripe = &settings.api.stripe;
        assert_stripe_defaults(stripe);
        let defaults = ApiStripe::default();
        assert_eq!(stripe.secret_key, defaults.secret_key);
        assert_eq!(stripe.webhook_secret, defaults.webhook_secret);
        assert_eq!(stripe.expect_livemode, defaults.expect_livemode);
        assert_eq!(stripe.tolerance_secs, defaults.tolerance_secs);
    }

    /// `Features.payments` is optional the same way
    #[test]
    fn missing_payments_table_alone_takes_the_defaults() {
        let mut skipping = false;
        let stripped = include_str!("../Revolt.toml")
            .lines()
            .filter(|line| {
                let line = line.trim_start();
                if line.starts_with('[') {
                    skipping = line == "[features.payments]";
                }
                !skipping
            })
            .collect::<Vec<_>>()
            .join("\n");

        let config = Config::builder()
            .add_source(File::from_str(&stripped, FileFormat::Toml))
            .build()
            .expect("the stripped config builds");
        assert!(config.get_table("features.payments").is_err());
        assert!(config.get_table("api.stripe").is_ok());

        let settings: Settings = config
            .try_deserialize()
            .expect("a config without [features.payments] must deserialize");
        assert_payments_defaults(&settings.features.payments);
    }

    /// An overrides file replaces the whole blocked list (an empty one
    /// blocks nothing); one that does not set it keeps the default
    #[test]
    fn overrides_replace_the_blocked_countries() {
        let layered = |overrides: &str| -> Vec<String> {
            let settings: Settings = Config::builder()
                .add_source(File::from_str(
                    include_str!("../Revolt.toml"),
                    FileFormat::Toml,
                ))
                .add_source(File::from_str(overrides, FileFormat::Toml))
                .build()
                .expect("the layered config builds")
                .try_deserialize()
                .expect("the layered config deserializes");
            settings.features.payments.cipher_blocked_countries
        };

        assert_eq!(
            layered("[features.payments]\ncipher_blocked_countries = []\n"),
            Vec::<String>::new()
        );
        assert_eq!(
            layered("[features.payments]\ncipher_blocked_countries = [\"DE\", \"US\"]\n"),
            ["DE", "US"]
        );
        assert_eq!(
            layered("[features.payments]\nenabled = true\n"),
            CIPHER_BLOCKED_COUNTRIES_DEFAULT
                .map(str::to_string)
                .to_vec()
        );
    }

    /// The blocked list from the environment: one comma-separated string,
    /// each entry trimmed. An empty entry is kept for the payments config
    /// to refuse, never dropped.
    #[test]
    fn environment_sets_the_blocked_countries_as_a_comma_separated_string() {
        let from_env = |value: &str| -> Vec<String> {
            let settings: Settings = Config::builder()
                .add_source(File::from_str(
                    include_str!("../Revolt.toml"),
                    FileFormat::Toml,
                ))
                .add_source(
                    Environment::with_prefix("REVOLT")
                        .separator("__")
                        .source(Some(
                            [(
                                "REVOLT__FEATURES__PAYMENTS__CIPHER_BLOCKED_COUNTRIES".to_string(),
                                value.to_string(),
                            )]
                            .into(),
                        )),
                )
                .build()
                .expect("the config builds")
                .try_deserialize()
                .expect("the config deserializes");
            settings.features.payments.cipher_blocked_countries
        };

        assert_eq!(from_env("DE,FR"), ["DE", "FR"]);
        assert_eq!(from_env(" DE , US "), ["DE", "US"]);
        assert_eq!(from_env("GB"), ["GB"]);
        assert_eq!(from_env("DE,"), ["DE", ""]);
        assert_eq!(from_env(""), [""]);
    }

    /// The documented env form (double underscores) reaches the nested keys
    #[test]
    fn environment_override_reaches_the_tables() {
        let vars: HashMap<String, String> = [
            ("REVOLT__FEATURES__PAYMENTS__ENABLED", "true"),
            ("REVOLT__FEATURES__PAYMENTS__CIPHER_CAP", "250"),
            ("REVOLT__API__STRIPE__WEBHOOK_SECRET", WEBHOOK_SECRET),
            ("REVOLT__API__STRIPE__EXPECT_LIVEMODE", "true"),
        ]
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .into();

        let settings: Settings = Config::builder()
            .add_source(File::from_str(
                include_str!("../Revolt.toml"),
                FileFormat::Toml,
            ))
            .add_source(
                Environment::with_prefix("REVOLT")
                    .separator("__")
                    .source(Some(vars)),
            )
            .build()
            .expect("the config builds")
            .try_deserialize()
            .expect("the config deserializes");

        let payments = &settings.features.payments;
        assert!(payments.enabled);
        assert_eq!(payments.cipher_cap, 250);
        assert!(!payments.cipher_sales_open);

        let stripe = &settings.api.stripe;
        assert!(
            stripe.webhook_secret == WEBHOOK_SECRET,
            "webhook_secret did not take the override"
        );
        assert!(stripe.expect_livemode);
        assert!(stripe.secret_key.is_empty());
        assert_eq!(stripe.tolerance_secs, 300);
    }

    /// The test config layered on top, as CONFIG_BUILDER does under TEST_DB
    #[test]
    fn test_config_enables_payments_with_dummy_secrets() {
        let settings: Settings = Config::builder()
            .add_source(File::from_str(
                include_str!("../Revolt.toml"),
                FileFormat::Toml,
            ))
            .add_source(File::from_str(
                include_str!("../Revolt.test.toml"),
                FileFormat::Toml,
            ))
            .build()
            .expect("the test config builds")
            .try_deserialize()
            .expect("the test config deserializes");

        let payments = &settings.features.payments;
        assert!(payments.enabled);
        assert!(payments.cipher_sales_open);
        assert_eq!(payments.cipher_cap, 1000);
        assert_eq!(settings.api.stripe.secret_key, "sk_test_dummy");
        assert_eq!(settings.api.stripe.webhook_secret, "whsec_test_dummy");
    }

    #[test]
    fn stripe_debug_redacts_the_secrets_only() {
        let stripe = ApiStripe {
            secret_key: SECRET_KEY.to_string(),
            webhook_secret: WEBHOOK_SECRET.to_string(),
            ..Default::default()
        };

        let debug = format!("{stripe:?}");
        assert!(
            !debug.contains(SECRET_KEY),
            "ApiStripe Debug leaks secret_key"
        );
        assert!(
            !debug.contains(WEBHOOK_SECRET),
            "ApiStripe Debug leaks webhook_secret"
        );
        assert_eq!(
            debug,
            r#"ApiStripe { secret_key: "<redacted>", webhook_secret: "<redacted>", expect_livemode: false, success_url_web: "https://app.sloga.gg/settings?cipher=success", cancel_url_web: "https://app.sloga.gg/settings?cipher=cancel", success_url_shell: "https://sloga.gg/cipher/thanks/", cancel_url_shell: "https://sloga.gg/cipher/", tolerance_secs: 300, automatic_tax: false }"#
        );

        // Empty secrets say so, so a missing override is visible in the dump
        let debug = format!("{:?}", ApiStripe::default());
        assert!(debug.contains(r#"secret_key: "<unset>""#));
        assert!(debug.contains(r#"webhook_secret: "<unset>""#));
    }

    /// Nested in Settings, the way `init()` prints it
    #[test]
    fn settings_debug_never_prints_a_stripe_secret() {
        let overrides = format!(
            "[api.stripe]\nsecret_key = \"{SECRET_KEY}\"\nwebhook_secret = \"{WEBHOOK_SECRET}\"\n"
        );
        let settings: Settings = Config::builder()
            .add_source(File::from_str(
                include_str!("../Revolt.toml"),
                FileFormat::Toml,
            ))
            .add_source(File::from_str(&overrides, FileFormat::Toml))
            .build()
            .expect("the config builds")
            .try_deserialize()
            .expect("the config deserializes");

        // The secrets really did deserialize, or the assertions below prove nothing
        assert!(
            settings.api.stripe.secret_key == SECRET_KEY,
            "secret_key not loaded"
        );
        assert!(
            settings.api.stripe.webhook_secret == WEBHOOK_SECRET,
            "webhook_secret not loaded"
        );

        let debug = format!("{settings:?}");
        assert!(
            !debug.contains(SECRET_KEY),
            "Settings Debug leaks secret_key"
        );
        assert!(
            !debug.contains(WEBHOOK_SECRET),
            "Settings Debug leaks webhook_secret"
        );
    }
}

// Built from in-process sources only, never the cached `config()`, so no
// local Revolt.overrides.toml or environment variable can skew the result.
// `ProtectionFeatures` holds no secrets and has no PartialEq, so whole values
// are compared through their Debug output.
#[cfg(test)]
mod prot_config_tests {
    use std::collections::HashMap;

    use config::{Config, ConfigError, Environment, File, FileFormat};

    use super::{
        FeaturePayments, ProtPackConfig, ProtTierCosts, ProtectionFeatures, Settings,
        CIPHER_BLOCKED_COUNTRIES_DEFAULT, PROT_BLOCKED_COUNTRIES_DEFAULT,
    };

    /// The embedded Revolt.toml with each overlay layered on top, in order
    fn layered(overlays: &[&str]) -> Result<Settings, ConfigError> {
        let embedded = File::from_str(include_str!("../Revolt.toml"), FileFormat::Toml);
        let mut builder = Config::builder().add_source(embedded);
        for overlay in overlays {
            builder = builder.add_source(File::from_str(overlay, FileFormat::Toml));
        }
        builder.build()?.try_deserialize()
    }

    fn settings(overlays: &[&str]) -> Settings {
        layered(overlays).expect("the layered config deserializes")
    }

    fn pack(id: &str, cents: i64, prot: i64) -> ProtPackConfig {
        ProtPackConfig {
            id: id.to_string(),
            cents,
            prot,
        }
    }

    fn default_packs() -> Vec<ProtPackConfig> {
        vec![
            pack("p5", 500, 500),
            pack("p10", 1000, 1000),
            pack("p25", 2500, 2600),
            pack("p50", 5000, 5300),
            pack("p100", 10000, 11000),
        ]
    }

    fn assert_protection_defaults(protection: &ProtectionFeatures) {
        assert!(!protection.enabled);
        assert!(!protection.self_serve_enabled);
        assert!(!protection.burn_enabled);
        assert!(!protection.deletion_enabled);
        assert!(!protection.cipher_grants_enabled);
        assert_eq!(
            protection.channel_daily_cost,
            ProtTierCosts {
                t10: 40,
                t25: 90,
                t50: 160,
                t100: 280,
            }
        );
        assert_eq!(
            protection.server_daily_cost,
            ProtTierCosts {
                t10: 60,
                t25: 135,
                t50: 240,
                t100: 420,
            }
        );
        assert_eq!(protection.grace_days, 5);
        assert_eq!(protection.freeze_days, 25);
        assert_eq!(protection.final_warning_day, 20);
        assert_eq!(protection.warn_days, [7, 3, 1]);
        assert_eq!(protection.min_reactivation_days, 1);
        assert_eq!(protection.launch_goal_deadline_days, 30);
        assert_eq!(protection.launch_window_days, 7);
        assert_eq!(protection.launch_seat_window_days, 7);
        assert_eq!(protection.min_contribution, 50);
        assert_eq!(protection.min_launch_goal_days, 30);
        assert_eq!(protection.withdraw_cutoff_hours, 48);
        assert_eq!(protection.contribute_hold_hours, 72);
        assert_eq!(protection.wallet_cap, 100000);
    }

    fn assert_prot_payments_defaults(payments: &FeaturePayments) {
        assert!(!payments.prot_sales_open);
        assert_eq!(payments.prot_packs, default_packs());
        assert_eq!(payments.prot_exact_min_cents, 50);
        assert_eq!(payments.prot_exact_max_cents, 50000);
        assert_eq!(
            payments.prot_blocked_countries,
            PROT_BLOCKED_COUNTRIES_DEFAULT.map(str::to_string).to_vec()
        );
        assert_eq!(
            payments.prot_success_url,
            "https://app.sloga.gg/settings?prot=success"
        );
        assert_eq!(
            payments.prot_cancel_url,
            "https://app.sloga.gg/settings?prot=cancel"
        );
        assert_eq!(
            payments.prot_shell_return_url,
            "https://sloga.gg/prot/thanks/"
        );
    }

    #[test]
    fn hand_written_prot_defaults_have_the_planned_values() {
        assert_protection_defaults(&ProtectionFeatures::default());
        assert_protection_defaults(&super::BoostFeatures::default().protection);
        assert_prot_payments_defaults(&FeaturePayments::default());
    }

    /// The default packs pass the rules the payments config enforces: ids
    /// unique "p" + digits, at least Stripe's 50 cents, never fewer Prot than
    /// cents, and within the pay-exact ceiling
    #[test]
    fn default_packs_are_well_formed() {
        let payments = FeaturePayments::default();
        let mut seen: Vec<&str> = Vec::new();
        for p in &payments.prot_packs {
            assert!(!seen.contains(&p.id.as_str()), "{} repeats", p.id);
            seen.push(&p.id);

            let digits = p.id.strip_prefix('p').expect("ids start with p");
            assert!(
                !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()),
                "{} is not p + digits",
                p.id
            );
            assert!(p.cents >= 50, "{} costs under 50 cents", p.id);
            assert!(p.prot >= p.cents, "{} credits less than it costs", p.id);
            assert!(
                p.cents <= payments.prot_exact_max_cents,
                "{} costs more than the pay-exact ceiling",
                p.id
            );
        }
        assert_eq!(seen.len(), 5);
    }

    /// The embedded tables must not drift from the code defaults, and the
    /// protection table stays commented out (its defaults live in code)
    #[test]
    fn embedded_tables_match_the_code_defaults() {
        let config = Config::builder()
            .add_source(File::from_str(
                include_str!("../Revolt.toml"),
                FileFormat::Toml,
            ))
            .build()
            .expect("the embedded Revolt.toml builds");
        assert!(config.get_table("features.boosts.protection").is_err());

        let settings: Settings = config
            .try_deserialize()
            .expect("the embedded Revolt.toml deserializes");
        assert_protection_defaults(&settings.features.boosts.protection);
        assert_prot_payments_defaults(&settings.features.payments);
    }

    /// The commented `[features.boosts.protection]` block in Revolt.toml,
    /// uncommented, parses to exactly the code defaults, so the documented
    /// values cannot drift
    #[test]
    fn documented_protection_block_matches_the_code_defaults() {
        let block = include_str!("../Revolt.toml")
            .lines()
            .skip_while(|line| *line != "# [features.boosts.protection]")
            .take_while(|line| line.starts_with('#'))
            .map(|line| line.trim_start_matches('#').trim_start())
            .collect::<Vec<_>>()
            .join("\n");

        // Every key is in the block, or the comparison below proves little
        let documented = block.lines().filter(|line| line.contains(" = ")).count();
        assert_eq!(documented, 20, "the documented block lists every key");

        let protection = settings(&[block.as_str()]).features.boosts.protection;
        let expected = ProtectionFeatures::default();
        assert_eq!(format!("{protection:?}"), format!("{expected:?}"));
    }

    /// The test config turns on `enabled` and `prot_sales_open` only:
    /// `cipher_grants_enabled` stays off, so the Cipher tests never post Prot
    #[test]
    fn test_config_turns_on_prot_and_prot_sales_only() {
        let settings = settings(&[include_str!("../Revolt.test.toml")]);

        let protection = &settings.features.boosts.protection;
        assert!(protection.enabled);
        assert!(!protection.cipher_grants_enabled);
        let expected = ProtectionFeatures {
            enabled: true,
            ..Default::default()
        };
        assert_eq!(format!("{protection:?}"), format!("{expected:?}"));
        assert!(!settings.features.boosts.enabled);

        let payments = &settings.features.payments;
        assert!(payments.prot_sales_open);
        assert_eq!(payments.prot_packs, default_packs());
        assert_eq!(
            payments.prot_blocked_countries,
            PROT_BLOCKED_COUNTRIES_DEFAULT.map(str::to_string).to_vec()
        );
    }

    /// The Prot default is the Cipher list plus Norway, Iceland and
    /// Liechtenstein, each code once; widening it must not touch Cipher's
    #[test]
    fn prot_blocked_countries_default_adds_the_rest_of_the_eea() {
        assert_eq!(
            PROT_BLOCKED_COUNTRIES_DEFAULT[..28],
            CIPHER_BLOCKED_COUNTRIES_DEFAULT
        );
        assert_eq!(PROT_BLOCKED_COUNTRIES_DEFAULT[28..], ["NO", "IS", "LI"]);
        let mut codes = PROT_BLOCKED_COUNTRIES_DEFAULT.to_vec();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), 31);
        for code in ["US", "CH", "UK", "EL"] {
            assert!(!codes.contains(&code), "{code} must not be listed");
        }

        // Cipher keeps the 27 EU member states and the UK, in code and in
        // the embedded Revolt.toml
        let cipher = [
            "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE",
            "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "GB",
        ]
        .map(str::to_string)
        .to_vec();
        assert_eq!(FeaturePayments::default().cipher_blocked_countries, cipher);
        assert_eq!(
            settings(&[]).features.payments.cipher_blocked_countries,
            cipher
        );
    }

    /// Prot keeps its own flags in both directions
    #[test]
    fn boosts_and_prot_switch_independently() {
        let boosts_on = settings(&["[features.boosts]\nenabled = true\n"]);
        assert!(boosts_on.features.boosts.enabled);
        assert_protection_defaults(&boosts_on.features.boosts.protection);

        let prot_on = settings(&["[features.boosts.protection]\nenabled = true\n"]);
        assert!(prot_on.features.boosts.protection.enabled);
        assert!(!prot_on.features.boosts.enabled);
        assert!(!prot_on.features.boosts.purchases_enabled);
        assert_eq!(prot_on.features.boosts.tier_thresholds, [2, 7, 14]);
    }

    /// An overrides file sets protection keys (the rest keep their defaults)
    /// and replaces the whole pack list
    #[test]
    fn overrides_set_the_prot_keys() {
        let overrides = r#"
[features.boosts.protection]
cipher_grants_enabled = true
channel_daily_cost = { 10 = 1, 25 = 2, 50 = 3, 100 = 4 }
warn_days = [2]
wallet_cap = 2500

[features.payments]
prot_sales_open = true
prot_packs = [{ id = "p7", cents = 700, prot = 750 }]
prot_blocked_countries = []
prot_shell_return_url = "https://example.test/prot/thanks/"
"#;
        let settings = settings(&[overrides]);

        let protection = &settings.features.boosts.protection;
        assert!(protection.cipher_grants_enabled);
        assert!(!protection.enabled);
        assert_eq!(
            protection.channel_daily_cost,
            ProtTierCosts {
                t10: 1,
                t25: 2,
                t50: 3,
                t100: 4,
            }
        );
        assert_eq!(
            protection.server_daily_cost,
            ProtectionFeatures::default().server_daily_cost
        );
        assert_eq!(protection.warn_days, [2]);
        assert_eq!(protection.wallet_cap, 2500);
        assert_eq!(protection.contribute_hold_hours, 72);

        let payments = &settings.features.payments;
        assert!(payments.prot_sales_open);
        assert_eq!(payments.prot_packs, [pack("p7", 700, 750)]);
        assert!(payments.prot_blocked_countries.is_empty());
        assert_eq!(
            payments.prot_shell_return_url,
            "https://example.test/prot/thanks/"
        );
        assert_eq!(
            payments.prot_success_url,
            "https://app.sloga.gg/settings?prot=success"
        );
        // The Cipher keys are untouched
        assert!(!payments.cipher_sales_open);
        assert_eq!(
            payments.cipher_blocked_countries,
            CIPHER_BLOCKED_COUNTRIES_DEFAULT
                .map(str::to_string)
                .to_vec()
        );
    }

    /// A cost table missing a tier fails the config instead of pricing that
    /// tier at zero; so does a pack missing a field
    #[test]
    fn partial_cost_tables_and_packs_fail_the_config() {
        let overlays = [
            "[features.boosts.protection]\nchannel_daily_cost = { 10 = 1 }\n",
            "[features.boosts.protection]\nserver_daily_cost = { 10 = 1, 25 = 2, 50 = 3 }\n",
            "[features.payments]\nprot_packs = [{ id = \"p7\", cents = 700 }]\n",
        ];
        for overlay in overlays {
            assert!(layered(&[overlay]).is_err(), "accepted: {overlay}");
        }
    }

    /// The documented env form (double underscores) reaches the nested keys,
    /// including a cost table given tier by tier
    #[test]
    fn environment_override_reaches_the_prot_keys() {
        // Each key is prefixed with REVOLT__FEATURES__
        let vars: HashMap<String, String> = [
            ("BOOSTS__PROTECTION__ENABLED", "true"),
            ("BOOSTS__PROTECTION__WALLET_CAP", "5000"),
            ("BOOSTS__PROTECTION__SERVER_DAILY_COST__10", "61"),
            ("BOOSTS__PROTECTION__SERVER_DAILY_COST__25", "136"),
            ("BOOSTS__PROTECTION__SERVER_DAILY_COST__50", "241"),
            ("BOOSTS__PROTECTION__SERVER_DAILY_COST__100", "421"),
            ("PAYMENTS__PROT_SALES_OPEN", "true"),
            ("PAYMENTS__PROT_EXACT_MAX_CENTS", "20000"),
            ("PAYMENTS__PROT_BLOCKED_COUNTRIES", "DE, FR"),
        ]
        .map(|(k, v)| (format!("REVOLT__FEATURES__{k}"), v.to_owned()))
        .into();

        let settings: Settings = Config::builder()
            .add_source(File::from_str(
                include_str!("../Revolt.toml"),
                FileFormat::Toml,
            ))
            .add_source(
                Environment::with_prefix("REVOLT")
                    .separator("__")
                    .source(Some(vars)),
            )
            .build()
            .expect("the config builds")
            .try_deserialize()
            .expect("the config deserializes");

        let protection = &settings.features.boosts.protection;
        assert!(protection.enabled);
        assert!(!protection.cipher_grants_enabled);
        assert_eq!(protection.wallet_cap, 5000);
        assert_eq!(
            protection.server_daily_cost,
            ProtTierCosts {
                t10: 61,
                t25: 136,
                t50: 241,
                t100: 421,
            }
        );
        assert_eq!(
            protection.channel_daily_cost,
            ProtectionFeatures::default().channel_daily_cost
        );

        let payments = &settings.features.payments;
        assert!(payments.prot_sales_open);
        assert_eq!(payments.prot_exact_max_cents, 20000);
        assert_eq!(payments.prot_exact_min_cents, 50);
        assert_eq!(payments.prot_blocked_countries, ["DE", "FR"]);
        assert_eq!(payments.prot_packs, default_packs());
        assert!(!settings.features.boosts.enabled);
    }
}
