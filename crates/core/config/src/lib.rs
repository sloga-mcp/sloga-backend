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
pub use sentry_anyhow::capture_anyhow;

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

/// Import an existing community into Sloga.
///
/// The primary path (server templates) hits a PUBLIC, unauthenticated
/// Discord endpoint (`GET /guilds/templates/{code}`), so it needs no
/// credentials at all — `enabled` is the whole config. The optional bot
/// upgrade (emojis/icon/banner) adds client_id/client_secret/bot_token
/// later; those belong in Revolt.overrides.toml, never here.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct ApiImportDiscord {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct ApiImport {
    #[serde(default)]
    pub discord: ApiImportDiscord,
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
}

#[derive(Deserialize, Debug, Clone)]
pub struct FilesLimit {
    pub min_file_size: usize,
    pub min_resolution: [usize; 2],
    pub max_mega_pixels: usize,
    pub max_pixel_side: usize,
}

#[derive(Deserialize, Debug, Clone)]
pub struct FilesS3 {
    pub endpoint: String,
    pub path_style_buckets: bool,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub default_bucket: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Files {
    pub encryption_key: String,
    pub webp_quality: f32,
    pub blocked_mime_types: Vec<String>,
    pub clamd_host: String,
    pub scan_mime_types: Vec<String>,

    pub limit: FilesLimit,
    pub preview: HashMap<String, [usize; 2]>,
    pub s3: FilesS3,
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

#[derive(Deserialize, Debug, Clone)]
pub struct FeaturesLimitsCollection {
    pub global: GlobalLimits,

    pub new_user: FeaturesLimits,
    pub default: FeaturesLimits,

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
        }
    }
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

    /// Optional server id that every newly-onboarded user is automatically
    /// added to (a "Welcome" / landing-spot server). Empty/unset disables the
    /// behaviour. Existing users are unaffected (backfill separately).
    #[serde(default)]
    pub welcome_server: Option<String>,

    /// Server-boost feature (ships dark; see BoostFeatures docs for the
    /// flip-requires-restart caveat)
    #[serde(default)]
    pub boosts: BoostFeatures,

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
