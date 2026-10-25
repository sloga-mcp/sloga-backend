use revolt_config::{config, Settings};
use revolt_models::v0;
use revolt_payments::settings::{PaymentsSettings, ProtSalesSettings};
use revolt_result::Result;
use rocket::serde::json::Json;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use super::import::{api_url_is_https, ImportSource};

/// # hCaptcha Configuration
#[derive(Serialize, JsonSchema, Debug)]
pub struct CaptchaFeature {
    /// Whether captcha is enabled
    pub enabled: bool,
    /// Client key used for solving captcha
    pub key: String,
}

/// # Generic Service Configuration
#[derive(Serialize, JsonSchema, Debug)]
pub struct Feature {
    /// Whether the service is enabled
    pub enabled: bool,
    /// URL pointing to the service
    pub url: String,
}

/// # Information about a livekit node
#[derive(Serialize, JsonSchema, Debug)]
pub struct VoiceNode {
    pub name: String,
    pub lat: f64,
    pub lon: f64,
    pub public_url: String,
}

/// # Voice Server Configuration
#[derive(Serialize, JsonSchema, Debug)]
pub struct VoiceFeature {
    /// Whether voice is enabled
    pub enabled: bool,
    /// All livekit nodes
    pub nodes: Vec<VoiceNode>,
}

/// # Server Boost Configuration
#[derive(Serialize, JsonSchema, Debug)]
pub struct BoostsFeature {
    /// Whether server boosts are enabled
    pub enabled: bool,
    /// Whether boosts can be purchased (future billing; advertisement only)
    pub purchases_enabled: bool,
    /// Boosts required for tiers 1/2/3
    pub tier_thresholds: [u32; 3],
}

/// # Prot Configuration
#[derive(Serialize, JsonSchema, Debug, Clone)]
pub struct ProtFeature {
    /// features.boosts.protection.enabled
    pub enabled: bool,
    /// features.boosts.protection.self_serve_enabled
    pub self_serve_enabled: bool,
    /// ProtSalesSettings::checkout_open (false when either config fails to validate)
    pub sales_open: bool,
    /// ProtSalesSettings::grants_active
    pub cipher_grants_enabled: bool,
    pub packs: Vec<v0::ProtPackView>,
    pub exact_min_cents: i64,
    pub exact_max_cents: i64,
    pub wallet_cap: i64,
}

/// # Bot-Based Import Source
#[derive(Serialize, JsonSchema, Debug, PartialEq)]
pub struct ImportBotSourceFeature {
    /// Link on the source platform that adds the operator's import bot to
    /// a server
    pub add_bot_url: String,
}

/// # Import Sources Configuration
///
/// One key per import source that is ready on this node; a source that is
/// not ready is left out entirely.
#[derive(Serialize, JsonSchema, Debug, PartialEq)]
pub struct ImportSourcesFeature {
    /// Importing a server from Stoat
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stoat: Option<ImportBotSourceFeature>,
    /// Importing a server from Fluxer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fluxer: Option<ImportBotSourceFeature>,
}

/// Fluxer's add-bot link: the OAuth2 authorize route on its API (which
/// redirects to whichever web app Fluxer currently serves), asking for
/// Administrator (`permissions=8`) so the bot can see private channels and
/// the audit log. The route is appended to `api_url`'s own path, so a base
/// with a path prefix keeps it.
///
/// `None` unless `bot_id` is a non-empty run of ASCII digits (a snowflake)
/// and `api_url` is an absolute `https://` URL with a host and no
/// credentials, query or fragment (the link is public).
pub fn fluxer_add_bot_url(api_url: &str, bot_id: &str) -> Option<String> {
    if bot_id.is_empty() || !bot_id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    if !api_url_is_https(api_url) {
        return None;
    }
    let mut url = url::Url::parse(api_url.trim_end_matches('/')).ok()?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }

    url.path_segments_mut()
        .ok()?
        .pop_if_empty()
        .extend(["v1", "oauth2", "authorize"]);
    url.query_pairs_mut()
        .append_pair("client_id", bot_id)
        .append_pair("scope", "bot")
        .append_pair("permissions", "8");
    Some(url.into())
}

/// Which import sources to advertise. A source is advertised only when its
/// import can actually run (the same `ready()` the import routes check,
/// which includes an `https://` API URL) AND the client has everything it
/// needs to build the add-bot link; otherwise its key is left out.
pub fn import_sources_feature(config: &Settings) -> ImportSourcesFeature {
    let import = &config.api.import;
    let stoat = &import.stoat;
    let stoat_advertised =
        ImportSource::Stoat.ready(import) && !stoat.app_url.is_empty() && !stoat.bot_id.is_empty();

    let fluxer = &import.fluxer;
    let fluxer_url = if ImportSource::Fluxer.ready(import) {
        let url = fluxer_add_bot_url(&fluxer.api_url, &fluxer.bot_id);
        // Once per process: this runs on every `GET /`
        static WARNED: AtomicBool = AtomicBool::new(false);
        if url.is_none() && !WARNED.swap(true, Ordering::Relaxed) {
            log::warn!(
                "Fluxer import is ready but not advertised: bot_id must be digits only and \
                 api_url an https URL without credentials, query or fragment"
            );
        }
        url
    } else {
        None
    };

    ImportSourcesFeature {
        stoat: stoat_advertised.then(|| ImportBotSourceFeature {
            add_bot_url: format!(
                "{}/bot/{}",
                stoat.app_url.trim_end_matches('/'),
                stoat.bot_id
            ),
        }),
        fluxer: fluxer_url.map(|add_bot_url| ImportBotSourceFeature { add_bot_url }),
    }
}

/// What to advertise for Prot. The sale and grant flags come from the same
/// validated settings the engine uses, so a config the engine would refuse
/// is advertised closed: no packs, sales and grants off.
pub fn prot_feature_from(config: &Settings) -> ProtFeature {
    let protection = &config.features.boosts.protection;
    let Ok(prot) = ProtSalesSettings::from_config(config) else {
        return ProtFeature {
            enabled: protection.enabled,
            self_serve_enabled: protection.self_serve_enabled,
            sales_open: false,
            cipher_grants_enabled: false,
            packs: Vec::new(),
            exact_min_cents: config.features.payments.prot_exact_min_cents,
            exact_max_cents: config.features.payments.prot_exact_max_cents,
            wallet_cap: protection.wallet_cap,
        };
    };

    // Checkout also needs `[features.payments]` to validate and be enabled
    let sales_open = PaymentsSettings::from_config(config).is_ok_and(|s| prot.checkout_open(&s));

    ProtFeature {
        enabled: protection.enabled,
        self_serve_enabled: protection.self_serve_enabled,
        sales_open,
        cipher_grants_enabled: prot.grants_active(),
        packs: prot
            .packs
            .iter()
            .map(|pack| v0::ProtPackView {
                id: pack.id.clone(),
                cents: pack.cents,
                prot: pack.prot,
            })
            .collect(),
        exact_min_cents: prot.exact_min_cents,
        exact_max_cents: prot.exact_max_cents,
        wallet_cap: prot.wallet_cap,
    }
}

/// The Prot advert of this process: [`prot_feature_from`] once, on the first
/// `GET /`. The config is frozen into the process at first load, so the
/// answer cannot change, and validating both payment configs on every
/// request would log a bad key at error level each time.
pub fn prot_feature(config: &Settings) -> ProtFeature {
    static PROT_FEATURE: OnceLock<ProtFeature> = OnceLock::new();
    PROT_FEATURE
        .get_or_init(|| prot_feature_from(config))
        .clone()
}

/// # Feature Configuration
#[derive(Serialize, JsonSchema, Debug)]
pub struct RevoltFeatures {
    /// hCaptcha configuration
    pub captcha: CaptchaFeature,
    /// Whether email verification is enabled
    pub email: bool,
    /// Whether Google OAuth login is enabled
    pub oauth_google: bool,
    /// Whether Sign in with Apple login is enabled
    pub oauth_apple: bool,
    /// Whether Twitch channel linking is enabled
    pub oauth_twitch: bool,
    /// Whether YouTube channel linking is enabled
    pub oauth_youtube: bool,
    /// Whether Kick channel linking is enabled
    pub oauth_kick: bool,
    /// Whether importing a server from Discord is enabled
    pub import_discord: bool,
    /// When the optional sticker-import step is available, the Discord
    /// application id of the importer bot (the client builds the bot-invite
    /// URL from it). Absent when the bot upgrade is not configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import_discord_stickers: Option<String>,
    /// Import sources other than Discord that are ready on this node
    pub import_sources: ImportSourcesFeature,
    /// Whether remote desktop control during screen share is enabled
    pub remote_control: bool,
    /// Whether this server is invite only
    pub invite_only: bool,
    /// File server service configuration
    pub autumn: Feature,
    /// Proxy service configuration
    pub january: Feature,
    /// Voice server configuration
    pub livekit: VoiceFeature,
    /// Limits
    pub limits: LimitsConfig,
    /// Legal links
    pub legal_links: LegalLinks,
    /// Server boost configuration
    pub boosts: BoostsFeature,
    /// Prot configuration
    pub prot: ProtFeature,
}

/// # Limits For Users
#[derive(Serialize, JsonSchema, Debug)]
pub struct LimitsConfig {
    /// Global Limits
    pub global: GlobalLimits,
    /// New User Limits
    pub new_user: UserLimits,
    /// Default User Limits
    pub default: UserLimits,
    /// Limits for accounts with the upload perk (the default limits with the perk's upload sizes laid over them)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub perk: Option<UserLimits>,
}

/// # Legal links
#[derive(Serialize, JsonSchema, Debug)]
pub struct LegalLinks {
    /// Terms of Service URL
    pub terms_of_service: String,
    /// Privacy Policy URL
    pub privacy_policy: String,
    /// Guidelines URL
    pub guidelines: String,
}

/// # Global limits
#[derive(Serialize, JsonSchema, Debug)]
pub struct GlobalLimits {
    /// max group size
    group_size: i64,
    /// max message embeds
    message_embeds: i64,
    /// max replies
    message_replies: i64,
    /// max reactions per message
    message_reactions: i64,
    /// max server emoji
    server_emoji: i64,
    /// max server roles
    server_roles: i64,
    /// max server channels
    server_channels: i64,
    body_limit_size: i64,

    /// restrict server creation to these users.
    /// if blank, all users can create servers
    pub restrict_server_creation: Vec<String>,
    /// New user hours
    new_user_hours: i64,
}

/// # User Limits
#[derive(Serialize, JsonSchema, Debug)]
pub struct UserLimits {
    /// Max Outgoing Friend Requests
    pub outgoing_friend_requests: i64,
    /// Max Owned Bots
    pub bots: i64,
    /// Max message content length
    pub message_length: i64,
    /// max message attachments
    pub message_attachments: i64,
    /// max servers
    pub servers: i64,
    /// max audio quality
    pub voice_quality: i64,
    /// video streaming enabled
    pub video: bool,
    /// max video resolution (vertical, horizontal)
    pub video_resolution: [i64; 2],
    /// min/max aspect ratios
    pub video_aspect_ratio: [f64; 2],
    pub file_upload_size_limits: HashMap<String, usize>,
}

impl UserLimits {
    fn from_feature_limits(fl: revolt_config::FeaturesLimits) -> UserLimits {
        UserLimits {
            outgoing_friend_requests: fl.outgoing_friend_requests as i64,
            bots: fl.bots as i64,
            message_length: fl.message_length as i64,
            message_attachments: fl.message_attachments as i64,
            servers: fl.servers as i64,
            voice_quality: fl.voice_quality as i64,
            video: fl.video,
            video_resolution: [fl.video_resolution[0] as i64, fl.video_resolution[1] as i64],
            video_aspect_ratio: [
                fl.video_aspect_ratio[0] as f64,
                fl.video_aspect_ratio[1] as f64,
            ],
            file_upload_size_limits: fl.file_upload_size_limit,
        }
    }
}

/// # Build Information
#[derive(Serialize, JsonSchema, Debug)]
pub struct BuildInformation {
    /// Commit Hash
    pub commit_sha: String,
    /// Commit Timestamp
    pub commit_timestamp: String,
    /// Git Semver
    pub semver: String,
    /// Git Origin URL
    pub origin_url: String,
    /// Build Timestamp
    pub timestamp: String,
}

/// # Server Configuration
#[derive(Serialize, JsonSchema, Debug)]
pub struct RevoltConfig {
    /// Revolt API Version
    pub revolt: String,
    /// Features enabled on this Revolt node
    pub features: RevoltFeatures,
    /// WebSocket URL
    pub ws: String,
    /// URL pointing to the client serving this node
    pub app: String,
    /// Web Push VAPID public key
    pub vapid: String,
    /// Build information
    pub build: BuildInformation,
}

/// # Query Node
///
/// Fetch the server configuration for this Revolt instance.
#[openapi(tag = "Core")]
#[get("/")]
pub async fn root() -> Result<Json<RevoltConfig>> {
    let config = config().await;

    // Same overlay as `User::limits()`, so the advertised perk limits always
    // match the enforced ones.
    let perk = config.features.limits.perk.as_ref().map(|p| {
        let mut fl = config.features.limits.default.clone();
        for (tag, size) in &p.file_upload_size_limit {
            fl.file_upload_size_limit.insert(tag.clone(), *size);
        }

        UserLimits::from_feature_limits(fl)
    });

    // Built before the literal below, which moves fields out of `config`
    let prot = prot_feature(&config);

    Ok(Json(RevoltConfig {
        revolt: env!("CARGO_PKG_VERSION").to_string(),
        features: RevoltFeatures {
            captcha: CaptchaFeature {
                enabled: !config.api.security.captcha.hcaptcha_key.is_empty(),
                key: config.api.security.captcha.hcaptcha_sitekey.clone(),
            },
            email: !config.api.smtp.host.is_empty(),
            oauth_google: config.api.oauth.google.enabled,
            oauth_apple: config.api.oauth.apple.enabled,
            oauth_twitch: config.api.oauth.twitch.enabled,
            oauth_youtube: config.api.oauth.youtube.enabled,
            oauth_kick: config.api.oauth.kick.enabled,
            import_discord: config.api.import.discord.enabled,
            // The client_id is public by nature (it appears verbatim in the
            // bot-invite URL); the bot token never leaves the server.
            import_discord_stickers: config
                .api
                .import
                .discord
                .stickers_enabled()
                .then(|| config.api.import.discord.client_id.clone()),
            import_sources: import_sources_feature(&config),
            // Unlike the flags above (per-service config), this comes from
            // `features` — the real Features flags are otherwise not
            // surfaced in RevoltFeatures at all, so this is net-new
            // plumbing, not a mirror of an existing pattern.
            remote_control: config.features.remote_control,
            invite_only: config.api.registration.invite_only,
            autumn: Feature {
                enabled: !config.hosts.autumn.is_empty(),
                url: config.hosts.autumn.clone(),
            },
            january: Feature {
                enabled: !config.hosts.january.is_empty(),
                url: config.hosts.january.clone(),
            },
            livekit: VoiceFeature {
                enabled: !config.hosts.livekit.is_empty(),
                nodes: config
                    .api
                    .livekit
                    .nodes
                    .iter()
                    .filter(|(_, node)| !node.private)
                    .map(|(name, value)| VoiceNode {
                        name: name.clone(),
                        lat: value.lat,
                        lon: value.lon,
                        public_url: config
                            .hosts
                            .livekit
                            .get(name)
                            .expect("Missing corresponding host for voice node")
                            .clone(),
                    })
                    .collect(),
            },
            limits: LimitsConfig {
                global: GlobalLimits {
                    group_size: config.features.limits.global.group_size as i64,
                    message_embeds: config.features.limits.global.message_embeds as i64,
                    message_replies: config.features.limits.global.message_replies as i64,
                    message_reactions: config.features.limits.global.message_reactions as i64,
                    server_emoji: config.features.limits.global.server_emoji as i64,
                    server_roles: config.features.limits.global.server_roles as i64,
                    server_channels: config.features.limits.global.server_channels as i64,
                    body_limit_size: config.features.limits.global.body_limit_size as i64,
                    restrict_server_creation: config
                        .features
                        .limits
                        .global
                        .restrict_server_creation,
                    new_user_hours: config.features.limits.global.new_user_hours as i64,
                },
                new_user: UserLimits::from_feature_limits(config.features.limits.new_user),
                default: UserLimits::from_feature_limits(config.features.limits.default),
                perk,
            },
            legal_links: LegalLinks {
                terms_of_service: config.features.legal_links.terms_of_service,
                privacy_policy: config.features.legal_links.privacy_policy,
                guidelines: config.features.legal_links.guidelines,
            },
            boosts: BoostsFeature {
                enabled: config.features.boosts.enabled,
                purchases_enabled: config.features.boosts.purchases_enabled,
                tier_thresholds: config.features.boosts.tier_thresholds,
            },
            prot,
        },
        ws: config.hosts.events,
        app: config.hosts.app,
        vapid: config.pushd.vapid.public_key,
        build: BuildInformation {
            commit_sha: option_env!("VERGEN_GIT_SHA")
                .unwrap_or_else(|| "<failed to generate>")
                .to_string(),
            commit_timestamp: option_env!("VERGEN_GIT_COMMIT_TIMESTAMP")
                .unwrap_or_else(|| "<failed to generate>")
                .to_string(),
            semver: option_env!("VERGEN_GIT_SEMVER")
                .unwrap_or_else(|| "<failed to generate>")
                .to_string(),
            origin_url: option_env!("GIT_ORIGIN_URL")
                .unwrap_or_else(|| "<failed to generate>")
                .to_string(),
            timestamp: option_env!("VERGEN_BUILD_TIMESTAMP")
                .unwrap_or_else(|| "<failed to generate>")
                .to_string(),
        },
    }))
}

#[cfg(test)]
mod test {
    use crate::rocket;
    use rocket::http::Status;

    #[test]
    fn hello_world() {
        crate::util::test::rt().block_on(hello_world_case())
    }

    async fn hello_world_case() {
        let harness = crate::util::test::TestHarness::new().await;
        let response = harness.client.get("/").dispatch().await;
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    fn hello_world_concurrent() {
        crate::util::test::rt().block_on(hello_world_concurrent_case())
    }

    async fn hello_world_concurrent_case() {
        let harness = crate::util::test::TestHarness::new().await;
        let response = harness.client.get("/").dispatch().await;
        assert_eq!(response.status(), Status::Ok);
    }

    /// The node's own config with Stoat fully ready
    fn ready_settings() -> revolt_config::Settings {
        let mut config = crate::util::test::rt().block_on(revolt_config::config());
        let import = &mut config.api.import;
        import.challenge_secret = "secret".to_string();
        import.stoat.enabled = true;
        import.stoat.api_url = "https://api.stoat.chat".to_string();
        import.stoat.app_url = "https://stoat.chat".to_string();
        import.stoat.cdn_url = "https://cdn.stoatusercontent.com".to_string();
        import.stoat.bot_id = "01BOT".to_string();
        import.stoat.bot_token = "token".to_string();
        import.fluxer = import.stoat.clone();
        config
    }

    fn import_sources_json(config: &revolt_config::Settings) -> serde_json::Value {
        serde_json::to_value(super::import_sources_feature(config)).unwrap()
    }

    #[test]
    fn import_sources_advertises_stoat_when_ready() {
        let config = ready_settings();
        assert!(config.api.import.stoat_ready());
        // Fluxer is fully configured but stays out: `01BOT` is not a Fluxer
        // bot id, so no add-bot link can be built
        assert!(config.api.import.fluxer_ready());
        assert_eq!(
            import_sources_json(&config),
            serde_json::json!({ "stoat": { "add_bot_url": "https://stoat.chat/bot/01BOT" } })
        );

        let mut config = ready_settings();
        config.api.import.stoat.app_url = "https://stoat.chat//".to_string();
        assert_eq!(
            import_sources_json(&config),
            serde_json::json!({ "stoat": { "add_bot_url": "https://stoat.chat/bot/01BOT" } }),
            "trailing slashes on app_url are trimmed"
        );
    }

    #[test]
    fn import_sources_is_an_empty_object_when_dark() {
        type Darken = fn(&mut revolt_config::Settings);
        let cases: [(&str, Darken); 8] = [
            ("disabled", |c| c.api.import.stoat.enabled = false),
            ("no challenge secret", |c| {
                c.api.import.challenge_secret.clear()
            }),
            ("no bot token", |c| c.api.import.stoat.bot_token.clear()),
            ("no bot id", |c| c.api.import.stoat.bot_id.clear()),
            // Ready for the read path, but the client cannot build the link
            ("no app url", |c| c.api.import.stoat.app_url.clear()),
            // The client refuses plain HTTP, so the import could never run
            ("http api url", |c| {
                c.api.import.stoat.api_url = "http://api.stoat.chat".to_string()
            }),
            ("no api url", |c| c.api.import.stoat.api_url.clear()),
            ("api url without a scheme", |c| {
                c.api.import.stoat.api_url = "api.stoat.chat".to_string()
            }),
        ];
        for (name, darken) in cases {
            let mut config = ready_settings();
            darken(&mut config);
            assert_eq!(
                import_sources_json(&config),
                serde_json::json!({}),
                "stoat advertised with {name}"
            );
        }
    }

    /// `GET /` carries exactly what the builder produces for the node's
    /// config, under `features`
    #[test]
    fn root_serves_import_sources() {
        crate::util::test::rt().block_on(root_serves_import_sources_case())
    }

    async fn root_serves_import_sources_case() {
        let harness = crate::util::test::TestHarness::new().await;
        let response = harness.client.get("/").dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        let body: serde_json::Value =
            serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
        let config = revolt_config::config().await;
        let expected = import_sources_json(&config);
        assert!(expected.is_object());
        assert_eq!(body["features"]["import_sources"], expected);

        // The test node's Fluxer source is not ready, so `GET /` leaves it out
        assert!(!super::ImportSource::Fluxer.ready(&config.api.import));
        assert!(body["features"]["import_sources"].get("fluxer").is_none());
    }

    const FLUXER_BOT_ID: &str = "1560481642991071233";

    #[test]
    fn fluxer_add_bot_url_appends_the_authorize_route() {
        let expected = format!(
            "https://api.fluxer.app/v1/oauth2/authorize?client_id={FLUXER_BOT_ID}&scope=bot&permissions=8"
        );
        for api_url in [
            "https://api.fluxer.app",
            "https://api.fluxer.app/",
            "https://api.fluxer.app//",
        ] {
            assert_eq!(
                super::fluxer_add_bot_url(api_url, FLUXER_BOT_ID).as_deref(),
                Some(expected.as_str()),
                "{api_url}"
            );
        }

        // A path prefix on the base is kept, not replaced
        for api_url in ["https://x.test/api", "https://x.test/api/"] {
            assert_eq!(
                super::fluxer_add_bot_url(api_url, "42").as_deref(),
                Some("https://x.test/api/v1/oauth2/authorize?client_id=42&scope=bot&permissions=8"),
                "{api_url}"
            );
        }
    }

    #[test]
    fn fluxer_add_bot_url_rejects_bad_input() {
        for bot_id in [
            "",
            "01BOT",
            "123&scope=admin",
            "123#x",
            "123/../x",
            " 123",
            "123 ",
            "+123",
            "-123",
        ] {
            assert_eq!(
                super::fluxer_add_bot_url("https://api.fluxer.app", bot_id),
                None,
                "bot_id {bot_id:?}"
            );
        }

        for api_url in [
            "http://api.fluxer.app",
            "",
            "api.fluxer.app",
            "ftp://api.fluxer.app",
            "https://",
            "https://user:pw@api.fluxer.app",
            "https://user@api.fluxer.app",
            "https://api.fluxer.app/?x=1",
            "https://api.fluxer.app/#x",
        ] {
            assert_eq!(
                super::fluxer_add_bot_url(api_url, FLUXER_BOT_ID),
                None,
                "api_url {api_url:?}"
            );
        }
    }

    /// The node's own config with Fluxer configured the way the operator
    /// would: digit bot id, default `https://` API URL
    fn fluxer_ready_settings() -> revolt_config::Settings {
        let mut config = crate::util::test::rt().block_on(revolt_config::config());
        let import = &mut config.api.import;
        import.challenge_secret = "secret".to_string();
        import.fluxer.enabled = true;
        import.fluxer.api_url = "https://api.fluxer.app".to_string();
        import.fluxer.bot_id = FLUXER_BOT_ID.to_string();
        import.fluxer.bot_token = "token".to_string();
        config
    }

    #[test]
    fn import_sources_leaves_fluxer_out_when_not_ready() {
        type Darken = fn(&mut revolt_config::Settings);
        let cases: [(&str, Darken); 6] = [
            ("disabled", |c| c.api.import.fluxer.enabled = false),
            ("no bot token", |c| c.api.import.fluxer.bot_token.clear()),
            ("no challenge secret", |c| {
                c.api.import.challenge_secret.clear()
            }),
            ("http api url", |c| {
                c.api.import.fluxer.api_url = "http://api.fluxer.app".to_string()
            }),
            // Ready for the read path, but the link cannot be built
            ("non-digit bot id", |c| {
                c.api.import.fluxer.bot_id = "01BOT".to_string()
            }),
            ("credentials in api url", |c| {
                c.api.import.fluxer.api_url = "https://u:p@api.fluxer.app".to_string()
            }),
        ];
        for (name, darken) in cases {
            let mut config = fluxer_ready_settings();
            darken(&mut config);
            assert!(
                import_sources_json(&config).get("fluxer").is_none(),
                "fluxer advertised with {name}"
            );
        }
    }

    #[test]
    fn fluxer_advertised_when_ready() {
        let config = fluxer_ready_settings();
        assert!(config.api.import.fluxer_ready());
        assert!(super::ImportSource::Fluxer.ready(&config.api.import));

        assert_eq!(
            import_sources_json(&config)["fluxer"],
            serde_json::json!({
                "add_bot_url": "https://api.fluxer.app/v1/oauth2/authorize?client_id=1560481642991071233&scope=bot&permissions=8"
            })
        );
    }

    /// The node's own config with every Prot switch on and a valid sale
    /// config set explicitly, so a local override file can't change it
    fn prot_settings() -> revolt_config::Settings {
        let mut config = crate::util::test::rt().block_on(revolt_config::config());
        let payments = &mut config.features.payments;
        payments.enabled = true;
        payments.cipher_cap = 1000;
        payments.cipher_sales_close_at = String::new();
        payments.prot_sales_open = true;
        payments.prot_packs = vec![
            revolt_config::ProtPackConfig {
                id: "p5".to_string(),
                cents: 500,
                prot: 500,
            },
            revolt_config::ProtPackConfig {
                id: "p25".to_string(),
                cents: 2500,
                prot: 2600,
            },
        ];
        payments.prot_exact_min_cents = 50;
        payments.prot_exact_max_cents = 50000;
        payments.prot_blocked_countries = vec!["GB".to_string()];
        payments.prot_success_url = "https://app.sloga.gg/settings?prot=success".to_string();
        payments.prot_cancel_url = "https://app.sloga.gg/settings?prot=cancel".to_string();
        payments.prot_shell_return_url = "https://sloga.gg/prot/thanks/".to_string();

        let protection = &mut config.features.boosts.protection;
        protection.enabled = true;
        protection.self_serve_enabled = false;
        protection.cipher_grants_enabled = true;
        protection.wallet_cap = 100000;
        config
    }

    fn prot_json(config: &revolt_config::Settings) -> serde_json::Value {
        serde_json::to_value(super::prot_feature_from(config)).unwrap()
    }

    #[test]
    fn prot_feature_advertises_the_validated_config() {
        assert_eq!(
            prot_json(&prot_settings()),
            serde_json::json!({
                "enabled": true,
                "self_serve_enabled": false,
                "sales_open": true,
                "cipher_grants_enabled": true,
                "packs": [
                    { "id": "p5", "cents": 500, "prot": 500 },
                    { "id": "p25", "cents": 2500, "prot": 2600 },
                ],
                "exact_min_cents": 50,
                "exact_max_cents": 50000,
                "wallet_cap": 100000,
            })
        );

        let mut config = prot_settings();
        config.features.boosts.protection.self_serve_enabled = true;
        assert_eq!(prot_json(&config)["self_serve_enabled"], true);
    }

    #[test]
    fn prot_feature_sales_open_needs_every_switch() {
        type Darken = fn(&mut revolt_config::Settings);
        let cases: [(&str, Darken); 3] = [
            ("payments disabled", |c| c.features.payments.enabled = false),
            ("prot disabled", |c| {
                c.features.boosts.protection.enabled = false
            }),
            ("prot sales closed", |c| {
                c.features.payments.prot_sales_open = false
            }),
        ];
        for (name, darken) in cases {
            let mut config = prot_settings();
            darken(&mut config);
            assert_eq!(prot_json(&config)["sales_open"], false, "{name}");
        }

        // Grants need the master switch too, but not the sale
        let mut config = prot_settings();
        config.features.boosts.protection.enabled = false;
        assert_eq!(prot_json(&config)["cipher_grants_enabled"], false);
        let mut config = prot_settings();
        config.features.payments.enabled = false;
        config.features.payments.prot_sales_open = false;
        assert_eq!(prot_json(&config)["cipher_grants_enabled"], true);
        let mut config = prot_settings();
        config.features.boosts.protection.cipher_grants_enabled = false;
        assert_eq!(prot_json(&config)["cipher_grants_enabled"], false);
    }

    #[test]
    fn prot_feature_is_closed_when_the_prot_config_is_invalid() {
        type Break = fn(&mut revolt_config::Settings);
        let cases: [(&str, Break); 5] = [
            ("pack id without the p prefix", |c| {
                c.features.payments.prot_packs[0].id = "x5".to_string()
            }),
            ("duplicate pack id", |c| {
                c.features.payments.prot_packs[1].id = "p5".to_string()
            }),
            ("exact minimum below 50", |c| {
                c.features.payments.prot_exact_min_cents = 10
            }),
            ("zero wallet cap", |c| {
                c.features.boosts.protection.wallet_cap = 0
            }),
            ("plain http return url", |c| {
                c.features.payments.prot_success_url = "http://app.sloga.gg/".to_string()
            }),
        ];
        for (name, break_config) in cases {
            let mut config = prot_settings();
            break_config(&mut config);
            let json = prot_json(&config);
            assert_eq!(json["sales_open"], false, "{name}");
            assert_eq!(json["cipher_grants_enabled"], false, "{name}");
            assert_eq!(json["packs"], serde_json::json!([]), "{name}");
            // The master switch is advertised as configured, so the wallet
            // page still shows the balance
            assert_eq!(json["enabled"], true, "{name}");
        }
    }

    #[test]
    fn prot_feature_sales_closed_when_the_payments_config_is_invalid() {
        let mut config = prot_settings();
        config.features.payments.cipher_cap = 0;
        let json = prot_json(&config);
        assert_eq!(json["sales_open"], false);
        // Grants and the pack list don't depend on `[features.payments]`
        // validating
        assert_eq!(json["cipher_grants_enabled"], true);
        assert_eq!(json["packs"].as_array().map(Vec::len), Some(2));
    }

    /// The route's advert is built once per process: a later call with a
    /// config that no longer validates still answers the first advert (and
    /// so validates and logs nothing again)
    #[test]
    fn prot_feature_is_built_once_per_process() {
        let config = crate::util::test::rt().block_on(revolt_config::config());
        let first = serde_json::to_value(super::prot_feature(&config)).unwrap();
        assert_eq!(first, prot_json(&config));
        assert_eq!(first["sales_open"], true);

        let mut invalid = config.clone();
        invalid.features.payments.prot_exact_min_cents = 10;
        assert_eq!(prot_json(&invalid)["sales_open"], false);
        assert_eq!(
            serde_json::to_value(super::prot_feature(&invalid)).unwrap(),
            first
        );
    }

    /// `GET /` carries exactly what the builder produces for the node's
    /// config, under `features.prot`, and leaves the boosts advert alone
    #[test]
    fn root_serves_prot_feature() {
        crate::util::test::rt().block_on(root_serves_prot_feature_case())
    }

    async fn root_serves_prot_feature_case() {
        let harness = crate::util::test::TestHarness::new().await;
        let response = harness.client.get("/").dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        let body: serde_json::Value =
            serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
        let config = revolt_config::config().await;
        assert_eq!(body["features"]["prot"], prot_json(&config));

        // Revolt.test.toml turns Prot and its sale on, grants stay off
        assert_eq!(body["features"]["prot"]["enabled"], true);
        assert_eq!(body["features"]["prot"]["sales_open"], true);
        assert_eq!(body["features"]["prot"]["cipher_grants_enabled"], false);

        assert_eq!(
            body["features"]["boosts"]["purchases_enabled"],
            config.features.boosts.purchases_enabled
        );
    }
}
