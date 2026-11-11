use revolt_config::{config, ProtectionFeatures, Settings};
use revolt_database::{ProtTankRules, PROT_SLOT_TIERS};
use revolt_models::v0;
use revolt_payments::settings::ProtStoreSettings;
use revolt_payments::settings::{PaymentsSettings, ProtSalesSettings};
use revolt_result::Result;
use rocket::serde::json::Json;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
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
    /// Tank rules the client previews prices with (the server computes every price)
    pub tank: ProtTankFeature,
    /// In-app Prot packs (S6). Per-user preview access is NOT here (GET /payments/prot/@me store_preview)
    pub store: ProtStoreFeature,
}

/// # In-App Prot Packs
///
/// `[features.payments] prot_store_*` as validated by `ProtStoreSettings`. A
/// config the engine would refuse is advertised closed with no products.
#[derive(Serialize, JsonSchema, Debug, Clone)]
pub struct ProtStoreFeature {
    /// prot_store_apple_open AND App Store credentials configured
    pub apple_open: bool,
    /// prot_store_play_open AND Play credentials configured
    pub play_open: bool,
    pub products: Vec<v0::ProtStoreProductView>,
    pub us_web_link: bool,
}

/// # Prot Tank Rules
///
/// `[features.boosts.protection]` as validated by `ProtTankRules`. A config
/// the engine would refuse is advertised as zeros and false with no tier
/// costs, so `min_contribution: 0` makes the client hide contribute.
#[derive(Serialize, JsonSchema, Debug, Clone)]
pub struct ProtTankFeature {
    /// Prot per day for a protected channel, keyed by slot tier ("10".."100")
    pub channel_daily_cost: BTreeMap<String, i64>,
    /// Smallest contribution or pledge, in Prot
    pub min_contribution: i64,
    pub min_launch_goal_days: u32,
    pub max_launch_goal_days: u32,
    pub launch_goal_deadline_days: u32,
    pub withdraw_cutoff_hours: u32,
    /// Prot bought in the last this many hours can't go into a tank or a pledge
    pub contribute_hold_hours: u32,
    pub grace_days: u32,
    pub freeze_days: u32,
    /// Whether a channel whose tank stays empty past its freeze is deleted
    pub deletion_enabled: bool,
}

/// The tank rules to advertise, from the same `ProtTankRules::from_config`
/// the engine validates with
pub fn prot_tank_feature_from(protection: &ProtectionFeatures) -> ProtTankFeature {
    let Ok(rules) = ProtTankRules::from_config(protection) else {
        return ProtTankFeature {
            channel_daily_cost: BTreeMap::new(),
            min_contribution: 0,
            min_launch_goal_days: 0,
            max_launch_goal_days: 0,
            launch_goal_deadline_days: 0,
            withdraw_cutoff_hours: 0,
            contribute_hold_hours: 0,
            grace_days: 0,
            freeze_days: 0,
            deletion_enabled: false,
        };
    };

    ProtTankFeature {
        channel_daily_cost: PROT_SLOT_TIERS
            .iter()
            .filter_map(|&slots| Some((slots.to_string(), rules.daily_cost(slots)?)))
            .collect(),
        min_contribution: rules.min_contribution,
        min_launch_goal_days: rules.min_launch_goal_days,
        max_launch_goal_days: rules.max_launch_goal_days,
        launch_goal_deadline_days: rules.launch_goal_deadline_days,
        withdraw_cutoff_hours: rules.withdraw_cutoff_hours,
        contribute_hold_hours: rules.contribute_hold_hours,
        grace_days: rules.grace_days,
        freeze_days: rules.freeze_days,
        deletion_enabled: rules.deletion_enabled,
    }
}

/// The in-app Prot packs to advertise, from the same
/// `ProtStoreSettings::from_config` the engine validates with. A store is
/// open only while payments and Prot are both enabled (R54; the intent
/// route refuses otherwise), with its flag on AND its credentials in the
/// config (Play also needs the Pub/Sub subscription its intents require):
/// the advert can't see the managed store clients, and in production those
/// are built from the same credentials. Every configured product is listed
/// even while both stores are closed, since preview accounts buy them.
pub fn prot_store_feature_from(config: &Settings) -> ProtStoreFeature {
    let Ok(st) = ProtStoreSettings::from_config(config) else {
        return ProtStoreFeature {
            apple_open: false,
            play_open: false,
            products: Vec::new(),
            us_web_link: false,
        };
    };

    // The intent route's first gates, from the same validated settings: a
    // config that fails either is a 500 there, so it is closed here too
    let selling = PaymentsSettings::from_config(config).is_ok_and(|s| s.enabled)
        && ProtSalesSettings::from_config(config).is_ok_and(|ps| ps.enabled);

    ProtStoreFeature {
        apple_open: selling && st.apple_open && st.apple.is_some(),
        play_open: selling
            && st.play_open
            && st
                .play
                .as_ref()
                .is_some_and(|play| !play.pubsub_subscription.is_empty()),
        products: st
            .products
            .iter()
            .map(|product| v0::ProtStoreProductView {
                store: product.store,
                product_id: product.product_id.clone(),
                prot: product.prot,
            })
            .collect(),
        us_web_link: st.us_web_link,
    }
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
    // Independent of the sale config: a broken pack list still advertises
    // the tank rules, and a broken tank config the sale
    let tank = prot_tank_feature_from(protection);
    // Independent of both: the store packs validate on their own
    let store = prot_store_feature_from(config);
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
            tank,
            store,
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
        tank,
        store,
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

/// # Protected Channels Configuration
#[derive(Serialize, JsonSchema, Debug)]
pub struct ProtectedChannelsFeature {
    /// Whether protected channels can grow (grants, protect, seating, adds).
    /// The effective value: true only when E2EE is enabled as well, since
    /// the text plane needs the E2EE identity directory
    pub enabled: bool,
    /// Device cap used when a channel's entitlement sets none (0 = unlimited)
    pub default_device_cap: u32,
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
    /// Protected channels configuration
    pub protected_channels: ProtectedChannelsFeature,
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
            // The effective flag (design 7.1): growth also needs E2EE, so the
            // advert never offers protecting a channel the gates would refuse
            protected_channels: ProtectedChannelsFeature {
                enabled: config.features.e2ee_enabled && config.features.protected_channels.enabled,
                default_device_cap: config.features.protected_channels.default_device_cap,
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

    /// Device cap set by every advert case, distinct from the default (5) so
    /// the test proves the configured value is the one advertised
    const ADVERT_DEVICE_CAP: u32 = 7;

    /// Sets both flags (and the device cap) explicitly, then fetches the root
    /// and checks the protected channels advert. Every case is its own
    /// `#[test]`: `overwrite_config` runs once per process (nextest)
    async fn protected_channels_advert_case(e2ee: bool, enabled: bool, advertised: bool) {
        revolt_config::overwrite_config(|settings| {
            settings.features.e2ee_enabled = e2ee;
            settings.features.protected_channels.enabled = enabled;
            settings.features.protected_channels.default_device_cap = ADVERT_DEVICE_CAP;
        })
        .await;

        let harness = crate::util::test::TestHarness::new().await;
        let response = harness.client.get("/").dispatch().await;
        assert_eq!(response.status(), Status::Ok);

        // Raw JSON so the assertions cover the wire shape, not the typed struct
        let body: serde_json::Value =
            serde_json::from_str(&response.into_string().await.expect("body")).expect("json");
        let advert = body["features"]["protected_channels"]
            .as_object()
            .expect("protected_channels object");

        assert_eq!(advert.len(), 2, "advert fields: {advert:?}");
        assert_eq!(advert["enabled"].as_bool(), Some(advertised));
        assert_eq!(
            advert["default_device_cap"].as_u64(),
            Some(ADVERT_DEVICE_CAP as u64)
        );
    }

    #[test]
    fn protected_channels_advert_with_e2ee_on_and_enabled_on() {
        crate::util::test::rt().block_on(protected_channels_advert_case(true, true, true))
    }

    #[test]
    fn protected_channels_advert_with_e2ee_on_and_enabled_off() {
        crate::util::test::rt().block_on(protected_channels_advert_case(true, false, false))
    }

    #[test]
    fn protected_channels_advert_with_e2ee_off_and_enabled_on() {
        crate::util::test::rt().block_on(protected_channels_advert_case(false, true, false))
    }

    #[test]
    fn protected_channels_advert_with_e2ee_off_and_enabled_off() {
        crate::util::test::rt().block_on(protected_channels_advert_case(false, false, false))
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
                "tank": {
                    "channel_daily_cost": { "10": 40, "25": 90, "50": 160, "100": 280 },
                    "min_contribution": 50,
                    "min_launch_goal_days": 30,
                    "max_launch_goal_days": 365,
                    "launch_goal_deadline_days": 30,
                    "withdraw_cutoff_hours": 48,
                    "contribute_hold_hours": 72,
                    "grace_days": 5,
                    "freeze_days": 25,
                    "deletion_enabled": false,
                },
                "store": {
                    "apple_open": false,
                    "play_open": false,
                    "products": [
                        { "store": "apple", "product_id": "gg.sloga.prot.p5", "prot": 500 },
                        { "store": "apple", "product_id": "gg.sloga.prot.p10", "prot": 1000 },
                        { "store": "apple", "product_id": "gg.sloga.prot.p25", "prot": 2600 },
                        { "store": "apple", "product_id": "gg.sloga.prot.p50", "prot": 5300 },
                        { "store": "apple", "product_id": "gg.sloga.prot.p100", "prot": 11000 },
                        { "store": "play", "product_id": "gg.sloga.prot.p5", "prot": 500 },
                        { "store": "play", "product_id": "gg.sloga.prot.p10", "prot": 1000 },
                        { "store": "play", "product_id": "gg.sloga.prot.p25", "prot": 2600 },
                        { "store": "play", "product_id": "gg.sloga.prot.p50", "prot": 5300 },
                        { "store": "play", "product_id": "gg.sloga.prot.p100", "prot": 11000 },
                    ],
                    "us_web_link": false,
                },
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

    /// `prot_settings()` with every advertised tank key set explicitly, each
    /// different from its default, so the advert is proved to carry the
    /// configured values
    fn prot_tank_settings() -> revolt_config::Settings {
        let mut config = prot_settings();
        let protection = &mut config.features.boosts.protection;
        protection.channel_daily_cost = revolt_config::ProtTierCosts {
            t10: 41,
            t25: 91,
            t50: 161,
            t100: 281,
        };
        protection.grace_days = 4;
        protection.freeze_days = 20;
        protection.final_warning_day = 15;
        protection.warn_days = vec![5, 2];
        protection.min_reactivation_days = 2;
        protection.launch_goal_deadline_days = 21;
        protection.launch_window_days = 5;
        protection.launch_seat_window_days = 5;
        protection.min_contribution = 75;
        protection.min_launch_goal_days = 14;
        protection.max_launch_goal_days = 180;
        protection.withdraw_cutoff_hours = 36;
        protection.contribute_hold_hours = 48;
        protection.deletion_enabled = true;
        config
    }

    fn prot_tank_json() -> serde_json::Value {
        serde_json::json!({
            "channel_daily_cost": { "10": 41, "25": 91, "50": 161, "100": 281 },
            "min_contribution": 75,
            "min_launch_goal_days": 14,
            "max_launch_goal_days": 180,
            "launch_goal_deadline_days": 21,
            "withdraw_cutoff_hours": 36,
            "contribute_hold_hours": 48,
            "grace_days": 4,
            "freeze_days": 20,
            "deletion_enabled": true,
        })
    }

    /// The tank rules ride in both of the builder's literals: beside a valid
    /// sale and beside a sale config that fails to validate
    #[test]
    fn prot_feature_advertises_the_tank_rules() {
        assert_eq!(prot_json(&prot_tank_settings())["tank"], prot_tank_json());

        let mut config = prot_tank_settings();
        config.features.payments.prot_exact_min_cents = 10;
        let json = prot_json(&config);
        assert_eq!(json["packs"], serde_json::json!([]));
        assert_eq!(json["tank"], prot_tank_json());
    }

    /// A tank config the engine would refuse is advertised as zeros and false
    /// with no tier costs, and leaves the sale advert alone
    #[test]
    fn prot_feature_tank_is_zeroed_when_the_tank_config_is_invalid() {
        type Break = fn(&mut revolt_config::Settings);
        let cases: [(&str, Break); 6] = [
            ("tier costs not increasing", |c| {
                c.features.boosts.protection.channel_daily_cost.t25 = 41
            }),
            ("zero grace days", |c| {
                c.features.boosts.protection.grace_days = 0
            }),
            ("final warning after the freeze", |c| {
                c.features.boosts.protection.final_warning_day = 24
            }),
            ("zero minimum contribution", |c| {
                c.features.boosts.protection.min_contribution = 0
            }),
            ("launch goal over ten years", |c| {
                c.features.boosts.protection.max_launch_goal_days = 3651
            }),
            ("withdraw cutoff past the goal deadline", |c| {
                c.features.boosts.protection.withdraw_cutoff_hours = 21 * 24
            }),
        ];
        for (name, break_config) in cases {
            let mut config = prot_tank_settings();
            break_config(&mut config);
            let json = prot_json(&config);
            assert_eq!(
                json["tank"],
                serde_json::json!({
                    "channel_daily_cost": {},
                    "min_contribution": 0,
                    "min_launch_goal_days": 0,
                    "max_launch_goal_days": 0,
                    "launch_goal_deadline_days": 0,
                    "withdraw_cutoff_hours": 0,
                    "contribute_hold_hours": 0,
                    "grace_days": 0,
                    "freeze_days": 0,
                    "deletion_enabled": false,
                }),
                "{name}"
            );
            assert_eq!(json["sales_open"], true, "{name}");
            assert_eq!(json["packs"].as_array().map(Vec::len), Some(2), "{name}");
        }
    }

    /// `GET /` carries the tank rules of the node's config, and the test
    /// node's tank config validates (the S5b tests rely on it)
    #[test]
    fn root_serves_the_prot_tank_rules() {
        crate::util::test::rt().block_on(root_serves_the_prot_tank_rules_case())
    }

    async fn root_serves_the_prot_tank_rules_case() {
        let harness = crate::util::test::TestHarness::new().await;
        let response = harness.client.get("/").dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        let body: serde_json::Value =
            serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
        let config = revolt_config::config().await;
        let tank = &body["features"]["prot"]["tank"];
        assert_eq!(
            *tank,
            serde_json::to_value(super::prot_tank_feature_from(
                &config.features.boosts.protection
            ))
            .unwrap()
        );
        assert!(tank["min_contribution"].as_i64() >= Some(1), "{}", tank);
        assert_eq!(
            tank["channel_daily_cost"]
                .as_object()
                .map(serde_json::Map::len),
            Some(4)
        );
    }

    /// `prot_settings()` with both stores open, the US web link on, the
    /// default product table, and App Store and Play credentials plus the
    /// Pub/Sub subscription, all set explicitly so a local override file
    /// can't change them. The keys are placeholders: the advert only checks
    /// that they are present
    fn prot_store_settings() -> revolt_config::Settings {
        let mut config = prot_settings();
        let defaults = revolt_config::FeaturePayments::default();
        let payments = &mut config.features.payments;
        payments.prot_store_apple_open = true;
        payments.prot_store_play_open = true;
        payments.prot_store_products = defaults.prot_store_products;
        payments.prot_store_preview_user_ids = Vec::new();
        payments.prot_store_test_user_ids = Vec::new();
        payments.prot_store_test_max_prot = defaults.prot_store_test_max_prot;
        payments.prot_store_us_web_link = true;
        payments.ops_alert_email = String::new();
        config.api.appstore = revolt_config::ApiAppStore {
            issuer_id: "issuer".to_string(),
            key_id: "KEYID".to_string(),
            private_key: "placeholder".to_string(),
            ..Default::default()
        };
        config.api.googleplay = revolt_config::ApiGooglePlay {
            client_email: "rtdn@sloga-test.iam.gserviceaccount.com".to_string(),
            private_key: "placeholder".to_string(),
            pubsub_subscription: "projects/sloga-test/subscriptions/play-rtdn".to_string(),
            ..Default::default()
        };
        config
    }

    fn store_product(
        store: &str,
        product_id: &str,
        prot: i64,
    ) -> revolt_config::ProtStoreProductConfig {
        revolt_config::ProtStoreProductConfig {
            store: store.to_string(),
            product_id: product_id.to_string(),
            prot,
        }
    }

    /// The default product table (prot-s6-contracts section 4): 5 Apple
    /// rows, then the same 5 on Play
    fn default_store_products_json() -> serde_json::Value {
        serde_json::json!([
            { "store": "apple", "product_id": "gg.sloga.prot.p5", "prot": 500 },
            { "store": "apple", "product_id": "gg.sloga.prot.p10", "prot": 1000 },
            { "store": "apple", "product_id": "gg.sloga.prot.p25", "prot": 2600 },
            { "store": "apple", "product_id": "gg.sloga.prot.p50", "prot": 5300 },
            { "store": "apple", "product_id": "gg.sloga.prot.p100", "prot": 11000 },
            { "store": "play", "product_id": "gg.sloga.prot.p5", "prot": 500 },
            { "store": "play", "product_id": "gg.sloga.prot.p10", "prot": 1000 },
            { "store": "play", "product_id": "gg.sloga.prot.p25", "prot": 2600 },
            { "store": "play", "product_id": "gg.sloga.prot.p50", "prot": 5300 },
            { "store": "play", "product_id": "gg.sloga.prot.p100", "prot": 11000 },
        ])
    }

    /// A store is advertised open only with its flag on AND its credentials
    /// in the config, and Play only with the Pub/Sub subscription as well
    /// (its intents refuse without one). Closing one store leaves the other
    /// and the product list alone
    #[test]
    fn store_advert_is_closed_without_credentials() {
        assert_eq!(
            prot_json(&prot_store_settings())["store"],
            serde_json::json!({
                "apple_open": true,
                "play_open": true,
                "products": default_store_products_json(),
                "us_web_link": true,
            })
        );

        type Darken = fn(&mut revolt_config::Settings);
        let apple: [(&str, Darken); 4] = [
            ("no issuer id", |c| c.api.appstore.issuer_id.clear()),
            ("no key id", |c| c.api.appstore.key_id.clear()),
            ("no private key", |c| c.api.appstore.private_key.clear()),
            ("apple closed", |c| {
                c.features.payments.prot_store_apple_open = false
            }),
        ];
        for (name, darken) in apple {
            let mut config = prot_store_settings();
            darken(&mut config);
            let json = prot_json(&config);
            assert_eq!(json["store"]["apple_open"], false, "{name}");
            assert_eq!(json["store"]["play_open"], true, "{name}");
            assert_eq!(
                json["store"]["products"],
                default_store_products_json(),
                "{name}"
            );
        }

        let play: [(&str, Darken); 4] = [
            ("no client email", |c| c.api.googleplay.client_email.clear()),
            ("no private key", |c| c.api.googleplay.private_key.clear()),
            ("no Pub/Sub subscription", |c| {
                c.api.googleplay.pubsub_subscription.clear()
            }),
            ("play closed", |c| {
                c.features.payments.prot_store_play_open = false
            }),
        ];
        for (name, darken) in play {
            let mut config = prot_store_settings();
            darken(&mut config);
            let json = prot_json(&config);
            assert_eq!(json["store"]["play_open"], false, "{name}");
            assert_eq!(json["store"]["apple_open"], true, "{name}");
            assert_eq!(
                json["store"]["products"],
                default_store_products_json(),
                "{name}"
            );
        }

        // Both flags on (as Revolt.test.toml has them) and no credentials
        // at all: both closed, the products still listed
        let mut config = prot_store_settings();
        config.api.appstore = revolt_config::ApiAppStore::default();
        config.api.googleplay = revolt_config::ApiGooglePlay::default();
        assert_eq!(
            prot_json(&config)["store"],
            serde_json::json!({
                "apple_open": false,
                "play_open": false,
                "products": default_store_products_json(),
                "us_web_link": true,
            })
        );
    }

    /// The products are the configured rows in config order, listed whether
    /// or not a store is open (preview accounts buy them), and the US web
    /// link flag is carried as configured
    #[test]
    fn store_advert_lists_the_products() {
        let mut config = prot_store_settings();
        config.features.payments.prot_store_products = vec![
            store_product("play", "gg.sloga.prot.p10", 1000),
            store_product("apple", "gg.sloga.prot.x_1", 7),
            store_product("play", "gg.sloga.prot.x_1", 9),
        ];
        let products = serde_json::json!([
            { "store": "play", "product_id": "gg.sloga.prot.p10", "prot": 1000 },
            { "store": "apple", "product_id": "gg.sloga.prot.x_1", "prot": 7 },
            { "store": "play", "product_id": "gg.sloga.prot.x_1", "prot": 9 },
        ]);
        assert_eq!(
            prot_json(&config)["store"],
            serde_json::json!({
                "apple_open": true,
                "play_open": true,
                "products": products,
                "us_web_link": true,
            })
        );

        let payments = &mut config.features.payments;
        payments.prot_store_apple_open = false;
        payments.prot_store_play_open = false;
        payments.prot_store_us_web_link = false;
        assert_eq!(
            prot_json(&config)["store"],
            serde_json::json!({
                "apple_open": false,
                "play_open": false,
                "products": products,
                "us_web_link": false,
            })
        );

        // An empty table is valid: nothing listed, the stores as configured
        let mut config = prot_store_settings();
        config.features.payments.prot_store_products = Vec::new();
        assert_eq!(
            prot_json(&config)["store"],
            serde_json::json!({
                "apple_open": true,
                "play_open": true,
                "products": [],
                "us_web_link": true,
            })
        );
    }

    /// A store config the engine would refuse is advertised closed with no
    /// products and no web link, however the flags and credentials are set,
    /// and leaves the rest of the Prot advert alone
    #[test]
    fn store_advert_is_closed_when_the_store_config_is_invalid() {
        type Break = fn(&mut revolt_config::Settings);
        let cases: [(&str, Break); 9] = [
            ("zero-Prot product", |c| {
                c.features.payments.prot_store_products[0].prot = 0
            }),
            ("duplicate product", |c| {
                c.features.payments.prot_store_products[1].product_id =
                    "gg.sloga.prot.p5".to_string()
            }),
            ("unknown store", |c| {
                c.features.payments.prot_store_products[0].store = "steam".to_string()
            }),
            ("product id with a dash", |c| {
                c.features.payments.prot_store_products[0].product_id =
                    "gg-sloga-prot-p5".to_string()
            }),
            ("preview id that is not a user id", |c| {
                c.features.payments.prot_store_preview_user_ids = vec!["01ABC-".to_string()]
            }),
            ("negative tester cap", |c| {
                c.features.payments.prot_store_test_max_prot = -1
            }),
            ("alert mailbox without an @", |c| {
                c.features.payments.ops_alert_email = "ops".to_string()
            }),
            ("unknown App Store environment", |c| {
                c.api.appstore.environment = "Xcode".to_string()
            }),
            ("root pin that is not a SHA-256", |c| {
                c.api.appstore.root_ca_g3_sha256 = "abc".to_string()
            }),
        ];
        let valid = prot_json(&prot_store_settings());
        for (name, break_config) in cases {
            let mut config = prot_store_settings();
            break_config(&mut config);
            let json = prot_json(&config);
            assert_eq!(
                json["store"],
                serde_json::json!({
                    "apple_open": false,
                    "play_open": false,
                    "products": [],
                    "us_web_link": false,
                }),
                "{name}"
            );
            assert_eq!(json["sales_open"], true, "{name}");
            assert_eq!(json["packs"], valid["packs"], "{name}");
            assert_eq!(json["tank"], valid["tank"], "{name}");
        }
    }

    /// Both stores are advertised closed unless payments and Prot are both
    /// enabled and their configs validate, the intent route's first gates
    /// (R54); the products and the web link stay as configured, in both of
    /// the builder's literals
    #[test]
    fn store_advert_is_closed_while_payments_or_prot_are_off() {
        type Darken = fn(&mut revolt_config::Settings);
        let cases: [(&str, Darken); 4] = [
            ("payments off", |c| c.features.payments.enabled = false),
            ("Prot off", |c| c.features.boosts.protection.enabled = false),
            ("payments config invalid", |c| {
                c.features.payments.cipher_cap = 0
            }),
            ("Prot sale config invalid", |c| {
                c.features.payments.prot_exact_min_cents = 10
            }),
        ];
        for (name, darken) in cases {
            let mut config = prot_store_settings();
            darken(&mut config);
            assert_eq!(
                prot_json(&config)["store"],
                serde_json::json!({
                    "apple_open": false,
                    "play_open": false,
                    "products": default_store_products_json(),
                    "us_web_link": true,
                }),
                "{name}"
            );
        }

        // Prot's own sale switch is not a store gate: both stay open
        let mut config = prot_store_settings();
        config.features.payments.prot_sales_open = false;
        let store = &prot_json(&config)["store"];
        assert_eq!(store["apple_open"], true);
        assert_eq!(store["play_open"], true);
    }

    /// `GET /` carries the store advert of the node's config. The test node
    /// turns both store flags on but has no store credentials, so both
    /// stores are advertised closed with the default products listed
    #[test]
    fn root_serves_the_store_advert() {
        crate::util::test::rt().block_on(root_serves_the_store_advert_case())
    }

    async fn root_serves_the_store_advert_case() {
        let harness = crate::util::test::TestHarness::new().await;
        let response = harness.client.get("/").dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        let body: serde_json::Value =
            serde_json::from_str(&response.into_string().await.unwrap()).unwrap();
        let config = revolt_config::config().await;
        let store = &body["features"]["prot"]["store"];
        assert_eq!(
            *store,
            serde_json::to_value(super::prot_store_feature_from(&config)).unwrap()
        );
        assert!(config.features.payments.prot_store_apple_open);
        assert!(config.features.payments.prot_store_play_open);
        assert_eq!(store["apple_open"], false, "{}", store);
        assert_eq!(store["play_open"], false, "{}", store);
        assert_eq!(store["products"].as_array().map(Vec::len), Some(10));
        assert_eq!(store["us_web_link"], false);
    }
}
