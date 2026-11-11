//! Validated payments settings, read from `[features.payments]` and `[api.stripe]`
//! (and, for Prot, `[features.boosts.protection]`; for in-app Prot,
//! `[api.appstore]` and `[api.googleplay]`)

use chrono::DateTime;
use revolt_config::{
    ApiAppStore, ApiGooglePlay, ApiStripe, FeaturePayments, ProtPackConfig, ProtectionFeatures,
    Settings,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};

use crate::catalog::CIPHER_CAP_MAX;

/// Everything the payments engine reads from the config, checked once
///
/// A config that cannot be trusted (bad close date, cap out of range) is an
/// error, never a silent default: the routes then fail instead of selling.
#[derive(Clone)]
pub struct PaymentsSettings {
    /// Master switch (`features.payments.enabled`)
    pub enabled: bool,
    /// Whether new Cipher checkouts may start (`features.payments.cipher_sales_open`)
    pub sales_open: bool,
    /// Cipher numbers on sale, 1..=CIPHER_CAP_MAX (`features.payments.cipher_cap`)
    pub cap: u32,
    /// Epoch ms at which the sale closes, from `cipher_sales_close_at`; None = no close date
    pub close_at_ms: Option<i64>,
    /// Events and sessions whose `livemode` differs are ignored
    pub expect_livemode: bool,
    /// Maximum age, in seconds, of a webhook signature timestamp
    pub tolerance_secs: u64,
    /// Stripe Tax on Checkout, tax-inclusive (`api.stripe.automatic_tax`)
    pub automatic_tax: bool,
    /// Countries Cipher is not sold to, ISO 3166-1 alpha-2, uppercase
    /// (`features.payments.cipher_blocked_countries`)
    pub blocked_countries: Vec<String>,
    /// Stripe API secret key; never printed
    pub secret_key: String,
    /// Webhook endpoint signing secret; never printed
    pub webhook_secret: String,
    pub success_url_web: String,
    pub cancel_url_web: String,
    pub success_url_shell: String,
    pub cancel_url_shell: String,
}

impl std::fmt::Debug for PaymentsSettings {
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
        let PaymentsSettings {
            enabled,
            sales_open,
            cap,
            close_at_ms,
            expect_livemode,
            tolerance_secs,
            automatic_tax,
            blocked_countries,
            secret_key,
            webhook_secret,
            success_url_web,
            cancel_url_web,
            success_url_shell,
            cancel_url_shell,
        } = self;

        f.debug_struct("PaymentsSettings")
            .field("enabled", enabled)
            .field("sales_open", sales_open)
            .field("cap", cap)
            .field("close_at_ms", close_at_ms)
            .field("expect_livemode", expect_livemode)
            .field("tolerance_secs", tolerance_secs)
            .field("automatic_tax", automatic_tax)
            .field("blocked_countries", blocked_countries)
            .field("secret_key", &redact(secret_key))
            .field("webhook_secret", &redact(webhook_secret))
            .field("success_url_web", success_url_web)
            .field("cancel_url_web", cancel_url_web)
            .field("success_url_shell", success_url_shell)
            .field("cancel_url_shell", cancel_url_shell)
            .finish()
    }
}

impl PaymentsSettings {
    /// Build from the loaded config
    ///
    /// Err(InternalError), logged, when `cipher_sales_close_at` is non-empty
    /// and not RFC 3339, `cipher_cap` is 0 or above [`CIPHER_CAP_MAX`], or
    /// an entry of `cipher_blocked_countries` is not two uppercase ASCII
    /// letters.
    pub fn from_config(c: &Settings) -> Result<Self> {
        Self::from_parts(&c.features.payments, &c.api.stripe)
    }

    /// Build from the two config sections; [`Self::from_config`] without a
    /// whole `Settings` (tests)
    pub fn from_parts(payments: &FeaturePayments, stripe: &ApiStripe) -> Result<Self> {
        let cap = payments.cipher_cap;
        if cap == 0 || cap > CIPHER_CAP_MAX {
            log::error!(
                "[features.payments] cipher_cap = {cap} is out of range (1..={CIPHER_CAP_MAX})"
            );
            return Err(create_error!(InternalError));
        }

        let close_at_ms = parse_close_at(&payments.cipher_sales_close_at).map_err(|err| {
            log::error!("[features.payments] cipher_sales_close_at: {err}");
            create_error!(InternalError)
        })?;

        // A typo (`"de"`, `"DEU"`, `" DE"`) would silently sell to a country
        // meant to be blocked: refuse the whole config instead
        if let Some(bad) = payments
            .cipher_blocked_countries
            .iter()
            .find(|code| !is_country_code(code))
        {
            log::error!(
                "[features.payments] cipher_blocked_countries: {bad:?} is not an ISO 3166-1 \
                 alpha-2 code in uppercase"
            );
            return Err(create_error!(InternalError));
        }

        Ok(Self {
            enabled: payments.enabled,
            sales_open: payments.cipher_sales_open,
            cap,
            close_at_ms,
            expect_livemode: stripe.expect_livemode,
            tolerance_secs: stripe.tolerance_secs,
            automatic_tax: stripe.automatic_tax,
            blocked_countries: payments.cipher_blocked_countries.clone(),
            secret_key: stripe.secret_key.clone(),
            webhook_secret: stripe.webhook_secret.clone(),
            success_url_web: stripe.success_url_web.clone(),
            cancel_url_web: stripe.cancel_url_web.clone(),
            success_url_shell: stripe.success_url_shell.clone(),
            cancel_url_shell: stripe.cancel_url_shell.clone(),
        })
    }

    /// Build from the current config
    pub async fn load() -> Result<Self> {
        Self::from_config(&revolt_config::config().await)
    }

    /// The fallback for settling money already taken (refunds, disputes,
    /// voids) when `[features.payments]` does not validate: the sale fields
    /// at their defaults (payments off, sales closed) and `[api.stripe]` as
    /// configured. None of the sale fields bears on a refund or a dispute,
    /// but fulfilment and expiry read the cap and the close date, so those
    /// must never run on these settings.
    pub fn for_settlement(stripe: &ApiStripe) -> Result<Self> {
        Self::from_parts(&FeaturePayments::default(), stripe)
    }

    /// Whether a checkout may start at `at_ms`:
    /// enabled && sales_open && (no close date || at_ms < close date)
    pub fn sales_open_at(&self, at_ms: i64) -> bool {
        self.enabled && self.sales_open && self.close_at_ms.is_none_or(|close| at_ms < close)
    }

    /// Whether Cipher is not sold to `country` (an ISO 3166-1 alpha-2 code
    /// as Cloudflare or Stripe report it; compared without regard to case)
    pub fn region_blocked(&self, country: &str) -> bool {
        self.blocked_countries
            .iter()
            .any(|blocked| blocked.eq_ignore_ascii_case(country))
    }
}

/// Exactly two uppercase ASCII letters
pub(crate) fn is_country_code(code: &str) -> bool {
    code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase())
}

/// Smallest Prot purchase Stripe takes in USD, in cents
const PROT_MIN_CENTS: i64 = 50;

/// Ceiling on `prot_exact_max_cents`, in cents
const PROT_MAX_CENTS: i64 = 1_000_000;

/// The Prot sale and wallet settings, checked once
///
/// Kept apart from [`PaymentsSettings`] (which the payments tests build as
/// full literals). Like it, a config that cannot be trusted is an error,
/// never a silent default: checkout refuses, and fulfilment falls back to
/// [`ProtSalesSettings::closed`] (sales closed, the shipped blocked list).
#[derive(Clone, Debug)]
pub struct ProtSalesSettings {
    /// `features.boosts.protection.enabled`
    pub enabled: bool,
    /// `features.boosts.protection.cipher_grants_enabled`
    pub cipher_grants_enabled: bool,
    /// `features.boosts.protection.wallet_cap`
    pub wallet_cap: i64,
    /// `features.boosts.protection.contribute_hold_hours`
    pub contribute_hold_hours: u32,
    /// `features.payments.prot_sales_open`
    pub sales_open: bool,
    /// `features.payments.prot_packs`
    pub packs: Vec<ProtPackConfig>,
    /// `features.payments.prot_exact_min_cents`
    pub exact_min_cents: i64,
    /// `features.payments.prot_exact_max_cents`
    pub exact_max_cents: i64,
    /// Countries Prot is not sold to, ISO 3166-1 alpha-2, uppercase
    /// (`features.payments.prot_blocked_countries`)
    pub blocked_countries: Vec<String>,
    /// `features.payments.prot_success_url`
    pub success_url: String,
    /// `features.payments.prot_cancel_url`
    pub cancel_url: String,
    /// `features.payments.prot_shell_return_url` (success and cancel)
    pub shell_return_url: String,
}

impl ProtSalesSettings {
    /// Build from the two config sections
    ///
    /// Err(InternalError), logged naming the key, when: a pack id is not
    /// "p" + digits or is duplicated; a pack has cents < 50, prot < cents
    /// or cents > `prot_exact_max_cents`; the exact bounds are not
    /// 50 <= min <= max <= 1,000,000; `wallet_cap` < 1; a blocked country
    /// is not two uppercase letters; a return URL is not https://.
    pub fn from_parts(payments: &FeaturePayments, protection: &ProtectionFeatures) -> Result<Self> {
        let (min, max) = (payments.prot_exact_min_cents, payments.prot_exact_max_cents);
        if !(PROT_MIN_CENTS..=max).contains(&min) || max > PROT_MAX_CENTS {
            log::error!(
                "[features.payments] prot_exact_min_cents = {min}, prot_exact_max_cents = {max}: \
                 need {PROT_MIN_CENTS} <= min <= max <= {PROT_MAX_CENTS}"
            );
            return Err(create_error!(InternalError));
        }

        for (i, pack) in payments.prot_packs.iter().enumerate() {
            let id = &pack.id;
            if !is_pack_id(id) {
                log::error!("[features.payments] prot_packs: id {id:?} is not \"p\" + digits");
                return Err(create_error!(InternalError));
            }
            if payments.prot_packs[..i].iter().any(|other| other.id == *id) {
                log::error!("[features.payments] prot_packs: id {id:?} is listed twice");
                return Err(create_error!(InternalError));
            }
            if !(PROT_MIN_CENTS..=max).contains(&pack.cents) || pack.prot < pack.cents {
                log::error!(
                    "[features.payments] prot_packs: pack {id:?} ({} cents, {} Prot) needs \
                     {PROT_MIN_CENTS} <= cents <= prot_exact_max_cents ({max}) and prot >= cents",
                    pack.cents,
                    pack.prot
                );
                return Err(create_error!(InternalError));
            }
        }

        if protection.wallet_cap < 1 {
            log::error!(
                "[features.boosts.protection] wallet_cap = {} must be at least 1",
                protection.wallet_cap
            );
            return Err(create_error!(InternalError));
        }

        // As for Cipher: a typo would silently sell to a country meant to be
        // blocked, so the whole config is refused instead
        if let Some(bad) = payments
            .prot_blocked_countries
            .iter()
            .find(|code| !is_country_code(code))
        {
            log::error!(
                "[features.payments] prot_blocked_countries: {bad:?} is not an ISO 3166-1 \
                 alpha-2 code in uppercase"
            );
            return Err(create_error!(InternalError));
        }

        for (key, url) in [
            ("prot_success_url", &payments.prot_success_url),
            ("prot_cancel_url", &payments.prot_cancel_url),
            ("prot_shell_return_url", &payments.prot_shell_return_url),
        ] {
            if !url.starts_with("https://") {
                log::error!("[features.payments] {key} = {url:?} is not an https:// URL");
                return Err(create_error!(InternalError));
            }
        }

        Ok(Self::unchecked(payments, protection))
    }

    /// Build from the loaded config
    pub fn from_config(c: &Settings) -> Result<Self> {
        Self::from_parts(&c.features.payments, &c.features.boosts.protection)
    }

    /// Build from the current config
    pub async fn load() -> Result<Self> {
        Self::from_config(&revolt_config::config().await)
    }

    /// The shipped defaults with sales closed and Cipher grants off. Never
    /// fails: it is built without the checks (`from_parts` of the defaults
    /// is pinned valid by a test).
    pub fn closed() -> Self {
        let mut closed =
            Self::unchecked(&FeaturePayments::default(), &ProtectionFeatures::default());
        closed.sales_open = false;
        closed.cipher_grants_enabled = false;
        closed
    }

    /// [`Self::load`], else [`Self::closed`], logged at error level as
    /// `PROT_CONFIG_INVALID` (the check that failed is logged by `from_parts`)
    pub async fn load_or_closed() -> Self {
        match Self::load().await {
            Ok(ps) => ps,
            Err(_) => {
                log::error!(
                    "payments: PROT_CONFIG_INVALID: the Prot settings do not validate; Prot sales \
                     are closed and Cipher grants off until they do"
                );
                Self::closed()
            }
        }
    }

    /// Whether a Prot checkout may start: payments on, Prot on, Prot sales open
    pub fn checkout_open(&self, s: &PaymentsSettings) -> bool {
        s.enabled && self.enabled && self.sales_open
    }

    /// Whether Cipher members are credited their founding Prot
    pub fn grants_active(&self) -> bool {
        self.enabled && self.cipher_grants_enabled
    }

    /// Whether Prot is not sold to `country` (compared without regard to
    /// case, as [`PaymentsSettings::region_blocked`])
    pub fn region_blocked(&self, country: &str) -> bool {
        self.blocked_countries
            .iter()
            .any(|blocked| blocked.eq_ignore_ascii_case(country))
    }

    /// The pack on sale with this id
    pub fn pack(&self, id: &str) -> Option<&ProtPackConfig> {
        self.packs.iter().find(|pack| pack.id == id)
    }

    /// `contribute_hold_hours` in milliseconds
    pub fn hold_ms(&self) -> i64 {
        i64::from(self.contribute_hold_hours) * 3_600_000
    }

    /// Copy the config sections as they are
    fn unchecked(payments: &FeaturePayments, protection: &ProtectionFeatures) -> Self {
        Self {
            enabled: protection.enabled,
            cipher_grants_enabled: protection.cipher_grants_enabled,
            wallet_cap: protection.wallet_cap,
            contribute_hold_hours: protection.contribute_hold_hours,
            sales_open: payments.prot_sales_open,
            packs: payments.prot_packs.clone(),
            exact_min_cents: payments.prot_exact_min_cents,
            exact_max_cents: payments.prot_exact_max_cents,
            blocked_countries: payments.prot_blocked_countries.clone(),
            success_url: payments.prot_success_url.clone(),
            cancel_url: payments.prot_cancel_url.clone(),
            shell_return_url: payments.prot_shell_return_url.clone(),
        }
    }
}

/// "p" followed by one or more ASCII digits
fn is_pack_id(id: &str) -> bool {
    id.strip_prefix('p')
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

/// Parse `cipher_sales_close_at`: "" → None; otherwise an RFC 3339 instant
/// with an explicit offset (`Z` or `±HH:MM`) → epoch ms
///
/// Surrounding whitespace is refused rather than trimmed, so a value that is
/// not exactly an instant never reads as one.
pub fn parse_close_at(raw: &str) -> std::result::Result<Option<i64>, String> {
    if raw.is_empty() {
        return Ok(None);
    }

    if raw.trim() != raw {
        return Err(format!("{raw:?} has surrounding whitespace"));
    }

    DateTime::parse_from_rfc3339(raw)
        .map(|at| Some(at.timestamp_millis()))
        .map_err(|err| format!("{raw:?} is not an RFC 3339 date-time ({err})"))
}

// ---------------------------------------------------------------------------
// In-app Prot (S6)
// ---------------------------------------------------------------------------

/// Most Prot one unit of a store product may credit
const PROT_STORE_PRODUCT_PROT_MAX: i64 = 100_000;

/// Longest store product id, and longest preview or tester user id
const PROT_STORE_ID_MAX: usize = 64;

/// One in-app product on sale: what one unit of it credits
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtStoreProduct {
    pub store: v0::ProtStore,
    pub product_id: String,
    pub prot: i64,
}

/// The App Store Server API credentials and the JWS pins (`[api.appstore]`).
/// Present only when `issuer_id`, `key_id` and `private_key` are all set.
/// `Debug` never prints the key.
#[derive(Clone)]
pub struct AppleStoreConfig {
    pub issuer_id: String,
    pub key_id: String,
    /// In-App Purchase key, PEM; never printed
    pub private_key: String,
    pub bundle_id: String,
    pub app_apple_id: u64,
    /// The deployment's own environment (R23): a Sandbox deployment refuses
    /// Production transactions
    pub environment: v0::ProtStoreEnvironment,
    /// SHA-256 of the DER of Apple Root CA - G3, the pin of every JWS chain
    pub root_g3_sha256: [u8; 32],
}

/// The Google Play Developer API service account and the RTDN subscription
/// (`[api.googleplay]`). Present only when `client_email` and `private_key`
/// are set. `Debug` never prints the key.
#[derive(Clone)]
pub struct PlayStoreConfig {
    pub package_name: String,
    pub client_email: String,
    /// Service-account key, PEM; never printed
    pub private_key: String,
    pub token_uri: String,
    /// "projects/{p}/subscriptions/{s}"; empty = RTDN not pulled
    pub pubsub_subscription: String,
}

/// The in-app Prot settings, checked once (prot-s6-contracts 9.1). As with
/// the other settings, a config that cannot be trusted is an error: the
/// routes then fail instead of selling or crediting under a default.
#[derive(Clone)]
pub struct ProtStoreSettings {
    /// `prot_store_apple_open`: new App Store intents (verify never reads it)
    pub apple_open: bool,
    /// `prot_store_play_open`: new Google Play intents
    pub play_open: bool,
    /// `prot_store_credit_paused` (E9): verified purchases are recorded Held
    pub credit_paused: bool,
    /// `prot_store_us_web_link` (E8; advertised only)
    pub us_web_link: bool,
    pub products: Vec<ProtStoreProduct>,
    /// See packs and are credited while a store is closed (E3)
    pub preview_user_ids: Vec<String>,
    /// Sandbox and test purchases are credited for these accounts only (E4)
    pub test_user_ids: Vec<String>,
    /// Most Prot an account may hold from sandbox and test purchases (E4)
    pub test_max_prot: i64,
    /// Staff alert mailbox; empty = log only
    pub ops_alert_email: String,
    /// None unless issuer_id, key_id and private_key are all non-empty
    pub apple: Option<AppleStoreConfig>,
    /// None unless client_email and private_key are non-empty
    pub play: Option<PlayStoreConfig>,
}

/// What the store `Debug` impls print for a private key
fn redact_store_key(secret: &str) -> &'static str {
    if secret.is_empty() {
        "<unset>"
    } else {
        "<redacted>"
    }
}

impl std::fmt::Debug for AppleStoreConfig {
    /// Same output as a derive, except `private_key` prints as
    /// `"<redacted>"` (or `"<unset>"`) and the root pin as hex
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Exhaustive destructure: a new field fails to compile until it is
        // either printed or deliberately redacted here
        let AppleStoreConfig {
            issuer_id,
            key_id,
            private_key,
            bundle_id,
            app_apple_id,
            environment,
            root_g3_sha256,
        } = self;

        let root: String = root_g3_sha256.iter().map(|b| format!("{b:02x}")).collect();
        f.debug_struct("AppleStoreConfig")
            .field("issuer_id", issuer_id)
            .field("key_id", key_id)
            .field("private_key", &redact_store_key(private_key))
            .field("bundle_id", bundle_id)
            .field("app_apple_id", app_apple_id)
            .field("environment", environment)
            .field("root_g3_sha256", &root)
            .finish()
    }
}

impl std::fmt::Debug for PlayStoreConfig {
    /// Same output as a derive, except `private_key` prints as
    /// `"<redacted>"` (or `"<unset>"`)
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let PlayStoreConfig {
            package_name,
            client_email,
            private_key,
            token_uri,
            pubsub_subscription,
        } = self;

        f.debug_struct("PlayStoreConfig")
            .field("package_name", package_name)
            .field("client_email", client_email)
            .field("private_key", &redact_store_key(private_key))
            .field("token_uri", token_uri)
            .field("pubsub_subscription", pubsub_subscription)
            .finish()
    }
}

impl std::fmt::Debug for ProtStoreSettings {
    /// Same output as a derive; the store configs redact their keys
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ProtStoreSettings {
            apple_open,
            play_open,
            credit_paused,
            us_web_link,
            products,
            preview_user_ids,
            test_user_ids,
            test_max_prot,
            ops_alert_email,
            apple,
            play,
        } = self;

        f.debug_struct("ProtStoreSettings")
            .field("apple_open", apple_open)
            .field("play_open", play_open)
            .field("credit_paused", credit_paused)
            .field("us_web_link", us_web_link)
            .field("products", products)
            .field("preview_user_ids", preview_user_ids)
            .field("test_user_ids", test_user_ids)
            .field("test_max_prot", test_max_prot)
            .field("ops_alert_email", ops_alert_email)
            .field("apple", apple)
            .field("play", play)
            .finish()
    }
}

impl ProtStoreSettings {
    /// Build from the three config sections
    ///
    /// Err(InternalError), logged naming the key, when: a product's store is
    /// not "apple" / "play", its id is not 1..=64 of `[A-Za-z0-9._]`, its
    /// Prot is not 1..=100,000, or (store, id) is listed twice; a preview or
    /// tester id is not 1..=64 ASCII letters and digits; `test_max_prot` < 0;
    /// `ops_alert_email` is set without an `@`; `[api.appstore] environment`
    /// is not "Production" / "Sandbox"; `root_ca_g3_sha256` is not 64 hex
    /// digits. Missing credentials are not an error: that store is simply not
    /// configured.
    pub fn from_parts(
        payments: &FeaturePayments,
        appstore: &ApiAppStore,
        googleplay: &ApiGooglePlay,
    ) -> Result<Self> {
        let mut products: Vec<ProtStoreProduct> =
            Vec::with_capacity(payments.prot_store_products.len());
        for row in &payments.prot_store_products {
            let store = match row.store.as_str() {
                "apple" => v0::ProtStore::Apple,
                "play" => v0::ProtStore::Play,
                other => {
                    log::error!(
                        "[features.payments] prot_store_products: store {other:?} is not \
                         \"apple\" or \"play\""
                    );
                    return Err(create_error!(InternalError));
                }
            };
            let id = &row.product_id;
            if !is_store_product_id(id) {
                log::error!(
                    "[features.payments] prot_store_products: product id {id:?} is not 1 to \
                     {PROT_STORE_ID_MAX} of A-Z, a-z, 0-9, '.', '_'"
                );
                return Err(create_error!(InternalError));
            }
            if !(1..=PROT_STORE_PRODUCT_PROT_MAX).contains(&row.prot) {
                log::error!(
                    "[features.payments] prot_store_products: {} product {id:?} credits {} \
                     Prot; need 1..={PROT_STORE_PRODUCT_PROT_MAX}",
                    row.store,
                    row.prot
                );
                return Err(create_error!(InternalError));
            }
            if products
                .iter()
                .any(|product| product.store == store && product.product_id == *id)
            {
                log::error!(
                    "[features.payments] prot_store_products: {} product {id:?} is listed twice",
                    row.store
                );
                return Err(create_error!(InternalError));
            }
            products.push(ProtStoreProduct {
                store,
                product_id: id.clone(),
                prot: row.prot,
            });
        }

        for (key, ids) in [
            (
                "prot_store_preview_user_ids",
                &payments.prot_store_preview_user_ids,
            ),
            (
                "prot_store_test_user_ids",
                &payments.prot_store_test_user_ids,
            ),
        ] {
            if let Some(bad) = ids.iter().find(|id| !is_store_user_id(id)) {
                log::error!(
                    "[features.payments] {key}: {bad:?} is not a user id (1 to \
                     {PROT_STORE_ID_MAX} ASCII letters and digits)"
                );
                return Err(create_error!(InternalError));
            }
        }

        if payments.prot_store_test_max_prot < 0 {
            log::error!(
                "[features.payments] prot_store_test_max_prot = {} must be at least 0",
                payments.prot_store_test_max_prot
            );
            return Err(create_error!(InternalError));
        }

        if !payments.ops_alert_email.is_empty() && !payments.ops_alert_email.contains('@') {
            log::error!("[features.payments] ops_alert_email is set but is not an email address");
            return Err(create_error!(InternalError));
        }

        let environment = match appstore.environment.as_str() {
            "Production" => v0::ProtStoreEnvironment::Production,
            "Sandbox" => v0::ProtStoreEnvironment::Sandbox,
            other => {
                log::error!(
                    "[api.appstore] environment = {other:?} is not \"Production\" or \"Sandbox\""
                );
                return Err(create_error!(InternalError));
            }
        };

        let Some(root_g3_sha256) = parse_sha256_hex(&appstore.root_ca_g3_sha256) else {
            log::error!("[api.appstore] root_ca_g3_sha256 is not a SHA-256 (64 hex digits)");
            return Err(create_error!(InternalError));
        };

        let apple = (!appstore.issuer_id.is_empty()
            && !appstore.key_id.is_empty()
            && !appstore.private_key.is_empty())
        .then(|| AppleStoreConfig {
            issuer_id: appstore.issuer_id.clone(),
            key_id: appstore.key_id.clone(),
            private_key: appstore.private_key.clone(),
            bundle_id: appstore.bundle_id.clone(),
            app_apple_id: appstore.app_apple_id,
            environment,
            root_g3_sha256,
        });

        let play = (!googleplay.client_email.is_empty() && !googleplay.private_key.is_empty())
            .then(|| PlayStoreConfig {
                package_name: googleplay.package_name.clone(),
                client_email: googleplay.client_email.clone(),
                private_key: googleplay.private_key.clone(),
                token_uri: googleplay.token_uri.clone(),
                pubsub_subscription: googleplay.pubsub_subscription.clone(),
            });

        Ok(Self {
            apple_open: payments.prot_store_apple_open,
            play_open: payments.prot_store_play_open,
            credit_paused: payments.prot_store_credit_paused,
            us_web_link: payments.prot_store_us_web_link,
            products,
            preview_user_ids: payments.prot_store_preview_user_ids.clone(),
            test_user_ids: payments.prot_store_test_user_ids.clone(),
            test_max_prot: payments.prot_store_test_max_prot,
            ops_alert_email: payments.ops_alert_email.clone(),
            apple,
            play,
        })
    }

    /// Build from the loaded config
    pub fn from_config(c: &Settings) -> Result<Self> {
        Self::from_parts(&c.features.payments, &c.api.appstore, &c.api.googleplay)
    }

    /// Build from the current config
    pub async fn load() -> Result<Self> {
        Self::from_config(&revolt_config::config().await)
    }

    /// All closed, no credentials, nothing on sale, credits paused (nothing
    /// is credited under these). The caller logs `PROT_STORE_CONFIG_INVALID`.
    pub fn closed() -> Self {
        Self {
            apple_open: false,
            play_open: false,
            credit_paused: true,
            us_web_link: false,
            products: Vec::new(),
            preview_user_ids: Vec::new(),
            test_user_ids: Vec::new(),
            test_max_prot: 0,
            ops_alert_email: String::new(),
            apple: None,
            play: None,
        }
    }

    /// [`Self::load`], else [`Self::closed`], logged at error level as
    /// `PROT_STORE_CONFIG_INVALID` (the check that failed is logged by
    /// `from_parts`)
    pub async fn load_or_closed() -> Self {
        match Self::load().await {
            Ok(st) => st,
            Err(_) => {
                log::error!(
                    "payments: PROT_STORE_CONFIG_INVALID: the in-app Prot settings do not \
                     validate; the stores are closed and unconfigured until they do"
                );
                Self::closed()
            }
        }
    }

    /// The product on sale with this id in this store
    pub fn product(&self, store: v0::ProtStore, product_id: &str) -> Option<&ProtStoreProduct> {
        self.products
            .iter()
            .find(|product| product.store == store && product.product_id == product_id)
    }

    /// Whether `user_id` is on `prot_store_preview_user_ids` (E3)
    pub fn is_preview(&self, user_id: &str) -> bool {
        self.preview_user_ids.iter().any(|id| id == user_id)
    }

    /// Whether `user_id` is on `prot_store_test_user_ids` (E4)
    pub fn is_tester(&self, user_id: &str) -> bool {
        self.test_user_ids.iter().any(|id| id == user_id)
    }

    /// `configured` (the MANAGED client's `configured()`, audit N4) AND (the
    /// store's open flag OR preview)
    pub fn store_offered_to(&self, store: v0::ProtStore, user_id: &str, configured: bool) -> bool {
        let open = match store {
            v0::ProtStore::Apple => self.apple_open,
            v0::ProtStore::Play => self.play_open,
        };
        configured && (open || self.is_preview(user_id))
    }
}

/// 1..=64 of `[A-Za-z0-9._]`
fn is_store_product_id(id: &str) -> bool {
    (1..=PROT_STORE_ID_MAX).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
}

/// 1..=64 ASCII letters and digits
fn is_store_user_id(id: &str) -> bool {
    (1..=PROT_STORE_ID_MAX).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// 64 hex digits (either case) → the 32 bytes
fn parse_sha256_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0_u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use revolt_result::ErrorType;

    /// 2027-07-01T00:00:00Z
    const JULY_1_2027_MS: i64 = 1_814_400_000_000;

    fn payments(cap: u32, close_at: &str) -> FeaturePayments {
        FeaturePayments {
            enabled: true,
            cipher_sales_open: true,
            cipher_cap: cap,
            cipher_sales_close_at: close_at.to_string(),
            ..FeaturePayments::default()
        }
    }

    fn settings(close_at: &str) -> PaymentsSettings {
        PaymentsSettings::from_parts(&payments(1000, close_at), &ApiStripe::default()).unwrap()
    }

    fn assert_internal_error(result: Result<PaymentsSettings>) {
        match result {
            Err(err) => assert!(
                matches!(err.error_type, ErrorType::InternalError),
                "expected InternalError, got {:?}",
                err.error_type
            ),
            Ok(s) => panic!("expected InternalError, got {s:?}"),
        }
    }

    #[test]
    fn empty_close_at_is_none() {
        assert_eq!(parse_close_at(""), Ok(None));
        assert_eq!(settings("").close_at_ms, None);
    }

    #[test]
    fn close_at_utc() {
        assert_eq!(
            parse_close_at("2027-07-01T00:00:00Z"),
            Ok(Some(JULY_1_2027_MS))
        );
        assert_eq!(
            parse_close_at("2027-06-30T23:59:59Z"),
            Ok(Some(JULY_1_2027_MS - 1_000))
        );
    }

    #[test]
    fn close_at_with_offset() {
        assert_eq!(
            parse_close_at("2027-06-30T20:00:00-04:00"),
            Ok(Some(JULY_1_2027_MS))
        );
        assert_eq!(
            parse_close_at("2027-07-01T02:00:00+02:00"),
            Ok(Some(JULY_1_2027_MS))
        );
        assert_eq!(
            parse_close_at("2027-07-01T00:00:00+00:00"),
            Ok(Some(JULY_1_2027_MS))
        );
    }

    #[test]
    fn close_at_with_fraction() {
        assert_eq!(
            parse_close_at("2027-07-01T00:00:00.250Z"),
            Ok(Some(JULY_1_2027_MS + 250))
        );
        assert_eq!(
            parse_close_at("2027-06-30T20:00:00.5-04:00"),
            Ok(Some(JULY_1_2027_MS + 500))
        );
    }

    #[test]
    fn close_at_garbage_is_err() {
        for raw in [
            "tomorrow",
            "2027-07-01",
            "2027-07-01T00:00:00",
            "2027-07-01T00:00Z",
            "2027-13-01T00:00:00Z",
            "2027-02-30T00:00:00Z",
            "2027-07-01T24:00:00Z",
            "2027-07-01T00:00:00+0400",
            "2027-07-01T00:00:00Zjunk",
            "1814400000000",
            " 2027-07-01T00:00:00Z",
            "2027-07-01T00:00:00Z ",
            " ",
        ] {
            assert!(parse_close_at(raw).is_err(), "{raw:?} must not parse");
            assert_internal_error(PaymentsSettings::from_parts(
                &payments(1000, raw),
                &ApiStripe::default(),
            ));
        }
    }

    #[test]
    fn cap_bounds() {
        assert_internal_error(PaymentsSettings::from_parts(
            &payments(0, ""),
            &ApiStripe::default(),
        ));
        assert_internal_error(PaymentsSettings::from_parts(
            &payments(CIPHER_CAP_MAX + 1, ""),
            &ApiStripe::default(),
        ));

        for cap in [1, CIPHER_CAP_MAX] {
            let s =
                PaymentsSettings::from_parts(&payments(cap, ""), &ApiStripe::default()).unwrap();
            assert_eq!(s.cap, cap);
        }
    }

    #[test]
    fn default_config_is_valid_and_closed() {
        // shipped defaults: payments off, sales closed, full cap, no close date
        let s = PaymentsSettings::from_parts(&FeaturePayments::default(), &ApiStripe::default())
            .unwrap();
        assert!(!s.enabled);
        assert!(!s.sales_open);
        assert_eq!(s.cap, CIPHER_CAP_MAX);
        assert_eq!(s.close_at_ms, None);
        assert!(!s.sales_open_at(0));
        // ...and the EU and the UK blocked
        assert_eq!(s.blocked_countries.len(), 28);
        for code in ["DE", "FR", "GB", "IE", "de"] {
            assert!(s.region_blocked(code), "{code}");
        }
        for code in ["US", "BR", "CH", "", "XX", "DEU"] {
            assert!(!s.region_blocked(code), "{code}");
        }
    }

    #[test]
    fn blocked_countries_must_be_uppercase_alpha_2() {
        let with = |codes: &[&str]| FeaturePayments {
            cipher_blocked_countries: codes.iter().map(|c| c.to_string()).collect(),
            ..payments(1000, "")
        };
        for bad in ["de", "De", "DEU", "D", "", " DE", "DE ", "D1", "A-"] {
            assert_internal_error(PaymentsSettings::from_parts(
                &with(&["FR", bad]),
                &ApiStripe::default(),
            ));
        }

        let s = PaymentsSettings::from_parts(&with(&["FR", "US"]), &ApiStripe::default()).unwrap();
        assert_eq!(s.blocked_countries, ["FR", "US"]);
        assert!(s.region_blocked("US"));
        assert!(!s.region_blocked("DE"));

        // An empty list blocks nothing
        let s = PaymentsSettings::from_parts(&with(&[]), &ApiStripe::default()).unwrap();
        assert!(s.blocked_countries.is_empty());
        assert!(!s.region_blocked("DE"));
    }

    #[test]
    fn copies_stripe_section() {
        let stripe = ApiStripe {
            secret_key: "sk_test_abc".to_string(),
            webhook_secret: "whsec_abc".to_string(),
            expect_livemode: true,
            success_url_web: "https://w/s".to_string(),
            cancel_url_web: "https://w/c".to_string(),
            success_url_shell: "https://s/s".to_string(),
            cancel_url_shell: "https://s/c".to_string(),
            tolerance_secs: 42,
            automatic_tax: true,
        };
        let s = PaymentsSettings::from_parts(&payments(500, ""), &stripe).unwrap();
        assert!(s.expect_livemode);
        assert_eq!(s.tolerance_secs, 42);
        assert!(s.automatic_tax);
        assert_eq!(s.secret_key, "sk_test_abc");
        assert_eq!(s.webhook_secret, "whsec_abc");
        assert_eq!(s.success_url_web, "https://w/s");
        assert_eq!(s.cancel_url_web, "https://w/c");
        assert_eq!(s.success_url_shell, "https://s/s");
        assert_eq!(s.cancel_url_shell, "https://s/c");
        assert_eq!(s.cap, 500);
    }

    #[test]
    fn settlement_fallback_keeps_the_stripe_section_and_closes_the_sale() {
        let stripe = ApiStripe {
            webhook_secret: ["whsec", "settlement", "fallback"].join("_"),
            expect_livemode: true,
            tolerance_secs: 120,
            ..ApiStripe::default()
        };
        let s = PaymentsSettings::for_settlement(&stripe).unwrap();
        assert_eq!(s.webhook_secret, stripe.webhook_secret);
        assert!(s.expect_livemode);
        assert_eq!(s.tolerance_secs, 120);
        assert!(!s.enabled);
        assert!(!s.sales_open);
        assert!(!s.sales_open_at(0));
    }

    #[test]
    fn sales_open_at_boundary() {
        let s = settings("2027-07-01T00:00:00Z");
        assert!(s.sales_open_at(JULY_1_2027_MS - 1));
        // at == close → closed
        assert!(!s.sales_open_at(JULY_1_2027_MS));
        assert!(!s.sales_open_at(JULY_1_2027_MS + 1));

        // no close date → open at any time
        let s = settings("");
        assert!(s.sales_open_at(JULY_1_2027_MS));
        assert!(s.sales_open_at(i64::MAX));
    }

    #[test]
    fn sales_open_at_needs_both_switches() {
        let mut s = settings("");
        s.enabled = false;
        assert!(!s.sales_open_at(0));

        let mut s = settings("");
        s.sales_open = false;
        assert!(!s.sales_open_at(0));
    }

    #[test]
    fn debug_redacts_secrets() {
        let stripe = ApiStripe {
            secret_key: "sk_live_SECRETKEY".to_string(),
            webhook_secret: "whsec_SECRETHOOK".to_string(),
            ..ApiStripe::default()
        };
        let s = PaymentsSettings::from_parts(&payments(1000, ""), &stripe).unwrap();
        let debug = format!("{s:?}");
        assert!(
            !debug.contains("SECRETKEY"),
            "Debug leaks secret_key: {debug}"
        );
        assert!(
            !debug.contains("SECRETHOOK"),
            "Debug leaks webhook_secret: {debug}"
        );
        assert!(debug.contains(r#"secret_key: "<redacted>""#), "{debug}");
        assert!(debug.contains(r#"webhook_secret: "<redacted>""#), "{debug}");

        let unset = format!("{:?}", settings(""));
        assert!(unset.contains(r#"secret_key: "<unset>""#), "{unset}");
        assert!(unset.contains(r#"webhook_secret: "<unset>""#), "{unset}");
    }

    // --- Prot ----------------------------------------------------------

    fn prot_on() -> ProtectionFeatures {
        ProtectionFeatures {
            enabled: true,
            cipher_grants_enabled: true,
            ..ProtectionFeatures::default()
        }
    }

    fn pack(id: &str, cents: i64, prot: i64) -> ProtPackConfig {
        ProtPackConfig {
            id: id.to_string(),
            cents,
            prot,
        }
    }

    fn assert_prot_internal_error(result: Result<ProtSalesSettings>) {
        match result {
            Err(err) => assert!(
                matches!(err.error_type, ErrorType::InternalError),
                "expected InternalError, got {:?}",
                err.error_type
            ),
            Ok(ps) => panic!("expected InternalError, got {ps:?}"),
        }
    }

    #[test]
    fn prot_defaults_are_valid_and_closed() {
        let ps = ProtSalesSettings::from_parts(
            &FeaturePayments::default(),
            &ProtectionFeatures::default(),
        )
        .unwrap();
        assert!(!ps.enabled);
        assert!(!ps.sales_open);
        assert!(!ps.grants_active());
        assert_eq!(ps.wallet_cap, 100_000);
        assert_eq!(ps.hold_ms(), 72 * 3_600_000);
        assert_eq!((ps.exact_min_cents, ps.exact_max_cents), (50, 50_000));
        assert_eq!(ps.pack("p25"), Some(&pack("p25", 2500, 2600)));
        assert_eq!(ps.pack("p1000"), None);
        // The EU and the UK, like Cipher, plus Norway, Iceland and
        // Liechtenstein
        assert_eq!(ps.blocked_countries.len(), 31);
        for code in ["DE", "fr", "GB", "NO", "is", "LI"] {
            assert!(ps.region_blocked(code), "{code}");
        }
        for code in ["US", "CH", ""] {
            assert!(!ps.region_blocked(code), "{code}");
        }
    }

    #[test]
    fn prot_closed_is_the_defaults_with_sales_and_grants_off() {
        let closed = ProtSalesSettings::closed();
        assert!(!closed.sales_open);
        assert!(!closed.grants_active());
        assert_eq!(
            closed.blocked_countries,
            FeaturePayments::default().prot_blocked_countries
        );
        assert_eq!(closed.packs, FeaturePayments::default().prot_packs);
    }

    #[test]
    fn prot_switches() {
        let open = FeaturePayments {
            prot_sales_open: true,
            ..FeaturePayments::default()
        };
        let ps = ProtSalesSettings::from_parts(&open, &prot_on()).unwrap();
        let mut s = settings("");
        assert!(ps.checkout_open(&s));
        assert!(ps.grants_active());

        s.enabled = false;
        assert!(!ps.checkout_open(&s), "payments off");

        let s = settings("");
        let closed =
            ProtSalesSettings::from_parts(&FeaturePayments::default(), &prot_on()).unwrap();
        assert!(!closed.checkout_open(&s), "Prot sales closed");

        let off = ProtSalesSettings::from_parts(&open, &ProtectionFeatures::default()).unwrap();
        assert!(!off.checkout_open(&s), "Prot off");
        assert!(!off.grants_active());

        let no_grants = ProtSalesSettings::from_parts(
            &open,
            &ProtectionFeatures {
                enabled: true,
                ..ProtectionFeatures::default()
            },
        )
        .unwrap();
        assert!(no_grants.checkout_open(&s));
        assert!(!no_grants.grants_active(), "grants have their own switch");
    }

    #[test]
    fn prot_packs_must_be_well_formed() {
        let with = |packs: Vec<ProtPackConfig>| FeaturePayments {
            prot_packs: packs,
            ..FeaturePayments::default()
        };
        for bad in [
            vec![pack("25", 2500, 2600)],
            vec![pack("p", 2500, 2600)],
            vec![pack("P25", 2500, 2600)],
            vec![pack("p2a", 2500, 2600)],
            vec![pack("p25 ", 2500, 2600)],
            vec![pack("p25", 2500, 2600), pack("p25", 1000, 1000)],
            vec![pack("p1", 49, 49)],
            vec![pack("p2", 1000, 999)],
            vec![pack("p3", 50_001, 60_000)],
        ] {
            assert_prot_internal_error(ProtSalesSettings::from_parts(&with(bad), &prot_on()));
        }

        let ps = ProtSalesSettings::from_parts(
            &with(vec![pack("p1", 50, 50), pack("p500", 50_000, 50_000)]),
            &prot_on(),
        )
        .unwrap();
        assert_eq!(ps.packs.len(), 2);

        // No packs: only pay-exact is on sale
        assert!(ProtSalesSettings::from_parts(&with(vec![]), &prot_on()).is_ok());
    }

    #[test]
    fn prot_exact_bounds_and_wallet_cap() {
        let bounds = |min: i64, max: i64| FeaturePayments {
            prot_exact_min_cents: min,
            prot_exact_max_cents: max,
            prot_packs: vec![],
            ..FeaturePayments::default()
        };
        for (min, max) in [(49, 50_000), (100, 99), (50, 1_000_001), (0, 0), (-1, 50)] {
            assert_prot_internal_error(ProtSalesSettings::from_parts(
                &bounds(min, max),
                &prot_on(),
            ));
        }
        for (min, max) in [(50, 50), (50, 1_000_000), (500, 600)] {
            assert!(ProtSalesSettings::from_parts(&bounds(min, max), &prot_on()).is_ok());
        }

        // A pack dearer than the exact ceiling is refused
        let packs_over = FeaturePayments {
            prot_exact_max_cents: 5_000,
            ..FeaturePayments::default()
        };
        assert_prot_internal_error(ProtSalesSettings::from_parts(&packs_over, &prot_on()));

        for cap in [0, -1] {
            let protection = ProtectionFeatures {
                wallet_cap: cap,
                ..prot_on()
            };
            assert_prot_internal_error(ProtSalesSettings::from_parts(
                &FeaturePayments::default(),
                &protection,
            ));
        }
    }

    #[test]
    fn prot_blocked_countries_and_urls_are_checked() {
        for bad in ["de", "DEU", "", " DE"] {
            let payments = FeaturePayments {
                prot_blocked_countries: vec!["FR".to_string(), bad.to_string()],
                ..FeaturePayments::default()
            };
            assert_prot_internal_error(ProtSalesSettings::from_parts(&payments, &prot_on()));
        }

        // Its own list, independent of Cipher's
        let payments = FeaturePayments {
            prot_blocked_countries: vec!["US".to_string()],
            ..FeaturePayments::default()
        };
        let ps = ProtSalesSettings::from_parts(&payments, &prot_on()).unwrap();
        assert!(ps.region_blocked("us"));
        assert!(!ps.region_blocked("DE"));

        let urls: [fn(&mut FeaturePayments); 3] = [
            |p: &mut FeaturePayments| p.prot_success_url = "http://app.test/s".to_string(),
            |p: &mut FeaturePayments| p.prot_cancel_url = String::new(),
            |p: &mut FeaturePayments| p.prot_shell_return_url = "sloga.gg/prot/".to_string(),
        ];
        for change in urls {
            let mut payments = FeaturePayments::default();
            change(&mut payments);
            assert_prot_internal_error(ProtSalesSettings::from_parts(&payments, &prot_on()));
        }
    }

    // --- in-app Prot (S6) ------------------------------------------------

    fn store_settings(payments: &FeaturePayments) -> Result<ProtStoreSettings> {
        ProtStoreSettings::from_parts(payments, &ApiAppStore::default(), &ApiGooglePlay::default())
    }

    fn assert_store_internal_error(result: Result<ProtStoreSettings>) {
        match result {
            Err(err) => assert!(
                matches!(err.error_type, ErrorType::InternalError),
                "expected InternalError, got {:?}",
                err.error_type
            ),
            Ok(st) => panic!("expected InternalError, got {st:?}"),
        }
    }

    fn store_product(store: &str, id: &str, prot: i64) -> revolt_config::ProtStoreProductConfig {
        // The config type has no public constructor; build it the way the
        // TOML does
        serde_json::from_value(serde_json::json!({
            "store": store,
            "product_id": id,
            "prot": prot,
        }))
        .expect("a product row parses")
    }

    #[test]
    fn prot_store_defaults_are_valid_closed_and_without_credentials() {
        let st = store_settings(&FeaturePayments::default()).unwrap();
        assert!(!st.apple_open);
        assert!(!st.play_open);
        assert!(!st.credit_paused);
        assert!(!st.us_web_link);
        assert!(st.apple.is_none(), "no App Store credentials by default");
        assert!(st.play.is_none(), "no Play credentials by default");
        assert_eq!(st.test_max_prot, 25_000);
        assert_eq!(st.products.len(), 10);
        assert_eq!(
            st.product(v0::ProtStore::Apple, "gg.sloga.prot.p25"),
            Some(&ProtStoreProduct {
                store: v0::ProtStore::Apple,
                product_id: "gg.sloga.prot.p25".to_string(),
                prot: 2600,
            })
        );
        assert_eq!(
            st.product(v0::ProtStore::Play, "gg.sloga.prot.p100")
                .map(|product| product.prot),
            Some(11_000)
        );
        assert_eq!(st.product(v0::ProtStore::Play, "gg.sloga.prot.p1"), None);

        // Not offered to anyone, configured or not
        for configured in [false, true] {
            for store in [v0::ProtStore::Apple, v0::ProtStore::Play] {
                assert!(!st.store_offered_to(store, "01USER", configured));
            }
        }
    }

    #[test]
    fn prot_store_credentials_build_the_store_configs() {
        let appstore = ApiAppStore {
            issuer_id: "issuer".to_string(),
            key_id: "KEYID".to_string(),
            private_key: concat!("-----BEGIN PRIVATE", " KEY-----APPLESECRET").to_string(),
            environment: "Sandbox".to_string(),
            ..ApiAppStore::default()
        };
        let googleplay = ApiGooglePlay {
            client_email: "play@sloga-test.iam.gserviceaccount.com".to_string(),
            private_key: concat!("-----BEGIN PRIVATE", " KEY-----PLAYSECRET").to_string(),
            pubsub_subscription: "projects/p/subscriptions/s".to_string(),
            ..ApiGooglePlay::default()
        };
        let st = ProtStoreSettings::from_parts(&FeaturePayments::default(), &appstore, &googleplay)
            .unwrap();

        let apple = st.apple.as_ref().expect("App Store configured");
        assert_eq!(apple.bundle_id, "gg.sloga.app");
        assert_eq!(apple.app_apple_id, 6_809_989_506);
        assert_eq!(apple.environment, v0::ProtStoreEnvironment::Sandbox);
        assert_eq!(
            apple.root_g3_sha256,
            parse_sha256_hex(crate::store::apple_jws::APPLE_ROOT_G3_SHA256_HEX).unwrap()
        );
        let play = st.play.as_ref().expect("Play configured");
        assert_eq!(play.package_name, "gg.sloga.app");
        assert_eq!(play.token_uri, "https://oauth2.googleapis.com/token");
        assert_eq!(play.pubsub_subscription, "projects/p/subscriptions/s");

        // Any one App Store credential missing: not configured
        for missing in 0..3 {
            let mut partial = appstore.clone();
            match missing {
                0 => partial.issuer_id.clear(),
                1 => partial.key_id.clear(),
                _ => partial.private_key.clear(),
            }
            let st =
                ProtStoreSettings::from_parts(&FeaturePayments::default(), &partial, &googleplay)
                    .unwrap();
            assert!(st.apple.is_none(), "missing credential {missing}");
        }
        for missing in 0..2 {
            let mut partial = googleplay.clone();
            match missing {
                0 => partial.client_email.clear(),
                _ => partial.private_key.clear(),
            }
            let st =
                ProtStoreSettings::from_parts(&FeaturePayments::default(), &appstore, &partial)
                    .unwrap();
            assert!(st.play.is_none(), "missing credential {missing}");
        }
    }

    #[test]
    fn prot_store_debug_never_prints_a_key() {
        let appstore = ApiAppStore {
            issuer_id: "issuer".to_string(),
            key_id: "KEYID".to_string(),
            private_key: "APPLESECRETKEY".to_string(),
            ..ApiAppStore::default()
        };
        let googleplay = ApiGooglePlay {
            client_email: "play@sloga-test.iam.gserviceaccount.com".to_string(),
            private_key: "PLAYSECRETKEY".to_string(),
            ..ApiGooglePlay::default()
        };
        let st = ProtStoreSettings::from_parts(&FeaturePayments::default(), &appstore, &googleplay)
            .unwrap();
        let debug = format!("{st:?}");
        assert!(!debug.contains("APPLESECRETKEY"), "{debug}");
        assert!(!debug.contains("PLAYSECRETKEY"), "{debug}");
        assert_eq!(
            debug.matches(r#"private_key: "<redacted>""#).count(),
            2,
            "{debug}"
        );
        assert!(debug.contains("KEYID"), "{debug}");
        assert!(
            debug.contains(crate::store::apple_jws::APPLE_ROOT_G3_SHA256_HEX),
            "{debug}"
        );
    }

    #[test]
    fn prot_store_products_are_checked() {
        let with = |products: Vec<revolt_config::ProtStoreProductConfig>| FeaturePayments {
            prot_store_products: products,
            ..FeaturePayments::default()
        };
        for bad in [
            // A duplicate (store, id)
            vec![
                store_product("apple", "gg.sloga.prot.p5", 500),
                store_product("apple", "gg.sloga.prot.p5", 600),
            ],
            // Zero, negative and too much Prot
            vec![store_product("apple", "gg.sloga.prot.p0", 0)],
            vec![store_product("play", "gg.sloga.prot.n", -5)],
            vec![store_product("play", "gg.sloga.prot.big", 100_001)],
            // Ids
            vec![store_product("apple", "", 500)],
            vec![store_product("apple", "gg.sloga.prot-p5", 500)],
            vec![store_product("apple", "gg.sloga.prot p5", 500)],
            vec![store_product("apple", &"p".repeat(65), 500)],
            // Stores
            vec![store_product("Apple", "gg.sloga.prot.p5", 500)],
            vec![store_product("google", "gg.sloga.prot.p5", 500)],
        ] {
            assert_store_internal_error(store_settings(&with(bad)));
        }

        // The same id on both stores, the bounds, and an empty table are fine
        let st = store_settings(&with(vec![
            store_product("apple", "gg.sloga.prot.p5", 1),
            store_product("play", "gg.sloga.prot.p5", 100_000),
            store_product("apple", &"P_9.".repeat(16), 500),
        ]))
        .unwrap();
        assert_eq!(st.products.len(), 3);
        assert!(store_settings(&with(vec![])).unwrap().products.is_empty());
    }

    #[test]
    fn prot_store_lists_email_environment_and_root_are_checked() {
        let user_lists: [fn(&mut FeaturePayments, Vec<String>); 2] = [
            |p: &mut FeaturePayments, ids: Vec<String>| p.prot_store_preview_user_ids = ids,
            |p: &mut FeaturePayments, ids: Vec<String>| p.prot_store_test_user_ids = ids,
        ];
        let too_long = "A".repeat(65);
        for set in user_lists {
            for bad in ["", "01HZ-USER", "01HZ USER", "user@x", too_long.as_str()] {
                let mut payments = FeaturePayments::default();
                set(&mut payments, vec!["01HZUSER".to_string(), bad.to_string()]);
                assert_store_internal_error(store_settings(&payments));
            }
            let mut payments = FeaturePayments::default();
            set(&mut payments, vec!["01HZUSER".to_string(), "A".repeat(64)]);
            assert!(store_settings(&payments).is_ok());
        }

        let test_max = |max: i64| FeaturePayments {
            prot_store_test_max_prot: max,
            ..FeaturePayments::default()
        };
        assert_store_internal_error(store_settings(&test_max(-1)));
        assert_eq!(store_settings(&test_max(0)).unwrap().test_max_prot, 0);

        let email = |to: &str| FeaturePayments {
            ops_alert_email: to.to_string(),
            ..FeaturePayments::default()
        };
        assert_store_internal_error(store_settings(&email("ops.sloga.gg")));
        assert_eq!(
            store_settings(&email("ops@sloga.gg"))
                .unwrap()
                .ops_alert_email,
            "ops@sloga.gg"
        );

        for environment in ["production", "Xcode", ""] {
            let appstore = ApiAppStore {
                environment: environment.to_string(),
                ..ApiAppStore::default()
            };
            assert_store_internal_error(ProtStoreSettings::from_parts(
                &FeaturePayments::default(),
                &appstore,
                &ApiGooglePlay::default(),
            ));
        }
        let (not_hex, too_long) = ("g".repeat(64), "0".repeat(65));
        for root in ["", "63343abf", not_hex.as_str(), too_long.as_str()] {
            let appstore = ApiAppStore {
                root_ca_g3_sha256: root.to_string(),
                ..ApiAppStore::default()
            };
            assert_store_internal_error(ProtStoreSettings::from_parts(
                &FeaturePayments::default(),
                &appstore,
                &ApiGooglePlay::default(),
            ));
        }
        let upper = ApiAppStore {
            root_ca_g3_sha256: crate::store::apple_jws::APPLE_ROOT_G3_SHA256_HEX.to_uppercase(),
            ..ApiAppStore::default()
        };
        assert!(ProtStoreSettings::from_parts(
            &FeaturePayments::default(),
            &upper,
            &ApiGooglePlay::default()
        )
        .is_ok());
    }

    #[test]
    fn prot_store_offered_needs_the_client_and_the_flag_or_preview() {
        let payments = FeaturePayments {
            prot_store_apple_open: true,
            prot_store_preview_user_ids: vec!["01PREVIEW".to_string()],
            ..FeaturePayments::default()
        };
        let st = store_settings(&payments).unwrap();

        // Apple open: anyone, but only with a configured client
        assert!(st.store_offered_to(v0::ProtStore::Apple, "01ANYONE", true));
        assert!(!st.store_offered_to(v0::ProtStore::Apple, "01ANYONE", false));
        // Play closed: preview only, and still only with a configured client
        assert!(!st.store_offered_to(v0::ProtStore::Play, "01ANYONE", true));
        assert!(st.store_offered_to(v0::ProtStore::Play, "01PREVIEW", true));
        assert!(!st.store_offered_to(v0::ProtStore::Play, "01PREVIEW", false));
        assert!(st.is_preview("01PREVIEW"));
        assert!(!st.is_preview("01preview"));
        assert!(!st.is_tester("01PREVIEW"));
    }

    #[test]
    fn prot_store_closed_sells_and_credits_nothing() {
        let closed = ProtStoreSettings::closed();
        assert!(closed.credit_paused);
        assert!(closed.products.is_empty());
        assert!(closed.apple.is_none() && closed.play.is_none());
        assert_eq!(closed.test_max_prot, 0);
        for store in [v0::ProtStore::Apple, v0::ProtStore::Play] {
            assert!(!closed.store_offered_to(store, "01ANYONE", true));
        }
    }
}
