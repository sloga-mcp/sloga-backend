//! Validated payments settings, read from `[features.payments]` and `[api.stripe]`

use chrono::DateTime;
use revolt_config::{ApiStripe, FeaturePayments, Settings};
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
    /// and not RFC 3339, or `cipher_cap` is 0 or above [`CIPHER_CAP_MAX`].
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

        Ok(Self {
            enabled: payments.enabled,
            sales_open: payments.cipher_sales_open,
            cap,
            close_at_ms,
            expect_livemode: stripe.expect_livemode,
            tolerance_secs: stripe.tolerance_secs,
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
        };
        let s = PaymentsSettings::from_parts(&payments(500, ""), &stripe).unwrap();
        assert!(s.expect_livemode);
        assert_eq!(s.tolerance_secs, 42);
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
}
