use std::{
    collections::{HashMap, HashSet},
    sync::LazyLock,
};

use lettre::{
    message::Mailbox,
    transport::smtp::{authentication::Credentials, client::Tls},
    SmtpTransport,
};
use regex::Regex;
use revolt_config::{config, ApiSmtp};
use revolt_result::Result;

static SPLIT: LazyLock<Regex> = LazyLock::new(|| Regex::new("([^@]+)(@.+)").unwrap());
static SYMBOL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new("\\+.+|\\.").unwrap());
static HANDLEBARS: LazyLock<handlebars::Handlebars<'static>> =
    LazyLock::new(handlebars::Handlebars::new);
static REVOLT_SOURCE_LIST: LazyLock<HashSet<String>> = LazyLock::new(|| {
    include_str!("../../assets/revolt_source_list.txt")
        .split('\n')
        .map(|x| x.into())
        .collect()
});

/// Strip special characters and aliases from emails
pub fn normalise_email(original: String) -> String {
    // Total, never panicking: `login` normalises BEFORE it validates, so an
    // address with no "@" reached the unwrap below and answered the most-hit
    // unauthenticated route with a 500 (audit 2026-09-05 L3). There is nothing
    // to normalise in a string that is not an addr-spec — lower-case it and
    // let the caller's own validation reject it.
    let Some(split) = SPLIT.captures(&original) else {
        return original.to_lowercase();
    };
    let mut clean = SYMBOL_RE
        .replace_all(split.get(1).unwrap().as_str(), "")
        .to_string();

    clean.push_str(split.get(2).unwrap().as_str());
    clean.to_lowercase()
}

/// Domain of the address stored on an account that has no email
pub const NO_EMAIL_DOMAIN: &str = "noemail.invalid";

/// A fresh stand-in address for an account that has no email: 32 lower-case
/// hex characters from 128 random bits, at `NO_EMAIL_DOMAIN`.
///
/// Never derived from an id. The local part has no `.` or `+`, so
/// `normalise_email` leaves it as it is and it fits both unique indexes.
/// It never leaves the model: nothing is mailed to it and the API never
/// returns it.
pub fn generate_placeholder_email() -> String {
    format!("{:032x}@{}", rand::random::<u128>(), NO_EMAIL_DOMAIN)
}

/// The characters IDNA reads as the dot between two labels of a domain
const LABEL_DOTS: [char; 4] = ['.', '\u{3002}', '\u{FF0E}', '\u{FF61}'];

/// A domain in its IDNA to-ASCII form, the form the format check
/// (`validator::validate_email`) and a mail server read it in: fullwidth
/// letters become the ASCII letters they stand for, an ideographic full
/// stop becomes a dot, upper case becomes lower case.
///
/// A domain to-ASCII refuses as a whole is taken label by label, and a
/// label it refuses stays as it was written: one bad label must not hide
/// the labels next to it from the comparison.
fn ascii_domain(domain: &str) -> String {
    if let Ok(ascii) = idna::domain_to_ascii(domain) {
        return ascii;
    }

    domain
        .split(LABEL_DOTS)
        .map(|label| idna::domain_to_ascii(label).unwrap_or_else(|_| label.to_string()))
        .collect::<Vec<String>>()
        .join(".")
}

/// The domain of an address in the form it is compared in: trimmed, IDNA
/// to-ASCII (see `ascii_domain`), trailing dot dropped, lower-cased
fn address_domain(email: &str) -> Option<String> {
    let (_, domain) = email.trim().rsplit_once('@')?;
    Some(
        ascii_domain(domain)
            .trim_end_matches('.')
            .to_ascii_lowercase(),
    )
}

/// Whether this address is at `NO_EMAIL_DOMAIN`, the stand-in domain of an
/// account that has no email. Such an address is never looked up or mailed.
///
/// Exact: another `.invalid` address stored on an account is an ordinary
/// address. Use `is_invalid_tld_address` where a new address is taken in.
pub fn is_no_email_address(email: &str) -> bool {
    address_domain(email).is_some_and(|domain| domain == NO_EMAIL_DOMAIN)
}

/// Whether this address is anywhere under the reserved `.invalid` top-level
/// domain, the stand-in domain included. No such address is ever accepted
/// as a new address for an account.
pub fn is_invalid_tld_address(email: &str) -> bool {
    address_domain(email)
        .is_some_and(|domain| domain == "invalid" || domain.ends_with(".invalid"))
}

/// Email template
#[derive(Clone)]
pub struct Template {
    /// Title of the email
    pub title: String,
    /// Plain text version of this email
    pub text: String,
    /// HTML version of this email
    pub html: Option<String>,
    /// URL to redirect people to from the email
    ///
    /// Use `{{url}}` to fill this field.
    ///
    /// Any given URL will be suffixed with a unique token if applicable.
    ///
    /// e.g. `https://example.com?t=` becomes `https://example.com?t=UNIQUE_CODE`
    pub url: String,
}

/// Email templates
#[derive(Clone)]
pub struct Templates {
    /// Template for email verification
    pub verify: Template,
    /// Template for password reset
    pub reset: Template,
    /// Template for password reset when the account already exists on creation
    pub reset_existing: Template,
    /// Template for account deletion
    pub deletion: Template,
    /// Template sent when signing in cancels a pending account deletion
    ///
    /// Carries no token: its `url` is used as-is.
    pub deletion_cancelled: Template,
    /// Template for suspention
    pub suspension: Template,

    // Passkey sign-up and recovery. Send these with `send_email_safe`: the
    // first two go to an address anyone could have typed.
    /// The 8-digit code that confirms an email address, at passkey sign-up
    /// and at "add an email". Variables: `username`, `code`, `email` (the
    /// address being confirmed)
    pub email_code: Template,
    /// Sent instead of the code when a passkey sign-up names an address that
    /// already has an account. Variables: `email`, `url` (this template's
    /// `url`, the sign-in page)
    pub signup_existing: Template,
    /// The lost-passkey recovery link. Variables: `email`, `url` (this
    /// template's `url` followed by the one-time token)
    pub passkey_recovery: Template,
    /// Notice that a passkey was added to the account. Variables: `email`,
    /// `url` (this template's `url`, the sign-in page)
    pub passkey_added: Template,

    // Take It Down. Send these with `send_email_safe`, which also renders
    // the title. Variables: `reference`, plus `url` (received), `reason`
    // (partial, declined), `summary` and `deadline` (alert), `count`
    // (heartbeat). Only fixed text and the reference go in; never anything
    // the requester or uploader wrote.
    /// Takedown request received (to the requester); `url` is the status
    /// link, and this template's `url` field is the status page base
    pub takedown_received: Template,
    /// More information needed (to the requester)
    pub takedown_needs_info: Template,
    /// Content removed (to the requester)
    pub takedown_removed: Template,
    /// Some items could not be acted on (to the requester)
    pub takedown_partial: Template,
    /// Request declined (to the requester)
    pub takedown_declined: Template,
    /// Content removed (to the uploader)
    pub takedown_uploader: Template,
    /// Deadline or new-request alert (to staff)
    pub takedown_alert: Template,
    /// Alerting heartbeat (to staff)
    pub takedown_heartbeat: Template,
}

/// One set of takedown templates (see the `takedown_*` fields of `Templates`)
struct TakedownTemplates {
    received: Template,
    needs_info: Template,
    removed: Template,
    partial: Template,
    declined: Template,
    uploader: Template,
    alert: Template,
    heartbeat: Template,
}

/// Short stand-ins for tests, with the same variables as the real ones
fn takedown_test_templates(status_url_base: &str) -> TakedownTemplates {
    let template = |title: &str, text: &str| Template {
        title: title.into(),
        text: text.into(),
        url: "".into(),
        html: None,
    };

    TakedownTemplates {
        received: Template {
            url: status_url_base.into(),
            ..template("takedown_received", "[[{{{reference}}}]] {{{url}}}")
        },
        needs_info: template("takedown_needs_info", "[[{{{reference}}}]]"),
        removed: template("takedown_removed", "[[{{{reference}}}]]"),
        partial: template("takedown_partial", "[[{{{reference}}}]] {{{reason}}}"),
        declined: template("takedown_declined", "[[{{{reference}}}]] {{{reason}}}"),
        uploader: template("takedown_uploader", "[[{{{reference}}}]]"),
        alert: template(
            "takedown_alert",
            "[[{{{reference}}}]] {{{summary}}} {{{deadline}}}",
        ),
        heartbeat: template("takedown_heartbeat", "[[{{{count}}}]]"),
    }
}

/// The Sloga takedown templates (production and whitelabel share them)
fn takedown_sloga_templates(status_url_base: &str) -> TakedownTemplates {
    TakedownTemplates {
        received: Template {
            title: "Take It Down request {{{reference}}}: received".into(),
            text: include_str!("../../templates/takedown-received.txt").into(),
            url: status_url_base.into(),
            html: Some(include_str!("../../templates/takedown-received.html").into()),
        },
        needs_info: Template {
            title: "Take It Down request {{{reference}}}: more information needed".into(),
            text: include_str!("../../templates/takedown-needs-info.txt").into(),
            url: "".into(),
            html: Some(include_str!("../../templates/takedown-needs-info.html").into()),
        },
        removed: Template {
            title: "Take It Down request {{{reference}}}: content removed".into(),
            text: include_str!("../../templates/takedown-removed.txt").into(),
            url: "".into(),
            html: Some(include_str!("../../templates/takedown-removed.html").into()),
        },
        partial: Template {
            title: "Take It Down request {{{reference}}}: update".into(),
            text: include_str!("../../templates/takedown-partial.txt").into(),
            url: "".into(),
            html: Some(include_str!("../../templates/takedown-partial.html").into()),
        },
        declined: Template {
            title: "Take It Down request {{{reference}}}: decision".into(),
            text: include_str!("../../templates/takedown-declined.txt").into(),
            url: "".into(),
            html: Some(include_str!("../../templates/takedown-declined.html").into()),
        },
        uploader: Template {
            title: "Content you shared on Sloga was removed".into(),
            text: include_str!("../../templates/takedown-uploader.txt").into(),
            url: "".into(),
            html: Some(include_str!("../../templates/takedown-uploader.html").into()),
        },
        alert: Template {
            title: "Take It Down {{{reference}}}: {{{summary}}}".into(),
            text: include_str!("../../templates/takedown-alert.txt").into(),
            url: "".into(),
            html: None,
        },
        heartbeat: Template {
            title: "Take It Down queue: {{{count}}} open".into(),
            text: include_str!("../../templates/takedown-heartbeat.txt").into(),
            url: "".into(),
            html: None,
        },
    }
}

/// The passkey sign-up and recovery templates (see the fields of the same
/// names on `Templates`)
struct PasskeyTemplates {
    email_code: Template,
    signup_existing: Template,
    passkey_recovery: Template,
    passkey_added: Template,
}

/// Short stand-ins for tests, with the same variables as the real ones. The
/// code and the recovery token come first in `[[...]]`, where
/// `TestHarness::assert_email` reads them; the urls stay empty for the same
/// reason as the deletion ones.
fn passkey_test_templates() -> PasskeyTemplates {
    let template = |title: &str, text: &str| Template {
        title: title.into(),
        text: text.into(),
        url: "".into(),
        html: None,
    };

    PasskeyTemplates {
        email_code: template("email_code", "[[{{{code}}}]] {{{username}}} {{{email}}}"),
        signup_existing: template("signup_existing", "[[{{{url}}}]] {{{email}}}"),
        passkey_recovery: template("passkey_recovery", "[[{{{url}}}]] {{{email}}}"),
        passkey_added: template("passkey_added", "[[{{{url}}}]] {{{email}}}"),
    }
}

// wording: draft, owner approval pending
const EMAIL_CODE_TEXT: &str = "Someone is creating or changing a Sloga account named {{{username}}} with this email address.

Confirmation code: {{{code}}}

Type this code into Sloga to confirm the address. It works for 15 minutes.

If this was not you, ignore this email. Nothing happens without the code.

This email is intended for {{{email}}}
Sent by Sloga

Sloga Technologies LLC
";

// wording: draft, owner approval pending
const SIGNUP_EXISTING_TEXT: &str = "Someone tried to create a Sloga account with this email address, but it already has one.

If this was you, sign in instead: {{{url}}}

If this was not you, ignore this email. Nothing was changed.

This email is intended for {{{email}}}
Sent by Sloga

Sloga Technologies LLC
";

// wording: draft, owner approval pending
const PASSKEY_RECOVERY_TEXT: &str = "Someone asked to get back into the Sloga account for this email address because its passkey was lost.

Open this link to create a new passkey. It works once, for 30 minutes:

{{{url}}}

Creating the new passkey removes every other passkey on the account and signs out every device.

If this was not you, ignore this email. Nothing happens unless the link is used.

This email is intended for {{{email}}}
Sent by Sloga

Sloga Technologies LLC
";

// wording: draft, owner approval pending
const PASSKEY_ADDED_TEXT: &str = "A passkey was added to your Sloga account. A passkey can be used to sign in.

If this was you, there is nothing to do.

If this was not you, sign in and remove the passkey under Settings: {{{url}}}
Then write to support@sloga.gg.

This email is intended for {{{email}}}
Sent by Sloga

Sloga Technologies LLC
";

/// The Sloga passkey templates (production and whitelabel share them).
/// Text only for now. `app` is `hosts.app`.
fn passkey_sloga_templates(app: &str) -> PasskeyTemplates {
    PasskeyTemplates {
        // wording: draft, owner approval pending
        email_code: Template {
            title: "Your Sloga confirmation code".into(),
            text: EMAIL_CODE_TEXT.into(),
            url: "".into(),
            html: None,
        },
        // wording: draft, owner approval pending
        signup_existing: Template {
            title: "You already have a Sloga account".into(),
            text: SIGNUP_EXISTING_TEXT.into(),
            url: format!("{}/login", app),
            html: None,
        },
        // wording: draft, owner approval pending
        passkey_recovery: Template {
            title: "Create a new passkey for your Sloga account".into(),
            text: PASSKEY_RECOVERY_TEXT.into(),
            url: format!("{}/login/passkey/recover/", app),
            html: None,
        },
        // wording: draft, owner approval pending
        passkey_added: Template {
            title: "A passkey was added to your Sloga account".into(),
            text: PASSKEY_ADDED_TEXT.into(),
            url: format!("{}/login", app),
            html: None,
        },
    }
}

pub async fn email_templates() -> Templates {
    let config = config().await;
    let status_url_base = &config.features.takedown.status_url_base;

    build_templates(
        std::env::var("TEST_DB").is_ok(),
        config.production,
        &config.hosts.app,
        status_url_base,
    )
}

/// Pick the template set: the test stubs when `TEST_DB` is set, otherwise the
/// production or whitelabel set. `app` is `hosts.app`; `status_url_base` is
/// `features.takedown.status_url_base`. Split out of `email_templates` so
/// every branch can be unit tested without the config.
fn build_templates(test: bool, production: bool, app: &str, status_url_base: &str) -> Templates {
    if test {
        let takedown = takedown_test_templates(status_url_base);
        let passkey = passkey_test_templates();

        Templates {
            verify: Template {
                title: "verify".into(),
                text: "[[{{url}}]]".into(),
                url: "".into(),
                html: None,
            },
            reset: Template {
                title: "reset".into(),
                text: "[[{{url}}]]".into(),
                url: "".into(),
                html: None,
            },
            reset_existing: Template {
                title: "reset_existing".into(),
                text: "[[{{url}}]]".into(),
                url: "".into(),
                html: None,
            },
            // Test urls stay empty: `TestHarness::assert_email` pulls the
            // token out of `[[...]]` and only accepts `[A-Za-z0-9_-]`, so a
            // host prefix would break every token-reading test.
            deletion: Template {
                title: "deletion".into(),
                text: "[[{{url}}]]".into(),
                url: "".into(),
                html: None,
            },
            // No token, so the mail body renders as `[[]]` (an empty code).
            deletion_cancelled: Template {
                title: "deletion_cancelled".into(),
                text: "[[{{url}}]]".into(),
                url: "".into(),
                html: None,
            },
            suspension: Template {
                title: "suspension".into(),
                text: "[[dummy]]".into(),
                url: "".into(),
                html: None,
            },
            email_code: passkey.email_code,
            signup_existing: passkey.signup_existing,
            passkey_recovery: passkey.passkey_recovery,
            passkey_added: passkey.passkey_added,
            takedown_received: takedown.received,
            takedown_needs_info: takedown.needs_info,
            takedown_removed: takedown.removed,
            takedown_partial: takedown.partial,
            takedown_declined: takedown.declined,
            takedown_uploader: takedown.uploader,
            takedown_alert: takedown.alert,
            takedown_heartbeat: takedown.heartbeat,
        }
    } else if production {
        let takedown = takedown_sloga_templates(status_url_base);
        let passkey = passkey_sloga_templates(app);

        Templates {
            verify: Template {
                title: "Verify your Sloga account.".into(),
                text: include_str!("../../templates/verify.txt").into(),
                url: format!("{}/login/verify/", app),
                html: Some(include_str!("../../templates/verify.html").into()),
            },
            reset: Template {
                title: "Reset your Sloga password.".into(),
                text: include_str!("../../templates/reset.txt").into(),
                url: format!("{}/login/reset/", app),
                html: Some(include_str!("../../templates/reset.html").into()),
            },
            reset_existing: Template {
                title: "You already have a Sloga account, reset your password.".into(),
                text: include_str!("../../templates/reset-existing.txt").into(),
                url: format!("{}/login/reset/", app),
                html: Some(include_str!("../../templates/reset-existing.html").into()),
            },
            deletion: Template {
                title: "Confirm your Sloga account deletion".into(),
                text: include_str!("../../templates/deletion.txt").into(),
                url: format!("{}/login/delete/", app),
                html: Some(include_str!("../../templates/deletion.html").into()),
            },
            deletion_cancelled: Template {
                title: "Your Sloga account was restored".into(),
                text: include_str!("../../templates/deletion-cancelled.txt").into(),
                url: format!("{}/login", app),
                html: Some(include_str!("../../templates/deletion-cancelled.html").into()),
            },
            suspension: Template {
                title: "Account Suspension".to_string(),
                html: Some(include_str!("../../templates/suspension.html").to_owned()),
                text: include_str!("../../templates/suspension.txt").to_owned(),
                url: Default::default(),
            },
            email_code: passkey.email_code,
            signup_existing: passkey.signup_existing,
            passkey_recovery: passkey.passkey_recovery,
            passkey_added: passkey.passkey_added,
            takedown_received: takedown.received,
            takedown_needs_info: takedown.needs_info,
            takedown_removed: takedown.removed,
            takedown_partial: takedown.partial,
            takedown_declined: takedown.declined,
            takedown_uploader: takedown.uploader,
            takedown_alert: takedown.alert,
            takedown_heartbeat: takedown.heartbeat,
        }
    } else {
        let takedown = takedown_sloga_templates(status_url_base);
        let passkey = passkey_sloga_templates(app);

        Templates {
            verify: Template {
                title: "Verify your account.".into(),
                text: include_str!("../../templates/verify.whitelabel.txt").into(),
                url: format!("{}/login/verify/", app),
                // The .whitelabel.txt above stays the plain-text alternative; the
                // HTML part carries the Sloga logo. Both templates are branded and
                // their legal footer names Sloga Technologies LLC. suspension
                // stays text-only -- its .html still carries the upstream Revolt
                // Platforms Ltd. footer, so do NOT wire it up without fixing that
                // first. deletion and deletion_cancelled are also text-only here;
                // their .html is Sloga-branded and could be wired up later.
                html: Some(include_str!("../../templates/verify.html").into()),
            },
            reset: Template {
                title: "Reset your password.".into(),
                text: include_str!("../../templates/reset.whitelabel.txt").into(),
                url: format!("{}/login/reset/", app),
                html: Some(include_str!("../../templates/reset.html").into()),
            },
            reset_existing: Template {
                title: "Reset your password.".into(),
                text: include_str!("../../templates/reset.whitelabel.txt").into(),
                url: format!("{}/login/reset/", app),
                html: Some(include_str!("../../templates/reset-existing.html").into()),
            },
            deletion: Template {
                title: "Confirm your Sloga account deletion".into(),
                text: include_str!("../../templates/deletion.whitelabel.txt").into(),
                url: format!("{}/login/delete/", app),
                html: None,
            },
            deletion_cancelled: Template {
                title: "Your Sloga account was restored".into(),
                text: include_str!("../../templates/deletion-cancelled.whitelabel.txt").into(),
                url: format!("{}/login", app),
                html: None,
            },
            suspension: Template {
                title: "Account Suspension".to_string(),
                text: include_str!("../../templates/suspension.whitelabel.txt").to_owned(),
                url: Default::default(),
                html: None,
            },
            email_code: passkey.email_code,
            signup_existing: passkey.signup_existing,
            passkey_recovery: passkey.passkey_recovery,
            passkey_added: passkey.passkey_added,
            takedown_received: takedown.received,
            takedown_needs_info: takedown.needs_info,
            takedown_removed: takedown.removed,
            takedown_partial: takedown.partial,
            takedown_declined: takedown.declined,
            takedown_uploader: takedown.uploader,
            takedown_alert: takedown.alert,
            takedown_heartbeat: takedown.heartbeat,
        }
    }
}

/// Create SMTP transport
pub fn create_transport(smtp: &ApiSmtp) -> SmtpTransport {
    let relay = if smtp.use_starttls == Some(true) {
        SmtpTransport::starttls_relay(&smtp.host).unwrap()
    } else {
        SmtpTransport::relay(&smtp.host).unwrap()
    };

    let relay = if let Some(port) = smtp.port {
        relay.port(port.try_into().unwrap())
    } else {
        relay
    };

    let relay = if smtp.use_tls == Some(false) {
        relay.tls(Tls::None)
    } else {
        relay
    };

    relay
        .credentials(Credentials::new(
            smtp.username.clone(),
            smtp.password.clone(),
        ))
        .build()
}

/// Render an email template
fn render_template(text: &str, variables: &handlebars::JsonValue) -> Result<String> {
    HANDLEBARS
        .render_template(text, variables)
        .map_err(|_| create_error!(RenderFail))
}

/// Send an email
pub fn send_email(
    smtp: &ApiSmtp,
    address: String,
    template: &Template,
    variables: handlebars::JsonValue,
) -> Result<()> {
    let m = lettre::Message::builder()
        .from(smtp.from_address.parse().expect("valid `smtp_from`"))
        .to(address.parse().expect("valid `smtp_to`"))
        .subject(template.title.clone());

    let m = if let Some(reply_to) = &smtp.reply_to {
        m.reply_to(reply_to.parse().expect("valid `smtp_reply_to`"))
    } else {
        m
    };

    let text = render_template(&template.text, &variables).expect("valid `template`");

    let m = if let Some(html) = &template.html {
        m.multipart(lettre::message::MultiPart::alternative_plain_html(
            text,
            render_template(html, &variables).expect("valid `template`"),
        ))
    } else {
        m.body(text)
    }
    .expect("valid `message`");

    use lettre::Transport;
    let sender = create_transport(smtp);

    match sender.send(&m) {
        Ok(_) => Ok(()),
        Err(error) => {
            error!(
                "Failed to send email to {}!\nlettre error: {}",
                address, error
            );

            revolt_config::capture_error(&error);

            Err(create_error!(EmailFailed))
        }
    }
}

/// Longest recipient address `send_email_safe` accepts
const MAX_SAFE_ADDRESS_LEN: usize = 254;

/// `reason` for `takedown_partial`
pub const TAKEDOWN_PARTIAL_REASON: &str =
    "Some of the items you listed point to messages we have no stored copy of, for example deleted messages or end-to-end encrypted conversations, which Sloga cannot read. Someone in the conversation can report the message in the app.";
/// `reason` for `takedown_declined`, per decline reason
pub const TAKEDOWN_DECLINE_NOT_INTIMATE: &str =
    "It does not appear to be an intimate image as defined by the Take It Down Act.";
pub const TAKEDOWN_DECLINE_NOT_FOUND: &str =
    "We could not find the content on Sloga from the information provided.";
pub const TAKEDOWN_DECLINE_NOT_ON_SLOGA: &str =
    "The content does not appear to be hosted on Sloga.";
pub const TAKEDOWN_DECLINE_DUPLICATE: &str = "It was already handled under another request.";
pub const TAKEDOWN_DECLINE_OTHER: &str = "It did not meet the requirements for removal.";

/// The address, trimmed, if it parses as an addr-spec (no display name)
fn parse_safe_address(address: &str) -> Result<lettre::Address> {
    let address = address.trim();
    if address.is_empty() || address.len() > MAX_SAFE_ADDRESS_LEN {
        return Err(create_error!(InvalidOperation));
    }

    address
        .parse::<lettre::Address>()
        .map_err(|_| create_error!(InvalidOperation))
}

/// Send an email to an address anyone could have typed, without panicking
/// and without blocking the async runtime.
///
/// The address only has to parse as an address (format only: unlike
/// `validate_email`, no disposable-domain list), else `InvalidOperation`.
/// With no SMTP host configured nothing is sent and the result is `Ok`. The
/// title and both bodies are rendered with `variables`. Unlike `send_email`,
/// nothing logged or reported names the recipient.
pub async fn send_email_safe(
    address: &str,
    template: &Template,
    variables: HashMap<&'static str, String>,
) -> Result<()> {
    let to = parse_safe_address(address)?;

    let config = config().await;
    if config.api.smtp.host.is_empty() {
        return Ok(());
    }

    let smtp = config.api.smtp.clone();
    let template = template.clone();
    let variables = serde_json::to_value(variables).map_err(|_| create_error!(InternalError))?;

    tokio::task::spawn_blocking(move || deliver_safe(&smtp, to, &template, &variables))
        .await
        .map_err(|_| create_error!(InternalError))?
}

/// Build and send one message for `send_email_safe`. Bad config or a bad
/// template is an error, not a panic, and the log line carries only the SMTP
/// status: the server's reply text can quote the recipient.
fn deliver_safe(
    smtp: &ApiSmtp,
    to: lettre::Address,
    template: &Template,
    variables: &handlebars::JsonValue,
) -> Result<()> {
    let from = smtp.from_address.parse::<Mailbox>().map_err(|_| {
        error!("`smtp.from_address` is not a valid mailbox");
        create_error!(InternalError)
    })?;

    let builder = lettre::Message::builder()
        .from(from)
        .to(Mailbox::new(None, to))
        .subject(render_template(&template.title, variables)?);

    let builder = match &smtp.reply_to {
        Some(reply_to) => builder.reply_to(reply_to.parse::<Mailbox>().map_err(|_| {
            error!("`smtp.reply_to` is not a valid mailbox");
            create_error!(InternalError)
        })?),
        None => builder,
    };

    let text = render_template(&template.text, variables)?;
    let message = match &template.html {
        Some(html) => builder.multipart(lettre::message::MultiPart::alternative_plain_html(
            text,
            render_template(html, variables)?,
        )),
        None => builder.body(text),
    }
    .map_err(|_| create_error!(InternalError))?;

    use lettre::Transport;
    create_transport(smtp)
        .send(&message)
        .map(|_| ())
        .map_err(|error| {
            error!(
                "Failed to send an email (smtp status {}, transient {}, permanent {})",
                error
                    .status()
                    .map_or_else(|| "none".to_string(), |code| code.to_string()),
                error.is_transient(),
                error.is_permanent(),
            );
            create_error!(EmailFailed)
        })
}

/// Checks an address that is about to be STORED on an account (sign-up,
/// change email, add email). Refuses every `.invalid` address.
pub fn validate_email(email: &str) -> Result<()> {
    check_email(email, is_invalid_tld_address)
}

/// Checks an address that is only used to FIND an account (password reset
/// send, resend verification). Same format and blocklist checks as
/// `validate_email`, but only the stand-in domain is refused: an account
/// that already stores another `.invalid` address must still be found.
pub fn validate_lookup_email(email: &str) -> Result<()> {
    check_email(email, is_no_email_address)
}

fn check_email(email: &str, reserved: fn(&str) -> bool) -> Result<()> {
    // Make sure this is an actual email
    if !validator::validate_email(email) {
        return Err(create_error!(IncorrectData {
            with: "email".to_string()
        }));
    }

    // `noemail.invalid` is where accounts with no email keep their stand-in
    // address; nobody may type one in
    if reserved(email) {
        return Err(create_error!(IncorrectData {
            with: "email".to_string()
        }));
    }

    // Check if the email is blacklisted
    if let Some(domain) = email.split('@').next_back() {
        if REVOLT_SOURCE_LIST.contains(&domain.to_string()) {
            return Err(create_error!(Blacklisted));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{build_templates, render_template};
    use serde_json::json;

    const SUSPENSION: &str = include_str!("../../templates/suspension.whitelabel.txt");
    const APP: &str = "https://app.example.test";
    const STATUS: &str = "https://site.example.test/take-it-down-status.html";

    #[test]
    fn deletion_emails_link_to_the_login_confirm_page() {
        // production, then whitelabel
        for production in [true, false] {
            let templates = build_templates(false, production, APP, STATUS);

            // The frontend route is /login/delete/:token; the bare /delete/
            // the upstream template built never resolved.
            assert_eq!(
                templates.deletion.url,
                format!("{APP}/login/delete/"),
                "production = {production}"
            );
            assert_eq!(
                templates.deletion_cancelled.url,
                format!("{APP}/login"),
                "production = {production}"
            );

            for template in [&templates.deletion, &templates.deletion_cancelled] {
                assert!(template.text.contains("{{url}}"), "production = {production}");
                assert!(template.text.contains("{{email}}"), "production = {production}");
                assert!(!template.text.contains("Revolt"), "production = {production}");
                if let Some(html) = &template.html {
                    assert!(html.contains("href=\"{{url}}\""), "production = {production}");
                    assert!(!html.contains("Revolt"), "production = {production}");
                }
            }

            // html only where the deletion email already had it
            assert_eq!(
                templates.deletion.html.is_some(),
                templates.deletion_cancelled.html.is_some()
            );
            assert_eq!(templates.deletion.html.is_some(), production);
        }
    }

    #[test]
    fn deletion_email_copy_states_it_is_final_and_how_to_cancel() {
        for production in [true, false] {
            let templates = build_templates(false, production, APP, STATUS);
            let token_url = format!("{}TOKEN", templates.deletion.url);
            let vars = json!({ "email": "a@example.com", "url": token_url });

            let mut bodies = vec![render_template(&templates.deletion.text, &vars).unwrap()];
            if let Some(html) = &templates.deletion.html {
                bodies.push(render_template(html, &vars).unwrap());
            }

            for body in bodies {
                assert!(body.contains("/login/delete/TOKEN"), "{body}");
                assert!(body.contains("a@example.com"), "{body}");
                assert!(body.contains("Delete permanently"), "{body}");
                assert!(body.contains("no going back"), "{body}");
                assert!(body.contains("24 hours"), "{body}");
                assert!(body.contains("sign in to Sloga before you use the link"), "{body}");
                assert!(body.contains("change your password"), "{body}");
            }
        }
    }

    #[test]
    fn deletion_cancelled_email_renders_with_email_and_url_only() {
        for production in [true, false] {
            let templates = build_templates(false, production, APP, STATUS);
            let template = &templates.deletion_cancelled;
            let vars = json!({ "email": "a@example.com", "url": template.url });

            let mut bodies = vec![render_template(&template.text, &vars).unwrap()];
            if let Some(html) = &template.html {
                bodies.push(render_template(html, &vars).unwrap());
            }

            for body in bodies {
                assert!(body.contains("restored"), "{body}");
                assert!(body.contains("Nothing was deleted."), "{body}");
                assert!(body.contains("change your password right away"), "{body}");
                assert!(body.contains("Open Sloga"), "{body}");
                assert!(body.contains("https:&#x2F;&#x2F;app.example.test&#x2F;login")
                    || body.contains("https://app.example.test/login"), "{body}");
                assert!(body.contains("a@example.com"), "{body}");
            }
        }
    }

    #[test]
    fn test_db_templates_keep_token_only_urls() {
        // `TestHarness::assert_email` reads the token out of `[[...]]` and only
        // accepts `[A-Za-z0-9_-]`, so the TEST_DB urls must stay empty.
        let templates = build_templates(true, false, APP, STATUS);

        assert_eq!(templates.deletion.url, "");
        assert_eq!(templates.deletion_cancelled.url, "");
        assert_eq!(templates.deletion_cancelled.text, "[[{{url}}]]");
        assert_eq!(templates.deletion_cancelled.title, "deletion_cancelled");
        assert_eq!(templates.takedown_received.url, STATUS);
    }

    #[test]
    fn suspension_email_states_duration_and_how_to_appeal() {
        let text = render_template(
            SUSPENSION,
            &json!({ "email": "a@example.com", "list": "Spam", "duration": 7 }),
        )
        .unwrap();

        assert!(text.contains("again in 7 days."));
        assert!(!text.contains("no end date"));
        assert!(text.contains("https://sloga.gg/legal/guidelines.html"));
        assert!(text.contains("support@sloga.gg"));
        assert!(text.contains("within 72 hours"));
    }

    #[test]
    fn suspension_email_without_duration_has_no_end_date() {
        let text = render_template(
            SUSPENSION,
            &json!({ "email": "a@example.com", "list": "Spam", "duration": null }),
        )
        .unwrap();

        assert!(text.contains("This suspension has no end date."));
        assert!(!text.contains("again in"));
    }
}

#[cfg(test)]
mod placeholder_tests {
    use std::collections::HashSet;

    use revolt_result::ErrorType;

    use super::{
        generate_placeholder_email, is_invalid_tld_address, is_no_email_address, normalise_email,
        validate_email, validate_lookup_email, NO_EMAIL_DOMAIN,
    };

    /// Fails if: the stand-in address is not 32 lower-case hex characters at
    /// `noemail.invalid`, is changed by `normalise_email`, or repeats.
    #[test]
    fn a_placeholder_is_32_hex_characters_and_never_repeats() {
        let mut seen = HashSet::new();

        for _ in 0..500 {
            let placeholder = generate_placeholder_email();
            let (local, domain) = placeholder.split_once('@').expect("an address");

            assert_eq!(domain, "noemail.invalid", "{placeholder}");
            assert_eq!(domain, NO_EMAIL_DOMAIN);
            assert_eq!(local.len(), 32, "{placeholder}");
            assert!(
                local
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                "{placeholder}"
            );

            // Stored in `email` and `email_normalised` alike
            assert_eq!(normalise_email(placeholder.clone()), placeholder);
            assert!(is_no_email_address(&placeholder));
            assert!(is_invalid_tld_address(&placeholder));
            assert!(seen.insert(placeholder), "a placeholder repeated");
        }
    }

    /// Addresses at the stand-in domain, however they are written
    const AT_THE_STAND_IN_DOMAIN: [&str; 9] = [
        "0123456789abcdef0123456789abcdef@noemail.invalid",
        "someone@noemail.invalid",
        "someone@NoEmail.INVALID",
        "someone@noemail.invalid.",
        "  someone@noemail.invalid\n",
        // Spellings IDNA reads as the stand-in domain: an ideographic full
        // stop (U+3002) for the dot, in the middle and at the end, a
        // fullwidth full stop (U+FF0E), fullwidth letters
        "x@noemail\u{3002}invalid",
        "x@noemail.invalid\u{3002}",
        "x@noemail\u{FF0E}invalid",
        "x@\u{FF4E}\u{FF4F}\u{FF45}\u{FF4D}\u{FF41}\u{FF49}\u{FF4C}.invalid",
    ];

    /// Addresses under `.invalid` that are not at the stand-in domain
    const ELSEWHERE_UNDER_INVALID: [&str; 9] = [
        "someone@other.invalid",
        "tester@sloga.invalid",
        "someone@Sloga.INVALID",
        "someone@invalid",
        "someone@sub.noemail.invalid",
        "someone@xnoemail.invalid",
        // `sloga.invalid` with the top-level domain in fullwidth letters
        "new@sloga.\u{FF49}\u{FF4E}\u{FF56}\u{FF41}\u{FF4C}\u{FF49}\u{FF44}",
        "new@sloga\u{3002}invalid",
        // A label IDNA refuses (it starts with a combining mark) next to
        // the reserved one
        "someone@\u{301}bad\u{3002}invalid",
    ];

    const NOT_UNDER_INVALID: [&str; 12] = [
        "someone@example.com",
        "invalid@example.com",
        "noemail.invalid@example.com",
        "someone@invalid.example.com",
        "someone@notinvalid",
        "someone@example.invalidx",
        "noemail.invalid",
        "Deleted User 01ACCOUNT",
        "",
        // Real domains outside ASCII, and the reserved word as a label
        // that is not the last one
        "someone@b\u{FC}cher.example",
        "someone@invalid\u{3002}example.com",
        "someone@\u{FF49}\u{FF4E}\u{FF56}\u{FF41}\u{FF4C}\u{FF49}\u{FF44}.example.com",
    ];

    /// Fails if: `address_domain` compares the domain as it was typed, so a
    /// spelling the format check and a mail server read as `.invalid`
    /// (fullwidth letters, an ideographic full stop) passes for an ordinary
    /// address; or a plain ASCII domain no longer comes back as it was.
    #[test]
    fn the_domain_is_compared_in_its_ascii_form() {
        use super::address_domain;

        for (address, domain) in [
            (
                "new@sloga.\u{FF49}\u{FF4E}\u{FF56}\u{FF41}\u{FF4C}\u{FF49}\u{FF44}",
                "sloga.invalid",
            ),
            ("x@noemail\u{3002}invalid", "noemail.invalid"),
            ("x@NoEmail\u{FF0E}INVALID\u{3002}", "noemail.invalid"),
            ("someone@Example.COM.", "example.com"),
            ("someone@b\u{FC}cher.example", "xn--bcher-kva.example"),
        ] {
            assert_eq!(address_domain(address).as_deref(), Some(domain), "{address:?}");
        }

        assert_eq!(address_domain("no at sign"), None);
    }

    /// Fails if: the exact predicate matches a `.invalid` address outside
    /// the stand-in domain (an account storing one would lose its email
    /// again), is case sensitive, or misses a way of writing the stand-in
    /// domain, a non-ASCII spelling of it included.
    #[test]
    fn the_exact_predicate_matches_the_stand_in_domain_and_nothing_else() {
        for placeholder in AT_THE_STAND_IN_DOMAIN {
            assert!(is_no_email_address(placeholder), "{placeholder:?}");
        }

        for ordinary in ELSEWHERE_UNDER_INVALID.iter().chain(&NOT_UNDER_INVALID) {
            assert!(!is_no_email_address(ordinary), "{ordinary:?}");
        }
    }

    /// Fails if: the broad predicate stops at the exact stand-in domain, is
    /// case sensitive, or starts matching real domains.
    #[test]
    fn the_broad_predicate_matches_every_invalid_address_and_nothing_else() {
        for reserved in AT_THE_STAND_IN_DOMAIN.iter().chain(&ELSEWHERE_UNDER_INVALID) {
            assert!(is_invalid_tld_address(reserved), "{reserved:?}");
        }

        for real in NOT_UNDER_INVALID {
            assert!(!is_invalid_tld_address(real), "{real:?}");
        }
    }

    /// Fails if: `validate_lookup_email` accepts a stand-in address, refuses
    /// another `.invalid` address (the account storing one could no longer
    /// ask for a reset mail), or drops the format check.
    #[test]
    fn validate_lookup_email_refuses_only_the_stand_in_domain() {
        for refused in [
            generate_placeholder_email(),
            "someone@noemail.invalid".to_string(),
            "someone@NOEMAIL.INVALID".to_string(),
            "x@noemail\u{3002}invalid".to_string(),
            "not an address".to_string(),
        ] {
            let error = validate_lookup_email(&refused).expect_err("must be refused");
            assert!(
                matches!(error.error_type, ErrorType::IncorrectData { .. }),
                "{refused}: {:?}",
                error.error_type
            );
        }

        for accepted in ["tester@sloga.invalid", "someone@other.invalid", "someone@sloga.gg"] {
            validate_lookup_email(accepted).expect(accepted);
        }

        // The control: the same addresses as new addresses
        validate_email("tester@sloga.invalid").expect_err("a new .invalid address");
        validate_email("someone@other.invalid").expect_err("a new .invalid address");
    }

    /// Fails if: `validate_email` accepts an address nobody may type in.
    #[test]
    fn validate_email_refuses_every_invalid_address() {
        for refused in [
            generate_placeholder_email(),
            "someone@noemail.invalid".to_string(),
            "someone@NOEMAIL.INVALID".to_string(),
            "someone@other.invalid".to_string(),
            "new@sloga.\u{FF49}\u{FF4E}\u{FF56}\u{FF41}\u{FF4C}\u{FF49}\u{FF44}".to_string(),
            "x@noemail\u{3002}invalid".to_string(),
        ] {
            let error = validate_email(&refused).expect_err("must be refused");
            assert!(
                matches!(error.error_type, ErrorType::IncorrectData { .. }),
                "{refused}: {:?}",
                error.error_type
            );
        }

        // The control: an ordinary address still passes
        validate_email("someone@sloga.gg").expect("an ordinary address");
    }
}

#[cfg(test)]
mod passkey_template_tests {
    use std::collections::BTreeSet;

    use regex::Regex;
    use serde_json::json;

    use super::{
        build_templates, passkey_sloga_templates, passkey_test_templates, render_template,
        PasskeyTemplates, Template,
    };

    const APP: &str = "https://app.example.test";
    const STATUS: &str = "https://site.example.test/take-it-down-status.html";

    impl PasskeyTemplates {
        fn all(&self) -> [&Template; 4] {
            [
                &self.email_code,
                &self.signup_existing,
                &self.passkey_recovery,
                &self.passkey_added,
            ]
        }
    }

    fn variable_names(template: &Template) -> BTreeSet<String> {
        let re = Regex::new(r"\{\{\{?\s*([A-Za-z_]+)\s*\}?\}\}").unwrap();
        [&template.title, &template.text]
            .into_iter()
            .chain(template.html.as_ref())
            .flat_map(|source| {
                re.captures_iter(source)
                    .map(|capture| capture[1].to_string())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Fails if: a test stand-in drifts from the variables the real template
    /// fills, or a template leaves a variable unrendered.
    #[test]
    fn test_templates_use_the_real_variables_and_everything_renders() {
        let real = passkey_sloga_templates(APP);
        let test = passkey_test_templates();
        let variables = json!({
            "username": "alice",
            "code": "01234567",
            "email": "alice@example.test",
            "url": "https://app.example.test/login/passkey/recover/TOKEN",
        });

        for (real, test) in real.all().into_iter().zip(test.all()) {
            assert_eq!(variable_names(real), variable_names(test), "{}", test.title);
            assert!(!variable_names(real).is_empty());

            for template in [real, test] {
                for source in [&template.title, &template.text] {
                    let rendered = render_template(source, &variables).unwrap();
                    assert!(!rendered.contains("{{") && !rendered.contains("}}"));
                }
            }
        }
    }

    /// Fails if: the code mail loses the code, the username or the address,
    /// or stops saying what to do when it was not you.
    #[test]
    fn the_code_mail_names_the_username_the_code_and_the_address() {
        let template = passkey_sloga_templates(APP).email_code;
        let text = render_template(
            &template.text,
            &json!({ "username": "alice", "code": "01234567", "email": "a+b@example.test" }),
        )
        .unwrap();

        assert!(text.contains("named alice"), "{text}");
        assert!(text.contains("Confirmation code: 01234567"), "{text}");
        assert!(text.contains("intended for a+b@example.test"), "{text}");
        assert!(text.contains("If this was not you, ignore this email."), "{text}");
        // The code is not in the subject, where a lock screen would show it
        assert!(!template.title.contains("{{"), "{}", template.title);
    }

    /// Fails if: the links move, or the TEST_DB stand-ins gain a url prefix
    /// (`TestHarness::assert_email` reads a bare token out of `[[...]]`).
    #[test]
    fn the_links_point_at_the_app_and_test_urls_stay_empty() {
        for production in [true, false] {
            let templates = build_templates(false, production, APP, STATUS);
            assert_eq!(templates.email_code.url, "");
            assert_eq!(templates.signup_existing.url, format!("{APP}/login"));
            assert_eq!(
                templates.passkey_recovery.url,
                format!("{APP}/login/passkey/recover/")
            );
            assert_eq!(templates.passkey_added.url, format!("{APP}/login"));
        }

        let templates = build_templates(true, false, APP, STATUS);
        for template in [
            &templates.email_code,
            &templates.signup_existing,
            &templates.passkey_recovery,
            &templates.passkey_added,
        ] {
            assert_eq!(template.url, "", "{}", template.title);
            assert!(template.text.starts_with("[["), "{}", template.title);
        }
        assert_eq!(templates.email_code.title, "email_code");
    }
}

#[cfg(test)]
mod takedown_tests {
    use std::collections::BTreeSet;

    use regex::Regex;
    use revolt_result::ErrorType;
    use serde_json::{json, Value};

    use super::{
        parse_safe_address, render_template, send_email_safe, takedown_sloga_templates,
        takedown_test_templates, TakedownTemplates, Template, TAKEDOWN_DECLINE_NOT_FOUND,
        TAKEDOWN_PARTIAL_REASON,
    };

    impl TakedownTemplates {
        fn all(&self) -> [&Template; 8] {
            [
                &self.received,
                &self.needs_info,
                &self.removed,
                &self.partial,
                &self.declined,
                &self.uploader,
                &self.alert,
                &self.heartbeat,
            ]
        }
    }

    const FTC: &str = "You can also contact the FTC at TakeItDown.ftc.gov.";
    const BASE: &str = "https://sloga.gg/legal/take-it-down-status.html";
    const REFERENCE: &str = "TD-01JCDW8V5Q3M7K2N4P6R8T0V9X";
    const URL: &str =
        "https://sloga.gg/legal/take-it-down-status.html#TD-01JCDW8V5Q3M7K2N4P6R8T0V9X.aB3-_x";

    fn variables(reason: &str) -> Value {
        json!({
            "reference": REFERENCE,
            "url": URL,
            "reason": reason,
            "deadline": "2026-11-13T14:00:00Z",
            "count": "3",
            "summary": "24 hours left",
        })
    }

    /// (title, text, html) rendered
    fn render(template: &Template, reason: &str) -> (String, String, Option<String>) {
        let variables = variables(reason);
        (
            render_template(&template.title, &variables).unwrap(),
            render_template(&template.text, &variables).unwrap(),
            template
                .html
                .as_ref()
                .map(|html| render_template(html, &variables).unwrap()),
        )
    }

    fn variable_names(template: &Template) -> BTreeSet<String> {
        let re = Regex::new(r"\{\{\{?\s*([A-Za-z_]+)\s*\}?\}\}").unwrap();
        [&template.title, &template.text]
            .into_iter()
            .chain(template.html.as_ref())
            .flat_map(|source| {
                re.captures_iter(source)
                    .map(|capture| capture[1].to_string())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    #[test]
    fn requester_emails_carry_the_fixed_wording_and_the_ftc_line() {
        let TakedownTemplates {
            received,
            needs_info,
            removed,
            partial,
            declined,
            ..
        } = takedown_sloga_templates(BASE);

        let r = REFERENCE;
        let cases: [(&Template, Vec<String>); 5] = [
            (
                &received,
                vec![
                    format!("We received your Take It Down request {r}. A person will review it and we will act within 48 hours of receiving it. Keep this link to check the status or add information:"),
                    URL.to_string(),
                    "If you did not send this request, you can ignore this email.".to_string(),
                ],
            ),
            (
                &needs_info,
                vec![format!("We need more information to act on Take It Down request {r}. Please open the status link from your first email and add a link to the image on Sloga or more detail about where it is.")],
            ),
            (
                &removed,
                vec![format!("We removed the content you reported in Take It Down request {r}, along with any identical copies we found on Sloga, and blocked it from being uploaded again.")],
            ),
            (
                &partial,
                vec![format!("We acted on Take It Down request {r}. REASON")],
            ),
            (
                &declined,
                vec![format!("We reviewed Take It Down request {r} and did not remove the content. REASON If you think we got this wrong, reply to support@sloga.gg with the reference.")],
            ),
        ];

        for (template, sentences) in cases {
            let (title, text, html) = render(template, "REASON");
            let html = html.expect("requester emails have an HTML part");
            assert!(title.contains(r), "{title}");
            for sentence in &sentences {
                assert!(text.contains(sentence.as_str()), "text lacks {sentence:?}");
                assert!(html.contains(sentence.as_str()), "html lacks {sentence:?}");
            }
            assert!(text.contains(FTC) && html.contains(FTC), "{title}");
        }

        let (_, _, html) = render(&received, "");
        assert!(html.unwrap().contains(&format!("<a href=\"{URL}\"")));
    }

    #[test]
    fn uploader_and_staff_emails_have_their_fixed_text() {
        let TakedownTemplates {
            uploader,
            alert,
            heartbeat,
            ..
        } = takedown_sloga_templates(BASE);

        let (_, text, html) = render(&uploader, "");
        let sentence = format!("Content you shared on Sloga was removed under our Community Guidelines and the Take It Down Act (reference {REFERENCE}). If you believe this was a mistake, reply to support@sloga.gg with the reference.");
        assert!(text.contains(&sentence));
        assert!(html.unwrap().contains(&sentence));
        assert!(!text.contains("FTC"));

        let (title, text, html) = render(&alert, "");
        assert_eq!(title, format!("Take It Down {REFERENCE}: 24 hours left"));
        assert_eq!(
            text,
            format!("Take It Down {REFERENCE}: 24 hours left. Deadline 2026-11-13T14:00:00Z.\n")
        );
        assert!(html.is_none());

        let (title, text, html) = render(&heartbeat, "");
        assert_eq!(title, "Take It Down queue: 3 open");
        assert_eq!(text, "Take It Down queue: 3 open. Alerting works.\n");
        assert!(html.is_none());
    }

    #[test]
    fn reasons_render_verbatim_in_text_and_escaped_in_html() {
        let TakedownTemplates {
            partial, declined, ..
        } = takedown_sloga_templates(BASE);

        let (_, text, _) = render(&partial, TAKEDOWN_PARTIAL_REASON);
        assert!(text.contains(&format!(
            "We acted on Take It Down request {REFERENCE}. {TAKEDOWN_PARTIAL_REASON}"
        )));

        let (_, text, _) = render(&declined, TAKEDOWN_DECLINE_NOT_FOUND);
        assert!(text.contains(&format!(
            "did not remove the content. {TAKEDOWN_DECLINE_NOT_FOUND} If you think"
        )));

        let (_, text, html) = render(&declined, "it's <b>");
        assert!(text.contains("it's <b>"));
        let html = html.unwrap();
        assert!(!html.contains("it's <b>"));
        assert!(html.contains("&lt;b&gt;"));
    }

    #[test]
    fn nothing_is_left_unrendered() {
        let real = takedown_sloga_templates(BASE);
        let test = takedown_test_templates(BASE);
        for template in real.all().into_iter().chain(test.all()) {
            let (title, text, html) = render(template, "REASON");
            for rendered in [Some(title), Some(text), html].into_iter().flatten() {
                assert!(!rendered.contains("{{") && !rendered.contains("}}"));
            }
        }
    }

    /// The test stand-ins must expose the same variables as the real
    /// templates, or a test passes on a variable prod never fills
    #[test]
    fn test_templates_use_the_real_variables() {
        let real = takedown_sloga_templates(BASE);
        let test = takedown_test_templates(BASE);
        for (real, test) in real.all().into_iter().zip(test.all()) {
            assert_eq!(variable_names(real), variable_names(test), "{}", test.title);
            assert!(!variable_names(real).is_empty());
        }
    }

    #[test]
    fn received_carries_the_status_page_base() {
        assert_eq!(takedown_sloga_templates(BASE).received.url, BASE);
        assert_eq!(takedown_test_templates(BASE).received.url, BASE);
    }

    #[test]
    fn safe_address_is_format_only() {
        for good in [
            "alice@example.com",
            "  alice@example.com\n",
            "user+tag@mailinator.com",
            "a.b-c@sub.example.co.uk",
        ] {
            assert!(parse_safe_address(good).is_ok(), "{good:?}");
        }

        let long = format!("{}@example.com", "a".repeat(250));
        for bad in [
            "",
            "   ",
            "no-at-sign",
            "a@",
            "@example.com",
            "a b@example.com",
            "a@@example.com",
            "a@example.com\r\nBcc: x@example.org",
            "\"Name\" <a@example.com>",
            "Name <a@example.com>",
            "a@example.com, b@example.com",
            long.as_str(),
        ] {
            let Err(error) = parse_safe_address(bad) else {
                panic!("{bad:?} was accepted");
            };
            assert!(
                matches!(error.error_type, ErrorType::InvalidOperation),
                "{bad:?}"
            );
        }
    }

    /// A bad address is refused before config or SMTP is touched
    #[tokio::test]
    async fn send_email_safe_refuses_a_bad_address() {
        let received = takedown_test_templates(BASE).received;
        let error = send_email_safe("not an address", &received, Default::default())
            .await
            .expect_err("a bad address must be refused");
        assert!(matches!(error.error_type, ErrorType::InvalidOperation));
    }
}
