//! Prot fuel tank emails to the server owner (contracts section 12.4).
//!
//! `util::email::send_email` blocks the calling thread and `.expect`s on its
//! configuration, which would take a crond task down with it. This module
//! never calls it: every address, template and render failure is an error the
//! caller can log and move past, and the blocking SMTP send runs on the
//! blocking pool. The templates live here rather than on `email::Templates`
//! (refinement BR19).

use std::sync::LazyLock;
use std::time::Duration;

use chrono::{DateTime, Utc};
use handlebars::Handlebars;
use lettre::{
    message::{Mailbox, MultiPart},
    transport::smtp::{authentication::Credentials, client::Tls, Error as SmtpError},
    Message, SmtpTransport, Transport,
};
use revolt_config::{config, ApiSmtp, Settings};
use revolt_result::Result;
use serde_json::json;

use crate::{Database, DeletionInfo, ProtTankRules};

/// Plain text: nothing is escaped
static TEXT: LazyLock<Handlebars<'static>> = LazyLock::new(|| {
    let mut registry = Handlebars::new();
    registry.register_escape_fn(handlebars::no_escape);
    registry
});

/// HTML: `{{var}}` is escaped, `{{{body}}}` is inserted as rendered
static HTML: LazyLock<Handlebars<'static>> = LazyLock::new(Handlebars::new);

/// lettre's per-operation SMTP timeout
const SMTP_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest a caller ever waits for one send; past it the send is reported
/// as failed and the blocking thread finishes on its own
const SEND_DEADLINE: Duration = Duration::from_secs(120);

/// Which owner email to send (D12: grace, freeze, day 20, deletion)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtEmailKind {
    Grace,
    Freeze,
    Final,
    Deleted,
}

/// One email: subject, plain text body and HTML body (handlebars), and the
/// label of the link to the app
struct ProtEmailTemplate {
    subject: &'static str,
    text: &'static str,
    html: &'static str,
    link: &'static str,
}

// Copy rules: no server or channel name, no amounts; "Protected servers and
// channels" on first mention; deletion is "deleted from Sloga's servers" and is
// only promised while `deletion_enabled` is on; day counts come from the config.

const GRACE: ProtEmailTemplate = ProtEmailTemplate {
    subject: "Your Protected channel has run out of Prot",
    text: "Protected servers and channels on Sloga run on Prot. One of your Protected channels \
           has run out of Prot.\n\nIt is now in a {{grace_days}}-day grace period{{#if date}} \
           that ends on {{date}}{{/if}}. Until then it keeps working, but new members can't be \
           added. Top it up to keep it active. If it isn't topped up in time, it will be frozen: \
           members can still read its history, but nothing can be sent.",
    html: "<p>Protected servers and channels on Sloga run on Prot. One of your Protected channels \
           has run out of Prot.</p>\n<p>It is now in a {{grace_days}}-day grace period{{#if date}} \
           that ends on {{date}}{{/if}}. Until then it keeps working, but new members can't be \
           added. Top it up to keep it active. If it isn't topped up in time, it will be frozen: \
           members can still read its history, but nothing can be sent.</p>",
    link: "Top it up in Sloga",
};

const FREEZE: ProtEmailTemplate = ProtEmailTemplate {
    subject: "Your Protected channel is frozen",
    text: "Protected servers and channels on Sloga run on Prot. One of your Protected channels \
           ran out of Prot and its grace period has ended, so it is now frozen. Members can still \
           read its history, but nothing can be sent until it's topped up.{{#if deletion}}\n\n\
           If it isn't topped up, it may be deleted from Sloga's servers {{#if date}}after \
           {{date}}{{else}}{{freeze_days}} days after it froze{{/if}}.{{/if}}",
    html: "<p>Protected servers and channels on Sloga run on Prot. One of your Protected channels \
           ran out of Prot and its grace period has ended, so it is now frozen. Members can still \
           read its history, but nothing can be sent until it's topped up.</p>{{#if deletion}}\n\
           <p>If it isn't topped up, it may be deleted from Sloga's servers {{#if date}}after \
           {{date}}{{else}}{{freeze_days}} days after it froze{{/if}}.</p>{{/if}}",
    link: "Top it up in Sloga",
};

const FINAL: ProtEmailTemplate = ProtEmailTemplate {
    subject: "Your Protected channel may be deleted in {{final_days}} days",
    text: "Protected servers and channels on Sloga run on Prot. One of your Protected channels is \
           frozen because it ran out of Prot.\n\nIf it isn't topped up, it may be deleted from \
           Sloga's servers in {{final_days}} days{{#if date}}, after {{date}}{{/if}}. Top it up \
           to keep it.",
    html: "<p>Protected servers and channels on Sloga run on Prot. One of your Protected channels \
           is frozen because it ran out of Prot.</p>\n<p>If it isn't topped up, it may be deleted \
           from Sloga's servers in {{final_days}} days{{#if date}}, after {{date}}{{/if}}. Top it \
           up to keep it.</p>",
    link: "Top it up in Sloga",
};

const DELETED: ProtEmailTemplate = ProtEmailTemplate {
    subject: "Your Protected channel was deleted",
    text: "Protected servers and channels on Sloga run on Prot. One of your Protected channels \
           was deleted from Sloga's servers{{#if date}} on {{date}}{{/if}} because it ran out of \
           Prot.",
    html: "<p>Protected servers and channels on Sloga run on Prot. One of your Protected channels \
           was deleted from Sloga's servers{{#if date}} on {{date}}{{/if}} because it ran out of \
           Prot.</p>",
    link: "Open Sloga",
};

const PROT_TEXT_LAYOUT: &str =
    "{{{body}}}\n\n{{link}}: {{url}}\n\nThis email is intended for {{email}}\n\nSloga\n";

const PROT_HTML_LAYOUT: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body style="margin: 0; padding: 24px; background-color: #f7fafc; color: #000000; font-family: Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px;">
<div style="max-width: 560px; margin: 0 auto; padding: 24px; background-color: #ffffff; border-radius: 8px;">
<img src="https://sloga.gg/assets/logo-512.png" alt="Sloga" width="64" style="display: block; width: 64px; height: auto; border: 0;">
{{{body}}}
<p><a href="{{url}}" style="display: inline-block; padding: 12px 20px; background-color: #0d6efd; color: #ffffff; border-radius: 6px; text-decoration: none; font-weight: 700;">{{link}}</a></p>
<p style="margin-top: 32px; color: #6c757d; font-size: 13px; line-height: 20px;">This email is intended for {{email}}<br>Sloga Technologies LLC</p>
</div>
</body>
</html>
"#;

impl ProtEmailKind {
    fn template(self) -> &'static ProtEmailTemplate {
        match self {
            ProtEmailKind::Grace => &GRACE,
            ProtEmailKind::Freeze => &FREEZE,
            ProtEmailKind::Final => &FINAL,
            ProtEmailKind::Deleted => &DELETED,
        }
    }
}

/// A rendered email, ready to send
struct RenderedProtEmail {
    subject: String,
    text: String,
    html: String,
}

/// Send the owner of a tank one of the D12 emails.
///
/// Non-panicking: SMTP not configured → Ok(false) logged at info; any address/template/render/send
/// failure → Err(InternalError) logged `PROT_EMAIL_FAILED kind=.. user=..`; the blocking lettre
/// send runs in tokio::task::spawn_blocking, its JoinError (a panic) is mapped to Err, never
/// propagated. Never calls send_email.
///
/// Also Ok(false), logged `PROT_EMAIL_SKIPPED` at info: a `Final` while `deletion_enabled` is
/// off (no deletion promise, 12.2), and an owner whose account is deleted. Ok(true) = handed to
/// the SMTP server. An invalid `[features.boosts.protection]` config is an Err (the day counts
/// come from it).
///
/// `date_ms` (rendered in UTC, omitted when None): Grace = `grace_ends_at`; Freeze =
/// `deletes_at` (ignored while `deletion_enabled` is off); Final = the earliest deletion time;
/// Deleted = `ended_at`.
pub async fn send_prot_owner_email(
    db: &Database,
    owner_id: &str,
    kind: ProtEmailKind,
    date_ms: Option<i64>,
) -> Result<bool> {
    let config = config().await;
    send_prot_owner_email_with(db, &config, owner_id, kind, date_ms).await
}

/// `send_prot_owner_email` against a given config (tests swap in a broken one)
async fn send_prot_owner_email_with(
    db: &Database,
    config: &Settings,
    owner_id: &str,
    kind: ProtEmailKind,
    date_ms: Option<i64>,
) -> Result<bool> {
    if config.api.smtp.host.is_empty() {
        log::info!("PROT_EMAIL_SKIPPED kind={kind:?} user={owner_id} reason=smtp_not_configured");
        return Ok(false);
    }

    let rules = ProtTankRules::from_config(&config.features.boosts.protection)
        .map_err(|_| prot_email_failed(kind, owner_id, "invalid protection config"))?;
    if kind == ProtEmailKind::Final && !rules.deletion_enabled {
        log::info!("PROT_EMAIL_SKIPPED kind={kind:?} user={owner_id} reason=deletion_disabled");
        return Ok(false);
    }

    let account = db.fetch_account(owner_id).await.map_err(|error| {
        prot_email_failed(kind, owner_id, format!("account: {:?}", error.error_type))
    })?;
    if matches!(account.deletion, Some(DeletionInfo::Deleted)) {
        log::info!("PROT_EMAIL_SKIPPED kind={kind:?} user={owner_id} reason=account_deleted");
        return Ok(false);
    }

    let email = render_prot_email(kind, date_ms, &rules, &config.hosts.app, &account.email)
        .map_err(|reason| prot_email_failed(kind, owner_id, reason))?;
    deliver_prot_email(&config.api.smtp, &account.email, email)
        .await
        .map_err(|reason| prot_email_failed(kind, owner_id, reason))?;

    log::info!("PROT_EMAIL_SENT kind={kind:?} user={owner_id}");
    Ok(true)
}

/// Log a failed owner email by user id and answer InternalError
fn prot_email_failed(
    kind: ProtEmailKind,
    owner_id: &str,
    reason: impl std::fmt::Display,
) -> revolt_result::Error {
    log::error!("{}", prot_email_failure_line(kind, owner_id, reason));
    create_error!(InternalError)
}

/// The `PROT_EMAIL_FAILED` log line. Every `reason` in this file is built to
/// hold no address: fixed text, a reply code, a day number, or lettre's
/// `AddressError` (four fixed messages). Never an error's Display/Debug text
/// that can quote the server or the input.
fn prot_email_failure_line(
    kind: ProtEmailKind,
    owner_id: &str,
    reason: impl std::fmt::Display,
) -> String {
    format!("PROT_EMAIL_FAILED kind={kind:?} user={owner_id} reason={reason}")
}

/// What the log may say about a lettre SMTP error: the stage, the error class
/// and the reply code. Never its Display or Debug text: a permanent or
/// transient error carries the server's reply, and a 550 usually echoes the
/// recipient (`<owner@domain>`).
fn smtp_failure_reason(stage: &str, error: &SmtpError) -> String {
    let class = if error.is_permanent() {
        "permanent"
    } else if error.is_transient() {
        "transient"
    } else if error.is_timeout() {
        "timeout"
    } else if error.is_tls() {
        "tls"
    } else if error.is_response() {
        "response"
    } else if error.is_client() {
        "client"
    } else {
        "connection"
    };
    match error.status() {
        Some(code) => format!("{stage}: {class} code={code}"),
        None => format!("{stage}: {class}"),
    }
}

/// "November 12, 2026 at 00:00 UTC"
fn prot_email_date(ms: i64) -> std::result::Result<String, String> {
    DateTime::<Utc>::from_timestamp_millis(ms)
        .map(|at| at.format("%B %-d, %Y at %H:%M UTC").to_string())
        .ok_or_else(|| format!("date out of range: {ms}"))
}

/// Render one handlebars source; a failure is a reason string (without the
/// render error's text, which can quote the template data)
fn render_part(
    registry: &Handlebars<'static>,
    kind: ProtEmailKind,
    source: &str,
    data: &serde_json::Value,
) -> std::result::Result<String, String> {
    registry
        .render_template(source, data)
        .map_err(|_| format!("render {kind:?} failed"))
}

/// Render the subject and both bodies of one email
fn render_prot_email(
    kind: ProtEmailKind,
    date_ms: Option<i64>,
    rules: &ProtTankRules,
    app_url: &str,
    address: &str,
) -> std::result::Result<RenderedProtEmail, String> {
    let template = kind.template();
    // A Freeze email names a deletion date only while deletion is on
    let date = match date_ms {
        Some(_) if kind == ProtEmailKind::Freeze && !rules.deletion_enabled => None,
        Some(ms) => Some(prot_email_date(ms)?),
        None => None,
    };

    let variables = json!({
        "url": app_url,
        "email": address,
        "date": date,
        "deletion": rules.deletion_enabled,
        "grace_days": rules.grace_days,
        "freeze_days": rules.freeze_days,
        "final_days": rules.final_notice_days(),
    });
    let subject = render_part(&TEXT, kind, template.subject, &variables)?;
    let text_body = render_part(&TEXT, kind, template.text, &variables)?;
    let html_body = render_part(&HTML, kind, template.html, &variables)?;

    let text = render_part(
        &TEXT,
        kind,
        PROT_TEXT_LAYOUT,
        &json!({ "body": text_body, "link": template.link, "url": app_url, "email": address }),
    )?;
    let html = render_part(
        &HTML,
        kind,
        PROT_HTML_LAYOUT,
        &json!({ "body": html_body, "link": template.link, "url": app_url, "email": address }),
    )?;

    Ok(RenderedProtEmail {
        subject,
        text,
        html,
    })
}

/// Build the message on the async side (no I/O), then connect and send on the
/// blocking pool. A panic in the blocking task comes back as a JoinError and
/// is answered as a failure like any other.
async fn deliver_prot_email(
    smtp: &ApiSmtp,
    address: &str,
    email: RenderedProtEmail,
) -> std::result::Result<(), String> {
    let from = smtp
        .from_address
        .parse::<Mailbox>()
        .map_err(|error| format!("invalid smtp from_address: {error}"))?;
    let to = address
        .parse::<Mailbox>()
        .map_err(|error| format!("invalid owner address: {error}"))?;

    let builder = Message::builder().from(from).to(to).subject(email.subject);
    let builder = match &smtp.reply_to {
        Some(reply_to) => builder.reply_to(
            reply_to
                .parse::<Mailbox>()
                .map_err(|error| format!("invalid smtp reply_to: {error}"))?,
        ),
        None => builder,
    };
    let message = builder
        .multipart(MultiPart::alternative_plain_html(email.text, email.html))
        .map_err(|_| "invalid message".to_string())?;

    let port = smtp
        .port
        .map(u16::try_from)
        .transpose()
        .map_err(|_| "invalid smtp port".to_string())?;
    let smtp = smtp.clone();

    let send = tokio::task::spawn_blocking(move || -> std::result::Result<(), String> {
        let relay = if smtp.use_starttls == Some(true) {
            SmtpTransport::starttls_relay(&smtp.host)
        } else {
            SmtpTransport::relay(&smtp.host)
        }
        .map_err(|error| smtp_failure_reason("smtp relay", &error))?;

        let relay = match port {
            Some(port) => relay.port(port),
            None => relay,
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
            .timeout(Some(SMTP_TIMEOUT))
            .build()
            .send(&message)
            .map(|_| ())
            .map_err(|error| smtp_failure_reason("smtp send", &error))
    });

    // A JoinError's text holds the panic message, which can quote anything
    match tokio::time::timeout(SEND_DEADLINE, send).await {
        Ok(Ok(result)) => result,
        Ok(Err(join_error)) if join_error.is_panic() => Err("send task panicked".to_string()),
        Ok(Err(_)) => Err("send task cancelled".to_string()),
        Err(_) => Err("send timed out".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use revolt_config::{config, ProtectionFeatures, Settings};
    use revolt_result::ErrorType;

    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};

    use lettre::{transport::smtp::authentication::Credentials, Message, SmtpTransport, Transport};

    use super::{
        deliver_prot_email, prot_email_failure_line, render_prot_email, send_prot_owner_email_with,
        ProtEmailKind, RenderedProtEmail,
    };
    use crate::{Account, DeletionInfo, EmailVerification, ProtTankRules};

    /// 2026-11-12T00:00:00Z
    const DATE: i64 = 1_794_441_600_000;
    const DATE_TEXT: &str = "November 12, 2026 at 00:00 UTC";
    const APP: &str = "https://app.example.test/?a=1&b=2";
    const KINDS: [ProtEmailKind; 4] = [
        ProtEmailKind::Grace,
        ProtEmailKind::Freeze,
        ProtEmailKind::Final,
        ProtEmailKind::Deleted,
    ];

    fn account(id: &str, email: &str) -> Account {
        Account {
            id: id.to_string(),
            email: email.to_string(),
            email_normalised: email.to_string(),
            password: "hash".to_string(),
            disabled: false,
            verification: EmailVerification::Verified,
            password_reset: None,
            deletion: None,
            lockout: None,
            mfa: Default::default(),
            google_id: None,
            apple_id: None,
        }
    }

    /// Non-default day counts (grace 7, freeze 20, Final on day 15 → 12 days)
    fn rules(deletion_enabled: bool) -> ProtTankRules {
        ProtTankRules {
            grace_days: 7,
            freeze_days: 20,
            final_warning_day: 15,
            deletion_enabled,
            ..ProtTankRules::from_config(&ProtectionFeatures::default()).unwrap()
        }
    }

    /// The test config with SMTP pointed nowhere and deletion on
    async fn settings() -> Settings {
        let mut settings = config().await;
        settings.features.boosts.protection = Box::new(ProtectionFeatures {
            deletion_enabled: true,
            ..Default::default()
        });
        settings.api.smtp.host = "127.0.0.1".to_string();
        settings.api.smtp.port = Some(1);
        settings.api.smtp.use_tls = Some(false);
        settings.api.smtp.use_starttls = Some(false);
        settings.api.smtp.from_address = "noreply@example.test".to_string();
        settings.api.smtp.reply_to = None;
        settings
    }

    fn assert_internal(result: revolt_result::Result<bool>, what: &str) {
        match result {
            Err(error) => assert!(
                matches!(error.error_type, ErrorType::InternalError),
                "{what}: {error:?}"
            ),
            Ok(sent) => panic!("{what}: expected InternalError, got Ok({sent})"),
        }
    }

    /// 12.4: a broken SMTP config is an error the caller gets back, never a
    /// panic, and the caller goes on to the next email.
    #[tokio::test]
    async fn email_failure_never_panics() {
        database_test!(|db| async move {
            db.save_account(&account("01PROTEMAIL000000000000001", "owner@example.test"))
                .await
                .unwrap();
            db.save_account(&account("01PROTEMAIL000000000000002", "not-an-address"))
                .await
                .unwrap();

            let mut failures = 0;

            let mut broken = settings().await;
            broken.api.smtp.from_address = "not an address".to_string();
            for kind in KINDS {
                assert_internal(
                    send_prot_owner_email_with(
                        &db,
                        &broken,
                        "01PROTEMAIL000000000000001",
                        kind,
                        Some(DATE),
                    )
                    .await,
                    "invalid from_address",
                );
                failures += 1;
            }

            let mut broken = settings().await;
            broken.api.smtp.reply_to = Some("not an address either".to_string());
            assert_internal(
                send_prot_owner_email_with(
                    &db,
                    &broken,
                    "01PROTEMAIL000000000000001",
                    ProtEmailKind::Grace,
                    Some(DATE),
                )
                .await,
                "invalid reply_to",
            );
            failures += 1;

            let mut broken = settings().await;
            broken.api.smtp.port = Some(-1);
            assert_internal(
                send_prot_owner_email_with(
                    &db,
                    &broken,
                    "01PROTEMAIL000000000000001",
                    ProtEmailKind::Freeze,
                    None,
                )
                .await,
                "invalid port",
            );
            failures += 1;

            assert_internal(
                send_prot_owner_email_with(
                    &db,
                    &settings().await,
                    "01PROTEMAIL000000000000002",
                    ProtEmailKind::Final,
                    Some(DATE),
                )
                .await,
                "invalid owner address",
            );
            failures += 1;

            assert_internal(
                send_prot_owner_email_with(
                    &db,
                    &settings().await,
                    "01PROTEMAIL000000000000001",
                    ProtEmailKind::Deleted,
                    Some(i64::MAX),
                )
                .await,
                "date out of range",
            );
            failures += 1;

            // Nothing listens on 127.0.0.1:1: the send itself fails on the
            // blocking pool and comes back as an error
            assert_internal(
                send_prot_owner_email_with(
                    &db,
                    &settings().await,
                    "01PROTEMAIL000000000000001",
                    ProtEmailKind::Grace,
                    Some(DATE),
                )
                .await,
                "send failure",
            );
            failures += 1;

            assert_eq!(failures, 9, "the caller reached every email");
        });
    }

    #[tokio::test]
    async fn owner_email_is_skipped_without_smtp_a_deletion_promise_or_an_account() {
        database_test!(|db| async move {
            let mut deleted = account("01PROTEMAIL000000000000003", "gone@example.test");
            deleted.deletion = Some(DeletionInfo::Deleted);
            db.save_account(&deleted).await.unwrap();

            // SMTP not configured: Ok(false) before any account lookup
            let mut no_smtp = settings().await;
            no_smtp.api.smtp.host = String::new();
            for kind in KINDS {
                let sent = send_prot_owner_email_with(
                    &db,
                    &no_smtp,
                    "01PROTEMAIL00000000000NONE",
                    kind,
                    Some(DATE),
                )
                .await
                .unwrap();
                assert!(!sent, "{kind:?} without SMTP");
            }

            // No Final while deletion is off (NIT 32)
            let mut no_deletion = settings().await;
            *no_deletion.features.boosts.protection = ProtectionFeatures::default();
            let sent = send_prot_owner_email_with(
                &db,
                &no_deletion,
                "01PROTEMAIL00000000000NONE",
                ProtEmailKind::Final,
                Some(DATE),
            )
            .await
            .unwrap();
            assert!(!sent, "Final while deletion is off");

            // A deleted account is never written to
            for kind in KINDS {
                let sent = send_prot_owner_email_with(
                    &db,
                    &settings().await,
                    "01PROTEMAIL000000000000003",
                    kind,
                    Some(DATE),
                )
                .await
                .unwrap();
                assert!(!sent, "{kind:?} to a deleted account");
            }

            // An owner with no account is an error, not a panic
            assert_internal(
                send_prot_owner_email_with(
                    &db,
                    &settings().await,
                    "01PROTEMAIL00000000000NONE",
                    ProtEmailKind::Grace,
                    Some(DATE),
                )
                .await,
                "missing account",
            );

            // An invalid protection config is an error, not a panic
            let mut invalid = settings().await;
            *invalid.features.boosts.protection = ProtectionFeatures {
                grace_days: 0,
                ..Default::default()
            };
            assert_internal(
                send_prot_owner_email_with(
                    &db,
                    &invalid,
                    "01PROTEMAIL000000000000003",
                    ProtEmailKind::Grace,
                    Some(DATE),
                )
                .await,
                "invalid protection config",
            );
        });
    }

    #[tokio::test]
    async fn email_send_failure_is_an_error() {
        let mut smtp = settings().await.api.smtp;
        let email = || RenderedProtEmail {
            subject: "subject".to_string(),
            text: "text".to_string(),
            html: "<p>html</p>".to_string(),
        };

        // Built and sent on the blocking pool ("smtp relay: " / "smtp send: ")
        assert!(deliver_prot_email(&smtp, "owner@example.test", email())
            .await
            .unwrap_err()
            .starts_with("smtp "));

        smtp.from_address = "not an address".to_string();
        assert!(deliver_prot_email(&smtp, "owner@example.test", email())
            .await
            .unwrap_err()
            .starts_with("invalid smtp from_address"));
    }

    /// The RCPT reply of the fake server: a typical 550 that echoes the recipient
    const REJECT_RCPT: &[u8] = b"550 5.1.1 <owner@example.test>: Recipient address rejected\r\n";

    /// One plain-text SMTP session: AUTH PLAIN accepted, every RCPT rejected
    fn serve_smtp(stream: TcpStream) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut writer = stream;
        writer.write_all(b"220 fake ESMTP\r\n").unwrap();
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let reply: &[u8] = if line.starts_with("EHLO") {
                b"250-fake\r\n250 AUTH PLAIN LOGIN\r\n"
            } else if line.starts_with("AUTH") {
                b"235 2.7.0 ok\r\n"
            } else if line.starts_with("RCPT") {
                REJECT_RCPT
            } else if line.starts_with("QUIT") {
                b"221 bye\r\n"
            } else {
                b"250 ok\r\n"
            };
            if writer.write_all(reply).is_err() || line.starts_with("QUIT") {
                return;
            }
        }
    }

    /// A fake SMTP server on 127.0.0.1 for `sessions` connections; its port.
    /// Each connection gets its own thread: lettre's pool parks an idle
    /// session that stays open until the transport drops, and it must not
    /// stall the session the send runs on.
    fn fake_smtp_server(sessions: usize) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(sessions).flatten() {
                std::thread::spawn(move || serve_smtp(stream));
            }
        });
        port
    }

    /// W5 re-review: a 550's reply text quotes the owner's address; the
    /// `PROT_EMAIL_FAILED` line carries the class and code only.
    #[tokio::test]
    async fn prot_email_failure_log_never_contains_the_address() {
        // Two transports below, and lettre 0.10's pool opens one idle
        // connection beside each send, so allow up to 4 sessions (plus slack)
        let port = fake_smtp_server(8);

        // Premise: lettre's own text for this failure holds the address, so a
        // reason built from it would leak
        let raw = tokio::task::spawn_blocking(move || {
            let message = Message::builder()
                .from("noreply@example.test".parse().unwrap())
                .to("owner@example.test".parse().unwrap())
                .subject("subject")
                .body("text".to_string())
                .unwrap();
            SmtpTransport::builder_dangerous("127.0.0.1")
                .port(port)
                .credentials(Credentials::new("smtp".to_string(), "smtp".to_string()))
                .build()
                .send(&message)
                .unwrap_err()
        })
        .await
        .unwrap();
        assert!(raw.is_permanent(), "{raw}");
        assert!(raw.to_string().contains("owner@example.test"), "{raw}");

        let mut smtp = settings().await.api.smtp;
        smtp.port = Some(i32::from(port));
        let reason = deliver_prot_email(
            &smtp,
            "owner@example.test",
            RenderedProtEmail {
                subject: "subject".to_string(),
                text: "text".to_string(),
                html: "<p>html</p>".to_string(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(reason, "smtp send: permanent code=550");

        let line =
            prot_email_failure_line(ProtEmailKind::Final, "01PROTEMAIL000000000000001", &reason);
        assert_eq!(
            line,
            "PROT_EMAIL_FAILED kind=Final user=01PROTEMAIL000000000000001 \
             reason=smtp send: permanent code=550"
        );
        assert!(!line.contains('@'), "{line}");
    }

    fn render(kind: ProtEmailKind, date: Option<i64>, deletion: bool) -> RenderedProtEmail {
        render_prot_email(kind, date, &rules(deletion), APP, "owner@example.test").unwrap()
    }

    #[test]
    fn prot_email_subjects_are_pinned() {
        assert_eq!(
            render(ProtEmailKind::Grace, Some(DATE), true).subject,
            "Your Protected channel has run out of Prot"
        );
        assert_eq!(
            render(ProtEmailKind::Freeze, Some(DATE), true).subject,
            "Your Protected channel is frozen"
        );
        // n = grace 7 + freeze 20 - Final day 15, from the config (NIT 26)
        assert_eq!(
            render(ProtEmailKind::Final, Some(DATE), true).subject,
            "Your Protected channel may be deleted in 12 days"
        );
        assert_eq!(
            render(ProtEmailKind::Deleted, Some(DATE), true).subject,
            "Your Protected channel was deleted"
        );
    }

    #[test]
    fn prot_email_bodies_follow_the_copy_rules() {
        for kind in KINDS {
            for date in [Some(DATE), None] {
                for deletion in [true, false] {
                    let email = render(kind, date, deletion);
                    for body in [&email.text, &email.html] {
                        let first = body.find("Protected").unwrap();
                        assert_eq!(
                            body[first..].find("Protected servers and channels"),
                            Some(0),
                            "{kind:?}: first mention"
                        );
                        assert!(!body.contains("{{") && !body.contains("}}"), "{kind:?}");
                        assert!(!body.contains('$'), "{kind:?}: no amounts");
                        assert!(body.contains("owner@example.test"), "{kind:?}");
                        assert_eq!(
                            body.contains(DATE_TEXT),
                            date.is_some() && (kind != ProtEmailKind::Freeze || deletion),
                            "{kind:?} {date:?} {deletion}: the date"
                        );
                    }
                    // The link: raw in the text, escaped in the HTML
                    assert!(email.text.contains(APP), "{kind:?}");
                    assert!(
                        email.html.contains("https://app.example.test/?a"),
                        "{kind:?}"
                    );
                    assert!(email.html.contains("&amp;b"), "{kind:?}");
                }
            }
        }

        let grace = render(ProtEmailKind::Grace, Some(DATE), false).text;
        assert!(grace.contains(&format!("7-day grace period that ends on {DATE_TEXT}.")));
        assert!(!grace.to_lowercase().contains("delete"));

        let frozen = render(ProtEmailKind::Freeze, Some(DATE), true).text;
        assert!(frozen.contains(&format!(
            "it may be deleted from Sloga's servers after {DATE_TEXT}."
        )));
        let frozen = render(ProtEmailKind::Freeze, None, true).text;
        assert!(frozen.contains("it may be deleted from Sloga's servers 20 days after it froze."));
        // No deletion promise while deletion is off, even with a date
        for date in [Some(DATE), None] {
            let frozen = render(ProtEmailKind::Freeze, date, false);
            assert!(!frozen.text.to_lowercase().contains("delete"));
            assert!(!frozen.html.to_lowercase().contains("delete"));
        }

        let last = render(ProtEmailKind::Final, Some(DATE), true).text;
        assert!(last.contains(&format!(
            "it may be deleted from Sloga's servers in 12 days, after {DATE_TEXT}."
        )));

        let deleted = render(ProtEmailKind::Deleted, Some(DATE), true).text;
        assert!(deleted.contains(&format!(
            "was deleted from Sloga's servers on {DATE_TEXT} because it ran out of Prot."
        )));
    }

    #[test]
    fn prot_email_escapes_the_html_only() {
        let email = render_prot_email(
            ProtEmailKind::Grace,
            None,
            &rules(true),
            APP,
            "o<b>wner@example.test",
        )
        .unwrap();
        assert!(email.text.contains("o<b>wner@example.test"));
        assert!(email.html.contains("o&lt;b&gt;wner@example.test"));
        assert!(!email.html.contains("o<b>wner"));
    }

    #[test]
    fn prot_email_date_out_of_range_is_an_error() {
        assert!(render_prot_email(
            ProtEmailKind::Final,
            Some(i64::MAX),
            &rules(true),
            APP,
            "owner@example.test"
        )
        .is_err());
    }

    /// The production half of this file never reaches a panicking helper
    #[test]
    fn prot_email_never_calls_send_email() {
        let source = include_str!("prot_email.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for needle in [
            "send_email(",
            "create_transport(",
            ".unwrap(",
            ".expect(",
            "panic!(",
            "unreachable!(",
            "block_on(",
        ] {
            assert!(!production.contains(needle), "{needle}");
        }
    }
}
