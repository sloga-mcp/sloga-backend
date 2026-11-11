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
    /// Template for suspention
    pub suspension: Template,

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

pub async fn email_templates() -> Templates {
    let config = config().await;
    let status_url_base = &config.features.takedown.status_url_base;

    if std::env::var("TEST_DB").is_ok() {
        let takedown = takedown_test_templates(status_url_base);

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
            deletion: Template {
                title: "deletion".into(),
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
            takedown_received: takedown.received,
            takedown_needs_info: takedown.needs_info,
            takedown_removed: takedown.removed,
            takedown_partial: takedown.partial,
            takedown_declined: takedown.declined,
            takedown_uploader: takedown.uploader,
            takedown_alert: takedown.alert,
            takedown_heartbeat: takedown.heartbeat,
        }
    } else if config.production {
        let takedown = takedown_sloga_templates(status_url_base);

        Templates {
            verify: Template {
                title: "Verify your Sloga account.".into(),
                text: include_str!("../../templates/verify.txt").into(),
                url: format!("{}/login/verify/", config.hosts.app),
                html: Some(include_str!("../../templates/verify.html").into()),
            },
            reset: Template {
                title: "Reset your Sloga password.".into(),
                text: include_str!("../../templates/reset.txt").into(),
                url: format!("{}/login/reset/", config.hosts.app),
                html: Some(include_str!("../../templates/reset.html").into()),
            },
            reset_existing: Template {
                title: "You already have a Sloga account, reset your password.".into(),
                text: include_str!("../../templates/reset-existing.txt").into(),
                url: format!("{}/login/reset/", config.hosts.app),
                html: Some(include_str!("../../templates/reset-existing.html").into()),
            },
            deletion: Template {
                title: "Confirm account deletion.".into(),
                text: include_str!("../../templates/deletion.txt").into(),
                url: format!("{}/delete/", config.hosts.app),
                html: Some(include_str!("../../templates/deletion.html").into()),
            },
            suspension: Template {
                title: "Account Suspension".to_string(),
                html: Some(include_str!("../../templates/suspension.html").to_owned()),
                text: include_str!("../../templates/suspension.txt").to_owned(),
                url: Default::default(),
            },
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

        Templates {
            verify: Template {
                title: "Verify your account.".into(),
                text: include_str!("../../templates/verify.whitelabel.txt").into(),
                url: format!("{}/login/verify/", config.hosts.app),
                // The .whitelabel.txt above stays the plain-text alternative; the
                // HTML part carries the Sloga logo. Both templates are branded and
                // their legal footer names Sloga Technologies LLC. deletion and
                // suspension stay text-only -- their .html still carries the
                // upstream Revolt Platforms Ltd. footer, so do NOT wire them up
                // without fixing that first.
                html: Some(include_str!("../../templates/verify.html").into()),
            },
            reset: Template {
                title: "Reset your password.".into(),
                text: include_str!("../../templates/reset.whitelabel.txt").into(),
                url: format!("{}/login/reset/", config.hosts.app),
                html: Some(include_str!("../../templates/reset.html").into()),
            },
            reset_existing: Template {
                title: "Reset your password.".into(),
                text: include_str!("../../templates/reset.whitelabel.txt").into(),
                url: format!("{}/login/reset/", config.hosts.app),
                html: Some(include_str!("../../templates/reset-existing.html").into()),
            },
            deletion: Template {
                title: "Confirm account deletion.".into(),
                text: include_str!("../../templates/deletion.whitelabel.txt").into(),
                url: format!("{}/delete/", config.hosts.app),
                html: None,
            },
            suspension: Template {
                title: "Account Suspension".to_string(),
                text: include_str!("../../templates/suspension.whitelabel.txt").to_owned(),
                url: Default::default(),
                html: None,
            },
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

pub fn validate_email(email: &str) -> Result<()> {
    // Make sure this is an actual email
    if !validator::validate_email(email) {
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
    use super::render_template;
    use serde_json::json;

    const SUSPENSION: &str = include_str!("../../templates/suspension.whitelabel.txt");

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
