use std::{collections::HashSet, sync::LazyLock};

use lettre::{
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
    /// Template sent when signing in cancels a pending account deletion
    ///
    /// Carries no token: its `url` is used as-is.
    pub deletion_cancelled: Template,
    /// Template for suspention
    pub suspension: Template,
}

pub async fn email_templates() -> Templates {
    let config = config().await;

    build_templates(
        std::env::var("TEST_DB").is_ok(),
        config.production,
        &config.hosts.app,
    )
}

/// Pick the template set: the test stubs when `TEST_DB` is set, otherwise the
/// production or whitelabel set. `app` is `hosts.app`. Split out of
/// `email_templates` so every branch can be unit tested without the config.
fn build_templates(test: bool, production: bool, app: &str) -> Templates {
    if test {
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
        }
    } else if production {
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
        }
    } else {
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
    use super::{build_templates, render_template};
    use serde_json::json;

    const SUSPENSION: &str = include_str!("../../templates/suspension.whitelabel.txt");
    const APP: &str = "https://app.example.test";

    #[test]
    fn deletion_emails_link_to_the_login_confirm_page() {
        // production, then whitelabel
        for production in [true, false] {
            let templates = build_templates(false, production, APP);

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
            let templates = build_templates(false, production, APP);
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
            let templates = build_templates(false, production, APP);
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
        let templates = build_templates(true, false, APP);

        assert_eq!(templates.deletion.url, "");
        assert_eq!(templates.deletion_cancelled.url, "");
        assert_eq!(templates.deletion_cancelled.text, "[[{{url}}]]");
        assert_eq!(templates.deletion_cancelled.title, "deletion_cancelled");
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
