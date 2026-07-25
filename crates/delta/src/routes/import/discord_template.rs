//! Start a Discord server import from a guild-template link.
//! POST /import/discord/template

use revolt_config::config;
use revolt_database::{Database, DiscordImportJob, User};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use serde::{Deserialize, Serialize};

/// Discord template codes are short, URL-safe tokens. Bound the accepted
/// length generously but finitely — this string is interpolated into an
/// outbound URL, so it must never carry path separators or whitespace.
const CODE_MIN: usize = 1;
const CODE_MAX: usize = 64;

/// # Import Request
#[derive(Deserialize, JsonSchema, Debug)]
pub struct DataImportDiscordTemplate {
    /// A Discord template link or bare code, e.g.
    /// `https://discord.new/abc123` or `abc123`
    pub template: String,
}

/// # Import Job Handle
#[derive(Serialize, JsonSchema, Debug)]
pub struct ResponseImportStarted {
    /// Job id to follow for progress
    pub job_id: String,
}

/// Pull a bare template code out of whatever the user pasted.
///
/// Accepts `https://discord.new/CODE`, `discord.new/CODE`,
/// `https://discord.com/template/CODE`, `.../templates/CODE`, or a bare code.
/// Query strings and fragments are stripped.
///
/// Takes the **final path segment** and whitelists it to `[A-Za-z0-9_-]{1,64}`,
/// returning `None` otherwise. That alphabet is what makes the result safe to
/// interpolate straight into the Discord API URL: it cannot introduce a path
/// segment, a host, a query, or an encoded separator.
///
/// Note this *extracts* rather than *rejects* — `https://discord.new/../../x`
/// yields `Some("x")`, not `None`. That is harmless (the caller looks up a
/// template by that code and gets a 404) but is worth stating plainly, because
/// "rejects traversal" would be the wrong mental model.
pub fn extract_template_code(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Drop scheme, then take the final path segment of any known host form.
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);

    // Cut query/fragment before segmenting.
    let path_only = without_scheme
        .split(['?', '#'])
        .next()
        .unwrap_or(without_scheme);

    let candidate = path_only
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(path_only);

    // A URL whose last segment is just the host means no code was supplied.
    if candidate.eq_ignore_ascii_case("discord.new")
        || candidate.eq_ignore_ascii_case("discord.com")
        || candidate.eq_ignore_ascii_case("discord.gg")
    {
        return None;
    }

    let length = candidate.chars().count();
    if !(CODE_MIN..=CODE_MAX).contains(&length) {
        return None;
    }

    // Whitelist: alphanumerics plus the two separators Discord uses.
    if !candidate
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return None;
    }

    Some(candidate.to_string())
}

/// # Import a Discord Server
///
/// Queues an import of a Discord server's structure from a template link.
/// Returns immediately with a job id; the work runs in the background and
/// streams progress over the user's private WebSocket topic.
#[openapi(tag = "Import")]
#[post("/discord/template", data = "<data>")]
pub async fn import_discord_template(
    db: &State<Database>,
    user: User,
    data: Json<DataImportDiscordTemplate>,
) -> Result<Json<ResponseImportStarted>> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let config = config().await;
    if !config.api.import.discord.enabled {
        return Err(create_error!(OperationFailed));
    }

    // This route creates a server, so it must honour the same operator gate as
    // `POST /servers/create` (server_create.rs:26-40). Without it an operator
    // who has locked server creation to an allowlist can still have servers
    // minted for barred users by way of an import. The worker re-checks this
    // immediately before `Server::create` (time-of-use).
    if !config
        .features
        .limits
        .global
        .restrict_server_creation
        .is_empty()
        && !config
            .features
            .limits
            .global
            .restrict_server_creation
            .contains(&user.id)
    {
        return Err(create_error!(CantCreateServers));
    }

    let code = extract_template_code(&data.template).ok_or_else(|| create_error!(InvalidOperation))?;

    // Fail fast on the server quota rather than after doing all the work —
    // the worker enforces it again at creation time.
    user.can_acquire_server(db).await?;

    // One import at a time per user: imports are expensive and a user with a
    // queue of them is either confused or abusing the endpoint.
    if db
        .fetch_active_discord_import_job_for_user(&user.id)
        .await?
        .is_some()
    {
        return Err(create_error!(ImportAlreadyInProgress));
    }

    let job = DiscordImportJob::new(user.id.clone(), code);
    db.insert_discord_import_job(&job).await?;

    Ok(Json(ResponseImportStarted { job_id: job.id }))
}

#[cfg(test)]
mod tests {
    use super::{extract_template_code, CODE_MAX, CODE_MIN};

    #[test]
    fn accepts_the_shapes_users_actually_paste() {
        for input in [
            "https://discord.new/abc123",
            "http://discord.new/abc123",
            "discord.new/abc123",
            "https://discord.com/template/abc123",
            "https://discord.com/templates/abc123",
            "abc123",
            "  https://discord.new/abc123/  ",
            "https://discord.new/abc123?utm_source=x",
            "https://discord.new/abc123#frag",
        ] {
            assert_eq!(
                extract_template_code(input).as_deref(),
                Some("abc123"),
                "failed for {input}"
            );
        }
    }

    #[test]
    fn preserves_dashes_and_underscores() {
        assert_eq!(
            extract_template_code("https://discord.new/ab-c_123").as_deref(),
            Some("ab-c_123")
        );
    }

    #[test]
    fn returns_none_for_empty_and_hostonly_input() {
        for input in ["", "   ", "https://discord.new/", "discord.new", "discord.com"] {
            assert!(
                extract_template_code(input).is_none(),
                "expected None for {input:?}"
            );
        }
    }

    /// The output alphabet is the whole security property: whatever comes back
    /// is interpolated into `https://discord.com/api/v10/guilds/templates/{}`,
    /// so it must never be able to add a path segment, host, query or an
    /// encoded separator.
    #[test]
    fn output_can_never_escape_the_url_path_segment() {
        let overlong = "a".repeat(CODE_MAX + 1);

        for input in [
            "https://discord.new/../../admin",
            "https://evil.example/discord.new/abc123",
            "abc%2F..%2Fadmin",
            "abc/../../x",
            "ab\\cd",
            "a b",
            "semi;colon",
            "plus+sign",
            "dot.dot",
            "at@sign",
            "hash#frag",
            "q?uery",
            "co:lon",
            "unicode／solidus",
            "new\nline",
            "tab\there",
            overlong.as_str(),
        ] {
            if let Some(code) = extract_template_code(input) {
                assert!(
                    code.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                    "unsafe character survived for {input:?} -> {code:?}"
                );
                assert!(
                    (CODE_MIN..=CODE_MAX).contains(&code.chars().count()),
                    "out-of-bounds length survived for {input:?} -> {code:?}"
                );
            }
        }
    }

    /// Documents the *actual* traversal behaviour: the last segment is
    /// extracted, not rejected. Harmless (it 404s upstream) but it should be
    /// asserted rather than assumed — the previous version of this test only
    /// checked the literal string "../..", which no input could ever produce,
    /// so it passed vacuously.
    #[test]
    fn traversal_is_reduced_to_its_last_segment() {
        assert_eq!(
            extract_template_code("https://discord.new/../../admin").as_deref(),
            Some("admin")
        );
        // ...and anything with a traversal character left in it is rejected.
        assert!(extract_template_code("..").is_none());
        assert!(extract_template_code("../").is_none());
    }

    #[test]
    fn rejects_overlong_codes() {
        let long = "a".repeat(65);
        assert!(extract_template_code(&long).is_none());
        let ok = "a".repeat(64);
        assert!(extract_template_code(&ok).is_some());
    }
}
