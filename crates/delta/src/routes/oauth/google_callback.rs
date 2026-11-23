//! Google OAuth callback
//! GET /auth/oauth/google/callback
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use nanoid::nanoid;
use redis_kiss::{get_connection, redis, AsyncCommands};
use revolt_config::config;
use revolt_database::{Account, Database, EmailVerification, MFATicket};
use revolt_models::v0;
use rocket::response::Redirect;
use rocket::State;

#[derive(serde::Deserialize)]
struct TokenResponse {
    id_token: String,
}

#[derive(serde::Deserialize)]
struct IdTokenClaims {
    iss: String,
    aud: String,
    exp: i64,
    sub: String,
    email: Option<String>,
    #[serde(default)]
    email_verified: bool,
}

/// # Google OAuth Callback
///
/// Completes the code exchange with Google, finds or creates the
/// matching account and redirects to the frontend with a one-time
/// handoff code the client swaps for the session.
#[openapi(skip)]
#[get("/google/callback?<code>&<state>&<error>")]
pub async fn google_callback(
    db: &State<Database>,
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
) -> Redirect {
    match callback_inner(db, code, state, error).await {
        Ok(redirect) => redirect,
        Err(code) => error_redirect(code).await,
    }
}

async fn error_redirect(code: &str) -> Redirect {
    let config = config().await;
    Redirect::to(format!("{}/login/oauth?error={}", config.hosts.app, code))
}

async fn callback_inner(
    db: &State<Database>,
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
) -> std::result::Result<Redirect, &'static str> {
    let config = config().await;
    let google = &config.api.oauth.google;

    if !google.enabled {
        return Err("disabled");
    }

    if error.is_some() {
        // User cancelled at the consent screen or Google reported failure
        return Err("cancelled");
    }

    let (code, state) = match (code, state) {
        (Some(code), Some(state)) => (code, state),
        _ => return Err("invalid_request"),
    };

    // Retrieve + consume the PKCE verifier; missing means forged or expired state
    let mut conn = get_connection()
        .await
        .map_err(|_| "internal")?
        .into_inner();

    let verifier: Option<String> = redis::cmd("GETDEL")
        .arg(super::state_key("google", &state))
        .query_async(&mut conn)
        .await
        .map_err(|_| "internal")?;

    let verifier = verifier.ok_or("invalid_state")?;

    // Exchange the authorisation code for tokens
    let response = reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", code.as_str()),
            ("client_id", google.client_id.as_str()),
            ("client_secret", google.client_secret.as_str()),
            (
                "redirect_uri",
                &super::google_authorise::redirect_uri(google, &config.hosts.api),
            ),
            ("grant_type", "authorization_code"),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .map_err(|_| "exchange_failed")?;

    if !response.status().is_success() {
        return Err("exchange_failed");
    }

    let tokens: TokenResponse = response.json().await.map_err(|_| "exchange_failed")?;

    // The id_token comes directly from Google over TLS on an
    // authenticated (client_secret) exchange, so validating claims is
    // sufficient without a JWKS signature check (OIDC Core 3.1.3.7).
    let claims = decode_claims(&tokens.id_token).ok_or("invalid_token")?;

    if claims.iss != "https://accounts.google.com" && claims.iss != "accounts.google.com" {
        return Err("invalid_token");
    }

    if claims.aud != google.client_id {
        return Err("invalid_token");
    }

    if claims.exp
        < std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs() as i64
    {
        return Err("invalid_token");
    }

    if !claims.email_verified {
        return Err("email_unverified");
    }
    let email = claims.email.clone().ok_or("email_unverified")?;

    // Find or create the account: by Google id, then by verified email
    // (auto-link), then a brand new account.
    let mut account =
        if let Some(account) = fetch_by_google_id(db, &claims.sub).await? {
            account
        } else {
            let normalised = revolt_database::util::email::normalise_email(email.clone());
            if let Some(mut account) = db
                .fetch_account_by_normalised_email(&normalised)
                .await
                .map_err(|_| "internal")?
            {
                account.google_id = Some(claims.sub.clone());
                account.save(db).await.map_err(|_| "internal")?;
                account
            } else {
                Account::new_from_google(db, email, claims.sub.clone())
                    .await
                    .map_err(|_| "internal")?
            }
        };

    if account.disabled {
        return Err("disabled_account");
    }

    // Google has verified ownership of this email
    if let EmailVerification::Pending { .. } = account.verification {
        account.verification = EmailVerification::Verified;
        account.save(db).await.map_err(|_| "internal")?;
    }

    // Never bypass a second factor: mirror the password login flow
    let response_login = if account.mfa.is_active() {
        let mut ticket = MFATicket::new(account.id.clone(), false);
        ticket.populate(&account.mfa).await;
        ticket.save(db).await.map_err(|_| "internal")?;

        v0::ResponseLogin::MFA {
            ticket: ticket.token,
            allowed_methods: account.mfa.get_methods().into_iter().map(Into::into).collect(),
        }
    } else {
        let session = account
            .create_session(db, "Google OAuth".to_string())
            .await
            .map_err(|_| "internal")?;

        // Written here, by the server, so the first-passkey rule can tell a
        // session Google just signed in from any other session of a linked
        // account. Best effort: a failure costs the shortcut, not the login.
        crate::util::passkey::mark_oauth_session(&session.id).await;

        v0::ResponseLogin::Success(session.into())
    };

    // Hand the login response to the client via a one-time code so the
    // session token never appears in a URL.
    let handoff = nanoid!(43);
    let payload = serde_json::to_string(&response_login).map_err(|_| "internal")?;

    let set: Option<String> = conn
        .set_options(
            super::handoff_key("google", &handoff),
            payload,
            redis::SetOptions::default()
                .conditional_set(redis::ExistenceCheck::NX)
                .with_expiration(redis::SetExpiry::EX(60)),
        )
        .await
        .map_err(|_| "internal")?;

    if set.is_none() {
        return Err("internal");
    }

    Ok(Redirect::to(format!(
        "{}/login/oauth?code={}",
        config.hosts.app, handoff
    )))
}

fn decode_claims(id_token: &str) -> Option<IdTokenClaims> {
    let payload = id_token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&bytes).ok()
}

async fn fetch_by_google_id(
    db: &State<Database>,
    google_id: &str,
) -> std::result::Result<Option<Account>, &'static str> {
    db.fetch_account_by_google_id(google_id)
        .await
        .map_err(|_| "internal")
}

#[cfg(test)]
mod tests {
    //! The callbacks cannot be driven here: they exchange a code with Google
    //! or Apple. So the marker is pinned on the source of every file in this
    //! directory instead.
    use std::path::Path;

    use crate::util::test::{without_comments, without_whitespace};

    const CREATE: &str = ".create_session(";
    const BOUND: &str = "letsession=account";
    const MARK: &str = "crate::util::passkey::mark_oauth_session(&session.id).await;";

    /// The code that ships in `source`: everything above its test module,
    /// without comments or whitespace
    fn shipping(source: &str) -> String {
        let shipping = source.find("#[cfg(test)]").map_or(source, |end| &source[..end]);
        without_whitespace(&without_comments(shipping))
    }

    /// How many sessions `code` creates, and how many of them are bound to
    /// `session` and marked in the very next statement
    fn created_and_marked(code: &str) -> (usize, usize) {
        let mut created = 0;
        let mut marked = 0;

        for (at, _) in code.match_indices(CREATE) {
            created += 1;

            let after = &code[at..];
            let next_statement = after.find(';').map_or("", |end| &after[end + 1..]);
            if code[..at].ends_with(BOUND) && next_statement.starts_with(MARK) {
                marked += 1;
            }
        }

        (created, marked)
    }

    /// Fails if: a callback creates a session and does not call
    /// `mark_oauth_session` on it straight away, or a new `create_session`
    /// appears anywhere under `routes/oauth/` without the marker.
    #[test]
    fn every_oauth_session_is_marked() {
        let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src/routes/oauth"));
        let mut per_file = Vec::new();

        for entry in std::fs::read_dir(dir).expect("routes/oauth") {
            let path = entry.expect("a directory entry").path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }

            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {}", path.display(), error));
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("a file name")
                .to_string();
            let (created, marked) = created_and_marked(&shipping(&source));

            assert_eq!(
                created, marked,
                "{name}: a session is created without the OAuth marker"
            );
            if created > 0 {
                per_file.push((name, created));
            }
        }

        // The control: the scan saw the two callbacks, one session each
        per_file.sort();
        assert_eq!(
            per_file,
            vec![
                ("apple_callback.rs".to_string(), 1),
                ("google_callback.rs".to_string(), 1),
            ]
        );
    }

    /// The scan itself: it counts a marked session, and tells apart one
    /// that is not marked, marked late, or marked only in a comment
    #[test]
    fn the_scan_tells_marked_from_unmarked() {
        let good = shipping(
            "let session = account\n    .create_session(db, name)\n    .await?;\n\n\
             // why\ncrate::util::passkey::mark_oauth_session(&session.id).await;\n\
             #[cfg(test)]\nmod tests { a.create_session(db, name); }",
        );
        assert_eq!(created_and_marked(&good), (1, 1));

        for bad in [
            "let session = account.create_session(db, name).await?;\nOk(session)",
            "let session = account.create_session(db, name).await?;\n\
             // crate::util::passkey::mark_oauth_session(&session.id).await;\nOk(session)",
            "let session = account.create_session(db, name).await?;\nsave(&session).await?;\n\
             crate::util::passkey::mark_oauth_session(&session.id).await;",
            "let session = account.create_session(db, name).await?;\n\
             let _ = crate::util::passkey::mark_oauth_session(&other.id);",
            "respond(account.create_session(db, name).await?.into());\n\
             crate::util::passkey::mark_oauth_session(&session.id).await;",
        ] {
            assert_eq!(created_and_marked(&shipping(bad)), (1, 0), "{bad}");
        }
    }
}
