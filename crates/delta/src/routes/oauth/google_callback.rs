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
        .arg(super::state_key(&state))
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
        v0::ResponseLogin::Success(
            account
                .create_session(db, "Google OAuth".to_string())
                .await
                .map_err(|_| "internal")?
                .into(),
        )
    };

    // Hand the login response to the client via a one-time code so the
    // session token never appears in a URL.
    let handoff = nanoid!(43);
    let payload = serde_json::to_string(&response_login).map_err(|_| "internal")?;

    let set: Option<String> = conn
        .set_options(
            super::handoff_key(&handoff),
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
