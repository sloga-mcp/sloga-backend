//! Sign in with Apple callback
//! POST /auth/oauth/apple/callback
//!
//! Apple POSTs the result here (`response_mode=form_post`) because we
//! request the `email` scope — this is the one structural difference
//! from the Google flow, which uses a GET redirect.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use nanoid::nanoid;
use redis_kiss::{get_connection, redis, AsyncCommands};
use revolt_config::config;
use revolt_database::{Account, Database, EmailVerification, MFATicket};
use revolt_models::v0;
use rocket::form::Form;
use rocket::response::Redirect;
use rocket::State;

#[derive(FromForm)]
pub struct AppleCallbackForm {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    /// JSON blob with the user's name, sent on first authorisation only —
    /// unused, the username comes from onboarding
    #[allow(dead_code)]
    user: Option<String>,
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    id_token: String,
}

/// Apple serialises some boolean claims as the string "true"/"false"
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum BoolOrString {
    Bool(bool),
    String(String),
}

impl BoolOrString {
    fn as_bool(&self) -> bool {
        match self {
            BoolOrString::Bool(value) => *value,
            BoolOrString::String(value) => value == "true",
        }
    }
}

#[derive(serde::Deserialize)]
struct IdTokenClaims {
    iss: String,
    aud: String,
    exp: i64,
    sub: String,
    email: Option<String>,
    email_verified: Option<BoolOrString>,
}

/// # Apple OAuth Callback
///
/// Completes the code exchange with Apple, finds or creates the
/// matching account and redirects to the frontend with a one-time
/// handoff code the client swaps for the session.
#[openapi(skip)]
#[post("/apple/callback", data = "<form>")]
pub async fn apple_callback(db: &State<Database>, form: Form<AppleCallbackForm>) -> Redirect {
    match callback_inner(db, form.into_inner()).await {
        Ok(redirect) => redirect,
        Err(code) => error_redirect(code).await,
    }
}

async fn error_redirect(code: &str) -> Redirect {
    let config = config().await;
    Redirect::to(format!(
        "{}/login/oauth?error={}&provider=apple",
        config.hosts.app, code
    ))
}

async fn callback_inner(
    db: &State<Database>,
    form: AppleCallbackForm,
) -> std::result::Result<Redirect, &'static str> {
    let config = config().await;
    let apple = &config.api.oauth.apple;

    if !apple.enabled {
        return Err("disabled");
    }

    if form.error.is_some() {
        // User cancelled at the consent screen or Apple reported failure
        return Err("cancelled");
    }

    let (code, state) = match (form.code, form.state) {
        (Some(code), Some(state)) => (code, state),
        _ => return Err("invalid_request"),
    };

    // Retrieve + consume the PKCE verifier; missing means forged or expired state
    let mut conn = get_connection()
        .await
        .map_err(|_| "internal")?
        .into_inner();

    let verifier: Option<String> = redis::cmd("GETDEL")
        .arg(super::state_key("apple", &state))
        .query_async(&mut conn)
        .await
        .map_err(|_| "internal")?;

    let verifier = verifier.ok_or("invalid_state")?;

    // Apple's client secret is not static: it is a short-lived ES256 JWT
    // signed with the Sign in with Apple private key.
    let client_secret = client_secret(apple).ok_or("internal")?;

    // Exchange the authorisation code for tokens
    let response = reqwest::Client::new()
        .post("https://appleid.apple.com/auth/token")
        .form(&[
            ("code", code.as_str()),
            ("client_id", apple.client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            (
                "redirect_uri",
                &super::apple_authorise::redirect_uri(apple, &config.hosts.api),
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

    // The id_token comes directly from Apple over TLS on an
    // authenticated (client_secret) exchange, so validating claims is
    // sufficient without a JWKS signature check (OIDC Core 3.1.3.7).
    let claims = decode_claims(&tokens.id_token).ok_or("invalid_token")?;

    if claims.iss != "https://appleid.apple.com" {
        return Err("invalid_token");
    }

    if claims.aud != apple.client_id {
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

    if !claims.email_verified.as_ref().is_some_and(BoolOrString::as_bool) {
        return Err("email_unverified");
    }
    let email = claims.email.clone().ok_or("email_unverified")?;

    // Find or create the account: by Apple id, then by verified email
    // (auto-link), then a brand new account. Note the email may be a
    // @privaterelay.appleid.com address if the user hid their real one.
    let mut account =
        if let Some(account) = fetch_by_apple_id(db, &claims.sub).await? {
            account
        } else {
            let normalised = revolt_database::util::email::normalise_email(email.clone());
            if let Some(mut account) = db
                .fetch_account_by_normalised_email(&normalised)
                .await
                .map_err(|_| "internal")?
            {
                account.apple_id = Some(claims.sub.clone());
                account.save(db).await.map_err(|_| "internal")?;
                account
            } else {
                Account::new_from_apple(db, email, claims.sub.clone())
                    .await
                    .map_err(|_| "internal")?
            }
        };

    if account.disabled {
        return Err("disabled_account");
    }

    // Apple has verified ownership of this email
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
                .create_session(db, "Apple OAuth".to_string())
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
            super::handoff_key("apple", &handoff),
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
        "{}/login/oauth?code={}&provider=apple",
        config.hosts.app, handoff
    )))
}

/// Build the ES256 client-secret JWT (Team ID as issuer, Services ID as
/// subject, signed with the .p8 key)
fn client_secret(apple: &revolt_config::ApiOauthApple) -> Option<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs() as i64;

    let header = jsonwebtoken::Header {
        alg: jsonwebtoken::Algorithm::ES256,
        kid: Some(apple.key_id.clone()),
        ..Default::default()
    };

    let claims = serde_json::json!({
        "iss": apple.team_id,
        "iat": now,
        "exp": now + 300,
        "aud": "https://appleid.apple.com",
        "sub": apple.client_id,
    });

    let key = jsonwebtoken::EncodingKey::from_ec_pem(apple.private_key.as_bytes()).ok()?;
    jsonwebtoken::encode(&header, &claims, &key).ok()
}

fn decode_claims(id_token: &str) -> Option<IdTokenClaims> {
    let payload = id_token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&bytes).ok()
}

async fn fetch_by_apple_id(
    db: &State<Database>,
    apple_id: &str,
) -> std::result::Result<Option<Account>, &'static str> {
    db.fetch_account_by_apple_id(apple_id)
        .await
        .map_err(|_| "internal")
}
