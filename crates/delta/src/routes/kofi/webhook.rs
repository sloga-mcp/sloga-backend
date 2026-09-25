//! Ko-fi webhook
//! POST /kofi/webhook
//!
//! Ko-fi posts `application/x-www-form-urlencoded` with a single `data`
//! field holding the payment as JSON.
use revolt_config::config;
use revolt_database::{Database, Donation, KofiPayload};
use revolt_result::{create_error, Result};
use rocket::form::Form;
use rocket::State;
use subtle::ConstantTimeEq;

#[derive(FromForm)]
pub struct KofiForm {
    /// JSON payment payload
    data: String,
}

/// # Ko-fi Webhook
///
/// Stores a Ko-fi payment. Unauthenticated: the request is trusted only
/// when its verification token matches the configured one. Returns 200
/// with an empty body once the payment is stored, including redeliveries.
#[openapi(skip)]
#[post("/webhook", data = "<form>")]
pub async fn webhook(db: &State<Database>, form: Form<KofiForm>) -> Result<()> {
    let config = config().await;
    let kofi = &config.api.kofi;

    // Unconfigured: behave as if the route does not exist
    if kofi.verification_token.is_empty() || kofi.email_hmac_key.is_empty() {
        return Err(create_error!(NotFound));
    }

    // The serde error can echo field values, so it is never returned
    let payload: KofiPayload = serde_json::from_str(&form.data).map_err(|_| {
        create_error!(FailedValidation {
            error: "invalid Ko-fi payload".to_string()
        })
    })?;

    if !token_matches(&kofi.verification_token, &payload.verification_token) {
        log::warn!("kofi webhook: verification token mismatch");
        return Err(create_error!(NotFound));
    }

    // Idempotent on message_id, so an error here is safe for Ko-fi to retry
    Donation::ingest(db, &payload, &kofi.email_hmac_key).await?;
    Ok(())
}

/// Constant-time token comparison (only the length can differ in timing)
fn token_matches(expected: &str, given: &str) -> bool {
    !expected.is_empty() && bool::from(expected.as_bytes().ct_eq(given.as_bytes()))
}

#[cfg(test)]
mod test {
    use super::token_matches;

    #[test]
    fn token_must_match_exactly() {
        assert!(token_matches("secret-token", "secret-token"));
        assert!(!token_matches("secret-token", "secret-tokeN"));
        assert!(!token_matches("secret-token", "secret-token "));
        assert!(!token_matches("secret-token", ""));
        assert!(!token_matches("", ""));
    }
}
