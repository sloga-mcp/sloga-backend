use revolt_config::config;
use revolt_database::{
    donation_tier_list, generate_claim_code, next_donation_tier, now_ms, Database, Donation,
    DonationClaimCode, User, CLAIM_CODE_TTL_DAYS, DAY_MS,
};
use revolt_models::v0;
use revolt_result::{create_error, ErrorType, Result};
use validator::Validate;

use rocket::{serde::json::Json, State};

/// How many fresh codes to try before giving up on a collision streak
const CLAIM_CODE_ATTEMPTS: usize = 8;

/// Build the supporter summary shown to the user themselves
async fn supporter_summary(user: &User) -> v0::SupporterSummary {
    let now = now_ms();
    let (lifetime_usd_cents, monthly_until, show_badges) = match &user.supporter {
        Some(supporter) => (
            supporter.lifetime_usd_cents,
            supporter.monthly_until,
            supporter.show_badges,
        ),
        None => (0, None, true),
    };

    v0::SupporterSummary {
        lifetime_usd_cents,
        monthly_active: monthly_until.is_some_and(|until| until > now),
        monthly_until,
        show_badges,
        next_tier_cents: next_donation_tier(lifetime_usd_cents),
        tiers: donation_tier_list(),
        kofi_url: config().await.api.kofi.page_url,
    }
}

/// When a claim code stops being accepted
fn claim_code_expiry(code: &DonationClaimCode) -> i64 {
    code.created_at + CLAIM_CODE_TTL_DAYS * DAY_MS
}

/// # Fetch Supporter Status
///
/// Fetch your donation total, monthly status and progress along the
/// donation ladder.
#[openapi(tag = "User Information")]
#[get("/@me/supporter")]
pub async fn fetch_supporter(
    _db: &State<Database>,
    user: User,
) -> Result<Json<v0::SupporterSummary>> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    Ok(Json(supporter_summary(&user).await))
}

/// # Create Supporter Claim Code
///
/// Get a code to include in a Ko-fi donation message so the donation is
/// linked to your account. An unexpired code is returned again rather
/// than replaced. Returns NotFound when Ko-fi donations are not set up on
/// this server.
#[openapi(tag = "User Information")]
#[post("/@me/supporter/code")]
pub async fn create_supporter_code(
    db: &State<Database>,
    user: User,
) -> Result<Json<v0::SupporterClaimCode>> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    // Only the webhook ever redeems a code, and it refuses every call unless
    // both secrets are set. Without them no code could link a donation, so
    // none is handed out and the answer matches the claim route's.
    let config = config().await;
    let kofi = &config.api.kofi;
    if kofi.verification_token.is_empty() || kofi.email_hmac_key.is_empty() {
        return Err(create_error!(NotFound));
    }

    let now = now_ms();
    if let Some(existing) = db.fetch_claim_code_by_user(&user.id).await? {
        if claim_code_expiry(&existing) > now {
            return Ok(Json(v0::SupporterClaimCode {
                expires_at: claim_code_expiry(&existing),
                code: existing.code,
            }));
        }

        // Already gone means a cleanup got there first
        match db.delete_claim_code(&existing.code).await {
            Ok(()) => {}
            Err(error) if matches!(error.error_type, ErrorType::NotFound) => {}
            Err(error) => return Err(error),
        }
    }

    let mut last_error = None;
    for _ in 0..CLAIM_CODE_ATTEMPTS {
        let code = DonationClaimCode {
            code: generate_claim_code(),
            user: user.id.clone(),
            created_at: now,
        };

        // A collision with another user's code is an error; try a fresh one
        match db.insert_claim_code(&code).await {
            Ok(()) => {
                return Ok(Json(v0::SupporterClaimCode {
                    expires_at: claim_code_expiry(&code),
                    code: code.code,
                }))
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| create_error!(InternalError)))
}

/// # Claim Donation
///
/// Link a Ko-fi donation to your account by its transaction id. The
/// donation is claimed when it was paid from your account's email address;
/// otherwise it is queued for staff review.
#[openapi(tag = "User Information")]
#[post("/@me/supporter/claim", data = "<data>")]
pub async fn claim_supporter(
    db: &State<Database>,
    user: User,
    data: Json<v0::DataSupporterClaim>,
) -> Result<Json<v0::SupporterClaimResult>> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let config = config().await;
    let key = &config.api.kofi.email_hmac_key;
    if key.is_empty() {
        return Err(create_error!(NotFound));
    }

    let account = db.fetch_account(&user.id).await?;
    let outcome =
        Donation::claim_by_transaction(db, &user, &account.email, &data.transaction_id, key)
            .await?;

    Ok(Json(v0::SupporterClaimResult { outcome }))
}

/// # Edit Supporter Preferences
///
/// Choose whether your supporter badges are shown on your profile.
#[openapi(tag = "User Information")]
#[patch("/@me/supporter", data = "<data>")]
pub async fn edit_supporter(
    db: &State<Database>,
    user: User,
    data: Json<v0::DataEditSupporter>,
) -> Result<Json<v0::SupporterSummary>> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let data = data.into_inner();

    // Snapshot what other clients see before the write, so only a real
    // change goes out
    let now = now_ms();
    let before_badges = user.get_badges().await;
    let before_style = user.filtered_name_style(now);
    let before_perks = user.perks(now);

    db.set_supporter_show_badges(&user.id, data.show_badges)
        .await?;

    let user = db.fetch_user(&user.id).await?;
    user.publish_perks_update_if_changed(db, before_badges, before_style, before_perks)
        .await;

    Ok(Json(supporter_summary(&user).await))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use rocket::http::{ContentType, Status};
    use serde_json::json;

    #[test]
    fn supporter_code_not_found_when_kofi_unconfigured() {
        crate::util::test::rt().block_on(supporter_code_not_found_when_kofi_unconfigured_case())
    }

    async fn supporter_code_not_found_when_kofi_unconfigured_case() {
        let harness = TestHarness::new().await;

        // The test config leaves both Ko-fi secrets empty. With either one
        // set, this test would not reach the not-configured path.
        let kofi = revolt_config::config().await.api.kofi;
        assert!(
            kofi.verification_token.is_empty() && kofi.email_hmac_key.is_empty(),
            "Ko-fi secrets are configured for this test run"
        );

        let (_, session, user) = harness.new_user().await;

        // Claim route: the existing not-configured answer
        let response = TestHarness::with_session(
            session.clone(),
            harness
                .client
                .post("/users/@me/supporter/claim")
                .header(ContentType::JSON)
                .body(json!({ "transaction_id": "txn-unconfigured" }).to_string()),
        )
        .await;
        assert_eq!(response.status(), Status::NotFound);
        let error = response
            .into_json::<serde_json::Value>()
            .await
            .expect("claim error body");
        assert_eq!(error["type"], "NotFound");

        // Code route: the same answer, and no code is stored
        let response =
            TestHarness::with_session(session, harness.client.post("/users/@me/supporter/code"))
                .await;
        assert_eq!(response.status(), Status::NotFound);
        let error = response
            .into_json::<serde_json::Value>()
            .await
            .expect("code error body");
        assert_eq!(error["type"], "NotFound");

        let stored = harness
            .db
            .fetch_claim_code_by_user(&user.id)
            .await
            .expect("fetch claim code");
        assert!(stored.is_none(), "no claim code may be handed out");
    }
}
