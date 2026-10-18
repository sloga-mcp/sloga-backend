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
    let before_cipher = user.public_cipher();

    db.set_supporter_show_badges(&user.id, data.show_badges)
        .await?;

    let user = db.fetch_user(&user.id).await?;
    user.publish_perks_update_if_changed(db, before_badges, before_style, before_perks)
        .await;
    // The Cipher badge follows the same preference; the stored copy does
    // not change, so it is re-published (or cleared) here
    user.publish_public_cipher_if_changed(db, before_cipher)
        .await;

    Ok(Json(supporter_summary(&user).await))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::events::client::EventV1;
    use revolt_database::{now_ms, CipherMembership};
    use revolt_models::v0;
    use revolt_payments::engine::sync_user_badge;
    use rocket::http::{ContentType, Status};
    use serde_json::json;

    /// `(cipher carried, Cipher cleared)` of a UserUpdate about `user_id`
    fn cipher_update(event: &EventV1, user_id: &str) -> Option<(Option<v0::UserCipher>, bool)> {
        match event {
            EventV1::UserUpdate {
                id, data, clear, ..
            } if id == user_id => {
                Some((data.cipher.clone(), clear.contains(&v0::FieldsUser::Cipher)))
            }
            _ => None,
        }
    }

    /// The user as their own session reads it
    async fn fetched(
        harness: &TestHarness,
        session: &revolt_database::Session,
        id: &str,
    ) -> serde_json::Value {
        let response =
            TestHarness::with_session(session.clone(), harness.client.get(format!("/users/{id}")))
                .await;
        assert_eq!(response.status(), Status::Ok);
        response.into_json().await.expect("user body")
    }

    async fn set_show_badges(
        harness: &TestHarness,
        session: &revolt_database::Session,
        show: bool,
    ) {
        let response = TestHarness::with_session(
            session.clone(),
            harness
                .client
                .patch("/users/@me/supporter")
                .header(ContentType::JSON)
                .body(json!({ "show_badges": show }).to_string()),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
        let summary = response
            .into_json::<serde_json::Value>()
            .await
            .expect("supporter summary");
        // `show_badges` is left out of the summary when false
        assert_eq!(summary["show_badges"].as_bool().unwrap_or(false), show);
    }

    /// "Show supporter badges on my profile" covers the Cipher badge: hidden
    /// from every read and every event while off (the stored copy keeps
    /// following the membership), shown again, current, when back on
    #[test]
    fn the_show_badges_toggle_hides_and_republishes_the_cipher_badge() {
        crate::util::test::rt()
            .block_on(the_show_badges_toggle_hides_and_republishes_the_cipher_badge_case())
    }

    async fn the_show_badges_toggle_hides_and_republishes_the_cipher_badge_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let id = user.id.clone();
        let t99 = v0::UserCipher {
            number: 42,
            tier: v0::CipherTier::T99,
        };
        let t299 = v0::UserCipher {
            number: 42,
            tier: v0::CipherTier::T299,
        };

        // A member: the badge is published
        assert!(harness
            .db
            .insert_cipher_membership(&CipherMembership {
                user_id: id.clone(),
                number: 42,
                tier: v0::CipherTier::T99,
                prot_grant: 16_500,
                orders: vec!["01JTESTCIPHERORDER00000001".to_string()],
                disputed_orders: vec![],
                granted_at: now_ms(),
                revoked_at: None,
                revoke_reason: None,
                prot_posted_at: None,
                version: 0,
            })
            .await
            .unwrap());
        sync_user_badge(&harness.db, &id).await.unwrap();
        harness
            .wait_for_event(&id, |e| {
                cipher_update(e, &id) == Some((Some(t99.clone()), false))
            })
            .await;
        assert_eq!(
            fetched(&harness, &session, &id).await["cipher"]["number"],
            42
        );

        // Badges off: one clear goes out and no read shows it
        set_show_badges(&harness, &session, false).await;
        harness
            .wait_for_event(&id, |e| cipher_update(e, &id) == Some((None, true)))
            .await;
        assert!(fetched(&harness, &session, &id).await["cipher"].is_null());
        assert_eq!(
            harness.db.fetch_user(&id).await.unwrap().cipher,
            Some(t99.clone()),
            "the stored badge still mirrors the membership"
        );

        // The membership changes while hidden: the sync stores the new
        // badge but publishes a clear, never the badge
        let m = harness
            .db
            .fetch_cipher_membership(&id)
            .await
            .unwrap()
            .unwrap();
        let mut upgraded = m.clone();
        upgraded.tier = v0::CipherTier::T299;
        upgraded.prot_grant = 75_000;
        assert!(harness
            .db
            .update_cipher_membership_if_version(&upgraded, m.version)
            .await
            .unwrap());
        sync_user_badge(&harness.db, &id).await.unwrap();
        harness
            .wait_for_event(&id, |e| cipher_update(e, &id) == Some((None, true)))
            .await;
        assert_eq!(
            harness.db.fetch_user(&id).await.unwrap().cipher,
            Some(t299.clone())
        );
        assert!(fetched(&harness, &session, &id).await["cipher"].is_null());

        // Badges on: the current badge is published again
        set_show_badges(&harness, &session, true).await;
        harness
            .wait_for_event(&id, |e| {
                cipher_update(e, &id) == Some((Some(t299.clone()), false))
            })
            .await;
        let shown = fetched(&harness, &session, &id).await;
        assert_eq!(shown["cipher"]["number"], 42);
        assert_eq!(
            serde_json::from_value::<v0::UserCipher>(shown["cipher"].clone()).unwrap(),
            t299
        );

        // Nothing carried a badge while it was hidden: every event pulled
        // in before the last one is buffered (FIFO), and none carries one
        harness
            .assert_no_buffered_event(&id, |e| matches!(cipher_update(e, &id), Some((Some(_), _))));
    }

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
