use revolt_config::config;
use revolt_database::{
    next_referral_tier, referral_tier_list, Database, Referral, ReferralStatus, User,
};
use revolt_models::v0;
use revolt_result::{create_error, Result};

use rocket::{serde::json::Json, State};

/// # Fetch Referrals
///
/// Fetch your referral code, shareable link and ladder progress.
/// Only counts are returned, never the identities of invited users.
#[openapi(tag = "User Information")]
#[get("/@me/referrals")]
pub async fn fetch_referrals(
    db: &State<Database>,
    user: User,
) -> Result<Json<v0::ReferralSummary>> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let code = Referral::code_for_user(db, &user.id).await?;
    let display_code = format!("SLOGA-{code}");
    let link = format!(
        "{}/r/{code}",
        config().await.hosts.app.trim_end_matches('/')
    );

    let qualified = db
        .count_referrals_by_referrer(&user.id, ReferralStatus::Qualified)
        .await?;
    let pending = db
        .count_referrals_by_referrer(&user.id, ReferralStatus::Pending)
        .await?;
    let expired = db
        .count_referrals_by_referrer(&user.id, ReferralStatus::Expired)
        .await?;

    Ok(Json(v0::ReferralSummary {
        code,
        display_code,
        link,
        qualified,
        pending,
        expired,
        next_tier: next_referral_tier(qualified),
        tiers: referral_tier_list(),
    }))
}
