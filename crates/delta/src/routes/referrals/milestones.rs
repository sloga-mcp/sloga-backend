use revolt_database::{Database, User, TIER_CUSTOM_BADGE};
use revolt_models::v0::{self, UserFlags};
use revolt_result::{create_error, Result};

use rocket::{serde::json::Json, State};

/// # Fetch Referral Milestones
///
/// List every user who has reached the custom badge tier, highest count
/// first, so staff can reach out about their badge. Requires a privileged
/// account.
#[openapi(tag = "Referrals")]
#[get("/milestones")]
pub async fn milestones(
    db: &State<Database>,
    user: User,
) -> Result<Json<Vec<v0::ReferralMilestone>>> {
    if !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    let mut milestones: Vec<v0::ReferralMilestone> = db
        .fetch_users_with_referral_count_at_least(TIER_CUSTOM_BADGE as i32)
        .await?
        .into_iter()
        .filter(|u| u.flags.unwrap_or_default() & UserFlags::Deleted as i32 == 0)
        .map(|u| v0::ReferralMilestone {
            referral_count: u.referral_count.unwrap_or_default().max(0) as u32,
            user_id: u.id,
        })
        .collect();

    milestones.sort_by(|a, b| {
        b.referral_count
            .cmp(&a.referral_count)
            .then_with(|| a.user_id.cmp(&b.user_id))
    });

    log::info!(
        "AUDIT referral_milestones: actor={} count={}",
        user.id,
        milestones.len()
    );

    Ok(Json(milestones))
}
