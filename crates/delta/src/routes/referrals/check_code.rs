use revolt_database::{Database, Referral};
use revolt_models::v0::UserFlags;
use revolt_result::{create_error, Result};
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Check Referral Code
///
/// Public, unauthenticated: check whether a referral code can be used at
/// signup. Accepts the bare code or its `SLOGA-` display form.
///
/// Returns an identical NotFound for an unknown code and for one whose owner
/// is a bot or a deleted account, so the owner's state cannot be probed.
#[openapi(tag = "Referrals")]
#[get("/codes/<code>")]
pub async fn check_code(db: &State<Database>, code: String) -> Result<EmptyResponse> {
    let Some(owner_id) = Referral::resolve_code(db, &code).await? else {
        return Err(create_error!(NotFound));
    };

    // A missing owner is already NotFound
    let owner = db.fetch_user(&owner_id).await?;
    let deleted = owner.flags.unwrap_or_default() & UserFlags::Deleted as i32 != 0;
    if owner.bot.is_some() || deleted {
        return Err(create_error!(NotFound));
    }

    Ok(EmptyResponse)
}
