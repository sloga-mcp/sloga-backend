use revolt_database::{util::reference::Reference, Database, User};
use revolt_result::{create_error, Result};
use rocket_empty::EmptyResponse;
use serde::Deserialize;
use validator::Validate;

use rocket::{serde::json::Json, State};

/// # Suspension Data
#[derive(Validate, Deserialize, JsonSchema)]
pub struct DataUserSuspend {
    /// Days to suspend the user for; omit for an indefinite suspension
    duration_days: Option<usize>,
    /// Reasons for the suspension, emailed to the user if provided
    #[validate(length(min = 0, max = 16))]
    reason: Option<Vec<String>>,
}

/// # Suspend User
///
/// Suspend a user from the platform: disables their account,
/// revokes all of their sessions and optionally emails them the reason.
///
/// Requires a privileged account.
#[openapi(tag = "User Safety")]
#[post("/users/<target>/suspend", data = "<data>")]
pub async fn user_suspend(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<DataUserSuspend>,
) -> Result<EmptyResponse> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    if !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    let mut target_user = target.as_user(db).await?;

    // Cannot suspend yourself or another privileged user
    if target_user.id == user.id || target_user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    target_user
        .suspend(db, data.duration_days, data.reason)
        .await
        .map(|_| EmptyResponse)
}
