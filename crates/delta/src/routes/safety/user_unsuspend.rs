use revolt_database::{util::reference::Reference, Database, User};
use revolt_result::{create_error, Result};
use rocket_empty::EmptyResponse;

use rocket::State;

/// # Unsuspend User
///
/// Lift a user's suspension: re-enables their account and clears
/// their suspension flags so they can log in again.
///
/// Requires a privileged account.
#[openapi(tag = "User Safety")]
#[delete("/users/<target>/suspend")]
pub async fn user_unsuspend(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<EmptyResponse> {
    if !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    let mut target_user = target.as_user(db).await?;
    target_user.unsuspend(db).await.map(|_| EmptyResponse)
}
