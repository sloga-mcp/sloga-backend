use once_cell::sync::Lazy;
use regex::Regex;
use revolt_config::config;
use revolt_database::{Database, Member, Session, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};

use rocket::{serde::json::Json, State};
use serde::{Deserialize, Serialize};
use validator::Validate;

/// Regex for valid usernames
///
/// Block zero width space
/// Block lookalike characters
pub static RE_USERNAME: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(\p{L}|[\d_.-])+$").unwrap());

/// # New User Data
#[derive(Validate, Serialize, Deserialize, JsonSchema)]
pub struct DataOnboard {
    /// New username which will be used to identify the user on the platform
    #[validate(length(min = 2, max = 32), regex = "RE_USERNAME")]
    username: String,
}

/// # Complete Onboarding
///
/// This sets a new username, completes onboarding and allows a user to start using Revolt.
#[openapi(tag = "Onboarding")]
#[post("/complete", data = "<data>")]
pub async fn complete(
    db: &State<Database>,
    session: Session,
    user: Option<User>,
    data: Json<DataOnboard>,
) -> Result<Json<v0::User>> {
    if user.is_some() {
        return Err(create_error!(AlreadyOnboarded));
    }

    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let user = User::create(db, data.username, session.user_id, None).await?;

    // Auto-join the configured welcome / landing-spot server, if one is set.
    // Best-effort: onboarding must never fail because of this. We ignore a
    // missing/misconfigured server id, an existing membership, a ban, etc.
    if let Some(welcome_id) = config()
        .await
        .features
        .welcome_server
        .as_deref()
        .filter(|id| !id.is_empty())
    {
        match db.fetch_server(welcome_id).await {
            Ok(server) => {
                if let Err(err) = Member::create(db, &server, &user, None).await {
                    log::warn!(
                        "Failed to auto-join user {} to welcome server {welcome_id}: {err:?}",
                        user.id
                    );
                }
            }
            Err(err) => log::warn!(
                "welcome_server {welcome_id} is set but could not be fetched: {err:?}"
            ),
        }
    }

    Ok(Json(user.into_self(false).await))
}
