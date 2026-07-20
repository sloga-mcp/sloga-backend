//! Unlink a streaming channel
//! DELETE /users/@me/connections/<platform>

use revolt_database::{ConnectionPlatform, Database, StreamConnection, User};
use revolt_result::{create_error, Result};
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Unlink Streaming Channel
///
/// Removes the connection, revokes provider tokens (best-effort) and
/// broadcasts the updated user.
#[openapi(tag = "User Information")]
#[delete("/@me/connections/<platform>")]
pub async fn connections_unlink(
    db: &State<Database>,
    user: User,
    platform: &str,
) -> Result<EmptyResponse> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let platform =
        ConnectionPlatform::from_str(platform).ok_or_else(|| create_error!(InvalidOperation))?;

    let removed = db.delete_stream_connection(&user.id, &platform).await?;
    removed.revoke_tokens().await;

    StreamConnection::sync_user_field(db, &user.id).await?;

    Ok(EmptyResponse)
}
