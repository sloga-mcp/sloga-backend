//! Finalize a streaming-channel link
//! POST /users/@me/connections/complete

use iso8601_timestamp::Timestamp;
use revolt_database::{ConnectionPlatform, Database, StreamConnection, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use validator::Validate;

use crate::routes::oauth::link;

/// # Complete Streaming-Channel Link
///
/// Consumes the one-time handoff parked by the provider callback and
/// persists the connection — but ONLY when the session user is the user
/// who initiated the flow. That check is the CSRF gate: a handoff created
/// from someone else's consent must never attach to this account.
#[openapi(tag = "User Information")]
#[post("/@me/connections/complete", data = "<data>")]
pub async fn connections_complete(
    db: &State<Database>,
    user: User,
    data: Json<v0::DataConnectionComplete>,
) -> Result<Json<v0::UserConnection>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let platform =
        ConnectionPlatform::from_str(&data.platform).ok_or_else(|| create_error!(InvalidOperation))?;

    let handoff = link::consume_link_handoff(&data.platform, &data.code)
        .await
        .ok_or_else(|| create_error!(NotFound))?;

    // Session user must be the state-bound initiator (see module doc in
    // routes/oauth/link.rs) — mismatched handoffs are discarded, not retried
    if handoff.user_id != user.id {
        return Err(create_error!(InvalidOperation));
    }

    let connection = StreamConnection {
        id: StreamConnection::compose_id(&user.id, &platform),
        user_id: user.id.clone(),
        platform,
        channel_id: handoff.channel_id,
        handle: handoff.handle,
        display_name: handoff.display_name,
        refresh_token: handoff.refresh_token,
        access_token: handoff.access_token,
        token_expiry: handoff.expires_in.and_then(|secs| {
            Timestamp::now_utc().checked_add(iso8601_timestamp::Duration::seconds(secs as i64))
        }),
        live: None,
        poll_failures: 0,
        last_notified_live_at: None,
    };

    db.upsert_stream_connection(&connection).await?;
    StreamConnection::sync_user_field(db, &user.id).await?;

    Ok(Json(connection.to_public().into()))
}
