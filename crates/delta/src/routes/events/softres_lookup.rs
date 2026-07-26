use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{Database, User};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;

use crate::util::polls::now_ms;
use crate::util::softres::can_see_full;

/// # Fetch Event's Soft-Reserve Sheet
///
/// The soft-reserve sheet linked to a calendar event, if any. Event
/// visibility does NOT override sheet-channel visibility: the requester
/// must also be able to view the channel the sheet lives in. "No sheet"
/// and "can't view the sheet's channel" are both 404 — no existence
/// oracle.
#[openapi(tag = "Soft Reserves")]
#[get("/event/<target>/softres")]
pub async fn fetch_event_softres(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<v0::SoftRes>> {
    super::require_events_enabled().await?;

    let event = db.fetch_event(target.id).await?;
    super::authorize_view(db, &user, &event).await?;

    // A sheet linked to a cancelled event still resolves (the cancel hook
    // locks it; unlink semantics are v2).
    let Some(sheet) = db.fetch_sheet_by_event(&event.id).await? else {
        return Err(create_error!(NotFound));
    };

    // Sheet-channel visibility, resolved through `permission_target` —
    // sheets can live in threads, whose permissions delegate to the
    // parent; a naive per-channel query would skip parent overrides.
    let channel = db.fetch_channel(&sheet.channel).await?;
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    if !permissions.has_channel_permission(ChannelPermission::ViewChannel) {
        return Err(create_error!(NotFound));
    }

    let rows = db.fetch_reserves_for_sheet(&sheet.id).await?;
    let include_full = can_see_full(&sheet, &user.id, &permissions);
    Ok(Json(sheet.into_model(include_full, rows, &user.id, now_ms())))
}
