use revolt_database::{util::reference::Reference, Database, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # Fetch Open MLS Group
///
/// The channel's open MLS group, if any — the pre-join mode surface's
/// probe (plan §3.4 compose-time rule: the join button shows the mode the
/// call WILL use) and the A3 cap pre-warning input.
///
/// Read-only; reveals only metadata the server already holds and §5.6
/// already concedes (group existence + roster size), and only to users who
/// pass the channel-access check. 404 when no open group exists (a
/// `room_finished` webhook closes groups, so absence is live truth).
#[openapi(tag = "MLS")]
#[get("/channels/<channel_id>/open_group")]
pub async fn open_group(
    db: &State<Database>,
    user: User,
    channel_id: String,
) -> Result<Json<v0::ResponseOpenMlsGroup>> {
    super::require_media_e2ee_enabled().await?;

    let channel = Reference::from_unchecked(&channel_id).as_channel(db).await?;
    super::require_channel_access(db, &user, &channel).await?;

    let group = db
        .fetch_open_mls_group_for_channel(&channel.id())
        .await?
        .ok_or_else(|| create_error!(NotFound))?;

    Ok(Json(v0::ResponseOpenMlsGroup {
        group_id: group.id,
        member_count: group.members.len(),
    }))
}
