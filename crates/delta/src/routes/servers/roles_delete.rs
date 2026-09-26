use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    voice::{sync_server_voice_permissions, VoiceClient},
    Database, User,
};
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Delete Role
///
/// Delete a server role by its id.
#[openapi(tag = "Server Permissions")]
#[delete("/<target>/roles/<role_id>")]
pub async fn delete(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    role_id: String,
    voice_client: &State<VoiceClient>,
) -> Result<EmptyResponse> {
    let mut server = target.as_server(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    calculate_server_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageRole)?;

    let member_rank = query.get_member_rank().unwrap_or(i64::MIN);

    let role = server
        .roles
        .remove(&role_id)
        .ok_or_else(|| create_error!(NotFound))?;

    if role.rank <= member_rank {
        return Err(create_error!(NotElevated));
    }

    role.delete(db, &server.id).await?;

    // Everyone in every call re-syncs, not just the role's holders (AFK S-3
    // F-8): on MongoDB `delete_role` has already pulled the role from every
    // member, so a sync scoped to it would match nobody. `server` no longer
    // holds the role, so each grant is computed without it. The helper tries
    // every channel before answering its first failure (D-6).
    sync_server_voice_permissions(db, voice_client, &server, None).await?;

    Ok(EmptyResponse)
}
