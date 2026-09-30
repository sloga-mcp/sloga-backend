use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference}, voice::{sync_server_voice_permissions, VoiceClient}, Database, PartialServer, User
};
use revolt_models::v0;
use revolt_permissions::{
    calculate_server_permissions, ChannelPermission, DataPermissionsValue, Override,
};
use revolt_result::Result;
use rocket::{serde::json::Json, State};

/// # Set Default Permission
///
/// Sets permissions for the default role in this server.
#[openapi(tag = "Server Permissions")]
#[put("/<target>/permissions/default", data = "<data>", rank = 1)]
pub async fn set_default_server_permissions(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    target: Reference<'_>,
    data: Json<DataPermissionsValue>,
) -> Result<Json<v0::Server>> {
    let data = data.into_inner();

    let mut server = target.as_server(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    let permissions = calculate_server_permissions(&mut query).await;

    permissions.throw_if_lacking_channel_permission(ChannelPermission::ManagePermissions)?;

    // Ensure we have permissions to grant these permissions forwards
    permissions
        .throw_permission_override(
            None,
            &Override {
                allow: data.permissions,
                deny: 0,
            },
        )
        .await?;

    server
        .update(
            db,
            PartialServer {
                default_permissions: Some(data.permissions as i64),
                ..Default::default()
            },
            vec![],
        )
        .await?;

    // Every channel is tried before the first failure is answered (AFK S-3
    // D-6); `server` already carries the new default permissions.
    sync_server_voice_permissions(db, voice_client, &server, None).await?;

    Ok(Json(server.into()))
}
