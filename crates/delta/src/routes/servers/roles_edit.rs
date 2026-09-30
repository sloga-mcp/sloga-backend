use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Database, File, PartialRole, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use validator::Validate;

/// # Edit Role
///
/// Edit a role by its id.
#[openapi(tag = "Server Permissions")]
#[patch("/<target>/roles/<role_id>", data = "<data>", rank = 1)]
pub async fn edit(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    role_id: String,
    data: Json<v0::DataEditRole>,
) -> Result<Json<v0::Role>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let mut server = target.as_server(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    calculate_server_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageRole)?;

    let member_rank = query.get_member_rank().unwrap_or(i64::MIN);

    if let Some(mut role) = server.roles.remove(&role_id) {
        // Prevent us from editing roles above us
        if role.rank <= member_rank {
            return Err(create_error!(NotElevated));
        }

        let v0::DataEditRole {
            name,
            colour,
            hoist,
            icon,
            remove,
            ..
        } = data;

        if remove.contains(&v0::FieldsRole::Icon) {
            if let Some(existing_icon) = &role.icon {
                db.mark_attachment_as_deleted(&existing_icon.id).await?;
            }
        }

        let mut final_icon = None;
        if let Some(icon_id) = icon {
            final_icon = Some(File::use_role_icon(db, &icon_id, &role_id, &user.id).await?);
        }

        let partial = PartialRole {
            name,
            colour,
            hoist,
            icon: final_icon,
            ..Default::default()
        };

        role.update(
            db,
            &server.id,
            partial,
            remove.into_iter().map(Into::into).collect(),
        )
        .await?;

        // No voice permission sync here (AFK S-3 F-7): `DataEditRole` only
        // changes the name, colour, hoist and icon, none of which a grant
        // reads, and `server` no longer holds this role (it was removed from
        // the in-memory document above), so a sync would compute every holder
        // as if they lacked it.

        Ok(Json(role.into()))
    } else {
        Err(create_error!(NotFound))
    }
}
