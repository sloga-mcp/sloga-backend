use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Database, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_user_permissions, UserPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # List E2EE Devices
///
/// List a user's registered E2EE devices without consuming any key material.
/// Used for device-list reconciliation on connect and for the own-device
/// management UI.
///
/// For your own devices the listing includes registration/last-seen times and
/// the remaining one-time key count (drives replenishment); for peers only
/// the device id, protocol version and identity key are returned.
#[openapi(tag = "E2EE")]
#[get("/devices/<target>")]
pub async fn fetch_devices(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<Vec<v0::E2EEDeviceInfo>>> {
    super::require_e2ee_enabled().await?;

    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let target = target.as_user(db).await?;
    let own = target.id == user.id;

    if !own {
        let mut query = DatabasePermissionQuery::new(db, &user).user(&target);
        calculate_user_permissions(&mut query)
            .await
            .throw_if_lacking_user_permission(UserPermission::SendMessage)?;
    }

    let mut devices = vec![];
    for identity in db.fetch_e2ee_identities(&target.id).await? {
        let one_time_key_count = if own {
            Some(
                db.count_e2ee_one_time_keys(&target.id, &identity.device_id)
                    .await?,
            )
        } else {
            None
        };

        devices.push(v0::E2EEDeviceInfo {
            created_at: own.then(|| identity.created_at.to_string()),
            last_seen_at: own.then(|| identity.last_seen_at.to_string()),
            device_id: identity.device_id,
            protocol_version: identity.protocol_version,
            ed25519_key: identity.ed25519_key,
            one_time_key_count,
        });
    }

    Ok(Json(devices))
}
