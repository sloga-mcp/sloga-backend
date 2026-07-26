//! Shared helpers for the soft-reserve sheet routes.

use revolt_database::events::client::EventV1;
use revolt_database::{Database, SoftResSheet};
use revolt_models::v0;
use revolt_permissions::{ChannelPermission, PermissionValue};
use revolt_result::{create_error, Result};

use crate::util::polls::now_ms;
use crate::util::softres_catalog;

/// The hidden-sheet rule, applied server-side on every read: full reserve
/// rows AND per-item aggregate counts are visible only to the sheet
/// creator, moderators (ManageMessages), or everyone when the sheet is
/// not hidden. (The viewer's own row is always visible regardless.)
pub fn can_see_full(sheet: &SoftResSheet, user_id: &str, permissions: &PermissionValue) -> bool {
    !sheet.hidden
        || sheet.creator == user_id
        || permissions.has_channel_permission(ChannelPermission::ManageMessages)
}

/// Sheet management rule (settings edit / lock / unlock / export):
/// creator or ManageMessages.
pub fn authorize_manage_sheet(
    sheet: &SoftResSheet,
    user_id: &str,
    permissions: &PermissionValue,
) -> Result<()> {
    if sheet.creator != user_id {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageMessages)?;
    }
    Ok(())
}

/// Validate a set of reserve item ids against a sheet's rules: every id
/// must be in the sheet's raids' loot tables, must not be hard-reserved,
/// duplicates only when the sheet allows them, and (when the sheet
/// enforces class restriction) usable by the declared class.
pub fn validate_reserve_items(
    sheet: &SoftResSheet,
    items: &[u32],
    class: &v0::WowClass,
) -> Result<()> {
    if !sheet.allow_duplicates {
        let mut seen = std::collections::HashSet::new();
        if !items.iter().all(|item| seen.insert(*item)) {
            return Err(create_error!(SoftResInvalidItems));
        }
    }

    for item_id in items {
        // Hard-reserved items are off the table (softres.it parity).
        if sheet
            .hard_reserves
            .iter()
            .any(|hr| hr.item_id == *item_id)
        {
            return Err(create_error!(SoftResInvalidItems));
        }

        let item = softres_catalog::item_in_raids(*item_id, &sheet.raids)
            .ok_or_else(|| create_error!(SoftResInvalidItems))?;

        if sheet.class_restriction {
            if let Some(allowed) = &item.allowable_classes {
                if !allowed.iter().any(|c| c == class.as_str()) {
                    return Err(create_error!(SoftResClassRestricted));
                }
            }
        }
    }

    Ok(())
}

/// Publish `SoftresSheetUpdate` with the PUBLIC-gated model (reserves /
/// item_counts omitted when hidden even for the leader — the channel
/// topic has one audience; leaders refetch over REST).
pub async fn publish_sheet_update(db: &Database, sheet: SoftResSheet) -> Result<()> {
    let rows = db.fetch_reserves_for_sheet(&sheet.id).await?;
    let id = sheet.id.clone();
    let channel_id = sheet.channel.clone();
    let message_id = sheet.message.clone();
    let include_full = !sheet.hidden;

    EventV1::SoftresSheetUpdate {
        id,
        channel_id: channel_id.clone(),
        // The broadcast has no viewer: "" matches no user id, so
        // `my_reserve` is never populated in the shared payload.
        message_id,
        sheet: sheet.into_model(include_full, rows, "", now_ms()),
    }
    .p(channel_id)
    .await;

    Ok(())
}
