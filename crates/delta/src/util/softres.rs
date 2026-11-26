//! Shared helpers for the soft-reserve sheet routes.

use revolt_database::events::client::EventV1;
use revolt_database::{Channel, Database, ProtectedReadView, SoftResSheet};
use revolt_models::v0;
use revolt_permissions::{ChannelPermission, PermissionValue};
use revolt_result::{create_error, ErrorType, Result};

use crate::util::polls::now_ms;
use crate::util::softres_catalog;

/// Whether a read of `channel` (`permission_channel` is its permission
/// target) may serve `sheet`: only while its carrying message is servable
/// (`Message::is_servable`), so the sheet of a wipe-pending row answers like
/// a sheet of another channel (design 7.4 "S4"). An unprotected view serves
/// every row, so only a protected one reads the message; a missing message
/// is not served.
pub(crate) async fn sheet_is_servable(
    db: &Database,
    channel: &Channel,
    permission_channel: &Channel,
    sheet: &SoftResSheet,
) -> Result<bool> {
    let view = ProtectedReadView::of_read_target(channel, permission_channel);
    if !view.protected {
        return Ok(true);
    }

    match db.fetch_message(&sheet.message).await {
        Ok(message) => Ok(message.is_servable(&view)),
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => Ok(false),
        Err(error) => Err(error),
    }
}

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
///
/// Nothing is sent for a sheet whose carrying message is not servable
/// ([`sheet_is_servable`]): from a wipe's `Requested` on, pre-boundary
/// plaintext is unservable to broadcasts as well as reads (S4-D21). The
/// caller's lock or edit stands either way.
///
/// The callers publish after their write has landed, so a failed read in
/// that gate is reported and answers `Ok` with nothing sent (fail closed)
/// rather than turning a landed edit, lock or unlock into an error.
pub async fn publish_sheet_update(db: &Database, sheet: SoftResSheet) -> Result<()> {
    match sheet_may_be_published(db, &sheet).await {
        Ok(true) => {}
        Ok(false) => return Ok(()),
        Err(error) => {
            revolt_config::capture_error(&error);
            return Ok(());
        }
    }

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

/// The gate of [`publish_sheet_update`]: [`sheet_is_servable`] on the
/// sheet's own channel, a thread judged by its parent (#182)
async fn sheet_may_be_published(db: &Database, sheet: &SoftResSheet) -> Result<bool> {
    let channel = db.fetch_channel(&sheet.channel).await?;
    let permission_channel = channel.permission_target(db).await?.into_owned();
    sheet_is_servable(db, &channel, &permission_channel, sheet).await
}
