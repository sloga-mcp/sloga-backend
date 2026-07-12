//! Thread write-lock enforcement, shared by every route that mutates content
//! inside a thread (`message_send`, `message_edit`, `message_react`,
//! `message_pin`).

use revolt_database::Channel;
use revolt_permissions::{ChannelPermission, PermissionValue};
use revolt_result::{create_error, Result};

/// Reject participation in an archived or locked thread.
///
/// Holders of `ManageChannel` on the parent are exempt (managing a thread is
/// also how it gets unarchived/unlocked). No-op for every other channel type.
pub fn ensure_thread_writable(channel: &Channel, permissions: &PermissionValue) -> Result<()> {
    if let Channel::Thread {
        archived, locked, ..
    } = channel
    {
        if (*archived || *locked)
            && !permissions.has_channel_permission(ChannelPermission::ManageChannel)
        {
            return Err(create_error!(InvalidOperation));
        }
    }

    Ok(())
}
