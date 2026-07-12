//! Thread write-lock enforcement, shared by every route that mutates content
//! inside a thread (`message_send`, `message_edit`, `message_react`,
//! `message_pin`), plus forum tag validation shared by post create/edit.

use revolt_database::{Channel, ForumTag};
use revolt_permissions::{ChannelPermission, PermissionValue};
use revolt_result::{create_error, Result};

/// Maximum number of tag definitions on a forum channel
pub const MAX_FORUM_TAGS: usize = 20;

/// Maximum number of tags applied to a single forum post
pub const MAX_APPLIED_TAGS: usize = 5;

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

/// Validate the tag ids a user wants applied to a forum post.
///
/// Every id must reference a tag defined on the forum, moderated tags require
/// `ManageChannel`, at most [`MAX_APPLIED_TAGS`] may be applied, duplicates
/// are rejected, and an empty set is rejected when the forum requires a tag.
pub fn validate_applied_tags(
    forum_tags: &[ForumTag],
    applied: &[String],
    require_tag: bool,
    permissions: &PermissionValue,
) -> Result<()> {
    if require_tag && applied.is_empty() {
        return Err(create_error!(InvalidProperty));
    }

    if applied.len() > MAX_APPLIED_TAGS {
        return Err(create_error!(InvalidProperty));
    }

    let can_manage = permissions.has_channel_permission(ChannelPermission::ManageChannel);
    for (index, id) in applied.iter().enumerate() {
        if applied[..index].contains(id) {
            return Err(create_error!(InvalidProperty));
        }

        let Some(tag) = forum_tags.iter().find(|tag| &tag.id == id) else {
            return Err(create_error!(InvalidProperty));
        };

        if tag.moderated && !can_manage {
            return Err(create_error!(MissingPermission {
                permission: ChannelPermission::ManageChannel.to_string(),
            }));
        }
    }

    Ok(())
}
