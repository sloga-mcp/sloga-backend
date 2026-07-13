use revolt_database::Poll;
use revolt_permissions::{ChannelPermission, PermissionValue};
use std::time::{SystemTime, UNIX_EPOCH};

/// Current time in milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The hidden-until-vote rule, applied server-side on every read: live
/// counts are visible only to voters, the poll author, moderators
/// (ManageMessages), or everyone once the poll has closed.
pub fn can_see_counts(
    poll: &Poll,
    user_id: &str,
    permissions: &PermissionValue,
    has_voted: bool,
) -> bool {
    poll.closed
        || has_voted
        || poll.author == user_id
        || permissions.has_channel_permission(ChannelPermission::ManageMessages)
}
