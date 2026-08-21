//! Structural rules shared by every route that resolves an interaction's
//! channel.

use revolt_database::Channel;
use revolt_result::{create_error, Result};

/// Reject channels where interactions are structurally unavailable.
///
/// This is the E2EE fail-closed rule, and it is structural rather than a
/// permission check: the server has no channel-level encryption flag (E2EE is
/// negotiated between clients), so a bot must never be able to become a silent
/// party to a conversation that may be encrypted. Direct messages and saved
/// messages are excluded outright; forum containers have no message stream to
/// answer into.
///
/// Worth calling even where the rule already held transitively — for saved
/// messages in particular the owner holds `SendMessage`, so a permission check
/// alone fails OPEN.
pub fn ensure_interactions_allowed(channel: &Channel) -> Result<()> {
    match channel {
        Channel::Forum { .. } | Channel::DirectMessage { .. } | Channel::SavedMessages { .. } => {
            Err(create_error!(InvalidOperation))
        }
        _ => Ok(()),
    }
}
