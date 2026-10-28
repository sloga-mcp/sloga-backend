//! Structural rules shared by every route that resolves an interaction's
//! channel.

use revolt_database::Channel;
use revolt_result::{create_error, Result};

/// Reject channels where interactions are structurally unavailable.
///
/// This is the E2EE fail-closed rule, and it is structural rather than a
/// permission check: a bot must never be able to become a silent party to a
/// conversation that is, or may be, encrypted.
///
/// - A protected text channel (`is_protected()`) carries only ciphertext the
///   server cannot read, so no interaction may be created, answered or
///   delivered there: `ChannelProtected`. The rule keys on the channel flag
///   alone, never on a feature flag, so it holds with E2EE switched off.
/// - Direct messages and saved messages negotiate E2EE between clients with no
///   server-side flag, so they are excluded outright; forum containers have no
///   message stream to answer into: `InvalidOperation`.
///
/// Callers run this after their first authorization on the channel, so a
/// caller who cannot see the channel learns nothing about its protected
/// status. Worth calling even where the rule already held transitively — for
/// saved messages in particular the owner holds `SendMessage`, so a permission
/// check alone fails OPEN.
///
/// This form judges `channel` alone, so a thread under a protected parent
/// passes it. Callers that have resolved the permission target use
/// [`ensure_interactions_allowed_in`]; this one is kept for the two modal
/// routes, which run it before their permission calculation (the accepted
/// decision 18 exemption).
pub fn ensure_interactions_allowed(channel: &Channel) -> Result<()> {
    ensure_interactions_allowed_in(channel, channel)
}

/// [`ensure_interactions_allowed`] for a resolved channel: `channel` is the
/// one the interaction lives in and `permission_channel` its permission
/// target (`Channel::permission_target`; a thread's parent, otherwise the
/// channel itself). The structural exclusions read `channel`; the protected
/// refusal reads either, so a thread under a protected parent refuses too
/// (W2 audit B1).
pub fn ensure_interactions_allowed_in(
    channel: &Channel,
    permission_channel: &Channel,
) -> Result<()> {
    match channel {
        Channel::Forum { .. } | Channel::DirectMessage { .. } | Channel::SavedMessages { .. } => {
            Err(create_error!(InvalidOperation))
        }
        _ if channel.is_protected() || permission_channel.is_protected() => {
            Err(create_error!(ChannelProtected))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use revolt_database::{Channel, ForumLayout, ForumSortOrder};
    use revolt_result::ErrorType;

    use super::{ensure_interactions_allowed, ensure_interactions_allowed_in};

    fn thread() -> Channel {
        Channel::Thread {
            id: "thread".to_string(),
            server: "server".to_string(),
            parent_channel: "channel".to_string(),
            name: "thread".to_string(),
            creator: "user".to_string(),
            origin_message_id: None,
            last_message_id: None,
            archived: false,
            archived_timestamp: None,
            auto_archive_minutes: 0,
            locked: false,
            applied_tags: vec![],
        }
    }

    /// W2 audit B1: a thread is judged by its permission target, so one
    /// under a protected parent refuses; under an open parent it is allowed
    ///
    /// Control: the `permission_channel` arm dropped → the first assertion
    /// fails.
    #[test]
    fn thread_under_a_protected_parent_refuses_interactions() {
        assert!(matches!(
            ensure_interactions_allowed_in(&thread(), &text_channel(true))
                .err()
                .map(|error| error.error_type),
            Some(ErrorType::ChannelProtected)
        ));
        assert!(ensure_interactions_allowed_in(&thread(), &text_channel(false)).is_ok());
        assert!(matches!(
            ensure_interactions_allowed_in(&text_channel(true), &text_channel(true))
                .err()
                .map(|error| error.error_type),
            Some(ErrorType::ChannelProtected)
        ));
    }

    fn text_channel(protected: bool) -> Channel {
        Channel::TextChannel {
            id: "channel".to_string(),
            server: "server".to_string(),
            name: "general".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: HashMap::new(),
            nsfw: false,
            spoiler: false,
            voice: None,
            slowmode: None,
            announcement: None,
            protected,
        }
    }

    fn error_type(channel: &Channel) -> Option<ErrorType> {
        ensure_interactions_allowed(channel)
            .err()
            .map(|error| error.error_type)
    }

    #[test]
    fn protected_text_channel_refuses_interactions() {
        assert!(matches!(
            error_type(&text_channel(true)),
            Some(ErrorType::ChannelProtected)
        ));
    }

    #[test]
    fn unprotected_text_channel_allows_interactions() {
        assert!(ensure_interactions_allowed(&text_channel(false)).is_ok());
    }

    #[test]
    fn private_and_forum_channels_still_refuse_with_invalid_operation() {
        let saved = Channel::SavedMessages {
            id: "saved".to_string(),
            user: "user".to_string(),
        };
        let direct = Channel::DirectMessage {
            id: "direct".to_string(),
            active: true,
            recipients: vec!["a".to_string(), "b".to_string()],
            last_message_id: None,
        };
        let forum = Channel::Forum {
            id: "forum".to_string(),
            server: "server".to_string(),
            name: "forum".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: HashMap::new(),
            nsfw: false,
            spoiler: false,
            tags: vec![],
            require_tag: false,
            default_sort: ForumSortOrder::default(),
            force_sort: false,
            default_layout: ForumLayout::default(),
            default_auto_archive_minutes: 0,
        };

        for channel in [saved, direct, forum] {
            assert!(matches!(
                error_type(&channel),
                Some(ErrorType::InvalidOperation)
            ));
        }
    }

    #[test]
    fn group_channel_still_allows_interactions() {
        let group = Channel::Group {
            id: "group".to_string(),
            name: "group".to_string(),
            owner: "user".to_string(),
            description: None,
            recipients: vec!["user".to_string()],
            icon: None,
            last_message_id: None,
            permissions: None,
            nsfw: false,
            spoiler: false,
            voice: None,
        };

        assert!(ensure_interactions_allowed(&group).is_ok());
    }
}
