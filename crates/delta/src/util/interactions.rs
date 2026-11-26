//! Structural rules shared by every route that resolves an interaction's
//! channel.

use revolt_config::{config, E2EEFeatures};
use revolt_database::{util::e2ee_only, Channel, Database, User};
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
/// decision 18 exemption). It reads no account, so it never refuses for
/// encrypted-only reasons; those routes call the full form afterwards.
pub fn ensure_interactions_allowed(channel: &Channel) -> Result<()> {
    structural_rule(channel, channel)
}

/// [`ensure_interactions_allowed`] for a resolved channel: `channel` is the
/// one the interaction lives in and `permission_channel` its permission
/// target (`Channel::permission_target`; a thread's parent, otherwise the
/// channel itself). The structural exclusions read `channel`; the protected
/// refusal reads either, so a thread under a protected parent refuses too
/// (W2 audit B1).
///
/// Then the encrypted-only rule for `user`, the account acting on the
/// route (the invoking or submitting user, or the answering bot): every
/// interaction carries plain text to or from a bot, so a group marked
/// encrypted-only refuses it (`group`), and so does an unmarked group for
/// an encrypted-only account (`sender`). Lifted with
/// `[features.e2ee] only_enforced = false`.
pub async fn ensure_interactions_allowed_in(
    db: &Database,
    user: &User,
    channel: &Channel,
    permission_channel: &Channel,
) -> Result<()> {
    let e2ee_config = config().await.features.e2ee.clone();
    interactions_allowed_in(db, &e2ee_config, user, channel, permission_channel).await
}

/// [`ensure_interactions_allowed_in`] with the switch passed in
async fn interactions_allowed_in(
    db: &Database,
    e2ee_config: &E2EEFeatures,
    user: &User,
    channel: &Channel,
    permission_channel: &Channel,
) -> Result<()> {
    structural_rule(channel, permission_channel)?;
    e2ee_only::plain_write_allowed(db, e2ee_config, user, channel, None).await
}

/// The structural exclusions and the protected refusal
fn structural_rule(channel: &Channel, permission_channel: &Channel) -> Result<()> {
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

    use revolt_config::E2EEFeatures;
    use revolt_database::{Channel, Database, ForumLayout, ForumSortOrder, User};
    use revolt_result::{ErrorType, Result};

    use super::{ensure_interactions_allowed, interactions_allowed_in};

    fn user(e2ee_only: bool) -> User {
        User {
            id: "user".to_string(),
            username: "user".to_string(),
            discriminator: "0001".to_string(),
            e2ee_only,
            ..Default::default()
        }
    }

    /// The full rule for `user` with the switch at `only_enforced`, against
    /// an empty in-memory database: no channel kind that reaches the
    /// encrypted-only check here needs a lookup
    fn allowed_for(
        user: &User,
        only_enforced: bool,
        channel: &Channel,
        permission_channel: &Channel,
    ) -> Result<()> {
        let db = Database::Reference(Default::default());
        let e2ee_config = E2EEFeatures {
            only_enforced,
            ..Default::default()
        };
        crate::util::test::rt().block_on(interactions_allowed_in(
            &db,
            &e2ee_config,
            user,
            channel,
            permission_channel,
        ))
    }

    /// The full rule for an ordinary account, switch on
    fn allowed_in(channel: &Channel, permission_channel: &Channel) -> Result<()> {
        allowed_for(&user(false), true, channel, permission_channel)
    }

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
            allowed_in(&thread(), &text_channel(true))
                .err()
                .map(|error| error.error_type),
            Some(ErrorType::ChannelProtected)
        ));
        assert!(allowed_in(&thread(), &text_channel(false)).is_ok());
        assert!(matches!(
            allowed_in(&text_channel(true), &text_channel(true))
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
            protected_history: None,
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

    fn group(e2ee_only: bool) -> Channel {
        Channel::Group {
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
            e2ee_only,
        }
    }

    #[test]
    fn group_channel_still_allows_interactions() {
        let group = group(false);

        assert!(ensure_interactions_allowed(&group).is_ok());
        assert!(allowed_in(&group, &group).is_ok());
    }

    /// The side an encrypted-only refusal names, or `None` when allowed.
    /// Any other error fails the test.
    fn side_of(result: Result<()>) -> Option<String> {
        match result {
            Ok(()) => None,
            Err(error) => match error.error_type {
                ErrorType::EncryptionRequired { side } => Some(side),
                other => panic!("expected EncryptionRequired, got {other:?}"),
            },
        }
    }

    /// A marked group refuses every interaction (`group`); an unmarked one
    /// refuses an encrypted-only account (`sender`) and nobody else; the
    /// switch lifts both.
    ///
    /// Control: the `plain_write_allowed` line removed → every case allows.
    #[test]
    fn encrypted_only_groups_refuse_interactions() {
        for only_enforced in [true, false] {
            for marked in [false, true] {
                for author_only in [false, true] {
                    let group = group(marked);
                    let expected = match (only_enforced, marked, author_only) {
                        (false, ..) => None,
                        (true, true, _) => Some("group"),
                        (true, false, true) => Some("sender"),
                        (true, false, false) => None,
                    };
                    assert_eq!(
                        side_of(allowed_for(
                            &user(author_only),
                            only_enforced,
                            &group,
                            &group
                        ))
                        .as_deref(),
                        expected,
                        "enforced={only_enforced} marked={marked} author_only={author_only}"
                    );
                }
            }
        }
    }

    /// The account-free form the modal routes run before their permission
    /// check never reads the mark, so it reveals nothing before that check
    #[test]
    fn the_account_free_form_ignores_the_mark() {
        assert!(ensure_interactions_allowed(&group(true)).is_ok());
    }

    /// Server channels and threads are untouched by an encrypted-only
    /// account, and the structural refusals still come first for one
    #[test]
    fn encrypted_only_accounts_change_nothing_outside_groups() {
        let only = user(true);

        assert!(allowed_for(&only, true, &text_channel(false), &text_channel(false)).is_ok());
        assert!(allowed_for(&only, true, &thread(), &text_channel(false)).is_ok());
        assert!(matches!(
            allowed_for(&only, true, &thread(), &text_channel(true))
                .err()
                .map(|error| error.error_type),
            Some(ErrorType::ChannelProtected)
        ));

        let direct = Channel::DirectMessage {
            id: "direct".to_string(),
            active: true,
            recipients: vec!["user".to_string(), "peer".to_string()],
            last_message_id: None,
        };
        assert!(matches!(
            allowed_for(&only, true, &direct, &direct)
                .err()
                .map(|error| error.error_type),
            Some(ErrorType::InvalidOperation)
        ));
    }
}
