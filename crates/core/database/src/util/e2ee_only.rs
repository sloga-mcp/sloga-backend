//! Encrypted-only accounts and groups.
//!
//! An account can ask that its direct messages and groups only ever carry
//! end-to-end encrypted messages (`User::e2ee_only`), and a group created
//! with such a member is marked the same way (`Channel::Group::e2ee_only`).
//! Encrypted messages never pass through the message routes, so every write
//! those routes would store in such a conversation is a plain one, and the
//! checks here refuse it with `EncryptionRequired`.
//!
//! The checks are a safety net behind the apps, which decide for themselves
//! and never send a plain message there in the first place.
//!
//! `[features.e2ee] only_enforced = false` lifts every refusal at once and
//! leaves the stored flags alone.

use revolt_config::E2EEFeatures;
use revolt_result::{Error, ErrorType, Result};

use crate::{Channel, Database, User};

/// The author's own account is encrypted-only
pub const SIDE_SENDER: &str = "sender";

/// The other account in the direct message (or the account joining a group)
/// is encrypted-only
pub const SIDE_RECIPIENT: &str = "recipient";

/// The group is marked encrypted-only
pub const SIDE_GROUP: &str = "group";

/// An account to be added to a marked group cannot take encrypted messages
pub const SIDE_MEMBER: &str = "member";

/// Most members a group marked encrypted-only may have
pub const E2EE_GROUP_MAX: usize = 24;

/// File tag message attachments are uploaded under (see
/// `File::use_attachment`)
const ATTACHMENTS_TAG: &str = "attachments";

/// Whether the refusals are switched on.
///
/// The single source of truth for every gate, like
/// `antispam::dm_pause_enforced`.
pub fn enforced(cfg: &E2EEFeatures) -> bool {
    cfg.only_enforced
}

/// The refusal, naming which side requires encryption (one of the `SIDE_*`
/// constants).
pub fn refused(side: &str) -> Error {
    create_error!(EncryptionRequired {
        side: side.to_string()
    })
}

/// Whether `author` may write a plain message (or any other plain content)
/// into `channel`.
///
/// - Always allowed while the refusals are switched off.
/// - Saved Notes and every server channel: allowed.
/// - Direct message: refused with `sender` if the author is encrypted-only,
///   else with `recipient` if the other account is. `peer` saves the lookup
///   when the caller already holds the other account; without it the other
///   id in `recipients` is fetched. A peer that does not exist is allowed
///   through (the route's own checks fail it); any other database error is
///   returned, so a failed lookup never lets a plain write through.
/// - Group: refused with `group` if the group is marked, else with `sender`
///   if the author is encrypted-only.
pub async fn plain_write_allowed(
    db: &Database,
    cfg: &E2EEFeatures,
    author: &User,
    channel: &Channel,
    peer: Option<&User>,
) -> Result<()> {
    if !enforced(cfg) {
        return Ok(());
    }

    match channel {
        Channel::DirectMessage { recipients, .. } => {
            if author.e2ee_only {
                return Err(refused(SIDE_SENDER));
            }

            let peer_requires = match peer {
                Some(peer) => peer.e2ee_only,
                None => match recipients.iter().find(|id| *id != &author.id) {
                    Some(peer_id) => match db.fetch_user(peer_id).await {
                        Ok(peer) => peer.e2ee_only,
                        Err(Error {
                            error_type: ErrorType::NotFound,
                            ..
                        }) => false,
                        Err(error) => return Err(error),
                    },
                    None => false,
                },
            };

            if peer_requires {
                return Err(refused(SIDE_RECIPIENT));
            }

            Ok(())
        }
        Channel::Group {
            e2ee_only: true, ..
        } => Err(refused(SIDE_GROUP)),
        Channel::Group { .. } => {
            if author.e2ee_only {
                return Err(refused(SIDE_SENDER));
            }

            Ok(())
        }
        Channel::SavedMessages { .. }
        | Channel::TextChannel { .. }
        | Channel::Thread { .. }
        | Channel::Forum { .. } => Ok(()),
    }
}

/// Whether a plain write with no user account behind it (a webhook) may go
/// into `channel`.
///
/// Refused with `group` only while the refusals are switched on and the
/// channel is a group marked encrypted-only.
pub fn plain_write_allowed_unauthored(cfg: &E2EEFeatures, channel: &Channel) -> Result<()> {
    if !enforced(cfg) {
        return Ok(());
    }

    match channel {
        Channel::Group {
            e2ee_only: true, ..
        } => Err(refused(SIDE_GROUP)),
        _ => Ok(()),
    }
}

/// Mark the attachments named by a refused request as deleted, so a plain
/// file uploaded for a message the server refused does not stay in storage
/// until the dangling file sweep.
///
/// Best effort and never fails the request. A file is marked only when all
/// of these hold; anything else is left alone:
///
/// - it is a message attachment upload,
/// - no message has claimed it (no `used_for`),
/// - it was uploaded by `author_id`.
///
/// The check and the mark are two steps, as in the dangling file sweep.
pub async fn release_refused_attachments(db: &Database, author_id: &str, ids: &[String]) {
    for id in ids {
        let file = match db.fetch_attachment(ATTACHMENTS_TAG, id).await {
            Ok(file) => file,
            Err(_) => continue,
        };

        if file.used_for.is_some()
            || file.deleted.is_some_and(|v| v)
            || file.uploader_id.as_deref() != Some(author_id)
        {
            continue;
        }

        if let Err(err) = db.mark_attachment_as_deleted(&file.id).await {
            revolt_config::capture_error(&err);
        }
    }
}

#[cfg(test)]
mod tests {
    use ulid::Ulid;

    use super::*;
    use crate::{File, FileUsedFor, FileUsedForType, Metadata};

    fn config(only_enforced: bool) -> E2EEFeatures {
        E2EEFeatures {
            only_enforced,
            ..Default::default()
        }
    }

    fn user(e2ee_only: bool) -> User {
        let id = Ulid::new().to_string();
        User {
            username: format!("u{}", &id[16..]),
            discriminator: "0001".to_string(),
            id,
            e2ee_only,
            ..Default::default()
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Kind {
        SavedMessages,
        DirectMessage,
        Group,
        TextChannel,
        Thread,
        Forum,
    }

    const KINDS: [Kind; 6] = [
        Kind::SavedMessages,
        Kind::DirectMessage,
        Kind::Group,
        Kind::TextChannel,
        Kind::Thread,
        Kind::Forum,
    ];

    /// A channel of `kind` between `author` and `peer`. `marked` only means
    /// something for a group.
    fn channel(kind: Kind, author: &str, peer: &str, marked: bool) -> Channel {
        let id = Ulid::new().to_string();
        let server = "01E2EEONLYSERVER".to_string();

        match kind {
            Kind::SavedMessages => Channel::SavedMessages {
                id,
                user: author.to_string(),
            },
            Kind::DirectMessage => Channel::DirectMessage {
                id,
                active: true,
                recipients: vec![author.to_string(), peer.to_string()],
                last_message_id: None,
            },
            Kind::Group => Channel::Group {
                id,
                name: "group".to_string(),
                owner: author.to_string(),
                description: None,
                recipients: vec![author.to_string(), peer.to_string()],
                icon: None,
                last_message_id: None,
                permissions: None,
                nsfw: false,
                spoiler: false,
                voice: None,
                e2ee_only: marked,
            },
            Kind::TextChannel => Channel::TextChannel {
                id,
                server,
                name: "text".to_string(),
                description: None,
                icon: None,
                last_message_id: None,
                default_permissions: None,
                role_permissions: Default::default(),
                nsfw: false,
                spoiler: false,
                voice: None,
                slowmode: None,
                announcement: None,
                protected: false,
                protected_history: None,
            },
            Kind::Thread => Channel::Thread {
                id,
                server,
                parent_channel: "01E2EEONLYPARENT".to_string(),
                name: "thread".to_string(),
                creator: author.to_string(),
                origin_message_id: None,
                last_message_id: None,
                archived: false,
                archived_timestamp: None,
                auto_archive_minutes: Channel::default_auto_archive_minutes(),
                locked: false,
                applied_tags: vec![],
            },
            Kind::Forum => Channel::Forum {
                id,
                server,
                name: "forum".to_string(),
                description: None,
                icon: None,
                last_message_id: None,
                default_permissions: None,
                role_permissions: Default::default(),
                nsfw: false,
                spoiler: false,
                tags: vec![],
                require_tag: false,
                default_sort: Default::default(),
                force_sort: false,
                default_layout: Default::default(),
                default_auto_archive_minutes: Channel::default_forum_auto_archive_minutes(),
            },
        }
    }

    /// The side a result refuses with, or `None` when it allows. Any other
    /// error fails the test.
    fn side_of(result: Result<()>) -> Option<String> {
        match result {
            Ok(()) => None,
            Err(Error {
                error_type: ErrorType::EncryptionRequired { side },
                ..
            }) => Some(side),
            Err(other) => panic!("expected EncryptionRequired, got {other:?}"),
        }
    }

    #[test]
    fn sides_and_cap_are_pinned() {
        assert_eq!(SIDE_SENDER, "sender");
        assert_eq!(SIDE_RECIPIENT, "recipient");
        assert_eq!(SIDE_GROUP, "group");
        assert_eq!(SIDE_MEMBER, "member");
        assert_eq!(E2EE_GROUP_MAX, 24);
    }

    #[test]
    fn refused_names_the_side() {
        for side in [SIDE_SENDER, SIDE_RECIPIENT, SIDE_GROUP, SIDE_MEMBER] {
            assert_eq!(side_of(Err(refused(side))).as_deref(), Some(side));
        }
    }

    #[test]
    fn enforced_follows_the_config_switch() {
        assert!(enforced(&config(true)));
        assert!(!enforced(&config(false)));
        // On unless switched off
        assert!(enforced(&E2EEFeatures::default()));
    }

    /// Every channel kind, with the author flag, the peer flag, the group
    /// mark and the switch each on and off. Direct messages are asked both
    /// with the peer handed in and with the peer fetched.
    #[tokio::test]
    async fn plain_write_allowed_table() {
        database_test!(|db| async move {
            let peers = [user(false), user(true)];
            for peer in &peers {
                db.insert_user(peer).await.unwrap();
            }

            let mut refusals = 0;
            for only_enforced in [false, true] {
                let cfg = config(only_enforced);
                for author_only in [false, true] {
                    let author = user(author_only);
                    for peer in &peers {
                        for marked in [false, true] {
                            for kind in KINDS {
                                let expected =
                                    match (only_enforced, kind, marked, author_only, peer.e2ee_only)
                                    {
                                        (false, ..) => None,
                                        (true, Kind::Group, true, _, _) => Some(SIDE_GROUP),
                                        (true, Kind::Group, false, true, _) => Some(SIDE_SENDER),
                                        (true, Kind::DirectMessage, _, true, _) => {
                                            Some(SIDE_SENDER)
                                        }
                                        (true, Kind::DirectMessage, _, false, true) => {
                                            Some(SIDE_RECIPIENT)
                                        }
                                        _ => None,
                                    };
                                let case = format!(
                                    "enforced={only_enforced} kind={kind:?} marked={marked} \
                                     author_only={author_only} peer_only={}",
                                    peer.e2ee_only
                                );

                                let channel = channel(kind, &author.id, &peer.id, marked);

                                let handed =
                                    plain_write_allowed(&db, &cfg, &author, &channel, Some(peer))
                                        .await;
                                assert_eq!(side_of(handed).as_deref(), expected, "{case} (handed)");

                                let fetched =
                                    plain_write_allowed(&db, &cfg, &author, &channel, None).await;
                                assert_eq!(
                                    side_of(fetched).as_deref(),
                                    expected,
                                    "{case} (fetched)"
                                );

                                if expected.is_some() {
                                    refusals += 1;
                                }
                            }
                        }
                    }
                }
            }

            // Direct message: 2 marks x (2 sender + 1 recipient) = 6.
            // Group: 4 marked + 2 unmarked with an encrypted-only author = 6.
            assert_eq!(refusals, 12);
        });
    }

    /// The cases the table computes, written out once by hand.
    #[tokio::test]
    async fn plain_write_allowed_named_cases() {
        database_test!(|db| async move {
            let on = config(true);
            let off = config(false);
            let open = user(false);
            let only = user(true);
            db.insert_user(&open).await.unwrap();
            db.insert_user(&only).await.unwrap();
            let other_open = user(false);

            let dm_with_only = channel(Kind::DirectMessage, &open.id, &only.id, false);
            let dm_open = channel(Kind::DirectMessage, &open.id, &other_open.id, false);
            let marked_group = channel(Kind::Group, &open.id, &other_open.id, true);
            let open_group = channel(Kind::Group, &open.id, &only.id, false);

            // An encrypted-only author is refused as the sender, whoever the
            // peer is
            let result = plain_write_allowed(&db, &on, &only, &dm_with_only, Some(&open)).await;
            assert_eq!(side_of(result).as_deref(), Some("sender"));

            // An open author writing to an encrypted-only peer is refused
            // for the recipient, with the peer handed in or fetched
            let result = plain_write_allowed(&db, &on, &open, &dm_with_only, Some(&only)).await;
            assert_eq!(side_of(result).as_deref(), Some("recipient"));
            let result = plain_write_allowed(&db, &on, &open, &dm_with_only, None).await;
            assert_eq!(side_of(result).as_deref(), Some("recipient"));

            // Two open accounts
            let result = plain_write_allowed(&db, &on, &open, &dm_open, Some(&other_open)).await;
            assert_eq!(side_of(result), None);

            // A marked group refuses everyone, and names the group even for
            // an encrypted-only author
            let result = plain_write_allowed(&db, &on, &open, &marked_group, None).await;
            assert_eq!(side_of(result).as_deref(), Some("group"));
            let result = plain_write_allowed(&db, &on, &only, &marked_group, None).await;
            assert_eq!(side_of(result).as_deref(), Some("group"));

            // An unmarked group refuses only an encrypted-only author; an
            // encrypted-only member does not close it for the others
            let result = plain_write_allowed(&db, &on, &only, &open_group, None).await;
            assert_eq!(side_of(result).as_deref(), Some("sender"));
            let result = plain_write_allowed(&db, &on, &open, &open_group, None).await;
            assert_eq!(side_of(result), None);

            // Saved Notes and server channels never refuse
            for kind in [
                Kind::SavedMessages,
                Kind::TextChannel,
                Kind::Thread,
                Kind::Forum,
            ] {
                let elsewhere = channel(kind, &only.id, &only.id, true);
                let result = plain_write_allowed(&db, &on, &only, &elsewhere, Some(&only)).await;
                assert_eq!(side_of(result), None, "{kind:?}");
            }

            // The switch lifts every refusal
            for refused_channel in [&dm_with_only, &marked_group, &open_group] {
                let result = plain_write_allowed(&db, &off, &only, refused_channel, None).await;
                assert_eq!(side_of(result), None);
                let result =
                    plain_write_allowed(&db, &off, &open, refused_channel, Some(&only)).await;
                assert_eq!(side_of(result), None);
            }
        });
    }

    #[tokio::test]
    async fn direct_message_peer_lookup() {
        database_test!(|db| async move {
            let on = config(true);
            let author = user(false);

            // A peer that does not exist is allowed through
            let ghost = Ulid::new().to_string();
            let dm = channel(Kind::DirectMessage, &author.id, &ghost, false);
            let result = plain_write_allowed(&db, &on, &author, &dm, None).await;
            assert_eq!(side_of(result), None);

            // A handed-in peer is used as it is, with no lookup: this one is
            // not stored at all
            let unstored = user(true);
            let dm = channel(Kind::DirectMessage, &author.id, &unstored.id, false);
            let result = plain_write_allowed(&db, &on, &author, &dm, Some(&unstored)).await;
            assert_eq!(side_of(result).as_deref(), Some(SIDE_RECIPIENT));

            // The peer is the other id wherever it sits in `recipients`
            let stored = user(true);
            db.insert_user(&stored).await.unwrap();
            let dm = Channel::DirectMessage {
                id: Ulid::new().to_string(),
                active: true,
                recipients: vec![stored.id.clone(), author.id.clone()],
                last_message_id: None,
            };
            let result = plain_write_allowed(&db, &on, &author, &dm, None).await;
            assert_eq!(side_of(result).as_deref(), Some(SIDE_RECIPIENT));

            // No other id in `recipients`: nothing to refuse for
            let alone = Channel::DirectMessage {
                id: Ulid::new().to_string(),
                active: true,
                recipients: vec![author.id.clone()],
                last_message_id: None,
            };
            let result = plain_write_allowed(&db, &on, &author, &alone, None).await;
            assert_eq!(side_of(result), None);

            // The stored flag is what counts: switching it off reopens the
            // conversation
            let mut reopened = stored.clone();
            reopened.e2ee_only = false;
            let dm = channel(Kind::DirectMessage, &author.id, &reopened.id, false);
            let result = plain_write_allowed(&db, &on, &author, &dm, Some(&reopened)).await;
            assert_eq!(side_of(result), None);
        });
    }

    #[test]
    fn unauthored_writes_are_refused_only_in_marked_groups() {
        let on = config(true);
        let off = config(false);

        for kind in KINDS {
            for marked in [false, true] {
                let channel = channel(kind, "01AUTHOR", "01PEER", marked);
                let expected = (kind == Kind::Group && marked).then_some(SIDE_GROUP);

                assert_eq!(
                    side_of(plain_write_allowed_unauthored(&on, &channel)).as_deref(),
                    expected,
                    "{kind:?} marked={marked}"
                );
                assert_eq!(
                    side_of(plain_write_allowed_unauthored(&off, &channel)),
                    None,
                    "{kind:?} marked={marked} with the switch off"
                );
            }
        }
    }

    fn file(id: &str, tag: &str, uploader: Option<&str>, used_for: Option<&str>) -> File {
        File {
            id: id.to_string(),
            tag: tag.to_string(),
            filename: "file.png".to_string(),
            hash: None,
            uploaded_at: None,
            uploader_id: uploader.map(|uploader| uploader.to_string()),
            used_for: used_for.map(|id| FileUsedFor {
                object_type: FileUsedForType::Message,
                id: id.to_string(),
            }),
            deleted: None,
            reported: None,
            metadata: Metadata::File,
            content_type: "image/png".to_string(),
            size: 1,
            message_id: None,
            user_id: None,
            server_id: None,
            object_id: None,
        }
    }

    #[tokio::test]
    async fn release_refused_attachments_marks_only_own_unclaimed_files() {
        database_test!(|db| async move {
            const AUTHOR: &str = "01RELEASEAUTHOR00000000001";
            const OTHER: &str = "01RELEASEOTHER000000000001";
            const MESSAGE: &str = "01RELEASEMESSAGE0000000001";

            const OWN_UNCLAIMED: &str = "01RELEASEFILEA000000000001";
            const OWN_CLAIMED: &str = "01RELEASEFILEB000000000001";
            const FOREIGN_UNCLAIMED: &str = "01RELEASEFILEC000000000001";
            const NO_UPLOADER: &str = "01RELEASEFILED000000000001";
            const OWN_AVATAR: &str = "01RELEASEFILEE000000000001";
            const OWN_UNLISTED: &str = "01RELEASEFILEF000000000001";
            const OWN_SECOND: &str = "01RELEASEFILEG000000000001";

            let files = [
                file(OWN_UNCLAIMED, "attachments", Some(AUTHOR), None),
                file(OWN_CLAIMED, "attachments", Some(AUTHOR), Some(MESSAGE)),
                file(FOREIGN_UNCLAIMED, "attachments", Some(OTHER), None),
                file(NO_UPLOADER, "attachments", None, None),
                // Own and unclaimed, but not a message attachment upload
                file(OWN_AVATAR, "avatars", Some(AUTHOR), None),
                // Own and unclaimed, but the request never named it
                file(OWN_UNLISTED, "attachments", Some(AUTHOR), None),
                file(OWN_SECOND, "attachments", Some(AUTHOR), None),
            ];
            for file in &files {
                db.insert_attachment(file).await.unwrap();
            }

            // Nothing named: nothing marked
            release_refused_attachments(&db, AUTHOR, &[]).await;
            assert!(db.fetch_deleted_attachments().await.unwrap().is_empty());

            // An id that does not exist does not stop the ones after it
            release_refused_attachments(
                &db,
                AUTHOR,
                &[
                    OWN_UNCLAIMED.to_string(),
                    OWN_CLAIMED.to_string(),
                    FOREIGN_UNCLAIMED.to_string(),
                    NO_UPLOADER.to_string(),
                    OWN_AVATAR.to_string(),
                    "01RELEASENOSUCHFILE0000001".to_string(),
                    OWN_SECOND.to_string(),
                ],
            )
            .await;

            let mut deleted: Vec<String> = db
                .fetch_deleted_attachments()
                .await
                .unwrap()
                .into_iter()
                .map(|file| file.id)
                .collect();
            deleted.sort();
            assert_eq!(
                deleted,
                vec![OWN_UNCLAIMED.to_string(), OWN_SECOND.to_string()]
            );

            for (id, tag) in [
                (OWN_CLAIMED, "attachments"),
                (FOREIGN_UNCLAIMED, "attachments"),
                (NO_UPLOADER, "attachments"),
                (OWN_AVATAR, "avatars"),
                (OWN_UNLISTED, "attachments"),
            ] {
                let untouched = db.fetch_attachment(tag, id).await.unwrap();
                assert_eq!(untouched.deleted, None, "{id} was touched");
            }

            // The claimed file keeps its claim
            let claimed = db
                .fetch_attachment("attachments", OWN_CLAIMED)
                .await
                .unwrap();
            assert_eq!(claimed.used_for, files[1].used_for);

            // Repeating the call is harmless
            release_refused_attachments(&db, AUTHOR, &[OWN_UNCLAIMED.to_string()]).await;
            assert_eq!(db.fetch_deleted_attachments().await.unwrap().len(), 2);
        });
    }
}
