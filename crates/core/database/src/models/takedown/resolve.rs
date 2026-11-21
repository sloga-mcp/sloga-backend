use crate::{Channel, Database, TakedownTarget, UnresolvableKind};

use super::links::{parse_location_with_hosts, ParsedLocation};

/// Resolve submitted locations into the Sloga objects they name.
///
/// Never errors: anything that can't be found or acted on becomes an
/// `Unresolvable` target carrying the location's index. Identical targets are
/// kept once.
pub async fn resolve_locations(db: &Database, locations: &[String]) -> Vec<TakedownTarget> {
    let config = revolt_config::config().await;
    let bases = [
        config.hosts.app.as_str(),
        config.hosts.api.as_str(),
        config.hosts.autumn.as_str(),
    ];

    let mut targets: Vec<TakedownTarget> = Vec::new();
    for (index, raw) in locations.iter().enumerate() {
        let target = resolve_one(db, index, parse_location_with_hosts(raw, &bases)).await;
        if !targets.contains(&target) {
            targets.push(target);
        }
    }

    targets
}

fn unresolvable(location_index: usize, kind: UnresolvableKind) -> TakedownTarget {
    TakedownTarget::Unresolvable {
        location_index,
        kind,
    }
}

async fn resolve_one(db: &Database, index: usize, parsed: ParsedLocation) -> TakedownTarget {
    match parsed {
        ParsedLocation::Message { channel, message } => match db.fetch_message(&message).await {
            // The stored row says where the message really is
            Ok(row) => TakedownTarget::Message {
                channel: row.channel,
                message: row.id,
            },
            Err(_) => match db.fetch_channel(&channel).await {
                Ok(Channel::DirectMessage { .. } | Channel::Group { .. }) => {
                    unresolvable(index, UnresolvableKind::PrivateConversation)
                }
                _ => unresolvable(index, UnresolvableKind::NotFound),
            },
        },
        ParsedLocation::File { file, .. } => match db.fetch_attachment_by_id(&file).await {
            Ok(row) => TakedownTarget::File { file: row.id },
            Err(_) => unresolvable(index, UnresolvableKind::NotFound),
        },
        ParsedLocation::User { user } => match db.fetch_user(&user).await {
            Ok(row) => TakedownTarget::User { user: row.id },
            Err(_) => unresolvable(index, UnresolvableKind::NotFound),
        },
        ParsedLocation::Server { server } => match db.fetch_server(&server).await {
            Ok(row) => TakedownTarget::Server { server: row.id },
            Err(_) => unresolvable(index, UnresolvableKind::NotFound),
        },
        ParsedLocation::Emoji { emoji } => match db.fetch_emoji(&emoji).await {
            Ok(row) => TakedownTarget::Emoji { emoji: row.id },
            // The emoji is gone but its file (same id) may still be served
            Err(_) => match db.fetch_attachment_by_id(&emoji).await {
                Ok(row) => TakedownTarget::File { file: row.id },
                Err(_) => unresolvable(index, UnresolvableKind::NotFound),
            },
        },
        ParsedLocation::Channel { .. } | ParsedLocation::Unrecognized => {
            unresolvable(index, UnresolvableKind::Unrecognized)
        }
        ParsedLocation::External => unresolvable(index, UnresolvableKind::External),
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_locations;
    use crate::{Channel, Emoji, EmojiParent, Message, TakedownTarget, UnresolvableKind, User};

    const DM: &str = "01KWFKG47HBFTEEN6XPPS8H3HQ";
    const GONE_CHANNEL: &str = "01KWFKG47HBFTEEN6XPPS8H3HR";
    const MSG: &str = "01KWFKH2ZQ3M7B0V5S9XWCD4EA";
    const GONE_MSG: &str = "01KWFKH2ZQ3M7B0V5S9XWCD4EB";
    const USER: &str = "01KWFKK3AB5C7D9EFGHJKMNPQR";
    const GONE_USER: &str = "01KWFKK3AB5C7D9EFGHJKMNPQS";
    const SERVER: &str = "01KWFKJ8RT6N2P4Q8S0VWXYZ12";
    const EMOJI: &str = "01KWFKM0AB5C7D9EFGHJKMNPQR";

    #[tokio::test]
    async fn resolves_each_kind_and_never_errors() {
        database_test!(|db| async move {
            db.insert_channel(&Channel::DirectMessage {
                id: DM.to_string(),
                active: true,
                recipients: vec![USER.to_string(), GONE_USER.to_string()],
                last_message_id: None,
            })
            .await
            .unwrap();
            db.insert_message(&Message {
                id: MSG.to_string(),
                channel: DM.to_string(),
                author: USER.to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
            db.insert_user(&User {
                id: USER.to_string(),
                username: "someone".to_string(),
                discriminator: "0001".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
            db.insert_emoji(&Emoji {
                id: EMOJI.to_string(),
                parent: EmojiParent::Detached,
                creator_id: USER.to_string(),
                name: "e".to_string(),
                animated: false,
                nsfw: false,
            })
            .await
            .unwrap();

            let locations: Vec<String> = vec![
                // 0: an existing message, linked with the wrong channel
                format!("https://app.sloga.gg/channel/{GONE_CHANNEL}/{MSG}"),
                // 1: a missing message in a DM (encrypted DMs have no rows)
                format!("https://app.sloga.gg/channel/{DM}/{GONE_MSG}"),
                // 2: a missing message in a missing channel
                format!("https://app.sloga.gg/channel/{GONE_CHANNEL}/{GONE_MSG}"),
                // 3, 4
                format!("https://app.sloga.gg/user/{USER}"),
                format!("https://app.sloga.gg/user/{GONE_USER}"),
                // 5: a server that does not exist
                format!("https://app.sloga.gg/server/{SERVER}"),
                // 6
                format!("https://app.sloga.gg/autumn/emojis/{EMOJI}"),
                // 7: a channel alone is not specific enough
                format!("https://app.sloga.gg/channel/{DM}"),
                // 8, 9
                "https://example.com/image.png".to_string(),
                DM.to_string(),
                // 10: the same message again is kept once
                format!("https://app.sloga.gg/channel/{DM}/{MSG}"),
            ];

            let targets = resolve_locations(&db, &locations).await;
            assert_eq!(
                targets,
                vec![
                    TakedownTarget::Message {
                        channel: DM.to_string(),
                        message: MSG.to_string(),
                    },
                    TakedownTarget::Unresolvable {
                        location_index: 1,
                        kind: UnresolvableKind::PrivateConversation,
                    },
                    TakedownTarget::Unresolvable {
                        location_index: 2,
                        kind: UnresolvableKind::NotFound,
                    },
                    TakedownTarget::User {
                        user: USER.to_string(),
                    },
                    TakedownTarget::Unresolvable {
                        location_index: 4,
                        kind: UnresolvableKind::NotFound,
                    },
                    TakedownTarget::Unresolvable {
                        location_index: 5,
                        kind: UnresolvableKind::NotFound,
                    },
                    TakedownTarget::Emoji {
                        emoji: EMOJI.to_string(),
                    },
                    TakedownTarget::Unresolvable {
                        location_index: 7,
                        kind: UnresolvableKind::Unrecognized,
                    },
                    TakedownTarget::Unresolvable {
                        location_index: 8,
                        kind: UnresolvableKind::External,
                    },
                    TakedownTarget::Unresolvable {
                        location_index: 9,
                        kind: UnresolvableKind::Unrecognized,
                    },
                ]
            );
        });
    }
}
