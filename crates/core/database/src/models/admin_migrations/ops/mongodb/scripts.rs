use std::{
    collections::{HashMap, HashSet},
    ops::BitXor,
    time::Duration,
};

use crate::{
    mongodb::{
        bson::{doc, from_bson, from_document, to_document, Bson, DateTime, Document},
        options::FindOptions,
    },
    AbstractServers, Invite, MongoDb, User, DISCRIMINATOR_SEARCH_SPACE,
};
use bson::{oid::ObjectId, to_bson};
use futures::StreamExt;
use iso8601_timestamp::Timestamp;
use rand::seq::SliceRandom;
use revolt_permissions::{ChannelPermission, DEFAULT_WEBHOOK_PERMISSIONS};
use serde::{Deserialize, Serialize};
use ulid::Ulid;
use unicode_segmentation::UnicodeSegmentation;

#[derive(Serialize, Deserialize)]
struct MigrationInfo {
    _id: i32,
    revision: i32,
}

pub const LATEST_REVISION: i32 = 69; // MUST BE +1 to last migration

pub async fn migrate_database(db: &MongoDb) {
    let migrations = db.col::<Document>("migrations");
    let data = migrations
        .find_one(doc! {})
        .await
        .expect("Failed to fetch migration data.");

    if let Some(doc) = data {
        let info: MigrationInfo =
            from_document(doc).expect("Failed to read migration information.");

        let revision = run_migrations(db, info.revision).await;

        migrations
            .update_one(
                doc! {
                    "_id": info._id
                },
                doc! {
                    "$set": {
                        "revision": revision
                    }
                },
            )
            .await
            .expect("Failed to commit migration information.");

        info!("Migration complete. Currently at revision {}.", revision);
    } else {
        panic!("Database was configured incorrectly, possibly because initalization failed.")
    }
}

pub async fn run_migrations(db: &MongoDb, revision: i32) -> i32 {
    info!("Starting database migration.");

    if revision <= 0 {
        info!("Running migration [revision 0]: Test migration system.");
    }

    if revision <= 1 {
        info!("Running migration [revision 1 / 2021-04-24]: Migrate to Autumn v1.0.0.");

        let messages = db.col::<Document>("messages");
        let attachments = db.col::<Document>("attachments");

        messages
            .update_many(
                doc! { "attachment": { "$exists": 1_i32 } },
                doc! { "$set": { "attachment.tag": "attachments", "attachment.size": 0_i32 } },
            )
            .await
            .expect("Failed to update messages.");

        attachments
            .update_many(
                doc! {},
                doc! { "$set": { "tag": "attachments", "size": 0_i32 } },
            )
            .await
            .expect("Failed to update attachments.");
    }

    if revision <= 2 {
        info!("Running migration [revision 2 / 2021-05-08]: Add servers collection.");

        db.db()
            .create_collection("servers")
            .await
            .expect("Failed to create servers collection.");
    }

    if revision <= 3 {
        info!("Running migration [revision 3 / 2021-05-25]: Support multiple file uploads, add channel_unreads and user_settings.");

        let messages = db.col::<Document>("messages");
        let mut cursor = messages
            .find(doc! {
                "attachment": {
                    "$exists": 1_i32
                }
            })
            .with_options(
                FindOptions::builder()
                    .projection(doc! {
                        "_id": 1_i32,
                        "attachments": [ "$attachment" ]
                    })
                    .build(),
            )
            .await
            .expect("Failed to fetch messages.");

        while let Some(result) = cursor.next().await {
            let doc = result.unwrap();
            let id = doc.get_str("_id").unwrap();
            let attachments = doc.get_array("attachments").unwrap();

            messages
                .update_one(
                    doc! { "_id": id },
                    doc! { "$unset": { "attachment": 1_i32 }, "$set": { "attachments": attachments } },
                )
                .await
                .unwrap();
        }

        db.db()
            .create_collection("channel_unreads")
            .await
            .expect("Failed to create channel_unreads collection.");

        db.db()
            .create_collection("user_settings")
            .await
            .expect("Failed to create user_settings collection.");
    }

    if revision <= 4 {
        info!("Running migration [revision 4 / 2021-06-01]: Add more server collections.");

        db.db()
            .create_collection("server_members")
            .await
            .expect("Failed to create server_members collection.");

        db.db()
            .create_collection("server_bans")
            .await
            .expect("Failed to create server_bans collection.");

        db.db()
            .create_collection("channel_invites")
            .await
            .expect("Failed to create channel_invites collection.");
    }

    if revision <= 5 {
        info!("Running migration [revision 5 / 2021-06-26]: Add permissions.");

        #[derive(Serialize)]
        struct Server {
            pub default_permissions: (i32, i32),
        }

        let server = Server {
            default_permissions: (0_i32, 0_i32),
        };

        db.col::<Document>("servers")
            .update_many(
                doc! {},
                doc! {
                    "$set": to_document(&server).unwrap()
                },
            )
            .await
            .expect("Failed to migrate servers.");
    }

    if revision <= 6 {
        info!("Running migration [revision 6 / 2021-07-09]: Add message text index.");

        db.db()
            .run_command(doc! {
                "createIndexes": "messages",
                "indexes": [
                    {
                        "key": {
                            "content": "text"
                        },
                        "name": "content"
                    }
                ]
            })
            .await
            .expect("Failed to create message index.");
    }

    if revision <= 7 {
        info!("Running migration [revision 7 / 2021-08-11]: Add message text index.");

        db.db()
            .create_collection("bots")
            .await
            .expect("Failed to create bots collection.");
    }

    if revision <= 8 {
        info!("Running migration [revision 8 / 2021-09-10]: Update to Authifier version 1.");

        db.db()
            .run_command(doc! {
                "dropIndexes": "accounts",
                "index": ["email", "email_normalised"]
            })
            .await
            .expect("Failed to delete legacy account indexes.");

        let col = db.col::<Document>("sessions");
        let mut cursor = db.col::<Document>("accounts").find(doc! {}).await.unwrap();

        while let Some(doc) = cursor.next().await {
            if let Ok(account) = doc {
                let id = account.get_str("_id").unwrap();
                if let Some(sessions) = account.get("sessions") {
                    #[derive(Deserialize)]
                    struct Session {
                        id: String,
                        token: String,
                        friendly_name: String,
                        subscription: Option<Document>,
                    }

                    let sessions = from_bson::<Vec<Session>>(sessions.clone()).unwrap();
                    for session in sessions {
                        info!("Converting session {} to new format.", &session.id);

                        let mut doc = doc! {
                            "_id": session.id,
                            "token": session.token,
                            "user_id": id,
                            "name": session.friendly_name,
                        };

                        if let Some(sub) = session.subscription {
                            doc.insert("subscription", sub);
                        }

                        col.insert_one(doc).await.ok();
                    }
                } else {
                    info!("Account doesn't have any sessions!");
                }
            }
        }

        db.col::<Document>("accounts")
            .update_many(
                doc! {},
                doc! {
                    "$unset": {
                        "sessions": 1_i32,
                    },
                    "$set": {
                        "mfa": {
                            "recovery_codes": []
                        }
                    }
                },
            )
            .await
            .unwrap();
    }

    if revision <= 9 {
        info!("Running migration [revision 9 / 2021-09-14]: Switch from last_message to last_message_id.");

        let mut cursor = db.col::<Document>("channels").find(doc! {}).await.unwrap();

        while let Some(doc) = cursor.next().await {
            if let Ok(channel) = doc {
                let channel_id = channel.get_str("_id").unwrap();
                if let Some(last_message) = channel.get("last_message") {
                    #[derive(Serialize, Deserialize, Debug, Clone)]
                    pub struct Obj {
                        #[serde(rename = "_id")]
                        id: String,
                    }

                    #[derive(Serialize, Deserialize, Debug, Clone)]
                    #[serde(untagged)]
                    pub enum LastMessage {
                        Obj(Obj),
                        Id(String),
                    }

                    let lm = from_bson::<LastMessage>(last_message.clone()).unwrap();
                    let id = match lm {
                        LastMessage::Obj(Obj { id }) => id,
                        LastMessage::Id(id) => id,
                    };

                    info!("Converting session {} to new format.", &channel_id);
                    db.col::<Document>("channels")
                        .update_one(
                            doc! {
                                "_id": channel_id
                            },
                            doc! {
                                "$set": {
                                    "last_message_id": id
                                },
                                "$unset": {
                                    "last_message": 1_i32,
                                }
                            },
                        )
                        .await
                        .unwrap();
                } else {
                    info!("{} has no last_message.", &channel_id);
                }
            }
        }
    }

    if revision <= 10 {
        info!("Running migration [revision 10 / 2021-11-01]: Remove nonce values on channels and servers.");

        db.col::<Document>("servers")
            .update_many(
                doc! {},
                doc! {
                    "$unset": {
                        "nonce": 1_i32,
                    }
                },
            )
            .await
            .unwrap();

        db.col::<Document>("channels")
            .update_many(
                doc! {},
                doc! {
                    "$unset": {
                        "nonce": 1_i32,
                    }
                },
            )
            .await
            .unwrap();
    }

    if revision <= 11 {
        info!("Running migration [revision 11 / 2021-11-14]: Add indexes to database.");

        db.db()
            .run_command(doc! {
                "createIndexes": "messages",
                "indexes": [
                    {
                        "key": {
                            "channel": 1_i32
                        },
                        "name": "channel"
                    }
                ]
            })
            .await
            .expect("Failed to create message index.");

        db.db()
            .run_command(doc! {
                "createIndexes": "channel_unreads",
                "indexes": [
                    {
                        "key": {
                            "_id.channel": 1_i32,
                            "_id.user": 1_i32,
                        },
                        "name": "compound_id"
                    },
                    {
                        "key": {
                            "_id.user": 1_i32,
                        },
                        "name": "user_id"
                    }
                ]
            })
            .await
            .expect("Failed to create channel_unreads index.");

        db.db()
            .run_command(doc! {
                "createIndexes": "server_members",
                "indexes": [
                    {
                        "key": {
                            "_id.server": 1_i32,
                            "_id.user": 1_i32,
                        },
                        "name": "compound_id"
                    },
                    {
                        "key": {
                            "_id.user": 1_i32,
                        },
                        "name": "user_id"
                    }
                ]
            })
            .await
            .expect("Failed to create server_members index.");
    }

    if revision <= 12 {
        info!("Running migration [revision 12 / 2021-11-21]: Add indexes to database.");

        db.db()
            .run_command(doc! {
                "createIndexes": "messages",
                "indexes": [
                    {
                        "key": {
                            "channel": 1_i32,
                            "_id": 1_i32
                        },
                        "name": "channel_id_compound"
                    }
                ]
            })
            .await
            .expect("Failed to create message index.");
    }

    if revision <= 13 {
        info!("Running migration [revision 13 / 22-02-2022]: Wipe legacy permission values.");

        warn!("This is a destructive operation and will wipe existing permission data (excl. defaults for SendMessage).");
        warn!("Taking a backup is advised.");
        warn!("Continuing in 10 seconds...");
        tokio::time::sleep(Duration::from_secs(10)).await;

        let servers = db.col::<Document>("servers");
        let mut cursor = servers.find(doc! {}).await.unwrap();

        while let Some(Ok(mut document)) = cursor.next().await {
            let id = document.get_str("_id").unwrap().to_string();
            info!("Updating server {id}");

            let mut update = doc! {};

            // Try to pluck channel permission SendMessage (0x2)
            // Structure of default_permissions used to be [server, channel]
            let has_send = document
                .get_array("default_permissions")
                .map(|x| {
                    x.get(1)
                        .map(|x| x.as_i32().map(|x| (x as u32 & 0x2) == 0x2))
                })
                .ok()
                .flatten()
                .flatten()
                .unwrap_or_default();

            update.insert(
                "default_permissions",
                // Remove Send Message permission if it wasn't originally granted
                (4000323584).bitxor(if has_send { 0 } else { (1 << 22) as u64 }) as i64,
            );

            if let Some(Bson::Document(mut roles)) = document.remove("roles") {
                for role in roles.keys().cloned().collect::<Vec<String>>() {
                    if let Some(Bson::Document(role)) = roles.get_mut(role) {
                        role.insert(
                            "permissions",
                            doc! {
                                "a": 0_i64,
                                "d": 0_i64,
                            },
                        );
                    }
                }

                update.insert("roles", roles);
            }

            servers
                .update_one(doc! { "_id": id }, doc! { "$set": update })
                .await
                .unwrap();
        }

        let channels = db.col::<Document>("channels");
        let mut cursor = channels.find(doc! {}).await.unwrap();

        while let Some(Ok(document)) = cursor.next().await {
            let id = document.get_str("_id").unwrap().to_string();
            info!("Updating channel {id}");

            let mut unset = doc! {
                "permissions": 1_i32,
                "role_permissions": 1_i32,
            };

            // Try to pluck channel permission SendMessage (0x2)
            let has_send = document
                .get_i32("default_permissions")
                .map(|x| (x as u32 & 0x2) == 0x2)
                .unwrap_or(true);

            if has_send {
                // Let parent permissions fall through.
                unset.insert("default_permissions", 1_i32);
            }

            let mut update = doc! {
                "$unset": unset
            };

            if !has_send {
                // Block send message permission.
                update.insert(
                    "$set",
                    doc! {
                        "default_permissions": {
                            "a": 0_i64,
                            "d": (1 << 22) as i64
                        }
                    },
                );
            }

            channels
                .update_one(doc! { "_id": id }, update)
                .await
                .unwrap();
        }
    }

    if revision <= 14 {
        info!("Running migration [revision 14 / 21-04-2022]: Split content into content and system fields.");

        db.col::<Document>("messages")
            .update_many(
                doc! {
                    "content": {
                        "$type": "object"
                    }
                },
                doc! {
                    "$rename": {
                        "content": "system"
                    }
                },
            )
            .await
            .unwrap();
    }

    if revision <= 15 {
        info!("Running migration [revision 15 / 04-06-2022]: Migrate Authifier to latest version.");

        if !db
            .db()
            .collection::<Document>("mfa_tickets")
            .list_index_names()
            .await
            .unwrap_or_default()
            .contains(&"token".to_owned())
        {
            // Make sure all collections exist
            let list = db.db().list_collection_names().await.unwrap();
            let collections = ["accounts", "sessions", "invites", "mfa_tickets"];

            for name in collections {
                if !list.contains(&name.to_string()) {
                    db.db().create_collection(name).await.unwrap();
                }
            }

            // Setup index for `accounts`
            let col = db.db().collection::<Document>("accounts");
            col.drop_indexes().await.unwrap();

            db.db()
                .run_command(doc! {
                    "createIndexes": "accounts",
                    "indexes": [
                        {
                            "key": {
                                "email": 1
                            },
                            "name": "email",
                            "unique": true,
                            "collation": {
                                "locale": "en",
                                "strength": 2
                            }
                        },
                        {
                            "key": {
                                "email_normalised": 1
                            },
                            "name": "email_normalised",
                            "unique": true,
                            "collation": {
                                "locale": "en",
                                "strength": 2
                            }
                        },
                        {
                            "key": {
                                "verification.token": 1
                            },
                            "name": "email_verification"
                        },
                        {
                            "key": {
                                "password_reset.token": 1
                            },
                            "name": "password_reset"
                        }
                    ]
                })
                .await
                .unwrap();

            // Setup index for `sessions`
            let col = db.db().collection::<Document>("sessions");
            col.drop_indexes().await.unwrap();

            db.db()
                .run_command(doc! {
                    "createIndexes": "sessions",
                    "indexes": [
                        {
                            "key": {
                                "token": 1
                            },
                            "name": "token",
                            "unique": true
                        },
                        {
                            "key": {
                                "user_id": 1
                            },
                            "name": "user_id"
                        }
                    ]
                })
                .await
                .unwrap();

            // Setup index for `mfa_tickets`
            let col = db.db().collection::<Document>("mfa_tickets");
            col.drop_indexes().await.unwrap();

            db.db()
                .run_command(doc! {
                    "createIndexes": "mfa_tickets",
                    "indexes": [
                        {
                            "key": {
                                "token": 1
                            },
                            "name": "token",
                            "unique": true
                        }
                    ]
                })
                .await
                .unwrap();
        }
    }

    if revision <= 16 {
        info!("Running migration [revision 16 / 07-07-2022]: Add `emojis` collection and Authifier migration.");

        if !db
            .db()
            .collection::<Document>("accounts")
            .list_index_names()
            .await
            .expect("list of index names")
            .contains(&"account_deletion".to_owned())
        {
            db.db()
                .run_command(doc! {
                    "createIndexes": "accounts",
                    "indexes": [
                        {
                            "key": {
                                "deletion.token": 1
                            },
                            "name": "account_deletion"
                        }
                    ]
                })
                .await
                .unwrap();
        }

        db.db()
            .create_collection("emojis")
            .await
            .expect("Failed to create emojis collection.");

        db.db()
            .run_command(doc! {
                "createIndexes": "emojis",
                "indexes": [
                    {
                        "key": {
                            "parent.id": 1_i32,
                        },
                        "name": "parent_id"
                    }
                ]
            })
            .await
            .expect("Failed to create emoji parent index.");
    }

    if revision <= 17 {
        info!("Running migration [revision 17 / 15-07-2022]: Initialise `joined_at` property on server members.");

        db.col::<Document>("server_members")
            .update_many(
                doc! {},
                doc! {
                    "$set": {
                        "joined_at": DateTime::now().try_to_rfc3339_string().expect("Failed to convert the date to rfc3339")
                    }
                },
            )
            .await
            .expect("Failed to update server members.");
    }

    if revision <= 18 {
        info!("Running migration [revision 18 / 27-02-2022]: Create author index on messages. Drop plain channel index if exists.");

        if db
            .db()
            .run_command(doc! {
                "dropIndexes": "messages",
                "index": ["channel"]
            })
            .await
            .is_err()
        {
            info!("Failed to drop `messages.channel` index but this is ok since that means it's probably gone.");
        }

        db.db()
            .run_command(doc! {
                "createIndexes": "messages",
                "indexes": [
                    {
                        "key": {
                            "author": 1_i32,
                        },
                        "name": "author"
                    }
                ]
            })
            .await
            .expect("Failed to create messages author index.");
    }

    if revision <= 19 {
        info!(
            "Running migration [revision 19 / 27-02-2023]: Create report / snapshot collections."
        );

        db.db().create_collection("safety_reports").await.unwrap();

        db.db().create_collection("safety_snapshots").await.unwrap();
    }

    if revision <= 20 {
        info!("Running migration [revision 20 / 28-02-2023]: Add index `snapshot.report_id`.");

        db.db()
            .run_command(doc! {
                "createIndexes": "safety_snapshots",
                "indexes": [
                    {
                        "key": {
                            "report_id": 1_i32
                        },
                        "name": "report_id"
                    }
                ]
            })
            .await
            .expect("Failed to create safety snapshot index.");
    }

    if revision <= 21 {
        info!("Running migration [revision 21 / 31-05-2023]: Add collection `safety_strikes`.");

        db.db().create_collection("safety_strikes").await.unwrap();
    }

    if revision <= 22 {
        info!("Running migration [revision 22 / 31-05-2023]: Add moderator_id to account strikes.");

        db.col::<Document>("safety_strikes")
            .update_many(
                doc! {},
                doc! {
                    "$set": {
                        "moderator_id": "01EX2NCWQ0CHS3QJF0FEQS1GR4"
                    }
                },
            )
            .await
            .expect("Failed to update server members.");
    }

    if revision <= 23 {
        info!("Running migration [revision 23 / 10-06-2023]: Generate discriminators for users.");

        db.db()
            .run_command(doc! {
                "dropIndexes": "users",
                "index": "username"
            })
            .await
            .expect("Failed to drop existing username index.");

        #[derive(Serialize, Deserialize)]
        struct UserInformation {
            #[serde(rename = "_id")]
            id: String,
            username: String,
        }

        let re_username = regex::Regex::new(r"^(\p{L}|[\d_.-])+$").unwrap();

        let users: Vec<UserInformation> = db
            .col::<UserInformation>("users")
            .find(doc! {})
            .await
            .unwrap()
            .map(|doc| doc.expect("id and username"))
            .collect()
            .await;

        let search_space: Vec<String> = DISCRIMINATOR_SEARCH_SPACE.iter().cloned().collect();
        let mut claimed: HashSet<String> = HashSet::new();

        for i in 0..users.len() {
            let info = &users[i];
            let mut discriminator = {
                let mut rng = rand::thread_rng();
                search_space.choose(&mut rng).unwrap()
            };

            if re_username.is_match(&info.username) {
                while claimed.contains(&format!("{}#{}", info.username, discriminator)) {
                    let new_discriminator = {
                        let mut rng = rand::thread_rng();
                        search_space.choose(&mut rng).unwrap()
                    };

                    info!(
                        "Re-rolled {} to {new_discriminator} from {discriminator}",
                        info.username
                    );

                    discriminator = new_discriminator;
                }

                claimed.insert(format!("{}#{}", info.username, discriminator));

                info!(
                    "({}/{}) Migrating user \"{}\" to #{} - compliant",
                    i + 1,
                    users.len(),
                    info.username,
                    discriminator
                );

                db.col::<UserInformation>("users")
                    .update_one(
                        doc! {
                            "_id": &info.id
                        },
                        doc! {
                            "$set": {
                                "discriminator": discriminator
                            }
                        },
                    )
                    .await
                    .unwrap();
            } else {
                let mut sanitised = info
                    .username
                    .graphemes(true)
                    .filter(|s| re_username.is_match(s))
                    .collect::<String>();

                while sanitised.len() < 2 {
                    sanitised += "_";
                }

                while claimed.contains(&format!("{}#{}", sanitised, discriminator)) {
                    let new_discriminator = {
                        let mut rng = rand::thread_rng();
                        search_space.choose(&mut rng).unwrap()
                    };

                    info!("Re-rolled {sanitised} to {new_discriminator} from {discriminator}");
                    discriminator = new_discriminator;
                }

                claimed.insert(format!("{}#{}", sanitised, discriminator));

                info!(
                    "({}/{}) Migrating user \"{}\" to #{} - sanitised: \"{}\"",
                    i + 1,
                    users.len(),
                    info.username,
                    discriminator,
                    sanitised
                );

                db.col::<UserInformation>("users")
                    .update_one(
                        doc! {
                            "_id": &info.id
                        },
                        doc! {
                            "$set": {
                                "username": sanitised,
                                "discriminator": discriminator,
                                "display_name": &info.username
                            }
                        },
                    )
                    .await
                    .unwrap();
            }
        }
    }

    if revision <= 24 {
        info!("Running migration [revision 24 / 09-06-2023]: Add collection `channel_webhooks` if not exists, update users index.");

        db.db().create_collection("channel_webhooks").await.ok();

        db.db()
            .run_command(doc! {
                "createIndexes": "users",
                "indexes": [
                    {
                        "key": {
                            "username": 1_i32
                        },
                        "name": "username",
                        "unique": false,
                        "collation": {
                            "locale": "en",
                            "strength": 2_i32
                        }
                    },
                    {
                        "key": {
                            "username": 1_i32,
                            "discriminator": 1_i32
                        },
                        "name": "username_discriminator",
                        "unique": true,
                        "collation": {
                            "locale": "en",
                            "strength": 2_i32
                        }
                    }
                ]
            })
            .await
            .expect("Failed to create username index.");
    };

    if revision <= 25 {
        info!("Running migration [revision 25 / 11-06-2023]: Add permissions to webhooks.");

        db.col::<Document>("webhooks")
            .update_many(
                doc! {},
                doc! {
                    "$set": {
                        "permissions": *DEFAULT_WEBHOOK_PERMISSIONS as i64
                    }
                },
            )
            .await
            .expect("Failed to update webhooks.");
    }

    if revision <= 25 {
        info!("Running migration [revision 25 / 15-06-2023]: Add collection `ratelimit_events` with index.");

        db.db().create_collection("ratelimit_events").await.ok();

        db.db()
            .run_command(doc! {
                "createIndexes": "ratelimit_events",
                "indexes": [
                    {
                        "key": {
                            "_id": 1_i32,
                            "target_id": 1_i32,
                            "event_type": 1_i32,
                        },
                        "name": "compound_key"
                    }
                ]
            })
            .await
            .expect("Failed to create ratelimit_events index.");
    }

    if revision <= 26 {
        // Need to migrate fields on attachments, change `user_id`, `object_id`, etc to `parent`.
        info!("Running migration [revision 26 / 15-05-2024]: fix invites being incorrectly serialized with wrong enum tagging.");

        auto_derived!(
            pub enum OldInvite {
                Server {
                    #[serde(rename = "_id")]
                    code: String,
                    server: String,
                    creator: String,
                    channel: String,
                },
                Group {
                    #[serde(rename = "_id")]
                    code: String,
                    creator: String,
                    channel: String,
                },
            }
        );

        #[derive(serde::Serialize, serde::Deserialize)]
        struct Outer {
            _id: ObjectId,
            #[serde(flatten)]
            invite: OldInvite,
        }

        let invites = db
            .db()
            .collection::<Outer>("channel_invites")
            .find(doc! {
                "type": { "$exists": false }
            })
            .await
            .expect("failed to find invites")
            .filter_map(|s| async { s.ok() })
            .collect::<Vec<Outer>>()
            .await
            .into_iter()
            .map(|invite| match invite.invite {
                OldInvite::Server {
                    code,
                    server,
                    creator,
                    channel,
                } => Invite::Server {
                    code,
                    server,
                    creator,
                    channel,
                },
                OldInvite::Group {
                    code,
                    creator,
                    channel,
                } => Invite::Group {
                    code,
                    creator,
                    channel,
                },
            })
            .collect::<Vec<Invite>>();

        if !invites.is_empty() {
            db.db()
                .collection("channel_invites")
                .insert_many(invites)
                .await
                .expect("failed to insert corrected invite");

            db.db()
                .collection::<Outer>("channel_invites")
                .delete_many(doc! {
                    "type": { "$exists": false }
                })
                .await
                .expect("failed to find invites");
        }
    }

    if revision <= 27 {
        info!("Running migration [revision 27 / 21-07-2024]: create message pinned index.");

        db.db()
            .run_command(doc! {
                "createIndexes": "messages",
                "indexes": [
                    {
                        "key": {
                            "channel": 1_i32,
                            "pinned": 1_i32
                        },
                        "name": "channel_pinned_compound"
                    }
                ]
            })
            .await
            .expect("Failed to create message index.");
    }

    if revision <= 28 {
        info!("Running migration [revision 28 / 10-09-2024]: Add support for new Autumn.");

        db.db().create_collection("attachment_hashes").await.ok();

        db.db()
            .run_command(doc! {
                "createIndexes": "attachments",
                "indexes": [
                    {
                        "key": {
                            "hash": 1_i32
                        },
                        "name": "hash"
                    }
                ]
            })
            .await
            .expect("Failed to create attachments index.");

        db.db()
            .run_command(doc! {
                "createIndexes": "attachment_hashes",
                "indexes": [
                    {
                        "key": {
                            "processed_hash": 1_i32
                        },
                        "name": "processed_hash"
                    }
                ]
            })
            .await
            .expect("Failed to create attachment_hashes index.");
    }

    // Revision 29 omitted due to bug.

    if revision <= 30 {
        info!("Running migration [revision 30 / 29-09-2024]: Add index for used_for.id to attachments.");

        db.db()
            .run_command(doc! {
                "createIndexes": "attachments",
                "indexes": [
                    {
                        "key": {
                            "used_for.id": 1_i32
                        },
                        "name": "used_for_id"
                    }
                ]
            })
            .await
            .expect("Failed to create attachments index.");
    }

    if revision <= 31 {
        info!("Running migration [revision 31 / 31-10-2024]: Add creator_id to webhooks and delete those whose channels don't exist.");

        #[derive(serde::Serialize, serde::Deserialize)]
        struct WebhookShell {
            _id: String,
            channel_id: String,
        }

        #[allow(clippy::enum_variant_names)]
        #[derive(serde::Serialize, serde::Deserialize)]
        enum Channel {
            Group { owner: String },
            TextChannel { server: String },
            VoiceChannel { server: String },
        }

        let webhooks = db
            .db()
            .collection::<WebhookShell>("channel_webhooks")
            .find(doc! {})
            .await
            .expect("webhooks")
            .filter_map(|s| async { s.ok() })
            .collect::<Vec<WebhookShell>>()
            .await;

        for webhook in webhooks {
            match db
                .col::<Channel>("channels")
                .find_one(doc! { "_id": &webhook.channel_id })
                .await
                .unwrap()
            {
                Some(channel) => {
                    let creator_id = match channel {
                        Channel::Group { owner, .. } => owner,
                        Channel::TextChannel { server, .. }
                        | Channel::VoiceChannel { server, .. } => {
                            let server = db.fetch_server(&server).await.expect("server");
                            server.owner
                        }
                    };

                    db.db()
                        .collection::<Document>("channel_webhooks")
                        .update_one(
                            doc! {
                                "_id": webhook._id,
                            },
                            doc! {
                                "$set" : {
                                    "creator_id": creator_id
                                }
                            },
                        )
                        .await
                        .expect("update webhook");
                }
                None => {
                    db.db()
                        .collection::<WebhookShell>("channel_webhooks")
                        .delete_one(doc! { "_id": webhook._id })
                        .await
                        .expect("failed to delete invalid webhook");
                }
            }
        }
    }

    if revision <= 32 {
        info!(
            "Running migration [revision 32 / 12-05-2025]: (Authifier) Add last_seen to sessions."
        );

        loop {
            #[derive(Deserialize)]
            struct SessionId {
                _id: String,
            }

            let sessions: Vec<SessionId> = db
                .db()
                .collection("sessions")
                .find(doc! {
                    "$or": [
                        { "last_seen": { "$exists": false } },
                        { "last_seen": "1970-01-01T00:00:00.000Z" }
                    ]
                })
                .limit(50_000) // about 400 batches for 2 million
                .await
                .expect("Failed to create cursor for sessions!")
                .map(|doc| doc.expect("id and username"))
                .collect()
                .await;

            if sessions.is_empty() {
                break;
            }

            for session in sessions {
                let timestamp = iso8601_timestamp::Timestamp::from(Ulid::from_string(&session._id).unwrap().datetime());

                db.db()
                    .collection::<Document>("sessions")
                    .update_one(
                        doc! {
                            "_id": &session._id.to_string(),
                        },
                        doc! {
                            "$set": {
                                "last_seen": timestamp.format().to_string()
                            }
                        },
                    )
                    .await
                    .expect("Failed to update a session.");
            }
        }
    }

    if revision <= 40 {
        info!(
            "Running migration [revision |> 40 / 30-05-2025]: Set last policy acknowlegement date to now and create policy changes collection."
        );

        db.db()
            .create_collection("policy_changes")
            .await
            .expect("Failed to create policy_changes collection.");

        db.db()
            .collection::<User>("users")
            .update_many(
                doc! {},
                doc! {
                    "$set": {
                        "last_acknowledged_policy_change": to_bson(&Timestamp::now_utc())
                            .expect("failed to serialise timestamp")
                    }
                },
            )
            .await
            .expect("failed to update users");
    }

    if revision <= 43 {
        info!(
            "Running migration [revision 43 / 05-06-2025]: convert role ranks to uniform numbers."
        );

        #[derive(Serialize, Deserialize, Clone)]
        struct Role {
            pub rank: i64,
        }

        #[derive(Serialize, Deserialize, Clone)]
        struct Server {
            #[serde(rename = "_id")]
            pub id: String,
            #[serde(default = "HashMap::<String, Role>::new")]
            pub roles: HashMap<String, Role>,
        }

        let mut servers = db
            .db()
            .collection::<Server>("servers")
            .find(doc! {
                "roles": {
                    "$exists": true,
                    "$ne": []
                }
            })
            .await
            .unwrap()
            .filter_map(|s| async { s.ok() })
            .boxed();

        while let Some(server) = servers.next().await {
            let mut ordered_roles = server.roles.clone().into_iter().collect::<Vec<_>>();
            ordered_roles.sort_by(|(_, role_a), (_, role_b)| role_a.rank.cmp(&role_b.rank));
            let ordered_roles = ordered_roles
                .into_iter()
                .map(|(id, _)| id)
                .collect::<Vec<_>>();

            let mut doc = doc! {};

            for id in server.roles.keys() {
                doc.insert(
                    format!("roles.{id}.rank"),
                    ordered_roles.iter().position(|x| id == x).unwrap() as i64,
                );
            }

            db.db()
                .collection::<Server>("servers")
                .update_one(doc! { "_id": &server.id }, doc! { "$set": doc })
                .await
                .unwrap();
        }
    }

    if revision <= 46 {
        info!("Running migration [revision 46 / 29-04-2025]: Convert all `VoiceChannel`'s into `TextChannel`");

        db.col::<Document>("channels")
            .update_many(
                doc! { "channel_type": "VoiceChannel" },
                doc! {
                    "$set": {
                        "channel_type": "TextChannel",
                        "voice": {}
                    }
                },
            )
            .await
            .expect("Failed to update voice channels");
    };

    if revision <= 48 {
        info!("Running migration [revision 48 / 22-10-2025]: Add Video + Listen to default permissions");

        db.col::<Document>("servers")
            .update_many(
                doc! { },
                doc! {
                    "$bit": {
                        "default_permissions": {
                            "or": (ChannelPermission::Video + ChannelPermission::Speak + ChannelPermission::Listen) as i64
                        },
                    }
                }
            )
            .await
            .expect("Failed to update default_permissions");
    };

    if revision <= 49 {
        info!("Running migration [revision 49 / 12-12-2025]: Add _id key to roles");

        #[derive(Serialize, Deserialize, Clone)]
        struct Server {
            #[serde(rename = "_id")]
            pub id: String,
            #[serde(default = "HashMap::<String, Document>::new")]
            pub roles: HashMap<String, Document>,
        }

        let mut servers = db
            .db()
            .collection::<Server>("servers")
            .find(doc! {
                "roles": {
                    "$exists": true,
                    "$ne": {}
                }
            })
            .await
            .unwrap()
            .map(|res| res.expect("Failed to decode Server { id, roles }"));

        while let Some(server) = servers.next().await {
            let mut doc = doc! {};

            for id in server.roles.keys() {
                doc.insert(format!("roles.{id}._id"), id);
            }

            db.db()
                .collection::<Server>("servers")
                .update_one(doc! { "_id": &server.id }, doc! { "$set": doc })
                .await
                .unwrap();
        }
    };

    if revision <= 50 {
        info!("Running migration [revision 50 / 13-04-2026]: Rename invites collection to account_invites");

        db.db()
            .client()
            .database("admin")
            .run_command(doc! {
                "renameCollection": "revolt.invites",
                "to": "revolt.account_invites",
                "dropTarget": true
            })
            .await
            .unwrap();
    }

    if revision <= 51 {
        info!("Running migration [revision 51 / 07-07-2026]: Create E2EE collections and indexes");

        db.db().create_collection("e2ee_identity").await.ok();
        db.db().create_collection("e2ee_prekeys").await.ok();
        db.db().create_collection("e2ee_queue").await.ok();

        db.db()
            .run_command(doc! {
                "createIndexes": "e2ee_identity",
                "indexes": [
                    {
                        "key": {
                            "user_id": 1,
                            "device_id": 1
                        },
                        "name": "user_device",
                        "unique": true
                    }
                ]
            })
            .await
            .expect("Failed to create e2ee_identity index.");

        db.db()
            .run_command(doc! {
                "createIndexes": "e2ee_prekeys",
                "indexes": [
                    {
                        "key": {
                            "user_id": 1,
                            "device_id": 1
                        },
                        "name": "user_device"
                    }
                ]
            })
            .await
            .expect("Failed to create e2ee_prekeys index.");

        db.db()
            .run_command(doc! {
                "createIndexes": "e2ee_queue",
                "indexes": [
                    {
                        "key": {
                            "recipient_user_id": 1,
                            "recipient_device_id": 1,
                            "_id": 1
                        },
                        "name": "recipient_compound"
                    }
                ]
            })
            .await
            .expect("Failed to create e2ee_queue index.");
    }

    if revision <= 52 {
        info!("Running migration [revision 52 / 07-07-2026]: Create E2EE blob collection");

        db.db().create_collection("e2ee_blobs").await.ok();
        // Lookups are by _id (built-in index); the TTL sweep is an _id range
        // scan with an in-range size filter — no additional index needed
    }

    if revision <= 53 {
        info!("Running migration [revision 53 / 08-07-2026]: Create E2EE key-backup collection");

        db.db().create_collection("e2ee_backups").await.ok();

        // One backup blob per (user_id, device_id). The composite _id already
        // guarantees uniqueness; this named index makes the per-user restore
        // fetch and the account-deletion cascade efficient.
        db.db()
            .run_command(doc! {
                "createIndexes": "e2ee_backups",
                "indexes": [
                    {
                        "key": {
                            "user_id": 1,
                            "device_id": 1
                        },
                        "name": "user_device",
                        "unique": true
                    }
                ]
            })
            .await
            .expect("Failed to create e2ee_backups index.");
    }

    if revision <= 54 {
        info!("Running migration [revision 54 / 09-07-2026]: Create calendar events collections and indexes");

        // Existing deployments predate the calendar feature: init.rs only covers fresh
        // DBs. Collections + indexes mirror init.rs exactly; both operations are
        // idempotent (create_collection errors are ignored; createIndexes is a no-op
        // when key+name already match), so a re-run or a fresh DB is safe.
        db.db().create_collection("calendar_events").await.ok();
        db.db().create_collection("event_rsvps").await.ok();
        db.db().create_collection("event_reminders_sent").await.ok();

        db.db()
            .run_command(doc! {
                "createIndexes": "calendar_events",
                "indexes": [
                    {
                        "key": {
                            "server": 1_i32,
                            "series_end": 1_i32,
                        },
                        "name": "server_series_end"
                    },
                    {
                        "key": {
                            "server": 1_i32,
                            "start": 1_i32,
                        },
                        "name": "server_start"
                    },
                    // Global (server-agnostic) bound for crond's cross-server reminder
                    // scan, which filters on series_end/start without a server prefix
                    // (design §9).
                    {
                        "key": {
                            "series_end": 1_i32,
                        },
                        "name": "series_end_global"
                    }
                ]
            })
            .await
            .expect("Failed to create calendar_events indexes.");

        db.db()
            .run_command(doc! {
                "createIndexes": "event_rsvps",
                "indexes": [
                    {
                        "key": {
                            "_id.event": 1_i32,
                        },
                        "name": "event_id"
                    },
                    {
                        "key": {
                            "_id.user": 1_i32,
                        },
                        "name": "user_id"
                    }
                ]
            })
            .await
            .expect("Failed to create event_rsvps indexes.");

        db.db()
            .run_command(doc! {
                "createIndexes": "event_reminders_sent",
                "indexes": [
                    // Serves the reminder retention sweep (delete markers by occurrence).
                    {
                        "key": {
                            "_id.occurrence": 1_i32,
                        },
                        "name": "occurrence"
                    }
                ]
            })
            .await
            .expect("Failed to create event_reminders_sent indexes.");
    }

    if revision <= 55 {
        info!("Running migration [revision 55 / 10-07-2026]: Create MLS delivery-service collections and indexes (media E2EE)");

        // Existing deployments predate media E2EE: init.rs only covers fresh
        // DBs. Collections + indexes mirror init.rs exactly; both operations
        // are idempotent (create_collection errors are ignored; createIndexes
        // is a no-op when key+name already match), so a re-run or a fresh DB
        // is safe.
        db.db().create_collection("mls_key_packages").await.ok();
        db.db().create_collection("mls_groups").await.ok();
        db.db().create_collection("mls_commits").await.ok();
        db.db().create_collection("mls_join_intents").await.ok();

        db.db()
            .run_command(doc! {
                "createIndexes": "mls_key_packages",
                "indexes": [
                    {
                        "key": {
                            "user_id": 1_i32,
                            "device_id": 1_i32,
                            "last_resort": 1_i32
                        },
                        "name": "user_device_last_resort"
                    },
                    {
                        "key": {
                            "expires_at": 1_i32
                        },
                        "name": "expires_at"
                    }
                ]
            })
            .await
            .expect("Failed to create mls_key_packages indexes.");

        // The channel-scoped create-race arbitration (media-E2EE plan
        // §1.2/A5): at most ONE open group per channel.
        db.db()
            .run_command(doc! {
                "createIndexes": "mls_groups",
                "indexes": [
                    {
                        "key": {
                            "channel_id": 1_i32
                        },
                        "name": "open_channel_group",
                        "unique": true,
                        "partialFilterExpression": { "open": true }
                    }
                ]
            })
            .await
            .expect("Failed to create mls_groups indexes.");

        db.db()
            .run_command(doc! {
                "createIndexes": "mls_commits",
                "indexes": [
                    {
                        "key": {
                            "group_id": 1_i32,
                            "epoch": 1_i32
                        },
                        "name": "group_epoch"
                    }
                ]
            })
            .await
            .expect("Failed to create mls_commits indexes.");

        db.db()
            .run_command(doc! {
                "createIndexes": "mls_join_intents",
                "indexes": [
                    {
                        "key": {
                            "group_id": 1_i32
                        },
                        "name": "group_id"
                    }
                ]
            })
            .await
            .expect("Failed to create mls_join_intents indexes.");
    }

    if revision <= 56 {
        info!("Running migration [revision 56 / 11-07-2026]: Create thread_members collection and thread indexes");

        // Existing deployments predate threads: init.rs only covers fresh DBs.
        // Collections + indexes mirror init.rs exactly; both operations are
        // idempotent (create_collection errors are ignored; createIndexes is a
        // no-op when key+name already match), so a re-run or a fresh DB is safe.
        db.db().create_collection("thread_members").await.ok();

        db.db()
            .run_command(doc! {
                "createIndexes": "thread_members",
                "indexes": [
                    // Serves member-list fetches and thread-deletion cascades.
                    {
                        "key": {
                            "_id.thread": 1_i32,
                        },
                        "name": "thread"
                    },
                    // Serves "which threads has this user joined" (Ready assembly).
                    {
                        "key": {
                            "_id.user": 1_i32,
                        },
                        "name": "user"
                    }
                ]
            })
            .await
            .expect("Failed to create thread_members indexes.");

        // Serves the per-channel threads list, the active-thread cap and the
        // crond auto-archive scan.
        db.db()
            .run_command(doc! {
                "createIndexes": "channels",
                "indexes": [
                    {
                        "key": {
                            "channel_type": 1_i32,
                            "parent_channel": 1_i32,
                            "archived": 1_i32,
                        },
                        "name": "thread_parent_archived"
                    }
                ]
            })
            .await
            .expect("Failed to create channels thread index.");
    }

    if revision <= 57 {
        info!("Running migration [revision 57 / 12-07-2026]: Create application_commands and interactions collections (slash-command bots)");

        // Existing deployments predate slash commands: init.rs only covers
        // fresh DBs. Collections + indexes mirror init.rs exactly; both
        // operations are idempotent (create_collection errors are ignored;
        // createIndexes is a no-op when key+name already match), so a re-run
        // or a fresh DB is safe.
        db.db().create_collection("application_commands").await.ok();
        db.db().create_collection("interactions").await.ok();

        db.db()
            .run_command(doc! {
                "createIndexes": "application_commands",
                "indexes": [
                    // Uniqueness backstop for the (bot, scope, name) triple —
                    // global commands store `server` as missing/null, which
                    // the index treats as a value, so global names are unique
                    // per bot too.
                    {
                        "key": {
                            "bot_id": 1_i32,
                            "server": 1_i32,
                            "name": 1_i32
                        },
                        "name": "bot_scope_name",
                        "unique": true
                    },
                    // Serves the per-channel command picker (server-scoped
                    // OR global commands).
                    {
                        "key": {
                            "server": 1_i32
                        },
                        "name": "server"
                    }
                ]
            })
            .await
            .expect("Failed to create application_commands indexes.");

        // `interactions` needs a bot_id index for the bot-deletion cascade;
        // expiry cleanup deletes by _id range (ULID clock) so the primary
        // index covers it.
        db.db()
            .run_command(doc! {
                "createIndexes": "interactions",
                "indexes": [
                    {
                        "key": {
                            "bot_id": 1_i32
                        },
                        "name": "bot_id"
                    }
                ]
            })
            .await
            .expect("Failed to create interactions indexes.");
    }

    if revision <= 58 {
        info!("Running migration [revision 58 / 13-07-2026]: Create polls and poll_votes collections (Discord-style polls)");

        // Existing deployments predate polls: init.rs only covers fresh DBs.
        // Collections + indexes mirror init.rs exactly; both operations are
        // idempotent (create_collection errors are ignored; createIndexes is
        // a no-op when key+name already match), so a re-run or a fresh DB is
        // safe.
        db.db().create_collection("polls").await.ok();
        db.db().create_collection("poll_votes").await.ok();

        db.db()
            .run_command(doc! {
                "createIndexes": "polls",
                "indexes": [
                    // One poll per message; serves the message-deletion
                    // cascade.
                    {
                        "key": {
                            "message": 1_i32
                        },
                        "name": "message",
                        "unique": true
                    },
                    // Serves the crond expiry scan (open polls past their
                    // expiry).
                    {
                        "key": {
                            "closed": 1_i32,
                            "expires_at": 1_i32
                        },
                        "name": "closed_expires"
                    },
                    // Serves the channel-deletion cascade.
                    {
                        "key": {
                            "channel": 1_i32
                        },
                        "name": "channel"
                    }
                ]
            })
            .await
            .expect("Failed to create polls indexes.");

        db.db()
            .run_command(doc! {
                "createIndexes": "poll_votes",
                "indexes": [
                    // Multikey (answer_ids is an array): serves the
                    // author-gated voters-per-answer listing and the
                    // recount-at-close fetch.
                    {
                        "key": {
                            "poll": 1_i32,
                            "answer_ids": 1_i32
                        },
                        "name": "poll_answers"
                    },
                    // Serves the channel-deletion cascade.
                    {
                        "key": {
                            "channel": 1_i32
                        },
                        "name": "channel"
                    }
                ]
            })
            .await
            .expect("Failed to create poll_votes indexes.");
    }

    if revision <= 59 {
        info!("Running migration [revision 59 / 13-07-2026]: Create scheduled_messages collection (message scheduling)");

        // Existing deployments predate scheduled messages: init.rs only
        // covers fresh DBs. Collection + indexes mirror init.rs exactly;
        // both operations are idempotent (create_collection errors are
        // ignored; createIndexes is a no-op when key+name already match),
        // so a re-run or a fresh DB is safe.
        db.db().create_collection("scheduled_messages").await.ok();

        db.db()
            .run_command(doc! {
                "createIndexes": "scheduled_messages",
                "indexes": [
                    // Serves the crond due-delivery scan (pending rows past
                    // their instant) and the retention sweep.
                    {
                        "key": {
                            "status": 1_i32,
                            "scheduled_at": 1_i32
                        },
                        "name": "status_scheduled_at"
                    },
                    // Serves the author-scoped pending list and the pending
                    // caps.
                    {
                        "key": {
                            "author": 1_i32,
                            "channel": 1_i32
                        },
                        "name": "author_channel"
                    },
                    // Serves the channel-deletion cascade.
                    {
                        "key": {
                            "channel": 1_i32
                        },
                        "name": "channel"
                    }
                ]
            })
            .await
            .expect("Failed to create scheduled_messages indexes.");
    }

    if revision <= 60 {
        info!("Running migration [revision 60 / 14-07-2026]: Create channel_follows collection (announcement channels)");

        // Existing deployments predate announcement channels: init.rs only
        // covers fresh DBs. Collection + indexes mirror init.rs exactly;
        // both operations are idempotent (create_collection errors are
        // ignored; createIndexes is a no-op when key+name already match),
        // so a re-run or a fresh DB is safe.
        db.db().create_collection("channel_follows").await.ok();

        db.db()
            .run_command(doc! {
                "createIndexes": "channel_follows",
                "indexes": [
                    // Unique (source, target) makes follows idempotent AND
                    // serves the follower-list + publish fan-out (source
                    // prefix).
                    {
                        "key": {
                            "source_channel": 1_i32,
                            "target_channel": 1_i32
                        },
                        "name": "source_target",
                        "unique": true
                    },
                    // Serves target-side cleanup on channel deletion.
                    {
                        "key": {
                            "target_channel": 1_i32
                        },
                        "name": "target_channel"
                    },
                    // Serves the webhook-deletion unfollow hook.
                    {
                        "key": {
                            "webhook_id": 1_i32
                        },
                        "name": "webhook_id"
                    }
                ]
            })
            .await
            .expect("Failed to create channel_follows indexes.");
    }

    if revision <= 61 {
        info!("Running migration [revision 61 / 14-07-2026]: Create sounds collection (soundboard)");

        // Existing deployments predate the soundboard: init.rs only covers
        // fresh DBs. Collection + index mirror init.rs exactly; both
        // operations are idempotent (create_collection errors are ignored;
        // createIndexes is a no-op when key+name already match), so a re-run
        // or a fresh DB is safe.
        db.db().create_collection("sounds").await.ok();

        db.db()
            .run_command(doc! {
                "createIndexes": "sounds",
                "indexes": [
                    // Serves the per-server sound listing (settings + picker).
                    {
                        "key": {
                            "server_id": 1_i32
                        },
                        "name": "server_id"
                    }
                ]
            })
            .await
            .expect("Failed to create sounds indexes.");
    }

    if revision <= 62 {
        info!("Running migration [revision 62 / 19-07-2026]: Server discovery indexes");

        // Public directory + admin approval queue. Both flags are sparse
        // (false = absent field, skip_serializing_if = if_false), so the
        // queries use {"$ne": true} — these exact-match indexes serve the
        // `true` side, which is the only side ever queried by equality.
        db.db()
            .run_command(doc! {
                "createIndexes": "servers",
                "indexes": [
                    // Serves the public /discover/servers listing.
                    {
                        "key": {
                            "discoverable": 1_i32
                        },
                        "name": "discoverable"
                    },
                    // Serves the privileged /discover/requests queue.
                    {
                        "key": {
                            "discovery_requested": 1_i32
                        },
                        "name": "discovery_requested"
                    }
                ]
            })
            .await
            .expect("Failed to create servers discovery indexes.");
    }

    if revision <= 63 {
        info!("Running migration [revision 63 / 19-07-2026]: Create user_stream_connections collection (streaming connections)");

        // Private collection holding linked Twitch/YouTube channels +
        // provider tokens (never exposed on User). Same idempotency
        // contract as prior collection migrations; mirrors init.rs.
        db.db()
            .create_collection("user_stream_connections")
            .await
            .ok();

        db.db()
            .run_command(doc! {
                "createIndexes": "user_stream_connections",
                "indexes": [
                    // Serves per-user fetch/sync/unlink + deletion cascade.
                    {
                        "key": {
                            "user_id": 1_i32
                        },
                        "name": "user_id"
                    },
                    // Serves the live-status poller's per-platform scan.
                    {
                        "key": {
                            "platform": 1_i32
                        },
                        "name": "platform"
                    }
                ]
            })
            .await
            .expect("Failed to create user_stream_connections indexes.");
    }

    if revision <= 64 {
        info!("Running migration [revision 64 / 19-07-2026]: Create server_boosts collection (server boosts)");

        // One document per boost slot (user-owned, optionally allocated to
        // a server). Same idempotency contract as prior collection
        // migrations; mirrors init.rs.
        db.db().create_collection("server_boosts").await.ok();

        db.db()
            .run_command(doc! {
                "createIndexes": "server_boosts",
                "indexes": [
                    // Serves inventory fetch/count + account-deletion cascade.
                    {
                        "key": {
                            "user_id": 1_i32
                        },
                        "name": "user_id"
                    },
                    // Serves per-server counts/lists + deletion cascade.
                    // Sparse: unallocated slots have NO server_id field.
                    {
                        "key": {
                            "server_id": 1_i32
                        },
                        "name": "server_id",
                        "sparse": true
                    },
                    // Serves the crond expiry sweep ($lte scan). Sparse:
                    // permanent slots have NO expires_at field.
                    {
                        "key": {
                            "expires_at": 1_i32
                        },
                        "name": "expires_at",
                        "sparse": true
                    }
                ]
            })
            .await
            .expect("Failed to create server_boosts indexes.");
    }

    if revision <= 65 {
        info!("Running migration [revision 65 / 25-07-2026]: Create discord_import_jobs collection (Discord server import)");

        // One document per import attempt, driven by the crond claim
        // worker. Same idempotency contract as prior collection
        // migrations; mirrors init.rs.
        db.db().create_collection("discord_import_jobs").await.ok();

        db.db()
            .run_command(doc! {
                "createIndexes": "discord_import_jobs",
                "indexes": [
                    // ENFORCES one active import per user. delta's
                    // read-then-insert check is a TOCTOU — N concurrent
                    // requests all read "no active job" and would each
                    // create a server + invite. Partial, so the unique
                    // constraint applies only to non-terminal rows and a
                    // user's finished imports never block a new one.
                    // `insert_discord_import_job` maps the resulting 11000
                    // to ImportAlreadyInProgress.
                    // NB: $in inside partialFilterExpression needs MongoDB
                    // 6.0+.
                    {
                        "key": {
                            "user_id": 1_i32
                        },
                        "name": "active_user_id",
                        "unique": true,
                        "partialFilterExpression": {
                            "status": { "$in": ["Queued", "Running"] }
                        }
                    },
                    // Serves the one-active-import-per-user lookup for
                    // terminal rows too (job history by user).
                    {
                        "key": {
                            "user_id": 1_i32
                        },
                        "name": "user_id"
                    },
                    // Serves the claim worker's Queued pick and the
                    // sweeper's non-terminal + stale-heartbeat scan.
                    {
                        "key": {
                            "status": 1_i32
                        },
                        "name": "status"
                    }
                ]
            })
            .await
            .expect("Failed to create discord_import_jobs indexes.");
    }

    if revision <= 66 {
        info!("Running migration [revision 66 / 26-07-2026]: Create softres_sheets / softres_reserves collections (soft-reserve loot sheets)");

        // Same idempotency contract as prior collection migrations;
        // mirrors init.rs. The unique specs here MUST stay identical to
        // the copies in init.rs and the softres ops tests.
        db.db().create_collection("softres_sheets").await.ok();
        db.db().create_collection("softres_reserves").await.ok();

        db.db()
            .run_command(doc! {
                "createIndexes": "softres_sheets",
                "indexes": [
                    // One sheet per message; serves the message-deletion
                    // cascade.
                    {
                        "key": {
                            "message": 1_i32
                        },
                        "name": "message",
                        "unique": true
                    },
                    // ENFORCES one sheet per calendar event — delta's
                    // create-time check is a TOCTOU and the loser of the
                    // concurrent double-link race must fail here (mapped
                    // to SoftResEventAlreadyLinked). Sparse: un-linked
                    // sheets have NO event field.
                    {
                        "key": {
                            "event": 1_i32
                        },
                        "name": "event",
                        "unique": true,
                        "sparse": true
                    },
                    // Serves the channel-deletion cascade.
                    {
                        "key": {
                            "channel": 1_i32
                        },
                        "name": "channel"
                    },
                    // Serves the server-deletion cascade. Sparse: DM/group
                    // sheets have NO server field.
                    {
                        "key": {
                            "server": 1_i32
                        },
                        "name": "server",
                        "sparse": true
                    }
                ]
            })
            .await
            .expect("Failed to create softres_sheets indexes.");

        db.db()
            .run_command(doc! {
                "createIndexes": "softres_reserves",
                "indexes": [
                    // Serves the full-sheet fetch (render/export).
                    {
                        "key": {
                            "sheet": 1_i32
                        },
                        "name": "sheet"
                    },
                    // Multikey (items is an array): serves the per-item
                    // cap count.
                    {
                        "key": {
                            "sheet": 1_i32,
                            "items": 1_i32
                        },
                        "name": "sheet_items"
                    },
                    // Serves the channel-deletion cascade.
                    {
                        "key": {
                            "channel": 1_i32
                        },
                        "name": "channel"
                    }
                ]
            })
            .await
            .expect("Failed to create softres_reserves indexes.");
    }

    if revision <= 67 {
        info!("Running migration [revision 67 / 27-07-2026]: Create remote_control_audit collection (remote-control grant lifecycle audit)");

        // Same idempotency contract as prior collection migrations;
        // mirrors init.rs — keep the index specs identical there.
        db.db().create_collection("remote_control_audit").await.ok();

        db.db()
            .run_command(doc! {
                "createIndexes": "remote_control_audit",
                "indexes": [
                    // Serves per-channel audit review.
                    {
                        "key": {
                            "channel_id": 1_i32,
                            "created_at": 1_i32
                        },
                        "name": "channel_created"
                    },
                    // Serves the abuse lookup — rows pivoted on the account
                    // that was (or would have been) given control.
                    {
                        "key": {
                            "controller_id": 1_i32,
                            "created_at": 1_i32
                        },
                        "name": "controller"
                    }
                ]
            })
            .await
            .expect("Failed to create remote_control_audit indexes.");
    }

    if revision <= 68 {
        info!("Running migration [revision 68 / 19-08-2026]: Add UseWatchTogether to servers' default permissions");

        // `DEFAULT_PERMISSION` is stored onto `Server.default_permissions` at
        // creation and read back from there, so the constant alone reaches
        // only NEW servers (revision-48 shape). Same $bit or, same
        // idempotency: re-running it is a no-op.
        db.col::<Document>("servers")
            .update_many(
                doc! {},
                doc! {
                    "$bit": {
                        "default_permissions": {
                            "or": ChannelPermission::UseWatchTogether as i64
                        },
                    }
                },
            )
            .await
            .expect("Failed to add UseWatchTogether to default_permissions");
    }

    // Reminder to update LATEST_REVISION when adding new migrations.
    LATEST_REVISION.max(revision)
}
