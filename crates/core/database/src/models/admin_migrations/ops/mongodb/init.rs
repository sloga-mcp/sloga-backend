use super::scripts::LATEST_REVISION;

use crate::mongodb::bson::doc;
use crate::mongodb::options::CreateCollectionOptions;
use crate::MongoDb;

pub async fn create_database(db: &MongoDb) {
    info!("Creating database.");
    let db = db.db();

    db.create_collection("accounts")
        .await
        .expect("Failed to create accounts collection.");

    db.create_collection("users")
        .await
        .expect("Failed to create users collection.");

    db.create_collection("channels")
        .await
        .expect("Failed to create channels collection.");

    db.create_collection("messages")
        .await
        .expect("Failed to create messages collection.");

    db.create_collection("servers")
        .await
        .expect("Failed to create servers collection.");

    db.create_collection("server_members")
        .await
        .expect("Failed to create server_members collection.");

    db.create_collection("server_bans")
        .await
        .expect("Failed to create server_bans collection.");

    db.create_collection("channel_invites")
        .await
        .expect("Failed to create channel_invites collection.");

    db.create_collection("channel_unreads")
        .await
        .expect("Failed to create channel_unreads collection.");

    db.create_collection("channel_webhooks")
        .await
        .expect("Failed to create channel_webhooks collection.");

    db.create_collection("calendar_events")
        .await
        .expect("Failed to create calendar_events collection.");

    db.create_collection("event_rsvps")
        .await
        .expect("Failed to create event_rsvps collection.");

    db.create_collection("event_reminders_sent")
        .await
        .expect("Failed to create event_reminders_sent collection.");

    db.create_collection("migrations")
        .await
        .expect("Failed to create migrations collection.");

    db.create_collection("attachments")
        .await
        .expect("Failed to create attachments collection.");

    db.create_collection("attachment_hashes")
        .await
        .expect("Failed to create attachment_hashes collection.");

    db.create_collection("user_settings")
        .await
        .expect("Failed to create user_settings collection.");

    db.create_collection("policy_changes")
        .await
        .expect("Failed to create policy_changes collection.");

    db.create_collection("safety_reports")
        .await
        .expect("Failed to create safety_reports collection.");

    db.create_collection("safety_snapshots")
        .await
        .expect("Failed to create safety_snapshots collection.");

    db.create_collection("safety_strikes")
        .await
        .expect("Failed to create safety_strikes collection.");

    db.create_collection("bots")
        .await
        .expect("Failed to create bots collection.");

    db.create_collection("ratelimit_events")
        .await
        .expect("Failed to create ratelimit_events collection.");

    db.create_collection("pubsub")
        .with_options(
            CreateCollectionOptions::builder()
                .capped(true)
                .size(1_000_000)
                .build(),
        )
        .await
        .expect("Failed to create pubsub collection.");

    db.create_collection("sessions")
        .await
        .expect("Failed to create sessions collection.");

    db.create_collection("account_invites")
        .await
        .expect("Failed to create account_invites collection.");

    db.create_collection("mfa_tickets")
        .await
        .expect("Failed to create mfa_tickets collection.");

    db.create_collection("e2ee_identity")
        .await
        .expect("Failed to create e2ee_identity collection.");

    db.create_collection("e2ee_prekeys")
        .await
        .expect("Failed to create e2ee_prekeys collection.");

    db.create_collection("e2ee_queue")
        .await
        .expect("Failed to create e2ee_queue collection.");

    db.create_collection("mls_key_packages")
        .await
        .expect("Failed to create mls_key_packages collection.");

    db.create_collection("mls_groups")
        .await
        .expect("Failed to create mls_groups collection.");

    db.create_collection("mls_commits")
        .await
        .expect("Failed to create mls_commits collection.");

    db.create_collection("mls_join_intents")
        .await
        .expect("Failed to create mls_join_intents collection.");

    db.create_collection("thread_members")
        .await
        .expect("Failed to create thread_members collection.");

    db.create_collection("application_commands")
        .await
        .expect("Failed to create application_commands collection.");

    db.create_collection("interactions")
        .await
        .expect("Failed to create interactions collection.");

    db.create_collection("polls")
        .await
        .expect("Failed to create polls collection.");

    db.create_collection("poll_votes")
        .await
        .expect("Failed to create poll_votes collection.");

    db.create_collection("scheduled_messages")
        .await
        .expect("Failed to create scheduled_messages collection.");

    db.create_collection("channel_follows")
        .await
        .expect("Failed to create channel_follows collection.");

    db.create_collection("sounds")
        .await
        .expect("Failed to create sounds collection.");

    db.run_command(doc! {
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

    db.run_command(doc! {
        "createIndexes": "messages",
        "indexes": [
            {
                "key": {
                    "content": "text"
                },
                "name": "content"
            },
            {
                "key": {
                    "channel": 1_i32,
                    "_id": 1_i32
                },
                "name": "channel_id_compound"
            },
            {
                "key": {
                    "author": 1_i32
                },
                "name": "author"
            },
            {
                "key": {
                    "channel": 1_i32,
                    "pinned": 1_i32
                },
                "name": "channel_pinned_compound"
            },
        ]
    })
    .await
    .expect("Failed to create message index.");

    db.run_command(doc! {
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

    db.run_command(doc! {
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
    .expect("Failed to create thread_members index.");

    db.run_command(doc! {
        "createIndexes": "application_commands",
        "indexes": [
            // Uniqueness backstop for the (bot, scope, name) triple.
            {
                "key": {
                    "bot_id": 1_i32,
                    "server": 1_i32,
                    "name": 1_i32
                },
                "name": "bot_scope_name",
                "unique": true
            },
            // Serves the per-channel command picker.
            {
                "key": {
                    "server": 1_i32
                },
                "name": "server"
            }
        ]
    })
    .await
    .expect("Failed to create application_commands index.");

    db.run_command(doc! {
        "createIndexes": "interactions",
        "indexes": [
            // Serves the bot-deletion cascade; expiry cleanup deletes by
            // _id range (ULID clock) so the primary index covers it.
            {
                "key": {
                    "bot_id": 1_i32
                },
                "name": "bot_id"
            }
        ]
    })
    .await
    .expect("Failed to create interactions index.");

    db.run_command(doc! {
        "createIndexes": "polls",
        "indexes": [
            // One poll per message; serves the message-deletion cascade.
            {
                "key": {
                    "message": 1_i32
                },
                "name": "message",
                "unique": true
            },
            // Serves the crond expiry scan (open polls past their expiry).
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
    .expect("Failed to create polls index.");

    db.run_command(doc! {
        "createIndexes": "poll_votes",
        "indexes": [
            // Multikey (answer_ids is an array): serves the author-gated
            // voters-per-answer listing and the recount-at-close fetch.
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
    .expect("Failed to create poll_votes index.");

    db.run_command(doc! {
        "createIndexes": "scheduled_messages",
        "indexes": [
            // Serves the crond due-delivery scan (pending rows past their
            // instant) and the retention sweep.
            {
                "key": {
                    "status": 1_i32,
                    "scheduled_at": 1_i32
                },
                "name": "status_scheduled_at"
            },
            // Serves the author-scoped pending list and the pending caps.
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
    .expect("Failed to create scheduled_messages index.");

    db.run_command(doc! {
        "createIndexes": "channel_follows",
        "indexes": [
            // Unique (source, target) makes follows idempotent AND serves the
            // follower-list + publish fan-out (source prefix).
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
    .expect("Failed to create channel_follows index.");

    db.run_command(doc! {
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
    .expect("Failed to create sounds index.");

    db.run_command(doc! {
        "createIndexes": "servers",
        "indexes": [
            // Serves the public /discover/servers listing. Sparse boolean:
            // false is an absent field; queries match {"discoverable": true}.
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

    db.run_command(doc! {
        "createIndexes": "channels",
        "indexes": [
            // Serves the per-channel threads list, the active-thread cap and
            // the crond auto-archive scan.
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

    db.run_command(doc! {
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

    db.run_command(doc! {
        "createIndexes": "attachments",
        "indexes": [
            {
                "key": {
                    "hash": 1_i32
                },
                "name": "hash"
            },
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

    db.run_command(doc! {
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

    db.collection("migrations")
        .insert_one(doc! {
            "_id": 0_i32,
            "revision": LATEST_REVISION
        })
        .await
        .expect("Failed to save migration info.");

    db.run_command(doc! {
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

    db.run_command(doc! {
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
            },
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

    db.run_command(doc! {
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

    db.run_command(doc! {
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

    db.run_command(doc! {
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
    .unwrap();

    db.run_command(doc! {
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
    .unwrap();

    db.run_command(doc! {
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
    .unwrap();

    db.run_command(doc! {
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
            // Global (server-agnostic) bound for crond's cross-server reminder scan,
            // which filters on series_end/start without a server prefix (design §9).
            {
                "key": {
                    "series_end": 1_i32,
                },
                "name": "series_end_global"
            }
        ]
    })
    .await
    .expect("Failed to create calendar_events index.");

    db.run_command(doc! {
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
    .expect("Failed to create event_rsvps index.");

    db.run_command(doc! {
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
    .expect("Failed to create event_reminders_sent index.");

    db.run_command(doc! {
        "createIndexes": "mls_key_packages",
        "indexes": [
            // Serves count/consume/replace (consume filters on last_resort)
            {
                "key": {
                    "user_id": 1_i32,
                    "device_id": 1_i32,
                    "last_resort": 1_i32
                },
                "name": "user_device_last_resort"
            },
            // Serves the hourly expiry sweep
            {
                "key": {
                    "expires_at": 1_i32
                },
                "name": "expires_at"
            }
        ]
    })
    .await
    .expect("Failed to create mls_key_packages index.");

    db.run_command(doc! {
        "createIndexes": "mls_groups",
        "indexes": [
            // The channel-scoped create-race arbitration (media-E2EE plan
            // §1.2/A5): at most ONE open group per channel; racing creators
            // are settled by this partial unique index, never by group_id
            // (racing creators derive DIFFERENT group ids).
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
    .expect("Failed to create mls_groups index.");

    db.run_command(doc! {
        "createIndexes": "mls_commits",
        "indexes": [
            // Serves the gap refetch (epoch range scan per group)
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
    .expect("Failed to create mls_commits index.");

    db.run_command(doc! {
        "createIndexes": "mls_join_intents",
        "indexes": [
            // Serves the group sweep's cascade delete
            {
                "key": {
                    "group_id": 1_i32
                },
                "name": "group_id"
            }
        ]
    })
    .await
    .expect("Failed to create mls_join_intents index.");

    info!("Created database.");
}
