use revolt_result::Result;

use crate::ServerLegalHold;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

/// The legal-hold stub (design 2.9). No client route reaches these: writes
/// come from a privileged admin path (S9) or an operator; the wipe route,
/// protect with `wiped` and the `history_wipes` job read the hold.
#[async_trait]
pub trait AbstractServerLegalHolds: Sync + Send {
    /// Fetch the hold on a server, if one is set
    async fn fetch_server_legal_hold(&self, server_id: &str) -> Result<Option<ServerLegalHold>>;

    /// Set the hold on `hold.id`, replacing any stored row whole (a hold
    /// set again without a note stores no note)
    async fn set_server_legal_hold(&self, hold: &ServerLegalHold) -> Result<()>;

    /// Clear the hold on a server; clearing a server with no hold succeeds
    async fn clear_server_legal_hold(&self, server_id: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_models::v0::{DataCreateServer, DataCreateServerChannel, LegacyServerChannelType};

    use crate::{Channel, Database, Server, ServerLegalHold, User};

    const OTHER_SERVER: &str = "01OTHERSERVER000000000000000";

    /// Whole milliseconds: Mongo stores dates in milliseconds
    fn at(ms: i64) -> Timestamp {
        Timestamp::UNIX_EPOCH
            .checked_add(Duration::milliseconds(ms))
            .expect("timestamp")
    }

    fn hold(server_id: &str, set_by: &str, ms: i64, note: Option<&str>) -> ServerLegalHold {
        ServerLegalHold {
            id: server_id.to_string(),
            set_at: at(ms),
            set_by: set_by.to_string(),
            note: note.map(str::to_string),
        }
    }

    /// A server with one text channel, owned by a fresh user
    async fn server_with_a_channel(db: &Database) -> Server {
        let owner = User::create(db, "HoldOwner".to_string(), None, None)
            .await
            .expect("`User`");
        let (mut server, _) = Server::create(
            db,
            DataCreateServer {
                name: "Held".to_string(),
                description: None,
                nsfw: None,
            },
            &owner,
            false,
        )
        .await
        .expect("`Server`");
        Channel::create_server_channel(
            db,
            &mut server,
            DataCreateServerChannel {
                channel_type: LegacyServerChannelType::Text,
                name: "general".to_string(),
                ..Default::default()
            },
            true,
        )
        .await
        .expect("`Channel`");
        db.fetch_server(&server.id).await.expect("re-fetch")
    }

    #[tokio::test]
    async fn set_fetch_overwrite_and_clear() {
        database_test!(|db| async move {
            const SERVER: &str = "01HELDSERVER0000000000000000";

            assert_eq!(db.fetch_server_legal_hold(SERVER).await.expect("fetch"), None);
            // Clearing a server that never had a hold succeeds
            db.clear_server_legal_hold(SERVER)
                .await
                .expect("clear with no row");

            let first = hold(SERVER, "01ADMINA", 1_790_812_800_000, Some("case 7"));
            let other = hold(OTHER_SERVER, "01ADMINA", 1_790_812_800_000, None);
            db.set_server_legal_hold(&first).await.expect("set");
            db.set_server_legal_hold(&other).await.expect("set other");
            assert_eq!(
                db.fetch_server_legal_hold(SERVER).await.expect("fetch"),
                Some(first.clone())
            );

            // Upsert: the second set replaces the row whole, the note included
            let second = hold(SERVER, "01ADMINB", 1_790_899_200_000, None);
            db.set_server_legal_hold(&second).await.expect("overwrite");
            assert_eq!(
                db.fetch_server_legal_hold(SERVER).await.expect("fetch"),
                Some(second)
            );

            db.clear_server_legal_hold(SERVER).await.expect("clear");
            assert_eq!(db.fetch_server_legal_hold(SERVER).await.expect("fetch"), None);
            db.clear_server_legal_hold(SERVER)
                .await
                .expect("clear twice");
            assert_eq!(db.fetch_server_legal_hold(SERVER).await.expect("fetch"), None);

            // The other server's hold is untouched throughout
            assert_eq!(
                db.fetch_server_legal_hold(OTHER_SERVER)
                    .await
                    .expect("fetch other"),
                Some(other)
            );
        });
    }

    /// Server deletion deletes the server's hold and no other server's.
    /// Control: the clear removed from `Server::delete`.
    #[tokio::test]
    async fn server_delete_removes_the_hold() {
        database_test!(|db| async move {
            let server = server_with_a_channel(&db).await;
            let server_id = server.id.clone();
            let other = hold(OTHER_SERVER, "01ADMINA", 1_790_812_800_000, None);
            db.set_server_legal_hold(&hold(&server_id, "01ADMINA", 1_790_812_800_000, None))
                .await
                .expect("set");
            db.set_server_legal_hold(&other).await.expect("set other");
            // The row is really there, so the assertion below is not vacuous
            assert!(db
                .fetch_server_legal_hold(&server_id)
                .await
                .expect("fetch")
                .is_some());

            server.delete(&db).await.expect("delete");

            assert_eq!(
                db.fetch_server_legal_hold(&server_id).await.expect("fetch"),
                None
            );
            assert_eq!(
                db.fetch_server_legal_hold(OTHER_SERVER)
                    .await
                    .expect("fetch other"),
                Some(other)
            );
        });
    }

    /// A server delete that fails keeps the hold: the clear runs only after
    /// the server row is gone, so no failure leaves a surviving server
    /// without its hold. Reference: the row delete fails (the row was
    /// removed underneath); MongoDb: the protected cascade fails on a Text
    /// group that cannot decode. Control: the clear moved above the row
    /// delete (Reference) or above the cascades (both).
    #[tokio::test]
    async fn a_failed_server_delete_keeps_the_hold() {
        database_test!(|db| async move {
            let server = server_with_a_channel(&db).await;
            let server_id = server.id.clone();
            let channel_id = server.channels[0].clone();
            let held = hold(&server_id, "01ADMINA", 1_790_812_800_000, Some("case 7"));
            db.set_server_legal_hold(&held).await.expect("set");

            match &db {
                Database::Reference(reference) => {
                    reference.servers.lock().await.remove(&server_id);
                }
                #[cfg(feature = "mongodb")]
                Database::MongoDb(mongo) => {
                    mongo
                        .col::<bson::Document>("mls_groups")
                        .insert_one(bson::doc! {
                            "_id": "ee".repeat(32),
                            "channel_id": &channel_id,
                            "kind": "Text",
                        })
                        .await
                        .expect("corrupt group");
                }
            }
            let _ = &channel_id;

            server
                .delete(&db)
                .await
                .expect_err("the delete must fail");
            assert_eq!(
                db.fetch_server_legal_hold(&server_id).await.expect("fetch"),
                Some(held)
            );
        });
    }
}
