use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Database, Message, MessageFilter, MessageQuery, MessageTimePeriod, User,
};
use revolt_models::v0::{self, MessageSort};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use validator::Validate;

/// # Fetch Messages
///
/// Fetch multiple messages.
#[openapi(tag = "Messaging")]
#[get("/<target>/messages?<options..>")]
pub async fn query(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    options: v0::OptionsQueryMessages,
) -> Result<Json<v0::BulkMessageResponse>> {
    options.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    if let Some(MessageSort::Relevance) = options.sort {
        return Err(create_error!(InvalidOperation));
    }

    let channel = target.as_channel(db).await?;

    // Threads inherit their parent channel's permission overrides.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    calculate_channel_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ReadMessageHistory)?;

    let v0::OptionsQueryMessages {
        limit,
        before,
        after,
        sort,
        nearby,
        include_users,
    } = options;

    // Stray plaintext rows are dropped in a protected channel (decision 9
    // (W2)); a thread is judged by its parent (W2 audit B1)
    let channel_protected = channel.is_protected() || permission_channel.is_protected();

    Message::fetch_with_users(
        db,
        MessageQuery {
            filter: MessageFilter {
                channel: Some(channel.id().to_string()),
                ..Default::default()
            },
            time_period: if let Some(nearby) = nearby {
                MessageTimePeriod::Relative { nearby }
            } else {
                MessageTimePeriod::Absolute {
                    before,
                    after,
                    sort,
                }
            },
            limit,
        },
        &user,
        include_users,
        channel.server(),
        channel_protected,
    )
    .await
    .map(Json)
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::{Channel, Database, Message};
    use rocket::http::{Header, Status};
    use serde_json::Value;
    use ulid::Ulid;

    /// Ids of `channel_id`'s history as `token` reads it
    async fn history(harness: &TestHarness, token: &str, channel_id: &str) -> Vec<String> {
        let response = harness
            .client
            .get(format!("/channels/{channel_id}/messages"))
            .header(Header::new("x-session-token", token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let messages: Value = response.into_json().await.expect("JSON");
        messages
            .as_array()
            .expect("a list of messages")
            .iter()
            .map(|message| message["_id"].as_str().expect("an id").to_string())
            .collect()
    }

    /// Mark `channel_id` protected under its stored rows, raw
    async fn protect_under_stored_rows(db: &Database, channel_id: &str) {
        match db {
            Database::Reference(reference) => {
                match reference.channels.lock().await.get_mut(channel_id) {
                    Some(Channel::TextChannel { protected, .. }) => *protected = true,
                    other => panic!("expected a text channel, got {:?}", other),
                }
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, Document};

                let result = mongo
                    .col::<Document>("channels")
                    .update_one(
                        doc! { "_id": channel_id },
                        doc! { "$set": { "protected": true } },
                    )
                    .await
                    .expect("raw protect");
                assert_eq!(result.matched_count, 1);
            }
        }

        assert!(db
            .fetch_channel(channel_id)
            .await
            .expect("channel")
            .is_protected());
    }

    /// W2 audit B1: a thread is judged by its parent. The history of a
    /// thread left under a protected parent (stored directly, its plaintext
    /// rows written before the flag) drops those rows; it served them while
    /// the parent was open.
    ///
    /// Control: the `2acdf5f0` route (the thread's own flag) → the rows are
    /// still served after the flag.
    #[test]
    fn history_of_a_thread_under_a_protected_parent_drops_strays() {
        crate::util::test::rt()
            .block_on(history_of_a_thread_under_a_protected_parent_drops_strays_case())
    }

    async fn history_of_a_thread_under_a_protected_parent_drops_strays_case() {
        let harness = TestHarness::new().await;
        let (_, session, author) = harness.new_user().await;
        let (server, parent) = harness.new_protectable_channel(&author).await;
        let thread = Channel::Thread {
            id: Ulid::new().to_string(),
            server: server.id.clone(),
            parent_channel: parent.id().to_string(),
            name: "Thread".to_string(),
            creator: author.id.clone(),
            origin_message_id: None,
            last_message_id: None,
            archived: false,
            archived_timestamp: None,
            auto_archive_minutes: 0,
            locked: false,
            applied_tags: vec![],
        };
        harness.db.insert_channel(&thread).await.expect("thread");

        let mut ids = Vec::new();
        for _ in 0..2 {
            let message = Message {
                id: Ulid::new().to_string(),
                channel: thread.id().to_string(),
                author: author.id.clone(),
                content: Some("Stray".to_string()),
                ..Default::default()
            };
            harness.db.insert_message(&message).await.expect("message");
            ids.push(message.id);
        }
        ids.sort();

        let mut before = history(&harness, &session.token, thread.id()).await;
        before.sort();
        assert_eq!(before, ids, "served while the parent is open");

        protect_under_stored_rows(&harness.db, parent.id()).await;
        let after = history(&harness, &session.token, thread.id()).await;
        assert!(after.is_empty(), "{after:?}");
    }
}
