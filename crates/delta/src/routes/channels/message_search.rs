use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Database, Message, MessageFilter, MessageQuery, MessageTimePeriod, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use validator::Validate;

/// # Search for Messages
///
/// This route searches for messages within the given parameters.
#[openapi(tag = "Messaging")]
#[post("/<target>/search", data = "<options>")]
pub async fn search(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    options: Json<v0::DataMessageSearch>,
) -> Result<Json<v0::BulkMessageResponse>> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let options = options.into_inner();
    options.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    if options.query.is_some() && options.pinned.is_some() {
        return Err(create_error!(InvalidOperation));
    }

    let channel = target.as_channel(db).await?;

    // Threads inherit their parent channel's permission overrides.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    calculate_channel_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ReadMessageHistory)?;

    let v0::DataMessageSearch {
        query,
        pinned,
        limit,
        before,
        after,
        sort,
        include_users,
    } = options;

    // Decision 9 (W2): a protected channel holds no text the server can
    // search, so a content search there finds nothing, and answers so
    // without reading a message. The pinned listing below still runs; it
    // drops any stray plaintext row in `fetch_with_users`. A thread is
    // judged by its parent (W2 audit B1).
    let channel_protected = channel.is_protected() || permission_channel.is_protected();
    if query.is_some() && channel_protected {
        return Ok(Json(no_matches(include_users, channel.server())));
    }

    Message::fetch_with_users(
        db,
        MessageQuery {
            filter: MessageFilter {
                channel: Some(channel.id().to_string()),
                query,
                pinned,
                ..Default::default()
            },
            time_period: MessageTimePeriod::Absolute {
                before,
                after,
                sort: Some(sort),
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

/// What `Message::fetch_with_users` answers when no message matched
fn no_matches(include_users: Option<bool>, server_id: Option<&str>) -> v0::BulkMessageResponse {
    if let Some(true) = include_users {
        v0::BulkMessageResponse::MessagesAndUsers {
            messages: vec![],
            users: vec![],
            members: server_id.map(|_| vec![]),
        }
    } else {
        v0::BulkMessageResponse::JustMessages(vec![])
    }
}

#[cfg(test)]
mod tests {
    use revolt_database::{
        Channel, Database, Message, MessageFilter, MessageQuery, MessageTimePeriod, PartialChannel,
        PartialMessage, Session, User,
    };
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::{json, Value};
    use ulid::Ulid;

    use crate::util::test::{ProtectedChannel, TestHarness};

    /// What every searched row in these tests holds; lowercase, as the
    /// Reference driver matches `query` against the lowercased content
    const NEEDLE: &str = "needle";

    /// The route's full answer: status and body
    async fn search(
        harness: &TestHarness,
        session: &Session,
        channel_id: &str,
        options: Value,
    ) -> (Status, String) {
        let response = harness
            .client
            .post(format!("/channels/{channel_id}/search"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session.token.clone()))
            .body(options.to_string())
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    #[track_caller]
    fn body(answer: &(Status, String)) -> Value {
        serde_json::from_str(&answer.1).unwrap_or_else(|_| panic!("not JSON: {:?}", answer))
    }

    /// The `_id`s of a JSON array
    #[track_caller]
    fn ids(list: &Value) -> Vec<String> {
        list.as_array()
            .unwrap_or_else(|| panic!("not an array: {}", list))
            .iter()
            .map(|item| item["_id"].as_str().expect("an _id").to_string())
            .collect()
    }

    fn is_mongo(db: &Database) -> bool {
        !matches!(db, Database::Reference(_))
    }

    /// The `$text` index `init.rs` builds on `messages`; the test database
    /// is un-migrated, and a Mongo `$text` query without it is an error
    async fn ensure_text_index(db: &Database) {
        match db {
            Database::Reference(_) => {}
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::doc;

                mongo
                    .db()
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
                    .expect("the messages text index");
            }
        }
    }

    /// Store `message` raw, past `insert_message`'s protected-shape check,
    /// as the R15 compensation window can leave a stray behind
    async fn insert_raw(db: &Database, message: &Message) {
        match db {
            Database::Reference(reference) => {
                reference
                    .messages
                    .lock()
                    .await
                    .insert(message.id.clone(), message.clone());
            }
            Database::MongoDb(mongo) => {
                mongo
                    .col::<Message>("messages")
                    .insert_one(message)
                    .await
                    .expect("raw message row");
            }
        }
    }

    /// The rows of `channel_id` whose content the driver matches with
    /// `NEEDLE`: what a search that reads messages would start from
    async fn driver_matches(db: &Database, channel_id: &str) -> Vec<String> {
        db.fetch_messages(MessageQuery {
            filter: MessageFilter {
                channel: Some(channel_id.to_string()),
                query: Some(NEEDLE.to_string()),
                ..Default::default()
            },
            time_period: MessageTimePeriod::Absolute {
                before: None,
                after: None,
                sort: None,
            },
            limit: None,
        })
        .await
        .expect("the driver search")
        .into_iter()
        .map(|message| message.id)
        .collect()
    }

    /// A protected channel holding one ciphertext row (pinned) and one
    /// stray plaintext row (pinned, matching `NEEDLE`, by a member who
    /// wrote nothing else there); beside it, in the same server, an
    /// unprotected channel holding one plaintext row matching `NEEDLE`.
    /// The owner searches.
    struct Fixture {
        harness: TestHarness,
        owner: User,
        owner_session: Session,
        protected: ProtectedChannel,
        ciphertext: Message,
        stray: Message,
        open: Channel,
        plaintext: Message,
    }

    async fn fixture() -> Fixture {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        ensure_text_index(db).await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, _, writer) = harness.new_user().await;

        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[])
            .await;
        harness.join_server(&protected.server, &writer).await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let ciphertext = harness
            .new_encrypted_message(&protected.channel, &protected.owner_device, &group)
            .await;
        db.update_message(
            &ciphertext.id,
            &PartialMessage {
                pinned: Some(true),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("pin the ciphertext");

        let stray = Message {
            id: Ulid::new().to_string(),
            channel: protected.channel.id().to_string(),
            author: writer.id.clone(),
            content: Some(format!("a stray {NEEDLE}")),
            pinned: Some(true),
            ..Default::default()
        };
        insert_raw(db, &stray).await;

        let open = harness.new_channel(&protected.server).await;
        assert!(!open.is_protected());
        let plaintext = Message {
            id: Ulid::new().to_string(),
            channel: open.id().to_string(),
            author: writer.id.clone(),
            content: Some(format!("an open {NEEDLE}")),
            ..Default::default()
        };
        db.insert_message(&plaintext)
            .await
            .expect("the plaintext row");

        Fixture {
            harness,
            owner,
            owner_session,
            protected,
            ciphertext,
            stray,
            open,
            plaintext,
        }
    }

    /// Decision 9 (W2): a content search on a protected channel answers
    /// exactly what a search matching nothing answers, for every
    /// `include_users`, even when a stray plaintext row matches the query
    async fn a_protected_search_never_serves_a_stray_case() {
        let fixture = Box::pin(fixture()).await;
        let harness = &fixture.harness;
        let protected_id = fixture.protected.channel.id();
        assert!(fixture.protected.channel.is_protected());
        assert_eq!(
            driver_matches(&harness.db, protected_id).await,
            vec![fixture.stray.id.clone()],
            "the driver itself matches the stray"
        );

        for include_users in [json!(null), json!(false), json!(true)] {
            let answer = search(
                harness,
                &fixture.owner_session,
                protected_id,
                json!({ "query": NEEDLE, "include_users": include_users }),
            )
            .await;
            assert_eq!(answer.0, Status::Ok, "{}: {:?}", include_users, answer);
            assert!(
                !answer.1.contains(NEEDLE),
                "{}: {}",
                include_users,
                answer.1
            );

            let expected = if include_users == json!(true) {
                json!({ "messages": [], "users": [], "members": [] })
            } else {
                json!([])
            };
            assert_eq!(body(&answer), expected, "{}", include_users);

            // The same answer as a real search that matched nothing
            let nothing = search(
                harness,
                &fixture.owner_session,
                fixture.open.id(),
                json!({ "query": "zzqx", "include_users": include_users }),
            )
            .await;
            assert_eq!(nothing.0, Status::Ok, "{}: {:?}", include_users, nothing);
            assert_eq!(body(&answer), body(&nothing), "{}", include_users);
        }
    }

    #[test]
    fn a_protected_search_never_serves_a_stray() {
        crate::util::test::rt().block_on(Box::pin(a_protected_search_never_serves_a_stray_case()))
    }

    /// Decision 9 (W2): the empty answer comes BEFORE any message read. A
    /// probe row that carries `encrypted` (so `fetch_with_users` keeps it)
    /// and stored text matching the query, which no route can write, is
    /// what a search that read messages would serve.
    async fn a_protected_search_reads_no_message_case() {
        let fixture = Box::pin(fixture()).await;
        let harness = &fixture.harness;
        let protected_id = fixture.protected.channel.id();

        let probe = Message {
            id: Ulid::new().to_string(),
            channel: protected_id.to_string(),
            author: fixture.owner.id.clone(),
            nonce: Some(Ulid::new().to_string()),
            content: Some(format!("a probe {NEEDLE}")),
            encrypted: fixture.ciphertext.encrypted.clone(),
            ..Default::default()
        };
        assert!(probe.is_servable(true));
        insert_raw(&harness.db, &probe).await;
        let mut matched = driver_matches(&harness.db, protected_id).await;
        matched.sort();
        let mut expected = vec![fixture.stray.id.clone(), probe.id.clone()];
        expected.sort();
        assert_eq!(matched, expected, "the driver itself matches the probe");

        for include_users in [false, true] {
            let answer = search(
                harness,
                &fixture.owner_session,
                protected_id,
                json!({ "query": NEEDLE, "include_users": include_users }),
            )
            .await;
            assert_eq!(answer.0, Status::Ok, "{}: {:?}", include_users, answer);
            assert!(
                !answer.1.contains(&probe.id),
                "{}: a message was read: {}",
                include_users,
                answer.1
            );
            let messages = if include_users {
                body(&answer)["messages"].clone()
            } else {
                body(&answer)
            };
            assert_eq!(messages, json!([]), "{}", include_users);
        }
    }

    #[test]
    fn a_protected_search_reads_no_message() {
        crate::util::test::rt().block_on(Box::pin(a_protected_search_reads_no_message_case()))
    }

    /// A content search on an unprotected channel is unchanged: it serves
    /// the matching row, its author and the author's membership
    async fn an_unprotected_search_is_unchanged_case() {
        let fixture = Box::pin(fixture()).await;
        let harness = &fixture.harness;

        let answer = search(
            harness,
            &fixture.owner_session,
            fixture.open.id(),
            json!({ "query": NEEDLE }),
        )
        .await;
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        assert_eq!(ids(&body(&answer)), vec![fixture.plaintext.id.clone()]);

        let answer = search(
            harness,
            &fixture.owner_session,
            fixture.open.id(),
            json!({ "query": NEEDLE, "include_users": true }),
        )
        .await;
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        let value = body(&answer);
        assert_eq!(ids(&value["messages"]), vec![fixture.plaintext.id.clone()]);
        assert_eq!(ids(&value["users"]), vec![fixture.plaintext.author.clone()]);
        let members = value["members"].as_array().expect("members");
        assert_eq!(members.len(), 1, "{}", answer.1);
        assert_eq!(members[0]["_id"]["user"], fixture.plaintext.author.as_str());
    }

    #[test]
    fn an_unprotected_search_is_unchanged() {
        crate::util::test::rt().block_on(Box::pin(an_unprotected_search_is_unchanged_case()))
    }

    /// Decision 9 (W2): the pinned listing of a protected channel still
    /// serves its pinned ciphertext, and still drops the pinned stray and
    /// its author. MONGODB only: the Reference driver's `pinned` filter is
    /// inverted (`messages/ops/reference.rs`).
    async fn a_protected_pinned_listing_still_serves_ciphertext_case() {
        let fixture = Box::pin(fixture()).await;
        let harness = &fixture.harness;
        if !is_mongo(&harness.db) {
            eprintln!("skipped: the Reference driver's pinned filter is inverted");
            return;
        }

        let answer = search(
            harness,
            &fixture.owner_session,
            fixture.protected.channel.id(),
            json!({ "pinned": true, "include_users": true }),
        )
        .await;
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        let value = body(&answer);
        assert_eq!(ids(&value["messages"]), vec![fixture.ciphertext.id.clone()]);
        assert_eq!(ids(&value["users"]), vec![fixture.owner.id.clone()]);
        assert!(!answer.1.contains(&fixture.stray.id), "{}", answer.1);
        assert!(!answer.1.contains(&fixture.stray.author), "{}", answer.1);
    }

    #[test]
    fn a_protected_pinned_listing_still_serves_ciphertext() {
        crate::util::test::rt().block_on(Box::pin(
            a_protected_pinned_listing_still_serves_ciphertext_case(),
        ))
    }

    async fn deny_view(harness: &TestHarness, channel: &Channel) {
        let mut channel = channel.clone();
        channel
            .update(
                &harness.db,
                PartialChannel {
                    default_permissions: Some(OverrideField {
                        a: 0,
                        d: ChannelPermission::ViewChannel as i64,
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("deny view");
    }

    /// Decision 18 (W2): a member who cannot view the channel gets the
    /// pre-W2 refusal, the full body included, identical for a protected
    /// and an unprotected channel, for every kind of search
    async fn non_viewers_get_the_same_answer_protected_or_not_case() {
        let fixture = Box::pin(fixture()).await;
        let harness = &fixture.harness;
        let (_, member_session, member) = harness.new_user().await;
        harness
            .join_server(&fixture.protected.server, &member)
            .await;
        deny_view(harness, &fixture.protected.channel).await;
        deny_view(harness, &fixture.open).await;
        assert!(harness
            .db
            .fetch_channel(fixture.protected.channel.id())
            .await
            .expect("the protected channel")
            .is_protected());

        for options in [
            json!({ "query": NEEDLE }),
            json!({ "query": NEEDLE, "include_users": true }),
            json!({ "pinned": true }),
        ] {
            let protected = search(
                harness,
                &member_session,
                fixture.protected.channel.id(),
                options.clone(),
            )
            .await;
            let open = search(harness, &member_session, fixture.open.id(), options.clone()).await;
            assert_eq!(
                protected.0,
                Status::Forbidden,
                "{}: {:?}",
                options,
                protected
            );
            assert_eq!(body(&protected)["type"], "MissingPermission", "{}", options);
            assert_eq!(protected, open, "{}", options);
        }
    }

    #[test]
    fn non_viewers_get_the_same_answer_protected_or_not() {
        crate::util::test::rt().block_on(Box::pin(
            non_viewers_get_the_same_answer_protected_or_not_case(),
        ))
    }

    /// W2 audit B1: a thread is judged by its parent. In a thread left
    /// under a protected parent (stored directly) holding a pinned stray
    /// that matches the query, a content search answers nothing and the
    /// pinned listing drops the stray.
    ///
    /// Control: the `2acdf5f0` route (the thread's own flag) → the content
    /// search serves the stray.
    async fn a_search_in_a_thread_under_a_protected_parent_serves_no_stray_case() {
        let fixture = Box::pin(fixture()).await;
        let harness = &fixture.harness;
        let orphan = Channel::Thread {
            id: Ulid::new().to_string(),
            server: fixture.protected.server.id.clone(),
            parent_channel: fixture.protected.channel.id().to_string(),
            name: "Thread".to_string(),
            creator: fixture.owner.id.clone(),
            origin_message_id: None,
            last_message_id: None,
            archived: false,
            archived_timestamp: None,
            auto_archive_minutes: 0,
            locked: false,
            applied_tags: vec![],
        };
        harness.db.insert_channel(&orphan).await.expect("thread");
        let stray = Message {
            id: Ulid::new().to_string(),
            channel: orphan.id().to_string(),
            author: fixture.owner.id.clone(),
            content: Some(format!("a thread stray {NEEDLE}")),
            pinned: Some(true),
            ..Default::default()
        };
        insert_raw(&harness.db, &stray).await;
        assert_eq!(
            driver_matches(&harness.db, orphan.id()).await,
            vec![stray.id.clone()],
            "the driver itself matches the stray"
        );

        for options in [json!({ "query": NEEDLE }), json!({ "pinned": true })] {
            let answer = search(
                harness,
                &fixture.owner_session,
                orphan.id(),
                options.clone(),
            )
            .await;
            assert_eq!(answer.0, Status::Ok, "{}: {:?}", options, answer);
            assert_eq!(body(&answer), json!([]), "{}", options);
        }
    }

    #[test]
    fn a_search_in_a_thread_under_a_protected_parent_serves_no_stray() {
        crate::util::test::rt().block_on(Box::pin(
            a_search_in_a_thread_under_a_protected_parent_serves_no_stray_case(),
        ))
    }
}
