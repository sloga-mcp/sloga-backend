//! Prot route gates (S5b contracts 6.2 and 6.9), one call each from the S1
//! routes they guard. Kept out of the route files so S1's diffs stay one line
//! per route.
//!
//! The Frozen refusal (carry-forward 8) covers the routes that add to a
//! channel: send, react and pin. Unpins, deletes, bulk deletes, reaction
//! removal, acks and typing never call it (BR6, owner answer 6): removal
//! must always be possible, and typing writes nothing.

use revolt_database::{Channel, Database};
use revolt_result::{create_error, Result};

/// ProtTankFrozen when `channel` (or a thread's parent) is protected and its entitlement no longer allows text
/// traffic (Frozen or Deleted). No entitlement: Ok (S1 behaviour unchanged).
///
/// `permission_channel` is the route's permission target (a thread's parent,
/// otherwise `channel` itself). An unprotected channel is answered without a
/// read, and a failed read is returned, so an unreadable entitlement never
/// counts as one that allows traffic.
pub async fn refuse_if_tank_frozen(
    db: &Database,
    channel: &Channel,
    permission_channel: &Channel,
) -> Result<()> {
    let protected = if channel.is_protected() {
        channel
    } else if permission_channel.is_protected() {
        permission_channel
    } else {
        return Ok(());
    };

    match db.fetch_channel_entitlement(protected.id()).await? {
        Some(entitlement) if !entitlement.allows_text_traffic() => {
            Err(create_error!(ProtTankFrozen))
        }
        _ => Ok(()),
    }
}

/// ChannelProtected while the server has an open goal (6.9)
///
/// Reads only the open goals (Funding, Funded, Launching), not the tanks: a
/// launched tank implies a protected channel, which the caller's S1 refusal
/// already answers. Any owner-initiated transfer calls this after its owner check;
/// S2's succession transfer is exempt by S2's rule (O-19).
pub async fn refuse_owner_change_with_prot(db: &Database, server_id: &str) -> Result<()> {
    if db
        .fetch_open_prot_goals_by_server(server_id)
        .await?
        .is_empty()
    {
        Ok(())
    } else {
        Err(create_error!(ChannelProtected))
    }
}

#[cfg(test)]
mod tests {
    use revolt_database::{
        Channel, ChannelEntitlementState, Database, MessageFilter, MessageQuery, MessageTimePeriod,
        MlsGroup, Session,
    };
    use revolt_result::ErrorType;
    use rocket::http::{ContentType, Header, Method, Status};
    use serde_json::{json, Value};
    use ulid::Ulid;

    use super::refuse_if_tank_frozen;
    use crate::util::test::{ProtectedChannel, TestHarness};

    /// U+1F44D, as stored, and percent-encoded for the path
    const THUMBS_UP: &str = "\u{1F44D}";
    const THUMBS_UP_PATH: &str = "%F0%9F%91%8D";

    /// The two states that stop text traffic
    const STOPPED: [ChannelEntitlementState; 2] = [
        ChannelEntitlementState::Frozen,
        ChannelEntitlementState::Deleted,
    ];

    /// Set the state of `channel_id`'s entitlement, or delete it (`None`),
    /// raw: only the S5 tank transactions change it
    async fn set_entitlement(
        db: &Database,
        channel_id: &str,
        state: Option<ChannelEntitlementState>,
    ) {
        let expected = state.clone();
        match db {
            Database::Reference(reference) => {
                let mut entitlements = reference.channel_entitlements.lock().await;
                let id = entitlements
                    .values()
                    .find(|entitlement| entitlement.channel_id == channel_id)
                    .map(|entitlement| entitlement.id.clone())
                    .expect("an entitlement");
                match state {
                    Some(state) => {
                        entitlements.get_mut(&id).expect("an entitlement").state = state;
                    }
                    None => {
                        entitlements.remove(&id);
                    }
                }
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, to_bson, Document};

                let collection = mongo.col::<Document>("channel_entitlements");
                let matched = match state {
                    Some(state) => {
                        collection
                            .update_one(
                                doc! { "channel_id": channel_id },
                                doc! { "$set": { "state": to_bson(&state).expect("a state") } },
                            )
                            .await
                            .expect("raw state write")
                            .matched_count
                    }
                    None => {
                        collection
                            .delete_one(doc! { "channel_id": channel_id })
                            .await
                            .expect("raw delete")
                            .deleted_count
                    }
                };
                assert_eq!(matched, 1);
            }
        }

        let stored = db
            .fetch_channel_entitlement(channel_id)
            .await
            .expect("entitlement read");
        assert_eq!(stored.map(|entitlement| entitlement.state), expected);
    }

    struct Fixture {
        harness: TestHarness,
        protected: ProtectedChannel,
        /// Epoch 0, the owner's device its only member
        group: MlsGroup,
        owner_session: Session,
    }

    /// A protected channel (Active entitlement) whose owner is seated and
    /// sends from the device that created its Text group
    async fn fixture() -> Fixture {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[])
            .await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;

        Fixture {
            harness,
            protected,
            group,
            owner_session,
        }
    }

    impl Fixture {
        fn channel_id(&self) -> &str {
            self.protected.channel.id()
        }

        async fn set_state(&self, state: ChannelEntitlementState) {
            set_entitlement(&self.harness.db, self.channel_id(), Some(state)).await;
        }

        /// `method` `path` as the owner. Returns the status and the JSON body
        /// (`Null` when there is none).
        async fn call(&self, method: Method, path: &str, body: Option<&Value>) -> (Status, Value) {
            let mut request =
                self.harness
                    .client
                    .req(method, path.to_string())
                    .header(Header::new(
                        "x-session-token",
                        self.owner_session.token.to_string(),
                    ));
            if let Some(body) = body {
                request = request.header(ContentType::JSON).body(body.to_string());
            }
            let response = request.dispatch().await;
            let status = response.status();
            let body = response
                .into_string()
                .await
                .and_then(|body| serde_json::from_str(&body).ok())
                .unwrap_or(Value::Null);
            (status, body)
        }

        /// A valid encrypted send from the owner's device (a fresh nonce)
        async fn send(&self) -> (Status, Value) {
            let body = json!({
                "nonce": Ulid::new().to_string(),
                "encrypted": self.protected.owner_device.encrypted_payload(&self.group),
            });
            let path = format!("/channels/{}/messages", self.channel_id());
            self.call(Method::Post, &path, Some(&body)).await
        }

        async fn stored_messages(&self) -> usize {
            self.harness
                .db
                .fetch_messages(MessageQuery {
                    limit: Some(50),
                    filter: MessageFilter {
                        channel: Some(self.channel_id().to_string()),
                        ..Default::default()
                    },
                    time_period: MessageTimePeriod::Absolute {
                        before: None,
                        after: None,
                        sort: None,
                    },
                })
                .await
                .expect("the channel's messages")
                .len()
        }

        fn react_path(&self, message_id: &str) -> String {
            format!(
                "/channels/{}/messages/{}/reactions/{}",
                self.channel_id(),
                message_id,
                THUMBS_UP_PATH
            )
        }

        fn pin_path(&self, message_id: &str) -> String {
            format!(
                "/channels/{}/messages/{}/pin",
                self.channel_id(),
                message_id
            )
        }
    }

    fn assert_frozen(answer: &(Status, Value), case: &str) {
        assert_eq!(answer.0, Status::Forbidden, "{case}: {}", answer.1);
        assert_eq!(answer.1["type"], "ProtTankFrozen", "{case}: {}", answer.1);
    }

    fn assert_status(answer: &(Status, Value), status: Status, case: &str) {
        assert_eq!(answer.0, status, "{case}: {}", answer.1);
    }

    /// Carry-forward 8: a Frozen or Deleted entitlement refuses a protected
    /// send with 403 `ProtTankFrozen` and stores nothing; Active and Grace
    /// (D14) send, and the same send lands again once the state is Active.
    /// Control: delete step 0b in `check_protected_send` (both stopped sends
    /// land).
    #[test]
    fn frozen_send_is_refused() {
        crate::util::test::rt().block_on(Box::pin(frozen_send_is_refused_case()))
    }

    async fn frozen_send_is_refused_case() {
        let f = fixture().await;

        assert_status(&f.send().await, Status::Ok, "Active");
        f.set_state(ChannelEntitlementState::Grace).await;
        assert_status(&f.send().await, Status::Ok, "Grace");
        assert_eq!(f.stored_messages().await, 2);

        for state in STOPPED {
            f.set_state(state.clone()).await;
            assert_frozen(&f.send().await, &format!("{state:?}"));
            assert_eq!(f.stored_messages().await, 2, "{state:?} stored a message");
        }

        f.set_state(ChannelEntitlementState::Active).await;
        assert_status(&f.send().await, Status::Ok, "Active again");
        assert_eq!(f.stored_messages().await, 3);
    }

    /// 6.2: react and pin refuse a Frozen or Deleted entitlement and change
    /// nothing; Grace reacts and pins. An unpin is a removal (owner answer
    /// 6), so it lands in Frozen and Deleted as it does in Active. Control:
    /// put the `refuse_if_tank_frozen` call back into `message_unpin.rs` (the
    /// Frozen unpin answers 403)
    #[test]
    fn frozen_react_and_pin_are_refused() {
        crate::util::test::rt().block_on(Box::pin(frozen_react_and_pin_are_refused_case()))
    }

    async fn frozen_react_and_pin_are_refused_case() {
        let f = fixture().await;
        let db = &f.harness.db;
        let message = f
            .harness
            .new_encrypted_message(&f.protected.channel, &f.protected.owner_device, &f.group)
            .await;
        let react = f.react_path(&message.id);
        let pin = f.pin_path(&message.id);

        for state in STOPPED {
            f.set_state(state.clone()).await;
            assert_frozen(
                &f.call(Method::Put, &react, None).await,
                &format!("react, {state:?}"),
            );
            assert_frozen(
                &f.call(Method::Post, &pin, None).await,
                &format!("pin, {state:?}"),
            );
        }
        let stored = db.fetch_message(&message.id).await.expect("the message");
        assert!(stored.reactions.is_empty(), "{:?}", stored.reactions);
        assert!(!stored.pinned.unwrap_or_default());

        f.set_state(ChannelEntitlementState::Grace).await;
        assert_status(
            &f.call(Method::Put, &react, None).await,
            Status::NoContent,
            "react, Grace",
        );
        assert_status(
            &f.call(Method::Post, &pin, None).await,
            Status::NoContent,
            "pin, Grace",
        );
        let stored = db.fetch_message(&message.id).await.expect("the message");
        assert!(
            stored.reactions.contains_key(THUMBS_UP),
            "{:?}",
            stored.reactions
        );
        assert!(stored.pinned.unwrap_or_default());

        for state in STOPPED {
            f.set_state(state.clone()).await;
            assert_status(
                &f.call(Method::Delete, &pin, None).await,
                Status::NoContent,
                &format!("unpin, {state:?}"),
            );
            let stored = db.fetch_message(&message.id).await.expect("the message");
            assert!(
                !stored.pinned.unwrap_or_default(),
                "{:?}: the unpin did not land",
                state
            );

            // Pinning it again stays refused until the state allows traffic
            assert_frozen(
                &f.call(Method::Post, &pin, None).await,
                &format!("pin again, {state:?}"),
            );
            f.set_state(ChannelEntitlementState::Grace).await;
            assert_status(
                &f.call(Method::Post, &pin, None).await,
                Status::NoContent,
                &format!("pin again after {state:?}, Grace"),
            );
        }
        let stored = db.fetch_message(&message.id).await.expect("the message");
        assert!(stored.pinned.unwrap_or_default());

        f.set_state(ChannelEntitlementState::Active).await;
        assert_status(
            &f.call(Method::Delete, &pin, None).await,
            Status::NoContent,
            "unpin, Active",
        );
        let stored = db.fetch_message(&message.id).await.expect("the message");
        assert!(!stored.pinned.unwrap_or_default());
    }

    /// BR6 (owner answer 6): removal always works. With the entitlement
    /// Frozen the owner removes its own reaction and deletes a message, and
    /// with it Deleted deletes another, while a react is still refused
    #[test]
    fn frozen_delete_still_works() {
        crate::util::test::rt().block_on(Box::pin(frozen_delete_still_works_case()))
    }

    async fn frozen_delete_still_works_case() {
        let f = fixture().await;
        let db = &f.harness.db;
        let first = f
            .harness
            .new_encrypted_message(&f.protected.channel, &f.protected.owner_device, &f.group)
            .await;
        let second = f
            .harness
            .new_encrypted_message(&f.protected.channel, &f.protected.owner_device, &f.group)
            .await;
        assert_status(
            &f.call(Method::Put, &f.react_path(&first.id), None).await,
            Status::NoContent,
            "react, Active",
        );

        f.set_state(ChannelEntitlementState::Frozen).await;
        assert_frozen(
            &f.call(Method::Put, &f.react_path(&second.id), None).await,
            "react, Frozen",
        );
        assert_status(
            &f.call(Method::Delete, &f.react_path(&first.id), None).await,
            Status::NoContent,
            "un-react, Frozen",
        );
        let stored = db.fetch_message(&first.id).await.expect("the message");
        assert!(stored.reactions.is_empty(), "{:?}", stored.reactions);

        let delete = format!("/channels/{}/messages/{}", f.channel_id(), first.id);
        assert_status(
            &f.call(Method::Delete, &delete, None).await,
            Status::NoContent,
            "delete, Frozen",
        );
        assert!(db.fetch_message(&first.id).await.is_err());

        f.set_state(ChannelEntitlementState::Deleted).await;
        let delete = format!("/channels/{}/messages/{}", f.channel_id(), second.id);
        assert_status(
            &f.call(Method::Delete, &delete, None).await,
            Status::NoContent,
            "delete, Deleted",
        );
        assert!(db.fetch_message(&second.id).await.is_err());
        assert_eq!(f.stored_messages().await, 0);
    }

    /// The helper's own cases: a thread is judged by its protected parent;
    /// an unprotected channel is never refused, even with a stopped
    /// entitlement; a protected channel with no entitlement is S1's Ok
    #[test]
    fn only_a_protected_channel_or_its_thread_is_gated() {
        crate::util::test::rt().block_on(Box::pin(
            only_a_protected_channel_or_its_thread_is_gated_case(),
        ))
    }

    async fn only_a_protected_channel_or_its_thread_is_gated_case() {
        let f = fixture().await;
        let db = &f.harness.db;
        let parent = &f.protected.channel;
        let thread = Channel::Thread {
            id: Ulid::new().to_string(),
            server: f.protected.server.id.clone(),
            parent_channel: parent.id().to_string(),
            name: "Thread".to_string(),
            creator: f.owner_session.user_id.clone(),
            origin_message_id: None,
            last_message_id: None,
            archived: false,
            archived_timestamp: None,
            auto_archive_minutes: 0,
            locked: false,
            applied_tags: vec![],
        };
        assert!(!thread.is_protected());

        refuse_if_tank_frozen(db, &thread, parent)
            .await
            .expect("an Active parent");
        f.set_state(ChannelEntitlementState::Frozen).await;
        let error = refuse_if_tank_frozen(db, &thread, parent)
            .await
            .expect_err("a Frozen parent");
        assert!(
            matches!(error.error_type, ErrorType::ProtTankFrozen),
            "{:?}",
            error
        );

        let ordinary = f.harness.new_channel(&f.protected.server).await;
        assert!(!ordinary.is_protected());
        f.harness.grant_entitlement(&ordinary, 10, None).await;
        set_entitlement(db, ordinary.id(), Some(ChannelEntitlementState::Frozen)).await;
        refuse_if_tank_frozen(db, &ordinary, &ordinary)
            .await
            .expect("an unprotected channel");

        set_entitlement(db, parent.id(), None).await;
        refuse_if_tank_frozen(db, parent, parent)
            .await
            .expect("no entitlement");
    }
}
