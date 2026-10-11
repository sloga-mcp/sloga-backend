use revolt_config::config;
use revolt_database::{
    util::{antispam, permissions::DatabasePermissionQuery, reference::Reference},
    Channel, Database, RelationshipStatus, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_user_permissions, UserPermission};
use revolt_result::{create_error, ErrorType, Result};
use rocket::{serde::json::Json, State};

/// # Open Direct Message
///
/// Open a DM with another user.
///
/// If the target is oneself, a saved messages channel is returned.
#[openapi(tag = "Direct Messaging")]
#[get("/<target>/dm")]
pub async fn open_dm(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<v0::Channel>> {
    let target = target.as_user(db).await?;

    let mut query = DatabasePermissionQuery::new(db, &user).user(&target);
    calculate_user_permissions(&mut query)
        .await
        .throw_if_lacking_user_permission(UserPermission::SendMessage)?;

    // An account paused by the anti-spam detector keeps its existing DMs and
    // its friends, but cannot open a NEW DM with anyone else. Saved Messages
    // (target == self) is never gated. The client may reuse a cached DM
    // without calling this route, so the send routes enforce the pause too.
    if target.id != user.id
        && antispam::dm_pause_enforced(&config().await.features.antispam, &user)
        && !matches!(
            user.relationship_with(&target.id),
            RelationshipStatus::Friend
        )
    {
        return match db.find_direct_message_channel(&user.id, &target.id).await {
            Ok(channel) => Ok(Json(channel.into())),
            Err(error) if matches!(error.error_type, ErrorType::NotFound) => {
                Err(create_error!(DirectMessagesPaused))
            }
            Err(error) => Err(error),
        };
    }

    Channel::create_dm(db, &user, &target)
        .await
        .map(Into::into)
        .map(Json)
}

#[cfg(test)]
mod tests {
    use revolt_config::config;
    use revolt_database::{
        iso8601_timestamp::Timestamp, Channel, Database, DmGuard, Member, RelationshipStatus,
        Session, User,
    };
    use rocket::http::Status;

    use crate::util::test::TestHarness;

    /// Pause `user` the way the detector would, without running it.
    async fn pause(harness: &TestHarness, user: &User) {
        let guard = DmGuard {
            report_id: ulid::Ulid::new().to_string(),
            flagged_at: Timestamp::now_utc(),
            paused: true,
            cleared_at: None,
            recipients: 3,
            fingerprint: "test".into(),
        };
        let claimed = harness
            .db
            .claim_dm_guard(&user.id, &guard, Timestamp::now_utc())
            .await
            .expect("claim_dm_guard");
        assert!(claimed, "the fresh user must take the guard");

        // The route loads the caller from the session, so the stored copy is
        // what it sees.
        let stored = harness.db.fetch_user(&user.id).await.expect("user");
        assert!(stored.is_dm_paused());
    }

    /// Put both users in one server: a mutual server grants SendMessage, so
    /// only the pause can refuse the DM.
    async fn share_server(harness: &TestHarness, a: &User, b: &User) {
        let (server, _) = harness.new_server(a).await;
        Member::create(&harness.db, &server, a, None)
            .await
            .expect("member a");
        Member::create(&harness.db, &server, b, None)
            .await
            .expect("member b");
    }

    async fn befriend(harness: &TestHarness, a: &User, b: &User) {
        harness
            .db
            .set_relationship(&a.id, &b.id, &RelationshipStatus::Friend, None)
            .await
            .expect("relationship");
        harness
            .db
            .set_relationship(&b.id, &a.id, &RelationshipStatus::Friend, None)
            .await
            .expect("relationship");
    }

    async fn open(
        harness: &TestHarness,
        session: &Session,
        target: &str,
    ) -> (Status, serde_json::Value) {
        let response = TestHarness::with_session(
            session.clone(),
            harness.client.get(format!("/users/{target}/dm")),
        )
        .await;
        let status = response.status();
        let body = response
            .into_json::<serde_json::Value>()
            .await
            .expect("json body");
        (status, body)
    }

    async fn assert_detector_on() {
        assert!(
            config().await.features.antispam.dm_dupe_enabled,
            "run with REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"
        );
    }

    #[test]
    #[ignore = "needs REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"]
    fn antispam_route_open_dm_paused_new_stranger_refused() {
        crate::util::test::rt().block_on(antispam_route_open_dm_paused_new_stranger_refused_case())
    }

    async fn antispam_route_open_dm_paused_new_stranger_refused_case() {
        assert_detector_on().await;

        let harness = TestHarness::new().await;
        let (_, session, spammer) = harness.new_user().await;
        let (_, other_session, other) = harness.new_user().await;
        let (_, _, stranger) = harness.new_user().await;
        share_server(&harness, &spammer, &stranger).await;
        share_server(&harness, &other, &stranger).await;
        pause(&harness, &spammer).await;

        let (status, body) = open(&harness, &session, &stranger.id).await;
        assert_eq!(status, Status::Forbidden, "{body}");
        assert_eq!(body["type"], "DirectMessagesPaused", "{body}");
        assert!(
            harness
                .db
                .find_direct_message_channel(&spammer.id, &stranger.id)
                .await
                .is_err(),
            "a refused open must not create the DM"
        );

        // Control: an unpaused user in the same position gets the DM, so the
        // refusal above is the pause and not the permission check.
        let (status, body) = open(&harness, &other_session, &stranger.id).await;
        assert_eq!(status, Status::Ok, "{body}");
        assert_eq!(body["channel_type"], "DirectMessage", "{body}");
    }

    #[test]
    #[ignore = "needs REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"]
    fn antispam_route_open_dm_paused_existing_and_friend_allowed() {
        crate::util::test::rt()
            .block_on(antispam_route_open_dm_paused_existing_and_friend_allowed_case())
    }

    async fn antispam_route_open_dm_paused_existing_and_friend_allowed_case() {
        assert_detector_on().await;

        let harness = TestHarness::new().await;
        let (_, session, spammer) = harness.new_user().await;
        let (_, _, stranger) = harness.new_user().await;
        let (_, _, friend) = harness.new_user().await;
        share_server(&harness, &spammer, &stranger).await;
        befriend(&harness, &spammer, &friend).await;

        // A DM that existed before the pause stays reachable.
        let existing = Channel::create_dm(&harness.db, &spammer, &stranger)
            .await
            .expect("existing DM");
        pause(&harness, &spammer).await;

        let (status, body) = open(&harness, &session, &stranger.id).await;
        assert_eq!(status, Status::Ok, "{body}");
        assert_eq!(body["_id"], existing.id(), "{body}");

        // A friend is never gated, even for a NEW DM.
        let (status, body) = open(&harness, &session, &friend.id).await;
        assert_eq!(status, Status::Ok, "{body}");
        assert_eq!(body["channel_type"], "DirectMessage", "{body}");

        // Saved Messages is never gated.
        let (status, body) = open(&harness, &session, &spammer.id).await;
        assert_eq!(status, Status::Ok, "{body}");
        assert_ne!(body["type"], "DirectMessagesPaused", "{body}");
        // The reference driver's `find_direct_message_channel(a, a)` matches
        // any channel containing `a`, so there it hands back one of the DMs
        // above instead of Saved Messages; the channel type is only
        // meaningful on MongoDB.
        if matches!(harness.db, Database::MongoDb(_)) {
            assert_eq!(body["channel_type"], "SavedMessages", "{body}");
        }
    }

    #[test]
    fn open_dm_pause_not_enforced_while_detector_off() {
        crate::util::test::rt().block_on(open_dm_pause_not_enforced_while_detector_off_case())
    }

    /// `dm_dupe_enabled = false` is the kill switch: a stored pause must not
    /// refuse anything while it is off.
    async fn open_dm_pause_not_enforced_while_detector_off_case() {
        assert!(
            !config().await.features.antispam.dm_dupe_enabled,
            "run WITHOUT REVOLT__FEATURES__ANTISPAM__DM_DUPE_ENABLED=true"
        );

        let harness = TestHarness::new().await;
        let (_, session, spammer) = harness.new_user().await;
        let (_, _, stranger) = harness.new_user().await;
        share_server(&harness, &spammer, &stranger).await;
        pause(&harness, &spammer).await;

        let (status, body) = open(&harness, &session, &stranger.id).await;
        assert_eq!(status, Status::Ok, "{body}");
        assert_eq!(body["channel_type"], "DirectMessage", "{body}");
    }
}
