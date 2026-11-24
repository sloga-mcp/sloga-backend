use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Channel, Database, User, AMQP,
};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};

use rocket::State;
use rocket_empty::EmptyResponse;

/// # Add Member to Group
///
/// Adds another user to the group.
#[openapi(tag = "Groups")]
#[put("/<group_id>/recipients/<member_id>")]
pub async fn add_member(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    group_id: Reference<'_>,
    member_id: Reference<'_>,
) -> Result<EmptyResponse> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let mut channel = group_id.as_channel(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&channel);
    calculate_channel_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::InviteOthers)?;

    match &channel {
        Channel::Group { .. } => {
            // TODO: use permissions here? interesting if users could block new group invites
            let member = member_id.as_user(db).await?;
            if !user.is_friends_with(&member.id) {
                return Err(create_error!(NotFriends));
            }

            channel
                .add_user_to_group(db, amqp, &member, &user.id)
                .await
                .map(|_| EmptyResponse)
        }
        _ => Err(create_error!(InvalidOperation)),
    }
}

#[cfg(test)]
mod test {
    use crate::{
        rocket,
        util::test::{TestHarness, MEMBER_DEVICE_SEED},
    };
    use revolt_database::{
        events::client::EventV1, Channel, PartialUser, RelationshipStatus, Session, User,
    };
    use revolt_models::v0;
    use rocket::http::{Header, Status};
    use rocket::local::asynchronous::LocalResponse;

    /// Turn the encrypted-only setting on for `user`, as the setting route
    /// stores it
    async fn set_e2ee_only(harness: &TestHarness, user: &mut User) {
        user.update(
            &harness.db,
            PartialUser {
                e2ee_only: Some(true),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("`e2ee_only`");
    }

    #[allow(clippy::disallowed_methods)]
    async fn befriend(harness: &TestHarness, user: &mut User, other: &mut User) {
        user.apply_relationship(
            &harness.db,
            other,
            RelationshipStatus::Friend,
            RelationshipStatus::Friend,
            None,
        )
        .await
        .unwrap();
    }

    /// A stored group owned by `owner` with `others` more members (ids only)
    async fn stored_group(
        harness: &TestHarness,
        owner: &User,
        others: usize,
        marked: bool,
    ) -> Channel {
        let mut recipients = vec![owner.id.clone()];
        recipients.extend((0..others).map(|_| ulid::Ulid::new().to_string()));
        let group = Channel::Group {
            id: ulid::Ulid::new().to_string(),
            name: TestHarness::rand_string(),
            owner: owner.id.clone(),
            description: None,
            recipients,
            icon: None,
            last_message_id: None,
            permissions: None,
            nsfw: false,
            spoiler: false,
            voice: None,
            e2ee_only: marked,
        };
        harness.db.insert_channel(&group).await.expect("group");
        group
    }

    async fn add<'a>(
        harness: &'a TestHarness,
        session: &Session,
        group: &Channel,
        member: &User,
    ) -> LocalResponse<'a> {
        harness
            .client
            .put(format!("/channels/{}/recipients/{}", group.id(), member.id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await
    }

    async fn assert_refused(response: LocalResponse<'_>, side: &str) {
        assert_eq!(response.status(), Status::Forbidden);
        let body: serde_json::Value = response.into_json().await.expect("error body");
        assert_eq!(body["type"], "EncryptionRequired", "{body}");
        assert_eq!(body["side"], side, "{body}");
    }

    async fn is_member(harness: &TestHarness, group: &Channel, user: &User) -> bool {
        harness
            .db
            .fetch_channel(group.id())
            .await
            .expect("group")
            .contains_user(&user.id)
    }

    #[test]
    fn add_member_to_encrypted_group() {
        crate::util::test::rt().block_on(add_member_to_encrypted_group_case())
    }

    /// A member with a device joins a marked group as its 24th member, and
    /// the "added" system row is still written there
    async fn add_member_to_encrypted_group_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, mut user) = harness.new_user().await;
        let (_, member_session, mut member) = harness.new_user().await;
        befriend(&harness, &mut user, &mut member).await;
        harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;

        let group = stored_group(&harness, &user, 22, true).await;
        let response = add(&harness, &session, &group, &member).await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);
        assert!(is_member(&harness, &group, &member).await);

        let message = harness.wait_for_message(group.id()).await;
        assert_eq!(
            message.system,
            Some(v0::SystemMessage::UserAdded {
                id: member.id.to_string(),
                by: user.id.to_string()
            })
        );
    }

    #[test]
    fn add_member_encrypted_only_refusals() {
        crate::util::test::rt().block_on(add_member_encrypted_only_refusals_case())
    }

    /// A marked group refuses a member with no device and a 25th member; an
    /// unmarked group refuses an encrypted-only member; nobody is added
    async fn add_member_encrypted_only_refusals_case() {
        let harness = TestHarness::new().await;
        let (_, session, mut user) = harness.new_user().await;
        let (_, member_session, mut member) = harness.new_user().await;
        let (_, _, mut deviceless) = harness.new_user().await;
        let (_, only_session, mut only) = harness.new_user().await;
        befriend(&harness, &mut user, &mut member).await;
        befriend(&harness, &mut user, &mut deviceless).await;
        befriend(&harness, &mut user, &mut only).await;
        harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        harness
            .new_e2ee_device(&only, &only_session.id, MEMBER_DEVICE_SEED)
            .await;
        set_e2ee_only(&harness, &mut only).await;

        let marked = stored_group(&harness, &user, 1, true).await;
        assert_refused(add(&harness, &session, &marked, &deviceless).await, "member").await;
        assert!(!is_member(&harness, &marked, &deviceless).await);

        let full = stored_group(&harness, &user, 23, true).await;
        assert_refused(add(&harness, &session, &full, &member).await, "member").await;
        assert!(!is_member(&harness, &full, &member).await);

        let plain = stored_group(&harness, &user, 1, false).await;
        assert_refused(add(&harness, &session, &plain, &only).await, "recipient").await;
        assert!(!is_member(&harness, &plain, &only).await);

        // Controls: the same encrypted-only member joins the marked group, an
        // open one joins the unmarked group
        let response = add(&harness, &session, &marked, &only).await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);
        let response = add(&harness, &session, &plain, &deviceless).await;
        assert_eq!(response.status(), Status::NoContent);
    }

    #[test]
    fn add_member_not_enforced() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee.only_enforced = false;
            })
            .await;
            add_member_not_enforced_case().await
        })
    }

    /// With the marks not enforced (nextest only: the override is per
    /// process) both refusals above are lifted
    async fn add_member_not_enforced_case() {
        let harness = TestHarness::new().await;
        let (_, session, mut user) = harness.new_user().await;
        let (_, _, mut deviceless) = harness.new_user().await;
        let (_, _, mut only) = harness.new_user().await;
        befriend(&harness, &mut user, &mut deviceless).await;
        befriend(&harness, &mut user, &mut only).await;
        set_e2ee_only(&harness, &mut only).await;

        let marked = stored_group(&harness, &user, 1, true).await;
        let response = add(&harness, &session, &marked, &deviceless).await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);

        let plain = stored_group(&harness, &user, 1, false).await;
        let response = add(&harness, &session, &plain, &only).await;
        assert_eq!(response.status(), Status::NoContent);
    }

    #[test]
    fn success_add_member() {
        crate::util::test::rt().block_on(success_add_member_case())
    }

    async fn success_add_member_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, mut user) = harness.new_user().await;
        let (_, _, mut other_user) = harness.new_user().await;

        #[allow(clippy::disallowed_methods)]
        user.apply_relationship(
            &harness.db,
            &mut other_user,
            RelationshipStatus::Friend,
            RelationshipStatus::Friend,
            None,
        )
        .await
        .unwrap();

        let group = Channel::create_group(
            &harness.db,
            v0::DataCreateGroup {
                name: TestHarness::rand_string(),
                ..Default::default()
            },
            user.id.to_string(),
        )
        .await
        .unwrap();

        let response = harness
            .client
            .put(format!(
                "/channels/{}/recipients/{}",
                group.id(),
                other_user.id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::NoContent);
        drop(response);

        harness
            .wait_for_event(&format!("{}!", other_user.id), |event| match event {
                EventV1::ChannelCreate(channel) => channel.id() == group.id(),
                _ => false,
            })
            .await;

        let event = harness
            .wait_for_event(group.id(), |event| match event {
                EventV1::ChannelGroupJoin { id, .. } => id == group.id(),
                _ => false,
            })
            .await;

        match event {
            EventV1::ChannelGroupJoin { user, .. } => assert_eq!(user, other_user.id),
            _ => unreachable!(),
        };

        let message = harness.wait_for_message(group.id()).await;

        assert_eq!(
            message.system,
            Some(v0::SystemMessage::UserAdded {
                id: other_user.id.to_string(),
                by: user.id.to_string()
            })
        );
    }

    #[test]
    fn fail_add_non_friend() {
        crate::util::test::rt().block_on(fail_add_non_friend_case())
    }

    async fn fail_add_non_friend_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (_, _, other_user) = harness.new_user().await;

        let group = Channel::create_group(
            &harness.db,
            v0::DataCreateGroup {
                name: TestHarness::rand_string(),
                ..Default::default()
            },
            user.id.to_string(),
        )
        .await
        .unwrap();

        let response = harness
            .client
            .put(format!(
                "/channels/{}/recipients/{}",
                group.id(),
                other_user.id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Forbidden);
    }

    #[test]
    fn fail_add_already_in_group() {
        crate::util::test::rt().block_on(fail_add_already_in_group_case())
    }

    async fn fail_add_already_in_group_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;

        let group = Channel::create_group(
            &harness.db,
            v0::DataCreateGroup {
                name: TestHarness::rand_string(),
                ..Default::default()
            },
            user.id.to_string(),
        )
        .await
        .unwrap();

        let response = harness
            .client
            .put(format!("/channels/{}/recipients/{}", group.id(), user.id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Conflict);
    }
}
