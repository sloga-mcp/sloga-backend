use revolt_database::{Channel, Database, RelationshipStatus, Session, User};
use revolt_models::v0;
use revolt_result::{create_error, Result};

use rocket::serde::json::Json;
use rocket::State;
use validator::Validate;

/// # Create Group
///
/// Create a new group channel.
///
/// A group that includes an encrypted-only account (the creator or anyone
/// added) is created encrypted-only, which needs this session to be bound to
/// one of the creator's encryption devices, at most 24 members, no bots and
/// encryption set up by every member; otherwise it is refused with
/// `EncryptionRequired`.
#[openapi(tag = "Groups")]
#[post("/create", data = "<data>")]
pub async fn create_group(
    db: &State<Database>,
    user: User,
    session: Option<Session>,
    data: Json<v0::DataCreateGroup>,
) -> Result<Json<v0::Channel>> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    for target in &data.users {
        match user.relationship_with(target) {
            RelationshipStatus::Friend | RelationshipStatus::User => {}
            _ => {
                return Err(create_error!(NotFriends));
            }
        }
    }

    let session_id = session.as_ref().map(|session| session.id.as_str());
    Ok(Json(
        Channel::create_group_from_session(db, data, user.id, session_id)
            .await?
            .into(),
    ))
}

#[cfg(test)]
mod test {
    use crate::{
        rocket,
        util::test::{TestHarness, MEMBER_DEVICE_SEED, NEW_OWNER_DEVICE_SEED, OWNER_DEVICE_SEED},
    };
    use revolt_database::{
        events::client::EventV1, Channel, PartialUser, RelationshipStatus, Session, User,
    };
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};
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

    /// `POST /channels/create` as `session`, adding `members`
    async fn create<'a>(
        harness: &'a TestHarness,
        session: &Session,
        members: &[&User],
    ) -> LocalResponse<'a> {
        let users: Vec<String> = members.iter().map(|member| member.id.clone()).collect();
        harness
            .client
            .post("/channels/create")
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "name": TestHarness::rand_string(), "users": users }).to_string())
            .dispatch()
            .await
    }

    /// The group in a successful response, checked against the stored one
    async fn created(harness: &TestHarness, response: LocalResponse<'_>) -> (String, bool) {
        assert_eq!(response.status(), Status::Ok);
        let channel: v0::Channel = response.into_json().await.expect("`Channel`");
        let (id, e2ee_only) = match channel {
            v0::Channel::Group { id, e2ee_only, .. } => (id, e2ee_only),
            other => panic!("expected a group, got {other:?}"),
        };
        match harness.db.fetch_channel(&id).await.expect("stored group") {
            Channel::Group {
                e2ee_only: stored, ..
            } => assert_eq!(stored, e2ee_only, "stored mark"),
            other => panic!("expected a group, got {other:?}"),
        }
        (id, e2ee_only)
    }

    async fn assert_refused(response: LocalResponse<'_>, side: &str) {
        assert_eq!(response.status(), Status::Forbidden);
        let body: serde_json::Value = response.into_json().await.expect("error body");
        assert_eq!(body["type"], "EncryptionRequired", "{body}");
        assert_eq!(body["side"], side, "{body}");
    }

    /// No group was stored for `user`
    async fn assert_no_group(harness: &TestHarness, user: &User) {
        let channels = harness
            .db
            .find_direct_messages(&user.id)
            .await
            .expect("channels");
        assert!(
            !channels
                .iter()
                .any(|channel| matches!(channel, Channel::Group { .. })),
            "a refused group was stored: {channels:?}"
        );
    }

    #[test]
    fn encrypted_only_creator_or_member_marks_the_group() {
        crate::util::test::rt().block_on(encrypted_only_creator_or_member_marks_the_group_case())
    }

    /// The creator's flag marks the group, and so does a member's; both
    /// creators act from a session bound to their device
    async fn encrypted_only_creator_or_member_marks_the_group_case() {
        let harness = TestHarness::new().await;
        let (_, session, mut user) = harness.new_user().await;
        let (_, member_session, mut member) = harness.new_user().await;
        befriend(&harness, &mut user, &mut member).await;
        harness
            .new_e2ee_device(&user, &session.id, OWNER_DEVICE_SEED)
            .await;
        harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;

        // Control: nobody encrypted-only
        let (_, marked) = created(&harness, create(&harness, &session, &[&member]).await).await;
        assert!(!marked);

        set_e2ee_only(&harness, &mut member).await;
        let (_, marked) = created(&harness, create(&harness, &session, &[&member]).await).await;
        assert!(marked, "marked by the member");

        set_e2ee_only(&harness, &mut user).await;
        let (_, marked) = created(&harness, create(&harness, &session, &[]).await).await;
        assert!(marked, "marked by the creator");
    }

    #[test]
    fn encrypted_group_refusals() {
        crate::util::test::rt().block_on(encrypted_group_refusals_case())
    }

    /// `sender` without a session bound to a device of the creator, `member`
    /// for a member with no device; nothing is stored
    async fn encrypted_group_refusals_case() {
        let harness = TestHarness::new().await;
        let (_, session, mut user) = harness.new_user().await;
        let (_, member_session, mut member) = harness.new_user().await;
        let (_, _, mut deviceless) = harness.new_user().await;
        befriend(&harness, &mut user, &mut member).await;
        befriend(&harness, &mut user, &mut deviceless).await;
        harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        set_e2ee_only(&harness, &mut member).await;

        // The creator has no device: refused although only a member is
        // encrypted-only
        assert_refused(create(&harness, &session, &[&member]).await, "sender").await;

        // The creator's device is bound to another session
        harness
            .new_e2ee_device(&user, "another-session", OWNER_DEVICE_SEED)
            .await;
        assert_refused(create(&harness, &session, &[&member]).await, "sender").await;
        assert_no_group(&harness, &user).await;

        // A second device of the creator bound to this session; a member
        // with no device
        harness
            .new_e2ee_device(&user, &session.id, NEW_OWNER_DEVICE_SEED)
            .await;
        assert_refused(
            create(&harness, &session, &[&member, &deviceless]).await,
            "member",
        )
        .await;
        assert_no_group(&harness, &user).await;

        // The same request without that member
        let (_, marked) = created(&harness, create(&harness, &session, &[&member]).await).await;
        assert!(marked);
    }

    #[test]
    fn plain_group_needs_no_device() {
        crate::util::test::rt().block_on(plain_group_needs_no_device_case())
    }

    /// Without anyone encrypted-only nothing about devices is asked
    async fn plain_group_needs_no_device_case() {
        let harness = TestHarness::new().await;
        let (_, session, mut user) = harness.new_user().await;
        let (_, _, mut member) = harness.new_user().await;
        befriend(&harness, &mut user, &mut member).await;

        let (_, marked) = created(&harness, create(&harness, &session, &[&member]).await).await;
        assert!(!marked);
    }

    #[test]
    fn encrypted_group_not_enforced_is_marked_and_not_refused() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee.only_enforced = false;
            })
            .await;
            encrypted_group_not_enforced_is_marked_and_not_refused_case().await
        })
    }

    /// With the marks not enforced (nextest only: the override is per
    /// process) a group with an encrypted-only creator who has no device is
    /// still created, and still marked
    async fn encrypted_group_not_enforced_is_marked_and_not_refused_case() {
        let harness = TestHarness::new().await;
        let (_, session, mut user) = harness.new_user().await;
        let (_, _, mut deviceless) = harness.new_user().await;
        befriend(&harness, &mut user, &mut deviceless).await;
        set_e2ee_only(&harness, &mut user).await;

        let (_, marked) = created(&harness, create(&harness, &session, &[&deviceless]).await).await;
        assert!(marked);
    }

    #[test]
    fn create_group() {
        crate::util::test::rt().block_on(create_group_case())
    }

    async fn create_group_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;

        let response = harness
            .client
            .post("/channels/create")
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(
                json!(v0::DataCreateBot {
                    name: TestHarness::rand_string(),
                })
                .to_string(),
            )
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);

        let channel: v0::Channel = response.into_json().await.expect("`Channel`");
        match channel {
            v0::Channel::Group {
                id,
                owner,
                recipients,
                ..
            } => {
                assert_eq!(owner, user.id);
                assert_eq!(recipients.len(), 1);
                assert!(harness.db.fetch_channel(&id).await.is_ok());

                let event = harness
                    .wait_for_event(&format!("{}!", user.id), |event| match event {
                        EventV1::ChannelCreate(channel) => channel.id() == id,
                        _ => false,
                    })
                    .await;

                match event {
                    EventV1::ChannelCreate(v0::Channel::Group {
                        owner: channel_owner,
                        ..
                    }) => {
                        assert_eq!(owner, channel_owner);
                    }
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }
}
