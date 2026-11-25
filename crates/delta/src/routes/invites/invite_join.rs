use revolt_database::{
    util::reference::Reference, Channel, Database, Invite, Member, Referral, ReferralActivity,
    User, AMQP,
};
use revolt_models::v0::{self, InviteJoinResponse};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # Join Invite
///
/// Join an invite by its ID
#[openapi(tag = "Invites")]
#[post("/<target>")]
pub async fn join(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<v0::InviteJoinResponse>> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    user.can_acquire_server(db).await?;

    let invite = target.as_invite(db).await?;
    match &invite {
        Invite::Server {
            server, creator, ..
        } => {
            let server = db.fetch_server(server).await?;
            let (_, channels) = Member::create(db, &server, &user, None).await?;

            Referral::record_activity(db, &user, ReferralActivity::InviteJoin { creator }).await;

            Ok(Json(InviteJoinResponse::Server {
                channels: channels.into_iter().map(|c| c.into()).collect(),
                server: server.into(),
            }))
        }
        Invite::Group {
            channel, creator, ..
        } => {
            let mut channel = db.fetch_channel(channel).await?;
            channel.add_user_to_group(db, amqp, &user, creator).await?;
            if let Channel::Group { recipients, .. } = &channel {
                Ok(Json(InviteJoinResponse::Group {
                    users: User::fetch_many_ids_as_mutuals(db, &user, recipients).await?,
                    channel: channel.into(),
                }))
            } else {
                unreachable!()
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        rocket,
        util::test::{TestHarness, MEMBER_DEVICE_SEED},
    };
    use revolt_database::{Channel, Invite, PartialUser, Session, User};
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

    /// A stored group owned by `owner`, and an invite to it from `owner`
    async fn invited_group(harness: &TestHarness, owner: &User, marked: bool) -> (Channel, String) {
        let group = Channel::Group {
            id: ulid::Ulid::new().to_string(),
            name: TestHarness::rand_string(),
            owner: owner.id.clone(),
            description: None,
            recipients: vec![owner.id.clone()],
            icon: None,
            last_message_id: None,
            permissions: None,
            nsfw: false,
            spoiler: false,
            voice: None,
            e2ee_only: marked,
        };
        harness.db.insert_channel(&group).await.expect("group");

        let code = TestHarness::rand_string();
        harness
            .db
            .insert_invite(&Invite::Group {
                code: code.clone(),
                creator: owner.id.clone(),
                channel: group.id().to_string(),
            })
            .await
            .expect("invite");

        (group, code)
    }

    async fn join<'a>(
        harness: &'a TestHarness,
        session: &Session,
        code: &str,
    ) -> LocalResponse<'a> {
        harness
            .client
            .post(format!("/invites/{code}"))
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
    fn join_encrypted_group() {
        crate::util::test::rt().block_on(join_encrypted_group_case())
    }

    /// A joiner with a device joins a marked group, and the "added" system
    /// row is still written there; a joiner with none is refused
    async fn join_encrypted_group_case() {
        let mut harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, session, joiner) = harness.new_user().await;
        let (_, deviceless_session, deviceless) = harness.new_user().await;
        harness
            .new_e2ee_device(&joiner, &session.id, MEMBER_DEVICE_SEED)
            .await;

        let (group, code) = invited_group(&harness, &owner, true).await;

        assert_refused(join(&harness, &deviceless_session, &code).await, "member").await;
        assert!(!is_member(&harness, &group, &deviceless).await);

        let response = join(&harness, &session, &code).await;
        assert_eq!(response.status(), Status::Ok);
        drop(response);
        assert!(is_member(&harness, &group, &joiner).await);

        let message = harness.wait_for_message(group.id()).await;
        assert_eq!(
            message.system,
            Some(v0::SystemMessage::UserAdded {
                id: joiner.id.to_string(),
                by: owner.id.to_string()
            })
        );
    }

    #[test]
    fn join_plain_group() {
        crate::util::test::rt().block_on(join_plain_group_case())
    }

    /// An unmarked group refuses an encrypted-only joiner (who has a device)
    /// and takes an open one with none
    async fn join_plain_group_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, only_session, mut only) = harness.new_user().await;
        let (_, session, joiner) = harness.new_user().await;
        harness
            .new_e2ee_device(&only, &only_session.id, MEMBER_DEVICE_SEED)
            .await;
        set_e2ee_only(&harness, &mut only).await;

        let (group, code) = invited_group(&harness, &owner, false).await;

        assert_refused(join(&harness, &only_session, &code).await, "recipient").await;
        assert!(!is_member(&harness, &group, &only).await);

        let response = join(&harness, &session, &code).await;
        assert_eq!(response.status(), Status::Ok);
        drop(response);
        assert!(is_member(&harness, &group, &joiner).await);
    }

    #[test]
    fn join_not_enforced() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee.only_enforced = false;
            })
            .await;
            join_not_enforced_case().await
        })
    }

    /// With the marks not enforced (nextest only: the override is per
    /// process) both refusals above are lifted
    async fn join_not_enforced_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, deviceless_session, deviceless) = harness.new_user().await;
        let (_, only_session, mut only) = harness.new_user().await;
        set_e2ee_only(&harness, &mut only).await;

        let (marked, code) = invited_group(&harness, &owner, true).await;
        let response = join(&harness, &deviceless_session, &code).await;
        assert_eq!(response.status(), Status::Ok);
        drop(response);
        assert!(is_member(&harness, &marked, &deviceless).await);

        let (plain, code) = invited_group(&harness, &owner, false).await;
        let response = join(&harness, &only_session, &code).await;
        assert_eq!(response.status(), Status::Ok);
        drop(response);
        assert!(is_member(&harness, &plain, &only).await);
    }
}
