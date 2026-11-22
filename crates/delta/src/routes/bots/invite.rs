use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::{util::reference::Reference, Database, User};
use revolt_database::{Member, AMQP};
use revolt_models::v0;
use revolt_permissions::{
    calculate_channel_permissions, calculate_server_permissions, ChannelPermission,
};
use revolt_result::{create_error, Result};
use rocket::State;

use rocket::serde::json::Json;
use rocket_empty::EmptyResponse;

/// # Invite Bot
///
/// Invite a bot to a server or group by its id.`
#[openapi(tag = "Bots")]
#[post("/<target>/invite", data = "<dest>")]
pub async fn invite_bot(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    target: Reference<'_>,
    dest: Json<v0::InviteBotDestination>,
) -> Result<EmptyResponse> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let bot = target.as_bot(db).await?;
    if !bot.public && bot.owner != user.id {
        return Err(create_error!(BotIsPrivate));
    }

    let bot_user = db.fetch_user(&bot.id).await?;

    match dest.into_inner() {
        v0::InviteBotDestination::Server { server } => {
            let server = db.fetch_server(&server).await?;

            let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
            calculate_server_permissions(&mut query)
                .await
                .throw_if_lacking_channel_permission(ChannelPermission::ManageServer)?;

            Member::create(db, &server, &bot_user, None)
                .await
                .map(|_| EmptyResponse)
        }
        v0::InviteBotDestination::Group { group } => {
            let mut channel = db.fetch_channel(&group).await?;

            let mut query = DatabasePermissionQuery::new(db, &user).channel(&channel);
            calculate_channel_permissions(&mut query)
                .await
                .throw_if_lacking_channel_permission(ChannelPermission::InviteOthers)?;

            channel
                .add_user_to_group(db, amqp, &bot_user, &user.id)
                .await
                .map(|_| EmptyResponse)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{events::client::EventV1, Bot, Channel, Server, Session, User};
    use revolt_models::v0::{self, DataCreateServer};
    use rocket::http::{ContentType, Header, Status};
    use rocket::local::asynchronous::LocalResponse;

    /// A stored group of `owner` alone, marked encrypted-only or not
    async fn stored_group(harness: &TestHarness, owner: &User, marked: bool) -> Channel {
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
        group
    }

    async fn invite_to_group<'a>(
        harness: &'a TestHarness,
        session: &Session,
        bot: &Bot,
        group: &Channel,
    ) -> LocalResponse<'a> {
        harness
            .client
            .post(format!("/bots/{}/invite", bot.id))
            .header(ContentType::JSON)
            .body(
                json!(v0::InviteBotDestination::Group {
                    group: group.id().to_string()
                })
                .to_string(),
            )
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await
    }

    async fn is_member(harness: &TestHarness, group: &Channel, bot: &Bot) -> bool {
        harness
            .db
            .fetch_channel(group.id())
            .await
            .expect("group")
            .contains_user(&bot.id)
    }

    #[test]
    fn invite_bot_to_encrypted_group_is_refused() {
        crate::util::test::rt().block_on(invite_bot_to_encrypted_group_is_refused_case())
    }

    /// A marked group takes no bot (`member`), even one with a device row;
    /// an unmarked group does
    async fn invite_bot_to_encrypted_group_is_refused_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (bot, bot_user) = Bot::create(&harness.db, TestHarness::rand_string(), &user, None)
            .await
            .expect("`Bot`");
        harness
            .new_e2ee_device(&bot_user, "bot-session", crate::util::test::MEMBER_DEVICE_SEED)
            .await;

        let marked = stored_group(&harness, &user, true).await;
        let response = invite_to_group(&harness, &session, &bot, &marked).await;
        assert_eq!(response.status(), Status::Forbidden);
        let body: serde_json::Value = response.into_json().await.expect("error body");
        assert_eq!(body["type"], "EncryptionRequired", "{body}");
        assert_eq!(body["side"], "member", "{body}");
        assert!(!is_member(&harness, &marked, &bot).await);

        let plain = stored_group(&harness, &user, false).await;
        let response = invite_to_group(&harness, &session, &bot, &plain).await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);
        assert!(is_member(&harness, &plain, &bot).await);
    }

    #[test]
    fn invite_bot_to_encrypted_group_not_enforced() {
        crate::util::test::rt().block_on(async {
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee.only_enforced = false;
            })
            .await;
            invite_bot_to_encrypted_group_not_enforced_case().await
        })
    }

    /// With the marks not enforced (nextest only: the override is per
    /// process) a bot joins a marked group
    async fn invite_bot_to_encrypted_group_not_enforced_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &user, None)
            .await
            .expect("`Bot`");

        let marked = stored_group(&harness, &user, true).await;
        let response = invite_to_group(&harness, &session, &bot, &marked).await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);
        assert!(is_member(&harness, &marked, &bot).await);
    }

    #[test]
    fn invite_bot_to_group() {
        crate::util::test::rt().block_on(invite_bot_to_group_case())
    }

    async fn invite_bot_to_group_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;

        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &user, None)
            .await
            .expect("`Bot`");

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
            .post(format!("/bots/{}/invite", bot.id))
            .header(ContentType::JSON)
            .body(
                json!(v0::InviteBotDestination::Group {
                    group: group.id().to_string()
                })
                .to_string(),
            )
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::NoContent);
        drop(response);

        let event = harness
            .wait_for_event(group.id(), |event| match event {
                EventV1::ChannelGroupJoin { id, .. } => id == group.id(),
                _ => false,
            })
            .await;

        match event {
            EventV1::ChannelGroupJoin { user, .. } => {
                assert_eq!(bot.id, user);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn invite_bot_to_server() {
        crate::util::test::rt().block_on(invite_bot_to_server_case())
    }

    async fn invite_bot_to_server_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;

        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &user, None)
            .await
            .expect("`Bot`");

        let (server, _) = Server::create(
            &harness.db,
            DataCreateServer {
                name: TestHarness::rand_string(),
                ..Default::default()
            },
            &user,
            false,
        )
        .await
        .unwrap();

        let response = harness
            .client
            .post(format!("/bots/{}/invite", bot.id))
            .header(ContentType::JSON)
            .body(
                json!(v0::InviteBotDestination::Server {
                    server: server.id.to_string()
                })
                .to_string(),
            )
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::NoContent);
        drop(response);

        let event = harness
            .wait_for_event(&server.id, |event| match event {
                EventV1::ServerMemberJoin { id, .. } => id == &server.id,
                _ => false,
            })
            .await;

        match event {
            EventV1::ServerMemberJoin { member, .. } => {
                assert_eq!(bot.id, member.id.user);
            }
            _ => unreachable!(),
        }
    }
}
