use revolt_database::{
    util::reference::Reference,
    voice::{remove_user_from_voice_channels, VoiceClient},
    Database, User,
};
use revolt_result::{create_error, Result, ToRevoltError};
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Delete Bot
///
/// Delete a bot by its id.
#[openapi(tag = "Bots")]
#[delete("/<bot_id>")]
pub async fn delete_bot(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    bot_id: Reference<'_>,
) -> Result<EmptyResponse> {
    let bot = bot_id.as_bot(db).await?;
    if bot.owner != user.id {
        return Err(create_error!(NotFound));
    }

    bot.delete(db).await?;

    // The bot is already deleted, so a retry answers NotFound and can never
    // redo this eviction (AFK S-3 DS-1). A failed eviction is therefore
    // reported (ERROR + Sentry) and the delete still answers success. Every
    // call is tried before the first failure is returned.
    if let Err(error) = remove_user_from_voice_channels(db, voice_client, &bot.id).await {
        log::warn!(
            "bot {} was deleted, but evicting it from its calls failed: {error:?}",
            bot.id
        );
        let _ = Err::<(), _>(error).to_internal_error();
    }

    Ok(EmptyResponse)
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{events::client::EventV1, Bot};
    use rocket::http::{Header, Status};

    #[test]
    fn delete_bot() {
        crate::util::test::rt().block_on(delete_bot_case())
    }

    async fn delete_bot_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;

        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &user, None)
            .await
            .expect("`Bot`");

        let response = harness
            .client
            .delete(format!("/bots/{}", bot.id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::NoContent);
        assert!(harness.db.fetch_bot(&bot.id).await.is_err());
        drop(response);

        let event = harness
            .wait_for_event(&bot.id, |event| match event {
                EventV1::UserUpdate { id, .. } => id == &bot.id,
                _ => false,
            })
            .await;

        match event {
            EventV1::UserUpdate { data, .. } => {
                assert_eq!(data.flags, Some(2));
            }
            _ => unreachable!(),
        }
    }

    // ---- the eviction after the delete (AFK S-3 DS-1) ----------------------
    //
    // Needs RabbitMQ and Redis, as every route test here does.

    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        voice::{
            create_voice_state, delete_channel_node, delete_channel_voice_state,
            get_user_voice_channel_in_server, get_voice_channel_members, is_in_voice_channel,
            record_voice_connection, recorded_voice_connections, set_channel_node,
            UserVoiceChannel,
        },
        Channel, Server,
    };
    use revolt_models::v0;

    /// A node name deliberately absent from `Revolt.toml`: an eviction
    /// addressed to it fails with `UnknownNode` before any network.
    const ABSENT_NODE: &str = "test-node-with-no-sfu";

    async fn voice_channel(harness: &TestHarness, server: &Server) -> Channel {
        Channel::create_server_channel(
            &harness.db,
            &mut server.clone(),
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Text,
                name: "Voice".to_string(),
                description: None,
                nsfw: Some(false),
                spoiler: None,
                voice: Some(v0::VoiceInformation {
                    max_users: None,
                    disabled: false,
                }),
                announcement: None,
                ..Default::default()
            },
            true,
        )
        .await
        .expect("voice channel")
    }

    /// A join as voice-ingress records it: the connection first, then the
    /// state, created only for the user's first connection.
    async fn join_recorded(uvc: &UserVoiceChannel, user_id: &str, sid: &str, identity: &str) {
        if record_voice_connection(uvc, user_id, sid, identity)
            .await
            .expect("record")
        {
            create_voice_state(uvc, user_id, Timestamp::now_utc())
                .await
                .expect("voice state");
        }
    }

    /// What is left of `user_id` in `uvc`: the number of recorded
    /// connections, then whether it is in the user's channel set, in the
    /// channel's member set, and named by the per-server pointer.
    async fn voice_traces(uvc: &UserVoiceChannel, user_id: &str) -> (usize, bool, bool, bool) {
        let recorded = recorded_voice_connections(uvc, user_id)
            .await
            .expect("recorded read")
            .len();
        let listed = is_in_voice_channel(user_id, uvc).await.expect("vc read");
        let member = get_voice_channel_members(uvc)
            .await
            .expect("members read")
            .is_some_and(|members| members.iter().any(|id| id == user_id));
        let parent = uvc.server_id.as_deref().unwrap_or(&uvc.id);
        let pointer = get_user_voice_channel_in_server(user_id, parent)
            .await
            .expect("pointer read")
            .as_deref()
            == Some(uvc.id.as_str());
        (recorded, listed, member, pointer)
    }

    #[test]
    fn a_failed_eviction_still_deletes_the_bot() {
        crate::util::test::rt().block_on(a_failed_eviction_still_deletes_the_bot_case())
    }

    /// DS-1: the bot is in a call and the eviction fails (ABSENT_NODE,
    /// UnknownNode before any network). The bot is already deleted and a
    /// retry would answer NotFound, so the route answers success, and the
    /// failed eviction tore nothing down. Mutation: the eviction error
    /// propagated (a non-2xx).
    async fn a_failed_eviction_still_deletes_the_bot_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user).await;
        let channel = voice_channel(&harness, &server).await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &user, None)
            .await
            .expect("`Bot`");
        join_recorded(&uvc, &bot.id, "PA_bot_live", &bot.id).await;
        set_channel_node(channel.id(), ABSENT_NODE)
            .await
            .expect("node");

        let response = harness
            .client
            .delete(format!("/bots/{}", bot.id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        delete_channel_node(channel.id()).await.expect("unpin");

        assert_eq!(
            status,
            Status::NoContent,
            "a failed eviction after the delete must answer success: {}",
            body
        );
        assert!(
            harness.db.fetch_bot(&bot.id).await.is_err(),
            "the bot is deleted"
        );
        assert_eq!(
            voice_traces(&uvc, &bot.id).await,
            (1, true, true, true),
            "a failed eviction tears nothing down"
        );

        delete_channel_voice_state(&uvc, &[bot.id.clone()])
            .await
            .expect("cleanup");
    }

    #[test]
    fn a_deleted_bots_ghost_is_torn_down() {
        crate::util::test::rt().block_on(a_deleted_bots_ghost_is_torn_down_case())
    }

    /// A call that ended without its webhooks (no node pinned) left the bot
    /// on the roster with a recorded connection. Deleting the bot tears the
    /// ghost down from the recorded sids, with no SFU involved. Mutation:
    /// the eviction removed.
    async fn a_deleted_bots_ghost_is_torn_down_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user).await;
        let channel = voice_channel(&harness, &server).await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        let (bot, _) = Bot::create(&harness.db, TestHarness::rand_string(), &user, None)
            .await
            .expect("`Bot`");
        join_recorded(&uvc, &bot.id, "PA_bot_ghost", &bot.id).await;
        assert_eq!(
            voice_traces(&uvc, &bot.id).await,
            (1, true, true, true),
            "the ghost is in place"
        );

        let response = harness
            .client
            .delete(format!("/bots/{}", bot.id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);

        assert!(harness.db.fetch_bot(&bot.id).await.is_err());
        assert_eq!(
            voice_traces(&uvc, &bot.id).await,
            (0, false, false, false),
            "the deleted bot's ghost must be torn down"
        );
    }

    // ---- the route's text (AFK S-3 DS-1) -----------------------------------

    /// `delete_bot`'s body, comment lines dropped and whitespace collapsed.
    fn route_body() -> String {
        const SOURCE: &str = include_str!("delete.rs");
        let at = SOURCE
            .find("pub async fn delete_bot(")
            .expect("the route is defined");
        let open = at + SOURCE[at..].find('\u{7b}').expect("a body");
        let mut depth = 0usize;
        let mut close = None;
        for (i, ch) in SOURCE[open..].char_indices() {
            match ch {
                '\u{7b}' => depth += 1,
                '\u{7d}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        SOURCE[open..=close.expect("a closed body")]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// DS-1: the eviction runs AFTER the durable delete and its error is
    /// neither propagated nor silently dropped but reported through
    /// `to_internal_error()`. Mutations: the error propagated; the eviction
    /// removed.
    #[test]
    fn the_delete_evicts_after_it_is_durable_and_reports_a_failure() {
        const DURABLE: &str = "bot.delete(db).await?;";
        const EVICT: &str =
            "if let Err(error) = remove_user_from_voice_channels(db, voice_client, \
             &bot.id).await \u{7b}";
        const REPORT: &str = "let _ = Err::<(), _>(error).to_internal_error();";

        let body = route_body();
        let mut last = 0;
        for needle in [DURABLE, EVICT, REPORT] {
            assert_eq!(
                body.matches(needle).count(),
                1,
                "the delete must carry `{needle}` exactly once: {body}"
            );
            let at = body.find(needle).expect("counted above");
            assert!(last < at, "`{}` is out of order: {}", needle, body);
            last = at;
        }
        assert_eq!(
            body.matches("remove_user_from_voice_channels(").count(),
            1,
            "one eviction, the one pinned above: {body}"
        );
        for banned in [
            "let _ = remove_user_from_voice_channels",
            ".ok()",
            "to_internal_error()?",
        ] {
            assert!(
                !body.contains(banned),
                "the delete must not carry `{}`: {}",
                banned,
                body
            );
        }
    }
}
