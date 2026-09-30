//! AFK idle beacon (AFK-channel plan, Wave 5b-2).
//!
//! A member's client reports that it has seen no activity from its user in a
//! voice call for `idle_for` seconds. The claim is stored per user and server
//! (`revolt_database::voice::afk_idle`), and the crond AFK sweep moves the
//! member into the server's AFK channel once the server's own `afk_timeout`
//! has passed. The server stamps `since` from its own clock and applies the
//! timeout itself, so neither a client clock nor a timeout travels on the
//! wire.
//!
//! **`idle_for` is CLIENT-CLAIMED.** The server cannot verify it, and it
//! grants nothing: the only thing a claim can ever cause is its own author
//! being moved into the AFK channel, which that author could do by hand. A
//! false "idle" buys nothing, and a false "active" (the DELETE) only keeps
//! its author where they already are. Nothing security-bearing may ever be
//! gated on it.
//!
//! Neither route publishes anything. The claim is private bookkeeping for the
//! sweep, not a roster fact; the move itself, when it happens, announces
//! itself through the ordinary voice-move path.
//!
//! The DELETE is deliberately authentication-only (Stage 1 I-3): a withdrawal
//! refused for any reason leaves an idle claim standing against a member who
//! is active again, and clearing one's own claim can never harm anyone. For
//! the same reason both routes have their own ratelimit bucket (`afk_idle`),
//! so they can neither starve nor be starved by the plain channels bucket.
//!
//! The DELETE also leaves a short tombstone (`withdraw_afk_since`, re-audit
//! R-1). The client gives up waiting on a PUT after 10 s
//! (`AFK_IDLE_REQUEST_TIMEOUT_MS`), but Rocket keeps running the handler
//! after the client has gone, so a stalled PUT can land AFTER the withdrawal
//! that replaced it and re-create a claim nobody will ever withdraw; the
//! sweep would then move a member who is active.
//! While the tombstone stands, a claim PUT writes nothing (and still answers
//! 204). Only the client's withdrawal leaves one: a PUT from inside the AFK
//! channel clears with `clear_afk_since`, which leaves none, so sitting in the
//! AFK channel never delays a later claim elsewhere.
//!
//! Only the session recorded as owning the member's participant in the call
//! (the one `join_call` recorded, merge slice F11) may claim. Any other
//! session of the same user (another tab or device, or a join from before the
//! record existed) is refused `NotOwner` before anything is written: the
//! sweep would skip a member with no recorded owner anyway, and a claim from
//! a session that is not the one in the call says nothing about the member
//! who is. The refusal is not transient, so a client can stop posting from
//! that session.
//!
//! The session is read only at that step (merge slice M2C-7), so the PUT
//! still answers in its contract order: a bot, which has no session, is
//! refused `IsBot` after the two shape checks, not rejected by a session
//! guard before any of them. A request with no session of the user's own
//! that gets that far is refused `NotOwner`.

use revolt_config::config;
use revolt_database::{
    util::{permissions::perms, reference::Reference},
    voice::{
        afk_idle::{clear_afk_since, set_afk_since, withdraw_afk_since},
        get_user_voice_channel_in_server, is_in_voice_channel, voice_participant_session_is,
        UserVoiceChannel,
    },
    Database, Session, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};

use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;

/// # Report Voice Idle
///
/// Report that this client has seen no activity from its user in this voice
/// call for `idle_for` seconds. Once the server's AFK timeout has passed the
/// member may be moved to the server's AFK channel. A self-report that grants
/// nothing; repeating it only keeps the claim alive. Only the session that
/// joined the call may report it.
#[openapi(tag = "Voice")]
#[put("/<target>/afk_idle", data = "<data>")]
pub async fn afk_idle_set(
    db: &State<Database>,
    user: User,
    session: Option<Session>,
    target: Reference<'_>,
    data: Json<v0::DataAfkIdle>,
) -> Result<EmptyResponse> {
    let v0::DataAfkIdle { idle_for } = data.into_inner();
    let channel = target.as_channel(db).await?;

    // Shape before permission, ACCEPTED (AFK Stage 6 F-A6, operator ruling
    // 2026-09-23). `NotAVoiceChannel` and the no-server `InvalidOperation`
    // are answered before the `Connect` check below, so any account
    // holding a channel id can learn whether it is a voice channel and
    // whether it sits in a server. That is a LOW channel-type oracle, and it
    // is kept: it reveals no content, no membership and no occupancy, it
    // needs an id the caller already has (ids are ULIDs, not guessable), and
    // `put_validates_in_the_contract_order` pins this order as the wire
    // contract. Do not reorder without revisiting that ruling.
    if channel.voice().is_none() {
        return Err(create_error!(NotAVoiceChannel));
    }

    // There is no AFK channel outside a server: a DM or group call has
    // nowhere to be moved to.
    let Some(server_id) = channel.server() else {
        return Err(create_error!(InvalidOperation));
    };

    // The rc_capable rule: per-member voice flags key `{user}:{server}`,
    // which COLLIDES for a bot in two voice channels of one server. The sweep
    // skips bots as well.
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let mut query = perms(db, &user).channel(&channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::Connect)?;

    // `vc:{user}` alone is not enough (Stage 1 I-13): it is per user, so a
    // phone or a tab that is not the one in the call would pass, and a claim
    // for A landing after the user joined B would be recorded against the
    // server while they sit in B. The `{user}:{server}` pointer names the one
    // channel the member is live in, and the claim must be for exactly that
    // channel.
    if !is_in_voice_channel(&user.id, &UserVoiceChannel::from_channel(&channel)).await?
        || get_user_voice_channel_in_server(&user.id, server_id)
            .await?
            .as_deref()
            != Some(channel.id())
    {
        return Err(create_error!(NotInVoiceChannel));
    }

    // Merge slice F11 (P2A-15): the live seat is the user's, but only the
    // session recorded as owning it may claim, before any write (the clear
    // below included). Not `NotInVoiceChannel`, which the client treats as
    // transient: `NotOwner` stays true for this session until it joins
    // again, so a client can latch on it and stop posting. A failed read is
    // an error, never an acceptance.
    //
    // The session guard is optional so that a bot, which has none, is
    // answered `IsBot` above in the contract order (merge slice M2C-7). Past
    // that check the account signed in with a session, so it is always here
    // and always the user's own. Should that ever stop holding, a request
    // with no session of the user's own owns no seat and is refused the same
    // way, never waved through.
    let Some(session) = session.filter(|session| session.user_id == user.id) else {
        return Err(create_error!(NotOwner));
    };
    if !voice_participant_session_is(channel.id(), &user.id, Some(&session.id)).await? {
        return Err(create_error!(NotOwner));
    }

    // No designation or no timeout means the server never moves anyone, so
    // there is nothing to claim against. The sweep re-reads both on every
    // tick, so a later change still takes effect.
    let server = db.fetch_server(server_id).await?;
    let (Some(afk_channel_id), Some(_)) = (server.afk_channel_id.as_deref(), server.afk_timeout)
    else {
        return Err(create_error!(InvalidOperation));
    };

    // The deployment-wide kill switch (`features.afk_auto_move`, D-5b2-3):
    // with it off the sweep reads nothing, so a claim would be refreshed for
    // nobody. Refused the same way as a server that moves nobody, which the
    // client backs off from and then stops posting (audit A3).
    if !config().await.features.afk_auto_move {
        return Err(create_error!(InvalidOperation));
    }

    // Idle in the AFK channel itself is where the move would put them
    // anyway; drop any claim rather than record one. No tombstone here: this
    // is not a withdrawal, and must not delay a later claim elsewhere.
    if channel.id() == afk_channel_id {
        clear_afk_since(&user.id, server_id).await?;
        return Ok(EmptyResponse);
    }

    set_afk_since(&user.id, server_id, channel.id(), idle_for).await?;

    Ok(EmptyResponse)
}

/// # Withdraw Voice Idle
///
/// Withdraw this user's idle claim in the channel's server, because the user
/// is active again. Always succeeds for an authenticated user; there is
/// nothing to withdraw outside a server.
#[openapi(tag = "Voice")]
#[delete("/<target>/afk_idle")]
pub async fn afk_idle_clear(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<EmptyResponse> {
    let channel = target.as_channel(db).await?;

    let Some(server_id) = channel.server() else {
        return Ok(EmptyResponse);
    };

    // With a tombstone, so a claim PUT still running in this process cannot
    // re-create what this withdraws (see the module docs).
    withdraw_afk_since(&user.id, server_id).await?;

    Ok(EmptyResponse)
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{
        voice::{
            afk_idle::get_afk_since, create_voice_state, delete_channel_voice_state,
            set_voice_participant_session, UserVoiceChannel,
        },
        Bot, Channel, Member, PartialServer, Server,
    };
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};

    const SOURCE: &str = include_str!("afk_idle.rs");
    const ROUTES: &str = include_str!("mod.rs");

    /// The file up to its test module: the code that ships.
    fn shipping() -> &'static str {
        let end = SOURCE
            .find("#[cfg(test)]")
            .expect("the route file has a test module");
        &SOURCE[..end]
    }

    /// Body of the handler `definition`, comment lines dropped and every run
    /// of whitespace collapsed to one space, so a needle does not depend on
    /// rustfmt's line breaks.
    fn handler_body(definition: &str) -> String {
        let shipping = shipping();
        let at = shipping
            .find(definition)
            .unwrap_or_else(|| panic!("the route file no longer defines `{}`", definition));
        let open = at + shipping[at..].find('\u{7b}').expect("a body");
        let mut depth = 0usize;
        let mut close = None;
        for (i, ch) in shipping[open..].char_indices() {
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
        let body = &shipping[open..=close.expect("a closed body")];
        body.lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn position(body: &str, needle: &str) -> usize {
        body.find(needle)
            .unwrap_or_else(|| panic!("the handler lost `{}`: {}", needle, body))
    }

    const PUT: &str = "pub async fn afk_idle_set(";
    const DELETE: &str = "pub async fn afk_idle_clear(";

    #[test]
    fn module_doc_says_client_claimed_and_grants_nothing() {
        // Only the `//!` lines count: this test's own needles must not be
        // what satisfies it.
        let doc = SOURCE
            .lines()
            .filter_map(|line| line.strip_prefix("//!"))
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            doc.contains("CLIENT-CLAIMED"),
            "the module doc must say the claim is CLIENT-CLAIMED in those words"
        );
        assert!(
            doc.contains("grants nothing"),
            "the module doc must say the claim grants nothing"
        );
    }

    #[test]
    fn put_refuses_bots_before_any_write() {
        let body = handler_body(PUT);
        let bot = position(&body, "if user.bot.is_some()");
        assert!(bot < position(&body, "set_afk_since("), "{}", body);
        assert!(bot < position(&body, "clear_afk_since("), "{}", body);
    }

    #[test]
    fn put_checks_the_server_pointer_before_any_write() {
        let body = handler_body(PUT);
        let pointer = position(
            &body,
            "get_user_voice_channel_in_server(&user.id, server_id) .await? .as_deref() != Some(channel.id())",
        );
        assert!(pointer < position(&body, "set_afk_since("), "{}", body);
        assert!(pointer < position(&body, "clear_afk_since("), "{}", body);
    }

    /// The whole validation order of the wire contract, in one pass.
    #[test]
    fn put_validates_in_the_contract_order() {
        let body = handler_body(PUT);
        let order = [
            "create_error!(NotAVoiceChannel)",
            "let Some(server_id) = channel.server() else",
            "create_error!(InvalidOperation)",
            "create_error!(IsBot)",
            "throw_if_lacking_channel_permission(ChannelPermission::Connect)",
            "is_in_voice_channel(",
            "create_error!(NotInVoiceChannel)",
            "let Some(session) = session.filter(|session| session.user_id == user.id) else",
            "create_error!(NotOwner)",
            "voice_participant_session_is(channel.id(), &user.id, Some(&session.id))",
            "create_error!(NotOwner)",
            "server.afk_channel_id.as_deref(), server.afk_timeout",
            "config().await.features.afk_auto_move",
            "if channel.id() == afk_channel_id",
            "clear_afk_since(&user.id, server_id)",
            "set_afk_since(&user.id, server_id, channel.id(), idle_for)",
        ];
        let mut last = 0;
        for needle in order {
            let at = body[last..]
                .find(needle)
                .map(|offset| last + offset)
                .unwrap_or_else(|| panic!("`{}` is missing or out of order: {}", needle, body));
            last = at + needle.len();
        }
    }

    /// Merge slice F11 (P2A-15): only the session recorded as owning the
    /// participant claims. The check is one exact statement, reads the
    /// channel of the route and the REQUEST's session (a `None` or another
    /// binding compiles), refuses with `NotOwner`, propagates a failed read,
    /// and comes after the live-seat check and before both writes. Controls
    /// OWNER-GONE (deleted) and OWNER-LATE (moved after `set_afk_since(`).
    ///
    /// Merge slice M2C-7: the session guard is OPTIONAL and the session is
    /// first read after the `IsBot` refusal, so a bot (which has no session)
    /// gets `IsBot` in the contract order instead of failing a required
    /// guard before every shape check. A missing session, or one that is not
    /// the user's, is `NotOwner`, never a pass.
    #[test]
    fn put_accepts_only_the_recorded_session_before_any_write() {
        let body = handler_body(PUT);
        const SESSION: &str = "let Some(session) = \
             session.filter(|session| session.user_id == user.id) else \u{7b} \
             return Err(create_error!(NotOwner)); \u{7d};";
        const CHECK: &str = "if !voice_participant_session_is(channel.id(), &user.id, \
             Some(&session.id)).await? \u{7b} return Err(create_error!(NotOwner)); \u{7d}";

        assert_eq!(body.matches(SESSION).count(), 1, "{}", body);
        assert_eq!(body.matches(CHECK).count(), 1, "{}", body);
        assert_eq!(
            body.matches("voice_participant_session_is(").count(),
            1,
            "{}",
            body
        );
        assert_eq!(body.matches("NotOwner").count(), 2, "{}", body);
        let session = position(&body, SESSION);
        let check = position(&body, CHECK);
        assert!(
            position(&body, "create_error!(NotInVoiceChannel)") < session && session < check,
            "{}",
            body
        );
        assert!(check < position(&body, "set_afk_since("), "{}", body);
        assert!(check < position(&body, "clear_afk_since("), "{}", body);
        assert!(
            position(&body, "create_error!(IsBot)") < position(&body, "session"),
            "nothing may read the session before the bot refusal: {}",
            body
        );

        // The request's own session, from an optional request guard.
        assert!(
            shipping().contains(
                "    user: User,\n    session: Option<Session>,\n    target: Reference<'_>,\n"
            ),
            "the PUT takes the optional session guard"
        );
        // The DELETE stays authentication-only (Stage 1 I-3).
        assert!(!handler_body(DELETE).contains("voice_participant_session_is("));
    }

    /// Audit A3: with auto-move switched off the PUT refuses, and the
    /// polarity is exact. Without the `!` the default-on deployment would
    /// refuse every claim and the emergency-off one would accept them.
    #[test]
    fn put_refuses_while_auto_move_is_switched_off() {
        let body = handler_body(PUT);
        let switch = position(
            &body,
            "if !config().await.features.afk_auto_move \u{7b} \
             return Err(create_error!(InvalidOperation)); \u{7d}",
        );
        assert_eq!(
            body.matches("afk_auto_move").count(),
            1,
            "exactly one kill-switch read: {}",
            body
        );
        assert!(switch < position(&body, "set_afk_since("), "{}", body);
        assert!(switch < position(&body, "clear_afk_since("), "{}", body);

        let delete = handler_body(DELETE);
        assert!(
            !delete.contains("afk_auto_move"),
            "withdrawing a claim must work with the switch off: {}",
            delete
        );
    }

    /// Audit B4: the client posts to exactly these paths, so a renamed
    /// segment (`afk-idle`) would 404 the whole feature with every other pin
    /// green. Byte-exact, attribute directly above its handler.
    #[test]
    fn route_paths_are_exact() {
        let shipping = shipping();
        for (attribute, handler) in [
            (
                "#[put(\"/<target>/afk_idle\", data = \"<data>\")]\n",
                "pub async fn afk_idle_set(",
            ),
            (
                "#[delete(\"/<target>/afk_idle\")]\n",
                "pub async fn afk_idle_clear(",
            ),
        ] {
            let pinned = format!("{}{}", attribute, handler);
            assert!(
                shipping.contains(&pinned),
                "`{}` must carry exactly `{}`",
                handler,
                attribute.trim_end()
            );
        }
    }

    #[test]
    fn the_file_publishes_no_event() {
        let event = concat!("Event", "V1");
        assert!(
            !SOURCE.contains(event),
            "the idle beacon is private bookkeeping and must publish nothing"
        );
    }

    #[test]
    fn delete_is_authentication_only() {
        let body = handler_body(DELETE);
        position(&body, "withdraw_afk_since(&user.id, server_id)");
        for forbidden in [
            "calculate_channel_permissions",
            "throw_if_lacking_channel_permission",
            "is_in_voice_channel",
            "get_user_voice_channel_in_server",
            "user.bot",
        ] {
            assert!(
                !body.contains(forbidden),
                "withdrawing a claim must never be refused, but the DELETE \
                 checks `{}`: {}",
                forbidden,
                body
            );
        }
    }

    /// Re-audit R-1: only the client's withdrawal leaves the tombstone. The
    /// DELETE without it lets a stalled PUT re-create the claim after the
    /// withdrawal; the PUT's AFK-channel path with it would block the
    /// member's next claim elsewhere for the tombstone's lifetime.
    #[test]
    fn only_the_withdrawal_leaves_a_tombstone() {
        let delete = handler_body(DELETE);
        position(&delete, "withdraw_afk_since(&user.id, server_id)");
        assert!(
            !delete.contains("clear_afk_since("),
            "the DELETE must withdraw with a tombstone: {}",
            delete
        );

        let put = handler_body(PUT);
        position(&put, "clear_afk_since(&user.id, server_id)");
        assert!(
            !put.contains("withdraw_afk_since("),
            "the PUT's AFK-channel path must clear without a tombstone: {}",
            put
        );
    }

    #[test]
    fn both_handlers_are_registered() {
        let at = ROUTES
            .find("openapi_get_routes_spec![")
            .expect("routes/channels/mod.rs builds its route list");
        let end = at + ROUTES[at..].find(']').expect("the route list closes");
        let spec = &ROUTES[at..end];
        for handler in ["afk_idle::afk_idle_set,", "afk_idle::afk_idle_clear,"] {
            assert!(
                spec.contains(handler),
                "`{}` is not mounted: the route would answer 404",
                handler
            );
        }
        assert!(ROUTES.lines().any(|line| line == "mod afk_idle;"));
    }

    // ---- behavior (needs RabbitMQ and Redis) ------------------------------
    //
    // Compile-only on a box without those services: `TestHarness::new`
    // connects to RabbitMQ and the claim lives in Redis, so this fails before
    // it asserts anything there, like every other route test in this crate
    // (see the note on `voice_join.rs`'s tests).

    async fn voice_channel(harness: &TestHarness, server: &Server, name: &str) -> Channel {
        Channel::create_server_channel(
            &harness.db,
            &mut server.clone(),
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Text,
                name: name.to_string(),
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

    async fn claim(
        harness: &TestHarness,
        token: &str,
        channel_id: &str,
        idle_for: u32,
    ) -> (Status, String) {
        let response = harness
            .client
            .put(format!("/channels/{channel_id}/afk_idle"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token.to_string()))
            .body(serde_json::to_string(&v0::DataAfkIdle { idle_for }).unwrap())
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    /// A `joined_at` well before every `idle_for` this test claims. A claim
    /// idle for longer than its seat has existed writes nothing (AFK Stage 6
    /// F-A2, `afk_since_predates_join`), so a seat joined at `now` would turn
    /// every "the claim is stored" below into a refusal, and every "nothing
    /// is stored" into a pass for the wrong reason.
    fn joined_long_ago() -> Timestamp {
        Timestamp::now_utc()
            .checked_sub(Duration::minutes(30))
            .expect("a timestamp 30 minutes ago")
    }

    async fn withdraw(harness: &TestHarness, token: &str, channel_id: &str) -> Status {
        harness
            .client
            .delete(format!("/channels/{channel_id}/afk_idle"))
            .header(Header::new("x-session-token", token.to_string()))
            .dispatch()
            .await
            .status()
    }

    #[test]
    fn idle_claim_follows_the_live_seat_and_the_designation() {
        crate::util::test::rt()
            .block_on(idle_claim_follows_the_live_seat_and_the_designation_case())
    }

    async fn idle_claim_follows_the_live_seat_and_the_designation_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (mut server, _channels) = harness.new_server(&user).await;
        let server_id = server.id.clone();
        let lounge = voice_channel(&harness, &server, "Lounge").await;
        let other = voice_channel(&harness, &server, "Other").await;
        let afk = voice_channel(&harness, &server, "AFK").await;

        // Not in the call: refused, nothing written.
        let (status, body) = claim(&harness, &session.token, lounge.id(), 120).await;
        assert_eq!(status, Status::BadRequest, "{body}");
        assert!(body.contains("NotInVoiceChannel"), "{}", body);

        // In the call, but the server moves nobody yet. Each seat is
        // recorded as this session's, as `join_call` records it, so every
        // answer below is for the reason it names and not `NotOwner`.
        let lounge_seat = UserVoiceChannel::from_channel(&lounge);
        create_voice_state(&lounge_seat, &user.id, joined_long_ago())
            .await
            .expect("voice state");
        set_voice_participant_session(lounge.id(), &user.id, &session.id, None)
            .await
            .expect("session record");
        let (status, body) = claim(&harness, &session.token, lounge.id(), 120).await;
        assert_eq!(status, Status::BadRequest, "{body}");
        assert!(body.contains("InvalidOperation"), "{}", body);

        server
            .update(
                &harness.db,
                PartialServer {
                    afk_channel_id: Some(afk.id().to_string()),
                    afk_timeout: Some(300),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("designate");

        let (status, body) = claim(&harness, &session.token, lounge.id(), 120).await;
        assert_eq!(status, Status::NoContent, "{body}");
        let stored = get_afk_since(&user.id, &server_id)
            .await
            .expect("read")
            .expect("the claim is stored");
        assert_eq!(stored.channel_id, lounge.id());

        // Joining another channel of the server moves the pointer: a claim
        // for the old channel no longer names the live seat.
        let other_seat = UserVoiceChannel::from_channel(&other);
        create_voice_state(&other_seat, &user.id, joined_long_ago())
            .await
            .expect("voice state");
        set_voice_participant_session(other.id(), &user.id, &session.id, None)
            .await
            .expect("session record");
        let (status, body) = claim(&harness, &session.token, lounge.id(), 120).await;
        assert_eq!(status, Status::BadRequest, "{body}");
        assert!(body.contains("NotInVoiceChannel"), "{}", body);

        // Withdrawal is authentication only and always answers 204.
        assert_eq!(
            withdraw(&harness, &session.token, lounge.id()).await,
            Status::NoContent
        );
        assert!(get_afk_since(&user.id, &server_id)
            .await
            .expect("read")
            .is_none());

        // R-1: a claim landing after the withdrawal (a stalled PUT) answers
        // 204 but writes nothing while the tombstone stands.
        let (status, body) = claim(&harness, &session.token, other.id(), 120).await;
        assert_eq!(status, Status::NoContent, "{}", body);
        assert!(get_afk_since(&user.id, &server_id)
            .await
            .expect("read")
            .is_none());

        // Idle in the AFK channel itself records nothing.
        let afk_seat = UserVoiceChannel::from_channel(&afk);
        create_voice_state(&afk_seat, &user.id, joined_long_ago())
            .await
            .expect("voice state");
        set_voice_participant_session(afk.id(), &user.id, &session.id, None)
            .await
            .expect("session record");
        let (status, body) = claim(&harness, &session.token, afk.id(), 600).await;
        assert_eq!(status, Status::NoContent, "{body}");
        assert!(get_afk_since(&user.id, &server_id)
            .await
            .expect("read")
            .is_none());

        for seat in [&lounge_seat, &other_seat, &afk_seat] {
            delete_channel_voice_state(seat, &[user.id.clone()])
                .await
                .expect("cleanup");
        }
    }

    /// Merge slice F11: a claim is taken only from the session recorded as
    /// owning the participant. With no record at all, and from a session of
    /// the same user that is not the recorded one, the PUT answers
    /// `NotOwner` (403) and writes nothing, not even a clear; from the
    /// recorded session it is stored.
    #[test]
    fn idle_claim_is_accepted_only_from_the_recorded_session() {
        crate::util::test::rt()
            .block_on(idle_claim_is_accepted_only_from_the_recorded_session_case())
    }

    async fn idle_claim_is_accepted_only_from_the_recorded_session_case() {
        let harness = TestHarness::new().await;
        let (account, desktop, user) = harness.new_user().await;
        let phone = account
            .create_session(&harness.db, "phone".to_string())
            .await
            .expect("a second session");
        let (mut server, _channels) = harness.new_server(&user).await;
        let server_id = server.id.clone();
        let lounge = voice_channel(&harness, &server, "Lounge").await;
        let afk = voice_channel(&harness, &server, "AFK").await;
        server
            .update(
                &harness.db,
                PartialServer {
                    afk_channel_id: Some(afk.id().to_string()),
                    afk_timeout: Some(300),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("designate");

        let lounge_seat = UserVoiceChannel::from_channel(&lounge);
        create_voice_state(&lounge_seat, &user.id, joined_long_ago())
            .await
            .expect("voice state");

        // In the call, but no session is recorded as owning the seat (a
        // join from before the record existed): refused, nothing written.
        let (status, body) = claim(&harness, &desktop.token, lounge.id(), 120).await;
        assert_eq!(status, Status::Forbidden, "{body}");
        assert!(body.contains("NotOwner"), "{}", body);
        assert!(get_afk_since(&user.id, &server_id)
            .await
            .expect("read")
            .is_none());

        // The phone joined: the desktop is the same user, live seat and all,
        // but not the session that owns it.
        set_voice_participant_session(lounge.id(), &user.id, &phone.id, None)
            .await
            .expect("session record");
        let (status, body) = claim(&harness, &desktop.token, lounge.id(), 120).await;
        assert_eq!(status, Status::Forbidden, "{body}");
        assert!(body.contains("NotOwner"), "{}", body);
        assert!(get_afk_since(&user.id, &server_id)
            .await
            .expect("read")
            .is_none());

        // The recorded session claims.
        let (status, body) = claim(&harness, &phone.token, lounge.id(), 120).await;
        assert_eq!(status, Status::NoContent, "{body}");
        let stored = get_afk_since(&user.id, &server_id)
            .await
            .expect("read")
            .expect("the claim is stored");
        assert_eq!(stored.channel_id, lounge.id());

        // A refused claim from the other session changes nothing: with a
        // different `idle_for` an accepted one would move `since`.
        let (status, body) = claim(&harness, &desktop.token, lounge.id(), 600).await;
        assert_eq!(status, Status::Forbidden, "{body}");
        let after = get_afk_since(&user.id, &server_id)
            .await
            .expect("read")
            .expect("the claim still stands");
        assert_eq!(after.channel_id, stored.channel_id);
        assert_eq!(after.since_ms, stored.since_ms);

        delete_channel_voice_state(&lounge_seat, &[user.id.clone()])
            .await
            .expect("cleanup");
    }

    /// `claim`, authenticated as a bot.
    async fn bot_claim(
        harness: &TestHarness,
        bot_token: &str,
        channel_id: &str,
    ) -> (Status, String) {
        let response = harness
            .client
            .put(format!("/channels/{channel_id}/afk_idle"))
            .header(ContentType::JSON)
            .header(Header::new("x-bot-token", bot_token.to_string()))
            .body(serde_json::to_string(&v0::DataAfkIdle { idle_for: 120 }).unwrap())
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    /// Merge slice M2C-7: a bot authenticates with `x-bot-token` and has no
    /// session, and the PUT still answers it in the contract order: the
    /// shape check first (`NotAVoiceChannel` for a text channel), then
    /// `IsBot` for a voice call it sits in, and nothing is stored. A required
    /// session guard failed both requests before any of those checks ran,
    /// with a bare 401 from Rocket's catcher and no error body the client
    /// could read (control M2C-7-GUARD).
    #[test]
    fn a_bot_is_answered_in_the_contract_order() {
        crate::util::test::rt().block_on(a_bot_is_answered_in_the_contract_order_case())
    }

    async fn a_bot_is_answered_in_the_contract_order_case() {
        let harness = TestHarness::new().await;
        let (_, _session, owner) = harness.new_user().await;
        let (mut server, _channels) = harness.new_server(&owner).await;
        let server_id = server.id.clone();
        let (bot, bot_user) = Bot::create(&harness.db, TestHarness::rand_string(), &owner, None)
            .await
            .expect("bot");
        Member::create(&harness.db, &server, &bot_user, None)
            .await
            .expect("member");
        let lounge = voice_channel(&harness, &server, "Lounge").await;
        let afk = voice_channel(&harness, &server, "AFK").await;
        let text = harness.new_channel(&server).await;
        server
            .update(
                &harness.db,
                PartialServer {
                    afk_channel_id: Some(afk.id().to_string()),
                    afk_timeout: Some(300),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("designate");
        let lounge_seat = UserVoiceChannel::from_channel(&lounge);
        create_voice_state(&lounge_seat, &bot_user.id, joined_long_ago())
            .await
            .expect("voice state");

        let (status, body) = bot_claim(&harness, &bot.token, text.id()).await;
        assert_eq!(status, Status::BadRequest, "{body}");
        assert!(body.contains("NotAVoiceChannel"), "{}", body);

        let (status, body) = bot_claim(&harness, &bot.token, lounge.id()).await;
        assert_eq!(status, Status::BadRequest, "{body}");
        assert!(body.contains("IsBot"), "{}", body);
        assert!(get_afk_since(&bot_user.id, &server_id)
            .await
            .expect("read")
            .is_none());

        delete_channel_voice_state(&lounge_seat, &[bot_user.id.clone()])
            .await
            .expect("cleanup");
    }
}
