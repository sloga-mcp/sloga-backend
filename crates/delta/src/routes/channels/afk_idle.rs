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

use revolt_config::config;
use revolt_database::{
    util::{permissions::perms, reference::Reference},
    voice::{
        afk_idle::{clear_afk_since, set_afk_since, withdraw_afk_since},
        get_user_voice_channel_in_server, is_in_voice_channel, UserVoiceChannel,
    },
    Database, User,
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
/// nothing; repeating it only keeps the claim alive.
#[openapi(tag = "Voice")]
#[put("/<target>/afk_idle", data = "<data>")]
pub async fn afk_idle_set(
    db: &State<Database>,
    user: User,
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
            UserVoiceChannel,
        },
        Channel, PartialServer, Server,
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

        // In the call, but the server moves nobody yet.
        let lounge_seat = UserVoiceChannel::from_channel(&lounge);
        create_voice_state(&lounge_seat, &user.id, joined_long_ago())
            .await
            .expect("voice state");
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
}
