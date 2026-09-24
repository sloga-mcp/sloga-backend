use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::{
    util::reference::Reference,
    voice::{sync_afk_designation_change, VoiceClient},
    Channel, Database, FieldsServer, PartialServer, Server, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, Result};

use rocket::serde::json::Json;
use rocket::State;
use validator::Validate;

/// # Create Channel
///
/// Create a new Text or Voice channel.
#[openapi(tag = "Server Information")]
#[post("/<server>/channels", data = "<data>")]
pub async fn create_server_channel(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    server: Reference<'_>,
    data: Json<v0::DataCreateServerChannel>,
) -> Result<Json<v0::Channel>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let mut server = server.as_server(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    let permissions = calculate_server_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageChannel)?;

    // The AFK designation is a SERVER-level write (`Server.afk_channel_id`),
    // so it needs `ManageServer` on top of this route's `ManageChannel` - and
    // every check for it has to run BEFORE the channel is created.
    //
    // `Channel::create_server_channel` persists `server.channels` and fans
    // `ChannelCreate` out to every member of the server. A permission or shape
    // check placed after it would 403 the caller with the channel already
    // created and already announced to everybody, leaving an orphan behind.
    // Check first, create second.
    let designate_afk = data.afk == Some(true);
    // The timeout half of the designation, including "Never" (audit A7),
    // decided here so a malformed combination is refused before anything is
    // persisted. See `afk_create_timeout`.
    let (afk_timeout, clear_afk_timeout) =
        afk_create_timeout(designate_afk, data.afk_timeout, data.afk_timeout_never)?;

    if designate_afk {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageServer)?;

        // Same rule `Server::validate_afk_channel` applies to an existing
        // channel, evaluated against the request body because the channel does
        // not exist yet. See `validate_afk_creation_shape`.
        validate_afk_creation_shape(&data)?;

        // Closed preset set, in SECONDS, shared with `server_edit`. Never
        // clamped, so a rejected value can never land as a silently different
        // one.
        if let Some(afk_timeout) = afk_timeout {
            Server::validate_afk_timeout(afk_timeout)?;
        }
    }

    let channel = Channel::create_server_channel(db, &mut server, data, true).await?;

    if designate_afk {
        // `Server::validate_afk_channel` is deliberately NOT called here, but
        // its rule IS enforced - up front, by `validate_afk_creation_shape`,
        // against the request body. Calling the resolving helper at this point
        // would give the same verdict one step too late: the channel is already
        // persisted and already announced, so a rejection here would leave the
        // orphan that checking up front exists to prevent (audit MEDIUM-9).
        //
        // Only the "is it in this server" half holds by construction. The
        // "is it a voice channel" half does not - see
        // `validate_afk_creation_shape` for why.
        //
        // This is a SECOND `ServerUpdate`: `create_server_channel` already
        // emitted one for `server.channels`. Folding the two into one would
        // mean passing `update_server: false` and duplicating both the
        // `server.channels` read-modify-write and the `ChannelCreate` fan-out
        // into this route. That trades one extra websocket frame, on an
        // infrequent action, for a strictly worse failure mode: a write that
        // failed midway would leave a channel that is in no server's channel
        // list and was never announced. Two events, deliberately.
        //
        // A clear cannot travel in a partial: `Server` derives OptionalStruct
        // with `opt_some_priority` and both fields are already `Option<T>`, so
        // the generated assigner is a `replace()` and writing `None` here
        // would be a silent no-op. "Never" therefore clears the server's
        // timeout through `FieldsServer::AfkTimeout` in this same update,
        // which `Server::update` publishes as the `clear` of its one
        // `ServerUpdate`, exactly as `server_edit`'s removal is. Every other
        // request keeps an empty remove list.

        // Captured BEFORE the update mutates `server`, so the re-sync below
        // can still reach the OUTGOING channel.
        let previous_afk_channel_id = server.afk_channel_id.clone();

        server
            .update(
                db,
                PartialServer {
                    afk_channel_id: Some(channel.id().to_string()),
                    afk_timeout,
                    ..Default::default()
                },
                if clear_afk_timeout {
                    vec![FieldsServer::AfkTimeout]
                } else {
                    vec![]
                },
            )
            .await?;

        // A5: the designation just moved, so re-sync BOTH sides. This route
        // writes the same server-level field `server_edit` does, and used to
        // stop at the write - which, once the enforcement gate landed, left
        // the occupants of the OUTGOING channel muted at the SFU with no
        // `UserVoiceStateUpdate` until some unrelated role edit happened to
        // trigger a sync. Over-restrictive rather than a leak, and invisible
        // to the people stuck in it.
        //
        // `server` is the POST-update document, which is what makes one pass
        // enough: the gate reads `afk_channel_id` off it, so the old channel's
        // occupants resolve to their ungated sources and the new channel's to
        // an empty set. The incoming channel was just created, so it has no
        // LiveKit node and `sync_voice_permissions` early-returns on it - the
        // work that matters here is the outgoing side. Passed anyway rather
        // than special-cased, so this route and `server_edit` call the helper
        // the same way.
        sync_afk_designation_change(
            db,
            voice_client,
            &server,
            previous_afk_channel_id.as_deref(),
            Some(&channel),
        )
        .await?;
    }

    Ok(Json(channel.into()))
}

/// Would the channel this request is about to create actually be a valid AFK
/// target?
///
/// `Server::validate_afk_channel` is the shared rule for an *existing*
/// channel: it must resolve, it must be in this server, and it must satisfy
/// `Channel::voice().is_some()`. Creation cannot call it - there is no channel
/// to resolve yet, and calling it after the create is exactly what audit
/// MEDIUM-9 forbids - so the same rule is evaluated against the request body
/// instead, before anything is persisted.
///
/// The "in this server" half genuinely does hold by construction:
/// `Channel::create_server_channel` only ever builds against the server this
/// route already resolved.
///
/// The "is a voice channel" half does NOT hold by construction, which an
/// earlier revision of this route asserted in a comment and skipped the check
/// on. There is no `VoiceChannel` type; a voice channel is a `TextChannel`
/// carrying `voice: Some(..)`, and `Channel::voice()` (channels/model.rs)
/// returns `None` when that `VoiceInformation` has `disabled: true`. The
/// `Voice` arm of `create_server_channel` reads
/// `voice: Some(data.voice.unwrap_or_default().into())` - it *preserves* a
/// client-supplied `disabled: true`. So a body of
/// `{"type":"Voice","afk":true,"voice":{"disabled":true}}` created a channel
/// the repo's own discriminator classifies as NOT a voice channel, and
/// designated it AFK anyway - while `server_edit` rejected the identical
/// designation with `InvalidProperty`. Two writers, two validity rules, the
/// weaker one on the create path. Nothing downstream rescues it either: the
/// pointer-integrity clear in `channel_edit` fires on a de-voicing edit, and
/// for a channel born disabled no such edit ever happens.
///
/// `InvalidProperty` on both arms, matching the sibling rejection inside
/// `Server::validate_afk_channel`. Rejected loudly rather than silently
/// dropped (which is how the `Voice` arm treats `announcement`): the caller
/// asked for this control explicitly, and a silent drop would leave them
/// believing the server has an AFK channel when it does not.
fn validate_afk_creation_shape(data: &v0::DataCreateServerChannel) -> Result<()> {
    if !matches!(data.channel_type, v0::LegacyServerChannelType::Voice) {
        return Err(create_error!(InvalidProperty));
    }

    if data.voice.as_ref().is_some_and(|voice| voice.disabled) {
        return Err(create_error!(InvalidProperty));
    }

    Ok(())
}

/// The timeout half of a creation-time AFK designation (audit A7): the value
/// to write, and whether the server's existing timeout must be cleared in the
/// same update.
///
/// - `afk_timeout_never: true` ("Never") is only meaningful when the request
///   designates and names no timeout; it clears whatever timeout the server
///   already holds. Any other use of it is refused with `InvalidProperty`, the
///   variant this route already uses for AFK validation
///   (`validate_afk_creation_shape`, `Server::validate_afk_timeout`), rather
///   than guessed at.
/// - Otherwise `afk_timeout` is only read alongside `afk: true`, so one sent on
///   its own changes nothing for a request that does not designate, and
///   nothing is cleared: an `afk: true` with no timeout keeps the server's.
fn afk_create_timeout(
    designate_afk: bool,
    afk_timeout: Option<u32>,
    never: Option<bool>,
) -> Result<(Option<u32>, bool)> {
    if never == Some(true) {
        if !designate_afk {
            return Err(create_error!(InvalidProperty));
        }
        if afk_timeout.is_some() {
            return Err(create_error!(InvalidProperty));
        }
        return Ok((None, true));
    }

    Ok((afk_timeout.filter(|_| designate_afk), false))
}

#[cfg(test)]
mod tests {
    use super::{afk_create_timeout, validate_afk_creation_shape};
    use revolt_models::v0;
    use revolt_result::ErrorType;

    fn data(
        channel_type: v0::LegacyServerChannelType,
        voice: Option<v0::VoiceInformation>,
    ) -> v0::DataCreateServerChannel {
        v0::DataCreateServerChannel {
            channel_type,
            name: "AFK".to_string(),
            afk: Some(true),
            voice,
            ..Default::default()
        }
    }

    /// Wave-2 audit finding 1 (HIGH). Regression test.
    ///
    /// The `Voice` arm of `create_server_channel` preserves a client-supplied
    /// `voice.disabled`, and `Channel::voice()` returns `None` for a disabled
    /// one - so this body used to produce a channel that is not a voice
    /// channel and designate it AFK regardless. `server_edit` rejects the
    /// identical designation with `InvalidProperty`; so does this now.
    #[test]
    fn afk_rejects_a_disabled_voice_channel() {
        let error = validate_afk_creation_shape(&data(
            v0::LegacyServerChannelType::Voice,
            Some(v0::VoiceInformation {
                max_users: None,
                disabled: true,
            }),
        ))
        .expect_err("a disabled voice channel is not a voice channel");

        assert!(matches!(error.error_type, ErrorType::InvalidProperty));
    }

    /// The enabled and absent cases must still be accepted, or the rejection
    /// above would read as a pass while having broken the feature outright.
    #[test]
    fn afk_accepts_an_enabled_voice_channel() {
        assert!(validate_afk_creation_shape(&data(
            v0::LegacyServerChannelType::Voice,
            Some(v0::VoiceInformation {
                max_users: Some(5),
                disabled: false,
            }),
        ))
        .is_ok());

        assert!(
            validate_afk_creation_shape(&data(v0::LegacyServerChannelType::Voice, None)).is_ok()
        );
    }

    /// Behavior pin - this arm shipped in wave 2 and is unchanged here. Only
    /// the `Voice` arm of `create_server_channel` can produce a channel with
    /// voice information, so `afk: true` on a Text or Forum channel is
    /// rejected rather than silently dropped.
    #[test]
    fn afk_rejects_non_voice_channel_types() {
        for channel_type in [
            v0::LegacyServerChannelType::Text,
            v0::LegacyServerChannelType::Forum,
        ] {
            let error = validate_afk_creation_shape(&data(channel_type, None))
                .expect_err("only the Voice arm can produce a voice channel");

            assert!(matches!(error.error_type, ErrorType::InvalidProperty));
        }
    }

    // ---- "Never" on create (audit A7) ------------------------------------

    fn refused(designate: bool, timeout: Option<u32>, never: Option<bool>) -> bool {
        match afk_create_timeout(designate, timeout, never) {
            Err(error) => matches!(error.error_type, ErrorType::InvalidProperty),
            Ok(_) => false,
        }
    }

    fn decided(designate: bool, timeout: Option<u32>, never: Option<bool>) -> (Option<u32>, bool) {
        afk_create_timeout(designate, timeout, never).expect("accepted")
    }

    #[test]
    fn never_with_a_timeout_is_refused() {
        assert!(refused(true, Some(300), Some(true)));
    }

    #[test]
    fn never_without_the_designation_is_refused() {
        assert!(refused(false, None, Some(true)));
        assert!(refused(false, Some(300), Some(true)));
    }

    #[test]
    fn never_with_the_designation_clears_the_timeout() {
        assert_eq!(decided(true, None, Some(true)), (None, true));
    }

    /// Every other path keeps an empty remove list: a numeric timeout sets,
    /// no timeout keeps the server's, and a timeout without `afk: true` is
    /// ignored exactly as before.
    #[test]
    fn everything_else_clears_nothing() {
        assert_eq!(decided(true, Some(300), None), (Some(300), false));
        assert_eq!(decided(true, Some(300), Some(false)), (Some(300), false));
        assert_eq!(decided(true, None, None), (None, false));
        assert_eq!(decided(false, Some(300), None), (None, false));
        assert_eq!(decided(false, None, None), (None, false));
    }

    /// `create_server_channel`'s body, comment lines dropped and whitespace
    /// collapsed.
    fn route_body() -> String {
        const SOURCE: &str = include_str!("channel_create.rs");
        let at = SOURCE
            .find("pub async fn create_server_channel(")
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

    /// The route decides through `afk_create_timeout` before the channel
    /// exists, and hands its clear to the SAME update that sets the
    /// designation, so the one `ServerUpdate` carries both.
    #[test]
    fn the_route_uses_the_decision_in_the_designating_update() {
        let body = route_body();
        let at = |needle: &str| {
            body.find(needle)
                .unwrap_or_else(|| panic!("the route lost `{}`: {}", needle, body))
        };

        let decide = at("let (afk_timeout, clear_afk_timeout) = \
             afk_create_timeout(designate_afk, data.afk_timeout, data.afk_timeout_never)?;");
        assert!(decide < at("Channel::create_server_channel("), "{}", body);
        assert!(
            !body.contains(".filter(|_| designate_afk)"),
            "the timeout must come from `afk_create_timeout` alone: {}",
            body
        );

        let update = at(
            "PartialServer \u{7b} afk_channel_id: Some(channel.id().to_string()), \
             afk_timeout, ..Default::default() \u{7d}, \
             if clear_afk_timeout \u{7b} vec![FieldsServer::AfkTimeout] \u{7d} \
             else \u{7b} vec![] \u{7d}, )",
        );
        assert!(decide < update, "{}", body);
        assert_eq!(
            body.matches(".update(").count(),
            1,
            "one server update, carrying both the designation and the clear: {}",
            body
        );
    }

    /// AFK Stage 6 F-B3: `afk: true` writes `Server.afk_channel_id`, a
    /// SERVER-level field, so it needs `ManageServer` on top of the route's
    /// own `ManageChannel` - otherwise a ManageChannel-only moderator can
    /// designate the AFK channel, which hard-mutes everyone in it. And the
    /// check has to run BEFORE `Channel::create_server_channel`, which
    /// persists the channel and announces it to the whole server: a refusal
    /// after it leaves an orphan behind. Mutations: `ManageChannel` in place
    /// of `ManageServer`, the check deleted, or the check moved below the
    /// create.
    #[test]
    fn designating_on_create_needs_manage_server_before_the_channel_exists() {
        let body = route_body();
        const GATE: &str = "if designate_afk \u{7b} \
             permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageServer)?;";

        assert_eq!(
            body.matches(GATE).count(),
            1,
            "`afk: true` must demand ManageServer exactly once, first thing in \
             the designation block: {}",
            body
        );
        assert_eq!(
            body.matches("ChannelPermission::ManageServer").count(),
            1,
            "{}",
            body
        );
        let gate = body.find(GATE).expect("counted above");
        let create = body
            .find("Channel::create_server_channel(")
            .unwrap_or_else(|| panic!("the route no longer creates a channel: {}", body));
        assert!(
            gate < create,
            "ManageServer must be checked BEFORE the channel is created: {}",
            body
        );
    }

    // ---- behavior (needs RabbitMQ) ---------------------------------------
    //
    // Compile-only on a box without RabbitMQ: `TestHarness::new` connects to
    // it, so this fails before it asserts anything there, like every other
    // route test in this crate.

    #[test]
    fn never_on_create_clears_the_servers_timeout() {
        crate::util::test::rt().block_on(never_on_create_clears_the_servers_timeout_case())
    }

    async fn never_on_create_clears_the_servers_timeout_case() {
        use crate::util::test::TestHarness;
        use revolt_database::{events::client::EventV1, PartialServer};
        use rocket::http::{ContentType, Header, Status};

        let mut harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (mut server, _channels) = harness.new_server(&owner).await;
        server
            .update(
                &harness.db,
                PartialServer {
                    afk_timeout: Some(300),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("seed a timeout");

        async fn create(
            harness: &TestHarness,
            token: &str,
            server_id: &str,
            body: serde_json::Value,
        ) -> Status {
            harness
                .client
                .post(format!("/servers/{}/channels", server_id))
                .header(ContentType::JSON)
                .header(Header::new("x-session-token", token.to_string()))
                .body(body.to_string())
                .dispatch()
                .await
                .status()
        }

        // Never together with a timeout is refused.
        let status = create(
            &harness,
            &session.token,
            &server.id,
            serde_json::json!({
                "type": "Voice", "name": "AFK", "afk": true,
                "afk_timeout": 600, "afk_timeout_never": true
            }),
        )
        .await;
        assert_eq!(status, Status::BadRequest);

        let status = create(
            &harness,
            &session.token,
            &server.id,
            serde_json::json!({
                "type": "Voice", "name": "AFK", "afk": true, "afk_timeout_never": true
            }),
        )
        .await;
        assert_eq!(status, Status::Ok);
        let stored = harness.db.fetch_server(&server.id).await.expect("server");
        assert!(stored.afk_channel_id.is_some());
        assert_eq!(stored.afk_timeout, None);

        let server_id = server.id.clone();
        harness
            .wait_for_event(&server_id, |event| {
                matches!(
                    event,
                    EventV1::ServerUpdate { clear, .. }
                        if clear.contains(&v0::FieldsServer::AfkTimeout)
                )
            })
            .await;
    }
}
