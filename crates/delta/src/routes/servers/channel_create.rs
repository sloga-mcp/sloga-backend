use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::{util::reference::Reference, Channel, Database, PartialServer, Server, User};
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
    // Only read alongside `afk: true`. Without this filter an `afk_timeout`
    // sent on its own would change behaviour for requests that do not ask for
    // the designation at all.
    let afk_timeout = data.afk_timeout.filter(|_| designate_afk);

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
        // This only ever SETS. A clear cannot travel in a partial: `Server`
        // derives OptionalStruct with `opt_some_priority` and both fields are
        // already `Option<T>`, so the generated assigner is a `replace()` and
        // writing `None` here would be a silent no-op. Clearing must go
        // through `FieldsServer::AfkChannel` / `FieldsServer::AfkTimeout`.
        server
            .update(
                db,
                PartialServer {
                    afk_channel_id: Some(channel.id().to_string()),
                    afk_timeout,
                    ..Default::default()
                },
                vec![],
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

#[cfg(test)]
mod tests {
    use super::validate_afk_creation_shape;
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

    /// Behaviour pin - this arm shipped in wave 2 and is unchanged here. Only
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
}
