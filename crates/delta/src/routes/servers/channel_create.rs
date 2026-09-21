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

        // There is no `VoiceChannel` type - a voice channel is a `TextChannel`
        // carrying `voice: Some(..)`, and only the `Voice` arm of
        // `create_server_channel` produces one. The `Voice` arm drops
        // `announcement` silently as the precedent for "this flag applies to
        // one flavour only"; we mirror the intent but reject loudly, because
        // this control was asked for explicitly and a silent drop would leave
        // the caller believing the server had an AFK channel when it does not.
        if !matches!(data.channel_type, v0::LegacyServerChannelType::Voice) {
            return Err(create_error!(InvalidProperty));
        }

        // Closed preset set, in SECONDS, shared with `server_edit`. Never
        // clamped, so a rejected value can never land as a silently different
        // one.
        if let Some(afk_timeout) = afk_timeout {
            Server::validate_afk_timeout(afk_timeout)?;
        }
    }

    let channel = Channel::create_server_channel(db, &mut server, data, true).await?;

    if designate_afk {
        // `Server::validate_afk_channel` is deliberately NOT called here. It
        // exists to prove an id resolves to a voice channel in this server;
        // we just created this channel through the `Voice` arm against this
        // very server, so both properties hold by construction and a re-fetch
        // would only re-read what we already hold.
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
