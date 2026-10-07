use std::collections::HashSet;

use revolt_database::{
    util::{
        audit_reason::AuditLogReason, permissions::DatabasePermissionQuery, reference::Reference,
    },
    voice::{sync_afk_designation_change, VoiceClient},
    AuditLogAction, AuditLogChange, AuditLogDraft, AuditLogEntry, AuditValue, Database, File,
    PartialServer, Server, User, ValidatedTicket,
};
use revolt_models::v0;
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use validator::Validate;

/// # Edit Server
///
/// Edit a server by its id.
#[openapi(tag = "Server Information")]
#[patch("/<target>", data = "<data>")]
pub async fn edit(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataEditServer>,
    validated_ticket: Option<ValidatedTicket>,
    reason: AuditLogReason,
) -> Result<Json<v0::Server>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Validated before anything is read or written, so an over-long reason
    // refuses the whole edit instead of failing after the edit has landed.
    let reason = reason.validated()?;

    let mut server = target.as_server(db).await?;
    // Audit M2: the audit log's "before" values, taken straight after the
    // load. Further down, the icon, banner and owner are written into
    // `server` in place ahead of the update, and `update` then applies the
    // whole partial to it, so a snapshot taken any later would record the new
    // values as the old ones.
    let server_before_edit = server.clone();
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    let permissions = calculate_server_permissions(&mut query).await;

    // Check permissions. The decision is `edit_authorization`, by value; this
    // route has no membership precondition, so this match is the only thing
    // standing between an arbitrary account and every ManageServer field.
    match edit_authorization(&data) {
        EditAuthorization::NothingToEdit => return Ok(Json(server.into())),
        EditAuthorization::ManageServer => {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageServer)?;
        }
        EditAuthorization::FieldGatesOnly => {}
    }

    // A voice region must name a configured LiveKit node; "Auto" is expressed
    // by removing the field, never by a sentinel value.
    if let Some(voice_region) = &data.voice_region {
        if !revolt_config::config()
            .await
            .api
            .livekit
            .nodes
            .contains_key(voice_region)
        {
            return Err(create_error!(UnknownNode));
        }
    }

    // Shape rules for the AFK pair that need no database round-trip: the
    // set-and-remove collision, and "a timeout is meaningless without a
    // channel". Runs BEFORE the resolving validation below so a request that
    // is self-contradictory is refused on its own terms rather than on
    // whichever half happened to be looked up first.
    validate_afk_edit(server.afk_channel_id.as_deref(), &data)?;

    // The AFK designation must resolve to a voice channel in THIS server.
    // Validated here, before the destructure, mirroring the voice_region check
    // directly above. The resolved channel is kept so the A5 re-sync at the end
    // of this route does not have to fetch it a second time.
    let incoming_afk_channel = if let Some(afk_channel_id) = &data.afk_channel_id {
        Some(Server::validate_afk_channel(db, &server.id, afk_channel_id).await?)
    } else {
        None
    };

    // Idle timeout is a closed preset set, in SECONDS. Never clamped, so a
    // rejected value can never land as a silently different one.
    if let Some(afk_timeout) = data.afk_timeout {
        Server::validate_afk_timeout(afk_timeout)?;
    }

    // Captured BEFORE the update mutates `server`, so the A5 re-sync below can
    // still reach the OUTGOING channel. Note clearing never travels in the
    // partial: `Server` derives OptionalStruct with opt_some_priority and these
    // fields are already Option<T>, so the generated assigner is a `replace()`
    // and writing `afk_channel_id: None` into the partial is a silent no-op.
    // A clear must arrive as FieldsServer::AfkChannel in `remove`.
    let previous_afk_channel_id = server.afk_channel_id.clone();

    // Check we are the server owner or privileged if changing sensitive fields
    if data.owner.is_some() {
        if user.id != server.owner && !user.privileged {
            return Err(create_error!(NotOwner));
        }

        if validated_ticket.is_none() {
            return Err(create_error!(InvalidCredentials));
        }
    }

    // Check we are privileged if changing sensitive fields
    if data.flags.is_some() /*|| data.nsfw.is_some()*/ && !user.privileged {
        return Err(create_error!(NotPrivileged));
    }

    // Discovery gating, fail closed. server_edit has NO membership
    // precondition, so every arm must reject explicitly:
    // - listing (`discoverable: true`) is admin approval — privileged only
    // - delisting (`discoverable: false`) — owner or privileged, so an owner
    //   can withdraw public exposure without an admin round-trip
    // - `discovery_requested` (any value) — owner or privileged (privileged
    //   path is admin rejection); NOT ManageServer: publicly listing a
    //   community is an owner-level decision
    let is_owner_or_privileged = user.id == server.owner || user.privileged;
    match data.discoverable {
        Some(true) if !user.privileged => return Err(create_error!(NotPrivileged)),
        Some(false) if !is_owner_or_privileged => return Err(create_error!(NotPrivileged)),
        _ => {}
    }
    if data.discovery_requested.is_some() && !is_owner_or_privileged {
        return Err(create_error!(NotPrivileged));
    }

    // Changing categories requires manage channel
    if data.categories.is_some() {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageChannel)?;
    }

    let v0::DataEditServer {
        name,
        description,
        icon,
        banner,
        categories,
        system_messages,
        flags,
        // nsfw,
        discoverable,
        discovery_requested,
        analytics,
        voice_region,
        afk_channel_id,
        afk_timeout,
        owner,
        mut remove,
    } = data;

    // One rule, five writers: `AfkTimeout` is meaningless without
    // `AfkChannel`. The five are this route, `channel_create`, the Discord
    // import worker, the revision-72 migration and
    // `Server::clear_afk_channel_if_pointing_at` (from `channel_edit`'s
    // de-voice block and `Channel::delete`). Only the two routes re-sync
    // grants; the helper needs none, because both of its callers tear the
    // room down (see `sync_afk_designation_change`).
    // `validate_afk_edit` enforces the "setting a timeout needs
    // a channel" half by rejection; this is the other half, which has to be an
    // action rather than a rejection because clearing the channel is a
    // perfectly valid request that simply must not leave an orphan timeout
    // behind. `Server::clear_afk_channel_if_pointing_at` clears both for the
    // same reason - see its doc comment, which states the rule once.
    if remove.contains(&v0::FieldsServer::AfkChannel)
        && !remove.contains(&v0::FieldsServer::AfkTimeout)
    {
        remove.push(v0::FieldsServer::AfkTimeout);
    }

    // Any explicit transition of `discoverable` clears the pending request:
    // approval consumes it, delisting withdraws it. Set server-side, never
    // trusting the client to couple the two.
    let discovery_requested = if discoverable.is_some() {
        Some(false)
    } else {
        discovery_requested
    };

    let mut partial = PartialServer {
        name,
        description,
        categories: categories.map(|v| v.into_iter().map(Into::into).collect()),
        system_messages: system_messages.map(Into::into),
        flags,
        // nsfw,
        discoverable,
        discovery_requested,
        analytics,
        voice_region,
        afk_channel_id,
        afk_timeout,
        owner: owner.clone(),
        ..Default::default()
    };

    // 1. Remove fields from object
    if remove.contains(&v0::FieldsServer::Banner) {
        if let Some(banner) = &server.banner {
            db.mark_attachment_as_deleted(&banner.id).await?;
        }
    }

    if remove.contains(&v0::FieldsServer::Icon) {
        if let Some(icon) = &server.icon {
            db.mark_attachment_as_deleted(&icon.id).await?;
        }
    }

    // 2. Validate changes
    if let Some(system_messages) = &partial.system_messages {
        for id in system_messages.clone().into_channel_ids() {
            if !server.channels.contains(&id) {
                return Err(create_error!(NotFound));
            }
        }
    }

    if let Some(categories) = &mut partial.categories {
        let mut channel_ids = HashSet::new();
        for category in categories {
            for channel in &category.channels {
                if channel_ids.contains(channel) {
                    return Err(create_error!(InvalidOperation));
                }

                channel_ids.insert(channel.to_string());
            }

            category
                .channels
                .retain(|item| server.channels.contains(item));
        }
    }

    // 3. Apply new icon
    if let Some(icon) = icon {
        partial.icon = Some(File::use_server_icon(db, &icon, &server.id, &user.id).await?);
        server.icon = partial.icon.clone();
    }

    // 4. Apply new banner
    if let Some(banner) = banner {
        partial.banner = Some(File::use_server_banner(db, &banner, &server.id, &user.id).await?);
        server.banner = partial.banner.clone();
    }

    // 5. Transfer ownership
    if let Some(owner) = owner {
        let owner_reference = Reference::from_unchecked(&owner);
        // Check if member exists
        owner_reference.as_member(db, &server.id).await?;
        let owner_user = owner_reference.as_user(db).await?;

        if owner_user.bot.is_some() {
            return Err(create_error!(InvalidOperation));
        }

        server.owner = owner;
        partial.owner = Some(server.owner.clone());
    }

    server
        .update(db, partial, remove.into_iter().map(Into::into).collect())
        .await?;

    // Written only once the edit is persisted, and before the voice re-sync
    // below: that sync can still return an error, which must not lose the
    // record of an edit that has already landed.
    record_audit_entries(db, &user, &server_before_edit, &server, reason).await;

    // A5: re-sync voice permissions on BOTH sides of a designation change.
    // Without this, flagging an already-occupied channel is inert until some
    // unrelated role or permission edit happens to trigger a sync.
    //
    // Shared with `channel_create`, which writes the same server field and
    // used to do none of this. The two failure modes the helper keeps apart -
    // a swallowed resolve on the outgoing side, a propagating `?` on the sync
    // itself - are documented on it.
    //
    // `server` is passed POST-update on purpose: the gate reads
    // `afk_channel_id` off it.
    sync_afk_designation_change(
        db,
        voice_client,
        &server,
        previous_afk_channel_id.as_deref(),
        incoming_afk_channel.as_ref(),
    )
    .await?;

    Ok(Json(server.into()))
}

/// Write the audit log entries for an edit that has been persisted.
///
/// Two kinds, kept apart so that filtering on either one finds it:
/// - `server_update`, with one change per field the edit actually changed
///   (see `server_update_changes`). Skipped when there is none; the owner
///   does not count.
/// - `server_owner_transfer`, targeting the new owner, whenever the owner
///   changed. It is written even when the actor IS the new owner (a
///   privileged account taking a server over): that is a change of control
///   over the server, not a self-edit, and staff actions are logged under the
///   staff member's own name.
///
/// Fields only privileged accounts may edit (`flags`, `discoverable`) are
/// logged like any other.
async fn record_audit_entries(
    db: &Database,
    actor: &User,
    before: &Server,
    after: &Server,
    reason: Option<String>,
) {
    let changes = server_update_changes(before, after);
    if !changes.is_empty() {
        AuditLogEntry::record(
            db,
            AuditLogDraft {
                server: after.id.clone(),
                actor: Some(actor.id.clone()),
                action: AuditLogAction::ServerUpdate,
                changes,
                reason: reason.clone(),
                ..Default::default()
            },
        )
        .await;
    }

    if before.owner != after.owner {
        AuditLogEntry::record(
            db,
            AuditLogDraft {
                server: after.id.clone(),
                actor: Some(actor.id.clone()),
                action: AuditLogAction::ServerOwnerTransfer,
                target: Some(after.owner.clone()),
                changes: vec![AuditLogChange::new(
                    "owner",
                    Some(AuditValue::String(before.owner.clone())),
                    Some(AuditValue::String(after.owner.clone())),
                )],
                reason,
                ..Default::default()
            },
        )
        .await;
    }
}

/// The `server_update` changes between the server as loaded before an edit
/// and as persisted after it.
///
/// One change for each field `DataEditServer` can set or `FieldsServer` can
/// remove, and only when the stored value really differs, so saving an
/// unchanged settings form records nothing. `owner` is left out on purpose:
/// it gets its own `server_owner_transfer` entry. Value shapes:
/// - Scalars carry old and new with their natural type. A field that was
///   unset has no `old`; a removed field has no `new`.
/// - `icon` / `banner` carry only `new`: `Bool(true)` when one was set or
///   replaced, `Bool(false)` when it was removed. File ids are not recorded.
/// - `categories` / `system_messages` are structured, so they carry only
///   `new: Bool(true)`, which means "changed" (set, edited or removed alike).
///   Their contents are not copied into the log.
fn server_update_changes(before: &Server, after: &Server) -> Vec<AuditLogChange> {
    fn push_if_changed(
        changes: &mut Vec<AuditLogChange>,
        key: &str,
        old: Option<AuditValue>,
        new: Option<AuditValue>,
    ) {
        if old != new {
            changes.push(AuditLogChange::new(key, old, new));
        }
    }

    fn changed_marker(changes: &mut Vec<AuditLogChange>, key: &str, changed: bool, new: bool) {
        if changed {
            changes.push(AuditLogChange::new(key, None, Some(AuditValue::Bool(new))));
        }
    }

    let text = |value: &Option<String>| value.clone().map(AuditValue::String);
    let file_id = |file: &Option<File>| file.as_ref().map(|file| file.id.clone());

    let mut changes = Vec::new();
    push_if_changed(
        &mut changes,
        "name",
        Some(AuditValue::String(before.name.clone())),
        Some(AuditValue::String(after.name.clone())),
    );
    push_if_changed(
        &mut changes,
        "description",
        text(&before.description),
        text(&after.description),
    );
    changed_marker(
        &mut changes,
        "icon",
        file_id(&before.icon) != file_id(&after.icon),
        after.icon.is_some(),
    );
    changed_marker(
        &mut changes,
        "banner",
        file_id(&before.banner) != file_id(&after.banner),
        after.banner.is_some(),
    );
    changed_marker(
        &mut changes,
        "categories",
        before.categories != after.categories,
        true,
    );
    changed_marker(
        &mut changes,
        "system_messages",
        before.system_messages != after.system_messages,
        true,
    );
    push_if_changed(
        &mut changes,
        "flags",
        before.flags.map(|flags| AuditValue::Int(flags.into())),
        after.flags.map(|flags| AuditValue::Int(flags.into())),
    );
    push_if_changed(
        &mut changes,
        "discoverable",
        Some(AuditValue::Bool(before.discoverable)),
        Some(AuditValue::Bool(after.discoverable)),
    );
    push_if_changed(
        &mut changes,
        "discovery_requested",
        Some(AuditValue::Bool(before.discovery_requested)),
        Some(AuditValue::Bool(after.discovery_requested)),
    );
    push_if_changed(
        &mut changes,
        "analytics",
        Some(AuditValue::Bool(before.analytics)),
        Some(AuditValue::Bool(after.analytics)),
    );
    push_if_changed(
        &mut changes,
        "voice_region",
        text(&before.voice_region),
        text(&after.voice_region),
    );
    push_if_changed(
        &mut changes,
        "afk_channel_id",
        text(&before.afk_channel_id),
        text(&after.afk_channel_id),
    );
    push_if_changed(
        &mut changes,
        "afk_timeout",
        before
            .afk_timeout
            .map(|seconds| AuditValue::Int(seconds.into())),
        after
            .afk_timeout
            .map(|seconds| AuditValue::Int(seconds.into())),
    );

    changes
}

/// What `edit` demands of the caller before any field-specific gate runs.
#[derive(Debug, PartialEq, Eq)]
enum EditAuthorization {
    /// The request changes nothing. Answered with the current server and no
    /// permission check, as it always has been.
    NothingToEdit,
    /// At least one field in the request needs `ManageServer`.
    ManageServer,
    /// Only fields that carry their own gate further down the route: `flags`
    /// (privileged), `discoverable` / `discovery_requested` (privileged or
    /// owner), `owner` (owner plus a validated ticket) and `categories`
    /// (`ManageChannel`).
    FieldGatesOnly,
}

/// Which edits need `ManageServer` (AFK Stage 6 F-B1).
///
/// Extracted from the route unchanged, so it can be pinned by value.
/// `server_edit` has NO membership precondition: a field that should be on
/// the `ManageServer` arm but is not lands with no authorization at all, from
/// any account, on any server. `afk_channel_id` and `afk_timeout` are the
/// sharp case - designating an AFK channel hard-mutes everyone in it, the
/// owner included, and deleting either term used to leave every test green.
///
/// `data` is destructured with no `..`, so a field added to `DataEditServer`
/// does not compile here until it has been placed on one side or the other.
/// A field missing from the first arm would be silently discarded by the
/// early return; one missing from the second would skip `ManageServer`.
fn edit_authorization(data: &v0::DataEditServer) -> EditAuthorization {
    let v0::DataEditServer {
        name,
        description,
        icon,
        banner,
        categories,
        system_messages,
        flags,
        // nsfw,
        discoverable,
        discovery_requested,
        analytics,
        voice_region,
        afk_channel_id,
        afk_timeout,
        owner,
        remove,
    } = data;

    if name.is_none()
        && description.is_none()
        && icon.is_none()
        && banner.is_none()
        && system_messages.is_none()
        && categories.is_none()
        // && nsfw.is_none()
        && flags.is_none()
        && analytics.is_none()
        && discoverable.is_none()
        && discovery_requested.is_none()
        && voice_region.is_none()
        && afk_channel_id.is_none()
        && afk_timeout.is_none()
        && owner.is_none()
        && remove.is_empty()
    {
        EditAuthorization::NothingToEdit
    } else if name.is_some()
        || description.is_some()
        || icon.is_some()
        || banner.is_some()
        || system_messages.is_some()
        || analytics.is_some()
        || voice_region.is_some()
        || afk_channel_id.is_some()
        || afk_timeout.is_some()
        || !remove.is_empty()
    {
        EditAuthorization::ManageServer
    } else {
        EditAuthorization::FieldGatesOnly
    }
}

/// The AFK edit rules that need no database round-trip.
///
/// Two defects, one place:
///
/// 1. SET-AND-REMOVE COLLISION. `{"afk_channel_id":"X","remove":["AfkChannel"]}`
///    asks to set and clear one field in a single edit, and the two drivers
///    disagree about the result. `MongoDb` builds one
///    `{"$set":.., "$unset":..}` document with no de-duplication
///    (`drivers/mongodb.rs`) and Mongo rejects the conflicting path outright;
///    `Reference` applies `remove_field` first and then `apply_options`, so it
///    lands on `Some("X")`. Either way the `ServerUpdate` that fans out
///    carries the set AND the clear and contradicts itself. `member_edit`
///    refuses exactly this class - for `CanPublish`, `CanReceive` and
///    `VoiceChannel` - with `InvalidOperation`, and documents the reasoning;
///    this is the same refusal, for the same reason, on the same grounds.
///
/// 2. ORPHAN TIMEOUT. `afk_timeout` has meaning only relative to a
///    destination, so it is refused unless a channel is designated once this
///    edit lands: either one is arriving in this same request, or the server
///    already has one and this request is not removing it. `InvalidProperty`,
///    matching how `Server::validate_afk_timeout` rejects an out-of-set value.
///
/// The other half of rule 2 - clearing the channel clears the timeout - is an
/// action rather than a rejection and lives at the call site, because clearing
/// the channel is a perfectly valid request that simply must not leave an
/// orphan behind. `Server::clear_afk_channel_if_pointing_at` states the whole
/// rule once in its doc comment, and lists the five writers it binds; this is
/// one of them.
///
/// `voice_region` has the same collision gap today. That is a second instance
/// of the same bug, deliberately left out of scope here - not a reason to
/// think the gap is acceptable.
fn validate_afk_edit(
    current_afk_channel_id: Option<&str>,
    data: &v0::DataEditServer,
) -> Result<()> {
    if (data.afk_channel_id.is_some() && data.remove.contains(&v0::FieldsServer::AfkChannel))
        || (data.afk_timeout.is_some() && data.remove.contains(&v0::FieldsServer::AfkTimeout))
    {
        return Err(create_error!(InvalidOperation));
    }

    if data.afk_timeout.is_some() {
        let designated_after_this_edit = data.afk_channel_id.is_some()
            || (current_afk_channel_id.is_some()
                && !data.remove.contains(&v0::FieldsServer::AfkChannel));

        if !designated_after_this_edit {
            return Err(create_error!(InvalidProperty));
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::{
        AuditLogAction, AuditLogChange, AuditLogEntry, AuditValue, File, MFATicket, Member,
        Metadata, PartialUser, Server, Session, User,
    };
    use revolt_models::v0;
    use revolt_result::ErrorType;
    use rocket::http::{ContentType, Header, Status};

    async fn edit(
        harness: &TestHarness,
        server_id: &str,
        session: &Session,
        body: serde_json::Value,
    ) -> Status {
        harness
            .client
            .patch(format!("/servers/{}", server_id))
            .header(ContentType::JSON)
            .body(body.to_string())
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await
            .status()
    }

    /// Audit MAJOR 5: server_edit has no membership precondition, so every
    /// discovery arm must fail closed on its own.
    #[test]
    fn discovery_gating_fail_closed() {
        crate::util::test::rt().block_on(discovery_gating_fail_closed_case())
    }

    async fn discovery_gating_fail_closed_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member_user) = harness.new_user().await;
        let (_, outsider_session, _) = harness.new_user().await;
        let (_, admin_session, mut admin) = harness.new_user().await;

        admin
            .update(
                &harness.db,
                PartialUser {
                    privileged: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("privileged admin");

        let (server, _) = Server::create(
            &harness.db,
            v0::DataCreateServer {
                name: "Gated".to_string(),
                ..Default::default()
            },
            &owner,
            true,
        )
        .await
        .expect("`Server`");

        Member::create(&harness.db, &server, &member_user, None)
            .await
            .expect("`Member`");

        // Non-owner member: every discovery field is rejected.
        for body in [
            json!({ "discovery_requested": true }),
            json!({ "discovery_requested": false }),
            json!({ "discoverable": true }),
            json!({ "discoverable": false }),
        ] {
            assert_eq!(
                edit(&harness, &server.id, &member_session, body).await,
                Status::Forbidden
            );
        }

        // Non-member authenticated user: same, fail closed.
        for body in [
            json!({ "discovery_requested": true }),
            json!({ "discovery_requested": false }),
            json!({ "discoverable": true }),
            json!({ "discoverable": false }),
        ] {
            assert_eq!(
                edit(&harness, &server.id, &outsider_session, body).await,
                Status::Forbidden
            );
        }

        // Owner cannot list their own server (admin approval required)...
        assert_eq!(
            edit(
                &harness,
                &server.id,
                &owner_session,
                json!({ "discoverable": true })
            )
            .await,
            Status::Forbidden
        );

        // ...but can request a listing...
        assert_eq!(
            edit(
                &harness,
                &server.id,
                &owner_session,
                json!({ "discovery_requested": true })
            )
            .await,
            Status::Ok
        );
        let fetched = harness.db.fetch_server(&server.id).await.unwrap();
        assert!(fetched.discovery_requested);
        assert!(!fetched.discoverable);

        // ...and privileged approval flips discoverable AND consumes the
        // pending request server-side.
        assert_eq!(
            edit(
                &harness,
                &server.id,
                &admin_session,
                json!({ "discoverable": true })
            )
            .await,
            Status::Ok
        );
        let fetched = harness.db.fetch_server(&server.id).await.unwrap();
        assert!(fetched.discoverable);
        assert!(!fetched.discovery_requested);

        // Owner can instantly delist without an admin round-trip.
        assert_eq!(
            edit(
                &harness,
                &server.id,
                &owner_session,
                json!({ "discoverable": false })
            )
            .await,
            Status::Ok
        );
        let fetched = harness.db.fetch_server(&server.id).await.unwrap();
        assert!(!fetched.discoverable);
        assert!(!fetched.discovery_requested);
    }

    /// Wave-2 audit finding 2 (MEDIUM). Regression test.
    ///
    /// Setting and removing the same field in one edit diverged by driver:
    /// Mongo rejected the conflicting `$set`/`$unset` path pair, the reference
    /// driver landed on the set value, and the event carried both. Refused
    /// here the way `member_edit` refuses its three equivalents.
    #[test]
    fn afk_set_and_remove_in_one_edit_is_refused() {
        for body in [
            json!({ "afk_channel_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV", "remove": ["AfkChannel"] }),
            json!({ "afk_timeout": 300, "remove": ["AfkTimeout"] }),
            // Both pairs at once, plus an unrelated field, still refused.
            json!({
                "name": "Somewhere",
                "afk_channel_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "afk_timeout": 300,
                "remove": ["AfkChannel", "AfkTimeout"]
            }),
        ] {
            let data: v0::DataEditServer = serde_json::from_value(body).expect("`DataEditServer`");
            let error = super::validate_afk_edit(None, &data)
                .expect_err("set-and-remove of one field must be refused");

            assert!(matches!(error.error_type, ErrorType::InvalidOperation));
        }
    }

    /// Wave-2 audit finding 4 (LOW). Regression test for one half of the rule:
    /// `AfkTimeout` is meaningless without `AfkChannel`, so a timeout is only
    /// accepted when a channel is designated once the edit lands.
    #[test]
    fn afk_timeout_requires_a_designated_channel() {
        // No channel on the server, none arriving.
        let data: v0::DataEditServer =
            serde_json::from_value(json!({ "afk_timeout": 300 })).expect("`DataEditServer`");
        let error = super::validate_afk_edit(None, &data)
            .expect_err("a timeout with no destination is meaningless");
        assert!(matches!(error.error_type, ErrorType::InvalidProperty));

        // A channel is being cleared in the same edit, so none remains.
        let data: v0::DataEditServer =
            serde_json::from_value(json!({ "afk_timeout": 300, "remove": ["AfkChannel"] }))
                .expect("`DataEditServer`");
        let error = super::validate_afk_edit(Some("01ARZ3NDEKTSV4RRFFQ69G5FAV"), &data)
            .expect_err("clearing the channel leaves the timeout orphaned");
        assert!(matches!(error.error_type, ErrorType::InvalidProperty));

        // Channel arriving in the same request: accepted.
        let data: v0::DataEditServer = serde_json::from_value(
            json!({ "afk_channel_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV", "afk_timeout": 300 }),
        )
        .expect("`DataEditServer`");
        assert!(super::validate_afk_edit(None, &data).is_ok());

        // Channel already designated and not being removed: accepted.
        let data: v0::DataEditServer =
            serde_json::from_value(json!({ "afk_timeout": 300 })).expect("`DataEditServer`");
        assert!(super::validate_afk_edit(Some("01ARZ3NDEKTSV4RRFFQ69G5FAV"), &data).is_ok());
    }

    /// Guard against the two rules above turning into a blanket refusal:
    /// edits that say nothing about AFK must pass through untouched, and so
    /// must a plain designation or a plain clear.
    #[test]
    fn afk_rules_leave_unrelated_edits_alone() {
        for (current, body) in [
            (None, json!({})),
            (None, json!({ "name": "Somewhere" })),
            (None, json!({ "remove": ["Banner", "Icon"] })),
            (
                None,
                json!({ "afk_channel_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV" }),
            ),
            (
                Some("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
                json!({ "remove": ["AfkChannel"] }),
            ),
            (
                Some("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
                json!({ "remove": ["AfkTimeout"] }),
            ),
        ] {
            let data: v0::DataEditServer = serde_json::from_value(body).expect("`DataEditServer`");
            assert!(super::validate_afk_edit(current, &data).is_ok());
        }
    }

    // ---- which edits need ManageServer (AFK Stage 6 F-B1) ----------------

    fn authorization(body: serde_json::Value) -> super::EditAuthorization {
        let data: v0::DataEditServer =
            serde_json::from_value(body.clone()).expect("`DataEditServer`");
        super::edit_authorization(&data)
    }

    /// The AFK pair, each on its own. This route has no membership check, so
    /// without these an arbitrary account could designate another server's
    /// AFK channel - hard-muting everyone in it, the owner too.
    #[test]
    fn the_afk_fields_each_need_manage_server_on_their_own() {
        for body in [
            json!({ "afk_channel_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV" }),
            json!({ "afk_timeout": 300 }),
            json!({ "remove": ["AfkChannel"] }),
            json!({ "remove": ["AfkTimeout"] }),
        ] {
            assert_eq!(
                authorization(body.clone()),
                super::EditAuthorization::ManageServer,
                "{body} must need ManageServer"
            );
        }
    }

    /// Every other field that needed ManageServer before the extraction still
    /// does, one at a time, and so does every `remove` entry.
    #[test]
    fn every_other_manage_server_field_still_needs_it() {
        for body in [
            json!({ "name": "Somewhere" }),
            json!({ "description": "About" }),
            json!({ "icon": "01ARZ3NDEKTSV4RRFFQ69G5FAV" }),
            json!({ "banner": "01ARZ3NDEKTSV4RRFFQ69G5FAV" }),
            json!({ "system_messages": {} }),
            json!({ "analytics": true }),
            json!({ "voice_region": "worldwide" }),
            json!({ "remove": ["Description"] }),
            json!({ "remove": ["Categories"] }),
            json!({ "remove": ["SystemMessages"] }),
            json!({ "remove": ["Icon"] }),
            json!({ "remove": ["Banner"] }),
            json!({ "remove": ["VoiceRegion"] }),
            // A field with its own gate never waives ManageServer for a
            // ManageServer field in the same request.
            json!({ "flags": 1, "afk_channel_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV" }),
            json!({ "owner": "01ARZ3NDEKTSV4RRFFQ69G5FAV", "afk_timeout": 300 }),
        ] {
            assert_eq!(
                authorization(body.clone()),
                super::EditAuthorization::ManageServer,
                "{body} must need ManageServer"
            );
        }
    }

    /// The fields that never needed ManageServer keep that answer: each is
    /// gated further down the route on its own terms (privileged, owner, or
    /// ManageChannel). Pinned so the extraction changed nothing.
    #[test]
    fn fields_with_their_own_gate_do_not_need_manage_server() {
        for body in [
            json!({ "categories": [] }),
            json!({ "flags": 1 }),
            json!({ "discoverable": true }),
            json!({ "discoverable": false }),
            json!({ "discovery_requested": true }),
            json!({ "owner": "01ARZ3NDEKTSV4RRFFQ69G5FAV" }),
        ] {
            assert_eq!(
                authorization(body.clone()),
                super::EditAuthorization::FieldGatesOnly,
                "{body} is gated elsewhere in the route"
            );
        }
    }

    /// The empty edit is the early return, unchecked, as before.
    #[test]
    fn the_empty_edit_changes_nothing() {
        for body in [json!({}), json!({ "remove": [] })] {
            assert_eq!(
                authorization(body.clone()),
                super::EditAuthorization::NothingToEdit,
                "{body} is the no-op"
            );
        }
    }

    /// `edit`'s body, comment lines dropped and whitespace collapsed.
    fn route_body() -> String {
        const SOURCE: &str = include_str!("server_edit.rs");
        let at = SOURCE
            .find("pub async fn edit(")
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

    /// The value tests above only matter if the route acts on the answer: it
    /// calls `edit_authorization` once, returns on `NothingToEdit`, demands
    /// `ManageServer` on `ManageServer`, and does so before it validates,
    /// writes or syncs anything.
    #[test]
    fn the_route_demands_manage_server_from_the_decision() {
        let body = route_body();
        const GATE: &str = "match edit_authorization(&data) \u{7b} \
             EditAuthorization::NothingToEdit => return Ok(Json(server.into())), \
             EditAuthorization::ManageServer => \u{7b} \
             permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageServer)?; \
             \u{7d} EditAuthorization::FieldGatesOnly => \u{7b}\u{7d} \u{7d}";

        assert_eq!(
            body.matches(GATE).count(),
            1,
            "the route must gate on `edit_authorization` exactly once: {body}"
        );
        assert_eq!(body.matches("edit_authorization(").count(), 1, "{body}");
        let gate = body.find(GATE).expect("counted above");
        for later in [
            "validate_afk_edit(",
            "Server::validate_afk_channel(",
            "db.mark_attachment_as_deleted(",
            ".update(db, partial,",
            "sync_afk_designation_change(",
        ] {
            let at = body
                .find(later)
                .unwrap_or_else(|| panic!("the route lost `{}`: {}", later, body));
            assert!(gate < at, "the gate must precede `{}`: {}", later, body);
        }
    }

    // ---- audit log (moderation slice 1) -----------------------------------

    /// Where the audit trail sits in the route:
    /// - the reason is validated before the server is even loaded, so an
    ///   over-long reason refuses the edit instead of failing after it;
    /// - the "before" snapshot is the very next statement after the load,
    ///   ahead of the in-place icon / banner / owner writes (audit M2);
    /// - the entries are written after the update and before the voice
    ///   re-sync, whose `?` must not lose the record of a landed edit.
    #[test]
    fn the_route_audits_from_a_snapshot_taken_before_any_write() {
        let body = route_body();

        assert_eq!(
            body.matches(
                "let mut server = target.as_server(db).await?; \
                 let server_before_edit = server.clone();"
            )
            .count(),
            1,
            "the snapshot must directly follow the load: {body}"
        );

        let mut previous = 0;
        for step in [
            "let reason = reason.validated()?;",
            "let mut server = target.as_server(db).await?;",
            "match edit_authorization(&data)",
            "db.mark_attachment_as_deleted(",
            "server.icon = partial.icon.clone();",
            "server.banner = partial.banner.clone();",
            "server.owner = owner;",
            ".update(db, partial,",
            "record_audit_entries(db, &user, &server_before_edit, &server, reason).await;",
            "sync_afk_designation_change(",
        ] {
            let at = body
                .find(step)
                .unwrap_or_else(|| panic!("the route lost `{}`: {}", step, body));
            assert!(previous <= at, "`{}` is out of order: {}", step, body);
            previous = at;
        }
        assert_eq!(body.matches("record_audit_entries(").count(), 1, "{body}");
    }

    /// PATCH the server with the optional `X-Audit-Log-Reason` and
    /// `X-MFA-Ticket` headers. Returns the status and the response body.
    async fn edit_with_headers(
        harness: &TestHarness,
        server_id: &str,
        session: &Session,
        body: serde_json::Value,
        reason: Option<&str>,
        mfa_ticket: Option<&str>,
    ) -> (Status, String) {
        let mut request = harness
            .client
            .patch(format!("/servers/{}", server_id))
            .header(ContentType::JSON)
            .body(body.to_string())
            .header(Header::new("x-session-token", session.token.to_string()));
        if let Some(reason) = reason {
            request = request.header(Header::new("X-Audit-Log-Reason", reason.to_string()));
        }
        if let Some(ticket) = mfa_ticket {
            request = request.header(Header::new("X-MFA-Ticket", ticket.to_string()));
        }

        let response = request.dispatch().await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    async fn audit_entries(harness: &TestHarness, server_id: &str) -> Vec<AuditLogEntry> {
        harness
            .db
            .fetch_audit_log(server_id, None, 50, None, None)
            .await
            .expect("audit log")
    }

    /// A validated MFA ticket for `account_id`, as the ownership transfer
    /// demands.
    async fn mfa_ticket(harness: &TestHarness, account_id: &str) -> String {
        let ticket = MFATicket::new(account_id.to_string(), true);
        ticket.save(&harness.db).await.expect("`MFATicket`");
        ticket.token
    }

    /// Seed an unclaimed file in the `icons` bucket, as Autumn leaves one
    /// after an upload, so the route can claim it as the server icon.
    async fn upload_icon(harness: &TestHarness, uploader: &User) -> String {
        use iso8601_timestamp::Timestamp;
        let id = ulid::Ulid::new().to_string();
        harness
            .db
            .insert_attachment(&File {
                id: id.clone(),
                tag: "icons".to_string(),
                filename: "icon.png".to_string(),
                hash: None,
                uploaded_at: Some(Timestamp::now_utc()),
                uploader_id: Some(uploader.id.clone()),
                used_for: None,
                deleted: None,
                reported: None,
                metadata: Metadata::File,
                content_type: "image/png".to_string(),
                size: 10,
                message_id: None,
                user_id: None,
                server_id: None,
                object_id: None,
            })
            .await
            .expect("insert icon");
        id
    }

    /// A rename: exactly one `server_update` entry carrying the old and new
    /// name, the newly set description, the owner as actor, and the
    /// percent-encoded reason header decoded. Saving the same values again
    /// changes nothing and records nothing.
    #[test]
    fn a_rename_records_one_server_update_with_its_reason() {
        crate::util::test::rt().block_on(a_rename_records_one_server_update_with_its_reason_case())
    }

    async fn a_rename_records_one_server_update_with_its_reason_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;

        let edit_body = json!({ "name": "Renamed", "description": "About" });
        let (status, body) = edit_with_headers(
            &harness,
            &server.id,
            &owner_session,
            edit_body.clone(),
            Some("rename%20reason"),
            None,
        )
        .await;
        assert_eq!(status, Status::Ok, "{body}");

        let entries = audit_entries(&harness, &server.id).await;
        assert_eq!(entries.len(), 1, "{entries:?}");
        let entry = &entries[0];
        assert_eq!(entry.server, server.id);
        assert_eq!(entry.action, AuditLogAction::ServerUpdate);
        assert_eq!(entry.actor.as_deref(), Some(owner.id.as_str()));
        assert_eq!(entry.target, None);
        assert_eq!(entry.channel, None);
        assert_eq!(entry.count, None);
        assert_eq!(entry.reason.as_deref(), Some("rename reason"));
        assert_eq!(
            entry.changes,
            vec![
                AuditLogChange::new(
                    "name",
                    Some(AuditValue::String("Test Server".to_string())),
                    Some(AuditValue::String("Renamed".to_string())),
                ),
                AuditLogChange::new(
                    "description",
                    None,
                    Some(AuditValue::String("About".to_string())),
                ),
            ]
        );

        let (status, body) =
            edit_with_headers(&harness, &server.id, &owner_session, edit_body, None, None).await;
        assert_eq!(status, Status::Ok, "{body}");
        assert_eq!(audit_entries(&harness, &server.id).await.len(), 1);
    }

    /// Setting an icon records `icon: Bool(true)`, removing it records
    /// `icon: Bool(false)`, and removing an icon that is no longer there
    /// records nothing.
    #[test]
    fn icon_set_and_removal_are_recorded_as_bools() {
        crate::util::test::rt().block_on(icon_set_and_removal_are_recorded_as_bools_case())
    }

    async fn icon_set_and_removal_are_recorded_as_bools_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        let icon = upload_icon(&harness, &owner).await;

        let (status, body) = edit_with_headers(
            &harness,
            &server.id,
            &owner_session,
            json!({ "icon": icon }),
            None,
            None,
        )
        .await;
        assert_eq!(status, Status::Ok, "{body}");
        let entries = audit_entries(&harness, &server.id).await;
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(
            entries[0].changes,
            vec![AuditLogChange::new(
                "icon",
                None,
                Some(AuditValue::Bool(true))
            )]
        );

        let (status, body) = edit_with_headers(
            &harness,
            &server.id,
            &owner_session,
            json!({ "remove": ["Icon"] }),
            None,
            None,
        )
        .await;
        assert_eq!(status, Status::Ok, "{body}");
        assert!(harness
            .db
            .fetch_server(&server.id)
            .await
            .unwrap()
            .icon
            .is_none());

        let entries = audit_entries(&harness, &server.id).await;
        assert_eq!(entries.len(), 2, "{entries:?}");
        let removal = vec![AuditLogChange::new(
            "icon",
            None,
            Some(AuditValue::Bool(false)),
        )];
        let entry = entries
            .iter()
            .find(|entry| entry.changes == removal)
            .unwrap_or_else(|| panic!("no icon removal entry: {entries:?}"));
        assert_eq!(entry.action, AuditLogAction::ServerUpdate);
        assert_eq!(entry.actor.as_deref(), Some(owner.id.as_str()));
        assert_eq!(entry.reason, None);

        let (status, body) = edit_with_headers(
            &harness,
            &server.id,
            &owner_session,
            json!({ "remove": ["Icon"] }),
            None,
            None,
        )
        .await;
        assert_eq!(status, Status::Ok, "{body}");
        assert_eq!(audit_entries(&harness, &server.id).await.len(), 2);
    }

    /// The `NothingToEdit` early return writes no entry, reason or not.
    #[test]
    fn nothing_to_edit_records_nothing() {
        crate::util::test::rt().block_on(nothing_to_edit_records_nothing_case())
    }

    async fn nothing_to_edit_records_nothing_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;

        for body in [json!({}), json!({ "remove": [] })] {
            let (status, body) = edit_with_headers(
                &harness,
                &server.id,
                &owner_session,
                body,
                Some("nothing%20at%20all"),
                None,
            )
            .await;
            assert_eq!(status, Status::Ok, "{body}");
        }

        assert_eq!(audit_entries(&harness, &server.id).await, vec![]);
    }

    /// Refused edits write no entry: a member without ManageServer, an
    /// account that is not a member at all, and an ownership transfer with
    /// no MFA ticket.
    #[test]
    fn refused_edits_record_nothing() {
        crate::util::test::rt().block_on(refused_edits_record_nothing_case())
    }

    async fn refused_edits_record_nothing_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member_user) = harness.new_user().await;
        let (_, outsider_session, _) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        Member::create(&harness.db, &server, &member_user, None)
            .await
            .expect("`Member`");

        for session in [&member_session, &outsider_session] {
            let (status, body) = edit_with_headers(
                &harness,
                &server.id,
                session,
                json!({ "name": "Taken" }),
                Some("hostile"),
                None,
            )
            .await;
            assert_eq!(status, Status::Forbidden, "{body}");
        }

        let (status, body) = edit_with_headers(
            &harness,
            &server.id,
            &owner_session,
            json!({ "owner": member_user.id }),
            None,
            None,
        )
        .await;
        assert_eq!(status, Status::Unauthorized, "{body}");
        assert!(body.contains("InvalidCredentials"), "{body}");

        let fetched = harness.db.fetch_server(&server.id).await.unwrap();
        assert_eq!(fetched.name, "Test Server");
        assert_eq!(fetched.owner, owner.id);
        assert_eq!(audit_entries(&harness, &server.id).await, vec![]);
    }

    /// A 513-char reason is refused with `AuditLogReasonTooLong` and the
    /// edit does not happen. 512 chars is accepted and stored whole.
    #[test]
    fn an_overlong_reason_refuses_the_edit() {
        crate::util::test::rt().block_on(an_overlong_reason_refuses_the_edit_case())
    }

    async fn an_overlong_reason_refuses_the_edit_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;

        let too_long = "a".repeat(513);
        let (status, body) = edit_with_headers(
            &harness,
            &server.id,
            &owner_session,
            json!({ "name": "Renamed" }),
            Some(too_long.as_str()),
            None,
        )
        .await;
        assert_eq!(status, Status::BadRequest, "{body}");
        assert!(body.contains("AuditLogReasonTooLong"), "{body}");
        assert_eq!(
            harness.db.fetch_server(&server.id).await.unwrap().name,
            "Test Server"
        );
        assert_eq!(audit_entries(&harness, &server.id).await, vec![]);

        let longest = "a".repeat(512);
        let (status, body) = edit_with_headers(
            &harness,
            &server.id,
            &owner_session,
            json!({ "name": "Renamed" }),
            Some(longest.as_str()),
            None,
        )
        .await;
        assert_eq!(status, Status::Ok, "{body}");
        let entries = audit_entries(&harness, &server.id).await;
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].reason.as_deref(), Some(longest.as_str()));
    }

    /// Audit M2 regression test. The owner is written into `server` in place
    /// before the update, so a snapshot taken late would record the NEW
    /// owner as the old one. The transfer gets its own entry targeting the
    /// new owner, and the rename in the same request gets a `server_update`
    /// that does not mention the owner.
    #[test]
    fn an_ownership_transfer_records_the_old_owner() {
        crate::util::test::rt().block_on(an_ownership_transfer_records_the_old_owner_case())
    }

    async fn an_ownership_transfer_records_the_old_owner_case() {
        let harness = TestHarness::new().await;
        let (owner_account, owner_session, owner) = harness.new_user().await;
        let (_, _, heir) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        Member::create(&harness.db, &server, &heir, None)
            .await
            .expect("`Member`");
        let ticket = mfa_ticket(&harness, &owner_account.id).await;

        let (status, body) = edit_with_headers(
            &harness,
            &server.id,
            &owner_session,
            json!({ "owner": heir.id, "name": "Handed over" }),
            Some("stepping%20down"),
            Some(ticket.as_str()),
        )
        .await;
        assert_eq!(status, Status::Ok, "{body}");
        assert_eq!(
            harness.db.fetch_server(&server.id).await.unwrap().owner,
            heir.id
        );

        let entries = audit_entries(&harness, &server.id).await;
        assert_eq!(entries.len(), 2, "{entries:?}");

        let transfer = entries
            .iter()
            .find(|entry| entry.action == AuditLogAction::ServerOwnerTransfer)
            .unwrap_or_else(|| panic!("no transfer entry: {entries:?}"));
        assert_eq!(transfer.actor.as_deref(), Some(owner.id.as_str()));
        assert_eq!(transfer.target.as_deref(), Some(heir.id.as_str()));
        assert_eq!(transfer.channel, None);
        assert_eq!(transfer.reason.as_deref(), Some("stepping down"));
        assert_eq!(
            transfer.changes,
            vec![AuditLogChange::new(
                "owner",
                Some(AuditValue::String(owner.id.clone())),
                Some(AuditValue::String(heir.id.clone())),
            )]
        );

        let update = entries
            .iter()
            .find(|entry| entry.action == AuditLogAction::ServerUpdate)
            .unwrap_or_else(|| panic!("no server_update entry: {entries:?}"));
        assert_eq!(update.actor.as_deref(), Some(owner.id.as_str()));
        assert_eq!(update.target, None);
        assert_eq!(update.reason.as_deref(), Some("stepping down"));
        assert_eq!(
            update.changes,
            vec![AuditLogChange::new(
                "name",
                Some(AuditValue::String("Test Server".to_string())),
                Some(AuditValue::String("Handed over".to_string())),
            )]
        );
    }

    /// A privileged account taking a server over is the actor AND the new
    /// owner. That is a change of control, not a self-edit, so it is
    /// recorded, under the staff member's own name.
    #[test]
    fn a_staff_takeover_is_recorded() {
        crate::util::test::rt().block_on(a_staff_takeover_is_recorded_case())
    }

    async fn a_staff_takeover_is_recorded_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (admin_account, admin_session, mut admin) = harness.new_user().await;
        admin
            .update(
                &harness.db,
                PartialUser {
                    privileged: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("privileged admin");
        let (server, _) = harness.new_server(&owner).await;
        Member::create(&harness.db, &server, &admin, None)
            .await
            .expect("`Member`");
        let ticket = mfa_ticket(&harness, &admin_account.id).await;

        let (status, body) = edit_with_headers(
            &harness,
            &server.id,
            &admin_session,
            json!({ "owner": admin.id }),
            None,
            Some(ticket.as_str()),
        )
        .await;
        assert_eq!(status, Status::Ok, "{body}");

        let entries = audit_entries(&harness, &server.id).await;
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].action, AuditLogAction::ServerOwnerTransfer);
        assert_eq!(entries[0].actor.as_deref(), Some(admin.id.as_str()));
        assert_eq!(entries[0].target.as_deref(), Some(admin.id.as_str()));
        assert_eq!(
            entries[0].changes,
            vec![AuditLogChange::new(
                "owner",
                Some(AuditValue::String(owner.id.clone())),
                Some(AuditValue::String(admin.id.clone())),
            )]
        );
    }
}
