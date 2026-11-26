use std::collections::{HashMap, HashSet};

use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{
    AuditLogAction, AuditLogEntry, Database, Server, User, AUDIT_LOG_FETCH_DEFAULT,
    AUDIT_LOG_FETCH_MAX,
};
use revolt_models::v0;
use revolt_permissions::{
    calculate_channel_permissions, calculate_server_permissions, ChannelPermission,
};
use revolt_result::{create_error, ErrorType, Result};
use rocket::serde::json::Json;
use rocket::State;

/// How many further batches of `AUDIT_LOG_FETCH_MAX` entries a fetch may read
/// to refill a page after dropping entries the caller may not see.
const AUDIT_LOG_REFILL_BATCHES: usize = 10;

/// Whether an entry of this action stores a user id in `target`.
///
/// Only those targets are resolved into the page's `users`. The other kinds
/// target a channel, a role or `"default"`, and `Unknown` (an entry written by
/// a newer build) is never assumed to be a user. There is deliberately no
/// wildcard arm: a new action must decide here what its target is.
fn targets_a_user(action: AuditLogAction) -> bool {
    match action {
        AuditLogAction::MemberKick
        | AuditLogAction::MemberBanAdd
        | AuditLogAction::MemberBanRemove
        | AuditLogAction::MemberTimeout
        | AuditLogAction::MemberTimeoutRemove
        | AuditLogAction::MemberRoleUpdate
        | AuditLogAction::MemberUpdate
        | AuditLogAction::MemberVoiceUpdate
        | AuditLogAction::MemberMove
        | AuditLogAction::MemberDisconnect
        | AuditLogAction::MessageDelete
        | AuditLogAction::ServerOwnerTransfer
        | AuditLogAction::ProtectedSeatRelease => true,
        AuditLogAction::MessageBulkDelete
        | AuditLogAction::ProtectedSeatsUpdate
        | AuditLogAction::ChannelProtect
        | AuditLogAction::ChannelHistoryWipe
        | AuditLogAction::ChannelCreate
        | AuditLogAction::ChannelUpdate
        | AuditLogAction::ChannelDelete
        | AuditLogAction::ChannelOverwriteUpdate
        | AuditLogAction::ServerPermissionsUpdate
        | AuditLogAction::RoleCreate
        | AuditLogAction::RoleUpdate
        | AuditLogAction::RoleDelete
        | AuditLogAction::RoleRanksUpdate
        | AuditLogAction::ServerUpdate
        | AuditLogAction::Unknown => false,
    }
}

/// Whether an entry of this action names a protected channel and its seat
/// holders, and so is served only to readers with ViewChannel on the entry's
/// `channel` (protected channels design §7.5, #221). No wildcard arm, as in
/// `targets_a_user`. `Unknown` is served as before: an entry this build
/// cannot name has no channel rule it could apply.
fn needs_channel_view(action: AuditLogAction) -> bool {
    match action {
        AuditLogAction::ProtectedSeatsUpdate
        | AuditLogAction::ProtectedSeatRelease
        | AuditLogAction::ChannelProtect
        | AuditLogAction::ChannelHistoryWipe => true,
        AuditLogAction::MemberKick
        | AuditLogAction::MemberBanAdd
        | AuditLogAction::MemberBanRemove
        | AuditLogAction::MemberTimeout
        | AuditLogAction::MemberTimeoutRemove
        | AuditLogAction::MemberRoleUpdate
        | AuditLogAction::MemberUpdate
        | AuditLogAction::MemberVoiceUpdate
        | AuditLogAction::MemberMove
        | AuditLogAction::MemberDisconnect
        | AuditLogAction::MessageDelete
        | AuditLogAction::MessageBulkDelete
        | AuditLogAction::ChannelCreate
        | AuditLogAction::ChannelUpdate
        | AuditLogAction::ChannelDelete
        | AuditLogAction::ChannelOverwriteUpdate
        | AuditLogAction::ServerPermissionsUpdate
        | AuditLogAction::RoleCreate
        | AuditLogAction::RoleUpdate
        | AuditLogAction::RoleDelete
        | AuditLogAction::RoleRanksUpdate
        | AuditLogAction::ServerUpdate
        | AuditLogAction::ServerOwnerTransfer
        | AuditLogAction::Unknown => false,
    }
}

/// Whether `user` has ViewChannel on `channel_id`, a channel of `server`.
///
/// Fails closed: a channel that no longer exists, or that belongs to another
/// server, is viewed by nobody (the owner and privileged accounts included).
async fn can_view_channel(
    db: &Database,
    user: &User,
    server: &Server,
    channel_id: &str,
) -> Result<bool> {
    let channel = match db.fetch_channel(channel_id).await {
        Ok(channel) => channel,
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => return Ok(false),
        Err(error) => return Err(error),
    };
    if channel.server() != Some(server.id.as_str()) {
        return Ok(false);
    }

    let mut query = DatabasePermissionQuery::new(db, user).channel(&channel);
    Ok(calculate_channel_permissions(&mut query)
        .await
        .has_channel_permission(ChannelPermission::ViewChannel))
}

/// Parse the `?action=` filter.
///
/// `AuditLogAction` decodes any unrecognised string to `Unknown` (its
/// `#[serde(other)]` arm, there so that stored entries from a newer build
/// still decode). As a filter that would silently match only such entries,
/// so a string that does not name a known action, `"unknown"` included, is
/// rejected here instead.
fn parse_action_filter(action: &str) -> Result<AuditLogAction> {
    match serde_json::from_value::<v0::AuditLogAction>(serde_json::Value::String(
        action.to_string(),
    )) {
        Ok(v0::AuditLogAction::Unknown) | Err(_) => Err(create_error!(FailedValidation {
            error: "UnknownAuditLogAction".to_string()
        })),
        Ok(action) => Ok(action.into()),
    }
}

/// # Fetch Audit Log
///
/// Fetch a page of the server's audit log, newest first. Requires the
/// ViewAuditLog permission.
///
/// Page backwards by passing the id of the last (oldest) entry received as
/// `before`. The end of the log is an EMPTY page: a page shorter than `limit`
/// is NOT the end, because stored entries that fail to decode are skipped
/// after the limit has been applied.
///
/// `protected_seats_update` and `protected_seat_release` entries name a
/// protected channel's seat holders, so they are returned only to a caller
/// with ViewChannel on the entry's channel, under every filter. The page is
/// refilled from older entries in their place, so neither its length nor an
/// empty page tells the caller how many it was denied. The refill reads at
/// most ten further batches of 100 entries; a longer run of hidden entries
/// ends that caller's page early.
///
/// `users` holds every user an entry on the page refers to (actors, and the
/// targets of member, message, ownership and seat release actions), as the
/// caller sees them. A deleted user is simply absent, and an entry the caller
/// may not see contributes no user.
#[openapi(tag = "Audit Log")]
#[get("/<target>/audit_log?<options..>")]
pub async fn fetch_audit_log(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    options: v0::OptionsFetchAuditLog,
) -> Result<Json<v0::AuditLogPage>> {
    let server = target.as_server(db).await?;
    // Fails closed: a non-member calculates to no permissions at all, and a
    // member in timeout is restricted to ALLOW_IN_TIMEOUT, which has no
    // ViewAuditLog. The owner and privileged accounts get GrantAllSafe.
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    calculate_server_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ViewAuditLog)?;

    if let Some(before) = &options.before {
        if before.len() != 26 || !before.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(create_error!(FailedValidation {
                error: "InvalidAuditLogCursor".to_string()
            }));
        }
    }

    let action = options
        .action
        .as_deref()
        .map(parse_action_filter)
        .transpose()?;

    let limit = options
        .limit
        .unwrap_or(AUDIT_LOG_FETCH_DEFAULT)
        .clamp(1, AUDIT_LOG_FETCH_MAX);

    // Seat entries the caller may not see are dropped HERE, before `users`
    // is collected below, so a hidden entry leaks neither its seat holder
    // nor its actor. ViewChannel is computed once per channel per request.
    let mut entries: Vec<AuditLogEntry> = Vec::new();
    let mut viewable: HashMap<String, bool> = HashMap::new();
    let mut cursor = options.before.clone();
    let mut batch_limit = limit;
    'scan: for _ in 0..=AUDIT_LOG_REFILL_BATCHES {
        let batch = db
            .fetch_audit_log(
                &server.id,
                cursor.as_deref(),
                batch_limit,
                action,
                options.user.as_deref(),
            )
            .await?;
        let Some(oldest) = batch.last() else {
            break;
        };
        cursor = Some(oldest.id.clone());
        // A short batch reached the oldest entry: nothing is left to refill from
        let exhausted = (batch.len() as i64) < batch_limit;

        for entry in batch {
            if needs_channel_view(entry.action) {
                let visible = match &entry.channel {
                    None => false,
                    Some(channel) => match viewable.get(channel).copied() {
                        Some(visible) => visible,
                        None => {
                            let visible = can_view_channel(db, &user, &server, channel).await?;
                            viewable.insert(channel.clone(), visible);
                            visible
                        }
                    },
                };
                if !visible {
                    continue;
                }
            }

            entries.push(entry);
            if entries.len() as i64 >= limit {
                break 'scan;
            }
        }

        if exhausted {
            break;
        }
        batch_limit = AUDIT_LOG_FETCH_MAX;
    }

    let mut seen = HashSet::new();
    let mut user_ids = Vec::new();
    for entry in &entries {
        if let Some(actor) = &entry.actor {
            if seen.insert(actor.as_str()) {
                user_ids.push(actor.clone());
            }
        }

        if targets_a_user(entry.action) {
            if let Some(target) = &entry.target {
                if seen.insert(target.as_str()) {
                    user_ids.push(target.clone());
                }
            }
        }
    }

    // Projected as the caller sees each user, as poll_voters does. Never the
    // account-owner projection that ban_list uses: it would hand the caller
    // every user's relations and connections and mark each one as the caller.
    let mut users = Vec::with_capacity(user_ids.len());
    if !user_ids.is_empty() {
        for referenced in db.fetch_users(&user_ids).await? {
            users.push(referenced.into(db, Some(&user)).await);
        }
    }

    Ok(Json(v0::AuditLogPage {
        entries: entries.into_iter().map(Into::into).collect(),
        users,
    }))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{
        AuditLogAction, AuditLogChange, AuditLogEntry, AuditValue, Channel, Member,
        PartialChannel, PartialMember, RelationshipStatus, Server, Session, User,
    };
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{Header, Status};
    use serde_json::Value;

    /// S4 (design §7.5 "S4"): the protect and history-wipe entries name a
    /// protected channel, so only readers with ViewChannel on it get them
    /// (#221), and neither stores a user in `target`
    ///
    /// Control: either action moved to the `false` arm of
    /// `needs_channel_view`.
    #[test]
    fn s4_channel_entries_need_view_channel() {
        for action in [
            AuditLogAction::ChannelProtect,
            AuditLogAction::ChannelHistoryWipe,
        ] {
            assert!(super::needs_channel_view(action), "{action:?}");
            assert!(!super::targets_a_user(action), "{action:?}");
        }
    }

    /// A 26-character ULID-shaped id that sorts by `n`.
    fn id(n: u32) -> String {
        format!("01J0000000000000000000{n:04}")
    }

    fn entry(
        n: u32,
        server: &Server,
        actor: Option<&str>,
        action: AuditLogAction,
        target: Option<&str>,
    ) -> AuditLogEntry {
        AuditLogEntry {
            id: id(n),
            server: server.id.clone(),
            actor: actor.map(str::to_string),
            action,
            target: target.map(str::to_string),
            channel: None,
            changes: Vec::new(),
            count: None,
            reason: None,
        }
    }

    async fn seed(harness: &TestHarness, entries: &[AuditLogEntry]) {
        for entry in entries {
            harness
                .db
                .insert_audit_log_entry(entry)
                .await
                .expect("seed audit log entry");
        }
    }

    /// GET the audit log; returns the status and the raw JSON body.
    async fn fetch(
        harness: &TestHarness,
        session: &Session,
        server: &Server,
        query: &str,
    ) -> (Status, Value) {
        let response = harness
            .client
            .get(format!("/servers/{}/audit_log{}", server.id, query))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        let json = serde_json::from_str(&body).unwrap_or(Value::Null);
        (status, json)
    }

    fn entry_ids(page: &Value) -> Vec<String> {
        page["entries"]
            .as_array()
            .expect("entries array")
            .iter()
            .map(|entry| entry["_id"].as_str().expect("entry id").to_string())
            .collect()
    }

    fn assert_error(status: Status, body: &Value, expected: Status, kind: &str) {
        assert_eq!(status, expected, "body: {body}");
        assert_eq!(body["type"], kind, "body: {body}");
    }

    async fn member_with_role(
        harness: &TestHarness,
        server: &Server,
        user: &User,
        role: Option<&str>,
        timed_out: bool,
    ) {
        let (mut member, _) = Member::create(&harness.db, server, user, None)
            .await
            .expect("member");
        let timeout = timed_out.then(|| {
            Timestamp::now_utc()
                .checked_add(Duration::hours(1))
                .expect("timeout timestamp")
        });
        if role.is_some() || timeout.is_some() {
            member
                .update(
                    &harness.db,
                    PartialMember {
                        roles: role.map(|role| vec![role.to_string()]),
                        timeout,
                        ..Default::default()
                    },
                    vec![],
                )
                .await
                .expect("member update");
        }
    }

    #[test]
    fn view_audit_log_gates_the_route() {
        crate::util::test::rt().block_on(view_audit_log_gates_the_route_case())
    }

    /// Owner (GrantAllSafe, no roles) and a ViewAuditLog holder read; a member
    /// without the bit, a non-member and a timed-out holder are all refused
    /// with MissingPermission (ban_list's non-member behavior: the server
    /// resolves, the calculus yields nothing).
    async fn view_audit_log_gates_the_route_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, mod_session, moderator) = harness.new_user().await;
        let (_, plain_session, plain) = harness.new_user().await;
        let (_, outsider_session, _outsider) = harness.new_user().await;
        let (_, timed_session, timed) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;

        let role = harness
            .new_role(
                &server,
                1,
                Some(OverrideField {
                    a: ChannelPermission::ViewAuditLog as i64,
                    d: 0,
                }),
            )
            .await;
        member_with_role(&harness, &server, &moderator, Some(&role.id), false).await;
        member_with_role(&harness, &server, &plain, None, false).await;
        member_with_role(&harness, &server, &timed, Some(&role.id), true).await;

        seed(
            &harness,
            &[entry(
                1,
                &server,
                Some(&owner.id),
                AuditLogAction::MemberKick,
                Some(&plain.id),
            )],
        )
        .await;

        let (status, page) = fetch(&harness, &owner_session, &server, "").await;
        assert_eq!(status, Status::Ok, "owner: {page}");
        assert_eq!(entry_ids(&page), vec![id(1)]);

        let (status, page) = fetch(&harness, &mod_session, &server, "").await;
        assert_eq!(status, Status::Ok, "ViewAuditLog holder: {page}");
        assert_eq!(entry_ids(&page), vec![id(1)]);

        let (status, body) = fetch(&harness, &plain_session, &server, "").await;
        assert_error(status, &body, Status::Forbidden, "MissingPermission");
        assert_eq!(body["permission"], "ViewAuditLog", "body: {body}");

        let (status, body) = fetch(&harness, &outsider_session, &server, "").await;
        assert_error(status, &body, Status::Forbidden, "MissingPermission");

        let (status, body) = fetch(&harness, &timed_session, &server, "").await;
        assert_error(status, &body, Status::Forbidden, "MissingPermission");
    }

    #[test]
    fn pages_newest_first_and_filters() {
        crate::util::test::rt().block_on(pages_newest_first_and_filters_case())
    }

    /// Newest first, `before` paging down to an empty end page, the action and
    /// user filters, and isolation from another server's entries. Split over
    /// two sessions to stay inside the per-session route bucket.
    async fn pages_newest_first_and_filters_case() {
        let harness = TestHarness::new().await;
        let (account, session, owner) = harness.new_user().await;
        let second_session = account
            .create_session(&harness.db, String::new())
            .await
            .expect("second session");
        let (_, _, moderator) = harness.new_user().await;
        let (_, _, victim) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        let (other_server, _) = harness.new_server(&owner).await;

        // Inserted out of order: the order must come from the sort.
        seed(
            &harness,
            &[
                entry(
                    3,
                    &server,
                    Some(&moderator.id),
                    AuditLogAction::MemberKick,
                    Some(&victim.id),
                ),
                entry(
                    1,
                    &server,
                    Some(&owner.id),
                    AuditLogAction::MemberBanAdd,
                    Some(&victim.id),
                ),
                entry(
                    5,
                    &server,
                    Some(&owner.id),
                    AuditLogAction::MemberKick,
                    Some(&victim.id),
                ),
                entry(
                    2,
                    &server,
                    Some(&moderator.id),
                    AuditLogAction::RoleUpdate,
                    Some("01ROLE00000000000000000001"),
                ),
                entry(4, &server, None, AuditLogAction::ServerUpdate, None),
                entry(
                    6,
                    &other_server,
                    Some(&owner.id),
                    AuditLogAction::MemberKick,
                    Some(&victim.id),
                ),
            ],
        )
        .await;

        let (status, page) = fetch(&harness, &session, &server, "").await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page), vec![id(5), id(4), id(3), id(2), id(1)]);

        let (status, page) = fetch(&harness, &session, &server, "?limit=2").await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page), vec![id(5), id(4)]);

        let (status, page) = fetch(
            &harness,
            &session,
            &server,
            &format!("?limit=2&before={}", id(4)),
        )
        .await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page), vec![id(3), id(2)]);

        // The end of the log is an empty page.
        let (status, page) =
            fetch(&harness, &session, &server, &format!("?before={}", id(1))).await;
        assert_eq!(status, Status::Ok, "{page}");
        assert!(entry_ids(&page).is_empty(), "{page}");
        assert_eq!(page["users"], Value::Array(vec![]), "{page}");

        let (status, page) = fetch(&harness, &second_session, &server, "?action=member_kick").await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page), vec![id(5), id(3)]);

        let (status, page) = fetch(
            &harness,
            &second_session,
            &server,
            &format!("?user={}", moderator.id),
        )
        .await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page), vec![id(3), id(2)]);

        let (status, page) = fetch(&harness, &second_session, &other_server, "").await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page), vec![id(6)]);
    }

    #[test]
    fn rejects_bad_options_and_clamps_the_limit() {
        crate::util::test::rt().block_on(rejects_bad_options_and_clamps_the_limit_case())
    }

    /// An unrecognised action (which serde would decode to `Unknown`) and the
    /// literal `unknown` are both 400 UnknownAuditLogAction; a malformed
    /// cursor is 400; the limit is clamped to 1..=100 and defaults to 50.
    async fn rejects_bad_options_and_clamps_the_limit_case() {
        let harness = TestHarness::new().await;
        let (account, session, owner) = harness.new_user().await;
        let second_session = account
            .create_session(&harness.db, String::new())
            .await
            .expect("second session");
        let (server, _) = harness.new_server(&owner).await;

        let rows: Vec<AuditLogEntry> = (1..=105)
            .map(|n| {
                entry(
                    n,
                    &server,
                    Some(&owner.id),
                    AuditLogAction::ServerUpdate,
                    None,
                )
            })
            .collect();
        seed(&harness, &rows).await;

        let (status, body) = fetch(&harness, &session, &server, "?action=garbage").await;
        assert_error(status, &body, Status::BadRequest, "FailedValidation");
        assert_eq!(body["error"], "UnknownAuditLogAction", "body: {body}");

        let (status, body) = fetch(&harness, &session, &server, "?action=unknown").await;
        assert_error(status, &body, Status::BadRequest, "FailedValidation");
        assert_eq!(body["error"], "UnknownAuditLogAction", "body: {body}");

        let (status, body) = fetch(&harness, &session, &server, "?before=short").await;
        assert_error(status, &body, Status::BadRequest, "FailedValidation");

        let (status, page) = fetch(&harness, &session, &server, "?limit=0").await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page), vec![id(105)]);

        let (status, page) = fetch(&harness, &second_session, &server, "?limit=1000").await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page).len(), 100);
        assert_eq!(entry_ids(&page)[0], id(105));

        let (status, page) = fetch(&harness, &second_session, &server, "").await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page).len(), 50);
    }

    #[test]
    fn users_are_projected_as_the_viewer_sees_them() {
        crate::util::test::rt().block_on(users_are_projected_as_the_viewer_sees_them_case())
    }

    /// `users` holds the actor and the user target, not the target of a
    /// non-user action (even when that target happens to be a user id), not a
    /// deleted user, and never the fields the account-owner projection leaks:
    /// the moderator and the victim are friends, so that projection would emit
    /// their `relations` and mark both `relationship: "User"`.
    async fn users_are_projected_as_the_viewer_sees_them_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (_, _, moderator) = harness.new_user().await;
        let (_, _, victim) = harness.new_user().await;
        let (_, _, bystander) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        for user in [&moderator, &victim, &bystander] {
            member_with_role(&harness, &server, user, None, false).await;
        }

        harness
            .db
            .set_relationship(&moderator.id, &victim.id, &RelationshipStatus::Friend, None)
            .await
            .expect("relationship");
        harness
            .db
            .set_relationship(&victim.id, &moderator.id, &RelationshipStatus::Friend, None)
            .await
            .expect("relationship");

        let deleted = ulid::Ulid::new().to_string();
        seed(
            &harness,
            &[
                entry(
                    1,
                    &server,
                    Some(&moderator.id),
                    AuditLogAction::MemberKick,
                    Some(&victim.id),
                ),
                // Not a user-target action: the bystander must not be resolved.
                entry(
                    2,
                    &server,
                    Some(&moderator.id),
                    AuditLogAction::RoleUpdate,
                    Some(&bystander.id),
                ),
                entry(
                    3,
                    &server,
                    Some(&deleted),
                    AuditLogAction::Unknown,
                    Some(&bystander.id),
                ),
                entry(4, &server, None, AuditLogAction::ServerUpdate, None),
            ],
        )
        .await;

        let (status, page) = fetch(&harness, &session, &server, "").await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page), vec![id(4), id(3), id(2), id(1)]);
        assert_eq!(page["entries"][1]["action"], "unknown", "{page}");

        let users = page["users"].as_array().expect("users array");
        let mut ids: Vec<&str> = users
            .iter()
            .map(|user| user["_id"].as_str().expect("user id"))
            .collect();
        ids.sort_unstable();
        let mut expected = vec![moderator.id.as_str(), victim.id.as_str()];
        expected.sort_unstable();
        assert_eq!(ids, expected, "{page}");

        for user in users {
            let object = user.as_object().expect("user object");
            assert!(
                !object.contains_key("relations"),
                "relations leaked: {user}"
            );
            assert!(
                !object.contains_key("connections"),
                "connections present: {user}"
            );
            assert_ne!(user["relationship"], "User", "self projection: {user}");
        }
    }

    /// A `ProtectedSeatRelease` of `holder` in `channel`, as the reconciler
    /// writes it (design §7.5).
    fn seat_release(n: u32, server: &Server, holder: &str, channel: Option<&str>) -> AuditLogEntry {
        AuditLogEntry {
            channel: channel.map(str::to_string),
            changes: vec![AuditLogChange::new(
                "cause",
                None,
                Some(AuditValue::String("access_lost".to_string())),
            )],
            ..entry(
                n,
                server,
                None,
                AuditLogAction::ProtectedSeatRelease,
                Some(holder),
            )
        }
    }

    /// A `ProtectedSeatsUpdate` by `actor` in `channel` that released
    /// `released`, as the seat PUT writes it (design §7.5).
    fn seats_update(
        n: u32,
        server: &Server,
        actor: &str,
        released: &str,
        channel: &str,
    ) -> AuditLogEntry {
        AuditLogEntry {
            channel: Some(channel.to_string()),
            changes: vec![
                AuditLogChange::new(
                    "released",
                    None,
                    Some(AuditValue::StringList(vec![released.to_string()])),
                ),
                AuditLogChange::new("seated", None, Some(AuditValue::StringList(vec![]))),
            ],
            ..entry(
                n,
                server,
                Some(actor),
                AuditLogAction::ProtectedSeatsUpdate,
                None,
            )
        }
    }

    /// The sorted ids in the page's `users`.
    fn user_ids(page: &Value) -> Vec<String> {
        let mut ids: Vec<String> = page["users"]
            .as_array()
            .expect("users array")
            .iter()
            .map(|user| user["_id"].as_str().expect("user id").to_string())
            .collect();
        ids.sort_unstable();
        ids
    }

    fn sorted(ids: &[&String]) -> Vec<String> {
        let mut ids: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        ids.sort_unstable();
        ids
    }

    /// A server with one channel and two ViewAuditLog readers: `viewer` can
    /// see the channel, `hidden` has ViewChannel denied on it by a channel
    /// override. `holder` appears only as a seat holder, `seat_moderator`
    /// only as the actor of a seat PUT.
    struct SeatFixture {
        server: Server,
        channel: String,
        owner_session: Session,
        viewer_session: Session,
        hidden_session: Session,
        holder: User,
        seat_moderator: User,
        moderator: User,
        victim: User,
    }

    async fn seat_fixture(harness: &TestHarness) -> SeatFixture {
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, viewer_session, viewer) = harness.new_user().await;
        let (_, hidden_session, hidden) = harness.new_user().await;
        let (_, _, holder) = harness.new_user().await;
        let (_, _, seat_moderator) = harness.new_user().await;
        let (_, _, moderator) = harness.new_user().await;
        let (_, _, victim) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        let channel = harness.new_channel(&server).await.id().to_string();

        let audit = OverrideField {
            a: ChannelPermission::ViewAuditLog as i64,
            d: 0,
        };
        let viewer_role = harness.new_role(&server, 1, Some(audit)).await;
        let hidden_role = harness.new_role(&server, 2, Some(audit)).await;
        // Written through `update`: the reference driver's
        // `set_channel_role_permission` only replaces an EXISTING entry.
        let mut channel_model = harness
            .db
            .fetch_channel(&channel)
            .await
            .expect("channel read");
        let Channel::TextChannel {
            role_permissions, ..
        } = &channel_model
        else {
            panic!("a text channel");
        };
        let mut role_permissions = role_permissions.clone();
        role_permissions.insert(
            hidden_role.id.clone(),
            OverrideField {
                a: 0,
                d: ChannelPermission::ViewChannel as i64,
            },
        );
        channel_model
            .update(
                &harness.db,
                PartialChannel {
                    role_permissions: Some(role_permissions),
                    ..Default::default()
                },
                Vec::new(),
            )
            .await
            .expect("channel override");
        member_with_role(harness, &server, &viewer, Some(&viewer_role.id), false).await;
        member_with_role(harness, &server, &hidden, Some(&hidden_role.id), false).await;

        SeatFixture {
            server,
            channel,
            owner_session,
            viewer_session,
            hidden_session,
            holder,
            seat_moderator,
            moderator,
            victim,
        }
    }

    /// A kick, a seat release, a seat PUT and an update of the same channel.
    async fn seed_seat_entries(harness: &TestHarness, f: &SeatFixture) {
        seed(
            harness,
            &[
                entry(
                    1,
                    &f.server,
                    Some(&f.moderator.id),
                    AuditLogAction::MemberKick,
                    Some(&f.victim.id),
                ),
                seat_release(2, &f.server, &f.holder.id, Some(&f.channel)),
                seats_update(3, &f.server, &f.seat_moderator.id, &f.holder.id, &f.channel),
                entry(
                    4,
                    &f.server,
                    Some(&f.moderator.id),
                    AuditLogAction::ChannelUpdate,
                    Some(&f.channel),
                ),
            ],
        )
        .await;
    }

    #[test]
    fn seat_entries_need_view_channel_on_their_channel() {
        crate::util::test::rt().block_on(seat_entries_need_view_channel_on_their_channel_case())
    }

    /// Design §7.5 (#221): a ViewAuditLog reader without ViewChannel on the
    /// channel gets neither seat entry, and neither the seat holder nor the
    /// seat PUT's actor in `users` (the holder's id is nowhere in the body);
    /// a reader with ViewChannel, and the owner, get both. The kick and the
    /// update of that same channel are served to every reader.
    async fn seat_entries_need_view_channel_on_their_channel_case() {
        let harness = TestHarness::new().await;
        let f = seat_fixture(&harness).await;
        seed_seat_entries(&harness, &f).await;

        let (status, page) = fetch(&harness, &f.hidden_session, &f.server, "").await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(
            entry_ids(&page),
            vec![id(4), id(1)],
            "hidden seat entry served: {page}"
        );
        assert_eq!(
            user_ids(&page),
            sorted(&[&f.moderator.id, &f.victim.id]),
            "seat holder leaked into users: {page}"
        );
        assert!(
            !page.to_string().contains(&f.holder.id),
            "seat holder leaked: {page}"
        );

        let (status, page) = fetch(&harness, &f.viewer_session, &f.server, "").await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page), vec![id(4), id(3), id(2), id(1)], "{page}");
        assert_eq!(
            page["entries"][2]["action"], "protected_seat_release",
            "{page}"
        );
        assert_eq!(page["entries"][2]["target"], f.holder.id.as_str(), "{page}");
        assert_eq!(
            user_ids(&page),
            sorted(&[
                &f.moderator.id,
                &f.victim.id,
                &f.holder.id,
                &f.seat_moderator.id
            ]),
            "{page}"
        );

        let (status, page) = fetch(&harness, &f.owner_session, &f.server, "").await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page), vec![id(4), id(3), id(2), id(1)], "{page}");
    }

    #[test]
    fn the_action_filter_is_no_oracle_for_seat_entries() {
        crate::util::test::rt().block_on(the_action_filter_is_no_oracle_for_seat_entries_case())
    }

    /// `?action=` naming either seat action, and `?user=` naming the seat
    /// PUT's actor, give a non-viewer the same empty page as a log without
    /// such entries; a viewer gets the entry and its user. Another action's
    /// filter is unaffected.
    async fn the_action_filter_is_no_oracle_for_seat_entries_case() {
        let harness = TestHarness::new().await;
        let f = seat_fixture(&harness).await;
        seed_seat_entries(&harness, &f).await;
        let nothing = serde_json::json!({ "entries": [], "users": [] });

        for query in [
            "?action=protected_seat_release".to_string(),
            "?action=protected_seats_update".to_string(),
            format!("?user={}", f.seat_moderator.id),
        ] {
            let (status, page) = fetch(&harness, &f.hidden_session, &f.server, &query).await;
            assert_eq!(status, Status::Ok, "{query}: {page}");
            assert_eq!(page, nothing, "{query} is an oracle: {page}");
        }

        let (status, page) = fetch(
            &harness,
            &f.hidden_session,
            &f.server,
            "?action=member_kick",
        )
        .await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page), vec![id(1)], "{page}");

        let (status, page) = fetch(
            &harness,
            &f.viewer_session,
            &f.server,
            "?action=protected_seat_release",
        )
        .await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page), vec![id(2)], "{page}");
        assert_eq!(user_ids(&page), sorted(&[&f.holder.id]), "{page}");

        let (status, page) = fetch(
            &harness,
            &f.viewer_session,
            &f.server,
            &format!("?user={}", f.seat_moderator.id),
        )
        .await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page), vec![id(3)], "{page}");
        assert_eq!(user_ids(&page), sorted(&[&f.seat_moderator.id]), "{page}");
    }

    #[test]
    fn hidden_entries_are_refilled_not_a_short_or_empty_page() {
        crate::util::test::rt()
            .block_on(hidden_entries_are_refilled_not_a_short_or_empty_page_case())
    }

    /// A run of hidden seat entries longer than the page (60 > the default
    /// 50) is refilled from older entries: the non-viewer's page is not short,
    /// and a page starting inside the run is not the empty end-of-log page.
    async fn hidden_entries_are_refilled_not_a_short_or_empty_page_case() {
        let harness = TestHarness::new().await;
        let f = seat_fixture(&harness).await;
        let kick = |n| {
            entry(
                n,
                &f.server,
                Some(&f.moderator.id),
                AuditLogAction::MemberKick,
                Some(&f.victim.id),
            )
        };
        let mut rows = vec![kick(1)];
        rows.extend((2..=61).map(|n| seat_release(n, &f.server, &f.holder.id, Some(&f.channel))));
        rows.push(kick(62));
        seed(&harness, &rows).await;

        let (status, page) = fetch(&harness, &f.hidden_session, &f.server, "?limit=2").await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page), vec![id(62), id(1)], "short page: {page}");

        let (status, page) = fetch(&harness, &f.hidden_session, &f.server, "").await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page), vec![id(62), id(1)], "{page}");
        assert!(
            !page.to_string().contains(&f.holder.id),
            "seat holder leaked: {page}"
        );

        let (status, page) = fetch(
            &harness,
            &f.hidden_session,
            &f.server,
            &format!("?limit=1&before={}", id(62)),
        )
        .await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page), vec![id(1)], "false end of log: {page}");

        let (status, page) = fetch(
            &harness,
            &f.hidden_session,
            &f.server,
            &format!("?before={}", id(1)),
        )
        .await;
        assert_eq!(status, Status::Ok, "{page}");
        assert!(entry_ids(&page).is_empty(), "{page}");

        let (status, page) = fetch(&harness, &f.viewer_session, &f.server, "?limit=2").await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page), vec![id(62), id(61)], "{page}");
    }

    #[test]
    fn a_seat_entry_without_a_viewable_channel_fails_closed() {
        crate::util::test::rt()
            .block_on(a_seat_entry_without_a_viewable_channel_fails_closed_case())
    }

    /// A seat entry whose channel cannot be checked is served to nobody, the
    /// owner (GrantAllSafe) included: no channel, a channel that does not
    /// exist, and a channel of another server that the owner can view. A
    /// seat entry about the server's own channel still reaches the owner.
    async fn a_seat_entry_without_a_viewable_channel_fails_closed_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (_, _, victim) = harness.new_user().await;
        let (_, _, holder) = harness.new_user().await;
        let (_, _, seated) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        let (other_server, _) = harness.new_server(&owner).await;
        let own = harness.new_channel(&server).await.id().to_string();
        let foreign = harness.new_channel(&other_server).await.id().to_string();
        let missing = ulid::Ulid::new().to_string();

        seed(
            &harness,
            &[
                entry(
                    1,
                    &server,
                    Some(&owner.id),
                    AuditLogAction::MemberKick,
                    Some(&victim.id),
                ),
                seat_release(2, &server, &holder.id, None),
                seat_release(3, &server, &holder.id, Some(&missing)),
                seat_release(4, &server, &holder.id, Some(&foreign)),
                seat_release(5, &server, &seated.id, Some(&own)),
            ],
        )
        .await;

        let (status, page) = fetch(&harness, &session, &server, "").await;
        assert_eq!(status, Status::Ok, "{page}");
        assert_eq!(entry_ids(&page), vec![id(5), id(1)], "{page}");
        assert_eq!(
            user_ids(&page),
            sorted(&[&owner.id, &victim.id, &seated.id]),
            "{page}"
        );
    }
}
