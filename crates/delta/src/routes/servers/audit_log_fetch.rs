use std::collections::HashSet;

use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{
    AuditLogAction, Database, User, AUDIT_LOG_FETCH_DEFAULT, AUDIT_LOG_FETCH_MAX,
};
use revolt_models::v0;
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;

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
        | AuditLogAction::ServerOwnerTransfer => true,
        AuditLogAction::MessageBulkDelete
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
/// `users` holds every user an entry on the page refers to (actors, and the
/// targets of member, message and ownership actions), as the caller sees
/// them. A deleted user is simply absent.
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

    let entries = db
        .fetch_audit_log(
            &server.id,
            options.before.as_deref(),
            limit,
            action,
            options.user.as_deref(),
        )
        .await?;

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
        AuditLogAction, AuditLogEntry, Member, PartialMember, RelationshipStatus, Server, Session,
        User,
    };
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{Header, Status};
    use serde_json::Value;

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
}
