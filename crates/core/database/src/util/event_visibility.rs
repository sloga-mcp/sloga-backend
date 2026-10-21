//! Visibility checks for calendar events.
//!
//! An event pinned to a channel is visible to members who can view that
//! channel; a thread's permissions delegate to its parent channel.

use std::collections::HashMap;

use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{ErrorType, Result};

use crate::{
    util::permissions::DatabasePermissionQuery, CalendarEvent, Channel, Database, Member, Server,
    User,
};

/// Decides which calendar events a user may view, caching per-server and
/// per-channel lookups for the lifetime of one request.
pub struct EventViewer<'a> {
    db: &'a Database,
    user: &'a User,
    /// Server id to the user's member row
    members: HashMap<String, Member>,
    /// Server id to the server (None when the fetch failed)
    servers: HashMap<String, Option<Server>>,
    /// Event channel id to (server id of the permission target, ViewChannel)
    /// (None when the channel cannot be resolved)
    channels: HashMap<String, Option<(String, bool)>>,
}

impl<'a> EventViewer<'a> {
    /// Build a viewer from member rows the caller has already fetched.
    ///
    /// Rows belonging to any other user are ignored: a pre-loaded member row
    /// is trusted as proof of membership by the permission calculator.
    pub fn with_memberships(db: &'a Database, user: &'a User, members: Vec<Member>) -> Self {
        EventViewer {
            db,
            user,
            members: members
                .into_iter()
                .filter(|member| {
                    let own = member.id.user == user.id;
                    debug_assert!(own, "EventViewer given a member row for another user");
                    own
                })
                .map(|member| (member.id.server.clone(), member))
                .collect(),
            servers: HashMap::new(),
            channels: HashMap::new(),
        }
    }

    /// Build a viewer for one server (no member row means nothing is visible).
    pub async fn for_server(db: &'a Database, user: &'a User, server_id: &str) -> Self {
        let members = match db.fetch_member(server_id, &user.id).await {
            Ok(member) => vec![member],
            Err(_) => vec![],
        };

        Self::with_memberships(db, user, members)
    }

    /// Whether the user may view this event.
    pub async fn can_view(&mut self, event: &CalendarEvent) -> bool {
        if !self.members.contains_key(&event.server) {
            return false;
        }

        let Some(channel_id) = &event.channel else {
            // Server-wide event: membership is sufficient.
            return true;
        };

        if !self.channels.contains_key(channel_id) {
            let resolved = self.resolve_channel(channel_id).await;
            self.channels.insert(channel_id.clone(), resolved);
        }

        // The server comparison runs on every call, never from the cache: two
        // events can name the same channel while claiming different servers.
        matches!(
            self.channels.get(channel_id),
            Some(Some((server_id, true))) if *server_id == event.server
        )
    }

    /// Resolve a channel to (server id of its permission target, ViewChannel).
    ///
    /// The verdict is computed with the member row of the target's own server,
    /// so a pre-loaded member always belongs to the pre-loaded server.
    async fn resolve_channel(&mut self, channel_id: &str) -> Option<(String, bool)> {
        let channel = self.db.fetch_channel(channel_id).await.ok()?;
        let target = resolve_event_channel_target(self.db, &channel).await?;
        let server_id = target.server()?.to_string();

        if !self.members.contains_key(&server_id) {
            return Some((server_id, false));
        }

        if !self.servers.contains_key(&server_id) {
            let server = self.db.fetch_server(&server_id).await.ok();
            self.servers.insert(server_id.clone(), server);
        }

        let verdict = match (self.servers.get(&server_id), self.members.get(&server_id)) {
            (Some(Some(server)), Some(member))
                if server.id == server_id && member.id.server == server_id =>
            {
                let mut query = DatabasePermissionQuery::new(self.db, self.user)
                    .server(server)
                    .member(member)
                    .channel(&target);

                calculate_channel_permissions(&mut query)
                    .await
                    .has_channel_permission(ChannelPermission::ViewChannel)
            }
            _ => false,
        };

        Some((server_id, verdict))
    }
}

/// Resolve the channel whose permissions govern an event channel: a thread resolves to
/// its parent text/forum channel in the same server; anything unresolvable, a parent in
/// another server, or a channel outside a server yields None.
pub async fn resolve_event_channel_target(db: &Database, channel: &Channel) -> Option<Channel> {
    try_resolve_event_channel_target(db, channel)
        .await
        .ok()
        .flatten()
}

/// As `resolve_event_channel_target`, but a lookup failure other than NotFound is
/// returned as an error instead of being treated as unresolvable.
pub async fn try_resolve_event_channel_target(
    db: &Database,
    channel: &Channel,
) -> Result<Option<Channel>> {
    let target = match channel.permission_target(db).await {
        Ok(target) => target,
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    if target.server().is_none() || target.server() != channel.server() {
        return Ok(None);
    }

    Ok(Some(target.into_owned()))
}

/// Whether `user` may view `target` as a MEMBER of `server_id`. `target` must already be
/// resolved with `resolve_event_channel_target`; a Thread, a channel outside `server_id`,
/// or a non-member yields false.
pub async fn user_can_view_channel(
    db: &Database,
    user: &User,
    server_id: &str,
    target: &Channel,
) -> bool {
    // A raw thread carries no overrides of its own; judging it would ignore
    // the parent's (callers must resolve first).
    if matches!(target, Channel::Thread { .. }) {
        return false;
    }

    if target.server() != Some(server_id) {
        return false;
    }

    // Membership first: privileged accounts are granted everything by the
    // calculator, so without this a non-member staff account would pass.
    let Ok(member) = db.fetch_member(server_id, &user.id).await else {
        return false;
    };
    if member.id.server != server_id || member.id.user != user.id {
        return false;
    }

    let mut query = DatabasePermissionQuery::new(db, user)
        .member(&member)
        .channel(target);
    calculate_channel_permissions(&mut query)
        .await
        .has_channel_permission(ChannelPermission::ViewChannel)
}

/// Require that `channel` belongs to `server_id` and that the user, as a member of
/// that server, may view it (a thread is judged by its parent).
///
/// Err(InvalidOperation) when the channel is not in `server_id`; Err(NotFound) when
/// it cannot be resolved or is not visible.
pub async fn require_event_channel_view(
    db: &Database,
    user: &User,
    server_id: &str,
    channel: &Channel,
) -> Result<()> {
    if channel.server() != Some(server_id) {
        return Err(create_error!(InvalidOperation));
    }

    let target = resolve_event_channel_target(db, channel)
        .await
        .ok_or_else(|| create_error!(NotFound))?;

    if user_can_view_channel(db, user, server_id, &target).await {
        Ok(())
    } else {
        Err(create_error!(NotFound))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use revolt_result::ErrorType;

    use super::{
        require_event_channel_view, resolve_event_channel_target, user_can_view_channel,
        EventViewer,
    };
    use crate::{
        util::test_fixtures::{load_fixture, FetchFixture},
        CalendarEvent, Channel, Database, PartialMember, User,
    };

    /// 0 owner, 1 member, 2 outsider, 3 privileged non-member, 4 privileged
    /// member of A, 5 plain member of A and B; 10 server A, 20 server B.
    /// A: 11 private text (role 40 is allowed ViewChannel on it), 12 public
    /// text, 13 thread under 11, 14 thread under 12, 15 private forum, 16 post
    /// under 15, 17 thread with a missing parent, 18 public forum, 19 post
    /// under 18, 22 thread whose parent is in B, 23 public text (deleted by
    /// one test); role 40 "Insider" (held by nobody until a test assigns it).
    /// B: 21 public text. 30 saved messages of user 1.
    const FIXTURE: &str = r#"[
      { "_object_type": "User", "_id": "__ID:0__", "username": "Owner",
        "last_acknowledged_policy_change": "2025-06-07T04:04:48+0000", "discriminator": "0001" },
      { "_object_type": "User", "_id": "__ID:1__", "username": "Member",
        "last_acknowledged_policy_change": "2025-06-07T04:04:48+0000", "discriminator": "0001" },
      { "_object_type": "User", "_id": "__ID:2__", "username": "Outsider",
        "last_acknowledged_policy_change": "2025-06-07T04:04:48+0000", "discriminator": "0001" },
      { "_object_type": "User", "_id": "__ID:3__", "username": "Staff", "privileged": true,
        "last_acknowledged_policy_change": "2025-06-07T04:04:48+0000", "discriminator": "0001" },
      { "_object_type": "User", "_id": "__ID:4__", "username": "StaffMember", "privileged": true,
        "last_acknowledged_policy_change": "2025-06-07T04:04:48+0000", "discriminator": "0001" },
      { "_object_type": "User", "_id": "__ID:5__", "username": "Bystander",
        "last_acknowledged_policy_change": "2025-06-07T04:04:48+0000", "discriminator": "0001" },
      { "_object_type": "Server", "_id": "__ID:10__", "owner": "__ID:0__", "name": "A",
        "channels": ["__ID:11__", "__ID:12__", "__ID:15__", "__ID:18__", "__ID:23__"],
        "roles": { "__ID:40__": { "_id": "__ID:40__", "name": "Insider",
          "permissions": { "a": 0, "d": 0 }, "rank": 1 } },
        "default_permissions": 4000322560 },
      { "_object_type": "Server", "_id": "__ID:20__", "owner": "__ID:0__", "name": "B",
        "channels": ["__ID:21__"], "default_permissions": 4000322560 },
      { "_object_type": "Channel", "_id": "__ID:11__", "channel_type": "TextChannel",
        "server": "__ID:10__", "name": "private", "default_permissions": { "a": 0, "d": 1048576 },
        "role_permissions": { "__ID:40__": { "a": 1048576, "d": 0 } } },
      { "_object_type": "Channel", "_id": "__ID:12__", "channel_type": "TextChannel",
        "server": "__ID:10__", "name": "public" },
      { "_object_type": "Channel", "_id": "__ID:13__", "channel_type": "Thread",
        "server": "__ID:10__", "parent_channel": "__ID:11__", "name": "hidden thread",
        "creator": "__ID:0__" },
      { "_object_type": "Channel", "_id": "__ID:14__", "channel_type": "Thread",
        "server": "__ID:10__", "parent_channel": "__ID:12__", "name": "open thread",
        "creator": "__ID:0__" },
      { "_object_type": "Channel", "_id": "__ID:15__", "channel_type": "Forum",
        "server": "__ID:10__", "name": "private forum",
        "default_permissions": { "a": 0, "d": 1048576 } },
      { "_object_type": "Channel", "_id": "__ID:16__", "channel_type": "Thread",
        "server": "__ID:10__", "parent_channel": "__ID:15__", "name": "hidden post",
        "creator": "__ID:0__" },
      { "_object_type": "Channel", "_id": "__ID:17__", "channel_type": "Thread",
        "server": "__ID:10__", "parent_channel": "__ID:99__", "name": "orphan",
        "creator": "__ID:0__" },
      { "_object_type": "Channel", "_id": "__ID:18__", "channel_type": "Forum",
        "server": "__ID:10__", "name": "public forum" },
      { "_object_type": "Channel", "_id": "__ID:19__", "channel_type": "Thread",
        "server": "__ID:10__", "parent_channel": "__ID:18__", "name": "open post",
        "creator": "__ID:0__" },
      { "_object_type": "Channel", "_id": "__ID:21__", "channel_type": "TextChannel",
        "server": "__ID:20__", "name": "other server" },
      { "_object_type": "Channel", "_id": "__ID:22__", "channel_type": "Thread",
        "server": "__ID:10__", "parent_channel": "__ID:21__", "name": "split thread",
        "creator": "__ID:0__" },
      { "_object_type": "Channel", "_id": "__ID:23__", "channel_type": "TextChannel",
        "server": "__ID:10__", "name": "doomed" },
      { "_object_type": "Channel", "_id": "__ID:30__", "channel_type": "SavedMessages",
        "user": "__ID:1__" },
      { "_object_type": "ServerMember", "_id": { "user": "__ID:0__", "server": "__ID:10__" },
        "joined_at": 1698318340195 },
      { "_object_type": "ServerMember", "_id": { "user": "__ID:1__", "server": "__ID:10__" },
        "joined_at": 1698318340195 },
      { "_object_type": "ServerMember", "_id": { "user": "__ID:0__", "server": "__ID:20__" },
        "joined_at": 1698318340195 },
      { "_object_type": "ServerMember", "_id": { "user": "__ID:1__", "server": "__ID:20__" },
        "joined_at": 1698318340195 },
      { "_object_type": "ServerMember", "_id": { "user": "__ID:4__", "server": "__ID:10__" },
        "joined_at": 1698318340195 },
      { "_object_type": "ServerMember", "_id": { "user": "__ID:5__", "server": "__ID:10__" },
        "joined_at": 1698318340195 },
      { "_object_type": "ServerMember", "_id": { "user": "__ID:5__", "server": "__ID:20__" },
        "joined_at": 1698318340195 }
    ]"#;

    const A: usize = 10;
    const B: usize = 20;

    fn id(ids: &HashMap<String, String>, d: usize) -> String {
        ids.get(&d.to_string()).unwrap().clone()
    }

    fn event(server: &str, channel: Option<&str>) -> CalendarEvent {
        CalendarEvent {
            id: ulid::Ulid::new().to_string(),
            server: server.to_string(),
            channel: channel.map(str::to_string),
            creator: "01CREATOR".to_string(),
            title: "Event".to_string(),
            description: None,
            location: None,
            start: 1_900_000_000_000,
            end: None,
            duration_ms: 0,
            series_end: 1_900_000_000_000,
            all_day: false,
            timezone: "UTC".to_string(),
            recurrence: None,
            color: None,
            cancelled: false,
            source_message_id: None,
            attachments: None,
            created_at: 1_800_000_000_000,
            edited_at: None,
        }
    }

    /// Fresh single-server viewer verdict for (event server, event channel).
    async fn sees(
        db: &Database,
        ids: &HashMap<String, String>,
        user: usize,
        server: usize,
        channel: Option<usize>,
    ) -> bool {
        let user = ids.user(db, user).await;
        let server_id = id(ids, server);
        let channel_id = channel.map(|d| id(ids, d));
        let mut viewer = EventViewer::for_server(db, &user, &server_id).await;
        viewer
            .can_view(&event(&server_id, channel_id.as_deref()))
            .await
    }

    /// The two-step path routes use: resolve the target, then judge it.
    async fn views(db: &Database, user: &User, server_id: &str, channel: &Channel) -> bool {
        match resolve_event_channel_target(db, channel).await {
            Some(target) => user_can_view_channel(db, user, server_id, &target).await,
            None => false,
        }
    }

    #[tokio::test]
    async fn server_wide_events_follow_membership() {
        database_test!(|db| async move {
            let ids = load_fixture(&db, FIXTURE).await;

            assert!(sees(&db, &ids, 1, A, None).await);
            assert!(sees(&db, &ids, 0, A, None).await);
            assert!(!sees(&db, &ids, 2, A, None).await);

            // No member row for the event's server.
            let member = ids.user(&db, 1).await;
            let mut empty = EventViewer::with_memberships(&db, &member, vec![]);
            assert!(!empty.can_view(&event(&id(&ids, A), None)).await);

            let row_a = ids.member(&db, A, 1).await;
            let mut only_a = EventViewer::with_memberships(&db, &member, vec![row_a]);
            assert!(only_a.can_view(&event(&id(&ids, A), None)).await);
            assert!(!only_a.can_view(&event(&id(&ids, B), None)).await);
        });
    }

    #[tokio::test]
    async fn channel_overrides_apply() {
        database_test!(|db| async move {
            let ids = load_fixture(&db, FIXTURE).await;

            assert!(!sees(&db, &ids, 1, A, Some(11)).await);
            assert!(sees(&db, &ids, 1, A, Some(12)).await);
            assert!(sees(&db, &ids, 0, A, Some(11)).await);
            assert!(!sees(&db, &ids, 2, A, Some(12)).await);
        });
    }

    #[tokio::test]
    async fn threads_take_parent_permissions() {
        database_test!(|db| async move {
            let ids = load_fixture(&db, FIXTURE).await;

            // Thread under a channel the member cannot view.
            assert!(!sees(&db, &ids, 1, A, Some(13)).await);
            // Forum post under a forum the member cannot view.
            assert!(!sees(&db, &ids, 1, A, Some(16)).await);
            // Visible parents.
            assert!(sees(&db, &ids, 1, A, Some(14)).await);
            assert!(sees(&db, &ids, 1, A, Some(19)).await);
            // The owner sees everything in their server.
            assert!(sees(&db, &ids, 0, A, Some(13)).await);
            assert!(sees(&db, &ids, 0, A, Some(16)).await);

            // Same verdicts through one multi-server viewer with a warm cache.
            let member = ids.user(&db, 1).await;
            let rows = vec![ids.member(&db, A, 1).await, ids.member(&db, B, 1).await];
            let mut viewer = EventViewer::with_memberships(&db, &member, rows);
            let a = id(&ids, A);
            for _ in 0..2 {
                assert!(!viewer.can_view(&event(&a, Some(&id(&ids, 13)))).await);
                assert!(viewer.can_view(&event(&a, Some(&id(&ids, 14)))).await);
                assert!(!viewer.can_view(&event(&a, Some(&id(&ids, 16)))).await);
                assert!(viewer.can_view(&event(&a, Some(&id(&ids, 19)))).await);
            }
        });
    }

    #[tokio::test]
    async fn event_claiming_another_servers_channel_is_hidden() {
        database_test!(|db| async move {
            let ids = load_fixture(&db, FIXTURE).await;
            let member = ids.user(&db, 1).await;
            let (a, b) = (id(&ids, A), id(&ids, B));
            let public_a = id(&ids, 12);

            // Valid event first, so the channel is cached as visible.
            let rows = vec![ids.member(&db, A, 1).await, ids.member(&db, B, 1).await];
            let mut viewer = EventViewer::with_memberships(&db, &member, rows.clone());
            assert!(viewer.can_view(&event(&a, Some(&public_a))).await);
            assert!(!viewer.can_view(&event(&b, Some(&public_a))).await);
            assert!(viewer.can_view(&event(&a, Some(&public_a))).await);

            // Mismatched event first: it must not hide the valid one.
            let mut viewer = EventViewer::with_memberships(&db, &member, rows.clone());
            assert!(!viewer.can_view(&event(&b, Some(&public_a))).await);
            assert!(viewer.can_view(&event(&a, Some(&public_a))).await);

            // Single-server viewer for B.
            assert!(!sees(&db, &ids, 1, B, Some(12)).await);

            // A thread recorded in A whose parent lives in B resolves nowhere.
            let split = id(&ids, 22);
            let mut viewer = EventViewer::with_memberships(&db, &member, rows);
            assert!(!viewer.can_view(&event(&a, Some(&split))).await);
            assert!(!viewer.can_view(&event(&b, Some(&split))).await);
        });
    }

    #[tokio::test]
    async fn unresolvable_channels_are_hidden() {
        database_test!(|db| async move {
            let ids = load_fixture(&db, FIXTURE).await;

            // Deleted channel.
            assert!(sees(&db, &ids, 1, A, Some(23)).await);
            let doomed = ids.channel(&db, 23).await;
            db.delete_channel(&doomed).await.unwrap();
            assert!(!sees(&db, &ids, 1, A, Some(23)).await);
            assert!(!sees(&db, &ids, 0, A, Some(23)).await);

            // Channel id that never existed.
            let member = ids.user(&db, 1).await;
            let a = id(&ids, A);
            let mut viewer = EventViewer::for_server(&db, &member, &a).await;
            let missing = ulid::Ulid::new().to_string();
            assert!(!viewer.can_view(&event(&a, Some(&missing))).await);

            // Thread whose parent is gone, even for the owner.
            assert!(!sees(&db, &ids, 1, A, Some(17)).await);
            assert!(!sees(&db, &ids, 0, A, Some(17)).await);

            // Not a server channel.
            assert!(!sees(&db, &ids, 1, A, Some(30)).await);
        });
    }

    #[tokio::test]
    async fn require_event_channel_view_checks() {
        database_test!(|db| async move {
            let ids = load_fixture(&db, FIXTURE).await;
            let owner = ids.user(&db, 0).await;
            let member = ids.user(&db, 1).await;
            let outsider = ids.user(&db, 2).await;
            let a = id(&ids, A);

            let error_of = |result: revolt_result::Result<()>| result.unwrap_err().error_type;

            // Channel from another server, or not a server channel at all.
            let other = ids.channel(&db, 21).await;
            assert!(matches!(
                error_of(require_event_channel_view(&db, &member, &a, &other).await),
                ErrorType::InvalidOperation
            ));
            let saved = ids.channel(&db, 30).await;
            assert!(matches!(
                error_of(require_event_channel_view(&db, &member, &a, &saved).await),
                ErrorType::InvalidOperation
            ));

            // Hidden from the member.
            for d in [11, 13, 16, 17, 22] {
                let channel = ids.channel(&db, d).await;
                assert!(
                    matches!(
                        error_of(require_event_channel_view(&db, &member, &a, &channel).await),
                        ErrorType::NotFound
                    ),
                    "channel {d}"
                );
            }

            // Not a member at all.
            let public = ids.channel(&db, 12).await;
            assert!(matches!(
                error_of(require_event_channel_view(&db, &outsider, &a, &public).await),
                ErrorType::NotFound
            ));

            // Visible.
            for d in [12, 14, 19] {
                let channel = ids.channel(&db, d).await;
                assert!(
                    require_event_channel_view(&db, &member, &a, &channel)
                        .await
                        .is_ok(),
                    "channel {d}"
                );
            }
            let hidden_thread = ids.channel(&db, 13).await;
            assert!(require_event_channel_view(&db, &owner, &a, &hidden_thread)
                .await
                .is_ok());
        });
    }

    #[tokio::test]
    async fn user_can_view_channel_resolves_parents() {
        database_test!(|db| async move {
            let ids = load_fixture(&db, FIXTURE).await;
            let owner = ids.user(&db, 0).await;
            let member = ids.user(&db, 1).await;
            let outsider = ids.user(&db, 2).await;
            let a = id(&ids, A);

            for (d, expected) in [
                (11, false),
                (12, true),
                (13, false),
                (14, true),
                (16, false),
                (17, false),
                (19, true),
                (22, false),
            ] {
                let channel = ids.channel(&db, d).await;
                assert_eq!(
                    views(&db, &member, &a, &channel).await,
                    expected,
                    "channel {d}"
                );
            }

            let hidden_thread = ids.channel(&db, 13).await;
            assert!(views(&db, &owner, &a, &hidden_thread).await);
            let public = ids.channel(&db, 12).await;
            assert!(!views(&db, &outsider, &a, &public).await);
        });
    }

    #[tokio::test]
    async fn resolve_event_channel_target_cases() {
        database_test!(|db| async move {
            let ids = load_fixture(&db, FIXTURE).await;
            let target_of = |d: usize| {
                let (db, ids) = (db.clone(), ids.clone());
                async move {
                    let channel = ids.channel(&db, d).await;
                    resolve_event_channel_target(&db, &channel)
                        .await
                        .map(|target| target.id().to_string())
                }
            };

            // Threads and forum posts resolve to their parent.
            assert_eq!(target_of(13).await, Some(id(&ids, 11)));
            assert_eq!(target_of(14).await, Some(id(&ids, 12)));
            assert_eq!(target_of(16).await, Some(id(&ids, 15)));
            assert_eq!(target_of(19).await, Some(id(&ids, 18)));
            // Text and forum channels resolve to themselves.
            assert_eq!(target_of(12).await, Some(id(&ids, 12)));
            assert_eq!(target_of(15).await, Some(id(&ids, 15)));
            // Orphan thread, parent in another server, not a server channel.
            assert_eq!(target_of(17).await, None);
            assert_eq!(target_of(22).await, None);
            assert_eq!(target_of(30).await, None);
        });
    }

    #[tokio::test]
    async fn user_can_view_channel_rejects_unresolved_inputs() {
        database_test!(|db| async move {
            let ids = load_fixture(&db, FIXTURE).await;
            let owner = ids.user(&db, 0).await;
            let member = ids.user(&db, 1).await;
            let outsider = ids.user(&db, 2).await;
            let (a, b) = (id(&ids, A), id(&ids, B));

            // A raw thread is refused even when its parent is visible, even for
            // the owner: the caller skipped `resolve_event_channel_target`.
            for d in [13, 14, 19] {
                let thread = ids.channel(&db, d).await;
                assert!(
                    !user_can_view_channel(&db, &owner, &a, &thread).await,
                    "raw thread {d}"
                );
                assert!(
                    !user_can_view_channel(&db, &member, &a, &thread).await,
                    "raw thread {d}"
                );
            }

            // Target in another server than the one named.
            let other = ids.channel(&db, 21).await;
            assert!(user_can_view_channel(&db, &member, &b, &other).await);
            assert!(!user_can_view_channel(&db, &member, &a, &other).await);
            let public_a = ids.channel(&db, 12).await;
            assert!(!user_can_view_channel(&db, &member, &b, &public_a).await);

            // Not a member.
            assert!(!user_can_view_channel(&db, &outsider, &a, &public_a).await);

            // Not a server channel.
            let saved = ids.channel(&db, 30).await;
            assert!(!user_can_view_channel(&db, &member, &a, &saved).await);
        });
    }

    /// A role override that allows ViewChannel on a private channel opens that
    /// channel and its threads to holders of the role, and only to them.
    #[tokio::test]
    async fn role_override_opens_private_channel() {
        database_test!(|db| async move {
            let ids = load_fixture(&db, FIXTURE).await;
            let (a, b) = (id(&ids, A), id(&ids, B));
            let role = id(&ids, 40);

            // Before the role is assigned.
            assert!(!sees(&db, &ids, 1, A, Some(11)).await);
            assert!(!sees(&db, &ids, 1, A, Some(13)).await);

            let row = ids.member(&db, A, 1).await;
            db.update_member(
                &row.id,
                &PartialMember {
                    roles: Some(vec![role.clone()]),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .unwrap();
            assert_eq!(ids.member(&db, A, 1).await.roles, vec![role]);

            // Single-server viewer.
            assert!(
                sees(&db, &ids, 1, A, Some(11)).await,
                "role holder, channel"
            );
            assert!(sees(&db, &ids, 1, A, Some(13)).await, "role holder, thread");
            // The role does not open the private forum.
            assert!(!sees(&db, &ids, 1, A, Some(16)).await);

            // Two-server viewer built from fresh member rows.
            let holder = ids.user(&db, 1).await;
            let rows = vec![ids.member(&db, A, 1).await, ids.member(&db, B, 1).await];
            let mut viewer = EventViewer::with_memberships(&db, &holder, rows);
            for _ in 0..2 {
                assert!(viewer.can_view(&event(&a, Some(&id(&ids, 11)))).await);
                assert!(viewer.can_view(&event(&a, Some(&id(&ids, 13)))).await);
                assert!(!viewer.can_view(&event(&a, Some(&id(&ids, 16)))).await);
                assert!(viewer.can_view(&event(&b, Some(&id(&ids, 21)))).await);
            }

            // The route helpers agree.
            let private = ids.channel(&db, 11).await;
            let thread = ids.channel(&db, 13).await;
            assert!(views(&db, &holder, &a, &private).await);
            assert!(views(&db, &holder, &a, &thread).await);
            assert!(require_event_channel_view(&db, &holder, &a, &thread)
                .await
                .is_ok());

            // A member without the role still sees neither.
            assert!(!sees(&db, &ids, 5, A, Some(11)).await);
            assert!(!sees(&db, &ids, 5, A, Some(13)).await);
            let bystander = ids.user(&db, 5).await;
            let rows = vec![ids.member(&db, A, 5).await, ids.member(&db, B, 5).await];
            let mut viewer = EventViewer::with_memberships(&db, &bystander, rows);
            assert!(!viewer.can_view(&event(&a, Some(&id(&ids, 11)))).await);
            assert!(!viewer.can_view(&event(&a, Some(&id(&ids, 13)))).await);
            assert!(viewer.can_view(&event(&a, Some(&id(&ids, 12)))).await);
            assert!(!views(&db, &bystander, &a, &private).await);
            assert!(!views(&db, &bystander, &a, &thread).await);
        });
    }

    /// Privileged accounts see channel events only in servers they belong to.
    #[tokio::test]
    async fn privileged_accounts_need_membership() {
        database_test!(|db| async move {
            let ids = load_fixture(&db, FIXTURE).await;
            let a = id(&ids, A);
            let staff = ids.user(&db, 3).await;
            assert!(staff.privileged, "fixture: user 3 is privileged");
            let private = ids.channel(&db, 11).await;
            let public = ids.channel(&db, 12).await;
            let thread = ids.channel(&db, 13).await;

            // Not a member of A.
            assert!(!sees(&db, &ids, 3, A, None).await);
            assert!(!sees(&db, &ids, 3, A, Some(11)).await);
            assert!(!sees(&db, &ids, 3, A, Some(12)).await);
            for channel in [&private, &public] {
                assert!(
                    !user_can_view_channel(&db, &staff, &a, channel).await,
                    "privileged non-member must not view {}",
                    channel.id()
                );
            }
            assert!(!views(&db, &staff, &a, &thread).await);
            for channel in [&private, &public, &thread] {
                assert!(matches!(
                    require_event_channel_view(&db, &staff, &a, channel)
                        .await
                        .unwrap_err()
                        .error_type,
                    ErrorType::NotFound
                ));
            }

            // A privileged member sees the private channel and its thread.
            let staff_member = ids.user(&db, 4).await;
            assert!(staff_member.privileged, "fixture: user 4 is privileged");
            assert!(sees(&db, &ids, 4, A, Some(11)).await);
            assert!(sees(&db, &ids, 4, A, Some(13)).await);
            assert!(user_can_view_channel(&db, &staff_member, &a, &private).await);
            assert!(views(&db, &staff_member, &a, &thread).await);
            assert!(require_event_channel_view(&db, &staff_member, &a, &thread)
                .await
                .is_ok());
        });
    }

    /// A member row for someone else is flagged in debug builds (and dropped
    /// in release builds, where the viewer then treats the server as unjoined).
    #[cfg(debug_assertions)]
    #[tokio::test]
    #[should_panic(expected = "EventViewer given a member row for another user")]
    async fn with_memberships_flags_foreign_rows() {
        database_test!(|db| async move {
            let ids = load_fixture(&db, FIXTURE).await;
            let outsider = ids.user(&db, 2).await;
            let someone_elses = ids.member(&db, A, 1).await;
            let _ = EventViewer::with_memberships(&db, &outsider, vec![someone_elses]);
        });
    }

    #[tokio::test]
    async fn can_view_future_is_send() {
        database_test!(|db| async move {
            fn assert_send<T: Send>(_: &T) {}

            let ids = load_fixture(&db, FIXTURE).await;
            let member = ids.user(&db, 1).await;
            let a = id(&ids, A);
            let mut viewer = EventViewer::for_server(&db, &member, &a).await;
            let event = event(&a, Some(&id(&ids, 12)));
            let future = viewer.can_view(&event);
            assert_send(&future);
            assert!(future.await);
        });
    }
}
