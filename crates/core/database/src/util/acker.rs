use std::collections::{HashMap, HashSet};

use redis_kiss::{get_connection, AsyncCommands};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{Result, ToRevoltError};

use crate::{events::client::EventV1, Channel, ChannelUnread, Database, Server, User, AMQP};

/// Redis key holding the newest read pointer for a user in a channel until
/// crond commits it to the database.
fn acker_key(user: &str, channel: &str) -> String {
    format!("acker:{user}+{channel}")
}

/// Record a read pointer and tell crond to commit it.
///
/// The pointer goes into Redis and a `process_ack` event goes to crond, which
/// takes the pointer with `GETDEL` and writes it. The event is published on
/// EVERY ack, never only when the key was absent: that older dedup assumed
/// the in-flight event would be processed, and when it was rejected instead
/// (a Redis or broker restart under crond) the key outlived the event and
/// every later ack for that pair was skipped for good, so the user's reads
/// never reached the database again. A redundant event costs one `GETDEL`
/// that finds nothing; a missing one costs a read that never persists.
async fn record_and_publish(
    user: &str,
    channel: &str,
    message: &str,
    server: Option<&str>,
    amqp: &AMQP,
) -> Result<()> {
    let mut redis = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?;

    let _: () = redis
        .set(acker_key(user, channel), message)
        .await
        .to_internal_error()?;

    debug!("Recorded read pointer for {channel}:{user}, publishing to crond");

    amqp.process_ack(user, Some(channel), server)
        .await
        .to_internal_error()
}

pub async fn ack_channel(user: &str, channel: &str, message: &str, amqp: &AMQP) -> Result<()> {
    record_and_publish(user, channel, message, None, amqp).await
}

/// Mark a whole server as read for a user.
///
/// Acks every pair chosen by `server_ack_targets`, in its order. The first
/// failure to record a pointer aborts the rest, as it always has.
pub async fn ack_server(user: &User, server: &Server, db: &Database, amqp: &AMQP) -> Result<()> {
    for (channel_id, message_id) in server_ack_targets(user, server, db).await? {
        record_and_publish(&user.id, &channel_id, &message_id, Some(&server.id), amqp).await?;

        EventV1::ChannelAck {
            id: channel_id,
            user: user.id.clone(),
            message_id,
        }
        .private(user.id.clone())
        .await;
    }

    Ok(())
}

/// Work out what a server-wide mark-as-read acks, as
/// `(channel id, message id)` pairs.
///
/// The top-level channels the user can view come first, in the order they
/// were fetched, each at its `last_message_id`. Threads and forum posts
/// follow, sorted by id (see [`thread_ack_targets`]). No channel appears
/// twice.
///
/// Kept apart from `ack_server` so the selection can be tested without Redis
/// or a broker.
pub(crate) async fn server_ack_targets(
    user: &User,
    server: &Server,
    db: &Database,
) -> Result<Vec<(String, String)>> {
    let channels = db.fetch_channels(&server.channels).await?;
    let query = crate::util::permissions::DatabasePermissionQuery::new(db, user).server(server);

    let mut targets = Vec::new();
    let mut visible_parents = HashSet::new();

    for channel in channels {
        // Only text channels and forums are acked here or used as parents.
        // Anything else is skipped before a permission query is built: a
        // Thread given to the query resolves as a server channel with no
        // overrides, so it would pass a member who cannot see its parent.
        let last_message_id = match &channel {
            Channel::TextChannel {
                last_message_id, ..
            }
            | Channel::Forum {
                last_message_id, ..
            } => last_message_id.clone(),
            _ => continue,
        };

        let mut q = query.clone().channel(&channel);
        if !calculate_channel_permissions(&mut q)
            .await
            .has_channel_permission(ChannelPermission::ViewChannel)
        {
            continue;
        }

        // A visible channel is a parent even without messages of its own: a
        // forum can have unread posts while it has no pointer. An id listed
        // twice in `server.channels` is acked once.
        if !visible_parents.insert(channel.id().to_string()) {
            continue;
        }

        if let Some(last_message_id) = last_message_id {
            targets.push((channel.id().to_string(), last_message_id));
        }
    }

    // The thread half is best-effort. Acking less is always safe: the
    // top-level channels still go through and the threads keep their badges.
    match thread_ack_targets(user, server, db, &visible_parents).await {
        Ok(thread_targets) => targets.extend(thread_targets),
        Err(err) => {
            error!(
                "Skipped thread acks while marking server {} as read: {err:?}",
                server.id
            );
            revolt_config::capture_error(&err);
        }
    }

    Ok(targets)
}

/// Threads and forum posts a server-wide mark-as-read acks, sorted by id.
///
/// Threads have no permission overrides of their own: a thread is visible
/// exactly when its parent is, which is also how bonfire and the channel ack
/// route decide it. Visibility is therefore taken from `visible_parents` and
/// never calculated on a thread. The ids come only from those parents, and
/// each fetched thread is checked against them again.
///
/// Only threads the user has joined or has an unread row for are considered.
/// Anything else is a post the user never opened; forum posts and archived
/// threads are uncapped, and acking each one would write a permanent unread
/// row per post. Of those candidates, only the ones still unread are acked
/// (see [`thread_is_unread`]).
async fn thread_ack_targets(
    user: &User,
    server: &Server,
    db: &Database,
    visible_parents: &HashSet<String>,
) -> Result<Vec<(String, String)>> {
    if visible_parents.is_empty() {
        return Ok(vec![]);
    }

    let parent_ids: Vec<String> = visible_parents.iter().cloned().collect();
    let thread_ids: HashSet<String> = db
        .fetch_thread_ids_by_parents(&parent_ids)
        .await?
        .into_iter()
        .collect();

    if thread_ids.is_empty() {
        return Ok(vec![]);
    }

    let joined = db.fetch_joined_thread_ids(&user.id, &server.id).await?;
    let rows: HashMap<String, ChannelUnread> = db
        .fetch_unreads(&user.id)
        .await?
        .into_iter()
        .filter(|row| thread_ids.contains(&row.id.channel))
        .map(|row| (row.id.channel.clone(), row))
        .collect();

    let mut candidates: Vec<String> = joined
        .into_iter()
        .filter(|id| thread_ids.contains(id))
        .chain(rows.keys().cloned())
        .collect();
    candidates.sort();
    candidates.dedup();

    if candidates.is_empty() {
        return Ok(vec![]);
    }

    let mut targets = Vec::new();
    for channel in db.fetch_channels(&candidates).await? {
        if let Channel::Thread {
            id,
            server: thread_server,
            parent_channel,
            last_message_id: Some(last_message_id),
            ..
        } = channel
        {
            if thread_server == server.id
                && visible_parents.contains(&parent_channel)
                && thread_is_unread(rows.get(&id), &last_message_id)
            {
                targets.push((id, last_message_id));
            }
        }
    }

    targets.sort();
    Ok(targets)
}

/// Whether a thread whose newest message is `last_message_id` still shows as
/// unread to a user whose unread row for it is `row`.
///
/// A row pointing past `last_message_id` is never treated as unread. That
/// pointer is the user's own newer ack, written while the thread's
/// `last_message_id` still waits on the debounced last-message-id worker.
/// crond commits a pointer with an unconditional `$set`, so acking the older
/// id would move the user's read position backwards.
fn thread_is_unread(row: Option<&ChannelUnread>, last_message_id: &str) -> bool {
    let Some(row) = row else {
        return true;
    };

    match row.last_id.as_deref() {
        None => true,
        Some(last_id) if last_id < last_message_id => true,
        // Read up to the newest message, but a mention up to that point still
        // draws a badge. After a `$pull` MongoDB keeps `Some([])` where the
        // reference driver has `None`, so look at the contents, not the Option.
        Some(last_id) if last_id == last_message_id => row
            .mentions
            .as_ref()
            .is_some_and(|mentions| mentions.iter().any(|m| m.as_str() <= last_message_id)),
        Some(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::{fixture, Channel, ChannelCompositeKey, ChannelUnread, Database};

    use super::{server_ack_targets, thread_is_unread};

    // Every message id in these tests comes from this one ordered family, so
    // comparisons between them mean what the names say. `Ulid::new()` ids
    // start with `01K` and would sort before all of them.
    const MSG_OLD: &str = "01SATKM0000000000000000001";
    const MSG_P1: &str = "01SATKM0000000000000000010";
    const MSG_CH3: &str = "01SATKM0000000000000000011";
    const MSG_T1: &str = "01SATKM0000000000000000012";
    const MSG_T2: &str = "01SATKM0000000000000000013";
    const MSG_T3: &str = "01SATKM0000000000000000014";
    const MSG_T5: &str = "01SATKM0000000000000000015";
    const MSG_T6: &str = "01SATKM0000000000000000016";
    const MSG_T7: &str = "01SATKM0000000000000000017";
    const MSG_T7B: &str = "01SATKM0000000000000000018";
    const MSG_T9: &str = "01SATKM0000000000000000019";
    const MSG_T10: &str = "01SATKM0000000000000000020";
    const MSG_T8: &str = "01SATKM0000000000000000021";
    const MSG_T8B: &str = "01SATKM0000000000000000022";
    const MSG_TX: &str = "01SATKM0000000000000000023";
    const MSG_NEWER: &str = "01SATKM0000000000000000030";

    const P1: &str = "01SATKC00000000000000000P1";
    const P2: &str = "01SATKC00000000000000000P2";
    const P8: &str = "01SATKC00000000000000000P8";
    const T1: &str = "01SATKC00000000000000000T1";
    const T2: &str = "01SATKC00000000000000000T2";
    const T3: &str = "01SATKC00000000000000000T3";
    const T4: &str = "01SATKC00000000000000000T4";
    const T5: &str = "01SATKC00000000000000000T5";
    const T6: &str = "01SATKC00000000000000000T6";
    const T7: &str = "01SATKC00000000000000000T7";
    const T7B: &str = "01SATKC0000000000000000T7B";
    const T8: &str = "01SATKC00000000000000000T8";
    const T8B: &str = "01SATKC0000000000000000T8B";
    const T9: &str = "01SATKC00000000000000000T9";
    const T10: &str = "01SATKC0000000000000000T10";
    const TX: &str = "01SATKC00000000000000000TX";
    const OTHER_SERVER: &str = "01SATKS0000000000000000002";

    fn text_channel(id: &str, server: &str, last_message_id: Option<&str>) -> Channel {
        Channel::TextChannel {
            id: id.to_string(),
            server: server.to_string(),
            name: "text".to_string(),
            description: None,
            icon: None,
            last_message_id: last_message_id.map(str::to_string),
            default_permissions: None,
            role_permissions: Default::default(),
            nsfw: false,
            spoiler: false,
            voice: None,
            slowmode: None,
            announcement: None,
        }
    }

    fn forum(id: &str, server: &str) -> Channel {
        Channel::Forum {
            id: id.to_string(),
            server: server.to_string(),
            name: "forum".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: Default::default(),
            nsfw: false,
            spoiler: false,
            tags: vec![],
            require_tag: false,
            default_sort: Default::default(),
            force_sort: false,
            default_layout: Default::default(),
            default_auto_archive_minutes: Channel::default_forum_auto_archive_minutes(),
        }
    }

    fn thread(
        id: &str,
        server: &str,
        parent: &str,
        last_message_id: Option<&str>,
        archived: bool,
        locked: bool,
    ) -> Channel {
        Channel::Thread {
            id: id.to_string(),
            server: server.to_string(),
            parent_channel: parent.to_string(),
            name: "thread".to_string(),
            creator: "01SATKV0000000000000000001".to_string(),
            origin_message_id: None,
            last_message_id: last_message_id.map(str::to_string),
            archived,
            archived_timestamp: None,
            auto_archive_minutes: Channel::default_auto_archive_minutes(),
            locked,
            applied_tags: vec![],
        }
    }

    fn row(last_id: Option<&str>, mentions: Option<&[&str]>) -> ChannelUnread {
        ChannelUnread {
            id: ChannelCompositeKey {
                channel: T1.to_string(),
                user: "01SATKV0000000000000000002".to_string(),
            },
            last_id: last_id.map(str::to_string),
            mentions: mentions.map(|ids| ids.iter().map(|id| id.to_string()).collect()),
        }
    }

    fn assert_target(targets: &[(String, String)], id: &str, message_id: &str, case: &str) {
        assert!(
            targets.contains(&(id.to_string(), message_id.to_string())),
            "{case}; targets: {targets:?}"
        );
    }

    fn assert_absent(targets: &[(String, String)], id: &str, case: &str) {
        assert!(
            !targets.iter().any(|(channel, _)| channel == id),
            "{case}; targets: {targets:?}"
        );
    }

    /// Asserts the exact set of targets, that no channel appears twice, and
    /// that the `top_level` ids come first with the threads after them in id
    /// order.
    fn assert_exact(
        targets: &[(String, String)],
        top_level: &[(&str, &str)],
        threads: &[(&str, &str)],
        who: &str,
    ) {
        let channels: HashSet<&str> = targets.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(
            channels.len(),
            targets.len(),
            "no channel may be acked twice for {who}; targets: {targets:?}"
        );

        let got: HashSet<(&str, &str)> = targets
            .iter()
            .map(|(id, message)| (id.as_str(), message.as_str()))
            .collect();
        let expected: HashSet<(&str, &str)> =
            top_level.iter().chain(threads.iter()).copied().collect();
        assert_eq!(got, expected, "exact target set for {who}");

        let head: HashSet<(&str, &str)> = targets[..top_level.len()]
            .iter()
            .map(|(id, message)| (id.as_str(), message.as_str()))
            .collect();
        assert_eq!(
            head,
            top_level.iter().copied().collect::<HashSet<_>>(),
            "top-level channels must come before threads for {who}; targets: {targets:?}"
        );

        let mut sorted_threads = threads.to_vec();
        sorted_threads.sort();
        let tail: Vec<(&str, &str)> = targets[top_level.len()..]
            .iter()
            .map(|(id, message)| (id.as_str(), message.as_str()))
            .collect();
        assert_eq!(
            tail, sorted_threads,
            "threads must follow in id order for {who}"
        );
    }

    /// Seeds the case table onto the `server_with_roles` fixture. `ch3` is the
    /// fixture channel that only the moderator (user 1) can view; user 2 is a
    /// plain member.
    #[allow(clippy::disallowed_methods)]
    async fn seed_case_table(db: &Database, server: &str, ch3: &str, user1: &str, user2: &str) {
        let insert = |channel: Channel| async move { db.insert_channel(&channel).await.unwrap() };

        assert!(db
            .set_last_message_id_if_newer(ch3, MSG_CH3, false)
            .await
            .unwrap());

        insert(text_channel(P1, server, Some(MSG_P1))).await;
        insert(forum(P2, server)).await;

        // T1: joined, unread, no row.
        insert(thread(T1, server, P1, Some(MSG_T1), false, false)).await;
        db.join_thread_if_absent(T1, user2).await.unwrap();

        // T2: under the hidden ch3, joined by both users.
        insert(thread(T2, server, ch3, Some(MSG_T2), false, false)).await;
        db.join_thread_if_absent(T2, user1).await.unwrap();
        db.join_thread_if_absent(T2, user2).await.unwrap();

        // T3: forum post, not joined, row behind the newest message.
        insert(thread(T3, server, P2, Some(MSG_T3), false, false)).await;
        db.acknowledge_message(T3, user2, MSG_OLD).await.unwrap();

        // T4: joined, no messages yet.
        insert(thread(T4, server, P1, None, false, false)).await;
        db.join_thread_if_absent(T4, user2).await.unwrap();

        // T5: archived and locked, joined.
        insert(thread(T5, server, P1, Some(MSG_T5), true, true)).await;
        db.join_thread_if_absent(T5, user2).await.unwrap();

        // T6: never joined, never opened.
        insert(thread(T6, server, P1, Some(MSG_T6), false, false)).await;

        // T7: joined and read up to the newest message.
        insert(thread(T7, server, P1, Some(MSG_T7), false, false)).await;
        db.join_thread_if_absent(T7, user2).await.unwrap();
        db.acknowledge_message(T7, user2, MSG_T7).await.unwrap();

        // T7b: an older mention cleared by the ack. MongoDB leaves
        // `mentions: []`, the reference driver `None`.
        insert(thread(T7B, server, P1, Some(MSG_T7B), false, false)).await;
        db.add_mention_to_unread(T7B, user2, &[MSG_OLD.to_string()])
            .await
            .unwrap();
        db.acknowledge_message(T7B, user2, MSG_T7B).await.unwrap();

        // T9: read up to the newest message, then a mention at or before it.
        insert(thread(T9, server, P1, Some(MSG_T9), false, false)).await;
        db.acknowledge_message(T9, user2, MSG_T9).await.unwrap();
        db.add_mention_to_unread(T9, user2, &[MSG_OLD.to_string()])
            .await
            .unwrap();

        // T10: the row is already past the thread's newest message.
        insert(thread(T10, server, P1, Some(MSG_T10), false, false)).await;
        db.acknowledge_message(T10, user2, MSG_NEWER).await.unwrap();
        db.add_mention_to_unread(T10, user2, &[MSG_OLD.to_string()])
            .await
            .unwrap();

        // T8: a thread in another server, joined and with a row.
        insert(text_channel(P8, OTHER_SERVER, None)).await;
        insert(thread(T8, OTHER_SERVER, P8, Some(MSG_T8), false, false)).await;
        db.join_thread_if_absent(T8, user2).await.unwrap();
        db.acknowledge_message(T8, user2, MSG_OLD).await.unwrap();

        // T8b: a document under P1 that names another server. It can only be
        // a candidate through its row, and only the server re-check drops it.
        insert(thread(T8B, OTHER_SERVER, P1, Some(MSG_T8B), false, false)).await;
        db.join_thread_if_absent(T8B, user2).await.unwrap();
        db.acknowledge_message(T8B, user2, MSG_OLD).await.unwrap();
    }

    #[tokio::test]
    async fn server_ack_targets_case_table() {
        database_test!(|db| async move {
            fixture!(db, "server_with_roles",
                owner user 0
                moderator user 1
                user user 2
                channel channel 3
                server server 4);

            let ch3 = channel.id().to_string();
            seed_case_table(&db, &server.id, &ch3, &moderator.id, &user.id).await;

            let mut server = server;
            server.channels.push(P1.to_string());
            server.channels.push(P2.to_string());

            let targets = server_ack_targets(&user, &server, &db)
                .await
                .expect("server_ack_targets must succeed for user 2");

            assert_target(&targets, P1, MSG_P1, "P1 must be a target for user 2");
            assert_absent(&targets, P2, "P2 has no messages and must be absent");
            assert_absent(&targets, &ch3, "ch3 must be absent for user 2");
            assert_target(&targets, T1, MSG_T1, "T1 must be a target for user 2");
            assert_absent(&targets, T2, "T2 must be absent for user 2");
            assert_target(&targets, T3, MSG_T3, "T3 must be a target for user 2");
            assert_absent(&targets, T4, "T4 has no messages and must be absent");
            assert_target(&targets, T5, MSG_T5, "T5 must be a target for user 2");
            assert_absent(&targets, T6, "T6 (unjoined, no row) must be absent");
            assert_absent(&targets, T7, "T7 is caught up and must be absent");
            assert_absent(&targets, T7B, "T7b is caught up and must be absent");
            assert_target(&targets, T9, MSG_T9, "T9 must be a target for user 2");
            assert_absent(&targets, T10, "T10 must be absent (no rewind)");
            assert_absent(&targets, T8, "T8 is in another server and must be absent");
            assert_absent(&targets, T8B, "T8b names another server and must be absent");
            assert_exact(
                &targets,
                &[(P1, MSG_P1)],
                &[(T1, MSG_T1), (T3, MSG_T3), (T5, MSG_T5), (T9, MSG_T9)],
                "user 2",
            );

            let targets = server_ack_targets(&moderator, &server, &db)
                .await
                .expect("server_ack_targets must succeed for user 1");

            assert_target(&targets, &ch3, MSG_CH3, "ch3 must be a target for user 1");
            assert_target(&targets, T2, MSG_T2, "T2 must be a target for user 1");
            assert_exact(
                &targets,
                &[(P1, MSG_P1), (ch3.as_str(), MSG_CH3)],
                &[(T2, MSG_T2)],
                "user 1",
            );

            // The owner gets GrantAllSafe before any override is read, so ch3
            // and its thread are visible. Joined to T2 only.
            db.join_thread_if_absent(T2, &owner.id).await.unwrap();
            let targets = server_ack_targets(&owner, &server, &db)
                .await
                .expect("server_ack_targets must succeed for the owner");

            assert_target(
                &targets,
                &ch3,
                MSG_CH3,
                "ch3 must be a target for the owner",
            );
            assert_target(&targets, T2, MSG_T2, "T2 must be a target for the owner");
            assert_exact(
                &targets,
                &[(P1, MSG_P1), (ch3.as_str(), MSG_CH3)],
                &[(T2, MSG_T2)],
                "the owner",
            );
        });
    }

    #[tokio::test]
    async fn server_ack_targets_thread_in_server_channels() {
        database_test!(|db| async move {
            fixture!(db, "server_with_roles",
                user user 2
                server server 4);

            #[allow(clippy::disallowed_methods)]
            for channel in [
                text_channel(P1, &server.id, Some(MSG_P1)),
                thread(T1, &server.id, P1, Some(MSG_T1), false, false),
                // Hangs off T1. Only reachable if T1 were taken as a parent.
                thread(TX, &server.id, T1, Some(MSG_TX), false, false),
            ] {
                db.insert_channel(&channel).await.unwrap();
            }
            db.join_thread_if_absent(T1, &user.id).await.unwrap();
            db.join_thread_if_absent(TX, &user.id).await.unwrap();

            // P1 is listed twice as well. MongoDB's `$in` returns it once
            // anyway; the reference driver returns it twice.
            let mut server = server;
            server.channels = vec![P1.to_string(), T1.to_string(), P1.to_string()];

            let targets = server_ack_targets(&user, &server, &db)
                .await
                .expect("NP: a Thread listed in server.channels must not fail the ack");

            assert_absent(&targets, TX, "NP: T1 must not be used as a parent");
            assert_eq!(
                targets.iter().filter(|(id, _)| id == T1).count(),
                1,
                "NP: T1 must be a target exactly once; targets: {targets:?}"
            );
            assert_eq!(
                targets.iter().filter(|(id, _)| id == P1).count(),
                1,
                "NP: P1 listed twice must be a target exactly once; targets: {targets:?}"
            );
            assert_exact(&targets, &[(P1, MSG_P1)], &[(T1, MSG_T1)], "NP");
        });
    }

    #[test]
    fn thread_unread_rule() {
        let m = MSG_T7;

        assert!(thread_is_unread(None, m), "no row: unread");
        assert!(
            thread_is_unread(Some(&row(None, None)), m),
            "row without a pointer: unread"
        );
        assert!(
            thread_is_unread(Some(&row(Some(MSG_OLD), None)), m),
            "pointer behind the newest message: unread"
        );
        assert!(
            !thread_is_unread(Some(&row(Some(m), None)), m),
            "caught up, mentions None: read"
        );
        assert!(
            !thread_is_unread(Some(&row(Some(m), Some(&[]))), m),
            "caught up, mentions Some([]): read"
        );
        assert!(
            thread_is_unread(Some(&row(Some(m), Some(&[MSG_OLD]))), m),
            "caught up with a mention at or before the newest message: unread"
        );
        assert!(
            !thread_is_unread(Some(&row(Some(m), Some(&[MSG_NEWER]))), m),
            "caught up with only a mention past the newest message: read"
        );
        assert!(
            !thread_is_unread(Some(&row(Some(MSG_NEWER), Some(&[MSG_OLD]))), m),
            "pointer past the newest message: never unread (no rewind)"
        );
    }
}
