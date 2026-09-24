use std::time::{Duration, SystemTime, UNIX_EPOCH};

use revolt_database::{
    events::client::EventV1,
    util::{idempotency::IdempotencyKey, permissions::DatabasePermissionQuery},
    Channel, Database, File, FileUsedForType, Message, MessageFilter, MessageQuery,
    MessageTimePeriod, ScheduledMessage, ScheduledMessageStatus, User, AMQP,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission, PermissionQuery};
use revolt_result::Result;
use tokio::time::sleep;
use ulid::Ulid;

/// How often the delivery scan runs. Delivery therefore has up to ~30s of
/// jitter past the requested instant (UI copy says "around" the time).
const DELIVERY_TICK: Duration = Duration::from_secs(30);

/// Rows more than this far past their instant are marked Failed instead of
/// fired — delivering a message hours late (after a crond outage) without
/// its temporal context does more harm than dropping it loudly.
const DELIVERY_GRACE_MS: i64 = 5 * 60 * 1000;

/// Finished (Sent / Failed / crash-stuck Sending) rows are retained a day
/// for debugging, then swept.
const RETENTION_MS: i64 = 24 * 60 * 60 * 1000;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Scheduled-message delivery.
///
/// Each tick claims due rows atomically (`Pending` → `Sending`, so a second
/// crond instance can never double-send), re-runs the full permission
/// calculus as of NOW, and sends through `Message::create_from_api` so
/// validation, mention scrubbing, push fan-out and the `Message` event all
/// happen exactly as for a live send. Any error on a claimed row is
/// permanent: the row is marked Failed (never re-queued) and the author is
/// told why on their private topic.
pub async fn task(db: Database, amqp: AMQP) -> Result<()> {
    loop {
        let now = now_ms();

        match db.fetch_due_scheduled_messages(now).await {
            Ok(due) => {
                for row in due {
                    // Claim first — losing the claim means another instance
                    // (or a previous tick) already owns the row.
                    match db.claim_scheduled_message(&row.id).await {
                        Ok(true) => {}
                        Ok(false) => continue,
                        Err(err) => {
                            revolt_config::capture_error(&err);
                            continue;
                        }
                    }

                    if row.scheduled_at < now - DELIVERY_GRACE_MS {
                        fail(&db, &row, "missed its delivery window").await;
                        continue;
                    }

                    if let Err(reason) = deliver(&db, &amqp, &row).await {
                        fail(&db, &row, &reason).await;
                    } else if let Err(err) = db.mark_scheduled_message_sent(&row.id).await {
                        // The message IS delivered; a failed mark leaves the
                        // row Sending, which the retention sweep collects.
                        revolt_config::capture_error(&err);
                    }
                }
            }
            Err(err) => {
                revolt_config::capture_error(&err);
            }
        }

        // Bounded storage for finished rows. Rows stuck in `Sending` by a
        // daemon crash still hold attachments claimed against the row id
        // (never retargeted), so release those into the deletion sweep;
        // `Sent`/`Failed` rows already released theirs at delivery/failure.
        match db
            .delete_finished_scheduled_messages_before(now - RETENTION_MS)
            .await
        {
            Ok(removed) => {
                for row in removed {
                    if matches!(row.status, ScheduledMessageStatus::Sending) {
                        if let Some(attachments) = &row.data.attachments {
                            if !attachments.is_empty() {
                                db.mark_attachments_as_deleted(attachments).await.ok();
                            }
                        }
                    }
                }
            }
            Err(err) => {
                revolt_config::capture_error(&err);
            }
        }

        sleep(DELIVERY_TICK).await
    }
}

/// Mark a claimed row permanently failed, release its claimed attachments
/// into the deletion sweep, and tell the author why.
async fn fail(db: &Database, row: &ScheduledMessage, reason: &str) {
    if let Err(err) = db.mark_scheduled_message_failed(&row.id, reason).await {
        revolt_config::capture_error(&err);
    }

    if let Some(attachments) = &row.data.attachments {
        if !attachments.is_empty() {
            db.mark_attachments_as_deleted(attachments).await.ok();
        }
    }

    EventV1::ScheduledMessageFailed {
        id: row.id.clone(),
        channel: row.channel.clone(),
        reason: reason.to_string(),
    }
    .private(row.author.clone())
    .await;
}

/// Whether the author has already read everything in the channel.
///
/// A live send acks the channel for its author, but a scheduled delivery
/// happens while the author is absent: acking unconditionally would mark
/// messages other people sent in the meantime as read without the author
/// ever seeing them. So the delivery only keeps the author caught up if they
/// already were — their read pointer is at (or past) the newest message.
///
/// Reads the newest message itself rather than the channel's
/// `last_message_id`, which is written by a debounced worker and can lag. Any
/// error, a missing unread row or an unset pointer answers `false`: the
/// channel then stays unread, which is the safe direction.
async fn author_caught_up(db: &Database, user_id: &str, channel_id: &str) -> bool {
    let last_read = match db.fetch_unread(user_id, channel_id).await {
        Ok(Some(unread)) => unread.last_id,
        Ok(None) => None,
        Err(err) => {
            revolt_config::capture_error(&err);
            return false;
        }
    };

    let newest = match db
        .fetch_messages(MessageQuery {
            limit: Some(1),
            filter: MessageFilter {
                channel: Some(channel_id.to_string()),
                ..Default::default()
            },
            time_period: MessageTimePeriod::Absolute {
                before: None,
                after: None,
                sort: Some(v0::MessageSort::Latest),
            },
        })
        .await
    {
        Ok(messages) => messages.into_iter().next(),
        Err(err) => {
            revolt_config::capture_error(&err);
            return false;
        }
    };

    match newest {
        // Nothing to have missed.
        None => true,
        // Ids are ULIDs, so string order is creation order.
        Some(newest) => last_read.is_some_and(|last_read| last_read >= newest.id),
    }
}

/// Attempt delivery of one claimed row. Any `Err` is a PERMANENT failure
/// reason surfaced to the author — claimed rows are never re-queued.
async fn deliver(db: &Database, amqp: &AMQP, row: &ScheduledMessage) -> std::result::Result<(), String> {
    // The channel may have been deleted since scheduling (the cascade
    // normally cancels rows; this is the backstop for wholesale server
    // deletion, which drops channels without running per-channel deletes).
    let channel = db
        .fetch_channel(&row.channel)
        .await
        .map_err(|_| "the channel no longer exists".to_string())?;

    let user: User = db
        .fetch_user(&row.author)
        .await
        .map_err(|_| "your account no longer exists".to_string())?;

    if user.flags.unwrap_or(0) != 0 {
        return Err("your account is suspended or deactivated".to_string());
    }

    // Author must still be part of the conversation.
    match &channel {
        Channel::TextChannel { server, .. }
        | Channel::Thread { server, .. }
        | Channel::Forum { server, .. } => {
            db.fetch_member(server, &user.id)
                .await
                .map_err(|_| "you are no longer a member of the server".to_string())?;
        }
        Channel::DirectMessage { recipients, .. } | Channel::Group { recipients, .. } => {
            if !recipients.contains(&user.id) {
                return Err("you are no longer part of the conversation".to_string());
            }
        }
        Channel::SavedMessages { user: owner, .. } => {
            if owner != &user.id {
                return Err("you are no longer part of the conversation".to_string());
            }
        }
    }

    // Full permission re-check as of now — scheduling never outlives a
    // revoked permission. Threads inherit the parent channel's overrides.
    let permission_channel = channel
        .permission_target(db)
        .await
        .map_err(|_| "the channel no longer exists".to_string())?
        .into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;

    if !permissions.has_channel_permission(ChannelPermission::SendMessage) {
        return Err("you no longer have permission to send messages here".to_string());
    }

    // Archived or locked threads reject scheduled sends exactly like live
    // ones (same rule as delta's ensure_thread_writable).
    if let Channel::Thread {
        archived, locked, ..
    } = &channel
    {
        if (*archived || *locked)
            && !permissions.has_channel_permission(ChannelPermission::ManageChannel)
        {
            return Err("the thread is archived or locked".to_string());
        }
    }

    if let Some(masq) = &row.data.masquerade {
        if !permissions.has_channel_permission(ChannelPermission::Masquerade) {
            return Err("you no longer have permission to masquerade".to_string());
        }
        if masq.colour.is_some()
            && !permissions.has_channel_permission(ChannelPermission::ManageRole)
        {
            return Err("you no longer have permission to masquerade with a colour".to_string());
        }
    }

    if row.data.embeds.as_ref().is_some_and(|v| !v.is_empty())
        && !permissions.has_channel_permission(ChannelPermission::SendEmbeds)
    {
        return Err("you no longer have permission to send embeds".to_string());
    }

    if row.data.attachments.as_ref().is_some_and(|v| !v.is_empty())
        && !permissions.has_channel_permission(ChannelPermission::UploadFiles)
    {
        return Err("you no longer have permission to upload files".to_string());
    }

    // Same TRUST-0 rule as a live send: brand-new users don't get mentions
    // in discoverable servers.
    let allow_mentions = if let Some(server) = query.server_ref() {
        if server.discoverable {
            Ulid::from_string(&user.id)
                .ok()
                .and_then(|ulid| ulid.datetime().elapsed().ok())
                .is_some_and(|age| age >= Duration::from_secs(12 * 60 * 60))
        } else {
            true
        }
    } else {
        true
    };

    // Resolve the attachments claimed at schedule time and repoint them at
    // the real message id. `create_from_api`'s own claim path only matches
    // UNCLAIMED files, so these are handed over pre-resolved instead.
    let message_id = Ulid::new().to_string();
    let mut resolved: Vec<File> = Vec::new();
    for attachment_id in row.data.attachments.as_deref().unwrap_or_default() {
        let mut file = db
            .fetch_attachment("attachments", attachment_id)
            .await
            .map_err(|_| "an attachment no longer exists".to_string())?;

        let owned_by_row = file.used_for.as_ref().is_some_and(|used_for| {
            used_for.id == row.id && used_for.object_type == FileUsedForType::Message
        });
        if !owned_by_row || file.deleted.is_some_and(|deleted| deleted) {
            return Err("an attachment is no longer available".to_string());
        }

        db.retarget_attachment(attachment_id, &message_id)
            .await
            .map_err(|_| "an attachment could not be attached".to_string())?;

        if let Some(used_for) = &mut file.used_for {
            used_for.id = message_id.clone();
        }
        resolved.push(file);
    }

    // Build author objects for the event fan-out, exactly like a live send.
    let author: v0::User = user.clone().into(db, Some(&user)).await;

    query.are_we_a_member().await;

    let model_user = user
        .clone()
        .into_known_static(revolt_presence::is_online(&user.id).await)
        .await;

    let model_member: Option<v0::Member> = query
        .member_ref()
        .as_ref()
        .map(|member| member.clone().into_owned().into());

    let generate_embeds = permissions.has_channel_permission(ChannelPermission::SendEmbeds);

    // Capture the thread's identity before `channel` is consumed by the
    // send, for the auto-join below.
    let thread_info = if let Channel::Thread { server, .. } = &channel {
        Some((channel.id().to_string(), server.clone()))
    } else {
        None
    };

    // Only move the author's read pointer if they were already caught up;
    // see `author_caught_up`.
    let ack_author = author_caught_up(db, &user.id, &row.channel).await;

    // The stored payload's nonce was already consumed at schedule time and
    // stripped; the row id doubles as the delivery nonce so clients can
    // correlate the arriving message with their pending entry.
    Message::create_from_api_with_id(
        db,
        Some(amqp),
        channel,
        row.data.clone(),
        v0::MessageAuthor::User(&author),
        Some(model_user),
        model_member,
        user.limits().await,
        IdempotencyKey::unchecked_from_string(row.id.clone()),
        generate_embeds,
        allow_mentions,
        Some(message_id),
        Some(resolved),
        ack_author,
    )
    .await
    .map_err(|error| format!("the message could not be sent ({:?})", error.error_type))?;

    // Sending in a thread joins you to it, exactly like a live send
    // (Discord parity). Best-effort: the message IS delivered by now.
    if let Some((thread_id, server_id)) = thread_info {
        match db.join_thread_if_absent(&thread_id, &user.id).await {
            Ok(true) => {
                EventV1::ThreadMemberJoin {
                    id: thread_id,
                    user: user.id.clone(),
                }
                .p(server_id)
                .await;
            }
            Ok(false) => {}
            Err(err) => {
                revolt_config::capture_error(&err);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use revolt_database::{
        DatabaseInfo, MessageFilter, MessageQuery, MessageTimePeriod, Relationship,
        RelationshipStatus,
    };

    fn make_user(username: &str, relations: Option<Vec<Relationship>>) -> User {
        User {
            id: Ulid::new().to_string(),
            username: username.to_string(),
            discriminator: "0001".to_string(),
            relations,
            // `deliver` re-fetches the author and rejects any non-zero flags.
            flags: None,
            ..Default::default()
        }
    }

    // `insert_user` / `insert_channel` are disallowed in favor of
    // `Object::create()`, but this test needs bare rows and nothing else (the
    // same exemption as `discord_import/worker.rs`).
    #[allow(clippy::disallowed_methods)]
    async fn insert_fixtures(db: &Database, users: &[&User], dm: &Channel) {
        for user in users {
            db.insert_user(user).await.unwrap();
        }
        db.insert_channel(dm).await.unwrap();
    }

    /// A claimed row. Content carries no URL, so the embed worker never calls
    /// January.
    fn claimed_row(author: &User, channel: &str) -> ScheduledMessage {
        ScheduledMessage {
            id: Ulid::new().to_string(),
            author: author.id.clone(),
            channel: channel.to_string(),
            server: None,
            scheduled_at: now_ms(),
            data: v0::DataMessageSend {
                nonce: None,
                content: Some("scheduled side-effect witness".to_string()),
                attachments: None,
                replies: None,
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                flags: None,
            },
            status: ScheduledMessageStatus::Sending,
            failure_reason: None,
        }
    }

    /// `deliver` mints the message id internally; the row id is stamped on
    /// the delivered message as its nonce.
    async fn delivered_id(db: &Database, row: &ScheduledMessage) -> String {
        db.fetch_messages(MessageQuery {
            limit: Some(50),
            filter: MessageFilter {
                channel: Some(row.channel.clone()),
                ..Default::default()
            },
            time_period: MessageTimePeriod::Absolute {
                before: None,
                after: None,
                sort: None,
            },
        })
        .await
        .expect("fetch_messages")
        .into_iter()
        .find(|message| message.nonce.as_deref() == Some(row.id.as_str()))
        .expect("no delivered message carries the row id as its nonce")
        .id
    }

    async fn dm_active(db: &Database, id: &str) -> bool {
        match db.fetch_channel(id).await.expect("fetch dm") {
            Channel::DirectMessage { active, .. } => active,
            _ => panic!("fixture channel is not a DM"),
        }
    }

    async fn mentions(db: &Database, user: &str, channel: &str) -> Option<Vec<String>> {
        db.fetch_unread(user, channel)
            .await
            .expect("fetch_unread")
            .and_then(|unread| unread.mentions)
    }

    /// Scheduled delivery only QUEUES its last_message_id / mention+push
    /// side effects; they land only once `start_side_effect_workers` runs.
    ///
    /// Phase 1 is the in-test known-bad control (no workers: nothing lands),
    /// phase 2 starts the workers and requires every witness to land.
    /// Witnesses: the last_message_id worker flips a DM `active` false → true
    /// (the DM-reopen side effect, which fires only when the delivered id
    /// advances the pointer) and records the delivered id as the DM's
    /// `last_message_id`, and the ack worker records the recipient's mention
    /// of the delivered id.
    ///
    /// The queues are process statics, and other crond tests (the
    /// discord_import worker tests → `Member::create`) may enqueue into them.
    /// Run this test alone (name filter, `--ignored`). It asserts only on its
    /// own channel ids.
    ///
    /// The base config keeps `pushd.production = true`, so the ack worker
    /// publishes pushes to the `-prd` routing key. That is harmless only
    /// because this test must run against an isolated RabbitMQ with no pushd
    /// consumer: nothing declares the `revolt.notifications` exchange there
    /// (only pushd does), so the broker rejects the publish and closes the
    /// channel, and nothing is delivered. Never point it at a RabbitMQ that
    /// has a pushd consumer.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs isolated local Redis + RabbitMQ; TEST_DB=REFERENCE"]
    async fn scheduled_delivery_side_effects_drain_only_with_workers() {
        assert_eq!(
            std::env::var("TEST_DB").as_deref(),
            Ok("REFERENCE"),
            "refusing to run without TEST_DB=REFERENCE"
        );

        let db = DatabaseInfo::Reference.connect().await.expect("database");
        let amqp = AMQP::new_auto().await;

        let other = make_user("sched-other", None);
        let author = make_user(
            "sched-author",
            Some(vec![Relationship {
                id: other.id.clone(),
                status: RelationshipStatus::Friend,
                note: None,
            }]),
        );
        let dm = Channel::DirectMessage {
            id: Ulid::new().to_string(),
            active: false,
            recipients: vec![author.id.clone(), other.id.clone()],
            last_message_id: None,
        };
        insert_fixtures(&db, &[&author, &other], &dm).await;

        let group = Channel::create_group(
            &db,
            v0::DataCreateGroup {
                name: "scheduled".to_string(),
                users: [other.id.clone()].into_iter().collect(),
                ..Default::default()
            },
            author.id.clone(),
        )
        .await
        .expect("create_group");

        let dm_row = claimed_row(&author, dm.id());
        let group_row = claimed_row(&author, group.id());
        for row in [&dm_row, &group_row] {
            deliver(&db, &amqp, row)
                .await
                .unwrap_or_else(|reason| panic!("deliver failed: {reason}"));
        }
        let dm_message = delivered_id(&db, &dm_row).await;
        let group_message = delivered_id(&db, &group_row).await;

        // Phase 1: no workers, so nothing drains.
        sleep(Duration::from_secs(8)).await;
        assert!(!dm_active(&db, dm.id()).await, "DM went active without workers");
        assert_eq!(db.fetch_unread(&other.id, dm.id()).await.unwrap(), None);
        assert_eq!(db.fetch_unread(&other.id, group.id()).await.unwrap(), None);

        // Phase 2: start the workers. A worker commits once more than 5 s
        // have passed since it picked the task up (checked on a 1 s loop, so
        // ~6 s); the poll below is bounded by this test's own 30 s deadline.
        crate::start_side_effect_workers(&db, &amqp);

        let dm_expected = Some(vec![dm_message]);
        let group_expected = Some(vec![group_message]);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if dm_active(&db, dm.id()).await
                && mentions(&db, &other.id, dm.id()).await == dm_expected
                && mentions(&db, &other.id, group.id()).await == group_expected
            {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            sleep(Duration::from_millis(250)).await;
        }

        assert!(dm_active(&db, dm.id()).await, "DM never went active");
        // The worker sets `active` and `last_message_id` in one write, so the
        // pointer has landed too; `dm_expected` holds exactly the delivered id.
        match db.fetch_channel(dm.id()).await.expect("fetch dm") {
            Channel::DirectMessage {
                last_message_id, ..
            } => assert_eq!(
                last_message_id.map(|id| vec![id]),
                dm_expected,
                "DM last_message_id is not the delivered id"
            ),
            _ => panic!("fixture channel is not a DM"),
        }
        assert_eq!(mentions(&db, &other.id, dm.id()).await, dm_expected);
        assert_eq!(mentions(&db, &other.id, group.id()).await, group_expected);
        // The author is never a recipient of their own message.
        assert_eq!(db.fetch_unread(&author.id, dm.id()).await.unwrap(), None);
        assert_eq!(db.fetch_unread(&author.id, group.id()).await.unwrap(), None);
    }
}
