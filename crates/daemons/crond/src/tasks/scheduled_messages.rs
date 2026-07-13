use std::time::{Duration, SystemTime, UNIX_EPOCH};

use revolt_database::{
    events::client::EventV1,
    util::{idempotency::IdempotencyKey, permissions::DatabasePermissionQuery},
    Channel, Database, File, FileUsedForType, Message, ScheduledMessage, ScheduledMessageStatus,
    User, AMQP,
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
