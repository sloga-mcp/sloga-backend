//! Channel slowmode enforcement, shared by every route that creates
//! user-authored messages (`message_send`, `message_roll`).

use redis_kiss::{get_connection, redis, AsyncCommands};
use revolt_database::events::client::EventV1;
use revolt_database::{Channel, User};
use revolt_models::v0::ChannelSlowmode;
use revolt_permissions::{ChannelPermission, PermissionValue};
use revolt_result::{create_error, Result};

/// Enforce slowmode for `user` posting into `channel`.
///
/// No-op for users holding `BypassSlowmode`, non-text channels, and
/// channels without slowmode configured. If Redis is unavailable the
/// check is skipped entirely (fail-open, matching historic behaviour).
pub async fn enforce_slowmode(
    user: &User,
    channel: &Channel,
    permissions: &PermissionValue,
) -> Result<()> {
    if !permissions.has_channel_permission(ChannelPermission::BypassSlowmode) {
        if let Channel::TextChannel {
            slowmode: Some(channel_slowmode),
            id: channel_id,
            ..
        } = channel
        {
            if *channel_slowmode > 0 {
                if let Ok(conn) = get_connection().await {
                    let mut conn = conn.into_inner();

                    let slowmode_key = format!("slowmode:{}:{}", user.id, channel_id);

                    // Atomic check-and-set: only set if absent and apply expiry in one command.
                    let set_result: Option<String> = conn
                        .set_options(
                            &slowmode_key,
                            "1", // The value doesn't matter, only the key's existence
                            redis::SetOptions::default()
                                .conditional_set(redis::ExistenceCheck::NX)
                                .with_expiration(redis::SetExpiry::EX(*channel_slowmode as usize)),
                        )
                        .await
                        .unwrap_or(None);

                    if set_result.is_some() {
                        let idx_key = format!("slowmode_idx:{}", user.id);
                        conn.sadd::<_, _, ()>(&idx_key, channel_id.as_str())
                            .await
                            .ok();
                        conn.expire::<_, ()>(&idx_key, *channel_slowmode as usize)
                            .await
                            .ok();
                    }

                    // If `set_result` is None, the `NX` condition failed because the key already exists.
                    // This means the user is currently in slowmode.
                    if set_result.is_none() {
                        // Fetch the remaining TTL to accurately populate the retry_after field
                        let ttl: i64 = conn.ttl(&slowmode_key).await.unwrap_or(0);

                        // Redis returns positive integers for valid TTLs
                        if ttl > 0 {
                            EventV1::UserSlowmodes {
                                slowmodes: vec![ChannelSlowmode {
                                    channel_id: channel_id.to_string(),
                                    duration: *channel_slowmode,
                                    retry_after: ttl as u64,
                                }],
                            }
                            .private(user.id.clone())
                            .await;
                            return Err(create_error!(InSlowmode {
                                retry_after: ttl as u64
                            }));
                        }
                    } else {
                        EventV1::UserSlowmodes {
                            slowmodes: vec![ChannelSlowmode {
                                channel_id: channel_id.to_string(),
                                duration: *channel_slowmode,
                                retry_after: *channel_slowmode,
                            }],
                        }
                        .private(user.id.clone())
                        .await;
                    }
                }
                // If Redis connection fails, just skip the slowmode check
            }
        }
    }

    Ok(())
}
