use std::time::Duration;

use revolt_database::{
    voice::{
        remote_control::{
            all_remote_control_members, end_remote_control_grant, expired_remote_control_members,
            fetch_remote_control_grant_by_id, parse_expiry_member, remove_expiry_member,
            requeue_expiry_member,
        },
        VoiceClient,
    },
    Database,
};
use revolt_result::Result;
use tokio::time::sleep;

/// Sweep interval. The grant TTL is single-digit seconds (sharer-driven
/// heartbeat), so this is deliberately far tighter than the hourly `prune_*`
/// tasks: it bounds how long a controller keeps a `can_publish_data`
/// capability after the sharer stops consenting.
const SWEEP_INTERVAL_SECS: u64 = 2;

/// Backoff before a failed fail-closed ejection is retried.
const EJECT_RETRY_SECS: i64 = 15;

/// Retire an expiry member once its capability is confirmed gone
async fn drop_member(member: &str) {
    if let Err(error) = remove_expiry_member(member).await {
        log::error!("remote control: failed to retire expiry member: {error:?}");
    }
}

/// Push a member's deadline out so the next sweep retries it. The member is
/// the LAST trace of a capability we have not managed to revoke, so it must
/// never be dropped on failure.
async fn requeue_member(member: &str) {
    if let Err(error) = requeue_expiry_member(member, EJECT_RETRY_SECS * 1000).await {
        log::error!("remote control: failed to requeue expiry member: {error:?}");
    }
}

/// Revocation actor for remote-control grants (remote-control plan §1).
///
/// Passive Redis TTL is NOT revocation: a key expiring fires no callback
/// while the SFU capability persists, and once the record is gone nothing
/// can find the grant to revoke it. So grants never carry a Redis TTL —
/// they carry an entry in an explicit expiry ZSET, and this task is the
/// actor that acts on it. It is driven by that index and NEVER by a SCAN
/// over a key pattern (the ghost-room lesson: a key-pattern scan can
/// silently miss entries).
///
/// Fail-closed: if the index names a grant whose record is gone (partial
/// teardown, Redis eviction), the controller is EJECTED from the room
/// rather than left holding a capability nothing can revoke.
pub async fn task(db: Database, _: revolt_database::AMQP) -> Result<()> {
    let voice_client = VoiceClient::from_revolt_config().await;

    loop {
        // The feature flag is not itself a kill switch (config() is cached
        // per process), but a crond restarted with it off must mass-revoke
        // every live grant rather than leave capabilities standing.
        let enabled = revolt_config::config().await.features.remote_control;

        // Never `?` inside this loop. `cron_task_wrapper` sleeps 60s before
        // restarting a task that returns, so one transient Redis error
        // would turn the intended ~10s revocation ceiling into ~70s.
        let read = if enabled {
            let now = iso8601_timestamp::Timestamp::now_utc()
                .duration_since(iso8601_timestamp::Timestamp::UNIX_EPOCH)
                .whole_milliseconds() as i64;
            expired_remote_control_members(now).await.map(|m| (m, "expired"))
        } else {
            all_remote_control_members().await.map(|m| (m, "disabled"))
        };

        let (members, reason) = match read {
            Ok(read) => read,
            Err(error) => {
                log::error!("remote control: expiry-index read failed: {error:?}");
                sleep(Duration::from_secs(SWEEP_INTERVAL_SECS)).await;
                continue;
            }
        };

        if !members.is_empty() {
            log::info!(
                "Reaping {} remote control grant(s) ({reason})",
                members.len()
            );
        }

        for member in members {
            // One member's failure must never abort the sweep: `?` here
            // would propagate out of `task`, and `cron_task_wrapper` sleeps
            // 60s before restarting — turning a transient Redis hiccup into
            // a ~70s revocation ceiling against an intended ~10s.
            let Some(parsed) = parse_expiry_member(&member) else {
                log::warn!("remote control: unparseable expiry member {member:?}, dropping");
                if let Err(error) = remove_expiry_member(&member).await {
                    log::error!("remote control: failed to drop bad expiry member: {error:?}");
                }
                continue;
            };

            match fetch_remote_control_grant_by_id(&parsed.grant_id).await {
                Ok(Some(grant)) => {
                    // The normal path: actively revoke the capability (with
                    // ejection as the escalation inside), delete the
                    // records, emit RemoteControlEnded, write the audit row.
                    end_remote_control_grant(&db, &voice_client, &grant, reason, true).await;
                }
                Ok(None) => {
                    // Grant-store loss fails CLOSED to ejection, addressed
                    // by the EXACT identity carried in the expiry member —
                    // re-resolving it here would hit the bare-user-id
                    // fallback (the ingress mapping is usually already
                    // gone by this point) and silently eject nobody.
                    log::warn!(
                        "remote control: grant {} record missing; ejecting controller {} from {} (fail closed)",
                        parsed.grant_id,
                        parsed.controller_identity,
                        parsed.channel_id
                    );

                    match revolt_database::voice::get_channel_node(&parsed.channel_id).await {
                        // No node recorded for the channel means the room
                        // itself is gone (`delete_channel_voice_state`
                        // drops the node key), so there is nothing left to
                        // eject from and the member can be retired.
                        Ok(None) => drop_member(&member).await,
                        Ok(Some(node)) => {
                            match voice_client
                                .remove_identity(
                                    &node,
                                    &parsed.controller_identity,
                                    &parsed.channel_id,
                                )
                                .await
                            {
                                Ok(()) => drop_member(&member).await,
                                Err(error) => {
                                    // Do NOT retire the member on failure:
                                    // it is the last trace of a capability
                                    // we have not managed to take away.
                                    log::error!(
                                        "remote control: fail-closed ejection failed for {} in {}, retrying: {error:?}",
                                        parsed.controller_identity,
                                        parsed.channel_id
                                    );
                                    requeue_member(&member).await;
                                }
                            }
                        }
                        Err(error) => {
                            log::error!(
                                "remote control: node lookup failed for {}, retrying: {error:?}",
                                parsed.channel_id
                            );
                            requeue_member(&member).await;
                        }
                    }
                }
                Err(error) => {
                    log::error!(
                        "remote control: grant lookup failed for {}: {error:?}",
                        parsed.grant_id
                    );
                }
            }
        }

        sleep(Duration::from_secs(SWEEP_INTERVAL_SECS)).await
    }
}
