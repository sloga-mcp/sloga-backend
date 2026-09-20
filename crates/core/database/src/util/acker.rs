use redis_kiss::{get_connection, AsyncCommands};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{Result, ToRevoltError};

use crate::{events::client::EventV1, Channel, Database, Server, User, AMQP};

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

pub async fn ack_server(user: &User, server: &Server, db: &Database, amqp: &AMQP) -> Result<()> {
    let channels = db.fetch_channels(&server.channels).await?;
    let query = crate::util::permissions::DatabasePermissionQuery::new(db, user).server(server);

    for channel in channels {
        let channel_id = channel.id();
        let mut q = query.clone().channel(&channel);

        if calculate_channel_permissions(&mut q)
            .await
            .has_channel_permission(ChannelPermission::ViewChannel)
        {
            let channel_last_msg = match &channel {
                Channel::TextChannel {
                    last_message_id, ..
                }
                | Channel::Forum {
                    last_message_id, ..
                } => last_message_id,
                _ => unreachable!(),
            }
            .clone();

            if let Some(channel_last_msg) = channel_last_msg {
                record_and_publish(
                    &user.id,
                    channel_id,
                    &channel_last_msg,
                    Some(&server.id),
                    amqp,
                )
                .await?;

                EventV1::ChannelAck {
                    id: channel_id.to_string(),
                    user: user.id.clone(),
                    message_id: channel_last_msg,
                }
                .private(user.id.clone())
                .await;
            }
        }
    }

    Ok(())
}
