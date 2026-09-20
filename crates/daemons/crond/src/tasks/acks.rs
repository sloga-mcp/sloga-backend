use std::time::Duration;

use futures_lite::stream::StreamExt;
use lapin::{
    message::Delivery,
    options::*,
    types::FieldTable,
    uri::{AMQPAuthority, AMQPQueryString, AMQPUri, AMQPUserInfo},
    ConnectionBuilder, ConnectionProperties, ExchangeKind,
};
use log::{debug, info, warn};
use redis_kiss::{get_connection, AsyncCommands};
use revolt_config::config;
use revolt_database::{events::rabbit::AckEventPayload, Database, AMQP};
use revolt_result::{Result, ToRevoltError};
use serde_json;

/// How long to hold a failed ack before handing it back to the broker, so a
/// Redis or database blip does not turn into a hot redelivery loop.
const RETRY_DELAY: Duration = Duration::from_secs(1);

pub async fn task(db: Database, amqp: AMQP) -> Result<()> {
    let config = config().await;

    let uri = AMQPUri {
        scheme: lapin::uri::AMQPScheme::AMQP,
        authority: AMQPAuthority {
            userinfo: AMQPUserInfo {
                username: config.rabbit.username,
                password: config.rabbit.password,
            },
            host: config.rabbit.host,
            port: config.rabbit.port,
        },
        vhost: "/".to_string(),
        query: AMQPQueryString::default(),
    };

    let connection = ConnectionBuilder::new()
        .expect("Builder")
        .with_uri(uri)
        .with_properties(ConnectionProperties::default())
        .connect()
        .await
        .expect("Failed to connect to rabbitmq");

    let reader_channel = connection
        .create_channel()
        .await
        .expect("Failed to create channel");

    reader_channel
        .exchange_declare(
            config.rabbit.default_exchange.clone().into(),
            ExchangeKind::Topic,
            ExchangeDeclareOptions {
                durable: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await
        .expect("Failed to declare exchange");

    reader_channel
        .queue_declare(
            config.rabbit.queues.acks.clone().into(),
            QueueDeclareOptions {
                durable: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await
        .expect("Failed to bind queue");

    reader_channel
        .queue_bind(
            config.rabbit.queues.acks.clone().into(),
            config.rabbit.default_exchange.into(),
            config.rabbit.queues.acks.clone().into(),
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await
        .expect("Failed to bind channel");

    let mut consumer = reader_channel
        .basic_consume(
            config.rabbit.queues.acks.into(),
            "crond-ack-consumer".into(),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .expect("Failed to create consumer");

    while let Some(delivery) = consumer.next().await {
        if let Ok(delivery) = delivery {
            handle_delivery(&db, &amqp, delivery).await;
        }
    }
    Ok(())
}

/// Commit one ack event, and settle the delivery according to the outcome.
///
/// A transient failure (Redis or the database unreachable) is handed back to
/// the broker once, after a short pause; the Redis pointer stays or is put
/// back, so the read is not lost either way. A second failure of the same
/// delivery is dropped: the pointer is still in Redis and the user's next
/// ack in that channel publishes a fresh event for it.
async fn handle_delivery(db: &Database, amqp: &AMQP, delivery: Delivery) {
    let payload = match serde_json::from_slice::<AckEventPayload>(&delivery.data) {
        Ok(payload) => payload,
        Err(_) => {
            revolt_config::capture_message(
                format!("Failed to decode ack data: {:?}", delivery.data).as_str(),
                revolt_config::Level::Error,
            );
            _ = delivery.reject(BasicRejectOptions { requeue: false }).await;
            return;
        }
    };

    debug!("Received ack event: {payload:?}");

    let Some(channel) = payload.channel_id else {
        warn!("Ack event without a channel for user {}", payload.user_id);
        _ = delivery.reject(BasicRejectOptions { requeue: false }).await;
        return;
    };

    match process_channel_ack(db, amqp, &payload.user_id, &channel).await {
        Ok(()) => {
            _ = delivery.ack(BasicAckOptions { multiple: false }).await;
        }
        Err(e) => {
            revolt_config::capture_error(&e);
            let requeue = !delivery.redelivered;
            warn!(
                "Ack for {}:{} failed ({e:?}); requeue={requeue}",
                channel, payload.user_id
            );
            tokio::time::sleep(RETRY_DELAY).await;
            _ = delivery.reject(BasicRejectOptions { requeue }).await;
        }
    }
}

/// Move the read pointer for one user in one channel from Redis into the
/// database.
///
/// A fresh pooled Redis connection is taken per event. The previous consumer
/// checked one out for its whole lifetime, so a Redis restart left it holding
/// a dead socket and every ack after that failed until crond itself was
/// restarted.
async fn process_channel_ack(db: &Database, amqp: &AMQP, user: &str, channel: &str) -> Result<()> {
    let key = format!("acker:{user}+{channel}");

    let mut redis = get_connection()
        .await
        .map_err(|_| revolt_result::create_error!(InternalError))?;

    let message_id: Option<String> = redis.get_del(&key).await.to_internal_error()?;

    let Some(message_id) = message_id else {
        // Already committed by an earlier event for the same pair: every ack
        // publishes, so this is the expected case for a busy channel.
        debug!("No pending ack for {channel}:{user}");
        return Ok(());
    };

    let committed = commit_ack(db, amqp, user, channel, &message_id).await;

    if committed.is_err() {
        // The pointer left Redis but never reached the database. Put it back
        // unless a newer ack has arrived in the meantime, so the retry (or
        // the user's next ack) still carries this read.
        let restored: std::result::Result<bool, _> = redis.set_nx(&key, &message_id).await;
        if restored.is_err() {
            warn!("Could not restore the ack pointer for {channel}:{user}");
        }
    }

    committed
}

/// How often the sweep below looks for pointers whose event never arrived.
const SWEEP_INTERVAL: Duration = Duration::from_secs(300);

/// Commit every read pointer still sitting in Redis, at start and then every
/// five minutes.
///
/// A pointer outlives its event when the broker or this daemon was down at
/// the wrong moment, or when a delivery failed twice and was dropped. The
/// event path above then has nothing to hand it to, and until the user acks
/// the same channel again the read stays uncommitted. Committing a pointer
/// whose event is merely still in flight is harmless: the event finds
/// nothing to do.
pub async fn sweep_task(db: Database, amqp: AMQP) -> Result<()> {
    loop {
        match sweep(&db, &amqp).await {
            Ok(0) => debug!("Ack sweep found nothing pending"),
            Ok(n) => info!("Ack sweep committed {n} pointers left behind"),
            Err(e) => warn!("Ack sweep failed: {e:?}"),
        }

        tokio::time::sleep(SWEEP_INTERVAL).await;
    }
}

async fn sweep(db: &Database, amqp: &AMQP) -> Result<usize> {
    let mut redis = get_connection()
        .await
        .map_err(|_| revolt_result::create_error!(InternalError))?;

    let mut keys = Vec::new();
    {
        let mut iter = redis
            .scan_match::<_, String>("acker:*")
            .await
            .to_internal_error()?;

        while let Some(key) = iter.next_item().await {
            keys.push(key);
        }
    }

    let mut committed = 0;
    for key in keys {
        let Some((user, channel)) = key
            .strip_prefix("acker:")
            .and_then(|pair| pair.split_once('+'))
        else {
            warn!("Ack sweep skipping a key it cannot parse: {key}");
            continue;
        };

        match process_channel_ack(db, amqp, user, channel).await {
            Ok(()) => committed += 1,
            Err(e) => warn!("Ack sweep could not commit {channel}:{user}: {e:?}"),
        }
    }

    Ok(committed)
}

#[allow(clippy::disallowed_methods)]
async fn commit_ack(
    db: &Database,
    amqp: &AMQP,
    user: &str,
    channel: &str,
    message_id: &str,
) -> Result<()> {
    let unread = db.fetch_unread(user, channel).await?;
    let updated = db.acknowledge_message(channel, user, message_id).await?;

    info!("Set new state for ack: {}:{}:{}", channel, user, message_id);

    if let (Some(before), Some(after)) = (unread, updated) {
        let before_mentions = before.mentions.unwrap_or_default().len();
        let after_mentions = after.mentions.unwrap_or_default().len();

        if after_mentions < before_mentions {
            if let Err(err) = amqp
                .ack_notification_message(
                    user.to_string(),
                    channel.to_string(),
                    message_id.to_string(),
                )
                .await
            {
                revolt_config::capture_error(&err);
            }
        };
    }

    Ok(())
}
