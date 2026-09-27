#[macro_use]
extern crate log;

use std::sync::Arc;

use lapin::{
    options::{BasicConsumeOptions, ExchangeDeclareOptions, QueueBindOptions, QueueDeclareOptions},
    types::{AMQPValue, FieldTable},
    Channel, Connection, ConnectionProperties,
};
use revolt_config::{config, Settings};
use revolt_database::Database;
use tokio::signal::ctrl_c;

mod consumers;
mod utils;
use consumers::{
    inbound::{
        ack::AckConsumer, calendar_event::CalendarEventConsumer, dm_call::DmCallConsumer,
        fr_accepted::FRAcceptedConsumer, fr_received::FRReceivedConsumer, generic::GenericConsumer,
        mass_mention::MassMessageConsumer, message::MessageConsumer,
    },
    outbound::{
        apn::ApnsOutboundConsumer,
        fcm::FcmOutboundConsumer,
        vapid::{self, VapidOutboundConsumer},
    },
};

use crate::utils::{Consumer, Delegate};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    // Validate the VAPID config and exit, before logging, the database or RabbitMQ are touched
    if std::env::args().any(|a| a == "--check-config") {
        std::process::exit(check_config().await);
    }

    // Configure logging and environment
    revolt_config::configure!(pushd);

    // Setup database
    let db = revolt_database::DatabaseInfo::Auto.connect().await.unwrap();

    let config = config().await;

    let connection = Arc::new(
        Connection::connect(
            &format!(
                "amqp://{}:{}@{}:{}",
                &config.rabbit.username,
                &config.rabbit.password,
                &config.rabbit.host,
                &config.rabbit.port,
            ),
            ConnectionProperties::default(),
        )
        .await
        .expect("Failed to connect to RabbitMQ"),
    );

    let mut channels = Vec::new();

    // An explainer of how this works:
    // The inbound connections are on separate routing keys, such that they only receive the proper payload
    // from their respective api (prod or test).
    // However, the outbound queues that go to the services are routed to receive from both, so that messages
    // sent from beta are still notified on prod, and vice versa.

    // This'll require some interesting shimming if we need to add more events once this is in prod (different payloads between prod and test),
    // but that sounds like a problem for future us.

    channels.push(
        make_queue_and_consume::<GenericConsumer>(
            &db,
            &connection,
            &config,
            &config.pushd.generic_queue,
            &config.pushd.get_generic_routing_key(),
            None,
        )
        .await,
    );

    channels.push(
        make_queue_and_consume::<MessageConsumer>(
            &db,
            &connection,
            &config,
            &config.pushd.message_queue,
            &config.pushd.get_message_routing_key(),
            None,
        )
        .await,
    );

    channels.push(
        make_queue_and_consume::<FRReceivedConsumer>(
            &db,
            &connection,
            &config,
            &config.pushd.fr_received_queue,
            &config.pushd.get_fr_received_routing_key(),
            None,
        )
        .await,
    );

    channels.push(
        make_queue_and_consume::<FRAcceptedConsumer>(
            &db,
            &connection,
            &config,
            &config.pushd.fr_accepted_queue,
            &config.pushd.get_fr_accepted_routing_key(),
            None,
        )
        .await,
    );

    channels.push(
        make_queue_and_consume::<MassMessageConsumer>(
            &db,
            &connection,
            &config,
            &config.pushd.mass_mention_queue,
            &config.pushd.get_mass_mention_routing_key(),
            None,
        )
        .await,
    );

    channels.push(
        make_queue_and_consume::<DmCallConsumer>(
            &db,
            &connection,
            &config,
            &config.pushd.dm_call_queue,
            &config.pushd.get_dm_call_routing_key(),
            None,
        )
        .await,
    );

    channels.push(
        make_queue_and_consume::<CalendarEventConsumer>(
            &db,
            &connection,
            &config,
            &config.pushd.calendar_event_queue,
            &config.pushd.get_calendar_event_routing_key(),
            None,
        )
        .await,
    );

    if !config.pushd.apn.pkcs8.is_empty() {
        channels.push(
            make_queue_and_consume::<ApnsOutboundConsumer>(
                &db,
                &connection,
                &config,
                &config.pushd.apn.queue,
                &config.pushd.apn.queue,
                None,
            )
            .await,
        );

        let mut table = FieldTable::default();
        table.insert("x-message-deduplication".into(), AMQPValue::Boolean(true));

        channels.push(
            make_queue_and_consume::<AckConsumer>(
                &db,
                &connection,
                &config,
                &config.pushd.ack_queue,
                &config.pushd.ack_queue,
                Some(table),
            )
            .await,
        );
    }

    if !config.pushd.fcm.auth_uri.is_empty() {
        channels.push(
            make_queue_and_consume::<FcmOutboundConsumer>(
                &db,
                &connection,
                &config,
                &config.pushd.fcm.queue,
                &config.pushd.fcm.queue,
                None,
            )
            .await,
        );
    }

    if !config.pushd.vapid.public_key.is_empty() {
        channels.push(
            make_queue_and_consume::<VapidOutboundConsumer>(
                &db,
                &connection,
                &config,
                &config.pushd.vapid.queue,
                &config.pushd.vapid.queue,
                None,
            )
            .await,
        );
    }

    ctrl_c().await.unwrap();

    for channel in channels {
        let _ = channel.close(0, "close".into()).await;
    }
}

/// `revolt-pushd --check-config`: load the config through the same sources and merge as a
/// normal start, derive the VAPID public points and print only lengths and sha256 prefixes.
/// Returns the process exit code: 0 if the config is safe to start with, 1 otherwise.
async fn check_config() -> i32 {
    // A panic message may quote config contents, so only its location is printed
    std::panic::set_hook(Box::new(|info| match info.location() {
        Some(location) => eprintln!(
            "check-config: panic at {}:{}",
            location.file(),
            location.line()
        ),
        None => eprintln!("check-config: panic"),
    }));

    let Ok(config) = tokio::task::spawn(config()).await else {
        println!("config=unloadable");
        return 1;
    };

    let keys = &config.pushd.vapid;

    let primary_derived = vapid::derive_public_b64url(&keys.private_key);
    match &primary_derived {
        Ok(public) => println!(
            "primary-derived len={} sha256={}",
            public.len(),
            vapid::sha256_prefix(public)
        ),
        Err(_) => println!("primary-derived=unparseable"),
    }

    let config_public = vapid::normalize_b64url(&keys.public_key);
    println!(
        "config-public len={} sha256={}",
        config_public.len(),
        vapid::sha256_prefix(&config_public)
    );

    let legacy_derived = if keys.legacy_private_key.is_empty() {
        println!("legacy=empty");
        None
    } else {
        let derived = vapid::derive_public_b64url(&keys.legacy_private_key);
        match &derived {
            Ok(public) => println!(
                "legacy-derived len={} sha256={}",
                public.len(),
                vapid::sha256_prefix(public)
            ),
            Err(_) => println!("legacy-derived=unparseable"),
        }
        Some(derived)
    };

    println!(
        "queue present={}",
        if keys.queue.is_empty() { "no" } else { "yes" }
    );

    if check_config_verdict(&primary_derived, &config_public, legacy_derived.as_ref()) {
        0
    } else {
        1
    }
}

/// The primary key's derived public point must equal the normalized config `public_key`,
/// and a legacy key, when set, must parse
fn check_config_verdict(
    primary_derived: &Result<String, String>,
    config_public: &str,
    legacy_derived: Option<&Result<String, String>>,
) -> bool {
    let primary_ok = matches!(primary_derived, Ok(public) if public == config_public);
    let legacy_ok = legacy_derived.is_none_or(|legacy| legacy.is_ok());

    primary_ok && legacy_ok
}

#[cfg(test)]
mod tests {
    use super::check_config_verdict;

    fn derived(public: &str) -> Result<String, String> {
        Ok(public.to_string())
    }

    fn unparseable() -> Result<String, String> {
        Err("unparseable".to_string())
    }

    #[test]
    fn vapid_check_config_match_passes() {
        assert!(check_config_verdict(&derived("point-a"), "point-a", None));
        assert!(check_config_verdict(
            &derived("point-a"),
            "point-a",
            Some(&derived("point-b"))
        ));
    }

    #[test]
    fn vapid_check_config_mismatch_fails() {
        assert!(!check_config_verdict(&derived("point-a"), "point-b", None));
        assert!(!check_config_verdict(
            &derived("point-a"),
            "point-b",
            Some(&derived("point-c"))
        ));
    }

    #[test]
    fn vapid_check_config_unparseable_primary_fails() {
        assert!(!check_config_verdict(&unparseable(), "point-a", None));
        assert!(!check_config_verdict(&unparseable(), "", None));
    }

    #[test]
    fn vapid_check_config_unparseable_legacy_fails() {
        assert!(!check_config_verdict(
            &derived("point-a"),
            "point-a",
            Some(&unparseable())
        ));
    }
}

async fn make_queue_and_consume<F>(
    db: &Database,
    connection: &Arc<Connection>,
    config: &Settings,
    queue_name: &str,
    routing_key: &str,
    queue_args: Option<FieldTable>,
) -> Arc<Channel>
where
    F: Consumer,
{
    let channel = Arc::new(connection.create_channel().await.unwrap());

    channel
        .exchange_declare(
            config.pushd.exchange.clone().into(),
            lapin::ExchangeKind::Direct,
            ExchangeDeclareOptions {
                durable: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await
        .expect("Failed to declare exchange");

    let mut queue_name = queue_name.to_string();

    if config.pushd.production {
        queue_name += "-prd";
    } else {
        queue_name += "-tst";
    }

    let queue_name = queue_name.as_str();

    let args = QueueDeclareOptions {
        durable: true,
        ..Default::default()
    };

    channel
        .queue_declare(queue_name.into(), args, queue_args.unwrap_or_default())
        .await
        .unwrap();

    channel
        .queue_bind(
            queue_name.into(),
            config.pushd.exchange.clone().into(),
            routing_key.into(),
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await
        .expect(
            "This probably means the revolt.notifications exchange does not exist in rabbitmq!",
        );

    let consumer = channel
        .basic_consume(
            queue_name.into(),
            "".into(),
            BasicConsumeOptions {
                no_ack: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await
        .unwrap();
    info!(
        "Consuming routing key {} as queue {}, tag {}",
        routing_key,
        queue_name,
        consumer.tag()
    );

    let delegate = Delegate(
        F::create(
            db.clone(),
            connection.clone(),
            channel.clone(),
        )
        .await,
    );

    consumer.set_delegate(delegate);

    channel
}
