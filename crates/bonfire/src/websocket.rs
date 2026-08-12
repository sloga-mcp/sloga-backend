use std::{collections::HashSet, net::SocketAddr, sync::Arc};

use async_tungstenite::WebSocketStream;
use fred::{
    error::RedisErrorKind,
    interfaces::{ClientLike, EventInterface, PubsubInterface},
    types::{ReconnectPolicy, RedisConfig},
};
use futures::{
    channel::oneshot,
    join, pin_mut, select,
    stream::{SplitSink, SplitStream},
    FutureExt, SinkExt, StreamExt, TryStreamExt,
};
use redis_kiss::{get_connection, AsyncCommands, PayloadType, REDIS_PAYLOAD_TYPE, REDIS_URI};
use revolt_config::report_internal_error;
use revolt_database::{
    events::{client::EventV1, server::ClientMessage},
    iso8601_timestamp::Timestamp,
    voice::remote_control::remote_control_active_snapshot,
    Database, User, UserHint,
};
use revolt_presence::{create_session, delete_session};

use tokio::{
    net::TcpStream,
    sync::{Mutex, RwLock},
    task::spawn,
};
use tokio_util::compat::{TokioAsyncReadCompatExt, Compat};
use revolt_result::create_error;
use sentry::Level;

use crate::config::{ProtocolConfiguration, WebsocketHandshakeCallback};
use crate::events::state::{State, SubscriptionStateChange};
use revolt_models::v0;

/// Upper bound on envelopes pushed in one drain; comfortably above the
/// per-device queue-depth cap enforced at submission
const E2EE_DRAIN_LIMIT: i64 = 1024;

/// Maximum envelope ids per acknowledgement frame
const E2EE_MAX_ACK_BATCH: usize = 128;

/// Random 256-bit device-claim nonce, unpadded standard base64
fn e2ee_generate_nonce() -> String {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    STANDARD_NO_PAD.encode(bytes)
}

type WsReader = SplitStream<WebSocketStream<Compat<TcpStream>>>;
type WsWriter = SplitSink<WebSocketStream<Compat<TcpStream>>, async_tungstenite::tungstenite::Message>;

/// Start a new WebSocket client worker given access to the database,
/// the relevant TCP stream and the remote address of the client.
pub async fn client(db: &'static Database, stream: TcpStream, addr: SocketAddr) {
    // Upgrade the TCP connection to a WebSocket connection.
    // In this process, we also parse any additional parameters given.
    // e.g. wss://example.com?format=json&version=1
    let (sender, receiver) = oneshot::channel();
    let Ok(ws) = async_tungstenite::accept_hdr_async_with_config(
        stream.compat(),
        WebsocketHandshakeCallback::from(sender),
        None,
    )
    .await
    else {
        return;
    };

    // Verify we've received a valid config, otherwise we should just drop the connection.
    let Ok(mut config) = receiver.await else {
        return;
    };

    info!(
        "User {addr:?} provided protocol configuration (version = {}, format = {:?})",
        config.get_protocol_version(),
        config.get_protocol_format()
    );

    // Split the socket for simultaneously read and write.
    let (mut write, mut read) = ws.split();

    // If the user has not provided authentication, request information.
    if config.get_session_token().is_none() {
        while let Ok(Some(message)) = read.try_next().await {
            if let Ok(ClientMessage::Authenticate { token }) = config.decode(&message) {
                config.set_session_token(token);
                break;
            }
        }
    }

    // Try to authenticate the user.
    let Some(token) = config.get_session_token().as_ref() else {
        write
            .send(config.encode(&EventV1::Error {
                data: create_error!(InvalidSession),
            }))
            .await
            .ok();
        return;
    };

    let (user, session_id) = match User::from_token(db, token, UserHint::Any).await {
        Ok(user) => user,
        Err(err) => {
            write
                .send(config.encode(&EventV1::Error { data: err }))
                .await
                .ok();
            return;
        }
    };

    info!("User {addr:?} authenticated as @{}", user.username);

    db.update_session_last_seen(&session_id, Timestamp::now_utc())
        .await
        .ok();

    // Create local state.
    let mut state = State::from(user, session_id);
    let user_id = state.cache.user_id.clone();

    // Notify socket we have authenticated.
    if report_internal_error!(write.send(config.encode(&EventV1::Authenticated)).await).is_err() {
        return;
    }

    // Download required data to local cache and send Ready payload.
    let ready_payload = match report_internal_error!(
        state
            .generate_ready_payload(db, config.get_ready_payload_fields())
            .await
    ) {
        Ok(ready_payload) => ready_payload,
        Err(_) => return,
    };

    if report_internal_error!(write.send(config.encode(&ready_payload)).await).is_err() {
        return;
    }

    let slowmodes = fetch_user_slowmodes(&user_id).await.unwrap_or_default();
    if !slowmodes.is_empty() {
        let event = EventV1::UserSlowmodes { slowmodes };
        if report_internal_error!(write.send(config.encode(&event)).await).is_err() {
            return;
        }
    }

    // Backfill the channel-topic remote-control visibility pair: clients
    // source their "who is controlling" state from the
    // `RemoteControlActive`/`Ended` events and drop it with the socket, so a
    // session connecting after a grant went active would show nothing until
    // the next grant. Re-send the same redacted event for every live grant,
    // to this socket only. The candidate set is the Ready payload's own
    // voice states — already ViewChannel-filtered, and a grant cannot outlive
    // its call. Gated on the same flag as the delta routes: with remote
    // control disabled the reaper is mass-revoking whatever remains, and a
    // fresh session must not re-light a badge that is being torn down.
    // (Same caveat as every other Ready datum: an Ended fired between this
    // read and the pubsub listener attaching below is not replayed; the
    // frontend clears the map on the next reconnect.)
    if revolt_config::config().await.features.remote_control {
        if let EventV1::Ready {
            voice_states: Some(voice_states),
            ..
        } = &ready_payload
        {
            let channel_ids: Vec<&str> = voice_states
                .iter()
                .map(|voice_state| voice_state.id.as_str())
                .collect();
            for event in remote_control_active_snapshot(&channel_ids).await {
                if report_internal_error!(write.send(config.encode(&event)).await).is_err() {
                    return;
                }
            }
        }
    }

    // Create presence session.
    let (first_session, session_id) = create_session(&user_id, 0).await;

    // If this was the first session, notify other users that we just went online.
    if first_session {
        state.broadcast_presence_change(true).await;
    }

    {
        // Setup channels and mutexes
        let write = Mutex::new(write);
        let subscribed = state.subscribed.clone();
        let active_servers = state.active_servers.clone();
        let session_id = state.session_id.clone();
        let (topic_signal_s, topic_signal_r) = async_channel::unbounded();

        // TODO: this needs to be rewritten
        // Create channels through which the tasks can signal to each other they need to clean up
        let (kill_signal_1_s, kill_signal_1_r) = async_channel::bounded(1);
        let (kill_signal_2_s, kill_signal_2_r) = async_channel::bounded(1);

        // Create a PubSub connection to poll on.
        let listener = listener_with_kill_signal(
            db,
            &mut state,
            addr,
            &config,
            topic_signal_r,
            kill_signal_1_r,
            &write,
            kill_signal_2_s,
        );

        // Read from WebSocket stream.
        let worker = worker_with_kill_signal(
            db,
            addr,
            subscribed,
            active_servers,
            user_id.clone(),
            session_id,
            &config,
            topic_signal_s,
            kill_signal_2_r,
            read,
            &write,
            kill_signal_1_s,
        );

        join!(listener, worker);
    }
    // Clean up presence session.
    let last_session = delete_session(&user_id, session_id).await;

    // If this was the last session, notify other users that we just went offline.
    if last_session {
        state.broadcast_presence_change(false).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn listener_with_kill_signal(
    db: &'static Database,
    state: &mut State,
    addr: SocketAddr,
    config: &ProtocolConfiguration,
    topic_signal_r: async_channel::Receiver<()>,
    kill_signal_r: async_channel::Receiver<()>,
    write: &Mutex<WsWriter>,
    kill_signal_s: async_channel::Sender<()>,
) {
    listener(
        db,
        state,
        addr,
        config,
        topic_signal_r,
        kill_signal_r,
        write,
    )
    .await;
    kill_signal_s.send(()).await.ok();
}

async fn listener(
    db: &'static Database,
    state: &mut State,
    addr: SocketAddr,
    config: &ProtocolConfiguration,
    topic_signal_r: async_channel::Receiver<()>,
    kill_signal_r: async_channel::Receiver<()>,
    write: &Mutex<WsWriter>,
) {
    let stoat_config = revolt_config::config().await;
    let url = stoat_config
        .database
        .redis_pubsub
        .unwrap_or(REDIS_URI.to_string());

    let redis_config = RedisConfig::from_url(&url).unwrap();
    let mut builder = fred::types::Builder::from_config(redis_config);
    builder.set_policy(ReconnectPolicy::new_exponential(8, 100, 30_000, 2));
    let subscriber = match report_internal_error!(builder.build_subscriber_client()) {
        Ok(subscriber) => subscriber,
        Err(_) => return,
    };

    if report_internal_error!(subscriber.init().await).is_err() {
        return;
    }

    // Let Fred automatically re-subscribe to tracked channels on reconnect.
    subscriber.manage_subscriptions();

    // Handle Redis connection dropping
    let (clean_up_s, clean_up_r) = async_channel::bounded(1);
    let clean_up_s = Arc::new(Mutex::new(clean_up_s));
    subscriber.on_error(move |err| {
        warn!("Redis subscriber error: {:?}", err);
        if let RedisErrorKind::Canceled = err.kind() {
            let clean_up_s = clean_up_s.clone();
            spawn(async move {
                clean_up_s.lock().await.send(()).await.ok();
            });
        }
        // Transient errors (IO, timeout) are handled by the reconnect policy.

        Ok(())
    });

    let mut message_rx = subscriber.message_rx();
    'out: loop {
        // Check for state changes for subscriptions.
        match state.apply_state().await {
            SubscriptionStateChange::Reset => {
                if report_internal_error!(subscriber.unsubscribe_all().await).is_err() {
                    break 'out;
                }

                let subscribed = state.subscribed.read().await;
                for id in subscribed.iter() {
                    if report_internal_error!(subscriber.subscribe(id).await).is_err() {
                        break 'out;
                    }
                }

                #[cfg(debug_assertions)]
                info!("{addr:?} has reset their subscriptions");
            }
            SubscriptionStateChange::Change { add, remove } => {
                for id in remove {
                    #[cfg(debug_assertions)]
                    info!("{addr:?} unsubscribing from {id}");

                    if report_internal_error!(subscriber.unsubscribe(id).await).is_err() {
                        break 'out;
                    }
                }

                for id in add {
                    #[cfg(debug_assertions)]
                    info!("{addr:?} subscribing to {id}");

                    if report_internal_error!(subscriber.subscribe(id).await).is_err() {
                        break 'out;
                    }
                }
            }
            SubscriptionStateChange::None => {}
        }

        let t1 = message_rx.recv().fuse();
        let t2 = topic_signal_r.recv().fuse();
        let t3 = kill_signal_r.recv().fuse();
        let t4 = clean_up_r.recv().fuse();

        pin_mut!(t1, t2, t3, t4);

        select! {
            _ = t4 => {
                break 'out;
            },
            _ = t3 => {
                break 'out;
            },
            _ = t2 => {},
            message = t1 => {
                // Handle incoming events.
                let message = match report_internal_error!(message) {
                    Ok(message) => message,
                    Err(_) => break 'out
                };

                let event = match *REDIS_PAYLOAD_TYPE {
                    PayloadType::Json => message
                        .value
                        .as_str()
                        .and_then(|s| report_internal_error!(serde_json::from_str::<EventV1>(s.as_ref())).ok()),
                    PayloadType::Msgpack => message
                        .value
                        .as_bytes()
                        .and_then(|b| report_internal_error!(rmp_serde::from_slice::<EventV1>(b)).ok()),
                    PayloadType::Bincode => message
                        .value
                        .as_bytes()
                        .and_then(|b| report_internal_error!(bincode::deserialize::<EventV1>(b)).ok()),
                };

                let Some(mut event) = event else {
                    let err = format!(
                        "Failed to deserialise event for {}: `{:?}`",
                        message.channel,
                        message
                            .value
                    );

                    error!("{}", err);
                    sentry::capture_message(&err, Level::Error);
                    break 'out;
                };

                if let EventV1::DeleteSession { session_id, .. } = &event {
                    if &state.session_id == session_id {
                        event = EventV1::Logout;
                    }
                } else if let EventV1::DeleteAllSessions {
                    exclude_session_id, ..
                } = &event
                {
                    if let Some(excluded) = exclude_session_id {
                        if &state.session_id != excluded {
                            event = EventV1::Logout;
                        }
                    } else {
                        event = EventV1::Logout;
                    }
                } else {
                    let should_send = state.handle_incoming_event_v1(db, &mut event).await;
                    if !should_send {
                        continue;
                    }
                }

                let result = write.lock().await.send(config.encode(&event)).await;
                if let Err(e) = result {
                    use async_tungstenite::tungstenite::Error;
                    if !matches!(e, Error::AlreadyClosed | Error::ConnectionClosed) {
                        let err = format!("Error while sending an event to {addr:?}: {e:?}");
                        warn!("{}", err);
                        sentry::capture_message(&err, Level::Warning);
                    }

                    break 'out;
                }

                if let EventV1::Logout = event {
                    info!("User {addr:?} received log out event!");
                    break 'out;
                }
            }
        }
    }

    report_internal_error!(subscriber.quit().await).ok();
}

#[allow(clippy::too_many_arguments)]
async fn worker_with_kill_signal(
    db: &'static Database,
    addr: SocketAddr,
    subscribed: Arc<RwLock<HashSet<String>>>,
    active_servers: Arc<Mutex<lru_time_cache::LruCache<String, ()>>>,
    user_id: String,
    session_id: String,
    config: &ProtocolConfiguration,
    topic_signal_s: async_channel::Sender<()>,
    kill_signal_r: async_channel::Receiver<()>,
    read: WsReader,
    write: &Mutex<WsWriter>,
    kill_signal_s: async_channel::Sender<()>,
) {
    worker(
        db,
        addr,
        subscribed,
        active_servers,
        user_id,
        session_id,
        config,
        topic_signal_s,
        kill_signal_r,
        read,
        write,
    )
    .await;
    kill_signal_s.send(()).await.ok();
}

#[allow(clippy::too_many_arguments)]
async fn worker(
    db: &'static Database,
    addr: SocketAddr,
    subscribed: Arc<RwLock<HashSet<String>>>,
    active_servers: Arc<Mutex<lru_time_cache::LruCache<String, ()>>>,
    user_id: String,
    session_id: String,
    config: &ProtocolConfiguration,
    topic_signal_s: async_channel::Sender<()>,
    kill_signal_r: async_channel::Receiver<()>,
    mut read: WsReader,
    write: &Mutex<WsWriter>,
) {
    let revolt_config = revolt_config::config().await;

    // E2EE device-claim state, local to this connection. A claim must be
    // proven (Ed25519 signature over a server nonce) before this connection
    // gains drain or acknowledgement rights — a stolen session token alone
    // must not be able to drain-and-ack (silently destroy) queued messages.
    let mut e2ee_pending_challenge: Option<(String, String)> = None;
    let mut e2ee_proven_device: Option<String> = None;

    loop {
        let t1 = read.try_next().fuse();
        let t2 = kill_signal_r.recv().fuse();

        pin_mut!(t1, t2);

        select! {
            _ = t2 => {
                return;
            },
            result = t1 => {
                let msg = match result {
                    Ok(Some(msg)) => msg,
                    Ok(None) => {
                        warn!("Received a None message!");
                        sentry::capture_message("Received a None message!", Level::Warning);
                        return;
                    }
                    Err(e) => {
                        use async_tungstenite::tungstenite::Error;
                        if !matches!(e, Error::AlreadyClosed | Error::ConnectionClosed) {
                            let err = format!("Error while reading an event from {addr:?}: {e:?}");
                            warn!("{}", err);
                            sentry::capture_message(&err, Level::Warning);
                        }

                        return;
                    }
                };

                let Ok(payload) = config.decode(&msg) else {
                    continue;
                };

                match payload {
                    ClientMessage::BeginTyping { channel } => {
                        if revolt_config.disable_events_dont_use {
                            continue;
                        }

                        if !subscribed.read().await.contains(&channel) {
                            continue;
                        }

                        EventV1::ChannelStartTyping {
                            id: channel.clone(),
                            user: user_id.clone(),
                        }
                        .p(channel.clone())
                        .await;
                    }
                    ClientMessage::EndTyping { channel } => {
                        if revolt_config.disable_events_dont_use {
                            continue;
                        }

                        if !subscribed.read().await.contains(&channel) {
                            continue;
                        }

                        EventV1::ChannelStopTyping {
                            id: channel.clone(),
                            user: user_id.clone(),
                        }
                        .p(channel.clone())
                        .await;
                    }
                    ClientMessage::Subscribe { server_id } => {
                        let mut servers = active_servers.lock().await;
                        let has_item = servers.contains_key(&server_id);
                        servers.insert(server_id, ());

                        if !has_item {
                            // Poke the listener to adjust subscriptions
                            topic_signal_s.send(()).await.ok();
                        }
                    }
                    ClientMessage::Ping { data, responded } => {
                        if responded.is_none() {
                            write
                                .lock()
                                .await
                                .send(config.encode(&EventV1::Pong { data }))
                                .await
                                .ok();
                        }
                    }
                    ClientMessage::E2EERequestChallenge { device_id } => {
                        if !revolt_config.features.e2ee_enabled {
                            continue;
                        }

                        // Fresh nonce per attempt; issuing a new challenge
                        // invalidates any previous one
                        let nonce = e2ee_generate_nonce();
                        e2ee_pending_challenge = Some((device_id, nonce.clone()));

                        write
                            .lock()
                            .await
                            .send(config.encode(&EventV1::E2EEChallenge { nonce }))
                            .await
                            .ok();
                    }
                    ClientMessage::E2EEProveDevice {
                        device_id,
                        signature,
                    } => {
                        if !revolt_config.features.e2ee_enabled {
                            continue;
                        }

                        // Single-use challenge: taken here so a failed proof
                        // cannot be retried against the same nonce
                        let challenge = e2ee_pending_challenge.take();

                        let accepted = match challenge {
                            Some((challenged_device, nonce)) if challenged_device == device_id => {
                                if let Ok(identity) =
                                    db.fetch_e2ee_identity(&user_id, &device_id).await
                                {
                                    identity.verify_claim(&nonce, &session_id, &signature)
                                } else {
                                    false
                                }
                            }
                            _ => false,
                        };

                        if accepted {
                            e2ee_proven_device = Some(device_id.clone());

                            db.update_e2ee_identity_session(
                                &user_id,
                                &device_id,
                                &session_id,
                                Timestamp::now_utc(),
                            )
                            .await
                            .ok();

                            // Same-session predecessor sweep (device-
                            // lifecycle fixes §2): an accepted claim
                            // proves THIS install's store holds device_id;
                            // any other row bound to this session is a
                            // dead predecessor. Recurring self-heal for a
                            // crash between publish-insert and its sweep.
                            revolt_database::E2EEIdentity::revoke_same_session_predecessors(
                                db,
                                &user_id,
                                &session_id,
                                &device_id,
                            )
                            .await;
                        }

                        {
                            let mut write = write.lock().await;

                            if write
                                .send(config.encode(&EventV1::E2EEClaimResult {
                                    device_id: device_id.clone(),
                                    accepted,
                                }))
                                .await
                                .is_err()
                            {
                                return;
                            }

                            // Drain the queue for the proven device, ordered
                            // by envelope ULID. Envelopes stay queued until
                            // acknowledged; clients dedup against live pushes
                            // by envelope id.
                            if accepted {
                                if let Ok(envelopes) = db
                                    .fetch_e2ee_envelopes(&user_id, &device_id, E2EE_DRAIN_LIMIT)
                                    .await
                                {
                                    for envelope in envelopes {
                                        if write
                                            .send(
                                                config.encode(&EventV1::E2EEMessage(
                                                    envelope.into(),
                                                )),
                                            )
                                            .await
                                            .is_err()
                                        {
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    ClientMessage::E2EEAck { ids } => {
                        if !revolt_config.features.e2ee_enabled {
                            continue;
                        }

                        // Acknowledgement rights require a proven device
                        // claim; acks are scoped to that device and
                        // idempotent (deleting an already-deleted envelope
                        // is a no-op)
                        let Some(device_id) = &e2ee_proven_device else {
                            continue;
                        };

                        for id in ids.iter().take(E2EE_MAX_ACK_BATCH) {
                            db.delete_e2ee_envelope(id, &user_id, device_id).await.ok();
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn fetch_user_slowmodes(user_id: &str) -> Option<Vec<v0::ChannelSlowmode>> {
    let mut conn = get_connection().await.ok()?.into_inner();
    let idx_key = format!("slowmode_idx:{}", user_id);

    let channel_ids: Vec<String> = conn.smembers(&idx_key).await.unwrap_or_default();
    if channel_ids.is_empty() {
        return Some(vec![]);
    }

    // Bulk fetch all TTLs in one round trip
    let mut pipe = redis_kiss::redis::pipe();
    for channel_id in &channel_ids {
        pipe.ttl(format!("slowmode:{}:{}", user_id, channel_id));
    }
    let ttls: Vec<i64> = pipe.query_async(&mut conn).await.unwrap_or_default();

    // Partition into alive/expired in one pass
    let mut slowmodes = vec![];
    let mut expired = vec![];
    for (channel_id, ttl) in channel_ids.iter().zip(ttls.iter()) {
        if *ttl > 0 {
            slowmodes.push(v0::ChannelSlowmode {
                channel_id: channel_id.clone(),
                duration: *ttl as u64,
                retry_after: *ttl as u64,
            });
        } else {
            expired.push(channel_id.as_str());
        }
    }

    // Bulk remove all expired members in one SREM call
    if !expired.is_empty() {
        conn.srem::<_, _, ()>(&idx_key, expired).await.ok();
    }

    Some(slowmodes)
}
