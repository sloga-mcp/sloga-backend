use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use async_tungstenite::{
    tungstenite::{protocol::WebSocketConfig, Error as WsError, Message},
    WebSocketStream,
};
use fred::{
    error::RedisErrorKind,
    interfaces::{ClientLike, EventInterface, PubsubInterface},
    types::{ReconnectPolicy, RedisConfig},
};
use futures::{
    channel::oneshot,
    io::{AsyncRead, AsyncWrite},
    join, pin_mut, select, select_biased,
    stream::{SplitSink, SplitStream},
    FutureExt, Sink, SinkExt, StreamExt, TryStreamExt,
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
type WsWriter = SplitSink<WebSocketStream<Compat<TcpStream>>, Message>;

/// Absolute bound on everything before authentication: the upgrade, the
/// configuration hand-off and waiting for a token. Kept above the 10 s
/// after which stoat.js gives up on a connect.
const PREAUTH_DEADLINE: Duration = Duration::from_secs(15);

/// Frames other than `Authenticate` tolerated while waiting for a token
const PREAUTH_MAX_OTHER_FRAMES: usize = 16;

/// Largest message, and largest single frame, accepted from a client.
/// The largest legitimate one is an `E2EEAck` of a few tens of KiB.
const MAX_INBOUND_SIZE: usize = 1 << 20;

/// Bound on the session lookup and the Ready database work, generous so a
/// large account's slow Ready is never cut into a reconnect loop
const BOOTSTRAP_DB_DEADLINE: Duration = Duration::from_secs(120);

/// Bound on a single send to a client that stopped reading
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on sending the Ready payload, which can be large: a slow link must
/// not be cut into a reconnect loop
const READY_SEND_TIMEOUT: Duration = Duration::from_secs(120);

/// How often an authenticated socket is pinged
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// Inbound silence after which an authenticated socket is dropped
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Room for typing requests queued from the worker to the listener; a full
/// queue makes the worker wait, so a typing flood slows its own reads
const LISTENER_SIGNAL_CAPACITY: usize = 64;

/// Keep-alive timing of an authenticated socket
#[derive(Clone, Copy, Debug)]
struct KeepAlive {
    ping_interval: Duration,
    idle_timeout: Duration,
    send_timeout: Duration,
}

const KEEP_ALIVE: KeepAlive = KeepAlive {
    ping_interval: PING_INTERVAL,
    idle_timeout: IDLE_TIMEOUT,
    send_timeout: SEND_TIMEOUT,
};

/// Socket limits for the whole connection; they cannot be changed after
/// the upgrade, so they already apply before authentication
fn websocket_config() -> WebSocketConfig {
    WebSocketConfig {
        max_message_size: Some(MAX_INBOUND_SIZE),
        max_frame_size: Some(MAX_INBOUND_SIZE),
        ..Default::default()
    }
}

/// Why a connection never got as far as a session token
#[derive(Debug)]
enum PreAuthError {
    /// The pre-auth deadline passed
    Timeout,
    /// The upgrade failed, or the socket failed while waiting for a token
    Socket(WsError),
    /// The upgrade finished without handing over a configuration
    NoConfiguration,
    /// The socket closed before a token arrived
    Closed,
    /// Too many frames other than `Authenticate`
    TooManyFrames,
}

/// Upgrade `stream` to a WebSocket, read the protocol configuration from
/// the request, and wait for a session token (from the query or an
/// `Authenticate` frame), all within one absolute `deadline`, so trickling
/// bytes or frames cannot extend it.
///
/// Only succeeds with a session token set on the configuration.
async fn preauth<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    deadline: Duration,
) -> Result<(WebSocketStream<S>, ProtocolConfiguration), PreAuthError> {
    let upgrade = async move {
        // The callback parses parameters such as
        // wss://example.com?format=json&version=1
        let (sender, receiver) = oneshot::channel();
        let mut ws = async_tungstenite::accept_hdr_async_with_config(
            stream,
            WebsocketHandshakeCallback::from(sender),
            Some(websocket_config()),
        )
        .await
        .map_err(PreAuthError::Socket)?;

        let mut config = receiver.await.map_err(|_| PreAuthError::NoConfiguration)?;

        let mut other_frames = 0;
        while config.get_session_token().is_none() {
            let message = match ws.try_next().await {
                Ok(Some(message)) => message,
                Ok(None) => return Err(PreAuthError::Closed),
                Err(err) => return Err(PreAuthError::Socket(err)),
            };

            if let Ok(ClientMessage::Authenticate { token }) = config.decode(&message) {
                config.set_session_token(token);
            } else {
                other_frames += 1;
                if other_frames > PREAUTH_MAX_OTHER_FRAMES {
                    return Err(PreAuthError::TooManyFrames);
                }
            }
        }

        Ok((ws, config))
    };

    tokio::time::timeout(deadline, upgrade)
        .await
        .unwrap_or(Err(PreAuthError::Timeout))
}

/// Outcome of one socket send under a time limit
#[derive(Debug)]
enum Sent {
    Done,
    Failed(WsError),
    TimedOut,
}

/// Send one frame, giving up after `limit` (a client that stopped reading)
async fn send_bounded<W>(write: &mut W, message: Message, limit: Duration) -> Sent
where
    W: Sink<Message, Error = WsError> + Unpin,
{
    match tokio::time::timeout(limit, write.send(message)).await {
        Ok(Ok(())) => Sent::Done,
        Ok(Err(err)) => Sent::Failed(err),
        Err(_) => Sent::TimedOut,
    }
}

/// A send before the presence session exists: a failure is reported as
/// before, a timeout is logged; either way the connection is dropped.
async fn bootstrap_send(
    write: &mut WsWriter,
    message: Message,
    limit: Duration,
    addr: SocketAddr,
    started: Instant,
) -> bool {
    match send_bounded(write, message, limit).await {
        Sent::Done => true,
        Sent::Failed(err) => {
            report_internal_error!(Err::<(), _>(err)).ok();
            false
        }
        Sent::TimedOut => {
            bootstrap_timed_out(addr, started, "a send");
            false
        }
    }
}

fn bootstrap_timed_out(addr: SocketAddr, started: Instant, step: &str) {
    warn!(
        "User {addr:?} timed out on {step} while connecting, {:?} after accept",
        started.elapsed()
    );
}

/// After the presence session exists, a send that timed out ends the
/// connection the normal way
fn slow_reader(addr: SocketAddr) {
    info!("User {addr:?} stopped reading, closing the connection");
}

/// When an authenticated socket last showed signs of life
#[derive(Clone, Copy, Debug)]
struct Liveness {
    last_inbound: Instant,
    idle_timeout: Duration,
}

impl Liveness {
    fn new(now: Instant, idle_timeout: Duration) -> Self {
        Liveness {
            last_inbound: now,
            idle_timeout,
        }
    }

    /// Any inbound frame counts, Pongs included
    fn record_inbound(&mut self, now: Instant) {
        self.last_inbound = self.last_inbound.max(now);
    }

    fn deadline(&self) -> Instant {
        self.last_inbound + self.idle_timeout
    }

    fn is_expired(&self, now: Instant) -> bool {
        now >= self.deadline()
    }
}

/// Requests from the worker to the listener task, which owns the state
#[derive(Debug)]
enum ListenerSignal {
    /// The active servers changed: re-run `apply_state`
    Topics,
    /// The client started (`begin`) or stopped typing in `channel`;
    /// published only if `typing_allowed`
    Typing { channel: String, begin: bool },
}

/// Whether this connection may publish a typing indicator to `id`: only a
/// channel (or thread) in the cache that the connection is also subscribed
/// to. `subscribed` alone also holds user, server, member and private
/// topics, and the cache alone can hold threads the user cannot see.
fn typing_allowed(state: &State, subscribed: &HashSet<String>, id: &str) -> bool {
    state.cache.channels.contains_key(id) && subscribed.contains(id)
}

/// The typing event the listener publishes to `channel` for this
/// connection's user, or `None` if `typing_allowed` refuses it
fn typing_event(
    state: &State,
    subscribed: &HashSet<String>,
    channel: &str,
    begin: bool,
) -> Option<EventV1> {
    if !typing_allowed(state, subscribed, channel) {
        return None;
    }

    let id = channel.to_string();
    let user = state.cache.user_id.clone();
    Some(if begin {
        EventV1::ChannelStartTyping { id, user }
    } else {
        EventV1::ChannelStopTyping { id, user }
    })
}

/// Start a new WebSocket client worker given access to the database,
/// the relevant TCP stream and the remote address of the client.
pub async fn client(db: &'static Database, stream: TcpStream, addr: SocketAddr) {
    let started = Instant::now();

    // Upgrade the TCP connection to a WebSocket connection, parse any
    // additional parameters given and wait for a session token.
    let (ws, config) = match preauth(stream.compat(), PREAUTH_DEADLINE).await {
        Ok(upgraded) => upgraded,
        Err(PreAuthError::Socket(err)) => {
            debug!("User {addr:?} failed before authenticating: {err}");
            return;
        }
        Err(err) => {
            debug!("User {addr:?} left before authenticating: {err:?}");
            return;
        }
    };

    info!(
        "User {addr:?} provided protocol configuration (version = {}, format = {:?})",
        config.get_protocol_version(),
        config.get_protocol_format()
    );

    // Split the socket for simultaneously read and write.
    let (mut write, read) = ws.split();

    // Try to authenticate the user. `preauth` only succeeds with a token,
    // so the refusal below is unreachable; it stays as a defensive answer.
    let Some(token) = config.get_session_token().as_ref() else {
        send_bounded(
            &mut write,
            config.encode(&EventV1::Error {
                data: create_error!(InvalidSession),
            }),
            SEND_TIMEOUT,
        )
        .await;
        return;
    };

    // Everything up to `create_session` is bounded: database work by one
    // shared deadline, each send by `SEND_TIMEOUT`. Nothing after it is,
    // so the presence session is always cleaned up.
    let db_deadline = tokio::time::Instant::now() + BOOTSTRAP_DB_DEADLINE;

    let (user, session_id) = match tokio::time::timeout_at(
        db_deadline,
        User::from_token(db, token, UserHint::Any),
    )
    .await
    {
        Ok(Ok(user)) => user,
        Ok(Err(err)) if revolt_database::is_invalid_session(&err) => {
            send_bounded(
                &mut write,
                config.encode(&EventV1::Error { data: err }),
                SEND_TIMEOUT,
            )
            .await;
            return;
        }
        Ok(Err(err)) => {
            // Any other failure (database or internal) closes with no frame.
            // Shipped clients treat every Error frame as permanent and stop
            // reconnecting, while a plain close makes them back off and
            // retry. The jitter blunts immediate reconnects from other SDKs.
            warn!(
                "User {addr:?} could not be authenticated, closing without an error frame: {:?}",
                err.error_type
            );

            // `ThreadRng` is not Send: draw the value before any await.
            let jitter_ms = {
                use rand::Rng;
                rand::thread_rng().gen_range(1000..=3000u64)
            };
            tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
            return;
        }
        Err(_) => {
            bootstrap_timed_out(addr, started, "the session lookup");
            return;
        }
    };

    info!("User {addr:?} authenticated as @{}", user.username);

    if tokio::time::timeout_at(
        db_deadline,
        db.update_session_last_seen(&session_id, Timestamp::now_utc()),
    )
    .await
    .is_err()
    {
        bootstrap_timed_out(addr, started, "the session update");
        return;
    }

    // Create local state.
    let mut state = State::from(user, session_id);
    let user_id = state.cache.user_id.clone();

    // Notify socket we have authenticated.
    if !bootstrap_send(
        &mut write,
        config.encode(&EventV1::Authenticated),
        SEND_TIMEOUT,
        addr,
        started,
    )
    .await
    {
        return;
    }

    // Download required data to local cache and send Ready payload.
    let ready_payload = match tokio::time::timeout_at(
        db_deadline,
        state.generate_ready_payload(db, config.get_ready_payload_fields()),
    )
    .await
    {
        Ok(ready_payload) => match report_internal_error!(ready_payload) {
            Ok(ready_payload) => ready_payload,
            Err(_) => return,
        },
        Err(_) => {
            bootstrap_timed_out(addr, started, "the Ready payload");
            return;
        }
    };

    if !bootstrap_send(
        &mut write,
        config.encode(&ready_payload),
        READY_SEND_TIMEOUT,
        addr,
        started,
    )
    .await
    {
        return;
    }

    let slowmodes = match tokio::time::timeout_at(db_deadline, fetch_user_slowmodes(&user_id)).await
    {
        Ok(slowmodes) => slowmodes.unwrap_or_default(),
        Err(_) => {
            bootstrap_timed_out(addr, started, "the slowmode lookup");
            return;
        }
    };
    if !slowmodes.is_empty() {
        let event = EventV1::UserSlowmodes { slowmodes };
        if !bootstrap_send(
            &mut write,
            config.encode(&event),
            SEND_TIMEOUT,
            addr,
            started,
        )
        .await
        {
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
            let Ok(events) =
                tokio::time::timeout_at(db_deadline, remote_control_active_snapshot(&channel_ids))
                    .await
            else {
                bootstrap_timed_out(addr, started, "the remote-control snapshot");
                return;
            };
            for event in events {
                if !bootstrap_send(
                    &mut write,
                    config.encode(&event),
                    SEND_TIMEOUT,
                    addr,
                    started,
                )
                .await
                {
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
        let (topic_signal_s, topic_signal_r) = async_channel::bounded(LISTENER_SIGNAL_CAPACITY);

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
            KEEP_ALIVE,
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
    topic_signal_r: async_channel::Receiver<ListenerSignal>,
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
    topic_signal_r: async_channel::Receiver<ListenerSignal>,
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
            signal = t2 => {
                // `Topics` only needs the `apply_state` at the top of the loop
                if let Ok(ListenerSignal::Typing { channel, begin }) = signal {
                    let event = {
                        let subscribed = state.subscribed.read().await;
                        typing_event(state, &subscribed, &channel, begin)
                    };

                    if let Some(event) = event {
                        event.p(channel).await;
                    }
                }
            },
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

                let result =
                    send_bounded(&mut *write.lock().await, config.encode(&event), SEND_TIMEOUT)
                        .await;
                match result {
                    Sent::Done => {}
                    Sent::Failed(e) => {
                        if !matches!(e, WsError::AlreadyClosed | WsError::ConnectionClosed) {
                            let err = format!("Error while sending an event to {addr:?}: {e:?}");
                            warn!("{}", err);
                            sentry::capture_message(&err, Level::Warning);
                        }

                        break 'out;
                    }
                    Sent::TimedOut => {
                        slow_reader(addr);
                        break 'out;
                    }
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
    active_servers: crate::events::state::SharedActiveServers,
    user_id: String,
    session_id: String,
    config: &ProtocolConfiguration,
    topic_signal_s: async_channel::Sender<ListenerSignal>,
    kill_signal_r: async_channel::Receiver<()>,
    read: WsReader,
    write: &Mutex<WsWriter>,
    keep_alive: KeepAlive,
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
        keep_alive,
    )
    .await;
    kill_signal_s.send(()).await.ok();
}

#[allow(clippy::too_many_arguments)]
async fn worker(
    db: &'static Database,
    addr: SocketAddr,
    subscribed: Arc<RwLock<HashSet<String>>>,
    active_servers: crate::events::state::SharedActiveServers,
    user_id: String,
    session_id: String,
    config: &ProtocolConfiguration,
    topic_signal_s: async_channel::Sender<ListenerSignal>,
    kill_signal_r: async_channel::Receiver<()>,
    mut read: WsReader,
    write: &Mutex<WsWriter>,
    keep_alive: KeepAlive,
) {
    let revolt_config = revolt_config::config().await;

    // E2EE device-claim state, local to this connection. A claim must be
    // proven (Ed25519 signature over a server nonce) before this connection
    // gains drain or acknowledgement rights — a stolen session token alone
    // must not be able to drain-and-ack (silently destroy) queued messages.
    let mut e2ee_pending_challenge: Option<(String, String)> = None;
    let mut e2ee_proven_device: Option<String> = None;

    // Ping the client regularly; a client that sends nothing at all (not
    // even the Pong) for `idle_timeout` is gone.
    let mut liveness = Liveness::new(Instant::now(), keep_alive.idle_timeout);
    let mut ping = tokio::time::interval_at(
        tokio::time::Instant::now() + keep_alive.ping_interval,
        keep_alive.ping_interval,
    );
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let t1 = read.try_next().fuse();
        let t2 = kill_signal_r.recv().fuse();
        let t3 = ping.tick().fuse();
        let t4 = tokio::time::sleep_until(liveness.deadline().into()).fuse();

        pin_mut!(t1, t2, t3, t4);

        // Biased, in this order: a frame that is already waiting must win
        // over the idle timer, or a client whose frames queued up while
        // this loop was busy would be dropped as silent.
        select_biased! {
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
                        if !matches!(e, WsError::AlreadyClosed | WsError::ConnectionClosed) {
                            let err = format!("Error while reading an event from {addr:?}: {e:?}");
                            warn!("{}", err);
                            sentry::capture_message(&err, Level::Warning);
                        }

                        return;
                    }
                };

                liveness.record_inbound(Instant::now());

                let Ok(payload) = config.decode(&msg) else {
                    continue;
                };

                match payload {
                    ClientMessage::BeginTyping { channel } => {
                        if revolt_config.disable_events_dont_use {
                            continue;
                        }

                        forward_typing(&subscribed, &topic_signal_s, channel, true).await;
                    }
                    ClientMessage::EndTyping { channel } => {
                        if revolt_config.disable_events_dont_use {
                            continue;
                        }

                        forward_typing(&subscribed, &topic_signal_s, channel, false).await;
                    }
                    ClientMessage::Subscribe { server_id } => {
                        // Membership is checked by the listener against its
                        // server cache; here only junk ids are kept out of
                        // the bounded set.
                        if !crate::events::state::is_ulid_shaped(&server_id) {
                            continue;
                        }

                        // A new key changes the live set (and may evict
                        // another); refreshing an existing one does not.
                        let changed = {
                            let mut servers = active_servers.lock().await;
                            let is_new = !servers.contains(&server_id);
                            let evicted = servers.touch(server_id, std::time::Instant::now());
                            is_new || evicted.is_some()
                        };

                        if changed {
                            // Poke the listener to adjust subscriptions
                            topic_signal_s.send(ListenerSignal::Topics).await.ok();
                        }
                    }
                    ClientMessage::Ping { data, responded } => {
                        if responded.is_none() {
                            let sent = send_bounded(
                                &mut *write.lock().await,
                                config.encode(&EventV1::Pong { data }),
                                keep_alive.send_timeout,
                            )
                            .await;
                            if matches!(sent, Sent::TimedOut) {
                                slow_reader(addr);
                                return;
                            }
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

                        let sent = send_bounded(
                            &mut *write.lock().await,
                            config.encode(&EventV1::E2EEChallenge { nonce }),
                            keep_alive.send_timeout,
                        )
                        .await;
                        if matches!(sent, Sent::TimedOut) {
                            slow_reader(addr);
                            return;
                        }
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

                            let sent = send_bounded(
                                &mut *write,
                                config.encode(&EventV1::E2EEClaimResult {
                                    device_id: device_id.clone(),
                                    accepted,
                                }),
                                keep_alive.send_timeout,
                            )
                            .await;
                            match sent {
                                Sent::Done => {}
                                Sent::Failed(_) => return,
                                Sent::TimedOut => {
                                    slow_reader(addr);
                                    return;
                                }
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
                                        let sent = send_bounded(
                                            &mut *write,
                                            config.encode(&EventV1::E2EEMessage(envelope.into())),
                                            keep_alive.send_timeout,
                                        )
                                        .await;
                                        match sent {
                                            Sent::Done => {}
                                            Sent::Failed(_) => return,
                                            Sent::TimedOut => {
                                                slow_reader(addr);
                                                return;
                                            }
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
            },
            _ = t3 => {
                let sent = send_bounded(
                    &mut *write.lock().await,
                    Message::Ping(Vec::new()),
                    keep_alive.send_timeout,
                )
                .await;
                match sent {
                    Sent::Done => {}
                    Sent::Failed(e) => {
                        debug!("Failed to ping {addr:?}: {e:?}");
                        return;
                    }
                    Sent::TimedOut => {
                        slow_reader(addr);
                        return;
                    }
                }
            },
            _ = t4 => {
                if liveness.is_expired(Instant::now()) {
                    info!("User {addr:?} went silent, closing the connection");
                    return;
                }
            },
        }
    }
}

/// Hand a typing request to the listener, which alone sees the channel
/// cache and decides with `typing_allowed`. Ids this connection is not
/// subscribed to at all are dropped here already, so they never queue.
async fn forward_typing(
    subscribed: &RwLock<HashSet<String>>,
    topic_signal_s: &async_channel::Sender<ListenerSignal>,
    channel: String,
    begin: bool,
) {
    if !subscribed.read().await.contains(&channel) {
        return;
    }

    topic_signal_s
        .send(ListenerSignal::Typing { channel, begin })
        .await
        .ok();
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

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        future::Future,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use revolt_database::{events::client::ReadyPayloadFields, Channel, DatabaseInfo};
    use tokio::io::{AsyncWriteExt, DuplexStream};

    use super::*;
    use crate::config::ProtocolFormat;
    use crate::events::state::ActiveServers;

    /// Pre-auth deadline the timing tests inject
    const DEADLINE: Duration = Duration::from_millis(300);

    /// Scheduling slack allowed past `DEADLINE`
    const SLACK: Duration = Duration::from_millis(250);

    type Upgraded = (WebSocketStream<Compat<DuplexStream>>, ProtocolConfiguration);

    /// Run `preauth` with `deadline` on one end of an in-memory pipe while
    /// `client` drives the other end. Fails, rather than hangs, once three
    /// deadlines pass. Returns the outcome and how long it took.
    async fn run_preauth<F, Fut>(
        deadline: Duration,
        client: F,
    ) -> (Result<Upgraded, PreAuthError>, Duration)
    where
        F: FnOnce(DuplexStream) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        let client = tokio::spawn(client(client_io));

        let started = Instant::now();
        let outcome = tokio::time::timeout(deadline * 3, preauth(server_io.compat(), deadline))
            .await
            .expect("preauth outlived three times its deadline");
        let elapsed = started.elapsed();

        client.abort();
        (outcome, elapsed)
    }

    async fn upgrade(io: DuplexStream, url: &str) -> WebSocketStream<Compat<DuplexStream>> {
        async_tungstenite::client_async(url, io.compat())
            .await
            .expect("client handshake")
            .0
    }

    fn expect_err(outcome: Result<Upgraded, PreAuthError>) -> PreAuthError {
        match outcome {
            Ok(_) => panic!("preauth let the client through"),
            Err(err) => err,
        }
    }

    fn assert_deadline_hit(outcome: Result<Upgraded, PreAuthError>, elapsed: Duration) {
        let err = expect_err(outcome);
        assert!(
            matches!(err, PreAuthError::Timeout),
            "expected the deadline, got {err:?}"
        );
        assert!(elapsed < DEADLINE + SLACK, "took {elapsed:?}");
    }

    fn expect_token(outcome: Result<Upgraded, PreAuthError>) -> Option<String> {
        match outcome {
            Ok((_, config)) => config.get_session_token().clone(),
            Err(err) => panic!("expected a session token, got {err:?}"),
        }
    }

    fn junk() -> Message {
        Message::Text("{}".to_string())
    }

    fn authenticate() -> Message {
        Message::Text(r#"{"type":"Authenticate","token":"abc"}"#.to_string())
    }

    #[tokio::test]
    async fn sec005_preauth_drops_a_silent_client() {
        let (outcome, elapsed) = run_preauth(DEADLINE, |io| async move {
            let _io = io;
            std::future::pending::<()>().await
        })
        .await;

        assert_deadline_hit(outcome, elapsed);
    }

    #[tokio::test]
    async fn sec005_preauth_drops_a_header_trickle() {
        // tungstenite refuses a request after 64 tiny reads by itself; keep
        // that well past the outer guard so only the deadline can end it
        const INTERVAL: Duration = Duration::from_millis(100);
        assert!(INTERVAL * 64 > DEADLINE * 3);

        let (outcome, elapsed) = run_preauth(DEADLINE, |mut io| async move {
            let request = b"GET /?token=abc HTTP/1.1\r\nHost: localhost\r\n\
                Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
                Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
            for byte in request {
                if io.write_all(&[*byte]).await.is_err() {
                    break;
                }
                tokio::time::sleep(INTERVAL).await;
            }
            std::future::pending::<()>().await
        })
        .await;

        assert_deadline_hit(outcome, elapsed);
    }

    #[tokio::test]
    async fn sec005_preauth_drops_an_upgrade_without_a_token() {
        let (outcome, elapsed) = run_preauth(DEADLINE, |io| async move {
            let _ws = upgrade(io, "ws://localhost/").await;
            std::future::pending::<()>().await
        })
        .await;

        assert_deadline_hit(outcome, elapsed);
    }

    /// A frame every 50 ms would keep a per-read timeout alive forever (and
    /// reach the frame cap only after 850 ms); the deadline must still hold.
    #[tokio::test]
    async fn sec005_preauth_deadline_is_absolute_not_idle() {
        let (outcome, elapsed) = run_preauth(DEADLINE, |io| async move {
            let mut ws = upgrade(io, "ws://localhost/").await;
            while ws.send(junk()).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;

        assert_deadline_hit(outcome, elapsed);
    }

    #[tokio::test]
    async fn sec005_preauth_drops_after_sixteen_other_frames() {
        let (outcome, elapsed) = run_preauth(DEADLINE, |io| async move {
            let mut ws = upgrade(io, "ws://localhost/").await;
            for _ in 0..PREAUTH_MAX_OTHER_FRAMES + 1 {
                ws.send(junk()).await.ok();
            }
            std::future::pending::<()>().await
        })
        .await;

        let err = expect_err(outcome);
        assert!(
            matches!(err, PreAuthError::TooManyFrames),
            "expected the frame cap, got {err:?}"
        );
        assert!(elapsed < DEADLINE, "took {elapsed:?}");
    }

    #[tokio::test]
    async fn sec005_preauth_accepts_a_token_after_sixteen_other_frames() {
        let (outcome, _) = run_preauth(DEADLINE, |io| async move {
            let mut ws = upgrade(io, "ws://localhost/").await;
            for _ in 0..PREAUTH_MAX_OTHER_FRAMES {
                ws.send(junk()).await.ok();
            }
            ws.send(authenticate()).await.ok();
            std::future::pending::<()>().await
        })
        .await;

        assert_eq!(expect_token(outcome).as_deref(), Some("abc"));
    }

    #[tokio::test]
    async fn sec005_preauth_refuses_a_two_mib_frame() {
        // Long enough that only the size limit can end it in time
        let deadline = Duration::from_secs(2);

        let (outcome, elapsed) = run_preauth(deadline, |io| async move {
            let mut ws = upgrade(io, "ws://localhost/").await;
            ws.send(Message::Binary(vec![0; 2 << 20])).await.ok();
            std::future::pending::<()>().await
        })
        .await;

        let err = expect_err(outcome);
        assert!(
            matches!(err, PreAuthError::Socket(WsError::Capacity(_))),
            "expected the size limit, got {err:?}"
        );
        assert!(elapsed < Duration::from_secs(1), "took {elapsed:?}");
    }

    #[tokio::test]
    async fn sec005_preauth_accepts_a_token_in_the_query() {
        let (outcome, _) = run_preauth(DEADLINE, |io| async move {
            let _ws = upgrade(io, "ws://localhost/?version=1&token=abc").await;
            std::future::pending::<()>().await
        })
        .await;

        assert_eq!(expect_token(outcome).as_deref(), Some("abc"));
    }

    #[tokio::test]
    async fn sec005_preauth_accepts_an_authenticate_frame() {
        let (outcome, _) = run_preauth(DEADLINE, |io| async move {
            let mut ws = upgrade(io, "ws://localhost/").await;
            ws.send(authenticate()).await.ok();
            std::future::pending::<()>().await
        })
        .await;

        assert_eq!(expect_token(outcome).as_deref(), Some("abc"));
    }

    #[tokio::test]
    async fn sec005_send_gives_up_on_a_client_that_stops_reading() {
        let (server_io, client_io) = tokio::io::duplex(1024);
        let (server, client) = tokio::join!(
            async_tungstenite::accept_async(server_io.compat()),
            async_tungstenite::client_async("ws://localhost/", client_io.compat()),
        );
        let mut server = server.expect("server handshake");
        // Kept open and never read from
        let _client = client.expect("client handshake");

        let started = Instant::now();
        let sent = tokio::time::timeout(
            DEADLINE * 3,
            send_bounded(&mut server, Message::Binary(vec![0; 64 * 1024]), DEADLINE),
        )
        .await
        .expect("send outlived three times its limit");

        assert!(matches!(sent, Sent::TimedOut), "got {sent:?}");
        assert!(started.elapsed() < DEADLINE + SLACK);
    }

    #[test]
    fn sec005_liveness_starts_alive() {
        let now = Instant::now();
        let liveness = Liveness::new(now, IDLE_TIMEOUT);

        assert!(!liveness.is_expired(now));
        assert!(!liveness.is_expired(now + IDLE_TIMEOUT - Duration::from_secs(1)));
        assert_eq!(liveness.deadline(), now + IDLE_TIMEOUT);
    }

    #[test]
    fn sec005_liveness_inbound_frame_extends_it() {
        let now = Instant::now();
        let mut liveness = Liveness::new(now, IDLE_TIMEOUT);

        liveness.record_inbound(now + Duration::from_secs(100));
        assert!(!liveness.is_expired(now + Duration::from_secs(150)));
        assert!(liveness.is_expired(now + Duration::from_secs(220)));

        // An older timestamp never moves it back
        liveness.record_inbound(now);
        assert!(!liveness.is_expired(now + Duration::from_secs(150)));
    }

    #[test]
    fn sec005_liveness_expires_after_silence() {
        let now = Instant::now();
        let liveness = Liveness::new(now, IDLE_TIMEOUT);

        assert!(liveness.is_expired(now + IDLE_TIMEOUT));
        assert!(liveness.is_expired(now + IDLE_TIMEOUT + Duration::from_secs(1)));
    }

    /// Keep-alive timing the worker tests inject
    const TEST_KEEP_ALIVE: KeepAlive = KeepAlive {
        ping_interval: Duration::from_millis(100),
        idle_timeout: Duration::from_millis(300),
        send_timeout: Duration::from_millis(300),
    };

    /// An upgraded server and client over loopback TCP
    async fn tcp_pair() -> (
        WebSocketStream<Compat<TcpStream>>,
        WebSocketStream<Compat<TcpStream>>,
        SocketAddr,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("address");

        let (server, client) = tokio::join!(
            async {
                let (stream, _) = listener.accept().await.expect("accept");
                async_tungstenite::accept_async(stream.compat())
                    .await
                    .expect("server handshake")
            },
            async {
                let stream = TcpStream::connect(addr).await.expect("connect");
                async_tungstenite::client_async(format!("ws://{addr}/"), stream.compat())
                    .await
                    .expect("client handshake")
                    .0
            },
        );

        (server, client, addr)
    }

    /// Run the worker on `server` with `TEST_KEEP_ALIVE`; how long it ran,
    /// or `None` if it was still running after `limit`
    async fn run_worker(
        server: WebSocketStream<Compat<TcpStream>>,
        addr: SocketAddr,
        limit: Duration,
    ) -> Option<Duration> {
        run_worker_with(
            server,
            addr,
            limit,
            TEST_KEEP_ALIVE,
            HashSet::new(),
            Duration::ZERO,
        )
        .await
        .0
    }

    /// Run the worker on `server` with `keep_alive` and `subscribed`, the
    /// socket's write lock held elsewhere for its first `stall`; how long
    /// it ran (`None` if still running after `limit`), and what it
    /// signalled to the listener
    async fn run_worker_with(
        server: WebSocketStream<Compat<TcpStream>>,
        addr: SocketAddr,
        limit: Duration,
        keep_alive: KeepAlive,
        subscribed: HashSet<String>,
        stall: Duration,
    ) -> (Option<Duration>, async_channel::Receiver<ListenerSignal>) {
        let db: &'static Database = Box::leak(Box::new(
            DatabaseInfo::Reference.connect().await.expect("database"),
        ));
        let config = ProtocolConfiguration::from(
            1,
            ProtocolFormat::Json,
            None,
            ReadyPayloadFields::default(),
        );

        let (write, read) = server.split();
        let write = Mutex::new(write);
        let (topic_signal_s, topic_signal_r) = async_channel::bounded(LISTENER_SIGNAL_CAPACITY);
        // Held open: a dropped sender reads as the kill signal
        let (_kill_signal_s, kill_signal_r) = async_channel::bounded(1);

        let stalled = write.lock().await;
        let release = async move {
            tokio::time::sleep(stall).await;
            drop(stalled);
        };

        let started = Instant::now();
        let run = tokio::time::timeout(
            limit,
            worker(
                db,
                addr,
                Arc::new(RwLock::new(subscribed)),
                Arc::new(Mutex::new(ActiveServers::new(5, Duration::from_secs(900)))),
                "user".to_string(),
                "session".to_string(),
                &config,
                topic_signal_s,
                kill_signal_r,
                read,
                &write,
                keep_alive,
            ),
        );
        let (ran, ()) = tokio::join!(run, release);

        (ran.ok().map(|()| started.elapsed()), topic_signal_r)
    }

    #[tokio::test]
    async fn sec005_worker_drops_a_client_that_never_answers() {
        let (server, mut client, addr) = tcp_pair().await;

        let ran = run_worker(server, addr, TEST_KEEP_ALIVE.idle_timeout * 3)
            .await
            .expect("worker kept a silent client past three idle timeouts");
        assert!(ran >= TEST_KEEP_ALIVE.idle_timeout, "left after {ran:?}");

        // It pinged before giving up
        let first = tokio::time::timeout(Duration::from_secs(1), client.next())
            .await
            .expect("a frame in time")
            .expect("a frame")
            .expect("a readable frame");
        assert!(matches!(first, Message::Ping(_)), "got {first:?}");
    }

    #[tokio::test]
    async fn sec005_worker_keeps_a_client_that_answers_pings() {
        let (server, mut client, addr) = tcp_pair().await;

        // Reading is enough: tungstenite answers each Ping on the next read
        let pings = Arc::new(AtomicUsize::new(0));
        let counter = pings.clone();
        let reader = tokio::spawn(async move {
            while let Some(Ok(message)) = client.next().await {
                if let Message::Ping(_) = message {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            }
        });

        let ran = run_worker(server, addr, TEST_KEEP_ALIVE.idle_timeout * 3).await;
        reader.abort();

        assert!(ran.is_none(), "worker dropped a live client after {ran:?}");
        assert!(pings.load(Ordering::SeqCst) >= 3);
    }

    /// Frames that queued up while the worker was stalled must be handled,
    /// not lost to an idle timer that expired meanwhile. The first Ping's
    /// answer waits on the write lock past the idle timeout; the second
    /// Ping is then buffered while the timer is due, and only reading first
    /// answers it. A fair pick would pass all runs one time in 1024.
    #[tokio::test]
    async fn sec005_worker_buffered_frame_beats_idle_timer() {
        const RUNS: usize = 10;
        const FRAMES: usize = 2;
        let keep_alive = KeepAlive {
            ping_interval: Duration::from_secs(3600),
            idle_timeout: Duration::from_millis(50),
            send_timeout: Duration::from_secs(1),
        };

        for run in 0..RUNS {
            let (server, mut client, addr) = tcp_pair().await;

            for n in 0..FRAMES {
                client
                    .send(Message::Text(format!(r#"{{"type":"Ping","data":{n}}}"#)))
                    .await
                    .expect("client send");
            }
            // Let them land in the server's socket before the worker polls
            tokio::time::sleep(Duration::from_millis(50)).await;

            let (ran, _) = run_worker_with(
                server,
                addr,
                Duration::from_secs(2),
                keep_alive,
                HashSet::new(),
                keep_alive.idle_timeout * 3,
            )
            .await;
            assert!(ran.is_some(), "run {run}: worker outlived its idle timeout");

            let mut pongs = 0;
            while let Ok(Some(Ok(message))) =
                tokio::time::timeout(Duration::from_secs(1), client.next()).await
            {
                if let Message::Text(text) = message {
                    if text.contains(r#""type":"Pong""#) {
                        pongs += 1;
                    }
                }
            }
            assert_eq!(pongs, FRAMES, "run {run}: buffered Pings left unanswered");
        }
    }

    /// The worker publishes nothing itself: typing requests for subscribed
    /// ids go to the listener, which alone applies `typing_event`
    #[tokio::test]
    async fn sec105_worker_forwards_typing_to_the_listener() {
        let (server, mut client, addr) = tcp_pair().await;

        for frame in [
            format!(r#"{{"type":"BeginTyping","channel":"{TEXT_ID}"}}"#),
            format!(r#"{{"type":"EndTyping","channel":"{TEXT_ID}"}}"#),
            // Not subscribed at all: dropped before it queues
            format!(r#"{{"type":"BeginTyping","channel":"{THREAD_ID}"}}"#),
        ] {
            client
                .send(Message::Text(frame))
                .await
                .expect("client send");
        }

        let subscribed = [TEXT_ID.to_string()].into_iter().collect();
        let (ran, signals) = run_worker_with(
            server,
            addr,
            TEST_KEEP_ALIVE.idle_timeout * 3,
            TEST_KEEP_ALIVE,
            subscribed,
            Duration::ZERO,
        )
        .await;
        assert!(ran.is_some(), "worker outlived its idle timeout");

        let got: Vec<ListenerSignal> = std::iter::from_fn(|| signals.try_recv().ok()).collect();
        assert!(
            matches!(
                got.as_slice(),
                [
                    ListenerSignal::Typing { channel: a, begin: true },
                    ListenerSignal::Typing { channel: b, begin: false },
                ] if a == TEXT_ID && b == TEXT_ID
            ),
            "got {got:?}"
        );
    }

    const SELF_ID: &str = "01USER00000000000000000SLF";
    const FRIEND_ID: &str = "01USER00000000000000000FRD";
    const SERVER_ID: &str = "01SERVER000000000000000SRV";
    const TEXT_ID: &str = "01CHANNEL00000000000000TXT";
    const THREAD_ID: &str = "01CHANNEL00000000000000THR";

    /// A user with a cached text channel and a cached thread under it. The
    /// connection subscribes the text channel, the server, a friend and its
    /// own topics, but not the thread.
    fn typing_fixture() -> (State, HashSet<String>) {
        let user = User {
            id: SELF_ID.to_string(),
            username: "self".to_string(),
            ..Default::default()
        };
        let mut state = State::from(user, "session".to_string());

        state.cache.channels.insert(
            TEXT_ID.to_string(),
            Channel::TextChannel {
                id: TEXT_ID.to_string(),
                server: SERVER_ID.to_string(),
                name: "text".to_string(),
                description: None,
                icon: None,
                last_message_id: None,
                default_permissions: None,
                role_permissions: HashMap::new(),
                nsfw: false,
                spoiler: false,
                voice: None,
                slowmode: None,
                announcement: None,
            },
        );
        state.cache.channels.insert(
            THREAD_ID.to_string(),
            Channel::Thread {
                id: THREAD_ID.to_string(),
                server: SERVER_ID.to_string(),
                parent_channel: TEXT_ID.to_string(),
                name: "thread".to_string(),
                creator: FRIEND_ID.to_string(),
                origin_message_id: None,
                last_message_id: None,
                archived: false,
                archived_timestamp: None,
                auto_archive_minutes: Channel::default_auto_archive_minutes(),
                locked: false,
                applied_tags: vec![],
            },
        );

        let subscribed = [
            SELF_ID.to_string(),
            format!("{SELF_ID}!"),
            FRIEND_ID.to_string(),
            SERVER_ID.to_string(),
            format!("{SERVER_ID}u"),
            TEXT_ID.to_string(),
        ]
        .into_iter()
        .collect();

        (state, subscribed)
    }

    #[test]
    fn sec105_typing_allowed_in_a_subscribed_cached_channel() {
        let (state, subscribed) = typing_fixture();
        assert!(typing_allowed(&state, &subscribed, TEXT_ID));
    }

    #[test]
    fn sec105_typing_refused_for_a_friend_id() {
        let (state, subscribed) = typing_fixture();
        assert!(!typing_allowed(&state, &subscribed, FRIEND_ID));
    }

    #[test]
    fn sec105_typing_refused_for_a_server_id() {
        let (state, subscribed) = typing_fixture();
        assert!(!typing_allowed(&state, &subscribed, SERVER_ID));
    }

    #[test]
    fn sec105_typing_refused_for_own_and_member_topics() {
        let (state, subscribed) = typing_fixture();
        for topic in [
            SELF_ID.to_string(),
            format!("{SELF_ID}!"),
            format!("{SERVER_ID}u"),
        ] {
            assert!(!typing_allowed(&state, &subscribed, &topic), "{topic}");
        }
    }

    #[test]
    fn sec105_typing_refused_in_a_cached_thread_not_subscribed() {
        let (state, subscribed) = typing_fixture();
        assert!(!typing_allowed(&state, &subscribed, THREAD_ID));
    }

    #[test]
    fn sec105_typing_event_for_a_subscribed_cached_channel() {
        let (state, subscribed) = typing_fixture();

        let start = typing_event(&state, &subscribed, TEXT_ID, true);
        assert!(
            matches!(
                &start,
                Some(EventV1::ChannelStartTyping { id, user }) if id == TEXT_ID && user == SELF_ID
            ),
            "got {start:?}"
        );

        let stop = typing_event(&state, &subscribed, TEXT_ID, false);
        assert!(
            matches!(
                &stop,
                Some(EventV1::ChannelStopTyping { id, user }) if id == TEXT_ID && user == SELF_ID
            ),
            "got {stop:?}"
        );
    }

    #[test]
    fn sec105_typing_event_refused_outside_subscribed_cached_channels() {
        let (state, subscribed) = typing_fixture();
        for id in [FRIEND_ID, SERVER_ID, THREAD_ID] {
            for begin in [true, false] {
                let event = typing_event(&state, &subscribed, id, begin);
                assert!(event.is_none(), "{id} begin={begin}: got {event:?}");
            }
        }
    }
}
