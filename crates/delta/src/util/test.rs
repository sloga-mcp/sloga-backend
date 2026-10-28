use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use iso8601_timestamp::Timestamp;
use rand::Rng;
use redis_kiss::redis;
use revolt_database::util::email::normalise_email;
use revolt_database::util::password::hash_password;
use revolt_database::{
    events::client::EventV1, Channel, Database, Member, Message, PartialRole, Server, User, AMQP,
};
use revolt_database::{
    seat_list_channel_server, ChannelEntitlement, ChannelEntitlementSource,
    ChannelEntitlementState, E2EEIdentity, E2EESignedKey, EncryptedPayload, HandoverBody, MlsGroup,
    MlsGroupCreateOutcome, MlsGroupKind, MlsMemberDevice, SeatListBody, SeatListSubmission,
    SeatListWriteOutcome, CONTEXT_HANDOVER, E2EE_PROTOCOL_VERSION, E2EE_SIGN_CONTEXT_FALLBACK,
};
use revolt_database::{util::idempotency::IdempotencyKey, Role};
use revolt_database::{Account, EmailVerification, Session};
use revolt_models::v0;
use revolt_payments::stripe::MockStripe;
use revolt_permissions::OverrideField;
use rocket::http::Header;
use rocket::local::asynchronous::{Client, LocalRequest, LocalResponse};
use rocket::tokio;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ulid::Ulid;

use crate::routes::mls::text::text_group_id;

/// One process-lifetime runtime shared by every Redis-backed test.
///
/// `redis_kiss` pools connections in a GLOBAL mobc pool, but
/// `#[rocket::async_test]` builds a fresh tokio runtime per test, and a
/// pooled connection is registered with the I/O driver of whichever runtime
/// created it. With per-test runtimes that poisons the pool two ways:
///
///  * test A finishes, its runtime drops, and a connection it returned dies
///    in the pool — mobc's PING-on-checkout (on by default) catches this one;
///  * test B checks a connection out while A is still running (the PING
///    passes), then A's runtime drops MID-QUERY — the op fails with
///    `InternalError` from whatever Redis call was in flight, and no
///    checkout-time health check can catch it.
///
/// Driving every Redis-touching test on this one immortal runtime removes
/// both: pool connections are only ever registered to an I/O driver that
/// lives as long as the process. Mirrors the fix in the
/// `crates/core/database/src/voice/mod.rs` tests.
///
/// Usage — instead of `#[rocket::async_test] async fn name() { … }`:
///
/// ```ignore
/// #[test]
/// fn name() {
///     crate::util::test::rt().block_on(name_case())
/// }
///
/// async fn name_case() { … }
/// ```
pub fn rt() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    })
}

pub struct TestHarness {
    pub client: Client,
    pub db: Database,
    pub amqp: AMQP,
    /// The Stripe client the rocket manages (as `Arc<dyn StripeApi>`). Script
    /// responses and failures here and read back the calls a route made; the
    /// harness never reaches the network.
    pub stripe: Arc<MockStripe>,
    /// Connection string this harness resolved to, kept so `Drop` can
    /// reconnect and delete the throwaway database. `None` on the reference
    /// driver, which leaves nothing behind. Captured at construction because
    /// `Drop` cannot await `config()`.
    mongo_uri: Option<String>,
    events: Subscription<(String, EventV1)>,
    event_buffer: Vec<(String, EventV1)>,
}

/// How long the event pump's blocking read waits before it looks whether its
/// harness is gone.
const PUMP_POLL: Duration = Duration::from_millis(250);

/// How long a (re)subscription may wait for redis to confirm it. The
/// `PSUBSCRIBE` reply is read under this bound, not under `PUMP_POLL`: a
/// redis that stalls for longer than a poll (a BGSAVE fork, a slow script
/// from a voice test, a WSL stall) must not fail `TestHarness::new` (HD
/// re-audit HDA-1). A redis that accepts the connection and never answers
/// fails after this bound; a host that never accepts it still hangs in the
/// connect, as before.
const SUBSCRIBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Where a pump reports whether its first subscription landed.
type PumpReady = tokio::sync::oneshot::Sender<Result<(), String>>;

/// A live `PSUBSCRIBE`, pumped on a thread of its own: every message that
/// `forward` accepts, in the order redis sent it.
///
/// Why a blocking connection on a thread and not `redis::aio::PubSub`
/// (merge slice S6B-7, the "event pump ended (subscription dropped)" flake):
/// the async `PubSub::on_message()` of the redis version pinned here (0.23)
/// frames the socket with a NEW codec, so whatever the connection's own
/// decoder had already read past the `PSUBSCRIBE` reply is thrown away. On a
/// busy redis (a full delta run, every harness subscribed to `*`) that read
/// can end inside a message published right after the subscription landed.
/// The new codec then starts mid-frame and fails to parse, tokio-util's
/// `Framed` yields that error and ends the stream, and `on_message` filters
/// the error out, so all a harness ever saw was its stream ending, about
/// once per full run, on whichever test subscribed at the wrong moment. The
/// blocking `Connection` keeps ONE parser for the reply and every message
/// after it, so nothing read is discarded. A thread of its own also keeps
/// reading while its test blocks its runtime (argon2, the blocking SMTP
/// send).
struct Subscription<T> {
    items: tokio::sync::mpsc::UnboundedReceiver<T>,
    /// How many times the subscription ended and was taken out again. A
    /// message published in such a gap is lost for good.
    gaps: Arc<AtomicUsize>,
}

impl<T: Send + 'static> Subscription<T> {
    /// Subscribe to `pattern`, and return once redis has confirmed it, so
    /// every message published after this returns is delivered.
    async fn open(pattern: &str, forward: fn(&redis::Msg) -> Option<T>) -> Subscription<T> {
        let (items_tx, items) = tokio::sync::mpsc::unbounded_channel();
        let (ready_tx, ready) = tokio::sync::oneshot::channel();
        let gaps = Arc::new(AtomicUsize::new(0));
        let pump_gaps = gaps.clone();
        let pattern = pattern.to_string();
        std::thread::Builder::new()
            .name(format!("event pump {pattern}"))
            .spawn(move || pump(&pattern, forward, &items_tx, &pump_gaps, ready_tx))
            .expect("start the event pump thread");
        match ready.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => panic!("could not subscribe to redis: {}", error),
            Err(_) => panic!("the event pump thread died before it subscribed"),
        }
        Subscription { items, gaps }
    }

    fn gaps(&self) -> usize {
        self.gaps.load(Ordering::SeqCst)
    }
}

/// The body of a [`Subscription`]'s thread. Runs until the receiving side is
/// dropped. When the subscription ends (the connection closes, a reply does
/// not parse), it logs why, counts the gap and subscribes again. The log goes
/// to the test's captured output, which a passing test discards, so the
/// count is what makes a gap loud: the harness fails the wait that spans it
/// and, when dropped, any test that had one (HD re-audit HDA-2).
fn pump<T>(
    pattern: &str,
    forward: fn(&redis::Msg) -> Option<T>,
    items: &tokio::sync::mpsc::UnboundedSender<T>,
    gaps: &AtomicUsize,
    ready: PumpReady,
) {
    let mut ready = Some(ready);
    loop {
        let mut connection = match redis::Client::open(redis_kiss::REDIS_URI.as_str())
            .and_then(|client| client.get_connection())
        {
            Ok(connection) => connection,
            Err(error) => {
                if retry_subscribing(error, &mut ready, items, pattern) {
                    continue;
                }
                return;
            }
        };
        let mut pubsub = connection.as_pubsub();
        // The poll timeout is set only once the subscription is confirmed:
        // the reply itself gets `SUBSCRIBE_TIMEOUT` (HDA-1).
        if let Err(error) = pubsub
            .set_read_timeout(Some(SUBSCRIBE_TIMEOUT))
            .and_then(|()| pubsub.psubscribe(pattern))
            .and_then(|()| pubsub.set_read_timeout(Some(PUMP_POLL)))
        {
            if retry_subscribing(error, &mut ready, items, pattern) {
                continue;
            }
            return;
        }
        match ready.take() {
            Some(ready) => {
                if ready.send(Ok(())).is_err() {
                    return;
                }
            }
            None => eprintln!("event pump ({pattern}): subscribed again"),
        }

        let error = loop {
            match pubsub.get_message() {
                Ok(message) => {
                    // Checked on every message, not only when idle: a busy
                    // redis (another test's flood, every harness subscribed
                    // to `*`) may never let the read time out, and messages
                    // `forward` drops never fail a send (HDA-3).
                    if items.is_closed() {
                        return;
                    }
                    if let Some(item) = forward(&message) {
                        if items.send(item).is_err() {
                            return;
                        }
                    }
                }
                // The read timeout is how the thread notices its harness is gone.
                Err(error) if error.is_timeout() => {
                    if items.is_closed() {
                        return;
                    }
                }
                Err(error) => break error,
            }
        };
        gaps.fetch_add(1, Ordering::SeqCst);
        eprintln!(
            "event pump ({pattern}): the subscription ended ({:?}: {error}); subscribing \
             again, and anything published until then is lost",
            error.kind()
        );
    }
}

/// After a failed (re)subscription: whether the pump tries again. The first
/// subscription's failure goes to `open`, which fails loudly; after that it
/// retries for as long as its harness lives.
fn retry_subscribing<T>(
    error: redis::RedisError,
    ready: &mut Option<PumpReady>,
    items: &tokio::sync::mpsc::UnboundedSender<T>,
    pattern: &str,
) -> bool {
    if let Some(ready) = ready.take() {
        let _ = ready.send(Err(error.to_string()));
        return false;
    }
    if items.is_closed() {
        return false;
    }
    eprintln!("event pump ({pattern}): could not subscribe again: {error}; retrying");
    std::thread::sleep(PUMP_POLL);
    true
}

impl TestHarness {
    /// Database name used by production. The harness must never touch it.
    const PRODUCTION_DATABASE: &'static str = "revolt";

    pub async fn new() -> TestHarness {
        // `web()` builds its database through `DatabaseInfo::Auto`, which only
        // routes to a throwaway `revolt_test_*` database when `TEST_DB` is set.
        // With the variable unset it silently falls through to the configured
        // production MongoDB instead — a plain `cargo test -p revolt-delta`
        // then writes accounts, users, sessions and servers straight into live
        // data (this is exactly how ~41 test accounts and 77 test servers ended
        // up in production). Fail loudly instead of polluting prod.
        assert!(
            std::env::var("TEST_DB").is_ok(),
            "`TEST_DB` is not set — refusing to run: `DatabaseInfo::Auto` would \
             connect this harness to the PRODUCTION database. Set \
             `TEST_DB=REFERENCE` (mock) or `TEST_DB=MONGODB` (throwaway db)."
        );

        let stripe = Arc::new(MockStripe::new());
        let client = Client::tracked(crate::web_with_stripe(stripe.clone()).await)
            .await
            .expect("valid rocket instance");

        // Pump the subscription from construction time. The previous
        // per-`wait_for_event`-call `on_message()` stream lost events that
        // fanned while no stream was polling — an event published BEFORE
        // the first wait (or between two waits) never surfaced even though
        // redis delivered it (verified with an external subscriber), which
        // turned event assertions into permanent hangs. The pump owns the
        // connection for the harness's lifetime and forwards every
        // decodable event in order; `wait_for_event` reads the channel.
        // `open` returns once the subscription is confirmed, so every event
        // the test causes from here on is delivered.
        let events = Subscription::open("*", |message| {
            // The wildcard psubscribe sees EVERY topic on a shared redis;
            // skip payloads that are not EventV1 (e.g. LiveKit keepalives)
            // silently — a genuinely missing target event surfaces as a
            // wait_for_event TIMEOUT, not a hang.
            let payload = redis_kiss::decode_payload::<EventV1>(message).ok()?;
            Some((message.get_channel_name().to_string(), payload))
        })
        .await;

        let db = client
            .rocket()
            .state::<Database>()
            .expect("`Database`")
            .clone();

        // Belt-and-braces: check the database we actually resolved to, not just
        // the environment variable. A stray `TEST_DB` value or a config
        // override could still land the harness on live data.
        if let Database::MongoDb(mongo) = &db {
            assert_ne!(
                mongo.1,
                Self::PRODUCTION_DATABASE,
                "refusing to run: harness resolved to the PRODUCTION database. \
                 Expected a throwaway `revolt_test_*` database."
            );
        }

        // Read the URI now so `Drop` can reconnect without awaiting. This is
        // the same value `DatabaseInfo::MongoDb` connected with above.
        let mongo_uri = match &db {
            Database::MongoDb(_) => Some(revolt_config::config().await.database.mongodb),
            _ => None,
        };

        let amqp = AMQP::new_auto().await;

        TestHarness {
            client,
            db,
            amqp,
            stripe,
            mongo_uri,
            events,
            event_buffer: vec![],
        }
    }

    pub fn rand_string() -> String {
        // Consonants only. These strings become usernames, and User::create
        // runs them through the name filter, which matches folded LETTER
        // sequences — digits unleet onto letters (0→o, 1→i, 3→e, 4→a, …), so
        // a random alphanumeric name occasionally spells a blocked substring
        // and the harness dies with InvalidUsername. Every term in the
        // blocklists contains a vowel; a vowel-free name can never match.
        const SAFE: &[u8] = b"bcdfghjkmnpqrstvwxz";
        let mut rng = rand::thread_rng();
        (0..20)
            .map(|_| SAFE[rng.gen_range(0..SAFE.len())] as char)
            .collect()
    }

    pub async fn new_user(&self) -> (Account, Session, User) {
        let user = User::create(&self.db, TestHarness::rand_string(), None, None)
            .await
            .expect("`User`");

        let (account, session) = self.account_from_user(user.id.clone()).await;

        (account, session, user)
    }

    pub async fn account_from_user(&self, id: String) -> (Account, Session) {
        let email = format!("{}@stoat.chat", TestHarness::rand_string());
        let account = Account {
            id,
            email: email.clone(),
            password: hash_password("password_insecure".to_string()).unwrap(),
            email_normalised: normalise_email(email),
            deletion: None,
            disabled: false,
            lockout: None,
            mfa: Default::default(),
            password_reset: None,
            verification: EmailVerification::Verified,
            google_id: None,
            apple_id: None,
        };

        self.db.save_account(&account).await.expect("`Account`");

        let session = account
            .create_session(&self.db, String::new())
            .await
            .expect("`Session`");

        (account, session)
    }

    pub async fn new_server(&self, user: &User) -> (Server, Vec<Channel>) {
        Server::create(
            &self.db,
            v0::DataCreateServer {
                name: "Test Server".to_string(),
                ..Default::default()
            },
            user,
            true,
        )
        .await
        .expect("Failed to create test server")
    }

    pub async fn new_role(
        &self,
        server: &Server,
        rank: i64,
        overrides: Option<OverrideField>,
    ) -> Role {
        let mut role = Role::create(&self.db, &server, TestHarness::rand_string())
            .await
            .expect("Failed to create test role");

        if let Some(overrides) = overrides {
            role.update(
                &self.db,
                &server.id,
                PartialRole {
                    permissions: Some(overrides),
                    ..Default::default()
                },
                Vec::new(),
            )
            .await
            .expect("Failed to set test role overrides");
        };

        role
    }

    pub async fn new_channel(&self, server: &Server) -> Channel {
        Channel::create_server_channel(
            &self.db,
            &mut server.clone(),
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Text,
                name: "Test Channel".to_string(),
                description: None,
                nsfw: Some(false),
                spoiler: None,
                voice: None,
                announcement: None,
                ..Default::default()
            },
            true,
        )
        .await
        .expect("Failed to make test channel")
    }

    pub async fn new_message(
        &self,
        user: &User,
        server: &Server,
        channels: Vec<Channel>,
    ) -> (Channel, Member, Message) {
        let (member, channels) = Member::create(&self.db, server, user, Some(channels))
            .await
            .expect("Failed to create member");
        let channel = &channels[0];
        let message = Message::create_from_api(
            &self.db,
            None,
            channel.clone(),
            v0::DataMessageSend {
                content: Some("Test message".to_string()),
                nonce: None,
                attachments: None,
                replies: None,
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                encrypted: None,
                flags: None,
            },
            v0::MessageAuthor::User(&user.clone().into(&self.db, Some(user)).await),
            Some(user.clone().into(&self.db, Some(user)).await),
            Some(member.clone().into()),
            user.limits().await,
            IdempotencyKey::unchecked_from_string("0".to_string()),
            false,
            false,
        )
        .await
        .expect("Failed to create message");
        (channel.clone(), member, message)
    }

    pub async fn with_session(session: Session, request: LocalRequest<'_>) -> LocalResponse<'_> {
        request
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await
    }

    pub async fn wait_for_event<F>(&mut self, topic: &str, predicate: F) -> EventV1
    where
        F: Fn(&EventV1) -> bool,
    {
        for (msg_topic, event) in &self.event_buffer {
            if topic == msg_topic && predicate(event) {
                // does not remove from buffer
                return event.clone();
            }
        }

        // Events arrive via the construction-time pump (see `new`), so
        // anything fanned since harness creation is observable here even
        // if it fired before this call. Bounded: a missing event fails the
        // test in 30s instead of hanging the whole suite.
        //
        // A subscription that ends is taken out again by the pump (see
        // `pump`), and an event published in that gap is lost. A later
        // event that the predicate also accepts would then pass this wait
        // in place of the lost one, so a gap that opens while this waits
        // fails it, checked at least every `PUMP_POLL` (HD re-audit HDA-2).
        let gaps_before = self.events.gaps();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let poll = deadline.min(tokio::time::Instant::now() + PUMP_POLL);
            let received = tokio::time::timeout_at(poll, self.events.items.recv()).await;
            let gaps = self.events.gaps();
            assert!(
                gaps == gaps_before,
                "wait_for_event: the event subscription ended and was taken out again \
                 while this waited for an event on '{}' ({} gap(s)): an event published \
                 in the gap was lost, and a later match must not stand in for it",
                topic,
                gaps - gaps_before
            );
            let received = match received {
                Ok(received) => received,
                Err(_) if tokio::time::Instant::now() < deadline => continue,
                Err(_) => panic!(
                    "wait_for_event: no event matching predicate on '{topic}' within 30s \
                     (buffered: {} events; subscription gaps: {})",
                    self.event_buffer.len(),
                    gaps
                ),
            };
            let Some((msg_topic, payload)) = received else {
                // The pump returns only once this receiver is gone, so a
                // closed channel means its thread panicked (see stderr).
                panic!("wait_for_event: the event pump thread is gone");
            };

            if topic == msg_topic && predicate(&payload) {
                return payload;
            }

            self.event_buffer.push((msg_topic, payload));
        }
    }

    /// Assert that no already-buffered event on `topic` matches the
    /// predicate. Only events pulled off the wire by earlier
    /// `wait_for_event` calls are visible here — to prove a NEGATIVE
    /// ("nothing leaked to this topic"), publish a later marker event and
    /// `wait_for_event` on it first: redis pub/sub is FIFO per
    /// subscription, so anything published before the marker is guaranteed
    /// to be in the buffer by the time the marker is observed.
    ///
    /// FIFO holds only within ONE subscription. If the pump ever had to
    /// subscribe again, an event published in the gap was never received,
    /// so the negative cannot be proven and this fails.
    pub fn assert_no_buffered_event<F>(&self, topic: &str, predicate: F)
    where
        F: Fn(&EventV1) -> bool,
    {
        for (msg_topic, event) in &self.event_buffer {
            // Explicit arguments: this crate is edition 2018, where a lone
            // literal message is printed as it is, braces and all.
            assert!(
                !(topic == msg_topic && predicate(event)),
                "unexpected event on '{}': {:?}",
                topic,
                event
            );
        }
        assert_eq!(
            self.events.gaps(),
            0,
            "cannot prove that no event on '{}' matched: the event subscription \
             ended and was taken out again, and an event published in that gap was \
             never received",
            topic
        );
    }

    /// Read the mail delta just sent to `mailbox` out of maildev, and pull the
    /// `[[CODE]]` token out of its body.
    ///
    /// Requires `[api.smtp]` to point at the maildev container from
    /// `compose.yml` (host `localhost`, port 14025, no TLS, user/pass
    /// `smtp`/`smtp` — maildev runs with `MAILDEV_INCOMING_USER`/`_PASS` set,
    /// so an unauthenticated transport is rejected at SMTP time).
    ///
    /// LANDMINE: maildev 3.x moved the REST API under `/api`
    /// (`GET /api/email`, `DELETE /api/email/:id`). maildev 1.x/2.x served
    /// bare `/email` and `/delete/:id`, which is what this used to call —
    /// `compose.yml` pins the floating `maildev/maildev` tag, so the image
    /// silently rolled forward and every path started 404ing. The mail was
    /// being delivered fine the whole time; only these two URLs were wrong.
    /// If this starts failing again, curl `http://localhost:14080/api/healthz`
    /// and re-check the route table before suspecting the send path.
    pub async fn assert_email(&self, mailbox: &str) -> (Mail, String) {
        const MAILDEV_API: &str = "http://localhost:14080/api";

        let client = reqwest::Client::new();
        let re = regex::Regex::new(r"\[\[([A-Za-z0-9_-]*)\]\]").unwrap();

        // Poll instead of sleeping a flat second. Delivery is normally well
        // under 100ms, but the send is a *blocking* lettre call and the suite
        // runs many test processes at once, so a fixed wait is a coin flip on
        // a loaded machine.
        let deadline = Instant::now() + Duration::from_secs(15);

        loop {
            let results = client
                .get(format!("{MAILDEV_API}/email"))
                .send()
                .await
                .expect("maildev unreachable on :14080 — is `stoatchat-maildev-1` running?")
                .json::<Vec<Mail>>()
                .await
                .expect("maildev did not return `Vec<Mail>` — did the API shape change?");

            // Every mail addressed to this mailbox, newest first. Mailboxes are
            // unique per test, so anything else sitting here is a leftover from
            // an earlier run — maildev persists mail across runs, and until the
            // URLs above were fixed nothing was ever deleted. Take the newest
            // and delete the whole set so the next run starts clean.
            let mut matches = results
                .into_iter()
                .filter(|entry| entry.envelope.to.iter().any(|to| to.address == mailbox))
                .collect::<Vec<_>>();

            matches.sort_by(|a, b| b.time.cmp(&a.time));

            if !matches.is_empty() {
                for entry in &matches {
                    client
                        .delete(format!("{MAILDEV_API}/email/{}", &entry.id))
                        .send()
                        .await
                        .unwrap();
                }

                let entry = matches.swap_remove(0);
                let code = re
                    .captures_iter(&entry.text)
                    .next()
                    .unwrap_or_else(|| {
                        panic!("no `[[CODE]]` token in mail to {mailbox}: {:?}", entry.text)
                    })[1]
                    .to_string();

                return (entry, code);
            }

            if Instant::now() >= deadline {
                // Only now read the config, to explain the timeout rather
                // than to predict it (HD re-audit HDA-9): read up front it
                // could fail a send that had already happened with SMTP on,
                // once `config()`'s 30 s cache turned over.
                //
                // A config overwrite is process-wide:
                // `revolt_config::overwrite_config` sets a `OnceLock`, and
                // `change_email`'s tests overwrite `api.smtp.host` with "".
                // Under a plain `cargo test`, where every test shares one
                // process, SMTP can be off for every test that reads the
                // config after one of them overwrote it, and the send is
                // skipped (the reset route swallows the `OperationFailed`)
                // (merge slice S6B-7, the mailbox flake).
                let smtp_host = revolt_config::config().await.api.smtp.host;
                if smtp_host.is_empty() {
                    panic!(
                        "no email delivered to {} within 15s, and SMTP is off in this \
                         process now (`api.smtp.host` is empty), so it was likely never \
                         sent. Either this environment has no SMTP host configured, or a \
                         test's `overwrite_config` turned it off (a config overwrite is \
                         process-wide; nextest runs one process per test)",
                        mailbox
                    );
                }
                panic!(
                    "no email delivered to {} within 15s (SMTP host `{}`)",
                    mailbox, smtp_host
                );
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn wait_for_message(&mut self, channel_id: &str) -> v0::Message {
        dbg!(&self.event_buffer);

        match self
            .wait_for_event(channel_id, |event| match event {
                EventV1::Message(v0::Message { channel, .. }) => channel == channel_id,
                _ => false,
            })
            .await
        {
            EventV1::Message(message) => message,
            _ => unreachable!(),
        }
    }
}

impl Drop for TestHarness {
    /// Delete the throwaway database this harness created.
    ///
    /// `DatabaseInfo::Auto` mints a fresh `revolt_test_<n>` per harness and
    /// nothing ever removed them, so they accumulated across every run. At
    /// 1191 leftovers (observed 2026-07-27) mongod was slow enough that
    /// harness boot alone blew nextest's 50s kill threshold and the whole
    /// delta suite failed at once, looking exactly like a mass code
    /// regression.
    ///
    /// `Drop` rather than a `harness.teardown().await` call at the end of each
    /// test: a failing assertion unwinds, so an explicit call would be skipped
    /// by precisely the runs whose databases most need collecting — and it
    /// would have to be added to, and never forgotten by, every test.
    ///
    /// Not a complete fix on its own. nextest SIGKILLs a test that overruns
    /// `terminate-after`, and a killed process runs no destructors, so a
    /// timing-out test still leaks. `scripts/drop-test-databases.sh` sweeps
    /// whatever survives.
    ///
    /// Then, unless the test is already failing, it fails a test whose event
    /// subscription had a gap (HD re-audit HDA-2): an event published in it
    /// was lost, and nothing else would say so for a test that passed.
    fn drop(&mut self) {
        self.drop_test_database();

        if !std::thread::panicking() {
            assert_eq!(
                self.events.gaps(),
                0,
                "the harness's event subscription ended and was taken out again during \
                 this test (see the pump's lines in its output): an event published in \
                 that gap was lost"
            );
        }
    }
}

impl TestHarness {
    /// The database half of `Drop`, see there.
    fn drop_test_database(&self) {
        let Database::MongoDb(mongo) = &self.db else {
            return;
        };

        let Some(uri) = &self.mongo_uri else {
            return;
        };

        // Same invariant as `new()`: never, under any circumstances, drop
        // production. `drop_test_database_blocking` re-checks this against its
        // own allow-list, but the guard belongs at the call site too.
        if mongo.1 == Self::PRODUCTION_DATABASE {
            return;
        }

        revolt_database::test_teardown::drop_test_database_blocking(uri, &mongo.1);
    }
}

// ---------------------------------------------------------------------------
// Protected-channel fixtures (W2)
//
// Built through the database primitives, which verify no signature and run
// none of the route checks, so a route test starts from a known state and
// exercises its own route only. Keys, seat lists and handovers are
// deterministic (Ed25519 signing is), so a test can rebuild a byte-identical
// list for a retry; ids are fresh on every call.
// ---------------------------------------------------------------------------

/// Key seed of the design 5.1 owner device (seed bytes `00 01 .. 1f`)
pub const OWNER_DEVICE_SEED: u8 = 0x00;

/// Key seed of the design 5.1 member device (seed bytes `20 21 .. 3f`)
pub const MEMBER_DEVICE_SEED: u8 = 0x20;

/// Key seed of the design 5.1 new owner device (seed bytes `80 81 .. 9f`)
pub const NEW_OWNER_DEVICE_SEED: u8 = 0x80;

/// `issued_at` of every fixture seat list and handover (the design 5.1 value)
pub const FIXTURE_ISSUED_AT: i64 = 1_790_812_800_000;

/// Slot cap of the entitlement [`TestHarness::new_protected_channel`] grants
pub const FIXTURE_SLOT_CAP: u32 = 10;

/// `device_cap` of the list [`TestHarness::new_protected_channel`] signs: the
/// configured default entitlement cap, so the route's 4.3 step 6 accepts it
pub const FIXTURE_DEVICE_CAP: u32 = 5;

fn fixture_b64(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

/// An E2EE device with a known Ed25519 identity key, which signs seat lists,
/// handovers and payloads the way a client device does
pub struct TestE2EEDevice {
    pub user_id: String,
    pub device_id: String,
    pub signing_key: SigningKey,
    /// Its directory row (stored by [`TestHarness::new_e2ee_device`])
    pub identity: E2EEIdentity,
}

impl TestE2EEDevice {
    /// The Ed25519 key whose 32 seed bytes are `seed, seed + 1, ..` (wrapping)
    pub fn signing_key_for(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&std::array::from_fn(|i| seed.wrapping_add(i as u8)))
    }

    /// A device of `user_id` with the key for `seed` and a directory row that
    /// verifies, bound to `session_id`; nothing is stored
    pub fn new(user_id: &str, device_id: &str, seed: u8, session_id: &str) -> TestE2EEDevice {
        let signing_key = Self::signing_key_for(seed);
        let ed25519_key = fixture_b64(signing_key.verifying_key().as_bytes());
        let curve25519_key = fixture_b64(&Sha256::digest(format!("curve25519:{ed25519_key}")));
        let fallback_key = fixture_b64(&Sha256::digest(format!("fallback0:{ed25519_key}")));
        // The database's (private) signed-key payload, as
        // `routes::e2ee::tests::TestDevice` builds it
        let fallback_payload = format!(
            "{E2EE_SIGN_CONTEXT_FALLBACK}\nprotocol_version:{E2EE_PROTOCOL_VERSION}\ndevice_id:{device_id}\nkey_id:fallback0\nkey:{fallback_key}"
        );
        let identity_payload = E2EEIdentity::signed_payload(
            E2EE_PROTOCOL_VERSION,
            device_id,
            &ed25519_key,
            &curve25519_key,
        );
        let now = Timestamp::now_utc();

        let identity = E2EEIdentity {
            id: E2EEIdentity::composite_id(user_id, device_id),
            user_id: user_id.to_string(),
            device_id: device_id.to_string(),
            protocol_version: E2EE_PROTOCOL_VERSION,
            ed25519_key,
            curve25519_key,
            signature: fixture_b64(&signing_key.sign(identity_payload.as_bytes()).to_bytes()),
            fallback_key: E2EESignedKey {
                key_id: "fallback0".to_string(),
                key: fallback_key,
                signature: fixture_b64(&signing_key.sign(fallback_payload.as_bytes()).to_bytes()),
            },
            previous_fallback_key: None,
            created_at: now,
            last_seen_at: now,
            last_session_id: session_id.to_string(),
        };

        TestE2EEDevice {
            user_id: user_id.to_string(),
            device_id: device_id.to_string(),
            signing_key,
            identity,
        }
    }

    /// b64 of the Ed25519 public key (the directory `ed25519_key`)
    pub fn identity_key(&self) -> String {
        self.identity.ed25519_key.clone()
    }

    /// The b64 Ed25519 signature of `payload` by this device
    pub fn sign(&self, payload: &str) -> String {
        fixture_b64(&self.signing_key.sign(payload.as_bytes()).to_bytes())
    }

    /// A seat list signed by this device (design 4.1, 4.2), no handover: the
    /// builder sorts and de-duplicates `seats`, which must include this
    /// device's user
    pub fn seat_list(
        &self,
        channel_id: &str,
        version: i64,
        device_cap: u32,
        seats: &[impl AsRef<str>],
    ) -> v0::DataSeatList {
        let body = SeatListBody {
            channel_id: channel_id.to_string(),
            version,
            device_cap,
            issued_at: FIXTURE_ISSUED_AT,
            signer_user_id: self.user_id.clone(),
            signer_device_id: self.device_id.clone(),
            seats: seats.iter().map(|seat| seat.as_ref().to_string()).collect(),
        }
        .build()
        .expect("a canonical seat list body");

        v0::DataSeatList {
            signature: self.sign(&body),
            body,
            signer_device_id: self.device_id.clone(),
            handover: None,
        }
    }

    /// The protect request: this device's genesis (`version: 1`) seat list
    pub fn protect_request(
        &self,
        channel_id: &str,
        device_cap: u32,
        seats: &[impl AsRef<str>],
    ) -> v0::DataProtectChannel {
        v0::DataProtectChannel {
            seat_list: self.seat_list(channel_id, 1, device_cap, seats),
        }
    }

    /// A handover statement (design 4.6) from this device to `to`, signed by
    /// this device, for a later list's `handover`
    pub fn handover_to(&self, channel_id: &str, to: &TestE2EEDevice) -> v0::SignedHandover {
        let body = format!(
            "{CONTEXT_HANDOVER}\nv:1\nchannel_id:{channel_id}\nfrom_user_id:{}\nfrom_device_id:{}\nfrom_identity_key:{}\nto_user_id:{}\nto_device_id:{}\nto_identity_key:{}\nissued_at:{FIXTURE_ISSUED_AT}",
            self.user_id,
            self.device_id,
            self.identity.ed25519_key,
            to.user_id,
            to.device_id,
            to.identity.ed25519_key
        );
        HandoverBody::parse(&body).expect("a canonical handover body");

        v0::SignedHandover {
            signature: self.sign(&body),
            body,
        }
    }

    /// A structurally valid payload (design 2.6) from this device into
    /// `group` at its current epoch. The AEAD nonce and ciphertext are random
    /// and `sig` is filler: the server never decrypts or verifies them.
    pub fn encrypted_payload(&self, group: &MlsGroup) -> v0::EncryptedPayload {
        let mut rng = rand::thread_rng();
        let mut nonce = [0u8; EncryptedPayload::NONCE_BYTES];
        let mut ciphertext = [0u8; 48];
        let mut sig = [0u8; EncryptedPayload::SIG_BYTES];
        rng.fill(&mut nonce[..]);
        rng.fill(&mut ciphertext[..]);
        rng.fill(&mut sig[..]);

        v0::EncryptedPayload {
            v: EncryptedPayload::VERSION,
            group_id: group.id.clone(),
            epoch: group.current_epoch,
            sender_device_id: self.device_id.clone(),
            nonce: fixture_b64(&nonce),
            ciphertext: fixture_b64(&ciphertext),
            sig: fixture_b64(&sig),
            franking: None,
        }
    }
}

/// What [`TestHarness::new_protected_channel`] built
pub struct ProtectedChannel {
    /// The server, owned by the owner
    pub server: Server,
    /// The channel, re-read after protect (`protected: true`)
    pub channel: Channel,
    /// Its Active entitlement
    pub entitlement: ChannelEntitlement,
    /// The owner's device that signed the genesis list, bound to the owner's
    /// session
    pub owner_device: TestE2EEDevice,
    /// The stored genesis seat list
    pub seat_list: v0::DataSeatList,
}

impl TestHarness {
    /// A server owned by `owner`, the owner's membership (as `server_create`
    /// leaves it) and a fresh unprotected TextChannel; the server is re-read,
    /// so its `channels` lists that channel
    pub async fn new_protectable_channel(&self, owner: &User) -> (Server, Channel) {
        let (server, _) = self.new_server(owner).await;
        self.join_server(&server, owner).await;
        let channel = self.new_channel(&server).await;
        let server = self.db.fetch_server(&server.id).await.expect("`Server`");
        (server, channel)
    }

    /// `user`'s membership of `server`, through `Member::create`
    pub async fn join_server(&self, server: &Server, user: &User) -> Member {
        Member::create(&self.db, server, user, None)
            .await
            .expect("Failed to join test server")
            .0
    }

    /// An Active admin-grant entitlement on `channel` (a server TextChannel),
    /// through the database primitive
    pub async fn grant_entitlement(
        &self,
        channel: &Channel,
        slot_cap: u32,
        device_cap: Option<u32>,
    ) -> ChannelEntitlement {
        let server_id = seat_list_channel_server(channel).expect("a server TextChannel");
        let now = Timestamp::now_utc();
        self.db
            .upsert_channel_entitlement(
                &ChannelEntitlement {
                    id: Ulid::new().to_string(),
                    channel_id: channel.id().to_string(),
                    server_id: server_id.to_string(),
                    source: ChannelEntitlementSource::AdminGrant,
                    slot_cap,
                    device_cap,
                    state: ChannelEntitlementState::Active,
                    granted_by: Ulid::new().to_string(),
                    created_at: now,
                },
                now,
            )
            .await
            .expect("`ChannelEntitlement`")
    }

    /// Register a device of `user` with the key for `seed` (its device id is
    /// derived from the key), bound to `session_id`: pass the harness
    /// session's `id` to bind it, any other value for an unbound device
    pub async fn new_e2ee_device(&self, user: &User, session_id: &str, seed: u8) -> TestE2EEDevice {
        let key = TestE2EEDevice::signing_key_for(seed);
        let device_id: String = key.verifying_key().as_bytes()[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let device = TestE2EEDevice::new(&user.id, &device_id, seed, session_id);
        device
            .identity
            .verify()
            .expect("a valid directory identity");
        self.db
            .insert_e2ee_identity(&device.identity)
            .await
            .expect("`E2EEIdentity`");
        device
    }

    /// Protect `channel` with `data`'s genesis list through the database
    /// primitive (no signature or route check)
    pub async fn protect_with_db(
        &self,
        channel: &Channel,
        data: &v0::DataProtectChannel,
    ) -> SeatListWriteOutcome {
        self.db
            .protect_channel(
                channel.id(),
                &SeatListSubmission::from(data.seat_list.clone()),
                Timestamp::now_utc(),
            )
            .await
            .expect("Failed to protect test channel")
    }

    /// Store `data` as `channel`'s next seat list through the database
    /// primitive, claims allowed (no signature or route check)
    pub async fn put_seats_with_db(
        &self,
        channel: &Channel,
        data: &v0::DataSeatList,
    ) -> SeatListWriteOutcome {
        self.db
            .put_seat_list(
                channel.id(),
                &SeatListSubmission::from(data.clone()),
                true,
                Timestamp::now_utc(),
            )
            .await
            .expect("Failed to store test seat list")
    }

    /// End to end: [`Self::new_protectable_channel`], an entitlement
    /// ([`FIXTURE_SLOT_CAP`], default device cap), the owner's
    /// [`OWNER_DEVICE_SEED`] device bound to `owner_session`, `members` (not
    /// the owner) joined, then protected through the database with a genesis
    /// list ([`FIXTURE_DEVICE_CAP`]) seating the owner and `members`
    pub async fn new_protected_channel(
        &self,
        owner: &User,
        owner_session: &Session,
        members: &[&User],
    ) -> ProtectedChannel {
        let (server, channel) = self.new_protectable_channel(owner).await;
        let entitlement = self
            .grant_entitlement(&channel, FIXTURE_SLOT_CAP, None)
            .await;
        let owner_device = self
            .new_e2ee_device(owner, &owner_session.id, OWNER_DEVICE_SEED)
            .await;

        let mut seats = vec![owner.id.clone()];
        for member in members {
            self.join_server(&server, member).await;
            seats.push(member.id.clone());
        }

        let protect = owner_device.protect_request(channel.id(), FIXTURE_DEVICE_CAP, &seats);
        self.protect_with_db(&channel, &protect).await;
        let channel = self
            .db
            .fetch_channel(channel.id())
            .await
            .expect("the protected channel");

        ProtectedChannel {
            server,
            channel,
            entitlement,
            owner_device,
            seat_list: protect.seat_list,
        }
    }

    /// `channel`'s Text group `text_group_id(channel, generation)`, created
    /// by `creator` (the current list signer's device) through the database
    /// primitive; `supersedes` names the group it succeeds (generation - 1).
    /// Returns the stored group (members: the creator only, epoch 0).
    pub async fn new_text_group(
        &self,
        channel: &Channel,
        creator: &TestE2EEDevice,
        generation: u32,
        supersedes: Option<&str>,
    ) -> MlsGroup {
        let creator = MlsMemberDevice {
            user_id: creator.user_id.clone(),
            device_id: creator.device_id.clone(),
        };
        let group = MlsGroup {
            id: text_group_id(channel.id(), generation),
            channel_id: channel.id().to_string(),
            open: true,
            created_by: creator.clone(),
            created_at: Timestamp::now_utc(),
            current_epoch: 0,
            members: vec![creator],
            closed_at: None,
            superseded_by: None,
            kind: MlsGroupKind::Text,
            generation: Some(generation),
            seat_list_ad_sha256: None,
            pending_removals: vec![],
            member_added: vec![],
        };

        match self
            .db
            .create_text_mls_group(&group, supersedes)
            .await
            .expect("Failed to create test text group")
        {
            MlsGroupCreateOutcome::Created => {}
            other => panic!("test text group not created: {:?}", other),
        }

        self.db
            .fetch_mls_group(&group.id)
            .await
            .expect("the stored text group")
    }

    /// An encrypted message from `sender` into `channel` under `group`
    /// ([`TestE2EEDevice::encrypted_payload`], a fresh id and client message
    /// id), stored through `insert_message`
    pub async fn new_encrypted_message(
        &self,
        channel: &Channel,
        sender: &TestE2EEDevice,
        group: &MlsGroup,
    ) -> Message {
        let message = Message {
            id: Ulid::new().to_string(),
            channel: channel.id().to_string(),
            author: sender.user_id.clone(),
            nonce: Some(Ulid::new().to_string()),
            encrypted: Some(sender.encrypted_payload(group).into()),
            ..Default::default()
        };
        self.db
            .insert_message(&message)
            .await
            .expect("Failed to store test encrypted message");
        message
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Mail {
    pub id: String,
    /// RFC 3339, always UTC — compared lexicographically to order mail.
    pub time: String,
    pub envelope: MailEnvelope,
    pub subject: String,
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MailEnvelope {
    pub from: MailAddress,
    pub to: Vec<MailAddress>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MailAddress {
    pub address: String,
}

/// `source` with its comments cut out, for the textual pins that stand in for
/// a route test that cannot reach a line (no live LiveKit). A pin must not be
/// satisfied by code that is commented out.
///
/// Cuts `// ...` to the end of the line, whole-line or trailing (doc comments
/// too), and `/* ... */` blocks, nested as Rust nests them. Newlines stay, so
/// the line structure survives. Literals are copied as they are, so a `//` or
/// `/*` inside one (a URL) is not taken for a comment: strings and byte
/// strings with their escapes, raw strings (`r"..."`, `r#"..."#`), and char
/// literals (`'"'`, `'\''`, longer escapes), told from a lifetime by their
/// closing quote.
pub fn without_comments(source: &str) -> String {
    fn is_ident(c: char) -> bool {
        c.is_alphanumeric() || c == '_'
    }

    let chars: Vec<char> = source.chars().collect();
    let char_at = |at: usize| chars.get(at).copied();
    let mut out = String::with_capacity(source.len());
    let mut at = 0;

    while let Some(c) = char_at(at) {
        match (c, char_at(at + 1)) {
            ('/', Some('/')) => {
                while char_at(at).is_some_and(|c| c != '\n') {
                    at += 1;
                }
            }
            ('/', Some('*')) => {
                let mut depth = 0usize;
                loop {
                    match (char_at(at), char_at(at + 1)) {
                        (Some('/'), Some('*')) => {
                            depth += 1;
                            at += 2;
                        }
                        (Some('*'), Some('/')) => {
                            depth -= 1;
                            at += 2;
                            if depth == 0 {
                                break;
                            }
                        }
                        (Some('\n'), _) => {
                            out.push('\n');
                            at += 1;
                        }
                        (Some(_), _) => at += 1,
                        (None, _) => panic!("an unclosed /* comment"),
                    }
                }
            }
            ('"', _) => {
                out.push('"');
                at += 1;
                loop {
                    let c = char_at(at).expect("an unclosed string literal");
                    out.push(c);
                    at += 1;
                    match c {
                        '\\' => {
                            out.push(char_at(at).expect("an unclosed string literal"));
                            at += 1;
                        }
                        '"' => break,
                        _ => {}
                    }
                }
            }
            ('r', _)
                if at == 0
                    || !is_ident(chars[at - 1])
                    || (chars[at - 1] == 'b' && (at == 1 || !is_ident(chars[at - 2]))) =>
            {
                let mut quote = at + 1;
                while char_at(quote) == Some('#') {
                    quote += 1;
                }
                if char_at(quote) != Some('"') {
                    // `r` starting an identifier, or a raw identifier `r#name`
                    out.push('r');
                    at += 1;
                    continue;
                }
                // The closing quote, followed by as many `#` as opened it
                let hashes = quote - at - 1;
                let mut close = quote + 1;
                while !(char_at(close).expect("an unclosed raw string literal") == '"'
                    && (1..=hashes).all(|offset| char_at(close + offset) == Some('#')))
                {
                    close += 1;
                }
                let end = close + hashes + 1;
                out.extend(&chars[at..end]);
                at = end;
            }
            ('\'', Some('\\')) => {
                // An escaped char literal: `'\''`, `'\\'` and longer escapes
                let close = (at + 3..chars.len())
                    .find(|&close| chars[close] == '\'')
                    .expect("an unclosed char literal");
                out.extend(&chars[at..=close]);
                at = close + 1;
            }
            ('\'', Some(_)) if char_at(at + 2) == Some('\'') => {
                // A plain char literal, `'"'` included
                out.extend(&chars[at..at + 3]);
                at += 3;
            }
            _ => {
                // Everything else, a lifetime's `'` included
                out.push(c);
                at += 1;
            }
        }
    }

    out
}

/// `code` with every whitespace character removed, so a textual pin matches
/// whatever line breaks and indentation rustfmt picks.
pub fn without_whitespace(code: &str) -> String {
    code.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Where the whole statement `statement` stands in `code`, both without
/// whitespace ([`without_whitespace`]). It must appear exactly once, and on
/// its own: right after a `;`, `{` or `}`. So a pin on `call(..).await?;`
/// fails for `let _ = call(..).await?;`, `let _ = call(..).await;` and
/// `call(..).await;` alike.
pub fn statement_at(code: &str, statement: &str) -> usize {
    assert!(
        !statement.chars().any(char::is_whitespace) && statement.ends_with(';'),
        "`{}` is not a whitespace-free statement",
        statement
    );
    assert_eq!(
        code.matches(statement).count(),
        1,
        "`{statement}` must appear exactly once"
    );
    let at = code.find(statement).expect("counted above");
    let statement_start = code[..at].rfind([';', '{', '}']).map_or(0, |end| end + 1);
    assert!(
        statement_start == at && at > 0,
        "`{statement}` must be a statement of its own, not the value of `{}`",
        &code[statement_start..at]
    );
    at
}

#[test]
fn without_comments_drops_line_and_block_comments_only() {
    let stripped = without_comments(concat!(
        "keep(1);\n",
        "    // gone(2);\n",
        "/// gone(3);\n",
        "keep(4); /* gone(5); */ keep(6);\n",
        "/*\ngone(7);\n*/\n",
        "keep(8); // gone(9);\n",
        "keep(10).await?; // gone(11) trailing\n",
        "/* outer /* gone(12); */ gone(13); */ keep(14);\n",
        "//! gone(15);\n",
    ));
    assert!(!stripped.contains("gone("), "{}", stripped);
    for kept in [1, 4, 6, 8, 10, 14] {
        assert!(stripped.contains(&format!("keep({kept})")), "{}", stripped);
    }
    assert!(stripped.contains("keep(10).await?;"), "{}", stripped);

    // `//` and `/*` inside literals are not comments
    let literals = concat!(
        "let url = \"http://127.0.0.1:1\"; keep(1);\n",
        "let raw = r#\"a // \"quoted\" /* b\"#; keep(2);\n",
        "let raw = r\"c // d\"; keep(3);\n",
        "let bytes = b\"e // f\"; keep(4);\n",
        "let escaped = \"g \\\" // h\"; keep(5);\n",
        "let quote = '\"'; keep(6); // gone(1);\n",
        "let tick = '\\''; keep(7);\n",
        "fn f<'a>(x: &'a str) -> &'a str { x } // gone(2);\n",
        "let r#type = 1; keep(8); // gone(3);\n",
    );
    let stripped = without_comments(literals);
    assert!(!stripped.contains("gone("), "{}", stripped);
    for kept in 1..=8 {
        assert!(stripped.contains(&format!("keep({kept})")), "{}", stripped);
    }
    for literal in [
        "\"http://127.0.0.1:1\"",
        "r#\"a // \"quoted\" /* b\"#",
        "r\"c // d\"",
        "b\"e // f\"",
        "\"g \\\" // h\"",
        "fn f<'a>(x: &'a str) -> &'a str { x }",
    ] {
        assert!(
            stripped.contains(literal),
            "`{}` lost: {}",
            literal,
            stripped
        );
    }
    assert_eq!(stripped.lines().count(), literals.lines().count());
}

#[test]
fn statement_at_needs_the_whole_statement_on_its_own() {
    let code = without_whitespace("a();\n    call(x, y).await?;\n}");
    assert_eq!(statement_at(&code, "call(x,y).await?;"), 4);

    for (label, code) in [
        ("discarded", "a(); let _ = call(x, y).await?;"),
        ("discarded, no `?`", "a(); let _ = call(x, y).await;"),
        ("assigned", "a(); r = call(x, y).await?;"),
        ("returned", "a(); return call(x, y).await?;"),
        ("no `?`", "a(); call(x, y).await;"),
        ("twice", "a(); call(x, y).await?; call(x, y).await?;"),
    ] {
        let code = without_whitespace(code);
        let caught = std::panic::catch_unwind(|| statement_at(&code, "call(x,y).await?;"));
        assert!(
            caught.is_err(),
            "{}: must not count as the statement",
            label
        );
    }
}

/// Merge slice S6B-7: the event pump delivers every message published after
/// it subscribed, and does not end, even when its subscription lands in the
/// middle of a burst. Each round opens a [`Subscription`] while a publisher
/// floods one channel with numbered messages in pipelined bursts, then
/// requires an unbroken run of numbers that starts no later than the first
/// message published after `open` returned. The async pump this replaced
/// could lose its stream here: its first read past the `PSUBSCRIBE` reply
/// was discarded, and when that read ended mid-message the stream ended.
///
/// The flood is paced (HD re-audit HDA-3). Every harness pump in the process
/// is subscribed to `*` and receives it too, and a pump that falls far enough
/// behind is disconnected by redis, which would hand an unrelated test the
/// very gap this test guards against. So the publisher only publishes what a
/// round allows: up to `OPENING` messages while the round subscribes, then
/// exactly what the round still reads. Between rounds it is idle, and no
/// round can make it flood on: a round that hangs has stopped it already.
#[test]
fn the_event_pump_keeps_every_message_published_while_it_subscribes() {
    use std::sync::atomic::{AtomicBool, AtomicU64};

    /// Stops the publisher however the test ends, so a failed round never
    /// leaves it flooding the redis every other test shares.
    struct Stop(Arc<AtomicBool>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    const ROUNDS: u64 = 30;
    const RUN: u64 = 300;
    const BURST: u64 = 64;
    /// How far the publisher may run ahead while a round subscribes: long
    /// enough that the subscription lands inside the flood, and about 1 MB.
    const OPENING: u64 = 64 * BURST;

    rt().block_on(async {
        let channel = format!("harness-pump-check-{}", TestHarness::rand_string());
        let published = Arc::new(AtomicU64::new(0));
        // The publisher starts no burst once it has published this many.
        let allowed = Arc::new(AtomicU64::new(0));
        let stop = Stop(Arc::new(AtomicBool::new(false)));
        let publisher = tokio::spawn({
            let channel = channel.clone();
            let published = published.clone();
            let allowed = allowed.clone();
            let stop = stop.0.clone();
            async move {
                let mut connection = redis_kiss::get_connection()
                    .await
                    .expect("a redis connection");
                // Big enough that a burst spans several socket reads.
                let pad = "x".repeat(150);
                let mut sequence = 0u64;
                while !stop.load(Ordering::SeqCst) {
                    if sequence >= allowed.load(Ordering::SeqCst) {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                        continue;
                    }
                    let mut burst = redis::pipe();
                    for _ in 0..BURST {
                        sequence += 1;
                        burst
                            .cmd("PUBLISH")
                            .arg(&channel)
                            .arg(format!("{sequence} {pad}"))
                            .ignore();
                    }
                    let () = burst
                        .query_async(&mut *connection)
                        .await
                        .expect("publish a burst");
                    published.store(sequence, Ordering::SeqCst);
                }
            }
        });

        for round in 0..ROUNDS {
            // Start the round's flood, and subscribe only once it is running.
            let start = published.load(Ordering::SeqCst);
            allowed.store(start + OPENING, Ordering::SeqCst);
            let flooding = Instant::now() + Duration::from_secs(10);
            while published.load(Ordering::SeqCst) == start {
                assert!(
                    Instant::now() < flooding,
                    "round {}: the publisher never started",
                    round
                );
                tokio::time::sleep(Duration::from_millis(1)).await;
            }

            let mut subscription = Subscription::open(&channel, |message| {
                let payload: String = message.get_payload().ok()?;
                payload.split(' ').next()?.parse::<u64>().ok()
            })
            .await;
            // `published` moves once a burst is sent, so the burst after the
            // one in flight now starts after this read, after the
            // subscription was confirmed: from it on, every number is owed.
            let owed = published.load(Ordering::SeqCst) + BURST + 1;
            // From here on, only what this round still reads.
            allowed.store(owed + RUN, Ordering::SeqCst);
            let mut previous = None;
            loop {
                let sequence =
                    tokio::time::timeout(Duration::from_secs(10), subscription.items.recv())
                        .await
                        .unwrap_or_else(|_| {
                            panic!("round {}: nothing for 10 s after {:?}", round, previous)
                        })
                        .unwrap_or_else(|| {
                            panic!("round {}: the pump ended after {:?}", round, previous)
                        });
                match previous {
                    None => assert!(
                        sequence <= owed,
                        "round {}: the first message is {}, but {} was published after the \
                         subscription was confirmed",
                        round,
                        sequence,
                        owed
                    ),
                    Some(previous) => assert_eq!(
                        sequence,
                        previous + 1,
                        "round {}: a message lost after {}",
                        round,
                        previous
                    ),
                }
                previous = Some(sequence);
                if sequence >= owed + RUN {
                    break;
                }
            }
            assert_eq!(
                subscription.gaps(),
                0,
                "round {}: the subscription had to be taken out again",
                round
            );
        }

        drop(stop);
        publisher.await.expect("the publisher");
    })
}

/// The message a caught panic carries.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|text| text.to_string()))
        .unwrap_or_default()
}

/// HD re-audit HDA-2: a gap in a harness's subscription that opens while a
/// wait is waiting fails that wait promptly and says so, instead of waiting
/// out its 30 s or letting a later match stand in for the lost event; and a
/// harness that had a gap fails its test when it is dropped. The gap is
/// counted by hand here, the way the pump counts one: cutting the
/// subscription on the shared redis would cut every other test's as well.
/// Controls: the check in `wait_for_event` dropped (the wait times out
/// instead), and the one in `Drop` dropped.
#[test]
fn a_subscription_gap_fails_the_wait_it_spans_and_the_test() {
    use futures::FutureExt;

    rt().block_on(async {
        let mut harness = TestHarness::new().await;
        let gaps = harness.events.gaps.clone();
        let gap = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            gaps.fetch_add(1, Ordering::SeqCst);
        });

        let started = Instant::now();
        let failed =
            std::panic::AssertUnwindSafe(harness.wait_for_event("harness-gap-check", |_| false))
                .catch_unwind()
                .await
                .expect_err("a wait that spans a gap must fail");
        gap.await.expect("the gap");
        let message = panic_message(&*failed);
        assert!(
            message.contains("taken out again while this waited"),
            "{}",
            message
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the wait failed only after {:?}",
            started.elapsed()
        );

        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(harness)))
            .expect_err("a harness that had a gap must fail its test");
        let message = panic_message(&*dropped);
        assert!(
            message.contains("an event published in that gap was lost"),
            "{}",
            message
        );
    })
}

/// `assert_no_buffered_event` names the topic and the event it found. This
/// crate is edition 2018, where an `assert!` message that is a lone literal
/// is printed as it is, so `'{topic}'` used to reach the log unformatted.
/// Control: the message back to that lone literal.
#[test]
fn an_unexpected_buffered_event_is_named() {
    rt().block_on(async {
        let mut harness = TestHarness::new().await;
        harness
            .event_buffer
            .push(("harness-literal-check".to_string(), EventV1::Logout));

        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            harness.assert_no_buffered_event("harness-literal-check", |_| true)
        }))
        .expect_err("a buffered match must fail");
        let message = panic_message(&*failed);
        assert!(
            message.contains("unexpected event on 'harness-literal-check': Logout"),
            "{}",
            message
        );
    })
}

/// The protected-channel fixtures build what the W2 routes take. Run under
/// nextest (one process per test).
mod protected_fixture_tests {
    use revolt_database::validate_protected_send;
    use revolt_result::ErrorType;

    use super::*;
    use crate::routes::mls::{
        dispatch_group, require_seated, require_text_gate, GroupDispatch, TextGate,
    };

    // Design 5.1 inputs
    const CHANNEL: &str = "01J9Z3K4M5N6P7Q8R9S0T1V2W3";
    const OWNER: &str = "01HZXAAAAAAAAAAAAAAAAAAAAA";
    const MEMBER: &str = "01HZXBBBBBBBBBBBBBBBBBBBBB";
    const OTHER: &str = "01HZXCCCCCCCCCCCCCCCCCCCCC";
    const OWNER_DEVICE: &str = "00112233445566778899aabbccddeeff";
    const NEW_OWNER_DEVICE: &str = "0123456789abcdef0123456789abcdef";
    const MEMBER_DEVICE: &str = "ffeeddccbbaa99887766554433221100";

    // Design 5.2 identity keys
    const OWNER_IDENTITY_KEY: &str = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
    const MEMBER_IDENTITY_KEY: &str = "Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc";
    const NEW_OWNER_IDENTITY_KEY: &str = "zRSzf5VulTGU/3+3Oz2B3MVh1hp1OAlLfD4aZD7l86o";

    // Design 5.3 seat list and 5.4 handover
    const VECTOR_SEAT_LIST_BODY: &str = "sloga-seat-list-v1\nv:1\nchannel_id:01J9Z3K4M5N6P7Q8R9S0T1V2W3\nversion:3\ndevice_cap:5\nissued_at:1790812800000\nsigner_user_id:01HZXAAAAAAAAAAAAAAAAAAAAA\nsigner_device_id:00112233445566778899aabbccddeeff\nseats:01HZXAAAAAAAAAAAAAAAAAAAAA,01HZXBBBBBBBBBBBBBBBBBBBBB,01HZXCCCCCCCCCCCCCCCCCCCCC";
    const VECTOR_SEAT_LIST_SIGNATURE: &str =
        "HtbS6jbLvwSZxAe4i2a4lwmKhv4hM+3NkMY1EuwRaPyv9kI3x/3t1SsalteuxoxmG4YFczXUA77134HTJwLRCA";
    const VECTOR_HANDOVER_BODY: &str = "sloga-owner-handover-v1\nv:1\nchannel_id:01J9Z3K4M5N6P7Q8R9S0T1V2W3\nfrom_user_id:01HZXAAAAAAAAAAAAAAAAAAAAA\nfrom_device_id:00112233445566778899aabbccddeeff\nfrom_identity_key:A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg\nto_user_id:01HZXAAAAAAAAAAAAAAAAAAAAA\nto_device_id:0123456789abcdef0123456789abcdef\nto_identity_key:zRSzf5VulTGU/3+3Oz2B3MVh1hp1OAlLfD4aZD7l86o\nissued_at:1790812800000";
    const VECTOR_HANDOVER_SIGNATURE: &str =
        "JKnYtaiK/i3tYSxV71XoXyz9l0XaDsWIhzoCu8s9IuTdmFmWX5BNtoEhpt+v9gSvhE+nqS2/kZEA0CX6giR6BA";

    #[track_caller]
    fn assert_not_authenticated(result: revolt_result::Result<()>, case: &str) {
        assert!(
            matches!(&result, Err(error) if matches!(error.error_type, ErrorType::NotAuthenticated)),
            "{}: expected NotAuthenticated, got {:?}",
            case,
            result
        );
    }

    /// The builders are canonical and sign with the seed's key: they
    /// reproduce the design 5.3 seat list and the 5.4 handover byte for
    /// byte, signatures included, from the 5.1 inputs
    #[test]
    fn the_builders_reproduce_the_5_3_and_5_4_vectors() {
        let owner = TestE2EEDevice::new(OWNER, OWNER_DEVICE, OWNER_DEVICE_SEED, "unbound");
        let member = TestE2EEDevice::new(MEMBER, MEMBER_DEVICE, MEMBER_DEVICE_SEED, "unbound");
        let new_owner =
            TestE2EEDevice::new(OWNER, NEW_OWNER_DEVICE, NEW_OWNER_DEVICE_SEED, "unbound");
        for (device, key) in [
            (&owner, OWNER_IDENTITY_KEY),
            (&member, MEMBER_IDENTITY_KEY),
            (&new_owner, NEW_OWNER_IDENTITY_KEY),
        ] {
            assert_eq!(device.identity_key(), key);
            device.identity.verify().expect("the identity row verifies");
        }

        // `seats_unsorted` (5.1): the builder sorts
        let list = owner.seat_list(CHANNEL, 3, 5, &[OTHER, OWNER, MEMBER]);
        assert_eq!(list.body, VECTOR_SEAT_LIST_BODY);
        assert_eq!(list.signature, VECTOR_SEAT_LIST_SIGNATURE);
        assert_eq!(list.signer_device_id, OWNER_DEVICE);
        assert!(list.handover.is_none());

        let handover = owner.handover_to(CHANNEL, &new_owner);
        assert_eq!(handover.body, VECTOR_HANDOVER_BODY);
        assert_eq!(handover.signature, VECTOR_HANDOVER_SIGNATURE);

        let genesis = owner.protect_request(CHANNEL, 5, &[OWNER]).seat_list;
        let body = SeatListBody::parse(&genesis.body).expect("the genesis body");
        assert_eq!((body.version, body.seats), (1, vec![OWNER.to_string()]));
    }

    #[test]
    fn the_e2ee_device_fixture_is_registered_and_bound_to_its_session() {
        rt().block_on(the_e2ee_device_fixture_is_registered_and_bound_to_its_session_case())
    }

    /// The device is stored, its row verifies, and it is bound to the session
    /// it was given and no other (the `assert_bound_session` rule)
    async fn the_e2ee_device_fixture_is_registered_and_bound_to_its_session_case() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, session, user) = harness.new_user().await;
        let (_, other_session, _) = harness.new_user().await;

        let device = harness
            .new_e2ee_device(&user, &session.id, OWNER_DEVICE_SEED)
            .await;
        assert_eq!(device.identity_key(), OWNER_IDENTITY_KEY);
        let stored = db
            .fetch_e2ee_identity(&user.id, &device.device_id)
            .await
            .expect("the stored identity");
        assert_eq!(stored.ed25519_key, OWNER_IDENTITY_KEY);
        stored.verify().expect("the stored identity verifies");
        stored
            .assert_bound_session(&session.id)
            .expect("bound to the harness session");
        assert_not_authenticated(
            stored.assert_bound_session(&other_session.id),
            "another session",
        );
        E2EEIdentity::require_device_bound_session(db, &user.id, &session.id)
            .await
            .expect("a device-bound session");

        // A second device of the same user, bound elsewhere
        let unbound = harness
            .new_e2ee_device(&user, "elsewhere", NEW_OWNER_DEVICE_SEED)
            .await;
        assert_ne!(unbound.device_id, device.device_id);
        let stored = db
            .fetch_e2ee_identity(&user.id, &unbound.device_id)
            .await
            .expect("the unbound identity");
        assert_eq!(stored.ed25519_key, NEW_OWNER_IDENTITY_KEY);
        assert_not_authenticated(stored.assert_bound_session(&session.id), "unbound device");
    }

    #[test]
    fn the_seat_list_builder_signs_what_the_directory_key_verifies() {
        rt().block_on(the_seat_list_builder_signs_what_the_directory_key_verifies_case())
    }

    /// What the builders sign verifies under the signer device's STORED
    /// directory key (the route's 4.3 step 3 and step 8 primitive) for a
    /// genesis list, a v+1 list and its handover; a rebuild is byte-identical
    /// (the 4.9 retry); and the database protect and PUT take them
    async fn the_seat_list_builder_signs_what_the_directory_key_verifies_case() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, _, member) = harness.new_user().await;
        let (server, channel) = harness.new_protectable_channel(&owner).await;
        harness.join_server(&server, &member).await;
        harness
            .grant_entitlement(&channel, FIXTURE_SLOT_CAP, None)
            .await;
        let device = harness
            .new_e2ee_device(&owner, &owner_session.id, OWNER_DEVICE_SEED)
            .await;
        let successor = harness
            .new_e2ee_device(&owner, "elsewhere", NEW_OWNER_DEVICE_SEED)
            .await;
        let signer = db
            .fetch_e2ee_identity(&owner.id, &device.device_id)
            .await
            .expect("the signer identity");
        let successor_identity = db
            .fetch_e2ee_identity(&owner.id, &successor.device_id)
            .await
            .expect("the successor identity");

        let seats = [&owner.id, &member.id];
        let genesis = device
            .protect_request(channel.id(), FIXTURE_DEVICE_CAP, &seats)
            .seat_list;
        let mut next = device.seat_list(channel.id(), 2, FIXTURE_DEVICE_CAP, &seats);
        let handover = device.handover_to(channel.id(), &successor);
        next.handover = Some(handover.clone());

        // Verified first, so a bad signature fails here and nowhere else
        for (case, body, signature) in [
            ("genesis list", &genesis.body, &genesis.signature),
            ("v2 list", &next.body, &next.signature),
            ("handover", &handover.body, &handover.signature),
        ] {
            assert!(
                signer.verify_payload(body, signature),
                "the {} signature does not verify under the signer device key",
                case
            );
        }

        let rebuilt = device
            .protect_request(channel.id(), FIXTURE_DEVICE_CAP, &seats)
            .seat_list;
        assert_eq!(
            (&rebuilt.body, &rebuilt.signature),
            (&genesis.body, &genesis.signature)
        );

        let mut seated = vec![owner.id.clone(), member.id.clone()];
        seated.sort();
        let body = SeatListBody::parse(&genesis.body).expect("the genesis body");
        assert_eq!(body.channel_id, channel.id());
        assert_eq!(body.signer_user_id, owner.id);
        assert_eq!(body.signer_device_id, device.device_id);
        assert_eq!(genesis.signer_device_id, device.device_id);
        assert_eq!(body.seats, seated);

        let statement = HandoverBody::parse(&handover.body).expect("the handover body");
        assert_eq!(statement.channel_id, channel.id());
        assert_eq!(statement.from_device_id, device.device_id);
        assert_eq!(statement.from_identity_key, signer.ed25519_key);
        assert_eq!(statement.to_device_id, successor.device_id);
        assert_eq!(statement.to_identity_key, successor_identity.ed25519_key);

        let protected = harness
            .protect_with_db(
                &channel,
                &v0::DataProtectChannel {
                    seat_list: genesis.clone(),
                },
            )
            .await;
        assert!(!protected.unchanged);
        assert_eq!(protected.claimed, seated);
        let put = harness.put_seats_with_db(&channel, &next).await;
        assert!(!put.unchanged);
        assert_eq!(put.list.version, 2);
        assert_eq!(put.list.handovers.len(), 1);
    }

    #[test]
    fn the_protected_channel_fixture_is_what_the_routes_need() {
        rt().block_on(the_protected_channel_fixture_is_what_the_routes_need_case())
    }

    /// End to end: the server, memberships, entitlement, stored seat list and
    /// seats, the Text groups (ids from `text_group_id`, through the route
    /// gate) and an encrypted message the send allowlist and the stored-shape
    /// rule take
    async fn the_protected_channel_fixture_is_what_the_routes_need_case() {
        let harness = TestHarness::new().await;
        let db = &harness.db;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (_, _, outsider) = harness.new_user().await;

        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let channel = &protected.channel;

        assert_eq!(protected.server.owner, owner.id);
        assert!(protected
            .server
            .channels
            .iter()
            .any(|id| id == channel.id()));
        assert_eq!(
            seat_list_channel_server(channel),
            Some(protected.server.id.as_str())
        );
        assert!(channel.is_protected());
        for user in [&owner, &member] {
            db.fetch_member(&protected.server.id, &user.id)
                .await
                .expect("a member");
        }

        let entitlement = db
            .fetch_channel_entitlement(channel.id())
            .await
            .expect("the entitlement read")
            .expect("an entitlement");
        assert_eq!(entitlement.id, protected.entitlement.id);
        assert_eq!(entitlement.server_id, protected.server.id);
        assert_eq!(entitlement.slot_cap, FIXTURE_SLOT_CAP);
        assert!(entitlement.is_active());

        let stored = db
            .fetch_seat_list(channel.id())
            .await
            .expect("the seat list read")
            .expect("a seat list");
        assert_eq!(stored.version, 1);
        assert_eq!(stored.body, protected.seat_list.body);
        assert_eq!(stored.signature, protected.seat_list.signature);
        let owner_identity = db
            .fetch_e2ee_identity(&owner.id, &protected.owner_device.device_id)
            .await
            .expect("the owner device");
        owner_identity
            .assert_bound_session(&owner_session.id)
            .expect("the owner device is bound to the owner session");
        assert!(owner_identity.verify_payload(&stored.body, &stored.signature));
        for user in [&owner, &member] {
            require_seated(db, channel.id(), &user.id)
                .await
                .expect("seated");
        }
        assert!(
            matches!(
                require_seated(db, channel.id(), &outsider.id).await,
                Err(error) if matches!(error.error_type, ErrorType::NotSeated)
            ),
            "{}",
            "an outsider is not seated"
        );

        let group = harness
            .new_text_group(channel, &protected.owner_device, 0, None)
            .await;
        assert_eq!(group.id, text_group_id(channel.id(), 0));
        assert_eq!(
            (group.kind, group.generation, group.current_epoch),
            (MlsGroupKind::Text, Some(0), 0)
        );
        assert_eq!(
            group.seat_list_ad_sha256,
            Some(stored.commit_ad_sha256().expect("the AD hash"))
        );
        let GroupDispatch::Text(gated) = dispatch_group(db, &group.id)
            .await
            .expect("the kind dispatch")
        else {
            panic!("the fixture's group dispatches as a Text group");
        };
        require_text_gate(TextGate::Available)
            .await
            .expect("the text gate");
        assert_eq!(gated.kind, MlsGroupKind::Text);

        let successor = harness
            .new_text_group(channel, &protected.owner_device, 1, Some(&group.id))
            .await;
        assert_eq!(successor.id, text_group_id(channel.id(), 1));
        assert_eq!(successor.generation, Some(1));
        let superseded = db.fetch_mls_group(&group.id).await.expect("generation 0");
        assert!(!superseded.open);
        assert_eq!(
            superseded.superseded_by.as_deref(),
            Some(successor.id.as_str())
        );

        let member_device = harness
            .new_e2ee_device(&member, &member_session.id, MEMBER_DEVICE_SEED)
            .await;
        let author = member.clone().into(db, Some(&member)).await;
        validate_protected_send(
            true,
            &v0::MessageAuthor::User(&author),
            &v0::DataMessageSend {
                content: None,
                nonce: Some(Ulid::new().to_string()),
                attachments: None,
                replies: None,
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                encrypted: Some(member_device.encrypted_payload(&successor)),
                flags: None,
            },
            false,
        )
        .expect("the send allowlist takes the payload");

        let message = harness
            .new_encrypted_message(channel, &member_device, &successor)
            .await;
        let fetched = db
            .fetch_message(&message.id)
            .await
            .expect("the stored message");
        assert_eq!(fetched.author, member.id);
        assert_eq!(fetched.nonce, message.nonce);
        assert_eq!(fetched.encrypted, message.encrypted);
        let encrypted = fetched.encrypted.as_ref().expect("encrypted");
        assert_eq!(encrypted.group_id, successor.id);
        assert_eq!(encrypted.epoch, successor.current_epoch);
        assert_eq!(encrypted.sender_device_id, member_device.device_id);
        assert!(fetched.is_servable(true));
        fetched
            .validate_protected_shape(true)
            .expect("the stored shape");
    }
}
