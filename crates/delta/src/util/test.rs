use std::time::{Duration, Instant};

use futures::StreamExt;
use rand::Rng;
use revolt_database::util::email::normalise_email;
use revolt_database::util::password::hash_password;
use revolt_database::{
    events::client::EventV1, Channel, Database, Member, Message, PartialRole, Server, User, AMQP,
};
use revolt_database::{util::idempotency::IdempotencyKey, Role};
use revolt_database::{Account, EmailVerification, Session};
use revolt_models::v0;
use revolt_permissions::OverrideField;
use rocket::http::Header;
use rocket::local::asynchronous::{Client, LocalRequest, LocalResponse};
use rocket::tokio;
use serde::{Deserialize, Serialize};

pub struct TestHarness {
    pub client: Client,
    pub db: Database,
    pub amqp: AMQP,
    /// Connection string this harness resolved to, kept so `Drop` can
    /// reconnect and delete the throwaway database. `None` on the reference
    /// driver, which leaves nothing behind. Captured at construction because
    /// `Drop` cannot await `config()`.
    mongo_uri: Option<String>,
    events_rx: tokio::sync::mpsc::UnboundedReceiver<(String, EventV1)>,
    event_buffer: Vec<(String, EventV1)>,
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

        let client = Client::tracked(crate::web().await)
            .await
            .expect("valid rocket instance");

        let mut sub = redis_kiss::open_pubsub_connection()
            .await
            .expect("`PubSub`");

        sub.psubscribe("*").await.unwrap();

        // Pump the subscription from construction time. The previous
        // per-`wait_for_event`-call `on_message()` stream lost events that
        // fanned while no stream was polling — an event published BEFORE
        // the first wait (or between two waits) never surfaced even though
        // redis delivered it (verified with an external subscriber), which
        // turned event assertions into permanent hangs. The pump owns the
        // connection for the harness's lifetime and forwards every
        // decodable event in order; `wait_for_event` reads the channel.
        let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut stream = sub.on_message();
            while let Some(item) = stream.next().await {
                let msg_topic = item.get_channel_name().to_string();
                // The wildcard psubscribe sees EVERY topic on a shared
                // redis; skip payloads that are not EventV1 (e.g. LiveKit
                // keepalives) silently — a genuinely missing target event
                // now surfaces as a wait_for_event TIMEOUT, not a hang.
                if let Ok(payload) = redis_kiss::decode_payload::<EventV1>(&item) {
                    if events_tx.send((msg_topic, payload)).is_err() {
                        break;
                    }
                }
            }
        });

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
            mongo_uri,
            events_rx,
            event_buffer: vec![],
        }
    }

    pub fn rand_string() -> String {
        let mut rng = rand::thread_rng();
        (&mut rng)
            .sample_iter(rand::distributions::Alphanumeric)
            .take(20)
            .map(char::from)
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
                voice: None,
                announcement: None,
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
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let received = tokio::time::timeout_at(deadline, self.events_rx.recv())
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "wait_for_event: no event matching predicate on '{topic}' within 30s \
                         (buffered: {} events)",
                        self.event_buffer.len()
                    )
                });
            let Some((msg_topic, payload)) = received else {
                panic!("wait_for_event: event pump ended (subscription dropped)");
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
    pub fn assert_no_buffered_event<F>(&self, topic: &str, predicate: F)
    where
        F: Fn(&EventV1) -> bool,
    {
        for (msg_topic, event) in &self.event_buffer {
            assert!(
                !(topic == msg_topic && predicate(event)),
                "unexpected event on '{topic}': {event:?}"
            );
        }
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

            assert!(
                Instant::now() < deadline,
                "no email delivered to {} within 15s",
                mailbox
            );

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
    fn drop(&mut self) {
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
