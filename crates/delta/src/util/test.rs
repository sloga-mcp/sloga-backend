use std::time::Duration;

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
    events_rx: tokio::sync::mpsc::UnboundedReceiver<(String, EventV1)>,
    event_buffer: Vec<(String, EventV1)>,
}

impl TestHarness {
    pub async fn new() -> TestHarness {
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

        let amqp = AMQP::new_auto().await;

        TestHarness {
            client,
            db,
            amqp,
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

    pub async fn assert_email(&self, mailbox: &str) -> (Mail, String) {
        // Wait a moment for maildev to catch the email

        tokio::time::sleep(Duration::from_secs(1)).await;

        let client = reqwest::Client::new();
        let results = client
            .get("http://localhost:14080/email")
            .send()
            .await
            .unwrap()
            .json::<Vec<Mail>>()
            .await
            .unwrap();

        let re = regex::Regex::new(r"\[\[([A-Za-z0-9_-]*)\]\]").unwrap();

        for entry in results.into_iter().rev() {
            if entry.envelope.to[0].address == mailbox {
                client
                    .delete(format!("http://localhost:14080/delete/{}", &entry.id))
                    .send()
                    .await
                    .unwrap();

                let code = re.captures_iter(&entry.text).next().unwrap()[1].to_string();

                return (entry, code);
            }
        }

        panic!("Email not found.")
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Mail {
    pub id: String,
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
