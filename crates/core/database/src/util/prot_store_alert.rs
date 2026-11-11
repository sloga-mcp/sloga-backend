//! Staff alerts for app-store purchase work items (prot-s6-contracts section 19).
//!
//! `util::email::send_email` blocks the calling thread and `.expect`s on its
//! configuration, which would take a crond task or a webhook down with it.
//! This module never calls it. The pinned log line is written first and
//! always; the mail is a convenience on top of it, and the work item stays on
//! the row (`needs_action`) whatever the mail does. Callers set the work item,
//! then claim the alert (`claim_prot_store_alert`) and only the winner calls
//! `send_ops_alert`, so a row is alerted once per kind across replicas.
//!
//! S5b's owner mail sender in `prot_email.rs` is private to that file and
//! sends a multipart owner email (R24), so the plain-text send lives here.

use std::time::Duration;

use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::{authentication::Credentials, client::Tls, Error as SmtpError},
    Message, SmtpTransport, Transport,
};
use revolt_config::ApiSmtp;
use revolt_result::Result;

/// A purchase no intent binds (E10 assign)
pub const PROT_STORE_NEEDS_UNBOUND: &str = "unbound";
/// Play's pending refund review (9.6)
pub const PROT_STORE_NEEDS_CHARGEBACK: &str = "chargeback_review";
/// A Play credit still unconsumed 24 h later (16 step 2)
pub const PROT_STORE_NEEDS_UNCONSUMED: &str = "play_unconsumed_24h";
/// A refund reversal that re-credited nothing (6)
pub const PROT_STORE_NEEDS_REVERSED_UNPAID: &str = "reversed_unpaid";
/// A Play purchase still Held 24 h into a credit pause (R59)
pub const PROT_STORE_NEEDS_HELD: &str = "play_held_24h";

// Log-only kinds are named PROT_STORE_LOG_* (no work item) and listed in
// PROT_STORE_LOG_ONLY_KINDS, which `send_ops_alert` never mails.

/// A verified Apple notification whose payload did not decode (R61)
pub const PROT_STORE_LOG_UNDECODABLE_NOTIFICATION: &str = "undecodable_notification";
/// Kinds that are logged and never mailed, whatever the mailbox
pub const PROT_STORE_LOG_ONLY_KINDS: &[&str] = &[PROT_STORE_LOG_UNDECODABLE_NOTIFICATION];

/// lettre's per-operation SMTP timeout
const SMTP_TIMEOUT: Duration = Duration::from_secs(10);

/// The longest a caller waits for one alert mail; past it the send is
/// reported as failed and the blocking thread finishes on its own
const SEND_DEADLINE: Duration = Duration::from_secs(30);

/// Non-panicking (never calls send_email, `util/email.rs:221-260` .expects): logs the pinned line
/// `PROT_STORE_ALERT kind=<kind> id=<id>` at warn level ALWAYS, then, when `to` is non-empty and SMTP is
/// configured, sends a plain-text mail (subject "Sloga store alert: <kind>", body = kind, id, the admin route) in
/// tokio::task::spawn_blocking; every failure (address, build, send, JoinError) → Ok(false) logged
/// `PROT_STORE_ALERT_MAIL_FAILED kind=.. id=..`. Returns Ok(true) when mailed.
///
/// A kind in `PROT_STORE_LOG_ONLY_KINDS` is logged and never mailed (R61).
pub async fn send_ops_alert(smtp: &ApiSmtp, to: &str, kind: &str, id: &str) -> Result<bool> {
    log::warn!("{}", alert_line(kind, id));

    let skipped = if PROT_STORE_LOG_ONLY_KINDS.contains(&kind) {
        Some("log_only")
    } else if to.is_empty() {
        Some("no_mailbox")
    } else if smtp.host.is_empty() {
        Some("smtp_not_configured")
    } else {
        None
    };
    if let Some(reason) = skipped {
        log::info!("PROT_STORE_ALERT_MAIL_SKIPPED kind={kind} id={id} reason={reason}");
        return Ok(false);
    }

    match deliver_ops_alert(smtp, to, kind, id).await {
        Ok(()) => {
            log::info!("PROT_STORE_ALERT_MAIL_SENT kind={kind} id={id}");
            Ok(true)
        }
        Err(reason) => {
            log::error!("{}", mail_failed_line(kind, id, &reason));
            Ok(false)
        }
    }
}

/// The pinned alert line (section 19)
fn alert_line(kind: &str, id: &str) -> String {
    format!("PROT_STORE_ALERT kind={kind} id={id}")
}

/// The failed-mail line. Every `reason` in this file holds no address: fixed
/// text, a reply code, or lettre's `AddressError` (fixed messages).
fn mail_failed_line(kind: &str, id: &str, reason: &str) -> String {
    format!("PROT_STORE_ALERT_MAIL_FAILED kind={kind} id={id} reason={reason}")
}

/// The plain-text body: the kind, the purchase and where staff act on it
fn alert_body(kind: &str, id: &str) -> String {
    format!(
        "A Prot store purchase needs staff action.\n\n\
         Kind: {kind}\n\
         Purchase: {id}\n\n\
         Admin route: GET /admin/prot/store/{id}\n\
         Work list: GET /admin/prot/store?needs_action=true\n\
         (privileged account, MFA ticket and audit reason)\n"
    )
}

/// What the log may say about a lettre SMTP error: the stage, the error class
/// and the reply code. Never its Display or Debug text, which carries the
/// server's reply (a 550 usually echoes the recipient).
fn smtp_failure_reason(stage: &str, error: &SmtpError) -> String {
    let class = if error.is_permanent() {
        "permanent"
    } else if error.is_transient() {
        "transient"
    } else if error.is_timeout() {
        "timeout"
    } else if error.is_tls() {
        "tls"
    } else if error.is_response() {
        "response"
    } else if error.is_client() {
        "client"
    } else {
        "connection"
    };
    match error.status() {
        Some(code) => format!("{stage}: {class} code={code}"),
        None => format!("{stage}: {class}"),
    }
}

/// Build the message on the async side (no I/O), then connect and send on the
/// blocking pool
async fn deliver_ops_alert(
    smtp: &ApiSmtp,
    to: &str,
    kind: &str,
    id: &str,
) -> std::result::Result<(), String> {
    let from = smtp
        .from_address
        .parse::<Mailbox>()
        .map_err(|error| format!("invalid smtp from_address: {error}"))?;
    let to = to
        .parse::<Mailbox>()
        .map_err(|error| format!("invalid ops_alert_email: {error}"))?;

    let builder = Message::builder()
        .from(from)
        .to(to)
        .subject(format!("Sloga store alert: {kind}"));
    let builder = match &smtp.reply_to {
        Some(reply_to) => builder.reply_to(
            reply_to
                .parse::<Mailbox>()
                .map_err(|error| format!("invalid smtp reply_to: {error}"))?,
        ),
        None => builder,
    };
    let message = builder
        .header(ContentType::TEXT_PLAIN)
        .body(alert_body(kind, id))
        .map_err(|_| "invalid message".to_string())?;

    let port = smtp
        .port
        .map(u16::try_from)
        .transpose()
        .map_err(|_| "invalid smtp port".to_string())?;
    let smtp = smtp.clone();

    run_blocking_send(SEND_DEADLINE, move || {
        let relay = if smtp.use_starttls == Some(true) {
            SmtpTransport::starttls_relay(&smtp.host)
        } else {
            SmtpTransport::relay(&smtp.host)
        }
        .map_err(|error| smtp_failure_reason("smtp relay", &error))?;

        let relay = match port {
            Some(port) => relay.port(port),
            None => relay,
        };
        let relay = if smtp.use_tls == Some(false) {
            relay.tls(Tls::None)
        } else {
            relay
        };

        relay
            .credentials(Credentials::new(
                smtp.username.clone(),
                smtp.password.clone(),
            ))
            .timeout(Some(SMTP_TIMEOUT))
            .build()
            .send(&message)
            .map(|_| ())
            .map_err(|error| smtp_failure_reason("smtp send", &error))
    })
    .await
}

/// Run one blocking send on the blocking pool. A panic in it comes back as a
/// JoinError and is answered as a failure like any other; so is a send that
/// outlives `deadline`.
async fn run_blocking_send<F>(deadline: Duration, send: F) -> std::result::Result<(), String>
where
    F: FnOnce() -> std::result::Result<(), String> + Send + 'static,
{
    // A JoinError's text holds the panic message, which can quote anything
    match tokio::time::timeout(deadline, tokio::task::spawn_blocking(send)).await {
        Ok(Ok(result)) => result,
        Ok(Err(join_error)) if join_error.is_panic() => Err("send task panicked".to_string()),
        Ok(Err(_)) => Err("send task cancelled".to_string()),
        Err(_) => Err("send timed out".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::sync::{Mutex, Once};
    use std::time::Duration;

    use futures::future::join_all;
    use revolt_config::{config, ApiSmtp};
    use revolt_models::v0;

    use super::{
        alert_line, mail_failed_line, run_blocking_send, send_ops_alert, PROT_STORE_LOG_ONLY_KINDS,
        PROT_STORE_LOG_UNDECODABLE_NOTIFICATION, PROT_STORE_NEEDS_CHARGEBACK,
        PROT_STORE_NEEDS_HELD, PROT_STORE_NEEDS_REVERSED_UNPAID, PROT_STORE_NEEDS_UNBOUND,
        PROT_STORE_NEEDS_UNCONSUMED, SEND_DEADLINE,
    };
    use crate::{
        build_store_move, plan_store_move, Database, ProtStoreEvent, ProtStoreMoveOutcome,
        ProtStorePlay, ProtStorePurchase, ProtStoreVerdict,
    };

    /// 2027-01-15T08:00:00Z
    const NOW: i64 = 1_800_000_000_000;
    const OPS: &str = "ops@example.test";
    const ALERT: &str = "PROT_STORE_ALERT kind=";
    const SKIPPED: &str = "PROT_STORE_ALERT_MAIL_SKIPPED ";
    const SENT: &str = "PROT_STORE_ALERT_MAIL_SENT ";
    const FAILED: &str = "PROT_STORE_ALERT_MAIL_FAILED ";

    /// Info-and-above log lines of this test binary (level, text); each test
    /// filters by its own purchase ids
    static LINES: Mutex<Vec<(log::Level, String)>> = Mutex::new(Vec::new());

    struct CaptureLog;

    impl log::Log for CaptureLog {
        fn enabled(&self, metadata: &log::Metadata) -> bool {
            metadata.level() <= log::Level::Info
        }

        fn log(&self, record: &log::Record) {
            if self.enabled(record.metadata()) {
                LINES
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((record.level(), record.args().to_string()));
            }
        }

        fn flush(&self) {}
    }

    /// Start capturing log lines (once per test binary). Panics if another
    /// logger is installed: the assertions would see nothing.
    fn capture_log() {
        static LOGGER: CaptureLog = CaptureLog;
        static INSTALL: Once = Once::new();
        INSTALL.call_once(|| {
            log::set_logger(&LOGGER).expect("no other logger in this test binary");
            log::set_max_level(log::LevelFilter::Info);
        });
    }

    /// Captured lines starting with `prefix` whose `id=` field is `id`
    fn lines(prefix: &str, id: &str) -> Vec<(log::Level, String)> {
        let field = format!("id={id}");
        LINES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(_, line)| line.starts_with(prefix) && line.split(' ').any(|f| f == field))
            .cloned()
            .collect()
    }

    /// The exact pinned alert lines for (`kind`, `id`); each must be a warning
    fn alerts(kind: &str, id: &str) -> usize {
        let pinned = alert_line(kind, id);
        let found = lines(ALERT, id);
        assert!(
            found.iter().all(|(level, _)| *level == log::Level::Warn),
            "{found:?}"
        );
        found.iter().filter(|(_, line)| *line == pinned).count()
    }

    fn play(pattern: &str) -> String {
        format!("play:{}", pattern.repeat(32))
    }

    /// The test config's SMTP block pointed at 127.0.0.1:`port`, plain text
    async fn smtp(port: i32) -> ApiSmtp {
        let mut smtp = config().await.api.smtp;
        smtp.host = "127.0.0.1".to_string();
        smtp.port = Some(port);
        smtp.use_tls = Some(false);
        smtp.use_starttls = Some(false);
        smtp.from_address = "noreply@example.test".to_string();
        smtp.reply_to = None;
        smtp
    }

    /// One plain-text SMTP session: AUTH accepted; every RCPT accepted (the
    /// DATA goes to `mail`) or rejected with a 550 that echoes the recipient
    fn serve_smtp(stream: TcpStream, reject_rcpt: bool, mail: Sender<String>) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut writer = stream;
        if writer.write_all(b"220 fake ESMTP\r\n").is_err() {
            return;
        }
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let reply: &[u8] = if line.starts_with("EHLO") {
                b"250-fake\r\n250 AUTH PLAIN LOGIN\r\n"
            } else if line.starts_with("AUTH") {
                b"235 2.7.0 ok\r\n"
            } else if line.starts_with("RCPT") && reject_rcpt {
                b"550 5.1.1 <ops@example.test>: Recipient address rejected\r\n"
            } else if line.starts_with("DATA") {
                if writer.write_all(b"354 go ahead\r\n").is_err() {
                    return;
                }
                let mut data = String::new();
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    if line == ".\r\n" {
                        break;
                    }
                    data.push_str(&line);
                }
                let _ = mail.send(data);
                b"250 2.0.0 queued\r\n"
            } else if line.starts_with("QUIT") {
                b"221 bye\r\n"
            } else {
                b"250 ok\r\n"
            };
            if writer.write_all(reply).is_err() || line.starts_with("QUIT") {
                return;
            }
        }
    }

    /// A fake SMTP server on 127.0.0.1; its port and the messages it took.
    /// Each connection gets its own thread: lettre's pool parks an idle
    /// session beside each send, and it must not stall the one that sends.
    fn fake_smtp_server(reject_rcpt: bool) -> (u16, Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (sender, receiver) = channel();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(8).flatten() {
                let sender = sender.clone();
                std::thread::spawn(move || serve_smtp(stream, reject_rcpt, sender));
            }
        });
        (port, receiver)
    }

    /// Undo quoted-printable (lettre encodes a body with a line past 76
    /// characters); a 7bit body passes through unchanged
    fn unfold(data: &str) -> String {
        data.replace("=\r\n", "").replace("=3D", "=")
    }

    #[test]
    fn ops_alert_lines_and_kinds_are_pinned() {
        assert_eq!(PROT_STORE_NEEDS_UNBOUND, "unbound");
        assert_eq!(PROT_STORE_NEEDS_CHARGEBACK, "chargeback_review");
        assert_eq!(PROT_STORE_NEEDS_UNCONSUMED, "play_unconsumed_24h");
        assert_eq!(PROT_STORE_NEEDS_REVERSED_UNPAID, "reversed_unpaid");
        assert_eq!(PROT_STORE_NEEDS_HELD, "play_held_24h");
        assert_eq!(
            PROT_STORE_LOG_UNDECODABLE_NOTIFICATION,
            "undecodable_notification"
        );
        // Only the log-only kinds are listed; every work-item kind is mailed
        assert_eq!(
            PROT_STORE_LOG_ONLY_KINDS,
            &[PROT_STORE_LOG_UNDECODABLE_NOTIFICATION]
        );
        for kind in [
            PROT_STORE_NEEDS_UNBOUND,
            PROT_STORE_NEEDS_CHARGEBACK,
            PROT_STORE_NEEDS_UNCONSUMED,
            PROT_STORE_NEEDS_REVERSED_UNPAID,
            PROT_STORE_NEEDS_HELD,
        ] {
            assert!(!PROT_STORE_LOG_ONLY_KINDS.contains(&kind), "{kind}");
        }

        let id = play("ab");
        assert_eq!(
            alert_line(PROT_STORE_NEEDS_UNCONSUMED, &id),
            format!("PROT_STORE_ALERT kind=play_unconsumed_24h id={id}")
        );
        assert_eq!(
            mail_failed_line("unbound_play", &id, "send timed out"),
            format!("PROT_STORE_ALERT_MAIL_FAILED kind=unbound_play id={id} reason=send timed out")
        );
    }

    /// No mailbox, or no SMTP: Ok(false), the pinned line still written at
    /// warn level, and nothing tried (no connection, no failure line)
    #[tokio::test]
    async fn ops_alert_is_skipped_without_a_mailbox_or_smtp() {
        capture_log();
        let (port, mail) = fake_smtp_server(false);
        let configured = smtp(i32::from(port)).await;
        let mut no_smtp = configured.clone();
        no_smtp.host = String::new();

        let no_mailbox = play("a1");
        let unconfigured = play("a2");
        assert!(
            !send_ops_alert(&configured, "", PROT_STORE_NEEDS_UNBOUND, &no_mailbox)
                .await
                .unwrap()
        );
        assert!(
            !send_ops_alert(&no_smtp, OPS, PROT_STORE_NEEDS_UNBOUND, &unconfigured)
                .await
                .unwrap()
        );

        // A log-only kind is never mailed, even with a mailbox and SMTP (R61)
        let log_only = play("a3");
        assert!(!send_ops_alert(
            &configured,
            OPS,
            PROT_STORE_LOG_UNDECODABLE_NOTIFICATION,
            &log_only
        )
        .await
        .unwrap());

        assert!(mail.recv_timeout(Duration::from_millis(300)).is_err());
        for (kind, id, reason) in [
            (PROT_STORE_NEEDS_UNBOUND, &no_mailbox, "no_mailbox"),
            (
                PROT_STORE_NEEDS_UNBOUND,
                &unconfigured,
                "smtp_not_configured",
            ),
            (
                PROT_STORE_LOG_UNDECODABLE_NOTIFICATION,
                &log_only,
                "log_only",
            ),
        ] {
            assert_eq!(alerts(kind, id), 1, "{reason}");
            assert_eq!(
                lines(SKIPPED, id),
                vec![(
                    log::Level::Info,
                    format!("PROT_STORE_ALERT_MAIL_SKIPPED kind={kind} id={id} reason={reason}")
                )]
            );
            assert!(lines(FAILED, id).is_empty(), "{reason}");
            assert!(lines(SENT, id).is_empty(), "{reason}");
        }
    }

    /// Sections 19 + 28: every broken input is Ok(false) and one failure line,
    /// never a panic, and the caller reaches every alert. Control: call
    /// send_email instead and the invalid from-address panics here.
    #[tokio::test]
    async fn ops_alert_never_panics() {
        capture_log();
        // Nothing listens on 127.0.0.1:1
        let base = smtp(1).await;
        let mut cases: Vec<(&str, ApiSmtp, &str)> = Vec::new();

        let mut broken = base.clone();
        broken.from_address = "not an address".to_string();
        cases.push(("invalid from_address", broken, OPS));

        let mut broken = base.clone();
        broken.reply_to = Some("not an address either".to_string());
        cases.push(("invalid reply_to", broken, OPS));

        let mut broken = base.clone();
        broken.port = Some(-1);
        cases.push(("negative port", broken, OPS));

        let mut broken = base.clone();
        broken.port = Some(70_000);
        cases.push(("port out of range", broken, OPS));

        cases.push(("invalid mailbox", base.clone(), "ops at example"));
        cases.push(("send failure", base.clone(), OPS));

        let mut reached = 0;
        for (n, (what, smtp, to)) in cases.iter().enumerate() {
            let id = format!("apple:prod:{}", 3_000_000_000_000_000_u64 + n as u64);
            let sent = send_ops_alert(smtp, to, PROT_STORE_NEEDS_REVERSED_UNPAID, &id).await;
            assert!(matches!(sent, Ok(false)), "{what}: {sent:?}");
            assert_eq!(
                alerts(PROT_STORE_NEEDS_REVERSED_UNPAID, &id),
                1,
                "{what}: the alert line is written whatever the mail does"
            );
            let failed = lines(FAILED, &id);
            assert_eq!(failed.len(), 1, "{what}: {failed:?}");
            assert_eq!(failed[0].0, log::Level::Error, "{what}");
            assert!(!failed[0].1.contains('@'), "{what}: {failed:?}");
            reached += 1;
        }
        assert_eq!(reached, 6, "the caller reached every alert");
    }

    /// A panic or a hang on the blocking pool is an answer, not a crash
    #[tokio::test]
    async fn ops_alert_send_task_failures_are_answers() {
        assert_eq!(
            run_blocking_send(SEND_DEADLINE, || panic!("send exploded")).await,
            Err("send task panicked".to_string())
        );
        assert_eq!(
            run_blocking_send(Duration::from_millis(20), || {
                std::thread::sleep(Duration::from_secs(1));
                Ok(())
            })
            .await,
            Err("send timed out".to_string())
        );
        assert_eq!(run_blocking_send(SEND_DEADLINE, || Ok(())).await, Ok(()));
    }

    #[tokio::test]
    async fn ops_alert_mails_the_staff_mailbox() {
        capture_log();
        let (port, mail) = fake_smtp_server(false);
        let id = play("c3");

        let sent = send_ops_alert(
            &smtp(i32::from(port)).await,
            OPS,
            PROT_STORE_NEEDS_UNCONSUMED,
            &id,
        )
        .await
        .unwrap();
        assert!(sent);

        let data = unfold(
            &mail
                .recv_timeout(Duration::from_secs(10))
                .expect("the fake server took the message"),
        );
        assert!(
            data.contains("Subject: Sloga store alert: play_unconsumed_24h\r\n"),
            "{data}"
        );
        assert!(data.contains("To: ops@example.test\r\n"), "{data}");
        assert!(
            data.contains("Content-Type: text/plain; charset=utf-8\r\n"),
            "{data}"
        );
        assert!(!data.contains("multipart"), "{data}");
        assert!(data.contains("Kind: play_unconsumed_24h\r\n"), "{data}");
        assert!(data.contains(&format!("Purchase: {id}\r\n")), "{data}");
        assert!(
            data.contains(&format!("Admin route: GET /admin/prot/store/{id}\r\n")),
            "{data}"
        );
        assert!(
            data.contains("Work list: GET /admin/prot/store?needs_action=true\r\n"),
            "{data}"
        );

        assert_eq!(alerts(PROT_STORE_NEEDS_UNCONSUMED, &id), 1);
        assert_eq!(
            lines(SENT, &id),
            vec![(
                log::Level::Info,
                format!("PROT_STORE_ALERT_MAIL_SENT kind=play_unconsumed_24h id={id}")
            )]
        );
        assert!(lines(FAILED, &id).is_empty());
    }

    /// A 550's reply text quotes the mailbox; the failure line carries the
    /// class and code only
    #[tokio::test]
    async fn ops_alert_failure_log_never_contains_the_address() {
        capture_log();
        let (port, mail) = fake_smtp_server(true);
        let id = play("d4");

        let sent = send_ops_alert(
            &smtp(i32::from(port)).await,
            OPS,
            PROT_STORE_NEEDS_CHARGEBACK,
            &id,
        )
        .await
        .unwrap();
        assert!(!sent);
        assert!(mail.try_recv().is_err());

        assert_eq!(alerts(PROT_STORE_NEEDS_CHARGEBACK, &id), 1);
        assert_eq!(
            lines(FAILED, &id),
            vec![(
                log::Level::Error,
                format!(
                    "PROT_STORE_ALERT_MAIL_FAILED kind=chargeback_review id={id} \
                     reason=smtp send: permanent code=550"
                )
            )]
        );
        assert!(lines(SENT, &id).is_empty());
    }

    /// Install the S5a, S5b and S6 indexes on MongoDB with the migration's
    /// own helpers and create every collection up front, so no transaction
    /// has to create one. The reference driver needs no setup.
    async fn install_indexes(db: &Database) {
        match db {
            Database::Reference(_) => {}
            #[cfg(feature = "mongodb")]
            Database::MongoDb(mongo) => {
                for collection in crate::PROT_COLLECTIONS
                    .iter()
                    .chain(crate::PROT_TANK_COLLECTIONS.iter())
                    .chain(crate::PROT_STORE_COLLECTIONS.iter())
                {
                    mongo.db().create_collection(*collection).await.ok();
                }
                crate::create_prot_indexes(&mongo.db())
                    .await
                    .expect("failed to create the Prot ledger indexes");
                crate::create_prot_tank_indexes(&mongo.db())
                    .await
                    .expect("failed to create the Prot tank indexes");
                crate::create_prot_store_indexes(&mongo.db())
                    .await
                    .expect("failed to create the Prot store indexes");
            }
        }
    }

    /// An unbound Play purchase, written the way the engine writes one
    /// (plan, build, one move)
    async fn unbound_play_row(db: &Database, id: &str) -> ProtStorePurchase {
        let seed = ProtStorePurchase {
            id: id.to_string(),
            store: v0::ProtStore::Play,
            user_id: None,
            intent_id: None,
            product_id: "gg.sloga.prot.p25".to_string(),
            prot: 2_600,
            quantity: 1,
            environment: v0::ProtStoreEnvironment::Production,
            storefront: None,
            country: None,
            state: v0::ProtStoreState::Rejected,
            reject_reason: None,
            refund_gen: 0,
            refunds: vec![],
            unreinstated_reversals: 0,
            apple: None,
            play: Some(ProtStorePlay {
                purchase_token: format!("token-{id}"),
                order_id: None,
                obfuscated_account_id: None,
                consumed_at: None,
                test: false,
                region_code: None,
            }),
            credited_at: None,
            unconsumed: None,
            revoked_at: None,
            revocation_reason: None,
            assigned_by: None,
            needs_action: None,
            alerted: vec![],
            created_at: NOW,
            updated_at: NOW,
            version: 0,
        };
        let event = ProtStoreEvent::Seen(ProtStoreVerdict::Reject {
            reason: v0::ProtStoreRejectReason::Unbound,
            user_id: None,
            intent_id: None,
        });
        let plan = plan_store_move(None, &event, 0);
        let m = build_store_move(None, &seed, &event, &plan, 0, NOW)
            .expect("an unbound purchase is written");
        match db.apply_store_purchase_move(&m).await.unwrap() {
            ProtStoreMoveOutcome::Applied { row, .. } => row,
            ProtStoreMoveOutcome::Conflict => panic!("a fresh row cannot conflict"),
        }
    }

    /// What a caller does (16 step 2, audit 17): the work item first, then
    /// the claim; only the claim's winner raises the alert
    async fn raise(db: &Database, smtp: &ApiSmtp, id: &str, kind: &str) -> bool {
        db.set_prot_store_needs_action(id, kind, NOW).await.unwrap();
        if !db.claim_prot_store_alert(id, kind).await.unwrap() {
            return false;
        }
        assert!(!send_ops_alert(smtp, "", kind, id).await.unwrap());
        true
    }

    /// Section 19 dedupe through both drivers: racing replicas alert a row
    /// once per kind; another kind, or another row, is alerted on its own
    #[tokio::test]
    async fn alert_is_raised_once_per_row_and_kind() {
        capture_log();
        database_test!(|db| async move {
            install_indexes(&db).await;
            let smtp = smtp(1).await;
            let first = play("e5");
            let second = play("f6");
            let absent = play("07");

            let row = unbound_play_row(&db, &first).await;
            // The planner's work item is this module's string
            assert_eq!(row.needs_action.as_deref(), Some(PROT_STORE_NEEDS_UNBOUND));
            unbound_play_row(&db, &second).await;

            let raised =
                join_all((0..10).map(|_| raise(&db, &smtp, &first, PROT_STORE_NEEDS_UNCONSUMED)))
                    .await;
            assert_eq!(raised.iter().filter(|won| **won).count(), 1, "{raised:?}");
            assert_eq!(alerts(PROT_STORE_NEEDS_UNCONSUMED, &first), 1);

            // Another kind on the same row
            assert!(raise(&db, &smtp, &first, PROT_STORE_NEEDS_CHARGEBACK).await);
            assert!(!raise(&db, &smtp, &first, PROT_STORE_NEEDS_CHARGEBACK).await);
            assert_eq!(alerts(PROT_STORE_NEEDS_CHARGEBACK, &first), 1);

            // The same kind on another row
            assert!(raise(&db, &smtp, &second, PROT_STORE_NEEDS_UNCONSUMED).await);
            assert_eq!(alerts(PROT_STORE_NEEDS_UNCONSUMED, &second), 1);

            // No row, no alert
            assert!(!raise(&db, &smtp, &absent, PROT_STORE_NEEDS_UNCONSUMED).await);
            assert_eq!(alerts(PROT_STORE_NEEDS_UNCONSUMED, &absent), 0);

            let stored = db.fetch_prot_store_purchase(&first).await.unwrap().unwrap();
            assert_eq!(
                stored.alerted,
                vec![
                    PROT_STORE_NEEDS_UNCONSUMED.to_string(),
                    PROT_STORE_NEEDS_CHARGEBACK.to_string()
                ]
            );
            // One kind at a time: the later set overwrote (section 5)
            assert_eq!(
                stored.needs_action.as_deref(),
                Some(PROT_STORE_NEEDS_CHARGEBACK)
            );
        });
    }

    /// The production half of this file never reaches a panicking helper
    #[test]
    fn prot_store_alert_never_calls_send_email() {
        let source = include_str!("prot_store_alert.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for needle in [
            "send_email(",
            "create_transport(",
            ".unwrap(",
            ".expect(",
            "panic!(",
            "unreachable!(",
            "block_on(",
        ] {
            assert!(!production.contains(needle), "{needle}");
        }
    }
}
