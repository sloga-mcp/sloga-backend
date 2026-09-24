use std::{
    env, io,
    time::{Duration, Instant},
};

use tokio::net::TcpListener;
use revolt_presence::clear_region;

#[macro_use]
extern crate log;

pub mod config;
pub mod events;

mod database;
mod websocket;

/// How often a run of failing accepts, or the recovery from one, may be
/// reported to Sentry.
const ACCEPT_ERROR_REPORT_INTERVAL: Duration = Duration::from_secs(600);

/// How long to wait after a failed accept, or `None` to try the next one at once.
///
/// The errors that only cost one connection (the peer went away before we took
/// it) are skipped. Anything else - EMFILE/ENFILE/ENOBUFS/ENOMEM, or a broken
/// listener - leaves the listener readable, so retrying at once would spin;
/// wait a second instead, as axum's `serve` does.
fn accept_backoff(err: &io::Error) -> Option<Duration> {
    match err.kind() {
        io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::Interrupted => None,
        _ => Some(Duration::from_secs(1)),
    }
}

#[tokio::main]
async fn main() {
    // Configure requirements for Bonfire.
    revolt_config::configure!(events);
    database::connect().await;

    // Clean up the current region information.
    let no_clear_region = env::var("NO_CLEAR_PRESENCE").unwrap_or_else(|_| "0".into()) == "1";
    if !no_clear_region {
        clear_region(None).await;
    }

    // Setup a TCP listener to accept WebSocket connections on.
    // By default, we bind to port 14703 on all interfaces.
    let bind = env::var("HOST").unwrap_or_else(|_| "0.0.0.0:14703".into());
    info!("Listening on host {bind}");
    let try_socket = TcpListener::bind(bind).await;
    let listener = try_socket.expect("Failed to bind");

    // Accept connections forever. Leaving this loop returns from `main`, which
    // drops the runtime and disconnects every connected client.
    //
    // Sentry needs file descriptors to send, so a report made while we are out
    // of them is likely lost; the log line is the reliable signal, and the
    // recovery report is the one that can get through.
    let mut failed_accepts: u64 = 0;
    let mut last_failure_reported: Option<Instant> = None;
    let mut last_recovery_reported: Option<Instant> = None;
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                if failed_accepts > 0 {
                    info!("Accepting connections again after {failed_accepts} failed accept(s)");
                    if last_recovery_reported
                        .is_none_or(|at| at.elapsed() >= ACCEPT_ERROR_REPORT_INTERVAL)
                    {
                        last_recovery_reported = Some(Instant::now());
                        sentry::capture_message(
                            &format!(
                                "bonfire accepted connections again after {failed_accepts} failed accept(s)"
                            ),
                            sentry::Level::Warning,
                        );
                    }
                    failed_accepts = 0;
                }

                tokio::task::spawn(async move {
                    info!("User connected from {addr:?}");
                    websocket::client(database::get_db(), stream, addr).await;
                    info!("User disconnected from {addr:?}");
                });
            }
            Err(err) => match accept_backoff(&err) {
                None => debug!("Skipped a connection that failed before it was accepted: {err}"),
                Some(delay) => {
                    failed_accepts += 1;
                    error!("Failed to accept a connection, retrying in {delay:?}: {err}");
                    if last_failure_reported
                        .is_none_or(|at| at.elapsed() >= ACCEPT_ERROR_REPORT_INTERVAL)
                    {
                        last_failure_reported = Some(Instant::now());
                        sentry::capture_message(
                            &format!("bonfire failed to accept a connection: {err}"),
                            sentry::Level::Error,
                        );
                    }
                    tokio::time::sleep(delay).await;
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{io, time::Duration};

    use super::accept_backoff;

    #[test]
    fn connection_errors_move_on_at_once() {
        for kind in [
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::Interrupted,
        ] {
            assert_eq!(accept_backoff(&io::Error::from(kind)), None, "{kind:?}");
        }
    }

    /// Real Linux errnos, so this also pins std's errno -> ErrorKind mapping.
    #[cfg(target_os = "linux")]
    #[test]
    fn errnos_are_classified() {
        // ECONNABORTED, ECONNRESET, ECONNREFUSED, EINTR
        for errno in [103, 104, 111, 4] {
            assert_eq!(accept_backoff(&io::Error::from_raw_os_error(errno)), None, "errno {errno}");
        }
        // EMFILE, ENFILE, ENOBUFS, ENOMEM, EPERM, EBADF, EINVAL, ENOTSOCK
        for errno in [24, 23, 105, 12, 1, 9, 22, 88] {
            assert_eq!(
                accept_backoff(&io::Error::from_raw_os_error(errno)),
                Some(Duration::from_secs(1)),
                "errno {errno}"
            );
        }
    }
}
