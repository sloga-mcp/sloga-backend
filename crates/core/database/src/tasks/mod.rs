//! Semi-important background task management

use crate::{Database, AMQP};

use futures::FutureExt;
use std::{
    any::Any,
    future::Future,
    panic::AssertUnwindSafe,
    time::{Duration, Instant},
};
use tokio::task;

const WORKER_COUNT: usize = 5;

/// Shortest delay before a failed worker is restarted.
const MIN_BACKOFF: Duration = Duration::from_secs(1);

/// Longest delay between restarts of a worker that keeps failing.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// A worker that ran at least this long before failing counts as having been
/// healthy, so its restart delay drops back to the minimum.
const HEALTHY_RUN: Duration = Duration::from_secs(60);

pub mod ack;
pub mod last_message_id;
pub mod process_embeds;

/// Spawn background workers
pub fn start_workers(db: Database, amqp: AMQP) {
    for _ in 0..WORKER_COUNT {
        task::spawn(supervise("ack", MIN_BACKOFF, {
            let (db, amqp) = (db.clone(), amqp.clone());
            move || ack::worker(db.clone(), amqp.clone())
        }));
        task::spawn(supervise("last_message_id", MIN_BACKOFF, {
            let db = db.clone();
            move || last_message_id::worker(db.clone())
        }));
        task::spawn(supervise("process_embeds", MIN_BACKOFF, {
            let db = db.clone();
            move || process_embeds::worker(db.clone())
        }));
    }
}

/// Read the message out of a panic payload.
///
/// Call this as `panic_message(&*payload)`. Passing `&payload` for a
/// `Box<dyn Any + Send>` also compiles, but it unsizes the `Box` itself into
/// the trait object, so neither downcast matches and the fallback is returned
/// silently.
pub(crate) fn panic_message(payload: &(dyn Any + Send)) -> &str {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        s
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.as_str()
    } else {
        "<non-string panic payload>"
    }
}

/// Run a background worker forever, restarting it whenever it exits or panics.
///
/// A panicking worker used to be gone for the life of the process, taking its
/// in-memory debounce map with it. This restarts it after a delay that doubles
/// on each consecutive failure (capped at [`MAX_BACKOFF`]) and resets to
/// `min_backoff` once a run lasted at least [`HEALTHY_RUN`].
///
/// Only a panic inside the future returned by `make` is caught, so `make`
/// itself must not panic synchronously; the async worker fns cannot.
async fn supervise<F, Fut>(name: &'static str, min_backoff: Duration, make: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut backoff = min_backoff;

    loop {
        let start = Instant::now();
        let fut = AssertUnwindSafe(make());
        let outcome = fut.catch_unwind().await;

        // The payload is moved into its match arm and dropped when the arm
        // ends, so only the owned message lives across the awaits below.
        let msg = match outcome {
            Ok(()) => format!("{name} worker exited unexpectedly; restarting"),
            Err(payload) => format!(
                "{name} worker panicked: {}; restarting",
                panic_message(&*payload)
            ),
        };

        error!("{msg}");
        revolt_config::capture_message(&msg, revolt_config::Level::Error);

        if start.elapsed() >= HEALTHY_RUN {
            backoff = min_backoff;
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Task with additional information on when it should run
pub struct DelayedTask<T> {
    pub data: T,
    run_now: bool,
    last_updated: Instant,
    first_seen: Instant,
}

/// Commit to database every 30 seconds if the task is particularly active.
static EXPIRE_CONSTANT: u64 = 30;

/// Otherwise, commit to database after 5 seconds.
static SAVE_CONSTANT: u64 = 5;

impl<T> DelayedTask<T> {
    /// Create a new delayed task
    pub fn new(data: T) -> Self {
        DelayedTask {
            data,
            run_now: false,
            last_updated: Instant::now(),
            first_seen: Instant::now(),
        }
    }

    /// Push a task further back in time
    pub fn delay(&mut self) {
        self.last_updated = Instant::now()
    }

    /// Flag the task to run right away, regardless of the time
    pub fn run_immediately(&mut self) {
        self.run_now = true
    }

    /// Check if a task should run yet
    pub fn should_run(&self) -> bool {
        self.run_now
            || self.first_seen.elapsed().as_secs() > EXPIRE_CONSTANT
            || self.last_updated.elapsed().as_secs() > SAVE_CONSTANT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering::SeqCst},
        Arc,
    };

    #[tokio::test]
    async fn supervise_restarts_a_panicking_worker() {
        let c = Arc::new(AtomicUsize::new(0));
        let c2 = c.clone();
        let make = move || {
            let n = c2.fetch_add(1, SeqCst);
            async move {
                if n == 0 {
                    panic!("supervise-test intentional panic")
                }
                std::future::pending::<()>().await
            }
        };

        let handle = task::spawn(supervise("test", Duration::from_millis(10), make));

        let deadline = Instant::now() + Duration::from_secs(2);
        while c.load(SeqCst) < 2 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let starts = c.load(SeqCst);
        handle.abort();

        assert_eq!(starts, 2, "the worker was not restarted after it panicked");
    }

    #[tokio::test]
    async fn panic_message_reads_str_and_string_payloads() {
        let payload = std::panic::catch_unwind(|| panic!("lit")).unwrap_err();
        assert_eq!(panic_message(&*payload), "lit");

        let payload = std::panic::catch_unwind(|| panic!("{}", String::from("owned"))).unwrap_err();
        assert_eq!(panic_message(&*payload), "owned");

        let payload = std::panic::catch_unwind(|| std::panic::panic_any(42u8)).unwrap_err();
        assert_eq!(panic_message(&*payload), "<non-string panic payload>");
    }
}
