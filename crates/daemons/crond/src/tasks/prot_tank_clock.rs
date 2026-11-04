//! Hourly fuel-tank clock (S5b): pause bookkeeping, burns with catch-up, stage moves, deletion (guarded), pending
//! downgrades, notices, second purge pass. No-op loop unless enabled + burn_enabled (D16 records the pause).
//!
//! Every step is `revolt_payments::engine::tank::clock_tick` (contracts
//! 7.1); this task only runs it once an hour for as long as crond runs.
//!
//! The task checks no flag of its own. `clock_tick` reads the Prot config on
//! every tick, and with burning off (`enabled && burn_enabled` false) it still
//! has work to do: it records the pause, so the days the switch was off are
//! never billed once it is back on (D16), and it finishes settlements and
//! purges that had already started. A gate here, even on `enabled` alone,
//! would skip the pause, and the first tick after the switch came back would
//! bill every missed day as an outage catch-up.
//!
//! Nor does the task ever return: `cron_task_wrapper` treats a returning task
//! as a failure and restarts it every 60 s with an error each time, so an
//! early return is not a no-op (prune_expired_boosts.rs). The tick logs its
//! own failures, per tank, and the next tick starts over.
//!
//! crond has no leader election. Two replicas ticking at once is safe: every
//! clock write is a compare-and-swap on the tank or a unique ledger key
//! (`burn:{tank}:{day}`), so a day is billed once.
//!
//! The config is frozen into the process at first access, so turning burning
//! on or off takes a crond restart.

use std::{future::Future, time::Duration};

use revolt_database::{Database, AMQP};
use revolt_payments::engine;
use revolt_result::Result;
use tokio::time::sleep;

/// Time between ticks
const TICK: Duration = Duration::from_secs(60 * 60);

/// Run the clock every [`TICK`]. Never returns: while burning is off each
/// tick is the pause bookkeeping (see the module docs).
pub async fn task(db: Database, amqp: AMQP) -> Result<()> {
    let (db, amqp) = (&db, &amqp);
    run(TICK, move || async move {
        engine::tank::clock_tick(db, amqp, revolt_database::now_ms()).await;
    })
    .await
}

/// Call `tick`, then sleep `period`, forever. Nothing leaves the loop: the
/// tick handles its own failures. Tests pass a counting tick, because an
/// [`AMQP`] cannot be built without a broker.
async fn run<F, Fut>(period: Duration, mut tick: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    loop {
        tick().await;
        sleep(period).await;
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    const SOURCE: &str = include_str!("prot_tank_clock.rs");

    /// The code of the item that starts at `head`, up to its closing brace
    /// at column 0, without comment lines
    fn item(head: &str) -> String {
        let start = SOURCE
            .find(head)
            .unwrap_or_else(|| panic!("`{head}` is in the file"));
        let len = SOURCE[start..]
            .find("\n}\n")
            .unwrap_or_else(|| panic!("`{head}` is closed"));
        SOURCE[start..start + len]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The loop runs tick after tick and never returns. Under the test
    /// config burning is off (`burn_enabled` is not set), so an early return
    /// on the burning flag added to `run` ends this loop at once.
    #[tokio::test]
    async fn the_clock_loop_never_returns() {
        let ticks = Cell::new(0_u32);
        let outcome = tokio::time::timeout(
            Duration::from_millis(500),
            run(Duration::from_millis(10), || {
                ticks.set(ticks.get() + 1);
                std::future::ready(())
            }),
        )
        .await;

        assert!(outcome.is_err(), "the clock loop returned: {outcome:?}");
        assert!(ticks.get() >= 3, "only {} ticks in 500 ms", ticks.get());
    }

    /// The shape the wrapper and D16 need, pinned in the text: `task` hands
    /// the engine tick to `run` with no flag check of its own, and `run` is
    /// a sleep-in-loop with no way out (prune_expired_boosts.rs). An early
    /// `return Ok(())` when Prot is disabled, in either function, fails it;
    /// so does a `sleep; continue` gate, which would skip the pause.
    #[test]
    fn the_clock_task_is_a_sleep_in_loop() {
        let task = item("pub async fn task(");
        let run = item("async fn run<");

        assert!(
            task.contains("engine::tank::clock_tick(db, amqp, revolt_database::now_ms()).await;"),
            "{task}"
        );
        assert!(task.contains("run(TICK,"), "{task}");
        assert!(run.contains("loop {"), "{run}");
        assert!(run.contains("tick().await;"), "{run}");
        assert!(run.contains("sleep(period).await;"), "{run}");

        for (name, code) in [("task", &task), ("run", &run)] {
            for exit in ["return", "break", "continue", "?", "if "] {
                assert!(
                    !code.contains(exit),
                    "`{exit}` in {name}: the clock loop must tick every hour, whatever the flags \
                     say, and never end\n{code}"
                );
            }
        }

        assert_eq!(TICK, Duration::from_secs(60 * 60));
    }
}
