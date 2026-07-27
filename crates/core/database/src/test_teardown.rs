//! Teardown for the throwaway databases the test harnesses create.
//!
//! With `TEST_DB=MONGODB`, `DatabaseInfo::Auto` mints a fresh
//! `revolt_test_<n>` database for every `TestHarness::new()`, and
//! `database_test!` mints one named after the source file and line. Nothing
//! deleted them, so they accumulated across every run ever made.
//!
//! That is not cosmetic. At 1191 leftover databases (observed 2026-07-27) the
//! mongod instance was slow enough that harness boot *alone* blew nextest's
//! kill threshold (`.config/nextest.toml`: a 5s slow period terminated after
//! 10 periods = 50s). A full delta run failed across account, bots, channels
//! and e2ee at once and read exactly like a mass code regression. It was
//! leftover databases; dropping them made the suite green again.
//!
//! This module is compiled only under `cfg(test)` or the `test-teardown`
//! feature, so no code capable of dropping a database is linked into a
//! production binary.

use std::time::Duration;

/// Database name used by production. Nothing here may ever drop it.
pub const PRODUCTION_DATABASE: &str = "revolt";

/// Longest a teardown may block before it gives up and reports a leak.
///
/// Bounded because teardown time counts against nextest's `terminate-after`
/// budget: a wedged mongod must not convert a passing test into a SIGKILL.
const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether `name` is a throwaway database minted by one of the test harnesses.
///
/// Deliberately an allow-list rather than a deny-list: anything this does not
/// recognise is left alone. `revolt` can never match — it is rejected by name
/// first, and it also fails every pattern below.
pub fn is_throwaway_test_database(name: &str) -> bool {
    if name == PRODUCTION_DATABASE {
        return false;
    }

    // `DatabaseInfo::Auto` with `TEST_DB` set, i.e. delta's `TestHarness`:
    // `revolt_test_` plus a random 7-digit number.
    let harness_database = name
        .strip_prefix("revolt_test_")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()));

    // `database_test!`, which names the database after its own call site:
    // the source path with `/` replaced by `_`, then `:` and the line number.
    let macro_database = name
        .rsplit_once(':')
        .is_some_and(|(path, line)| {
            path.starts_with("crates_")
                && !line.is_empty()
                && line.bytes().all(|b| b.is_ascii_digit())
        });

    harness_database || macro_database
}

/// Drop `database_name` from the mongod at `uri`.
#[cfg(feature = "mongodb")]
async fn drop_throwaway(uri: &str, database_name: &str) -> Result<(), String> {
    // Re-checked here as well as at every call site: this is the last point
    // before an irreversible operation.
    if !is_throwaway_test_database(database_name) {
        return Err(format!(
            "refusing to drop `{database_name}`: not a recognisable throwaway test database"
        ));
    }

    ::mongodb::Client::with_uri_str(uri)
        .await
        .map_err(|err| format!("could not connect for teardown: {err}"))?
        .database(database_name)
        .drop()
        .await
        .map_err(|err| format!("could not drop `{database_name}`: {err}"))
}

/// Drop a throwaway test database, blocking until it is gone.
///
/// Safe to call from a `Drop` impl inside a tokio runtime. The work runs on a
/// dedicated OS thread with its own current-thread runtime and a *fresh*
/// mongo client, so it never re-enters the caller's reactor, never depends on
/// the caller's runtime flavour (`block_in_place` would require multi-thread;
/// this does not) and never borrows connections registered with a reactor
/// that may be shutting down.
///
/// Never panics. A `Drop` that panics while the thread is already unwinding
/// from a failed assertion aborts the process and buries the real failure, so
/// every error path here reports and swallows.
pub fn drop_test_database_blocking(uri: &str, database_name: &str) {
    #[cfg(not(feature = "mongodb"))]
    {
        let _ = (uri, database_name);
    }

    #[cfg(feature = "mongodb")]
    {
        if !is_throwaway_test_database(database_name) {
            eprintln!(
                "test teardown: refusing to drop `{database_name}` \
                 (not a recognisable throwaway test database)"
            );
            return;
        }

        let uri = uri.to_owned();
        let name = database_name.to_owned();

        let outcome = std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => return Err(format!("could not build teardown runtime: {err}")),
            };

            runtime.block_on(async {
                tokio::time::timeout(TEARDOWN_TIMEOUT, drop_throwaway(&uri, &name))
                    .await
                    .unwrap_or_else(|_| Err(format!("timed out after {TEARDOWN_TIMEOUT:?}")))
            })
        })
        .join();

        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                eprintln!("test teardown: {err} — `{database_name}` leaked")
            }
            Err(_) => eprintln!(
                "test teardown: teardown thread panicked — `{database_name}` leaked"
            ),
        }
    }
}

/// Drops a throwaway test database when it goes out of scope, including when
/// the scope is left by unwinding.
///
/// `database_test!` already dropped its database on the happy path, but that
/// call is skipped when the test body panics. The guard covers the unwind
/// path; the happy path calls [`TestDatabaseGuard::disarm`] after the cheaper
/// async drop, so the database is not dropped twice.
///
/// This does not close the macro's *other* leak. It names its database after
/// its own call site — `<source path>:<line>` — so moving the invocation
/// orphans the old database permanently: no later run ever generates that
/// name again, and nothing will ever collect it. That is what the stray
/// `crates_core_database_src_models_channel_follows_ops:70` and `:71` are;
/// both invocations in that file now sit on lines 79 and 190. Only the sweep
/// in `scripts/drop-test-databases.sh` can clear those.
pub struct TestDatabaseGuard {
    /// `(uri, database_name)` while armed. `None` once disarmed, and always
    /// `None` for the reference driver, which leaves nothing behind.
    target: Option<(String, String)>,
}

impl TestDatabaseGuard {
    /// Arm a guard for `db`. No-op for the in-memory reference driver.
    pub async fn arm(db: &crate::Database) -> TestDatabaseGuard {
        #[cfg(feature = "mongodb")]
        if let crate::Database::MongoDb(mongo) = db {
            // Read the URI now: `Drop` cannot await `config()`.
            let uri = revolt_config::config().await.database.mongodb;
            return TestDatabaseGuard {
                target: Some((uri, mongo.1.clone())),
            };
        }

        let _ = db;
        TestDatabaseGuard { target: None }
    }

    /// Give up ownership of the cleanup, because it has already happened.
    pub fn disarm(mut self) {
        self.target = None;
    }
}

impl Drop for TestDatabaseGuard {
    fn drop(&mut self) {
        if let Some((uri, name)) = self.target.take() {
            drop_test_database_blocking(&uri, &name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{is_throwaway_test_database, PRODUCTION_DATABASE};

    #[test]
    fn never_matches_production() {
        assert!(!is_throwaway_test_database(PRODUCTION_DATABASE));
        assert!(!is_throwaway_test_database("revolt"));
    }

    #[test]
    fn matches_harness_databases() {
        assert!(is_throwaway_test_database("revolt_test_1909289"));
        assert!(is_throwaway_test_database("revolt_test_8650800"));
    }

    #[test]
    fn matches_macro_databases() {
        assert!(is_throwaway_test_database(
            "crates_core_database_src_models_channel_follows_ops:70"
        ));
        assert!(is_throwaway_test_database(
            "crates_core_database_src_models_users_model:1234"
        ));
    }

    #[test]
    fn rejects_everything_else() {
        // Neighbours of the real names, which is where a bad prefix check bites.
        assert!(!is_throwaway_test_database("revolt_testing"));
        assert!(!is_throwaway_test_database("revolt_test_"));
        assert!(!is_throwaway_test_database("revolt_test_prod"));
        assert!(!is_throwaway_test_database("revolt_backup"));
        assert!(!is_throwaway_test_database("crates_something"));
        assert!(!is_throwaway_test_database("crates_something:"));
        assert!(!is_throwaway_test_database("admin"));
        assert!(!is_throwaway_test_database("config"));
        assert!(!is_throwaway_test_database("local"));
        assert!(!is_throwaway_test_database(""));
    }
}
