//! Throttle on what delta sends to an import source's API, shared across
//! every session and user.
//!
//! The route ratelimit keys on the session, and one user can hold many, so
//! it does not bound outbound calls. Stoat's `servers` bucket is 5 requests
//! / 10 s per (bot, server id) and crond's import fetch spends from it too:
//! anyone able to make delta call it at will could keep another user's
//! verification, and their import, at 429 just by naming their server.
//! Three budgets are checked after every local refusal and before each
//! upstream call. For Stoat:
//!
//! - per user: one verification per 30 s;
//! - per target: two calls per 10 s for one server id, and for an invite
//!   code (checked before the invite is resolved);
//! - global: ten calls per 10 s from delta, which protects the operator's
//!   bot account and the shared IP the unauthenticated invite lookup
//!   leaves from.
//!
//! Every source has its own keys and its own budgets
//! ([`UpstreamThrottle::for_source`]): calls to one platform never spend
//! another's. Fluxer allows two verifications per user per 30 s (a quick
//! retry after fixing the role is not mistaken for an outage) and five
//! calls per target per 10 s (one verification makes up to five calls on
//! the guild id); its global budget is the same size as Stoat's, on its own
//! key.
//!
//! The budgets live in Redis, so a restart does not reset them and every
//! delta process shares them. One script checks every budget before it
//! records against any, so a refused call spends nothing and parallel
//! requests cannot all slip past. A Redis failure refuses the call.

use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use redis_kiss::get_connection;
use redis_kiss::redis::Script;
use revolt_result::{create_error, Result};

/// At most `limit` calls in any `window_ms`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Budget {
    limit: u32,
    window_ms: i64,
}

/// Stoat's budgets
const PER_USER: Budget = Budget {
    limit: 1,
    window_ms: 30_000,
};
const PER_TARGET: Budget = Budget {
    limit: 2,
    window_ms: 10_000,
};
const GLOBAL: Budget = Budget {
    limit: 10,
    window_ms: 10_000,
};

/// Fluxer's budgets
const FLUXER_PER_USER: Budget = Budget {
    limit: 2,
    window_ms: 30_000,
};
const FLUXER_PER_TARGET: Budget = Budget {
    limit: 5,
    window_ms: 10_000,
};
const FLUXER_GLOBAL: Budget = Budget {
    limit: 10,
    window_ms: 10_000,
};

/// The three budgets of one source
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceBudgets {
    per_user: Budget,
    per_target: Budget,
    global: Budget,
}

const STOAT_BUDGETS: SourceBudgets = SourceBudgets {
    per_user: PER_USER,
    per_target: PER_TARGET,
    global: GLOBAL,
};
const FLUXER_BUDGETS: SourceBudgets = SourceBudgets {
    per_user: FLUXER_PER_USER,
    per_target: FLUXER_PER_TARGET,
    global: FLUXER_GLOBAL,
};

/// Prefix of every live key; a source's keys are `<this>:<tag>:…`
const LIVE_NAMESPACE: &str = "import_upstream";

/// The key segment and budgets for the source tagged `tag`. A tag with no
/// arm of its own still gets keys of its own (its tag), with Stoat's
/// budgets, the strictest: a source added without a row here is throttled
/// harder than it needs, never shares another source's budget, and never
/// runs unthrottled.
fn source_budgets(tag: &'static str) -> (&'static str, SourceBudgets) {
    match tag {
        "stoat" => ("stoat", STOAT_BUDGETS),
        "fluxer" => ("fluxer", FLUXER_BUDGETS),
        other => (other, STOAT_BUDGETS),
    }
}

/// Sliding windows, one sorted set per key, scored by milliseconds.
///
/// `ARGV[1]` is a unique member and `ARGV[2]` the time; then per key `i`,
/// `ARGV[3i]` the limit, `ARGV[3i+1]` the cutoff (time minus window) and
/// `ARGV[3i+2]` the window. Returns the index of the first key at its
/// limit, having recorded nothing, or 0 after recording against every key.
/// Every write refreshes the key's expiry, so no key outlives its window.
/// Single-node Redis / KeyDB, as deployed (see the voice scripts).
const TAKE_LUA: &str = r"
for i, key in ipairs(KEYS) do
  redis.call('ZREMRANGEBYSCORE', key, '-inf', ARGV[3 * i + 1])
  if redis.call('ZCARD', key) >= tonumber(ARGV[3 * i]) then
    return i
  end
end
for i, key in ipairs(KEYS) do
  redis.call('ZADD', key, ARGV[2], ARGV[1])
  redis.call('PEXPIRE', key, ARGV[3 * i + 2])
end
return 0
";

static TAKE: LazyLock<Script> = LazyLock::new(|| Script::new(TAKE_LUA));

/// What an upstream call is about. Both values are whitelisted tokens
/// (`[A-Za-z0-9]`) by the time they get here.
#[derive(Clone, Copy, Debug)]
pub enum UpstreamTarget<'a> {
    /// An invite code, before it is resolved
    Invite(&'a str),
    /// A server id
    Server(&'a str),
}

/// Budgets for one import source
#[derive(Clone, Debug)]
pub struct UpstreamThrottle {
    prefix: String,
    budgets: SourceBudgets,
}

impl UpstreamThrottle {
    /// The budgets for calls to the source tagged `tag` (its challenge
    /// tag, e.g. `stoat_source::SOURCE_TAG`), shared by every delta process
    pub fn for_source(tag: &'static str) -> UpstreamThrottle {
        UpstreamThrottle::in_namespace(LIVE_NAMESPACE, tag)
    }

    /// The budgets for calls to Stoat
    pub fn stoat() -> UpstreamThrottle {
        UpstreamThrottle::for_source("stoat")
    }

    fn in_namespace(namespace: &str, tag: &'static str) -> UpstreamThrottle {
        let (key, budgets) = source_budgets(tag);
        UpstreamThrottle {
            prefix: format!("{namespace}:{key}"),
            budgets,
        }
    }

    /// Stoat's budgets, on keys no other test shares
    #[cfg(test)]
    pub fn isolated_for_tests() -> UpstreamThrottle {
        UpstreamThrottle::isolated_for_source_tests("stoat")
    }

    /// `tag`'s budgets, on keys no other test shares
    #[cfg(test)]
    pub fn isolated_for_source_tests(tag: &'static str) -> UpstreamThrottle {
        UpstreamThrottle::in_test_namespace(
            &format!("import_upstream_test:{}", ulid::Ulid::new()),
            tag,
        )
    }

    /// `tag`'s budgets under a test's own `namespace` (use a fresh one per
    /// test). Throttles for different sources in one namespace are keyed
    /// exactly as [`UpstreamThrottle::for_source`] keys them, so a test can
    /// check one source never spends another's.
    #[cfg(test)]
    pub fn in_test_namespace(namespace: &str, tag: &'static str) -> UpstreamThrottle {
        UpstreamThrottle::in_namespace(namespace, tag)
    }

    fn user_key(&self, user_id: &str) -> String {
        format!("{}:user:{user_id}", self.prefix)
    }

    /// Folded to lowercase / uppercase: a variant spelling of the same
    /// code or id shares its budget (folding can only throttle more)
    fn target_key(&self, target: UpstreamTarget<'_>) -> String {
        match target {
            UpstreamTarget::Invite(code) => {
                format!("{}:invite:{}", self.prefix, code.to_ascii_lowercase())
            }
            UpstreamTarget::Server(id) => {
                format!("{}:server:{}", self.prefix, id.to_ascii_uppercase())
            }
        }
    }

    fn global_key(&self) -> String {
        format!("{}:global", self.prefix)
    }

    /// Before the first upstream call of `user_id`'s verification: spends
    /// the user's verification, the target's and the global budget, or
    /// none of them. Refused: `ImportUpstreamUnavailable`.
    pub async fn begin_verification(
        &self,
        user_id: &str,
        target: UpstreamTarget<'_>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.take(
            &[
                ("user", self.user_key(user_id), self.budgets.per_user),
                ("target", self.target_key(target), self.budgets.per_target),
                ("global", self.global_key(), self.budgets.global),
            ],
            now,
        )
        .await
    }

    /// Before each later upstream call of a verification already begun:
    /// spends the target's and the global budget, or neither
    pub async fn next_call(&self, target: UpstreamTarget<'_>, now: DateTime<Utc>) -> Result<()> {
        self.take(
            &[
                ("target", self.target_key(target), self.budgets.per_target),
                ("global", self.global_key(), self.budgets.global),
            ],
            now,
        )
        .await
    }

    async fn take(&self, budgets: &[(&str, String, Budget)], now: DateTime<Utc>) -> Result<()> {
        let now_ms = now.timestamp_millis();
        let mut invocation = TAKE.prepare_invoke();
        invocation
            .arg(format!("{now_ms}:{}", ulid::Ulid::new()))
            .arg(now_ms);
        for (_, key, budget) in budgets {
            invocation
                .key(key)
                .arg(budget.limit)
                .arg(now_ms - budget.window_ms)
                .arg(budget.window_ms);
        }

        let refused = match get_connection().await {
            Ok(conn) => {
                let mut conn = conn.into_inner();
                invocation.invoke_async::<_, i64>(&mut conn).await
            }
            Err(_) => {
                log::error!("import upstream throttle: no Redis connection; call refused");
                return Err(create_error!(ImportUpstreamUnavailable));
            }
        };

        match refused {
            Ok(0) => Ok(()),
            Ok(index) => {
                // Per-user and per-target refusals are the throttle doing its
                // job; the global cap is worth an operator's attention. Never
                // the key: it carries what the user pasted.
                let name = (index >= 1)
                    .then(|| budgets.get(index as usize - 1))
                    .flatten()
                    .map(|(name, _, _)| *name)
                    .unwrap_or("unknown");
                if name != "user" && name != "target" {
                    log::warn!("import upstream throttle: {name} budget exhausted; call refused");
                }
                Err(create_error!(ImportUpstreamUnavailable))
            }
            Err(error) => {
                // The kind only: a reply's detail can quote a key
                log::error!(
                    "import upstream throttle: Redis script failed ({:?}); call refused",
                    error.kind()
                );
                Err(create_error!(ImportUpstreamUnavailable))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};
    use redis_kiss::AsyncCommands;

    const SERVER: &str = "01HSERVER00000000000000000";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 15, 12, 0, 0).unwrap()
    }

    fn assert_refused(result: Result<()>) {
        match result {
            Ok(()) => panic!("expected ImportUpstreamUnavailable, got Ok"),
            Err(error) => assert_eq!(
                format!("{:?}", error.error_type),
                "ImportUpstreamUnavailable"
            ),
        }
    }

    /// The four budgets the spec names, pinned
    #[test]
    fn budgets_are_the_specified_ones() {
        assert_eq!(
            PER_USER,
            Budget {
                limit: 1,
                window_ms: 30_000
            }
        );
        assert_eq!(
            PER_TARGET,
            Budget {
                limit: 2,
                window_ms: 10_000
            }
        );
        assert_eq!(
            GLOBAL,
            Budget {
                limit: 10,
                window_ms: 10_000
            }
        );
    }

    #[test]
    fn one_verification_per_user_per_30_seconds() {
        crate::util::test::rt().block_on(async {
            let throttle = UpstreamThrottle::isolated_for_tests();
            throttle
                .begin_verification("U1", UpstreamTarget::Server("S1"), now())
                .await
                .unwrap();
            // Another target does not help
            assert_refused(
                throttle
                    .begin_verification("U1", UpstreamTarget::Invite("abc"), now())
                    .await,
            );
            assert_refused(
                throttle
                    .begin_verification(
                        "U1",
                        UpstreamTarget::Server("S2"),
                        now() + Duration::seconds(29),
                    )
                    .await,
            );
            // Another user is unaffected
            throttle
                .begin_verification("U2", UpstreamTarget::Server("S3"), now())
                .await
                .unwrap();
            // Once the window has passed
            throttle
                .begin_verification(
                    "U1",
                    UpstreamTarget::Server("S4"),
                    now() + Duration::milliseconds(30_001),
                )
                .await
                .unwrap();
        })
    }

    #[test]
    fn two_calls_per_target_per_10_seconds() {
        crate::util::test::rt().block_on(async {
            let throttle = UpstreamThrottle::isolated_for_tests();
            for user in ["U1", "U2"] {
                throttle
                    .begin_verification(user, UpstreamTarget::Server(SERVER), now())
                    .await
                    .unwrap();
            }
            assert_refused(
                throttle
                    .begin_verification("U3", UpstreamTarget::Server(SERVER), now())
                    .await,
            );
            // A follow-up call on the same server is refused too, and a
            // lowercase spelling of the id is the same target
            assert_refused(
                throttle
                    .next_call(UpstreamTarget::Server(&SERVER.to_lowercase()), now())
                    .await,
            );

            // Invite codes have their own keys, folded to lowercase
            for user in ["U4", "U5"] {
                throttle
                    .begin_verification(user, UpstreamTarget::Invite("AbC123"), now())
                    .await
                    .unwrap();
            }
            assert_refused(
                throttle
                    .begin_verification("U6", UpstreamTarget::Invite("abc123"), now())
                    .await,
            );

            // After the window
            throttle
                .begin_verification(
                    "U7",
                    UpstreamTarget::Server(SERVER),
                    now() + Duration::milliseconds(10_001),
                )
                .await
                .unwrap();
        })
    }

    #[test]
    fn ten_calls_per_10_seconds_globally() {
        crate::util::test::rt().block_on(async {
            let throttle = UpstreamThrottle::isolated_for_tests();
            for i in 0..10 {
                throttle
                    .next_call(UpstreamTarget::Server(&format!("S{i}")), now())
                    .await
                    .unwrap();
            }
            assert_refused(
                throttle
                    .next_call(UpstreamTarget::Server("S10"), now())
                    .await,
            );
            assert_refused(
                throttle
                    .begin_verification("U1", UpstreamTarget::Invite("fresh"), now())
                    .await,
            );
            throttle
                .next_call(
                    UpstreamTarget::Server("S11"),
                    now() + Duration::milliseconds(10_001),
                )
                .await
                .unwrap();
        })
    }

    /// A refusal by one budget spends none of the others
    #[test]
    fn a_refusal_spends_nothing() {
        crate::util::test::rt().block_on(async {
            let throttle = UpstreamThrottle::isolated_for_tests();

            // Fill the target; U3 is refused on it...
            for user in ["U1", "U2"] {
                throttle
                    .begin_verification(user, UpstreamTarget::Server(SERVER), now())
                    .await
                    .unwrap();
            }
            assert_refused(
                throttle
                    .begin_verification("U3", UpstreamTarget::Server(SERVER), now())
                    .await,
            );
            // ...and still has its user budget
            throttle
                .begin_verification("U3", UpstreamTarget::Server("OTHER"), now())
                .await
                .unwrap();

            // Global now at 3; a user refusal (U1 again) adds nothing to it
            // or to the fresh target
            for _ in 0..5 {
                assert_refused(
                    throttle
                        .begin_verification("U1", UpstreamTarget::Server("FRESH"), now())
                        .await,
                );
            }
            for user in ["U4", "U5"] {
                throttle
                    .begin_verification(user, UpstreamTarget::Server("FRESH"), now())
                    .await
                    .unwrap();
            }
            // Global at 5: five more fit, exactly
            for i in 0..5 {
                throttle
                    .next_call(UpstreamTarget::Server(&format!("G{i}")), now())
                    .await
                    .unwrap();
            }
            assert_refused(
                throttle
                    .next_call(UpstreamTarget::Server("G5"), now())
                    .await,
            );
        })
    }

    /// Every key the throttle writes expires within its window: nothing is
    /// left behind without a TTL
    #[test]
    fn every_key_expires() {
        crate::util::test::rt().block_on(async {
            let throttle = UpstreamThrottle::isolated_for_tests();
            throttle
                .begin_verification("U1", UpstreamTarget::Invite("AbC"), now())
                .await
                .unwrap();
            throttle
                .next_call(UpstreamTarget::Server(SERVER), now())
                .await
                .unwrap();

            let mut conn = get_connection().await.unwrap().into_inner();
            for (key, window) in [
                (throttle.user_key("U1"), PER_USER.window_ms),
                (
                    throttle.target_key(UpstreamTarget::Invite("AbC")),
                    PER_TARGET.window_ms,
                ),
                (
                    throttle.target_key(UpstreamTarget::Server(SERVER)),
                    PER_TARGET.window_ms,
                ),
                (throttle.global_key(), GLOBAL.window_ms),
            ] {
                let ttl: i64 = conn.pttl(&key).await.unwrap();
                assert!(ttl > 0 && ttl <= window, "{}: pttl {}", key, ttl);
            }
        })
    }

    // ---- per-source budgets ----

    /// `stoat()` and `for_source("stoat")` are release 1's Stoat throttle:
    /// the same Redis keys, literally, and the same budgets
    #[test]
    fn for_source_stoat_is_the_stoat_throttle() {
        for throttle in [
            UpstreamThrottle::stoat(),
            UpstreamThrottle::for_source("stoat"),
        ] {
            assert_eq!(throttle.user_key("U1"), "import_upstream:stoat:user:U1");
            assert_eq!(
                throttle.target_key(UpstreamTarget::Invite("AbC123")),
                "import_upstream:stoat:invite:abc123"
            );
            assert_eq!(
                throttle.target_key(UpstreamTarget::Server("01hserver")),
                "import_upstream:stoat:server:01HSERVER"
            );
            assert_eq!(throttle.global_key(), "import_upstream:stoat:global");
            assert_eq!(
                throttle.budgets,
                SourceBudgets {
                    per_user: Budget {
                        limit: 1,
                        window_ms: 30_000
                    },
                    per_target: Budget {
                        limit: 2,
                        window_ms: 10_000
                    },
                    global: Budget {
                        limit: 10,
                        window_ms: 10_000
                    },
                }
            );
        }
    }

    /// Fluxer's budgets, pinned, on keys of its own
    #[test]
    fn fluxer_has_its_own_keys_and_budgets() {
        let throttle = UpstreamThrottle::for_source("fluxer");
        assert_eq!(throttle.user_key("U1"), "import_upstream:fluxer:user:U1");
        assert_eq!(
            throttle.target_key(UpstreamTarget::Server("123")),
            "import_upstream:fluxer:server:123"
        );
        assert_eq!(
            throttle.target_key(UpstreamTarget::Invite("AbC")),
            "import_upstream:fluxer:invite:abc"
        );
        assert_eq!(throttle.global_key(), "import_upstream:fluxer:global");
        assert_eq!(
            throttle.budgets,
            SourceBudgets {
                per_user: Budget {
                    limit: 2,
                    window_ms: 30_000
                },
                per_target: Budget {
                    limit: 5,
                    window_ms: 10_000
                },
                global: Budget {
                    limit: 10,
                    window_ms: 10_000
                },
            }
        );
    }

    /// A tag with no row gets keys of its own and Stoat's (strictest)
    /// budgets, never another source's keys
    #[test]
    fn an_unlisted_source_gets_its_own_keys_and_stoats_budgets() {
        let throttle = UpstreamThrottle::for_source("matrix");
        assert_eq!(throttle.user_key("U1"), "import_upstream:matrix:user:U1");
        assert_eq!(throttle.global_key(), "import_upstream:matrix:global");
        assert_eq!(throttle.budgets, STOAT_BUDGETS);
    }

    #[test]
    fn fluxer_allows_two_verifications_per_user_per_30_seconds() {
        crate::util::test::rt().block_on(async {
            let throttle = UpstreamThrottle::isolated_for_source_tests("fluxer");
            throttle
                .begin_verification("U1", UpstreamTarget::Server("1001"), now())
                .await
                .unwrap();
            throttle
                .begin_verification(
                    "U1",
                    UpstreamTarget::Server("1002"),
                    now() + Duration::seconds(1),
                )
                .await
                .unwrap();
            // The third within 30 s of the first, on any target
            assert_refused(
                throttle
                    .begin_verification(
                        "U1",
                        UpstreamTarget::Invite("fresh"),
                        now() + Duration::seconds(29),
                    )
                    .await,
            );
            // Once the first has left the window
            throttle
                .begin_verification(
                    "U1",
                    UpstreamTarget::Server("1004"),
                    now() + Duration::milliseconds(30_001),
                )
                .await
                .unwrap();
        })
    }

    #[test]
    fn fluxer_allows_five_calls_per_target_per_10_seconds() {
        crate::util::test::rt().block_on(async {
            let throttle = UpstreamThrottle::isolated_for_source_tests("fluxer");
            throttle
                .begin_verification("U1", UpstreamTarget::Server("1001"), now())
                .await
                .unwrap();
            for _ in 0..4 {
                throttle
                    .next_call(UpstreamTarget::Server("1001"), now())
                    .await
                    .unwrap();
            }
            assert_refused(
                throttle
                    .next_call(UpstreamTarget::Server("1001"), now())
                    .await,
            );
            assert_refused(
                throttle
                    .begin_verification("U2", UpstreamTarget::Server("1001"), now())
                    .await,
            );
        })
    }

    /// Spending one source's budgets, global included, refuses nothing on
    /// another: both directions, with every key in one namespace as live
    /// throttles share Redis
    #[test]
    fn sources_never_spend_each_others_budgets() {
        crate::util::test::rt().block_on(async {
            // Fluxer exhausted: U1's verifications, the target, the global
            let namespace = format!("import_upstream_test:{}", ulid::Ulid::new());
            let fluxer = UpstreamThrottle::in_test_namespace(&namespace, "fluxer");
            let stoat = UpstreamThrottle::in_test_namespace(&namespace, "stoat");
            for _ in 0..2 {
                fluxer
                    .begin_verification("U1", UpstreamTarget::Server("G0"), now())
                    .await
                    .unwrap();
            }
            for target in ["G0", "G0", "G0", "G1", "G2", "G3", "G4", "G5"] {
                fluxer
                    .next_call(UpstreamTarget::Server(target), now())
                    .await
                    .unwrap();
            }
            assert_refused(
                fluxer
                    .begin_verification("U2", UpstreamTarget::Server("G9"), now())
                    .await,
            );
            assert_refused(fluxer.next_call(UpstreamTarget::Server("G9"), now()).await);

            stoat
                .begin_verification("U1", UpstreamTarget::Server("G0"), now())
                .await
                .unwrap();
            stoat
                .next_call(UpstreamTarget::Server("G0"), now())
                .await
                .unwrap();

            // Stoat exhausted the same way; Fluxer is unaffected
            let namespace = format!("import_upstream_test:{}", ulid::Ulid::new());
            let fluxer = UpstreamThrottle::in_test_namespace(&namespace, "fluxer");
            let stoat = UpstreamThrottle::in_test_namespace(&namespace, "stoat");
            stoat
                .begin_verification("U1", UpstreamTarget::Server("G0"), now())
                .await
                .unwrap();
            for target in ["G0", "G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8"] {
                stoat
                    .next_call(UpstreamTarget::Server(target), now())
                    .await
                    .unwrap();
            }
            assert_refused(stoat.next_call(UpstreamTarget::Server("G9"), now()).await);

            for _ in 0..2 {
                fluxer
                    .begin_verification("U1", UpstreamTarget::Server("G0"), now())
                    .await
                    .unwrap();
            }
            fluxer
                .next_call(UpstreamTarget::Server("G0"), now())
                .await
                .unwrap();
        })
    }
}
