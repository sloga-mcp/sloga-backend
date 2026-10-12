//! Public founding-streamer directory.
//!
//! `GET /discover/streamers` is ANONYMOUS: no session, no perspective. That
//! is deliberate — the page is a marketing surface — and it is also why this
//! route cannot go through the normal user bridge. `User::into()` gates
//! `connections` (and `status`, and `online`) behind `can_see_profile`, which
//! is hard-`false` for a `None` perspective
//! (`crates/core/database/src/util/bridge/v0.rs:1375`), so the standard
//! payload would ship `connections: []` and the directory would be empty of
//! the only data it exists to show. `v0::StreamerCard` is the strict
//! whitelist that replaces the bridge.
//!
//! Replacing the bridge means replacing everything the bridge was doing FOR
//! us. `AbstractUsers::fetch_badged_users()` is deliberately permissive: it
//! returns every user carrying ANY stored badge bit, in any account state,
//! bots included, with no cap. Each of the filters below is load-bearing and
//! has no second line of defence anywhere downstream.
//!
//! # Cost
//!
//! A cache HIT is one Redis GET.
//!
//! A cache MISS is a collection scan (there is no index on `badges`) followed
//! by ONE account point read per user that survives `is_publishable` — not
//! one per emitted card. A rejected account `continue`s without filling a
//! slot, so the cap bounds the RESPONSE, not the work: in the degenerate case
//! where every badge holder has self-disabled, the route scans, reads one
//! account each, and returns `[]`.
//!
//! The scan is projected to `BADGED_USER_FIELDS` in the database crate, so a
//! miss never loads relations, profiles or supporter data it does not read.
//!
//! Two bounds apply to misses, and only one of them is aggregate. The path
//! inherits the `discover` bucket from `crate::util::ratelimits`
//! (`("discover", _, _)`, 20 requests per 10s), but for sessionless requests
//! that counter is keyed by IP — it bounds one client, not total load. The
//! aggregate bound is the cache: at most one complete miss per `CACHE_TTL`
//! per process, Redis up or not (see below).
//!
//! # Single-flight
//!
//! Misses run one at a time behind `MISS_PERMIT`, a one-permit
//! `tokio::sync::Semaphore` (not a mutex held across an await). A request
//! that waited re-reads the cache once it holds the permit, so a herd that
//! arrives during one miss is served by that miss.
//!
//! The re-read only finds something if the miss was stored somewhere, and
//! Redis may be the thing that is down. So every complete response is also
//! kept in-process (`LOCAL_CACHE`, a std mutex never held across an await),
//! checked before Redis.
//!
//! Not collapsed: a response that skipped an unreadable account row is never
//! cached (see the route body), so while such a row exists every request
//! recomputes, one at a time. The error log names the row.
//!
//! Deliberately NOT claimed: that a CDN absorbs the stampede. Nothing in this
//! repo configures origin fronting for `/discover/*`.

use redis_kiss::{get_connection, redis, AsyncCommands};
use revolt_database::{Database, ProfileVisibility, User};
use revolt_models::v0::{self, UserBadges, UserFlags};
use revolt_result::{create_error, ErrorType, Result};
use revolt_rocket_okapi::gen::OpenApiGenerator;
use revolt_rocket_okapi::response::OpenApiResponderInner;
use revolt_rocket_okapi::revolt_okapi::openapi3::Responses;
use revolt_rocket_okapi::OpenApiError;
use rocket::response::{self, Responder};
use rocket::serde::json::Json;
use rocket::{Request, Response, State};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// Hard cap on cards emitted, applied AFTER every filter.
///
/// Bounds the RESPONSE, not the scan (see the module `# Cost` note). The badge
/// grant is manual so this should never bind in practice, but an unbounded
/// anonymous response is not something to leave to operational discipline.
const MAX_STREAMERS: usize = 50;

/// Redis key holding the composed response body.
///
/// Versioned: bump the suffix whenever the response SHAPE **or the publication
/// CRITERIA** change. Shape is the obvious case. Criteria is the one that has
/// already bitten this route — the account-state gate was added at unchanged
/// shape, and across a rolling deploy an old binary keeps refilling this key
/// with ungated bodies that the new binary then serves verbatim for up to
/// `CACHE_TTL`. A new key means the two binaries cannot feed each other.
const CACHE_KEY: &str = "discover:streamers:v1";

/// Cache lifetime, seconds.
const CACHE_TTL: usize = 30;

/// `Cache-Control` emitted on every response.
///
/// `public`, unlike the softres catalog's `private`: this route takes no
/// session and its body is identical for every caller, so a shared cache
/// storing it leaks nothing. Explicit rather than omitted because this
/// deployment's edge pins artifacts for hours when a response says nothing.
///
/// The `max-age` must equal `CACHE_TTL`. That is enforced from the TEST side
/// (`cache_control_tracks_the_cache_ttl`), which builds the expected header
/// out of `CACHE_TTL` — so editing this string alone fails, and a deliberate
/// TTL change that updates both passes. A `const` assertion pinning either
/// value to a literal would have it exactly backwards: it would reject the
/// correct change and wave the drift through.
///
/// Worst case a client holds a view `CACHE_TTL * 2` old — a body served at
/// the very end of its Redis window, then held for its own `max-age`. That is
/// acceptable for a directory whose only volatile field is live status.
const CACHE_CONTROL: &str = "public, max-age=30";

/// Only one cache miss computes at a time (see the module `# Single-flight`)
static MISS_PERMIT: Semaphore = Semaphore::const_new(1);

/// Last complete response computed by this process, and when
///
/// Lets waiters on `MISS_PERMIT` reuse a miss while Redis is unreachable.
static LOCAL_CACHE: Mutex<Option<(Instant, v0::StreamersResponse)>> = Mutex::new(None);

/// The one badge bit this directory publishes.
const FOUNDING_STREAMER: u32 = UserBadges::FoundingStreamer as u32;

/// Account states, as recorded on the USER document, that must never be
/// published.
///
/// This mask is only half the account-state story and must not be read as the
/// whole of it: `UserFlags::Deleted` is stamped by the crond sweep a week
/// after the user asked to be deleted, and `Account::disable` writes nothing
/// here at all. The second half — the live account row — is checked in the
/// route body, where the account is reachable.
///
/// Exhaustive over `UserFlags` today, and kept that way by
/// `blocking_flags_covers_every_user_flag`: unlike the `ProfileVisibility`
/// catch-all below, a bitmask cannot fail closed on a variant it has never
/// heard of, so the guard has to live in a test that stops compiling.
const BLOCKING_FLAGS: u32 = UserFlags::SuspendedUntil as u32
    | UserFlags::Deleted as u32
    | UserFlags::Banned as u32
    | UserFlags::Spam as u32;

/// `Json` with `Cache-Control` attached.
///
/// Modelled on `crate::routes::softres::CachedJson`, which cannot be reused:
/// its header value is a module-private const baked to
/// `private, max-age=86400`, and this route needs `public` with a very short
/// age.
pub struct CachedStreamers(pub Json<v0::StreamersResponse>);

impl<'r> Responder<'r, 'static> for CachedStreamers {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'static> {
        Response::build_from(self.0.respond_to(req)?)
            .raw_header("Cache-Control", CACHE_CONTROL)
            .ok()
    }
}

impl OpenApiResponderInner for CachedStreamers {
    fn responses(generator: &mut OpenApiGenerator) -> Result<Responses, OpenApiError> {
        <Json<v0::StreamersResponse> as OpenApiResponderInner>::responses(generator)
    }
}

/// Whether the Redis cache in front of this route is live.
///
/// MUST be false under test. `redis_kiss` pools into ONE process-global pool
/// (see the runtime note in `crates/delta/src/util/test.rs`), and every test
/// in this module hits the same `CACHE_KEY`. With the cache on, the first
/// test to run would populate it and every later test would be served that
/// first response — a suite that passes green while asserting nothing about
/// its own fixtures. The negative tests ("a Developer badge is not listed",
/// "a Friends-only profile is not listed") are exactly the ones that would go
/// vacuously green, which is the worst possible failure mode for this file.
///
/// Two independent guards, because one of them is a compile-time property of
/// how the tests happen to be written today:
///
///  * `cfg!(test)` — covers the inline `#[cfg(test)] mod test` below;
///  * `TEST_DB` — covers any future harness that is NOT compiled with
///    `cfg(test)` for this crate (a `tests/` integration target, say).
///    `TEST_DB` is already mandatory for `TestHarness::new`, which refuses to
///    run without it, so this is a guard that cannot be forgotten.
fn cache_enabled() -> bool {
    if cfg!(test) {
        return false;
    }

    std::env::var("TEST_DB").is_err()
}

/// Whether this badged user may appear in the anonymous directory, judged on
/// the USER document alone.
///
/// Necessary, not sufficient — the account-row gate in the route body runs
/// after this and is equally load-bearing.
///
/// Fail-closed throughout: every check is written as "exclude unless
/// positively known to be fine".
fn is_publishable(user: &User) -> bool {
    // 1. THE BADGE BIT. `fetch_badged_users` does NO bit filtering — it
    //    returns every user with a non-zero `badges` field. Without this mask
    //    an anonymous, unauthenticated page would enumerate every Developer,
    //    Supporter, PlatformModeration, Founder and Paw account on the
    //    instance, complete with their linked streaming channels. This is the
    //    single most important line in the file.
    //
    //    Read the STORED bitfield, not `User::get_badges()`: that one is
    //    async and would fold in the derived EarlyAdopter bit, which has
    //    nothing to do with who may appear here.
    //
    //    `.max(0)` before the widening cast is defence in depth, not the only
    //    gate. `badges` is a signed `i32` straight off the wire
    //    (`DataEditUser::badges`), and a negative value sign-extends:
    //    `-1 as u32` is `0xFFFFFFFF`, which carries EVERY bit including this
    //    one. Both drivers now also reject negatives at the query (`$gt: 0`
    //    and `badges > 0` in `models/users/ops/`), so such a row does not
    //    reach this function today — but that is the DRIVER's invariant, not
    //    this route's, and an anonymous directory must not start publishing
    //    every account on the instance if it is ever relaxed. Clamp locally.
    //
    //    The same cast on `flags` below needs no clamp: there a negative
    //    value widens to all-bits-set and therefore matches BLOCKING_FLAGS,
    //    which excludes the user. Garbage fails closed on both sides, just
    //    by opposite arithmetic.
    if user.badges.unwrap_or_default().max(0) as u32 & FOUNDING_STREAMER == 0 {
        return false;
    }

    // 2. ACCOUNT STATE, as far as the user document knows it. A suspended or
    //    banned streamer must drop off the page immediately; moderation
    //    action is not supposed to need a second manual step to un-publish
    //    someone. See the route body for the disabled/pending-deletion half.
    if user.flags.unwrap_or_default() as u32 & BLOCKING_FLAGS != 0 {
        return false;
    }

    // ... and belt-and-braces on the timestamp. `unsuspend` clears
    // `suspended_until` together with the flag, so a present value means the
    // suspension has not been lifted — including the case where the flags
    // field was clobbered by some other write path.
    if user.suspended_until.is_some() {
        return false;
    }

    // 3. BOTS. A bot can hold badges and connections like any other user
    //    document; this directory is about people.
    if user.bot.is_some() {
        return false;
    }

    // 4. PROFILE VISIBILITY. This route deliberately BYPASSES the bridge's
    //    `can_see_profile` gate — that bypass is the entire reason
    //    `StreamerCard` exists (see the module comment) — so the restriction
    //    the gate was enforcing has to be re-applied here, explicitly, or the
    //    bypass silently becomes a privacy regression.
    //
    //    The badge being opt-in does NOT excuse skipping this. The two
    //    settings are granted by different parties for different reasons: the
    //    badge is awarded by platform staff (the user may never have asked
    //    for it, and cannot remove it themselves), while `profile_visibility:
    //    Friends` is the user's own, later, explicit statement that people
    //    who are not their friends may not read their profile. Publishing a
    //    Friends-only user's handle, avatar, linked Twitch/YouTube/Kick
    //    channels and live status to the whole internet because staff once
    //    granted them a badge would override the user's own privacy choice
    //    with a decision they did not make.
    //
    //    Catch-all arm, not `!= Friends`: any stricter variant added to
    //    `ProfileVisibility` later must be excluded by default, not
    //    accidentally published until someone remembers this file.
    if !matches!(
        user.profile_visibility,
        None | Some(ProfileVisibility::Everyone)
    ) {
        return false;
    }

    true
}

/// Project a user onto the public card.
///
/// Field-by-field by construction — no `..` spread, no bridge — so adding a
/// field to `User` can never silently add it to this payload. The avatar goes
/// through `PublicFile`, which drops the uploader's `user_id` (and
/// `server_id` / `message_id` / `reported` / `deleted`) the same way
/// `DiscoverableServer`'s icon does.
fn to_streamer_card(user: User) -> v0::StreamerCard {
    v0::StreamerCard {
        id: user.id,
        username: user.username,
        discriminator: user.discriminator,
        display_name: user.display_name,
        avatar: user.avatar.map(|file| v0::File::from(file).into()),
        connections: user
            .connections
            .unwrap_or_default()
            .into_iter()
            .map(Into::into)
            .collect(),
    }
}

/// Read the composed response out of Redis, if it is cached and fresh.
///
/// Every failure path (cache off, no connection, malformed payload) returns
/// `None` and the route recomputes — the cache is an optimisation, never a
/// correctness dependency.
async fn read_cache() -> Option<v0::StreamersResponse> {
    if !cache_enabled() {
        return None;
    }

    if let Some(local) = read_local(Instant::now()) {
        return Some(local);
    }

    let mut conn = get_connection().await.ok()?.into_inner();
    let payload: Option<String> = conn.get(CACHE_KEY).await.ok()?;

    serde_json::from_str(&payload?).ok()
}

/// The in-process copy, if it is younger than `CACHE_TTL` at `now`
fn read_local(now: Instant) -> Option<v0::StreamersResponse> {
    let guard = LOCAL_CACHE.lock().ok()?;
    fresh(guard.as_ref(), now)
}

/// Whether a stored entry is still inside `CACHE_TTL` at `now`
fn fresh(
    entry: Option<&(Instant, v0::StreamersResponse)>,
    now: Instant,
) -> Option<v0::StreamersResponse> {
    let (stored_at, response) = entry?;
    (now.saturating_duration_since(*stored_at) < Duration::from_secs(CACHE_TTL as u64))
        .then(|| response.clone())
}

/// Store the composed response for `CACHE_TTL` seconds, in-process and in
/// Redis. Best effort.
///
/// Only ever called on a response the route is certain is COMPLETE — see the
/// error split in the route body. Caching a listing that was truncated by a
/// transient database fault would publish that fault for `CACHE_TTL`.
async fn write_cache(response: &v0::StreamersResponse) {
    if !cache_enabled() {
        return;
    }

    if let Ok(mut guard) = LOCAL_CACHE.lock() {
        *guard = Some((Instant::now(), response.clone()));
    }

    let Ok(payload) = serde_json::to_string(response) else {
        return;
    };

    let Ok(conn) = get_connection().await else {
        return;
    };

    let mut conn = conn.into_inner();
    let _: std::result::Result<Option<String>, _> = conn
        .set_options(
            CACHE_KEY,
            payload,
            redis::SetOptions::default().with_expiration(redis::SetExpiry::EX(CACHE_TTL)),
        )
        .await;
}

/// # List Founding Streamers
///
/// Public, unauthenticated: list users carrying the Founding Streamer badge,
/// with their linked streaming channels and live status. Newest accounts
/// first, up to a fixed server-side maximum.
#[openapi(tag = "Discovery")]
#[get("/streamers")]
pub async fn streamers(db: &State<Database>) -> Result<CachedStreamers> {
    if let Some(cached) = read_cache().await {
        return Ok(CachedStreamers(Json(cached)));
    }

    // Single-flight: one miss computes, the rest wait and then re-read what it
    // stored. The semaphore is never closed, so acquire cannot fail in
    // practice.
    let _permit = MISS_PERMIT
        .acquire()
        .await
        .map_err(|_| create_error!(InternalError))?;

    if let Some(cached) = read_cache().await {
        return Ok(CachedStreamers(Json(cached)));
    }

    // ACCOUNT STATE, second half. `is_publishable` works off the `User`
    // document and structurally CANNOT see this:
    //
    //  * `Account::disable` (accounts/model.rs:710-714) sets `disabled` on
    //    the ACCOUNT row and writes nothing whatsoever to the user document;
    //  * `schedule_deletion` does the same and adds `deletion`;
    //  * `UserFlags::Deleted` only appears a week later, when the hourly
    //    crond sweep (`daemons/crond/src/tasks/delete_accounts.rs`) finally
    //    runs `user.delete()`.
    //
    // So without this gate a founding streamer who clicks "delete my
    // account" loses their sessions immediately and then watches this
    // anonymous endpoint serve their username, avatar and linked
    // Twitch/YouTube/Kick handles to the whole internet for another week,
    // with no way to stop it — and a plain self-disable publishes them
    // indefinitely.
    //
    // Cost: ONE point read per user that survived `is_publishable` — not per
    // emitted card. A rejected user consumes a read and no slot, so the cap
    // below cannot shorten this loop (see the module `# Cost` note).
    let mut streamers = Vec::with_capacity(MAX_STREAMERS);
    let mut complete = true;

    for user in db
        .fetch_badged_users()
        .await?
        .into_iter()
        .filter(is_publishable)
    {
        // "No account row" and "the account could not be read" are NOT the
        // same answer and must not share an arm. A missing account is a real,
        // permanent verdict: skip the user, fail closed.
        //
        // Any other error is an ABSENCE of a verdict: a transient fault, or a
        // row that no longer deserializes, and the driver cannot tell those
        // apart. Either way the user is skipped (fail closed) rather than
        // failing the request, so one bad row cannot take the whole
        // directory down. The response is then marked incomplete and NOT
        // cached: pinning a listing truncated by a blip would outlive the
        // blip by CACHE_TTL.
        let account = match db.fetch_account(&user.id).await {
            Ok(account) => account,
            Err(error) if matches!(error.error_type, ErrorType::UnknownUser) => continue,
            Err(error) => {
                log::error!(
                    "streamer directory: skipping {}, account read failed: {:?}",
                    user.id,
                    error
                );
                complete = false;
                continue;
            }
        };

        if account.disabled || account.deletion.is_some() {
            continue;
        }

        streamers.push(to_streamer_card(user));

        // Cap AFTER both filters. Hoisting it onto the iterator — a `.take()`
        // before the account gate — would let rejected users consume slots
        // and silently shorten the listing; `streamers_caps_the_listing`
        // pins that with disabled users deliberately placed at the head of
        // the newest-first scan.
        if streamers.len() == MAX_STREAMERS {
            break;
        }
    }

    let response = v0::StreamersResponse { streamers };
    if complete {
        write_cache(&response).await;
    }

    Ok(CachedStreamers(Json(response)))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        Account, BotInformation, ConnectionPlatform, DeletionInfo, EmailVerification, File,
        Metadata, ProfileVisibility, User, UserConnection,
    };
    use revolt_models::v0::{self, UserBadges, UserFlags};
    use ulid::Ulid;

    const FOUNDING_STREAMER: i32 = UserBadges::FoundingStreamer as i32;

    /// Fixture user.
    ///
    /// ULIDs come from `Ulid::new()`, never hand-written: `U` is not in the
    /// Crockford alphabet, so an id like `01USER…` is not a valid ULID at
    /// all. `User::get_badges` tolerates that today (`is_ok_and`, not
    /// `unwrap`), but a fixture whose id silently fails to parse is a fixture
    /// that quietly skips whatever id-derived logic it was meant to cover.
    fn fixture(badges: Option<i32>) -> User {
        User {
            id: Ulid::new().to_string(),
            username: TestHarness::rand_string(),
            discriminator: "0001".to_string(),
            badges,
            ..Default::default()
        }
    }

    /// A fixture whose id sorts ABOVE anything `Ulid::new()` mints now.
    ///
    /// `fetch_badged_users` orders newest-first by `_id`, and the cap test
    /// needs its rejected users at the HEAD of that scan. "Inserted later" is
    /// not enough: two `Ulid::new()` calls inside the same millisecond differ
    /// only in random low bits, so ordering between them is a coin flip.
    /// Forcing
    /// the leading timestamp character to `7` — the largest a valid ULID can
    /// carry — makes it deterministic.
    fn newest_fixture(badges: Option<i32>) -> User {
        let mut user = fixture(badges);
        user.id.replace_range(0..1, "7");
        assert!(
            Ulid::from_string(&user.id).is_ok(),
            "forced-newest id is not a valid ULID: {}",
            user.id
        );
        user
    }

    /// Insert a user together with its account row.
    ///
    /// Every fixture needs one: the route fails closed on a missing account,
    /// so a user inserted without one is never published (which is itself
    /// asserted below). The password is a literal, NOT `hash_password` —
    /// nothing here logs in, and argon2 on 70-odd cap-test fixtures would
    /// push the test past its timeout for no coverage at all.
    async fn insert(
        harness: &TestHarness,
        user: &User,
        disabled: bool,
        deletion: Option<DeletionInfo>,
    ) {
        harness.db.insert_user(user).await.expect("insert user");

        let email = format!("{}@stoat.chat", TestHarness::rand_string());
        harness
            .db
            .save_account(&Account {
                id: user.id.clone(),
                email: email.clone(),
                email_normalised: email,
                password: "not-a-real-hash".to_string(),
                deletion,
                disabled,
                lockout: None,
                mfa: Default::default(),
                password_reset: None,
                verification: EmailVerification::Verified,
                google_id: None,
                apple_id: None,
            })
            .await
            .expect("save account");
    }

    /// Healthy account: the common case.
    async fn insert_ok(harness: &TestHarness, user: &User) {
        insert(harness, user, false, None).await
    }

    async fn listing(harness: &TestHarness) -> v0::StreamersResponse {
        harness
            .client
            .get("/discover/streamers")
            .dispatch()
            .await
            .into_json::<v0::StreamersResponse>()
            .await
            .expect("streamers json")
    }

    fn ids(response: &v0::StreamersResponse) -> Vec<String> {
        response.streamers.iter().map(|c| c.id.clone()).collect()
    }

    /// `BLOCKING_FLAGS` must name every `UserFlags` variant.
    ///
    /// A bitmask cannot fail closed on a variant it has never heard of: add
    /// a fifth flag and the mask silently keeps publishing users carrying it.
    /// The exhaustive `match` below is the guard — a new variant stops this
    /// file compiling, which forces the decision to be made deliberately.
    #[test]
    fn blocking_flags_covers_every_user_flag() {
        fn bit(flag: UserFlags) -> u32 {
            match flag {
                UserFlags::SuspendedUntil => UserFlags::SuspendedUntil as u32,
                UserFlags::Deleted => UserFlags::Deleted as u32,
                UserFlags::Banned => UserFlags::Banned as u32,
                UserFlags::Spam => UserFlags::Spam as u32,
            }
        }

        for flag in [
            UserFlags::SuspendedUntil,
            UserFlags::Deleted,
            UserFlags::Banned,
            UserFlags::Spam,
        ] {
            let value = bit(flag);
            assert!(
                super::BLOCKING_FLAGS & value != 0,
                "BLOCKING_FLAGS does not cover user flag bit {}",
                value
            );
        }
    }

    /// The emitted `Cache-Control` must be derived from `CACHE_TTL`.
    ///
    /// Built here rather than pinned with a `const` assertion on purpose: an
    /// assertion on the literal 30 would reject a correct TTL bump and let a
    /// lone edit of `CACHE_CONTROL` through. This fails on the drift and
    /// survives the correct change.
    #[test]
    fn cache_control_tracks_the_cache_ttl() {
        assert_eq!(
            super::CACHE_CONTROL,
            format!("public, max-age={}", super::CACHE_TTL),
            "Cache-Control max-age drifted from CACHE_TTL"
        );
    }

    /// THE bit-mask test. `fetch_badged_users` returns every user with any
    /// stored badge; only the FoundingStreamer bit may be published.
    #[test]
    fn streamers_lists_only_the_founding_streamer_bit() {
        crate::util::test::rt().block_on(streamers_lists_only_the_founding_streamer_bit_case())
    }

    async fn streamers_lists_only_the_founding_streamer_bit_case() {
        let harness = TestHarness::new().await;

        let wanted = fixture(Some(FOUNDING_STREAMER));
        // Same bit alongside others: still published.
        let also_wanted = fixture(Some(
            FOUNDING_STREAMER | UserBadges::Supporter as i32 | UserBadges::Developer as i32,
        ));
        // A DIFFERENT badge. The driver returns this row; the route must
        // drop it. Deleting the mask in the route makes this assertion fail.
        let other_badge = fixture(Some(UserBadges::Developer as i32));
        let moderator = fixture(Some(UserBadges::PlatformModeration as i32));
        // Stored `badges: 0`, and no `badges` field at all.
        let zero = fixture(Some(0));
        let absent = fixture(None);
        // Sign extension: `-1 as u32` is 0xFFFFFFFF, which carries every bit
        // including this one.
        //
        // HONEST LABEL: both drivers now filter `badges > 0`, so this row is
        // dropped before the route ever sees it. This fixture pins the
        // end-to-end behaviour; it does NOT exercise the route's own
        // `.max(0)` clamp and will NOT fail if that clamp is deleted.
        let negative = fixture(Some(-1));

        for user in [
            &wanted,
            &also_wanted,
            &other_badge,
            &moderator,
            &zero,
            &absent,
            &negative,
        ] {
            insert_ok(&harness, user).await;
        }

        let listing = listing(&harness).await;
        let ids = ids(&listing);

        assert!(ids.contains(&wanted.id), "badged user must be listed");
        assert!(
            ids.contains(&also_wanted.id),
            "the bit must be tested, not the whole bitfield compared"
        );
        assert!(
            !ids.contains(&other_badge.id),
            "a Developer-badged user must NOT appear in the founding-streamer directory"
        );
        assert!(
            !ids.contains(&moderator.id),
            "a PlatformModeration-badged user must NOT appear in the founding-streamer directory"
        );
        assert!(!ids.contains(&zero.id), "badges:0 must not be listed");
        assert!(
            !ids.contains(&absent.id),
            "a user with no badges field must not be listed"
        );
        assert!(
            !ids.contains(&negative.id),
            "badges:-1 sign-extended to all-bits-set and was published"
        );
    }

    /// Account state, bots and profile visibility.
    #[test]
    fn streamers_excludes_restricted_bot_and_suspended_accounts() {
        crate::util::test::rt()
            .block_on(streamers_excludes_restricted_bot_and_suspended_accounts_case())
    }

    async fn streamers_excludes_restricted_bot_and_suspended_accounts_case() {
        let harness = TestHarness::new().await;

        let ok = fixture(Some(FOUNDING_STREAMER));

        let mut friends_only = fixture(Some(FOUNDING_STREAMER));
        friends_only.profile_visibility = Some(ProfileVisibility::Friends);

        let mut suspended = fixture(Some(FOUNDING_STREAMER));
        suspended.flags = Some(UserFlags::SuspendedUntil as i32);

        let mut banned = fixture(Some(FOUNDING_STREAMER));
        banned.flags = Some(UserFlags::Banned as i32);

        let mut deleted = fixture(Some(FOUNDING_STREAMER));
        deleted.flags = Some(UserFlags::Deleted as i32);

        let mut spam = fixture(Some(FOUNDING_STREAMER));
        spam.flags = Some(UserFlags::Spam as i32);

        // Flags clobbered, timestamp still standing: the belt-and-braces arm.
        let mut timed_out = fixture(Some(FOUNDING_STREAMER));
        timed_out.suspended_until =
            Timestamp::now_utc().checked_add(iso8601_timestamp::Duration::days(7));
        assert!(
            timed_out.suspended_until.is_some(),
            "fixture did not get a suspension timestamp"
        );

        let mut bot = fixture(Some(FOUNDING_STREAMER));
        bot.bot = Some(BotInformation {
            owner: ok.id.clone(),
        });

        for user in [
            &ok,
            &friends_only,
            &suspended,
            &banned,
            &deleted,
            &spam,
            &timed_out,
            &bot,
        ] {
            insert_ok(&harness, user).await;
        }

        // The account-row half, which no `UserFlags` bit reflects. A plain
        // self-disable writes ONLY `Account::disabled`; scheduling deletion
        // adds `deletion` and leaves the user document untouched for a week.
        let disabled = fixture(Some(FOUNDING_STREAMER));
        insert(&harness, &disabled, true, None).await;

        let pending_deletion = fixture(Some(FOUNDING_STREAMER));
        insert(
            &harness,
            &pending_deletion,
            true,
            Some(DeletionInfo::Scheduled {
                after: Timestamp::now_utc()
                    .checked_add(iso8601_timestamp::Duration::weeks(1))
                    .expect("deletion deadline"),
            }),
        )
        .await;

        // Awaiting email confirmation of deletion — also disabled in practice,
        // but assert the `deletion.is_some()` arm independently of `disabled`.
        let mut awaiting_confirmation = fixture(Some(FOUNDING_STREAMER));
        awaiting_confirmation.display_name = Some("Leaving Soon".to_string());
        insert(
            &harness,
            &awaiting_confirmation,
            false,
            Some(DeletionInfo::WaitingForVerification {
                token: "tok".to_string(),
                expiry: Timestamp::now_utc()
                    .checked_add(iso8601_timestamp::Duration::days(1))
                    .expect("token expiry"),
            }),
        )
        .await;

        // No account row at all: the route must fail CLOSED, not publish.
        let orphan = fixture(Some(FOUNDING_STREAMER));
        harness.db.insert_user(&orphan).await.expect("insert user");

        let listing = listing(&harness).await;
        let ids = ids(&listing);

        assert!(ids.contains(&ok.id), "control user must be listed");

        // One assertion naming EVERY leaked class, so a single control run
        // shows all of them rather than stopping at the first panic.
        let leaked: Vec<&str> = [
            ("Friends-only profile", &friends_only.id),
            ("suspended (flag)", &suspended.id),
            ("banned", &banned.id),
            ("deleted (flag)", &deleted.id),
            ("spam", &spam.id),
            ("standing suspended_until", &timed_out.id),
            ("bot", &bot.id),
            ("disabled account", &disabled.id),
            ("account scheduled for deletion", &pending_deletion.id),
            (
                "account awaiting deletion confirmation",
                &awaiting_confirmation.id,
            ),
            ("no account row (must fail closed)", &orphan.id),
        ]
        .iter()
        .filter(|(_, id)| ids.contains(*id))
        .map(|(label, _)| *label)
        .collect();

        assert!(
            leaked.is_empty(),
            "anonymous streamer listing published users it must never publish: {:?}",
            leaked
        );
    }

    /// The point of the whole DTO: `connections` must survive for a caller
    /// with NO session, where the normal bridge would have emptied them.
    #[test]
    fn streamers_card_carries_connections_for_anonymous_caller() {
        crate::util::test::rt()
            .block_on(streamers_card_carries_connections_for_anonymous_caller_case())
    }

    async fn streamers_card_carries_connections_for_anonymous_caller_case() {
        let harness = TestHarness::new().await;

        let mut user = fixture(Some(FOUNDING_STREAMER));
        user.display_name = Some("Streamer One".to_string());

        // A REAL avatar, carrying every id-bearing field `v0::File` would
        // serialize. Without this the `user_id` leak assertion below is
        // vacuous: a card with no avatar has no `PublicFile` to sanitise, so
        // the test would pass even if `to_streamer_card` emitted a raw
        // `v0::File`.
        let uploader = Ulid::new().to_string();
        user.avatar = Some(File {
            id: Ulid::new().to_string(),
            tag: "avatars".to_string(),
            filename: "avatar.png".to_string(),
            hash: None,
            uploaded_at: None,
            uploader_id: Some(uploader.clone()),
            used_for: None,
            deleted: Some(false),
            reported: Some(false),
            metadata: Metadata::default(),
            content_type: "image/png".to_string(),
            size: 1024,
            message_id: None,
            user_id: Some(uploader.clone()),
            server_id: None,
            object_id: Some(uploader.clone()),
        });

        user.connections = Some(vec![
            UserConnection {
                platform: ConnectionPlatform::Twitch,
                handle: "streamer_one".to_string(),
                display_name: "Streamer One".to_string(),
                live: true,
                live_title: Some("playing something".to_string()),
                live_since: Timestamp::now_utc()
                    .checked_add(iso8601_timestamp::Duration::hours(-1)),
            },
            UserConnection {
                platform: ConnectionPlatform::Kick,
                handle: "streamer-one".to_string(),
                display_name: "Streamer One on Kick".to_string(),
                live: false,
                live_title: None,
                live_since: None,
            },
        ]);

        insert_ok(&harness, &user).await;

        // Raw response first: the leak assertion has to be made against the
        // bytes on the wire, not against a struct that cannot represent the
        // field. The header check rides along on the same request.
        let response = harness.client.get("/discover/streamers").dispatch().await;

        assert_eq!(
            response.headers().get_one("Cache-Control"),
            Some(format!("public, max-age={}", super::CACHE_TTL).as_str()),
            "listing must carry a shared-cache lifetime matching CACHE_TTL"
        );

        let body = response.into_string().await.expect("body");

        assert!(
            !body.contains("user_id") && !body.contains("uploader_id"),
            "anonymous streamer listing leaked a user_id: {}",
            body
        );
        assert!(
            !body.contains(&uploader),
            "anonymous streamer listing leaked the avatar uploader's id: {}",
            body
        );
        assert!(
            !body.contains("object_id") && !body.contains("deleted") && !body.contains("reported"),
            "anonymous streamer listing leaked raw File internals: {}",
            body
        );
        assert!(
            !body.contains("profile_visibility") && !body.contains("relations"),
            "anonymous streamer listing leaked profile internals: {}",
            body
        );

        let listing: v0::StreamersResponse = serde_json::from_str(&body).expect("streamers json");
        let card = listing
            .streamers
            .iter()
            .find(|c| c.id == user.id)
            .expect("card present");

        assert_eq!(card.display_name.as_deref(), Some("Streamer One"));
        let avatar = card.avatar.as_ref().expect("avatar survived into the card");
        assert_eq!(avatar.filename, "avatar.png");
        assert_eq!(avatar.tag, "avatars");
        assert_eq!(card.connections.len(), 2, "connections were emptied");

        let twitch = &card.connections[0];
        assert!(matches!(twitch.platform, v0::ConnectionPlatform::Twitch));
        assert_eq!(twitch.handle, "streamer_one");
        assert!(twitch.live, "live flag did not survive into the card");
        assert_eq!(twitch.live_title.as_deref(), Some("playing something"));
        assert!(twitch.live_since.is_some());

        let kick = &card.connections[1];
        assert!(matches!(kick.platform, v0::ConnectionPlatform::Kick));
        assert!(!kick.live);
        assert!(kick.live_title.is_none());
    }

    /// The cap binds, AND it is applied after the account gate.
    ///
    /// The second half is the one with teeth. With only healthy users present
    /// this test cannot tell `.filter(is_publishable).take(MAX_STREAMERS)`
    /// — cap hoisted ahead of the account gate — from the correct order, and
    /// the whole suite stays green through that mutation. The rejected users
    /// below are minted with forced-newest ULIDs so the newest-first scan
    /// hands them over FIRST: correct code skips them and still returns 50,
    /// cap-before-gate spends 10 of its 50 slots on users it then drops and
    /// returns 40.
    #[test]
    fn streamers_caps_the_listing() {
        crate::util::test::rt().block_on(streamers_caps_the_listing_case())
    }

    async fn streamers_caps_the_listing_case() {
        const REJECTED_AT_HEAD: usize = 10;

        let harness = TestHarness::new().await;

        for _ in 0..super::MAX_STREAMERS + 12 {
            insert_ok(&harness, &fixture(Some(FOUNDING_STREAMER))).await;
        }

        // Newer than every healthy user above, so these come off the scan
        // first and a hoisted cap would burn slots on them.
        for _ in 0..REJECTED_AT_HEAD {
            insert(
                &harness,
                &newest_fixture(Some(FOUNDING_STREAMER)),
                true,
                None,
            )
            .await;
        }

        let listing = listing(&harness).await;
        assert_eq!(
            listing.streamers.len(),
            super::MAX_STREAMERS,
            "expected a full page of {} healthy streamers; {} rejected users were placed at the \
             head of the scan, so a short listing means the cap is being applied BEFORE the \
             account gate",
            super::MAX_STREAMERS,
            REJECTED_AT_HEAD
        );
    }

    /// The cache must be OFF under test. Two requests either side of a write
    /// must observe the write — if this fails, every negative assertion in
    /// this module is being served a stale body and proves nothing.
    #[test]
    fn streamers_cache_is_bypassed_under_test() {
        crate::util::test::rt().block_on(streamers_cache_is_bypassed_under_test_case())
    }

    async fn streamers_cache_is_bypassed_under_test_case() {
        let harness = TestHarness::new().await;

        let first = fixture(Some(FOUNDING_STREAMER));
        insert_ok(&harness, &first).await;

        let before = ids(&listing(&harness).await);
        assert!(before.contains(&first.id));

        // Same key, different underlying data, well inside the 30s TTL.
        let second = fixture(Some(FOUNDING_STREAMER));
        insert_ok(&harness, &second).await;

        let after = ids(&listing(&harness).await);
        assert!(
            after.contains(&second.id),
            "second request was served a cached body — the cache bypass is not working, \
             and every other test in this module is passing vacuously"
        );
        assert_ne!(before, after);
    }

    /// One account row that no longer deserializes must cost that one user,
    /// not the whole directory.
    #[test]
    fn streamers_skips_an_unreadable_account_row() {
        crate::util::test::rt().block_on(streamers_skips_an_unreadable_account_row_case())
    }

    async fn streamers_skips_an_unreadable_account_row_case() {
        use revolt_database::mongodb::bson::{doc, Document};
        use revolt_database::Database;

        let harness = TestHarness::new().await;
        let Database::MongoDb(mongo) = &harness.db else {
            return; // REFERENCE cannot hold a row that fails to deserialize
        };

        let healthy = fixture(Some(FOUNDING_STREAMER));
        insert_ok(&harness, &healthy).await;

        let broken = fixture(Some(FOUNDING_STREAMER));
        harness.db.insert_user(&broken).await.expect("insert user");
        mongo
            .col::<Document>("accounts")
            .insert_one(doc! { "_id": &broken.id, "email": 7 })
            .await
            .expect("insert malformed account");
        assert!(
            harness.db.fetch_account(&broken.id).await.is_err(),
            "fixture account row deserialized; this test would prove nothing"
        );

        let response = harness.client.get("/discover/streamers").dispatch().await;
        assert_eq!(
            response.status(),
            rocket::http::Status::Ok,
            "one unreadable account row failed the whole directory"
        );

        let listing: v0::StreamersResponse =
            serde_json::from_str(&response.into_string().await.expect("body"))
                .expect("streamers json");
        let ids = ids(&listing);
        assert!(ids.contains(&healthy.id), "healthy streamer must be listed");
        assert!(
            !ids.contains(&broken.id),
            "a user whose account could not be read must fail closed"
        );
    }

    /// The in-process copy is served for exactly `CACHE_TTL`.
    #[test]
    fn local_cache_freshness_tracks_the_cache_ttl() {
        use std::time::{Duration, Instant};

        let stored_at = Instant::now();
        let entry = (stored_at, v0::StreamersResponse { streamers: vec![] });
        let ttl = Duration::from_secs(super::CACHE_TTL as u64);

        assert!(super::fresh(None, stored_at).is_none());
        assert!(super::fresh(Some(&entry), stored_at).is_some());
        assert!(super::fresh(Some(&entry), stored_at + ttl - Duration::from_millis(1)).is_some());
        assert!(
            super::fresh(Some(&entry), stored_at + ttl).is_none(),
            "an entry CACHE_TTL old must be stale"
        );
    }

    /// Requests arriving together all complete: the single-flight permit is
    /// released after each miss rather than held, which would hang the rest.
    #[test]
    fn streamers_concurrent_requests_all_complete() {
        crate::util::test::rt().block_on(streamers_concurrent_requests_all_complete_case())
    }

    async fn streamers_concurrent_requests_all_complete_case() {
        let harness = TestHarness::new().await;

        let user = fixture(Some(FOUNDING_STREAMER));
        insert_ok(&harness, &user).await;

        let responses = futures::future::join_all(
            (0..6).map(|_| harness.client.get("/discover/streamers").dispatch()),
        )
        .await;

        for response in responses {
            assert_eq!(response.status(), rocket::http::Status::Ok);
        }

        assert!(ids(&listing(&harness).await).contains(&user.id));
    }
}
