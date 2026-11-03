//! A revoked E2EE device leaves every call it is seated in.
//!
//! When a device is revoked, its SFU seats go with it: the device-qualified
//! primary `{user}:{device}` and that primary's screen leg, in every voice
//! channel the user is in. The user's other devices, and everyone else, keep
//! their seats. The other members then remove the device's MLS leaf through
//! their normal leave-grace, as they would for any member who left.
//!
//! Best-effort throughout: it never returns an error, never panics, and runs
//! under ONE bound ([`EVICTION_BUDGET`]), because the revoke that calls it
//! has already happened and must not wait on, or fail with, the SFU.

use std::{future::Future, time::Duration};

use revolt_result::Result;

use super::{
    get_channel_node, get_user_voice_channels, move_token_identity, screen_leg_identity,
    UserVoiceChannel, VoiceClient,
};

/// The bound on the WHOLE of [`evict_revoked_device`]: the Redis reads, the
/// listing of every channel and every removal, together.
///
/// At most 5 s, because the revoke awaits it. Longer than one SFU call's own
/// deadline (`SFU_CALL_TIMEOUT`, 3 s), so a single slow call does not use up
/// the whole budget before it can answer. Each SFU call still runs under that
/// per-call deadline as well; this bound is what caps their sum when the user
/// is in several channels or the node is slow.
const EVICTION_BUDGET: Duration = Duration::from_secs(5);

/// Remove a revoked device's SFU seats from every voice channel its user is
/// in: the primary `{user_id}:{device_id}` and its screen leg, nothing else.
///
/// Best-effort and bounded by [`EVICTION_BUDGET`]: a failure is logged (with
/// channel ids only) and the rest carries on. Returns nothing, so a revoke can
/// never fail because of it.
pub async fn evict_revoked_device(voice_client: &VoiceClient, user_id: &str, device_id: &str) {
    evict_within(
        EVICTION_BUDGET,
        voice_client,
        user_id,
        device_id,
        get_user_voice_channels(user_id),
        |channel_id: String| async move { get_channel_node(&channel_id).await },
    )
    .await;
}

/// [`evict_revoked_device`] with the bound and the two Redis reads passed in,
/// so the tests can drive the whole flow against an SFU stub without Redis.
/// The bound covers everything, the reads included: `channels` is a future
/// that has not been polled yet.
async fn evict_within<C, N, NF>(
    budget: Duration,
    voice_client: &VoiceClient,
    user_id: &str,
    device_id: &str,
    channels: C,
    node_of: N,
) where
    C: Future<Output = Result<Vec<UserVoiceChannel>>>,
    N: Fn(String) -> NF,
    NF: Future<Output = Result<Option<String>>>,
{
    let work = evict_everywhere(voice_client, user_id, device_id, channels, node_of);
    if tokio::time::timeout(budget, work).await.is_err() {
        log::warn!("revoked-device seat eviction stopped after {budget:?} with work outstanding");
    }
}

async fn evict_everywhere<C, N, NF>(
    voice_client: &VoiceClient,
    user_id: &str,
    device_id: &str,
    channels: C,
    node_of: N,
) where
    C: Future<Output = Result<Vec<UserVoiceChannel>>>,
    N: Fn(String) -> NF,
    NF: Future<Output = Result<Option<String>>>,
{
    // Only a well-formed device seat is ever addressed. An empty or
    // colon-bearing id would compose an identity of another shape: with an
    // empty device, `{user}:` derives the leg `{user}::screen`, which is the
    // BARE seat's leg.
    let well_formed = |id: &str| !id.is_empty() && !id.contains(':');
    if !well_formed(user_id) || !well_formed(device_id) {
        log::warn!("revoked-device seat eviction skipped: the identity is not a device seat");
        return;
    }

    if !voice_client.is_enabled() {
        return;
    }

    let primary = move_token_identity(user_id, Some(device_id));

    let channels = match channels.await {
        Ok(channels) => channels,
        Err(_) => {
            log::warn!(
                "revoked-device seat eviction skipped: the voice channels could not be read"
            );
            return;
        }
    };

    for channel in channels {
        let node = match node_of(channel.id.clone()).await {
            Ok(Some(node)) => node,
            Ok(None) => continue,
            Err(_) => {
                log::warn!(
                    "revoked-device seat eviction skipped voice channel {}: its node could not \
                     be read",
                    channel.id
                );
                continue;
            }
        };
        evict_in_room(voice_client, &node, &channel.id, &primary).await;
    }
}

/// One room: list it, then remove the seats [`seats_to_remove`] picks, each
/// on its own, so one failed removal does not stop the next.
///
/// `remove_identity_if_present` is the removal: by exact identity, with
/// "not in the room" as an answer. Its own WARN on a real failure names the
/// identity it was asked to remove; that is the one place a seat identity
/// reaches the log from here, accepted on purpose. The transport's
/// non-logging removal is private to it, and `remove_connection_if_present`
/// reports a failure at ERROR to Sentry instead.
async fn evict_in_room(voice_client: &VoiceClient, node: &str, room: &str, primary: &str) {
    let listed = match voice_client.list_participants_if_present(node, room).await {
        Ok(Some(listed)) => listed,
        Ok(None) => return,
        Err(_) => {
            log::warn!("revoked-device seat eviction could not list voice channel {room}");
            return;
        }
    };

    let seats = seats_to_remove(
        listed
            .iter()
            .map(|participant| participant.identity.as_str()),
        primary,
    );

    let (mut removed, mut failed) = (0usize, 0usize);
    for seat in &seats {
        match voice_client
            .remove_identity_if_present(node, seat, room)
            .await
        {
            Ok(true) => removed += 1,
            Ok(false) => {}
            Err(_) => failed += 1,
        }
    }

    if removed > 0 {
        log::info!(
            "revoked-device seat eviction removed {removed} seat(s) from voice channel {room}"
        );
    }
    if failed > 0 {
        log::warn!(
            "revoked-device seat eviction failed to remove {failed} seat(s) from voice channel {room}"
        );
    }
}

/// The seats to remove from a room whose participants are `listed`: if the
/// primary or its screen leg is listed, both, the primary first. Nothing
/// otherwise.
///
/// The primary goes first because it is the only one of the two seats that
/// can subscribe: under a slow SFU the budget is spent on removing it before
/// anything else.
///
/// Both halves go once either is listed, because the leg is a pure function
/// of the primary: a leg that joined after the listing is still reached, and
/// a half that is already gone answers "not in the room", which is no
/// failure. Matching is by EXACT identity, so another device of the same
/// user, the bare seat and its leg, and an id that merely extends this
/// device's are never selected.
fn seats_to_remove<'a>(listed: impl IntoIterator<Item = &'a str>, primary: &str) -> Vec<String> {
    let leg = screen_leg_identity(primary);
    if listed
        .into_iter()
        .any(|identity| identity == primary || identity == leg)
    {
        vec![primary.to_string(), leg]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{evict_revoked_device, evict_within, seats_to_remove, EVICTION_BUDGET};
    use crate::voice::{
        voice_client::sfu_stub::{
            self, identity, internal, list_participants_response, ok, routes, Stub, LIST, NODE,
            REMOVE,
        },
        UserVoiceChannel, VoiceClient, SFU_BREAKER_WINDOW, SFU_CALL_TIMEOUT,
    };
    use revolt_result::{create_error, Error, Result};
    use std::{
        collections::HashMap,
        future::{ready, Ready},
        sync::atomic::{AtomicBool, Ordering},
        time::{Duration, Instant},
    };

    const U: &str = "01KX7HASD9FHBYA3XGKA5YACYX";
    const V: &str = "01KX7HASD9FHBYA3XGKA5YACYZ";
    const DEV: &str = "4208aa7e9ff58761b2d7a5d6c45f7383";
    const OTHER: &str = "9c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f";
    const ROOM: &str = "01KX7HASD9FHBYA3XGKA5YROOM";

    fn primary() -> String {
        format!("{U}:{DEV}")
    }

    fn leg() -> String {
        format!("{U}:{DEV}:screen")
    }

    fn requests(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(path, identity)| (path.to_string(), identity.to_string()))
            .collect()
    }

    fn channel(id: &str) -> UserVoiceChannel {
        UserVoiceChannel {
            id: id.to_string(),
            server_id: None,
        }
    }

    fn one_channel() -> Ready<Result<Vec<UserVoiceChannel>>> {
        ready(Ok(vec![channel(ROOM)]))
    }

    fn on_stub_node(_: String) -> Ready<Result<Option<String>>> {
        ready(Ok(Some(NODE.to_string())))
    }

    /// The listing holds the revoked seat and its leg among every near miss:
    /// another device of the same user, another user on the same device id,
    /// the bare seat and its leg, and an id that extends this device's. Only
    /// the primary and its leg are removed, the primary first.
    ///
    /// Mutation caught: selecting by user id (or by prefix) instead of by
    /// exact identity, which also removes `U:OTHER`, the bare seat and its
    /// leg, and `U:DEV0`.
    #[tokio::test]
    async fn removes_the_revoked_seat_and_its_leg_and_nothing_else() {
        let (primary, leg) = (primary(), leg());
        let (other, bare_leg, longer) = (
            format!("{U}:{OTHER}"),
            format!("{U}::screen"),
            format!("{U}:{DEV}0"),
        );
        let stranger = format!("{V}:{DEV}");
        let listed = list_participants_response(&[
            (U, ""),
            (&bare_leg, ""),
            (&other, ""),
            (&primary, ""),
            (&stranger, ""),
            (&leg, ""),
            (&longer, ""),
        ]);
        let stub = Stub::serve(routes(vec![(LIST, ok(listed)), (REMOVE, ok(Vec::new()))]));

        evict_within(
            EVICTION_BUDGET,
            &sfu_stub::voice_client(stub.url()),
            U,
            DEV,
            one_channel(),
            on_stub_node,
        )
        .await;

        assert_eq!(
            stub.finish(),
            requests(&[(LIST, ""), (REMOVE, &primary), (REMOVE, &leg)])
        );
    }

    /// A failed listing removes nothing, issues no blind removal, and does
    /// not panic.
    ///
    /// Mutation caught: falling back to removing the derived identities
    /// unlisted when the listing fails.
    #[tokio::test]
    async fn a_failed_listing_removes_nothing() {
        let stub = Stub::serve(routes(vec![(LIST, internal()), (REMOVE, ok(Vec::new()))]));

        evict_within(
            EVICTION_BUDGET,
            &sfu_stub::voice_client(stub.url()),
            U,
            DEV,
            one_channel(),
            on_stub_node,
        )
        .await;

        assert_eq!(stub.finish(), requests(&[(LIST, "")]));
    }

    /// An SFU that takes the request and never answers: the eviction comes
    /// back on its own once the budget runs out, even with a per-call
    /// deadline far longer than the budget.
    ///
    /// Mutation caught: the `tokio::time::timeout` around the work removed,
    /// which waits out the 60 s per-call deadline here.
    #[tokio::test]
    async fn a_stuck_sfu_returns_within_the_budget() {
        const BUDGET: Duration = Duration::from_millis(300);
        const OUTER: Duration = Duration::from_secs(10);

        let stub = Stub::silent();
        let client = sfu_stub::voice_client_with_bounds(
            stub.url(),
            Duration::from_secs(60),
            SFU_BREAKER_WINDOW,
        );

        let started = Instant::now();
        let outcome = tokio::time::timeout(
            OUTER,
            evict_within(BUDGET, &client, U, DEV, one_channel(), on_stub_node),
        )
        .await;
        let elapsed = started.elapsed();
        let seen = stub.finish();

        assert!(
            outcome.is_ok(),
            "still waiting after {OUTER:?}: the eviction has no bound of its own"
        );
        assert!(
            elapsed >= BUDGET,
            "returned after {elapsed:?}, before the {BUDGET:?} budget: the SFU was never waited on"
        );
        assert_eq!(
            seen,
            requests(&[(LIST, "")]),
            "the stub never saw the listing"
        );
    }

    /// Best-effort per channel and per seat. Four channels: one whose node
    /// cannot be read, one with no node, one whose listing fails, and last one
    /// whose primary removal fails. The last channel is still listed, and its
    /// leg is still removed after the failed primary.
    ///
    /// Mutations caught: `return` (or `break`) instead of `continue` on a
    /// node read error or a missing node, and stopping a room's removals at
    /// the first failed one.
    #[tokio::test]
    async fn one_failure_does_not_stop_the_rest() {
        const NODE_A: &str = "node-a";
        const NODE_B: &str = "node-b";
        let (primary, leg) = (primary(), leg());

        let failing_list = Stub::serve(routes(vec![(LIST, internal())]));
        let listed = list_participants_response(&[(&primary, ""), (&leg, "")]);
        let failing_primary = primary.clone();
        let failing_primary_removal = Stub::serve(move |path, body| match path {
            LIST => ok(listed.clone()),
            REMOVE if identity(body).as_deref() == Some(failing_primary.as_str()) => internal(),
            REMOVE => ok(Vec::new()),
            _ => internal(),
        });
        let client = sfu_stub::voice_client_nodes(
            &[
                (NODE_A, failing_list.url()),
                (NODE_B, failing_primary_removal.url()),
            ],
            SFU_CALL_TIMEOUT,
            SFU_BREAKER_WINDOW,
        );

        let channels = ready(Ok(vec![
            channel("unreadable"),
            channel("nodeless"),
            channel("unlisted"),
            channel(ROOM),
        ]));
        let node_of = |channel_id: String| {
            ready(match channel_id.as_str() {
                "unreadable" => Err(create_error!(InternalError)),
                "nodeless" => Ok(None),
                "unlisted" => Ok(Some(NODE_A.to_string())),
                _ => Ok(Some(NODE_B.to_string())),
            })
        };

        evict_within(EVICTION_BUDGET, &client, U, DEV, channels, node_of).await;

        assert_eq!(failing_list.finish(), requests(&[(LIST, "")]));
        assert_eq!(
            failing_primary_removal.finish(),
            requests(&[(LIST, ""), (REMOVE, &primary), (REMOVE, &leg)])
        );
    }

    /// The user's voice channels cannot be read: no node is looked up and the
    /// SFU is never called.
    ///
    /// Mutation caught: an `unwrap` or `expect` on the channel read, which
    /// panics here. (Carrying on with an empty list instead would be
    /// harmless, and is not what this pins.)
    #[tokio::test]
    async fn an_unreadable_channel_list_calls_nothing() {
        let stub = Stub::serve(routes(vec![(LIST, ok(Vec::new()))]));
        let looked_up = AtomicBool::new(false);

        evict_within(
            EVICTION_BUDGET,
            &sfu_stub::voice_client(stub.url()),
            U,
            DEV,
            ready(Err(create_error!(InternalError))),
            |_: String| {
                looked_up.store(true, Ordering::SeqCst);
                ready(Ok(Some(NODE.to_string())))
            },
        )
        .await;

        assert!(!looked_up.load(Ordering::SeqCst));
        assert!(stub.finish().is_empty());
    }

    /// A user or device id that is empty or carries a `:` addresses nothing:
    /// the channel list is never read and the SFU is never called, even when
    /// the room holds the bare seat and its leg.
    ///
    /// Mutation caught: the well-formedness guard removed. An empty device id
    /// then composes `U:`, whose derived leg is `U::screen`, the bare seat's
    /// leg, which this listing holds, so the bare seat's leg and `U:` are
    /// removed.
    #[tokio::test]
    async fn an_identity_that_is_not_a_device_seat_evicts_nothing() {
        let bare_leg = format!("{U}::screen");
        let listed = list_participants_response(&[(U, ""), (&bare_leg, "")]);

        for (user_id, device_id) in [(U, ""), (U, "a:b"), ("", DEV), ("x:y", DEV)] {
            let stub = Stub::serve(routes(vec![
                (LIST, ok(listed.clone())),
                (REMOVE, ok(Vec::new())),
            ]));
            let read = AtomicBool::new(false);
            let channels = async {
                read.store(true, Ordering::SeqCst);
                Ok::<_, Error>(vec![channel(ROOM)])
            };

            evict_within(
                EVICTION_BUDGET,
                &sfu_stub::voice_client(stub.url()),
                user_id,
                device_id,
                channels,
                on_stub_node,
            )
            .await;

            assert!(
                !read.load(Ordering::SeqCst),
                "({user_id:?}, {device_id:?}): the channel list was read"
            );
            assert!(
                stub.finish().is_empty(),
                "({user_id:?}, {device_id:?}): the SFU was called"
            );
        }
    }

    /// With no SFU node configured (voice off), not even the channel list is
    /// read.
    ///
    /// Mutation caught: the `is_enabled` early return removed.
    #[tokio::test]
    async fn with_voice_off_nothing_is_read() {
        let read = AtomicBool::new(false);
        let channels = async {
            read.store(true, Ordering::SeqCst);
            Ok::<_, Error>(vec![channel(ROOM)])
        };

        evict_within(
            EVICTION_BUDGET,
            &VoiceClient::new(HashMap::new()),
            U,
            DEV,
            channels,
            on_stub_node,
        )
        .await;

        assert!(!read.load(Ordering::SeqCst));
    }

    /// Either half listed takes both, the primary first; neither listed
    /// takes nothing; near misses never count as a listing of this seat.
    ///
    /// Mutations caught: dropping the half that was not listed (a leg that
    /// joined after the listing would keep its seat), and removing the leg
    /// before the primary.
    #[test]
    fn either_half_listed_takes_both_primary_first() {
        let (primary, leg) = (primary(), leg());
        let both = vec![primary.clone(), leg.clone()];

        assert_eq!(seats_to_remove([primary.as_str()], &primary), both);
        assert_eq!(seats_to_remove([leg.as_str()], &primary), both);
        assert_eq!(
            seats_to_remove([leg.as_str(), primary.as_str()], &primary),
            both
        );

        let other = format!("{U}:{OTHER}");
        let other_leg = format!("{U}:{OTHER}:screen");
        let bare_leg = format!("{U}::screen");
        let longer = format!("{U}:{DEV}0");
        let near_misses = [
            U,
            other.as_str(),
            other_leg.as_str(),
            bare_leg.as_str(),
            longer.as_str(),
        ];
        assert!(seats_to_remove(near_misses, &primary).is_empty());
        assert!(seats_to_remove([], &primary).is_empty());
    }

    /// The budget is a named bound of at most 5 s that still outlasts one
    /// SFU call's own deadline.
    ///
    /// Mutation caught: the budget raised past 5 s, or cut below the per-call
    /// deadline.
    #[test]
    fn the_budget_is_at_most_five_seconds() {
        assert!(
            EVICTION_BUDGET <= Duration::from_secs(5),
            "{EVICTION_BUDGET:?}"
        );
        assert!(EVICTION_BUDGET > SFU_CALL_TIMEOUT, "{EVICTION_BUDGET:?}");
    }

    /// The public entry point's future is `Send`, so a route handler or a
    /// spawned task can await it. Built and dropped, never polled, so no
    /// Redis is touched.
    ///
    /// Mutation caught: anything non-`Send` held across an await in the
    /// eviction, which would stop every caller from compiling only when it
    /// is spawned.
    #[test]
    fn the_eviction_future_is_send() {
        fn assert_send<T: Send>(_: &T) {}

        let client = VoiceClient::new(HashMap::new());
        let future = evict_revoked_device(&client, U, DEV);
        assert_send(&future);
        drop(future);
    }
}
