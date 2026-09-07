use revolt_ratelimits::ratelimiter::RatelimitResolver;
use rocket::{http::Method, Request};

pub struct DeltaRatelimits;

impl<'a> RatelimitResolver<Request<'a>> for DeltaRatelimits {
    fn resolve_bucket<'r>(&self, request: &'r Request<'_>) -> (&'r str, Option<&'r str>) {
        let versioned = request.routed_segment(0) == Some("0.8");
        let (segment, resource, extra) = if versioned {
            (
                request.routed_segment(1),
                request.routed_segment(2),
                request.routed_segment(3),
            )
        } else {
            (
                request.routed_segment(0),
                request.routed_segment(1),
                request.routed_segment(2),
            )
        };

        if let Some(segment) = segment {
            #[allow(clippy::redundant_locals)]
            let resource = resource;

            let method = request.method();
            match (segment, resource, method) {
                ("users", target, Method::Patch) => ("user_edit", target),
                // Respect wall writes (PUT …/respect, DELETE …/respect/<author>)
                // get their own bucket, keyed per wall — writing is a
                // deliberate, user-paced action, and a spammer must not be
                // able to churn someone else's wall at the generic users
                // rate. This arm must sit ABOVE the ("users", _, _) fallback.
                ("users", target, Method::Put | Method::Delete) if extra == Some("respect") => {
                    ("respect", target)
                }
                ("users", _, _) => {
                    if let Some("default_avatar") = extra {
                        return ("default_avatar", None);
                    }

                    ("users", None)
                }
                ("bots", _, _) => {
                    // Command registration is bounded separately from general
                    // bot management (audit: dedicated bucket).
                    if let Some("commands") = extra {
                        return ("bot_commands", None);
                    }

                    ("bots", None)
                }
                ("channels", Some(id), _) => {
                    // Vote casts / retractions (PUT+DELETE …/polls/<id>/vote)
                    // get their own bucket to stop vote-flip spam amplifying
                    // the count-only WS fan-out.
                    if matches!(request.method(), Method::Put | Method::Delete)
                        && extra == Some("polls")
                    {
                        return ("poll_vote", Some(id));
                    }

                    // Remote control needs TWO buckets, and this arm must
                    // sit ABOVE the POST-only block below: all four routes
                    // collapse onto extra == Some("control"), and PUT
                    // …/control/offers/<id>/respond and DELETE
                    // …/control/<grant_id> never reach that block, so they
                    // would otherwise fall through to the plain channels
                    // bucket. The heartbeat is sharer-driven at a
                    // single-digit-second cadence — sharing one tight
                    // bucket with `offer` would starve it and expire live
                    // grants mid-control.
                    if extra == Some("control") {
                        // The sharer's consent heartbeat, and the DELETE
                        // release, share the GENEROUS bucket. The release
                        // is a teardown — being ratelimited out of ending
                        // a control session is strictly worse than being
                        // ratelimited out of starting one — and a caller
                        // who has just spent the tight bucket on offers is
                        // exactly the caller most likely to need it.
                        if matches!(request.method(), Method::Delete)
                            || (request.method() == Method::Post
                                && request.routed_segment(if versioned { 4 } else { 3 })
                                    == Some("heartbeat"))
                        {
                            return ("remote_control_heartbeat", Some(id));
                        }

                        // POST …/control/request ("ask for a turn") gets its
                        // own bucket, checked BEFORE the offer arm below
                        // swallows every remaining POST. It must not share
                        // `remote_control_offer` (2/10s) in either direction:
                        // a spectator's raised hands must never spend the
                        // SHARER's offer budget mid-rotation, and one asker
                        // re-asking must not be able to drain it either.
                        if request.method() == Method::Post
                            && request.routed_segment(if versioned { 4 } else { 3 })
                                == Some("request")
                        {
                            return ("control_request", Some(id));
                        }

                        // POST …/control/offer and PUT …/respond: deliberate,
                        // user-paced actions, held to the tight bucket.
                        if matches!(request.method(), Method::Post | Method::Put) {
                            return ("remote_control_offer", Some(id));
                        }
                    }

                    // Reserve set/retract (PUT+DELETE …/softres/<id>/reserve)
                    // gets its own bucket to bound reserve-flip WS fan-out.
                    // The trailing literal segment MUST be checked: a bare
                    // method+extra match would drag DELETE …/softres/<id>/lock
                    // (manage-gated unlock) into the tight bucket. (Segment
                    // index shifts by one under the legacy "0.8" prefix.)
                    if matches!(request.method(), Method::Put | Method::Delete)
                        && extra == Some("softres")
                        && request.routed_segment(if versioned { 5 } else { 4 })
                            == Some("reserve")
                    {
                        return ("softres_reserve", Some(id));
                    }

                    // Scheduled-message routes (POST/GET
                    // …/scheduled_messages, DELETE …/scheduled_messages/
                    // <id>) manage a queue rather than creating live
                    // messages — they get their own bucket.
                    if extra == Some("scheduled_messages") {
                        return ("message_schedule", Some(id));
                    }

                    // Soundboard triggers fan audio to the whole call, so bound
                    // them tighter than plain messaging (per user, per channel).
                    if request.method() == Method::Post && extra == Some("soundboard") {
                        return ("soundboard", Some(id));
                    }

                    // Live captions are speech-paced rather than user-paced —
                    // one request per finalized utterance — so they need their
                    // own generous bucket. Sharing `soundboard` (4/10s) would
                    // silently swallow captions the moment anyone spoke in
                    // short sentences.
                    if request.method() == Method::Post && extra == Some("captions") {
                        return ("captions", Some(id));
                    }

                    // Annotation strokes are pointer-paced — the client
                    // coalesces to ≤10 Hz, so a live drawing session runs at
                    // ~100 requests per 10s window and needs its OWN generous
                    // bucket. The consent routes (…/annotations/allow) are
                    // user-paced list management and must NOT share it in
                    // either direction: a drawing helper must not spend the
                    // sharer's revoke budget, and the tight consent bucket
                    // must not swallow mid-stroke sends. Neither may fall
                    // through to the plain channels bucket (20/10s), which a
                    // steady drawing hand would exhaust in two seconds.
                    if extra == Some("annotations") {
                        if request.routed_segment(if versioned { 4 } else { 3 })
                            == Some("allow")
                        {
                            return ("annotations_consent", Some(id));
                        }
                        if request.method() == Method::Post {
                            return ("annotations", Some(id));
                        }
                    }

                    // Watch-together control writes are host-paced but bursty:
                    // a 5 s heartbeat plus seek-scrubbing the client debounces
                    // to ≤4/s is ~40 per 10 s window, well past the plain
                    // channels bucket — a scrubbing host would be 429'd
                    // mid-seek. Own bucket (plan §1.1).
                    if extra == Some("watch") {
                        return ("watch", Some(id));
                    }

                    // Following an announcement channel creates a webhook in
                    // the target and fans events to two server topics — bound
                    // it separately (both POST create and DELETE unfollow live
                    // under the `follow` segment). Publishing (crosspost) has
                    // extra == Some("messages") and shares the messaging
                    // bucket, additionally capped by the durable hourly limit
                    // enforced in the route.
                    if extra == Some("follow") {
                        return ("follow", Some(id));
                    }

                    if request.method() == Method::Post {
                        // Component clicks wake a bot per call — bounded
                        // separately from plain messaging. (Segment index
                        // shifts by one under the legacy "0.8" prefix.)
                        if extra == Some("messages")
                            && request.routed_segment(if versioned { 5 } else { 4 })
                                == Some("interact")
                        {
                            return ("message_interact", Some(id));
                        }

                        // Dice rolls create messages, so they share the
                        // messaging bucket — as do forwards
                        // (POST …/messages/<msg>/forward), which land here
                        // via the "messages" segment so a client cannot
                        // interleave forwards and sends to exceed the
                        // per-channel message rate.
                        if let Some("messages" | "roll") = extra {
                            return ("messaging", Some(id));
                        }

                        // Poll creation creates a message → messaging bucket
                        // (roll precedent). The bulk state fetch
                        // (POST …/polls/fetch — literal at segment 3) and
                        // manual close (POST …/polls/<poll_id>/end — literal
                        // at segment 4) are reads/updates, not message sends
                        // — they fall through to the channels bucket. All
                        // indexes shift by one under the legacy "0.8" prefix.
                        if extra == Some("polls") {
                            let seg3 =
                                request.routed_segment(if versioned { 4 } else { 3 });
                            let seg4 =
                                request.routed_segment(if versioned { 5 } else { 4 });
                            if seg3 != Some("fetch") && seg4 != Some("end") {
                                return ("messaging", Some(id));
                            }
                        }

                        // Sheet creation creates a message → messaging bucket
                        // (poll/roll precedent). Only the BARE create
                        // (POST …/softres, no further segment) is a message
                        // send; the bulk state fetch (POST …/softres/fetch)
                        // and manual lock (POST …/softres/<id>/lock) fall
                        // through to the channels bucket.
                        if extra == Some("softres")
                            && request
                                .routed_segment(if versioned { 4 } else { 3 })
                                .is_none()
                        {
                            return ("messaging", Some(id));
                        }

                        // Thread creation is bounded per parent channel to cap
                        // fan-out abuse.
                        if let Some("threads") = extra {
                            return ("thread_create", Some(id));
                        }

                        // Forum post creation is stricter than plain messaging
                        // (every post fans out a ChannelCreate to the server).
                        if let Some("posts") = extra {
                            return ("forum_post_create", Some(id));
                        }

                        // Command invocations wake a bot per call — bound
                        // the spam separately from plain messaging.
                        if let Some("interactions") = extra {
                            // Autocomplete is KEYSTROKE-paced, not
                            // user-paced, and must not share the invocation
                            // bucket in either direction: typing an argument
                            // would otherwise exhaust the budget and 429 the
                            // command the user was composing. (Segment index
                            // shifts by one under the legacy "0.8" prefix.)
                            if request.routed_segment(if versioned { 4 } else { 3 })
                                == Some("autocomplete")
                            {
                                return ("interaction_autocomplete", Some(id));
                            }

                            return ("interaction_create", Some(id));
                        }
                    }

                    ("channels", Some(id))
                }
                ("interactions", _, _) => {
                    // The bot's side of the same keystroke-paced exchange
                    // gets its OWN bucket, not the asking side's: bot-token
                    // requests carry no session, so they are keyed by IP —
                    // one counter for every user of every bot on that host.
                    // Sized against the asking side's per-user-per-channel
                    // budget times a plausible number of concurrent typists,
                    // which is safe because this side is already bounded by
                    // something stricter than a counter: every request must
                    // present an unused single-use token for an interaction
                    // the server itself created less than a minute earlier.
                    if extra == Some("autocomplete") {
                        return ("interaction_autocomplete_respond", None);
                    }

                    ("interaction_respond", None)
                }
                // Public unauthenticated directory (identity falls back to
                // IP for sessionless requests) — dedicated bucket so a burst
                // against /discover can't starve the shared "any" bucket.
                ("discover", _, _) => ("discover", None),
                ("servers", Some(id), _) => ("servers", Some(id)),
                ("auth", _, _) => {
                    if request.method() == Method::Delete {
                        ("auth_delete", None)
                    } else {
                        ("auth", None)
                    }
                }
                ("swagger", _, _) => ("swagger", None),
                ("safety", Some("report"), _) => ("safety_report", Some("report")),
                ("safety", _, _) => ("safety", None),
                // Bundle fetches are keyed by target user: probing one
                // user's keys can't be amortised across targets
                ("e2ee", Some("keys"), Method::Get) => ("e2ee_fetch_keys", extra),
                // Signed device listings get their own bucket, sized for the
                // bursts a client legitimately produces rather than for a
                // user-paced action. A session reads its OWN listing twice
                // on every connect (post-claim reconcile + one-time-key
                // replenish), once more per own-device event, once per DM
                // opened, and a media call reconciles every roster user on
                // establish, on each join request it admits and on each
                // Welcome/Add it processes. A fresh enrollment fans its own
                // DeviceCreate back at the enrolling session on top of all
                // that. Sharing the 10-per-window `e2ee` bucket with the key
                // publish and backup routes let a fresh enrollment answer 429
                // to the reconcile that pins a peer's leaf (observed live
                // 2026-09-06), and a failed reconcile is swallowed on the
                // call plane: the peer stays unverifiable and the admit is
                // refused. The listing is a cheap eligibility-gated read, so
                // headroom costs nothing.
                ("e2ee", Some("devices"), Method::Get) => ("e2ee_devices", None),
                ("e2ee", Some("messages"), Method::Post) => ("e2ee_messages", None),
                // The MFA-gated key-backup RESTORE fetch (`GET /e2ee/backup`)
                // gets a tight dedicated bucket — it is rare. The metadata
                // `GET /e2ee/backup/status` (settings-card/nag poller) uses the
                // normal e2ee bucket (LOW-4).
                ("e2ee", Some("backup"), Method::Get) => {
                    if extra == Some("status") {
                        ("e2ee", None)
                    } else {
                        ("e2ee_backup_get", None)
                    }
                }
                ("e2ee", _, _) => ("e2ee", None),
                // The MLS delivery service used to fall through to the shared
                // `any` bucket (20 per window), competing with every unmapped
                // startup route (sync, push, onboard, invites, custom). A
                // two-party call bring-up alone is an open-group probe, a
                // group create, a join intent re-broadcast every 10 s, a
                // KeyPackage claim, one or two commits and the startup
                // KeyPackage publish; a churny three-party call with rejoins
                // doubles that. Own bucket so a call cannot be 429'd into a
                // wedge by unrelated traffic in the same window, and vice
                // versa. Per-target claim budgets, the join-intent slowmode
                // and the ctl burst cap bound abuse of the individual routes
                // independently of this counter.
                ("mls", _, _) => ("mls", None),
                // Event creation (keyed per server) and invites (keyed per event) get
                // tight dedicated buckets — invites fan out to notifications in slice D.
                ("events", Some("server"), Method::Post) => ("events_create", extra),
                ("events", Some("event"), Method::Post) => ("events_invite", extra),
                ("events", _, _) => ("events", None),
                // GIF picker proxy — search fires per keystroke, so give it
                // headroom above the shared "any" bucket (server-side caching
                // keeps the upstream provider quota safe regardless).
                ("gifs", _, _) => ("gifs", None),
                // Starting an import kicks off a whole server build — keep it
                // tight. Job polling is only a reconnect fallback (progress
                // normally arrives over the WebSocket) so it stays modest too.
                ("import", Some("discord"), Method::Post) => ("import_start", None),
                ("import", _, _) => ("import", None),
                // Static loot-catalog reads (cheap, client-cached for a day)
                // get headroom above the shared "any" bucket. The sheet and
                // reserve routes are channel-scoped and are bounded by the
                // channels/messaging buckets plus the softres_reserve arm
                // above.
                ("softres", _, _) => ("softres_catalog", None),
                _ => ("any", None),
            }
        } else {
            ("any", None)
        }
    }

    fn resolve_bucket_limit(&self, bucket: &str) -> u32 {
        match bucket {
            "user_edit" => 2,
            "users" => 20,
            "bots" => 10,
            "messaging" => 10,
            "channels" => 15,
            "servers" => 5,
            "auth" => 15,
            "auth_delete" => 255,
            "default_avatar" => 255,
            "swagger" => 100,
            "safety" => 15,
            "safety_report" => 3,
            "gifs" => 30,
            "import_start" => 5,
            "import" => 30,
            "e2ee_fetch_keys" => 10,
            "e2ee_messages" => 30,
            "e2ee_backup_get" => 3,
            "e2ee" => 10,
            // Device listings: see the resolver. The admitter's roster
            // reconcile fetches EVERY distinct non-self user in the SFU
            // roster on every join request, not just the joiner, so a
            // ten-member call whose members all arrive inside one window
            // costs the lowest-leaf admitter 1+2+...+9 = 45 listings, plus
            // its two own-listing reads on connect, the DeviceCreate echo of
            // a fresh enrollment, one leaf-verify reconcile per Welcome/Add
            // that arrives unpinned (<= 9) and a 5 s admit re-drive that
            // repeats the roster fetch (<= 9): about 66. The previous 30
            // covered a three-party call and 429'd a five-party one. 120
            // leaves ~1.8x headroom; the read is cheap, eligibility-gated
            // and keyed per session.
            //
            // Together with the MLS bucket below this covers about TWELVE
            // members all arriving inside one 10 s window; the listing
            // bucket binds first (a fourteen-member burst is ~120
            // listings, the MLS bucket only runs out near twenty). The
            // roster ceiling is MAX_MLS_GROUP_MEMBERS = 100 and the video
            // cap 30, so a larger call is possible and past the covered
            // size it degrades VISIBLY, never silently: the admit whose
            // listing was refused aborts as `listing_unavailable`, the
            // roster reconcile reports that joiner non-enrolled, and the
            // client shows the mixed-call banner with publishing paused
            // until the 5 s admit re-drive lands in a later window.
            "e2ee_devices" => 120,
            // MLS delivery service: see the resolver. The busiest member of
            // a ten-member bring-up is the lowest-leaf admitter: probe +
            // create + KeyPackage publish (3), then a claim and a commit per
            // joiner (18), plus a rebase resubmit for every arbitration it
            // loses (<= 9) — about 30 inside one window when everyone
            // arrives at once, which the previous 30 had no headroom over.
            // 60 leaves 2x; the per-target claim budget, the join-intent
            // slowmode and the ctl burst cap still bound each route.
            "mls" => 60,
            "events_create" => 10,
            "events_invite" => 5,
            "events" => 30,
            "thread_create" => 5,
            "forum_post_create" => 5,
            "interaction_create" => 10,
            // Asking side, keyed per user per channel. The client debounces
            // to ~3/s, so a continuously typing hand is about 30 per 10s
            // window; 40 leaves headroom for a burst without letting a
            // hostile client hammer a bot on every character.
            "interaction_autocomplete" => 40,
            // Answering side, keyed per HOST (bot tokens carry no session).
            // One counter serves every concurrent typist of every bot on the
            // box, so the asking side's 40 would starve a popular bot at two
            // simultaneous users. Generous by design — see the resolver.
            "interaction_autocomplete_respond" => 250,
            "poll_vote" => 10,
            "softres_reserve" => 10,
            "message_schedule" => 10,
            "soundboard" => 4,
            // One request per FINALIZED utterance (interims never leave the
            // speaker's screen). Rapid short utterances — "yes", "right",
            // "okay" — can finalize about once a second, and the bucket window
            // is 10s, so this leaves roughly 3x headroom over natural speech
            // while still bounding a hostile client.
            "captions" => 30,
            // Annotation stroke batches. The client coalesces pointer
            // samples to ≤10 Hz, so a continuous drawing hand is exactly
            // 100 per 10s window — 180 leaves ~1.8x headroom so a burst or
            // a late coalescing tick never tears a visible gap mid-stroke
            // (plan §2.3: 100 would have ZERO headroom), while still
            // bounding a hostile client to well under fan-out-melting rates.
            "annotations" => 180,
            // Consent list management (allow/revoke/fetch): user-paced,
            // and the revoke is a safety action — the bucket must never be
            // small enough to lock a sharer out of clearing consent.
            "annotations_consent" => 10,
            // Watch-together: heartbeat (2/10s) + scrub bursts (≤4/s,
            // client-debounced) + the occasional GET/DELETE. 60 leaves ~1.5x
            // headroom over a continuous scrub; fan-out is one small event
            // per call member per write, so a hostile host is bounded.
            "watch" => 60,
            // Offer + respond are deliberate, user-paced actions.
            "remote_control_offer" => 2,
            // "Ask for a turn": user-paced, and request spam at a streamer
            // is the obvious abuse of a social feature. 3 in the window
            // allows a legitimate re-ask after a missed one without letting
            // a heckler keep the sharer's request list churning.
            "control_request" => 3,
            // Heartbeat + release. The heartbeat is SHARER-driven consent
            // re-assertion on a single-digit-second TTL and the bucket
            // window is 10s, so this must comfortably exceed the send rate
            // or grants would expire mid-control on a ratelimit rather
            // than on lost consent.
            "remote_control_heartbeat" => 30,
            "follow" => 2,
            // Respect wall writes: user-paced (write or edit one entry,
            // occasionally curate). 5 per 10s window is generous for a human
            // and bounding for a script.
            "respect" => 5,
            "discover" => 20,
            "interaction_respond" => 30,
            "message_interact" => 20,
            "bot_commands" => 10,
            "softres_catalog" => 20,
            _ => 20,
        }
    }
}

#[cfg(test)]
mod tests {
    //! Bucket resolution for the E2EE and MLS routes, driven through the real
    //! fairing on a database-free Rocket: no session header, so the guard
    //! keys on the (empty) client address, and the limits are read back from
    //! the `X-RateLimit-*` headers the fairing stamps. The resolver runs in
    //! `on_request`, BEFORE routing, so `routed_segment` counts from the
    //! path root exactly as it does in the service.
    use super::DeltaRatelimits;
    use revolt_ratelimits::rocket::{RatelimitFairing, RatelimitStorage};
    use rocket::http::Status;
    use rocket::local::blocking::{Client, LocalResponse};

    #[rocket::get("/devices/<_target>")]
    fn devices(_target: &str) -> &'static str {
        "[]"
    }

    #[rocket::put("/keys")]
    fn keys() -> &'static str {
        "{}"
    }

    #[rocket::get("/backup/status")]
    fn backup_status() -> &'static str {
        "{}"
    }

    #[rocket::post("/groups/<_group>/join_intent")]
    fn join_intent(_group: &str) -> &'static str {
        "{}"
    }

    #[rocket::put("/key_packages")]
    fn key_packages() -> &'static str {
        "{}"
    }

    #[rocket::get("/settings")]
    fn sync_settings() -> &'static str {
        "{}"
    }

    fn client() -> Client {
        let rocket = rocket::build()
            .manage(RatelimitStorage::new(DeltaRatelimits))
            .attach(RatelimitFairing)
            .mount("/", revolt_ratelimits::rocket::routes())
            .mount("/e2ee", rocket::routes![devices, keys, backup_status])
            .mount("/mls", rocket::routes![join_intent, key_packages])
            .mount("/sync", rocket::routes![sync_settings]);
        Client::untracked(rocket).expect("rocket builds without a database")
    }

    fn limit(response: &LocalResponse<'_>) -> u32 {
        response
            .headers()
            .get_one("X-RateLimit-Limit")
            .expect("the fairing stamps a limit")
            .parse()
            .expect("numeric limit")
    }

    fn bucket(response: &LocalResponse<'_>) -> String {
        response
            .headers()
            .get_one("X-RateLimit-Bucket")
            .expect("the fairing stamps a bucket key")
            .to_string()
    }

    #[test]
    fn device_listings_have_their_own_generous_bucket() {
        let client = client();
        let devices = client.get("/e2ee/devices/01ABC").dispatch();
        assert_eq!(devices.status(), Status::Ok);
        assert_eq!(limit(&devices), 120);

        let keys = client.put("/e2ee/keys").dispatch();
        assert_eq!(limit(&keys), 10);
        assert_ne!(
            bucket(&devices),
            bucket(&keys),
            "a listing read must not spend the key-publish budget"
        );

        let status = client.get("/e2ee/backup/status").dispatch();
        assert_eq!(
            bucket(&status),
            bucket(&keys),
            "backup status stays on the plain e2ee bucket"
        );
    }

    #[test]
    fn device_listings_for_different_users_share_one_counter() {
        let client = client();
        let a = client.get("/e2ee/devices/01AAA").dispatch();
        let b = client.get("/e2ee/devices/01BBB").dispatch();
        assert_eq!(bucket(&a), bucket(&b));
    }

    #[test]
    fn mls_routes_leave_the_shared_any_bucket() {
        let client = client();
        let intent = client.post("/mls/groups/01GRP/join_intent").dispatch();
        assert_eq!(intent.status(), Status::Ok);
        assert_eq!(limit(&intent), 60);

        let packages = client.put("/mls/key_packages").dispatch();
        assert_eq!(bucket(&packages), bucket(&intent));

        let any = client.get("/sync/settings").dispatch();
        assert_eq!(limit(&any), 20);
        assert_ne!(
            bucket(&any),
            bucket(&intent),
            "unmapped startup traffic must not compete with the call bring-up"
        );
    }

    #[test]
    fn exhausting_device_listings_leaves_key_publish_untouched() {
        let client = client();
        for _ in 0..120 {
            assert_eq!(
                client.get("/e2ee/devices/01ABC").dispatch().status(),
                Status::Ok
            );
        }
        let limited = client.get("/e2ee/devices/01ABC").dispatch();
        assert_eq!(limited.status(), Status::TooManyRequests);

        let keys = client.put("/e2ee/keys").dispatch();
        assert_eq!(keys.status(), Status::Ok);
        assert_eq!(
            keys.headers().get_one("X-RateLimit-Remaining"),
            Some("9"),
            "the e2ee bucket has spent exactly this one request"
        );
    }

    #[test]
    fn a_ten_member_bring_up_fits_one_window() {
        // The sizing math from `resolve_bucket_limit`: the lowest-leaf
        // admitter of a ten-member call reads about 66 device listings and
        // makes about 30 delivery-service calls inside one window. Every one
        // of them must answer 200, with headroom left in both buckets.
        let client = client();
        for _ in 0..66 {
            assert_eq!(
                client.get("/e2ee/devices/01ABC").dispatch().status(),
                Status::Ok
            );
        }
        for _ in 0..30 {
            assert_eq!(
                client
                    .post("/mls/groups/01GRP/join_intent")
                    .dispatch()
                    .status(),
                Status::Ok
            );
        }

        let devices = client.get("/e2ee/devices/01ABC").dispatch();
        assert_eq!(devices.status(), Status::Ok);
        assert_eq!(
            devices.headers().get_one("X-RateLimit-Remaining"),
            Some("53"),
            "67 of 120 listings spent"
        );
        let packages = client.put("/mls/key_packages").dispatch();
        assert_eq!(packages.status(), Status::Ok);
        assert_eq!(
            packages.headers().get_one("X-RateLimit-Remaining"),
            Some("29"),
            "31 of 60 delivery-service calls spent"
        );
    }
}
