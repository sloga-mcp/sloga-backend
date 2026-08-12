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
                            return ("interaction_create", Some(id));
                        }
                    }

                    ("channels", Some(id))
                }
                ("interactions", _, _) => ("interaction_respond", None),
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
            "auth" => 255,
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
            "events_create" => 10,
            "events_invite" => 5,
            "events" => 30,
            "thread_create" => 5,
            "forum_post_create" => 5,
            "interaction_create" => 10,
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
            "discover" => 20,
            "interaction_respond" => 30,
            "message_interact" => 20,
            "bot_commands" => 10,
            "softres_catalog" => 20,
            _ => 20,
        }
    }
}
