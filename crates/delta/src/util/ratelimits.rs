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

                    // Scheduled-message routes (POST/GET
                    // …/scheduled_messages, DELETE …/scheduled_messages/
                    // <id>) manage a queue rather than creating live
                    // messages — they get their own bucket.
                    if extra == Some("scheduled_messages") {
                        return ("message_schedule", Some(id));
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
            "message_schedule" => 10,
            "follow" => 2,
            "interaction_respond" => 30,
            "message_interact" => 20,
            "bot_commands" => 10,
            _ => 20,
        }
    }
}
