use revolt_ratelimits::ratelimiter::RatelimitResolver;
use rocket::{http::Method, Request};

pub struct DeltaRatelimits;

impl<'a> RatelimitResolver<Request<'a>> for DeltaRatelimits {
    fn resolve_bucket<'r>(&self, request: &'r Request<'_>) -> (&'r str, Option<&'r str>) {
        let (segment, resource, extra) = if request.routed_segment(0) == Some("0.8") {
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
                ("bots", _, _) => ("bots", None),
                ("channels", Some(id), _) => {
                    if request.method() == Method::Post {
                        // Dice rolls create messages, so they share the messaging bucket
                        if let Some("messages" | "roll") = extra {
                            return ("messaging", Some(id));
                        }
                    }

                    ("channels", Some(id))
                }
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
            _ => 20,
        }
    }
}
