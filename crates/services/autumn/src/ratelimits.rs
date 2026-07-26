use axum::http::{request::Parts, Method};
use revolt_ratelimits::ratelimiter::RatelimitResolver;

pub struct AutumnRatelimits;

impl RatelimitResolver<Parts> for AutumnRatelimits {
    fn resolve_bucket<'a>(&self, parts: &'a Parts) -> (&'a str, Option<&'a str>) {
        let path = parts
            .uri
            .path()
            .trim_matches('/')
            .split_terminator("/")
            .collect::<Vec<&str>>();

        match (&parts.method, path.as_slice()) {
            // Dedicated buckets for E2EE blob transit storage: ciphertext
            // uploads must not share accounting with (or exhaust) the
            // ordinary upload bucket, and fetches are authenticated
            // per-recipient downloads rather than public CDN traffic
            (&Method::POST, &["e2ee"]) => ("e2ee_upload", None),
            (&Method::GET, &["e2ee", _]) => ("e2ee_fetch", None),
            // Chunked uploads: session creation is scarce (each open session
            // can park gigabytes of parts); part PUTs must flow fast enough
            // for 150 parts at 3-way client concurrency plus retries;
            // status/complete/abort share a modest bucket
            (&Method::POST, &[_, "upload", "create"]) => ("upload_create", None),
            (&Method::PUT, &[_, "upload", _, "part", _]) => ("upload_part", None),
            (&Method::GET, &[_, "upload", _])
            | (&Method::POST, &[_, "upload", _, "complete"])
            | (&Method::DELETE, &[_, "upload", _]) => ("upload_session", None),
            (&Method::POST, &[tag]) => ("upload", Some(tag)),
            _ => ("any", None),
        }
    }

    fn resolve_bucket_limit(&self, bucket: &str) -> u32 {
        match bucket {
            "upload" => 10,
            "upload_create" => 5,
            "upload_part" => 30,
            "upload_session" => 20,
            "e2ee_upload" => 10,
            "e2ee_fetch" => 100,
            "any" => u32::MAX,
            _ => unreachable!("Bucket defined but no limit set"),
        }
    }
}
