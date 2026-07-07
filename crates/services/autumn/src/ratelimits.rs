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
            (&Method::POST, &[tag]) => ("upload", Some(tag)),
            _ => ("any", None),
        }
    }

    fn resolve_bucket_limit(&self, bucket: &str) -> u32 {
        match bucket {
            "upload" => 10,
            "e2ee_upload" => 10,
            "e2ee_fetch" => 100,
            "any" => u32::MAX,
            _ => unreachable!("Bucket defined but no limit set"),
        }
    }
}
