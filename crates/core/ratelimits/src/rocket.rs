use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::OnceLock;

use async_trait::async_trait;
use log::info;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::uri::Origin;
use rocket::http::{Method, Status};
use rocket::request::{FromRequest, Outcome};
use rocket::serde::json::Json;
use rocket::{Data, Request, Response, State};

use revolt_database::{Session, util::ip::rocket::to_real_ip};
use revolt_rocket_okapi::r#gen::OpenApiGenerator;
use revolt_rocket_okapi::request::{OpenApiFromRequest, RequestHeaderInput};

use crate::ratelimiter::RequestKind;
use crate::ratelimiter::{RatelimitInformation, Ratelimiter};

#[derive(Clone, Copy)]
pub struct RocketRequestKind;

impl RequestKind for RocketRequestKind {
    type R<'a> = Request<'a>;
}

pub type RatelimitStorage = crate::ratelimiter::RatelimitStorage<RocketRequestKind>;

#[async_trait]
impl<'r> FromRequest<'r> for Ratelimiter {
    type Error = Ratelimiter;

    async fn from_request<'a>(request: &'r rocket::Request<'a>) -> Outcome<Self, Self::Error> {
        let ratelimiter = request
            .local_cache_async(async {
                use rocket::outcome::Outcome;

                let storage = request.guard::<&State<RatelimitStorage>>().await.unwrap();

                let identifier = if let Outcome::Success(session) = request.guard::<Session>().await
                {
                    session.id
                } else {
                    to_real_ip(request).await
                };

                let (bucket, resource) = storage.resolver.resolve_bucket(request);
                let limit = storage.resolver.resolve_bucket_limit(bucket);

                Ratelimiter::from(&storage.map, &identifier, limit, (bucket, resource))
            })
            .await;

        match ratelimiter {
            Ok(ratelimiter) => Outcome::Success(*ratelimiter),
            Err(ratelimiter) => Outcome::Error((Status::TooManyRequests, *ratelimiter)),
        }
    }
}

impl OpenApiFromRequest<'_> for Ratelimiter {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> revolt_rocket_okapi::Result<RequestHeaderInput> {
        Ok(RequestHeaderInput::None)
    }
}

/// Pseudonymous tag for a rate-limited client.
///
/// The 429 log line used to print the caller's address, which put every
/// rate-limited visitor's IP into the API log for as long as the file lived,
/// while the privacy page promises that addresses are never written to log
/// files. An operator still needs to tell one client hammering a route apart
/// from many clients each hitting it once, so the address is replaced by a
/// keyed hash. The key is drawn at random when the process starts, lives only
/// in memory and is discarded on restart, so the tag is stable for the life of
/// the process and cannot be turned back into an address from the log alone.
fn client_tag(address: &str) -> String {
    static KEY: OnceLock<RandomState> = OnceLock::new();
    let mut hasher = KEY.get_or_init(RandomState::new).build_hasher();
    address.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Attach ratelimiter to the Rocket application
pub struct RatelimitFairing;

#[async_trait]
impl Fairing for RatelimitFairing {
    fn info(&self) -> Info {
        Info {
            name: "Ratelimiter",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        use rocket::outcome::Outcome;

        // A CORS preflight is browser-generated, carries no credentials and no
        // body, and performs no action — so it must never consume a bucket.
        // Counting it made every cross-origin call cost TWO slots: the client
        // sends X-Session-Token, which is not a CORS-safelisted header, so
        // every /auth request is preflighted. That is what exhausted the auth
        // bucket, and because the slot ran out on the PREFLIGHT the browser
        // reported it as a CORS failure rather than a 429 — the symptom that
        // led to the limit being raised to 255 instead of the cause being
        // fixed. Exempting preflights here restores real brute-force
        // protection at a sane limit with double the effective headroom.
        if request.method() == Method::Options {
            return;
        }

        if let Outcome::Error(_) = request.guard::<Ratelimiter>().await {
            info!(
                "User rate-limited on route {}! (client {})",
                request.uri(),
                client_tag(&to_real_ip(request).await)
            );

            request.set_method(Method::Get);
            request.set_uri(Origin::parse("/ratelimit").unwrap())
        }
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        // Mirrors the preflight exemption in on_request: evaluating the guard
        // here would resolve — and therefore CONSUME — the bucket the request
        // phase deliberately skipped, undoing the exemption entirely. A
        // preflight response needs no X-RateLimit-* headers; the real request
        // that follows carries them.
        if request.method() == Method::Options {
            return;
        }

        let guard = request.guard::<Ratelimiter>().await;
        let (Outcome::Success(ratelimiter) | Outcome::Error((_, ratelimiter))) = guard else {
            unreachable!()
        };
        let Ratelimiter {
            key,
            limit,
            remaining,
            reset,
        } = ratelimiter;

        response.set_raw_header("X-RateLimit-Limit", limit.to_string());
        response.set_raw_header("X-RateLimit-Bucket", key.to_string());
        response.set_raw_header("X-RateLimit-Remaining", remaining.to_string());
        response.set_raw_header("X-RateLimit-Reset-After", reset.to_string());

        if guard.is_error() {
            response.set_status(Status::TooManyRequests);
        }
    }
}

#[async_trait]
impl<'r> FromRequest<'r> for RatelimitInformation {
    type Error = u128;

    async fn from_request(request: &'r rocket::Request<'_>) -> Outcome<Self, Self::Error> {
        let info = match request.guard::<Ratelimiter>().await {
            Outcome::Success(ratelimiter) => RatelimitInformation::Success(ratelimiter),
            Outcome::Error((_, ratelimiter)) => RatelimitInformation::Failure {
                retry_after: ratelimiter.reset,
            },
            _ => unreachable!(),
        };
        Outcome::Success(info)
    }
}

#[rocket::get("/ratelimit")]
fn ratelimit_info(info: RatelimitInformation) -> Json<RatelimitInformation> {
    Json(info)
}

pub fn routes() -> Vec<rocket::Route> {
    rocket::routes![ratelimit_info]
}

#[cfg(test)]
mod tests {
    use super::client_tag;

    #[test]
    fn client_tag_is_stable_within_a_process_and_distinct_between_clients() {
        let tag = client_tag("203.0.113.7");
        assert_eq!(tag, client_tag("203.0.113.7"));
        assert_ne!(tag, client_tag("203.0.113.8"));
        assert_eq!(tag.len(), 16);
        assert!(tag.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
