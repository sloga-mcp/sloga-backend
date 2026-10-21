use crate::{credential_error_status, credential_lookup_error, Database, Session};
use revolt_result::Error;
use rocket::{
    http::Status,
    request::{FromRequest, Outcome},
    Request,
};

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Session {
    type Error = Error;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // Cached per request: the `User`, ratelimiter and MFA ticket guards
        // all resolve the session, and should share one lookup
        let outcome: &Outcome<Session, Error> = request
            .local_cache_async(async {
                if let Some(token) = request.headers().get("x-session-token").next() {
                    match request
                        .rocket()
                        .state::<Database>()
                        .expect("`Database`")
                        .fetch_session_by_token(token)
                        .await
                    {
                        Ok(session) => Outcome::Success(session),
                        Err(e) => {
                            // A database error is a 500, not a dead session (a 401 signs the client out)
                            let e = credential_lookup_error(e);
                            Outcome::Error((credential_error_status(&e), e))
                        }
                    }
                } else {
                    Outcome::Error((Status::Unauthorized, create_error!(MissingHeaders)))
                }
            })
            .await;

        outcome.clone()
    }
}
