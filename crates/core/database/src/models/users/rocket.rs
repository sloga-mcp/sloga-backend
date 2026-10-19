use revolt_result::{Error, ErrorType};
use rocket::request::{self, FromRequest, Outcome, Request};

use crate::{credential_error_status, credential_lookup_error, Database, Session, User};

#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
    type Error = Error;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let user: &Result<User, Error> = request
            .local_cache_async(async {
                let db = request.rocket().state::<Database>().expect("`Database`");

                let header_bot_token = request
                    .headers()
                    .get("x-bot-token")
                    .next()
                    .map(|x| x.to_string());

                if let Some(bot_token) = header_bot_token {
                    let bot = db
                        .fetch_bot_by_token(&bot_token)
                        .await
                        .map_err(credential_lookup_error)?;

                    db.fetch_user(&bot.id)
                        .await
                        .map_err(credential_lookup_error)
                } else {
                    match request.guard::<Session>().await {
                        Outcome::Success(session) => db
                            .fetch_user(&session.user_id)
                            .await
                            .map_err(credential_lookup_error),
                        // No credential at all: keep answering 401 InvalidSession, as before
                        Outcome::Error((_, e))
                            if matches!(e.error_type, ErrorType::MissingHeaders) =>
                        {
                            Err(create_error!(InvalidSession))
                        }
                        // The Session guard has already classified this error
                        Outcome::Error((_, e)) => Err(e),
                        // Unreachable today: the Session guard never forwards
                        Outcome::Forward(_) => Err(create_error!(InvalidSession)),
                    }
                }
            })
            .await;

        match user {
            Ok(user) => Outcome::Success(user.clone()),
            Err(e) => Outcome::Error((credential_error_status(e), e.clone())),
        }
    }
}
