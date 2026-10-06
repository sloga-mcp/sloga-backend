use crate::{Database, MFATicket, Session, UnvalidatedTicket, ValidatedTicket};
use revolt_result::Error;
use rocket::{
    http::Status,
    outcome::Outcome,
    request::{self, FromRequest},
    Request,
};

#[rocket::async_trait]
impl<'r> FromRequest<'r> for MFATicket {
    type Error = Error;

    #[allow(clippy::collapsible_match)]
    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        if let Some(header_mfa_ticket) = request.headers().get("x-mfa-ticket").next() {
            if let Ok(ticket) = request
                .rocket()
                .state::<Database>()
                .expect("`Database`")
                .fetch_ticket_by_token(header_mfa_ticket)
                .await
            {
                Outcome::Success(ticket)
            } else {
                Outcome::Error((Status::Unauthorized, create_error!(InvalidToken)))
            }
        } else {
            Outcome::Error((Status::Unauthorized, create_error!(MissingHeaders)))
        }
    }
}

/// Require the ticket to belong to the account of the requesting session.
///
/// A ticket only proves that some account passed MFA. Without this, a ticket
/// minted on one account would authorize actions on any account whose session
/// token the caller holds. Bot tokens are refused outright: the `User` guard
/// prefers them over the session, and bots cannot do MFA.
///
/// Session guard failures pass through unchanged.
async fn bind_to_session(
    request: &Request<'_>,
    ticket: &MFATicket,
) -> request::Outcome<(), Error> {
    if request.headers().get("x-bot-token").next().is_some() {
        return Outcome::Error((Status::Forbidden, create_error!(InvalidToken)));
    }

    match request.guard::<Session>().await {
        Outcome::Success(session) => {
            if session.user_id == ticket.account_id {
                Outcome::Success(())
            } else {
                Outcome::Error((Status::Forbidden, create_error!(InvalidToken)))
            }
        }
        Outcome::Forward(f) => Outcome::Forward(f),
        Outcome::Error(err) => Outcome::Error(err),
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ValidatedTicket {
    type Error = Error;

    #[allow(clippy::collapsible_match)]
    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        match request.guard::<MFATicket>().await {
            Outcome::Success(ticket) => {
                if !ticket.validated {
                    return Outcome::Error((Status::Forbidden, create_error!(InvalidToken)));
                }

                // Bind before claiming, so a foreign ticket is not burned
                match bind_to_session(request, &ticket).await {
                    Outcome::Success(()) => {}
                    Outcome::Forward(f) => return Outcome::Forward(f),
                    Outcome::Error(err) => return Outcome::Error(err),
                }

                let db = request
                    .rocket()
                    .state::<Database>()
                    .expect("`Database`");

                if ticket.claim(db).await.is_ok() {
                    Outcome::Success(ValidatedTicket(ticket))
                } else {
                    Outcome::Error((Status::Forbidden, create_error!(InvalidToken)))
                }
            }
            Outcome::Forward(f) => Outcome::Forward(f),
            Outcome::Error(err) => Outcome::Error(err),
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for UnvalidatedTicket {
    type Error = Error;

    #[allow(clippy::collapsible_match)]
    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        match request.guard::<MFATicket>().await {
            Outcome::Success(ticket) => {
                if ticket.validated {
                    return Outcome::Error((Status::Forbidden, create_error!(InvalidToken)));
                }

                match bind_to_session(request, &ticket).await {
                    Outcome::Success(()) => Outcome::Success(UnvalidatedTicket(ticket)),
                    Outcome::Forward(f) => Outcome::Forward(f),
                    Outcome::Error(err) => Outcome::Error(err),
                }
            }
            Outcome::Forward(f) => Outcome::Forward(f),
            Outcome::Error(err) => Outcome::Error(err),
        }
    }
}
