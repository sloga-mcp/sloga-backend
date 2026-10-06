use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};

use revolt_result::{Error, Result};

use crate::{Database, MFATicket, Session, UnvalidatedTicket, ValidatedTicket};

#[async_trait]
impl<S> FromRequestParts<S> for MFATicket
where
    Database: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self> {
        let db = Database::from_ref(state);

        if let Some(Ok(token)) = parts.headers.get("x-mfa-ticket").map(|v| v.to_str()) {
            db.fetch_ticket_by_token(token).await
        } else {
            Err(create_error!(MissingHeaders))
        }
    }
}

/// Require the ticket to belong to the account of the requesting session.
///
/// A ticket only proves that some account passed MFA. Without this, a ticket
/// minted on one account would authorize actions on any account whose session
/// token the caller holds. Bot tokens are refused outright: the `User`
/// extractor prefers them over the session, and bots cannot do MFA.
///
/// Session extractor failures pass through unchanged.
async fn bind_to_session<S>(parts: &mut Parts, state: &S, ticket: &MFATicket) -> Result<()>
where
    Database: FromRef<S>,
    S: Send + Sync,
{
    if parts.headers.contains_key("x-bot-token") {
        return Err(create_error!(InvalidToken));
    }

    let session = Session::from_request_parts(parts, state).await?;

    if session.user_id == ticket.account_id {
        Ok(())
    } else {
        Err(create_error!(InvalidToken))
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for ValidatedTicket
where
    Database: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self> {
        let db = Database::from_ref(state);

        let ticket = MFATicket::from_request_parts(parts, state).await?;

        if !ticket.validated {
            return Err(create_error!(InvalidToken));
        }

        // Bind before claiming, so a foreign ticket is not burned
        bind_to_session(parts, state, &ticket).await?;

        if ticket.claim(&db).await.is_ok() {
            Ok(ValidatedTicket(ticket))
        } else {
            Err(create_error!(InvalidToken))
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for UnvalidatedTicket
where
    Database: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self> {
        let ticket = MFATicket::from_request_parts(parts, state).await?;

        if ticket.validated {
            return Err(create_error!(InvalidToken));
        }

        bind_to_session(parts, state, &ticket).await?;

        Ok(UnvalidatedTicket(ticket))
    }
}
