use std::time::{Duration, SystemTime};

use crate::{AbstractMFATickets, MFATicket, MongoDb, MFA_TICKET_MAX_ATTEMPTS};
use bson::{to_document, Document};
use iso8601_timestamp::Timestamp;
use mongodb::options::{FindOneAndUpdateOptions, ReturnDocument, UpdateOptions};
use revolt_result::Result;
use ulid::Ulid;

const COL: &str = "mfa_tickets";

#[async_trait]
impl AbstractMFATickets for MongoDb {
    /// Find ticket by token
    ///
    /// Ticket is only valid for 5 minute
    async fn fetch_ticket_by_token(&self, token: &str) -> Result<MFATicket> {
        let ticket: MFATicket = query!(self, find_one, COL, doc! { "token": token })?
            .ok_or_else(|| create_error!(InvalidToken))?;

        if let Ok(ulid) = Ulid::from_string(&ticket.id) {
            if Timestamp::from(ulid.datetime() + Duration::from_mins(5)) > Timestamp::now_utc() {
                Ok(ticket)
            } else {
                Err(create_error!(InvalidToken))
            }
        } else {
            Err(create_error!(InvalidToken))
        }
    }

    /// Save ticket
    async fn save_ticket(&self, ticket: &MFATicket) -> Result<()> {
        self.col::<MFATicket>(COL)
            .update_one(
                doc! {
                    "_id": &ticket.id
                },
                doc! {
                    "$set": to_document(ticket).map_err(|_| create_database_error!("to_document", COL))?,
                },
            )
            .with_options(UpdateOptions::builder().upsert(true).build())
            .await
            .map_err(|_| create_database_error!("upsert_one", COL))
            .map(|_| ())
    }

    /// Atomically count one attempt against a ticket
    ///
    /// The attempt cap and the increment happen under one document lock, so
    /// concurrent requests cannot all read the same count. Never upserts: a
    /// ticket that was claimed or deleted stays gone.
    async fn reserve_ticket_attempt(&self, id: &str) -> Result<MFATicket> {
        let ticket = self
            .col::<MFATicket>(COL)
            .find_one_and_update(
                // Only one `_id` key: a second one would replace the first,
                // and the filter could then match another account's ticket
                doc! {
                    "_id": id,
                    "$or": [
                        { "attempts": { "$lt": MFA_TICKET_MAX_ATTEMPTS as i32 } },
                        // Tickets written before the counter existed
                        { "attempts": { "$exists": false } },
                    ]
                },
                doc! {
                    "$inc": { "attempts": 1 }
                },
            )
            .with_options(
                FindOneAndUpdateOptions::builder()
                    .return_document(ReturnDocument::After)
                    .build(),
            )
            .await
            .map_err(|_| create_database_error!("find_one_and_update", COL))?
            .ok_or_else(|| create_error!(InvalidToken))?;

        if ticket.is_expired() {
            return Err(create_error!(InvalidToken));
        }

        Ok(ticket)
    }

    /// Delete ticket
    ///
    /// Fails if nothing was deleted, so a ticket can only be claimed once
    async fn delete_ticket(&self, id: &str) -> Result<()> {
        query!(self, delete_one_by_id, COL, id).and_then(|result| {
            if result.deleted_count == 0 {
                Err(create_error!(InvalidToken))
            } else {
                Ok(())
            }
        })
    }

    /// Delete all expired tickets
    async fn delete_expired_tickets(&self) -> Result<usize> {
        let threshhold =
            Ulid::from_datetime(SystemTime::now() - Duration::from_mins(5)).to_string();

        self.col::<Document>(COL)
            .delete_many(doc! {
                "_id": { "$lt": threshhold }
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL))
            .map(|result| result.deleted_count as usize)
    }
}
