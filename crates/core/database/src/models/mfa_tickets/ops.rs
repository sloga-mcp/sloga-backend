use revolt_result::Result;

use crate::MFATicket;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractMFATickets: Sync + Send {
    /// Find ticket by token
    async fn fetch_ticket_by_token(&self, token: &str) -> Result<MFATicket>;

    /// Save ticket
    async fn save_ticket(&self, ticket: &MFATicket) -> Result<()>;

    /// Atomically count one attempt. Err(InvalidToken) if missing, expired, or attempts >= MAX.
    ///
    /// Returns the ticket with the attempt already counted. Never creates a
    /// ticket that does not exist.
    async fn reserve_ticket_attempt(&self, id: &str) -> Result<MFATicket>;

    /// Delete ticket
    ///
    /// Err(InvalidToken) when nothing was deleted
    async fn delete_ticket(&self, id: &str) -> Result<()>;

    /// Delete all expired tickets
    async fn delete_expired_tickets(&self) -> Result<usize>;
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use futures::future::join_all;
    use revolt_result::{ErrorType, Result};

    use super::AbstractMFATickets;
    use crate::{MFATicket, MFA_TICKET_MAX_ATTEMPTS};

    const TARGET_ACCOUNT: &str = "01ACCOUNTTARGET00000000000";
    const OTHER_ACCOUNT: &str = "01ACCOUNTBYSTANDER00000000";

    /// A ticket whose id was minted `age` ago
    fn aged_ticket(account_id: &str, age: Duration) -> MFATicket {
        MFATicket {
            id: ulid::Ulid::from_datetime(SystemTime::now() - age).to_string(),
            ..MFATicket::new(account_id.to_string(), false)
        }
    }

    fn assert_invalid_token<T: std::fmt::Debug>(result: Result<T>, what: &str) {
        match result {
            Err(error) => assert!(
                matches!(error.error_type, ErrorType::InvalidToken),
                "{what}: expected InvalidToken, got {:?}",
                error.error_type
            ),
            Ok(value) => panic!("{what}: expected InvalidToken, got Ok({value:?})"),
        }
    }

    #[tokio::test]
    async fn reserve_caps_concurrent() {
        database_test!(|db| async move {
            let ticket = MFATicket::new(TARGET_ACCOUNT.to_string(), false);
            db.save_ticket(&ticket).await.unwrap();

            let results = join_all((0..20).map(|_| db.reserve_ticket_attempt(&ticket.id))).await;

            let mut counts = Vec::new();
            for result in results {
                match result {
                    Ok(reserved) => counts.push(reserved.attempts),
                    Err(error) => assert!(
                        matches!(error.error_type, ErrorType::InvalidToken),
                        "a refused attempt must be InvalidToken, got {:?}",
                        error.error_type
                    ),
                }
            }

            assert_eq!(MFA_TICKET_MAX_ATTEMPTS, 3);
            assert_eq!(
                counts.len(),
                3,
                "exactly 3 of 20 concurrent attempts may count"
            );

            // Every winner saw its own post-increment count
            counts.sort_unstable();
            assert_eq!(counts, vec![1, 2, 3]);

            let stored = db.fetch_ticket_by_token(&ticket.token).await.unwrap();
            assert_eq!(stored.attempts, 3);
        });
    }

    #[tokio::test]
    async fn reserve_hits_target_only() {
        database_test!(|db| async move {
            // Saved first and with an older id, so a filter that loses the
            // target id matches the bystander before the target
            let bystander = aged_ticket(OTHER_ACCOUNT, Duration::from_secs(60));
            let target = MFATicket::new(TARGET_ACCOUNT.to_string(), false);
            db.save_ticket(&bystander).await.unwrap();
            db.save_ticket(&target).await.unwrap();

            let reserved = db.reserve_ticket_attempt(&target.id).await.unwrap();
            assert_eq!(reserved.id, target.id, "the reserve must return the target");
            assert_eq!(reserved.account_id, TARGET_ACCOUNT);
            assert_eq!(reserved.attempts, 1);

            let fetched = db.fetch_ticket_by_token(&target.token).await.unwrap();
            assert_eq!(fetched.attempts, 1);

            let fetched = db.fetch_ticket_by_token(&bystander.token).await.unwrap();
            assert_eq!(
                fetched.attempts, 0,
                "another account's ticket must be untouched"
            );
        });
    }

    #[tokio::test]
    async fn reserve_missing_expired() {
        database_test!(|db| async move {
            let missing = ulid::Ulid::new().to_string();
            assert_invalid_token(db.reserve_ticket_attempt(&missing).await, "missing ticket");

            let expired = aged_ticket(TARGET_ACCOUNT, Duration::from_secs(10 * 60));
            assert!(expired.is_expired());
            db.save_ticket(&expired).await.unwrap();

            assert_invalid_token(
                db.reserve_ticket_attempt(&expired.id).await,
                "expired ticket",
            );
        });
    }

    #[tokio::test]
    async fn delete_twice_fails() {
        database_test!(|db| async move {
            let ticket = MFATicket::new(TARGET_ACCOUNT.to_string(), true);
            db.save_ticket(&ticket).await.unwrap();

            db.delete_ticket(&ticket.id).await.unwrap();
            assert_invalid_token(db.delete_ticket(&ticket.id).await, "second delete");
        });
    }

    #[tokio::test]
    async fn claim_one_winner() {
        database_test!(|db| async move {
            let ticket = MFATicket::new(TARGET_ACCOUNT.to_string(), true);
            db.save_ticket(&ticket).await.unwrap();

            let results = join_all((0..2).map(|_| ticket.claim(&db))).await;
            let won = results.iter().filter(|result| result.is_ok()).count();
            assert_eq!(won, 1, "exactly one concurrent claim may succeed");

            assert!(db.fetch_ticket_by_token(&ticket.token).await.is_err());
        });
    }

    /// A ticket written by a binary from before the counter existed has no
    /// `attempts` key at all. MongoDB only: the reference driver has no raw
    /// document to leave the key out of.
    #[cfg(feature = "mongodb")]
    #[tokio::test]
    async fn legacy_ticket_reserves() {
        database_test!(|db| async move {
            let crate::Database::MongoDb(mongo) = &db else {
                return;
            };
            use bson::{doc, Document};

            let ticket = MFATicket::new(TARGET_ACCOUNT.to_string(), false);
            let mut raw = bson::to_document(&ticket).unwrap();
            assert!(raw.remove("attempts").is_some());

            let tickets = mongo.col::<Document>("mfa_tickets");
            tickets.insert_one(raw).await.unwrap();

            // Prove the control: the stored document has no counter
            let raw = tickets
                .find_one(doc! { "_id": &ticket.id })
                .await
                .unwrap()
                .expect("ticket exists");
            assert!(!raw.contains_key("attempts"));

            let fetched = db.fetch_ticket_by_token(&ticket.token).await.unwrap();
            assert_eq!(fetched.attempts, 0);

            let reserved = db.reserve_ticket_attempt(&ticket.id).await.unwrap();
            assert_eq!(reserved.id, ticket.id);
            assert_eq!(reserved.attempts, 1);

            // Once the counter exists, the cap applies as usual
            db.reserve_ticket_attempt(&ticket.id).await.unwrap();
            db.reserve_ticket_attempt(&ticket.id).await.unwrap();
            assert_invalid_token(
                db.reserve_ticket_attempt(&ticket.id).await,
                "fourth attempt on a legacy ticket",
            );
        });
    }
}
