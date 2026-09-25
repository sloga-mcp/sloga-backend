use bson::Document;
use revolt_result::Result;

use crate::MongoDb;
use crate::{Donation, DonationClaimCode};

use super::AbstractDonations;

static COL: &str = "donations";
static COL_CODES: &str = "donation_claim_codes";

/// Whether a Mongo error is a duplicate key violation
fn is_duplicate_key(error: &mongodb::error::Error) -> bool {
    matches!(
        *error.kind,
        mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(
            ref write_error,
        )) if write_error.code == 11000
    )
}

#[async_trait]
impl AbstractDonations for MongoDb {
    async fn insert_donation_if_absent(&self, d: &Donation) -> Result<bool> {
        // The pre-check covers a database without the unique message_id
        // index (fresh test databases run no migrations); the duplicate key
        // mapping covers the race between the check and the insert.
        let existing = self
            .col::<Document>(COL)
            .find_one(doc! {
                "$or": [
                    { "_id": &d.id },
                    { "message_id": &d.message_id }
                ]
            })
            .await
            .map_err(|_| create_database_error!("find_one", COL))?;

        if existing.is_some() {
            return Ok(false);
        }

        match self.col::<Donation>(COL).insert_one(d).await {
            Ok(_) => Ok(true),
            Err(error) if is_duplicate_key(&error) => Ok(false),
            Err(_) => Err(create_database_error!("insert_one", COL)),
        }
    }

    async fn fetch_donation(&self, id: &str) -> Result<Option<Donation>> {
        query!(self, find_one_by_id, COL, id)
    }

    async fn fetch_donation_by_message_id(&self, message_id: &str) -> Result<Option<Donation>> {
        query!(
            self,
            find_one,
            COL,
            doc! {
                "message_id": message_id
            }
        )
    }

    async fn update_donation(&self, d: &Donation) -> Result<()> {
        self.col::<Donation>(COL)
            .replace_one(doc! { "_id": &d.id }, d)
            .await
            .map_err(|_| create_database_error!("replace_one", COL))
            .and_then(|result| {
                if result.matched_count == 0 {
                    Err(create_error!(NotFound))
                } else {
                    Ok(())
                }
            })
    }

    async fn fetch_donations_by_user(&self, user_id: &str) -> Result<Vec<Donation>> {
        query!(
            self,
            find,
            COL,
            doc! {
                "user": user_id
            }
        )
    }

    async fn unlink_donations_by_user(&self, user_id: &str) -> Result<()> {
        self.col::<Document>(COL)
            .update_many(
                doc! {
                    "user": user_id
                },
                doc! {
                    "$unset": {
                        "user": 1_i32,
                        "payer_hmac": 1_i32
                    }
                },
            )
            .await
            .map_err(|_| create_database_error!("update_many", COL))?;

        // A claimant is only a suspected owner; the row's payer_hmac belongs
        // to the real payer, so it is left alone here.
        self.col::<Document>(COL)
            .update_many(
                doc! {
                    "claimant": user_id
                },
                doc! {
                    "$unset": {
                        "claimant": 1_i32
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_many", COL))
    }

    async fn wipe_stale_payer_hmacs(&self, before_ms: i64) -> Result<u64> {
        // Retention runs from when the row was stored, not from the payment
        // date, so imported historical payments keep their HMAC for the full
        // window. Rows stored before stored_at existed fall back to the
        // payment date.
        self.col::<Document>(COL)
            .update_many(
                doc! {
                    "state": { "$in": ["Unclaimed", "NeedsReview"] },
                    "payer_hmac": { "$exists": true },
                    "$or": [
                        { "stored_at": { "$lt": before_ms } },
                        {
                            "stored_at": { "$exists": false },
                            "timestamp": { "$lt": before_ms }
                        }
                    ]
                },
                doc! {
                    "$unset": {
                        "payer_hmac": 1_i32
                    }
                },
            )
            .await
            .map(|result| result.modified_count)
            .map_err(|_| create_database_error!("update_many", COL))
    }

    async fn insert_claim_code(&self, c: &DonationClaimCode) -> Result<()> {
        // Not query!: a duplicate must come back as an error (the caller
        // retries with a fresh code), never a debug-build panic.
        self.col::<DonationClaimCode>(COL_CODES)
            .insert_one(c)
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("insert_one", COL_CODES))
    }

    async fn fetch_claim_code(&self, code: &str) -> Result<Option<DonationClaimCode>> {
        query!(self, find_one_by_id, COL_CODES, code)
    }

    async fn fetch_claim_code_by_user(&self, user_id: &str) -> Result<Option<DonationClaimCode>> {
        query!(
            self,
            find_one,
            COL_CODES,
            doc! {
                "user": user_id
            }
        )
    }

    async fn delete_claim_code(&self, code: &str) -> Result<()> {
        self.col::<Document>(COL_CODES)
            .delete_one(doc! { "_id": code })
            .await
            .map_err(|_| create_database_error!("delete_one", COL_CODES))
            .and_then(|result| {
                if result.deleted_count == 1 {
                    Ok(())
                } else {
                    Err(create_error!(NotFound))
                }
            })
    }

    async fn delete_claim_codes_by_user(&self, user_id: &str) -> Result<()> {
        self.col::<Document>(COL_CODES)
            .delete_many(doc! {
                "user": user_id
            })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", COL_CODES))
    }

    async fn delete_expired_claim_codes(&self, before_ms: i64) -> Result<u64> {
        self.col::<Document>(COL_CODES)
            .delete_many(doc! {
                "created_at": { "$lt": before_ms }
            })
            .await
            .map(|result| result.deleted_count)
            .map_err(|_| create_database_error!("delete_many", COL_CODES))
    }
}
