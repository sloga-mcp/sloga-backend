use bson::{Bson, Document};
use revolt_result::Result;

use crate::MongoDb;
use crate::{Referral, ReferralCode, ReferralStatus};

use super::AbstractReferrals;

static COL: &str = "referrals";
static COL_CODES: &str = "referral_codes";

/// Whether a MongoDB error is a duplicate-key write rejection
fn is_duplicate_key(error: &mongodb::error::Error) -> bool {
    matches!(
        *error.kind,
        mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(
            ref write_error,
        )) if write_error.code == 11000
    )
}

/// A status exactly as the typed insert stores it (unit variants are
/// plain strings, e.g. "Pending")
fn status_bson(status: &ReferralStatus) -> Result<Bson> {
    bson::to_bson(status).map_err(|_| create_database_error!("to_bson", COL))
}

#[async_trait]
impl AbstractReferrals for MongoDb {
    async fn insert_referral_if_absent(&self, referral: &Referral) -> Result<bool> {
        // `_id` is the invitee, and it is the only unique index on this
        // collection, so 11000 means the invitee already has a referral.
        match self.col::<Referral>(COL).insert_one(referral).await {
            Ok(_) => Ok(true),
            Err(error) if is_duplicate_key(&error) => Ok(false),
            Err(_) => Err(create_database_error!("insert_one", COL)),
        }
    }

    async fn fetch_referral(&self, invitee_id: &str) -> Result<Option<Referral>> {
        query!(self, find_one_by_id, COL, invitee_id)
    }

    async fn fetch_pending_referrals(&self) -> Result<Vec<Referral>> {
        let pending = status_bson(&ReferralStatus::Pending)?;
        query!(
            self,
            find,
            COL,
            doc! {
                "status": pending
            }
        )
    }

    async fn update_referral_status(
        &self,
        invitee_id: &str,
        status: ReferralStatus,
        qualified_at: Option<i64>,
    ) -> Result<()> {
        let mut set = doc! {
            "status": status_bson(&status)?
        };
        if let Some(qualified_at) = qualified_at {
            set.insert("qualified_at", qualified_at);
        }

        let mut update = doc! {
            "$set": set
        };
        // Per-day activity is only kept while it can still matter
        if status != ReferralStatus::Pending {
            update.insert(
                "$unset",
                doc! {
                    "active_days": 1_i32,
                    "message_count": 1_i32
                },
            );
        }

        self.col::<Document>(COL)
            .update_one(doc! { "_id": invitee_id }, update)
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
    }

    async fn record_referral_activity(
        &self,
        invitee_id: &str,
        day: u32,
        message_inc: i32,
        invite_creator: Option<&str>,
    ) -> Result<()> {
        let pending = status_bson(&ReferralStatus::Pending)?;

        // Typed writes encode u32 as Int64; hand-built writes use the same
        // encoding so every stored day has one BSON type.
        let day = day as i64;

        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": invitee_id,
                    "status": pending.clone()
                },
                doc! {
                    "$addToSet": {
                        "active_days": day
                    },
                    "$inc": {
                        "message_count": message_inc
                    }
                },
            )
            .await
            .map_err(|_| create_database_error!("update_one", COL))?;

        // A join through the referrer's own invite proves nothing
        if let Some(creator) = invite_creator {
            self.col::<Document>(COL)
                .update_one(
                    doc! {
                        "_id": invitee_id,
                        "status": pending,
                        "referrer": { "$ne": creator }
                    },
                    doc! {
                        "$set": {
                            "joined_via_invite": true
                        }
                    },
                )
                .await
                .map_err(|_| create_database_error!("update_one", COL))?;
        }

        Ok(())
    }

    async fn count_referrals_by_referrer(
        &self,
        referrer: &str,
        status: ReferralStatus,
    ) -> Result<u32> {
        self.col::<Document>(COL)
            .count_documents(doc! {
                "referrer": referrer,
                "status": status_bson(&status)?
            })
            .await
            .map(|count| count.min(u32::MAX as u64) as u32)
            .map_err(|_| create_database_error!("count_documents", COL))
    }

    async fn count_referrals_qualified_since(&self, referrer: &str, since_ms: i64) -> Result<u32> {
        // A Qualified row always has qualified_at; revoked rows keep theirs
        // but no longer count, hence the status filter.
        self.col::<Document>(COL)
            .count_documents(doc! {
                "referrer": referrer,
                "status": status_bson(&ReferralStatus::Qualified)?,
                "qualified_at": { "$gte": since_ms }
            })
            .await
            .map(|count| count.min(u32::MAX as u64) as u32)
            .map_err(|_| create_database_error!("count_documents", COL))
    }

    async fn delete_referral(&self, invitee_id: &str) -> Result<()> {
        self.col::<Document>(COL)
            .delete_one(doc! { "_id": invitee_id })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_one", COL))
    }

    async fn insert_referral_code(&self, code: &ReferralCode) -> Result<()> {
        // Both `_id` (the code) and `user` are unique: either collision is
        // an error, and the caller decides whether to retry.
        self.col::<ReferralCode>(COL_CODES)
            .insert_one(code)
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("insert_one", COL_CODES))
    }

    async fn fetch_referral_code(&self, code: &str) -> Result<Option<ReferralCode>> {
        query!(self, find_one_by_id, COL_CODES, code)
    }

    async fn fetch_referral_code_by_user(&self, user_id: &str) -> Result<Option<ReferralCode>> {
        query!(
            self,
            find_one,
            COL_CODES,
            doc! {
                "user": user_id
            }
        )
    }

    async fn delete_referral_codes_by_user(&self, user_id: &str) -> Result<()> {
        self.col::<Document>(COL_CODES)
            .delete_many(doc! { "user": user_id })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", COL_CODES))
    }
}
