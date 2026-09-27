use ::mongodb::options::{Collation, CollationStrength, FindOneOptions, FindOptions};
use futures::StreamExt;
use revolt_result::Result;

use crate::DocumentId;
use crate::IntoDocumentPath;
use crate::MongoDb;
use crate::{FieldsUser, PartialUser, RelationshipStatus, User};

use super::AbstractUsers;

static COL: &str = "users";

#[async_trait]
impl AbstractUsers for MongoDb {
    /// Insert a new user into the database
    async fn insert_user(&self, user: &User) -> Result<()> {
        query!(self, insert_one, COL, &user).map(|_| ())
    }

    /// Fetch a user from the database
    async fn fetch_user(&self, id: &str) -> Result<User> {
        query!(self, find_one_by_id, COL, id)?.ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch a user from the database by their username
    async fn fetch_user_by_username(&self, username: &str, discriminator: &str) -> Result<User> {
        query!(
            self,
            find_one_with_options,
            COL,
            doc! {
                "username": username,
                "discriminator": discriminator
            },
            FindOneOptions::builder()
                .collation(
                    Collation::builder()
                        .locale("en")
                        .strength(CollationStrength::Secondary)
                        .build(),
                )
                .build()
        )?
        .ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch multiple users by their ids
    async fn fetch_users<'a>(&self, ids: &'a [String]) -> Result<Vec<User>> {
        Ok(self
            .col::<User>(COL)
            .find(doc! {
                "_id": {
                    "$in": ids
                }
            })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async {
                if cfg!(debug_assertions) {
                    Some(s.unwrap())
                } else {
                    s.ok()
                }
            })
            .collect()
            .await)
    }

    /// Fetch all discriminators in use for a username
    async fn fetch_discriminators_in_use(&self, username: &str) -> Result<Vec<String>> {
        #[derive(Deserialize)]
        struct UserDocument {
            discriminator: String,
        }

        Ok(self
            .col::<UserDocument>(COL)
            .find(doc! {
                "username": username
            })
            .with_options(
                FindOptions::builder()
                    .collation(
                        Collation::builder()
                            .locale("en")
                            .strength(CollationStrength::Secondary)
                            .build(),
                    )
                    .projection(doc! { "_id": 0, "discriminator": 1 })
                    .build(),
            )
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect::<Vec<UserDocument>>()
            .await
            .into_iter()
            .map(|user| user.discriminator)
            .collect::<Vec<String>>())
    }

    /// Fetch ids of users that both users are friends with
    async fn fetch_mutual_user_ids(&self, user_a: &str, user_b: &str) -> Result<Vec<String>> {
        Ok(self
            .col::<DocumentId>(COL)
            .find(doc! {
                "$and": [
                    { "relations": { "$elemMatch": { "_id": &user_a, "status": "Friend" } } },
                    { "relations": { "$elemMatch": { "_id": &user_b, "status": "Friend" } } }
                ]
            })
            .with_options(FindOptions::builder().projection(doc! { "_id": 1 }).build())
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .map(|user| user.id)
            .collect()
            .await)
    }

    /// Fetch ids of channels that both users are in
    async fn fetch_mutual_channel_ids(&self, user_a: &str, user_b: &str) -> Result<Vec<String>> {
        Ok(self
            .col::<DocumentId>("channels")
            .find(doc! {
                "channel_type": {
                    "$in": ["Group", "DirectMessage"]
                },
                "recipients": {
                    "$all": [ user_a, user_b ]
                }
            })
            .with_options(FindOptions::builder().projection(doc! { "_id": 1 }).build())
            .await
            .map_err(|_| create_database_error!("find", "channels"))?
            .filter_map(|s| async { s.ok() })
            .map(|user| user.id)
            .collect()
            .await)
    }

    /// Fetch ids of servers that both users share
    async fn fetch_mutual_server_ids(&self, user_a: &str, user_b: &str) -> Result<Vec<String>> {
        Ok(self
            .col::<DocumentId>("server_members")
            .aggregate(vec![
                doc! {
                    "$match": {
                        "_id.user": user_a
                    }
                },
                doc! {
                    "$lookup": {
                        "from": "server_members",
                        "as": "members",
                        "let": {
                            "server": "$_id.server"
                        },
                        "pipeline": [
                            {
                                "$match": {
                                    "$expr": {
                                        "$and": [
                                            { "$eq": [ "$_id.user", user_b ] },
                                            { "$eq": [ "$_id.server", "$$server" ] }
                                        ]
                                    }
                                }
                            }
                        ]
                    }
                },
                doc! {
                    "$match": {
                        "members": {
                            "$size": 1_i32
                        }
                    }
                },
                doc! {
                    "$project": {
                        "_id": "$_id.server"
                    }
                },
            ])
            .await
            .map_err(|_| create_database_error!("aggregate", "server_members"))?
            .filter_map(|s| async { s.ok() })
            .filter_map(|doc| async move { doc.get_str("_id").map(|id| id.to_string()).ok() })
            .collect()
            .await)
    }

    /// Update a user by their id given some data
    async fn update_user(
        &self,
        id: &str,
        partial: &PartialUser,
        remove: Vec<FieldsUser>,
    ) -> Result<()> {
        if remove.contains(&FieldsUser::StatusText) && partial.status.is_some() {
            // stupid-ass workaround to fix mongo conflicting the same item
            let _: Result<()> = query!(
                self,
                update_one_by_id,
                COL,
                id,
                PartialUser {
                    ..Default::default()
                },
                remove.iter().map(|x| x as &dyn IntoDocumentPath).collect(),
                None
            )
            .map(|_| ());

            query!(self, update_one_by_id, COL, id, partial, vec![], None).map(|_| ())
        } else {
            query!(
                self,
                update_one_by_id,
                COL,
                id,
                partial,
                remove.iter().map(|x| x as &dyn IntoDocumentPath).collect(),
                None
            )
            .map(|_| ())
        }
    }

    /// Set relationship with another user
    ///
    /// This should use pull_relationship if relationship is None.
    async fn set_relationship(
        &self,
        user_id: &str,
        target_id: &str,
        relationship: &RelationshipStatus,
        note: Option<&str>,
    ) -> Result<()> {
        if let RelationshipStatus::None = relationship {
            return self.pull_relationship(user_id, target_id).await;
        }

        // Entry is built by hand, not serde: keep in sync with Relationship
        let mut entry = doc! {
            "_id": target_id,
            "status": format!("{relationship:?}")
        };

        if let Some(note) = note {
            entry.insert("note", note);
        }

        self.col::<User>(COL)
            .update_one(
                doc! {
                    "_id": user_id
                },
                vec![doc! {
                    "$set": {
                        "relations": {
                            "$concatArrays": [
                                {
                                    "$ifNull": [
                                        {
                                            "$filter": {
                                                "input": "$relations",
                                                "cond": {
                                                    "$ne": [
                                                        "$$this._id",
                                                        target_id
                                                    ]
                                                }
                                            }
                                        },
                                        []
                                    ]
                                },
                                [entry]
                            ]
                        }
                    }
                }],
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", "user"))
    }

    /// Remove relationship with another user
    async fn pull_relationship(&self, user_id: &str, target_id: &str) -> Result<()> {
        self.col::<User>(COL)
            .update_one(
                doc! {
                    "_id": user_id
                },
                doc! {
                    "$pull": {
                        "relations": {
                            "_id": target_id
                        }
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Delete a user by their id
    async fn delete_user(&self, id: &str) -> Result<()> {
        query!(self, delete_one_by_id, COL, id).map(|_| ())
    }

    /// Removes all relationships with the user from the list of users
    async fn clear_user_relationships(&self, target_id: &str, user_ids: Vec<String>) -> Result<()> {
        self.col::<User>(COL)
            .update_many(
                doc! { "_id": { "$in": user_ids } },
                doc! {
                    "$pull": {
                        "relations": {
                            "_id": target_id.to_string()
                        }
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("bulk_write", COL))
    }

    /// Fetch the user whose supporter payer hashes contain the given hash
    async fn fetch_user_by_payer_hmac(&self, hmac: &str) -> Result<Option<User>> {
        query!(
            self,
            find_one,
            COL,
            doc! {
                "supporter.payer_hmacs": hmac
            }
        )
    }

    /// Fetch all users with a referral count of at least `n`
    async fn fetch_users_with_referral_count_at_least(&self, n: i32) -> Result<Vec<User>> {
        query!(
            self,
            find,
            COL,
            doc! {
                "referral_count": {
                    "$gte": n
                }
            }
        )
    }

    /// Fetch all users welcomed between the given timestamps (in milliseconds)
    async fn fetch_users_welcomed_between(&self, from_ms: i64, to_ms: i64) -> Result<Vec<User>> {
        query!(
            self,
            find,
            COL,
            doc! {
                "welcomed_at": {
                    "$gte": from_ms,
                    "$lt": to_ms
                }
            }
        )
    }

    /// Fetch all users whose monthly supporter status ends between the given
    /// timestamps (in milliseconds)
    async fn fetch_users_monthly_until_between(
        &self,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<Vec<User>> {
        query!(
            self,
            find,
            COL,
            doc! {
                "supporter.monthly_until": {
                    "$gte": from_ms,
                    "$lt": to_ms
                }
            }
        )
    }

    /// Fetch all users with a pending referral
    async fn fetch_users_with_referral_pending(&self) -> Result<Vec<User>> {
        query!(
            self,
            find,
            COL,
            doc! {
                "referral_pending": true
            }
        )
    }

    /// Claim a payer hash for a user
    async fn claim_payer_hmac(&self, user_id: &str, hmac: &str) -> Result<Vec<String>> {
        ensure_supporter(self, user_id).await?;

        // Add to this user first, so a missing user never costs anyone else the hash
        let result = self
            .col::<User>(COL)
            .update_one(
                doc! {
                    "_id": user_id
                },
                doc! {
                    "$addToSet": {
                        "supporter.payer_hmacs": hmac
                    }
                },
            )
            .await
            .map_err(|_| create_database_error!("update_one", COL))?;

        if result.matched_count == 0 {
            return Err(create_error!(NotFound));
        }

        let losers: Vec<String> = self
            .col::<DocumentId>(COL)
            .find(doc! {
                "supporter.payer_hmacs": hmac,
                "_id": {
                    "$ne": user_id
                }
            })
            .with_options(FindOptions::builder().projection(doc! { "_id": 1 }).build())
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .map(|user| user.id)
            .collect()
            .await;

        if !losers.is_empty() {
            self.col::<User>(COL)
                .update_many(
                    doc! {
                        "_id": {
                            "$in": &losers
                        }
                    },
                    doc! {
                        "$pull": {
                            "supporter.payer_hmacs": hmac
                        }
                    },
                )
                .await
                .map_err(|_| create_database_error!("update_many", COL))?;
        }

        Ok(losers)
    }

    /// Set a user's supporter totals
    async fn set_supporter_totals(
        &self,
        user_id: &str,
        lifetime_usd_cents: i64,
        monthly_until: Option<i64>,
    ) -> Result<()> {
        ensure_supporter(self, user_id).await?;

        let update = if let Some(monthly_until) = monthly_until {
            doc! {
                "$set": {
                    "supporter.lifetime_usd_cents": lifetime_usd_cents,
                    "supporter.monthly_until": monthly_until
                }
            }
        } else {
            doc! {
                "$set": {
                    "supporter.lifetime_usd_cents": lifetime_usd_cents
                },
                "$unset": {
                    "supporter.monthly_until": 1_i32
                }
            }
        };

        self.col::<User>(COL)
            .update_one(
                doc! {
                    "_id": user_id
                },
                update,
            )
            .await
            .map_err(|_| create_database_error!("update_one", COL))
            .and_then(|result| {
                if result.matched_count == 0 {
                    Err(create_error!(NotFound))
                } else {
                    Ok(())
                }
            })
    }

    /// Set whether a user's supporter badges are shown
    async fn set_supporter_show_badges(&self, user_id: &str, show: bool) -> Result<()> {
        ensure_supporter(self, user_id).await?;

        self.col::<User>(COL)
            .update_one(
                doc! {
                    "_id": user_id
                },
                doc! {
                    "$set": {
                        "supporter.show_badges": show
                    }
                },
            )
            .await
            .map_err(|_| create_database_error!("update_one", COL))
            .and_then(|result| {
                if result.matched_count == 0 {
                    Err(create_error!(NotFound))
                } else {
                    Ok(())
                }
            })
    }
}

/// Create an empty `supporter` for the user if they have none yet
async fn ensure_supporter(db: &MongoDb, user_id: &str) -> Result<()> {
    db.col::<User>(COL)
        .update_one(
            doc! {
                "_id": user_id,
                "supporter": {
                    "$exists": false
                }
            },
            doc! {
                "$set": {
                    "supporter": {
                        "lifetime_usd_cents": 0_i64,
                        "show_badges": true
                    }
                }
            },
        )
        .await
        .map(|_| ())
        .map_err(|_| create_database_error!("update_one", COL))
}

impl IntoDocumentPath for FieldsUser {
    fn as_path(&self) -> Option<&'static str> {
        Some(match self {
            FieldsUser::Avatar => "avatar",
            FieldsUser::ProfileBackground => "profile.background",
            FieldsUser::ProfileContent => "profile.content",
            FieldsUser::ProfileLinks => "profile.links",
            FieldsUser::StatusPresence => "status.presence",
            FieldsUser::StatusActivity => "status.activity",
            FieldsUser::StatusText => "status.text",
            FieldsUser::DisplayName => "display_name",
            FieldsUser::Pronouns => "pronouns",
            FieldsUser::Connections => "connections",
            FieldsUser::NameStyle => "name_style",
            FieldsUser::CustomBadge => "custom_badge",
            FieldsUser::Suspension => "suspended_until",
            FieldsUser::Supporter => "supporter",
            FieldsUser::ReferralPending => "referral_pending",
            FieldsUser::WelcomedAt => "welcomed_at",
            FieldsUser::ReferralCount => "referral_count",
            FieldsUser::None => "none",
        })
    }
}
