use revolt_result::Result;

use crate::{Channel, FieldsUser, PartialUser, RelationshipStatus, Supporter, User};
use crate::{ReferenceDb, Relationship};

/// Empty supporter record written when a user gains one for the first time
fn empty_supporter() -> Supporter {
    Supporter {
        lifetime_usd_cents: 0,
        monthly_until: None,
        payer_hmacs: vec![],
        show_badges: true,
    }
}

use super::AbstractUsers;

#[async_trait]
impl AbstractUsers for ReferenceDb {
    /// Insert a new user into the database
    async fn insert_user(&self, user: &User) -> Result<()> {
        let mut users = self.users.lock().await;
        if users.contains_key(&user.id) {
            Err(create_database_error!("insert", "user"))
        } else {
            users.insert(user.id.to_string(), user.clone());
            Ok(())
        }
    }

    /// Fetch a user from the database
    async fn fetch_user(&self, id: &str) -> Result<User> {
        let users = self.users.lock().await;
        users
            .get(id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch a user from the database by their username
    async fn fetch_user_by_username(&self, username: &str, discriminator: &str) -> Result<User> {
        let users = self.users.lock().await;
        let lowercase = username.to_lowercase();
        users
            .values()
            .find(|user| {
                user.username.to_lowercase() == lowercase && user.discriminator == discriminator
            })
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch multiple users by their ids
    async fn fetch_users<'a>(&self, ids: &'a [String]) -> Result<Vec<User>> {
        let users = self.users.lock().await;
        ids.iter()
            .map(|id| {
                users
                    .get(id)
                    .cloned()
                    .ok_or_else(|| create_error!(NotFound))
            })
            .collect()
    }

    /// Fetch all discriminators in use for a username
    async fn fetch_discriminators_in_use(&self, username: &str) -> Result<Vec<String>> {
        let users = self.users.lock().await;
        let lowercase = username.to_lowercase();
        Ok(users
            .values()
            .filter(|user| user.username.to_lowercase() == lowercase)
            .map(|user| &user.discriminator)
            .cloned()
            .collect())
    }

    /// Fetch ids of users that both users are friends with
    ///
    /// (Was `todo!()` — a latent panic on any request path reaching the
    /// friend/mutual eligibility fallback for strangers, e.g. the MLS
    /// KeyPackage claim route. Mirrors the Mongo query semantics.)
    async fn fetch_mutual_user_ids(&self, user_a: &str, user_b: &str) -> Result<Vec<String>> {
        let users = self.users.lock().await;

        let friends_of = |target: &str| -> std::collections::HashSet<String> {
            users
                .values()
                .filter(|user| {
                    user.relations.iter().flatten().any(|relation| {
                        relation.id == target
                            && matches!(relation.status, RelationshipStatus::Friend)
                    })
                })
                .map(|user| user.id.clone())
                .collect()
        };

        let of_a = friends_of(user_a);
        let of_b = friends_of(user_b);
        let mut mutual: Vec<String> = of_a.intersection(&of_b).cloned().collect();
        mutual.sort();
        Ok(mutual)
    }

    /// Fetch ids of channels that both users are in
    async fn fetch_mutual_channel_ids(&self, user_a: &str, user_b: &str) -> Result<Vec<String>> {
        let channels = self.channels.lock().await;
        let mut mutual: Vec<String> = channels
            .values()
            .filter_map(|channel| match channel {
                Channel::Group { id, recipients, .. }
                | Channel::DirectMessage { id, recipients, .. }
                    if recipients.iter().any(|r| r == user_a)
                        && recipients.iter().any(|r| r == user_b) =>
                {
                    Some(id.clone())
                }
                _ => None,
            })
            .collect();
        mutual.sort();
        Ok(mutual)
    }

    /// Fetch ids of servers that both users share
    async fn fetch_mutual_server_ids(&self, user_a: &str, user_b: &str) -> Result<Vec<String>> {
        let members = self.server_members.lock().await;
        let of_a: std::collections::HashSet<&str> = members
            .keys()
            .filter(|key| key.user == user_a)
            .map(|key| key.server.as_str())
            .collect();

        let mut mutual: Vec<String> = members
            .keys()
            .filter(|key| key.user == user_b && of_a.contains(key.server.as_str()))
            .map(|key| key.server.clone())
            .collect();
        mutual.sort();
        Ok(mutual)
    }

    /// Update a user by their id given some data
    async fn update_user(
        &self,
        id: &str,
        partial: &PartialUser,
        remove: Vec<FieldsUser>,
    ) -> Result<()> {
        let mut users = self.users.lock().await;
        if let Some(user) = users.get_mut(id) {
            for field in remove {
                #[allow(clippy::disallowed_methods)]
                user.remove_field(&field);
            }

            user.apply_options(partial.clone());
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Set relationship with another user
    ///
    /// This should use pull_relationship if relationship is None or User.
    async fn set_relationship(
        &self,
        user_id: &str,
        target_id: &str,
        relationship: &RelationshipStatus,
        note: Option<&str>,
    ) -> Result<()> {
        if let RelationshipStatus::User | RelationshipStatus::None = &relationship {
            self.pull_relationship(user_id, target_id).await
        } else {
            let mut users = self.users.lock().await;
            let user = users
                .get_mut(user_id)
                .ok_or_else(|| create_error!(NotFound))?;

            let relation = Relationship {
                id: target_id.to_string(),
                status: relationship.clone(),
                note: note.map(str::to_string),
            };

            if let Some(relations) = &mut user.relations {
                relations.retain(|relation| relation.id != target_id);
                relations.push(relation);
            } else {
                user.relations = Some(vec![relation]);
            }

            Ok(())
        }
    }

    /// Remove relationship with another user
    async fn pull_relationship(&self, user_id: &str, target_id: &str) -> Result<()> {
        let mut users = self.users.lock().await;
        let user = users
            .get_mut(user_id)
            .ok_or_else(|| create_error!(NotFound))?;

        if let Some(relations) = &mut user.relations {
            relations.retain(|relation| relation.id != target_id);
        }

        Ok(())
    }

    /// Delete a user by their id
    async fn delete_user(&self, id: &str) -> Result<()> {
        let mut users = self.users.lock().await;
        if users.remove(id).is_some() {
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    /// Removes all relationships with the user from the list of users
    async fn clear_user_relationships(
        &self,
        target_id: &str,
        user_ids: Vec<String>,
    ) -> Result<()> {
        let mut users = self.users.lock().await;

        for user_id in user_ids {
            if let Some(user) = users.get_mut(&user_id) {
                if let Some(relations) = &mut user.relations {
                    relations.retain(|relation| relation.id != target_id);
                }
            }
        }

        Ok(())
    }

    /// Fetch the user whose supporter record lists this payer HMAC
    async fn fetch_user_by_payer_hmac(&self, hmac: &str) -> Result<Option<User>> {
        let users = self.users.lock().await;
        Ok(users
            .values()
            .find(|u| {
                u.supporter
                    .as_ref()
                    .is_some_and(|s| s.payer_hmacs.iter().any(|h| h == hmac))
            })
            .cloned())
    }

    /// Fetch users with at least `n` qualified referrals
    async fn fetch_users_with_referral_count_at_least(&self, n: i32) -> Result<Vec<User>> {
        let users = self.users.lock().await;
        Ok(users
            .values()
            .filter(|u| u.referral_count.is_some_and(|count| count >= n))
            .cloned()
            .collect())
    }

    /// Fetch users whose `welcomed_at` falls in [from_ms, to_ms)
    async fn fetch_users_welcomed_between(&self, from_ms: i64, to_ms: i64) -> Result<Vec<User>> {
        let users = self.users.lock().await;
        Ok(users
            .values()
            .filter(|u| u.welcomed_at.is_some_and(|at| at >= from_ms && at < to_ms))
            .cloned()
            .collect())
    }

    /// Fetch users whose `supporter.monthly_until` falls in [from_ms, to_ms)
    async fn fetch_users_monthly_until_between(
        &self,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<Vec<User>> {
        let users = self.users.lock().await;
        Ok(users
            .values()
            .filter(|u| {
                u.supporter
                    .as_ref()
                    .and_then(|s| s.monthly_until)
                    .is_some_and(|until| until >= from_ms && until < to_ms)
            })
            .cloned()
            .collect())
    }

    /// Fetch users with a referral still awaiting attribution
    async fn fetch_users_with_referral_pending(&self) -> Result<Vec<User>> {
        let users = self.users.lock().await;
        Ok(users
            .values()
            .filter(|u| u.referral_pending == Some(true))
            .cloned()
            .collect())
    }

    /// Claim a payer hash for a user
    async fn claim_payer_hmac(&self, user_id: &str, hmac: &str) -> Result<Vec<String>> {
        let mut users = self.users.lock().await;
        if !users.contains_key(user_id) {
            return Err(create_error!(NotFound));
        }

        let mut lost: Vec<String> = Vec::new();
        for user in users.values_mut() {
            if user.id == user_id {
                continue;
            }

            if let Some(supporter) = &mut user.supporter {
                let before = supporter.payer_hmacs.len();
                supporter.payer_hmacs.retain(|h| h != hmac);
                if supporter.payer_hmacs.len() != before {
                    lost.push(user.id.clone());
                }
            }
        }
        lost.sort();

        let user = users
            .get_mut(user_id)
            .ok_or_else(|| create_error!(NotFound))?;
        let supporter = user.supporter.get_or_insert_with(empty_supporter);
        if !supporter.payer_hmacs.iter().any(|h| h == hmac) {
            supporter.payer_hmacs.push(hmac.to_string());
        }

        Ok(lost)
    }

    /// Set a user's supporter totals
    async fn set_supporter_totals(
        &self,
        user_id: &str,
        lifetime_usd_cents: i64,
        monthly_until: Option<i64>,
    ) -> Result<()> {
        let mut users = self.users.lock().await;
        let user = users
            .get_mut(user_id)
            .ok_or_else(|| create_error!(NotFound))?;
        let supporter = user.supporter.get_or_insert_with(empty_supporter);
        supporter.lifetime_usd_cents = lifetime_usd_cents;
        supporter.monthly_until = monthly_until;
        Ok(())
    }

    /// Set whether a user's supporter badges are shown
    async fn set_supporter_show_badges(&self, user_id: &str, show: bool) -> Result<()> {
        let mut users = self.users.lock().await;
        let user = users
            .get_mut(user_id)
            .ok_or_else(|| create_error!(NotFound))?;
        let supporter = user.supporter.get_or_insert_with(empty_supporter);
        supporter.show_badges = show;
        Ok(())
    }
}
