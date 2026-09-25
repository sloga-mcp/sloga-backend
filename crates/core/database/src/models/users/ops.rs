use revolt_result::Result;

use crate::{FieldsUser, PartialUser, RelationshipStatus, User};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractUsers: Sync + Send {
    /// Insert a new user into the database
    async fn insert_user(&self, user: &User) -> Result<()>;

    /// Fetch a user from the database
    async fn fetch_user(&self, id: &str) -> Result<User>;

    /// Fetch a user from the database by their username
    async fn fetch_user_by_username(&self, username: &str, discriminator: &str) -> Result<User>;

    /// Fetch multiple users by their ids
    async fn fetch_users<'a>(&self, ids: &'a [String]) -> Result<Vec<User>>;

    /// Fetch all discriminators in use for a username
    async fn fetch_discriminators_in_use(&self, username: &str) -> Result<Vec<String>>;

    /// Fetch ids of users that both users are friends with
    async fn fetch_mutual_user_ids(&self, user_a: &str, user_b: &str) -> Result<Vec<String>>;

    /// Fetch ids of channels that both users are in
    async fn fetch_mutual_channel_ids(&self, user_a: &str, user_b: &str) -> Result<Vec<String>>;

    /// Fetch ids of servers that both users share
    async fn fetch_mutual_server_ids(&self, user_a: &str, user_b: &str) -> Result<Vec<String>>;

    /// Update a user by their id given some data
    async fn update_user(
        &self,
        id: &str,
        user: &PartialUser,
        remove: Vec<FieldsUser>,
    ) -> Result<()>;

    /// Set relationship with another user
    ///
    /// This should use pull_relationship if relationship is None.
    async fn set_relationship(
        &self,
        user_id: &str,
        target_id: &str,
        relationship: &RelationshipStatus,
        note: Option<&str>,
    ) -> Result<()>;

    /// Remove relationship with another user
    async fn pull_relationship(&self, user_id: &str, target_id: &str) -> Result<()>;

    /// Delete a user by their id
    async fn delete_user(&self, id: &str) -> Result<()>;

    /// Removes all relationships with the user from the list of users
    async fn clear_user_relationships(&self, target_id: &str, user_ids: Vec<String>) -> Result<()>;

    /// Fetch the user whose supporter payer hashes contain the given hash
    async fn fetch_user_by_payer_hmac(&self, hmac: &str) -> Result<Option<User>>;

    /// Fetch all users with a referral count of at least `n`
    async fn fetch_users_with_referral_count_at_least(&self, n: i32) -> Result<Vec<User>>;

    /// Fetch all users welcomed between the given timestamps (in milliseconds)
    ///
    /// The window applies to the raw `welcomed_at` value; the caller is
    /// responsible for offsetting it by the trial length.
    async fn fetch_users_welcomed_between(&self, from_ms: i64, to_ms: i64) -> Result<Vec<User>>;

    /// Fetch all users whose monthly supporter status ends between the given
    /// timestamps (in milliseconds)
    async fn fetch_users_monthly_until_between(
        &self,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<Vec<User>>;

    /// Fetch all users with a pending referral
    async fn fetch_users_with_referral_pending(&self) -> Result<Vec<User>>;

    /// Claim a payer hash for a user
    ///
    /// Ensures `supporter` exists (lifetime 0, no hashes, badges shown),
    /// removes the hash from every other user's `supporter.payer_hmacs` and
    /// adds it to this user's. Returns the ids of the users that lost it.
    async fn claim_payer_hmac(&self, user_id: &str, hmac: &str) -> Result<Vec<String>>;

    /// Set a user's supporter totals
    ///
    /// Ensures `supporter` exists, sets `lifetime_usd_cents` and sets or
    /// unsets `monthly_until`.
    async fn set_supporter_totals(
        &self,
        user_id: &str,
        lifetime_usd_cents: i64,
        monthly_until: Option<i64>,
    ) -> Result<()>;

    /// Set whether a user's supporter badges are shown
    ///
    /// Ensures `supporter` exists, then sets `show_badges`.
    async fn set_supporter_show_badges(&self, user_id: &str, show: bool) -> Result<()>;
}
