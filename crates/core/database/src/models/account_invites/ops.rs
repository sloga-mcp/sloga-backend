use revolt_result::Result;

use crate::AccountInvite;

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractAccountInvites: Sync + Send {
    /// Find invite by id
    async fn fetch_account_invite(&self, id: &str) -> Result<AccountInvite>;

    /// Save invite
    async fn save_account_invite(&self, invite: &AccountInvite) -> Result<()>;

    /// Use an invite up for `account_id` (used, claimed by that account),
    /// but only while it is not used yet. One conditional write, so of any
    /// number of accounts asking for one invite, one gets it.
    ///
    /// Returns whether this call claimed it. An invite that does not exist
    /// or is already used is left alone and is `Ok(false)`.
    async fn claim_account_invite_if_unused(
        &self,
        invite_id: &str,
        account_id: &str,
    ) -> Result<bool>;

    /// Give an invite back (not used, claimed by nobody), but only while it
    /// is claimed by `account_id`. One conditional write.
    ///
    /// Returns whether an invite was released. An invite that does not exist
    /// or is claimed by another account is left alone and is `Ok(false)`.
    async fn release_account_invite_if_claimed_by(
        &self,
        invite_id: &str,
        account_id: &str,
    ) -> Result<bool>;
}

#[cfg(test)]
mod tests {
    use crate::AccountInvite;

    const ACCOUNT_A: &str = "01ACCOUNTA0000000000000000";
    const ACCOUNT_B: &str = "01ACCOUNTB0000000000000000";

    /// Fails if: a release for an account that does not hold the claim
    /// clears it or reports a release; a release for the holder leaves
    /// `used` or `claimed_by` stored (on MongoDB, writing the unused invite
    /// back with `save_account_invite` does exactly that); a second release
    /// reports a row; or a missing invite is an error instead of `false`.
    #[tokio::test]
    async fn release_only_clears_the_claim_of_the_account_that_holds_it() {
        database_test!(|db| async move {
            let invite = AccountInvite {
                id: "invite".to_string(),
                used: false,
                claimed_by: None,
            };
            db.save_account_invite(&invite).await.unwrap();

            // Claimed the way sign-up claims it
            let mut claimed = invite.clone();
            claimed.claimed_by = Some(ACCOUNT_A.to_string());
            claimed.used = true;
            db.save_account_invite(&claimed).await.unwrap();

            assert!(!db
                .release_account_invite_if_claimed_by(&invite.id, ACCOUNT_B)
                .await
                .unwrap());

            let stored = db.fetch_account_invite(&invite.id).await.unwrap();
            assert!(stored.used, "another account's release used the invite up");
            assert_eq!(stored.claimed_by.as_deref(), Some(ACCOUNT_A));

            assert!(db
                .release_account_invite_if_claimed_by(&invite.id, ACCOUNT_A)
                .await
                .unwrap());

            let stored = db.fetch_account_invite(&invite.id).await.unwrap();
            assert!(!stored.used, "the invite is still used up");
            assert_eq!(stored.claimed_by, None);

            // Nothing is left to release
            assert!(!db
                .release_account_invite_if_claimed_by(&invite.id, ACCOUNT_A)
                .await
                .unwrap());

            // It can be claimed again, and by another account
            let mut reclaimed = stored.clone();
            reclaimed.claimed_by = Some(ACCOUNT_B.to_string());
            reclaimed.used = true;
            db.save_account_invite(&reclaimed).await.unwrap();

            let stored = db.fetch_account_invite(&invite.id).await.unwrap();
            assert!(stored.used);
            assert_eq!(stored.claimed_by.as_deref(), Some(ACCOUNT_B));

            assert!(!db
                .release_account_invite_if_claimed_by("no such invite", ACCOUNT_A)
                .await
                .unwrap());
            assert!(db.fetch_account_invite("no such invite").await.is_err());
        });
    }

    /// Fails if: a claim of an unused invite reports false or does not
    /// store `used` and the claiming account; a second account's claim of
    /// the same invite reports true or replaces the first claim (a blind
    /// save does both); an invite stored as used with no `claimed_by` can
    /// still be claimed; a claim of a missing invite is an error instead of
    /// `false`, or creates the invite; or a released invite cannot be
    /// claimed again.
    #[tokio::test]
    async fn only_the_first_claim_of_an_invite_takes_it() {
        database_test!(|db| async move {
            let invite = AccountInvite {
                id: "invite".to_string(),
                used: false,
                claimed_by: None,
            };
            db.save_account_invite(&invite).await.unwrap();

            assert!(db
                .claim_account_invite_if_unused(&invite.id, ACCOUNT_A)
                .await
                .unwrap());

            let stored = db.fetch_account_invite(&invite.id).await.unwrap();
            assert!(stored.used, "the claim did not use the invite up");
            assert_eq!(stored.claimed_by.as_deref(), Some(ACCOUNT_A));

            // The loser of the race, and the winner asking twice
            for late in [ACCOUNT_B, ACCOUNT_A] {
                assert!(
                    !db.claim_account_invite_if_unused(&invite.id, late)
                        .await
                        .unwrap(),
                    "a used invite was claimed by {late}"
                );
            }

            let stored = db.fetch_account_invite(&invite.id).await.unwrap();
            assert!(stored.used);
            assert_eq!(
                stored.claimed_by.as_deref(),
                Some(ACCOUNT_A),
                "the second claim replaced the first"
            );

            // Used, with nobody named: still used
            let spent = AccountInvite {
                id: "spent".to_string(),
                used: true,
                claimed_by: None,
            };
            db.save_account_invite(&spent).await.unwrap();
            assert!(!db
                .claim_account_invite_if_unused(&spent.id, ACCOUNT_B)
                .await
                .unwrap());
            let stored = db.fetch_account_invite(&spent.id).await.unwrap();
            assert!(stored.used);
            assert_eq!(stored.claimed_by, None);

            // A missing invite is claimed by nobody and is not created
            assert!(!db
                .claim_account_invite_if_unused("no such invite", ACCOUNT_A)
                .await
                .unwrap());
            assert!(db.fetch_account_invite("no such invite").await.is_err());

            // Given back by its holder, it can be claimed again, once
            assert!(db
                .release_account_invite_if_claimed_by(&invite.id, ACCOUNT_A)
                .await
                .unwrap());
            assert!(db
                .claim_account_invite_if_unused(&invite.id, ACCOUNT_B)
                .await
                .unwrap());
            assert!(!db
                .claim_account_invite_if_unused(&invite.id, ACCOUNT_A)
                .await
                .unwrap());
            let stored = db.fetch_account_invite(&invite.id).await.unwrap();
            assert!(stored.used);
            assert_eq!(stored.claimed_by.as_deref(), Some(ACCOUNT_B));
        });
    }
}
