#[cfg(feature = "validator")]
use validator::Validate;

auto_derived!(
    /// Reward unlocked at a donation tier
    pub enum DonationReward {
        /// Supporter badge
        SupporterBadge,
        /// Custom name color
        NameColour,
        /// Custom name font
        NameFont,
        /// Animated name effect
        NameEffect,
        /// Patron badge
        PatronBadge,
    }

    /// One rung of the donation ladder
    pub struct DonationTier {
        /// Lifetime donation total required, in US cents
        pub cents: i64,
        /// Reward unlocked at this total
        pub reward: DonationReward,
    }

    /// The session user's donation standing and progress
    pub struct SupporterSummary {
        /// Lifetime total of claimed donations, in US cents
        pub lifetime_usd_cents: i64,
        /// Whether a monthly donation is currently active
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "crate::if_false", default)
        )]
        pub monthly_active: bool,
        /// Epoch ms until which the monthly donation counts as active
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub monthly_until: Option<i64>,
        /// Whether supporter badges are shown on the profile
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "crate::if_false", default)
        )]
        pub show_badges: bool,
        /// Lifetime total needed for the next tier, in US cents (absent once every tier is reached)
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub next_tier_cents: Option<i64>,
        /// Every tier of the donation ladder, in order
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Vec::is_empty", default)
        )]
        pub tiers: Vec<DonationTier>,
        /// Ko-fi page to donate through
        pub kofi_url: String,
    }

    /// One-time code the user includes with a donation to link it to their account
    pub struct SupporterClaimCode {
        /// Claim code
        pub code: String,
        /// Epoch ms after which this code can no longer be used
        pub expires_at: i64,
    }

    /// Outcome of claiming a donation
    pub enum ClaimOutcome {
        /// Donation was linked to the account
        Claimed,
        /// Donation could not be verified automatically and awaits staff review
        NeedsReview,
    }

    /// Result of claiming a donation
    pub struct SupporterClaimResult {
        /// What happened to the claim
        pub outcome: ClaimOutcome,
    }

    /// Claim a donation by its Ko-fi transaction id
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataSupporterClaim {
        /// Ko-fi transaction id
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 64)))]
        pub transaction_id: String,
    }

    /// Change the session user's supporter preferences
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataEditSupporter {
        /// Whether supporter badges are shown on the profile
        pub show_badges: bool,
    }

    /// Privileged: assign an unclaimed donation to a user
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataAssignDonation {
        /// Id of the user receiving the donation
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 128)))]
        pub user: String,
        /// Amount to count toward the lifetime total, in US cents, in place of the recorded amount
        #[cfg_attr(feature = "validator", validate(range(min = 1)))]
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub usd_cents: Option<i64>,
    }

    /// Privileged: set another user's custom profile badge
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataSetCustomBadge {
        /// Autumn file id of the badge image (uploaded with the `icons` tag)
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 128)))]
        pub image: String,
        /// Badge label shown on hover
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 32)))]
        pub label: String,
    }
);

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn edit_supporter_requires_show_badges() {
        // an empty body must not deserialize to `false` and hide a donor's badges
        assert!(serde_json::from_str::<DataEditSupporter>("{}").is_err());
    }

    #[test]
    fn edit_supporter_reads_show_badges() {
        let off: DataEditSupporter = serde_json::from_str(r#"{"show_badges": false}"#).unwrap();
        assert!(!off.show_badges);

        let on: DataEditSupporter = serde_json::from_str(r#"{"show_badges": true}"#).unwrap();
        assert!(on.show_badges);
    }
}
