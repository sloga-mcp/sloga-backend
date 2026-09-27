auto_derived!(
    /// Reward unlocked at a referral tier
    pub enum ReferralReward {
        /// Recruiter badge
        Badge,
        /// Custom name color
        NameColour,
        /// Upgraded (elite) recruiter badge
        BetterBadge,
        /// Custom name font
        NameFont,
        /// Animated name effect
        NameEffect,
        /// Raised file upload size limit
        UploadPerk,
        /// Custom profile badge
        CustomBadge,
    }

    /// One rung of the referral ladder
    pub struct ReferralTier {
        /// Number of qualified referrals required
        pub count: u32,
        /// Reward unlocked at this count
        pub reward: ReferralReward,
    }

    /// The session user's referral code and progress
    pub struct ReferralSummary {
        /// Bare referral code (e.g. `KX7P`)
        pub code: String,
        /// Referral code as shown to users (e.g. `SLOGA-KX7P`)
        pub display_code: String,
        /// Shareable referral link
        pub link: String,
        /// Number of referrals that have qualified
        pub qualified: u32,
        /// Number of referrals still waiting to qualify
        pub pending: u32,
        /// Number of referrals that expired before qualifying
        pub expired: u32,
        /// Qualified referral count needed for the next tier (absent once every tier is reached)
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub next_tier: Option<u32>,
        /// Every tier of the referral ladder, in order
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Vec::is_empty", default)
        )]
        pub tiers: Vec<ReferralTier>,
    }

    /// A user reached a new referral milestone
    pub struct ReferralMilestone {
        /// Id of the user who reached the milestone
        pub user_id: String,
        /// Qualified referral count they reached
        pub referral_count: u32,
    }
);
