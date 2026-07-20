#[cfg(feature = "validator")]
use validator::Validate;

auto_derived!(
    /// Where a boost slot came from
    pub enum BoostSource {
        /// Granted by a platform admin (the only mint path pre-monetization;
        /// remains the support/compensation lever afterwards)
        AdminGrant,
        /// Bought as an individual recurring boost (future billing)
        Purchase,
        /// Included with a premium subscription (future billing)
        Subscription,
    }

    /// A boost slot owned by a user. Full detail — only ever serialized to
    /// the slot's owner or a platform admin (member-facing routes use
    /// `BoostStatus` instead).
    pub struct ServerBoost {
        /// Unique Id
        #[cfg_attr(feature = "serde", serde(rename = "_id"))]
        pub id: String,
        /// Slot owner
        pub user_id: String,
        /// Server this slot is currently applied to, if any
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub server_id: Option<String>,
        /// How this slot entered the system
        pub source: BoostSource,
        /// Epoch ms after which this slot expires (absent = permanent)
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub expires_at: Option<i64>,
        /// Epoch ms of the current allocation
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub allocated_at: Option<i64>,
    }

    /// Apply boosts from your inventory to a server
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataAllocateBoosts {
        /// How many boosts to apply
        #[cfg_attr(feature = "validator", validate(range(min = 1, max = 16)))]
        pub count: u32,
    }

    /// Privileged: mint boost slots for a user
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataGrantBoosts {
        /// How many slots to mint
        #[cfg_attr(feature = "validator", validate(range(min = 1, max = 100)))]
        pub count: u32,
        /// Optional lifetime in days (absent = permanent)
        #[cfg_attr(feature = "validator", validate(range(min = 1, max = 3650)))]
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub expires_in_days: Option<u32>,
    }

    /// One user's contribution to a server's boosts (member-facing;
    /// deliberately excludes slot ids/sources/expiry)
    pub struct BoosterEntry {
        /// Booster's user id
        pub user_id: String,
        /// How many active boosts they have applied here
        pub boosts: u32,
        /// Epoch ms of their earliest active allocation
        pub since: i64,
    }

    /// A server's boost standing (member-facing)
    pub struct BoostStatus {
        /// Active boost count
        pub count: u32,
        /// Current perk tier (0-3)
        pub tier: u32,
        /// Boosts required for the next tier (absent at max tier)
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub next_tier_at: Option<u32>,
        /// Who is boosting, grouped per user
        pub boosters: Vec<BoosterEntry>,
    }

    /// Result of a boost removal
    pub struct BoostRemoved {
        /// How many boosts were returned to the caller's inventory
        pub removed: u32,
    }

    /// Aggregated allocation entry in a user's boost inventory
    pub struct BoostAllocation {
        /// Server the boosts are applied to
        pub server_id: String,
        /// How many of the user's slots are applied there
        pub count: u32,
    }

    /// A user's boost inventory (self or platform-admin view)
    pub struct UserBoosts {
        /// Total unexpired slots owned
        pub total: u32,
        /// Unexpired slots not currently applied to any server
        pub available: u32,
        /// Active allocations grouped by server
        pub allocations: Vec<BoostAllocation>,
        /// Every slot owned (including expired ones awaiting pruning, so
        /// the owner can see what lapsed)
        pub slots: Vec<ServerBoost>,
    }
);
