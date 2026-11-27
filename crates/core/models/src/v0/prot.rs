#[cfg(feature = "validator")]
use validator::Validate;

use super::{CipherReturnTo, Sku};

auto_derived!(
    /// Currency of a ledger row; only Prot today (Ward later, D4)
    #[derive(Copy)]
    pub enum ProtCurrency {
        Prot,
    }

    /// Kind of a Prot ledger row. COMPLETE for S5 (S5b kinds included) so the
    /// stored enum never grows mid-slice. Serialized as the variant name.
    #[derive(Copy)]
    pub enum ProtEntryKind {
        /// purchase:{order_id}
        Purchase,
        /// cipher-founding:...
        CipherFounding,
        /// cipher-upgrade:...
        CipherUpgrade,
        /// S5b contrib:
        Contribution,
        /// S5b tier:
        TierUpgrade,
        /// S5b pledge:
        PledgeHold,
        /// S5b pledge-capture:
        PledgeCapture,
        /// S5b pledge-return:
        PledgeReturn,
        /// S5b pledge-withdraw:
        PledgeWithdraw,
        /// S5b launch-return:
        LaunchReturn,
        /// S5b burn:
        Burn,
        /// S5b settle:
        Settlement,
        /// S5b writeoff:
        WriteOff,
        /// clawback:{order_id}
        Clawback,
        /// S5b clawback-hold:
        ClawbackHold,
        /// forfeit:{user_id}:{n}
        Forfeit,
        /// S5b forfeit-hold:
        ForfeitHold,
        /// S5b forfeit-tank:
        ForfeitTank,
        /// admin:{admin_id}:{nonce}
        AdminAdjust,
    }

    /// One Prot pack on sale (advertised in the root config)
    pub struct ProtPackView {
        /// Pack id from the config
        pub id: String,
        /// Price in US cents
        pub cents: i64,
        /// Prot credited (bonus included)
        pub prot: i64,
    }

    /// Start a Prot checkout. Exactly one of `pack` / `exact_cents`
    /// (enforced by the engine: `ProtPackInvalid` otherwise).
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataProtCheckout {
        /// Pack id to buy
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 16)))]
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub pack: Option<String>,
        /// Pay-exact amount in US cents (1 Prot per cent)
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub exact_cents: Option<i64>,
        /// Where the buyer is sent after checkout (same values as Cipher: "web" | "shell")
        pub return_to: CipherReturnTo,
    }

    /// Checkout page the client should navigate to
    pub struct ProtCheckoutResponse {
        /// Hosted checkout URL
        pub url: String,
    }

    /// The session user's unfinished Prot checkout
    pub struct ProtPendingView {
        /// Id of the payment order
        pub order_id: String,
        /// What the order buys
        pub sku: Sku,
        /// Epoch ms after which the checkout page expires
        pub expires_at: i64,
    }

    /// One ledger row as the wallet owner sees it
    pub struct ProtLedgerView {
        /// Ledger row id (ULID)
        pub id: String,
        /// Kind of the row
        pub kind: ProtEntryKind,
        /// Signed from the wallet's side: + credited to it, - debited from it
        pub amount: i64,
        /// Epoch ms the row was written
        pub created_at: i64,
        /// Payment order the row belongs to, if any
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub order_id: Option<String>,
    }

    /// GET /payments/prot/@me
    pub struct ProtMe {
        /// Wallet balance
        pub balance: i64,
        /// Part of `balance` under the D17 purchase hold (not yet usable for a
        /// tank or pledge; S5b enforces it): min(balance, Purchase credits in the
        /// last `contribute_hold_hours`)
        pub held: i64,
        /// The wallet account's `version` when read (0 when it has no account); the
        /// client drops any ProtBalanceUpdate with a version <= the one it holds
        pub version: u64,
        /// Unfinished checkout, if any
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub pending_order: Option<ProtPendingView>,
        /// Newest first, at most 20
        pub recent: Vec<ProtLedgerView>,
        /// The caller is on `prot_store_preview_user_ids` (E3); omitted when false
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "std::ops::Not::not", default)
        )]
        pub store_preview: bool,
    }

    /// POST /admin/prot/adjust (reason travels in X-Audit-Log-Reason)
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataProtAdjust {
        /// Target user id
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 64)))]
        pub user: String,
        /// Non-zero; + credits the wallet, - debits it (never below 0)
        pub amount: i64,
        /// Client-generated idempotency nonce (a ULID); key admin:{admin_id}:{nonce}
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 64)))]
        pub nonce: String,
    }

    /// Result of an admin Prot adjustment
    pub struct ProtAdjustResponse {
        /// Ledger row id of the adjustment
        pub entry_id: String,
        /// Wallet balance after the adjustment
        pub balance: i64,
        /// The nonce was already used with the same payload
        pub already_applied: bool,
    }

    /// GET /admin/prot/orders/:id
    pub struct ProtAdminOrder {
        /// Id of the payment order
        pub order_id: String,
        /// Buyer, if the order is linked to a user
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub user_id: Option<String>,
        /// What the order buys
        pub sku: Sku,
        /// Sum of Purchase / CipherFounding / CipherUpgrade rows with ref.order_id = this order
        pub credited: i64,
        /// Sum of `amount` of Clawback rows with ref.order_id = this order
        pub clawed_back: i64,
        /// Sum of `shortfall` of those Clawback rows
        pub shortfall: i64,
        /// The buyer's current wallet balance (None when the order is unlinked)
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub unspent: Option<i64>,
        /// Cipher orders of the buyer's CURRENT membership incarnation (`orders[0] <= order_id`):
        /// cipher_prot_posted of that incarnation's rows. None for Prot orders,
        /// unlinked orders and orders of a replaced incarnation.
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub membership_posted: Option<i64>,
        /// Same condition: cipher_prot_target of the current membership
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub membership_target: Option<i64>,
        /// Same condition: cipher_prot_shortfall of that incarnation's rows (membership-wide)
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub membership_shortfall: Option<i64>,
        /// Sum of `amount` of ClawbackHold rows with ref.order_id = this order (Prot taken back from held
        /// pledges); `clawed_back` keeps counting the wallet part only (S5a meaning unchanged)
        #[cfg_attr(feature = "serde", serde(default))]
        pub clawed_back_holds: i64,
    }

    /// Stage of a fuel tank (S5b). Serialized as the variant name.
    #[derive(Copy)]
    pub enum ProtTankStage {
        Launching,
        Active,
        Grace,
        Frozen,
        Settling,
        Deleted,
        Terminated,
    }

    #[derive(Copy)]
    pub enum ProtGoalState {
        Funding,
        Funded,
        Launching,
        Launched,
        Applied,
        Expired,
        Cancelled,
    }

    #[derive(Copy)]
    pub enum ProtGoalKind {
        Launch,
        Upgrade,
    }

    /// `ClawedBack` (BR9): a pledge a clawback drained to 0
    #[derive(Copy)]
    pub enum ProtPledgeState {
        Held,
        Captured,
        Returned,
        Withdrawn,
        Forfeited,
        ClawedBack,
    }

    /// What a tank pays for (S10 adds Server tanks; no migration)
    #[derive(Copy)]
    pub enum ProtPlan {
        Channel,
        Server,
    }

    /// The tank state every viewer of the channel may see (banner, shield, panel)
    pub struct ProtTankSummary {
        pub tank_id: String,
        pub channel_id: String,
        pub stage: ProtTankStage,
        /// 10 | 25 | 50 | 100
        pub slot_tier: u32,
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub pending_slot_tier: Option<u32>,
        pub daily_cost: i64,
        /// May be negative in Grace (borrowed grace)
        pub balance: i64,
        /// Active only: next UTC midnight + floor(balance / daily_cost) days
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub protected_until: Option<i64>,
        /// Grace only: exhausted_at + grace_days days
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub grace_ends_at: Option<i64>,
        /// Grace / Frozen, and ONLY while `deletion_enabled` is on (NIT 32): exhausted_at + (grace_days +
        /// freeze_days) days (the earliest deletion; the day-20 guard may postpone it). Absent = the client
        /// promises no deletion date.
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub deletes_at: Option<i64>,
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub launched_at: Option<i64>,
        /// The tank document's version; with `balance_version`, clients keep the
        /// lexicographically newest (version, balance_version)
        pub version: u64,
        /// The tank account's version
        pub balance_version: u64,
    }

    /// One contributor line. `user_id` is None for a hidden contributor ("Anonymous", hidden even from the owner)
    /// AND for a deleted user ("Deleted user", `deleted: true`); a deleted user's id is never returned (NIT 25)
    pub struct ProtContributorView {
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub user_id: Option<String>,
        /// Net Prot (after returns); > 0
        pub amount: i64,
        pub hidden: bool,
        pub deleted: bool,
        /// This line is the caller (also when hidden)
        pub you: bool,
    }

    pub struct ProtPledgeView {
        pub id: String,
        pub goal_id: String,
        pub amount: i64,
        pub remaining: i64,
        pub state: ProtPledgeState,
        pub created_at: i64,
    }

    pub struct ProtGoalView {
        pub id: String,
        pub kind: ProtGoalKind,
        pub server_id: String,
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub channel_id: Option<String>,
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub tank_id: Option<String>,
        pub slots: u32,
        /// Launch goals only
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub days: Option<u32>,
        pub daily_cost: i64,
        pub target_prot: i64,
        pub pledged_total: i64,
        pub state: ProtGoalState,
        pub deadline_at: i64,
        /// deadline_at - withdraw_cutoff_hours
        pub withdraw_until: i64,
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub funded_at: Option<i64>,
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub launch_deadline_at: Option<i64>,
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub launched_at: Option<i64>,
        pub contributors: Vec<ProtContributorView>,
        pub your_pledges: Vec<ProtPledgeView>,
        /// Verbatim PROT_SEAT_NOTICE
        pub notice: String,
    }

    pub struct ProtTankView {
        pub tank: ProtTankSummary,
        pub contributors: Vec<ProtContributorView>,
        /// Open goals of this tank (Upgrade), and the Launching launch goal if any
        pub goals: Vec<ProtGoalView>,
        /// What the caller contributed net (0 if nothing)
        pub you_contributed: i64,
        /// The caller passes D6 now and the stage takes top-ups
        pub can_contribute: bool,
        /// The caller is the server owner
        pub is_owner: bool,
        /// channel_seats_used(seats, now) (active + cooling), for "slots used" (audit 15)
        pub seats_used: u32,
        pub notice: String,
    }

    /// POST /prot/channels/<id>/contribute and POST /prot/goals/<id>/pledges
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataProtContribute {
        /// 1..=1_000_000 (min_contribution checked by the engine)
        pub amount: i64,
        /// Client ULID; scopes the idempotency key
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 64)))]
        pub nonce: String,
    }

    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataProtLaunchGoal {
        pub slots: u32,
        pub days: u32,
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 64)))]
        pub nonce: String,
    }

    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataProtUpgradeGoal {
        pub slots: u32,
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 64)))]
        pub nonce: String,
    }

    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataProtGoalLaunch {
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 64)))]
        pub channel_id: String,
    }

    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataProtTier {
        pub slots: u32,
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 64)))]
        pub nonce: String,
    }

    pub struct DataProtContributorPrefs {
        pub hidden: bool,
    }

    pub struct ProtContributionResponse {
        pub entry_id: String,
        pub tank: ProtTankSummary,
        /// Wallet after the posting
        pub balance: i64,
        pub already_applied: bool,
        pub notice: String,
    }

    pub struct ProtPledgeResponse {
        pub pledge: ProtPledgeView,
        pub goal: ProtGoalView,
        pub balance: i64,
        pub already_applied: bool,
        pub notice: String,
    }

    /// Which app store a purchase came through
    #[derive(Copy)]
    pub enum ProtStore {
        #[cfg_attr(feature = "serde", serde(rename = "apple"))]
        Apple,
        #[cfg_attr(feature = "serde", serde(rename = "play"))]
        Play,
    }

    /// Store environment of a purchase (Apple Sandbox / Play test purchase = Sandbox)
    #[derive(Copy)]
    pub enum ProtStoreEnvironment {
        Production,
        Sandbox,
    }

    /// State of a store purchase row (section 6 of the S6 contracts)
    #[derive(Copy)]
    pub enum ProtStoreState {
        Credited,
        Held,
        Rejected,
        Revoked,
        Reinstated,
    }

    /// Why a store purchase was not credited
    #[derive(Copy)]
    pub enum ProtStoreRejectReason {
        #[cfg_attr(feature = "serde", serde(rename = "test"))]
        TestPurchase,
        #[cfg_attr(feature = "serde", serde(rename = "unbound"))]
        Unbound,
        #[cfg_attr(feature = "serde", serde(rename = "unknown_product"))]
        UnknownProduct,
        #[cfg_attr(feature = "serde", serde(rename = "bad_payload"))]
        BadPayload,
        /// The intent's user was deleted before the purchase was seen (R12)
        #[cfg_attr(feature = "serde", serde(rename = "no_buyer"))]
        NoBuyer,
    }

    /// State of a purchase intent
    #[derive(Copy)]
    pub enum ProtStoreIntentState {
        Open,
        Used,
        Expired,
    }

    /// One store product on sale (root advert)
    pub struct ProtStoreProductView {
        pub store: ProtStore,
        pub product_id: String,
        /// Prot credited per unit
        pub prot: i64,
    }

    /// POST /payments/prot/store/intent
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataProtStoreIntent {
        pub store: ProtStore,
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 64)))]
        pub product_id: String,
    }

    pub struct ProtStoreIntentResponse {
        /// Intent id (ULID)
        pub intent_id: String,
        /// One-time token bound to the purchase: Apple `appAccountToken` (UUID v4, lowercase),
        /// Play `obfuscatedAccountId` (43 chars base64url)
        pub token: String,
        pub prot: i64,
        pub product_id: String,
        pub expires_at: i64,
    }

    /// POST /payments/prot/store/verify. Apple: `signed_transaction`; Play: `product_id` + `purchase_token`
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataProtStoreVerify {
        pub store: ProtStore,
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 65536)))]
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub signed_transaction: Option<String>,
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 64)))]
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub product_id: Option<String>,
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 1024)))]
        #[cfg_attr(
            feature = "serde",
            serde(skip_serializing_if = "Option::is_none", default)
        )]
        pub purchase_token: Option<String>,
    }

    #[derive(Copy)]
    pub enum ProtStoreVerifyStatus {
        #[cfg_attr(feature = "serde", serde(rename = "credited"))]
        Credited,
        #[cfg_attr(feature = "serde", serde(rename = "already_credited"))]
        AlreadyCredited,
        /// Play PENDING, or a verified purchase recorded Held (credit paused)
        #[cfg_attr(feature = "serde", serde(rename = "pending"))]
        Pending,
        #[cfg_attr(feature = "serde", serde(rename = "rejected"))]
        Rejected,
    }

    #[derive(Copy)]
    pub enum ProtStoreVerifyReason {
        #[cfg_attr(feature = "serde", serde(rename = "test"))]
        Test,
        #[cfg_attr(feature = "serde", serde(rename = "unbound"))]
        Unbound,
        #[cfg_attr(feature = "serde", serde(rename = "refunded"))]
        Refunded,
        #[cfg_attr(feature = "serde", serde(rename = "unknown_product"))]
        UnknownProduct,
        #[cfg_attr(feature = "serde", serde(rename = "wrong_account"))]
        WrongAccount,
        #[cfg_attr(feature = "serde", serde(rename = "no_buyer"))]
        NoBuyer,
        /// Held for staff review: crediting it would take the wallet past its cap (R63)
        #[cfg_attr(feature = "serde", serde(rename = "over_cap"))]
        OverCap,
    }

    /// Why a store purchase is Held (R63). A Held row without one is a legacy credit-pause hold.
    #[derive(Copy)]
    pub enum ProtStoreHoldReason {
        /// Store credits were paused when it was seen (or assigned)
        #[cfg_attr(feature = "serde", serde(rename = "paused"))]
        Paused,
        /// Crediting it would take the wallet past `wallet_cap`; only staff release it
        #[cfg_attr(feature = "serde", serde(rename = "over_cap"))]
        OverCap,
    }

    pub struct ProtStoreVerifyResponse {
        pub status: ProtStoreVerifyStatus,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub reason: Option<ProtStoreVerifyReason>,
        /// Store purchase id (`apple:prod:…` / `play:…`), present whenever a row exists
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub purchase_id: Option<String>,
        /// Wallet balance after a credit (credited / already_credited)
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub balance: Option<i64>,
        /// The `purchase:{id}` ledger row (credited / already_credited)
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub ledger_id: Option<String>,
    }

    /// One store purchase as staff see it (GET /admin/prot/store…)
    pub struct ProtStorePurchaseView {
        pub id: String,
        pub store: ProtStore,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub user_id: Option<String>,
        pub product_id: String,
        pub prot: i64,
        pub quantity: u32,
        pub environment: ProtStoreEnvironment,
        pub state: ProtStoreState,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub reject_reason: Option<ProtStoreRejectReason>,
        /// Why a Held purchase is held (R63; absent on a legacy pause hold and on every other state)
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub hold_reason: Option<ProtStoreHoldReason>,
        pub refund_gen: u32,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub storefront: Option<String>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub needs_action: Option<String>,
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub assigned_by: Option<String>,
        /// Play only: whether the server consumed it
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub consumed: Option<bool>,
        pub created_at: i64,
        pub updated_at: i64,
    }

    /// GET /admin/prot/store/:id
    pub struct ProtStoreAdminPurchase {
        pub purchase: ProtStorePurchaseView,
        /// Every ledger row with ref.order_id = the purchase id, oldest first
        pub ledger: Vec<ProtLedgerView>,
        /// The buyer's current wallet balance (None when unlinked)
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub unspent: Option<i64>,
    }

    /// POST /admin/prot/store/:id/assign (reason in X-Audit-Log-Reason)
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataProtStoreAssign {
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 64)))]
        pub user_id: String,
    }

    /// POST /admin/prot/store/:id/resolve: the work item to clear ("reversed_unpaid" | "chargeback_review")
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataProtStoreResolve {
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 32)))]
        pub kind: String,
    }
);

/// Shown with every contribution and pledge, and on every write response (11.1). Byte-pinned by
/// `prot_seat_notice_is_verbatim`; the clients carry the same text as a catalog msgid.
pub const PROT_SEAT_NOTICE: &str =
    "Contributing supports this server. It does not reserve a seat; the owner chooses members.";

impl ProtTankStage {
    /// Same string as serde; used by the Mongo filters
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtTankStage::Launching => "Launching",
            ProtTankStage::Active => "Active",
            ProtTankStage::Grace => "Grace",
            ProtTankStage::Frozen => "Frozen",
            ProtTankStage::Settling => "Settling",
            ProtTankStage::Deleted => "Deleted",
            ProtTankStage::Terminated => "Terminated",
        }
    }
}

impl ProtGoalState {
    /// Same string as serde; used by the Mongo filters
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtGoalState::Funding => "Funding",
            ProtGoalState::Funded => "Funded",
            ProtGoalState::Launching => "Launching",
            ProtGoalState::Launched => "Launched",
            ProtGoalState::Applied => "Applied",
            ProtGoalState::Expired => "Expired",
            ProtGoalState::Cancelled => "Cancelled",
        }
    }
}

impl ProtPledgeState {
    /// Same string as serde; used by the Mongo filters
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtPledgeState::Held => "Held",
            ProtPledgeState::Captured => "Captured",
            ProtPledgeState::Returned => "Returned",
            ProtPledgeState::Withdrawn => "Withdrawn",
            ProtPledgeState::Forfeited => "Forfeited",
            ProtPledgeState::ClawedBack => "ClawedBack",
        }
    }
}

impl ProtEntryKind {
    /// Same string as serde; used by the ledger payload hash
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtEntryKind::Purchase => "Purchase",
            ProtEntryKind::CipherFounding => "CipherFounding",
            ProtEntryKind::CipherUpgrade => "CipherUpgrade",
            ProtEntryKind::Contribution => "Contribution",
            ProtEntryKind::TierUpgrade => "TierUpgrade",
            ProtEntryKind::PledgeHold => "PledgeHold",
            ProtEntryKind::PledgeCapture => "PledgeCapture",
            ProtEntryKind::PledgeReturn => "PledgeReturn",
            ProtEntryKind::PledgeWithdraw => "PledgeWithdraw",
            ProtEntryKind::LaunchReturn => "LaunchReturn",
            ProtEntryKind::Burn => "Burn",
            ProtEntryKind::Settlement => "Settlement",
            ProtEntryKind::WriteOff => "WriteOff",
            ProtEntryKind::Clawback => "Clawback",
            ProtEntryKind::ClawbackHold => "ClawbackHold",
            ProtEntryKind::Forfeit => "Forfeit",
            ProtEntryKind::ForfeitHold => "ForfeitHold",
            ProtEntryKind::ForfeitTank => "ForfeitTank",
            ProtEntryKind::AdminAdjust => "AdminAdjust",
        }
    }
}

impl ProtStore {
    /// Same string as serde
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtStore::Apple => "apple",
            ProtStore::Play => "play",
        }
    }
}

impl ProtStoreState {
    /// Same string as serde; used by the Mongo filters
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtStoreState::Credited => "Credited",
            ProtStoreState::Held => "Held",
            ProtStoreState::Rejected => "Rejected",
            ProtStoreState::Revoked => "Revoked",
            ProtStoreState::Reinstated => "Reinstated",
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    use crate::v0::CipherTier;

    const ALL_KINDS: [(ProtEntryKind, &str); 19] = [
        (ProtEntryKind::Purchase, "Purchase"),
        (ProtEntryKind::CipherFounding, "CipherFounding"),
        (ProtEntryKind::CipherUpgrade, "CipherUpgrade"),
        (ProtEntryKind::Contribution, "Contribution"),
        (ProtEntryKind::TierUpgrade, "TierUpgrade"),
        (ProtEntryKind::PledgeHold, "PledgeHold"),
        (ProtEntryKind::PledgeCapture, "PledgeCapture"),
        (ProtEntryKind::PledgeReturn, "PledgeReturn"),
        (ProtEntryKind::PledgeWithdraw, "PledgeWithdraw"),
        (ProtEntryKind::LaunchReturn, "LaunchReturn"),
        (ProtEntryKind::Burn, "Burn"),
        (ProtEntryKind::Settlement, "Settlement"),
        (ProtEntryKind::WriteOff, "WriteOff"),
        (ProtEntryKind::Clawback, "Clawback"),
        (ProtEntryKind::ClawbackHold, "ClawbackHold"),
        (ProtEntryKind::Forfeit, "Forfeit"),
        (ProtEntryKind::ForfeitHold, "ForfeitHold"),
        (ProtEntryKind::ForfeitTank, "ForfeitTank"),
        (ProtEntryKind::AdminAdjust, "AdminAdjust"),
    ];

    /// Fails to compile when a variant is added without a row in `ALL_KINDS`
    #[allow(dead_code)]
    fn listed_in_all_kinds(kind: ProtEntryKind) {
        match kind {
            ProtEntryKind::Purchase
            | ProtEntryKind::CipherFounding
            | ProtEntryKind::CipherUpgrade
            | ProtEntryKind::Contribution
            | ProtEntryKind::TierUpgrade
            | ProtEntryKind::PledgeHold
            | ProtEntryKind::PledgeCapture
            | ProtEntryKind::PledgeReturn
            | ProtEntryKind::PledgeWithdraw
            | ProtEntryKind::LaunchReturn
            | ProtEntryKind::Burn
            | ProtEntryKind::Settlement
            | ProtEntryKind::WriteOff
            | ProtEntryKind::Clawback
            | ProtEntryKind::ClawbackHold
            | ProtEntryKind::Forfeit
            | ProtEntryKind::ForfeitHold
            | ProtEntryKind::ForfeitTank
            | ProtEntryKind::AdminAdjust => {}
        }
    }

    #[test]
    fn entry_kinds_round_trip_as_their_names() {
        for (kind, name) in ALL_KINDS {
            assert_eq!(serde_json::to_value(kind).unwrap(), serde_json::json!(name));
            assert_eq!(
                serde_json::from_value::<ProtEntryKind>(serde_json::json!(name)).unwrap(),
                kind
            );
            // the payload hash reads as_str, so it must never drift from serde
            assert_eq!(kind.as_str(), name);
        }

        let mut names: Vec<&str> = ALL_KINDS.iter().map(|(_, name)| *name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), ALL_KINDS.len());

        assert!(serde_json::from_str::<ProtEntryKind>(r#""purchase""#).is_err());
    }

    #[test]
    fn currency_serializes_as_its_name() {
        assert_eq!(
            serde_json::to_value(ProtCurrency::Prot).unwrap(),
            serde_json::json!("Prot")
        );
        assert_eq!(
            serde_json::from_str::<ProtCurrency>(r#""Prot""#).unwrap(),
            ProtCurrency::Prot
        );
    }

    #[test]
    fn prot_checkout_body_reads_pack_or_exact_cents() {
        let pack: DataProtCheckout =
            serde_json::from_str(r#"{"pack": "p25", "return_to": "web"}"#).unwrap();
        assert_eq!(
            pack,
            DataProtCheckout {
                pack: Some("p25".to_string()),
                exact_cents: None,
                return_to: CipherReturnTo::Web,
            }
        );

        let exact: DataProtCheckout =
            serde_json::from_str(r#"{"exact_cents": 1234, "return_to": "shell"}"#).unwrap();
        assert_eq!(
            exact,
            DataProtCheckout {
                pack: None,
                exact_cents: Some(1234),
                return_to: CipherReturnTo::Shell,
            }
        );
    }

    #[test]
    fn prot_checkout_body_rejects_unknown_return_to() {
        // the same closed set as Cipher; anything else is a 400, not a default
        assert!(
            serde_json::from_str::<DataProtCheckout>(r#"{"pack": "p25", "return_to": "Web"}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<DataProtCheckout>(r#"{"pack": "p25", "return_to": "app"}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<DataProtCheckout>(r#"{"pack": "p25"}"#).is_err());
    }

    #[test]
    fn prot_me_without_pending_order_omits_the_key() {
        let me = ProtMe {
            balance: 2600,
            held: 2600,
            version: 3,
            pending_order: None,
            recent: vec![ProtLedgerView {
                id: "01J00000000000000000000000".to_string(),
                kind: ProtEntryKind::AdminAdjust,
                amount: 2600,
                created_at: 1_700_000_000_000,
                order_id: None,
            }],
            store_preview: false,
        };
        assert_eq!(
            serde_json::to_value(&me).unwrap(),
            serde_json::json!({
                "balance": 2600,
                "held": 2600,
                "version": 3,
                "recent": [{
                    "id": "01J00000000000000000000000",
                    "kind": "AdminAdjust",
                    "amount": 2600,
                    "created_at": 1_700_000_000_000i64
                }]
            })
        );
    }

    #[test]
    fn admin_order_omits_absent_membership_fields() {
        let order = ProtAdminOrder {
            order_id: "01J00000000000000000000001".to_string(),
            user_id: None,
            sku: Sku::CipherNew {
                tier: CipherTier::T99,
            },
            credited: 0,
            clawed_back: 0,
            shortfall: 0,
            unspent: None,
            membership_posted: None,
            membership_target: None,
            membership_shortfall: None,
            clawed_back_holds: 0,
        };
        assert_eq!(
            serde_json::to_value(&order).unwrap(),
            serde_json::json!({
                "order_id": "01J00000000000000000000001",
                "sku": {"type": "CipherNew", "tier": "T99"},
                "credited": 0,
                "clawed_back": 0,
                "shortfall": 0,
                "clawed_back_holds": 0
            })
        );
    }
}

#[cfg(all(test, feature = "serde"))]
mod tank_tests {
    use super::*;

    const STAGES: [(ProtTankStage, &str); 7] = [
        (ProtTankStage::Launching, "Launching"),
        (ProtTankStage::Active, "Active"),
        (ProtTankStage::Grace, "Grace"),
        (ProtTankStage::Frozen, "Frozen"),
        (ProtTankStage::Settling, "Settling"),
        (ProtTankStage::Deleted, "Deleted"),
        (ProtTankStage::Terminated, "Terminated"),
    ];

    const GOAL_STATES: [(ProtGoalState, &str); 7] = [
        (ProtGoalState::Funding, "Funding"),
        (ProtGoalState::Funded, "Funded"),
        (ProtGoalState::Launching, "Launching"),
        (ProtGoalState::Launched, "Launched"),
        (ProtGoalState::Applied, "Applied"),
        (ProtGoalState::Expired, "Expired"),
        (ProtGoalState::Cancelled, "Cancelled"),
    ];

    const PLEDGE_STATES: [(ProtPledgeState, &str); 6] = [
        (ProtPledgeState::Held, "Held"),
        (ProtPledgeState::Captured, "Captured"),
        (ProtPledgeState::Returned, "Returned"),
        (ProtPledgeState::Withdrawn, "Withdrawn"),
        (ProtPledgeState::Forfeited, "Forfeited"),
        (ProtPledgeState::ClawedBack, "ClawedBack"),
    ];

    /// Fails to compile when a variant is added without a row in the tables above
    #[allow(dead_code)]
    fn listed_in_the_tables(
        stage: ProtTankStage,
        goal: ProtGoalState,
        pledge: ProtPledgeState,
        kind: ProtGoalKind,
        plan: ProtPlan,
    ) {
        match stage {
            ProtTankStage::Launching
            | ProtTankStage::Active
            | ProtTankStage::Grace
            | ProtTankStage::Frozen
            | ProtTankStage::Settling
            | ProtTankStage::Deleted
            | ProtTankStage::Terminated => {}
        }
        match goal {
            ProtGoalState::Funding
            | ProtGoalState::Funded
            | ProtGoalState::Launching
            | ProtGoalState::Launched
            | ProtGoalState::Applied
            | ProtGoalState::Expired
            | ProtGoalState::Cancelled => {}
        }
        match pledge {
            ProtPledgeState::Held
            | ProtPledgeState::Captured
            | ProtPledgeState::Returned
            | ProtPledgeState::Withdrawn
            | ProtPledgeState::Forfeited
            | ProtPledgeState::ClawedBack => {}
        }
        match kind {
            ProtGoalKind::Launch | ProtGoalKind::Upgrade => {}
        }
        match plan {
            ProtPlan::Channel | ProtPlan::Server => {}
        }
    }

    fn round_trips<T>(value: T, name: &str)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        assert_eq!(
            serde_json::to_value(&value).unwrap(),
            serde_json::json!(name)
        );
        assert_eq!(
            serde_json::from_value::<T>(serde_json::json!(name)).unwrap(),
            value
        );
    }

    /// The stored and wire names are the variant names, and `as_str` (the
    /// Mongo filters) never drifts from serde
    #[test]
    fn tank_enums_round_trip_as_their_names() {
        for (stage, name) in STAGES {
            round_trips(stage, name);
            assert_eq!(stage.as_str(), name);
        }
        for (state, name) in GOAL_STATES {
            round_trips(state, name);
            assert_eq!(state.as_str(), name);
        }
        for (state, name) in PLEDGE_STATES {
            round_trips(state, name);
            assert_eq!(state.as_str(), name);
        }
        round_trips(ProtGoalKind::Launch, "Launch");
        round_trips(ProtGoalKind::Upgrade, "Upgrade");
        round_trips(ProtPlan::Channel, "Channel");
        round_trips(ProtPlan::Server, "Server");

        assert!(serde_json::from_str::<ProtTankStage>(r#""active""#).is_err());
        assert!(serde_json::from_str::<ProtPledgeState>(r#""Clawed""#).is_err());
    }

    fn summary() -> ProtTankSummary {
        ProtTankSummary {
            tank_id: "01TANK".to_string(),
            channel_id: "01CHANNEL".to_string(),
            stage: ProtTankStage::Frozen,
            slot_tier: 25,
            pending_slot_tier: None,
            daily_cost: 90,
            balance: -450,
            protected_until: None,
            grace_ends_at: None,
            deletes_at: None,
            launched_at: None,
            version: 4,
            balance_version: 9,
        }
    }

    #[test]
    fn tank_summary_without_options_omits_the_keys() {
        assert_eq!(
            serde_json::to_value(summary()).unwrap(),
            serde_json::json!({
                "tank_id": "01TANK",
                "channel_id": "01CHANNEL",
                "stage": "Frozen",
                "slot_tier": 25,
                "daily_cost": 90,
                "balance": -450,
                "version": 4,
                "balance_version": 9
            })
        );

        // and reads back from that shape (the options default to None)
        let read: ProtTankSummary = serde_json::from_value(serde_json::json!({
            "tank_id": "01TANK",
            "channel_id": "01CHANNEL",
            "stage": "Frozen",
            "slot_tier": 25,
            "daily_cost": 90,
            "balance": -450,
            "version": 4,
            "balance_version": 9
        }))
        .unwrap();
        assert_eq!(read, summary());

        let mut full = summary();
        full.pending_slot_tier = Some(10);
        full.deletes_at = Some(1_700_000_000_000);
        let value = serde_json::to_value(&full).unwrap();
        assert_eq!(value["pending_slot_tier"], 10);
        assert_eq!(value["deletes_at"], 1_700_000_000_000i64);
        assert!(value.get("protected_until").is_none());
    }

    #[test]
    fn contributor_view_omits_a_hidden_or_deleted_user_id() {
        let hidden = ProtContributorView {
            user_id: None,
            amount: 300,
            hidden: true,
            deleted: false,
            you: false,
        };
        assert_eq!(
            serde_json::to_value(&hidden).unwrap(),
            serde_json::json!({ "amount": 300, "hidden": true, "deleted": false, "you": false })
        );
    }

    /// The EN notice is a legal text (Terms, the pt-BR msgstr is pinned in the
    /// client catalogs): any change here is a copy change, not a refactor
    #[test]
    fn prot_seat_notice_is_verbatim() {
        assert_eq!(
            PROT_SEAT_NOTICE,
            "Contributing supports this server. It does not reserve a seat; the owner chooses members."
        );
        assert_eq!(PROT_SEAT_NOTICE.len(), 89);
    }
}

#[cfg(all(test, feature = "serde"))]
mod store_tests {
    use super::*;

    const STORES: [(ProtStore, &str); 2] = [(ProtStore::Apple, "apple"), (ProtStore::Play, "play")];

    const ENVIRONMENTS: [(ProtStoreEnvironment, &str); 2] = [
        (ProtStoreEnvironment::Production, "Production"),
        (ProtStoreEnvironment::Sandbox, "Sandbox"),
    ];

    const STATES: [(ProtStoreState, &str); 5] = [
        (ProtStoreState::Credited, "Credited"),
        (ProtStoreState::Held, "Held"),
        (ProtStoreState::Rejected, "Rejected"),
        (ProtStoreState::Revoked, "Revoked"),
        (ProtStoreState::Reinstated, "Reinstated"),
    ];

    const REJECT_REASONS: [(ProtStoreRejectReason, &str); 5] = [
        (ProtStoreRejectReason::TestPurchase, "test"),
        (ProtStoreRejectReason::Unbound, "unbound"),
        (ProtStoreRejectReason::UnknownProduct, "unknown_product"),
        (ProtStoreRejectReason::BadPayload, "bad_payload"),
        (ProtStoreRejectReason::NoBuyer, "no_buyer"),
    ];

    const INTENT_STATES: [(ProtStoreIntentState, &str); 3] = [
        (ProtStoreIntentState::Open, "Open"),
        (ProtStoreIntentState::Used, "Used"),
        (ProtStoreIntentState::Expired, "Expired"),
    ];

    const VERIFY_STATUSES: [(ProtStoreVerifyStatus, &str); 4] = [
        (ProtStoreVerifyStatus::Credited, "credited"),
        (ProtStoreVerifyStatus::AlreadyCredited, "already_credited"),
        (ProtStoreVerifyStatus::Pending, "pending"),
        (ProtStoreVerifyStatus::Rejected, "rejected"),
    ];

    const VERIFY_REASONS: [(ProtStoreVerifyReason, &str); 7] = [
        (ProtStoreVerifyReason::Test, "test"),
        (ProtStoreVerifyReason::Unbound, "unbound"),
        (ProtStoreVerifyReason::Refunded, "refunded"),
        (ProtStoreVerifyReason::UnknownProduct, "unknown_product"),
        (ProtStoreVerifyReason::WrongAccount, "wrong_account"),
        (ProtStoreVerifyReason::NoBuyer, "no_buyer"),
        (ProtStoreVerifyReason::OverCap, "over_cap"),
    ];

    const HOLD_REASONS: [(ProtStoreHoldReason, &str); 2] = [
        (ProtStoreHoldReason::Paused, "paused"),
        (ProtStoreHoldReason::OverCap, "over_cap"),
    ];

    /// Fails to compile when a variant is added without a row in the tables above
    #[allow(dead_code)]
    fn listed_in_the_tables(
        store: ProtStore,
        environment: ProtStoreEnvironment,
        state: ProtStoreState,
        reject: ProtStoreRejectReason,
        intent: ProtStoreIntentState,
        status: ProtStoreVerifyStatus,
        reason: ProtStoreVerifyReason,
    ) {
        match store {
            ProtStore::Apple | ProtStore::Play => {}
        }
        match environment {
            ProtStoreEnvironment::Production | ProtStoreEnvironment::Sandbox => {}
        }
        match state {
            ProtStoreState::Credited
            | ProtStoreState::Held
            | ProtStoreState::Rejected
            | ProtStoreState::Revoked
            | ProtStoreState::Reinstated => {}
        }
        match reject {
            ProtStoreRejectReason::TestPurchase
            | ProtStoreRejectReason::Unbound
            | ProtStoreRejectReason::UnknownProduct
            | ProtStoreRejectReason::BadPayload
            | ProtStoreRejectReason::NoBuyer => {}
        }
        match intent {
            ProtStoreIntentState::Open
            | ProtStoreIntentState::Used
            | ProtStoreIntentState::Expired => {}
        }
        match status {
            ProtStoreVerifyStatus::Credited
            | ProtStoreVerifyStatus::AlreadyCredited
            | ProtStoreVerifyStatus::Pending
            | ProtStoreVerifyStatus::Rejected => {}
        }
        match reason {
            ProtStoreVerifyReason::Test
            | ProtStoreVerifyReason::Unbound
            | ProtStoreVerifyReason::Refunded
            | ProtStoreVerifyReason::UnknownProduct
            | ProtStoreVerifyReason::WrongAccount
            | ProtStoreVerifyReason::NoBuyer
            | ProtStoreVerifyReason::OverCap => {}
        }
    }

    /// Fails to compile when a hold reason is added without a row in `HOLD_REASONS`
    #[allow(dead_code)]
    fn listed_in_hold_reasons(reason: ProtStoreHoldReason) {
        match reason {
            ProtStoreHoldReason::Paused | ProtStoreHoldReason::OverCap => {}
        }
    }

    /// R63: the hold reasons and the `over_cap` verify reason are wire strings
    /// the clients match on; another spelling is refused
    #[test]
    fn hold_reasons_round_trip_as_their_wire_names() {
        round_trips(&HOLD_REASONS);
        assert!(serde_json::from_str::<ProtStoreHoldReason>(r#""OverCap""#).is_err());
        assert!(serde_json::from_str::<ProtStoreHoldReason>(r#""overCap""#).is_err());
        assert_eq!(
            serde_json::to_value(ProtStoreVerifyReason::OverCap).unwrap(),
            serde_json::json!("over_cap")
        );
    }

    /// R63: verify of an over-cap hold answers pending with the reason
    #[test]
    fn verify_response_of_an_over_cap_hold_carries_the_reason() {
        let held = ProtStoreVerifyResponse {
            status: ProtStoreVerifyStatus::Pending,
            reason: Some(ProtStoreVerifyReason::OverCap),
            purchase_id: Some("apple:prod:2000000123456789".to_string()),
            balance: None,
            ledger_id: None,
        };
        assert_eq!(
            serde_json::to_value(&held).unwrap(),
            serde_json::json!({
                "status": "pending",
                "reason": "over_cap",
                "purchase_id": "apple:prod:2000000123456789"
            })
        );
    }

    fn round_trips<T>(table: &[(T, &str)])
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        for (value, name) in table {
            assert_eq!(
                serde_json::to_value(value).unwrap(),
                serde_json::json!(name),
                "{value:?}"
            );
            assert_eq!(
                &serde_json::from_value::<T>(serde_json::json!(name)).unwrap(),
                value
            );
        }

        let mut names: Vec<&str> = table.iter().map(|(_, name)| *name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), table.len());
    }

    /// The wire strings are what the clients and the stored rows match on, and
    /// `as_str` (the Mongo filters) never drifts from serde
    #[test]
    fn store_enums_round_trip_as_their_wire_names() {
        round_trips(&STORES);
        round_trips(&ENVIRONMENTS);
        round_trips(&STATES);
        round_trips(&REJECT_REASONS);
        round_trips(&INTENT_STATES);
        round_trips(&VERIFY_STATUSES);
        round_trips(&VERIFY_REASONS);

        for (store, name) in STORES {
            assert_eq!(store.as_str(), name);
        }
        for (state, name) in STATES {
            assert_eq!(state.as_str(), name);
        }

        // another spelling is refused, never mapped
        assert!(serde_json::from_str::<ProtStore>(r#""Apple""#).is_err());
        assert!(serde_json::from_str::<ProtStoreEnvironment>(r#""sandbox""#).is_err());
        assert!(serde_json::from_str::<ProtStoreState>(r#""credited""#).is_err());
        assert!(serde_json::from_str::<ProtStoreRejectReason>(r#""TestPurchase""#).is_err());
        assert!(serde_json::from_str::<ProtStoreIntentState>(r#""open""#).is_err());
        assert!(serde_json::from_str::<ProtStoreVerifyStatus>(r#""Credited""#).is_err());
        assert!(serde_json::from_str::<ProtStoreVerifyReason>(r#""wrongAccount""#).is_err());
    }

    #[test]
    fn verify_body_reads_an_apple_or_a_play_purchase() {
        let apple: DataProtStoreVerify =
            serde_json::from_str(r#"{"store":"apple","signed_transaction":"a.b.c"}"#).unwrap();
        assert_eq!(
            apple,
            DataProtStoreVerify {
                store: ProtStore::Apple,
                signed_transaction: Some("a.b.c".to_string()),
                product_id: None,
                purchase_token: None,
            }
        );

        let play: DataProtStoreVerify = serde_json::from_str(
            r#"{"store":"play","product_id":"gg.sloga.prot.p5","purchase_token":"t"}"#,
        )
        .unwrap();
        assert_eq!(
            play,
            DataProtStoreVerify {
                store: ProtStore::Play,
                signed_transaction: None,
                product_id: Some("gg.sloga.prot.p5".to_string()),
                purchase_token: Some("t".to_string()),
            }
        );

        // and writes back without the absent keys
        assert_eq!(
            serde_json::to_value(&apple).unwrap(),
            serde_json::json!({ "store": "apple", "signed_transaction": "a.b.c" })
        );
    }

    #[test]
    fn unknown_store_is_refused() {
        for body in [
            r#"{"store":"google","product_id":"gg.sloga.prot.p5","purchase_token":"t"}"#,
            r#"{"store":"Apple","signed_transaction":"a.b.c"}"#,
            r#"{"store":"stripe","signed_transaction":"a.b.c"}"#,
            r#"{"store":null,"signed_transaction":"a.b.c"}"#,
            r#"{"signed_transaction":"a.b.c"}"#,
        ] {
            assert!(
                serde_json::from_str::<DataProtStoreVerify>(body).is_err(),
                "{body}"
            );
        }

        assert!(serde_json::from_str::<DataProtStoreIntent>(
            r#"{"store":"google","product_id":"gg.sloga.prot.p5"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<DataProtStoreIntent>(
            r#"{"product_id":"gg.sloga.prot.p5"}"#
        )
        .is_err());
        assert_eq!(
            serde_json::from_str::<DataProtStoreIntent>(
                r#"{"store":"play","product_id":"gg.sloga.prot.p5"}"#
            )
            .unwrap(),
            DataProtStoreIntent {
                store: ProtStore::Play,
                product_id: "gg.sloga.prot.p5".to_string(),
            }
        );
    }

    #[test]
    fn verify_response_omits_the_absent_keys() {
        let bare = ProtStoreVerifyResponse {
            status: ProtStoreVerifyStatus::Credited,
            reason: None,
            purchase_id: None,
            balance: None,
            ledger_id: None,
        };
        assert_eq!(
            serde_json::to_value(&bare).unwrap(),
            serde_json::json!({ "status": "credited" })
        );

        let credited = ProtStoreVerifyResponse {
            purchase_id: Some("apple:prod:2000000123456789".to_string()),
            balance: Some(500),
            ledger_id: Some("01J00000000000000000000002".to_string()),
            ..bare.clone()
        };
        assert_eq!(
            serde_json::to_value(&credited).unwrap(),
            serde_json::json!({
                "status": "credited",
                "purchase_id": "apple:prod:2000000123456789",
                "balance": 500,
                "ledger_id": "01J00000000000000000000002"
            })
        );

        // wrong_account writes no row, so it carries the reason only (R11)
        let wrong = ProtStoreVerifyResponse {
            status: ProtStoreVerifyStatus::Rejected,
            reason: Some(ProtStoreVerifyReason::WrongAccount),
            ..bare
        };
        assert_eq!(
            serde_json::to_value(&wrong).unwrap(),
            serde_json::json!({ "status": "rejected", "reason": "wrong_account" })
        );
    }

    #[test]
    fn admin_purchase_omits_the_absent_keys() {
        let purchase = ProtStorePurchaseView {
            id: "play:00000000000000000000000000000000000000000000000000000000000000ff".to_string(),
            store: ProtStore::Play,
            user_id: None,
            product_id: "gg.sloga.prot.p10".to_string(),
            prot: 1000,
            quantity: 1,
            environment: ProtStoreEnvironment::Production,
            state: ProtStoreState::Rejected,
            reject_reason: Some(ProtStoreRejectReason::Unbound),
            hold_reason: None,
            refund_gen: 0,
            storefront: None,
            needs_action: None,
            assigned_by: None,
            consumed: None,
            created_at: 1_700_000_000_000,
            updated_at: 1_700_000_000_000,
        };
        let admin = ProtStoreAdminPurchase {
            purchase,
            ledger: vec![],
            unspent: None,
        };
        assert_eq!(
            serde_json::to_value(&admin).unwrap(),
            serde_json::json!({
                "purchase": {
                    "id": "play:00000000000000000000000000000000000000000000000000000000000000ff",
                    "store": "play",
                    "product_id": "gg.sloga.prot.p10",
                    "prot": 1000,
                    "quantity": 1,
                    "environment": "Production",
                    "state": "Rejected",
                    "reject_reason": "unbound",
                    "refund_gen": 0,
                    "created_at": 1_700_000_000_000i64,
                    "updated_at": 1_700_000_000_000i64
                },
                "ledger": []
            })
        );
    }

    /// R63: staff see why a Held purchase is held
    #[test]
    fn admin_purchase_shows_the_hold_reason() {
        let view: ProtStorePurchaseView = serde_json::from_value(serde_json::json!({
            "id": "play:00000000000000000000000000000000000000000000000000000000000000ff",
            "store": "play",
            "product_id": "gg.sloga.prot.p10",
            "prot": 1000,
            "quantity": 1,
            "environment": "Production",
            "state": "Held",
            "refund_gen": 0,
            "created_at": 1_700_000_000_000i64,
            "updated_at": 1_700_000_000_000i64
        }))
        .unwrap();
        assert_eq!(view.hold_reason, None);

        let held = ProtStorePurchaseView {
            hold_reason: Some(ProtStoreHoldReason::OverCap),
            needs_action: Some("over_cap_review".to_string()),
            ..view
        };
        let value = serde_json::to_value(&held).unwrap();
        assert_eq!(value["hold_reason"], "over_cap");
        assert_eq!(value["needs_action"], "over_cap_review");
    }

    /// Bounds of the bodies (only built with the `validator` feature)
    #[cfg(feature = "validator")]
    #[test]
    fn store_bodies_are_length_bounded() {
        use validator::Validate;

        let verify = |signed: Option<String>, product: Option<String>, token: Option<String>| {
            DataProtStoreVerify {
                store: ProtStore::Apple,
                signed_transaction: signed,
                product_id: product,
                purchase_token: token,
            }
            .validate()
        };
        assert!(verify(Some("a.b.c".to_string()), None, None).is_ok());
        assert!(verify(Some("x".repeat(65536)), None, None).is_ok());
        assert!(verify(Some("x".repeat(65537)), None, None).is_err());
        assert!(verify(Some(String::new()), None, None).is_err());
        assert!(verify(None, Some("x".repeat(65)), Some("t".to_string())).is_err());
        assert!(verify(
            None,
            Some("gg.sloga.prot.p5".to_string()),
            Some(String::new())
        )
        .is_err());
        assert!(verify(
            None,
            Some("gg.sloga.prot.p5".to_string()),
            Some("x".repeat(1025))
        )
        .is_err());

        let intent = |product: &str| {
            DataProtStoreIntent {
                store: ProtStore::Play,
                product_id: product.to_string(),
            }
            .validate()
        };
        assert!(intent("gg.sloga.prot.p5").is_ok());
        assert!(intent("").is_err());
        assert!(intent(&"x".repeat(65)).is_err());

        let resolve = |kind: &str| {
            DataProtStoreResolve {
                kind: kind.to_string(),
            }
            .validate()
        };
        assert!(resolve("chargeback_review").is_ok());
        assert!(resolve("").is_err());
        assert!(resolve(&"x".repeat(33)).is_err());

        let assign = |user_id: &str| {
            DataProtStoreAssign {
                user_id: user_id.to_string(),
            }
            .validate()
        };
        assert!(assign("01J00000000000000000000003").is_ok());
        assert!(assign("").is_err());
        assert!(assign(&"x".repeat(65)).is_err());
    }
}
