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
