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
    }
);

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
        };
        assert_eq!(
            serde_json::to_value(&order).unwrap(),
            serde_json::json!({
                "order_id": "01J00000000000000000000001",
                "sku": {"type": "CipherNew", "tier": "T99"},
                "credited": 0,
                "clawed_back": 0,
                "shortfall": 0
            })
        );
    }
}
