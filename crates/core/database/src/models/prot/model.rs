use revolt_models::v0;
use sha2::{Digest, Sha256};

use crate::CipherMembership;

auto_derived!(
    /// A Prot account with a balance document. System sides (sys:*) have none.
    pub struct ProtAccount {
        /// `user:{user_id}` (S5b: `tank:{tank_id}`, `hold:{goal_id}`)
        #[serde(rename = "_id")]
        pub id: String,
        pub currency: v0::ProtCurrency,
        /// >= 0 for user (and S5b hold) accounts; a tank may go down to -grace floor (S5b)
        pub balance: i64,
        /// +1 on EVERY posting that names this account, zero-amount ones included
        #[serde(default)]
        pub version: u64,
        pub updated_at: i64,
    }

    /// References carried by a ledger row. Absent fields are not stored (the
    /// partial indexes on ref.* rely on that).
    #[derive(Default)]
    pub struct ProtRef {
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub order_id: Option<String>,
        /// S5b
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub tank_id: Option<String>,
        /// S5b
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub goal_id: Option<String>,
        /// S5b
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub pledge_id: Option<String>,
        /// S5b, "YYYY-MM-DD" UTC
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub day: Option<String>,
        /// Cipher rows: the membership's number
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub membership_number: Option<u32>,
        /// Cipher rows: the membership's base order (`CipherMembership.orders[0]`, its CipherNew order)
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub membership_order_id: Option<String>,
    }

    /// One append-only, double-entry ledger row (`prot_ledger`)
    pub struct ProtLedgerEntry {
        /// ULID
        #[serde(rename = "_id")]
        pub id: String,
        /// Idempotency key, unique
        pub key: String,
        pub kind: v0::ProtEntryKind,
        pub currency: v0::ProtCurrency,
        /// Account the Prot leaves (`user:..`, `sys:..`, S5b `tank:..`/`hold:..`)
        pub debit: String,
        /// Account the Prot reaches
        pub credit: String,
        /// Prot moved. > 0, except a row written for `ProtAmount::UpTo`/`All`, which may be 0
        pub amount: i64,
        /// `ProtAmount::UpTo` rows: what was asked for
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub requested: Option<i64>,
        /// `ProtAmount::UpTo` rows: requested - amount (what could not be recovered)
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub shortfall: Option<i64>,
        /// Who caused it: a user id, an admin id, or a PROT_ACTOR_* constant
        pub actor: String,
        #[serde(rename = "ref", default)]
        pub reference: ProtRef,
        /// sha256 hex of the canonical payload (`prot_payload_hash`)
        pub payload_hash: String,
        /// Admin reason (AdminAdjust), sanitized by AuditLogReason
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub reason: Option<String>,
        pub created_at: i64,
    }
);

/// How much a posting moves
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtAmount {
    /// Exactly n (> 0); refused with InsufficientProt when the debit side can't cover it
    Exact(i64),
    /// min(n, what the debit side holds above its floor); n > 0; records requested + shortfall
    UpTo(i64),
    /// Everything the debit side holds above its floor (forfeits)
    All,
}

/// One posting to apply atomically
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtPosting {
    pub key: String,
    pub kind: v0::ProtEntryKind,
    pub debit: String,
    pub credit: String,
    pub amount: ProtAmount,
    /// Lowest balance the debit account may reach: 0 for user (and hold) accounts;
    /// S5b passes -(grace_days x daily_cost) for a tank. Ignored for a sys: debit.
    pub debit_floor: i64,
    pub actor: String,
    pub reference: ProtRef,
    pub reason: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtApplyOutcome {
    /// Written now
    Applied(ProtLedgerEntry),
    /// A row with this key and the same payload hash already existed; nothing written
    AlreadyApplied(ProtLedgerEntry),
}

impl ProtApplyOutcome {
    /// The row written now, or the one found under the key
    pub fn entry(&self) -> &ProtLedgerEntry {
        match self {
            ProtApplyOutcome::Applied(entry) | ProtApplyOutcome::AlreadyApplied(entry) => entry,
        }
    }
}

/// Result of AbstractProtLedger::sync_cipher_prot
// One value per sync call, never collected; callers match on the unboxed
// `Posted(ProtApplyOutcome)`
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherProtSync {
    /// No membership, inactive, disputed, empty `orders`, or already posted up to the target
    Nothing,
    /// Posted the difference now, or found it already posted by a racing sync
    Posted(ProtApplyOutcome),
    /// posted > target on an active membership (a reversal's clawback did not run):
    /// logged at error level by the caller (`PROT_CIPHER_OVERPOSTED`), never clawed here
    OverPosted { posted: i64, target: i64 },
}

/// Purchases and Cipher grants
pub const PROT_SYS_ISSUED: &str = "sys:issued";
/// S5b burns and tier pro rata
pub const PROT_SYS_BURNED: &str = "sys:burned";
/// Clawbacks
pub const PROT_SYS_CLAWED: &str = "sys:clawed";
/// Forfeits
pub const PROT_SYS_FORFEITED: &str = "sys:forfeited";
/// S5b grace-debt write-off
pub const PROT_SYS_WRITEOFF: &str = "sys:writeoff";
/// Admin adjustments, both directions
pub const PROT_SYS_ADJUST: &str = "sys:adjust";

/// Purchase credit and every clawback
pub const PROT_ACTOR_PAYMENTS: &str = "sys:payments";
/// Cipher grants (fulfil hook and sweep)
pub const PROT_ACTOR_CIPHER: &str = "sys:cipher";
/// Forfeits
pub const PROT_ACTOR_DELETION: &str = "sys:account-deletion";

/// A user's wallet account
pub fn prot_user_account(user_id: &str) -> String {
    format!("user:{user_id}")
}

/// A tank account (S5b)
pub fn prot_tank_account(tank_id: &str) -> String {
    format!("tank:{tank_id}")
}

/// A goal's hold account (S5b)
pub fn prot_hold_account(goal_id: &str) -> String {
    format!("hold:{goal_id}")
}

/// Whether an account id is a system side (no balance document)
pub fn is_prot_system_account(id: &str) -> bool {
    id.starts_with("sys:")
}

/// Pack / pay-exact purchase
pub fn prot_key_purchase(order_id: &str) -> String {
    format!("purchase:{order_id}")
}

/// First Cipher grant of a membership incarnation
pub fn prot_key_cipher_founding(user_id: &str, number: u32, base_order_id: &str) -> String {
    format!("cipher-founding:{user_id}:{number}:{base_order_id}")
}

/// A later Cipher grant; `seq` = grant rows already written for that base
pub fn prot_key_cipher_upgrade(
    user_id: &str,
    number: u32,
    base_order_id: &str,
    seq: u64,
) -> String {
    format!("cipher-upgrade:{user_id}:{number}:{base_order_id}:{seq}")
}

/// Wallet part of a reversal (one key per reversed order)
pub fn prot_key_clawback(order_id: &str) -> String {
    format!("clawback:{order_id}")
}

/// Account-deletion forfeit pass `n` (1-based)
pub fn prot_key_forfeit(user_id: &str, n: u64) -> String {
    format!("forfeit:{user_id}:{n}")
}

/// Admin adjustment
pub fn prot_key_admin(admin_id: &str, nonce: &str) -> String {
    format!("admin:{admin_id}:{nonce}")
}

/// SHA-256 (lowercase hex) of the canonical payload of a posting: what moves
/// where and why. The key, actor, reason, created_at and debit_floor are
/// deliberately left out, so a retried request with the same content is
/// "already applied" whatever its metadata. Changing this format breaks the
/// comparison against every stored row.
pub fn prot_payload_hash(p: &ProtPosting) -> String {
    let amount = match p.amount {
        ProtAmount::Exact(n) => format!("exact:{n}"),
        ProtAmount::UpTo(n) => format!("upto:{n}"),
        ProtAmount::All => "all".to_string(),
    };
    let r = &p.reference;
    let lines = [
        "prot-posting/v1".to_string(),
        format!("kind={}", p.kind.as_str()),
        "currency=Prot".to_string(),
        format!("debit={}", p.debit),
        format!("credit={}", p.credit),
        format!("amount={amount}"),
        format!("ref.order_id={}", r.order_id.as_deref().unwrap_or("")),
        format!("ref.tank_id={}", r.tank_id.as_deref().unwrap_or("")),
        format!("ref.goal_id={}", r.goal_id.as_deref().unwrap_or("")),
        format!("ref.pledge_id={}", r.pledge_id.as_deref().unwrap_or("")),
        format!("ref.day={}", r.day.as_deref().unwrap_or("")),
        format!(
            "ref.membership_number={}",
            r.membership_number
                .map(|number| number.to_string())
                .unwrap_or_default()
        ),
        format!(
            "ref.membership_order_id={}",
            r.membership_order_id.as_deref().unwrap_or("")
        ),
    ];

    Sha256::digest(lines.join("\n").as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// What a membership should have posted: its grant while active, else 0.
/// (Disputes do not lower the target; they only pause upward syncs.)
pub fn cipher_prot_target(m: &CipherMembership) -> i64 {
    if m.is_active() {
        i64::from(m.prot_grant)
    } else {
        0
    }
}

/// Prot posted for one membership incarnation, from its ledger rows
/// (`ref.membership_order_id == base`): sum of `amount` of CipherFounding and
/// CipherUpgrade rows minus sum of `requested` (NOT `amount`) of Clawback rows.
/// Counting `requested` settles a clawback to its target even when it fell short.
pub fn cipher_prot_posted(rows: &[ProtLedgerEntry]) -> i64 {
    rows.iter().fold(0_i64, |posted, row| match row.kind {
        v0::ProtEntryKind::CipherFounding | v0::ProtEntryKind::CipherUpgrade => {
            posted.saturating_add(row.amount)
        }
        // Every Clawback row is an UpTo row, so `requested` is set; a row
        // without it counts what it moved
        v0::ProtEntryKind::Clawback => posted.saturating_sub(row.requested.unwrap_or(row.amount)),
        _ => posted,
    })
}

/// Number of CipherFounding + CipherUpgrade rows (the next upgrade key's `seq`)
pub fn cipher_prot_grant_count(rows: &[ProtLedgerEntry]) -> u64 {
    rows.iter()
        .filter(|row| {
            matches!(
                row.kind,
                v0::ProtEntryKind::CipherFounding | v0::ProtEntryKind::CipherUpgrade
            )
        })
        .count() as u64
}

/// Prot of this membership incarnation that was already spent when a clawback ran:
/// sum of `shortfall` (None = 0) over Clawback rows (`ref.membership_order_id == base`).
/// MEMBERSHIP-WIDE on purpose: a shortfall recorded on one order's clawback (e.g. an
/// upgrade refunded outside the window) must also stop a later 14-day undo of another
/// order of the same membership.
pub fn cipher_prot_shortfall(rows: &[ProtLedgerEntry]) -> i64 {
    rows.iter()
        .filter(|row| row.kind == v0::ProtEntryKind::Clawback)
        .fold(0_i64, |total, row| {
            total.saturating_add(row.shortfall.unwrap_or(0))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn purchase() -> ProtPosting {
        ProtPosting {
            key: prot_key_purchase("01ORDER"),
            kind: v0::ProtEntryKind::Purchase,
            debit: PROT_SYS_ISSUED.to_string(),
            credit: prot_user_account("01USER"),
            amount: ProtAmount::Exact(2600),
            debit_floor: 0,
            actor: PROT_ACTOR_PAYMENTS.to_string(),
            reference: ProtRef {
                order_id: Some("01ORDER".to_string()),
                ..Default::default()
            },
            reason: None,
            created_at: 1_000,
        }
    }

    fn row(kind: v0::ProtEntryKind, amount: i64, requested: Option<i64>) -> ProtLedgerEntry {
        ProtLedgerEntry {
            id: "01ROW".to_string(),
            key: "k".to_string(),
            kind,
            currency: v0::ProtCurrency::Prot,
            debit: PROT_SYS_ISSUED.to_string(),
            credit: prot_user_account("01USER"),
            amount,
            requested,
            shortfall: requested.map(|requested| requested - amount),
            actor: PROT_ACTOR_CIPHER.to_string(),
            reference: ProtRef::default(),
            payload_hash: String::new(),
            reason: None,
            created_at: 1_000,
        }
    }

    fn membership() -> CipherMembership {
        CipherMembership {
            user_id: "01USER".to_string(),
            number: 42,
            tier: v0::CipherTier::T149,
            prot_grant: 33_000,
            orders: vec!["01BASE".to_string()],
            disputed_orders: vec![],
            granted_at: 1_000,
            revoked_at: None,
            revoke_reason: None,
            prot_posted_at: None,
            version: 0,
        }
    }

    #[test]
    fn account_ids_and_keys_are_the_pinned_strings() {
        assert_eq!(prot_user_account("u1"), "user:u1");
        assert_eq!(prot_tank_account("t1"), "tank:t1");
        assert_eq!(prot_hold_account("g1"), "hold:g1");
        assert!(is_prot_system_account(PROT_SYS_ISSUED));
        assert!(is_prot_system_account(PROT_SYS_ADJUST));
        assert!(!is_prot_system_account("user:u1"));

        assert_eq!(prot_key_purchase("o1"), "purchase:o1");
        assert_eq!(
            prot_key_cipher_founding("u1", 42, "o1"),
            "cipher-founding:u1:42:o1"
        );
        assert_eq!(
            prot_key_cipher_upgrade("u1", 42, "o1", 3),
            "cipher-upgrade:u1:42:o1:3"
        );
        assert_eq!(prot_key_clawback("o2"), "clawback:o2");
        assert_eq!(prot_key_forfeit("u1", 2), "forfeit:u1:2");
        assert_eq!(prot_key_admin("a1", "n1"), "admin:a1:n1");
    }

    #[test]
    fn the_payload_hash_of_a_fixed_posting_is_pinned() {
        // Changing the canonical format breaks every stored row's comparison
        assert_eq!(
            prot_payload_hash(&purchase()),
            "c9c5ed7e6f03c6784e141a4f126d157e0575152e2d50e04f03cd894399159f61"
        );

        let clawback = ProtPosting {
            key: prot_key_clawback("01ORDER"),
            kind: v0::ProtEntryKind::Clawback,
            debit: prot_user_account("01USER"),
            credit: PROT_SYS_CLAWED.to_string(),
            amount: ProtAmount::UpTo(16_500),
            debit_floor: 0,
            actor: PROT_ACTOR_PAYMENTS.to_string(),
            reference: ProtRef {
                order_id: Some("01ORDER".to_string()),
                membership_number: Some(42),
                membership_order_id: Some("01BASE".to_string()),
                ..Default::default()
            },
            reason: None,
            created_at: 2_000,
        };
        assert_eq!(
            prot_payload_hash(&clawback),
            "302bdd35f11d617791c9a43f03b1f0f18e041796e1cfcef584d9070c18628faf"
        );

        let forfeit = ProtPosting {
            key: prot_key_forfeit("01USER", 1),
            kind: v0::ProtEntryKind::Forfeit,
            debit: prot_user_account("01USER"),
            credit: PROT_SYS_FORFEITED.to_string(),
            amount: ProtAmount::All,
            debit_floor: 0,
            actor: PROT_ACTOR_DELETION.to_string(),
            reference: ProtRef::default(),
            reason: None,
            created_at: 3_000,
        };
        assert_eq!(
            prot_payload_hash(&forfeit),
            "93719d5fb5eaea085599d0fe55eea9ed82282b92ac04f0e678dc9885cbd86b84"
        );
    }

    #[test]
    fn the_payload_hash_ignores_metadata_but_not_content() {
        let base = prot_payload_hash(&purchase());
        assert_eq!(base.len(), 64);

        // Metadata: same hash
        let mut metadata = purchase();
        metadata.key = "purchase:other".to_string();
        metadata.actor = "01ADMIN".to_string();
        metadata.reason = Some("why".to_string());
        metadata.created_at = 9_999;
        metadata.debit_floor = -500;
        assert_eq!(prot_payload_hash(&metadata), base);

        // Content: a different hash
        let mut amount = purchase();
        amount.amount = ProtAmount::Exact(2601);
        assert_ne!(prot_payload_hash(&amount), base);

        let mut mode = purchase();
        mode.amount = ProtAmount::UpTo(2600);
        assert_ne!(prot_payload_hash(&mode), base);

        let mut credit = purchase();
        credit.credit = prot_user_account("01OTHER");
        assert_ne!(prot_payload_hash(&credit), base);

        let mut kind = purchase();
        kind.kind = v0::ProtEntryKind::AdminAdjust;
        assert_ne!(prot_payload_hash(&kind), base);

        let mut reference = purchase();
        reference.reference.membership_number = Some(1);
        assert_ne!(prot_payload_hash(&reference), base);
    }

    #[test]
    fn cipher_posted_counts_grants_minus_requested_clawbacks() {
        let rows = vec![
            row(v0::ProtEntryKind::CipherFounding, 16_500, None),
            row(v0::ProtEntryKind::CipherUpgrade, 16_500, None),
            // Fell short by 1,000, still settles the full 16,500
            row(v0::ProtEntryKind::Clawback, 15_500, Some(16_500)),
            // Not a Cipher row
            row(v0::ProtEntryKind::AdminAdjust, 700, None),
        ];
        assert_eq!(cipher_prot_posted(&rows), 16_500);
        assert_eq!(cipher_prot_grant_count(&rows), 2);
        assert_eq!(cipher_prot_shortfall(&rows), 1_000);

        assert_eq!(cipher_prot_posted(&[]), 0);
        assert_eq!(cipher_prot_grant_count(&[]), 0);
        assert_eq!(cipher_prot_shortfall(&[]), 0);
    }

    #[test]
    fn cipher_shortfall_sums_every_clawback_of_the_membership() {
        let rows = vec![
            row(v0::ProtEntryKind::CipherFounding, 33_000, None),
            row(v0::ProtEntryKind::Clawback, 16_000, Some(16_500)),
            row(v0::ProtEntryKind::Clawback, 0, Some(16_500)),
        ];
        assert_eq!(cipher_prot_shortfall(&rows), 500 + 16_500);
        assert_eq!(cipher_prot_posted(&rows), 0);
    }

    #[test]
    fn cipher_target_is_the_grant_while_active_even_when_disputed() {
        let mut m = membership();
        assert_eq!(cipher_prot_target(&m), 33_000);

        m.disputed_orders = vec!["01BASE".to_string()];
        assert_eq!(cipher_prot_target(&m), 33_000);

        m.revoked_at = Some(2_000);
        assert_eq!(cipher_prot_target(&m), 0);
    }

    #[test]
    fn apply_outcome_exposes_its_entry() {
        let entry = row(v0::ProtEntryKind::Purchase, 1, None);
        assert_eq!(ProtApplyOutcome::Applied(entry.clone()).entry(), &entry);
        assert_eq!(
            ProtApplyOutcome::AlreadyApplied(entry.clone()).entry(),
            &entry
        );
    }

    #[cfg(feature = "mongodb")]
    #[test]
    fn absent_references_are_not_stored_and_numbers_are_int64() {
        // The partial indexes on ref.* skip missing fields, not explicit nulls
        let mut entry = row(v0::ProtEntryKind::Purchase, 2600, None);
        entry.reference.order_id = Some("01ORDER".to_string());
        let doc = bson::to_document(&entry).unwrap();
        assert_eq!(doc.get_str("_id").unwrap(), "01ROW");
        assert_eq!(doc.get_str("kind").unwrap(), "Purchase");
        assert_eq!(doc.get_str("currency").unwrap(), "Prot");
        assert!(!doc.contains_key("requested"));
        assert!(!doc.contains_key("shortfall"));
        assert!(!doc.contains_key("reason"));
        let reference = doc.get_document("ref").unwrap();
        assert_eq!(reference.get_str("order_id").unwrap(), "01ORDER");
        assert_eq!(reference.len(), 1);
        assert_eq!(doc.get("amount"), Some(&bson::Bson::Int64(2600)));

        let read: ProtLedgerEntry = bson::from_document(doc).unwrap();
        assert_eq!(read, entry);

        let account = ProtAccount {
            id: prot_user_account("01USER"),
            currency: v0::ProtCurrency::Prot,
            balance: 5,
            version: 3,
            updated_at: 1_000,
        };
        let mut doc = bson::to_document(&account).unwrap();
        assert_eq!(doc.get("version"), Some(&bson::Bson::Int64(3)));
        doc.remove("version");
        let read: ProtAccount = bson::from_document(doc).unwrap();
        assert_eq!(read.version, 0);
    }
}
