use revolt_models::v0;

auto_derived!(
    /// Why a Cipher membership was revoked
    pub enum CipherRevokeReason {
        /// The payment was refunded (in full or in part)
        Refund,
        /// A dispute on the payment was lost
        DisputeLost,
        /// Revoked by staff
        Admin,
    }

    /// A user's Cipher membership. A revoked row is kept, and its number
    /// stays retired; the row is deleted with the account, or when a refund
    /// within the release window puts its number back in the pool (the
    /// unique `number` index would otherwise block the number's reuse).
    /// Timestamps are epoch milliseconds.
    pub struct CipherMembership {
        /// Id of the member
        #[serde(rename = "_id")]
        pub user_id: String,
        /// Cipher number held
        pub number: u32,
        /// Current tier
        pub tier: v0::CipherTier,
        /// Prot granted with the current tier
        pub prot_grant: u32,
        /// Payment orders applied to this membership (purchase and upgrades)
        #[serde(default)]
        pub orders: Vec<String>,
        /// Orders with an open dispute; the public badge is hidden while
        /// any are listed
        #[serde(default)]
        pub disputed_orders: Vec<String>,
        /// When the membership was first granted
        pub granted_at: i64,
        /// When the membership was revoked
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub revoked_at: Option<i64>,
        /// Why the membership was revoked
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub revoke_reason: Option<CipherRevokeReason>,
        /// When the Prot grant was posted
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub prot_posted_at: Option<i64>,
        /// Optimistic-concurrency counter, bumped by every
        /// `update_cipher_membership_if_version`; a row stored before the
        /// field existed reads as 0
        #[serde(default)]
        pub version: u64,
    }
);

impl CipherMembership {
    /// Whether the membership has not been revoked
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }

    /// The public badge: Some only when the membership is active and no
    /// dispute is open, so a dispute is never broadcast
    pub fn public_badge(&self) -> Option<v0::UserCipher> {
        if self.is_active() && self.disputed_orders.is_empty() {
            Some(v0::UserCipher {
                number: self.number,
                tier: self.tier,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn membership() -> CipherMembership {
        CipherMembership {
            user_id: "01USER00000000000000000000".to_string(),
            number: 42,
            tier: v0::CipherTier::T149,
            prot_grant: 33_000,
            orders: vec!["order-a".to_string()],
            disputed_orders: vec![],
            granted_at: 1_000_000,
            revoked_at: None,
            revoke_reason: None,
            prot_posted_at: None,
            version: 0,
        }
    }

    #[test]
    fn active_undisputed_membership_shows_its_badge() {
        let row = membership();
        assert!(row.is_active());
        assert_eq!(
            row.public_badge(),
            Some(v0::UserCipher {
                number: 42,
                tier: v0::CipherTier::T149,
            })
        );
    }

    #[test]
    fn revoked_membership_has_no_badge() {
        let mut row = membership();
        row.revoked_at = Some(2_000_000);
        row.revoke_reason = Some(CipherRevokeReason::Refund);
        assert!(!row.is_active());
        assert_eq!(row.public_badge(), None);
    }

    #[test]
    fn open_dispute_hides_the_badge() {
        let mut row = membership();
        row.disputed_orders = vec!["order-a".to_string()];
        assert!(row.is_active());
        assert_eq!(row.public_badge(), None);

        // Resolved: the badge comes back
        row.disputed_orders.clear();
        assert!(row.public_badge().is_some());
    }

    #[test]
    fn revoked_and_disputed_membership_has_no_badge() {
        let mut row = membership();
        row.revoked_at = Some(2_000_000);
        row.revoke_reason = Some(CipherRevokeReason::DisputeLost);
        row.disputed_orders = vec!["order-a".to_string()];
        assert_eq!(row.public_badge(), None);
    }

    #[test]
    fn badge_follows_the_current_tier() {
        let mut row = membership();
        row.tier = v0::CipherTier::T299;
        row.orders.push("order-b".to_string());
        assert_eq!(
            row.public_badge(),
            Some(v0::UserCipher {
                number: 42,
                tier: v0::CipherTier::T299,
            })
        );
    }

    #[cfg(feature = "mongodb")]
    #[test]
    fn absent_options_are_not_serialized() {
        // Sparse and partial indexes skip missing fields, not explicit nulls
        let doc = bson::to_document(&membership()).unwrap();
        assert!(!doc.contains_key("revoked_at"));
        assert!(!doc.contains_key("revoke_reason"));
        assert!(!doc.contains_key("prot_posted_at"));
        assert_eq!(doc.get_str("_id").unwrap(), "01USER00000000000000000000");
        assert_eq!(doc.get_str("tier").unwrap(), "T149");
    }

    #[cfg(feature = "mongodb")]
    #[test]
    fn version_is_stored_as_int64_and_absent_reads_as_zero() {
        let mut row = membership();
        row.version = 3;
        let mut doc = bson::to_document(&row).unwrap();
        // The compare-and-swap filter matches on this encoding
        assert_eq!(doc.get("version"), Some(&bson::Bson::Int64(3)));

        // A row written before the field existed
        doc.remove("version");
        let read: CipherMembership = bson::from_document(doc).unwrap();
        assert_eq!(read.version, 0);
    }
}
