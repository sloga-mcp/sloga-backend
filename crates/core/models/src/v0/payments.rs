#[cfg(feature = "validator")]
use validator::Validate;

auto_derived!(
    /// Cipher membership tier, named after its price in US dollars
    #[derive(Copy)]
    pub enum CipherTier {
        /// $99 tier
        T99,
        /// $149 tier
        T149,
        /// $299 tier
        T299,
    }

    /// What a payment order buys
    #[cfg_attr(feature = "serde", serde(tag = "type"))]
    pub enum Sku {
        /// A new Cipher membership
        CipherNew {
            /// Tier being bought
            tier: CipherTier,
        },
        /// Upgrade of an existing Cipher membership, priced as the difference
        CipherUpgrade {
            /// Tier currently held
            from: CipherTier,
            /// Tier being bought
            to: CipherTier,
        },
    }

    /// Public Cipher badge on a user
    ///
    /// Present only while the membership is active and has no open dispute
    pub struct UserCipher {
        /// Cipher number
        pub number: u32,
        /// Current tier
        pub tier: CipherTier,
    }

    /// Where the buyer is sent after checkout
    pub enum CipherReturnTo {
        /// Back to the web app
        #[cfg_attr(feature = "serde", serde(rename = "web"))]
        Web,
        /// To the website, for desktop and mobile shells that open checkout
        /// in the system browser
        #[cfg_attr(feature = "serde", serde(rename = "shell"))]
        Shell,
    }

    /// Start a Cipher checkout
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataCipherCheckout {
        /// Tier to buy; an upgrade when the user already holds a lower tier
        pub tier: CipherTier,
        /// Where the buyer is sent after checkout
        pub return_to: CipherReturnTo,
    }

    /// Checkout page the client should navigate to
    pub struct CipherCheckoutResponse {
        /// Hosted checkout URL
        pub url: String,
    }

    /// The session user's Cipher membership
    pub struct CipherMembershipView {
        /// Cipher number
        pub number: u32,
        /// Current tier
        pub tier: CipherTier,
        /// Whether a payment for this membership is under dispute, which
        /// hides the public badge until it is resolved; only ever shown to
        /// the owner
        pub disputed: bool,
        /// Prot granted with the current tier
        pub prot_grant: u32,
    }

    /// The session user's unfinished checkout
    pub struct CipherPendingView {
        /// Id of the payment order
        pub order_id: String,
        /// What the order buys
        pub sku: Sku,
        /// Epoch ms after which the checkout page expires
        pub expires_at: i64,
    }

    /// The session user's Cipher standing
    pub struct CipherMe {
        /// Membership, if the user holds an active one
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub membership: Option<CipherMembershipView>,
        /// Unfinished checkout, if any
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub pending: Option<CipherPendingView>,
    }

    /// Public Cipher sale counter
    pub struct CipherStats {
        /// Cipher numbers claimed so far, retired numbers included
        pub claimed: u32,
        /// Total Cipher numbers on sale
        pub cap: u32,
        /// Whether the sale is currently open
        pub open: bool,
        /// Epoch ms at which the sale closes (absent = no close date)
        #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
        pub closes_at: Option<i64>,
    }
);

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn sku_is_tagged_by_type() {
        let new = Sku::CipherNew {
            tier: CipherTier::T149,
        };
        assert_eq!(
            serde_json::to_value(&new).unwrap(),
            serde_json::json!({"type": "CipherNew", "tier": "T149"})
        );

        let upgrade: Sku =
            serde_json::from_str(r#"{"type": "CipherUpgrade", "from": "T99", "to": "T299"}"#)
                .unwrap();
        assert_eq!(
            upgrade,
            Sku::CipherUpgrade {
                from: CipherTier::T99,
                to: CipherTier::T299,
            }
        );
    }

    #[test]
    fn checkout_body_reads_tier_and_return_to() {
        let web: DataCipherCheckout =
            serde_json::from_str(r#"{"tier": "T99", "return_to": "web"}"#).unwrap();
        assert_eq!(web.tier, CipherTier::T99);
        assert_eq!(web.return_to, CipherReturnTo::Web);

        let shell: DataCipherCheckout =
            serde_json::from_str(r#"{"tier": "T299", "return_to": "shell"}"#).unwrap();
        assert_eq!(shell.return_to, CipherReturnTo::Shell);
    }

    #[test]
    fn checkout_body_rejects_unknown_values() {
        // tiers and return targets are closed sets; anything else is a 400, not a default
        assert!(serde_json::from_str::<DataCipherCheckout>(
            r#"{"tier": "T50", "return_to": "web"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<DataCipherCheckout>(
            r#"{"tier": "T99", "return_to": "Web"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<DataCipherCheckout>(r#"{"tier": "T99"}"#).is_err());
    }

    #[test]
    fn empty_cipher_me_serializes_to_empty_object() {
        let me = CipherMe {
            membership: None,
            pending: None,
        };
        assert_eq!(serde_json::to_string(&me).unwrap(), "{}");
    }
}
