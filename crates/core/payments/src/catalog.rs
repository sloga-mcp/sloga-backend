//! Server-owned Cipher catalog
//!
//! Prices and Prot grants live here and nowhere else: the client only names a
//! tier, and upgrade prices are computed from this table, never sent in.

use revolt_models::v0::{CipherTier, Sku};
use revolt_result::{create_error, Result};

/// Size of the seeded `cipher_numbers` table; `cipher_cap` may not exceed it
pub const CIPHER_CAP_MAX: u32 = 1000;

/// Price of a tier in US cents
pub fn tier_cents(t: CipherTier) -> i64 {
    match t {
        CipherTier::T99 => 9_900,
        CipherTier::T149 => 14_900,
        CipherTier::T299 => 29_900,
    }
}

/// Launch-day Prot granted with a tier (recorded as a deferred credit)
pub fn tier_prot(t: CipherTier) -> u32 {
    match t {
        CipherTier::T99 => 16_500,
        CipherTier::T149 => 33_000,
        CipherTier::T299 => 75_000,
    }
}

/// Ordering of tiers; an upgrade must go strictly up
pub fn tier_rank(t: CipherTier) -> u8 {
    match t {
        CipherTier::T99 => 1,
        CipherTier::T149 => 2,
        CipherTier::T299 => 3,
    }
}

/// Price label shown on the Stripe Checkout page
fn tier_label(t: CipherTier) -> &'static str {
    match t {
        CipherTier::T99 => "$99",
        CipherTier::T149 => "$149",
        CipherTier::T299 => "$299",
    }
}

/// Amount charged for a SKU, in US cents
///
/// An upgrade is charged the difference between the two tiers. [`quote`]
/// only builds upgrades that go strictly up, but a `Sku` can also be built
/// by hand or read back from storage, so a same-tier or downgrade "upgrade"
/// (nothing or a negative amount to charge) is refused here with
/// `CipherTierInvalid` instead of being trusted.
pub fn sku_cents(s: &Sku) -> Result<i64> {
    let cents = match s {
        Sku::CipherNew { tier } => tier_cents(*tier),
        Sku::CipherUpgrade { from, to } => tier_cents(*to) - tier_cents(*from),
    };
    if cents <= 0 {
        return Err(create_error!(CipherTierInvalid));
    }
    Ok(cents)
}

/// Product name shown on the Stripe Checkout page
pub fn sku_product_name(s: &Sku) -> String {
    match s {
        Sku::CipherNew { tier } => format!("Cipher founding supporter ({})", tier_label(*tier)),
        Sku::CipherUpgrade { from, to } => {
            format!(
                "Cipher upgrade ({} to {})",
                tier_label(*from),
                tier_label(*to)
            )
        }
    }
}

/// What a user holding `current` (None = no active membership) is sold when
/// they ask for `wanted`
///
/// None → `CipherNew(wanted)`; a strictly higher tier → `CipherUpgrade`;
/// the same tier or a downgrade → `CipherTierInvalid`.
pub fn quote(current: Option<CipherTier>, wanted: CipherTier) -> Result<Sku> {
    match current {
        None => Ok(Sku::CipherNew { tier: wanted }),
        Some(from) if tier_rank(wanted) > tier_rank(from) => {
            Ok(Sku::CipherUpgrade { from, to: wanted })
        }
        Some(_) => Err(create_error!(CipherTierInvalid)),
    }
}

/// Tier the buyer holds once the SKU is fulfilled
pub fn sku_target_tier(s: &Sku) -> CipherTier {
    match s {
        Sku::CipherNew { tier } => *tier,
        Sku::CipherUpgrade { to, .. } => *to,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revolt_result::ErrorType;

    const TIERS: [CipherTier; 3] = [CipherTier::T99, CipherTier::T149, CipherTier::T299];

    fn assert_tier_invalid(current: CipherTier, wanted: CipherTier) {
        match quote(Some(current), wanted) {
            Err(err) => assert!(
                matches!(err.error_type, ErrorType::CipherTierInvalid),
                "{current:?} -> {wanted:?}: expected CipherTierInvalid, got {:?}",
                err.error_type
            ),
            Ok(sku) => panic!("{current:?} -> {wanted:?}: expected CipherTierInvalid, got {sku:?}"),
        }
    }

    #[test]
    fn tier_table() {
        assert_eq!(tier_cents(CipherTier::T99), 9_900);
        assert_eq!(tier_cents(CipherTier::T149), 14_900);
        assert_eq!(tier_cents(CipherTier::T299), 29_900);

        assert_eq!(tier_rank(CipherTier::T99), 1);
        assert_eq!(tier_rank(CipherTier::T149), 2);
        assert_eq!(tier_rank(CipherTier::T299), 3);
    }

    #[test]
    fn prot_amounts() {
        assert_eq!(tier_prot(CipherTier::T99), 16_500);
        assert_eq!(tier_prot(CipherTier::T149), 33_000);
        assert_eq!(tier_prot(CipherTier::T299), 75_000);
    }

    #[test]
    fn rank_order_matches_price_order() {
        // an "upgrade" by rank must always cost more, or quote() could sell a negative charge
        for a in TIERS {
            for b in TIERS {
                assert_eq!(
                    tier_rank(a) < tier_rank(b),
                    tier_cents(a) < tier_cents(b),
                    "{a:?} vs {b:?}"
                );
            }
        }
    }

    #[test]
    fn quote_new_purchases() {
        for tier in TIERS {
            let sku = quote(None, tier).unwrap();
            assert_eq!(sku, Sku::CipherNew { tier });
            assert_eq!(sku_cents(&sku).unwrap(), tier_cents(tier));
            assert_eq!(sku_target_tier(&sku), tier);
        }
    }

    #[test]
    fn quote_upgrades_charge_the_difference() {
        let cases = [
            (CipherTier::T99, CipherTier::T149, 5_000),
            (CipherTier::T99, CipherTier::T299, 20_000),
            (CipherTier::T149, CipherTier::T299, 15_000),
        ];

        for (from, to, cents) in cases {
            let sku = quote(Some(from), to).unwrap();
            assert_eq!(sku, Sku::CipherUpgrade { from, to });
            assert_eq!(sku_cents(&sku).unwrap(), cents, "{from:?} -> {to:?}");
            assert_eq!(sku_target_tier(&sku), to);
        }
    }

    #[test]
    fn quote_rejects_same_tier() {
        for tier in TIERS {
            assert_tier_invalid(tier, tier);
        }
    }

    #[test]
    fn quote_rejects_every_downgrade() {
        assert_tier_invalid(CipherTier::T149, CipherTier::T99);
        assert_tier_invalid(CipherTier::T299, CipherTier::T99);
        assert_tier_invalid(CipherTier::T299, CipherTier::T149);
    }

    #[test]
    fn quote_covers_every_pair() {
        // 3 new + 3 upgrades succeed; the other 6 (same tier, downgrade) are refused
        let mut ok = 0;
        let mut refused = 0;
        let currents = [
            None,
            Some(CipherTier::T99),
            Some(CipherTier::T149),
            Some(CipherTier::T299),
        ];
        for current in currents {
            for wanted in TIERS {
                match quote(current, wanted) {
                    Ok(sku) => {
                        assert!(
                            sku_cents(&sku).unwrap() > 0,
                            "{sku:?} must charge something"
                        );
                        ok += 1;
                    }
                    Err(_) => refused += 1,
                }
            }
        }
        assert_eq!((ok, refused), (6, 6));
    }

    #[test]
    fn hand_built_upgrades_that_charge_nothing_are_refused() {
        // Same tier (0 cents) and every downgrade (negative cents)
        for from in TIERS {
            for to in TIERS {
                if tier_rank(to) > tier_rank(from) {
                    continue;
                }
                match sku_cents(&Sku::CipherUpgrade { from, to }) {
                    Err(err) => assert!(
                        matches!(err.error_type, ErrorType::CipherTierInvalid),
                        "{from:?} -> {to:?}: expected CipherTierInvalid, got {:?}",
                        err.error_type
                    ),
                    Ok(cents) => panic!("{from:?} -> {to:?}: priced at {cents} cents"),
                }
            }
        }
    }

    #[test]
    fn product_names() {
        let new = |tier| sku_product_name(&Sku::CipherNew { tier });
        assert_eq!(new(CipherTier::T99), "Cipher founding supporter ($99)");
        assert_eq!(new(CipherTier::T149), "Cipher founding supporter ($149)");
        assert_eq!(new(CipherTier::T299), "Cipher founding supporter ($299)");

        let upgrade = |from, to| sku_product_name(&Sku::CipherUpgrade { from, to });
        assert_eq!(
            upgrade(CipherTier::T99, CipherTier::T149),
            "Cipher upgrade ($99 to $149)"
        );
        assert_eq!(
            upgrade(CipherTier::T99, CipherTier::T299),
            "Cipher upgrade ($99 to $299)"
        );
        assert_eq!(
            upgrade(CipherTier::T149, CipherTier::T299),
            "Cipher upgrade ($149 to $299)"
        );
    }

    #[test]
    fn labels_match_prices() {
        for tier in TIERS {
            assert_eq!(tier_label(tier), format!("${}", tier_cents(tier) / 100));
        }
    }
}
