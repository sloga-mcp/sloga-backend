//! Server-owned Cipher and Prot catalog
//!
//! Prices and Prot grants live here and nowhere else: the client only names a
//! tier, a Prot pack or a pay-exact amount, and upgrade prices are computed
//! from this table, never sent in.

use revolt_models::v0::{CipherTier, ProductFamily, Sku};
use revolt_result::{create_error, Result};

use crate::settings::ProtSalesSettings;
use crate::stripe::{
    CIPHER_TAX_CODE, PROT_TAX_CODE, PROT_TERMS_ACCEPTANCE_MESSAGE, TERMS_ACCEPTANCE_MESSAGE,
};

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
///
/// A Prot SKU is charged its stamped price (`cents` of a pack, `prot` of a
/// pay-exact one); nothing or a negative amount is `ProtPackInvalid`.
pub fn sku_cents(s: &Sku) -> Result<i64> {
    let cents = match s {
        Sku::CipherNew { tier } => tier_cents(*tier),
        Sku::CipherUpgrade { from, to } => tier_cents(*to) - tier_cents(*from),
        Sku::ProtPack { cents, .. } => return prot_cents(*cents),
        Sku::ProtExact { prot } => return prot_cents(*prot),
    };
    if cents <= 0 {
        return Err(create_error!(CipherTierInvalid));
    }
    Ok(cents)
}

/// A Prot price, refused unless it charges something
fn prot_cents(cents: i64) -> Result<i64> {
    if cents <= 0 {
        return Err(create_error!(ProtPackInvalid));
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
        Sku::ProtPack { prot, .. } | Sku::ProtExact { prot } => {
            format!("{} Prot", prot_label(*prot))
        }
    }
}

/// Thousands-grouped Prot count, "2,600"
pub fn prot_label(prot: i64) -> String {
    let digits = prot.unsigned_abs().to_string();
    let mut label = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    if prot < 0 {
        label.push('-');
    }
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            label.push(',');
        }
        label.push(digit);
    }
    label
}

/// What the buyer asked for at a Prot checkout
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtChoice {
    Pack(String),
    ExactCents(i64),
}

/// Server-side quote of a Prot checkout: a pack id → that pack as configured
/// now, its price and Prot stamped on the SKU (an unknown id is
/// `ProtPackInvalid`); a pay-exact amount → `ProtExact` of that many Prot for
/// as many cents, when within `exact_min_cents..=exact_max_cents`, else
/// `ProtPackInvalid`
pub fn quote_prot(ps: &ProtSalesSettings, choice: &ProtChoice) -> Result<Sku> {
    match choice {
        ProtChoice::Pack(id) => ps
            .pack(id)
            .map(|pack| Sku::ProtPack {
                pack: pack.id.clone(),
                prot: pack.prot,
                cents: pack.cents,
            })
            .ok_or_else(|| create_error!(ProtPackInvalid)),
        ProtChoice::ExactCents(cents)
            if (ps.exact_min_cents..=ps.exact_max_cents).contains(cents) =>
        {
            Ok(Sku::ProtExact { prot: *cents })
        }
        ProtChoice::ExactCents(_) => Err(create_error!(ProtPackInvalid)),
    }
}

/// Prot an order credits; None for Cipher SKUs (their grant is the
/// membership's, see [`tier_prot`])
pub fn sku_prot(s: &Sku) -> Option<i64> {
    match s {
        Sku::CipherNew { .. } | Sku::CipherUpgrade { .. } => None,
        Sku::ProtPack { prot, .. } | Sku::ProtExact { prot } => Some(*prot),
    }
}

/// Checkbox text on Stripe Checkout: a Cipher keeps
/// [`TERMS_ACCEPTANCE_MESSAGE`] (the 14-day refund promise), Prot gets
/// [`PROT_TERMS_ACCEPTANCE_MESSAGE`]
pub fn sku_consent_message(s: &Sku) -> &'static str {
    match s.family() {
        ProductFamily::Cipher => TERMS_ACCEPTANCE_MESSAGE,
        ProductFamily::Prot => PROT_TERMS_ACCEPTANCE_MESSAGE,
    }
}

/// Stripe tax code of the line item: a Cipher keeps [`CIPHER_TAX_CODE`],
/// Prot gets [`PROT_TAX_CODE`]
pub fn sku_tax_code(s: &Sku) -> &'static str {
    match s.family() {
        ProductFamily::Cipher => CIPHER_TAX_CODE,
        ProductFamily::Prot => PROT_TAX_CODE,
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

/// Tier a Cipher SKU leaves the buyer on once fulfilled; None for Prot
pub fn sku_cipher_tier(s: &Sku) -> Option<CipherTier> {
    match s {
        Sku::CipherNew { tier } => Some(*tier),
        Sku::CipherUpgrade { to, .. } => Some(*to),
        Sku::ProtPack { .. } | Sku::ProtExact { .. } => None,
    }
}

/// Tier the buyer holds once the SKU is fulfilled (a Cipher SKU only)
#[cfg(test)]
pub fn sku_target_tier(s: &Sku) -> CipherTier {
    sku_cipher_tier(s).expect("a Cipher SKU")
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

    // --- Prot ----------------------------------------------------------

    fn prot_settings() -> ProtSalesSettings {
        ProtSalesSettings::from_parts(
            &revolt_config::FeaturePayments::default(),
            &revolt_config::ProtectionFeatures::default(),
        )
        .unwrap()
    }

    fn assert_pack_invalid(result: Result<impl std::fmt::Debug>) {
        match result {
            Err(err) => assert!(
                matches!(err.error_type, ErrorType::ProtPackInvalid),
                "expected ProtPackInvalid, got {:?}",
                err.error_type
            ),
            Ok(value) => panic!("expected ProtPackInvalid, got {value:?}"),
        }
    }

    #[test]
    fn prot_packs_are_quoted_from_the_config() {
        let ps = prot_settings();
        let cases = [
            ("p5", 500, 500),
            ("p10", 1000, 1000),
            ("p25", 2500, 2600),
            ("p50", 5000, 5300),
            ("p100", 10000, 11000),
        ];
        for (id, cents, prot) in cases {
            let sku = quote_prot(&ps, &ProtChoice::Pack(id.to_string())).unwrap();
            assert_eq!(
                sku,
                Sku::ProtPack {
                    pack: id.to_string(),
                    prot,
                    cents
                }
            );
            assert_eq!(sku.family(), ProductFamily::Prot);
            assert_eq!(sku_cents(&sku).unwrap(), cents);
            assert_eq!(sku_prot(&sku), Some(prot));
            assert_eq!(sku_cipher_tier(&sku), None);
        }

        for id in ["p7", "P25", "", "p25 ", "cipher"] {
            assert_pack_invalid(quote_prot(&ps, &ProtChoice::Pack(id.to_string())));
        }
    }

    #[test]
    fn pay_exact_is_quoted_within_its_bounds() {
        let ps = prot_settings();
        for cents in [50, 51, 1234, 49_999, 50_000] {
            let sku = quote_prot(&ps, &ProtChoice::ExactCents(cents)).unwrap();
            assert_eq!(sku, Sku::ProtExact { prot: cents });
            assert_eq!(sku_cents(&sku).unwrap(), cents, "1 Prot = 1 cent");
            assert_eq!(sku_prot(&sku), Some(cents));
        }
        for cents in [i64::MIN, -50, 0, 49, 50_001, i64::MAX] {
            assert_pack_invalid(quote_prot(&ps, &ProtChoice::ExactCents(cents)));
        }
    }

    #[test]
    fn hand_built_prot_skus_that_charge_nothing_are_refused() {
        for sku in [
            Sku::ProtPack {
                pack: "p5".to_string(),
                prot: 500,
                cents: 0,
            },
            Sku::ProtPack {
                pack: "p5".to_string(),
                prot: 500,
                cents: -500,
            },
            Sku::ProtExact { prot: 0 },
            Sku::ProtExact { prot: -1 },
        ] {
            assert_pack_invalid(sku_cents(&sku));
        }
    }

    #[test]
    fn prot_product_names_group_thousands() {
        let pack = Sku::ProtPack {
            pack: "p25".to_string(),
            prot: 2600,
            cents: 2500,
        };
        assert_eq!(sku_product_name(&pack), "2,600 Prot");
        assert_eq!(sku_product_name(&Sku::ProtExact { prot: 50 }), "50 Prot");
        assert_eq!(
            sku_product_name(&Sku::ProtExact { prot: 1_000_000 }),
            "1,000,000 Prot"
        );

        for (prot, label) in [
            (0, "0"),
            (999, "999"),
            (1000, "1,000"),
            (11000, "11,000"),
            (123456, "123,456"),
            (1234567, "1,234,567"),
            (-2600, "-2,600"),
            (i64::MIN, "-9,223,372,036,854,775,808"),
        ] {
            assert_eq!(prot_label(prot), label, "{prot}");
        }
    }

    #[test]
    fn cipher_skus_keep_the_cipher_consent_text_and_tax_code() {
        for sku in [
            Sku::CipherNew {
                tier: CipherTier::T99,
            },
            Sku::CipherUpgrade {
                from: CipherTier::T99,
                to: CipherTier::T299,
            },
        ] {
            assert_eq!(sku_consent_message(&sku), TERMS_ACCEPTANCE_MESSAGE);
            assert_eq!(sku_tax_code(&sku), CIPHER_TAX_CODE);
            assert_eq!(sku_prot(&sku), None);
        }

        for sku in [
            Sku::ProtPack {
                pack: "p5".to_string(),
                prot: 500,
                cents: 500,
            },
            Sku::ProtExact { prot: 50 },
        ] {
            assert_eq!(sku_consent_message(&sku), PROT_TERMS_ACCEPTANCE_MESSAGE);
            assert_eq!(sku_tax_code(&sku), PROT_TAX_CODE);
        }
        assert_ne!(TERMS_ACCEPTANCE_MESSAGE, PROT_TERMS_ACCEPTANCE_MESSAGE);
    }

    #[test]
    fn cipher_tiers_of_skus() {
        assert_eq!(
            sku_cipher_tier(&Sku::CipherNew {
                tier: CipherTier::T149
            }),
            Some(CipherTier::T149)
        );
        assert_eq!(
            sku_cipher_tier(&Sku::CipherUpgrade {
                from: CipherTier::T99,
                to: CipherTier::T299,
            }),
            Some(CipherTier::T299)
        );
        assert_eq!(sku_cipher_tier(&Sku::ProtExact { prot: 50 }), None);
    }
}
