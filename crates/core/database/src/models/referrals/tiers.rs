//! Every referral / donation threshold lives here; routes, crond and the
//! client (via `tiers[]`) read them from this file and nowhere else.

use revolt_models::v0::{self, DonationReward, ReferralReward, UserBadges, UserPerks};

/// One UTC day in milliseconds
pub const DAY_MS: i64 = 86_400_000;

/// Qualified referrals needed for the Recruiter badge
pub const TIER_BADGE: u32 = 1;
/// Qualified referrals needed for a custom name color
pub const TIER_NAME_COLOUR: u32 = 3;
/// Qualified referrals needed for the RecruiterElite badge
pub const TIER_BETTER_BADGE: u32 = 5;
/// Qualified referrals needed for a custom name font
pub const TIER_NAME_FONT: u32 = 10;
/// Qualified referrals needed for an animated name effect
pub const TIER_NAME_EFFECT: u32 = 25;
/// Qualified referrals needed for the raised upload cap + 7-day retention
pub const TIER_UPLOAD: u32 = 50;
/// Qualified referrals needed for a staff-designed custom badge
pub const TIER_CUSTOM_BADGE: u32 = 100;

/// Lifetime USD cents for the Supporter badge ($10 = Ko-fi minimum)
pub const DONATION_SUPPORTER_CENTS: i64 = 1000;
/// Lifetime USD cents for a custom name color
pub const DONATION_NAME_COLOUR_CENTS: i64 = 2500;
/// Lifetime USD cents for a custom name font
pub const DONATION_NAME_FONT_CENTS: i64 = 5000;
/// Lifetime USD cents for an animated name effect
pub const DONATION_NAME_EFFECT_CENTS: i64 = 10000;
/// Lifetime USD cents for the Patron badge
pub const DONATION_PATRON_CENTS: i64 = 25000;

/// Length of the invitee's name-color trial once their referral qualifies
pub const WELCOME_TRIAL_DAYS: i64 = 30;
/// A monthly supporter stays active this long after their last payment
/// (Ko-fi sends no cancellation event)
pub const MONTHLY_GRACE_DAYS: i64 = 35;
/// Large-attachment retention for uploaders holding the upload perk
pub const PERK_RETENTION_DAYS: i64 = 7;

/// Q1: minimum days since `referral.created_at`
pub const QUALIFY_MIN_AGE_DAYS: i64 = 7;
/// Q3: minimum distinct active UTC days
pub const QUALIFY_MIN_ACTIVE_DAYS: usize = 4;
/// Q3: at least one active day must fall on or after this day offset
pub const QUALIFY_LATE_DAY: u32 = 7;
/// Q4: messages needed on their own
pub const QUALIFY_MESSAGES: u32 = 10;
/// Q4: messages needed alongside a qualifying invite join
pub const QUALIFY_MESSAGES_WITH_JOIN: u32 = 3;
/// Q6: qualifications credited to one referrer per rolling 7 days
pub const QUALIFY_WEEKLY_CAP: u32 = 10;
/// A referral not qualified within this many days expires
pub const PENDING_EXPIRY_DAYS: i64 = 60;

/// Current epoch milliseconds
pub fn now_ms() -> i64 {
    iso8601_timestamp::Timestamp::now_utc()
        .duration_since(iso8601_timestamp::Timestamp::UNIX_EPOCH)
        .whole_milliseconds() as i64
}

/// UTC day index (days since the epoch) of an epoch-ms instant
pub fn day_index(ms: i64) -> u32 {
    (ms / DAY_MS) as u32
}

/// Perk bits earned from qualified referrals
pub fn perks_for_referrals(count: u32) -> u32 {
    let mut perks = 0;
    if count >= TIER_NAME_COLOUR {
        perks |= UserPerks::NameColour as u32;
    }
    if count >= TIER_NAME_FONT {
        perks |= UserPerks::NameFont as u32;
    }
    if count >= TIER_NAME_EFFECT {
        perks |= UserPerks::NameEffect as u32;
    }
    if count >= TIER_UPLOAD {
        perks |= UserPerks::UploadPerk as u32;
    }
    if count >= TIER_CUSTOM_BADGE {
        perks |= UserPerks::CustomBadge as u32;
    }
    perks
}

/// Perk bits earned from donations (cosmetic only; never the upload perk)
pub fn perks_for_donations(lifetime_cents: i64, monthly_active: bool) -> u32 {
    let mut perks = 0;
    if lifetime_cents >= DONATION_NAME_COLOUR_CENTS || monthly_active {
        perks |= UserPerks::NameColour as u32;
    }
    if lifetime_cents >= DONATION_NAME_FONT_CENTS {
        perks |= UserPerks::NameFont as u32;
    }
    if lifetime_cents >= DONATION_NAME_EFFECT_CENTS {
        perks |= UserPerks::NameEffect as u32;
    }
    perks
}

/// Badge bits earned from qualified referrals
pub fn badges_for_referrals(count: u32) -> u32 {
    let mut badges = 0;
    if count >= TIER_BADGE {
        badges |= UserBadges::Recruiter as u32;
    }
    if count >= TIER_BETTER_BADGE {
        badges |= UserBadges::RecruiterElite as u32;
    }
    badges
}

/// Badge bits earned from donations
pub fn badges_for_donations(lifetime_cents: i64, monthly_active: bool) -> u32 {
    let mut badges = 0;
    if lifetime_cents >= DONATION_SUPPORTER_CENTS {
        badges |= UserBadges::Supporter as u32;
    }
    if lifetime_cents >= DONATION_PATRON_CENTS {
        badges |= UserBadges::Patron as u32;
    }
    if monthly_active {
        badges |= UserBadges::ActiveSupporter as u32;
    }
    badges
}

/// The referral ladder, lowest rung first
pub fn referral_tier_list() -> Vec<v0::ReferralTier> {
    [
        (TIER_BADGE, ReferralReward::Badge),
        (TIER_NAME_COLOUR, ReferralReward::NameColour),
        (TIER_BETTER_BADGE, ReferralReward::BetterBadge),
        (TIER_NAME_FONT, ReferralReward::NameFont),
        (TIER_NAME_EFFECT, ReferralReward::NameEffect),
        (TIER_UPLOAD, ReferralReward::UploadPerk),
        (TIER_CUSTOM_BADGE, ReferralReward::CustomBadge),
    ]
    .into_iter()
    .map(|(count, reward)| v0::ReferralTier { count, reward })
    .collect()
}

/// The donation ladder, lowest rung first
pub fn donation_tier_list() -> Vec<v0::DonationTier> {
    [
        (DONATION_SUPPORTER_CENTS, DonationReward::SupporterBadge),
        (DONATION_NAME_COLOUR_CENTS, DonationReward::NameColour),
        (DONATION_NAME_FONT_CENTS, DonationReward::NameFont),
        (DONATION_NAME_EFFECT_CENTS, DonationReward::NameEffect),
        (DONATION_PATRON_CENTS, DonationReward::PatronBadge),
    ]
    .into_iter()
    .map(|(cents, reward)| v0::DonationTier { cents, reward })
    .collect()
}

/// Qualified-referral count of the next rung above `count`, if any
pub fn next_referral_tier(count: u32) -> Option<u32> {
    referral_tier_list()
        .into_iter()
        .map(|tier| tier.count)
        .find(|&threshold| threshold > count)
}

/// Lifetime cents of the next donation rung above `lifetime_cents`, if any
pub fn next_donation_tier(lifetime_cents: i64) -> Option<i64> {
    donation_tier_list()
        .into_iter()
        .map(|tier| tier.cents)
        .find(|&threshold| threshold > lifetime_cents)
}

#[cfg(test)]
mod tests {
    use super::*;

    const COLOUR: u32 = UserPerks::NameColour as u32;
    const FONT: u32 = UserPerks::NameFont as u32;
    const EFFECT: u32 = UserPerks::NameEffect as u32;
    const UPLOAD: u32 = UserPerks::UploadPerk as u32;
    const CUSTOM: u32 = UserPerks::CustomBadge as u32;

    #[test]
    fn day_index_is_utc_days() {
        assert_eq!(day_index(0), 0);
        assert_eq!(day_index(DAY_MS - 1), 0);
        assert_eq!(day_index(DAY_MS), 1);
        assert_eq!(day_index(20_000 * DAY_MS + 5), 20_000);
    }

    #[test]
    fn referral_perks_at_boundaries() {
        assert_eq!(perks_for_referrals(0), 0);
        assert_eq!(perks_for_referrals(2), 0);
        assert_eq!(perks_for_referrals(3), COLOUR);
        assert_eq!(perks_for_referrals(9), COLOUR);
        assert_eq!(perks_for_referrals(10), COLOUR | FONT);
        assert_eq!(perks_for_referrals(24), COLOUR | FONT);
        assert_eq!(perks_for_referrals(25), COLOUR | FONT | EFFECT);
        assert_eq!(perks_for_referrals(49), COLOUR | FONT | EFFECT);
        assert_eq!(perks_for_referrals(50), COLOUR | FONT | EFFECT | UPLOAD);
        assert_eq!(perks_for_referrals(99), COLOUR | FONT | EFFECT | UPLOAD);
        assert_eq!(
            perks_for_referrals(100),
            COLOUR | FONT | EFFECT | UPLOAD | CUSTOM
        );
    }

    #[test]
    fn donation_perks_at_boundaries() {
        assert_eq!(perks_for_donations(0, false), 0);
        assert_eq!(perks_for_donations(999, false), 0);
        // $10 is a badge only
        assert_eq!(perks_for_donations(1000, false), 0);
        assert_eq!(perks_for_donations(2499, false), 0);
        assert_eq!(perks_for_donations(2500, false), COLOUR);
        assert_eq!(perks_for_donations(4999, false), COLOUR);
        assert_eq!(perks_for_donations(5000, false), COLOUR | FONT);
        assert_eq!(perks_for_donations(9999, false), COLOUR | FONT);
        assert_eq!(perks_for_donations(10000, false), COLOUR | FONT | EFFECT);
        // Monthly supporters get the colour regardless of lifetime
        assert_eq!(perks_for_donations(0, true), COLOUR);
        // Donations never grant the upload perk or the custom badge
        assert_eq!(perks_for_donations(i64::MAX, true) & (UPLOAD | CUSTOM), 0);
    }

    #[test]
    fn referral_badges_at_boundaries() {
        let recruiter = UserBadges::Recruiter as u32;
        let elite = UserBadges::RecruiterElite as u32;
        assert_eq!(badges_for_referrals(0), 0);
        assert_eq!(badges_for_referrals(1), recruiter);
        assert_eq!(badges_for_referrals(4), recruiter);
        assert_eq!(badges_for_referrals(5), recruiter | elite);
        assert_eq!(badges_for_referrals(1000), recruiter | elite);
    }

    #[test]
    fn donation_badges_at_boundaries() {
        let supporter = UserBadges::Supporter as u32;
        let active = UserBadges::ActiveSupporter as u32;
        let patron = UserBadges::Patron as u32;
        assert_eq!(badges_for_donations(999, false), 0);
        assert_eq!(badges_for_donations(1000, false), supporter);
        assert_eq!(badges_for_donations(24999, false), supporter);
        assert_eq!(badges_for_donations(25000, false), supporter | patron);
        assert_eq!(badges_for_donations(0, true), active);
        assert_eq!(badges_for_donations(1000, true), supporter | active);
    }

    #[test]
    fn referral_ladder_is_ordered() {
        let tiers = referral_tier_list();
        let counts: Vec<u32> = tiers.iter().map(|tier| tier.count).collect();
        assert_eq!(counts, vec![1, 3, 5, 10, 25, 50, 100]);
        assert_eq!(tiers[0].reward, ReferralReward::Badge);
        assert_eq!(tiers[2].reward, ReferralReward::BetterBadge);
        assert_eq!(tiers[5].reward, ReferralReward::UploadPerk);
        assert_eq!(tiers[6].reward, ReferralReward::CustomBadge);
    }

    #[test]
    fn donation_ladder_is_ordered() {
        let tiers = donation_tier_list();
        let cents: Vec<i64> = tiers.iter().map(|tier| tier.cents).collect();
        assert_eq!(cents, vec![1000, 2500, 5000, 10000, 25000]);
        assert_eq!(tiers[0].reward, DonationReward::SupporterBadge);
        assert_eq!(tiers[4].reward, DonationReward::PatronBadge);
    }

    #[test]
    fn next_tiers_at_boundaries() {
        assert_eq!(next_referral_tier(0), Some(1));
        assert_eq!(next_referral_tier(2), Some(3));
        assert_eq!(next_referral_tier(3), Some(5));
        assert_eq!(next_referral_tier(49), Some(50));
        assert_eq!(next_referral_tier(50), Some(100));
        assert_eq!(next_referral_tier(99), Some(100));
        assert_eq!(next_referral_tier(100), None);

        assert_eq!(next_donation_tier(0), Some(1000));
        assert_eq!(next_donation_tier(999), Some(1000));
        assert_eq!(next_donation_tier(1000), Some(2500));
        assert_eq!(next_donation_tier(24999), Some(25000));
        assert_eq!(next_donation_tier(25000), None);
    }
}
