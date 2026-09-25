use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use rand::Rng;
use regex::Regex;
use revolt_models::v0;
use revolt_result::{ErrorType, Result};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::{now_ms, Database, User, DAY_MS, MONTHLY_GRACE_DAYS};

auto_derived!(
    /// Where a donation stands in the matching pipeline
    pub enum DonationState {
        /// Stored, but not yet matched to an account
        Unclaimed,
        /// Counted towards `user`'s supporter totals
        Claimed,
        /// Needs a privileged assign (non-USD, unparseable amount, or a
        /// transaction claim whose email did not match)
        NeedsReview,
        /// Refunded or charged back; never counted
        Revoked,
    }

    /// A Ko-fi payment, as delivered by the webhook (or a backfill import).
    /// Timestamps are epoch milliseconds.
    pub struct Donation {
        /// Ko-fi transaction id
        #[serde(rename = "_id")]
        pub id: String,
        /// Ko-fi webhook message id (unique; retries reuse it)
        pub message_id: String,
        /// Ko-fi payment type
        pub kind: String,
        /// Amount in the smallest unit of `currency`
        pub amount_cents: i64,
        /// Uppercased ISO currency code
        pub currency: String,
        /// USD value set on a privileged assign; counted instead of
        /// `amount_cents`, and the only way a non-USD row counts at all
        #[serde(skip_serializing_if = "Option::is_none")]
        pub usd_cents_override: Option<i64>,
        /// Whether this is a membership payment
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub is_subscription: bool,
        /// Ko-fi membership tier name
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tier_name: Option<String>,
        /// When Ko-fi recorded the payment
        pub timestamp: i64,
        /// Epoch ms the row was first stored (webhook or import); the payer HMAC
        /// retention window starts here. Rows stored before this field existed
        /// fall back to `timestamp`.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub stored_at: Option<i64>,
        /// Account the donation counts towards
        #[serde(skip_serializing_if = "Option::is_none")]
        pub user: Option<String>,
        /// When the donation was matched to `user`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub claimed_at: Option<i64>,
        /// Keyed HMAC of the payer email, see `payer_hmac`
        #[serde(skip_serializing_if = "Option::is_none")]
        pub payer_hmac: Option<String>,
        /// Account that most likely made the payment, for review
        #[serde(skip_serializing_if = "Option::is_none")]
        pub claimant: Option<String>,
        /// Matching state
        pub state: DonationState,
    }

    /// Single-use code a user pastes into their Ko-fi message
    pub struct DonationClaimCode {
        /// The code, e.g. `KOFI-7QM2XR`
        #[serde(rename = "_id")]
        pub code: String,
        /// Owning user
        pub user: String,
        /// Epoch ms the code was issued
        pub created_at: i64,
    }
);

/// Ko-fi webhook JSON (the `data` form field). Deserialize only; unknown
/// fields are ignored.
#[derive(Deserialize, Debug, Clone)]
pub struct KofiPayload {
    pub verification_token: String,
    pub message_id: String,
    pub timestamp: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub is_public: bool,
    #[serde(default)]
    pub from_name: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    pub amount: String,
    pub currency: String,
    #[serde(default)]
    pub email: Option<String>,
    pub kofi_transaction_id: String,
    #[serde(default)]
    pub is_subscription_payment: bool,
    #[serde(default)]
    pub is_first_subscription_payment: bool,
    #[serde(default)]
    pub tier_name: Option<String>,
}

/// How long an issued claim code stays valid
pub const CLAIM_CODE_TTL_DAYS: i64 = 30;

/// How long an unmatched row keeps its payer HMAC, counted from when the row
/// was stored (`stored_at`) rather than the Ko-fi payment date, so a backfill
/// of old payments stays claimable for the full window
pub const PAYER_HMAC_RETENTION_DAYS: i64 = 180;

/// Crockford base32 (no I, L, O or U)
const CLAIM_CODE_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// `KOFI-` followed by exactly six Crockford characters, either case
static RE_CLAIM_CODE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[Kk][Oo][Ff][Ii]-([0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{6})\b")
        .expect("claim code pattern is valid")
});

/// Hex HMAC-SHA256 of the normalized payer email, keyed with the server
/// secret so the stored value cannot be reversed with a dictionary.
pub fn payer_hmac(key: &str, email: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(email.trim().to_lowercase().as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Parse a Ko-fi amount ("10.00", "5", "3.5") into cents. Anything else
/// (signs, separators, more than two decimals, overflow) is None.
pub fn parse_amount_cents(amount: &str) -> Option<i64> {
    let amount = amount.trim();
    let (whole, fraction) = match amount.split_once('.') {
        Some((whole, fraction)) if !fraction.is_empty() => (whole, fraction),
        Some(_) => return None,
        None => (amount, ""),
    };

    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 2
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }

    let cents = match fraction.len() {
        0 => 0,
        1 => fraction.parse::<i64>().ok()? * 10,
        _ => fraction.parse::<i64>().ok()?,
    };

    whole
        .parse::<i64>()
        .ok()?
        .checked_mul(100)?
        .checked_add(cents)
}

/// Find the first claim code in a free-text message, uppercased
pub fn find_claim_code(message: &str) -> Option<String> {
    RE_CLAIM_CODE
        .captures(message)
        .and_then(|captures| captures.get(1))
        .map(|code| format!("KOFI-{}", code.as_str().to_ascii_uppercase()))
}

/// Generate a fresh claim code (callers retry on collision)
pub fn generate_claim_code() -> String {
    let mut rng = rand::thread_rng();
    let suffix: String = (0..6)
        .map(|_| CLAIM_CODE_ALPHABET[rng.gen_range(0..CLAIM_CODE_ALPHABET.len())] as char)
        .collect();
    format!("KOFI-{suffix}")
}

/// Payer HMAC for an email, or None when there is no key or no email.
/// With an empty key the HMAC would be a plain, reversible hash.
fn keyed_payer_hmac(key: &str, email: &str) -> Option<String> {
    if key.is_empty() || email.trim().is_empty() {
        None
    } else {
        Some(payer_hmac(key, email))
    }
}

/// Ko-fi timestamps are RFC 3339 ("2026-09-01T12:00:00Z")
fn parse_timestamp_ms(timestamp: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(timestamp.trim())
        .ok()
        .map(|at| at.timestamp_millis())
}

fn is_deleted(user: &User) -> bool {
    (user.flags.unwrap_or(0) & v0::UserFlags::Deleted as i32) != 0
}

/// Fetch a user, treating a missing or deleted account as None
async fn fetch_live_user(db: &Database, user_id: &str) -> Result<Option<User>> {
    match db.fetch_user(user_id).await {
        Ok(user) if is_deleted(&user) => Ok(None),
        Ok(user) => Ok(Some(user)),
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Resolve a claim code that exists and has not expired
async fn fetch_live_claim_code(
    db: &Database,
    code: &str,
    now: i64,
) -> Result<Option<DonationClaimCode>> {
    Ok(db
        .fetch_claim_code(code)
        .await?
        .filter(|c| now - c.created_at < CLAIM_CODE_TTL_DAYS * DAY_MS))
}

/// Give a claim code back after the payment it was consumed for could not
/// be stored, so the owner can still use it
async fn restore_claim_code(db: &Database, code: Option<&DonationClaimCode>) {
    if let Some(code) = code {
        if let Err(error) = db.insert_claim_code(code).await {
            error!("Failed to restore donation claim code: {error:?}");
        }
    }
}

/// Whether applying a claim may take the payer HMAC from another user
#[derive(Clone, Copy, PartialEq, Eq)]
enum HmacClaim {
    /// A fresh match: the owner gets the HMAC, whoever held it before
    Take,
    /// A replay of an earlier match: the owner gets the HMAC only if no
    /// other user holds it
    IfUnheld,
}

/// What a Claimed row counts towards lifetime support, in USD cents
fn counted_usd_cents(donation: &Donation) -> i64 {
    match donation.usd_cents_override {
        Some(cents) => cents,
        None if donation.currency == "USD" => donation.amount_cents,
        None => 0,
    }
}

impl Donation {
    /// Webhook core; the delta route checks the token first. Idempotent on
    /// message_id (returns the existing row).
    ///
    /// Order: currency != "USD" (or an unparseable amount) -> NeedsReview;
    /// else a live claim code in the message -> Claimed to the code's user
    /// and the code is consumed; else a user already holding this payer's
    /// HMAC -> Claimed; else Unclaimed. A claimed row's payer HMAC moves to
    /// the owner's supporter record, then the totals are recomputed.
    pub async fn ingest(db: &Database, payload: &KofiPayload, hmac_key: &str) -> Result<Donation> {
        if let Some(existing) = db.fetch_donation_by_message_id(&payload.message_id).await? {
            // A redelivery heals a delivery that failed after the row was
            // stored, but never takes the HMAC back from a user who has
            // claimed it since.
            existing.apply_claim(db, HmacClaim::IfUnheld).await?;
            return Ok(existing);
        }

        let now = now_ms();
        let payer = payload
            .email
            .as_deref()
            .and_then(|email| keyed_payer_hmac(hmac_key, email));
        let amount_cents = parse_amount_cents(&payload.amount);
        let currency = payload.currency.trim().to_uppercase();
        let needs_review = currency != "USD" || amount_cents.is_none();

        let code = match payload.message.as_deref().and_then(find_claim_code) {
            Some(code) => fetch_live_claim_code(db, &code, now).await?,
            None => None,
        };
        let code_owner = match &code {
            Some(code) => fetch_live_user(db, &code.user).await?,
            None => None,
        };

        let mut owner: Option<String> = None;
        let mut claimant: Option<String> = None;
        let mut consumed: Option<DonationClaimCode> = None;

        if needs_review {
            // Leave the code unused, but record who the payment most likely
            // belongs to for the privileged assign.
            claimant = match code_owner {
                Some(user) => Some(user.id),
                None => match &payer {
                    Some(hmac) => db
                        .fetch_user_by_payer_hmac(hmac)
                        .await?
                        .filter(|user| !is_deleted(user))
                        .map(|user| user.id),
                    None => None,
                },
            };
        } else {
            if let (Some(code), Some(user)) = (code, code_owner) {
                // The delete is the single-use gate: exactly one concurrent
                // consumer sees it succeed.
                match db.delete_claim_code(&code.code).await {
                    Ok(()) => {
                        owner = Some(user.id);
                        consumed = Some(code);
                    }
                    Err(error) if matches!(error.error_type, ErrorType::NotFound) => {}
                    Err(error) => return Err(error),
                }
            }

            if owner.is_none() {
                if let Some(hmac) = &payer {
                    owner = db
                        .fetch_user_by_payer_hmac(hmac)
                        .await?
                        .filter(|user| !is_deleted(user))
                        .map(|user| user.id);
                }
            }
        }

        let state = if needs_review {
            DonationState::NeedsReview
        } else if owner.is_some() {
            DonationState::Claimed
        } else {
            DonationState::Unclaimed
        };

        let donation = Donation {
            id: payload.kofi_transaction_id.clone(),
            message_id: payload.message_id.clone(),
            kind: payload.kind.clone(),
            amount_cents: amount_cents.unwrap_or(0),
            currency,
            usd_cents_override: None,
            is_subscription: payload.is_subscription_payment,
            tier_name: payload.tier_name.clone(),
            timestamp: parse_timestamp_ms(&payload.timestamp).unwrap_or(now),
            stored_at: Some(now_ms()),
            claimed_at: owner.as_ref().map(|_| now),
            user: owner,
            payer_hmac: payer,
            claimant,
            state,
        };

        // From here on a consumed code must go back on every path where the
        // row did not get stored, or the owner's code is burnt for nothing.
        let inserted = match db.insert_donation_if_absent(&donation).await {
            Ok(inserted) => inserted,
            Err(error) => {
                restore_claim_code(db, consumed.as_ref()).await;
                return Err(error);
            }
        };

        if !inserted {
            // Already stored (a concurrent redelivery, or the same
            // transaction under another message id): hand the code back and
            // return the stored row.
            restore_claim_code(db, consumed.as_ref()).await;

            if let Some(existing) = db
                .fetch_donation_by_message_id(&donation.message_id)
                .await?
            {
                return Ok(existing);
            }

            return db
                .fetch_donation(&donation.id)
                .await?
                .ok_or_else(|| create_error!(NotFound));
        }

        donation.apply_claim(db, HmacClaim::Take).await?;
        Ok(donation)
    }

    /// Unclaimed row + matching HMAC of the account email -> Claimed (the
    /// payer HMAC moves to the user); NeedsReview + match -> Claimed the
    /// same way only if the row would count (USD with a positive amount, or
    /// a USD override), else it stays NeedsReview with claimant = user
    /// unless another claimant is already recorded; Unclaimed + mismatch ->
    /// NeedsReview with claimant = user; NeedsReview + mismatch, or any
    /// other state -> Err(InvalidClaim); missing -> Err(NotFound).
    pub async fn claim_by_transaction(
        db: &Database,
        user: &User,
        account_email: &str,
        transaction_id: &str,
        hmac_key: &str,
    ) -> Result<v0::ClaimOutcome> {
        let mut donation = db
            .fetch_donation(transaction_id.trim())
            .await?
            .ok_or_else(|| create_error!(NotFound))?;

        if !matches!(
            donation.state,
            DonationState::Unclaimed | DonationState::NeedsReview
        ) {
            return Err(create_error!(InvalidClaim));
        }

        let email_matches = match (
            &donation.payer_hmac,
            keyed_payer_hmac(hmac_key, account_email),
        ) {
            (Some(stored), Some(expected)) => {
                bool::from(stored.as_bytes().ct_eq(expected.as_bytes()))
            }
            _ => false,
        };

        // A row under review only leaves it on a matching email when it would
        // count: a positive USD amount, or a USD value set by an assign
        let countable = donation.usd_cents_override.is_some()
            || (donation.currency == "USD" && donation.amount_cents > 0);

        if email_matches && donation.state == DonationState::NeedsReview && !countable {
            // The payer is proven, but only a privileged assign can give the
            // row a value. Record them for that review unless another user
            // is already recorded.
            if donation.claimant.is_none() {
                donation.claimant = Some(user.id.clone());
                db.update_donation(&donation).await?;
            }
            Ok(v0::ClaimOutcome::NeedsReview)
        } else if email_matches {
            donation.state = DonationState::Claimed;
            donation.user = Some(user.id.clone());
            donation.claimed_at = Some(now_ms());
            donation.claimant = None;
            db.update_donation(&donation).await?;
            donation.apply_claim(db, HmacClaim::Take).await?;
            Ok(v0::ClaimOutcome::Claimed)
        } else if donation.state == DonationState::NeedsReview {
            // Already queued for review; a mismatched claim must not
            // overwrite the claimant recorded there
            Err(create_error!(InvalidClaim))
        } else {
            donation.state = DonationState::NeedsReview;
            donation.claimant = Some(user.id.clone());
            db.update_donation(&donation).await?;
            Ok(v0::ClaimOutcome::NeedsReview)
        }
    }

    /// Privileged: attribute a donation to a user, whatever its state. The
    /// payer HMAC moves to the new owner so renewals follow; a previous
    /// owner is recomputed. A row revoked while it had no owner has no payer
    /// HMAC left to move, so that payer's renewals then need a claim code or
    /// a transaction claim. `usd_cents`, when given, is stored as the row's
    /// USD value (how a non-USD payment counts); None keeps any value set
    /// by an earlier assign.
    pub async fn assign(
        db: &Database,
        transaction_id: &str,
        user_id: &str,
        usd_cents: Option<i64>,
    ) -> Result<()> {
        if usd_cents.is_some_and(|cents| cents < 1) {
            return Err(create_error!(InvalidOperation));
        }

        let mut donation = db
            .fetch_donation(transaction_id)
            .await?
            .ok_or_else(|| create_error!(NotFound))?;

        let user = fetch_live_user(db, user_id)
            .await?
            .ok_or_else(|| create_error!(NotFound))?;

        let previous = donation.user.replace(user.id);
        donation.state = DonationState::Claimed;
        donation.claimed_at = Some(now_ms());
        donation.claimant = None;
        if usd_cents.is_some() {
            donation.usd_cents_override = usd_cents;
        }
        db.update_donation(&donation).await?;
        let recomputed = donation.apply_claim(db, HmacClaim::Take).await?;

        if let Some(previous) =
            previous.filter(|previous| previous != user_id && !recomputed.contains(previous))
        {
            Donation::recompute_supporter(db, &previous).await?;
        }

        Ok(())
    }

    /// Privileged: refund or chargeback. The row stays for the record; the
    /// previous owner's totals are recomputed without it. A row with no
    /// owner loses its payer HMAC here, since the retention sweep only
    /// clears unmatched rows and would never reach a revoked one.
    pub async fn revoke(db: &Database, transaction_id: &str) -> Result<()> {
        let mut donation = db
            .fetch_donation(transaction_id)
            .await?
            .ok_or_else(|| create_error!(NotFound))?;

        donation.state = DonationState::Revoked;
        if donation.user.is_none() {
            donation.payer_hmac = None;
        }
        db.update_donation(&donation).await?;

        if let Some(user_id) = &donation.user {
            Donation::recompute_supporter(db, user_id).await?;
        }

        Ok(())
    }

    /// lifetime = sum over Claimed rows of `usd_cents_override`, else the
    /// USD `amount_cents` (a non-USD row without an override counts 0);
    /// monthly_until = latest Claimed membership payment +
    /// MONTHLY_GRACE_DAYS. Only the totals are written (payer_hmacs and
    /// show_badges are left alone), and only when they changed; the
    /// badge, name style and perk events go out for whatever that changed.
    /// Tolerates a missing or deleted user.
    pub async fn recompute_supporter(db: &Database, user_id: &str) -> Result<()> {
        let Some(user) = fetch_live_user(db, user_id).await? else {
            return Ok(());
        };

        let now = now_ms();
        let before_badges = user.get_badges().await;
        let before_style = user.filtered_name_style(now);
        let before_perks = user.perks(now);

        let mut lifetime_usd_cents: i64 = 0;
        let mut last_membership: Option<i64> = None;
        for donation in db
            .fetch_donations_by_user(user_id)
            .await?
            .iter()
            .filter(|d| d.state == DonationState::Claimed)
        {
            lifetime_usd_cents = lifetime_usd_cents.saturating_add(counted_usd_cents(donation));

            if donation.is_subscription {
                last_membership = Some(
                    last_membership.map_or(donation.timestamp, |at| at.max(donation.timestamp)),
                );
            }
        }

        let monthly_until =
            last_membership.map(|at| at.saturating_add(MONTHLY_GRACE_DAYS * DAY_MS));

        let unchanged = match &user.supporter {
            Some(current) => {
                current.lifetime_usd_cents == lifetime_usd_cents
                    && current.monthly_until == monthly_until
            }
            // Nothing to record, so do not create an empty supporter record
            None => lifetime_usd_cents == 0 && monthly_until.is_none(),
        };
        if unchanged {
            return Ok(());
        }

        db.set_supporter_totals(user_id, lifetime_usd_cents, monthly_until)
            .await?;

        let Some(user) = fetch_live_user(db, user_id).await? else {
            return Ok(());
        };
        user.publish_perks_update_if_changed(db, before_badges, before_style, before_perks)
            .await;

        Ok(())
    }

    /// Side effects of a Claimed row: move the payer HMAC to the owner (so
    /// renewals follow them), recompute every user that lost it, then
    /// recompute the owner. Returns the ids recomputed besides the owner.
    async fn apply_claim(&self, db: &Database, hmac_claim: HmacClaim) -> Result<Vec<String>> {
        if self.state != DonationState::Claimed {
            return Ok(vec![]);
        }

        let Some(user_id) = &self.user else {
            return Ok(vec![]);
        };

        // A deleted owner must not take the HMAC away from anyone
        if fetch_live_user(db, user_id).await?.is_none() {
            return Ok(vec![]);
        }

        let held_elsewhere = match (&self.payer_hmac, hmac_claim) {
            (Some(hmac), HmacClaim::IfUnheld) => db
                .fetch_user_by_payer_hmac(hmac)
                .await?
                .is_some_and(|holder| holder.id != *user_id),
            _ => false,
        };

        let mut losers = match &self.payer_hmac {
            Some(hmac) if !held_elsewhere => db.claim_payer_hmac(user_id, hmac).await?,
            _ => vec![],
        };
        losers.retain(|loser| loser != user_id);
        losers.dedup();

        for loser in &losers {
            Donation::recompute_supporter(db, loser).await?;
        }

        Donation::recompute_supporter(db, user_id).await?;
        Ok(losers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Database, ReferenceDb};

    const KEY: &str = "test-key";

    /// Always the in-memory driver: these tests never touch MongoDB.
    fn reference_db() -> Database {
        Database::Reference(ReferenceDb::default())
    }

    #[allow(clippy::disallowed_methods)]
    async fn insert_user(db: &Database, id: &str) {
        db.insert_user(&User {
            id: id.to_string(),
            username: id.to_string(),
            discriminator: "0001".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    }

    fn payload(
        message_id: &str,
        transaction_id: &str,
        amount: &str,
        currency: &str,
        email: Option<&str>,
        message: Option<&str>,
    ) -> KofiPayload {
        KofiPayload {
            verification_token: "token".to_string(),
            message_id: message_id.to_string(),
            timestamp: "2026-09-01T12:00:00Z".to_string(),
            kind: "Donation".to_string(),
            is_public: true,
            from_name: None,
            message: message.map(str::to_string),
            amount: amount.to_string(),
            currency: currency.to_string(),
            email: email.map(str::to_string),
            kofi_transaction_id: transaction_id.to_string(),
            is_subscription_payment: false,
            is_first_subscription_payment: false,
            tier_name: None,
        }
    }

    async fn issue_code(db: &Database, code: &str, user: &str, created_at: i64) {
        db.insert_claim_code(&DonationClaimCode {
            code: code.to_string(),
            user: user.to_string(),
            created_at,
        })
        .await
        .unwrap();
    }

    #[test]
    fn amounts_parse_to_cents() {
        assert_eq!(parse_amount_cents("10.00"), Some(1000));
        assert_eq!(parse_amount_cents("5"), Some(500));
        assert_eq!(parse_amount_cents("3.5"), Some(350));
        assert_eq!(parse_amount_cents(" 25.99 "), Some(2599));
        assert_eq!(parse_amount_cents("abc"), None);
        assert_eq!(parse_amount_cents(""), None);
        assert_eq!(parse_amount_cents("5."), None);
        assert_eq!(parse_amount_cents(".5"), None);
        assert_eq!(parse_amount_cents("1.234"), None);
        assert_eq!(parse_amount_cents("-5.00"), None);
        assert_eq!(parse_amount_cents("1,000.00"), None);
        assert_eq!(parse_amount_cents("99999999999999999999"), None);
    }

    #[test]
    fn claim_codes_are_found_in_messages() {
        assert_eq!(
            find_claim_code("KOFI-7QM2XR"),
            Some("KOFI-7QM2XR".to_string())
        );
        assert_eq!(
            find_claim_code("thanks! my code is kofi-7qm2xr :)"),
            Some("KOFI-7QM2XR".to_string())
        );
        assert_eq!(
            find_claim_code("(Kofi-ab12cd)"),
            Some("KOFI-AB12CD".to_string())
        );
        // I, L, O and U are not Crockford characters
        assert_eq!(find_claim_code("KOFI-7QM2XU"), None);
        assert_eq!(find_claim_code("KOFI-OOOOOO"), None);
        // Wrong length, or glued to other text
        assert_eq!(find_claim_code("KOFI-7QM2X"), None);
        assert_eq!(find_claim_code("KOFI-7QM2XRZ"), None);
        assert_eq!(find_claim_code("XKOFI-7QM2XR"), None);
        assert_eq!(find_claim_code("no code here"), None);
    }

    #[test]
    fn payer_hmac_is_normalized_and_keyed() {
        let hmac = payer_hmac(KEY, "payer@example.com");
        assert_eq!(hmac.len(), 64);
        assert!(hmac
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        assert_eq!(hmac, payer_hmac(KEY, "payer@example.com"));
        assert_eq!(hmac, payer_hmac(KEY, "  Payer@Example.COM \n"));
        assert_ne!(hmac, payer_hmac("other-key", "payer@example.com"));
        assert_ne!(hmac, payer_hmac(KEY, "someone@example.com"));
        assert_eq!(keyed_payer_hmac("", "payer@example.com"), None);
        assert_eq!(keyed_payer_hmac(KEY, "  "), None);
    }

    #[test]
    fn generated_claim_codes_round_trip() {
        for _ in 0..64 {
            let code = generate_claim_code();
            assert_eq!(code.len(), 11);
            assert!(code.starts_with("KOFI-"));
            assert!(code[5..].bytes().all(|b| CLAIM_CODE_ALPHABET.contains(&b)));
            assert_eq!(find_claim_code(&code), Some(code.clone()));
        }
    }

    #[test]
    fn timestamps_parse_to_epoch_ms() {
        assert_eq!(
            parse_timestamp_ms("2026-09-01T12:00:00Z"),
            Some(1_788_264_000_000)
        );
        assert_eq!(parse_timestamp_ms("yesterday"), None);
    }

    #[tokio::test]
    async fn duplicate_message_id_stores_one_row() {
        let db = reference_db();

        let first = Donation::ingest(
            &db,
            &payload("msg_1", "tx_1", "10.00", "USD", None, None),
            KEY,
        )
        .await
        .unwrap();

        // A redelivery carries the same message id
        let again = Donation::ingest(
            &db,
            &payload("msg_1", "tx_other", "10.00", "USD", None, None),
            KEY,
        )
        .await
        .unwrap();

        assert_eq!(first, again);
        assert_eq!(first.state, DonationState::Unclaimed);
        assert!(db.fetch_donation("tx_other").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn stored_at_is_set_once_on_insert() {
        let db = reference_db();

        let before = now_ms();
        let first = Donation::ingest(
            &db,
            &payload("msg_1", "tx_1", "10.00", "USD", None, None),
            KEY,
        )
        .await
        .unwrap();
        let after = now_ms();

        // Stamped with the time it was stored, not the Ko-fi payment date
        let stored_at = first.stored_at.expect("an inserted row has stored_at");
        assert!((before..=after).contains(&stored_at));
        assert_eq!(
            first.timestamp,
            parse_timestamp_ms("2026-09-01T12:00:00Z").unwrap()
        );
        assert_eq!(
            db.fetch_donation("tx_1").await.unwrap().unwrap().stored_at,
            Some(stored_at)
        );

        // Let the clock move so a restamp would show
        std::thread::sleep(std::time::Duration::from_millis(5));

        // A redelivery under the same message id keeps the original stamp
        let replay = Donation::ingest(
            &db,
            &payload("msg_1", "tx_1", "10.00", "USD", None, None),
            KEY,
        )
        .await
        .unwrap();
        assert_eq!(replay.stored_at, Some(stored_at));

        // So does the same transaction under another message id
        let duplicate = Donation::ingest(
            &db,
            &payload("msg_2", "tx_1", "10.00", "USD", None, None),
            KEY,
        )
        .await
        .unwrap();
        assert_eq!(duplicate.message_id, "msg_1");
        assert_eq!(duplicate.stored_at, Some(stored_at));
        assert_eq!(
            db.fetch_donation("tx_1").await.unwrap().unwrap().stored_at,
            Some(stored_at)
        );
    }

    #[tokio::test]
    async fn non_usd_and_bad_amounts_need_review() {
        let db = reference_db();
        insert_user(&db, "user_a").await;
        issue_code(&db, "KOFI-7QM2XR", "user_a", now_ms()).await;

        let euro = Donation::ingest(
            &db,
            &payload("msg_1", "tx_1", "10.00", "EUR", None, Some("KOFI-7QM2XR")),
            KEY,
        )
        .await
        .unwrap();
        assert_eq!(euro.state, DonationState::NeedsReview);
        assert_eq!(euro.user, None);
        assert_eq!(euro.claimant.as_deref(), Some("user_a"));
        // The code is left for a payment that can be counted
        assert!(db.fetch_claim_code("KOFI-7QM2XR").await.unwrap().is_some());

        let garbled = Donation::ingest(
            &db,
            &payload("msg_2", "tx_2", "ten", "USD", None, None),
            KEY,
        )
        .await
        .unwrap();
        assert_eq!(garbled.state, DonationState::NeedsReview);
        assert_eq!(garbled.amount_cents, 0);
    }

    #[tokio::test]
    async fn claim_code_is_consumed_once() {
        let db = reference_db();
        insert_user(&db, "user_a").await;
        issue_code(&db, "KOFI-7QM2XR", "user_a", now_ms()).await;

        let first = Donation::ingest(
            &db,
            &payload(
                "msg_1",
                "tx_1",
                "10.00",
                "USD",
                Some("a@example.com"),
                Some("for the devs kofi-7qm2xr"),
            ),
            KEY,
        )
        .await
        .unwrap();
        assert_eq!(first.state, DonationState::Claimed);
        assert_eq!(first.user.as_deref(), Some("user_a"));
        assert!(db.fetch_claim_code("KOFI-7QM2XR").await.unwrap().is_none());

        let supporter = db.fetch_user("user_a").await.unwrap().supporter.unwrap();
        assert_eq!(supporter.lifetime_usd_cents, 1000);
        assert_eq!(supporter.monthly_until, None);
        assert!(supporter.show_badges);
        assert_eq!(
            supporter.payer_hmacs,
            vec![payer_hmac(KEY, "a@example.com")]
        );

        // Reusing the code from another payer attaches nothing
        let second = Donation::ingest(
            &db,
            &payload(
                "msg_2",
                "tx_2",
                "10.00",
                "USD",
                Some("b@example.com"),
                Some("KOFI-7QM2XR"),
            ),
            KEY,
        )
        .await
        .unwrap();
        assert_eq!(second.state, DonationState::Unclaimed);
        assert_eq!(second.user, None);
    }

    #[tokio::test]
    async fn expired_claim_code_is_ignored() {
        let db = reference_db();
        insert_user(&db, "user_a").await;
        issue_code(
            &db,
            "KOFI-7QM2XR",
            "user_a",
            now_ms() - (CLAIM_CODE_TTL_DAYS + 1) * DAY_MS,
        )
        .await;

        let donation = Donation::ingest(
            &db,
            &payload("msg_1", "tx_1", "10.00", "USD", None, Some("KOFI-7QM2XR")),
            KEY,
        )
        .await
        .unwrap();
        assert_eq!(donation.state, DonationState::Unclaimed);
    }

    #[tokio::test]
    async fn renewal_attaches_by_payer_hmac() {
        let db = reference_db();
        insert_user(&db, "user_a").await;
        issue_code(&db, "KOFI-7QM2XR", "user_a", now_ms()).await;

        let mut first = payload(
            "msg_1",
            "tx_1",
            "5.00",
            "USD",
            Some("a@example.com"),
            Some("KOFI-7QM2XR"),
        );
        first.is_subscription_payment = true;
        first.is_first_subscription_payment = true;
        Donation::ingest(&db, &first, KEY).await.unwrap();

        // Next month: no code, same payer with different casing
        let mut renewal = payload("msg_2", "tx_2", "5.00", "USD", Some(" A@Example.com"), None);
        renewal.is_subscription_payment = true;
        renewal.timestamp = "2026-10-01T12:00:00Z".to_string();
        let donation = Donation::ingest(&db, &renewal, KEY).await.unwrap();
        assert_eq!(donation.state, DonationState::Claimed);
        assert_eq!(donation.user.as_deref(), Some("user_a"));

        let supporter = db.fetch_user("user_a").await.unwrap().supporter.unwrap();
        assert_eq!(supporter.lifetime_usd_cents, 1000);
        assert_eq!(
            supporter.monthly_until,
            Some(parse_timestamp_ms("2026-10-01T12:00:00Z").unwrap() + MONTHLY_GRACE_DAYS * DAY_MS)
        );
        assert_eq!(supporter.payer_hmacs.len(), 1);
    }

    #[tokio::test]
    async fn transaction_claim_checks_the_account_email() {
        let db = reference_db();
        insert_user(&db, "user_a").await;
        insert_user(&db, "user_b").await;
        let user_a = db.fetch_user("user_a").await.unwrap();
        let user_b = db.fetch_user("user_b").await.unwrap();

        for (message_id, transaction_id) in [("msg_1", "tx_1"), ("msg_2", "tx_2")] {
            Donation::ingest(
                &db,
                &payload(
                    message_id,
                    transaction_id,
                    "10.00",
                    "USD",
                    Some("a@example.com"),
                    None,
                ),
                KEY,
            )
            .await
            .unwrap();
        }

        // Wrong email -> review, recorded against the claimant
        assert_eq!(
            Donation::claim_by_transaction(&db, &user_b, "b@example.com", "tx_1", KEY)
                .await
                .unwrap(),
            v0::ClaimOutcome::NeedsReview
        );
        let row = db.fetch_donation("tx_1").await.unwrap().unwrap();
        assert_eq!(row.state, DonationState::NeedsReview);
        assert_eq!(row.claimant.as_deref(), Some("user_b"));
        assert_eq!(row.user, None);
        assert!(db.fetch_user("user_b").await.unwrap().supporter.is_none());

        // A row under review only moves for the matching email; a second
        // mismatch leaves the recorded claimant alone
        let error = Donation::claim_by_transaction(&db, &user_b, "b@example.com", "tx_1", KEY)
            .await
            .unwrap_err();
        assert!(matches!(error.error_type, ErrorType::InvalidClaim));
        let row = db.fetch_donation("tx_1").await.unwrap().unwrap();
        assert_eq!(row.state, DonationState::NeedsReview);
        assert_eq!(row.claimant.as_deref(), Some("user_b"));

        // Matching email -> claimed
        assert_eq!(
            Donation::claim_by_transaction(&db, &user_a, "A@example.com", "tx_2", KEY)
                .await
                .unwrap(),
            v0::ClaimOutcome::Claimed
        );
        let supporter = db.fetch_user("user_a").await.unwrap().supporter.unwrap();
        assert_eq!(supporter.lifetime_usd_cents, 1000);
        assert_eq!(
            supporter.payer_hmacs,
            vec![payer_hmac(KEY, "a@example.com")]
        );

        // A claimed row cannot be claimed again
        let error = Donation::claim_by_transaction(&db, &user_a, "a@example.com", "tx_2", KEY)
            .await
            .unwrap_err();
        assert!(matches!(error.error_type, ErrorType::InvalidClaim));

        let error = Donation::claim_by_transaction(&db, &user_a, "a@example.com", "tx_404", KEY)
            .await
            .unwrap_err();
        assert!(matches!(error.error_type, ErrorType::NotFound));
    }

    #[tokio::test]
    async fn needs_review_row_is_claimed_by_the_matching_email() {
        let db = reference_db();
        insert_user(&db, "user_a").await;
        insert_user(&db, "user_b").await;
        let user_a = db.fetch_user("user_a").await.unwrap();
        let user_b = db.fetch_user("user_b").await.unwrap();

        Donation::ingest(
            &db,
            &payload("msg_1", "tx_1", "10.00", "USD", Some("a@example.com"), None),
            KEY,
        )
        .await
        .unwrap();

        // Someone else tries first and sends the row to review
        assert_eq!(
            Donation::claim_by_transaction(&db, &user_b, "b@example.com", "tx_1", KEY)
                .await
                .unwrap(),
            v0::ClaimOutcome::NeedsReview
        );

        // The real payer can still claim it
        assert_eq!(
            Donation::claim_by_transaction(&db, &user_a, " A@Example.com", "tx_1", KEY)
                .await
                .unwrap(),
            v0::ClaimOutcome::Claimed
        );
        let row = db.fetch_donation("tx_1").await.unwrap().unwrap();
        assert_eq!(row.state, DonationState::Claimed);
        assert_eq!(row.user.as_deref(), Some("user_a"));
        assert_eq!(row.claimant, None);
        assert!(row.claimed_at.is_some());

        let supporter = db.fetch_user("user_a").await.unwrap().supporter.unwrap();
        assert_eq!(supporter.lifetime_usd_cents, 1000);
        assert_eq!(
            supporter.payer_hmacs,
            vec![payer_hmac(KEY, "a@example.com")]
        );
        assert!(db.fetch_user("user_b").await.unwrap().supporter.is_none());
    }

    #[tokio::test]
    async fn matching_email_does_not_claim_an_uncountable_row() {
        let db = reference_db();
        insert_user(&db, "user_a").await;
        insert_user(&db, "user_b").await;
        let user_a = db.fetch_user("user_a").await.unwrap();

        let euro = Donation::ingest(
            &db,
            &payload("msg_1", "tx_1", "15.00", "EUR", Some("a@example.com"), None),
            KEY,
        )
        .await
        .unwrap();
        assert_eq!(euro.state, DonationState::NeedsReview);
        assert_eq!(euro.claimant, None);

        // The payer is proven, but the row would count for nothing: it stays
        // under review with the payer recorded as claimant
        assert_eq!(
            Donation::claim_by_transaction(&db, &user_a, "A@example.com", "tx_1", KEY)
                .await
                .unwrap(),
            v0::ClaimOutcome::NeedsReview
        );
        let row = db.fetch_donation("tx_1").await.unwrap().unwrap();
        assert_eq!(row.state, DonationState::NeedsReview);
        assert_eq!(row.claimant.as_deref(), Some("user_a"));
        assert_eq!(row.user, None);
        assert_eq!(row.claimed_at, None);
        assert!(db.fetch_user("user_a").await.unwrap().supporter.is_none());

        // A claimant recorded by another user is left alone
        issue_code(&db, "KOFI-7QM2XR", "user_b", now_ms()).await;
        Donation::ingest(
            &db,
            &payload(
                "msg_2",
                "tx_2",
                "5.00",
                "EUR",
                Some("a@example.com"),
                Some("KOFI-7QM2XR"),
            ),
            KEY,
        )
        .await
        .unwrap();
        assert_eq!(
            Donation::claim_by_transaction(&db, &user_a, "a@example.com", "tx_2", KEY)
                .await
                .unwrap(),
            v0::ClaimOutcome::NeedsReview
        );
        let row = db.fetch_donation("tx_2").await.unwrap().unwrap();
        assert_eq!(row.state, DonationState::NeedsReview);
        assert_eq!(row.claimant.as_deref(), Some("user_b"));
        assert_eq!(row.user, None);

        // Once a USD value is assigned the row counts
        Donation::assign(&db, "tx_1", "user_a", Some(1500))
            .await
            .unwrap();
        let row = db.fetch_donation("tx_1").await.unwrap().unwrap();
        assert_eq!(row.state, DonationState::Claimed);
        assert_eq!(row.user.as_deref(), Some("user_a"));
        let supporter = db.fetch_user("user_a").await.unwrap().supporter.unwrap();
        assert_eq!(supporter.lifetime_usd_cents, 1500);
        assert_eq!(
            supporter.payer_hmacs,
            vec![payer_hmac(KEY, "a@example.com")]
        );
    }

    #[tokio::test]
    async fn payer_hmac_belongs_to_one_user() {
        let db = reference_db();
        insert_user(&db, "alice").await;
        insert_user(&db, "bob").await;
        let bob = db.fetch_user("bob").await.unwrap();
        let bob_hmac = payer_hmac(KEY, "bob@example.com");

        // Bob pays once with no code: nothing to match it to yet
        let early = Donation::ingest(
            &db,
            &payload(
                "msg_0",
                "tx_0",
                "5.00",
                "USD",
                Some("bob@example.com"),
                None,
            ),
            KEY,
        )
        .await
        .unwrap();
        assert_eq!(early.state, DonationState::Unclaimed);

        // Bob pays with Alice's code, so Alice picks up Bob's HMAC
        issue_code(&db, "KOFI-7QM2XR", "alice", now_ms()).await;
        let gift = Donation::ingest(
            &db,
            &payload(
                "msg_1",
                "tx_1",
                "10.00",
                "USD",
                Some("bob@example.com"),
                Some("KOFI-7QM2XR"),
            ),
            KEY,
        )
        .await
        .unwrap();
        assert_eq!(gift.user.as_deref(), Some("alice"));
        let alice = db.fetch_user("alice").await.unwrap().supporter.unwrap();
        assert_eq!(alice.payer_hmacs, vec![bob_hmac.clone()]);

        // Bob proves the earlier payment with his own email: the HMAC moves
        assert_eq!(
            Donation::claim_by_transaction(&db, &bob, "bob@example.com", "tx_0", KEY)
                .await
                .unwrap(),
            v0::ClaimOutcome::Claimed
        );
        let alice = db.fetch_user("alice").await.unwrap().supporter.unwrap();
        assert!(alice.payer_hmacs.is_empty());
        // Alice keeps the payment made with her code
        assert_eq!(alice.lifetime_usd_cents, 1000);
        let supporter = db.fetch_user("bob").await.unwrap().supporter.unwrap();
        assert_eq!(supporter.payer_hmacs, vec![bob_hmac.clone()]);
        assert_eq!(supporter.lifetime_usd_cents, 500);

        // A late redelivery of the code payment does not take it back
        let replay = Donation::ingest(
            &db,
            &payload(
                "msg_1",
                "tx_1",
                "10.00",
                "USD",
                Some("bob@example.com"),
                Some("KOFI-7QM2XR"),
            ),
            KEY,
        )
        .await
        .unwrap();
        assert_eq!(replay, gift);
        let alice = db.fetch_user("alice").await.unwrap().supporter.unwrap();
        assert!(alice.payer_hmacs.is_empty());

        // Bob's next payment goes to Bob
        let renewal = Donation::ingest(
            &db,
            &payload(
                "msg_2",
                "tx_2",
                "5.00",
                "USD",
                Some("Bob@example.com"),
                None,
            ),
            KEY,
        )
        .await
        .unwrap();
        assert_eq!(renewal.state, DonationState::Claimed);
        assert_eq!(renewal.user.as_deref(), Some("bob"));

        let supporter = db.fetch_user("bob").await.unwrap().supporter.unwrap();
        assert_eq!(supporter.lifetime_usd_cents, 1000);
        assert_eq!(supporter.payer_hmacs, vec![bob_hmac]);
        let alice = db.fetch_user("alice").await.unwrap().supporter.unwrap();
        assert_eq!(alice.lifetime_usd_cents, 1000);
        assert!(alice.payer_hmacs.is_empty());
    }

    #[tokio::test]
    async fn claim_code_survives_a_failed_or_duplicate_insert() {
        use super::super::ops::reference::FAILING_DONATION_ID;

        let db = reference_db();
        insert_user(&db, "user_a").await;
        issue_code(&db, "KOFI-7QM2XR", "user_a", now_ms()).await;

        // The insert errors after the code was consumed
        let error = Donation::ingest(
            &db,
            &payload(
                "msg_1",
                FAILING_DONATION_ID,
                "10.00",
                "USD",
                None,
                Some("KOFI-7QM2XR"),
            ),
            KEY,
        )
        .await
        .unwrap_err();
        assert!(matches!(error.error_type, ErrorType::DatabaseError { .. }));
        assert!(db.fetch_claim_code("KOFI-7QM2XR").await.unwrap().is_some());
        assert!(db
            .fetch_donation(FAILING_DONATION_ID)
            .await
            .unwrap()
            .is_none());

        // The same transaction arrives under another message id
        Donation::ingest(
            &db,
            &payload("msg_2", "tx_2", "10.00", "USD", None, None),
            KEY,
        )
        .await
        .unwrap();
        let existing = Donation::ingest(
            &db,
            &payload("msg_3", "tx_2", "10.00", "USD", None, Some("KOFI-7QM2XR")),
            KEY,
        )
        .await
        .unwrap();
        assert_eq!(existing.message_id, "msg_2");
        assert_eq!(existing.state, DonationState::Unclaimed);
        assert!(db.fetch_claim_code("KOFI-7QM2XR").await.unwrap().is_some());
        assert!(db.fetch_user("user_a").await.unwrap().supporter.is_none());

        // The code still works for a payment that does get stored
        let claimed = Donation::ingest(
            &db,
            &payload("msg_4", "tx_4", "10.00", "USD", None, Some("KOFI-7QM2XR")),
            KEY,
        )
        .await
        .unwrap();
        assert_eq!(claimed.user.as_deref(), Some("user_a"));
        assert!(db.fetch_claim_code("KOFI-7QM2XR").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn assigned_usd_value_counts_towards_lifetime() {
        let db = reference_db();
        insert_user(&db, "user_a").await;

        let euro = Donation::ingest(
            &db,
            &payload("msg_1", "tx_1", "10.00", "EUR", None, None),
            KEY,
        )
        .await
        .unwrap();
        assert_eq!(euro.state, DonationState::NeedsReview);

        // Without a USD value a non-USD row counts for nothing
        Donation::assign(&db, "tx_1", "user_a", None).await.unwrap();
        assert!(db.fetch_user("user_a").await.unwrap().supporter.is_none());

        Donation::assign(&db, "tx_1", "user_a", Some(1100))
            .await
            .unwrap();
        let row = db.fetch_donation("tx_1").await.unwrap().unwrap();
        assert_eq!(row.state, DonationState::Claimed);
        assert_eq!(row.usd_cents_override, Some(1100));
        let supporter = db.fetch_user("user_a").await.unwrap().supporter.unwrap();
        assert_eq!(supporter.lifetime_usd_cents, 1100);

        // A later assign without a value keeps the stored one
        Donation::assign(&db, "tx_1", "user_a", None).await.unwrap();
        let row = db.fetch_donation("tx_1").await.unwrap().unwrap();
        assert_eq!(row.usd_cents_override, Some(1100));

        // On a USD row the assigned value wins over the paid amount
        Donation::ingest(
            &db,
            &payload("msg_2", "tx_2", "10.00", "USD", None, None),
            KEY,
        )
        .await
        .unwrap();
        Donation::assign(&db, "tx_2", "user_a", Some(900))
            .await
            .unwrap();
        let supporter = db.fetch_user("user_a").await.unwrap().supporter.unwrap();
        assert_eq!(supporter.lifetime_usd_cents, 2000);

        let error = Donation::assign(&db, "tx_2", "user_a", Some(0))
            .await
            .unwrap_err();
        assert!(matches!(error.error_type, ErrorType::InvalidOperation));
        let row = db.fetch_donation("tx_2").await.unwrap().unwrap();
        assert_eq!(row.usd_cents_override, Some(900));
    }

    #[tokio::test]
    async fn assign_and_revoke_recompute_totals() {
        let db = reference_db();
        insert_user(&db, "user_a").await;

        Donation::ingest(
            &db,
            &payload("msg_1", "tx_1", "30.00", "USD", None, None),
            KEY,
        )
        .await
        .unwrap();

        Donation::assign(&db, "tx_1", "user_a", None).await.unwrap();
        let supporter = db.fetch_user("user_a").await.unwrap().supporter.unwrap();
        assert_eq!(supporter.lifetime_usd_cents, 3000);

        Donation::revoke(&db, "tx_1").await.unwrap();
        let row = db.fetch_donation("tx_1").await.unwrap().unwrap();
        assert_eq!(row.state, DonationState::Revoked);
        let supporter = db.fetch_user("user_a").await.unwrap().supporter.unwrap();
        assert_eq!(supporter.lifetime_usd_cents, 0);

        let error = Donation::assign(&db, "tx_1", "user_404", None)
            .await
            .unwrap_err();
        assert!(matches!(error.error_type, ErrorType::NotFound));
    }

    #[tokio::test]
    async fn revoke_drops_the_payer_hmac_only_from_unowned_rows() {
        let db = reference_db();
        insert_user(&db, "user_a").await;
        issue_code(&db, "KOFI-7QM2XR", "user_a", now_ms()).await;

        let unclaimed = Donation::ingest(
            &db,
            &payload("msg_1", "tx_1", "10.00", "USD", Some("b@example.com"), None),
            KEY,
        )
        .await
        .unwrap();
        assert_eq!(unclaimed.state, DonationState::Unclaimed);
        assert!(unclaimed.payer_hmac.is_some());

        let review = Donation::ingest(
            &db,
            &payload("msg_2", "tx_2", "10.00", "EUR", Some("c@example.com"), None),
            KEY,
        )
        .await
        .unwrap();
        assert_eq!(review.state, DonationState::NeedsReview);
        assert!(review.payer_hmac.is_some());

        let claimed = Donation::ingest(
            &db,
            &payload(
                "msg_3",
                "tx_3",
                "10.00",
                "USD",
                Some("a@example.com"),
                Some("KOFI-7QM2XR"),
            ),
            KEY,
        )
        .await
        .unwrap();
        assert_eq!(claimed.state, DonationState::Claimed);

        // Refunded before anyone matched them: nothing links the hash to an
        // account, so it goes with the revoke
        for transaction_id in ["tx_1", "tx_2"] {
            Donation::revoke(&db, transaction_id).await.unwrap();
            let row = db.fetch_donation(transaction_id).await.unwrap().unwrap();
            assert_eq!(row.state, DonationState::Revoked);
            assert_eq!(row.user, None);
            assert_eq!(row.payer_hmac, None);
        }

        // An owned row keeps its hash, and so does the owner's record, so
        // their later payments still find them
        Donation::revoke(&db, "tx_3").await.unwrap();
        let row = db.fetch_donation("tx_3").await.unwrap().unwrap();
        assert_eq!(row.state, DonationState::Revoked);
        assert_eq!(row.user.as_deref(), Some("user_a"));
        assert_eq!(row.payer_hmac, Some(payer_hmac(KEY, "a@example.com")));
        let supporter = db.fetch_user("user_a").await.unwrap().supporter.unwrap();
        assert_eq!(supporter.lifetime_usd_cents, 0);
        assert_eq!(
            supporter.payer_hmacs,
            vec![payer_hmac(KEY, "a@example.com")]
        );
    }
}
