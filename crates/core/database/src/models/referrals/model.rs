use std::collections::HashSet;

use iso8601_timestamp::Timestamp;
use rand::Rng;
use revolt_models::v0::UserFlags;
use revolt_result::Result;

use crate::{Database, User};

use super::tiers::{
    day_index, now_ms, DAY_MS, PENDING_EXPIRY_DAYS, QUALIFY_LATE_DAY, QUALIFY_MESSAGES,
    QUALIFY_MESSAGES_WITH_JOIN, QUALIFY_MIN_ACTIVE_DAYS, QUALIFY_MIN_AGE_DAYS, QUALIFY_WEEKLY_CAP,
};

auto_derived!(
    /// Lifecycle of a referral
    pub enum ReferralStatus {
        /// Waiting for the invitee to meet the qualification rules
        Pending,
        /// Counted toward the referrer's ladder
        Qualified,
        /// Not qualified within PENDING_EXPIRY_DAYS
        Expired,
        /// Withdrawn by staff
        Revoked,
    }

    /// How the invitee arrived
    #[serde(tag = "type")]
    pub enum ReferralSource {
        /// Entered the referrer's code (or opened their link)
        Code,
        /// Signed up through a server invite the referrer created
        ServerInvite { code: String },
    }

    /// Referral of one invitee by one referrer
    ///
    /// Timestamps are epoch milliseconds. The activity fields only exist
    /// while the referral is Pending and are unset once it leaves that state.
    pub struct Referral {
        /// Invitee user id (one referral per invitee, never reassigned)
        #[serde(rename = "_id")]
        pub id: String,
        /// Referrer user id
        pub referrer: String,
        /// How the invitee arrived
        pub source: ReferralSource,
        /// Epoch ms the referral was recorded (onboarding), which every
        /// qualification window is measured from
        pub created_at: i64,
        /// Current status
        pub status: ReferralStatus,
        /// Epoch ms the referral qualified
        #[serde(skip_serializing_if = "Option::is_none")]
        pub qualified_at: Option<i64>,
        /// Distinct UTC day indexes with a user-initiated action
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        pub active_days: Vec<u32>,
        /// Messages sent while pending
        #[serde(default)]
        pub message_count: i32,
        /// Joined a server through an invite not created by the referrer
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub joined_via_invite: bool,
    }

    /// A user's referral code (`_id` is the bare 4-character code)
    pub struct ReferralCode {
        #[serde(rename = "_id")]
        pub code: String,
        /// Owning user id
        pub user: String,
    }
);

/// A user-initiated action that counts toward qualification
#[derive(Debug, Clone, Copy)]
pub enum ReferralActivity<'a> {
    /// Sent a message
    Message,
    /// Acknowledged a channel
    Ack,
    /// Joined a server through an invite
    InviteJoin { creator: &'a str },
}

/// Outcome of evaluating a pending referral
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferralVerdict {
    /// Leave it pending and check again later
    Wait,
    /// Credit the referrer
    Qualify,
    /// Too old to qualify any more
    Expire,
    /// The invitee can never qualify
    Reject,
}

/// Crockford base32 alphabet (no I, L, O or U)
const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Length of a bare referral code
const CODE_LENGTH: usize = 4;
/// Optional display prefix, as in `SLOGA-KX7P`
const CODE_PREFIX: &str = "SLOGA";
/// Attempts at minting an unused code before giving up
const CODE_ATTEMPTS: usize = 8;

/// Whether the user is suspended at `now_ms`
///
/// A suspension without an end time is indefinite. An elapsed timed
/// suspension only has its flag lifted at the user's next login, so the
/// end time wins over the flag.
fn is_suspended(user: &User, now_ms: i64) -> bool {
    match &user.suspended_until {
        Some(until) => timestamp_ms(until) > now_ms,
        None => user.flags.unwrap_or(0) & UserFlags::SuspendedUntil as i32 != 0,
    }
}

fn timestamp_ms(at: &Timestamp) -> i64 {
    at.duration_since(Timestamp::UNIX_EPOCH)
        .whole_milliseconds() as i64
}

fn generate_code() -> String {
    let mut rng = rand::thread_rng();
    (0..CODE_LENGTH)
        .map(|_| CODE_ALPHABET[rng.gen_range(0..CODE_ALPHABET.len())] as char)
        .collect()
}

impl Referral {
    /// Pure. Rules Q1-Q6 of the referral plan.
    ///
    /// Reject = bot / deleted / banned / spam. A suspended invitee gives
    /// Wait. Expire when now_ms - created_at > PENDING_EXPIRY_DAYS.
    pub fn evaluate(
        &self,
        invitee: &User,
        email_verified: bool,
        now_ms: i64,
        credited_last_7d: u32,
    ) -> ReferralVerdict {
        // Only pending referrals move
        if self.status != ReferralStatus::Pending {
            return ReferralVerdict::Wait;
        }

        // Q5: bots and removed accounts can never qualify
        let removed = UserFlags::Deleted as i32 | UserFlags::Banned as i32 | UserFlags::Spam as i32;
        if invitee.bot.is_some() || invitee.flags.unwrap_or(0) & removed != 0 {
            return ReferralVerdict::Reject;
        }

        let age = now_ms - self.created_at;
        if age > PENDING_EXPIRY_DAYS * DAY_MS {
            return ReferralVerdict::Expire;
        }

        // Q5: a suspension pauses qualification, it does not end it
        if is_suspended(invitee, now_ms) {
            return ReferralVerdict::Wait;
        }

        // Q1: measured from the referral, so a pre-aged account gains nothing
        let old_enough = age >= QUALIFY_MIN_AGE_DAYS * DAY_MS;

        // Q3: several distinct days, one of them no earlier than day 7
        let distinct_days = self.active_days.iter().collect::<HashSet<_>>().len();
        let late_day = day_index(self.created_at).saturating_add(QUALIFY_LATE_DAY);
        let active = distinct_days >= QUALIFY_MIN_ACTIVE_DAYS
            && self.active_days.iter().any(|&day| day >= late_day);

        // Q4: enough messages, or fewer plus a join through someone else's invite
        let messages = self.message_count.max(0) as u32;
        let engaged = messages >= QUALIFY_MESSAGES
            || (messages >= QUALIFY_MESSAGES_WITH_JOIN && self.joined_via_invite);

        // Q6: per-referrer rolling weekly cap; over-cap referrals stay pending
        let under_cap = credited_last_7d < QUALIFY_WEEKLY_CAP;

        // Q2 is the caller's email_verified
        if old_enough && email_verified && active && engaged && under_cap {
            ReferralVerdict::Qualify
        } else {
            ReferralVerdict::Wait
        }
    }

    /// Record a qualifying action for a pending invitee.
    ///
    /// Never fails the caller: logs and swallows errors. No-op unless
    /// `user.referral_pending == Some(true)`, so nobody else pays a DB write.
    pub async fn record_activity(db: &Database, user: &User, activity: ReferralActivity<'_>) {
        if user.referral_pending != Some(true) {
            return;
        }

        let (message_inc, invite_creator) = match activity {
            ReferralActivity::Message => (1, None),
            ReferralActivity::Ack => (0, None),
            ReferralActivity::InviteJoin { creator } => (0, Some(creator)),
        };

        if let Err(error) = db
            .record_referral_activity(&user.id, day_index(now_ms()), message_inc, invite_creator)
            .await
        {
            warn!(
                "Failed to record referral activity for {}: {:?}",
                user.id, error
            );
        }
    }

    /// Record a new pending referral.
    ///
    /// Insert-if-absent on the invitee id; Ok(true) if inserted. A
    /// self-referral is never recorded.
    pub async fn create_for_invitee(
        db: &Database,
        invitee_id: &str,
        referrer: &str,
        source: ReferralSource,
    ) -> Result<bool> {
        if invitee_id == referrer {
            return Ok(false);
        }

        db.insert_referral_if_absent(&Referral {
            id: invitee_id.to_string(),
            referrer: referrer.to_string(),
            source,
            created_at: now_ms(),
            status: ReferralStatus::Pending,
            qualified_at: None,
            active_days: Vec::new(),
            message_count: 0,
            joined_via_invite: false,
        })
        .await
    }

    /// Normalize user input to a bare referral code.
    ///
    /// Case-insensitive; accepts the `SLOGA` prefix and separators
    /// (`sloga-kx7p`, `SLOGA KX7P` -> `KX7P`); reads O as 0 and I/L as 1
    /// (`kx7o` -> `KX70`). Anything that is not then 4 characters of the
    /// Crockford alphabet gives None.
    pub fn normalize_code(input: &str) -> Option<String> {
        if input.len() > 32 {
            return None;
        }

        let compact: String = input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
            .map(|c| c.to_ascii_uppercase())
            .collect();

        let bare = match compact.strip_prefix(CODE_PREFIX) {
            Some(rest) if rest.len() == CODE_LENGTH => rest,
            _ => compact.as_str(),
        };

        if bare.chars().count() != CODE_LENGTH {
            return None;
        }

        bare.chars()
            .map(|c| match c {
                'O' => Some('0'),
                'I' | 'L' => Some('1'),
                c if c.is_ascii() && CODE_ALPHABET.contains(&(c as u8)) => Some(c),
                _ => None,
            })
            .collect()
    }

    /// The user's referral code, created on first use.
    ///
    /// Retries up to CODE_ATTEMPTS times on a collision; a concurrent
    /// request that already created this user's code wins.
    pub async fn code_for_user(db: &Database, user_id: &str) -> Result<String> {
        if let Some(existing) = db.fetch_referral_code_by_user(user_id).await? {
            return Ok(existing.code);
        }

        let mut last_error = None;
        for _ in 0..CODE_ATTEMPTS {
            let code = ReferralCode {
                code: generate_code(),
                user: user_id.to_string(),
            };

            match db.insert_referral_code(&code).await {
                Ok(()) => return Ok(code.code),
                Err(error) => {
                    // The duplicate may be this user (unique index on user)
                    // rather than the code itself
                    if let Some(existing) = db.fetch_referral_code_by_user(user_id).await? {
                        return Ok(existing.code);
                    }
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| create_error!(InternalError)))
    }

    /// Normalizes, then returns the owning user id if the code exists
    pub async fn resolve_code(db: &Database, input: &str) -> Result<Option<String>> {
        let Some(code) = Referral::normalize_code(input) else {
            return Ok(None);
        };

        Ok(db.fetch_referral_code(&code).await?.map(|code| code.user))
    }
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_models::v0::UserFlags;

    use crate::{BotInformation, Database, ReferenceDb, User};

    use super::super::tiers::DAY_MS;
    use super::{Referral, ReferralActivity, ReferralSource, ReferralStatus, ReferralVerdict};

    /// Referral recorded at the start of UTC day 20,000
    const CREATED: i64 = 20_000 * DAY_MS;
    const DAY0: u32 = 20_000;

    fn referral(active_days: &[u32], message_count: i32, joined_via_invite: bool) -> Referral {
        Referral {
            id: "invitee".to_string(),
            referrer: "referrer".to_string(),
            source: ReferralSource::Code,
            created_at: CREATED,
            status: ReferralStatus::Pending,
            qualified_at: None,
            active_days: active_days.to_vec(),
            message_count,
            joined_via_invite,
        }
    }

    /// Meets every rule once 7 days have passed
    fn good() -> Referral {
        referral(&[DAY0, DAY0 + 2, DAY0 + 4, DAY0 + 7], 10, false)
    }

    fn invitee() -> User {
        User {
            id: "invitee".to_string(),
            ..Default::default()
        }
    }

    fn at(ms: i64) -> Timestamp {
        Timestamp::UNIX_EPOCH
            .checked_add(Duration::milliseconds(ms))
            .unwrap()
    }

    fn day(n: i64) -> i64 {
        CREATED + n * DAY_MS
    }

    #[test]
    fn evaluate_table() {
        use ReferralVerdict::*;

        let mut suspended = invitee();
        suspended.flags = Some(UserFlags::SuspendedUntil as i32);
        suspended.suspended_until = Some(at(day(30)));

        // Indefinite: flag set, no end time
        let mut forever = invitee();
        forever.flags = Some(UserFlags::SuspendedUntil as i32);

        // Timed suspension already over; the flag is only lifted at login
        let mut lapsed = invitee();
        lapsed.flags = Some(UserFlags::SuspendedUntil as i32);
        lapsed.suspended_until = Some(at(day(5)));

        let mut deleted = invitee();
        deleted.flags = Some(UserFlags::Deleted as i32);

        let mut banned = invitee();
        banned.flags = Some(UserFlags::Banned as i32);

        let mut bot = invitee();
        bot.bot = Some(BotInformation {
            owner: "owner".to_string(),
        });

        let mut qualified = good();
        qualified.status = ReferralStatus::Qualified;

        let spread = [DAY0, DAY0 + 2, DAY0 + 4, DAY0 + 7];
        let burst = referral(&[DAY0, DAY0 + 1, DAY0 + 2, DAY0 + 3], 50, false);
        let late6 = referral(&[DAY0, DAY0 + 2, DAY0 + 4, DAY0 + 6], 10, false);
        let late7 = referral(&[DAY0, DAY0 + 2, DAY0 + 4, DAY0 + 7], 10, false);
        let three = referral(&[DAY0, DAY0 + 3, DAY0 + 7], 10, false);
        let dupes = referral(&[DAY0, DAY0, DAY0 + 7, DAY0 + 7], 10, false);
        let nine = referral(&spread, 9, false);
        let three_join = referral(&spread, 3, true);
        let two_join = referral(&spread, 2, true);
        let negative = referral(&spread, -5, true);

        let plain = invitee();
        let good = good();
        let cases: Vec<(&str, &Referral, &User, bool, i64, u32, ReferralVerdict)> = vec![
            ("all met", &good, &plain, true, day(7), 0, Qualify),
            // Q1: 7 days since the referral, to the millisecond
            ("Q1 1ms short", &good, &plain, true, day(7) - 1, 0, Wait),
            ("Q1 day 6", &good, &plain, true, day(6), 0, Wait),
            // Q2
            ("Q2 unverified", &good, &plain, false, day(8), 0, Wait),
            // Q3: distinct days, one of them on or after day 7
            ("Q3 burst", &burst, &plain, true, day(10), 0, Wait),
            ("Q3 3 days", &three, &plain, true, day(10), 0, Wait),
            ("Q3 dupes", &dupes, &plain, true, day(10), 0, Wait),
            // Q3 late-day boundary: 4 distinct days, the last on day 6 or 7
            ("Q3 last day 6", &late6, &plain, true, day(7), 0, Wait),
            ("Q3 day 6, day 20", &late6, &plain, true, day(20), 0, Wait),
            ("Q3 last day 7", &late7, &plain, true, day(7), 0, Qualify),
            // Q4
            ("Q4 9 msgs", &nine, &plain, true, day(10), 0, Wait),
            ("Q4 3+join", &three_join, &plain, true, day(10), 0, Qualify),
            ("Q4 2+join", &two_join, &plain, true, day(10), 0, Wait),
            ("Q4 negative", &negative, &plain, true, day(10), 0, Wait),
            // Q5
            ("Q5 bot", &good, &bot, true, day(10), 0, Reject),
            ("Q5 deleted", &good, &deleted, true, day(10), 0, Reject),
            ("Q5 banned", &good, &banned, true, day(10), 0, Reject),
            ("Q5 suspended", &good, &suspended, true, day(10), 0, Wait),
            ("Q5 forever", &good, &forever, true, day(10), 0, Wait),
            ("Q5 lapsed", &good, &lapsed, true, day(10), 0, Qualify),
            // Q6: rolling weekly cap per referrer
            ("Q6 under cap", &good, &plain, true, day(10), 9, Qualify),
            ("Q6 at cap", &good, &plain, true, day(10), 10, Wait),
            // 60-day expiry, checked before the suspension pause
            ("day 60", &good, &plain, true, day(60), 10, Wait),
            ("expired", &good, &plain, true, day(60) + 1, 0, Expire),
            ("expired+susp", &good, &forever, true, day(61), 0, Expire),
            ("reject first", &good, &deleted, true, day(61), 0, Reject),
            // Only pending referrals move
            ("not pending", &qualified, &plain, true, day(10), 0, Wait),
        ];

        for (name, referral, user, email_verified, now, credited, expected) in cases {
            assert_eq!(
                referral.evaluate(user, email_verified, now, credited),
                expected,
                "case: {name}"
            );
        }
    }

    #[test]
    fn evaluate_pre_aged_account_gains_nothing() {
        // The account has existed for years (old ULID, old policy ack), but
        // the referral is younger than QUALIFY_MIN_AGE_DAYS. Every rule other
        // than Q1 is met, including an active day on day 7, so the only
        // thing holding it back is the age of the referral itself. Were Q1
        // measured from the account's ULID, this would qualify.
        let mut veteran = invitee();
        veteran.id = "01F00000000000000000000000".to_string();
        veteran.last_acknowledged_policy_change = at(DAY_MS);

        // Premise: the account predates the referral by far more than 7 days
        let account_created = ulid::Ulid::from_string(&veteran.id).unwrap().timestamp_ms() as i64;
        assert!(CREATED - account_created > 365 * DAY_MS);

        let mut recent = good();
        recent.id = veteran.id.clone();

        // One hour short of 7 days after the referral was recorded
        let almost = day(7) - 3_600_000;
        assert_eq!(
            recent.evaluate(&veteran, true, almost, 0),
            ReferralVerdict::Wait
        );

        // Control: the same referral once the window has passed
        assert_eq!(
            recent.evaluate(&veteran, true, day(7), 0),
            ReferralVerdict::Qualify
        );
    }

    #[test]
    fn normalize_code_cases() {
        let cases: &[(&str, Option<&str>)] = &[
            ("KX7P", Some("KX7P")),
            ("kx7p", Some("KX7P")),
            ("sloga-kx7p", Some("KX7P")),
            ("SLOGA KX7P", Some("KX7P")),
            ("  Sloga-KX7P  ", Some("KX7P")),
            ("KX7O", Some("KX70")),
            ("kx7o", Some("KX70")),
            ("kx7i", Some("KX71")),
            ("KX7L", Some("KX71")),
            ("ABCU", None),
            ("AB", None),
            ("", None),
            ("SLOGA", None),
            ("KX7PQ", None),
            ("SLOGA-KX7PQ", None),
            ("KX7!", None),
            ("KX7é", None),
        ];

        for (input, expected) in cases {
            assert_eq!(
                Referral::normalize_code(input).as_deref(),
                *expected,
                "input: {input:?}"
            );
        }
    }

    /// Always the in-memory driver: these tests never touch MongoDB
    fn reference_db() -> Database {
        Database::Reference(ReferenceDb::default())
    }

    #[tokio::test]
    async fn code_for_user_is_stable() {
        let db = reference_db();

        let first = Referral::code_for_user(&db, "user_a").await.unwrap();
        let second = Referral::code_for_user(&db, "user_a").await.unwrap();
        assert_eq!(first, second);
        assert_eq!(
            Referral::normalize_code(&first).as_deref(),
            Some(first.as_str())
        );

        // Another user gets their own code
        let other = Referral::code_for_user(&db, "user_b").await.unwrap();
        assert_ne!(first, other);
    }

    #[tokio::test]
    async fn resolve_code_round_trips() {
        let db = reference_db();

        let code = Referral::code_for_user(&db, "user_a").await.unwrap();
        assert_eq!(
            Referral::resolve_code(&db, &code).await.unwrap().as_deref(),
            Some("user_a")
        );

        // Display form, lower case
        let display = format!("sloga-{}", code.to_ascii_lowercase());
        assert_eq!(
            Referral::resolve_code(&db, &display)
                .await
                .unwrap()
                .as_deref(),
            Some("user_a")
        );

        // Malformed input and an unissued code resolve to nobody
        assert_eq!(Referral::resolve_code(&db, "nope!").await.unwrap(), None);
        let unissued = if code == "0000" { "0001" } else { "0000" };
        assert_eq!(Referral::resolve_code(&db, unissued).await.unwrap(), None);
    }

    #[tokio::test]
    async fn record_activity_only_for_pending_invitees() {
        let db = reference_db();

        // A self-referral is never recorded
        assert!(
            !Referral::create_for_invitee(&db, "same", "same", ReferralSource::Code)
                .await
                .unwrap()
        );
        assert!(db.fetch_referral("same").await.unwrap().is_none());

        // First referral wins; a second referrer is ignored
        assert!(
            Referral::create_for_invitee(&db, "invitee", "referrer", ReferralSource::Code)
                .await
                .unwrap()
        );
        assert!(
            !Referral::create_for_invitee(&db, "invitee", "other", ReferralSource::Code)
                .await
                .unwrap()
        );

        // Without the pending hint nothing is written
        let mut user = invitee();
        for hint in [None, Some(false)] {
            user.referral_pending = hint;
            Referral::record_activity(&db, &user, ReferralActivity::Message).await;
        }
        let untouched = db.fetch_referral("invitee").await.unwrap().unwrap();
        assert_eq!(untouched.referrer, "referrer");
        assert_eq!(untouched.message_count, 0);
        assert!(untouched.active_days.is_empty());

        user.referral_pending = Some(true);
        Referral::record_activity(&db, &user, ReferralActivity::Message).await;
        Referral::record_activity(&db, &user, ReferralActivity::Ack).await;
        Referral::record_activity(
            &db,
            &user,
            ReferralActivity::InviteJoin {
                creator: "referrer",
            },
        )
        .await;
        let recorded = db.fetch_referral("invitee").await.unwrap().unwrap();
        assert_eq!(recorded.message_count, 1);
        assert!(!recorded.active_days.is_empty());
        assert!(!recorded.joined_via_invite);
    }

    #[test]
    fn generated_codes_normalize_to_themselves() {
        for _ in 0..256 {
            let code = super::generate_code();
            assert_eq!(
                Referral::normalize_code(&code).as_deref(),
                Some(code.as_str())
            );
        }
    }
}
