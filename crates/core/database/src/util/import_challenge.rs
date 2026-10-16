//! Ownership challenge codes for importing a server from another platform.
//!
//! Before an import starts, the user proves they manage the source server by
//! placing a short code there (a server description, a role name, a room
//! topic). The code is an HMAC over the source, the Sloga user and the UTC
//! day, so it cannot be guessed, cannot be replayed by another account, and a
//! code minted for one source (Stoat) does not verify against another
//! (Matrix). Keyed by the shared `[api.import] challenge_secret`. The code that
//! matched at verification is stored on the job (`challenge_code`); later
//! checks compare against that stored value and never recompute it, so a UTC
//! day roll-over mid-import cannot invalidate it.
//!
//! On Fluxer a role name alone is not proof (any moderator can rename a role
//! without holding its permissions), so `fluxer_role_proof` also checks the
//! role against the guild audit log.

use std::collections::HashSet;

use chrono::{DateTime, NaiveDate, NaiveTime, Utc};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

/// Every challenge code starts with this, so users can tell what it is for
pub const CODE_PREFIX: &str = "sloga-import-";

/// Characters of the base32 digest kept after the prefix (40 bits)
const CODE_DIGEST_LEN: usize = 8;

/// Challenge code for `user_id` importing from `source_tag` on UTC `day`.
///
/// `CODE_PREFIX` followed by the first eight characters of the RFC 4648
/// base32 (uppercase, unpadded) encoding of
/// HMAC-SHA256(key, `"{source_tag}:{user_id}:{yyyy-mm-dd}"`).
pub fn code(key: &[u8], source_tag: &str, user_id: &str, day: NaiveDate) -> String {
    // Config readiness refuses an empty secret, so this never happens in a
    // running service; HMAC still accepts it, so release builds produce a value
    debug_assert!(!key.is_empty(), "import challenge key must not be empty");

    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(format!("{source_tag}:{user_id}:{}", day.format("%Y-%m-%d")).as_bytes());
    let digest = mac.finalize().into_bytes();

    let encoded = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &digest);
    format!("{CODE_PREFIX}{}", &encoded[..CODE_DIGEST_LEN])
}

/// The codes accepted at `now`: today's and yesterday's (UTC), so a code
/// shown just before midnight still verifies a little after it
pub fn accepted_codes(
    key: &[u8],
    source_tag: &str,
    user_id: &str,
    now: DateTime<Utc>,
) -> [String; 2] {
    let today = now.date_naive();
    // Only `NaiveDate::MIN` has no predecessor; fall back to today there
    let yesterday = today.pred_opt().unwrap_or(today);

    [
        code(key, source_tag, user_id, today),
        code(key, source_tag, user_id, yesterday),
    ]
}

/// Find an accepted code inside text the user controls on the source
/// platform (a description, topic or name), returning the code that matched.
///
/// Users paste the code among other text, so it may appear anywhere. The
/// match is exact (case-sensitive), and the character after the code must
/// be absent or non-alphanumeric: a longer token that merely starts with a
/// valid code (`sloga-import-ABCDEFGHX`) is a different string the user did
/// not get from us, and accepting it would make the check depend on where
/// the surrounding text happens to break rather than on the code itself.
pub fn find_accepted_code(
    haystack: &str,
    key: &[u8],
    source_tag: &str,
    user_id: &str,
    now: DateTime<Utc>,
) -> Option<String> {
    accepted_codes(key, source_tag, user_id, now)
        .into_iter()
        .find(|candidate| {
            haystack
                .match_indices(candidate.as_str())
                .any(|(start, _)| {
                    haystack[start + candidate.len()..]
                        .chars()
                        .next()
                        .map_or(true, |next| !next.is_alphanumeric())
                })
        })
}

/// The codes accepted at `now` (see `accepted_codes`), each paired with the
/// UTC day it was minted for: today's first, then yesterday's
pub fn accepted_codes_with_days(
    key: &[u8],
    source_tag: &str,
    user_id: &str,
    now: DateTime<Utc>,
) -> [(String, NaiveDate); 2] {
    let today = now.date_naive();
    // Same fallback as `accepted_codes`, so both return the same codes
    let yesterday = today.pred_opt().unwrap_or(today);
    let [today_code, yesterday_code] = accepted_codes(key, source_tag, user_id, now);

    [(today_code, today), (yesterday_code, yesterday)]
}

/// The UTC day `code` was minted for, given when the job holding it was
/// created: that date, the day before or the day before that. Anything else
/// (an older code, another user's, another source's) is `None`.
pub fn code_day(
    key: &[u8],
    source_tag: &str,
    user_id: &str,
    code: &str,
    created: DateTime<Utc>,
) -> Option<NaiveDate> {
    let mut day = created.date_naive();
    for _ in 0..3 {
        if self::code(key, source_tag, user_id, day) == code {
            return Some(day);
        }
        day = day.pred_opt()?;
    }
    None
}

/// Fluxer (Discord numbering): grants every permission and bypasses overwrites
pub const ADMINISTRATOR: u64 = 1 << 3;

/// Fluxer (Discord numbering): Manage Server
pub const MANAGE_GUILD: u64 = 1 << 5;

/// Fluxer snowflakes count milliseconds from the Discord epoch (2015-01-01 UTC)
pub const FLUXER_EPOCH_MS: u64 = 1_420_070_400_000;

/// Snowflakes keep their millisecond timestamp above this many low bits
const SNOWFLAKE_TIME_SHIFT: u32 = 22;

/// A Fluxer role as the ownership proof sees it
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofRole<'a> {
    pub id: u64,
    pub name: &'a str,
    pub permissions: u64,
}

/// What a role audit entry did to the role's name
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameChange {
    /// The entry does not touch the name
    Unchanged,
    /// The entry sets the name; `None` when the new value is missing or not a
    /// string
    To(Option<String>),
}

/// What a role audit entry did to the role's permission bits
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermChange {
    /// The entry does not touch the permissions
    Unchanged,
    /// The permissions went from `old` to `new` (`old` is 0 on creation)
    Changed { old: u64, new: u64 },
}

/// A ROLE_CREATE or ROLE_UPDATE entry from the Fluxer guild audit log
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAuditEvent {
    /// The entry's own id; entries are ordered by it
    pub entry_id: u64,
    pub role_id: u64,
    /// Who made the change, when the entry names a readable user
    pub user_id: Option<u64>,
    /// ROLE_CREATE (its name and permissions are the initial values)
    pub created: bool,
    pub name: NameChange,
    pub permissions: PermChange,
}

/// Bits that let a member manage the server
const PRIVILEGED: u64 = ADMINISTRATOR | MANAGE_GUILD;

/// When a Fluxer snowflake was minted
pub fn snowflake_time(id: u64) -> DateTime<Utc> {
    // At most 2^42 ms past 2015, far inside chrono's range
    let ms = FLUXER_EPOCH_MS + (id >> SNOWFLAKE_TIME_SHIFT);
    DateTime::from_timestamp_millis(ms as i64).expect("snowflake time is within chrono's range")
}

/// The smallest snowflake minted at or after 00:00 UTC on `day`, as the
/// audit-log `after` cursor. Saturates to 0 before the epoch and to
/// `u64::MAX` past the 42-bit timestamp range.
pub fn day_start_snowflake(day: NaiveDate) -> u64 {
    let since_epoch = day_start(day)
        .timestamp_millis()
        .saturating_sub(FLUXER_EPOCH_MS as i64);
    if since_epoch <= 0 {
        0
    } else if since_epoch as u64 >= 1 << (64 - SNOWFLAKE_TIME_SHIFT) {
        u64::MAX
    } else {
        (since_epoch as u64) << SNOWFLAKE_TIME_SHIFT
    }
}

fn day_start(day: NaiveDate) -> DateTime<Utc> {
    day.and_time(NaiveTime::MIN).and_utc()
}

/// Find the role that proves the user manages a Fluxer guild, returning the
/// code it carries and its id. `candidates` are the accepted codes with their
/// days (`accepted_codes_with_days`, or the stored code with `code_day`).
///
/// A role name alone proves nothing: any Manage Roles moderator can rename a
/// role they outrank, and a name-only edit skips Fluxer's permission check.
/// Every bot install also leaves a privileged role behind (named after the
/// app, holding its permissions, near the bottom of the list, never deleted
/// when the bot leaves). What a moderator cannot do is ADD Manage Server or
/// Administrator to a role: unless they own the guild, Fluxer refuses a role
/// create or permission edit asking for any bit they do not hold
/// themselves (`resolveRequestedPermissions`, `GuildRoleService.ts:216-221`
/// in fluxerapp/fluxer). So a role only counts if every one of these holds:
/// - its name is exactly the code (no trimming, no substring match);
/// - it is not `@everyone` (whose id is the guild id), which every member has;
/// - the bot does not hold it: that is the bot's own install role, carrying
///   the bot's permissions rather than the user's;
/// - it carries Administrator or Manage Server;
/// - it was created no earlier than the code's day, so it cannot predate the
///   code;
/// - the audit log has its creation;
/// - the last audit entry that set its name (creation included) set exactly
///   the code;
/// - the last audit entry that ADDED Administrator or Manage Server to it
///   (creation counts as adding to nothing) comes no earlier than that
///   naming entry, or was made by the same user.
///
/// The last rule is the proof: the privilege was granted, by someone able to
/// manage the server, to a role already carrying the code, or the person who
/// put the code on it is the one who granted it. Renaming a role somebody
/// else had already privileged (a bot-install role, an admin role) fails, and
/// so does renaming it away and back after the grant. A grant made by an admin
/// after a moderator's rename passes: the admin could manage the server.
/// The usual web flow (create "new role", rename it, grant Manage Server, in
/// either order, by one user) passes.
///
/// The caller fetches the audit log from the code's day onward and fails
/// closed when it cannot read all of it.
pub fn fluxer_role_proof(
    roles: &[ProofRole<'_>],
    guild_id: u64,
    bot_role_ids: &[u64],
    audit: &[RoleAuditEvent],
    candidates: &[(String, NaiveDate)],
) -> Option<(String, u64)> {
    roles.iter().find_map(|role| {
        if role.id == guild_id
            || bot_role_ids.contains(&role.id)
            || role.permissions & PRIVILEGED == 0
        {
            return None;
        }

        let (code, _) = candidates.iter().find(|(code, day)| {
            role.name == code.as_str() && snowflake_time(role.id) >= day_start(*day)
        })?;

        granted_under_code(role.id, code, audit).then(|| (code.clone(), role.id))
    })
}

/// The audit rules of `fluxer_role_proof` for one role
fn granted_under_code(role_id: u64, code: &str, audit: &[RoleAuditEvent]) -> bool {
    let mut events: Vec<&RoleAuditEvent> = audit
        .iter()
        .filter(|event| event.role_id == role_id)
        .collect();
    events.sort_by_key(|event| event.entry_id);

    if !events.iter().any(|event| event.created) {
        return false;
    }

    let named = match events
        .iter()
        .rev()
        .find(|event| matches!(event.name, NameChange::To(_)))
    {
        Some(named) => named,
        None => return false,
    };
    if !matches!(&named.name, NameChange::To(Some(name)) if name == code) {
        return false;
    }

    let granted = match events.iter().rev().find(|event| {
        matches!(event.permissions,
            PermChange::Changed { old, new } if new & !old & PRIVILEGED != 0)
    }) {
        Some(granted) => granted,
        None => return false,
    };

    granted.entry_id >= named.entry_id
        || (granted.user_id.is_some() && granted.user_id == named.user_id)
}

/// Fluxer audit action ROLE_CREATE
pub const FLUXER_AUDIT_ROLE_CREATE: u8 = 30;

/// Fluxer audit action ROLE_UPDATE
pub const FLUXER_AUDIT_ROLE_UPDATE: u8 = 31;

/// `limit` sent with every audit-log read (Fluxer's maximum)
pub const FLUXER_AUDIT_PAGE_LIMIT: u32 = 100;

/// Most audit-log pages a caller reads per action type. A caller whose last
/// page read is still full (`FluxerAuditPage::is_full`) has not seen the
/// whole window and fails closed.
///
/// Fluxer reads newest first even with `after`: it selects `log_id > after`
/// ordered by `log_id` descending (`GuildRepository.ts:619,624` in
/// fluxerapp/fluxer). A full `after` page has therefore dropped the OLDEST
/// entries of the window (the ones nearest the code's day), and no later
/// `after` read can reach them. `next_after` is always `None`, so callers read
/// one page per action type and a full first page already fails closed; this
/// cap only bounds the loop.
pub const FLUXER_AUDIT_MAX_PAGES: usize = 3;

/// Why an audit-log page was refused
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditParseError {
    /// Not the shape we read it as; nothing on the page is trusted
    Malformed,
}

/// One audit-log page, parsed
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FluxerAuditPage {
    pub entries: Vec<RoleAuditEvent>,
    /// Entries Fluxer returned
    pub count: usize,
    /// Always `None`: see `FLUXER_AUDIT_MAX_PAGES`
    pub next_after: Option<u64>,
}

impl FluxerAuditPage {
    /// Whether the window may hold entries this page left out. Callers fail
    /// closed on this, never on `next_after` being `None`.
    pub fn is_full(&self) -> bool {
        self.count >= FLUXER_AUDIT_PAGE_LIMIT as usize
    }
}

/// Parses one page fetched with `action_type`. A full page
/// (`FluxerAuditPage::is_full`) cannot be continued forward, so `next_after`
/// is always `None` and the caller fails closed on it (`FLUXER_AUDIT_MAX_PAGES`).
///
/// Fails closed: a page without an `audit_log_entries` array, an entry whose
/// `id` or `target_id` is not a decimal snowflake string, an entry of another
/// action type, or an `id` seen twice on the page is `Malformed`. When Fluxer
/// skips no-change entries while filling a page, it moves its `after` to the
/// oldest entry it read and reads the same newest entries again
/// (`GuildService.ts:346-352`): the page repeats entries and the older part
/// of the window goes unread, so a repeat means the page is incomplete.
///
/// Fluxer records a role's create and every update as `changes`, one
/// `{ key, old_value?, new_value? }` per field that changed, over the role's
/// `name`, `permissions` (a decimal string) and display fields
/// (`GuildRoleService.ts:116-123,177-184,290-305`, `serializeRoleForAudit`).
/// A `changes` that is missing or not a list of objects with a string `key`,
/// a field listed twice, or a `permissions` value that is not a number is
/// `Malformed`. Other keys are ignored. A `name` whose new value is not a
/// string is `NameChange::To(None)`, which proves nothing, and a creation
/// always names the role. `user_id` is kept only when it is a snowflake.
pub fn parse_fluxer_role_audit_page(
    body: &Value,
    action_type: u8,
) -> Result<FluxerAuditPage, AuditParseError> {
    use AuditParseError::Malformed;

    if action_type != FLUXER_AUDIT_ROLE_CREATE && action_type != FLUXER_AUDIT_ROLE_UPDATE {
        return Err(Malformed);
    }

    let raw = body
        .get("audit_log_entries")
        .and_then(Value::as_array)
        .ok_or(Malformed)?;

    let mut seen = HashSet::with_capacity(raw.len());
    let mut entries = Vec::new();
    for entry in raw {
        let id = entry.get("id").and_then(snowflake).ok_or(Malformed)?;
        if !seen.insert(id) {
            return Err(Malformed);
        }
        if entry.get("action_type").and_then(Value::as_u64) != Some(action_type.into()) {
            return Err(Malformed);
        }
        let role_id = entry
            .get("target_id")
            .and_then(snowflake)
            .ok_or(Malformed)?;

        let user_id = entry.get("user_id").and_then(snowflake);
        let created = action_type == FLUXER_AUDIT_ROLE_CREATE;

        let changes = entry
            .get("changes")
            .and_then(Value::as_array)
            .ok_or(Malformed)?;
        let mut name = None;
        let mut permissions = None;
        for change in changes {
            let key = change.get("key").and_then(Value::as_str).ok_or(Malformed)?;
            match key {
                "name" => {
                    let to = change
                        .get("new_value")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    if name.replace(NameChange::To(to)).is_some() {
                        return Err(Malformed);
                    }
                }
                "permissions" => {
                    let new = change
                        .get("new_value")
                        .and_then(permission_bits)
                        .ok_or(Malformed)?;
                    let old = if created {
                        0
                    } else {
                        change
                            .get("old_value")
                            .and_then(permission_bits)
                            .ok_or(Malformed)?
                    };
                    if permissions
                        .replace(PermChange::Changed { old, new })
                        .is_some()
                    {
                        return Err(Malformed);
                    }
                }
                _ => {}
            }
        }

        let name = match name {
            Some(name) => name,
            None if created => NameChange::To(None),
            None => NameChange::Unchanged,
        };
        entries.push(RoleAuditEvent {
            entry_id: id,
            role_id,
            user_id,
            created,
            name,
            permissions: permissions.unwrap_or(PermChange::Unchanged),
        });
    }

    Ok(FluxerAuditPage {
        entries,
        count: raw.len(),
        next_after: None,
    })
}

/// `after` cursor for the first page: just before 00:00 UTC of the EARLIEST
/// candidate day (inclusive of a role created exactly at midnight).
///
/// `after` is exclusive (`log_id > after`), and an entry's id is minted when
/// it is written, after the role it records. With no candidates (nothing can
/// prove anyway) this is 0, which Fluxer reads as no cursor at all
/// (`GuildRepository.ts:618`).
pub fn fluxer_audit_after_cursor(candidates: &[(String, NaiveDate)]) -> u64 {
    candidates
        .iter()
        .map(|(_, day)| *day)
        .min()
        .map_or(0, |day| day_start_snowflake(day).saturating_sub(1))
}

/// A snowflake as Fluxer writes it: a string of 1 to 20 decimal digits
fn snowflake(value: &Value) -> Option<u64> {
    let text = value.as_str()?;
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Permission bits as recorded: a decimal string, or a plain JSON integer
fn permission_bits(value: &Value) -> Option<u64> {
    // Same digit-string rule as a snowflake
    value.as_u64().or_else(|| snowflake(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    const KEY: &[u8] = b"test-challenge-secret";
    const USER: &str = "01J9ZQ4V6X7B8C9D0E1F2G3H4J";
    const OTHER_USER: &str = "01J9ZQ4V6X7B8C9D0E1F2G3H4K";

    fn day(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    fn at(y: i32, m: u32, d: u32, h: u32, min: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, min, s).unwrap()
    }

    #[test]
    fn known_answer_vector() {
        // Computed independently with Python's hmac + base64.b32encode; a
        // change to the message format or encoding breaks every issued code
        assert_eq!(
            code(KEY, "stoat", USER, day(2026, 10, 15)),
            "sloga-import-AKY7V2QD"
        );
        assert_eq!(
            code(KEY, "fluxer", USER, day(2026, 10, 15)),
            "sloga-import-Y7G2E4X2"
        );
    }

    #[test]
    fn deterministic() {
        let d = day(2026, 10, 15);
        assert_eq!(code(KEY, "stoat", USER, d), code(KEY, "stoat", USER, d));
    }

    #[test]
    fn length_and_alphabet() {
        let c = code(KEY, "matrix", USER, day(2026, 1, 2));
        assert_eq!(c.len(), CODE_PREFIX.len() + 8);
        let suffix = c
            .strip_prefix(CODE_PREFIX)
            .expect("code carries the prefix");
        assert!(suffix
            .bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)));
    }

    #[test]
    fn differs_per_user_source_day_and_key() {
        let d = day(2026, 10, 15);
        let base = code(KEY, "stoat", USER, d);
        assert_ne!(base, code(KEY, "stoat", OTHER_USER, d));
        assert_ne!(base, code(KEY, "fluxer", USER, d));
        assert_ne!(base, code(KEY, "stoat", USER, day(2026, 10, 16)));
        assert_ne!(base, code(b"another-secret", "stoat", USER, d));
    }

    #[test]
    fn accepted_codes_today_and_yesterday_across_midnight() {
        let just_before = at(2026, 10, 15, 23, 59, 59);
        let just_after = at(2026, 10, 16, 0, 0, 1);

        assert_eq!(
            accepted_codes(KEY, "stoat", USER, just_before),
            [
                code(KEY, "stoat", USER, day(2026, 10, 15)),
                code(KEY, "stoat", USER, day(2026, 10, 14)),
            ]
        );

        // A code shown at 23:59:59 still verifies two seconds later
        let shown = code(KEY, "stoat", USER, just_before.date_naive());
        assert_eq!(
            accepted_codes(KEY, "stoat", USER, just_after),
            [code(KEY, "stoat", USER, day(2026, 10, 16)), shown]
        );
    }

    #[test]
    fn day_before_yesterday_rejected() {
        let now = at(2026, 10, 16, 12, 0, 0);
        let stale = code(KEY, "stoat", USER, day(2026, 10, 14));
        assert!(!accepted_codes(KEY, "stoat", USER, now).contains(&stale));
        assert_eq!(
            find_accepted_code(&format!("code: {stale}"), KEY, "stoat", USER, now),
            None
        );
    }

    #[test]
    fn finds_code_embedded_in_surrounding_text() {
        let now = at(2026, 10, 15, 8, 30, 0);
        let today = code(KEY, "stoat", USER, day(2026, 10, 15));
        let yesterday = code(KEY, "stoat", USER, day(2026, 10, 14));

        let description = format!("Welcome to the server!\n\nVerify: {today}.\nRules below");
        assert_eq!(
            find_accepted_code(&description, KEY, "stoat", USER, now),
            Some(today.clone())
        );

        // At the very end of the text, with nothing after it
        assert_eq!(
            find_accepted_code(&format!("about us\n{yesterday}"), KEY, "stoat", USER, now),
            Some(yesterday)
        );

        // Bare code
        assert_eq!(
            find_accepted_code(&today, KEY, "stoat", USER, now),
            Some(today.clone())
        );
    }

    #[test]
    fn rejects_longer_token() {
        let now = at(2026, 10, 15, 8, 30, 0);
        let today = code(KEY, "stoat", USER, day(2026, 10, 15));

        for haystack in [
            format!("{today}X"),
            format!("{today}2"),
            format!("{today}é"),
        ] {
            assert_eq!(
                find_accepted_code(&haystack, KEY, "stoat", USER, now),
                None,
                "{haystack}"
            );
        }

        // A longer token earlier does not hide a valid occurrence later
        assert_eq!(
            find_accepted_code(&format!("{today}X then {today}"), KEY, "stoat", USER, now),
            Some(today)
        );
    }

    #[test]
    fn rejects_lowercased_code() {
        let now = at(2026, 10, 15, 8, 30, 0);
        let today = code(KEY, "stoat", USER, day(2026, 10, 15));
        assert_eq!(
            find_accepted_code(&today.to_lowercase(), KEY, "stoat", USER, now),
            None
        );
    }

    #[test]
    fn rejects_other_users_code() {
        let now = at(2026, 10, 15, 8, 30, 0);
        let theirs = code(KEY, "stoat", OTHER_USER, day(2026, 10, 15));
        assert_eq!(
            find_accepted_code(&format!("verify {theirs}"), KEY, "stoat", USER, now),
            None
        );
    }

    #[test]
    fn rejects_other_source_tags_code() {
        let now = at(2026, 10, 15, 8, 30, 0);
        let matrix = code(KEY, "matrix", USER, day(2026, 10, 15));
        assert_eq!(
            find_accepted_code(&format!("verify {matrix}"), KEY, "stoat", USER, now),
            None
        );
    }

    // ---- Fluxer role proof ----

    const MANAGE_ROLES: u64 = 1 << 28;
    const VIEW_AUDIT_LOG: u64 = 1 << 7;
    const KICK_MEMBERS: u64 = 1 << 1;

    /// What Fluxer gives a new role: nothing privileged
    const DEFAULTS: u64 = (1 << 10) | (1 << 11);

    const OWNER: u64 = 1_300_000_000_000_000_001;
    const ADMIN: u64 = 1_300_000_000_000_000_002;
    const MODERATOR: u64 = 1_300_000_000_000_000_003;
    const MEMBER: u64 = 1_300_000_000_000_000_004;

    /// A snowflake minted at `time`, with `low` in the worker/sequence bits
    fn snowflake_at(time: DateTime<Utc>, low: u64) -> u64 {
        assert!(low < 1 << 22);
        let ms = time.timestamp_millis() as u64 - FLUXER_EPOCH_MS;
        (ms << 22) | low
    }

    /// Verification at 12:00 UTC on 2026-10-15
    fn now() -> DateTime<Utc> {
        at(2026, 10, 15, 12, 0, 0)
    }

    fn candidates() -> [(String, NaiveDate); 2] {
        accepted_codes_with_days(KEY, "fluxer", USER, now())
    }

    fn today_code() -> String {
        code(KEY, "fluxer", USER, day(2026, 10, 15))
    }

    fn yesterday_code() -> String {
        code(KEY, "fluxer", USER, day(2026, 10, 14))
    }

    /// Guild created in 2021; its id is also the `@everyone` role id
    fn guild_id() -> u64 {
        snowflake_at(at(2021, 3, 4, 5, 6, 7), 11)
    }

    /// The role the bot's install created this morning
    fn bot_role_id() -> u64 {
        snowflake_at(at(2026, 10, 15, 9, 0, 0), 1)
    }

    /// A role created at 10:30 today
    fn fresh_role_id() -> u64 {
        snowflake_at(at(2026, 10, 15, 10, 30, 0), 7)
    }

    /// An audit entry id minted `minutes` past 10:00 today
    fn entry_id(minutes: u32) -> u64 {
        snowflake_at(
            at(2026, 10, 15, 10, 0, 0) + chrono::Duration::minutes(minutes as i64),
            99,
        )
    }

    /// ROLE_CREATE by `user` at 10:`minutes`
    fn created(minutes: u32, role_id: u64, user: u64, name: &str, bits: u64) -> RoleAuditEvent {
        RoleAuditEvent {
            entry_id: entry_id(minutes),
            role_id,
            user_id: Some(user),
            created: true,
            name: NameChange::To(Some(name.to_string())),
            permissions: PermChange::Changed { old: 0, new: bits },
        }
    }

    /// ROLE_UPDATE of the name only
    fn renamed(minutes: u32, role_id: u64, user: u64, name: &str) -> RoleAuditEvent {
        RoleAuditEvent {
            entry_id: entry_id(minutes),
            role_id,
            user_id: Some(user),
            created: false,
            name: NameChange::To(Some(name.to_string())),
            permissions: PermChange::Unchanged,
        }
    }

    /// ROLE_UPDATE of the permissions only
    fn regranted(minutes: u32, role_id: u64, user: u64, old: u64, new: u64) -> RoleAuditEvent {
        RoleAuditEvent {
            entry_id: entry_id(minutes),
            role_id,
            user_id: Some(user),
            created: false,
            name: NameChange::Unchanged,
            permissions: PermChange::Changed { old, new },
        }
    }

    fn prove(
        roles: &[ProofRole<'_>],
        guild: u64,
        audit: &[RoleAuditEvent],
    ) -> Option<(String, u64)> {
        fluxer_role_proof(roles, guild, &[bot_role_id()], audit, &candidates())
    }

    /// The bot's own install role, present in every guild it was added to
    fn bot_role() -> ProofRole<'static> {
        ProofRole {
            id: bot_role_id(),
            name: "Sloga Importer",
            permissions: ADMINISTRATOR,
        }
    }

    /// The code role as it stands now
    fn code_role(id: u64, code: &str, permissions: u64) -> ProofRole<'_> {
        ProofRole {
            id,
            name: code,
            permissions,
        }
    }

    #[test]
    fn web_flow_create_rename_then_grant_passes() {
        // Fluxer's web app creates "new role", then the user renames it and
        // ticks Manage Server
        let code = today_code();
        let id = fresh_role_id();
        let roles = [bot_role(), code_role(id, &code, DEFAULTS | MANAGE_GUILD)];
        let mut audit = vec![
            created(0, bot_role_id(), OWNER, "Sloga Importer", ADMINISTRATOR),
            created(30, id, MEMBER, "new role", DEFAULTS),
            renamed(31, id, MEMBER, &code),
            regranted(32, id, MEMBER, DEFAULTS, DEFAULTS | MANAGE_GUILD),
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), Some((code.clone(), id)));

        // Order on input does not matter: entries are ordered by id
        audit.reverse();
        assert_eq!(prove(&roles, guild_id(), &audit), Some((code.clone(), id)));
    }

    #[test]
    fn grant_before_rename_by_the_same_user_passes() {
        let code = today_code();
        let id = fresh_role_id();
        let roles = [code_role(id, &code, DEFAULTS | MANAGE_GUILD)];
        let audit = [
            created(30, id, MEMBER, "new role", DEFAULTS),
            regranted(31, id, MEMBER, DEFAULTS, DEFAULTS | MANAGE_GUILD),
            renamed(32, id, MEMBER, &code),
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), Some((code.clone(), id)));
    }

    #[test]
    fn grant_in_the_same_entry_as_the_rename_passes() {
        let code = today_code();
        let id = fresh_role_id();
        let roles = [code_role(id, &code, ADMINISTRATOR)];
        let audit = [
            created(30, id, MEMBER, "new role", DEFAULTS),
            RoleAuditEvent {
                entry_id: entry_id(31),
                role_id: id,
                user_id: Some(MEMBER),
                created: false,
                name: NameChange::To(Some(code.clone())),
                permissions: PermChange::Changed {
                    old: DEFAULTS,
                    new: ADMINISTRATOR,
                },
            },
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), Some((code.clone(), id)));
    }

    #[test]
    fn owner_creates_the_code_role_with_its_bits_passes() {
        let code = today_code();
        let id = fresh_role_id();
        for bits in [ADMINISTRATOR, MANAGE_GUILD | KICK_MEMBERS] {
            let roles = [bot_role(), code_role(id, &code, bits)];
            let audit = [
                created(0, bot_role_id(), OWNER, "Sloga Importer", ADMINISTRATOR),
                created(30, id, OWNER, &code, bits),
            ];
            assert_eq!(
                prove(&roles, guild_id(), &audit),
                Some((code.clone(), id)),
                "{bits:#x}"
            );
        }
    }

    #[test]
    fn yesterdays_code_with_role_created_yesterday_passes() {
        let code = yesterday_code();
        let id = snowflake_at(at(2026, 10, 14, 23, 50, 0), 3);
        let roles = [code_role(id, &code, MANAGE_GUILD)];
        let audit = [created(0, id, OWNER, &code, MANAGE_GUILD)];
        assert_eq!(prove(&roles, guild_id(), &audit), Some((code.clone(), id)));
    }

    #[test]
    fn role_created_exactly_at_midnight_of_codes_day_passes() {
        let code = today_code();
        let id = day_start_snowflake(day(2026, 10, 15));
        let roles = [code_role(id, &code, MANAGE_GUILD)];
        let audit = [created(0, id, OWNER, &code, MANAGE_GUILD)];
        assert_eq!(prove(&roles, guild_id(), &audit), Some((code.clone(), id)));
    }

    #[test]
    fn skips_failing_roles_and_returns_the_proving_one() {
        let code = today_code();
        let bare = snowflake_at(at(2026, 10, 15, 10, 0, 0), 2);
        let id = fresh_role_id();
        let roles = [
            // Same name, no permission bits: skipped, not a hard stop
            code_role(bare, &code, KICK_MEMBERS),
            code_role(id, &code, MANAGE_GUILD),
        ];
        let audit = [
            created(1, bare, OWNER, &code, KICK_MEMBERS),
            created(30, id, OWNER, &code, MANAGE_GUILD),
            // A rename of some other role does not count against this one
            renamed(40, bot_role_id(), MODERATOR, "x"),
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), Some((code.clone(), id)));
    }

    #[test]
    fn code_role_without_permission_bits_fails() {
        let code = today_code();
        let id = fresh_role_id();
        let audit = [created(30, id, OWNER, &code, ADMINISTRATOR)];
        for permissions in [
            0,
            KICK_MEMBERS,
            MANAGE_ROLES | VIEW_AUDIT_LOG | KICK_MEMBERS,
        ] {
            let roles = [code_role(id, &code, permissions)];
            assert_eq!(prove(&roles, guild_id(), &audit), None, "{permissions:#x}");
        }
    }

    #[test]
    fn bot_held_role_fails() {
        // The bot's install role renamed to the code by the admin who
        // installed it: still refused, the bot holds it
        let code = today_code();
        let roles = [code_role(bot_role_id(), &code, ADMINISTRATOR)];
        let audit = [
            created(0, bot_role_id(), ADMIN, "Sloga Importer", ADMINISTRATOR),
            renamed(1, bot_role_id(), ADMIN, &code),
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), None);
    }

    #[test]
    fn everyone_role_fails() {
        // A guild created today, so `@everyone` is fresh and the day check
        // alone would let it through
        let code = today_code();
        let guild = snowflake_at(at(2026, 10, 15, 8, 0, 0), 5);
        let roles = [code_role(guild, &code, ADMINISTRATOR)];
        let audit = [created(0, guild, OWNER, &code, ADMINISTRATOR)];
        assert_eq!(prove(&roles, guild, &audit), None);
    }

    #[test]
    fn role_created_before_the_codes_day_fails() {
        // Today's code on a role from the last instant before today's midnight
        let today = today_code();
        let late_yesterday = day_start_snowflake(day(2026, 10, 15)) - 1;
        let roles = [code_role(late_yesterday, &today, MANAGE_GUILD)];
        let audit = [created(0, late_yesterday, OWNER, &today, MANAGE_GUILD)];
        assert_eq!(prove(&roles, guild_id(), &audit), None);

        // Yesterday's code on a role from the day before yesterday
        let yesterday = yesterday_code();
        let two_days_ago = snowflake_at(at(2026, 10, 13, 23, 59, 59), 9);
        let roles = [code_role(two_days_ago, &yesterday, MANAGE_GUILD)];
        let audit = [created(0, two_days_ago, OWNER, &yesterday, MANAGE_GUILD)];
        assert_eq!(prove(&roles, guild_id(), &audit), None);
    }

    #[test]
    fn bot_install_role_renamed_by_a_moderator_fails() {
        // An earlier install of the importer (or any other bot) left an
        // Administrator role behind; a Manage Roles moderator renames it
        let code = today_code();
        let orphan = snowflake_at(at(2026, 10, 15, 10, 35, 0), 4);
        let roles = [bot_role(), code_role(orphan, &code, ADMINISTRATOR)];
        let audit = [
            created(0, bot_role_id(), ADMIN, "Sloga Importer", ADMINISTRATOR),
            created(35, orphan, ADMIN, "Sloga Importer", ADMINISTRATOR),
            renamed(40, orphan, MODERATOR, &code),
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), None);
    }

    #[test]
    fn admin_role_renamed_by_a_moderator_fails() {
        let code = today_code();
        let id = fresh_role_id();
        let roles = [code_role(id, &code, MANAGE_GUILD | KICK_MEMBERS)];
        let audit = [
            created(30, id, ADMIN, "Moderators", MANAGE_GUILD | KICK_MEMBERS),
            renamed(40, id, MODERATOR, &code),
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), None);

        // Granted later in a separate entry, still before the rename
        let audit = [
            created(30, id, ADMIN, "new role", DEFAULTS),
            regranted(31, id, ADMIN, DEFAULTS, MANAGE_GUILD | KICK_MEMBERS),
            renamed(40, id, MODERATOR, &code),
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), None);
    }

    #[test]
    fn permission_edit_after_rename_that_adds_no_privilege_fails() {
        // An admin later edits the renamed role's other bits; Manage Server
        // was already there, so nothing privileged was granted under the code
        let code = today_code();
        let id = fresh_role_id();
        let roles = [code_role(id, &code, MANAGE_GUILD | KICK_MEMBERS)];
        let audit = [
            created(30, id, ADMIN, "Moderators", MANAGE_GUILD),
            renamed(40, id, MODERATOR, &code),
            regranted(45, id, ADMIN, MANAGE_GUILD, MANAGE_GUILD | KICK_MEMBERS),
            // Removing a bit adds nothing either
            regranted(46, id, ADMIN, MANAGE_GUILD | KICK_MEMBERS, MANAGE_GUILD),
            regranted(47, id, ADMIN, MANAGE_GUILD, MANAGE_GUILD | KICK_MEMBERS),
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), None);
    }

    #[test]
    fn renamed_away_and_back_by_a_moderator_after_the_grant_fails() {
        let code = today_code();
        let id = fresh_role_id();
        let roles = [code_role(id, &code, DEFAULTS | MANAGE_GUILD)];

        // The admin made a real code role; a moderator renames it away and
        // back
        let audit = [
            created(30, id, ADMIN, &code, DEFAULTS),
            regranted(31, id, ADMIN, DEFAULTS, DEFAULTS | MANAGE_GUILD),
            renamed(32, id, MODERATOR, "Helpers"),
            renamed(33, id, MODERATOR, &code),
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), None);

        // Granted while it carried another name, renamed in and out and in
        let audit = [
            created(30, id, ADMIN, "new role", DEFAULTS),
            regranted(31, id, ADMIN, DEFAULTS, DEFAULTS | MANAGE_GUILD),
            renamed(32, id, MODERATOR, &code),
            renamed(33, id, MODERATOR, "Helpers"),
            renamed(34, id, MODERATOR, &code),
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), None);
    }

    #[test]
    fn admin_grant_after_a_moderators_rename_passes() {
        // Accepted: the grant came from someone able to manage the server,
        // made to a role already carrying the code
        let code = today_code();
        let id = fresh_role_id();
        let roles = [code_role(id, &code, DEFAULTS | MANAGE_GUILD)];
        let audit = [
            created(30, id, MODERATOR, "new role", DEFAULTS),
            renamed(31, id, MODERATOR, &code),
            regranted(32, id, ADMIN, DEFAULTS, DEFAULTS | MANAGE_GUILD),
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), Some((code.clone(), id)));
    }

    #[test]
    fn no_created_event_fails() {
        let code = today_code();
        let id = fresh_role_id();
        let roles = [code_role(id, &code, MANAGE_GUILD)];
        assert_eq!(prove(&roles, guild_id(), &[]), None);

        // Rename and grant by one user, but the creation is not in the log
        let audit = [
            renamed(31, id, MEMBER, &code),
            regranted(32, id, MEMBER, DEFAULTS, MANAGE_GUILD),
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), None);

        // A creation record for some other role does not stand in for it
        let audit = [created(30, id + 1, OWNER, &code, MANAGE_GUILD)];
        assert_eq!(prove(&roles, guild_id(), &audit), None);
    }

    #[test]
    fn last_name_not_the_code_fails() {
        let code = today_code();
        let id = fresh_role_id();
        let roles = [code_role(id, &code, MANAGE_GUILD)];

        // The log's last name for it is something else
        let audit = [
            created(30, id, OWNER, &code, MANAGE_GUILD),
            renamed(31, id, OWNER, "Admins"),
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), None);

        // A name change whose new value could not be read
        let audit = [
            created(30, id, OWNER, &code, MANAGE_GUILD),
            RoleAuditEvent {
                name: NameChange::To(None),
                ..renamed(31, id, OWNER, "")
            },
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), None);

        // Created under a near miss, or yesterday's code, and never renamed
        let lower = code.to_lowercase();
        let spaced = format!("{code} ");
        let yesterday = yesterday_code();
        for name in [
            lower.as_str(),
            spaced.as_str(),
            "new role",
            yesterday.as_str(),
        ] {
            let audit = [created(30, id, OWNER, name, MANAGE_GUILD)];
            assert_eq!(prove(&roles, guild_id(), &audit), None, "{name:?}");
        }
        let audit = [RoleAuditEvent {
            name: NameChange::To(None),
            ..created(30, id, OWNER, "", MANAGE_GUILD)
        }];
        assert_eq!(prove(&roles, guild_id(), &audit), None);
    }

    #[test]
    fn no_privilege_added_fails() {
        let code = today_code();
        let id = fresh_role_id();
        let roles = [code_role(id, &code, DEFAULTS | MANAGE_GUILD)];

        // The grant is not in the log at all
        let audit = [created(30, id, MEMBER, &code, DEFAULTS)];
        assert_eq!(prove(&roles, guild_id(), &audit), None);

        // Only unprivileged bits were ever added
        let audit = [
            created(30, id, MEMBER, &code, DEFAULTS),
            regranted(31, id, MEMBER, DEFAULTS, DEFAULTS | KICK_MEMBERS),
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), None);

        // A re-save that keeps Manage Server adds nothing
        let audit = [
            created(30, id, MEMBER, &code, DEFAULTS),
            regranted(31, id, MEMBER, MANAGE_GUILD, MANAGE_GUILD),
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), None);
    }

    #[test]
    fn unknown_users_only_count_by_entry_order() {
        let code = today_code();
        let id = fresh_role_id();
        let roles = [code_role(id, &code, DEFAULTS | MANAGE_GUILD)];
        let anonymous = |mut event: RoleAuditEvent| {
            event.user_id = None;
            event
        };

        // Grant before the rename, neither naming a user: not the same user
        let audit = [
            anonymous(created(30, id, MEMBER, "new role", DEFAULTS)),
            anonymous(regranted(31, id, MEMBER, DEFAULTS, DEFAULTS | MANAGE_GUILD)),
            anonymous(renamed(32, id, MEMBER, &code)),
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), None);

        // Grant after the rename needs no user
        let audit = [
            anonymous(created(30, id, MEMBER, "new role", DEFAULTS)),
            anonymous(renamed(31, id, MEMBER, &code)),
            anonymous(regranted(32, id, MEMBER, DEFAULTS, DEFAULTS | MANAGE_GUILD)),
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), Some((code.clone(), id)));
    }

    #[test]
    fn other_source_tags_code_fails() {
        let id = fresh_role_id();
        for tag in ["stoat", "matrix", "discord"] {
            let theirs = code(KEY, tag, USER, day(2026, 10, 15));
            let roles = [code_role(id, &theirs, MANAGE_GUILD)];
            let audit = [created(30, id, OWNER, &theirs, MANAGE_GUILD)];
            assert_eq!(prove(&roles, guild_id(), &audit), None, "{tag}");
        }
    }

    #[test]
    fn other_users_code_fails() {
        let theirs = code(KEY, "fluxer", OTHER_USER, day(2026, 10, 15));
        let id = fresh_role_id();
        let roles = [code_role(id, &theirs, MANAGE_GUILD)];
        let audit = [created(30, id, OWNER, &theirs, MANAGE_GUILD)];
        assert_eq!(prove(&roles, guild_id(), &audit), None);
    }

    #[test]
    fn name_containing_but_not_equal_to_code_fails() {
        let code = today_code();
        let id = fresh_role_id();
        for name in [
            format!("x{code}"),
            format!("{code} "),
            format!(" {code}"),
            format!("{code}X"),
            format!("verify {code}"),
            code.to_lowercase(),
            code[..code.len() - 1].to_string(),
        ] {
            // The audit trail agrees with the role name, so only the exact
            // name comparison can refuse it
            let roles = [code_role(id, &name, MANAGE_GUILD)];
            let audit = [created(30, id, OWNER, &name, MANAGE_GUILD)];
            assert_eq!(prove(&roles, guild_id(), &audit), None, "{name:?}");
        }
    }

    #[test]
    fn no_candidates_fails() {
        let code = today_code();
        let id = fresh_role_id();
        let roles = [code_role(id, &code, MANAGE_GUILD)];
        let audit = [created(30, id, OWNER, &code, MANAGE_GUILD)];
        assert_eq!(
            fluxer_role_proof(&roles, guild_id(), &[], &audit, &[]),
            None
        );
    }

    #[test]
    fn accepted_codes_with_days_matches_accepted_codes() {
        for now in [
            now(),
            at(2026, 10, 15, 23, 59, 59),
            at(2026, 10, 16, 0, 0, 0),
            at(2024, 3, 1, 0, 0, 1),
        ] {
            let [(today, today_day), (yesterday, yesterday_day)] =
                accepted_codes_with_days(KEY, "fluxer", USER, now);
            assert_eq!(
                [today.clone(), yesterday.clone()],
                accepted_codes(KEY, "fluxer", USER, now)
            );
            assert_eq!(today_day, now.date_naive());
            assert_eq!(Some(yesterday_day), now.date_naive().pred_opt());
            assert_eq!(today, code(KEY, "fluxer", USER, today_day));
            assert_eq!(yesterday, code(KEY, "fluxer", USER, yesterday_day));
        }
    }

    #[test]
    fn code_day_finds_the_last_three_days_only() {
        let created = at(2026, 10, 15, 0, 5, 0);
        for back in 0..=2u64 {
            let d = day(2026, 10, 15) - chrono::Days::new(back);
            let c = code(KEY, "fluxer", USER, d);
            assert_eq!(
                code_day(KEY, "fluxer", USER, &c, created),
                Some(d),
                "-{back}"
            );
        }

        let stale = code(KEY, "fluxer", USER, day(2026, 10, 12));
        assert_eq!(code_day(KEY, "fluxer", USER, &stale, created), None);

        // Another source's, another user's, or a future code
        let stoat = code(KEY, "stoat", USER, day(2026, 10, 15));
        assert_eq!(code_day(KEY, "fluxer", USER, &stoat, created), None);
        let theirs = code(KEY, "fluxer", OTHER_USER, day(2026, 10, 15));
        assert_eq!(code_day(KEY, "fluxer", USER, &theirs, created), None);
        let tomorrow = code(KEY, "fluxer", USER, day(2026, 10, 16));
        assert_eq!(code_day(KEY, "fluxer", USER, &tomorrow, created), None);
        assert_eq!(code_day(KEY, "fluxer", USER, "", created), None);
    }

    #[test]
    fn snowflake_time_known_answer() {
        // Discord's documented example; Fluxer uses the same epoch and layout
        assert_eq!(
            snowflake_time(175928847299117063),
            Utc.timestamp_millis_opt(1462015105796).unwrap()
        );
        assert_eq!(
            snowflake_time(0),
            Utc.timestamp_millis_opt(FLUXER_EPOCH_MS as i64).unwrap()
        );
    }

    #[test]
    fn day_start_snowflake_round_trips_to_midnight() {
        for d in [day(2015, 1, 2), day(2024, 2, 29), day(2026, 10, 15)] {
            let midnight = d.and_hms_opt(0, 0, 0).unwrap().and_utc();
            let start = day_start_snowflake(d);

            assert_eq!(snowflake_time(start), midnight);
            // Smallest at that millisecond: no worker/sequence bits set
            assert_eq!(start & ((1 << 22) - 1), 0);

            // One below, and a full millisecond earlier, are the previous day
            for earlier in [start - 1, start - (1 << 22)] {
                let t = snowflake_time(earlier);
                assert_eq!(t, midnight - chrono::Duration::milliseconds(1));
                assert_eq!(t.date_naive(), d.pred_opt().unwrap());
            }
        }

        // Saturates instead of wrapping
        assert_eq!(day_start_snowflake(day(2015, 1, 1)), 0);
        assert_eq!(day_start_snowflake(day(2010, 6, 1)), 0);
        assert_eq!(day_start_snowflake(day(2200, 1, 1)), u64::MAX);
    }

    // ---- Fluxer audit-log pages ----

    use serde_json::json;

    /// A ROLE_CREATE entry as Fluxer writes it (`computeChanges(null, role)`)
    fn create_entry(id: u64, role_id: u64, user: u64, name: &str, bits: u64) -> Value {
        json!({
            "id": id.to_string(),
            "action_type": 30,
            "user_id": user.to_string(),
            "target_id": role_id.to_string(),
            "changes": [
                { "key": "role_id", "new_value": role_id.to_string() },
                { "key": "name", "new_value": name },
                { "key": "permissions", "new_value": bits.to_string() },
                { "key": "position", "new_value": 1 },
                { "key": "hoist_position", "new_value": null },
                { "key": "color", "new_value": 0 },
                { "key": "icon_hash", "new_value": null },
                { "key": "unicode_emoji", "new_value": null },
                { "key": "hoist", "new_value": false },
                { "key": "mentionable", "new_value": false },
            ],
        })
    }

    /// A ROLE_UPDATE entry; `changes: None` leaves the field out
    fn update_entry(id: u64, role_id: u64, user: u64, changes: Option<Value>) -> Value {
        let mut entry = json!({
            "id": id.to_string(),
            "action_type": 31,
            "user_id": user.to_string(),
            "target_id": role_id.to_string(),
            "options": { "role_name": "whatever" },
        });
        if let Some(changes) = changes {
            entry["changes"] = changes;
        }
        entry
    }

    fn page(entries: Vec<Value>) -> Value {
        json!({ "audit_log_entries": entries, "users": [], "webhooks": [] })
    }

    fn parse(body: &Value, action_type: u8) -> Result<FluxerAuditPage, AuditParseError> {
        parse_fluxer_role_audit_page(body, action_type)
    }

    /// The single event parsed from a one-entry page
    fn parse_one(entry: Value) -> Result<RoleAuditEvent, AuditParseError> {
        let action = entry["action_type"].as_u64().unwrap_or(0) as u8;
        let parsed = parse(&page(vec![entry]), action)?;
        assert_eq!(parsed.count, 1);
        assert_eq!(parsed.entries.len(), 1);
        Ok(parsed.entries.into_iter().next().unwrap())
    }

    fn color_change() -> Value {
        json!([{ "key": "color", "old_value": 0, "new_value": 16711680 }])
    }

    fn malformed(entry: Value) {
        let action = entry["action_type"].as_u64().unwrap_or(0) as u8;
        for action in [action, FLUXER_AUDIT_ROLE_CREATE, FLUXER_AUDIT_ROLE_UPDATE] {
            assert_eq!(
                parse(&page(vec![entry.clone()]), action),
                Err(AuditParseError::Malformed),
                "{entry} as {action}"
            );
        }
    }

    #[test]
    fn create_page_parses() {
        let code = today_code();
        let body = page(vec![
            create_entry(entry_id(31), fresh_role_id(), OWNER, &code, MANAGE_GUILD),
            create_entry(
                entry_id(0),
                bot_role_id(),
                ADMIN,
                "Sloga Importer",
                ADMINISTRATOR,
            ),
        ]);
        assert_eq!(
            parse(&body, FLUXER_AUDIT_ROLE_CREATE),
            Ok(FluxerAuditPage {
                entries: vec![
                    RoleAuditEvent {
                        entry_id: entry_id(31),
                        role_id: fresh_role_id(),
                        user_id: Some(OWNER),
                        created: true,
                        name: NameChange::To(Some(code.clone())),
                        permissions: PermChange::Changed {
                            old: 0,
                            new: MANAGE_GUILD
                        },
                    },
                    RoleAuditEvent {
                        entry_id: entry_id(0),
                        role_id: bot_role_id(),
                        user_id: Some(ADMIN),
                        created: true,
                        name: NameChange::To(Some("Sloga Importer".to_string())),
                        permissions: PermChange::Changed {
                            old: 0,
                            new: ADMINISTRATOR
                        },
                    },
                ],
                count: 2,
                next_after: None,
            })
        );

        let empty = parse(&page(vec![]), FLUXER_AUDIT_ROLE_CREATE).unwrap();
        assert_eq!(empty.entries, vec![]);
        assert_eq!(empty.count, 0);
        assert!(!empty.is_full());
    }

    #[test]
    fn create_without_a_string_name_is_unnamed() {
        let id = fresh_role_id();
        let base = create_entry(entry_id(1), id, OWNER, "x", 0);

        let mut no_name = base.clone();
        no_name["changes"]
            .as_array_mut()
            .unwrap()
            .retain(|change| change["key"] != "name");
        assert_eq!(parse_one(no_name).unwrap().name, NameChange::To(None));

        for value in [json!(null), json!(5), json!(["a"]), json!({ "a": 1 })] {
            let mut entry = base.clone();
            entry["changes"][1]["new_value"] = value.clone();
            assert_eq!(
                parse_one(entry).unwrap().name,
                NameChange::To(None),
                "{value}"
            );
        }

        let mut no_value = base;
        no_value["changes"][1] = json!({ "key": "name", "old_value": "x" });
        assert_eq!(parse_one(no_value).unwrap().name, NameChange::To(None));
    }

    #[test]
    fn create_permissions() {
        let id = fresh_role_id();
        let base = create_entry(entry_id(1), id, OWNER, "x", ADMINISTRATOR);

        // A plain integer is read too
        let mut integer = base.clone();
        integer["changes"][2]["new_value"] = json!(ADMINISTRATOR);
        assert_eq!(
            parse_one(integer).unwrap().permissions,
            PermChange::Changed {
                old: 0,
                new: ADMINISTRATOR
            }
        );

        // No permissions field: unchanged, so it grants nothing
        let mut absent = base.clone();
        absent["changes"]
            .as_array_mut()
            .unwrap()
            .retain(|change| change["key"] != "permissions");
        assert_eq!(
            parse_one(absent).unwrap().permissions,
            PermChange::Unchanged
        );

        for value in [
            json!(null),
            json!("abc"),
            json!("-8"),
            json!(-8),
            json!(8.5),
            json!("1e3"),
            json!("123456789012345678901"),
            json!({ "added": ["ADMINISTRATOR"], "removed": [] }),
        ] {
            let mut entry = base.clone();
            entry["changes"][2]["new_value"] = value;
            malformed(entry);
        }
        let mut no_value = base;
        no_value["changes"][2] = json!({ "key": "permissions" });
        malformed(no_value);
    }

    #[test]
    fn update_with_a_name_change() {
        let id = fresh_role_id();
        let event = parse_one(update_entry(
            entry_id(2),
            id,
            MODERATOR,
            Some(json!([
                { "key": "color", "old_value": 0, "new_value": 1 },
                { "key": "name", "old_value": "Event Staff", "new_value": today_code() },
            ])),
        ))
        .unwrap();
        assert_eq!(
            event,
            RoleAuditEvent {
                entry_id: entry_id(2),
                role_id: id,
                user_id: Some(MODERATOR),
                created: false,
                name: NameChange::To(Some(today_code())),
                permissions: PermChange::Unchanged,
            }
        );

        // Set to something that is not a string
        let event = parse_one(update_entry(
            entry_id(2),
            id,
            MODERATOR,
            Some(json!([{ "key": "name", "old_value": "a", "new_value": null }])),
        ))
        .unwrap();
        assert_eq!(event.name, NameChange::To(None));
    }

    #[test]
    fn update_with_a_permission_change() {
        let id = fresh_role_id();
        let event = parse_one(update_entry(
            entry_id(2),
            id,
            ADMIN,
            Some(json!([
                { "key": "permissions", "old_value": "3072", "new_value": "3104" },
                { "key": "permissions_diff", "new_value": { "added": ["MANAGE_GUILD"], "removed": [] } },
            ])),
        ))
        .unwrap();
        assert_eq!(event.name, NameChange::Unchanged);
        assert_eq!(
            event.permissions,
            PermChange::Changed {
                old: DEFAULTS,
                new: DEFAULTS | MANAGE_GUILD
            }
        );

        let event = parse_one(update_entry(
            entry_id(2),
            id,
            ADMIN,
            Some(json!([{ "key": "permissions", "old_value": 0, "new_value": 8 }])),
        ))
        .unwrap();
        assert_eq!(
            event.permissions,
            PermChange::Changed {
                old: 0,
                new: ADMINISTRATOR
            }
        );
    }

    #[test]
    fn update_of_other_fields_is_kept_with_nothing_changed() {
        let id = fresh_role_id();
        for changes in [
            color_change(),
            json!([{ "key": "position", "old_value": 3, "new_value": 1 }]),
            json!([{ "key": "permissions_diff", "new_value": { "added": [], "removed": [] } }]),
            json!([]),
        ] {
            let event =
                parse_one(update_entry(entry_id(2), id, ADMIN, Some(changes.clone()))).unwrap();
            assert_eq!(event.name, NameChange::Unchanged, "{changes}");
            assert_eq!(event.permissions, PermChange::Unchanged, "{changes}");
            assert!(!event.created);
        }
    }

    #[test]
    fn update_with_unreadable_permissions_is_malformed() {
        let id = fresh_role_id();
        for change in [
            json!({ "key": "permissions", "new_value": "32" }),
            json!({ "key": "permissions", "old_value": "0" }),
            json!({ "key": "permissions", "old_value": null, "new_value": "32" }),
            json!({ "key": "permissions", "old_value": "0", "new_value": "abc" }),
            json!({ "key": "permissions", "old_value": "-1", "new_value": "32" }),
            json!({ "key": "permissions", "old_value": 0, "new_value": -32 }),
            json!({ "key": "permissions", "old_value": 0, "new_value": 32.5 }),
            json!({ "key": "permissions", "old_value": "0", "new_value": "18446744073709551616" }),
            json!({ "key": "permissions", "old_value": "0", "new_value": { "added": [] } }),
        ] {
            malformed(update_entry(entry_id(2), id, ADMIN, Some(json!([change]))));
        }
    }

    #[test]
    fn unreadable_changes_are_malformed() {
        let id = fresh_role_id();
        let mut missing = create_entry(entry_id(3), id, OWNER, "x", 0);
        missing.as_object_mut().unwrap().remove("changes");
        malformed(missing);
        malformed(update_entry(entry_id(3), id, MODERATOR, None));

        for changes in [
            json!(null),
            json!("name"),
            json!(7),
            json!({ "key": "color" }),
            // An item that is not an object
            json!([1]),
            json!([null]),
            json!(["name"]),
            json!([{ "key": "color", "new_value": 1 }, "color"]),
            // An object without a string key
            json!([{ "old_value": "a", "new_value": "b" }]),
            json!([{ "key": null, "new_value": "b" }]),
            json!([{ "key": ["name"], "new_value": "b" }]),
            // A field listed twice
            json!([
                { "key": "name", "old_value": "a", "new_value": "b" },
                { "key": "name", "old_value": "b", "new_value": "a" },
            ]),
            json!([
                { "key": "permissions", "old_value": "0", "new_value": "8" },
                { "key": "permissions", "old_value": "8", "new_value": "0" },
            ]),
        ] {
            malformed(update_entry(
                entry_id(3),
                id,
                MODERATOR,
                Some(changes.clone()),
            ));
            let mut create = create_entry(entry_id(3), id, OWNER, "x", 0);
            create["changes"] = changes;
            malformed(create);
        }
    }

    #[test]
    fn user_id_kept_only_when_a_snowflake() {
        let id = fresh_role_id();
        let base = update_entry(entry_id(4), id, MODERATOR, Some(color_change()));
        for value in [
            json!(null),
            json!("abc"),
            json!(""),
            json!(MODERATOR),
            json!("-3"),
        ] {
            let mut entry = base.clone();
            entry["user_id"] = value.clone();
            assert_eq!(parse_one(entry).unwrap().user_id, None, "{value}");
        }
        let mut entry = base;
        entry.as_object_mut().unwrap().remove("user_id");
        assert_eq!(parse_one(entry).unwrap().user_id, None);
    }

    #[test]
    fn wrong_action_type_is_malformed() {
        let id = fresh_role_id();
        let create = create_entry(entry_id(4), id, OWNER, &today_code(), MANAGE_GUILD);
        let update = update_entry(entry_id(5), id, ADMIN, Some(color_change()));

        assert_eq!(
            parse(&page(vec![create.clone()]), FLUXER_AUDIT_ROLE_UPDATE),
            Err(AuditParseError::Malformed)
        );
        assert_eq!(
            parse(&page(vec![update.clone()]), FLUXER_AUDIT_ROLE_CREATE),
            Err(AuditParseError::Malformed)
        );
        // One stray entry spoils a page that is otherwise fine
        assert_eq!(
            parse(
                &page(vec![
                    update_entry(entry_id(6), id, ADMIN, Some(color_change())),
                    create
                ]),
                FLUXER_AUDIT_ROLE_UPDATE
            ),
            Err(AuditParseError::Malformed)
        );

        for action in [json!("31"), json!(31.5), json!(null), json!(32), json!(-31)] {
            let mut entry = update.clone();
            entry["action_type"] = action.clone();
            assert_eq!(
                parse(&page(vec![entry]), FLUXER_AUDIT_ROLE_UPDATE),
                Err(AuditParseError::Malformed),
                "{action}"
            );
        }
        let mut entry = update.clone();
        entry.as_object_mut().unwrap().remove("action_type");
        assert_eq!(
            parse(&page(vec![entry]), FLUXER_AUDIT_ROLE_UPDATE),
            Err(AuditParseError::Malformed)
        );

        // Asking to parse any other action type
        let mut delete = update;
        delete["action_type"] = json!(32);
        assert_eq!(
            parse(&page(vec![delete]), 32),
            Err(AuditParseError::Malformed)
        );
        assert_eq!(parse(&page(vec![]), 0), Err(AuditParseError::Malformed));
    }

    #[test]
    fn missing_target_id_is_malformed() {
        let id = fresh_role_id();
        for entry in [
            create_entry(entry_id(7), id, OWNER, &today_code(), MANAGE_GUILD),
            update_entry(entry_id(7), id, ADMIN, Some(color_change())),
        ] {
            let mut missing = entry.clone();
            missing.as_object_mut().unwrap().remove("target_id");
            malformed(missing);

            for target in [
                json!(null),
                json!(""),
                json!("role"),
                json!(id),
                json!(format!(" {id}")),
                json!("123456789012345678901"),
            ] {
                let mut bad = entry.clone();
                bad["target_id"] = target;
                malformed(bad);
            }
        }
    }

    #[test]
    fn non_numeric_id_is_malformed() {
        let update = update_entry(entry_id(8), fresh_role_id(), ADMIN, Some(color_change()));
        for id in [
            json!("abc"),
            json!(""),
            json!("+5"),
            json!("-1"),
            json!("1e5"),
            json!("12 "),
            // 21 digits, and one past u64::MAX
            json!("123456789012345678901"),
            json!("18446744073709551616"),
            // A JSON number, not Fluxer's decimal string
            json!(entry_id(8)),
            json!(null),
        ] {
            let mut entry = update.clone();
            entry["id"] = id;
            malformed(entry);
        }

        let mut entry = update.clone();
        entry.as_object_mut().unwrap().remove("id");
        malformed(entry);

        // The largest snowflake still parses
        let mut entry = update;
        entry["id"] = json!(u64::MAX.to_string());
        assert_eq!(parse_one(entry).unwrap().entry_id, u64::MAX);
    }

    #[test]
    fn page_without_an_entry_list_is_malformed() {
        let update = update_entry(entry_id(9), fresh_role_id(), ADMIN, Some(color_change()));
        for body in [
            json!({}),
            json!({ "users": [], "webhooks": [] }),
            json!({ "audit_log_entries": null }),
            json!({ "audit_log_entries": {} }),
            json!({ "audit_log_entries": "[]" }),
            json!({ "entries": [update.clone()] }),
            json!([update.clone()]),
            json!(null),
            json!("audit_log_entries"),
            // An entry that is not an object
            json!({ "audit_log_entries": [1] }),
            json!({ "audit_log_entries": [update, null] }),
        ] {
            for action in [FLUXER_AUDIT_ROLE_CREATE, FLUXER_AUDIT_ROLE_UPDATE] {
                assert_eq!(
                    parse(&body, action),
                    Err(AuditParseError::Malformed),
                    "{body} {action}"
                );
            }
        }
    }

    #[test]
    fn repeated_entry_id_is_malformed() {
        // Fluxer re-reads the top of a batch when it skips entries, which
        // repeats them and leaves older ones unread
        let id = fresh_role_id();
        let entry = update_entry(entry_id(10), id, ADMIN, Some(color_change()));
        assert_eq!(
            parse(&page(vec![entry.clone(), entry]), FLUXER_AUDIT_ROLE_UPDATE),
            Err(AuditParseError::Malformed)
        );

        let entry = create_entry(entry_id(10), id, OWNER, &today_code(), MANAGE_GUILD);
        assert_eq!(
            parse(&page(vec![entry.clone(), entry]), FLUXER_AUDIT_ROLE_CREATE),
            Err(AuditParseError::Malformed)
        );
    }

    #[test]
    fn full_page_offers_no_cursor_and_is_full() {
        // Newest first, as Fluxer returns an `after` read
        let full: Vec<Value> = (0..FLUXER_AUDIT_PAGE_LIMIT)
            .rev()
            .map(|n| update_entry(entry_id(n), fresh_role_id(), ADMIN, Some(color_change())))
            .collect();
        let parsed = parse(&page(full.clone()), FLUXER_AUDIT_ROLE_UPDATE).unwrap();
        assert_eq!(parsed.count, FLUXER_AUDIT_PAGE_LIMIT as usize);
        assert_eq!(parsed.entries.len(), FLUXER_AUDIT_PAGE_LIMIT as usize);
        // Nothing forward of an `after` page reaches the entries it dropped
        assert_eq!(parsed.next_after, None);
        assert!(parsed.is_full());

        let short = parse(&page(full[1..].to_vec()), FLUXER_AUDIT_ROLE_UPDATE).unwrap();
        assert_eq!(short.count, FLUXER_AUDIT_PAGE_LIMIT as usize - 1);
        assert_eq!(short.next_after, None);
        assert!(!short.is_full());

        let creates: Vec<Value> = (0..FLUXER_AUDIT_PAGE_LIMIT)
            .rev()
            .map(|n| create_entry(entry_id(n), entry_id(n) - 1, OWNER, "role", 0))
            .collect();
        let parsed = parse(&page(creates), FLUXER_AUDIT_ROLE_CREATE).unwrap();
        assert_eq!(parsed.entries.len(), FLUXER_AUDIT_PAGE_LIMIT as usize);
        assert_eq!(parsed.next_after, None);
        assert!(parsed.is_full());
    }

    #[test]
    fn after_cursor_is_just_before_the_earliest_days_midnight() {
        let [today, yesterday] = candidates();
        let expected = day_start_snowflake(day(2026, 10, 14)) - 1;
        assert_eq!(
            fluxer_audit_after_cursor(&[today.clone(), yesterday.clone()]),
            expected
        );
        assert_eq!(
            fluxer_audit_after_cursor(&[yesterday, today.clone()]),
            expected
        );
        assert_eq!(
            fluxer_audit_after_cursor(&[today]),
            day_start_snowflake(day(2026, 10, 15)) - 1
        );

        // `after` is exclusive: an entry minted at midnight is above it, the
        // last instant of the day before is not
        assert!(day_start_snowflake(day(2026, 10, 14)) > expected);
        assert_eq!(snowflake_time(expected).date_naive(), day(2026, 10, 13));

        // Saturates, and no candidates reads the whole log
        assert_eq!(
            fluxer_audit_after_cursor(&[("c".to_string(), day(2015, 1, 1))]),
            0
        );
        assert_eq!(
            fluxer_audit_after_cursor(&[("c".to_string(), day(2010, 1, 1))]),
            0
        );
        assert_eq!(fluxer_audit_after_cursor(&[]), 0);
    }

    #[test]
    fn parsed_pages_feed_the_role_proof() {
        let code = today_code();
        // Made in the web app: "new role", renamed, then granted
        let web = fresh_role_id();
        // An earlier install's Administrator role, renamed by a moderator
        let orphan = snowflake_at(at(2026, 10, 15, 10, 35, 0), 4);

        let creates = page(vec![
            create_entry(entry_id(35), orphan, ADMIN, "Sloga Importer", ADMINISTRATOR),
            create_entry(entry_id(30), web, MEMBER, "new role", DEFAULTS),
            create_entry(
                entry_id(0),
                bot_role_id(),
                ADMIN,
                "Sloga Importer",
                ADMINISTRATOR,
            ),
        ]);
        let updates = page(vec![
            update_entry(
                entry_id(40),
                orphan,
                MODERATOR,
                Some(json!([{ "key": "name", "old_value": "Sloga Importer", "new_value": code }])),
            ),
            update_entry(
                entry_id(33),
                web,
                MEMBER,
                Some(json!([
                    { "key": "permissions", "old_value": DEFAULTS.to_string(), "new_value": (DEFAULTS | MANAGE_GUILD).to_string() },
                    { "key": "permissions_diff", "new_value": { "added": ["MANAGE_GUILD"], "removed": [] } },
                ])),
            ),
            update_entry(entry_id(32), web, MEMBER, Some(color_change())),
            update_entry(
                entry_id(31),
                web,
                MEMBER,
                Some(json!([{ "key": "name", "old_value": "new role", "new_value": code }])),
            ),
        ]);

        let mut audit = Vec::new();
        for (body, action) in [
            (&creates, FLUXER_AUDIT_ROLE_CREATE),
            (&updates, FLUXER_AUDIT_ROLE_UPDATE),
        ] {
            let parsed = parse(body, action).unwrap();
            assert!(!parsed.is_full());
            audit.extend(parsed.entries);
        }

        let web_role = code_role(web, &code, DEFAULTS | MANAGE_GUILD);
        let orphan_role = code_role(orphan, &code, ADMINISTRATOR);

        assert_eq!(prove(&[orphan_role], guild_id(), &audit), None);
        assert_eq!(
            prove(&[web_role], guild_id(), &audit),
            Some((code.clone(), web))
        );
        assert_eq!(
            prove(&[bot_role(), orphan_role, web_role], guild_id(), &audit),
            Some((code.clone(), web))
        );
    }
}
