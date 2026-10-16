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

use chrono::{DateTime, NaiveDate, NaiveTime, Utc};
use hmac::{Hmac, Mac};
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

/// A role entry from the Fluxer guild audit log
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleAudit<'a> {
    /// ROLE_CREATE, with the name the role was created under (if recorded)
    Created { role_id: u64, name: Option<&'a str> },
    /// ROLE_UPDATE whose changes include `name`
    Renamed { role_id: u64 },
}

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
/// A role name alone proves nothing: Fluxer checks that a member holds the
/// permissions they grant when a role is created and when its permissions
/// change, but a name-only edit skips that check. Any Manage Roles moderator
/// could rename an existing privileged role to the code, and every bot
/// install leaves one behind (named after the app, holding its permissions,
/// near the bottom of the list, never deleted when the bot leaves). So a role
/// only counts if every one of these holds:
/// - its name is exactly the code (no trimming, no substring match);
/// - it is not `@everyone` (whose id is the guild id), which every member has;
/// - the bot does not hold it: that is the bot's own install role, carrying
///   the bot's permissions rather than the user's;
/// - it carries Administrator or Manage Server;
/// - it was created no earlier than the code's day, so it cannot predate the
///   code;
/// - the audit log shows it was created under the code's name;
/// - the audit log shows no rename of it.
///
/// Together the last two mean the role has carried the code since it was
/// made, so every permission it holds was granted to a role of that name by
/// someone who held that permission. A role created under the code, renamed
/// into something an admin would grant rights to, then renamed back, fails.
///
/// The caller fetches the audit log from the code's day onward and fails
/// closed when it cannot read all of it.
pub fn fluxer_role_proof<'a>(
    roles: &[ProofRole<'a>],
    guild_id: u64,
    bot_role_ids: &[u64],
    audit: &[RoleAudit<'a>],
    candidates: &[(String, NaiveDate)],
) -> Option<(String, u64)> {
    roles.iter().find_map(|role| {
        if role.id == guild_id
            || bot_role_ids.contains(&role.id)
            || role.permissions & (ADMINISTRATOR | MANAGE_GUILD) == 0
        {
            return None;
        }

        let (code, _) = candidates.iter().find(|(code, day)| {
            role.name == code.as_str() && snowflake_time(role.id) >= day_start(*day)
        })?;

        let created_as_code = audit.iter().any(|entry| {
            matches!(entry, RoleAudit::Created { role_id, name: Some(name) }
                if *role_id == role.id && *name == code.as_str())
        });
        let renamed = audit
            .iter()
            .any(|entry| matches!(entry, RoleAudit::Renamed { role_id } if *role_id == role.id));

        (created_as_code && !renamed).then(|| (code.clone(), role.id))
    })
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

    fn prove(
        roles: &[ProofRole<'_>],
        guild: u64,
        audit: &[RoleAudit<'_>],
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

    #[test]
    fn fresh_code_role_with_manage_server_passes() {
        let code = today_code();
        let id = fresh_role_id();
        let roles = [
            bot_role(),
            ProofRole {
                id,
                name: &code,
                permissions: MANAGE_GUILD | KICK_MEMBERS,
            },
        ];
        let audit = [
            RoleAudit::Created {
                role_id: bot_role_id(),
                name: Some("Sloga Importer"),
            },
            RoleAudit::Created {
                role_id: id,
                name: Some(&code),
            },
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), Some((code.clone(), id)));
    }

    #[test]
    fn todays_code_with_administrator_only_passes() {
        let code = today_code();
        let id = fresh_role_id();
        let roles = [ProofRole {
            id,
            name: &code,
            permissions: ADMINISTRATOR,
        }];
        let audit = [RoleAudit::Created {
            role_id: id,
            name: Some(&code),
        }];
        assert_eq!(prove(&roles, guild_id(), &audit), Some((code.clone(), id)));
    }

    #[test]
    fn yesterdays_code_with_role_created_yesterday_passes() {
        let code = yesterday_code();
        let id = snowflake_at(at(2026, 10, 14, 23, 50, 0), 3);
        let roles = [ProofRole {
            id,
            name: &code,
            permissions: MANAGE_GUILD,
        }];
        let audit = [RoleAudit::Created {
            role_id: id,
            name: Some(&code),
        }];
        assert_eq!(prove(&roles, guild_id(), &audit), Some((code.clone(), id)));
    }

    #[test]
    fn role_created_exactly_at_midnight_of_codes_day_passes() {
        let code = today_code();
        let id = day_start_snowflake(day(2026, 10, 15));
        let roles = [ProofRole {
            id,
            name: &code,
            permissions: MANAGE_GUILD,
        }];
        let audit = [RoleAudit::Created {
            role_id: id,
            name: Some(&code),
        }];
        assert_eq!(prove(&roles, guild_id(), &audit), Some((code.clone(), id)));
    }

    #[test]
    fn skips_failing_roles_and_returns_the_proving_one() {
        let code = today_code();
        let bare = snowflake_at(at(2026, 10, 15, 10, 0, 0), 2);
        let id = fresh_role_id();
        let roles = [
            // Same name, no permission bits: skipped, not a hard stop
            ProofRole {
                id: bare,
                name: &code,
                permissions: KICK_MEMBERS,
            },
            ProofRole {
                id,
                name: &code,
                permissions: MANAGE_GUILD,
            },
        ];
        let audit = [
            RoleAudit::Created {
                role_id: bare,
                name: Some(&code),
            },
            RoleAudit::Created {
                role_id: id,
                name: Some(&code),
            },
            // A rename of some other role does not count against this one
            RoleAudit::Renamed {
                role_id: bot_role_id(),
            },
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), Some((code.clone(), id)));
    }

    #[test]
    fn code_role_without_permission_bits_fails() {
        let code = today_code();
        let id = fresh_role_id();
        let audit = [RoleAudit::Created {
            role_id: id,
            name: Some(&code),
        }];
        for permissions in [
            0,
            KICK_MEMBERS,
            MANAGE_ROLES | VIEW_AUDIT_LOG | KICK_MEMBERS,
        ] {
            let roles = [ProofRole {
                id,
                name: &code,
                permissions,
            }];
            assert_eq!(prove(&roles, guild_id(), &audit), None, "{permissions:#x}");
        }
    }

    #[test]
    fn bot_held_role_fails() {
        // The bot's install role renamed to the code, with a clean-looking
        // audit trail: still refused, the bot holds it
        let code = today_code();
        let roles = [ProofRole {
            id: bot_role_id(),
            name: &code,
            permissions: ADMINISTRATOR,
        }];
        let audit = [RoleAudit::Created {
            role_id: bot_role_id(),
            name: Some(&code),
        }];
        assert_eq!(prove(&roles, guild_id(), &audit), None);
    }

    #[test]
    fn everyone_role_fails() {
        // A guild created today, so `@everyone` is fresh and the day check
        // alone would let it through
        let code = today_code();
        let guild = snowflake_at(at(2026, 10, 15, 8, 0, 0), 5);
        let roles = [ProofRole {
            id: guild,
            name: &code,
            permissions: ADMINISTRATOR,
        }];
        let audit = [RoleAudit::Created {
            role_id: guild,
            name: Some(&code),
        }];
        assert_eq!(prove(&roles, guild, &audit), None);
    }

    #[test]
    fn role_created_before_the_codes_day_fails() {
        // Today's code on a role from the last instant before today's midnight
        let today = today_code();
        let late_yesterday = day_start_snowflake(day(2026, 10, 15)) - 1;
        let roles = [ProofRole {
            id: late_yesterday,
            name: &today,
            permissions: MANAGE_GUILD,
        }];
        let audit = [RoleAudit::Created {
            role_id: late_yesterday,
            name: Some(&today),
        }];
        assert_eq!(prove(&roles, guild_id(), &audit), None);

        // Yesterday's code on a role from the day before yesterday
        let yesterday = yesterday_code();
        let two_days_ago = snowflake_at(at(2026, 10, 13, 23, 59, 59), 9);
        let roles = [ProofRole {
            id: two_days_ago,
            name: &yesterday,
            permissions: MANAGE_GUILD,
        }];
        let audit = [RoleAudit::Created {
            role_id: two_days_ago,
            name: Some(&yesterday),
        }];
        assert_eq!(prove(&roles, guild_id(), &audit), None);
    }

    #[test]
    fn orphaned_earlier_bot_install_role_renamed_to_code_fails() {
        // An earlier install of the importer this morning left its role behind
        // when the bot was removed; a moderator renames it to the code
        let code = today_code();
        let orphan = snowflake_at(at(2026, 10, 15, 7, 15, 0), 4);
        let roles = [
            bot_role(),
            ProofRole {
                id: orphan,
                name: &code,
                permissions: ADMINISTRATOR,
            },
        ];
        let audit = [
            RoleAudit::Created {
                role_id: orphan,
                name: Some("Sloga Importer"),
            },
            RoleAudit::Renamed { role_id: orphan },
            RoleAudit::Created {
                role_id: bot_role_id(),
                name: Some("Sloga Importer"),
            },
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), None);

        // Created before the audit window: no entry at all, still refused
        assert_eq!(
            prove(
                &roles,
                guild_id(),
                &[RoleAudit::Renamed { role_id: orphan }]
            ),
            None
        );
    }

    #[test]
    fn third_party_bot_role_renamed_today_fails() {
        let code = today_code();
        let other_bot = snowflake_at(at(2026, 10, 15, 11, 0, 0), 8);
        let roles = [ProofRole {
            id: other_bot,
            name: &code,
            permissions: ADMINISTRATOR | MANAGE_GUILD,
        }];
        let audit = [
            RoleAudit::Created {
                role_id: other_bot,
                name: Some("Moderation Bot"),
            },
            RoleAudit::Renamed { role_id: other_bot },
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), None);
    }

    #[test]
    fn role_created_under_another_name_then_renamed_to_code_fails() {
        let code = today_code();
        let id = fresh_role_id();
        let roles = [ProofRole {
            id,
            name: &code,
            permissions: MANAGE_GUILD,
        }];
        let audit = [
            RoleAudit::Created {
                role_id: id,
                name: Some("Event Staff"),
            },
            RoleAudit::Renamed { role_id: id },
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), None);
    }

    #[test]
    fn role_created_as_code_renamed_away_and_back_fails() {
        // Created under the code with no rights, renamed to something
        // harmless-looking so an admin grants it Manage Server, then renamed
        // back: only the rename record catches this
        let code = today_code();
        let id = fresh_role_id();
        let roles = [ProofRole {
            id,
            name: &code,
            permissions: MANAGE_GUILD,
        }];
        let audit = [
            RoleAudit::Created {
                role_id: id,
                name: Some(&code),
            },
            RoleAudit::Renamed { role_id: id },
            RoleAudit::Renamed { role_id: id },
        ];
        assert_eq!(prove(&roles, guild_id(), &audit), None);
    }

    #[test]
    fn no_created_entry_fails() {
        let code = today_code();
        let id = fresh_role_id();
        let roles = [ProofRole {
            id,
            name: &code,
            permissions: MANAGE_GUILD,
        }];
        assert_eq!(prove(&roles, guild_id(), &[]), None);

        // A creation record for some other role does not stand in for it
        let audit = [RoleAudit::Created {
            role_id: id + 1,
            name: Some(&code),
        }];
        assert_eq!(prove(&roles, guild_id(), &audit), None);
    }

    #[test]
    fn created_name_not_the_code_fails() {
        let code = today_code();
        let id = fresh_role_id();
        let roles = [ProofRole {
            id,
            name: &code,
            permissions: MANAGE_GUILD,
        }];
        let lower = code.to_lowercase();
        let spaced = format!("{code} ");
        for name in [
            None,
            Some("new role"),
            Some(lower.as_str()),
            Some(spaced.as_str()),
        ] {
            let audit = [RoleAudit::Created { role_id: id, name }];
            assert_eq!(prove(&roles, guild_id(), &audit), None, "{name:?}");
        }

        // Created under yesterday's code but now named today's
        let yesterday = yesterday_code();
        let audit = [RoleAudit::Created {
            role_id: id,
            name: Some(&yesterday),
        }];
        assert_eq!(prove(&roles, guild_id(), &audit), None);
    }

    #[test]
    fn other_source_tags_code_fails() {
        let id = fresh_role_id();
        for tag in ["stoat", "matrix", "discord"] {
            let theirs = code(KEY, tag, USER, day(2026, 10, 15));
            let roles = [ProofRole {
                id,
                name: &theirs,
                permissions: MANAGE_GUILD,
            }];
            let audit = [RoleAudit::Created {
                role_id: id,
                name: Some(&theirs),
            }];
            assert_eq!(prove(&roles, guild_id(), &audit), None, "{tag}");
        }
    }

    #[test]
    fn other_users_code_fails() {
        let theirs = code(KEY, "fluxer", OTHER_USER, day(2026, 10, 15));
        let id = fresh_role_id();
        let roles = [ProofRole {
            id,
            name: &theirs,
            permissions: MANAGE_GUILD,
        }];
        let audit = [RoleAudit::Created {
            role_id: id,
            name: Some(&theirs),
        }];
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
            let roles = [ProofRole {
                id,
                name: &name,
                permissions: MANAGE_GUILD,
            }];
            let audit = [RoleAudit::Created {
                role_id: id,
                name: Some(&name),
            }];
            assert_eq!(prove(&roles, guild_id(), &audit), None, "{name:?}");
        }
    }

    #[test]
    fn no_candidates_fails() {
        let code = today_code();
        let id = fresh_role_id();
        let roles = [ProofRole {
            id,
            name: &code,
            permissions: MANAGE_GUILD,
        }];
        let audit = [RoleAudit::Created {
            role_id: id,
            name: Some(&code),
        }];
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
}
