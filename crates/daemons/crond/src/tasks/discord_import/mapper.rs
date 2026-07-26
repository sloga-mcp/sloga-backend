//! Pure mapping from a Discord guild template to a planned Sloga server.
//!
//! Deliberately free of database and HTTP concerns so it can be unit-tested
//! exhaustively. The worker turns an [`ImportPlan`] into real rows.
//!
//! Slice 0 mapped structure (name, categories, channels); slice 1 adds roles,
//! the `@everyone` → `default_permissions` rule and per-channel permission
//! overwrites. Emojis and the icon require the optional bot upgrade (slice 2)
//! because templates do not carry them.

use super::permissions::{
    administrator_grant, baseline_grants, has_administrator, map_overwrite, map_role_permissions,
    sloga_default_server_permissions,
};
use super::template::{
    channel_type, GuildTemplate, OverwriteKind, PlaceholderId, TemplateChannel, TemplateRole,
};

/// Sloga name limits (validated at the HTTP routes, which the worker bypasses —
/// so the mapper is where they get enforced).
const NAME_MIN: usize = 1;
const NAME_MAX: usize = 32;
const DESCRIPTION_MAX: usize = 1024;

const FALLBACK_CHANNEL_NAME: &str = "channel";
const FALLBACK_CATEGORY_NAME: &str = "category";
const FALLBACK_SERVER_NAME: &str = "Imported Server";
const FALLBACK_ROLE_NAME: &str = "role";

/// Placeholder id Discord assigns the `@everyone` role inside a template.
///
/// In a live guild `@everyone`'s id is the guild id; templates renumber every
/// id to a small integer and `@everyone` always lands on 0. Verified live
/// against Discord's own "Blank Server" template on 2026-07-25.
const EVERYONE_PLACEHOLDER: &str = "0";

/// The name Discord gives that role. Not user-renameable on Discord.
const EVERYONE_NAME: &str = "@everyone";

/// Why a template could not be turned into a plan.
///
/// The mapper refuses far more readily than it used to, and deliberately: this
/// slice writes **permissions**, and every remaining unknown about the template
/// format is one where guessing wrong publishes a private channel or hands out
/// administrative power. Failing the import is recoverable; silently importing
/// the wrong permissions is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// The role array does not begin with `@everyone`, so the ordering
    /// convention the whole rank inversion rests on does not hold for this
    /// template. See [`plan_roles`].
    UnexpectedRoleOrder,
    /// A channel permission overwrite named a target type outside the
    /// documented role/member pair.
    UnknownOverwriteKind,
}

impl PlanError {
    /// User-safe message stored on the job and shown in the client.
    pub fn user_message(&self) -> String {
        match self {
            PlanError::UnexpectedRoleOrder => {
                "This Discord template's roles are arranged in a way we don't recognise, and we \
                 won't guess at a server's permissions. Please report this — it means Discord \
                 changed their template format."
                    .to_string()
            }
            PlanError::UnknownOverwriteKind => {
                "This Discord template contains channel permissions we don't recognise. We've \
                 stopped rather than risk importing a private channel as a public one. Please \
                 report this."
                    .to_string()
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedChannelKind {
    Text {
        slowmode: Option<u64>,
        announcement: bool,
    },
    Voice {
        max_users: Option<u64>,
    },
    Forum,
}

/// One `allow`/`deny` pair, already translated into Sloga bits.
///
/// Kept as plain `u64`s rather than a `revolt_permissions::Override` so the
/// mapper stays free of model types; the worker converts on the way to the
/// stored `OverrideField` (which is `i64` — mind the cast).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PlannedOverride {
    pub allow: u64,
    pub deny: u64,
}

impl PlannedOverride {
    /// An override that grants and revokes nothing is indistinguishable from
    /// having no override at all, and writing one would turn Sloga's "inherit"
    /// into an explicit no-op entry.
    fn is_empty(&self) -> bool {
        self.allow == 0 && self.deny == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedRole {
    /// Template placeholder id, used to resolve channel overwrites once real
    /// role ids exist.
    pub template_id: PlaceholderId,
    pub name: String,
    /// `#RRGGBB`, or absent when Discord had no colour set (its `color: 0`).
    pub colour: Option<String>,
    pub hoist: bool,
    /// Sloga allow-bits. Discord role permissions are pure grants — deny only
    /// exists in channel overwrites — so there is no deny counterpart here.
    pub permissions: u64,
    /// This role held Discord's `ADMINISTRATOR`.
    ///
    /// Tracked separately from `permissions` because ADMINISTRATOR is not just
    /// "every bit": on Discord it also bypasses channel overwrites entirely.
    /// Sloga grants that bypass to the server **owner** only
    /// (`permissions/src/impl.rs`, `are_we_server_owner`), so for anyone else
    /// holding the role it has to be written out per channel.
    pub administrator: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedChannel {
    /// Template placeholder id, used to resolve `parent_id` and the system
    /// channel after real ids are minted.
    pub template_id: PlaceholderId,
    pub name: String,
    pub description: Option<String>,
    pub nsfw: bool,
    pub kind: PlannedChannelKind,
    pub parent: Option<PlaceholderId>,
    /// The `@everyone` overwrite for this channel, if it had one.
    pub default_permissions: Option<PlannedOverride>,
    /// Per-role overwrites, keyed by the role's template placeholder id.
    /// Ordered as Discord listed them, for deterministic output.
    pub role_overrides: Vec<(PlaceholderId, PlannedOverride)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedCategory {
    pub template_id: PlaceholderId,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportPlan {
    pub server_name: String,
    pub server_description: Option<String>,
    /// **Ordered most-authoritative first**, i.e. index 0 becomes Sloga rank 0.
    /// Truncating the tail of this list (for the role cap) therefore drops the
    /// least powerful roles and leaves the surviving ranks contiguous.
    pub roles: Vec<PlannedRole>,
    /// Server-wide baseline, from the Discord `@everyone` role's permissions
    /// OR-ed with Sloga's own member affordances. `@everyone` is a real role on
    /// Discord but is *not* a role on Sloga — this field is where it lands.
    pub default_permissions: u64,
    /// Ordered as they should appear.
    pub categories: Vec<PlannedCategory>,
    /// Ordered; `parent` refers to a category's `template_id`.
    pub channels: Vec<PlannedChannel>,
    /// Template id of the channel to mint the welcome invite in, if the guild
    /// nominated a system channel.
    pub system_channel: Option<PlaceholderId>,
    /// Human-readable notes about anything deliberately not imported.
    pub skipped: Vec<String>,
    /// How many source channels the mapper dropped (threads, directory
    /// channels, types Sloga has no equivalent for). Feeds the summary's
    /// skipped count so the number can't contradict the notes beside it.
    pub skipped_channel_count: u32,
}

impl ImportPlan {
    /// Total unit count for progress reporting.
    ///
    /// Channels only: they're the per-item loop the progress bar tracks.
    /// Categories are applied in a single batch write, so counting them here
    /// would make the bar stall at N/(N+M) and then jump to full.
    pub fn total_steps(&self) -> u32 {
        self.channels.len() as u32
    }
}

/// Truncate on a char boundary — Discord allows 100-char names and plenty of
/// non-ASCII; byte slicing would panic mid-codepoint.
fn clamp(value: &str, max: usize) -> String {
    value.trim().chars().take(max).collect::<String>()
}

fn clamp_name(raw: Option<&str>, fallback: &str) -> String {
    let cleaned = clamp(raw.unwrap_or(""), NAME_MAX);
    if cleaned.chars().count() < NAME_MIN {
        fallback.to_string()
    } else {
        cleaned
    }
}

fn clamp_description(raw: Option<&str>) -> Option<String> {
    raw.map(|value| clamp(value, DESCRIPTION_MAX))
        .filter(|value| !value.is_empty())
}

/// Discord's `user_limit` uses 0 to mean "unlimited"; Sloga expresses that as
/// absent, so 0 must NOT become `Some(0)` (which would mean "nobody").
fn voice_limit(raw: Option<u64>) -> Option<u64> {
    raw.filter(|limit| *limit > 0)
}

/// Slowmode of 0 means "off" in Discord; keep it absent rather than explicit.
fn slowmode(raw: Option<u64>) -> Option<u64> {
    raw.filter(|value| *value > 0)
}

/// Discord role colour (a 24-bit int, `0` meaning "no colour") → a CSS colour
/// Sloga's `RE_COLOUR` accepts.
///
/// Anything outside 24-bit RGB is corrupt input and yields no colour rather
/// than a string the server-edit validator would reject.
fn role_colour(raw: i64) -> Option<String> {
    (1..=0xFF_FFFF)
        .contains(&raw)
        .then(|| format!("#{raw:06X}"))
}

/// The `@everyone` role, split out from the roles that become Sloga roles.
struct RolePlan {
    /// Placeholder id of `@everyone`, so channel overwrites can be matched
    /// against the SAME value this function used — matching them separately is
    /// how a private channel silently becomes public.
    everyone_id: Option<PlaceholderId>,
    /// Its mapped permissions, which become `Server.default_permissions`.
    everyone_permissions: Option<u64>,
    /// Whether Discord's `@everyone` held ADMINISTRATOR — worth shouting about,
    /// since this feature's output is an invite link meant to be posted
    /// publicly.
    everyone_is_administrator: bool,
    /// Ordered most-authoritative first; index becomes Sloga rank.
    roles: Vec<PlannedRole>,
}

/// Split the template's roles into the `@everyone` baseline and real Sloga
/// roles, applying the rank inversion.
///
/// **The inversion is the easy thing to get backwards.** Discord: a *higher*
/// `position` means *more* authority, and `@everyone` sits at position 0.
/// Sloga: a *lower* `rank` means *more* authority. So the most powerful Discord
/// role must come out as rank 0.
///
/// # The ordering problem, and how this proves its way out of it
///
/// Templates carry **no role `position`** — verified live 2026-07-25 against
/// Discord's own "Blank Server" template, whose role object has exactly
/// `id, name, permissions, color, colors, hoist, mentionable, icon,
/// unicode_emoji`. Order therefore has to come from the array, and the array's
/// direction is not documented anywhere.
///
/// Rather than assume, this checks: **`roles[0]` must be NAMED `@everyone`.**
///
/// That **rules out a descending array** — and only that. `@everyone` is
/// definitionally the least-authoritative role (position 0), so a
/// position-descending array would put it last and `roles[0]` would be the top
/// role under some other name; the check refuses. Anything else returns
/// [`PlanError::UnexpectedRoleOrder`] and the import fails.
///
/// It does **not** establish that the array is ascending. See "What this still
/// does NOT settle" below — the earlier version of this comment claimed it did,
/// and that overclaim survived two audit rounds precisely because it reads as
/// airtight.
///
/// **It has to be the name.** Checking the placeholder id instead is a
/// tautology: ids are handed out in serialization order, so the id-0 role is
/// always the first element no matter which way the array runs. The id is kept
/// only as corroboration.
///
/// # What this still does NOT settle
///
/// "`@everyone` first" is *jointly* implied by position-ascending **and** by
/// the array simply being ordered by role **snowflake**, i.e. creation order —
/// `@everyone`'s id is the guild id, the oldest in every guild. So observing it
/// discriminates nothing between those two, and the remaining roles would then
/// be reversed on a false premise.
///
/// Under creation order nothing escalates: `default_permissions` still comes
/// from the genuine `@everyone`, and every role keeps its own mapped bits, so
/// **nobody gains a permission they should not have**. What breaks is the
/// *ranking* — oldest role gets rank 0 — which inverts rank-gated moderation
/// (an admin cannot kick a member), flips channel-override precedence for
/// multi-role users, and makes the role cap drop the oldest roles rather than
/// the weakest. HIGH on correctness, not a security cliff.
///
/// Distinguishing the two needs a real template from a guild where creation
/// order and authority order **differ**; no unit test can do it. Note the
/// asymmetry in how the two failures surface: a descending array is
/// self-announcing (the import refuses loudly), whereas creation order is
/// silent and shows up later as "my moderators can't kick anyone".
///
/// Getting this wrong is not merely an inverted hierarchy. Because `@everyone`
/// is what becomes `Server.default_permissions`, mistaking the *top* role for
/// it would write that role's permissions — plausibly `ADMINISTRATOR` —
/// server-wide, and this feature's whole output is an invite link the UI tells
/// the user to paste into a public Discord channel. Everyone who accepted it
/// would be an administrator. Hence: prove, don't assume.
///
/// A `position` field is still preferred if one ever appears, but only when
/// **every** role carries it — mixing real positions with array indices would
/// sort two incompatible scales against each other.
fn plan_roles(roles: &[TemplateRole]) -> Result<RolePlan, PlanError> {
    if roles.is_empty() {
        return Ok(RolePlan {
            everyone_id: None,
            everyone_permissions: None,
            everyone_is_administrator: false,
            roles: Vec::new(),
        });
    }

    let everyone = &roles[0];

    // THE ordering proof — see the doc comment. Both halves are required, and
    // the NAME is the load-bearing one.
    //
    // Checking only the id would be a tautology: Discord assigns placeholder
    // ids in serialization order, so the role holding id 0 is *by construction*
    // the first element, whichever direction the array runs. Asserting its
    // position proves nothing. The name is the only field whose value actually
    // differs between the two hypotheses — under ascending, `roles[0]` is
    // `@everyone`; under descending it is the top role, named something else —
    // and Discord does not permit renaming `@everyone`.
    // Relaxing the id half is not a free change: `plan_overwrites` resolves the
    // channel `@everyone` entry against the id threaded out of here, and while
    // this assertion holds that id is always "0", so the threading and a
    // hard-coded "0" behave identically and no test can force them apart. Loosen
    // this and `plan_overwrites`' `everyone_id` becomes load-bearing —
    // `plan_overwrites_matches_a_non_zero_everyone_id` is what guards it.
    //
    // Note also that this half is a total-outage switch, not a degrade: it is a
    // tautology while Discord's placeholder counter walks roles before channels,
    // and if that ever changes EVERY import fails with "please report this".
    // That is the intended fail-closed posture, but the failure rate goes to
    // 100%, so it needs to be visible wherever this job is monitored.
    if everyone.name.trim() != EVERYONE_NAME || everyone.id.0 != EVERYONE_PLACEHOLDER {
        return Err(PlanError::UnexpectedRoleOrder);
    }

    let rest = &roles[1..];

    // Use `position` only if every role has one; a partial rollout would have
    // us comparing real positions against array indices.
    let all_have_position = rest.iter().all(|role| role.position.is_some());

    let mut ranked: Vec<(i64, usize, &TemplateRole)> = rest
        .iter()
        .enumerate()
        .map(|(index, role)| {
            let key = if all_have_position {
                role.position.unwrap_or(index as i64)
            } else {
                index as i64
            };
            (key, index, role)
        })
        .collect();

    // Descending authority: the last array element (highest position) becomes
    // rank 0. The index is a deterministic tie-break for two roles sharing a
    // position.
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));

    let planned = ranked
        .into_iter()
        .map(|(_, _, role)| PlannedRole {
            template_id: role.id.clone(),
            name: clamp_name(Some(role.name.as_str()), FALLBACK_ROLE_NAME),
            colour: role_colour(role.color),
            hoist: role.hoist,
            permissions: map_role_permissions(role.permissions.0),
            administrator: has_administrator(role.permissions.0),
        })
        .collect();

    Ok(RolePlan {
        everyone_id: Some(everyone.id.clone()),
        everyone_permissions: Some(map_role_permissions(everyone.permissions.0)),
        everyone_is_administrator: has_administrator(everyone.permissions.0),
        roles: planned,
    })
}

/// What a channel's `permission_overwrites` array became.
#[derive(Default)]
struct PlannedOverwrites {
    default_permissions: Option<PlannedOverride>,
    role_overrides: Vec<(PlaceholderId, PlannedOverride)>,
    /// Overwrites targeting a specific member. Sloga has no per-member channel
    /// overrides, and the members are not coming over anyway.
    members_skipped: usize,
    /// Overwrites pointing at a role the template does not define.
    dangling_skipped: usize,
}

/// Translate one channel's overwrites, resolving role targets against the roles
/// that actually made it into the plan.
///
/// `everyone_id` comes from [`plan_roles`], never from a local constant: if the
/// two disagreed about which placeholder id is `@everyone`, the channel's
/// `@everyone` overwrite would be filed as a role override, fail to resolve,
/// and be dropped — leaving a channel that was private on Discord inheriting a
/// server default that lets everybody read it. Fails **open**, silently, with
/// only a misleading note. So there is exactly one answer to "which id is
/// `@everyone`" and it is threaded through.
fn plan_overwrites(
    overwrites: &[super::template::TemplateOverwrite],
    planned_roles: &[PlannedRole],
    everyone_id: Option<&PlaceholderId>,
) -> Result<PlannedOverwrites, PlanError> {
    let mut result = PlannedOverwrites::default();

    for overwrite in overwrites {
        match overwrite.kind {
            OverwriteKind::Member => {
                result.members_skipped += 1;
                continue;
            }
            // Nobody on this project has ever seen a template carrying a
            // non-empty `permission_overwrites` array (plan §0-PRE A-6 says as
            // much), so an unrecognised `type` means the one thing we cannot
            // afford to guess at. Dropping it would turn a `deny VIEW_CHANNEL`
            // into a public channel while the UI promises "private channels
            // included". Fail the import instead.
            OverwriteKind::Unknown => return Err(PlanError::UnknownOverwriteKind),
            OverwriteKind::Role => {}
        }

        let (allow, deny) = map_overwrite(overwrite.allow.0, overwrite.deny.0);
        let mapped = PlannedOverride { allow, deny };

        // Every Discord permission this overwrite touched fell outside the
        // mapping table, so there is nothing to write.
        if mapped.is_empty() {
            continue;
        }

        // No `@everyone` was identified, yet this channel has overwrites to
        // apply. Nothing here can be resolved correctly: the channel's
        // `@everyone` entry would fall through to the role match, find nothing,
        // and be dropped as "dangling" — leaving a channel that was private on
        // Discord inheriting a server default that grants ViewChannel. The one
        // remaining fail-OPEN path in an otherwise fail-closed mapper, so it
        // refuses too.
        let Some(everyone_id) = everyone_id else {
            return Err(PlanError::UnexpectedRoleOrder);
        };

        if &overwrite.id == everyone_id {
            // The `@everyone` overwrite is the channel's default, not a role
            // entry. Later duplicates would be a malformed template; the first
            // wins, matching "first definition" semantics elsewhere.
            result.default_permissions.get_or_insert(mapped);
            continue;
        }

        if planned_roles
            .iter()
            .any(|role| role.template_id == overwrite.id)
        {
            // A duplicate entry for the same role would collapse downstream
            // (the worker keys a map by role id), so drop it here where it can
            // be seen, rather than letting it inflate a "dropped" counter.
            if result
                .role_overrides
                .iter()
                .any(|(id, _)| id == &overwrite.id)
            {
                continue;
            }

            result.role_overrides.push((overwrite.id.clone(), mapped));
        } else {
            result.dangling_skipped += 1;
        }
    }

    Ok(result)
}

/// Materialise Discord's ADMINISTRATOR channel-overwrite bypass.
///
/// On Discord, ADMINISTRATOR short-circuits permission computation **before**
/// channel overwrites are consulted, so an admin sees every channel without
/// needing an overwrite anywhere — which is why real guilds don't have one.
/// Sloga grants that bypass to the server **owner** only
/// (`permissions/src/impl.rs`, `are_we_server_owner`); a mere role holder runs
/// the full pipeline, so a `@everyone deny VIEW_CHANNEL` on `#mod-chat` strips
/// the admin's access and `revoke_all()` finishes the job.
///
/// Without this, importing a normal guild produces admins who cannot see a
/// single private channel — and it would never show up in a one-account smoke
/// test, because the owner bypasses everything.
///
/// Only channels that carry an override need it: a channel with none inherits
/// the server default, where the admin role's own grant already applies.
///
/// One residual divergence, deliberately left: Sloga applies channel role
/// overrides rank-descending, so the *most authoritative* role wins, whereas
/// Discord unions allows across roles. A member holding both an admin role and
/// a higher-ranked role that denies on that channel therefore ends up denied.
/// Imported admin roles sit at the top of the hierarchy in every normal guild,
/// so this needs a contrived shape to reach — and it fails restrictive, never
/// permissive.
fn grant_administrator_channel_access(channels: &mut [PlannedChannel], roles: &[PlannedRole]) {
    let admins: Vec<&PlannedRole> = roles.iter().filter(|role| role.administrator).collect();
    if admins.is_empty() {
        return;
    }

    for channel in channels {
        if channel.default_permissions.is_none() && channel.role_overrides.is_empty() {
            continue;
        }

        for admin in &admins {
            let grant = PlannedOverride {
                allow: administrator_grant(),
                deny: 0,
            };

            // Overwrite rather than merge: on Discord an explicit overwrite on
            // an admin is inert, so the faithful result is a full grant either
            // way.
            match channel
                .role_overrides
                .iter_mut()
                .find(|(id, _)| id == &admin.template_id)
            {
                Some((_, existing)) => *existing = grant,
                None => channel
                    .role_overrides
                    .push((admin.template_id.clone(), grant)),
            }
        }
    }
}

fn sorted_channels(template: &GuildTemplate) -> Vec<&TemplateChannel> {
    let mut channels: Vec<&TemplateChannel> =
        template.serialized_source_guild.channels.iter().collect();
    // Position is the display order; the placeholder id breaks ties so the
    // result is deterministic (important for tests and for re-imports).
    //
    // Ties are the common case, not the edge case — Discord's own "Blank
    // Server" template gives all four of its channels `position: 0` — so the
    // tie-break has to sort ids NUMERICALLY. Comparing the raw strings puts
    // "10" before "2" and scrambles the sidebar of any guild with ten or more
    // channels.
    channels.sort_by(|a, b| {
        a.position
            .cmp(&b.position)
            .then_with(|| a.id.sort_key().cmp(&b.id.sort_key()))
    });
    channels
}

/// Map a fetched template into a plan.
pub fn plan_import(template: &GuildTemplate) -> Result<ImportPlan, PlanError> {
    let guild = &template.serialized_source_guild;
    let mut skipped: Vec<String> = Vec::new();

    let server_name = clamp_name(
        guild
            .name
            .as_deref()
            // Fall back to the template's own name only if the guild name is
            // missing — they are different things.
            .or(Some(template.name.as_str())),
        FALLBACK_SERVER_NAME,
    );

    // Roles first: channel overwrites reference them, and the `@everyone` role
    // is not a role at all on Sloga — its permissions are the server default.
    let role_plan = plan_roles(&guild.roles)?;
    let roles = role_plan.roles;

    // Only reachable for a template with no roles at all — `plan_roles` refuses
    // anything else it cannot locate `@everyone` at the head of. Falling back to
    // Sloga's own new-server default keeps the import usable instead of minting
    // a server whose members cannot see anything.
    let default_permissions = role_plan
        .everyone_permissions
        .unwrap_or_else(sloga_default_server_permissions)
        | baseline_grants();

    // Faithful to the source, but the output of this whole feature is an invite
    // link the UI tells the user to paste into a public Discord channel — so if
    // everyone who accepts it is about to be an administrator, say so in terms
    // nobody could miss.
    if role_plan.everyone_is_administrator {
        skipped.push(
            "⚠ In your Discord server, @everyone had the Administrator permission, so everyone \
             on this Sloga server can manage roles, channels and bans — including anyone who \
             joins using the invite link below. Change this in Server Settings if it wasn't \
             deliberate."
                .to_string(),
        );
    }

    let ordered = sorted_channels(template);

    // Pass 1: categories, so channel parents can be resolved against them.
    let mut categories: Vec<PlannedCategory> = Vec::new();
    for channel in &ordered {
        if channel.channel_type == channel_type::GUILD_CATEGORY {
            categories.push(PlannedCategory {
                template_id: channel.id.clone(),
                title: clamp_name(channel.name.as_deref(), FALLBACK_CATEGORY_NAME),
            });
        }
    }

    // Pass 2: real channels.
    let mut channels: Vec<PlannedChannel> = Vec::new();
    let mut skipped_threads = 0usize;
    let mut skipped_other = 0usize;
    let mut skipped_member_overwrites = 0usize;
    let mut skipped_dangling_overwrites = 0usize;

    for channel in &ordered {
        let kind = match channel.channel_type {
            channel_type::GUILD_CATEGORY => continue, // handled above
            channel_type::GUILD_TEXT => PlannedChannelKind::Text {
                slowmode: slowmode(channel.rate_limit_per_user),
                announcement: false,
            },
            channel_type::GUILD_ANNOUNCEMENT => PlannedChannelKind::Text {
                slowmode: slowmode(channel.rate_limit_per_user),
                announcement: true,
            },
            channel_type::GUILD_VOICE => PlannedChannelKind::Voice {
                max_users: voice_limit(channel.user_limit),
            },
            channel_type::GUILD_STAGE_VOICE => {
                // Closest equivalent; stage-specific semantics are lost.
                skipped.push(format!(
                    "\"{}\" was a Stage channel and became a normal voice channel.",
                    clamp_name(channel.name.as_deref(), FALLBACK_CHANNEL_NAME)
                ));
                PlannedChannelKind::Voice {
                    max_users: voice_limit(channel.user_limit),
                }
            }
            channel_type::GUILD_FORUM | channel_type::GUILD_MEDIA => PlannedChannelKind::Forum,
            // Threads live inside channels and are re-created by use, not by
            // import; directory channels have no Sloga equivalent.
            10 | 11 | 12 => {
                skipped_threads += 1;
                continue;
            }
            _ => {
                skipped_other += 1;
                continue;
            }
        };

        // A parent that isn't a real category (or points at a missing entry)
        // degrades to top-level rather than producing a dangling reference.
        let parent = channel.parent_id.as_ref().and_then(|parent_id| {
            categories
                .iter()
                .find(|category| &category.template_id == parent_id)
                .map(|category| category.template_id.clone())
        });

        let overwrites = plan_overwrites(
            &channel.permission_overwrites,
            &roles,
            role_plan.everyone_id.as_ref(),
        )?;
        skipped_member_overwrites += overwrites.members_skipped;
        skipped_dangling_overwrites += overwrites.dangling_skipped;

        channels.push(PlannedChannel {
            template_id: channel.id.clone(),
            name: clamp_name(channel.name.as_deref(), FALLBACK_CHANNEL_NAME),
            description: clamp_description(channel.topic.as_deref()),
            nsfw: channel.nsfw,
            kind,
            parent,
            default_permissions: overwrites.default_permissions,
            role_overrides: overwrites.role_overrides,
        });
    }

    if skipped_threads > 0 {
        skipped.push(format!(
            "{skipped_threads} thread(s) were not imported — threads are created as people use them."
        ));
    }
    if skipped_other > 0 {
        skipped.push(format!(
            "{skipped_other} channel(s) of a type Sloga doesn't have were not imported."
        ));
    }
    if skipped_member_overwrites > 0 {
        skipped.push(format!(
            "{skipped_member_overwrites} channel permission(s) set on individual Discord members \
             were not imported — Sloga sets channel permissions by role, and members come over \
             through your invite link rather than the template."
        ));
    }
    if skipped_dangling_overwrites > 0 {
        skipped.push(format!(
            "{skipped_dangling_overwrites} channel permission(s) pointed at a role the template \
             doesn't contain and were skipped."
        ));
    }

    // Discord admins bypass channel overwrites; Sloga role holders do not. Do
    // this once the channels' own overrides are known, so only restricted
    // channels get an entry.
    grant_administrator_channel_access(&mut channels, &roles);

    // Only keep the system channel if it survived mapping (it may have been a
    // skipped type).
    let system_channel = guild.system_channel_id.as_ref().and_then(|wanted| {
        channels
            .iter()
            .find(|channel| &channel.template_id == wanted)
            .map(|channel| channel.template_id.clone())
    });

    // Categories that ended up with no importable channels are dropped: Sloga
    // renders an empty category as dead weight, and server_edit drops unknown
    // ids anyway.
    let populated: Vec<PlannedCategory> = categories
        .into_iter()
        .filter(|category| {
            channels
                .iter()
                .any(|channel| channel.parent.as_ref() == Some(&category.template_id))
        })
        .collect();

    Ok(ImportPlan {
        server_name,
        server_description: clamp_description(guild.description.as_deref()),
        roles,
        default_permissions,
        categories: populated,
        channels,
        system_channel,
        skipped,
        skipped_channel_count: (skipped_threads + skipped_other) as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use revolt_permissions::ChannelPermission;

    /// Shadows `super::plan_import` for the majority of tests, which assert on
    /// a successful plan. Tests that exercise a refusal call
    /// `super::plan_import` directly.
    fn plan_import(template: &GuildTemplate) -> ImportPlan {
        super::plan_import(template).expect("template should plan cleanly")
    }

    fn template(guild_json: &str) -> GuildTemplate {
        serde_json::from_str(&format!(
            r#"{{"code":"c","name":"Template Name","serialized_source_guild":{guild_json}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn uses_guild_name_not_template_name() {
        let plan = plan_import(&template(r#"{"name":"Real Guild","channels":[]}"#));
        assert_eq!(plan.server_name, "Real Guild");
    }

    #[test]
    fn falls_back_to_template_name_then_placeholder() {
        let plan = plan_import(&template(r#"{"channels":[]}"#));
        assert_eq!(plan.server_name, "Template Name");

        // Neither name present at all.
        let bare: GuildTemplate =
            serde_json::from_str(r#"{"code":"c","name":"","serialized_source_guild":{}}"#).unwrap();
        assert_eq!(plan_import(&bare).server_name, FALLBACK_SERVER_NAME);
    }

    #[test]
    fn maps_channel_types() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[
                {"id":1,"type":0,"name":"text","position":0,"rate_limit_per_user":10},
                {"id":2,"type":2,"name":"voice","position":1,"user_limit":5},
                {"id":3,"type":5,"name":"news","position":2},
                {"id":4,"type":15,"name":"forum","position":3}
            ]}"#,
        ));

        assert_eq!(plan.channels.len(), 4);
        assert_eq!(
            plan.channels[0].kind,
            PlannedChannelKind::Text {
                slowmode: Some(10),
                announcement: false
            }
        );
        assert_eq!(
            plan.channels[1].kind,
            PlannedChannelKind::Voice { max_users: Some(5) }
        );
        assert_eq!(
            plan.channels[2].kind,
            PlannedChannelKind::Text {
                slowmode: None,
                announcement: true
            }
        );
        assert_eq!(plan.channels[3].kind, PlannedChannelKind::Forum);
    }

    #[test]
    fn voice_user_limit_zero_means_unlimited_not_zero() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[{"id":1,"type":2,"name":"v","user_limit":0}]}"#,
        ));
        assert_eq!(
            plan.channels[0].kind,
            PlannedChannelKind::Voice { max_users: None },
            "user_limit 0 is Discord's 'unlimited' — Some(0) would mean nobody can join"
        );
    }

    #[test]
    fn slowmode_zero_is_absent() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[{"id":1,"type":0,"name":"t","rate_limit_per_user":0}]}"#,
        ));
        assert_eq!(
            plan.channels[0].kind,
            PlannedChannelKind::Text {
                slowmode: None,
                announcement: false
            }
        );
    }

    #[test]
    fn categories_are_linked_and_ordered_by_position() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[
                {"id":10,"type":0,"name":"second","position":5,"parent_id":1},
                {"id":1,"type":4,"name":"CAT","position":0},
                {"id":11,"type":0,"name":"first","position":1,"parent_id":1}
            ]}"#,
        ));

        assert_eq!(plan.categories.len(), 1);
        assert_eq!(plan.categories[0].title, "CAT");
        // Ordered by position: "first" (1) before "second" (5)
        assert_eq!(plan.channels[0].name, "first");
        assert_eq!(plan.channels[1].name, "second");
        assert!(plan.channels.iter().all(|c| c.parent.is_some()));
    }

    #[test]
    fn dangling_parent_degrades_to_top_level() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[{"id":2,"type":0,"name":"orphan","parent_id":999}]}"#,
        ));
        assert_eq!(plan.channels[0].parent, None);
    }

    #[test]
    fn empty_categories_are_dropped() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[
                {"id":1,"type":4,"name":"EMPTY","position":0},
                {"id":2,"type":4,"name":"USED","position":1},
                {"id":3,"type":0,"name":"chan","position":2,"parent_id":2}
            ]}"#,
        ));
        assert_eq!(plan.categories.len(), 1);
        assert_eq!(plan.categories[0].title, "USED");
    }

    #[test]
    fn threads_and_unknown_types_are_skipped_with_notes() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[
                {"id":1,"type":0,"name":"keep"},
                {"id":2,"type":11,"name":"a thread"},
                {"id":3,"type":14,"name":"directory"}
            ]}"#,
        ));
        assert_eq!(plan.channels.len(), 1);
        assert_eq!(plan.skipped.len(), 2);
        assert!(plan.skipped.iter().any(|note| note.contains("thread")));
    }

    #[test]
    fn long_and_unicode_names_are_clamped_on_char_boundaries() {
        // 40 multi-byte chars — byte slicing here would panic.
        let long_name = "é".repeat(40);
        let plan = plan_import(&template(&format!(
            r#"{{"name":"g","channels":[{{"id":1,"type":0,"name":"{long_name}"}}]}}"#
        )));
        assert_eq!(plan.channels[0].name.chars().count(), NAME_MAX);
    }

    #[test]
    fn blank_names_get_a_fallback() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[{"id":1,"type":0,"name":"   "}]}"#,
        ));
        assert_eq!(plan.channels[0].name, FALLBACK_CHANNEL_NAME);
    }

    #[test]
    fn system_channel_resolves_only_if_it_survived_mapping() {
        let kept = plan_import(&template(
            r#"{"name":"g","system_channel_id":2,"channels":[{"id":2,"type":0,"name":"general"}]}"#,
        ));
        assert_eq!(kept.system_channel, Some(PlaceholderId("2".to_string())));

        // Points at a skipped thread → must not dangle.
        let dropped = plan_import(&template(
            r#"{"name":"g","system_channel_id":2,"channels":[{"id":2,"type":11,"name":"t"}]}"#,
        ));
        assert_eq!(dropped.system_channel, None);
    }

    /// Progress is driven by the per-channel loop, so categories must NOT be
    /// counted — including them made the bar stall at N/(N+M) and then jump
    /// straight to full when the single batch category write landed.
    #[test]
    fn total_steps_counts_channels_only() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[
                {"id":1,"type":4,"name":"CAT"},
                {"id":2,"type":0,"name":"a","parent_id":1},
                {"id":3,"type":0,"name":"b","parent_id":1}
            ]}"#,
        ));
        assert_eq!(plan.categories.len(), 1);
        assert_eq!(plan.total_steps(), 2);
    }

    // ----------------------------------------------------------------------
    // Roles (slice 1)
    // ----------------------------------------------------------------------

    /// `@everyone` is a real role on Discord and *not* a role on Sloga. Import
    /// it as one and every server gains a phantom role holding the baseline
    /// permissions.
    #[test]
    fn everyone_becomes_default_permissions_not_a_role() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[],"roles":[
                {"id":0,"name":"@everyone","permissions":1024},
                {"id":1,"name":"Member","permissions":2048}
            ]}"#,
        ));

        assert_eq!(plan.roles.len(), 1, "@everyone must not become a role");
        assert_eq!(plan.roles[0].name, "Member");

        // VIEW_CHANNEL (bit 10 = 1024)
        assert!(plan.default_permissions & ChannelPermission::ViewChannel as u64 != 0);
    }

    /// **The inversion, which is the easy thing to get backwards.**
    ///
    /// Discord orders its template role array position-ascending — `@everyone`
    /// (position 0, least authority) is always first. Sloga's rank runs the
    /// other way: 0 is the *most* authority. So the LAST role in the template
    /// array must come out as rank 0.
    #[test]
    fn discord_position_desc_maps_to_sloga_rank_asc() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[],"roles":[
                {"id":0,"name":"@everyone","permissions":0},
                {"id":1,"name":"Member","permissions":0},
                {"id":2,"name":"Moderator","permissions":0},
                {"id":3,"name":"Admin","permissions":0}
            ]}"#,
        ));

        // Index in `plan.roles` IS the rank the worker assigns.
        assert_eq!(
            plan.roles
                .iter()
                .map(|role| role.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Admin", "Moderator", "Member"],
            "highest-authority Discord role must land on Sloga rank 0"
        );
    }

    /// Templates carry no `position` today, but if Discord ever adds it back
    /// the authoritative value must beat the array-order inference.
    #[test]
    fn explicit_position_overrides_array_order() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[],"roles":[
                {"id":0,"name":"@everyone","permissions":0},
                {"id":1,"name":"Boss","permissions":0,"position":50},
                {"id":2,"name":"Peon","permissions":0,"position":1}
            ]}"#,
        ));

        assert_eq!(
            plan.roles
                .iter()
                .map(|role| role.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Boss", "Peon"]
        );
    }

    #[test]
    fn role_permissions_are_mapped_through_the_table() {
        // MANAGE_ROLES is bit 28 — one Discord bit, three Sloga bits.
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[],"roles":[
                {"id":0,"name":"@everyone","permissions":0},
                {"id":1,"name":"Mod","permissions":268435456}
            ]}"#,
        ));

        let mapped = plan.roles[0].permissions;
        assert!(mapped & ChannelPermission::ManageRole as u64 != 0);
        assert!(mapped & ChannelPermission::ManagePermissions as u64 != 0);
        assert!(mapped & ChannelPermission::AssignRoles as u64 != 0);
    }

    #[test]
    fn role_colour_zero_means_no_colour() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[],"roles":[
                {"id":0,"name":"@everyone","permissions":0},
                {"id":1,"name":"Plain","permissions":0,"color":0},
                {"id":2,"name":"Teal","permissions":0,"color":1752220}
            ]}"#,
        ));

        let by_name = |name: &str| {
            plan.roles
                .iter()
                .find(|role| role.name == name)
                .unwrap()
                .colour
                .clone()
        };

        assert_eq!(by_name("Plain"), None);
        // Discord's classic teal, zero-padded to six hex digits.
        assert_eq!(by_name("Teal"), Some("#1ABC9C".to_string()));
    }

    /// A colour that would fail Sloga's `RE_COLOUR` must be dropped, not
    /// written — the mapper is the only validation gate the worker has.
    #[test]
    fn out_of_range_colour_is_dropped() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[],"roles":[
                {"id":0,"name":"@everyone","permissions":0},
                {"id":1,"name":"Broken","permissions":0,"color":99999999}
            ]}"#,
        ));
        assert_eq!(plan.roles[0].colour, None);
    }

    #[test]
    fn role_names_are_clamped_and_blank_ones_get_a_fallback() {
        let long = "z".repeat(80);
        let plan = plan_import(&template(&format!(
            r#"{{"name":"g","channels":[],"roles":[
                {{"id":0,"name":"@everyone","permissions":0}},
                {{"id":1,"name":"{long}","permissions":0}},
                {{"id":2,"name":"  ","permissions":0}}
            ]}}"#
        )));

        let names: Vec<&str> = plan.roles.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&FALLBACK_ROLE_NAME));
        assert!(plan
            .roles
            .iter()
            .all(|r| r.name.chars().count() <= NAME_MAX));
    }

    /// Without these, an imported member cannot set a nickname or an avatar —
    /// affordances a normally created Sloga server grants and Discord has no
    /// equivalent of.
    #[test]
    fn sloga_baseline_grants_are_or_ed_into_default_permissions() {
        // Discord @everyone with literally nothing granted.
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[],"roles":[{"id":0,"name":"@everyone","permissions":0}]}"#,
        ));

        for granted in [
            ChannelPermission::React,
            ChannelPermission::ChangeNickname,
            ChannelPermission::ChangeAvatar,
        ] {
            assert!(
                plan.default_permissions & granted as u64 != 0,
                "{granted:?} must survive as a baseline grant"
            );
        }
    }

    /// A template carrying **no roles and no overwrites** has nothing to
    /// resolve, so it is allowed through on Sloga's own new-server default
    /// rather than minting a server nobody can see anything in.
    ///
    /// This is not a general permissive fallback: the moment such a template
    /// also carries a channel overwrite, the mapper refuses — see
    /// `refuses_channel_overwrites_when_no_everyone_role_was_identified`.
    #[test]
    fn a_role_less_template_falls_back_to_slogas_own_default() {
        let plan = plan_import(&template(r#"{"name":"g","channels":[],"roles":[]}"#));

        assert!(plan.roles.is_empty());
        assert!(
            plan.default_permissions & ChannelPermission::ViewChannel as u64 != 0,
            "fallback must still let members see channels"
        );
    }

    // ----------------------------------------------------------------------
    // Channel permission overwrites (slice 1)
    // ----------------------------------------------------------------------

    #[test]
    fn everyone_overwrite_becomes_channel_default_permissions() {
        // Deny VIEW_CHANNEL (1024) to @everyone — a private channel.
        let plan = plan_import(&template(
            r#"{"name":"g","roles":[{"id":0,"name":"@everyone","permissions":0}],
                "channels":[{"id":5,"type":0,"name":"secret","permission_overwrites":[
                    {"id":0,"type":0,"allow":0,"deny":1024}
                ]}]}"#,
        ));

        let default = plan.channels[0].default_permissions.unwrap();
        assert_eq!(default.allow, 0);
        assert_eq!(default.deny, ChannelPermission::ViewChannel as u64);
        assert!(plan.channels[0].role_overrides.is_empty());
    }

    #[test]
    fn role_overwrite_becomes_a_role_override_keyed_by_placeholder_id() {
        let plan = plan_import(&template(
            r#"{"name":"g","roles":[
                    {"id":0,"name":"@everyone","permissions":0},
                    {"id":1,"name":"Staff","permissions":0}
                ],
                "channels":[{"id":5,"type":0,"name":"staff","permission_overwrites":[
                    {"id":0,"type":0,"allow":0,"deny":1024},
                    {"id":1,"type":0,"allow":1024,"deny":0}
                ]}]}"#,
        ));

        let overrides = &plan.channels[0].role_overrides;
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].0, PlaceholderId("1".to_string()));
        assert_eq!(overrides[0].1.allow, ChannelPermission::ViewChannel as u64);
        assert_eq!(overrides[0].1.deny, 0);
    }

    /// Sloga has no per-member channel overrides, and the members are not
    /// coming across anyway — but the user must be told.
    #[test]
    fn member_overwrites_are_skipped_and_noted() {
        let plan = plan_import(&template(
            r#"{"name":"g","roles":[{"id":0,"name":"@everyone","permissions":0}],
                "channels":[{"id":5,"type":0,"name":"c","permission_overwrites":[
                    {"id":"99","type":1,"allow":"1024","deny":"0"}
                ]}]}"#,
        ));

        assert!(plan.channels[0].role_overrides.is_empty());
        assert!(plan.channels[0].default_permissions.is_none());
        assert!(plan
            .skipped
            .iter()
            .any(|note| note.contains("individual Discord members")));
    }

    #[test]
    fn overwrite_for_an_undefined_role_is_dropped_and_noted() {
        let plan = plan_import(&template(
            r#"{"name":"g","roles":[{"id":0,"name":"@everyone","permissions":0}],
                "channels":[{"id":5,"type":0,"name":"c","permission_overwrites":[
                    {"id":404,"type":0,"allow":1024,"deny":0}
                ]}]}"#,
        ));

        assert!(plan.channels[0].role_overrides.is_empty());
        assert!(plan
            .skipped
            .iter()
            .any(|note| note.contains("doesn't contain")));
    }

    /// An overwrite made entirely of permissions Sloga has no equivalent for
    /// must leave the channel inheriting, not pinned to an empty override.
    #[test]
    fn overwrite_of_only_unmapped_bits_writes_nothing() {
        // VIEW_AUDIT_LOG (bit 7 = 128), SEND_TTS_MESSAGES (bit 12 = 4096).
        let plan = plan_import(&template(
            r#"{"name":"g","roles":[{"id":0,"name":"@everyone","permissions":0}],
                "channels":[{"id":5,"type":0,"name":"c","permission_overwrites":[
                    {"id":0,"type":0,"allow":128,"deny":4096}
                ]}]}"#,
        ));

        assert!(
            plan.channels[0].default_permissions.is_none(),
            "an all-unmapped overwrite must not pin the channel's defaults"
        );
    }

    /// Landmine A-6, at the level that matters: the real Discord API sends
    /// permission bitfields as STRINGS (verified live 2026-07-25), while the
    /// documented template example uses integers. Both must reach the same
    /// mapped plan.
    #[test]
    fn string_and_integer_bitfields_produce_identical_plans() {
        let ints = plan_import(&template(
            r#"{"name":"g","roles":[
                    {"id":0,"name":"@everyone","permissions":1024},
                    {"id":1,"name":"Staff","permissions":268435456}
                ],
                "channels":[{"id":5,"type":0,"name":"c","permission_overwrites":[
                    {"id":1,"type":0,"allow":2048,"deny":1024}
                ]}]}"#,
        ));

        let strings = plan_import(&template(
            r#"{"name":"g","roles":[
                    {"id":"0","name":"@everyone","permissions":"1024"},
                    {"id":"1","name":"Staff","permissions":"268435456"}
                ],
                "channels":[{"id":"5","type":0,"name":"c","permission_overwrites":[
                    {"id":"1","type":"0","allow":"2048","deny":"1024"}
                ]}]}"#,
        ));

        assert_eq!(ints.default_permissions, strings.default_permissions);
        assert_eq!(ints.roles, strings.roles);
        assert_eq!(ints.channels, strings.channels);
    }

    /// The whole point of importing a Discord server: a private channel stays
    /// private, and the role that could see it still can.
    #[test]
    fn a_private_discord_channel_maps_to_a_private_sloga_channel() {
        let plan = plan_import(&template(
            r#"{"name":"g","roles":[
                    {"id":0,"name":"@everyone","permissions":1024},
                    {"id":1,"name":"Staff","permissions":0}
                ],
                "channels":[{"id":5,"type":0,"name":"mod-chat","permission_overwrites":[
                    {"id":"0","type":0,"allow":"0","deny":"1024"},
                    {"id":"1","type":0,"allow":"1024","deny":"0"}
                ]}]}"#,
        ));

        let channel = &plan.channels[0];
        let view = ChannelPermission::ViewChannel as u64;

        assert_eq!(channel.default_permissions.unwrap().deny & view, view);
        assert_eq!(channel.role_overrides[0].1.allow & view, view);
    }

    /// A real payload from Discord's own "Blank Server" template
    /// (`2TffvPucqHkN`), captured live 2026-07-25. Its `@everyone` permissions
    /// arrive as a STRING and its role object carries no `position` — the two
    /// facts the role mapping is built on.
    #[test]
    fn real_discord_blank_server_template_plans_cleanly() {
        let payload = r#"{
            "code": "2TffvPucqHkN",
            "name": "Blank Server",
            "description": null,
            "source_guild_id": "197038439483310086",
            "serialized_source_guild": {
                "name": "Blank Server",
                "description": null,
                "system_channel_id": 2,
                "roles": [{"id":0,"name":"@everyone","permissions":"2248329584430657",
                           "color":0,"colors":null,"hoist":false,"mentionable":false,
                           "icon":null,"unicode_emoji":null}],
                "channels": [
                    {"id":1,"type":4,"name":"Text Channels","position":0,"topic":null,
                     "bitrate":64000,"user_limit":0,"nsfw":false,"rate_limit_per_user":0,
                     "parent_id":null,"permission_overwrites":[]},
                    {"id":2,"type":0,"name":"general","position":0,"topic":null,
                     "bitrate":64000,"user_limit":0,"nsfw":false,"rate_limit_per_user":0,
                     "parent_id":1,"permission_overwrites":[]},
                    {"id":3,"type":4,"name":"Voice Channels","position":0,"topic":null,
                     "bitrate":64000,"user_limit":0,"nsfw":false,"rate_limit_per_user":0,
                     "parent_id":null,"permission_overwrites":[]},
                    {"id":4,"type":2,"name":"General","position":0,"topic":null,
                     "bitrate":64000,"user_limit":0,"nsfw":false,"rate_limit_per_user":0,
                     "parent_id":3,"permission_overwrites":[]}
                ]
            }
        }"#;

        let plan = plan_import(&serde_json::from_str(payload).unwrap());

        assert_eq!(plan.server_name, "Blank Server");
        // Only @everyone, which is never a Sloga role.
        assert!(plan.roles.is_empty());
        assert_eq!(plan.categories.len(), 2);
        assert_eq!(plan.channels.len(), 2);

        // The template's user_limit/rate_limit are both 0 — Discord's "off",
        // which must not become an explicit limit of zero.
        assert_eq!(
            plan.channels[1].kind,
            PlannedChannelKind::Voice { max_users: None }
        );

        for granted in [
            ChannelPermission::ViewChannel,
            ChannelPermission::SendMessage,
            ChannelPermission::Connect,
            ChannelPermission::Speak,
            ChannelPermission::ChangeAvatar,
        ] {
            assert!(
                plan.default_permissions & granted as u64 != 0,
                "{granted:?} missing from the imported default permissions"
            );
        }
    }

    // ----------------------------------------------------------------------
    // Fail-closed behaviour (post-audit)
    // ----------------------------------------------------------------------

    /// **The ordering proof.** Discord does not document the direction of the
    /// template role array and gives roles no `position`, so the mapper does
    /// not assume — it requires `@everyone` (definitionally the LEAST
    /// authoritative role) to be first, which is only consistent with an
    /// ascending array.
    ///
    /// Getting this wrong doesn't just invert ranks: the placeholder-0 match
    /// would consume the most powerful role as `@everyone` and write ITS
    /// permissions — plausibly Administrator — into the server defaults, on a
    /// server whose whole purpose is to be handed out via a public invite.
    #[test]
    fn refuses_a_template_whose_roles_do_not_start_with_everyone() {
        // **The shape that matters.** This is what Discord's serializer would
        // emit if the array ran descending: placeholder ids still handed out in
        // array order (0, 1, 2 …), but `@everyone` — the least authoritative —
        // pushed to the END. Note that `roles[0].id` is STILL "0", which is
        // exactly why the check has to be on the name: ids are array indices,
        // so an id-based check would pass this and hand `Admin`'s ADMINISTRATOR
        // to every member of the new server.
        let descending = super::plan_import(&template(
            r#"{"name":"g","channels":[],"roles":[
                {"id":0,"name":"Admin","permissions":8},
                {"id":1,"name":"Moderator","permissions":8192},
                {"id":2,"name":"@everyone","permissions":1024}
            ]}"#,
        ));
        assert_eq!(descending, Err(PlanError::UnexpectedRoleOrder));

        // Roles present but no @everyone at all: equally unrecognised.
        let no_everyone = super::plan_import(&template(
            r#"{"name":"g","channels":[],"roles":[{"id":0,"name":"Admin","permissions":8}]}"#,
        ));
        assert_eq!(no_everyone, Err(PlanError::UnexpectedRoleOrder));

        // Name right but id wrong — ids are array indices, so this cannot come
        // from Discord's serializer and something is being misread.
        let renumbered = super::plan_import(&template(
            r#"{"name":"g","channels":[],"roles":[{"id":7,"name":"@everyone","permissions":0}]}"#,
        ));
        assert_eq!(renumbered, Err(PlanError::UnexpectedRoleOrder));

        // A template with no roles at all is fine — nothing to order.
        assert!(super::plan_import(&template(r#"{"name":"g","channels":[],"roles":[]}"#)).is_ok());
    }

    /// `plan_overwrites` must resolve the channel's `@everyone` entry against
    /// the id `plan_roles` handed it, never a hard-coded `"0"`.
    ///
    /// Today those are the same value, because `plan_roles` asserts
    /// `roles[0].id == "0"` — so this drives `plan_overwrites` directly to
    /// exercise a divergence the public entry point cannot produce. Without it,
    /// anyone relaxing that id assertion would silently re-open the fail-open
    /// hole where a private channel's `@everyone` overwrite is filed as a role
    /// override, dropped as dangling, and the channel comes out world-readable.
    #[test]
    fn plan_overwrites_matches_a_non_zero_everyone_id() {
        let overwrites: Vec<super::super::template::TemplateOverwrite> = serde_json::from_str(
            r#"[{"id":7,"type":0,"allow":0,"deny":1024},
                {"id":8,"type":0,"allow":1024,"deny":0}]"#,
        )
        .unwrap();

        let staff = PlannedRole {
            template_id: PlaceholderId("8".to_string()),
            name: "Staff".to_string(),
            colour: None,
            hoist: false,
            permissions: 0,
            administrator: false,
        };

        let planned = plan_overwrites(
            &overwrites,
            std::slice::from_ref(&staff),
            Some(&PlaceholderId("7".to_string())),
        )
        .expect("should plan");

        assert_eq!(
            planned.default_permissions.unwrap().deny,
            ChannelPermission::ViewChannel as u64,
            "the @everyone overwrite must be routed by the THREADED id, not a \
             hard-coded \"0\""
        );
        assert_eq!(planned.role_overrides.len(), 1);
        assert_eq!(planned.dangling_skipped, 0);
    }

    /// The last fail-OPEN path in an otherwise fail-closed mapper: with no
    /// `@everyone` identified, a channel's `@everyone` overwrite falls through
    /// the role match, is dropped as "dangling", and the channel inherits a
    /// server default that grants ViewChannel — a private Discord channel
    /// arriving world-readable, with only a misleading note to show for it.
    #[test]
    fn refuses_channel_overwrites_when_no_everyone_role_was_identified() {
        let result = super::plan_import(&template(
            r#"{"name":"g","roles":[],
                "channels":[{"id":5,"type":0,"name":"secret","permission_overwrites":[
                    {"id":0,"type":0,"allow":0,"deny":1024}
                ]}]}"#,
        ));
        assert_eq!(result, Err(PlanError::UnexpectedRoleOrder));

        // No roles AND no overwrites is still fine — nothing to resolve.
        assert!(super::plan_import(&template(
            r#"{"name":"g","roles":[],
                "channels":[{"id":5,"type":0,"name":"open","permission_overwrites":[]}]}"#,
        ))
        .is_ok());
    }

    /// An overwrite type outside the documented role/member pair means we
    /// cannot tell who a permission applies to. Dropping it turns a
    /// `deny VIEW_CHANNEL` into a world-readable channel while the UI promises
    /// "private channels included", so the import stops instead.
    #[test]
    fn refuses_an_overwrite_with_an_unrecognised_target_type() {
        let result = super::plan_import(&template(
            r#"{"name":"g","roles":[{"id":0,"name":"@everyone","permissions":0}],
                "channels":[{"id":5,"type":0,"name":"c","permission_overwrites":[
                    {"id":0,"type":7,"allow":0,"deny":1024}
                ]}]}"#,
        ));
        assert_eq!(result, Err(PlanError::UnknownOverwriteKind));

        // A missing `type` is the same problem — it defaults to Unknown.
        let missing = super::plan_import(&template(
            r#"{"name":"g","roles":[{"id":0,"name":"@everyone","permissions":0}],
                "channels":[{"id":5,"type":0,"name":"c","permission_overwrites":[
                    {"id":0,"allow":0,"deny":1024}
                ]}]}"#,
        ));
        assert_eq!(missing, Err(PlanError::UnknownOverwriteKind));
    }

    /// Discord's ADMINISTRATOR bypasses channel overwrites entirely; Sloga
    /// grants that bypass to the server OWNER only, so for anyone else holding
    /// the role it has to be written out per channel.
    ///
    /// Without this an imported admin cannot see a single private channel —
    /// and a one-account smoke test would never notice, because the owner
    /// bypasses everything anyway.
    #[test]
    fn administrator_roles_are_granted_access_to_restricted_channels() {
        let plan = plan_import(&template(
            r#"{"name":"g","roles":[
                    {"id":0,"name":"@everyone","permissions":1024},
                    {"id":1,"name":"Member","permissions":0},
                    {"id":2,"name":"Admin","permissions":8}
                ],
                "channels":[
                    {"id":5,"type":0,"name":"mod-chat","permission_overwrites":[
                        {"id":0,"type":0,"allow":0,"deny":1024}
                    ]},
                    {"id":6,"type":0,"name":"general","permission_overwrites":[]}
                ]}"#,
        ));

        let admin = plan
            .roles
            .iter()
            .find(|role| role.name == "Admin")
            .expect("admin role");
        assert!(admin.administrator);

        let private = plan
            .channels
            .iter()
            .find(|channel| channel.name == "mod-chat")
            .unwrap();
        let granted = private
            .role_overrides
            .iter()
            .find(|(id, _)| id == &admin.template_id)
            .expect("admin must be granted access to the restricted channel");
        assert_eq!(granted.1.allow, ChannelPermission::GrantAllSafe as u64);
        assert_eq!(granted.1.deny, 0);

        // An unrestricted channel needs no entry — the server-wide grant covers
        // it, and writing one everywhere would be noise.
        let public = plan
            .channels
            .iter()
            .find(|channel| channel.name == "general")
            .unwrap();
        assert!(public.role_overrides.is_empty());
    }

    /// An explicit overwrite on an admin is inert on Discord (ADMINISTRATOR
    /// short-circuits before overwrites are read), so a deny must not survive
    /// the import as a real restriction.
    #[test]
    fn an_explicit_deny_on_an_administrator_is_overridden_not_merged() {
        let plan = plan_import(&template(
            r#"{"name":"g","roles":[
                    {"id":0,"name":"@everyone","permissions":0},
                    {"id":1,"name":"Admin","permissions":8}
                ],
                "channels":[{"id":5,"type":0,"name":"c","permission_overwrites":[
                    {"id":1,"type":0,"allow":0,"deny":1024}
                ]}]}"#,
        ));

        let override_ = &plan.channels[0].role_overrides[0].1;
        assert_eq!(override_.deny, 0);
        assert_eq!(override_.allow, ChannelPermission::GrantAllSafe as u64);
    }

    /// A guild whose `@everyone` holds Administrator produces a server where
    /// every invitee can ban and manage roles. Faithful, but it must not be
    /// silent — this feature's output is a link meant to be posted publicly.
    #[test]
    fn everyone_with_administrator_is_called_out_loudly() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[],"roles":[{"id":0,"name":"@everyone","permissions":8}]}"#,
        ));

        assert_eq!(
            plan.default_permissions & ChannelPermission::GrantAllSafe as u64,
            ChannelPermission::GrantAllSafe as u64
        );
        assert!(plan
            .skipped
            .iter()
            .any(|note| note.contains("Administrator")));
    }

    /// Placeholder ids are integers rendered as strings, and real templates tie
    /// on `position` constantly (Discord's own Blank Server gives all four
    /// channels position 0). Sorting the ids as strings puts "10" before "2".
    #[test]
    fn tied_positions_break_numerically_not_lexicographically() {
        let plan = plan_import(&template(
            r#"{"name":"g","roles":[],"channels":[
                {"id":10,"type":0,"name":"ten","position":0},
                {"id":2,"type":0,"name":"two","position":0},
                {"id":1,"type":0,"name":"one","position":0}
            ]}"#,
        ));

        assert_eq!(
            plan.channels
                .iter()
                .map(|channel| channel.name.as_str())
                .collect::<Vec<_>>(),
            vec!["one", "two", "ten"]
        );
    }

    /// A partial `position` rollout must not sort real positions against array
    /// indices — two incompatible scales.
    #[test]
    fn position_is_only_trusted_when_every_role_has_one() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[],"roles":[
                {"id":0,"name":"@everyone","permissions":0},
                {"id":1,"name":"Low","permissions":0},
                {"id":2,"name":"High","permissions":0,"position":99}
            ]}"#,
        ));

        // "High" carries a position but "Low" does not, so array order wins and
        // the last element is still the most authoritative.
        assert_eq!(
            plan.roles
                .iter()
                .map(|role| role.name.as_str())
                .collect::<Vec<_>>(),
            vec!["High", "Low"]
        );
    }

    /// The summary's skipped count is rendered next to the prose notes, so the
    /// two must agree: anything the mapper drops has to be countable, not just
    /// described.
    #[test]
    fn skipped_channel_count_matches_what_was_dropped() {
        let plan = plan_import(&template(
            r#"{"name":"g","channels":[
                {"id":1,"type":0,"name":"keep"},
                {"id":2,"type":11,"name":"thread"},
                {"id":3,"type":12,"name":"thread two"},
                {"id":4,"type":14,"name":"directory"}
            ]}"#,
        ));
        assert_eq!(plan.channels.len(), 1);
        assert_eq!(plan.skipped_channel_count, 3);
        assert!(!plan.skipped.is_empty());
    }
}
