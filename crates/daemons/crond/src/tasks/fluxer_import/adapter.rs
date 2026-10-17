//! Fluxer guild → the Discord mapper's [`GuildTemplate`].
//!
//! Fluxer uses Discord's permission numbering, channel types and overwrite
//! model, so a fetched guild is rewritten into the template shape and goes
//! through the same mapper as a Discord import (`plan_import_from` with
//! `SourceLabel::Fluxer`). What the rewrite has to get right, because the
//! mapper relies on it:
//!
//! * **`@everyone`.** On Fluxer it is the role whose id is the guild id. The
//!   mapper expects it FIRST, with id `"0"` and name `@everyone`. A guild
//!   without it fails closed (`UnexpectedRoleOrder`): its channel denies
//!   could not be told from role denies.
//! * **The `@everyone` overwrite.** Every overwrite whose id is the guild id
//!   becomes `"0"` too. Left as the guild id it would not match `@everyone`,
//!   be dropped as pointing at an unknown role, and a channel that was
//!   private on Fluxer would come over readable by everyone.
//! * **Role order.** Fluxer ranks a higher `position` above a lower one and,
//!   at a tie, the LOWER id above the higher (`GuildRoleService.ts`). The
//!   mapper reads positions and, at a tie, ranks the later array entry
//!   higher. So the roles are sorted (position ascending, id descending) and
//!   renumbered 1..n: no ties are left for the mapper to break.
//! * **Roles that are not the server's.** The roles the bot holds (its
//!   install role, which keeps the bot's permissions) and the role that
//!   carried the verification code are dropped, with every overwrite on
//!   them.
//! * **Channel types.** Fluxer has link channels (998), which the mapper's
//!   `u8` cannot hold. Types the mapper knows pass through; everything else
//!   becomes 255, which the mapper skips and counts.
//! * **Age restriction.** A channel's own setting wins, then its category's,
//!   then the guild's; an explicit `false` at any step stops the walk.
//!
//! Notes for the user are returned alongside; the caller appends them to
//! the plan's.

use std::collections::{HashMap, HashSet};

use revolt_database::util::import_challenge::ADMINISTRATOR;

use super::source::{ChannelType, FluxerChannel, FluxerEmoji, FluxerGuild, FluxerRole, Snowflake};
use crate::tasks::discord_import::mapper::{AssetKind, PlanError, PlannedAsset, PlannedEmoji};
use crate::tasks::discord_import::template::{
    channel_type, DiscordBits, GuildTemplate, PlaceholderId, SerializedGuild, TemplateChannel,
    TemplateOverwrite, TemplateRole,
};

/// The id and name the mapper requires of `@everyone`.
const EVERYONE_ID: &str = "0";
const EVERYONE_NAME: &str = "@everyone";

/// What a Fluxer bot-install role is called when the bot's own role has no
/// usable name.
const FALLBACK_BOT_ROLE_NAME: &str = "Sloga Importer";

/// Longest role name quoted in a note (Fluxer allows 100 characters).
const QUOTED_NAME_MAX: usize = 100;

/// Fluxer-only permissions with no Sloga equivalent, which the shared bit
/// table drops without a word.
const UPDATE_RTC_REGION: u64 = 1 << 53;
const VIEW_CHANNEL_MEMBERS: u64 = 1 << 54;
const FLUXER_ONLY_BITS: u64 = UPDATE_RTC_REGION | VIEW_CHANNEL_MEMBERS;

/// Fluxer's link channel.
const GUILD_LINK: i64 = 998;

/// The type the mapper skips as "a type Sloga doesn't have".
const UNSUPPORTED: u8 = 255;

/// Channel types handed to the mapper as they are. Threads (10-12) are
/// among them: the mapper skips those with its own note.
const PASSED_THROUGH: [u8; 9] = [
    channel_type::GUILD_TEXT,
    channel_type::GUILD_VOICE,
    channel_type::GUILD_CATEGORY,
    channel_type::GUILD_ANNOUNCEMENT,
    10,
    11,
    12,
    channel_type::GUILD_FORUM,
    channel_type::GUILD_MEDIA,
];

/// A Fluxer guild rewritten for the mapper, plus what the mapper does not
/// read.
#[derive(Debug)]
pub(crate) struct Adapted {
    pub template: GuildTemplate,
    /// The guild's adult-content flag, for `ImportPlan::nsfw`.
    pub nsfw: bool,
    pub icon: Option<PlannedAsset>,
    pub banner: Option<PlannedAsset>,
    /// Every emoji; the worker applies the new server's emoji cap.
    pub emojis: Vec<PlannedEmoji>,
    /// Notes to append to the plan's.
    pub notes: Vec<String>,
}

fn placeholder(id: Snowflake) -> PlaceholderId {
    PlaceholderId(id.to_string())
}

fn planned_image(kind: AssetKind, hash: Option<&str>) -> Option<PlannedAsset> {
    hash.filter(|hash| !hash.is_empty())
        .map(|hash| PlannedAsset {
            kind,
            id: hash.to_string(),
            animated: hash.starts_with("a_"),
        })
}

fn planned_emoji(emoji: &FluxerEmoji) -> PlannedEmoji {
    PlannedEmoji {
        // A blank name is refused (with a note) by the worker.
        name: emoji.name.clone().unwrap_or_default(),
        asset: PlannedAsset {
            kind: AssetKind::Emoji,
            id: emoji.id.to_string(),
            animated: emoji.animated.unwrap_or(false),
        },
    }
}

/// The channel's own age restriction: `nsfw_override` when set. A channel
/// whose `nsfw` alone says true (an older answer without the override
/// field) counts as set.
fn own_nsfw(channel: &FluxerChannel) -> Option<bool> {
    channel
        .nsfw_override
        .or_else(|| channel.nsfw.filter(|nsfw| *nsfw))
}

/// Rewrite a fetched guild for the mapper.
///
/// `roles` and `channels` are what the bot read; `bot_role_ids` are the
/// roles it holds; `challenge_role` is the role that proved ownership.
pub(crate) fn adapt(
    guild: &FluxerGuild,
    roles: &[FluxerRole],
    channels: &[FluxerChannel],
    bot_role_ids: &[Snowflake],
    challenge_role: Snowflake,
) -> Result<Adapted, PlanError> {
    let guild_id = guild.id;
    let mut notes: Vec<String> = Vec::new();

    // `@everyone` is the role whose id is the guild id. Without it nothing
    // tells the channels' `@everyone` denies from role denies.
    let Some(everyone) = roles.iter().find(|role| role.id == guild_id) else {
        return Err(PlanError::UnexpectedRoleOrder);
    };

    let dropped: HashSet<Snowflake> = bot_role_ids
        .iter()
        .copied()
        .chain(std::iter::once(challenge_role))
        .filter(|id| *id != guild_id)
        .collect();
    let bot_roles: Vec<&FluxerRole> = roles
        .iter()
        .filter(|role| role.id != guild_id && bot_role_ids.contains(&role.id))
        .collect();

    // Most authoritative last, as the mapper reads positions: position
    // ascending, and at a tie the higher id first (Fluxer ranks the lower
    // id higher). Renumbered so no tie is left.
    let mut kept: Vec<&FluxerRole> = roles
        .iter()
        .filter(|role| role.id != guild_id && !dropped.contains(&role.id))
        .collect();
    kept.sort_by(|a, b| {
        a.position
            .unwrap_or(0)
            .cmp(&b.position.unwrap_or(0))
            .then_with(|| b.id.cmp(&a.id))
    });

    let mut template_roles = vec![TemplateRole {
        id: PlaceholderId(EVERYONE_ID.to_string()),
        name: EVERYONE_NAME.to_string(),
        permissions: DiscordBits(everyone.permissions.0),
        color: 0,
        hoist: false,
        mentionable: false,
        position: Some(0),
    }];
    for (index, role) in kept.iter().enumerate() {
        template_roles.push(TemplateRole {
            id: placeholder(role.id),
            name: role.name.clone().unwrap_or_default(),
            permissions: DiscordBits(role.permissions.0),
            color: role.color.unwrap_or(0),
            hoist: role.hoist.unwrap_or(false),
            mentionable: false,
            position: Some(index as i64 + 1),
        });
    }

    // Fluxer gives every new guild's `@everyone` View Channel Members, and
    // Sloga lets every member see the member list, so that bit there loses
    // nothing; anywhere else it is a setting that did not come over.
    let mut fluxer_only = everyone.permissions.0 & UPDATE_RTC_REGION != 0
        || kept
            .iter()
            .any(|role| role.permissions.0 & FLUXER_ONLY_BITS != 0);

    // Age restriction walks channel → category → guild.
    let guild_nsfw = guild.nsfw.unwrap_or(false);
    let category_nsfw: HashMap<Snowflake, Option<bool>> = channels
        .iter()
        .filter(|channel| channel.channel_type == ChannelType(Some(4)))
        .map(|channel| (channel.id, own_nsfw(channel)))
        .collect();

    let mut link_channels = 0usize;
    let mut template_channels = Vec::with_capacity(channels.len());
    for channel in channels {
        let is_category = channel.channel_type == ChannelType(Some(4));
        let channel_type = match channel.channel_type.0 {
            Some(kind) => match u8::try_from(kind) {
                Ok(kind) if PASSED_THROUGH.contains(&kind) => kind,
                _ => {
                    if kind == GUILD_LINK {
                        link_channels += 1;
                    }
                    UNSUPPORTED
                }
            },
            None => UNSUPPORTED,
        };

        let nsfw = own_nsfw(channel)
            .or_else(|| {
                (!is_category)
                    .then_some(channel.parent_id)
                    .flatten()
                    .and_then(|parent| category_nsfw.get(&parent).copied().flatten())
            })
            .unwrap_or(guild_nsfw);

        let mut overwrites = Vec::with_capacity(channel.permission_overwrites.len());
        for overwrite in &channel.permission_overwrites {
            if dropped.contains(&overwrite.id) {
                continue;
            }
            if (overwrite.allow.0 | overwrite.deny.0) & FLUXER_ONLY_BITS != 0 {
                fluxer_only = true;
            }
            overwrites.push(TemplateOverwrite {
                id: if overwrite.id == guild_id {
                    PlaceholderId(EVERYONE_ID.to_string())
                } else {
                    placeholder(overwrite.id)
                },
                kind: overwrite.kind,
                allow: DiscordBits(overwrite.allow.0),
                deny: DiscordBits(overwrite.deny.0),
            });
        }

        template_channels.push(TemplateChannel {
            id: placeholder(channel.id),
            channel_type,
            name: channel.name.clone(),
            position: channel.position.unwrap_or(0),
            topic: channel.topic.clone(),
            nsfw,
            rate_limit_per_user: channel.rate_limit_per_user,
            user_limit: channel.user_limit,
            bitrate: channel.bitrate,
            parent_id: channel.parent_id.map(placeholder),
            permission_overwrites: overwrites,
        });
    }

    if link_channels > 0 {
        notes.push(format!(
            "{link_channels} of the skipped channels were Fluxer link channels, which Sloga \
             doesn't have."
        ));
    }
    if fluxer_only {
        notes.push(
            "Fluxer's Update Voice Region and View Channel Members permissions have no Sloga \
             equivalent and were not imported."
                .to_string(),
        );
    }

    // Fluxer lists only the channels the bot can view; with Administrator
    // it views them all.
    let bot_is_admin = everyone.permissions.0 & ADMINISTRATOR != 0
        || bot_roles
            .iter()
            .any(|role| role.permissions.0 & ADMINISTRATOR != 0);
    if !bot_is_admin {
        notes.push(
            "The importer bot didn't have Administrator on Fluxer, so channels it couldn't see \
             were not imported. To include them, give the bot Administrator and import again."
                .to_string(),
        );
    }

    let bot_role_name: String = bot_roles
        .iter()
        .find_map(|role| role.name.as_deref())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(FALLBACK_BOT_ROLE_NAME)
        .chars()
        .take(QUOTED_NAME_MAX)
        .collect();
    notes.push(format!(
        "Delete the '{bot_role_name}' role on Fluxer: it was made for the importer bot, keeps \
         the permissions the bot was added with, and stays after the bot leaves. You can delete \
         your verification role too. Neither was imported."
    ));

    let emojis = match &guild.emojis {
        Some(emojis) => emojis.iter().map(planned_emoji).collect(),
        None => {
            notes.push(
                "Your Fluxer server's emoji couldn't be read and were not imported.".to_string(),
            );
            Vec::new()
        }
    };

    let template = GuildTemplate {
        code: "fluxer".to_string(),
        name: guild.name.clone().unwrap_or_default(),
        description: None,
        source_guild_id: None,
        serialized_source_guild: SerializedGuild {
            name: guild.name.clone(),
            description: None,
            roles: template_roles,
            channels: template_channels,
            system_channel_id: guild.system_channel_id.map(placeholder),
            afk_channel_id: guild.afk_channel_id.map(placeholder),
            afk_timeout: guild.afk_timeout,
        },
    };

    Ok(Adapted {
        template,
        nsfw: guild_nsfw,
        icon: planned_image(AssetKind::Icon, guild.icon.as_deref()),
        banner: planned_image(AssetKind::Banner, guild.banner.as_deref()),
        emojis,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::discord_import::mapper::{plan_import_from, PlannedChannel, SourceLabel};
    use crate::tasks::discord_import::template::OverwriteKind;
    use revolt_permissions::ChannelPermission;
    use serde_json::{json, Value};

    const GUILD: Snowflake = Snowflake(1_300_000_000_000_000_100);
    const BOT_ROLE: Snowflake = Snowflake(1_300_000_000_000_000_201);
    const CODE_ROLE: Snowflake = Snowflake(1_300_000_000_000_000_202);
    const MOD: Snowflake = Snowflake(1_300_000_000_000_000_203);

    const VIEW: u64 = 1 << 10;
    const SEND: u64 = 1 << 11;
    const MANAGE_GUILD: u64 = 1 << 5;

    fn guild(extra: Value) -> FluxerGuild {
        let mut value =
            json!({ "id": GUILD.to_string(), "name": "Flux Place", "nsfw": false, "emojis": [] });
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(value).unwrap()
    }

    fn roles(value: Value) -> Vec<FluxerRole> {
        serde_json::from_value(value).unwrap()
    }

    fn channels(value: Value) -> Vec<FluxerChannel> {
        serde_json::from_value(value).unwrap()
    }

    /// `@everyone`, the bot's install role (Administrator), the code role
    /// and a moderator.
    fn base_roles() -> Value {
        json!([
            { "id": MOD.to_string(), "name": "Mod", "permissions": "8192", "position": 3 },
            { "id": CODE_ROLE.to_string(), "name": "sloga-import-ABCDEFGH",
              "permissions": MANAGE_GUILD.to_string(), "position": 2 },
            { "id": BOT_ROLE.to_string(), "name": "Sloga Importer", "permissions": "8",
              "position": 1 },
            { "id": GUILD.to_string(), "name": "@everyone",
              "permissions": (VIEW | SEND | VIEW_CHANNEL_MEMBERS).to_string(), "position": 0 }
        ])
    }

    fn adapt_ok(guild: &FluxerGuild, roles: &[FluxerRole], channels: &[FluxerChannel]) -> Adapted {
        adapt(guild, roles, channels, &[BOT_ROLE], CODE_ROLE).expect("adapted")
    }

    fn planned(
        plan: &crate::tasks::discord_import::mapper::ImportPlan,
        id: Snowflake,
    ) -> &PlannedChannel {
        plan.channels
            .iter()
            .find(|channel| channel.template_id.0 == id.to_string())
            .unwrap_or_else(|| panic!("channel {id} not planned"))
    }

    /// The everyone overwrite on Fluxer carries the GUILD id. Rewritten to
    /// the mapper's `"0"`, the channel stays private; left alone it would be
    /// dropped as a dangling role overwrite and the channel would come over
    /// public.
    #[test]
    fn a_private_fluxer_channel_stays_private() {
        let private = Snowflake(1_300_000_000_000_000_301);
        let fetched = channels(json!([
            { "id": private.to_string(), "type": 0, "name": "staff", "position": 0,
              "permission_overwrites": [
                { "id": GUILD.to_string(), "type": 0, "allow": "0", "deny": VIEW.to_string() },
                { "id": MOD.to_string(), "type": 0, "allow": VIEW.to_string(), "deny": "0" }
              ] }
        ]));
        let adapted = adapt_ok(&guild(json!({})), &roles(base_roles()), &fetched);

        let overwrites =
            &adapted.template.serialized_source_guild.channels[0].permission_overwrites;
        assert_eq!(overwrites[0].id, PlaceholderId("0".to_string()));

        let plan = plan_import_from(&adapted.template, SourceLabel::Fluxer).unwrap();
        let staff = planned(&plan, private);
        let everyone = staff
            .default_permissions
            .expect("the @everyone deny is kept");
        assert_ne!(everyone.deny & ChannelPermission::ViewChannel as u64, 0);
        assert!(!crate::tasks::discord_import::mapper::everyone_can_view(
            plan.default_permissions,
            staff.default_permissions
        ));
        assert_eq!(
            staff.role_overrides,
            vec![(
                placeholder(MOD),
                crate::tasks::discord_import::mapper::PlannedOverride {
                    allow: ChannelPermission::ViewChannel as u64,
                    deny: 0
                }
            )]
        );
        assert!(
            !plan
                .skipped
                .iter()
                .any(|note| note.contains("pointed at a role")),
            "{:?}",
            plan.skipped
        );
    }

    #[test]
    fn the_bot_role_and_the_code_role_are_dropped_with_their_overwrites() {
        let channel = Snowflake(1_300_000_000_000_000_302);
        let fetched = channels(json!([
            { "id": channel.to_string(), "type": 0, "name": "general",
              "permission_overwrites": [
                { "id": BOT_ROLE.to_string(), "type": 0, "allow": VIEW.to_string(), "deny": "0" },
                { "id": CODE_ROLE.to_string(), "type": 0, "allow": "0", "deny": SEND.to_string() },
                { "id": MOD.to_string(), "type": 0, "allow": SEND.to_string(), "deny": "0" }
              ] }
        ]));
        let adapted = adapt_ok(&guild(json!({})), &roles(base_roles()), &fetched);

        let names: Vec<&str> = adapted
            .template
            .serialized_source_guild
            .roles
            .iter()
            .map(|role| role.name.as_str())
            .collect();
        assert_eq!(names, vec!["@everyone", "Mod"]);
        let overwrites =
            &adapted.template.serialized_source_guild.channels[0].permission_overwrites;
        assert_eq!(overwrites.len(), 1);
        assert_eq!(overwrites[0].id, placeholder(MOD));

        // Nothing the mapper would call dangling, and the bot role's name in
        // the leftover-role note.
        let plan = plan_import_from(&adapted.template, SourceLabel::Fluxer).unwrap();
        assert!(!plan.skipped.iter().any(|n| n.contains("pointed at a role")));
        assert_eq!(plan.roles.len(), 1);
        assert!(
            adapted
                .notes
                .iter()
                .any(|note| note.starts_with("Delete the 'Sloga Importer' role on Fluxer")),
            "{:?}",
            adapted.notes
        );
    }

    #[test]
    fn the_leftover_role_note_names_the_bot_role_or_falls_back() {
        let mut renamed = base_roles();
        renamed[2]["name"] = json!("My Bot Role");
        let adapted = adapt_ok(&guild(json!({})), &roles(renamed), &[]);
        assert!(adapted
            .notes
            .iter()
            .any(|note| note.starts_with("Delete the 'My Bot Role' role")));

        let mut blank = base_roles();
        blank[2]["name"] = json!("  ");
        let adapted = adapt_ok(&guild(json!({})), &roles(blank), &[]);
        assert!(adapted
            .notes
            .iter()
            .any(|note| note.starts_with("Delete the 'Sloga Importer' role")));
    }

    /// Two roles at the same position: Fluxer ranks the LOWER id higher, so
    /// it must come out first (rank 0) in the plan.
    #[test]
    fn tied_positions_rank_the_lower_id_higher() {
        let low = Snowflake(1_300_000_000_000_000_210);
        let high = Snowflake(1_300_000_000_000_000_220);
        let fetched = roles(json!([
            // Listed in the order that would win with the mapper's own tie
            // break (later entry higher) if the adapter left the tie.
            { "id": low.to_string(), "name": "Low id", "permissions": "0", "position": 5 },
            { "id": high.to_string(), "name": "High id", "permissions": "0", "position": 5 },
            { "id": MOD.to_string(), "name": "Mod", "permissions": "0", "position": 2 },
            { "id": GUILD.to_string(), "name": "@everyone", "permissions": "0", "position": 0 }
        ]));
        let adapted = adapt(&guild(json!({})), &fetched, &[], &[], CODE_ROLE).unwrap();

        let positions: Vec<(&str, Option<i64>)> = adapted
            .template
            .serialized_source_guild
            .roles
            .iter()
            .map(|role| (role.name.as_str(), role.position))
            .collect();
        assert_eq!(
            positions,
            vec![
                ("@everyone", Some(0)),
                ("Mod", Some(1)),
                ("High id", Some(2)),
                ("Low id", Some(3))
            ]
        );

        let plan = plan_import_from(&adapted.template, SourceLabel::Fluxer).unwrap();
        let order: Vec<&str> = plan.roles.iter().map(|role| role.name.as_str()).collect();
        assert_eq!(order, vec!["Low id", "High id", "Mod"]);

        // Listed the other way round, the result is the same.
        let mut reversed = fetched.clone();
        reversed.swap(0, 1);
        let adapted = adapt(&guild(json!({})), &reversed, &[], &[], CODE_ROLE).unwrap();
        let plan = plan_import_from(&adapted.template, SourceLabel::Fluxer).unwrap();
        let order: Vec<&str> = plan.roles.iter().map(|role| role.name.as_str()).collect();
        assert_eq!(order, vec!["Low id", "High id", "Mod"]);
    }

    #[test]
    fn link_channels_and_unknown_types_are_skipped_with_a_note() {
        let fetched = channels(json!([
            { "id": "1300000000000000401", "type": 0, "name": "general", "permission_overwrites": [] },
            { "id": "1300000000000000402", "type": 998, "name": "website",
              "url": "https://example.com", "permission_overwrites": [] },
            { "id": "1300000000000000403", "type": 77777, "name": "future", "permission_overwrites": [] },
            { "id": "1300000000000000404", "type": 11, "name": "a thread", "permission_overwrites": [] },
            { "id": "1300000000000000405", "type": 15, "name": "forum", "permission_overwrites": [] }
        ]));
        let adapted = adapt_ok(&guild(json!({})), &roles(base_roles()), &fetched);
        let types: Vec<u8> = adapted
            .template
            .serialized_source_guild
            .channels
            .iter()
            .map(|channel| channel.channel_type)
            .collect();
        assert_eq!(types, vec![0, 255, 255, 11, 15]);
        assert!(adapted
            .notes
            .iter()
            .any(|note| note.starts_with("1 of the skipped channels were Fluxer link channels")));

        let plan = plan_import_from(&adapted.template, SourceLabel::Fluxer).unwrap();
        let names: Vec<&str> = plan.channels.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["general", "forum"]);
        assert_eq!(plan.skipped_channel_count, 3);
    }

    /// Channel → category → guild, an explicit false stopping the walk.
    #[test]
    fn age_restriction_is_resolved_channel_then_category_then_guild() {
        let fetched = channels(json!([
            { "id": "11", "type": 4, "name": "Adult", "nsfw": true, "nsfw_override": true,
              "permission_overwrites": [] },
            { "id": "12", "type": 4, "name": "Inherit", "nsfw": false, "nsfw_override": null,
              "permission_overwrites": [] },
            // Explicitly SFW inside the adult category.
            { "id": "21", "type": 0, "name": "sfw-in-adult", "parent_id": "11",
              "nsfw": false, "nsfw_override": false, "permission_overwrites": [] },
            // Inherits the adult category.
            { "id": "22", "type": 0, "name": "inherits-adult", "parent_id": "11",
              "nsfw": false, "nsfw_override": null, "permission_overwrites": [] },
            // Inherits through an inheriting category to the guild.
            { "id": "23", "type": 0, "name": "inherits-guild", "parent_id": "12",
              "nsfw_override": null, "permission_overwrites": [] },
            // Its own setting.
            { "id": "24", "type": 0, "name": "own-adult", "parent_id": "12",
              "nsfw": true, "nsfw_override": true, "permission_overwrites": [] },
            // An older answer with only `nsfw`.
            { "id": "25", "type": 0, "name": "legacy", "nsfw": true,
              "permission_overwrites": [] }
        ]));
        let nsfw_of = |guild_nsfw: bool| -> HashMap<String, bool> {
            adapt_ok(
                &guild(json!({ "nsfw": guild_nsfw })),
                &roles(base_roles()),
                &fetched,
            )
            .template
            .serialized_source_guild
            .channels
            .iter()
            .map(|channel| (channel.name.clone().unwrap(), channel.nsfw))
            .collect()
        };

        let sfw_guild = nsfw_of(false);
        assert!(!sfw_guild["sfw-in-adult"]);
        assert!(sfw_guild["inherits-adult"]);
        assert!(!sfw_guild["inherits-guild"]);
        assert!(sfw_guild["own-adult"]);
        assert!(sfw_guild["legacy"]);

        let adult_guild = nsfw_of(true);
        assert!(
            !adult_guild["sfw-in-adult"],
            "explicit SFW wins over the guild"
        );
        assert!(adult_guild["inherits-guild"]);

        // The mapper carries the flag onto the planned channel.
        let adapted = adapt_ok(&guild(json!({})), &roles(base_roles()), &fetched);
        let plan = plan_import_from(&adapted.template, SourceLabel::Fluxer).unwrap();
        assert!(!planned(&plan, Snowflake(21)).nsfw);
        assert!(planned(&plan, Snowflake(22)).nsfw);
        assert!(!adapted.nsfw);
        assert!(adapt_ok(&guild(json!({ "nsfw": true })), &roles(base_roles()), &[]).nsfw);
    }

    #[test]
    fn fluxer_only_bits_are_noted_only_when_set() {
        let note = |adapted: &Adapted| {
            adapted
                .notes
                .iter()
                .any(|note| note.contains("Update Voice Region and View Channel Members"))
        };

        // Base: only `@everyone`'s default View Channel Members.
        assert!(!note(&adapt_ok(
            &guild(json!({})),
            &roles(base_roles()),
            &[]
        )));

        let mut on_role = base_roles();
        on_role[0]["permissions"] = json!((1u64 << 53).to_string());
        assert!(note(&adapt_ok(&guild(json!({})), &roles(on_role), &[])));

        let mut on_everyone = base_roles();
        on_everyone[3]["permissions"] = json!((VIEW | (1u64 << 53)).to_string());
        assert!(note(&adapt_ok(&guild(json!({})), &roles(on_everyone), &[])));

        let with_overwrite = channels(json!([
            { "id": "31", "type": 0, "name": "c", "permission_overwrites": [
                { "id": GUILD.to_string(), "type": 0, "allow": "0",
                  "deny": VIEW_CHANNEL_MEMBERS.to_string() } ] }
        ]));
        assert!(note(&adapt_ok(
            &guild(json!({})),
            &roles(base_roles()),
            &with_overwrite
        )));

        // On a dropped role it is not the server's setting.
        let mut on_bot = base_roles();
        on_bot[2]["permissions"] = json!((8u64 | (1u64 << 54)).to_string());
        assert!(!note(&adapt_ok(&guild(json!({})), &roles(on_bot), &[])));
    }

    #[test]
    fn a_missing_everyone_role_fails_closed() {
        let mut without = base_roles();
        without.as_array_mut().unwrap().remove(3);
        assert_eq!(
            adapt(
                &guild(json!({})),
                &roles(without),
                &[],
                &[BOT_ROLE],
                CODE_ROLE
            )
            .unwrap_err(),
            PlanError::UnexpectedRoleOrder
        );
    }

    #[test]
    fn hidden_channel_note_unless_the_bot_or_everyone_is_admin() {
        let hidden = |adapted: &Adapted| {
            adapted
                .notes
                .iter()
                .any(|note| note.contains("didn't have Administrator"))
        };

        // The bot's role holds Administrator.
        assert!(!hidden(&adapt_ok(
            &guild(json!({})),
            &roles(base_roles()),
            &[]
        )));

        let mut no_admin = base_roles();
        no_admin[2]["permissions"] = json!("1024");
        assert!(hidden(&adapt_ok(
            &guild(json!({})),
            &roles(no_admin.clone()),
            &[]
        )));

        // Administrator on @everyone counts (on a role the bot does not hold,
        // it does not).
        let mut everyone_admin = no_admin.clone();
        everyone_admin[3]["permissions"] = json!("8");
        assert!(!hidden(&adapt_ok(
            &guild(json!({})),
            &roles(everyone_admin),
            &[]
        )));
        let mut mod_admin = no_admin;
        mod_admin[0]["permissions"] = json!("8");
        assert!(hidden(&adapt_ok(&guild(json!({})), &roles(mod_admin), &[])));
    }

    #[test]
    fn assets_and_template_fields() {
        let adapted = adapt_ok(
            &guild(json!({
                "icon": "a_0f0f", "banner": "abcd", "system_channel_id": "41",
                "afk_channel_id": "42", "afk_timeout": 300,
                "emojis": [
                    { "id": "51", "name": "party", "animated": true },
                    { "id": "52", "name": "wave" }
                ]
            })),
            &roles(base_roles()),
            &[],
        );
        assert_eq!(
            adapted.icon,
            Some(PlannedAsset {
                kind: AssetKind::Icon,
                id: "a_0f0f".to_string(),
                animated: true
            })
        );
        assert_eq!(
            adapted.banner,
            Some(PlannedAsset {
                kind: AssetKind::Banner,
                id: "abcd".to_string(),
                animated: false
            })
        );
        assert_eq!(
            adapted.emojis,
            vec![
                PlannedEmoji {
                    name: "party".to_string(),
                    asset: PlannedAsset {
                        kind: AssetKind::Emoji,
                        id: "51".to_string(),
                        animated: true
                    }
                },
                PlannedEmoji {
                    name: "wave".to_string(),
                    asset: PlannedAsset {
                        kind: AssetKind::Emoji,
                        id: "52".to_string(),
                        animated: false
                    }
                },
            ]
        );

        let serialized = &adapted.template.serialized_source_guild;
        assert_eq!(adapted.template.description, None);
        assert_eq!(serialized.description, None);
        assert_eq!(serialized.name.as_deref(), Some("Flux Place"));
        assert_eq!(
            serialized.system_channel_id,
            Some(PlaceholderId("41".to_string()))
        );
        assert_eq!(
            serialized.afk_channel_id,
            Some(PlaceholderId("42".to_string()))
        );
        assert_eq!(serialized.afk_timeout, Some(300));

        // No emoji list in the answer: noted, never guessed.
        let mut no_emojis = guild(json!({}));
        no_emojis.emojis = None;
        let adapted = adapt_ok(&no_emojis, &roles(base_roles()), &[]);
        assert!(adapted.emojis.is_empty());
        assert!(adapted
            .notes
            .iter()
            .any(|note| note.contains("emoji couldn't be read")));
    }

    /// Member overwrites reach the mapper as members (it skips them with a
    /// note); an unknown overwrite type reaches it as unknown (it refuses).
    #[test]
    fn overwrite_kinds_pass_through() {
        let fetched = channels(json!([
            { "id": "61", "type": 0, "name": "c", "permission_overwrites": [
                { "id": "1300000000000000999", "type": 1, "allow": "0", "deny": VIEW.to_string() } ] }
        ]));
        let adapted = adapt_ok(&guild(json!({})), &roles(base_roles()), &fetched);
        assert_eq!(
            adapted.template.serialized_source_guild.channels[0].permission_overwrites[0].kind,
            OverwriteKind::Member
        );
        let plan = plan_import_from(&adapted.template, SourceLabel::Fluxer).unwrap();
        assert!(plan
            .skipped
            .iter()
            .any(|note| note.contains("individual Fluxer members")));

        let unknown = channels(json!([
            { "id": "62", "type": 0, "name": "c", "permission_overwrites": [
                { "id": MOD.to_string(), "type": 7, "allow": "0", "deny": VIEW.to_string() } ] }
        ]));
        let adapted = adapt_ok(&guild(json!({})), &roles(base_roles()), &unknown);
        assert_eq!(
            plan_import_from(&adapted.template, SourceLabel::Fluxer).unwrap_err(),
            PlanError::UnknownOverwriteKind
        );
    }
}
