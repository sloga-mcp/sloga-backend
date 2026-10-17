//! Pure mapping from a fetched Stoat server to an [`ImportPlan`].
//!
//! Stoat is this codebase's upstream, so the mapping is close to identity:
//! the same role model (allow AND deny, rank ascending = more authority),
//! the same override shape, the same four system-message slots. What is not
//! identity:
//!
//! * **Permission bits.** Incoming values are masked to the bits Sloga knows
//!   that Stoat can send ([`STOAT_PERMISSION_MASK`]). That excludes bit 14,
//!   which Stoat reserves and Sloga uses for `ViewAuditLog`, and every
//!   Sloga-only bit from 40 up. `ViewAuditLog` is then derived the way
//!   migration revision 73 granted it to existing servers.
//! * **`@everyone`.** The server's `default_permissions`, masked, plus the
//!   Sloga-only bits a native server's default carries, so an imported
//!   server can use the soundboard and watch-together like a new one.
//! * **Hidden channels.** Stoat returns only the channels the bot can view;
//!   the server's own id list is complete, so the difference is reported.
//!
//! Names and descriptions go through the Discord mapper's clamps (the worker
//! bypasses the HTTP validators, so the mapper is where limits hold).

use std::collections::{HashMap, HashSet};

use revolt_models::v0::RE_COLOUR;
use revolt_permissions::{ChannelPermission, DEFAULT_PERMISSION};

use super::source::{
    StoatChannel, StoatEmoji, StoatFile, StoatOverride, StoatServer, StoatTextChannel,
};
use crate::tasks::discord_import::mapper::{
    clamp_description, clamp_name, everyone_can_view, AssetKind, ImportPlan, PlanError,
    PlannedAsset, PlannedCategory, PlannedChannel, PlannedChannelKind, PlannedEmoji,
    PlannedOverride, PlannedRole, PlannedSystemMessages,
};
use crate::tasks::discord_import::template::PlaceholderId;

/// Roles imported at most (Sloga's per-server role limit). The worker
/// re-applies the configured limit.
pub(crate) const ROLE_CAP: usize = 200;

/// Channels imported at most (Sloga's per-server channel limit). The worker
/// re-applies the configured limit.
pub(crate) const CHANNEL_CAP: usize = 200;

/// Longest role colour accepted, as the role-edit validator allows.
const COLOUR_MAX: usize = 128;

const FALLBACK_SERVER_NAME: &str = "Imported Server";
const FALLBACK_CHANNEL_NAME: &str = "channel";
const FALLBACK_CATEGORY_NAME: &str = "category";
const FALLBACK_ROLE_NAME: &str = "role";

/// The permission bits an incoming Stoat value may carry: every bit Sloga
/// defines below bit 40, except `ViewAuditLog` (bit 14).
///
/// Bit 14 sits in the range Stoat reserves; any Stoat value carrying it got
/// it by accident (an "every bit" value) and it must not grant Sloga's audit
/// log. Bits 40 and up are Sloga-only (`UseSoundboard`, `UseRemoteControl`,
/// `RecordCall`, `UseWatchTogether`, …) and Stoat cannot mean them either.
/// The reserved bits (5, 15-19) are not Sloga permissions at all.
pub(crate) const STOAT_PERMISSION_MASK: u64 = ChannelPermission::ManageChannel as u64
    | ChannelPermission::ManageServer as u64
    | ChannelPermission::ManagePermissions as u64
    | ChannelPermission::ManageRole as u64
    | ChannelPermission::ManageCustomisation as u64
    | ChannelPermission::KickMembers as u64
    | ChannelPermission::BanMembers as u64
    | ChannelPermission::TimeoutMembers as u64
    | ChannelPermission::AssignRoles as u64
    | ChannelPermission::ChangeNickname as u64
    | ChannelPermission::ManageNicknames as u64
    | ChannelPermission::ChangeAvatar as u64
    | ChannelPermission::RemoveAvatars as u64
    | ChannelPermission::ViewChannel as u64
    | ChannelPermission::ReadMessageHistory as u64
    | ChannelPermission::SendMessage as u64
    | ChannelPermission::ManageMessages as u64
    | ChannelPermission::ManageWebhooks as u64
    | ChannelPermission::InviteOthers as u64
    | ChannelPermission::SendEmbeds as u64
    | ChannelPermission::UploadFiles as u64
    | ChannelPermission::Masquerade as u64
    | ChannelPermission::React as u64
    | ChannelPermission::Connect as u64
    | ChannelPermission::Speak as u64
    | ChannelPermission::Video as u64
    | ChannelPermission::MuteMembers as u64
    | ChannelPermission::DeafenMembers as u64
    | ChannelPermission::MoveMembers as u64
    | ChannelPermission::Listen as u64
    | ChannelPermission::MentionEveryone as u64
    | ChannelPermission::MentionRoles as u64
    | ChannelPermission::BypassSlowmode as u64;

/// Bits 40 and up of the 52 permission bits: the Sloga-only range.
const SLOGA_ONLY_BITS: u64 = ChannelPermission::GrantAllSafe as u64 & !((1u64 << 40) - 1);

/// The Sloga-only bits a natively created server grants everyone
/// (`UseSoundboard`, `UseWatchTogether`), OR-ed into the imported default.
/// Only those: a Stoat admin who removed a bit Stoat has (say, React) from
/// `@everyone` did so deliberately.
pub(crate) fn sloga_only_defaults() -> u64 {
    *DEFAULT_PERMISSION & SLOGA_ONLY_BITS
}

fn masked(value: i64) -> u64 {
    value as u64 & STOAT_PERMISSION_MASK
}

fn planned_override(value: StoatOverride) -> PlannedOverride {
    PlannedOverride {
        allow: masked(value.a),
        deny: masked(value.d),
    }
}

/// A role's allow and deny bits on Sloga.
///
/// `ViewAuditLog` is derived exactly as migration revision 73 granted it to
/// every existing server (`view_audit_log_backfill_plan` in
/// `admin_migrations/ops/mongodb/scripts.rs`): a role whose ALLOW bits
/// include ManageServer and whose DENY bits do not. A role that both allows
/// and denies ManageServer does not grant it, so it gains nothing. Like the
/// migration, only roles: the server default never gains it.
fn role_permissions(value: StoatOverride) -> (u64, u64) {
    let PlannedOverride { mut allow, deny } = planned_override(value);
    let manage_server = ChannelPermission::ManageServer as u64;
    if allow & manage_server != 0 && deny & manage_server == 0 {
        allow |= ChannelPermission::ViewAuditLog as u64;
    }
    (allow, deny)
}

/// `text` with every occurrence of `code` removed, repeatedly, so the result
/// cannot contain it (removing one occurrence can join the text around it
/// into another).
pub(crate) fn strip_challenge_code(text: &str, code: &str) -> String {
    let mut out = text.to_string();
    if code.is_empty() {
        return out;
    }
    while let Some(start) = out.find(code) {
        out.replace_range(start..start + code.len(), "");
    }
    out
}

/// A colour Sloga's role validator would accept, else `None`. Gradients
/// pass through unchanged; the value ends up in every client's CSS, so
/// anything the validator would refuse is dropped rather than written.
fn role_colour(raw: Option<&str>) -> Result<Option<String>, ()> {
    match raw {
        None | Some("") => Ok(None),
        Some(colour) if colour.len() <= COLOUR_MAX && RE_COLOUR.is_match(colour) => {
            Ok(Some(colour.to_string()))
        }
        Some(_) => Err(()),
    }
}

fn planned_asset(kind: AssetKind, file: &StoatFile) -> PlannedAsset {
    PlannedAsset {
        kind,
        id: file.id.clone(),
        animated: file.content_type.as_deref() == Some("image/gif"),
    }
}

fn planned_channel(
    channel: &StoatTextChannel,
    parent: Option<PlaceholderId>,
    imported_roles: &HashSet<&str>,
    dropped_overrides: &mut usize,
) -> PlannedChannel {
    let kind = match &channel.voice {
        // `max_users` absent or 0 means unlimited, which Sloga writes as
        // absent: `Some(0)` would mean nobody.
        Some(voice) => PlannedChannelKind::Voice {
            max_users: voice.max_users.filter(|limit| *limit > 0),
        },
        None => PlannedChannelKind::Text {
            slowmode: channel.slowmode.filter(|seconds| *seconds > 0),
            announcement: false,
        },
    };

    let mut role_overrides: Vec<(PlaceholderId, PlannedOverride)> = Vec::new();
    for (role_id, value) in channel.role_permissions.iter().flatten() {
        if !imported_roles.contains(role_id.as_str()) {
            // A role over the cap, or one the server does not have.
            *dropped_overrides += 1;
            continue;
        }
        let value = planned_override(*value);
        // All-zero (perhaps only after masking) is no override at all.
        if value.allow != 0 || value.deny != 0 {
            role_overrides.push((PlaceholderId(role_id.clone()), value));
        }
    }
    role_overrides.sort_by(|a, b| a.0.cmp(&b.0));

    PlannedChannel {
        template_id: PlaceholderId(channel.id.clone()),
        name: clamp_name(channel.name.as_deref(), FALLBACK_CHANNEL_NAME),
        description: clamp_description(channel.description.as_deref()),
        nsfw: channel.nsfw.unwrap_or(false),
        kind,
        parent,
        // Unset means "inherit the server default"; an all-zero override
        // would mean the same thing, so it is left unset too.
        default_permissions: channel
            .default_permissions
            .map(planned_override)
            .filter(|value| value.allow != 0 || value.deny != 0),
        role_overrides,
    }
}

/// Map a fetched Stoat server into a plan.
///
/// `channels` are the channels the bot could see; `server.channels` is the
/// server's complete id list. `emoji_cap` is the new server's emoji limit.
/// `challenge_code` is removed from the description: the imported server
/// must not carry the user's verification code.
///
/// Order: roles most-authoritative first (Stoat rank ascending, ties by id).
/// Channels in category order, then uncategorized channels in the server's
/// own order. The welcome invite goes to the join-message channel when that
/// is a text channel `@everyone` can view, else the first such text channel,
/// else nowhere (the Discord mapper's choice is its system channel, with the
/// worker falling back to the first such text channel, which this mirrors).
///
/// Never refuses today; the `Result` matches the other sources' mappers.
pub(crate) fn plan_stoat_import(
    server: &StoatServer,
    channels: &[StoatChannel],
    emojis: &[StoatEmoji],
    emoji_cap: usize,
    challenge_code: &str,
) -> Result<ImportPlan, PlanError> {
    let mut plan = ImportPlan::new(clamp_name(server.name.as_deref(), FALLBACK_SERVER_NAME));
    let mut notes: Vec<String> = Vec::new();

    plan.server_description = clamp_description(
        server
            .description
            .as_deref()
            .map(|description| strip_challenge_code(description, challenge_code))
            .as_deref(),
    );
    plan.nsfw = server.nsfw.unwrap_or(false);
    plan.default_permissions = masked(server.default_permissions) | sloga_only_defaults();
    plan.icon = server
        .icon
        .as_ref()
        .map(|file| planned_asset(AssetKind::Icon, file));
    plan.banner = server
        .banner
        .as_ref()
        .map(|file| planned_asset(AssetKind::Banner, file));

    // Roles, most authoritative first. Stoat reads a missing rank as 0, and
    // so does this.
    let mut roles: Vec<(&String, _)> = server.roles.iter().flatten().collect();
    roles.sort_by(|(a_id, a), (b_id, b)| {
        a.rank
            .unwrap_or(0)
            .cmp(&b.rank.unwrap_or(0))
            .then_with(|| a_id.cmp(b_id))
    });
    let over_role_cap = roles.len().saturating_sub(ROLE_CAP);
    roles.truncate(ROLE_CAP);

    let mut invalid_colours = 0usize;
    for (role_id, role) in &roles {
        let (permissions, deny) = role_permissions(role.permissions);
        let colour = role_colour(role.colour.as_deref()).unwrap_or_else(|()| {
            invalid_colours += 1;
            None
        });
        plan.roles.push(PlannedRole {
            template_id: PlaceholderId((*role_id).clone()),
            name: clamp_name(role.name.as_deref(), FALLBACK_ROLE_NAME),
            colour,
            hoist: role.hoist.unwrap_or(false),
            permissions,
            deny,
            // Stoat has no channel-overwrite bypass to materialise: only the
            // owner bypasses, on both platforms.
            administrator: false,
        });
    }
    let imported_roles: HashSet<&str> = roles.iter().map(|(id, _)| id.as_str()).collect();

    // What came back, by id.
    let mut texts: HashMap<&str, &StoatTextChannel> = HashMap::new();
    let mut returned: HashSet<&str> = HashSet::new();
    let mut unsupported = 0usize;
    for channel in channels {
        if let Some(id) = channel.id() {
            returned.insert(id);
        }
        match channel {
            StoatChannel::Text(text) => {
                texts.insert(text.id.as_str(), text);
            }
            StoatChannel::Unsupported { .. } => unsupported += 1,
        }
    }

    // The bot only sees channels it may view; the server's id list has them
    // all.
    let hidden = server
        .channels
        .iter()
        .filter(|id| !returned.contains(id.as_str()))
        .count();

    // Channels in order: by category, then the rest. A channel listed twice
    // stays where it first appeared; an id that is not a visible text
    // channel (dangling, hidden, unsupported) is dropped from the category.
    let mut ordered: Vec<(&StoatTextChannel, Option<PlaceholderId>)> = Vec::new();
    let mut placed: HashSet<&str> = HashSet::new();
    let mut categories: Vec<PlannedCategory> = Vec::new();
    for (index, category) in server.categories.iter().flatten().enumerate() {
        // Stoat category ids are free-form strings; the plan only needs
        // them to link channels, so they are numbered instead.
        let template_id = PlaceholderId(format!("category-{index}"));
        for channel_id in &category.channels {
            if let Some(channel) = texts.get(channel_id.as_str()) {
                if placed.insert(channel_id.as_str()) {
                    ordered.push((channel, Some(template_id.clone())));
                }
            }
        }
        categories.push(PlannedCategory {
            template_id,
            title: clamp_name(category.title.as_deref(), FALLBACK_CATEGORY_NAME),
        });
    }
    let uncategorized = server
        .channels
        .iter()
        .map(String::as_str)
        // A visible channel missing from the id list (not expected) still
        // comes over, last.
        .chain(channels.iter().filter_map(StoatChannel::id));
    for channel_id in uncategorized {
        if let Some(channel) = texts.get(channel_id) {
            if placed.insert(channel_id) {
                ordered.push((channel, None));
            }
        }
    }

    let over_channel_cap = ordered.len().saturating_sub(CHANNEL_CAP);
    ordered.truncate(CHANNEL_CAP);

    let mut dropped_overrides = 0usize;
    plan.channels = ordered
        .into_iter()
        .map(|(channel, parent)| {
            planned_channel(channel, parent, &imported_roles, &mut dropped_overrides)
        })
        .collect();

    // A category none of whose channels survived is dead weight.
    plan.categories = categories
        .into_iter()
        .filter(|category| {
            plan.channels
                .iter()
                .any(|channel| channel.parent.as_ref() == Some(&category.template_id))
        })
        .collect();

    // System messages, each slot on its own, kept only if its channel is in
    // the plan.
    let planned_ids: HashSet<&str> = plan
        .channels
        .iter()
        .map(|channel| channel.template_id.0.as_str())
        .collect();
    let slot = |raw: &Option<String>| {
        raw.as_deref()
            .filter(|id| planned_ids.contains(id))
            .map(|id| PlaceholderId(id.to_string()))
    };
    let system = server.system_messages.clone().unwrap_or_default();
    plan.system_messages = PlannedSystemMessages {
        user_joined: slot(&system.user_joined),
        user_left: slot(&system.user_left),
        user_kicked: slot(&system.user_kicked),
        user_banned: slot(&system.user_banned),
    };

    // The invite goes to a text channel `@everyone` can view: an invite
    // shows its channel's name and description to anyone holding it, and
    // joiners land there. A private join channel is passed over; with no
    // public text channel at all there is no invite (the worker notes it).
    let server_default = plan.default_permissions;
    let invitable = |channel: &PlannedChannel| {
        matches!(channel.kind, PlannedChannelKind::Text { .. })
            && everyone_can_view(server_default, channel.default_permissions)
    };
    plan.invite_channel = plan
        .system_messages
        .user_joined
        .as_ref()
        .and_then(|id| {
            plan.channels
                .iter()
                .find(|channel| &channel.template_id == id)
        })
        .filter(|channel| invitable(channel))
        .or_else(|| plan.channels.iter().find(|channel| invitable(channel)))
        .map(|channel| channel.template_id.clone());

    // Emoji, up to the new server's cap.
    let over_emoji_cap = emojis.len().saturating_sub(emoji_cap);
    plan.emojis = emojis
        .iter()
        .take(emoji_cap)
        .map(|emoji| PlannedEmoji {
            // A blank name is refused (with a note) by the worker.
            name: emoji.name.clone().unwrap_or_default(),
            asset: PlannedAsset {
                kind: AssetKind::Emoji,
                id: emoji.id.clone(),
                animated: emoji.animated.unwrap_or(false),
            },
        })
        .collect();

    if hidden > 0 {
        notes.push(format!(
            "{hidden} channel(s) were not visible to the importer bot and were skipped. To \
             include them, give the bot a role that can view them on Stoat and import again."
        ));
    }
    if unsupported > 0 {
        notes.push(format!(
            "{unsupported} channel(s) of a type Sloga doesn't have, or that couldn't be read, \
             were not imported."
        ));
    }
    if over_channel_cap > 0 {
        notes.push(format!(
            "{over_channel_cap} channel(s) weren't imported — Sloga allows {CHANNEL_CAP} \
             channels per server."
        ));
    }
    if over_role_cap > 0 {
        notes.push(format!(
            "{over_role_cap} role(s) weren't imported — Sloga allows {ROLE_CAP} roles per \
             server. The roles with the least authority were dropped first."
        ));
    }
    if dropped_overrides > 0 {
        notes.push(format!(
            "{dropped_overrides} channel permission(s) referenced a role that wasn't imported \
             and were skipped."
        ));
    }
    if invalid_colours > 0 {
        notes.push(format!(
            "{invalid_colours} role color(s) Sloga can't display were dropped."
        ));
    }
    if over_emoji_cap > 0 {
        notes.push(format!(
            "{over_emoji_cap} emoji weren't imported — this server hit the {emoji_cap}-emoji \
             limit."
        ));
    }

    plan.skipped = notes;
    plan.skipped_channel_count = (hidden + unsupported + over_channel_cap) as u32;

    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const CODE: &str = "sloga-import-ABCDEFGH";

    const MANAGE_SERVER: u64 = ChannelPermission::ManageServer as u64;
    const VIEW_AUDIT_LOG: u64 = ChannelPermission::ViewAuditLog as u64;
    const VIEW: u64 = ChannelPermission::ViewChannel as u64;
    const SEND: u64 = ChannelPermission::SendMessage as u64;
    const REACT: u64 = ChannelPermission::React as u64;
    const SOUNDBOARD: u64 = ChannelPermission::UseSoundboard as u64;
    const WATCH: u64 = ChannelPermission::UseWatchTogether as u64;
    const RECORD: u64 = ChannelPermission::RecordCall as u64;
    const REMOTE: u64 = ChannelPermission::UseRemoteControl as u64;

    /// A server as `?include_channels=true` reads: `channels` here is the
    /// complete id list.
    fn server(value: Value) -> StoatServer {
        let ids: Vec<String> = value
            .get("channels")
            .and_then(Value::as_array)
            .map(|ids| {
                ids.iter()
                    .map(|id| id.as_str().unwrap().to_string())
                    .collect()
            })
            .unwrap_or_default();
        let mut server: StoatServer = serde_json::from_value(value).unwrap();
        server.channels = ids;
        server
    }

    fn channels(value: Value) -> Vec<StoatChannel> {
        value
            .as_array()
            .unwrap()
            .iter()
            .cloned()
            .map(StoatChannel::from_value)
            .collect()
    }

    fn text(id: &str, name: &str) -> Value {
        json!({ "channel_type": "TextChannel", "_id": id, "server": "S", "name": name })
    }

    fn plan(server_json: Value, channels_json: Value) -> ImportPlan {
        plan_stoat_import(
            &server(server_json),
            &channels(channels_json),
            &[],
            100,
            CODE,
        )
        .unwrap()
    }

    fn ids(plan: &ImportPlan) -> Vec<&str> {
        plan.channels
            .iter()
            .map(|channel| channel.template_id.0.as_str())
            .collect()
    }

    fn id(value: &str) -> Option<PlaceholderId> {
        Some(PlaceholderId(value.to_string()))
    }

    /// Everything a Stoat server can carry, and the plan it must produce.
    #[test]
    fn identity_round_trip_on_a_fixture_server() {
        let admin = (MANAGE_SERVER | VIEW | SEND) as i64;
        let fetched_server = server(json!({
            "_id": "S", "owner": "O", "name": "Stoat Place",
            "description": format!("Our place.\nVerify: {CODE}\nBe nice."),
            "nsfw": true,
            "channels": ["GEN", "WEL", "VOI", "PRV"],
            "categories": [
                { "id": "c1", "title": "Text", "channels": ["WEL", "GEN", "PRV"] },
                { "id": "c2", "title": "Voice", "channels": ["VOI"] }
            ],
            "system_messages": {
                "user_joined": "WEL", "user_left": "GEN",
                "user_kicked": "PRV", "user_banned": "GEN"
            },
            "roles": {
                "ADM": { "name": "Admin", "permissions": { "a": admin, "d": 0 },
                         "colour": "#ff0000", "hoist": true, "rank": 0 },
                "MUT": { "name": "Muted", "permissions": { "a": 0, "d": SEND as i64 },
                         "rank": 1 }
            },
            "default_permissions": (VIEW | SEND | REACT) as i64,
            "icon": { "_id": "ICON", "tag": "icons", "filename": "i.png",
                      "content_type": "image/png", "size": 1,
                      "metadata": { "type": "Image", "width": 1, "height": 1 } },
            "banner": { "_id": "BANNER", "content_type": "image/gif" }
        }));
        let fetched_channels = channels(json!([
            text("GEN", "general"),
            { "channel_type": "TextChannel", "_id": "WEL", "name": "welcome",
              "description": "Say hi", "slowmode": 5 },
            { "channel_type": "TextChannel", "_id": "VOI", "name": "Lounge",
              "voice": { "max_users": 8 } },
            { "channel_type": "TextChannel", "_id": "PRV", "name": "staff", "nsfw": true,
              "default_permissions": { "a": 0, "d": VIEW as i64 },
              "role_permissions": { "ADM": { "a": VIEW as i64, "d": 0 } } }
        ]));
        let emojis = vec![StoatEmoji {
            id: "EMOJI".to_string(),
            name: Some("party".to_string()),
            animated: Some(true),
        }];

        let plan =
            plan_stoat_import(&fetched_server, &fetched_channels, &emojis, 100, CODE).unwrap();

        assert_eq!(plan.server_name, "Stoat Place");
        assert_eq!(
            plan.server_description.as_deref(),
            Some("Our place.\nVerify: \nBe nice.")
        );
        assert!(plan.nsfw);
        assert_eq!(
            plan.default_permissions,
            VIEW | SEND | REACT | SOUNDBOARD | WATCH
        );

        assert_eq!(
            plan.roles,
            vec![
                PlannedRole {
                    template_id: PlaceholderId("ADM".to_string()),
                    name: "Admin".to_string(),
                    colour: Some("#ff0000".to_string()),
                    hoist: true,
                    permissions: MANAGE_SERVER | VIEW | SEND | VIEW_AUDIT_LOG,
                    deny: 0,
                    administrator: false,
                },
                PlannedRole {
                    template_id: PlaceholderId("MUT".to_string()),
                    name: "Muted".to_string(),
                    colour: None,
                    hoist: false,
                    permissions: 0,
                    deny: SEND,
                    administrator: false,
                },
            ]
        );

        assert_eq!(ids(&plan), vec!["WEL", "GEN", "PRV", "VOI"]);
        assert_eq!(
            plan.categories,
            vec![
                PlannedCategory {
                    template_id: PlaceholderId("category-0".to_string()),
                    title: "Text".to_string()
                },
                PlannedCategory {
                    template_id: PlaceholderId("category-1".to_string()),
                    title: "Voice".to_string()
                },
            ]
        );

        let welcome = &plan.channels[0];
        assert_eq!(welcome.description.as_deref(), Some("Say hi"));
        assert_eq!(
            welcome.kind,
            PlannedChannelKind::Text {
                slowmode: Some(5),
                announcement: false
            }
        );
        assert_eq!(welcome.parent, id("category-0"));

        let private = &plan.channels[2];
        assert!(private.nsfw);
        assert_eq!(
            private.default_permissions,
            Some(PlannedOverride {
                allow: 0,
                deny: VIEW
            })
        );
        assert_eq!(
            private.role_overrides,
            vec![(
                PlaceholderId("ADM".to_string()),
                PlannedOverride {
                    allow: VIEW,
                    deny: 0
                }
            )]
        );

        assert_eq!(
            plan.channels[3].kind,
            PlannedChannelKind::Voice { max_users: Some(8) }
        );
        assert_eq!(plan.channels[3].parent, id("category-1"));

        assert_eq!(
            plan.system_messages,
            PlannedSystemMessages {
                user_joined: id("WEL"),
                user_left: id("GEN"),
                user_kicked: id("PRV"),
                user_banned: id("GEN"),
            }
        );
        assert_eq!(plan.invite_channel, id("WEL"));

        assert_eq!(
            plan.icon,
            Some(PlannedAsset {
                kind: AssetKind::Icon,
                id: "ICON".to_string(),
                animated: false
            })
        );
        assert_eq!(
            plan.banner,
            Some(PlannedAsset {
                kind: AssetKind::Banner,
                id: "BANNER".to_string(),
                animated: true
            })
        );
        assert_eq!(
            plan.emojis,
            vec![PlannedEmoji {
                name: "party".to_string(),
                asset: PlannedAsset {
                    kind: AssetKind::Emoji,
                    id: "EMOJI".to_string(),
                    animated: true
                }
            }]
        );

        assert!(plan.skipped.is_empty(), "{:?}", plan.skipped);
        assert_eq!(plan.skipped_channel_count, 0);
        assert_eq!(plan.afk_channel, None);
    }

    #[test]
    fn the_mask_is_every_sloga_bit_below_40_except_view_audit_log() {
        let expected: u64 = (0..=4)
            .chain(6..=13)
            .chain(20..=39)
            .fold(0, |acc, bit| acc | (1u64 << bit));
        assert_eq!(STOAT_PERMISSION_MASK, expected);
        assert_eq!(STOAT_PERMISSION_MASK & VIEW_AUDIT_LOG, 0);
        assert_eq!(STOAT_PERMISSION_MASK >> 40, 0);
        assert_eq!(sloga_only_defaults(), SOUNDBOARD | WATCH);
    }

    /// Bit 14 and the Sloga-only bits never come in, on any of the four
    /// carriers: the server default, a role's allow and deny, and a
    /// channel's default and role overrides.
    #[test]
    fn view_audit_log_and_sloga_only_bits_are_masked_off_incoming_values() {
        let foreign = (VIEW_AUDIT_LOG | SOUNDBOARD | RECORD | REMOTE | (1 << 5) | (1 << 15)) as i64;
        let plan = plan(
            json!({
                "_id": "S", "channels": ["A"],
                "roles": { "R": { "name": "Role", "permissions": { "a": foreign | VIEW as i64, "d": foreign } } },
                "default_permissions": foreign | SEND as i64
            }),
            json!([{ "channel_type": "TextChannel", "_id": "A", "name": "a",
                     "default_permissions": { "a": foreign, "d": foreign | SEND as i64 },
                     "role_permissions": { "R": { "a": foreign | REACT as i64, "d": foreign } } }]),
        );

        // The default keeps SEND and gains exactly the native Sloga-only
        // defaults; RECORD and REMOTE do not come along.
        assert_eq!(plan.default_permissions, SEND | SOUNDBOARD | WATCH);
        assert_eq!(plan.roles[0].permissions, VIEW);
        assert_eq!(plan.roles[0].deny, 0);
        assert_eq!(
            plan.channels[0].default_permissions,
            Some(PlannedOverride {
                allow: 0,
                deny: SEND
            })
        );
        assert_eq!(
            plan.channels[0].role_overrides,
            vec![(
                PlaceholderId("R".to_string()),
                PlannedOverride {
                    allow: REACT,
                    deny: 0
                }
            )]
        );
    }

    /// Migration 73's rule: allowed AND not denied ManageServer.
    #[test]
    fn view_audit_log_is_derived_from_manage_server_as_migration_73_did() {
        let plan = plan(
            json!({
                "_id": "S", "channels": [],
                "roles": {
                    "A": { "permissions": { "a": MANAGE_SERVER as i64, "d": 0 }, "rank": 0 },
                    "B": { "permissions": { "a": MANAGE_SERVER as i64, "d": MANAGE_SERVER as i64 }, "rank": 1 },
                    "C": { "permissions": { "a": 0, "d": MANAGE_SERVER as i64 }, "rank": 2 },
                    "D": { "permissions": { "a": (VIEW_AUDIT_LOG | VIEW) as i64, "d": 0 }, "rank": 3 }
                },
                "default_permissions": (MANAGE_SERVER | VIEW) as i64
            }),
            json!([]),
        );
        let by_id = |wanted: &str| {
            plan.roles
                .iter()
                .find(|role| role.template_id.0 == wanted)
                .unwrap()
        };
        assert_eq!(by_id("A").permissions, MANAGE_SERVER | VIEW_AUDIT_LOG);
        assert_eq!(by_id("B").permissions, MANAGE_SERVER);
        assert_eq!(by_id("C").permissions, 0);
        // Incoming bit 14 without ManageServer is not a grant.
        assert_eq!(by_id("D").permissions, VIEW);
        // The default is never given the audit log.
        assert_eq!(plan.default_permissions & VIEW_AUDIT_LOG, 0);
    }

    #[test]
    fn roles_follow_stoat_rank_then_id_and_keep_deny_and_gradients() {
        let gradient = "linear-gradient(90deg, #ff0000 0%, #0000ff 100%)";
        let plan = plan(
            json!({
                "_id": "S", "channels": [],
                "roles": {
                    "Z": { "name": "Low", "permissions": { "a": 0, "d": SEND as i64 }, "rank": 5 },
                    "Y": { "name": "Top", "permissions": { "a": 0, "d": 0 }, "rank": 1, "colour": gradient },
                    "X": { "name": "Mid", "permissions": { "a": 0, "d": 0 }, "rank": 3 },
                    "W": { "name": "Also mid", "permissions": { "a": 0, "d": 0 }, "rank": 3 },
                    "V": { "name": "Bad colour", "permissions": { "a": 0, "d": 0 }, "rank": 9,
                           "colour": "red; background: url(https://evil.example)" }
                },
                "default_permissions": 0
            }),
            json!([]),
        );
        assert_eq!(
            plan.roles
                .iter()
                .map(|role| role.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Top", "Also mid", "Mid", "Low", "Bad colour"]
        );
        assert_eq!(plan.roles[0].colour.as_deref(), Some(gradient));
        assert_eq!(plan.roles[3].deny, SEND);
        assert_eq!(plan.roles[4].colour, None);
        assert!(plan
            .skipped
            .contains(&"1 role color(s) Sloga can't display were dropped.".to_string()));
    }

    #[test]
    fn system_message_slots_are_remapped_one_by_one() {
        let plan = plan(
            json!({
                "_id": "S", "channels": ["A", "B", "HIDDEN"],
                "system_messages": { "user_joined": "A", "user_left": "B",
                                     "user_kicked": "HIDDEN", "user_banned": "NOWHERE" },
                "default_permissions": 0
            }),
            json!([text("A", "a"), text("B", "b")]),
        );
        assert_eq!(
            plan.system_messages,
            PlannedSystemMessages {
                user_joined: id("A"),
                user_left: id("B"),
                user_kicked: None,
                user_banned: None,
            }
        );
    }

    #[test]
    fn the_invite_goes_to_the_join_channel_or_the_first_text_channel() {
        let with_join = |joined: Value| {
            plan(
                json!({
                    "_id": "S", "channels": ["V", "A", "B"],
                    "system_messages": { "user_joined": joined },
                    "default_permissions": VIEW as i64
                }),
                json!([
                    { "channel_type": "TextChannel", "_id": "V", "name": "v", "voice": {} },
                    text("A", "a"),
                    text("B", "b")
                ]),
            )
            .invite_channel
        };
        assert_eq!(with_join(json!("B")), id("B"));
        // A voice join channel is no place for an invite.
        assert_eq!(with_join(json!("V")), id("A"));
        assert_eq!(with_join(Value::Null), id("A"));
        assert_eq!(with_join(json!("GONE")), id("A"));
    }

    /// The invite never points at a channel `@everyone` cannot view: anyone
    /// holding it would read that channel's name and description, and
    /// joiners would land somewhere they cannot see. Neither the join
    /// channel nor the fallback may be private; with no public text channel
    /// there is no invite.
    #[test]
    fn the_invite_only_goes_to_a_channel_everyone_can_view() {
        let private = |id: &str| {
            json!({ "channel_type": "TextChannel", "_id": id, "name": id,
                    "default_permissions": { "a": 0, "d": VIEW as i64 } })
        };
        let opened = |id: &str| {
            json!({ "channel_type": "TextChannel", "_id": id, "name": id,
                    "default_permissions": { "a": VIEW as i64, "d": 0 } })
        };
        let invite = |default: u64, joined: &str, channels_json: Value| {
            let ids: Vec<Value> = channels_json
                .as_array()
                .unwrap()
                .iter()
                .map(|channel| channel["_id"].clone())
                .collect();
            plan(
                json!({
                    "_id": "S", "channels": ids,
                    "system_messages": { "user_joined": joined },
                    "default_permissions": default as i64
                }),
                channels_json,
            )
            .invite_channel
        };

        // A private join channel: the first public text channel instead,
        // passing over a private one ahead of it.
        assert_eq!(
            invite(
                VIEW | SEND,
                "STAFF",
                json!([private("MODS"), private("STAFF"), text("PUB", "pub")])
            ),
            id("PUB")
        );
        // Nothing public: no invite at all.
        assert_eq!(
            invite(VIEW, "STAFF", json!([private("STAFF"), private("MODS")])),
            None
        );
        // `@everyone` cannot view by default: only a channel that grants it
        // back qualifies, the join channel included.
        assert_eq!(
            invite(SEND, "A", json!([text("A", "a"), opened("B")])),
            id("B")
        );
        assert_eq!(
            invite(SEND, "B", json!([opened("A"), opened("B")])),
            id("B")
        );
        assert_eq!(invite(SEND, "A", json!([text("A", "a")])), None);
    }

    #[test]
    fn voice_max_users_zero_or_absent_means_unlimited() {
        let plan = plan(
            json!({ "_id": "S", "channels": ["A", "B", "C"], "default_permissions": 0 }),
            json!([
                { "channel_type": "TextChannel", "_id": "A", "voice": { "max_users": 0 } },
                { "channel_type": "TextChannel", "_id": "B", "voice": {} },
                { "channel_type": "TextChannel", "_id": "C", "voice": { "max_users": 3 } }
            ]),
        );
        assert_eq!(
            plan.channels
                .iter()
                .map(|channel| channel.kind.clone())
                .collect::<Vec<_>>(),
            vec![
                PlannedChannelKind::Voice { max_users: None },
                PlannedChannelKind::Voice { max_users: None },
                PlannedChannelKind::Voice { max_users: Some(3) },
            ]
        );
    }

    #[test]
    fn category_ids_that_point_nowhere_are_dropped_and_empty_categories_go() {
        let plan = plan(
            json!({
                "_id": "S", "channels": ["A", "B", "U"],
                "categories": [
                    { "id": "c1", "title": "One", "channels": ["GONE", "B", "A", "B"] },
                    { "id": "c2", "title": "Empty", "channels": ["GONE"] },
                    { "id": "c3", "title": "Duplicate", "channels": ["A"] }
                ],
                "default_permissions": 0
            }),
            json!([text("A", "a"), text("B", "b"), text("U", "u")]),
        );
        assert_eq!(ids(&plan), vec!["B", "A", "U"]);
        assert_eq!(plan.channels[2].parent, None);
        assert_eq!(
            plan.categories
                .iter()
                .map(|category| category.title.as_str())
                .collect::<Vec<_>>(),
            vec!["One"]
        );
        assert!(plan.skipped.is_empty(), "{:?}", plan.skipped);
    }

    #[test]
    fn hidden_channels_are_counted_and_noted() {
        let plan = plan(
            json!({ "_id": "S", "channels": ["A", "H1", "H2"], "default_permissions": 0 }),
            json!([text("A", "a")]),
        );
        assert_eq!(ids(&plan), vec!["A"]);
        assert_eq!(plan.skipped_channel_count, 2);
        assert_eq!(
            plan.skipped,
            vec![
                "2 channel(s) were not visible to the importer bot and were skipped. To include \
                 them, give the bot a role that can view them on Stoat and import again."
                    .to_string()
            ]
        );

        // All visible: no note.
        let plan = plan_fixture_all_visible();
        assert!(plan.skipped.is_empty());
    }

    fn plan_fixture_all_visible() -> ImportPlan {
        plan(
            json!({ "_id": "S", "channels": ["A"], "default_permissions": 0 }),
            json!([text("A", "a")]),
        )
    }

    #[test]
    fn unknown_channel_types_are_skipped_with_a_note() {
        let plan = plan(
            json!({ "_id": "S", "channels": ["A", "F", "X"], "default_permissions": 0 }),
            json!([
                text("A", "a"),
                { "channel_type": "Forum", "_id": "F", "name": "f" },
                { "channel_type": "TextChannel", "_id": "X", "default_permissions": { "a": 1 } }
            ]),
        );
        assert_eq!(ids(&plan), vec!["A"]);
        assert_eq!(plan.skipped_channel_count, 2);
        assert_eq!(
            plan.skipped,
            vec![
                "2 channel(s) of a type Sloga doesn't have, or that couldn't be read, were not \
                  imported."
                    .to_string()
            ]
        );
    }

    #[test]
    fn caps_drop_the_tail_with_notes() {
        let roles: serde_json::Map<String, Value> = (0..ROLE_CAP + 2)
            .map(|rank| {
                (
                    format!("R{rank:03}"),
                    json!({ "name": "r", "permissions": { "a": 0, "d": 0 }, "rank": rank }),
                )
            })
            .collect();
        let channel_ids: Vec<String> = (0..CHANNEL_CAP + 3).map(|n| format!("C{n:03}")).collect();
        let channel_list: Vec<Value> = channel_ids
            .iter()
            .enumerate()
            .map(|(index, channel_id)| {
                // The first channel has overrides for a kept role, a role
                // over the cap and a role that does not exist.
                let mut channel = text(channel_id, "c");
                if index == 0 {
                    channel["role_permissions"] = json!({
                        "R000": { "a": VIEW as i64, "d": 0 },
                        "R201": { "a": VIEW as i64, "d": 0 },
                        "NOPE": { "a": VIEW as i64, "d": 0 }
                    });
                }
                channel
            })
            .collect();
        let emojis: Vec<StoatEmoji> = (0..5)
            .map(|n| StoatEmoji {
                id: format!("E{n}"),
                name: Some(format!("e{n}")),
                animated: None,
            })
            .collect();

        let plan = plan_stoat_import(
            &server(json!({
                "_id": "S", "channels": channel_ids, "roles": roles, "default_permissions": 0
            })),
            &channels(Value::Array(channel_list)),
            &emojis,
            3,
            CODE,
        )
        .unwrap();

        assert_eq!(plan.roles.len(), ROLE_CAP);
        assert_eq!(plan.roles.last().unwrap().template_id.0, "R199");
        assert_eq!(plan.channels.len(), CHANNEL_CAP);
        assert_eq!(plan.channels.last().unwrap().template_id.0, "C199");
        assert_eq!(plan.skipped_channel_count, 3);
        assert_eq!(
            plan.channels[0].role_overrides,
            vec![(
                PlaceholderId("R000".to_string()),
                PlannedOverride {
                    allow: VIEW,
                    deny: 0
                }
            )]
        );
        assert_eq!(
            plan.emojis
                .iter()
                .map(|emoji| emoji.asset.id.as_str())
                .collect::<Vec<_>>(),
            vec!["E0", "E1", "E2"]
        );
        assert_eq!(
            plan.skipped,
            vec![
                format!(
                    "3 channel(s) weren't imported — Sloga allows {CHANNEL_CAP} channels per \
                     server."
                ),
                format!(
                    "2 role(s) weren't imported — Sloga allows {ROLE_CAP} roles per server. The \
                     roles with the least authority were dropped first."
                ),
                "2 channel permission(s) referenced a role that wasn't imported and were skipped."
                    .to_string(),
                "2 emoji weren't imported — this server hit the 3-emoji limit.".to_string(),
            ]
        );
    }

    #[test]
    fn the_challenge_code_never_survives_into_the_description() {
        let with = |description: &str| {
            plan(
                json!({ "_id": "S", "channels": [], "description": description,
                        "default_permissions": 0 }),
                json!([]),
            )
            .server_description
        };
        assert_eq!(with(&format!("Hello {CODE}")), Some("Hello".to_string()));
        assert_eq!(
            with(&format!("{CODE} a {CODE}b {CODE}")),
            Some("a b".to_string())
        );
        // Only the code: no description at all.
        assert_eq!(with(&format!("  {CODE}\n")), None);
        // Removing one occurrence must not leave another behind.
        let nested = format!("sloga-import-{CODE}ABCDEFGH");
        assert_eq!(strip_challenge_code(&nested, CODE), "");
        assert!(!with(&nested).unwrap_or_default().contains(CODE));
        // Another code is the user's own text.
        assert_eq!(
            with("sloga-import-ZZZZZZZZ"),
            Some("sloga-import-ZZZZZZZZ".to_string())
        );
        // Names and descriptions are clamped like every other import.
        let long = "x".repeat(2000);
        assert_eq!(with(&long).unwrap().chars().count(), 1024);
    }

    #[test]
    fn blank_names_fall_back_and_long_ones_are_clamped() {
        let plan = plan(
            json!({ "_id": "S", "name": "  ", "channels": ["A"],
                    "categories": [{ "title": "", "channels": ["A"] }],
                    "roles": { "R": { "name": "r".repeat(40), "permissions": { "a": 0, "d": 0 } } },
                    "default_permissions": 0 }),
            json!([{ "channel_type": "TextChannel", "_id": "A" }]),
        );
        assert_eq!(plan.server_name, FALLBACK_SERVER_NAME);
        assert_eq!(plan.channels[0].name, FALLBACK_CHANNEL_NAME);
        assert_eq!(plan.categories[0].title, FALLBACK_CATEGORY_NAME);
        assert_eq!(plan.roles[0].name.chars().count(), 32);
    }
}
