//! Discord permission bitfield → Sloga `ChannelPermission` bitfield.
//!
//! Pure, table-driven and deliberately conservative: a Discord bit with no
//! Sloga equivalent contributes nothing rather than being approximated onto
//! something adjacent. Silently granting a permission the source server never
//! granted is the failure mode that matters here, so unknown bits are dropped.
//!
//! ## Two mapping contexts, and why they differ
//!
//! Discord applies `ADMINISTRATOR` **only at the guild level** — it short
//! circuits the whole permission computation before channel overwrites are
//! ever consulted, which is why Discord's own UI will not let you grant it in
//! a channel overwrite. So:
//!
//! * [`map_role_permissions`] honours `ADMINISTRATOR` → `GrantAllSafe`.
//! * [`map_overwrite_permissions`] ignores it. Honouring it there would turn a
//!   stray bit in a channel overwrite's `deny` field into "deny all 52
//!   permissions on this channel", i.e. a channel nobody but the owner can
//!   see — created silently, from a template that behaved fine on Discord.

use revolt_permissions::{ChannelPermission, DEFAULT_PERMISSION_SERVER};

/// Discord permission bit positions, named so the table below can be read
/// against <https://discord.com/developers/docs/topics/permissions>.
mod discord {
    pub const CREATE_INSTANT_INVITE: u32 = 0;
    pub const KICK_MEMBERS: u32 = 1;
    pub const BAN_MEMBERS: u32 = 2;
    pub const ADMINISTRATOR: u32 = 3;
    pub const MANAGE_CHANNELS: u32 = 4;
    pub const MANAGE_GUILD: u32 = 5;
    pub const ADD_REACTIONS: u32 = 6;
    pub const STREAM: u32 = 9;
    pub const VIEW_CHANNEL: u32 = 10;
    pub const SEND_MESSAGES: u32 = 11;
    pub const MANAGE_MESSAGES: u32 = 13;
    pub const EMBED_LINKS: u32 = 14;
    pub const ATTACH_FILES: u32 = 15;
    pub const READ_MESSAGE_HISTORY: u32 = 16;
    pub const MENTION_EVERYONE: u32 = 17;
    pub const CONNECT: u32 = 20;
    pub const SPEAK: u32 = 21;
    pub const MUTE_MEMBERS: u32 = 22;
    pub const DEAFEN_MEMBERS: u32 = 23;
    pub const MOVE_MEMBERS: u32 = 24;
    pub const CHANGE_NICKNAME: u32 = 26;
    pub const MANAGE_NICKNAMES: u32 = 27;
    pub const MANAGE_ROLES: u32 = 28;
    pub const MANAGE_WEBHOOKS: u32 = 29;
    pub const MANAGE_GUILD_EXPRESSIONS: u32 = 30;
    pub const MODERATE_MEMBERS: u32 = 40;
    pub const USE_SOUNDBOARD: u32 = 42;
}

/// `(discord bit position, Sloga bits granted)`.
///
/// Several Discord permissions are one bit where Sloga has several — Discord's
/// `MANAGE_ROLES` covers what Sloga splits into managing roles, managing
/// permissions and assigning roles; `MENTION_EVERYONE` covers both mention
/// flavours; `CONNECT` implies being able to hear people. Those expansions are
/// listed here rather than hidden in code so the table stays auditable against
/// the plan's §5.2.
///
/// Everything Discord has and Sloga does not — `VIEW_AUDIT_LOG`,
/// `PRIORITY_SPEAKER`, `SEND_TTS_MESSAGES`, `USE_EXTERNAL_EMOJIS`,
/// `VIEW_GUILD_INSIGHTS`, `USE_VAD`, `USE_APPLICATION_COMMANDS`,
/// `REQUEST_TO_SPEAK`, `MANAGE_EVENTS`, the thread permissions,
/// `USE_EXTERNAL_STICKERS`, `USE_EMBEDDED_ACTIVITIES`, `USE_EXTERNAL_SOUNDS`,
/// `SEND_VOICE_MESSAGES`, `SEND_POLLS`, `USE_EXTERNAL_APPS` — is absent on
/// purpose and contributes no bits.
static TABLE: &[(u32, u64)] = &[
    (
        discord::CREATE_INSTANT_INVITE,
        ChannelPermission::InviteOthers as u64,
    ),
    (discord::KICK_MEMBERS, ChannelPermission::KickMembers as u64),
    (discord::BAN_MEMBERS, ChannelPermission::BanMembers as u64),
    (
        discord::MANAGE_CHANNELS,
        ChannelPermission::ManageChannel as u64,
    ),
    (
        discord::MANAGE_GUILD,
        ChannelPermission::ManageServer as u64,
    ),
    (discord::ADD_REACTIONS, ChannelPermission::React as u64),
    (discord::STREAM, ChannelPermission::Video as u64),
    (discord::VIEW_CHANNEL, ChannelPermission::ViewChannel as u64),
    (
        discord::SEND_MESSAGES,
        ChannelPermission::SendMessage as u64,
    ),
    // Discord's message managers bypass slowmode; Sloga splits that out.
    (
        discord::MANAGE_MESSAGES,
        ChannelPermission::ManageMessages as u64 | ChannelPermission::BypassSlowmode as u64,
    ),
    (discord::EMBED_LINKS, ChannelPermission::SendEmbeds as u64),
    (discord::ATTACH_FILES, ChannelPermission::UploadFiles as u64),
    (
        discord::READ_MESSAGE_HISTORY,
        ChannelPermission::ReadMessageHistory as u64,
    ),
    // One Discord bit covers @everyone/@here *and* role mentions.
    (
        discord::MENTION_EVERYONE,
        ChannelPermission::MentionEveryone as u64 | ChannelPermission::MentionRoles as u64,
    ),
    // Joining a voice channel on Discord implies hearing it; Sloga has a
    // separate Listen permission that would otherwise leave imported members
    // connected to a silent call.
    (
        discord::CONNECT,
        ChannelPermission::Connect as u64 | ChannelPermission::Listen as u64,
    ),
    (discord::SPEAK, ChannelPermission::Speak as u64),
    (discord::MUTE_MEMBERS, ChannelPermission::MuteMembers as u64),
    (
        discord::DEAFEN_MEMBERS,
        ChannelPermission::DeafenMembers as u64,
    ),
    (discord::MOVE_MEMBERS, ChannelPermission::MoveMembers as u64),
    (
        discord::CHANGE_NICKNAME,
        ChannelPermission::ChangeNickname as u64,
    ),
    (
        discord::MANAGE_NICKNAMES,
        ChannelPermission::ManageNicknames as u64,
    ),
    // Discord's single role permission is three on Sloga.
    (
        discord::MANAGE_ROLES,
        ChannelPermission::ManageRole as u64
            | ChannelPermission::ManagePermissions as u64
            | ChannelPermission::AssignRoles as u64,
    ),
    (
        discord::MANAGE_WEBHOOKS,
        ChannelPermission::ManageWebhooks as u64,
    ),
    (
        discord::MANAGE_GUILD_EXPRESSIONS,
        ChannelPermission::ManageCustomisation as u64,
    ),
    (
        discord::MODERATE_MEMBERS,
        ChannelPermission::TimeoutMembers as u64,
    ),
    (
        discord::USE_SOUNDBOARD,
        ChannelPermission::UseSoundboard as u64,
    ),
];

/// Sloga affordances a freshly created server grants its members that the
/// Discord mapping cannot be trusted to reproduce, OR-ed into the imported
/// `default_permissions` (plan §5.2).
///
/// `ChangeAvatar` genuinely has no Discord counterpart. `React` and
/// `ChangeNickname` do (`ADD_REACTIONS`, `CHANGE_NICKNAME`) but are included
/// deliberately: they are part of `DEFAULT_PERMISSION_SERVER`, so a server
/// whose Discord `@everyone` happened to lack them would land on Sloga feeling
/// broken — members unable to react or set a nickname — with nothing in the UI
/// explaining why. Fidelity loses to "the imported server works" for these
/// three, and only these three.
pub fn baseline_grants() -> u64 {
    ChannelPermission::React as u64
        | ChannelPermission::ChangeNickname as u64
        | ChannelPermission::ChangeAvatar as u64
}

/// What a server created through the normal Sloga flow grants its members.
///
/// Used only as the fallback when a template carries no `@everyone` role at
/// all — something Discord does not produce, but which would otherwise mint a
/// server whose members cannot see a single channel.
pub fn sloga_default_server_permissions() -> u64 {
    *DEFAULT_PERMISSION_SERVER
}

/// Apply the table. Bits with no entry contribute nothing.
fn map_bits(discord_bits: u64) -> u64 {
    TABLE.iter().fold(0u64, |acc, (bit, sloga)| {
        if discord_bits & (1u64 << bit) != 0 {
            acc | sloga
        } else {
            acc
        }
    })
}

/// Does this bitfield carry Discord's `ADMINISTRATOR`?
///
/// Callers need this separately from the mapping because ADMINISTRATOR is not
/// just "all the bits" on Discord — it also bypasses every channel overwrite,
/// which Sloga has no equivalent for and which therefore has to be
/// materialised (see `mapper::grant_administrator_channel_access`).
pub fn has_administrator(discord_bits: u64) -> bool {
    discord_bits & (1u64 << discord::ADMINISTRATOR) != 0
}

/// Everything a Sloga role can hold — what an imported Discord administrator
/// must end up with, both server-wide and on every restricted channel.
pub fn administrator_grant() -> u64 {
    ChannelPermission::GrantAllSafe as u64
}

/// Map a **role's** guild-level permissions.
///
/// `ADMINISTRATOR` is honoured here and only here: on Discord it grants every
/// permission and bypasses every channel overwrite, so `GrantAllSafe` is the
/// faithful Sloga equivalent *for the server-level grant*. The overwrite
/// bypass is a separate problem — see [`has_administrator`].
pub fn map_role_permissions(discord_bits: u64) -> u64 {
    if has_administrator(discord_bits) {
        return administrator_grant();
    }

    map_bits(discord_bits)
}

/// Map one side (`allow` or `deny`) of a **channel permission overwrite**.
///
/// `ADMINISTRATOR` is ignored — see the module docs.
pub fn map_overwrite_permissions(discord_bits: u64) -> u64 {
    map_bits(discord_bits & !(1u64 << discord::ADMINISTRATOR))
}

/// Map an overwrite's `allow`/`deny` pair into Sloga bits.
///
/// Returns `(allow, deny)` with the two guaranteed disjoint. Discord rejects
/// an overwrite that both allows and denies the same permission, so this can
/// only trigger on a malformed template — but the resolution still matters,
/// because Sloga and Discord break the tie in *opposite directions*:
/// `PermissionValue::apply` allows then revokes (deny wins), whereas Discord
/// denies then allows (allow wins). Clearing the overlap out of `deny`
/// preserves Discord's answer.
pub fn map_overwrite(allow: u64, deny: u64) -> (u64, u64) {
    let allow = map_overwrite_permissions(allow);
    let deny = map_overwrite_permissions(deny) & !allow;
    (allow, deny)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discord(bits: &[u32]) -> u64 {
        bits.iter().fold(0u64, |acc, bit| acc | (1u64 << bit))
    }

    #[test]
    fn one_to_one_permissions_map_across() {
        assert_eq!(
            map_role_permissions(discord(&[discord::VIEW_CHANNEL])),
            ChannelPermission::ViewChannel as u64
        );
        assert_eq!(
            map_role_permissions(discord(&[discord::SEND_MESSAGES])),
            ChannelPermission::SendMessage as u64
        );
        assert_eq!(
            map_role_permissions(discord(&[discord::USE_SOUNDBOARD])),
            ChannelPermission::UseSoundboard as u64
        );
        assert_eq!(
            map_role_permissions(discord(&[discord::MODERATE_MEMBERS])),
            ChannelPermission::TimeoutMembers as u64
        );
    }

    /// The many-to-one expansions are the part of the table most likely to rot.
    #[test]
    fn one_discord_bit_can_grant_several_sloga_bits() {
        assert_eq!(
            map_role_permissions(discord(&[discord::MANAGE_ROLES])),
            ChannelPermission::ManageRole as u64
                | ChannelPermission::ManagePermissions as u64
                | ChannelPermission::AssignRoles as u64
        );
        assert_eq!(
            map_role_permissions(discord(&[discord::MENTION_EVERYONE])),
            ChannelPermission::MentionEveryone as u64 | ChannelPermission::MentionRoles as u64
        );
        assert_eq!(
            map_role_permissions(discord(&[discord::CONNECT])),
            ChannelPermission::Connect as u64 | ChannelPermission::Listen as u64
        );
        assert_eq!(
            map_role_permissions(discord(&[discord::MANAGE_MESSAGES])),
            ChannelPermission::ManageMessages as u64 | ChannelPermission::BypassSlowmode as u64
        );
    }

    #[test]
    fn administrator_becomes_grant_all_safe_on_roles() {
        assert_eq!(
            map_role_permissions(discord(&[discord::ADMINISTRATOR])),
            ChannelPermission::GrantAllSafe as u64
        );

        // ...and swallows whatever else was set alongside it.
        assert_eq!(
            map_role_permissions(discord(&[discord::ADMINISTRATOR, discord::VIEW_CHANNEL])),
            ChannelPermission::GrantAllSafe as u64
        );
    }

    /// The dangerous direction: `ADMINISTRATOR` inside an overwrite's `deny`
    /// would otherwise revoke all 52 permissions on that channel, producing a
    /// channel nobody can see from a template that worked fine on Discord.
    #[test]
    fn administrator_is_ignored_inside_channel_overwrites() {
        assert_eq!(
            map_overwrite_permissions(discord(&[discord::ADMINISTRATOR])),
            0
        );

        let (allow, deny) = map_overwrite(
            discord(&[discord::ADMINISTRATOR, discord::VIEW_CHANNEL]),
            discord(&[discord::ADMINISTRATOR]),
        );
        assert_eq!(allow, ChannelPermission::ViewChannel as u64);
        assert_eq!(deny, 0);
    }

    #[test]
    fn unmapped_discord_permissions_grant_nothing() {
        // VIEW_AUDIT_LOG (7), PRIORITY_SPEAKER (8), SEND_TTS_MESSAGES (12),
        // USE_EXTERNAL_EMOJIS (18), MANAGE_THREADS (34), SEND_POLLS (48).
        assert_eq!(map_role_permissions(discord(&[7, 8, 12, 18, 34, 48])), 0);
    }

    #[test]
    fn empty_bitfield_maps_to_nothing() {
        assert_eq!(map_role_permissions(0), 0);
        assert_eq!(map_overwrite(0, 0), (0, 0));
    }

    /// Sloga restricts permission values to the lower 52 bits so JavaScript
    /// clients can hold them exactly; nothing the table emits may exceed that.
    #[test]
    fn mapped_output_never_escapes_the_safe_bit_range() {
        let everything = TABLE.iter().fold(0u64, |acc, (bit, _)| acc | (1u64 << bit));

        let mapped = map_role_permissions(everything);
        assert_eq!(
            mapped & !(ChannelPermission::GrantAllSafe as u64),
            0,
            "table emits a bit outside GrantAllSafe's 52-bit window"
        );
    }

    #[test]
    fn overwrite_allow_and_deny_are_kept_disjoint() {
        // Malformed input only Discord's API would reject: the same permission
        // in both directions. Allow must win, as it does on Discord.
        let both = discord(&[discord::SEND_MESSAGES]);
        let (allow, deny) = map_overwrite(both, both);

        assert_eq!(allow, ChannelPermission::SendMessage as u64);
        assert_eq!(deny, 0);
        assert_eq!(allow & deny, 0);
    }

    /// A partial overlap must only clear the shared bits, not the whole deny.
    #[test]
    fn partial_overlap_only_clears_the_shared_bits() {
        let (allow, deny) = map_overwrite(
            discord(&[discord::SEND_MESSAGES]),
            discord(&[discord::SEND_MESSAGES, discord::ATTACH_FILES]),
        );

        assert_eq!(allow, ChannelPermission::SendMessage as u64);
        assert_eq!(deny, ChannelPermission::UploadFiles as u64);
    }

    /// A real `@everyone` bitfield, read live from Discord's own "Blank Server"
    /// template (`2TffvPucqHkN`) on 2026-07-25. Guards the table against a
    /// mapping that only works on hand-written fixtures.
    #[test]
    fn real_discord_everyone_bitfield_maps_sensibly() {
        let mapped = map_role_permissions(2248329584430657);

        for expected in [
            ChannelPermission::ViewChannel,
            ChannelPermission::SendMessage,
            ChannelPermission::ReadMessageHistory,
            ChannelPermission::Connect,
            ChannelPermission::Speak,
            ChannelPermission::React,
            ChannelPermission::InviteOthers,
        ] {
            assert!(
                mapped & expected as u64 != 0,
                "expected {expected:?} in the mapped default role"
            );
        }

        // A default @everyone must not come out able to administer the server.
        for forbidden in [
            ChannelPermission::ManageServer,
            ChannelPermission::ManageRole,
            ChannelPermission::BanMembers,
            ChannelPermission::KickMembers,
        ] {
            assert!(
                mapped & forbidden as u64 == 0,
                "{forbidden:?} must not be granted to @everyone"
            );
        }
    }
}
