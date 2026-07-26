use std::collections::HashMap;

#[cfg(feature = "validator")]
use validator::Validate;

/// Maximum raids a single sheet may span (all must share one edition)
pub const MAX_SR_RAIDS_PER_SHEET: usize = 4;

/// Upper bound of the per-sheet reserves-per-user setting
pub const MAX_RESERVES_PER_USER: u8 = 10;

/// Upper bound of the per-sheet per-item cap setting
pub const MAX_ITEM_CAP: u8 = 20;

/// Maximum hard reserves on a sheet
pub const MAX_HARD_RESERVES: usize = 50;

/// Maximum length of a reserve / hard-reserve / sheet note
pub const MAX_SR_NOTE: usize = 200;

/// Character name length bounds (WoW name rules)
pub const MIN_CHARACTER_NAME: usize = 2;
/// Character name length bounds (WoW name rules)
pub const MAX_CHARACTER_NAME: usize = 12;

auto_derived!(
    /// A World of Warcraft class, in Gargul's lowercase wire form —
    /// the serde form is exported into addon blobs verbatim.
    #[serde(rename_all = "lowercase")]
    pub enum WowClass {
        Warrior,
        Paladin,
        Hunter,
        Rogue,
        Priest,
        Shaman,
        Mage,
        Warlock,
        Druid,
        /// Wrath sheets only — the class does not exist in Classic/TBC
        DeathKnight,
    }

    /// An item a leader has taken off the table before reserves open
    /// (loot-council / guild-bank items). Soft reserves on hard-reserved
    /// items are rejected.
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct HardReserve {
        /// Item id (must belong to one of the sheet's raids)
        pub item_id: u32,
        /// Who or what the item is reserved for
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 50)))]
        pub reserved_for: String,
        /// Optional note
        #[cfg_attr(feature = "validator", validate(length(max = 200)))]
        #[serde(skip_serializing_if = "Option::is_none", default)]
        pub note: Option<String>,
    }

    /// The immutable definition of a soft-reserve sheet, embedded in its
    /// carrying message.
    ///
    /// This is a creation-time snapshot for cold render only — settings
    /// edits leave it stale by design; hydrated dynamic state wins
    /// client-side. Mutable state lives in the sheet object and is
    /// fetched / pushed separately so reserves never republish the
    /// message.
    pub struct SoftResDefinition {
        /// Sheet id
        pub id: String,
        /// Sheet title
        pub title: String,
        /// Game edition every raid on this sheet belongs to
        /// ("classic" | "tbc" | "wrath")
        pub edition: String,
        /// Catalog raid ids in scope (1..=4, single edition)
        pub raids: Vec<String>,
        /// How many items each raider may reserve (1..=10)
        pub reserves_per_user: u8,
        /// Cap on distinct raiders per item, when set (1..=20)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub per_item_cap: Option<u8>,
        /// Whether one raider may reserve the same item more than once
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub allow_duplicates: bool,
        /// Whether items are restricted to classes that can use them
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub class_restriction: bool,
        /// Whether reserves are hidden from non-managers until export
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub hidden: bool,
        /// Whether the sheet locks when its linked event starts
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub lock_at_event_start: bool,
        /// Optional sheet note shown on the card
        #[serde(skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        /// Hard reserves (items taken off the table)
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        pub hard_reserves: Vec<HardReserve>,
    }

    /// One raider's reservation row on a sheet
    pub struct SoftResReserve {
        /// Reserving user's id (platform identity bound to the row)
        pub user_id: String,
        /// Self-reported character name (2..=12, letters only)
        pub character_name: String,
        /// Self-reported class
        pub class: WowClass,
        /// Reserved item ids (1..=reserves_per_user; duplicates allowed
        /// only when the sheet allows them)
        pub items: Vec<u32>,
        /// Optional note to the loot master
        #[serde(skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        /// +1 attendance bonus (always 0 in v1; exported verbatim)
        #[serde(skip_serializing_if = "crate::if_zero_i32", default)]
        pub plus_ones: i32,
        /// When this row was last written (ms since epoch, UTC)
        pub edited_at: i64,
    }

    /// Dynamic sheet state.
    ///
    /// `reserves` / `item_counts` are omitted on hidden sheets unless the
    /// requester is the creator or has ManageMessages — per-item
    /// aggregates are exactly the strategic signal `hidden` hides; this
    /// is enforced server-side. `my_reserve` is always the requester's
    /// own row (own data is never hidden from its owner).
    pub struct SoftRes {
        /// Sheet id
        #[serde(rename = "_id")]
        pub id: String,
        /// Id of the message carrying this sheet
        pub message_id: String,
        /// Id of the channel the sheet was created in
        pub channel_id: String,
        /// Id of the linked calendar event, when linked
        #[serde(skip_serializing_if = "Option::is_none")]
        pub event_id: Option<String>,
        /// Id of the sheet creator
        pub creator_id: String,
        /// Whether the sheet is locked (manual lock, event cancellation,
        /// or `locks_at` having passed — pre-resolved server-side)
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub locked: bool,
        /// When the sheet auto-locks (ms since epoch, UTC) — snapshotted
        /// from the linked event's start at creation
        #[serde(skip_serializing_if = "Option::is_none")]
        pub locks_at: Option<i64>,
        /// Number of reserve rows (raiders, not item picks)
        pub total_reserves: i64,
        /// Every reserve row (gated, see struct docs)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub reserves: Option<Vec<SoftResReserve>>,
        /// Aggregate reserve count per item id, keyed by stringified item
        /// id; zero-count items omitted (gated same as `reserves`)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub item_counts: Option<HashMap<String, u32>>,
        /// The requesting user's own reserve row, if they have reserved
        #[serde(skip_serializing_if = "Option::is_none")]
        pub my_reserve: Option<SoftResReserve>,
    }

    /// Create a new soft-reserve sheet
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataSoftResCreate {
        /// Unique token to prevent duplicate message sending
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 64)))]
        pub nonce: Option<String>,

        /// Sheet title
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 100)))]
        pub title: String,

        /// Game edition (must match every raid in `raids`)
        pub edition: String,

        /// Catalog raid ids in scope (1..=4, single edition)
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 4)))]
        pub raids: Vec<String>,

        /// How many items each raider may reserve (1..=10, default 1)
        #[cfg_attr(feature = "validator", validate(range(min = 1, max = 10)))]
        pub reserves_per_user: Option<u8>,

        /// Cap on distinct raiders per item (1..=20; absent = uncapped)
        #[cfg_attr(feature = "validator", validate(range(min = 1, max = 20)))]
        pub per_item_cap: Option<u8>,

        /// Whether one raider may reserve the same item more than once
        #[serde(default)]
        pub allow_duplicates: bool,

        /// Whether items are restricted to classes that can use them
        #[serde(default)]
        pub class_restriction: bool,

        /// Whether reserves are hidden from non-managers until export
        #[serde(default)]
        pub hidden: bool,

        /// Whether the sheet locks when its linked event starts
        /// (requires `event_id`)
        #[serde(default)]
        pub lock_at_event_start: bool,

        /// Optional sheet note
        #[cfg_attr(feature = "validator", validate(length(max = 200)))]
        pub note: Option<String>,

        /// Hard reserves (items taken off the table). Per-row field
        /// constraints are validated explicitly by the create route.
        #[cfg_attr(feature = "validator", validate(length(max = 50)))]
        #[serde(default)]
        pub hard_reserves: Vec<HardReserve>,

        /// Calendar event to link this sheet to (one sheet per event;
        /// requires event-manage rights, non-recurring, non-cancelled)
        pub event_id: Option<String>,
    }

    /// Set (or replace) the requesting user's reservation row
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataSoftResReserve {
        /// Character name (2..=12, letters only — validated at the route)
        #[cfg_attr(feature = "validator", validate(length(min = 2, max = 12)))]
        pub character_name: String,

        /// Character class (validated against the sheet's edition)
        pub class: WowClass,

        /// Item ids to reserve (1..=reserves_per_user — the per-sheet
        /// bound is enforced at the route; this is the hard ceiling)
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 10)))]
        pub items: Vec<u32>,

        /// Optional note to the loot master
        #[cfg_attr(feature = "validator", validate(length(max = 200)))]
        pub note: Option<String>,
    }

    /// Optional sheet fields that can be unset by an edit
    pub enum FieldsSoftRes {
        PerItemCap,
        Note,
    }

    /// Edit a sheet's settings (raids are immutable post-create —
    /// existing reserves reference them)
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataSoftResEdit {
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 100)))]
        #[serde(default)]
        pub title: Option<String>,

        #[cfg_attr(feature = "validator", validate(range(min = 1, max = 10)))]
        #[serde(default)]
        pub reserves_per_user: Option<u8>,

        #[cfg_attr(feature = "validator", validate(range(min = 1, max = 20)))]
        #[serde(default)]
        pub per_item_cap: Option<u8>,

        #[serde(default)]
        pub allow_duplicates: Option<bool>,

        #[serde(default)]
        pub class_restriction: Option<bool>,

        #[serde(default)]
        pub hidden: Option<bool>,

        #[serde(default)]
        pub lock_at_event_start: Option<bool>,

        #[cfg_attr(feature = "validator", validate(length(max = 200)))]
        #[serde(default)]
        pub note: Option<String>,

        /// Full replacement of the hard-reserve list, when present.
        /// A swap that now conflicts with existing reserves does NOT
        /// evict them (documented non-eviction rule).
        #[cfg_attr(feature = "validator", validate(length(max = 50)))]
        #[serde(default)]
        pub hard_reserves: Option<Vec<HardReserve>>,

        /// Fields to unset
        #[serde(default)]
        pub remove: Vec<FieldsSoftRes>,
    }

    /// Bulk-fetch sheet state for the sheets visible on a page of messages
    #[cfg_attr(feature = "validator", derive(Validate))]
    pub struct DataSoftResFetchBulk {
        /// Sheet ids to fetch (from the messages' embedded definitions)
        #[cfg_attr(feature = "validator", validate(length(min = 1, max = 25)))]
        pub ids: Vec<String>,
    }

    /// An addon-importable export of a sheet's full reserve data
    pub struct SoftResExportResponse {
        /// The format that was rendered ("gargul" | "raidres" | "csv")
        pub format: String,
        /// The rendered payload (base64 blob or CSV text)
        pub payload: String,
    }
);

impl WowClass {
    /// The lowercase wire / export form (identical to the serde form).
    pub fn as_str(&self) -> &'static str {
        match self {
            WowClass::Warrior => "warrior",
            WowClass::Paladin => "paladin",
            WowClass::Hunter => "hunter",
            WowClass::Rogue => "rogue",
            WowClass::Priest => "priest",
            WowClass::Shaman => "shaman",
            WowClass::Mage => "mage",
            WowClass::Warlock => "warlock",
            WowClass::Druid => "druid",
            WowClass::DeathKnight => "deathknight",
        }
    }

    /// Whether this class exists in the given edition — Death Knights
    /// only exist in Wrath.
    pub fn valid_in_edition(&self, edition: &str) -> bool {
        !matches!(self, WowClass::DeathKnight) || edition == "wrath"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wow_class_wire_form_is_gargul_lowercase() {
        // Gargul's SoftRes.lua matches on these exact strings; the serde
        // form and as_str must never drift apart.
        for class in [
            WowClass::Warrior,
            WowClass::Paladin,
            WowClass::Hunter,
            WowClass::Rogue,
            WowClass::Priest,
            WowClass::Shaman,
            WowClass::Mage,
            WowClass::Warlock,
            WowClass::Druid,
            WowClass::DeathKnight,
        ] {
            let wire = serde_json::to_string(&class).unwrap();
            assert_eq!(wire, format!("\"{}\"", class.as_str()));
        }
    }

    #[test]
    fn death_knight_is_wrath_only() {
        assert!(WowClass::DeathKnight.valid_in_edition("wrath"));
        assert!(!WowClass::DeathKnight.valid_in_edition("classic"));
        assert!(!WowClass::DeathKnight.valid_in_edition("tbc"));
        assert!(WowClass::Druid.valid_in_edition("classic"));
    }
}
