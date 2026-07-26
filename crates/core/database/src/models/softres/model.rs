use std::collections::HashMap;

use revolt_models::v0;

auto_derived!(
    /// The server-side record of a soft-reserve sheet.
    ///
    /// The immutable definition (title / edition / raids / settings) is
    /// snapshotted here AND embedded in the carrying message; the live
    /// lock state and the reserve rows live ONLY here (and in
    /// `softres_reserves`) so reserve traffic never republishes the
    /// message. Settings edits update this record and leave the embedded
    /// message copy stale by design — hydrated state wins client-side.
    pub struct SoftResSheet {
        /// Sheet id
        #[serde(rename = "_id")]
        pub id: String,
        /// Id of the message carrying this sheet (unique — one sheet per
        /// message)
        pub message: String,
        /// Id of the channel the sheet was created in
        pub channel: String,
        /// Id of the server, when the channel is a server channel
        #[serde(skip_serializing_if = "Option::is_none")]
        pub server: Option<String>,
        /// Id of the linked calendar event (unique sparse — one sheet per
        /// event). Never consulted after creation: `locks_at` is
        /// snapshotted at create, so a dangling reference is inert.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub event: Option<String>,
        /// Id of the sheet creator
        pub creator: String,
        /// Sheet title
        pub title: String,
        /// Game edition every raid on this sheet belongs to
        pub edition: String,
        /// Catalog raid ids in scope (immutable post-create — reserves
        /// reference them)
        pub raids: Vec<String>,
        /// How many items each raider may reserve (1..=10)
        pub reserves_per_user: u8,
        /// Cap on reserve copies per item, when set (1..=20)
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
        /// When the sheet auto-locks (ms since epoch, UTC) — snapshotted
        /// from the linked event's start at creation. Lock checks are a
        /// pure timestamp compare; the event is never re-fetched.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub locks_at: Option<i64>,
        /// Optional sheet note
        #[serde(skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        /// Hard reserves (items taken off the table)
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        pub hard_reserves: Vec<v0::HardReserve>,
        /// Whether the sheet is manually locked (leader lock or
        /// event-cancellation lock; `locks_at` passing does NOT set this —
        /// it is resolved lazily at read time)
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub locked: bool,
        /// When the sheet was created (ms since epoch, UTC)
        pub created_at: i64,
        /// When the sheet's settings were last edited (ms since epoch, UTC)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub edited_at: Option<i64>,
    }

    /// One raider's reservation row. `_id` is `"{sheet}:{user}"`, so a
    /// user can never hold two rows on one sheet — re-reserving replaces.
    pub struct SoftResReserveRow {
        /// Composite id: `"{sheet}:{user}"`
        #[serde(rename = "_id")]
        pub id: String,
        /// Sheet id
        pub sheet: String,
        /// Reserving user's id
        pub user: String,
        /// Channel the sheet lives in (channel-deletion cascade)
        pub channel: String,
        /// Self-reported character name (2..=12, letters only)
        pub character_name: String,
        /// Self-reported class
        pub class: v0::WowClass,
        /// Reserved item ids
        pub items: Vec<u32>,
        /// Optional note to the loot master
        #[serde(skip_serializing_if = "Option::is_none")]
        pub note: Option<String>,
        /// +1 attendance bonus (always 0 in v1; kept for export parity)
        pub plus_ones: i32,
        /// When this row was last written (ms since epoch, UTC)
        pub edited_at: i64,
    }
);

impl SoftResSheet {
    /// Composite reserve-row key.
    pub fn reserve_key(sheet: &str, user: &str) -> String {
        format!("{sheet}:{user}")
    }

    /// Whether the sheet is locked at the given instant: the stored flag
    /// (manual / event-cancel lock) OR the snapshotted auto-lock having
    /// passed. Pure compare — no DB or event fetch on the hot path.
    pub fn is_locked_now(&self, now_ms: i64) -> bool {
        self.locked || self.locks_at.is_some_and(|t| now_ms >= t)
    }

    /// The immutable definition embedded in the carrying message.
    pub fn definition(&self) -> v0::SoftResDefinition {
        v0::SoftResDefinition {
            id: self.id.clone(),
            title: self.title.clone(),
            edition: self.edition.clone(),
            raids: self.raids.clone(),
            reserves_per_user: self.reserves_per_user,
            per_item_cap: self.per_item_cap,
            allow_duplicates: self.allow_duplicates,
            class_restriction: self.class_restriction,
            hidden: self.hidden,
            lock_at_event_start: self.lock_at_event_start,
            note: self.note.clone(),
            hard_reserves: self.hard_reserves.clone(),
        }
    }

    /// Aggregate reserve copies per item id (stringified — BSON/JSON map
    /// keys must be strings), zero-count items absent by construction.
    pub fn item_counts_of(rows: &[SoftResReserveRow]) -> HashMap<String, u32> {
        let mut counts: HashMap<String, u32> = HashMap::new();
        for row in rows {
            for item in &row.items {
                *counts.entry(item.to_string()).or_insert(0) += 1;
            }
        }
        counts
    }

    /// API model with the hidden-sheet gate applied server-side.
    ///
    /// `include_full` must be true only when the sheet is not hidden OR
    /// the viewer is the creator / has ManageMessages: `reserves` AND
    /// `item_counts` are both gated (aggregate per-item counts are
    /// exactly the strategic signal `hidden` exists to hide). The
    /// viewer's own row is always included — own data is never hidden
    /// from its owner. `locked` is pre-resolved against `now_ms` so cold
    /// loads past `locks_at` render locked without any event firing.
    pub fn into_model(
        self,
        include_full: bool,
        rows: Vec<SoftResReserveRow>,
        viewer: &str,
        now_ms: i64,
    ) -> v0::SoftRes {
        let locked = self.is_locked_now(now_ms);
        let definition = self.definition();
        let total_reserves = rows.len() as i64;
        let my_reserve = rows
            .iter()
            .find(|row| row.user == viewer)
            .cloned()
            .map(SoftResReserveRow::into_model);

        let (reserves, item_counts) = if include_full {
            let item_counts = Self::item_counts_of(&rows);
            (
                Some(
                    rows.into_iter()
                        .map(SoftResReserveRow::into_model)
                        .collect(),
                ),
                Some(item_counts),
            )
        } else {
            (None, None)
        };

        v0::SoftRes {
            id: self.id,
            definition,
            message_id: self.message,
            channel_id: self.channel,
            event_id: self.event,
            creator_id: self.creator,
            locked,
            locks_at: self.locks_at,
            total_reserves,
            reserves,
            item_counts,
            my_reserve,
        }
    }
}

impl SoftResReserveRow {
    /// The wire form of this row.
    pub fn into_model(self) -> v0::SoftResReserve {
        v0::SoftResReserve {
            user_id: self.user,
            character_name: self.character_name,
            class: self.class,
            items: self.items,
            note: self.note,
            plus_ones: self.plus_ones,
            edited_at: self.edited_at,
        }
    }
}
