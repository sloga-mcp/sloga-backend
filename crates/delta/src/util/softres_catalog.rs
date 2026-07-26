//! Static soft-reserve loot catalog.
//!
//! Generated offline by `scripts/gen-softres-catalog/` from GPL world-DB
//! dumps (vmangos / cmangos tbc-db / TrinityCore TDB 335 — see that
//! directory's README for provenance) and checked into
//! `crates/delta/assets/softres_catalog/`. The catalog is edition-first:
//! a soft-res sheet's raids must all belong to one edition.
//!
//! Edition metadata (editions + raid lists) is parsed eagerly on first
//! touch — it is a few KB. The per-raid item tables are embedded via
//! `include_str!` but parsed lazily **per edition**, so a server whose
//! sheets only ever touch Classic never pays the TBC/Wrath parse cost.
//! Total embedded footprint is ~600 KB, well under the size at which the
//! plan calls for moving to disk reads.

use std::collections::HashMap;

use once_cell::sync::Lazy;
use revolt_result::{create_error, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One selectable game edition (Classic Era, TBC, Wrath).
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct CatalogEdition {
    /// Stable edition id ("classic", "tbc", "wrath")
    pub id: String,
    /// Display name
    pub name: String,
    /// Display ordering (ascending)
    pub sort: u8,
}

/// One raid instance (for Wrath, one size/difficulty variant of one).
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct CatalogRaid {
    /// Stable raid id — a public contract once exported (lands in
    /// Gargul's `metadata.instance`); never renamed.
    pub id: String,
    /// Owning edition id
    pub edition: String,
    /// Display name
    pub name: String,
    /// Raid player count (display metadata)
    pub slots: u8,
    /// Wrath only: 10/25-player variant discriminator
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u8>,
    /// Wrath only: "normal" | "heroic"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub difficulty: Option<String>,
}

/// One reservable item of a raid's loot table.
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct CatalogItem {
    /// Item id (globally unique across editions)
    pub id: u32,
    /// Item name
    pub name: String,
    /// Item quality (3 = rare, 4 = epic, 5 = legendary)
    pub quality: u8,
    /// Encounter attribution ("Ragnaros", "A / B" for shared drops,
    /// "Trash" for zone drops)
    pub boss: String,
    /// Lowercase class names allowed to use the item; absent when
    /// unrestricted. Tier tokens legitimately carry several.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowable_classes: Option<Vec<String>>,
}

macro_rules! asset {
    ($path:literal) => {
        include_str!(concat!("../../assets/softres_catalog/", $path))
    };
}

static EDITIONS_JSON: &str = asset!("editions.json");

static RAIDS_JSON: [(&str, &str); 3] = [
    ("classic", asset!("raids/classic.json")),
    ("tbc", asset!("raids/tbc.json")),
    ("wrath", asset!("raids/wrath.json")),
];

/// (edition, raid id, embedded item table). Raid ids are stable — see
/// [`CatalogRaid::id`].
static ITEMS_JSON: [(&str, &str, &str); 40] = [
    ("classic", "mc", asset!("items/classic/mc.json")),
    ("classic", "onyxia", asset!("items/classic/onyxia.json")),
    ("classic", "bwl", asset!("items/classic/bwl.json")),
    ("classic", "zg", asset!("items/classic/zg.json")),
    ("classic", "aq20", asset!("items/classic/aq20.json")),
    ("classic", "aq40", asset!("items/classic/aq40.json")),
    ("classic", "naxx", asset!("items/classic/naxx.json")),
    ("tbc", "kara", asset!("items/tbc/kara.json")),
    ("tbc", "gruul", asset!("items/tbc/gruul.json")),
    ("tbc", "magtheridon", asset!("items/tbc/magtheridon.json")),
    ("tbc", "ssc", asset!("items/tbc/ssc.json")),
    ("tbc", "tk", asset!("items/tbc/tk.json")),
    ("tbc", "hyjal", asset!("items/tbc/hyjal.json")),
    ("tbc", "bt", asset!("items/tbc/bt.json")),
    ("tbc", "za", asset!("items/tbc/za.json")),
    ("tbc", "swp", asset!("items/tbc/swp.json")),
    ("wrath", "naxx10", asset!("items/wrath/naxx10.json")),
    ("wrath", "naxx25", asset!("items/wrath/naxx25.json")),
    ("wrath", "os10", asset!("items/wrath/os10.json")),
    ("wrath", "os25", asset!("items/wrath/os25.json")),
    ("wrath", "eoe10", asset!("items/wrath/eoe10.json")),
    ("wrath", "eoe25", asset!("items/wrath/eoe25.json")),
    ("wrath", "voa10", asset!("items/wrath/voa10.json")),
    ("wrath", "voa25", asset!("items/wrath/voa25.json")),
    ("wrath", "ulduar10", asset!("items/wrath/ulduar10.json")),
    ("wrath", "ulduar25", asset!("items/wrath/ulduar25.json")),
    ("wrath", "toc10", asset!("items/wrath/toc10.json")),
    ("wrath", "toc25", asset!("items/wrath/toc25.json")),
    ("wrath", "toc10hc", asset!("items/wrath/toc10hc.json")),
    ("wrath", "toc25hc", asset!("items/wrath/toc25hc.json")),
    ("wrath", "onyxia10", asset!("items/wrath/onyxia10.json")),
    ("wrath", "onyxia25", asset!("items/wrath/onyxia25.json")),
    ("wrath", "icc10", asset!("items/wrath/icc10.json")),
    ("wrath", "icc25", asset!("items/wrath/icc25.json")),
    ("wrath", "icc10hc", asset!("items/wrath/icc10hc.json")),
    ("wrath", "icc25hc", asset!("items/wrath/icc25hc.json")),
    ("wrath", "rs10", asset!("items/wrath/rs10.json")),
    ("wrath", "rs25", asset!("items/wrath/rs25.json")),
    ("wrath", "rs10hc", asset!("items/wrath/rs10hc.json")),
    ("wrath", "rs25hc", asset!("items/wrath/rs25hc.json")),
];

/// Editions + raid metadata. Eager (a few KB); also backs raid-id →
/// edition lookups without touching item tables.
struct CatalogIndex {
    editions: Vec<CatalogEdition>,
    raids: Vec<CatalogRaid>,
    /// raid id -> index into `raids`
    raid_by_id: HashMap<&'static str, usize>,
}

static INDEX: Lazy<CatalogIndex> = Lazy::new(|| {
    let editions: Vec<CatalogEdition> =
        serde_json::from_str(EDITIONS_JSON).expect("valid softres editions.json");

    let mut raids: Vec<CatalogRaid> = Vec::new();
    for (edition, json) in RAIDS_JSON {
        let parsed: Vec<CatalogRaid> = serde_json::from_str(json)
            .unwrap_or_else(|e| panic!("valid raids/{}.json: {}", edition, e));
        raids.extend(parsed);
    }

    // Keys borrow from ITEMS_JSON's static ids so the map needs no owned
    // strings; this also asserts the raids files and item tables agree.
    let mut raid_by_id = HashMap::new();
    for (idx, raid) in raids.iter().enumerate() {
        let (_, id, _) = ITEMS_JSON
            .iter()
            .find(|(_, id, _)| *id == raid.id)
            .unwrap_or_else(|| panic!("raid {} has no embedded item table", raid.id));
        assert!(
            raid_by_id.insert(*id, idx).is_none(),
            "duplicate raid id {}",
            id
        );
    }

    CatalogIndex {
        editions,
        raids,
        raid_by_id,
    }
});

/// One edition's parsed item tables: raid id -> item list + id index.
type EditionItems = HashMap<&'static str, (Vec<CatalogItem>, HashMap<u32, usize>)>;

fn parse_edition_items(edition: &str) -> EditionItems {
    ITEMS_JSON
        .iter()
        .filter(|(ed, _, _)| *ed == edition)
        .map(|(_, raid_id, json)| {
            let items: Vec<CatalogItem> = serde_json::from_str(json)
                .unwrap_or_else(|e| panic!("valid items table for {}: {}", raid_id, e));
            let by_id = items
                .iter()
                .enumerate()
                .map(|(i, item)| (item.id, i))
                .collect();
            (*raid_id, (items, by_id))
        })
        .collect()
}

static CLASSIC_ITEMS: Lazy<EditionItems> = Lazy::new(|| parse_edition_items("classic"));
static TBC_ITEMS: Lazy<EditionItems> = Lazy::new(|| parse_edition_items("tbc"));
static WRATH_ITEMS: Lazy<EditionItems> = Lazy::new(|| parse_edition_items("wrath"));

fn edition_items(edition: &str) -> Option<&'static EditionItems> {
    match edition {
        "classic" => Some(&CLASSIC_ITEMS),
        "tbc" => Some(&TBC_ITEMS),
        "wrath" => Some(&WRATH_ITEMS),
        _ => None,
    }
}

/// All editions, ordered by `sort`.
pub fn editions() -> &'static [CatalogEdition] {
    &INDEX.editions
}

/// All raids of one edition, in catalog order.
pub fn raids_of_edition(edition: &str) -> impl Iterator<Item = &'static CatalogRaid> + '_ {
    INDEX.raids.iter().filter(move |r| r.edition == edition)
}

/// Raid metadata by id.
pub fn raid(raid_id: &str) -> Option<&'static CatalogRaid> {
    INDEX.raid_by_id.get(raid_id).map(|&idx| &INDEX.raids[idx])
}

/// The edition a raid belongs to.
pub fn edition_of(raid_id: &str) -> Option<&'static str> {
    raid(raid_id).map(|r| r.edition.as_str())
}

/// Whether a raid id exists in the catalog.
pub fn raid_exists(raid_id: &str) -> bool {
    INDEX.raid_by_id.contains_key(raid_id)
}

/// Whether every raid id exists and they all belong to a single edition.
/// An empty list has no edition — returns false.
pub fn same_edition(raid_ids: &[String]) -> bool {
    let mut editions = raid_ids.iter().map(|id| edition_of(id));
    match editions.next() {
        None | Some(None) => false,
        Some(Some(first)) => editions.all(|e| e == Some(first)),
    }
}

/// Look up an item in any of the given raids' loot tables (first match).
/// Unknown raid ids are skipped, not fatal: sheet creation validates its
/// raids with [`raid_exists`], but stored sheets outlive catalog
/// regenerations — if a slug ever vanished despite the stability
/// contract, reserves against the sheet's remaining valid raids must
/// keep working.
pub fn item_in_raids(item_id: u32, raid_ids: &[String]) -> Option<&'static CatalogItem> {
    for raid_id in raid_ids {
        let Some(edition) = edition_of(raid_id) else {
            continue;
        };
        let Some(tables) = edition_items(edition) else {
            continue;
        };
        if let Some((items, by_id)) = tables.get(raid_id.as_str()) {
            if let Some(&idx) = by_id.get(&item_id) {
                return Some(&items[idx]);
            }
        }
    }
    None
}

/// A raid's full item table, for the catalog route.
pub fn raid_items(raid_id: &str) -> Result<&'static [CatalogItem]> {
    let raid = raid(raid_id).ok_or_else(|| create_error!(UnknownRaid))?;
    let tables = edition_items(&raid.edition).ok_or_else(|| create_error!(UnknownRaid))?;
    let (items, _) = tables
        .get(raid.id.as_str())
        .ok_or_else(|| create_error!(UnknownRaid))?;
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every embedded blob parses and every raid has a non-empty table —
    /// a malformed regeneration must fail tests, not first traffic.
    #[test]
    fn catalog_parses_and_is_complete() {
        assert_eq!(editions().len(), 3);
        assert!(editions().windows(2).all(|w| w[0].sort < w[1].sort));

        assert_eq!(INDEX.raids.len(), ITEMS_JSON.len());
        for raid in &INDEX.raids {
            let items = raid_items(&raid.id).expect("raid has items");
            assert!(
                !items.is_empty(),
                "raid {} has an empty item table",
                raid.id
            );
            assert!((3..=5).contains(&items.iter().map(|i| i.quality).min().unwrap()));
            assert!((3..=5).contains(&items.iter().map(|i| i.quality).max().unwrap()));
        }
    }

    /// Wrath variants must carry size/difficulty; Classic/TBC must not.
    #[test]
    fn size_and_difficulty_are_wrath_only() {
        for raid in &INDEX.raids {
            if raid.edition == "wrath" {
                assert!(raid.size.is_some() && raid.difficulty.is_some(), "{}", raid.id);
            } else {
                assert!(raid.size.is_none() && raid.difficulty.is_none(), "{}", raid.id);
            }
        }
    }

    #[test]
    fn edition_helpers() {
        assert_eq!(edition_of("mc"), Some("classic"));
        assert_eq!(edition_of("icc25hc"), Some("wrath"));
        assert_eq!(edition_of("nope"), None);
        assert!(raid_exists("kara"));
        assert!(!raid_exists("kara2"));

        let ids = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(same_edition(&ids(&["mc", "bwl"])));
        assert!(!same_edition(&ids(&["mc", "kara"])));
        assert!(!same_edition(&[]));
        assert!(!same_edition(&ids(&["mc", "nope"])));
    }

    /// Marquee drops stay put across regenerations (raid ids and item
    /// membership are a public contract via addon exports).
    #[test]
    fn marquee_items_present() {
        for (item, raids) in [
            (17204, "mc"),          // Eye of Sulfuras
            (18563, "mc"),          // Bindings of the Windseeker (Garr half)
            (22691, "naxx"),        // Corrupted Ashbringer
            (32837, "bt"),          // Warglaive of Azzinoth
            (34334, "swp"),         // Thori'dal
            (45038, "ulduar25"),    // Fragment of Val'anyr
            (48705, "toc10hc"),     // Attrition (ToGC tribute chest)
            (47553, "toc25hc"),     // Bolvar's Devotion (ToGC tribute chest)
            (50818, "icc25hc"),     // Invincible's Reins
        ] {
            let found = item_in_raids(item, &[raids.to_string()]);
            assert!(found.is_some(), "item {} missing from {}", item, raids);
        }

        // Non-member lookups miss: Warglaives are not in Karazhan.
        assert!(item_in_raids(32837, &["kara".to_string()]).is_none());

        // An unknown raid id earlier in the list must not abort the
        // lookup for the valid raids after it.
        assert!(item_in_raids(17204, &["gone".to_string(), "mc".to_string()]).is_some());
    }

    /// TBC/Wrath tier tokens keep their multi-class restriction lists.
    #[test]
    fn multiclass_tokens_survive() {
        let token = item_in_raids(34851, &["swp".to_string()])
            .expect("Bracers of the Forgotten Protector in Sunwell");
        let classes = token.allowable_classes.as_ref().expect("restricted");
        assert!(
            classes.len() > 1,
            "token collapsed to one class: {:?}",
            classes
        );
    }
}
