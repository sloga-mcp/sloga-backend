# gen-softres-catalog

Offline generator for the static soft-reserve loot catalog served by delta
(`crates/delta/assets/softres_catalog/`). **Not part of the build** — the
generated JSON is checked in; this tool exists to regenerate or extend it.

## Output

```
editions.json               [{id, name, sort}]
raids/<edition>.json        [{id, edition, name, slots, size?, difficulty?}]
items/<edition>/<raid>.json [{id, name, quality, boss, allowable_classes?}]
```

- `slots` is the raid's player count. Wrath instances additionally carry
  `size` (10/25) and `difficulty` (normal/heroic) because each variant
  drops **different item ids** and is a distinct catalog raid.
- `allowable_classes` is emitted only when the item is class-restricted;
  TBC/Wrath tier tokens legitimately carry multi-class lists.
- **Raid ids are a public contract** once shipped (they land in Gargul's
  `metadata.instance` on export). Never rename one.

## Sources & licensing

| Edition | Source | File |
|---|---|---|
| `classic` | [vmangos/core](https://github.com/vmangos/core) `db_latest` release | `mysql-dump/mangos.sql` (world DB, 1.12 state via `patch <= 10` rows) |
| `tbc` | [cmangos/tbc-db](https://github.com/cmangos/tbc-db) | `Full_DB/TBCDB_1.10.0_ReturnOfTheVengeance.sql.gz` |
| `wrath` | [TrinityCore TDB 335](https://github.com/TrinityCore/TrinityCore/releases/tag/TDB335.25101) | `TDB_full_world_335.25101_2025_10_21.sql` |

All three databases are GPL-licensed community reconstructions. We ship
only extracted facts (item id/name/quality/class mask, boss attribution),
with this attribution. We deliberately do **not** use Gargul's data files
(All Rights Reserved).

`wrath` was originally planned against cmangos/wotlk-db, but that dump is
materially incomplete for late Wrath (The Lich King, Sindragosa,
Blood-Queen, half of VoA have empty loot; the ICC and Freya caches are
stubs) — TrinityCore's TDB is complete and its 3.3.5 branch is the same
pipeline later expansions (Cata/MoP) would use.

## Regenerating

```
python3 generate.py \
  --classic mangos.sql --tbc tbc.sql --wrath tdb335.sql \
  --out ../../crates/delta/assets/softres_catalog
```

Runtime is a few minutes (the dumps are parsed with a real SQL-value
tokenizer — strings contain commas, parens and newlines). The generator
prints per-raid item counts and `WARN:` lines for anything that resolved
empty or ambiguous; a clean run ends with `0 warnings`.

## How raids are assembled

`raids.py` is the hand-curated encounter config — the world DBs have no
per-map boss roster (many bosses are script-summoned and never appear in
spawn tables). Per raid:

- **Bosses** resolve by exact `creature_template` name, or explicit entry
  id where names collide (pre-raid Sindragosa, the two Hex Lord
  templates, …). Wrath 10/25/heroic variants resolve through
  `difficulty_entry_1..3` (1=25N, 2=10H, 3=25H, with fallback down the
  chain).
- **Chest-loot encounters** (Majordomo, Kara chess, the Ulduar caches,
  Kologarn's Cache of Living Stone, ICC's Gunship Armory /
  Deathbringer's Cache / Cache of the Dreamwalker, ToC's Champions'
  Cache, Malygos' Alexstrasza's Gift, the Four Horsemen chests, ZA's
  timed-run trunks) use explicit gameobject entries. Chest entry ids are
  NOT reliably in mode order — they were pinned by comparing item-level
  profiles and shared name-sets across the variants (`--compare-loot`),
  e.g. the Gunship 10H entry id is *lower* than its 10N entry id.
- **Trash** is a map-wide spawn sweep (epic-quality only), minus the
  configured boss creatures. Wrath raids also carry `trash_min_ilvl`
  because TDB trash tables reference low-level world-BoE lists.

Filtering rules (see constants in `generate.py`):

- boss loot: quality ≥ 3 (rare) — ZG/AQ20 bosses drop meaningful blues;
  trash: quality ≥ 4 (epic).
- mounts (item class 15, subclass 5) bypass every quality/ilvl filter — a
  mount is the archetypal soft-reserve item. 1.12 item data predates the
  Mount subclass, so the rare-quality AQ40 crystals are `CURATED_ADD`
  entries instead.
- quest-flagged drops are skipped (negative chance in MaNGOS dumps,
  `QuestRequired` in TDB). Positive-chance quest STARTERS (Head of
  Onyxia/Nefarian, Heart of Hakkar, Magtheridon's Head, Blood of Zul'jin,
  Verdant Sphere, the Focusing Iris keys, …) are deliberately KEPT: they
  are one-per-kill contested drops that raid leads do soft-reserve, and
  softres.it lists them too. The Wrath Onyxia heads stay excluded by id
  (pre-ship decision).
- gems (item class 3) are excluded — several TBC/Wrath bosses reference
  ~100-entry shared epic-gem lists.
- reference rows below 1% chance are skipped (shared world-drop lists).
- reference lists wired into ≥ 8 loot tables whose contents include
  recipes are treated as world-drop lists and skipped (the vmangos
  "boss drops a random world epic/recipe" mechanic). Sub-1% DIRECT rows
  can't be chance-filtered without losing legit rare mounts, so the
  handful of classic world drops wired directly into raid-trash tables
  are excluded by id instead.
- currency-style items (badges/emblems/Stone Keeper's Shards) and the
  condition-free Hallow's End boss drop are excluded by id
  (`EXCLUDED_ITEMS` in `raids.py`).
- `trash_max_ilvl` caps a wrath trash sweep per mode — Ulduar's trash
  templates carry the 25-player BoE reference list on their base
  (10-player) table.

## Curated deltas (`CURATED_ADD` / `CURATED_REMOVE` in `raids.py`)

The world DBs are community reconstructions with verified errors: TDB
wires XT-002's 25-hard items into the 10-man table, lacks any loot row
for Hodir's 25-hard Rare Cache of Winter contents and six real VoA
drops, and has two items that never drop (a vendor-only VoA glove, a VoA
item in Alexstrasza's Gift). These are patched per raid via
`CURATED_REMOVE` (ids dropped from one raid only) and `CURATED_ADD`
(raid → boss label → ids, metadata resolved from `item_template`). Every
entry cites its evidence inline; the 2026-07 full-catalog verification
pass (all 40 raids spot-checked against wowhead/wowtbc/wotlkdb + archived
2010 wowhead) is the baseline. Known-and-accepted source quirks NOT
patched: ToGC-10 carries the blacksmithing Plans but not the
tailoring/LW Patterns (TDB asymmetry, sub-1% recipes either way), and
ICC-25H drops both normal and heroic Marks (era-correct 3.3.5 behavior).

## Curation helpers

```
--find-creature "Name|Other"   # entries, rank, loot id, resolved item count
--find-go "Cache|Chest"        # chest gameobjects with loot
--dump-loot c:<entry>|go:<entry>       # resolved items with quality/ilvl
--dump-loot-raw creature:<loot_id>,... # raw rows (chance/group/ref)
--compare-loot go:A,go:B,...   # epic count + ilvl profile per variant
--map-audit <map id>           # spawned templates with epic loot (trash debug)
```

Each helper takes exactly one `--<edition> <dump>`.

## Adding an edition (Cata/MoP)

TrinityCore's corresponding TDB branch on the same pipeline: add the
edition to `EDITIONS`, its raids to `raids.py`, and run with a new
`--<edition>` flag wired in `main()` — the TrinityCore dialect is already
handled. This is intended to be a data-only commit plus a frontend
edition entry.
