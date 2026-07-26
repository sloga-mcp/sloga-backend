#!/usr/bin/env python3
"""Soft-reserve loot catalog generator.

Parses world-database SQL dumps (vmangos for Classic Era, cmangos tbc-db
for The Burning Crusade, TrinityCore TDB 335 for Wrath of the Lich King —
cmangos wotlk-db was rejected as materially incomplete, see README) and
emits the static, edition-first loot catalog that delta serves for
soft-reserve sheets:

    editions.json
    raids/<edition>.json
    items/<edition>/<raid_id>.json

This script is OFFLINE tooling — it is not part of the build. The dumps it
parses are GPL; we ship only extracted facts (item id/name/quality/class
mask, boss attribution) with attribution. See README.md for provenance and
regeneration instructions.

Usage:
    python3 generate.py --classic mangos.sql --tbc tbc.sql --wrath tdb335.sql \
        --out ../../crates/delta/assets/softres_catalog

    # curation helpers (print candidates, generate nothing):
    python3 generate.py --wrath wotlk.sql --find-go "Cache"
    python3 generate.py --tbc tbc.sql --find-creature "Illidari"
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict

import raids as raid_config

# ---------------------------------------------------------------------------
# SQL dump parsing
# ---------------------------------------------------------------------------

_CREATE_RE = re.compile(r"CREATE TABLE `(\w+)` \(", re.I)
_INSERT_RE = re.compile(r"^\s*INSERT\s+INTO\s+`(\w+)`", re.I)

# One token per match: NULL, 'string', "string", number, or punctuation.
_TOKEN_RE = re.compile(
    r"\s*(?:"
    r"(NULL)"
    r"|('(?:\\.|''|[^'\\])*')"
    r"|(\"(?:\\.|\"\"|[^\"\\])*\")"
    r"|([-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?)"
    r"|([(),;])"
    r")",
    re.S,
)

_STRING_UNESCAPE = re.compile(r"\\(.)|''|\"\"")
_UNESCAPE_MAP = {"n": "\n", "t": "\t", "r": "\r", "0": "\0"}


def _decode_string(raw: str) -> str:
    quote = raw[0]
    body = raw[1:-1]

    def sub(m: re.Match) -> str:
        if m.group(1) is not None:
            return _UNESCAPE_MAP.get(m.group(1), m.group(1))
        # Doubled-quote escape only applies to the string's own quote
        # character; a doubled other-quote is literal text.
        return quote if m.group(0) == quote * 2 else m.group(0)

    return _STRING_UNESCAPE.sub(sub, body)


class Dump:
    """Lazy access to the tables of one SQL dump.

    Table schemas come from the CREATE TABLE statements; rows from the
    INSERT statements (both mysqldump extended-insert style and the
    `insert into t(cols) values` style the cmangos dumps use). String
    values may contain commas, parens, quotes, and newlines — parsing is a
    real tokenizer, not a split.
    """

    def __init__(self, path: str):
        self.path = path
        self.columns: dict[str, list[str]] = {}
        self.rows: dict[str, list[tuple]] = {}

    def load(self, tables: set[str]) -> None:
        wanted = {t for t in tables if t not in self.rows}
        if not wanted:
            return
        for t in wanted:
            self.rows[t] = []

        in_create = None
        pending_table = None
        buf: list[str] = []

        with open(self.path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if pending_table is not None:
                    buf.append(line)
                    if self._try_finish_statement(pending_table, buf):
                        pending_table = None
                        buf = []
                    continue

                if in_create is not None:
                    stripped = line.strip()
                    if stripped.startswith(")"):
                        in_create = None
                        continue
                    m = re.match(r"`([^`]+)`", stripped)
                    if m:
                        self.columns[in_create].append(m.group(1))
                    continue

                m = _CREATE_RE.search(line)
                if m and m.group(1) in tables:
                    in_create = m.group(1)
                    self.columns[in_create] = []
                    continue

                m = _INSERT_RE.match(line)
                if m and m.group(1) in wanted:
                    buf = [line]
                    if not self._try_finish_statement(m.group(1), buf):
                        pending_table = m.group(1)

        # A statement that never terminated means the tokenizer choked on
        # something (new literal syntax in a future dump revision) and
        # silently dropped everything after it — fail loudly instead of
        # emitting a quietly hollow catalog.
        if pending_table is not None:
            raise RuntimeError(
                f"{self.path}: INSERT INTO `{pending_table}` never terminated "
                f"({sum(len(l) for l in buf)} bytes buffered) — tokenizer "
                f"cannot parse this dump revision"
            )

    def _try_finish_statement(self, table: str, buf: list[str]) -> bool:
        """Tokenize the accumulated statement; if it terminates (';' at
        depth 0), record its rows and return True. If it ends mid-string
        or mid-tuple, return False so more lines get appended."""
        text = "".join(buf)
        start = text.upper().find("VALUES")
        if start < 0:
            return False
        pos = start + len("VALUES")

        rows = []
        current: list = []
        depth = 0
        terminated = False
        while True:
            m = _TOKEN_RE.match(text, pos)
            if not m:
                # Either whitespace-only tail (incomplete statement) or an
                # unterminated string spanning into the next line.
                break
            pos = m.end()
            null_v, sq, dq, num, punct = m.groups()
            if punct == "(":
                depth += 1
                if depth == 1:
                    current = []
            elif punct == ")":
                depth -= 1
                if depth == 0:
                    rows.append(tuple(current))
            elif punct == ";":
                if depth == 0:
                    terminated = True
                    break
            elif punct == ",":
                pass
            elif depth >= 1:
                if null_v is not None:
                    current.append(None)
                elif num is not None:
                    current.append(float(num) if "." in num or "e" in num.lower() else int(num))
                else:
                    current.append(_decode_string(sq if sq is not None else dq))

        if terminated:
            self.rows[table].extend(rows)
            return True
        return False

    def table(self, name: str):
        cols = {c: i for i, c in enumerate(self.columns.get(name, []))}
        return cols, self.rows.get(name, [])


# ---------------------------------------------------------------------------
# Edition extraction
# ---------------------------------------------------------------------------

CLASS_BITS = [
    (1, "warrior"),
    (2, "paladin"),
    (4, "hunter"),
    (8, "rogue"),
    (16, "priest"),
    (32, "deathknight"),
    (64, "shaman"),
    (128, "mage"),
    (256, "warlock"),
    (1024, "druid"),
]

EDITION_CLASSES = {
    "classic": {c for _, c in CLASS_BITS if c != "deathknight"},
    "tbc": {c for _, c in CLASS_BITS if c != "deathknight"},
    "wrath": {c for _, c in CLASS_BITS},
}

# vmangos content patch for 1.12 state.
CLASSIC_PATCH = 10

BOSS_MIN_QUALITY = 3  # rare — ZG/AQ20 bosses legitimately drop blues
TRASH_MIN_QUALITY = 4  # epic — keeps map-wide sweeps from dredging junk

# Item classes excluded from the catalog: gems (3). Several TBC/Wrath bosses
# reference shared "random epic gem" loot lists ~100 entries deep — gems are
# rolled or banked, never soft-reserved, and they would drown the picker.
EXCLUDED_ITEM_CLASSES = {3}


def pick(cols, row, *names, default=None):
    for n in names:
        if n in cols:
            return row[cols[n]]
    return default


class Edition:
    """One edition's tables, indexed for catalog generation."""

    TABLES = {
        "item_template",
        "creature_template",
        "creature",
        "creature_loot_template",
        "reference_loot_template",
        "gameobject",
        "gameobject_template",
        "gameobject_loot_template",
    }

    def __init__(self, edition_id: str, dump: Dump):
        self.id = edition_id
        self.classic = edition_id == "classic"
        dump.load(self.TABLES)
        self._index(dump)

    def _patch_ok(self, cols, row) -> bool:
        if not self.classic:
            return True
        pmin = pick(cols, row, "patch_min", default=0) or 0
        pmax = pick(cols, row, "patch_max", default=CLASSIC_PATCH)
        if pmax is None:
            pmax = CLASSIC_PATCH
        return pmin <= CLASSIC_PATCH <= pmax

    def _index(self, dump: Dump) -> None:
        # item_template — vmangos has one row per (entry, patch); keep the
        # newest patch ≤ 1.12 for each entry.
        cols, rows = dump.table("item_template")
        items: dict[int, tuple] = {}
        for r in rows:
            entry = pick(cols, r, "entry")
            patch = pick(cols, r, "patch", default=0) or 0
            if self.classic and patch > CLASSIC_PATCH:
                continue
            prev = items.get(entry)
            if prev is None or patch >= prev[0]:
                items[entry] = (
                    patch,
                    pick(cols, r, "name"),
                    pick(cols, r, "quality", "Quality"),
                    pick(cols, r, "allowable_class", "AllowableClass"),
                    pick(cols, r, "class"),
                    pick(cols, r, "item_level", "ItemLevel"),
                )
        # entry -> (name, quality, allowable_class_mask, item_class, item_level)
        self.items = {e: v[1:] for e, v in items.items()}

        # creature_template
        cols, rows = dump.table("creature_template")
        self.creatures: dict[int, dict] = {}
        for r in rows:
            entry = pick(cols, r, "entry", "Entry")
            patch = pick(cols, r, "patch", default=0) or 0
            if self.classic and patch > CLASSIC_PATCH:
                continue
            prev = self.creatures.get(entry)
            if prev is not None and prev["patch"] > patch:
                continue
            self.creatures[entry] = {
                "patch": patch,
                "name": pick(cols, r, "name", "Name"),
                "rank": pick(cols, r, "rank", "Rank", default=0) or 0,
                "loot": pick(cols, r, "loot_id", "LootId", "lootid", default=0) or 0,
                "de": [
                    pick(cols, r, "DifficultyEntry1", "difficulty_entry_1", default=0) or 0,
                    pick(cols, r, "DifficultyEntry2", "difficulty_entry_2", default=0) or 0,
                    pick(cols, r, "DifficultyEntry3", "difficulty_entry_3", default=0) or 0,
                ],
            }
        self.creature_by_name: dict[str, list[int]] = defaultdict(list)
        for entry, c in self.creatures.items():
            self.creature_by_name[c["name"]].append(entry)
        self.difficulty_entries = {
            de for c in self.creatures.values() for de in c["de"] if de
        }

        # creature spawns per map
        cols, rows = dump.table("creature")
        self.spawns_by_map: dict[int, set[int]] = defaultdict(set)
        for r in rows:
            if not self._patch_ok(cols, r):
                continue
            map_id = pick(cols, r, "map")
            for id_col in ("id", "id2", "id3", "id4", "id5"):
                cid = pick(cols, r, id_col, default=0)
                if cid:
                    self.spawns_by_map[map_id].add(cid)

        # loot tables
        self.creature_loot = self._loot(dump, "creature_loot_template")
        self.reference_loot = self._loot(dump, "reference_loot_template")
        self.gameobject_loot = self._loot(dump, "gameobject_loot_template")
        self._compute_world_drop_refs()
        self.raw_loot = {
            "creature_loot_template": dump.table("creature_loot_template"),
            "reference_loot_template": dump.table("reference_loot_template"),
            "gameobject_loot_template": dump.table("gameobject_loot_template"),
        }

        # gameobjects (type 3 = chest; data1 = loot template id)
        cols, rows = dump.table("gameobject_template")
        self.gos: dict[int, dict] = {}
        for r in rows:
            entry = pick(cols, r, "entry")
            patch = pick(cols, r, "patch", default=0) or 0
            if self.classic and patch > CLASSIC_PATCH:
                continue
            prev = self.gos.get(entry)
            if prev is not None and prev["patch"] > patch:
                continue
            if (pick(cols, r, "type") or 0) != 3:
                continue
            self.gos[entry] = {
                "patch": patch,
                "name": pick(cols, r, "name"),
                "loot": pick(cols, r, "data1", "Data1", default=0) or 0,
            }
        self.go_by_name: dict[str, list[int]] = defaultdict(list)
        for entry, g in self.gos.items():
            self.go_by_name[g["name"]].append(entry)

        cols, rows = dump.table("gameobject")
        self.go_spawns_by_map: dict[int, set[int]] = defaultdict(set)
        for r in rows:
            if not self._patch_ok(cols, r):
                continue
            self.go_spawns_by_map[pick(cols, r, "map")].add(pick(cols, r, "id"))

    def _compute_world_drop_refs(self) -> None:
        users: dict[int, int] = defaultdict(int)
        for table in (self.creature_loot, self.gameobject_loot, self.reference_loot):
            for rows in table.values():
                for target, is_ref, _chance in rows:
                    if is_ref:
                        users[target] += 1
        self.world_drop_refs = set()
        for ref, count in users.items():
            if count < WORLD_REF_MIN_USERS:
                continue
            has_recipe = any(
                not is_ref
                and (info := self.items.get(target)) is not None
                and info[3] == RECIPE_ITEM_CLASS
                for target, is_ref, _c in self.reference_loot.get(ref, [])
            )
            if has_recipe:
                self.world_drop_refs.add(ref)

    def _loot(self, dump: Dump, table: str) -> dict[int, list[tuple[int, bool, float]]]:
        """loot id -> [(item id | reference id, is_reference)].

        Quest drops are skipped (negative ChanceOrQuestChance in the MaNGOS
        schema, QuestRequired flag in the TrinityCore schema): they are
        objective items handed to everyone, not reservable loot. Zero chance
        means "equal share of the loot group" and is a real drop.

        Two dialects: MaNGOS-family tables mark references with a negative
        mincountOrRef; TrinityCore tables have an explicit Reference column.
        """
        cols, rows = dump.table(table)
        trinity = "Reference" in cols
        out: dict[int, list[tuple[int, bool, float]]] = defaultdict(list)
        for r in rows:
            if not self._patch_ok(cols, r):
                continue
            if trinity:
                if pick(cols, r, "QuestRequired", default=0):
                    continue
                chance = pick(cols, r, "Chance", default=0) or 0
                ref = pick(cols, r, "Reference", default=0) or 0
                entry = pick(cols, r, "Entry")
                if ref:
                    out[entry].append((int(ref), True, chance))
                else:
                    out[entry].append((pick(cols, r, "Item"), False, chance))
                continue
            chance = pick(cols, r, "ChanceOrQuestChance", default=0) or 0
            if chance < 0:
                continue
            mc = pick(cols, r, "mincountOrRef", default=1)
            if mc is None:
                mc = 1
            entry = pick(cols, r, "entry")
            item = pick(cols, r, "item")
            if mc < 0:
                out[entry].append((-int(mc), True, chance))
            else:
                out[entry].append((item, False, chance))
        return out

MIN_REFERENCE_CHANCE = 1.0

# A reference list is treated as a shared world-drop list (and skipped) when
# it is wired into at least this many distinct loot tables AND its direct
# contents include recipe-class items. Real boss refs (tier tokens, slot
# groups) are shared by at most the bosses of one instance and contain gear
# only; the vmangos "boss drops a random world epic/recipe" lists are shared
# by dozens of tables and are full of Plans/Patterns/Schematics.
WORLD_REF_MIN_USERS = 8
RECIPE_ITEM_CLASS = 9


def resolve_loot(edition: Edition, table: dict, loot_id: int, seen=None) -> set[int]:
    """Resolve a loot id to item ids, following reference rows.

    Reference rows with a sub-1% chance are skipped: those are shared
    world-drop lists (recipes, rare vanity junk) that would attribute
    hundreds of foreign items to a boss. Real tier-token and shared-drop
    references roll at chance 0 (equal group share) or well above 1%.
    Direct item rows are never chance-filtered — legitimately rare drops
    (mounts) are exactly what people soft-reserve.
    """
    if seen is None:
        seen = set()
    key = (id(table), loot_id)
    if key in seen:
        return set()
    seen.add(key)
    result: set[int] = set()
    for target, is_ref, chance in table.get(loot_id, []):
        if is_ref:
            if 0 < chance < MIN_REFERENCE_CHANCE:
                continue
            if target in edition.world_drop_refs:
                continue
            result |= resolve_loot(edition, edition.reference_loot, target, seen)
        else:
            result.add(target)
    return result


def allowable_classes(edition: Edition, mask) -> list[str] | None:
    if mask is None:
        return None
    mask = int(mask)
    if mask <= 0:
        return None
    classes = [name for bit, name in CLASS_BITS if mask & bit]
    classes = [c for c in classes if c in EDITION_CLASSES[edition.id]]
    if not classes or set(classes) == EDITION_CLASSES[edition.id]:
        return None
    return classes


# ---------------------------------------------------------------------------
# Raid assembly
# ---------------------------------------------------------------------------


class Warnings:
    def __init__(self):
        self.entries: list[str] = []

    def add(self, msg: str) -> None:
        self.entries.append(msg)
        print(f"  WARN: {msg}", file=sys.stderr)


def resolve_creature_ref(edition: Edition, raid, ref, warn: Warnings) -> int | None:
    """A creature ref is an explicit entry id (int) or an exact template
    name. Names resolve against the base template set: rows that are
    themselves difficulty entries (Wrath 10→25/heroic clones share the
    boss's name) are excluded, then spawned-in-map candidates win, then
    boss-ranked looted candidates."""
    if isinstance(ref, int):
        if ref not in edition.creatures:
            warn.add(f"{raid['id']}: creature entry {ref} not in creature_template")
            return None
        return ref

    candidates = [
        e for e in edition.creature_by_name.get(ref, [])
        if e not in edition.difficulty_entries
    ]
    if not candidates:
        warn.add(f"{raid['id']}: no creature named {ref!r}")
        return None
    if len(candidates) > 1:
        spawned = [e for e in candidates if e in edition.spawns_by_map.get(raid["map"], set())]
        if len(spawned) == 1:
            return spawned[0]
        looted = [
            e for e in candidates
            if edition.creatures[e]["loot"] and edition.creatures[e]["rank"] == 3
        ]
        if len(looted) == 1:
            return looted[0]
        warn.add(
            f"{raid['id']}: ambiguous creature name {ref!r} -> {sorted(candidates)}"
            f" (picking lowest)"
        )
        return min(candidates)
    return candidates[0]


def creature_for_mode(edition: Edition, entry: int, mode: int) -> int:
    """Wrath size/difficulty variants live in DifficultyEntry1..3 of the
    base template (1=25N, 2=10H, 3=25H). Fall back down the chain
    (25H→25N→10N, 10H→10N) when a variant is missing, which is how the
    core resolves missing difficulty templates too."""
    if mode == 0:
        return entry
    de = edition.creatures[entry]["de"]
    for candidate_mode in _fallback_chain(mode):
        if candidate_mode == 0:
            return entry
        target = de[candidate_mode - 1]
        if target and target in edition.creatures:
            return target
    return entry


def _fallback_chain(mode: int) -> list[int]:
    return {1: [1, 0], 2: [2, 0], 3: [3, 1, 0]}[mode]


def collect_raid(edition: Edition, raid, warn: Warnings) -> list[dict]:
    mode = raid.get("mode", 0)
    map_id = raid["map"]

    # item id -> {"boss": ordered labels, "trash": bool}
    found: dict[int, dict] = {}
    boss_creature_entries: set[int] = set()

    def add_items(item_ids: set[int], label: str | None, min_quality: int):
        for item_id in sorted(item_ids):
            item = edition.items.get(item_id)
            if item is None:
                continue
            name, quality, _mask, iclass, _ilvl = item
            if quality is None or quality < min_quality:
                continue
            if iclass in EXCLUDED_ITEM_CLASSES:
                continue
            if item_id in raid_config.EXCLUDED_ITEMS:
                continue
            slot = found.setdefault(item_id, {"bosses": [], "trash": False})
            if label is None:
                slot["trash"] = True
            elif label not in slot["bosses"]:
                slot["bosses"].append(label)

    for boss in raid["bosses"]:
        label = boss["label"]
        got_any = False
        for ref in boss.get("creatures", []):
            entry = resolve_creature_ref(edition, raid, ref, warn)
            if entry is None:
                continue
            boss_creature_entries.add(entry)
            boss_creature_entries.update(d for d in edition.creatures[entry]["de"] if d)
            actual = creature_for_mode(edition, entry, mode)
            loot_id = edition.creatures[actual]["loot"]
            if not loot_id:
                warn.add(f"{raid['id']}: {label}: creature {actual} has no loot table")
                continue
            item_ids = resolve_loot(edition, edition.creature_loot, loot_id)
            if item_ids:
                got_any = True
            add_items(item_ids, label, BOSS_MIN_QUALITY)
        for go_ref in boss.get("gameobjects", []):
            entry = _resolve_go_ref(edition, raid, go_ref, warn)
            if entry is None:
                continue
            loot_id = edition.gos[entry]["loot"]
            if not loot_id:
                warn.add(f"{raid['id']}: {label}: gameobject {entry} has no loot")
                continue
            item_ids = resolve_loot(edition, edition.gameobject_loot, loot_id)
            if item_ids:
                got_any = True
            add_items(item_ids, label, BOSS_MIN_QUALITY)
        if not got_any:
            warn.add(f"{raid['id']}: boss {label!r} produced no items")

    # Map-wide trash sweep: everything spawned in the instance that is not
    # one of the configured boss creatures. Epic-only, and optionally
    # floored on item level (`trash_min_ilvl`) — Wrath trash tables mix in
    # low-level world BoE references that no quality filter can catch.
    if raid.get("trash", True):
        floor = raid.get("trash_min_ilvl", 0)
        for entry in sorted(edition.spawns_by_map.get(map_id, set())):
            if entry in boss_creature_entries or entry not in edition.creatures:
                continue
            actual = creature_for_mode(edition, entry, mode)
            loot_id = edition.creatures.get(actual, {}).get("loot", 0)
            if not loot_id:
                continue
            item_ids = resolve_loot(edition, edition.creature_loot, loot_id)
            if floor:
                item_ids = {
                    i for i in item_ids
                    if (info := edition.items.get(i)) is not None
                    and (info[4] or 0) >= floor
                }
            add_items(item_ids, None, TRASH_MIN_QUALITY)

    out = []
    for item_id, slot in found.items():
        name, quality, mask, _iclass, _ilvl = edition.items[item_id]
        if slot["bosses"]:
            boss_label = " / ".join(slot["bosses"])
        else:
            boss_label = "Trash"
        entry = {
            "id": item_id,
            "name": name,
            "quality": quality,
            "boss": boss_label,
        }
        classes = allowable_classes(edition, mask)
        if classes is not None:
            entry["allowable_classes"] = classes
        out.append(entry)

    boss_order = {b["label"]: i for i, b in enumerate(raid["bosses"])}
    boss_order["Trash"] = len(boss_order)

    def sort_key(item):
        first = item["boss"].split(" / ")[0]
        return (boss_order.get(first, len(boss_order)), item["boss"], item["name"])

    out.sort(key=sort_key)
    return out


def _resolve_go_ref(edition: Edition, raid, ref, warn: Warnings) -> int | None:
    if isinstance(ref, int):
        if ref not in edition.gos:
            warn.add(f"{raid['id']}: gameobject entry {ref} is not a chest template")
            return None
        return ref
    candidates = edition.go_by_name.get(ref, [])
    if not candidates:
        warn.add(f"{raid['id']}: no chest gameobject named {ref!r}")
        return None
    if len(candidates) > 1:
        warn.add(
            f"{raid['id']}: ambiguous gameobject name {ref!r} -> {sorted(candidates)};"
            f" use an explicit entry"
        )
        return None
    return candidates[0]


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def write_json(path: str, value) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(value, f, ensure_ascii=False, indent=1)
        f.write("\n")


def generate(dumps: dict[str, str], out_dir: str) -> int:
    warn = Warnings()
    editions_meta = []
    all_item_editions: dict[int, str] = {}

    for ed in raid_config.EDITIONS:
        editions_meta.append({"id": ed["id"], "name": ed["name"], "sort": ed["sort"]})
    write_json(os.path.join(out_dir, "editions.json"), editions_meta)

    for ed in raid_config.EDITIONS:
        edition_id = ed["id"]
        if edition_id not in dumps:
            print(f"Skipping edition {edition_id} (no dump provided)", file=sys.stderr)
            continue
        print(f"== {edition_id}: parsing {dumps[edition_id]}", file=sys.stderr)
        edition = Edition(edition_id, Dump(dumps[edition_id]))

        raids = [r for r in raid_config.RAIDS if r["edition"] == edition_id]
        raid_meta = []
        for raid in raids:
            print(f"-- {raid['id']} ({raid['name']})", file=sys.stderr)
            items = collect_raid(edition, raid, warn)
            if not items:
                warn.add(f"{raid['id']}: raid produced NO items")
            meta = {
                "id": raid["id"],
                "edition": edition_id,
                "name": raid["name"],
                "slots": raid["slots"],
            }
            if raid.get("size") is not None:
                meta["size"] = raid["size"]
            if raid.get("difficulty") is not None:
                meta["difficulty"] = raid["difficulty"]
            raid_meta.append(meta)
            write_json(os.path.join(out_dir, "items", edition_id, f"{raid['id']}.json"), items)
            for item in items:
                prev = all_item_editions.setdefault(item["id"], edition_id)
                if prev != edition_id:
                    warn.add(
                        f"cross-edition item id collision: {item['id']} in {prev} and {edition_id}"
                    )
            print(f"   {len(items)} items", file=sys.stderr)
        write_json(os.path.join(out_dir, "raids", f"{edition_id}.json"), raid_meta)

    print(f"\n{len(warn.entries)} warnings", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# Curation helpers
# ---------------------------------------------------------------------------


def find_go(dump_path: str, edition_id: str, needle: str) -> None:
    edition = Edition(edition_id, Dump(dump_path))
    needles = [n.lower() for n in needle.split("|")]
    for entry in sorted(edition.gos):
        g = edition.gos[entry]
        if any(n in g["name"].lower() for n in needles):
            n_items = len(resolve_loot(edition, edition.gameobject_loot, g["loot"]))
            print(f"{entry}\t{g['name']!r}\tloot={g['loot']}\titems={n_items}")


def find_creature(dump_path: str, edition_id: str, needle: str) -> None:
    edition = Edition(edition_id, Dump(dump_path))
    needles = [n.lower() for n in needle.split("|")]
    for entry in sorted(edition.creatures):
        c = edition.creatures[entry]
        if any(n in c["name"].lower() for n in needles):
            n_items = len(resolve_loot(edition, edition.creature_loot, c["loot"]))
            de = "de=" + ",".join(str(d) for d in c["de"]) if any(c["de"]) else ""
            tag = " [difficulty-entry]" if entry in edition.difficulty_entries else ""
            print(
                f"{entry}\t{c['name']!r}\trank={c['rank']}\tloot={c['loot']}"
                f"\titems={n_items}\t{de}{tag}"
            )


def dump_loot(dump_path: str, edition_id: str, spec: str) -> None:
    """Print the resolved loot of `c:<entry>` or `go:<entry>` with item
    class/quality, for curation decisions."""
    edition = Edition(edition_id, Dump(dump_path))
    kind, entry = spec.split(":")
    entry = int(entry)
    if kind == "c":
        loot_id = edition.creatures[entry]["loot"]
        table = edition.creature_loot
    else:
        loot_id = edition.gos[entry]["loot"]
        table = edition.gameobject_loot
    for item_id in sorted(resolve_loot(edition, table, loot_id)):
        info = edition.items.get(item_id)
        if info:
            name, quality, _mask, iclass, ilvl = info
            print(f"{item_id}\t{name!r}\tq={quality}\tclass={iclass}\tilvl={ilvl}")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--classic")
    p.add_argument("--tbc")
    p.add_argument("--wrath")
    p.add_argument("--out")
    p.add_argument("--find-go")
    p.add_argument("--find-creature")
    p.add_argument("--dump-loot", help="c:<entry> or go:<entry>")
    p.add_argument("--dump-loot-raw", help="creature|reference|gameobject:<loot id>")
    p.add_argument(
        "--map-audit",
        help="<map id>: list spawned creature templates in that map with "
        "their resolved epic counts (trash-sweep debugging)",
    )
    p.add_argument(
        "--compare-loot",
        help="comma list of c:<entry>|go:<entry>; prints epic count + item-level "
        "profile of each, to tell size/difficulty chest variants apart",
    )
    args = p.parse_args()

    dumps = {}
    for ed in ("classic", "tbc", "wrath"):
        path = getattr(args, ed)
        if path:
            dumps[ed] = path

    if (
        args.find_go
        or args.find_creature
        or args.dump_loot
        or args.dump_loot_raw
        or args.compare_loot
        or args.map_audit
    ):
        if len(dumps) != 1:
            p.error("curation helpers take exactly one dump")
        [(edition_id, path)] = dumps.items()
        if args.find_go:
            find_go(path, edition_id, args.find_go)
        if args.find_creature:
            find_creature(path, edition_id, args.find_creature)
        if args.dump_loot:
            dump_loot(path, edition_id, args.dump_loot)
        if args.map_audit:
            edition = Edition(edition_id, Dump(path))
            rows_out = []
            for entry in sorted(edition.spawns_by_map.get(int(args.map_audit), set())):
                c = edition.creatures.get(entry)
                if not c or not c["loot"]:
                    continue
                item_ids = resolve_loot(edition, edition.creature_loot, c["loot"])
                epics = [
                    i for i in item_ids
                    if (info := edition.items.get(i))
                    and info[1] is not None and info[1] >= 4 and info[3] != 3
                ]
                if epics:
                    rows_out.append((len(epics), entry, c["name"]))
            for n, entry, name in sorted(rows_out, reverse=True):
                print(f"{n}\t{entry}\t{name!r}")
        if args.compare_loot:
            edition = Edition(edition_id, Dump(path))
            for spec in args.compare_loot.split(","):
                kind, entry = spec.split(":")
                entry = int(entry)
                if kind == "c":
                    loot_id = edition.creatures[entry]["loot"]
                    table = edition.creature_loot
                else:
                    loot_id = edition.gos[entry]["loot"]
                    table = edition.gameobject_loot
                ilvls = []
                names = []
                for item_id in resolve_loot(edition, table, loot_id):
                    info = edition.items.get(item_id)
                    if info and info[1] is not None and info[1] >= 4 and info[3] not in (3,):
                        ilvls.append(info[4] or 0)
                        names.append(info[0])
                ilvls.sort()
                med = ilvls[len(ilvls) // 2] if ilvls else 0
                print(
                    f"{spec}\tloot={loot_id}\tepics={len(ilvls)}\tilvl min/med/max="
                    f"{ilvls[0] if ilvls else 0}/{med}/{ilvls[-1] if ilvls else 0}"
                    f"\te.g. {sorted(names)[:3]}"
                )
        if args.dump_loot_raw:
            edition = Edition(edition_id, Dump(path))
            for spec in args.dump_loot_raw.split(","):
                kind, loot_id = spec.split(":")
                print(f"### {spec}")
                cols, rows = edition.raw_loot[f"{kind}_loot_template"]
                for r in rows:
                    if pick(cols, r, "entry", "Entry") == int(loot_id):
                        item = pick(cols, r, "item", "Item")
                        info = edition.items.get(item, ("?", "?", None, "?", "?"))
                        print(
                            f"item={item}"
                            f"\tchance={pick(cols, r, 'ChanceOrQuestChance', 'Chance')}"
                            f"\tgroup={pick(cols, r, 'groupid', 'GroupId')}"
                            f"\tminOrRef={pick(cols, r, 'mincountOrRef', 'Reference')}"
                            f"\t{info[0]!r}"
                        )
        return 0

    if not args.out:
        p.error("--out is required to generate")
    return generate(dumps, args.out)


if __name__ == "__main__":
    sys.exit(main())
