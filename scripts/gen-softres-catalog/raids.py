"""Curated raid/boss configuration for the soft-reserve loot catalog.

Hand-maintained: the world databases have no per-map encounter roster
(bosses like Ragnaros or the whole Trial of the Crusader lineup are
script-summoned and never appear in the spawn tables), so each raid lists
its encounters explicitly.

Conventions:
  - `bosses[].creatures` — exact creature_template names, or explicit entry
    ids where a name is ambiguous. Encounters whose loot lives on a chest
    (Majordomo, Kara chess, Gunship, the Ulduar caches, …) use
    `gameobjects` with explicit entries, because chest names repeat across
    size/difficulty variants.
  - Wrath size/difficulty variants are distinct raid entries (10/25-player
    and normal/heroic drop DIFFERENT item ids). `mode` picks the loot
    variant: 0 = 10-player base template, 1 = DifficultyEntry1 (25),
    2 = DifficultyEntry2 (10 heroic), 3 = DifficultyEntry3 (25 heroic).
  - `slots` is the raid's player count (display metadata).
  - Raid ids are a PUBLIC CONTRACT once shipped (they land in Gargul's
    metadata.instance on export) — never rename one.
"""

EDITIONS = [
    {"id": "classic", "name": "Classic Era", "sort": 0},
    {"id": "tbc", "name": "The Burning Crusade", "sort": 1},
    {"id": "wrath", "name": "Wrath of the Lich King", "sort": 2},
]

# Currency-style drops that pass the quality filter but are never
# soft-reserved (every raider gets them / they are per-person tokens).
EXCLUDED_ITEMS = {
    29434,  # Badge of Justice
    40752,  # Emblem of Heroism
    40753,  # Emblem of Valor
    45624,  # Emblem of Conquest
    47241,  # Emblem of Triumph
    49426,  # Emblem of Frost
    43228,  # Stone Keeper's Shard
    49643,  # Head of Onyxia (Alliance quest starter, Wrath)
    49644,  # Head of Onyxia (Horde quest starter, Wrath)
    # Sub-1% DIRECT world-drop rows on classic raid trash. The shared
    # reference-list heuristic can't see these (they are direct item rows,
    # deliberately never chance-filtered so real rare mounts survive);
    # wowhead attributes them to generic world pools, not the raids.
    12717,  # Plans: Lionheart Helm
    12720,  # Plans: Stronghold Gauntlets
    12728,  # Plans: Invulnerable Mail
    14511,  # Pattern: Gloves of Spell Mastery
    14557,  # The Lion Horn of Stormwind
    14558,  # Lady Maye's Pendant
    # Hallow's End holiday drop wired condition-free into every TBC boss
    # table — unobtainable outside the event.
    33117,  # Jack-o'-Lantern
}

# Per-raid curated deltas over the generated data — the world DBs are
# community reconstructions and carry verified errors. Every entry cites
# its evidence; keep these short and prefer fixing the pipeline when a
# whole class of items is wrong.
#
# CURATED_REMOVE: item ids dropped from one raid (they stay in others).
CURATED_REMOVE = {
    # TDB puts XT-002's five 25-hard-mode ilvl-239 items in the 10-man
    # base loot table too (they correctly live in DifficultyEntry1's
    # table for ulduar25); wowhead/wowtbc attribute them to 25-hard only.
    # 45454 (Frost-bound Chain Bracers, ilvl 226) is a Hodir-25 normal
    # drop TDB also placed in the 10-man Rare Cache of Winter (194200).
    "ulduar10": {45442, 45443, 45444, 45445, 45446, 45454},
    # Valorous Dreadnaught Legguards (ilvl 213, Archavon's) sit in
    # Alexstrasza's Gift 25 (go 193967) — the lone 213 row among 226s;
    # wowhead attributes it to VoA only.
    "eoe25": {40547},
    # Valorous Plagueheart Gloves: token-vendor only — zero drops in
    # ~2.9k recorded Archavon-25 kills on wowhead classic and no
    # dropped-by on archived 2010 wowhead.
    "voa25": {40420},
}

# CURATED_ADD: raid id -> boss label -> item ids the source DB verifiably
# drops there but has NO loot row for (metadata resolves from
# item_template). All verified against wowhead per-mode drop data.
CURATED_ADD = {
    # The Qiraji Resonating Crystal mounts are RARE-quality direct rows on
    # ten spawned AQ40 trash creatures (1.1–17.5% in vmangos), but 1.12
    # item data has no Mount subclass (they are class 15/0 junk, like the
    # Swift Zulian Tiger), so the epic-quality trash floor drops them and
    # no subclass exemption can see them. A mount is the archetypal
    # soft-reserve item — pin them explicitly.
    "aq40": {"Trash": [
        21218,  # Blue Qiraji Resonating Crystal
        21321,  # Red Qiraji Resonating Crystal
        21323,  # Green Qiraji Resonating Crystal
        21324,  # Yellow Qiraji Resonating Crystal
    ]},
    # TDB's 10-man Rare Cache of Winter lacks Hodir-10's normal cloth
    # head (present on wowhead/wowtbc 10-normal tables).
    "ulduar10": {"Hodir": [45464]},  # Cowl of Icy Breaths
    # Hodir's five 25-hard-mode ilvl-239 Rare Cache items exist in
    # item_template but in no TDB loot table at all.
    "ulduar25": {"Hodir": [
        45457,  # Staff of Endless Winter
        45459,  # Frigid Strength of Hodir
        45460,  # Bindings of Winter Gale
        45461,  # Drape of Icy Intent
        45462,  # Gloves of the Frozen Glade
    ]},
    # VoA drops absent from TDB, confirmed on wowhead classic per-mode
    # kill statistics (each also on archived 2010 wowhead):
    "voa10": {
        "Archavon the Stone Watcher": [
            39601,  # Heroes' Earthshatter Grips
            39603,  # Heroes' Earthshatter War-Kilt
            41079,  # Hateful Gladiator's Linked Armor
            41648,  # Hateful Gladiator's Leather Tunic
        ],
        "Emalon the Storm Watcher": [42027],  # Deadly Gladiator's Pendant of Triumph
    },
    "voa25": {
        "Emalon the Storm Watcher": [40848],  # Furious Gladiator's Dreadplate Legguards
    },
}


def _boss(label, *creatures, gameobjects=()):
    return {"label": label, "creatures": list(creatures), "gameobjects": list(gameobjects)}


CLASSIC_RAIDS = [
    {
        "id": "mc", "edition": "classic", "name": "Molten Core", "slots": 40, "map": 409,
        "bosses": [
            _boss("Lucifron", "Lucifron"),
            _boss("Magmadar", "Magmadar"),
            _boss("Gehennas", "Gehennas"),
            _boss("Garr", "Garr"),
            _boss("Baron Geddon", "Baron Geddon"),
            _boss("Shazzrah", "Shazzrah"),
            _boss("Sulfuron Harbinger", "Sulfuron Harbinger"),
            _boss("Golemagg the Incinerator", "Golemagg the Incinerator"),
            _boss("Majordomo Executus", gameobjects=["Cache of the Firelord"]),
            _boss("Ragnaros", "Ragnaros"),
        ],
    },
    {
        "id": "onyxia", "edition": "classic", "name": "Onyxia's Lair", "slots": 40, "map": 249,
        "bosses": [_boss("Onyxia", "Onyxia")],
    },
    {
        "id": "bwl", "edition": "classic", "name": "Blackwing Lair", "slots": 40, "map": 469,
        "bosses": [
            _boss("Razorgore the Untamed", "Razorgore the Untamed"),
            _boss("Vaelastrasz the Corrupt", "Vaelastrasz the Corrupt"),
            _boss("Broodlord Lashlayer", "Broodlord Lashlayer"),
            _boss("Firemaw", "Firemaw"),
            _boss("Ebonroc", "Ebonroc"),
            _boss("Flamegor", "Flamegor"),
            _boss("Chromaggus", "Chromaggus"),
            _boss("Nefarian", "Nefarian"),
        ],
    },
    {
        "id": "zg", "edition": "classic", "name": "Zul'Gurub", "slots": 20, "map": 309,
        "bosses": [
            _boss("High Priest Venoxis", "High Priest Venoxis"),
            _boss("High Priestess Jeklik", "High Priestess Jeklik"),
            _boss("High Priestess Mar'li", "High Priestess Mar'li"),
            _boss("High Priest Thekal", "High Priest Thekal"),
            _boss("High Priestess Arlokk", "High Priestess Arlokk"),
            _boss("Bloodlord Mandokir", "Bloodlord Mandokir"),
            _boss("Edge of Madness", "Gri'lek", "Hazza'rah", "Renataki", "Wushoolay"),
            _boss("Gahz'ranka", "Gahz'ranka"),
            _boss("Jin'do the Hexxer", "Jin'do the Hexxer"),
            _boss("Hakkar", "Hakkar"),
        ],
    },
    {
        "id": "aq20", "edition": "classic", "name": "Ruins of Ahn'Qiraj", "slots": 20, "map": 509,
        "bosses": [
            _boss("Kurinnaxx", "Kurinnaxx"),
            _boss("General Rajaxx", "General Rajaxx"),
            _boss("Moam", "Moam"),
            _boss("Buru the Gorger", "Buru the Gorger"),
            _boss("Ayamiss the Hunter", "Ayamiss the Hunter"),
            _boss("Ossirian the Unscarred", "Ossirian the Unscarred"),
        ],
    },
    {
        "id": "aq40", "edition": "classic", "name": "Temple of Ahn'Qiraj", "slots": 40, "map": 531,
        "bosses": [
            _boss("The Prophet Skeram", "The Prophet Skeram"),
            _boss("Bug Trio", "Vem", "Lord Kri", "Princess Yauj"),
            _boss("Battleguard Sartura", "Battleguard Sartura"),
            _boss("Fankriss the Unyielding", "Fankriss the Unyielding"),
            _boss("Viscidus", "Viscidus"),
            _boss("Princess Huhuran", "Princess Huhuran"),
            _boss("Twin Emperors", "Emperor Vek'lor", "Emperor Vek'nilash"),
            _boss("Ouro", "Ouro"),
            _boss("C'Thun", "C'Thun"),
        ],
    },
    {
        "id": "naxx", "edition": "classic", "name": "Naxxramas", "slots": 40, "map": 533,
        "bosses": [
            _boss("Anub'Rekhan", "Anub'Rekhan"),
            _boss("Grand Widow Faerlina", "Grand Widow Faerlina"),
            _boss("Maexxna", "Maexxna"),
            _boss("Noth the Plaguebringer", "Noth the Plaguebringer"),
            _boss("Heigan the Unclean", "Heigan the Unclean"),
            _boss("Loatheb", "Loatheb"),
            _boss("Instructor Razuvious", "Instructor Razuvious"),
            _boss("Gothik the Harvester", "Gothik the Harvester"),
            _boss("The Four Horsemen", gameobjects=["Four Horsemen Chest"]),
            _boss("Patchwerk", "Patchwerk"),
            _boss("Grobbulus", "Grobbulus"),
            _boss("Gluth", "Gluth"),
            _boss("Thaddius", "Thaddius"),
            _boss("Sapphiron", "Sapphiron"),
            _boss("Kel'Thuzad", "Kel'Thuzad"),
        ],
    },
]

TBC_RAIDS = [
    {
        "id": "kara", "edition": "tbc", "name": "Karazhan", "slots": 10, "map": 532,
        "bosses": [
            _boss("Attumen the Huntsman", "Attumen the Huntsman"),
            _boss("Moroes", "Moroes"),
            _boss("Maiden of Virtue", "Maiden of Virtue"),
            _boss("Opera Event", "The Big Bad Wolf", "Julianne", "Romulo", "The Crone"),
            _boss("The Curator", "The Curator"),
            _boss("Terestian Illhoof", "Terestian Illhoof"),
            _boss("Shade of Aran", "Shade of Aran"),
            _boss("Netherspite", "Netherspite"),
            _boss("Chess Event", gameobjects=["Dust Covered Chest"]),
            _boss("Prince Malchezaar", "Prince Malchezaar"),
            _boss("Nightbane", "Nightbane"),
        ],
    },
    {
        "id": "gruul", "edition": "tbc", "name": "Gruul's Lair", "slots": 25, "map": 565,
        "bosses": [
            _boss("High King Maulgar", "High King Maulgar"),
            _boss("Gruul the Dragonkiller", "Gruul the Dragonkiller"),
        ],
    },
    {
        "id": "magtheridon", "edition": "tbc", "name": "Magtheridon's Lair", "slots": 25, "map": 544,
        "bosses": [_boss("Magtheridon", "Magtheridon")],
    },
    {
        "id": "ssc", "edition": "tbc", "name": "Serpentshrine Cavern", "slots": 25, "map": 548,
        "bosses": [
            _boss("Hydross the Unstable", "Hydross the Unstable"),
            _boss("The Lurker Below", "The Lurker Below"),
            _boss("Leotheras the Blind", "Leotheras the Blind"),
            _boss("Fathom-Lord Karathress", "Fathom-Lord Karathress"),
            _boss("Morogrim Tidewalker", "Morogrim Tidewalker"),
            _boss("Lady Vashj", "Lady Vashj"),
        ],
    },
    {
        "id": "tk", "edition": "tbc", "name": "Tempest Keep", "slots": 25, "map": 550,
        "bosses": [
            _boss("Al'ar", "Al'ar"),
            _boss("Void Reaver", "Void Reaver"),
            _boss("High Astromancer Solarian", "High Astromancer Solarian"),
            _boss("Kael'thas Sunstrider", "Kael'thas Sunstrider"),
        ],
    },
    {
        "id": "hyjal", "edition": "tbc", "name": "Mount Hyjal", "slots": 25, "map": 534,
        "bosses": [
            _boss("Rage Winterchill", "Rage Winterchill"),
            _boss("Anetheron", "Anetheron"),
            _boss("Kaz'rogal", "Kaz'rogal"),
            _boss("Azgalor", "Azgalor"),
            _boss("Archimonde", "Archimonde"),
        ],
    },
    {
        "id": "bt", "edition": "tbc", "name": "Black Temple", "slots": 25, "map": 564,
        "bosses": [
            _boss("High Warlord Naj'entus", "High Warlord Naj'entus"),
            _boss("Supremus", "Supremus"),
            _boss("Shade of Akama", "Shade of Akama"),
            _boss("Teron Gorefiend", "Teron Gorefiend"),
            _boss("Gurtogg Bloodboil", "Gurtogg Bloodboil"),
            _boss("Reliquary of Souls", "Essence of Anger"),
            _boss("Mother Shahraz", "Mother Shahraz"),
            # The council controller creature (23426) has no loot; the four
            # members hold it split between them.
            _boss("The Illidari Council", 22949, 22950, 22951, 22952),
            _boss("Illidan Stormrage", "Illidan Stormrage"),
        ],
    },
    {
        "id": "za", "edition": "tbc", "name": "Zul'Aman", "slots": 10, "map": 568,
        "bosses": [
            _boss("Nalorakk", "Nalorakk"),
            _boss("Akil'zon", "Akil'zon"),
            _boss("Jan'alai", "Jan'alai"),
            _boss("Halazzi", "Halazzi"),
            # Two templates share the name; 24239 is the looted boss.
            _boss("Hex Lord Malacrass", 24239),
            _boss("Zul'jin", "Zul'jin"),
            # The four timed-run reward containers share one loot pool
            # (including the Amani War Bear).
            _boss("Timed Run Reward", gameobjects=[186648, 186667, 187021, 186672]),
        ],
    },
    {
        "id": "swp", "edition": "tbc", "name": "Sunwell Plateau", "slots": 25, "map": 580,
        "bosses": [
            _boss("Kalecgos", "Sathrovarr the Corruptor"),
            _boss("Brutallus", "Brutallus"),
            _boss("Felmyst", "Felmyst"),
            _boss("Eredar Twins", "Grand Warlock Alythess", "Lady Sacrolash"),
            _boss("M'uru", "Entropius"),
            # Two templates share the name; 25315 is the looted boss.
            _boss("Kil'jaeden", 25315),
        ],
    },
]


def _wrath(base_id, name, map_id, bosses, modes, per_mode_gos=None, trash_min_ilvl=0,
           trash_max_ilvl_by_mode=None):
    """Expand one Wrath instance into its size/difficulty raid entries.

    `modes` maps raid-id suffix -> (mode, slots, difficulty).
    `per_mode_gos` optionally maps (boss label, mode) -> [gameobject entries]
    for chest-loot encounters, whose entries differ per variant.
    `trash_min_ilvl` floors the trash sweep — TDB trash tables reference
    low-level world BoE drop lists that would otherwise pollute the raid.
    `trash_max_ilvl_by_mode` optionally caps the sweep per mode — Ulduar's
    trash templates carry the 25-player BoE reference on their BASE
    (10-player) table, so the 10-man sweep needs a ceiling.
    """
    out = []
    for suffix, (mode, slots, difficulty) in modes.items():
        entry_bosses = []
        for boss in bosses:
            b = {
                "label": boss["label"],
                "creatures": list(boss["creatures"]),
                "gameobjects": list(boss["gameobjects"]),
            }
            if per_mode_gos and (boss["label"], mode) in per_mode_gos:
                b["gameobjects"] = list(per_mode_gos[(boss["label"], mode)])
            # Encounters with no loot source in this mode (e.g. the ToGC
            # tribute chest on normal difficulty) don't exist in this
            # raid entry at all.
            if b["creatures"] or b["gameobjects"]:
                entry_bosses.append(b)
        out.append({
            "id": f"{base_id}{suffix}",
            "edition": "wrath",
            "name": f"{name} ({slots})" if difficulty == "normal"
                    else f"{name} ({slots} Heroic)",
            "slots": slots,
            "map": map_id,
            "mode": mode,
            "size": slots,
            "difficulty": difficulty,
            "bosses": entry_bosses,
            "trash_min_ilvl": trash_min_ilvl,
            "trash_max_ilvl": (trash_max_ilvl_by_mode or {}).get(mode, 0),
        })
    return out


_N10_25 = {"10": (0, 10, "normal"), "25": (1, 25, "normal")}
_ALL_MODES = {
    "10": (0, 10, "normal"),
    "25": (1, 25, "normal"),
    "10hc": (2, 10, "heroic"),
    "25hc": (3, 25, "heroic"),
}

# Chest gameobject entries below were pinned by item-level profile
# (10N/25N/10H/25H have distinct item ids and item levels; several chest
# entry ids are NOT in mode order — e.g. ICC's Gunship Armory 10H entry id
# is LOWER than its 10N entry id). See README for the verification recipe.

_NAXX_BOSSES = [
    _boss("Anub'Rekhan", "Anub'Rekhan"),
    _boss("Grand Widow Faerlina", "Grand Widow Faerlina"),
    _boss("Maexxna", "Maexxna"),
    _boss("Noth the Plaguebringer", "Noth the Plaguebringer"),
    _boss("Heigan the Unclean", "Heigan the Unclean"),
    _boss("Loatheb", "Loatheb"),
    _boss("Instructor Razuvious", "Instructor Razuvious"),
    _boss("Gothik the Harvester", "Gothik the Harvester"),
    _boss("The Four Horsemen", gameobjects=[]),  # per-mode chest entries below
    _boss("Patchwerk", "Patchwerk"),
    _boss("Grobbulus", "Grobbulus"),
    _boss("Gluth", "Gluth"),
    _boss("Thaddius", "Thaddius"),
    _boss("Sapphiron", "Sapphiron"),
    _boss("Kel'Thuzad", "Kel'Thuzad"),
]

_NAXX_GOS = {
    ("The Four Horsemen", 0): [181366],
    ("The Four Horsemen", 1): [193426],
}

_ULDUAR_BOSSES = [
    _boss("Flame Leviathan", "Flame Leviathan"),
    _boss("Ignis the Furnace Master", "Ignis the Furnace Master"),
    _boss("Razorscale", "Razorscale"),
    _boss("XT-002 Deconstructor", "XT-002 Deconstructor"),
    _boss("Assembly of Iron", "Steelbreaker"),
    _boss("Kologarn", gameobjects=[]),  # Cache of Living Stone, per-mode below
    _boss("Auriaya", "Auriaya"),
    _boss("Hodir", gameobjects=[]),
    _boss("Thorim", gameobjects=[]),
    _boss("Freya", gameobjects=[]),
    _boss("Mimiron", gameobjects=[]),
    _boss("General Vezax", "General Vezax"),
    _boss("Yogg-Saron", "Yogg-Saron"),
    _boss("Algalon the Observer", gameobjects=[]),
]

# Normal + hard-mode caches are unioned per size: our Ulduar raid entries
# are per-size only, and hard-mode drops are exactly the chase items
# people soft-reserve.
_ULDUAR_GOS = {
    ("Kologarn", 0): [195046],
    ("Kologarn", 1): [195047],
    ("Hodir", 0): [194307, 194200],
    ("Hodir", 1): [194308, 194201],
    ("Thorim", 0): [194312, 194313],
    ("Thorim", 1): [194314, 194315],
    ("Freya", 0): [194324, 194325, 194326, 194327],
    ("Freya", 1): [194328, 194329, 194330, 194331],
    ("Mimiron", 0): [194789, 194957],
    ("Mimiron", 1): [194956, 194958],
    ("Algalon the Observer", 0): [194821],
    ("Algalon the Observer", 1): [194822],
}

_EOE_GOS = {
    ("Malygos", 0): [193905],
    ("Malygos", 1): [193967],
}

_TOC_BOSSES = [
    _boss("Northrend Beasts", "Icehowl"),
    _boss("Lord Jaraxxus", "Lord Jaraxxus"),
    _boss("Faction Champions", gameobjects=[]),
    _boss("Twin Val'kyr", "Fjola Lightbane", "Eydis Darkbane"),
    _boss("Anub'arak", "Anub'arak"),
    # Heroic (ToGC) only: the attempts-based Argent Crusade Tribute Chest
    # after Anub'arak. Variants per remaining-attempt tier are unioned; the
    # trophy-only variant (195668) is excluded — trophies are not a ToGC-10
    # reward and already drop in the 25-player lists. A boss with no
    # sources for a mode (here: modes 0/1) is dropped from that raid entry.
    _boss("Tribute Chest", gameobjects=[]),
]

_TOC_GOS = {
    ("Faction Champions", 0): [195631],
    ("Faction Champions", 1): [195632],
    ("Faction Champions", 2): [195633],
    ("Faction Champions", 3): [195635],
    ("Tribute Chest", 2): [195665, 195666, 195667],
    ("Tribute Chest", 3): [195669, 195670, 195671, 195672],
}

_ICC_BOSSES = [
    _boss("Lord Marrowgar", "Lord Marrowgar"),
    _boss("Lady Deathwhisper", "Lady Deathwhisper"),
    _boss("Gunship Battle", gameobjects=[]),
    _boss("Deathbringer Saurfang", gameobjects=[]),
    _boss("Festergut", "Festergut"),
    _boss("Rotface", "Rotface"),
    _boss("Professor Putricide", "Professor Putricide"),
    # Council loot lives on Prince Valanar (37970); Sindragosa's name is
    # shared with pre-raid versions, so both are pinned by entry.
    _boss("Blood Prince Council", 37970),
    _boss("Blood-Queen Lana'thel", "Blood-Queen Lana'thel"),
    _boss("Valithria Dreamwalker", gameobjects=[]),
    _boss("Sindragosa", 36853),
    _boss("The Lich King", "The Lich King"),
]

_ICC_GOS = {
    ("Gunship Battle", 0): [201873],
    ("Gunship Battle", 1): [201874],
    ("Gunship Battle", 2): [201872],
    ("Gunship Battle", 3): [201875],
    ("Deathbringer Saurfang", 0): [202239],
    ("Deathbringer Saurfang", 1): [202240],
    ("Deathbringer Saurfang", 2): [202238],
    ("Deathbringer Saurfang", 3): [202241],
    ("Valithria Dreamwalker", 0): [201959],
    ("Valithria Dreamwalker", 1): [202339],
    ("Valithria Dreamwalker", 2): [202338],
    ("Valithria Dreamwalker", 3): [202340],
}

WRATH_RAIDS = (
    _wrath("naxx", "Naxxramas", 533, _NAXX_BOSSES, _N10_25, _NAXX_GOS, trash_min_ilvl=200)
    + _wrath("os", "The Obsidian Sanctum", 615, [_boss("Sartharion", "Sartharion")], _N10_25,
             trash_min_ilvl=200)
    + _wrath("eoe", "The Eye of Eternity", 616, [_boss("Malygos", gameobjects=[])], _N10_25,
             _EOE_GOS, trash_min_ilvl=213)
    + _wrath("voa", "Vault of Archavon", 624, [
        _boss("Archavon the Stone Watcher", "Archavon the Stone Watcher"),
        _boss("Emalon the Storm Watcher", "Emalon the Storm Watcher"),
        _boss("Koralon the Flame Watcher", "Koralon the Flame Watcher"),
        _boss("Toravon the Ice Watcher", "Toravon the Ice Watcher"),
    ], _N10_25, trash_min_ilvl=213)
    + _wrath("ulduar", "Ulduar", 603, _ULDUAR_BOSSES, _N10_25, _ULDUAR_GOS, trash_min_ilvl=219,
             trash_max_ilvl_by_mode={0: 219})
    + _wrath("toc", "Trial of the Crusader", 649, _TOC_BOSSES, _ALL_MODES, _TOC_GOS,
             trash_min_ilvl=232)
    + _wrath("onyxia", "Onyxia's Lair", 249, [_boss("Onyxia", "Onyxia")], _N10_25,
             trash_min_ilvl=200)
    + _wrath("icc", "Icecrown Citadel", 631, _ICC_BOSSES, _ALL_MODES, _ICC_GOS,
             trash_min_ilvl=251)
    + _wrath("rs", "The Ruby Sanctum", 724, [_boss("Halion", 39863)], _ALL_MODES,
             trash_min_ilvl=258)
)

RAIDS = CLASSIC_RAIDS + TBC_RAIDS + WRATH_RAIDS
