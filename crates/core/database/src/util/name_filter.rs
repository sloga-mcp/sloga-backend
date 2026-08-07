//! Slur filter for the names users pick for themselves.
//!
//! Names get a stricter filter than message content because there is no way to
//! scroll past one: a username or nickname sits in the member list, on every
//! message and in every mention for as long as the account exists.
//!
//! Matching happens against a folded form of the name (see [`fold`]) in two
//! tiers, because a single tier cannot be both evasion-resistant and free of
//! the Scunthorpe problem.

use once_cell::sync::Lazy;
use regex::Regex;

/// Slurs blocked anywhere inside a name.
///
/// Only terms that do not turn up inside ordinary words belong here — these are
/// matched as substrings of the whole name with separators stripped, so
/// `n i g g e r` and `n.i.g.g.e.r` are caught alongside the plain spelling.
const SUBSTRING_TERMS: &[&str] = &[
    // racial
    "nigger",
    "nigga",
    "niggah",
    "niqqa",
    "niqqer",
    "niglet",
    "nignog",
    "wigger",
    "chinaman",
    "wetback",
    "raghead",
    "towelhead",
    "zipperhead",
    "cameljockey",
    "mudslime",
    "porchmonkey",
    "junglebunny",
    "spearchucker",
    "pickaninny",
    "jigaboo",
    "tarbaby",
    "groid",
    "halfbreed",
    "halfcaste",
    "slanteye",
    // homophobic / transphobic
    "faggot",
    "faggit",
    "faget",
    "bulldyke",
    "carpetmuncher",
    "fudgepacker",
    "shirtlifter",
    "poofter",
    "battyboy",
    "battyman",
    "nancyboy",
    "ladyboy",
    "shemale",
];

/// Slurs blocked only when they are a whole word of the name.
///
/// Every term here also lives inside an innocent word — `spicy`, `raccoon`,
/// `Pakistani`, `sauerkraut`, `heebie-jeebies`, `homophone` — so matching them
/// as substrings would block far more real names than slurs. The price of the
/// narrower rule is that `spicboy` gets through where `spic_boy` does not,
/// which is the right way round for a filter that runs on every name on the
/// platform.
///
/// A handful of these do collide with real names and phrases — `kike` is a
/// Spanish nickname for Enrique, `dyke` is a surname, `honky` shows up in
/// `honky tonk`. They are kept because the slur reading is the common one here;
/// deleting a line is all it takes to allow one back.
const WORD_TERMS: &[&str] = &[
    // racial
    "spic",
    "chink",
    "gook",
    "jap",
    "paki",
    "kike",
    "yid",
    "heeb",
    "hymie",
    "shylock",
    "coon",
    "wop",
    "dago",
    "kraut",
    "polack",
    "honky",
    "honkey",
    "whitey",
    "wog",
    "kaffir",
    "abbo",
    "abo",
    "gyppo",
    "gypo",
    "gippo",
    "pikey",
    "sambo",
    "injun",
    "redskin",
    "squaw",
    "coolie",
    "beaner",
    "muzzie",
    // homophobic / transphobic
    "fag",
    "fagg",
    "fagot",
    "faggy",
    "dyke",
    "homo",
    "tranny",
    "trannie",
];

/// Terms stretched into patterns that tolerate repeated letters, so `niiigggerrr`
/// is caught while `Niger` — one `g` where the term has two — is not.
static SUBSTRING_PATTERN: Lazy<Regex> = Lazy::new(|| {
    let alternatives = SUBSTRING_TERMS
        .iter()
        .map(|term| stretch(term))
        .collect::<Vec<_>>()
        .join("|");

    Regex::new(&alternatives).expect("valid slur pattern")
});

/// Whole-word terms are matched literally rather than stretched: repeat
/// tolerance on words this short blocks real names (`Jaap` would fold onto
/// `jap`), and a false block is worse here than a missed `faaag`.
static WORD_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&format!("^(?:{})[sz]?$", WORD_TERMS.join("|"))).expect("valid slur pattern")
});

/// Whether a name a user picked for themselves contains a slur we do not allow.
pub fn contains_blocked_slur(name: &str) -> bool {
    let folded = fold(name);

    SUBSTRING_PATTERN.is_match(&folded.dense)
        || folded.words.iter().any(|word| WORD_PATTERN.is_match(word))
}

/// A name reduced to the forms the two blocklists are matched against.
struct FoldedName {
    /// Everything that is not a letter removed, so `n.i.g.g.e.r` and
    /// `n i g g e r` collapse onto the plain spelling.
    dense: String,
    /// The name split on separators and camelCase humps. The dense form is
    /// included as a candidate as well, so `F.A.G.` is caught even though it
    /// splits into three single letters.
    words: Vec<String>,
}

/// Fold a name into its comparable forms.
///
/// `decancer` does the Unicode half — confusables, fullwidth forms, accents,
/// zalgo — and we fold the ASCII leetspeak and separators it leaves alone.
fn fold(name: &str) -> FoldedName {
    // Capitalization is retained so camelCase word boundaries survive; the
    // per-character mapping below lowercases.
    let options = decancer::Options::default().retain_capitalization();
    let cured = decancer::cure(name, options)
        .map(|cured| cured.to_string())
        .unwrap_or_else(|_| name.to_owned());

    let mut words: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut previous_was_lower = false;

    for character in cured.chars() {
        let letter = if character.is_ascii_alphabetic() {
            Some(character.to_ascii_lowercase())
        } else {
            unleet(character)
        };

        match letter {
            Some(letter) => {
                if character.is_uppercase() && previous_was_lower && !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }

                current.push(letter);
                previous_was_lower = !character.is_uppercase();
            }
            None => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }

                previous_was_lower = false;
            }
        }
    }

    if !current.is_empty() {
        words.push(current);
    }

    let dense = words.concat();
    if words.len() > 1 {
        words.push(dense.clone());
    }

    FoldedName { dense, words }
}

/// Map a leetspeak stand-in onto the letter it is standing in for.
fn unleet(character: char) -> Option<char> {
    Some(match character {
        '0' => 'o',
        '1' | '!' | '|' => 'i',
        '2' => 'z',
        '3' => 'e',
        '4' | '@' => 'a',
        '5' | '$' => 's',
        '6' | '9' => 'g',
        '7' | '+' => 't',
        '8' => 'b',
        _ => return None,
    })
}

/// Turn a term into a pattern where every letter may repeat, so padding a slur
/// out does not get past it.
fn stretch(term: &str) -> String {
    debug_assert!(
        term.chars().all(|character| character.is_ascii_lowercase()),
        "blocklist terms are plain lowercase ASCII"
    );

    term.chars()
        .map(|character| format!("{character}+"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::contains_blocked_slur;

    #[test]
    fn blocks_plain_slurs() {
        for name in [
            "nigger",
            "Nigga",
            "faggot",
            "fag",
            "FAGS",
            "spic",
            "tranny",
            "shemale",
            "wetback",
            "chink",
            "kike",
            "coon",
            "dyke",
            "homo",
            "porch monkey",
        ] {
            assert!(contains_blocked_slur(name), "{name} should be blocked");
        }
    }

    #[test]
    fn blocks_evasions() {
        for name in [
            // leetspeak
            "n1gg3r",
            "F4GG0T",
            "5p1c",
            // separators
            "n.i.g.g.e.r",
            "n i g g e r",
            "n_i_g_g_e_r",
            "F.A.G.",
            // padding
            "niiiggggerrr",
            "faaaggot",
            // camelCase hiding a whole-word term
            "SpicBoy",
            "TotallyNormalFagAccount",
            // unicode confusables, which decancer folds back to ASCII
            "ｎｉｇｇｅｒ",
            "𝓯𝓪𝓰𝓰𝓸𝓽",
        ] {
            assert!(contains_blocked_slur(name), "{name} should be blocked");
        }
    }

    #[test]
    fn allows_ordinary_names() {
        for name in [
            // the Scunthorpe set — every one of these contains a whole-word term
            "spicy",
            "Spice Girl",
            "suspicious",
            "conspicuous",
            "despicable",
            "raccoon",
            "cocoon",
            "tycoon",
            "Coonan",
            "Pakistan",
            "Pakistani",
            "sauerkraut",
            "heebie jeebies",
            "Japan",
            "Japanese",
            "homophone",
            "homogeneous",
            "Homer",
            "Fagan",
            "Chinatown",
            // one g, not two
            "Niger",
            "Nigeria",
            "Nigerian",
            // plain innocents
            "Scunthorpe",
            "analysis",
            "assassin",
            "transgender",
        ] {
            assert!(!contains_blocked_slur(name), "{name} should be allowed");
        }
    }

    #[test]
    fn allows_identity_words() {
        // Naming yourself is not the same as slurring somebody, and reclaimed
        // words belong to the people using them.
        for name in [
            "gay",
            "Gay Pride",
            "queer",
            "QueerCoded",
            "trans",
            "Trans Rights",
            "lesbian",
            "bisexual",
            "homosexual",
            "twink",
            "drag queen",
        ] {
            assert!(!contains_blocked_slur(name), "{name} should be allowed");
        }
    }
}
