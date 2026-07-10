//! Dice notation parser and roller for the `/roll` feature.
//!
//! Supports standard tabletop notation:
//! - `d20`, `1d20`, `2d6` — simple rolls
//! - `2d6+3`, `1d20+5-2` — modifiers
//! - `2d6+1d4` — multiple dice terms
//! - `4d6kh3` / `4d6kl3` — keep highest / keep lowest N
//! - advantage / disadvantage are expressed as `2d20kh1` / `2d20kl1`
//!
//! Rolls are always generated server-side so results cannot be spoofed
//! by clients.

use rand::Rng;

/// Maximum total number of dice across all terms in one roll
pub const MAX_DICE: u32 = 100;
/// Maximum number of sides on a die
pub const MAX_SIDES: u32 = 1000;
/// Maximum number of terms (dice groups + modifiers) in one roll
pub const MAX_TERMS: usize = 10;
/// Maximum absolute value of a constant modifier
pub const MAX_MODIFIER: i64 = 10_000;
/// Maximum accepted notation length
pub const MAX_NOTATION_LENGTH: usize = 64;

/// Keep rule applied to a dice term
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepRule {
    /// Keep the N highest dice
    Highest(u32),
    /// Keep the N lowest dice
    Lowest(u32),
}

/// A single rolled die within a term
#[derive(Debug, Clone)]
pub struct RolledDie {
    /// Face value rolled
    pub value: u32,
    /// Whether this die counts towards the total (false = dropped by a keep rule)
    pub kept: bool,
}

/// One term of a roll expression
#[derive(Debug, Clone)]
pub enum RolledTerm {
    /// A group of dice, e.g. `4d6kh3`
    Dice {
        /// +1 or -1 depending on the sign preceding this term
        sign: i64,
        /// Number of dice rolled
        count: u32,
        /// Number of sides per die
        sides: u32,
        /// Optional keep rule
        keep: Option<KeepRule>,
        /// Individual dice results, in rolled order
        rolls: Vec<RolledDie>,
    },
    /// A constant modifier, e.g. `+3` (sign already applied)
    Modifier(i64),
}

/// Natural 20 / natural 1 detection for d20 rolls
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Natural {
    Twenty,
    One,
}

/// The outcome of evaluating a roll expression
#[derive(Debug, Clone)]
pub struct DiceRoll {
    /// Canonical (lowercased, whitespace-stripped) notation
    pub notation: String,
    /// Grand total after keep rules, signs and modifiers
    pub total: i64,
    /// Every term in the expression, in order
    pub terms: Vec<RolledTerm>,
    /// Set when the roll is a single-kept-d20 check that rolled a nat 20 / nat 1
    pub natural: Option<Natural>,
}

/// Parse `notation` and roll it using `rng`.
pub fn roll(notation: &str, rng: &mut impl Rng) -> Result<DiceRoll, String> {
    let canonical: String = notation
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_lowercase();

    if canonical.is_empty() {
        return Err("Dice notation is empty".to_string());
    }

    if canonical.len() > MAX_NOTATION_LENGTH {
        return Err(format!(
            "Dice notation is too long (max {MAX_NOTATION_LENGTH} characters)"
        ));
    }

    // Split into signed tokens: "2d6+3-1d4" -> [(+, "2d6"), (+, "3"), (-, "1d4")]
    let mut tokens: Vec<(i64, String)> = Vec::new();
    let mut sign: i64 = 1;
    let mut current = String::new();

    for (i, c) in canonical.chars().enumerate() {
        match c {
            '+' | '-' => {
                if current.is_empty() {
                    return Err(format!(
                        "Unexpected '{c}' at position {i} in dice notation"
                    ));
                }
                tokens.push((sign, std::mem::take(&mut current)));
                sign = if c == '+' { 1 } else { -1 };
            }
            _ => current.push(c),
        }
    }
    if current.is_empty() {
        return Err("Dice notation ends with a dangling operator".to_string());
    }
    tokens.push((sign, current));

    if tokens.len() > MAX_TERMS {
        return Err(format!("Too many terms in dice notation (max {MAX_TERMS})"));
    }

    let mut terms = Vec::with_capacity(tokens.len());
    let mut total_dice: u32 = 0;
    let mut total: i64 = 0;

    for (sign, token) in tokens {
        if let Some(term) = parse_dice_token(&token)? {
            let (count, sides, keep) = term;

            total_dice += count;
            if total_dice > MAX_DICE {
                return Err(format!("Too many dice in one roll (max {MAX_DICE})"));
            }

            let mut rolls: Vec<RolledDie> = (0..count)
                .map(|_| RolledDie {
                    value: rng.gen_range(1..=sides),
                    kept: true,
                })
                .collect();

            if let Some(rule) = keep {
                apply_keep_rule(&mut rolls, rule);
            }

            total += sign
                * rolls
                    .iter()
                    .filter(|d| d.kept)
                    .map(|d| d.value as i64)
                    .sum::<i64>();

            terms.push(RolledTerm::Dice {
                sign,
                count,
                sides,
                keep,
                rolls,
            });
        } else {
            // Constant modifier
            let value: i64 = token
                .parse()
                .map_err(|_| format!("Invalid term '{token}' in dice notation"))?;
            if value.abs() > MAX_MODIFIER {
                return Err(format!("Modifier too large (max {MAX_MODIFIER})"));
            }
            let signed = sign * value;
            total += signed;
            terms.push(RolledTerm::Modifier(signed));
        }
    }

    if !terms
        .iter()
        .any(|t| matches!(t, RolledTerm::Dice { .. }))
    {
        return Err("Dice notation must contain at least one dice term".to_string());
    }

    let natural = detect_natural(&terms);

    Ok(DiceRoll {
        notation: canonical,
        total,
        terms,
        natural,
    })
}

/// Roll using the thread-local RNG.
pub fn roll_notation(notation: &str) -> Result<DiceRoll, String> {
    roll(notation, &mut rand::thread_rng())
}

/// Try to parse a token as a dice term (`NdS[khX|klX]`).
/// Returns Ok(None) if the token is not dice-shaped (i.e. a plain number).
#[allow(clippy::type_complexity)]
fn parse_dice_token(token: &str) -> Result<Option<(u32, u32, Option<KeepRule>)>, String> {
    let Some(d_pos) = token.find('d') else {
        return Ok(None);
    };

    let count_str = &token[..d_pos];
    let rest = &token[d_pos + 1..];

    let count: u32 = if count_str.is_empty() {
        1
    } else {
        count_str
            .parse()
            .map_err(|_| format!("Invalid dice count in '{token}'"))?
    };

    if count == 0 {
        return Err(format!("Cannot roll zero dice in '{token}'"));
    }
    if count > MAX_DICE {
        return Err(format!("Too many dice in '{token}' (max {MAX_DICE})"));
    }

    // Split off an optional keep suffix
    let (sides_str, keep) = if let Some(pos) = rest.find("kh") {
        (&rest[..pos], Some(("kh", &rest[pos + 2..])))
    } else if let Some(pos) = rest.find("kl") {
        (&rest[..pos], Some(("kl", &rest[pos + 2..])))
    } else {
        (rest, None)
    };

    let sides: u32 = sides_str
        .parse()
        .map_err(|_| format!("Invalid die size in '{token}'"))?;

    if sides < 2 {
        return Err(format!("Dice must have at least 2 sides in '{token}'"));
    }
    if sides > MAX_SIDES {
        return Err(format!("Too many sides in '{token}' (max {MAX_SIDES})"));
    }

    let keep = match keep {
        None => None,
        Some((kind, n_str)) => {
            let n: u32 = n_str
                .parse()
                .map_err(|_| format!("Invalid keep amount in '{token}'"))?;
            if n == 0 || n > count {
                return Err(format!(
                    "Keep amount must be between 1 and the dice count in '{token}'"
                ));
            }
            Some(if kind == "kh" {
                KeepRule::Highest(n)
            } else {
                KeepRule::Lowest(n)
            })
        }
    };

    Ok(Some((count, sides, keep)))
}

/// Mark dropped dice according to the keep rule.
fn apply_keep_rule(rolls: &mut [RolledDie], rule: KeepRule) {
    let mut indices: Vec<usize> = (0..rolls.len()).collect();
    // Sort indices by value, ties broken by original position for determinism
    indices.sort_by_key(|&i| rolls[i].value);

    let keep_n = match rule {
        KeepRule::Highest(n) | KeepRule::Lowest(n) => n as usize,
    };

    let dropped: &[usize] = match rule {
        // keep highest -> drop the lowest (front of sorted order)
        KeepRule::Highest(_) => &indices[..rolls.len() - keep_n],
        // keep lowest -> drop the highest (back of sorted order)
        KeepRule::Lowest(_) => &indices[keep_n..],
    };

    for &i in dropped {
        rolls[i].kept = false;
    }
}

/// A roll counts as a "d20 check" when exactly one d20 die is kept across the
/// whole expression and no other dice are kept — i.e. `1d20+5`, `2d20kh1`, `2d20kl1`.
fn detect_natural(terms: &[RolledTerm]) -> Option<Natural> {
    let mut kept_d20: Option<u32> = None;
    let mut kept_dice = 0u32;

    for term in terms {
        if let RolledTerm::Dice { sides, rolls, sign, .. } = term {
            for die in rolls.iter().filter(|d| d.kept) {
                kept_dice += 1;
                if *sides == 20 && *sign == 1 {
                    kept_d20 = Some(die.value);
                }
            }
        }
    }

    if kept_dice != 1 {
        return None;
    }

    match kept_d20 {
        Some(20) => Some(Natural::Twenty),
        Some(1) => Some(Natural::One),
        _ => None,
    }
}

/// Format a roll outcome as message content.
///
/// Produces stable, markdown-friendly output, e.g.:
/// `🎲 \`2d6+3\` → [4, 5] + 3 = **12**`
/// Dropped dice are struck through: `[6, 5, ~~2~~, ~~1~~]`.
pub fn format_roll(roll: &DiceRoll) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(roll.terms.len());

    for (i, term) in roll.terms.iter().enumerate() {
        match term {
            RolledTerm::Dice { sign, rolls, .. } => {
                let dice: Vec<String> = rolls
                    .iter()
                    .map(|d| {
                        if d.kept {
                            d.value.to_string()
                        } else {
                            format!("~~{}~~", d.value)
                        }
                    })
                    .collect();
                let group = format!("[{}]", dice.join(", "));
                if i == 0 {
                    if *sign < 0 {
                        parts.push(format!("-{group}"));
                    } else {
                        parts.push(group);
                    }
                } else if *sign < 0 {
                    parts.push(format!("- {group}"));
                } else {
                    parts.push(format!("+ {group}"));
                }
            }
            RolledTerm::Modifier(value) => {
                if i == 0 {
                    parts.push(value.to_string());
                } else if *value < 0 {
                    parts.push(format!("- {}", value.abs()));
                } else {
                    parts.push(format!("+ {value}"));
                }
            }
        }
    }

    let suffix = match roll.natural {
        Some(Natural::Twenty) => " — Natural 20! 🎉",
        Some(Natural::One) => " — Natural 1 💀",
        None => "",
    };

    format!(
        "🎲 `{}` → {} = **{}**{}",
        roll.notation,
        parts.join(" "),
        roll.total,
        suffix
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    fn rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    #[test]
    fn simple_roll_in_range() {
        for seed in 0..50 {
            let mut rng = StdRng::seed_from_u64(seed);
            let result = roll("1d20", &mut rng).unwrap();
            assert!((1..=20).contains(&result.total));
            assert_eq!(result.terms.len(), 1);
        }
    }

    #[test]
    fn default_count_is_one() {
        let result = roll("d6", &mut rng()).unwrap();
        match &result.terms[0] {
            RolledTerm::Dice { count, sides, .. } => {
                assert_eq!(*count, 1);
                assert_eq!(*sides, 6);
            }
            _ => panic!("expected dice term"),
        }
    }

    #[test]
    fn modifiers_apply() {
        let result = roll("1d6+3", &mut rng()).unwrap();
        let die = match &result.terms[0] {
            RolledTerm::Dice { rolls, .. } => rolls[0].value as i64,
            _ => panic!("expected dice term"),
        };
        assert_eq!(result.total, die + 3);
    }

    #[test]
    fn negative_modifier() {
        let result = roll("1d6-2", &mut rng()).unwrap();
        let die = match &result.terms[0] {
            RolledTerm::Dice { rolls, .. } => rolls[0].value as i64,
            _ => panic!("expected dice term"),
        };
        assert_eq!(result.total, die - 2);
    }

    #[test]
    fn multi_term() {
        let result = roll("2d6+1d4+3", &mut rng()).unwrap();
        assert_eq!(result.terms.len(), 3);
        let sum: i64 = result
            .terms
            .iter()
            .map(|t| match t {
                RolledTerm::Dice { sign, rolls, .. } => {
                    sign * rolls
                        .iter()
                        .filter(|d| d.kept)
                        .map(|d| d.value as i64)
                        .sum::<i64>()
                }
                RolledTerm::Modifier(v) => *v,
            })
            .sum();
        assert_eq!(result.total, sum);
    }

    #[test]
    fn keep_highest() {
        let result = roll("4d6kh3", &mut rng()).unwrap();
        match &result.terms[0] {
            RolledTerm::Dice { rolls, .. } => {
                assert_eq!(rolls.len(), 4);
                assert_eq!(rolls.iter().filter(|d| d.kept).count(), 3);
                let dropped = rolls.iter().find(|d| !d.kept).unwrap();
                let min_kept = rolls
                    .iter()
                    .filter(|d| d.kept)
                    .map(|d| d.value)
                    .min()
                    .unwrap();
                assert!(dropped.value <= min_kept);
            }
            _ => panic!("expected dice term"),
        }
    }

    #[test]
    fn keep_lowest() {
        let result = roll("2d20kl1", &mut rng()).unwrap();
        match &result.terms[0] {
            RolledTerm::Dice { rolls, .. } => {
                assert_eq!(rolls.iter().filter(|d| d.kept).count(), 1);
                let kept = rolls.iter().find(|d| d.kept).unwrap();
                let dropped = rolls.iter().find(|d| !d.kept).unwrap();
                assert!(kept.value <= dropped.value);
            }
            _ => panic!("expected dice term"),
        }
    }

    #[test]
    fn whitespace_and_case_normalised() {
        let result = roll(" 2D6 + 3 ", &mut rng()).unwrap();
        assert_eq!(result.notation, "2d6+3");
    }

    #[test]
    fn natural_twenty_detection() {
        // find a seed that rolls a 20 on 1d20
        for seed in 0..500 {
            let mut rng = StdRng::seed_from_u64(seed);
            let result = roll("1d20+5", &mut rng).unwrap();
            if result.total == 25 {
                assert_eq!(result.natural, Some(Natural::Twenty));
                return;
            }
        }
        panic!("no natural 20 in 500 seeds — statistically impossible");
    }

    #[test]
    fn no_natural_on_multiple_kept_dice() {
        for seed in 0..100 {
            let mut rng = StdRng::seed_from_u64(seed);
            let result = roll("2d20", &mut rng).unwrap();
            assert_eq!(result.natural, None);
        }
    }

    #[test]
    fn advantage_can_crit() {
        for seed in 0..500 {
            let mut rng = StdRng::seed_from_u64(seed);
            let result = roll("2d20kh1", &mut rng).unwrap();
            if result.total == 20 {
                assert_eq!(result.natural, Some(Natural::Twenty));
                return;
            }
        }
        panic!("no natural 20 in 500 seeds of advantage");
    }

    #[test]
    fn rejects_garbage() {
        assert!(roll("", &mut rng()).is_err());
        assert!(roll("hello", &mut rng()).is_err());
        assert!(roll("+", &mut rng()).is_err());
        assert!(roll("1d6+", &mut rng()).is_err());
        assert!(roll("+1d6", &mut rng()).is_err());
        assert!(roll("d", &mut rng()).is_err());
        assert!(roll("0d6", &mut rng()).is_err());
        assert!(roll("1d1", &mut rng()).is_err());
        assert!(roll("1d0", &mut rng()).is_err());
        assert!(roll("5", &mut rng()).is_err()); // no dice term
        assert!(roll("2d6kh3", &mut rng()).is_err()); // keep > count
        assert!(roll("2d6kh0", &mut rng()).is_err());
        assert!(roll("1e5d6", &mut rng()).is_err());
    }

    #[test]
    fn rejects_abuse() {
        assert!(roll("101d6", &mut rng()).is_err());
        assert!(roll("1d1001", &mut rng()).is_err());
        assert!(roll("50d6+51d6", &mut rng()).is_err()); // total dice cap
        assert!(roll("1d6+99999999", &mut rng()).is_err());
        assert!(roll("1d6+1+1+1+1+1+1+1+1+1+1+1", &mut rng()).is_err()); // term cap
        let long = "1d6+".repeat(20) + "1d6";
        assert!(roll(&long, &mut rng()).is_err());
    }

    #[test]
    fn format_basic() {
        let mut rng = StdRng::seed_from_u64(1);
        let result = roll("2d6+3", &mut rng).unwrap();
        let text = format_roll(&result);
        assert!(text.starts_with("🎲 `2d6+3` → ["));
        assert!(text.contains(&format!("= **{}**", result.total)));
    }

    #[test]
    fn format_shows_dropped_dice() {
        let mut rng = StdRng::seed_from_u64(1);
        let result = roll("4d6kh3", &mut rng).unwrap();
        let text = format_roll(&result);
        assert!(text.contains("~~"), "dropped die should be struck through: {text}");
    }
}
