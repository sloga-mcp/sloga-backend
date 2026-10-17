//! Small text helpers for upstream strings

/// Bidirectional-text controls: invisible characters that reorder how the
/// text around them is displayed (Trojan Source style spoofing)
pub(crate) fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}'
    )
}

/// Characters card text must never carry: control characters (other than
/// whitespace, which `clean` turns into a space) and bidi controls
pub(crate) fn is_hidden(c: char) -> bool {
    c.is_control() || is_bidi_control(c)
}

/// Upstream text made safe to show: whitespace controls (`\n`, `\t`, ...)
/// become spaces, every other control character and every bidi control is
/// dropped
pub(crate) fn clean(value: &str) -> String {
    value
        .chars()
        .filter_map(|c| {
            if c.is_control() && c.is_whitespace() {
                Some(' ')
            } else if is_hidden(c) {
                None
            } else {
                Some(c)
            }
        })
        .collect()
}

/// The first `max` characters of `value` (cut on a char boundary)
pub(crate) fn cap(value: &str, max: usize) -> String {
    match value.char_indices().nth(max) {
        Some((index, _)) => value[..index].to_string(),
        None => value.to_string(),
    }
}

/// Replace every `open ... close` span with a space. An `open` with no
/// matching `close` is kept as text.
pub(crate) fn strip_delimited(value: &str, open: char, close: char) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find(open) {
        out.push_str(&rest[..start]);
        let after = &rest[start + open.len_utf8()..];
        match after.find(close) {
            Some(end) => {
                out.push(' ');
                rest = &after[end + close.len_utf8()..];
            }
            None => {
                out.push_str(&rest[start..]);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Remove HTML tags
pub(crate) fn strip_tags(value: &str) -> String {
    strip_delimited(value, '<', '>')
}

/// Remove BBCode tags (`[b]`, `[url=...]`, `[/list]`, ...)
pub(crate) fn strip_bbcode(value: &str) -> String {
    strip_delimited(value, '[', ']')
}

/// Collapse every run of whitespace into one space and trim
pub(crate) fn collapse_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn named_entity(name: &str) -> Option<&'static str> {
    Some(match name {
        "amp" => "&",
        "lt" => "<",
        "gt" => ">",
        "quot" => "\"",
        "apos" => "'",
        "nbsp" => " ",
        "reg" => "\u{00AE}",
        "copy" => "\u{00A9}",
        "trade" => "\u{2122}",
        "hellip" => "\u{2026}",
        "mdash" => "\u{2014}",
        "ndash" => "\u{2013}",
        "lsquo" => "\u{2018}",
        "rsquo" => "\u{2019}",
        "ldquo" => "\u{201C}",
        "rdquo" => "\u{201D}",
        "laquo" => "\u{00AB}",
        "raquo" => "\u{00BB}",
        _ => return None,
    })
}

/// A numeric entity's text: the character, or nothing at all when it is a
/// control or bidi character (decoded, then dropped)
fn numeric_entity(body: &str) -> Option<String> {
    let code = if let Some(hex) = body.strip_prefix('x').or_else(|| body.strip_prefix('X')) {
        u32::from_str_radix(hex, 16).ok()?
    } else {
        body.parse::<u32>().ok()?
    };
    let c = char::from_u32(code).filter(|c| *c != '\0')?;
    Some(clean(&c.to_string()))
}

/// Decode the common named HTML entities and every numeric one; anything
/// unrecognised is left as written
pub(crate) fn decode_entities(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        let semi = tail
            .char_indices()
            .take(12)
            .find(|(_, c)| *c == ';')
            .map(|(index, _)| index);

        let decoded = semi.and_then(|semi| {
            let body = &tail[1..semi];
            let text = if let Some(numeric) = body.strip_prefix('#') {
                numeric_entity(numeric)
            } else {
                named_entity(body).map(String::from)
            };
            text.map(|text| (text, semi))
        });

        match decoded {
            Some((text, semi)) => {
                out.push_str(&text);
                rest = &tail[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Upstream HTML-ish text to plain text: tags stripped, entities decoded,
/// hidden characters dropped, whitespace collapsed
pub(crate) fn plain_text(value: &str) -> String {
    collapse_whitespace(&clean(&decode_entities(&strip_tags(value))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_cuts_on_char_boundaries() {
        assert_eq!(cap("hello", 10), "hello");
        assert_eq!(cap("hello", 5), "hello");
        assert_eq!(cap("hello", 2), "he");
        assert_eq!(cap("\u{00E9}\u{00E9}\u{00E9}", 2), "\u{00E9}\u{00E9}");
        assert_eq!(cap("\u{1F600}x", 1), "\u{1F600}");
        assert_eq!(cap("", 3), "");
    }

    #[test]
    fn strips_tags_and_bbcode() {
        assert_eq!(collapse_whitespace(&strip_tags("a<b>bold</b>c")), "a bold c");
        assert_eq!(
            collapse_whitespace(&strip_bbcode("[h1]Title[/h1] [url=https://x]link[/url]")),
            "Title link"
        );
        assert_eq!(strip_tags("1 < 2"), "1 < 2");
    }

    #[test]
    fn decodes_entities() {
        assert_eq!(decode_entities("The &quot;Test&quot; &amp; more"), "The \"Test\" & more");
        assert_eq!(decode_entities("&#39;x&#x27;"), "'x'");
        assert_eq!(decode_entities("AT&T &bogus; &"), "AT&T &bogus; &");
        assert_eq!(decode_entities("&#0;"), "&#0;");
        assert_eq!(decode_entities("\u{00E9}&amp;\u{00E9}"), "\u{00E9}&\u{00E9}");
    }

    #[test]
    fn drops_bidi_and_control_characters() {
        // Raw text: every bidi control and non-whitespace control dropped,
        // whitespace controls turned into spaces
        let raw = "a\u{202A}b\u{202B}c\u{202C}d\u{202D}e\u{202E}f\u{2066}g\u{2067}h\u{2068}i\u{2069}j\u{200E}k\u{200F}l\u{061C}m\u{0007}n\u{001B}o\u{007F}p\u{0085}q\nr\ts";
        assert_eq!(clean(raw), "abcdefghijklmnop q r s");
        // Decoded entities: a bidi or control entity decodes to nothing
        for entity in [
            "&#x202E;", "&#8238;", "&#x202a;", "&#x2066;", "&#x2069;", "&#x200E;", "&#x200F;",
            "&#x61C;", "&#7;", "&#x1B;",
        ] {
            assert_eq!(decode_entities(&format!("x{entity}y")), "xy", "{entity}");
        }
        assert_eq!(plain_text("evil &#x202E;gpj.exe\u{202E} name"), "evil gpj.exe name");
        // Ordinary non-ASCII text is untouched
        assert_eq!(clean("Kai'Sa \u{00E9}\u{4E2D}\u{1F600}"), "Kai'Sa \u{00E9}\u{4E2D}\u{1F600}");
    }
}
