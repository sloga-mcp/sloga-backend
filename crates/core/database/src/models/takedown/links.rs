//! Turning a submitted location (a link or id) into the Sloga object it
//! names. Pure: no database, no network, nothing fetched.

use reqwest::Url;

/// What a submitted location points at, by shape alone
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedLocation {
    Message {
        channel: String,
        message: String,
    },
    Channel {
        channel: String,
    },
    User {
        user: String,
    },
    Server {
        server: String,
    },
    File {
        tag: String,
        file: String,
    },
    Emoji {
        emoji: String,
    },
    /// An http(s) link to a host that is not Sloga's
    External,
    /// Anything else, including bare ids (an id alone does not say what it is)
    Unrecognized,
}

/// Upload tags the file server serves (`services/autumn` `Tag`)
const FILE_TAGS: [&str; 8] = [
    "attachments",
    "avatars",
    "backgrounds",
    "icons",
    "banners",
    "emojis",
    "stickers",
    "soundboard",
];

/// Path prefixes Sloga serves the client or the file server under
const KNOWN_PREFIXES: [&str; 2] = ["app", "autumn"];

/// Parse a location, treating `sloga.gg` and its subdomains as Sloga
pub fn parse_location(raw: &str) -> ParsedLocation {
    parse_location_with_hosts(raw, &[])
}

/// Parse a location, also treating the hosts of `bases` (the configured app,
/// API and file-server URLs) as Sloga. A base with a path (such as
/// `https://example.com/autumn`) also has that path stripped before matching.
pub fn parse_location_with_hosts(raw: &str, bases: &[&str]) -> ParsedLocation {
    let raw = raw.trim();
    if raw.is_empty() || raw.chars().any(char::is_whitespace) {
        return ParsedLocation::Unrecognized;
    }

    let Some(url) = parse_url(raw) else {
        return ParsedLocation::Unrecognized;
    };

    let Some(host) = url
        .host_str()
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
    else {
        return ParsedLocation::Unrecognized;
    };

    // A link copied inside a desktop or mobile app carries the app's own
    // origin. Only client routes live there, never the file server.
    if is_app_origin(url.scheme(), &host) {
        let path = segments(&url);
        let path: Vec<&str> = path.iter().map(String::as_str).collect();
        return interpret_client(&path).unwrap_or(ParsedLocation::Unrecognized);
    }

    if !matches!(url.scheme(), "http" | "https") {
        return ParsedLocation::Unrecognized;
    }

    let bases: Vec<Url> = bases
        .iter()
        .filter_map(|base| Url::parse(base.trim()).ok())
        .collect();

    let base_prefixes: Vec<Vec<String>> = bases
        .iter()
        .filter(|base| {
            base.host_str()
                .is_some_and(|base_host| base_host.eq_ignore_ascii_case(&host))
        })
        .map(segments)
        .collect();

    if !is_sloga_host(&host) && base_prefixes.is_empty() {
        return ParsedLocation::External;
    }

    let path = segments(&url);
    let path: Vec<&str> = path.iter().map(String::as_str).collect();

    // A configured base path first (it may be anything), then the known ones
    for prefix in base_prefixes.iter().filter(|prefix| !prefix.is_empty()) {
        if path.len() > prefix.len() && path.iter().zip(prefix).all(|(a, b)| *a == b.as_str()) {
            if let Some(parsed) = interpret(&path[prefix.len()..]) {
                return parsed;
            }
        }
    }

    if let Some(parsed) = interpret(&path) {
        return parsed;
    }

    if let Some((first, rest)) = path.split_first() {
        if KNOWN_PREFIXES.contains(first) {
            if let Some(parsed) = interpret(rest) {
                return parsed;
            }
        }
    }

    ParsedLocation::Unrecognized
}

/// Parse with a scheme, or as `host/path` when the scheme was left off
fn parse_url(raw: &str) -> Option<Url> {
    if raw.contains("://") {
        return Url::parse(raw).ok();
    }

    // `app.sloga.gg/channel/...` pasted without `https://`. Requires a dot in
    // the first segment so a bare id never becomes a host.
    let first = raw.split(['/', '?', '#']).next().unwrap_or_default();
    if first.contains('.') {
        Url::parse(&format!("https://{raw}")).ok()
    } else {
        None
    }
}

fn is_sloga_host(host: &str) -> bool {
    host == "sloga.gg" || host.ends_with(".sloga.gg")
}

/// Non-empty path segments, still percent-encoded (ids are plain ASCII, so
/// an encoded one just fails the id check)
fn segments(url: &Url) -> Vec<String> {
    url.path_segments()
        .map(|parts| {
            parts
                .filter(|part| !part.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Origins the Sloga apps load the client from:
/// - Tauri desktop: `https://tauri.localhost` (`useHttpsScheme`), or
///   `http://tauri.localhost` / `tauri://localhost` on other builds
/// - Electron desktop: `app://bundle` (`electron-shell` `APP_ORIGIN`)
/// - Capacitor: `https://localhost` (Android), `capacitor://localhost` (iOS)
/// - A local dev server: `http://localhost:<port>`
fn is_app_origin(scheme: &str, host: &str) -> bool {
    matches!(
        (scheme, host),
        ("http" | "https", "tauri.localhost")
            | ("http" | "https", "localhost")
            | ("tauri", "localhost")
            | ("capacitor", "localhost")
            | ("app", "bundle")
    )
}

/// Match a Sloga path (prefix already stripped) against the client routes
/// (`packages/client/src/index.tsx`) and the file server routes
fn interpret(path: &[&str]) -> Option<ParsedLocation> {
    interpret_client(path).or_else(|| interpret_file(path))
}

/// File server: /<tag>/<id>, /<tag>/<id>/<file name>
fn interpret_file(path: &[&str]) -> Option<ParsedLocation> {
    match path {
        [tag, file] | [tag, file, _] if FILE_TAGS.contains(tag) => file_route(tag, file),
        _ => None,
    }
}

/// Client routes only
fn interpret_client(path: &[&str]) -> Option<ParsedLocation> {
    match path {
        // /channel/<channel>/<message>, /channel/<channel>
        ["channel", channel, rest @ ..] => Some(channel_route(channel, rest)),

        // /server/<server>/channel/<channel>[/<message>], /server/<server>[/...]
        ["server", server, "channel", channel, rest @ ..] if ulid(server).is_some() => {
            Some(channel_route(channel, rest))
        }
        ["server", server, ..] => ulid(server).map(|server| ParsedLocation::Server { server }),

        // /discover/server/<server>
        ["discover", "server", server, ..] => {
            ulid(server).map(|server| ParsedLocation::Server { server })
        }

        // /user/<user>
        ["user", user, ..] => ulid(user).map(|user| ParsedLocation::User { user }),

        _ => None,
    }
}

fn channel_route(channel: &str, rest: &[&str]) -> ParsedLocation {
    let Some(channel) = ulid(channel) else {
        return ParsedLocation::Unrecognized;
    };

    match rest.first().and_then(|message| ulid(message)) {
        Some(message) => ParsedLocation::Message { channel, message },
        None => ParsedLocation::Channel { channel },
    }
}

fn file_route(tag: &str, file: &str) -> Option<ParsedLocation> {
    if !is_file_id(file) {
        return None;
    }

    // An emoji's id is its file's id, and emoji images have no other link
    if tag == "emojis" {
        return ulid(file).map(|emoji| ParsedLocation::Emoji { emoji });
    }

    Some(ParsedLocation::File {
        tag: tag.to_string(),
        file: file.to_string(),
    })
}

/// A 26-character Crockford base32 ULID, normalized to upper case
fn ulid(value: &str) -> Option<String> {
    let value = value.to_ascii_uppercase();
    let valid = value.len() == 26
        && value.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_uppercase() && !b"ILOU".contains(&byte))
        });
    valid.then_some(value)
}

/// File ids are 42-character nanoids, or ULIDs (emojis and imported files)
fn is_file_id(value: &str) -> bool {
    (value.len() == 42 || value.len() == 26)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::{parse_location, parse_location_with_hosts, ParsedLocation};

    const C: &str = "01KWFKG47HBFTEEN6XPPS8H3HQ";
    const M: &str = "01KWFKH2ZQ3M7B0V5S9XWCD4EA";
    const S: &str = "01KWFKJ8RT6N2P4Q8S0VWXYZ12";
    const U: &str = "01KWFKK3AB5C7D9EFGHJKMNPQR";
    const NANO: &str = "aBcD3fGh1jKlMnOpQrStUvWxYz0123456789_-AbCd";

    fn message() -> ParsedLocation {
        ParsedLocation::Message {
            channel: C.to_string(),
            message: M.to_string(),
        }
    }

    #[test]
    fn message_links() {
        assert_eq!(NANO.len(), 42);
        let lower = C.to_lowercase();
        for raw in [
            format!("https://app.sloga.gg/channel/{C}/{M}"),
            format!("https://app.sloga.gg/server/{S}/channel/{C}/{M}"),
            format!("https://sloga.gg/app/channel/{C}/{M}"),
            format!("https://sloga.gg/app/server/{S}/channel/{C}/{M}?x=1#frag"),
            format!("  app.sloga.gg/channel/{C}/{M}  "),
            // Host case and id case don't matter
            format!("https://APP.Sloga.GG/channel/{lower}/{M}"),
        ] {
            assert_eq!(parse_location(&raw), message(), "{raw}");
        }
    }

    #[test]
    fn channel_links() {
        let expected = ParsedLocation::Channel {
            channel: C.to_string(),
        };
        assert_eq!(
            parse_location(&format!("https://app.sloga.gg/channel/{C}")),
            expected
        );
        assert_eq!(
            parse_location(&format!("https://app.sloga.gg/server/{S}/channel/{C}/")),
            expected
        );
    }

    #[test]
    fn user_links() {
        assert_eq!(
            parse_location(&format!("https://app.sloga.gg/user/{U}")),
            ParsedLocation::User {
                user: U.to_string()
            }
        );
    }

    #[test]
    fn server_links() {
        let expected = ParsedLocation::Server {
            server: S.to_string(),
        };
        assert_eq!(
            parse_location(&format!("https://app.sloga.gg/server/{S}")),
            expected
        );
        assert_eq!(
            parse_location(&format!("https://app.sloga.gg/server/{S}/events")),
            expected
        );
        assert_eq!(
            parse_location(&format!("https://app.sloga.gg/discover/server/{S}")),
            expected
        );
    }

    #[test]
    fn file_links() {
        let expected = ParsedLocation::File {
            tag: "attachments".to_string(),
            file: NANO.to_string(),
        };
        for raw in [
            format!("https://app.sloga.gg/autumn/attachments/{NANO}"),
            format!("https://app.sloga.gg/autumn/attachments/{NANO}/photo%20one.png"),
            format!("https://cdn.sloga.gg/attachments/{NANO}"),
        ] {
            assert_eq!(parse_location(&raw), expected, "{raw}");
        }

        assert_eq!(
            parse_location(&format!("https://app.sloga.gg/autumn/avatars/{NANO}")),
            ParsedLocation::File {
                tag: "avatars".to_string(),
                file: NANO.to_string(),
            }
        );
    }

    #[test]
    fn emoji_links() {
        assert_eq!(
            parse_location(&format!("https://app.sloga.gg/autumn/emojis/{U}")),
            ParsedLocation::Emoji {
                emoji: U.to_string()
            }
        );
    }

    #[test]
    fn configured_hosts_count_as_sloga() {
        let bases = [
            "http://local.revolt.chat",
            "http://files.example.org/uploads",
        ];

        assert_eq!(
            parse_location_with_hosts(&format!("http://local.revolt.chat/channel/{C}/{M}"), &bases),
            message()
        );
        assert_eq!(
            parse_location_with_hosts(
                &format!("http://files.example.org/uploads/attachments/{NANO}"),
                &bases
            ),
            ParsedLocation::File {
                tag: "attachments".to_string(),
                file: NANO.to_string(),
            }
        );

        // Without the configuration the same hosts are someone else's.
        assert_eq!(
            parse_location(&format!("http://local.revolt.chat/channel/{C}/{M}")),
            ParsedLocation::External
        );
    }

    #[test]
    fn links_copied_inside_the_apps() {
        for origin in [
            "https://tauri.localhost",
            "http://tauri.localhost",
            "tauri://localhost",
            "app://bundle",
            "https://localhost",
            "http://localhost",
            "http://localhost:5173",
            "capacitor://localhost",
        ] {
            assert_eq!(
                parse_location(&format!("{origin}/channel/{C}/{M}")),
                message(),
                "{origin}"
            );
            assert_eq!(
                parse_location(&format!("{origin}/server/{S}/channel/{C}/{M}")),
                message(),
                "{origin}"
            );
            assert_eq!(
                parse_location(&format!("{origin}/user/{U}")),
                ParsedLocation::User {
                    user: U.to_string()
                },
                "{origin}"
            );
            assert_eq!(
                parse_location(&format!("{origin}/server/{S}")),
                ParsedLocation::Server {
                    server: S.to_string()
                },
                "{origin}"
            );

            // The apps don't serve files at their own origin.
            assert_eq!(
                parse_location(&format!("{origin}/attachments/{NANO}")),
                ParsedLocation::Unrecognized,
                "{origin}"
            );
            assert_eq!(
                parse_location(&format!("{origin}/autumn/attachments/{NANO}")),
                ParsedLocation::Unrecognized,
                "{origin}"
            );
        }

        // Other hosts on the app schemes are not the apps.
        for raw in [
            format!("app://other/channel/{C}/{M}"),
            format!("capacitor://example.com/channel/{C}/{M}"),
            format!("tauri://example.com/channel/{C}/{M}"),
        ] {
            assert_eq!(parse_location(&raw), ParsedLocation::Unrecognized, "{raw}");
        }
        assert_eq!(
            parse_location(&format!("https://localhost.example.com/channel/{C}/{M}")),
            ParsedLocation::External
        );
    }

    #[test]
    fn external_links() {
        for raw in [
            "https://example.com/channel/01KWFKG47HBFTEEN6XPPS8H3HQ",
            "http://imgur.com/abc",
            "https://sloga.gg.evil.com/channel/01KWFKG47HBFTEEN6XPPS8H3HQ",
            "https://notsloga.gg/user/01KWFKK3AB5C7D9EFGHJKMNPQR",
            "example.org/some/page",
        ] {
            assert_eq!(parse_location(raw), ParsedLocation::External, "{raw}");
        }
    }

    #[test]
    fn unrecognized_locations() {
        for raw in [
            String::new(),
            "   ".to_string(),
            // A bare id does not say what kind of object it is.
            C.to_string(),
            NANO.to_string(),
            "somewhere in the general channel".to_string(),
            "javascript:alert(1)".to_string(),
            "ftp://app.sloga.gg/channel/x".to_string(),
            "https://sloga.gg/legal/take-it-down.html".to_string(),
            "https://app.sloga.gg/invite/abc".to_string(),
            format!("https://app.sloga.gg/channel/not-an-id/{M}"),
            format!("https://app.sloga.gg/autumn/e2ee/{NANO}"),
            "https://app.sloga.gg/autumn/attachments/short".to_string(),
            format!("https://app.sloga.gg/autumn/emojis/{NANO}"),
            "https://app.sloga.gg/user/nobody".to_string(),
        ] {
            assert_eq!(parse_location(&raw), ParsedLocation::Unrecognized, "{raw}");
        }
    }
}
