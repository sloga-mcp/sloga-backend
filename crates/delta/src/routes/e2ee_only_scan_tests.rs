//! Encrypted-only chats: every route that can write plain user content into
//! a DM or a group calls the guard, or is listed in `EXEMPT` with a reason.
//!
//! A route file is a writer when its code (comments and inline `#[cfg(test)]`
//! modules cut) contains a trigger. A writer passes when it calls one of
//! `GUARDS`. An `EXEMPT` row fails when its file is gone, no longer has a
//! trigger, or now calls a guard, so the table cannot go stale.
//!
//! Some gated routes write without a trigger (a watch URL, a caption, a
//! reservation note, a modal answer). `MUST_GUARD` names them: each must
//! still call a guard, and a row for a missing file fails.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::util::test::{without_comments, without_whitespace};

/// Plain triggers, matched on code with every whitespace character removed.
/// `triggers` adds two computed ones: "message send" and "message update".
const PLAIN_TRIGGERS: &[&str] = &[
    "is_protected()",
    "dm_send_allowed",
    "create_from_api",
    "insert_poll",
    "insert_sheet",
    "insert_scheduled_message",
    "insert_interaction",
];

/// Calls that count as the guard. The group join funnel and group creation
/// apply the group rules themselves.
const GUARDS: &[&str] = &[
    "plain_write_allowed(",
    "plain_write_allowed_unauthored(",
    "ensure_interactions_allowed_in(",
    "add_user_to_group(",
    "Channel::create_group(",
    "Channel::create_group_from_session(",
];

/// Route files that match a trigger but write no plain user content into a
/// DM or a group, each with the reason.
const EXEMPT: &[(&str, &str)] = &[
    (
        "channels/call_recording.rs",
        "server-written system row only (recording started / stopped)",
    ),
    (
        "channels/channel_edit.rs",
        "server-written system rows only (renamed, description, icon, owner); \
         group name and description are metadata",
    ),
    (
        "channels/follow_create.rs",
        "server channels only: source and target must be server text channels",
    ),
    (
        "channels/forum_post_create.rs",
        "server channels only: posts need a forum channel, DMs and groups are refused",
    ),
    ("channels/message_clear_reactions.rs", "reactions only"),
    (
        "channels/message_crosspost.rs",
        "server channels only: announcement source and follower targets are server text channels",
    ),
    (
        "channels/message_fetch.rs",
        "read only: the protected check decides what is served",
    ),
    (
        "channels/message_pin.rs",
        "pin flag and its server-written system row",
    ),
    (
        "channels/message_query.rs",
        "read only: the protected check decides what is served",
    ),
    (
        "channels/message_search.rs",
        "read only: the protected check decides what is served",
    ),
    (
        "channels/message_unpin.rs",
        "unpin flag and its server-written system row",
    ),
    (
        "channels/seats_put.rs",
        "server channels only: seat lists exist on protected server channels",
    ),
    (
        "channels/thread_create.rs",
        "server channels only: a thread parent must be a server text channel",
    ),
    ("channels/voice_join.rs", "joins a call, writes no message"),
    (
        "events/events_crud.rs",
        "server channels only: calendar events belong to a server and its channels",
    ),
    (
        "events/import.rs",
        "server channels only: imports events from a server channel",
    ),
    (
        "mls/groups_create.rs",
        "server channels only: needs a protected server channel, carries no plaintext",
    ),
    (
        "servers/server_edit.rs",
        "server channels only: server settings, writes no message",
    ),
];

/// Gated route files that must keep calling a guard whether or not they
/// match a trigger, each with what it writes
const MUST_GUARD: &[(&str, &str)] = &[
    ("channels/watch.rs", "watch-together media URL and title"),
    ("channels/captions_send.rs", "live caption text"),
    ("channels/softres_reserve.rs", "reservation note"),
    ("channels/softres_manage.rs", "sheet edits"),
    ("interactions/modal_submit.rs", "modal answers relayed to a bot"),
];

/// What the scan saw in one route file
#[derive(Debug)]
struct Scanned {
    triggers: Vec<&'static str>,
    guarded: bool,
}

/// Test-only files: `tests.rs`, `test.rs`, `*_tests.rs`, and anything under
/// a `tests` directory. This file is one of them. Shared with the account
/// flag writer scan in `e2ee/tests.rs`.
pub(super) fn is_test_only(relative: &str) -> bool {
    let mut parts: Vec<&str> = relative.split('/').collect();
    let file = parts.pop().unwrap_or_default();
    file == "tests.rs"
        || file == "test.rs"
        || file.ends_with("_tests.rs")
        || parts.contains(&"tests")
}

/// `code` (no comments, no whitespace) without its inline `#[cfg(test)]`
/// modules, each cut to its closing brace by depth. Braces inside string
/// literals count as well, which balanced format strings survive. Shared
/// with `e2ee/tests.rs`.
pub(super) fn without_test_modules(code: &str) -> String {
    const MARK: &str = "#[cfg(test)]";

    let mut out = String::with_capacity(code.len());
    let mut rest = code;
    while let Some(at) = rest.find(MARK) {
        let mut item = &rest[at + MARK.len()..];
        // Further attributes on the same item
        while item.starts_with("#[") {
            match item.find(']') {
                Some(close) => item = &item[close + 1..],
                None => break,
            }
        }

        let is_module = ["mod", "pubmod", "pub(crate)mod"]
            .iter()
            .any(|prefix| item.starts_with(*prefix));
        let body = item
            .find(|c: char| c == '{' || c == ';')
            .filter(|&open| item[open..].starts_with('{'));

        match (is_module, body) {
            (true, Some(open)) => {
                out.push_str(&rest[..at]);
                let mut depth = 0usize;
                let mut end = item.len();
                for (offset, c) in item[open..].char_indices() {
                    if c == '{' {
                        depth += 1;
                    } else if c == '}' {
                        depth -= 1;
                        if depth == 0 {
                            end = open + offset + 1;
                            break;
                        }
                    }
                }
                rest = &item[end..];
            }
            _ => {
                out.push_str(&rest[..at + MARK.len()]);
                rest = &rest[at + MARK.len()..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// A message send: `.send(` with arguments (`Message::send` always takes
/// some; an HTTP builder's `.send()` takes none), or the two lower-level
/// send methods by name.
fn sends_a_message(code: &str) -> bool {
    code.match_indices(".send(")
        .any(|(at, call)| !code[at + call.len()..].starts_with(')'))
        || code.contains(".send_with_ack_author(")
        || code.contains(".send_without_notifications(")
}

/// A message update: `.update(` in a file that names `PartialMessage` or
/// `FieldsMessage` (what `Message::update` takes), or the driver's
/// `update_message(`.
fn updates_a_message(code: &str) -> bool {
    (code.contains(".update(")
        && (code.contains("PartialMessage") || code.contains("FieldsMessage")))
        || code.contains("update_message(")
}

/// The triggers and the guard in `source`, comments and test modules cut
fn scanned(source: &str) -> Scanned {
    let code = without_test_modules(&without_whitespace(&without_comments(source)));

    let mut triggers: Vec<&'static str> = PLAIN_TRIGGERS
        .iter()
        .copied()
        .filter(|trigger| code.contains(trigger))
        .collect();
    if sends_a_message(&code) {
        triggers.push("message send");
    }
    if updates_a_message(&code) {
        triggers.push("message update");
    }

    Scanned {
        triggers,
        guarded: GUARDS.iter().any(|guard| code.contains(guard)),
    }
}

/// Every non-test route file under `root`, relative and `/`-separated
fn route_files(root: &Path) -> BTreeMap<String, Scanned> {
    let mut found = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];

    while let Some(dir) = pending.pop() {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("read {}: {}", dir.display(), error));
        for entry in entries {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                continue;
            }

            let relative = path
                .strip_prefix(root)
                .expect("under the routes directory")
                .to_string_lossy()
                .replace('\\', "/");
            if is_test_only(&relative) {
                continue;
            }

            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {}", path.display(), error));
            found.insert(relative, scanned(&source));
        }
    }

    found
}

/// Every ungated writer missing from `exempt`, and every bad `exempt` row
fn problems(files: &BTreeMap<String, Scanned>, exempt: &[(&str, &str)]) -> Vec<String> {
    let mut found = Vec::new();
    let mut listed = BTreeSet::new();

    for (file, reason) in exempt {
        if !listed.insert(*file) {
            found.push(format!("{}: listed in EXEMPT twice", file));
        }
        if reason.trim().is_empty() {
            found.push(format!("{}: EXEMPT row without a reason", file));
        }
        match files.get(*file) {
            None => found.push(format!(
                "{}: EXEMPT row for a route file that does not exist: drop it",
                file
            )),
            Some(scan) if scan.triggers.is_empty() => found.push(format!(
                "{}: EXEMPT row, but the file no longer matches any trigger: drop it",
                file
            )),
            Some(scan) if scan.guarded => found.push(format!(
                "{}: EXEMPT row, but the file now calls the guard: drop it",
                file
            )),
            Some(_) => {}
        }
    }

    for (file, scan) in files {
        if !scan.triggers.is_empty() && !scan.guarded && !listed.contains(file.as_str()) {
            found.push(format!(
                "{}: matches {:?} but calls none of {:?}: gate it, or add an EXEMPT row with a reason",
                file, scan.triggers, GUARDS
            ));
        }
    }

    found
}

/// Every `must_guard` row whose file is gone or no longer calls a guard
fn must_guard_problems(
    files: &BTreeMap<String, Scanned>,
    must_guard: &[(&str, &str)],
) -> Vec<String> {
    let mut found = Vec::new();

    for (file, writes) in must_guard {
        match files.get(*file) {
            None => found.push(format!(
                "{}: MUST_GUARD row for a route file that does not exist: fix the path or drop it",
                file
            )),
            Some(scan) if !scan.guarded => found.push(format!(
                "{}: writes {} but calls none of {:?}",
                file, writes, GUARDS
            )),
            Some(_) => {}
        }
    }

    found
}

#[test]
fn every_plain_writer_is_gated_or_exempt() {
    let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src/routes"));
    let files = route_files(root);

    // The scan reads the real tree: known gated writers show as writers
    for file in [
        "channels/message_send.rs",
        "channels/poll_create.rs",
        "webhooks/webhook_execute.rs",
        "interactions/respond.rs",
    ] {
        let scan = files
            .get(file)
            .unwrap_or_else(|| panic!("{}: not scanned", file));
        assert!(
            !scan.triggers.is_empty() && scan.guarded,
            "{}: expected a gated writer, got {:?}",
            file,
            scan
        );
    }

    let mut found = problems(&files, EXEMPT);
    found.extend(must_guard_problems(&files, MUST_GUARD));
    assert!(
        found.is_empty(),
        "Encrypted-only scan:\n{}",
        found.join("\n")
    );
}

#[test]
fn scan_catches_an_ungated_writer_and_stale_rows() {
    // A guard named only in a comment is not a guard
    let ungated = scanned(concat!(
        "async fn route(db: &Database, channel: &Channel) -> Result<()> {\n",
        "    // plain_write_allowed(db, cfg, user, channel, None).await?;\n",
        "    let mut message = Message::default();\n",
        "    message\n",
        "        .send(db, None, author, None, None, channel, true)\n",
        "        .await\n",
        "}\n",
    ));
    assert_eq!(ungated.triggers, ["message send"]);
    assert!(!ungated.guarded);

    let gated = scanned(concat!(
        "async fn route(db: &Database, cfg: &E2EEFeatures, user: &User, channel: &Channel) -> Result<()> {\n",
        "    e2ee_only::plain_write_allowed(db, cfg, user, channel, None).await?;\n",
        "    if channel.is_protected() {\n",
        "        return Err(create_error!(ChannelProtected));\n",
        "    }\n",
        "    db.insert_poll(&poll).await\n",
        "}\n",
    ));
    assert_eq!(gated.triggers, ["is_protected()", "insert_poll"]);
    assert!(gated.guarded);

    let edit = scanned(concat!(
        "async fn edit(db: &Database, message: &mut Message, text: String) -> Result<()> {\n",
        "    let partial = PartialMessage { content: Some(text), ..Default::default() };\n",
        "    message.update(db, partial, vec![]).await\n",
        "}\n",
    ));
    assert_eq!(edit.triggers, ["message update"]);
    assert!(!edit.guarded);

    // Comments, inline test modules and an HTTP builder's `.send()` are not
    // writers
    let quiet = scanned(concat!(
        "async fn fetch(client: &Client) -> Result<()> {\n",
        "    // message.send(db, None, author, None, None, channel, true).await?;\n",
        "    /* db.insert_sheet(&sheet).await?; */\n",
        "    client.get(URL).send().await?;\n",
        "    Ok(())\n",
        "}\n",
        "#[cfg(test)]\n",
        "mod tests {\n",
        "    fn f() { db.insert_poll(&poll); message.update(db, PartialMessage::default(), vec![]); }\n",
        "}\n",
    ));
    assert!(quiet.triggers.is_empty(), "{:?}", quiet);

    let files: BTreeMap<String, Scanned> = vec![
        ("channels/ungated.rs", ungated),
        ("channels/gated.rs", gated),
        ("channels/edit.rs", edit),
        ("channels/quiet.rs", quiet),
    ]
    .into_iter()
    .map(|(file, scan)| (file.to_string(), scan))
    .collect();

    let found = problems(
        &files,
        &[
            ("channels/edit.rs", "a real exemption"),
            ("channels/quiet.rs", "no trigger left"),
            ("channels/gone.rs", "file removed"),
            ("channels/gated.rs", "now gated"),
        ],
    );
    let expected = [
        "channels/ungated.rs: matches",
        "channels/quiet.rs: EXEMPT row, but the file no longer matches any trigger",
        "channels/gone.rs: EXEMPT row for a route file that does not exist",
        "channels/gated.rs: EXEMPT row, but the file now calls the guard",
    ];
    assert_eq!(found.len(), expected.len(), "{:#?}", found);
    for start in expected {
        assert!(
            found.iter().any(|problem| problem.starts_with(start)),
            "`{}` not reported: {:#?}",
            start,
            found
        );
    }

    let found = problems(
        &files,
        &[
            ("channels/edit.rs", ""),
            ("channels/edit.rs", "twice"),
            ("channels/ungated.rs", "a real exemption"),
        ],
    );
    assert_eq!(found.len(), 2, "{:#?}", found);
    assert!(found
        .iter()
        .any(|problem| problem.ends_with("listed in EXEMPT twice")));
    assert!(found
        .iter()
        .any(|problem| problem.ends_with("EXEMPT row without a reason")));

    // Control: every writer gated or exempt with a reason, no stale rows
    let found = problems(
        &files,
        &[
            ("channels/ungated.rs", "a real exemption"),
            ("channels/edit.rs", "a real exemption"),
        ],
    );
    assert!(found.is_empty(), "{:#?}", found);
}

#[test]
fn scan_catches_a_must_guard_file_without_a_guard() {
    // No trigger, and the only guard call sits in an inline test module
    let unguarded = scanned(concat!(
        "async fn caption(text: String) -> Result<()> {\n",
        "    broadcast(text).await\n",
        "}\n",
        "#[cfg(test)]\n",
        "mod tests {\n",
        "    fn f() { e2ee_only::plain_write_allowed(db, cfg, user, channel, None); }\n",
        "}\n",
    ));
    assert!(unguarded.triggers.is_empty(), "{:?}", unguarded);
    assert!(!unguarded.guarded);

    let guarded = scanned(concat!(
        "async fn caption(db: &Database, cfg: &E2EEFeatures, user: &User, channel: &Channel, text: String) -> Result<()> {\n",
        "    e2ee_only::plain_write_allowed(db, cfg, user, channel, None).await?;\n",
        "    broadcast(text).await\n",
        "}\n",
    ));
    assert!(guarded.triggers.is_empty(), "{:?}", guarded);
    assert!(guarded.guarded);

    let files: BTreeMap<String, Scanned> = vec![
        ("channels/unguarded.rs", unguarded),
        ("channels/guarded.rs", guarded),
    ]
    .into_iter()
    .map(|(file, scan)| (file.to_string(), scan))
    .collect();

    // A writer with no trigger is not a problem for the trigger scan
    assert!(problems(&files, &[]).is_empty());

    let found = must_guard_problems(
        &files,
        &[
            ("channels/unguarded.rs", "caption text"),
            ("channels/gone.rs", "file removed"),
            ("channels/guarded.rs", "caption text"),
        ],
    );
    let expected = [
        "channels/unguarded.rs: writes caption text but calls none of",
        "channels/gone.rs: MUST_GUARD row for a route file that does not exist",
    ];
    assert_eq!(found.len(), expected.len(), "{:#?}", found);
    for start in expected {
        assert!(
            found.iter().any(|problem| problem.starts_with(start)),
            "`{}` not reported: {:#?}",
            start,
            found
        );
    }

    // Control: a listed file that calls a guard passes
    let found = must_guard_problems(&files, &[("channels/guarded.rs", "caption text")]);
    assert!(found.is_empty(), "{:#?}", found);
}

#[test]
fn without_test_modules_cuts_test_modules_only() {
    let code = without_whitespace(concat!(
        "fn a() { x(e2ee_only: Some(true)); }\n",
        "#[cfg(test)]\n",
        "#[allow(dead_code)]\n",
        "mod tests {\n",
        "    fn b() { if c { d(\"{}\") } y(e2ee_only: Some(true)); }\n",
        "}\n",
        "#[cfg(test)]\n",
        "use z;\n",
        "fn after() { w(e2ee_only: Some(false)); }\n",
        "#[cfg(test)]\n",
        "pub(crate) mod more { fn e() { v(e2ee_only: Some(true)); } }\n",
    ));
    let kept = without_test_modules(&code);
    assert_eq!(kept.matches("e2ee_only:Some(").count(), 2, "{}", kept);
    assert!(kept.contains("fna()"), "{}", kept);
    assert!(kept.contains("fnafter()"), "{}", kept);
    assert!(kept.contains("#[cfg(test)]usez;"), "{}", kept);
    assert!(!kept.contains("fnb()"), "{}", kept);
    assert!(!kept.contains("fne()"), "{}", kept);
}
