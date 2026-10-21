use std::collections::HashSet;

use futures::{stream, StreamExt, TryStreamExt};
use revolt_database::{
    occurrences_in_window, util::event_visibility::EventViewer, CalendarEvent, Database, Member,
    User,
};
use revolt_models::v0;
use revolt_result::{create_error, ErrorType, Result};
use rocket::{serde::json::Json, State};

/// Max window span (`to - from`): 62 days.
const MAX_UPCOMING_WINDOW_MS: i64 = 62 * 24 * 60 * 60 * 1000;

/// Rows returned when `limit` is omitted.
const DEFAULT_LIMIT: i64 = 20;

/// Largest accepted `limit`.
const MAX_LIMIT: i64 = 100;

/// Servers scanned per request, lowest server id first.
const MAX_UPCOMING_SERVERS: usize = 200;

/// Servers processed concurrently. `buffered` keeps their results in order.
const PARALLEL_SERVERS: usize = 8;

/// Recurring series read per server.
const SERIES_CAP: usize = 200;

/// One-off rows requested per page.
const PAGE: usize = 100;

/// One-off rows requested per server across all pages. Counted by the requested
/// page size, so a server costs at most `SCAN_BUDGET / PAGE` queries.
const SCAN_BUDGET: usize = 500;

/// A visible event with its occurrences at or after `from`; `key` is the first of them.
struct Candidate {
    key: i64,
    event: CalendarEvent,
    occurrences: Vec<i64>,
}

fn by_key_then_id(a: &Candidate, b: &Candidate) -> std::cmp::Ordering {
    (a.key, &a.event.id).cmp(&(b.key, &b.event.id))
}

/// # List Upcoming Events
///
/// The soonest events across every server the caller is a member of, limited to
/// events the caller can view and ordered by their first occurrence at or after
/// `from`. `from` and `to` are required; the window may span at most 62 days.
/// `limit` defaults to 20 and must be between 1 and 100. Cancelled series and
/// occurrences that start before `from` are not included.
#[openapi(tag = "Calendar")]
#[get("/@me/upcoming?<from>&<to>&<limit>")]
pub async fn list_upcoming_events(
    db: &State<Database>,
    user: User,
    from: Option<i64>,
    to: Option<i64>,
    limit: Option<i64>,
) -> Result<Json<Vec<v0::EventWithOccurrences>>> {
    super::require_events_enabled().await?;
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    // Checked span: reject missing, inverted or over-cap windows without overflow.
    let (from, to) = match (from, to) {
        (Some(from), Some(to))
            if to
                .checked_sub(from)
                .is_some_and(|span| (0..=MAX_UPCOMING_WINDOW_MS).contains(&span)) =>
        {
            (from, to)
        }
        _ => {
            return Err(create_error!(FailedValidation {
                error: "window".to_string()
            }))
        }
    };

    // Rocket reads a value that does not parse (`limit=abc`) as `None`, so it
    // gets the default rather than an error.
    let limit = match limit.unwrap_or(DEFAULT_LIMIT) {
        n @ 1..=MAX_LIMIT => n as usize,
        _ => {
            return Err(create_error!(FailedValidation {
                error: "limit".to_string()
            }))
        }
    };

    // An untyped 404 tells the client this server predates the route, so this
    // route never answers NotFound: no call below should produce one, and if one
    // ever does it is reported as an internal error instead.
    let rows = collect_upcoming(db, &user, from, to, limit)
        .await
        .map_err(|error| {
            if matches!(error.error_type, ErrorType::NotFound) {
                revolt_config::capture_error(&error);
                create_error!(InternalError)
            } else {
                error
            }
        })?;

    Ok(Json(
        rows.into_iter()
            .map(|row| v0::EventWithOccurrences {
                event: super::event_to_wire(row.event),
                occurrences: row.occurrences,
            })
            .collect(),
    ))
}

/// Every server's soonest visible events, merged, sorted by (key, event id) and cut
/// to `limit`. A database error fails the whole request.
async fn collect_upcoming(
    db: &Database,
    user: &User,
    from: i64,
    to: i64,
    limit: usize,
) -> Result<Vec<Candidate>> {
    let mut members = db.fetch_all_memberships(&user.id).await?;
    members.sort_by(|a, b| a.id.server.cmp(&b.id.server));
    if members.len() > MAX_UPCOMING_SERVERS {
        log::warn!(
            "upcoming events: caller is in {} servers; scanning the first {}",
            members.len(),
            MAX_UPCOMING_SERVERS
        );
        members.truncate(MAX_UPCOMING_SERVERS);
    }

    // Each member row moves into its server's future: a closure over borrowed rows
    // would not satisfy the handler's `Send` bound.
    let per_server: Vec<Vec<Candidate>> = stream::iter(members)
        .map(|member| upcoming_for_server(db, user, member, from, to, limit))
        .buffered(PARALLEL_SERVERS)
        .try_collect()
        .await?;

    let mut rows: Vec<Candidate> = per_server.into_iter().flatten().collect();
    rows.sort_by(by_key_then_id);
    rows.truncate(limit);
    Ok(rows)
}

/// One server's soonest visible events (at most `limit`), sorted by (key, event id).
///
/// One-offs come back from the database ordered by (start, id), which for a one-off
/// is its key, so once `limit` of them are visible no later one-off of this server
/// can make the merged cut and paging stops there.
async fn upcoming_for_server(
    db: &Database,
    user: &User,
    member: Member,
    from: i64,
    to: i64,
    limit: usize,
) -> Result<Vec<Candidate>> {
    let server_id = member.id.server.clone();
    // Each server gets its own viewer, holding only this server's member row.
    let mut viewer = EventViewer::with_memberships(db, user, vec![member]);
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();

    let series = db
        .fetch_upcoming_series_for_server(&server_id, from, to, SERIES_CAP)
        .await?;
    if series.len() >= SERIES_CAP {
        log::warn!("upcoming events: server {server_id} hit the {SERIES_CAP}-series cap");
    }
    for event in series {
        if let Some(row) = candidate(&mut viewer, &mut seen, event, from, to).await {
            out.push(row);
        }
    }

    // A short page does not mean the end of the results, so `offset` advances by
    // the requested page size and only an empty page or the budget ends the scan.
    let mut visible_oneoffs = 0;
    let mut offset = 0;
    let mut last_page_full = false;
    'pages: while offset < SCAN_BUDGET && visible_oneoffs < limit {
        let page_size = PAGE.min(SCAN_BUDGET - offset);
        let page = db
            .fetch_upcoming_oneoffs_for_server(&server_id, from, to, offset, page_size)
            .await?;
        if page.is_empty() {
            break;
        }
        offset += page_size;
        last_page_full = page.len() >= page_size;
        for event in page {
            if let Some(row) = candidate(&mut viewer, &mut seen, event, from, to).await {
                out.push(row);
                visible_oneoffs += 1;
                if visible_oneoffs >= limit {
                    break 'pages;
                }
            }
        }
    }
    // The budget ran out on a full page before `limit` visible one-offs were found,
    // so later visible one-offs of this server may be missing from the result.
    if offset >= SCAN_BUDGET && last_page_full && visible_oneoffs < limit {
        log::warn!(
            "upcoming events: server {server_id} hit the {SCAN_BUDGET}-row one-off scan budget"
        );
    }

    out.sort_by(by_key_then_id);
    out.truncate(limit);
    Ok(out)
}

/// The event as a candidate row, or None when it was already seen on this server,
/// is cancelled, is not visible to the caller, or has no occurrence at or after
/// `from` inside the window (excepted occurrences are already removed).
async fn candidate(
    viewer: &mut EventViewer<'_>,
    seen: &mut HashSet<String>,
    event: CalendarEvent,
    from: i64,
    to: i64,
) -> Option<Candidate> {
    if event.cancelled || !seen.insert(event.id.clone()) {
        return None;
    }
    if !viewer.can_view(&event).await {
        return None;
    }
    let occurrences: Vec<i64> = occurrences_in_window(&event, from, to)
        .into_iter()
        .filter(|start| *start >= from)
        .collect();
    // Occurrence starts come back in ascending order.
    let key = *occurrences.first()?;
    Some(Candidate {
        key,
        event,
        occurrences,
    })
}
