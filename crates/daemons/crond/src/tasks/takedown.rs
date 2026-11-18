//! Take It Down request upkeep (plan §4.1, §4.4, §4.6; D3, D4, D7).
//!
//! Every minute, while `features.takedown.active()`:
//! 1. resolves submitted links into Sloga objects, off the request path;
//! 2. links open requests that name the same file or message, and runs the
//!    later one's clock from the earliest;
//! 3. alerts reviewers (email, plus the webhook when set) at arrival, 12 hours
//!    unopened, 24, 12 and 4 hours before the deadline, and once overdue;
//! 4. hides, restorably, the plain attachments an unreviewed request links
//!    directly, `auto_hide_hour` hours into its clock (D4), never for a
//!    contact with a bad-faith request on record;
//! 5. records whether each request that left review met its deadline;
//! 6. ends expired holds, so the file deletion task can purge the objects,
//!    and closes a request that ended without being closed;
//! 7. purges requester details `retention_requester_days` after the request
//!    ended (closed, or removed and never closed);
//! 8. alerts reviewers once per clock hour when more than
//!    `VOLUME_ALARM_THRESHOLD` requests arrived in the last hour;
//! 9. sends a weekly "alerting works" heartbeat.
//!
//! crond has no leader election. Each once-only side effect is claimed first
//! with `claim_takedown_marker` (atomic in the database), and every write goes
//! through the request's revision check, so several crond instances never act
//! twice. Auto-hide and hold release, the steps that change file state, also
//! run only while holding the takedown mutex (`removal::try_takedown_mutex`,
//! shared with delta's reviewer actions); when it is busy or Redis is down
//! they are skipped for the tick. Nothing here emails a requester or an
//! uploader.
//!
//! Logs carry ids, counts and error kinds only: never sealed data, email
//! addresses, the webhook URL, locations or reviewer notes.
//!
//! The config is frozen into the process at first access: changing
//! `[features.takedown]` takes a crond restart.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    time::Duration,
};

use iso8601_timestamp::{Duration as Span, Timestamp};
use log::{error, info, warn};
use redis_kiss::{
    get_connection,
    redis::{ExistenceCheck, SetExpiry, SetOptions},
    AsyncCommands,
};
use revolt_config::{capture_error, FeaturesTakedown};
use revolt_database::{
    removal::{still_shown, try_takedown_mutex, TakedownMutexGuard},
    resolve_locations,
    util::{
        email::{email_templates, send_email_safe},
        takedown_crypto::reference_for,
    },
    Database, File, FileUsedForType, HeldFile, StaffAuditAction, StaffAuditEntry, TakedownRequest,
    TakedownStatus, TakedownTarget, UnresolvableKind, AMQP,
};
use revolt_result::{create_error, ErrorType, Result, ToRevoltError};
use tokio::time::sleep;

const TICK: Duration = Duration::from_secs(60);

/// Revision-checked write attempts (each on a fresh read) before the change
/// is left to the next tick
const WRITE_ATTEMPTS: usize = 3;

/// Markers spent while every link of a request resolves to "not found" (a
/// failed lookup reads the same), so resolution runs three times in all
/// before it settles on that answer
const RESOLVE_RETRIES: [&str; 2] = ["resolve:try1", "resolve:try2"];

const MARK_AUTOHIDE: &str = "autohide";
const MARK_DEADLINE_MET: &str = "deadline:met";
const MARK_DEADLINE_MISSED: &str = "deadline:missed";

/// Hours from receipt to the removal deadline
const DEADLINE_HOURS: i64 = 48;

/// Bound on configured hours and days, so the arithmetic stays in range
const MAX_CONFIG_DAYS: u64 = 3650;

const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);

/// Lifetime of a week's heartbeat claim: longer than the week it names
const HEARTBEAT_TTL_SECS: usize = 14 * 24 * 3600;

/// Requests received in the last hour above which reviewers get a volume
/// alert. A constant: `[features.takedown]` has no field for it.
const VOLUME_ALARM_THRESHOLD: usize = 20;

/// Fixed text of the volume alert; never requester data
const VOLUME_SUMMARY: &str = "VOLUME: many requests in the last hour";

/// Lifetime of an hour's volume claim: longer than the hour it names
const VOLUME_TTL_SECS: usize = 2 * 3600;

/// Run the upkeep once a minute while the feature is active.
pub async fn task(db: Database, _: AMQP) -> Result<()> {
    let notifier = Notifier::live();

    loop {
        let cfg = (*revolt_config::config().await.features.takedown).clone();
        if cfg.active() {
            let now = Timestamp::now_utc();
            tick(&db, &cfg, &notifier, now, &take_redis_mutex).await;
            let volume = volume_alarm(&db, &cfg, &notifier, now, |key| async move {
                claim(&key, VOLUME_TTL_SECS).await
            })
            .await;
            if let Err(err) = volume {
                warn!(
                    "Take It Down volume alarm skipped this tick: {:?}",
                    err.error_type
                );
            }
            heartbeat(&db, &cfg, &notifier, now).await;
        }

        sleep(TICK).await;
    }
}

/// One pass over every step. A failed step is logged and retried next tick;
/// it never stops the steps after it.
///
/// The two steps that change file state or save file bookkeeping (auto-hide
/// and hold release) take the takedown mutex that delta's reviewer actions
/// also take, once per request, around just that request's work; `take`
/// supplies it (Redis in the task, a fake in tests). The other steps never
/// touch files and run regardless.
async fn tick<Take, TakeFut>(
    db: &Database,
    cfg: &FeaturesTakedown,
    notifier: &Notifier,
    now: Timestamp,
    take: &Take,
) where
    Take: Fn() -> TakeFut,
    TakeFut: Future<Output = Result<Option<StepLock>>>,
{
    log_step("resolved", resolve_pending(db).await);
    log_step("merged", merge_duplicates(db).await);
    log_step("alerted", run_alerts(db, cfg, notifier, now).await);
    log_step("auto-hidden", auto_hide(db, cfg, now, take).await);
    log_step("deadline recorded", record_deadlines(db, now).await);
    log_step("hold released", release_holds(db, now, take).await);
    log_step("requester purged", purge_requesters(db, cfg, now).await);
}

/// A hold on the takedown mutex for one request's work
enum StepLock {
    Held(TakedownMutexGuard),
    /// For tests: can be made to report the hold lost, counts releases
    #[cfg(test)]
    Fake(std::sync::Arc<FakeLock>),
}

/// Test stand-in for the Redis mutex
#[cfg(test)]
#[derive(Default)]
struct FakeLock {
    /// `Some(n)`: `is_held` answers true `n` times, then false
    held_checks: Option<usize>,
    checks: std::sync::atomic::AtomicUsize,
    released: std::sync::atomic::AtomicUsize,
}

impl StepLock {
    /// Whether the mutex is still ours. Checked before every file-state
    /// write and every request save that moves work forward; once false,
    /// the request's work stops.
    fn is_held(&self) -> bool {
        match self {
            StepLock::Held(guard) => guard.is_held(),
            #[cfg(test)]
            StepLock::Fake(fake) => {
                let seen = fake
                    .checks
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                fake.held_checks.is_none_or(|limit| seen < limit)
            }
        }
    }

    async fn release(self) {
        match self {
            StepLock::Held(guard) => guard.release().await,
            #[cfg(test)]
            StepLock::Fake(fake) => {
                fake.released
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }
}

/// The takedown mutex in Redis, without waiting: `Ok(None)` when busy
async fn take_redis_mutex() -> Result<Option<StepLock>> {
    Ok(try_takedown_mutex().await?.map(StepLock::Held))
}

/// Requests a step skipped this tick because the mutex was busy or Redis
/// was down; logged once per step, without ids
#[derive(Default)]
struct Skipped {
    busy: usize,
    unavailable: usize,
}

impl Skipped {
    fn log(&self, step: &str) {
        if self.busy > 0 {
            info!(
                "Take It Down {step}: {} request(s) skipped this tick, the takedown mutex is busy",
                self.busy
            );
        }
        if self.unavailable > 0 {
            warn!(
                "Take It Down {step}: {} request(s) skipped this tick, the takedown mutex is unavailable",
                self.unavailable
            );
        }
    }
}

/// Take the mutex for one request without waiting; `None` (counted in
/// `skipped`) when busy or unavailable, so that request is left as it is
async fn lock_request<Take, TakeFut>(take: &Take, skipped: &mut Skipped) -> Option<StepLock>
where
    Take: Fn() -> TakeFut,
    TakeFut: Future<Output = Result<Option<StepLock>>>,
{
    match take().await {
        Ok(Some(lock)) => Some(lock),
        Ok(None) => {
            skipped.busy += 1;
            None
        }
        Err(_) => {
            skipped.unavailable += 1;
            None
        }
    }
}

/// The mutex was lost partway through a request; logged without ids
fn log_lost(step: &str) {
    warn!("Take It Down {step}: the takedown mutex was lost mid-request; stopped it, files left hidden");
}

fn log_step(step: &str, result: Result<usize>) {
    match result {
        Ok(0) => {}
        Ok(count) => info!("Take It Down: {count} request(s) {step}"),
        Err(err) => {
            error!(
                "Take It Down step ({step}) failed, retrying next tick: {:?}",
                err.error_type
            );
            capture_error(&err);
        }
    }
}

fn config_hours(hours: u64) -> Span {
    Span::hours(hours.min(MAX_CONFIG_DAYS * 24) as i64)
}

fn config_days(days: u64) -> Span {
    Span::days(days.min(MAX_CONFIG_DAYS) as i64)
}

fn has_marker(request: &TakedownRequest, marker: &str) -> bool {
    request.markers.iter().any(|existing| existing == marker)
}

/// Object ids of the resolved targets, for `staff_audit`
fn target_ids(targets: &[TakedownTarget]) -> Vec<String> {
    targets
        .iter()
        .filter_map(|target| match target {
            TakedownTarget::Message { message, .. } => Some(message.clone()),
            TakedownTarget::File { file } => Some(file.clone()),
            TakedownTarget::User { user } => Some(user.clone()),
            TakedownTarget::Server { server } => Some(server.clone()),
            TakedownTarget::Emoji { emoji } => Some(emoji.clone()),
            TakedownTarget::Unresolvable { .. } => None,
        })
        .collect()
}

/// Outcome of [`update_request`]
enum Write {
    /// Stored; the request as written
    Done(TakedownRequest),
    /// `apply` found nothing to change on the fresh copy
    Unchanged,
    /// Every attempt lost the revision race; try again next tick
    Contended,
}

/// Read the request, let `apply` change it, and store it under the revision
/// check. A lost race re-reads and re-applies, at most `WRITE_ATTEMPTS`
/// times. `apply` returns false when the fresh copy needs no change.
async fn update_request<F>(db: &Database, id: &str, mut apply: F) -> Result<Write>
where
    F: FnMut(&mut TakedownRequest) -> bool + Send,
{
    for _ in 0..WRITE_ATTEMPTS {
        let mut request = db.fetch_takedown_request(id).await?;
        if !apply(&mut request) {
            return Ok(Write::Unchanged);
        }

        match db.replace_takedown_request(&mut request).await {
            Ok(()) => return Ok(Write::Done(request)),
            Err(err) if matches!(err.error_type, ErrorType::InvalidOperation) => {}
            Err(err) => return Err(err),
        }
    }

    Ok(Write::Contended)
}

// 1. Resolution

/// Resolve the links of every open request not resolved yet. Returns how
/// many requests got their targets.
async fn resolve_pending(db: &Database) -> Result<usize> {
    let mut resolved = 0;
    for request in db.fetch_open_takedown_requests().await? {
        if request.resolved {
            continue;
        }

        match resolve_request(db, &request).await {
            Ok(true) => resolved += 1,
            Ok(false) => {}
            Err(err) => warn!(
                "Take It Down {}: resolution failed: {:?}",
                request.id, err.error_type
            ),
        }
    }

    Ok(resolved)
}

fn all_not_found(targets: &[TakedownTarget]) -> bool {
    !targets.is_empty()
        && targets.iter().all(|target| {
            matches!(
                target,
                TakedownTarget::Unresolvable {
                    kind: UnresolvableKind::NotFound,
                    ..
                }
            )
        })
}

/// Resolve one request's links and store the targets. Returns whether they
/// were stored.
///
/// Sends no email: what the requester hears about links Sloga can't act on
/// (a private conversation included) is a reviewer's decision.
async fn resolve_request(db: &Database, request: &TakedownRequest) -> Result<bool> {
    let locations = request.locations.clone();
    let targets = resolve_locations(db, &locations).await;

    if all_not_found(&targets) {
        if let Some(retry) = RESOLVE_RETRIES
            .iter()
            .find(|marker| !has_marker(request, marker))
        {
            // Try again next tick. A claim lost to another instance means
            // this attempt is already counted.
            db.claim_takedown_marker(&request.id, retry).await?;
            return Ok(false);
        }
    }

    let write = update_request(db, &request.id, |fresh| {
        // Links added since this resolution started are resolved next tick
        if fresh.resolved || fresh.locations != locations {
            return false;
        }

        fresh.targets = targets.clone();
        fresh.resolved = true;
        true
    })
    .await?;

    match write {
        Write::Done(stored) => {
            StaffAuditEntry::record(
                db,
                None,
                StaffAuditAction::TakedownResolved,
                Some(&stored.id),
                target_ids(&stored.targets),
                Some(stored.targets.len() as u64),
                None,
            )
            .await;
            Ok(true)
        }
        Write::Unchanged => Ok(false),
        Write::Contended => {
            warn!("Take It Down {}: resolution write contended", request.id);
            Ok(false)
        }
    }
}

// 2. Merging

/// One request's side of a merge
struct MergePlan {
    id: String,
    /// Requests to link that are not linked yet
    link: Vec<String>,
    /// Earliest deadline in the group
    deadline: Timestamp,
    /// Object ids this request shares with the group
    shared: Vec<String>,
}

/// What two requests can be merged on: the files and messages they name.
/// Never users, servers or anything unresolvable.
fn merge_keys(request: &TakedownRequest) -> Vec<String> {
    let mut keys = Vec::new();
    for target in &request.targets {
        let key = match target {
            TakedownTarget::File { file } => format!("file:{file}"),
            TakedownTarget::Message { message, .. } => format!("message:{message}"),
            _ => continue,
        };

        if !keys.contains(&key) {
            keys.push(key);
        }
    }

    keys
}

fn key_object_id(key: &str) -> String {
    key.split_once(':').map_or(key, |(_, id)| id).to_string()
}

/// Group requests that share a key (directly or through each other) and
/// plan, per request, the links it lacks and the group's earliest deadline.
/// `keys[i]` belongs to `requests[i]`. Requests needing no change get no plan.
fn plan_merges(requests: &[TakedownRequest], keys: &[Vec<String>]) -> Vec<MergePlan> {
    fn root(parent: &mut [usize], mut index: usize) -> usize {
        while parent[index] != index {
            parent[index] = parent[parent[index]];
            index = parent[index];
        }
        index
    }

    let mut parent: Vec<usize> = (0..requests.len()).collect();
    let mut first_holder: HashMap<&str, usize> = HashMap::new();
    for (index, request_keys) in keys.iter().enumerate() {
        for key in request_keys {
            match first_holder.get(key.as_str()) {
                Some(&holder) => {
                    let a = root(&mut parent, index);
                    let b = root(&mut parent, holder);
                    if a != b {
                        parent[a] = b;
                    }
                }
                None => {
                    first_holder.insert(key.as_str(), index);
                }
            }
        }
    }

    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for index in 0..requests.len() {
        let group = root(&mut parent, index);
        groups.entry(group).or_default().push(index);
    }

    let mut plans = Vec::new();
    for members in groups.values().filter(|members| members.len() > 1) {
        let Some(deadline) = members.iter().map(|&i| requests[i].deadline_at).min() else {
            continue;
        };

        let mut holders: HashMap<&str, usize> = HashMap::new();
        for &i in members {
            for key in &keys[i] {
                *holders.entry(key.as_str()).or_default() += 1;
            }
        }

        for &i in members {
            let request = &requests[i];
            let link: Vec<String> = members
                .iter()
                .filter(|&&j| j != i)
                .map(|&j| requests[j].id.clone())
                .filter(|id| !request.linked_request_ids.contains(id))
                .collect();

            if link.is_empty() && deadline >= request.deadline_at {
                continue;
            }

            let shared = keys[i]
                .iter()
                .filter(|key| holders.get(key.as_str()).is_some_and(|&n| n > 1))
                .map(|key| key_object_id(key))
                .collect();

            plans.push(MergePlan {
                id: request.id.clone(),
                link,
                deadline,
                shared,
            });
        }
    }

    plans.sort_by(|a, b| a.id.cmp(&b.id));
    plans
}

/// Link open, resolved requests naming the same file or message, and give
/// each the earliest deadline among them. Returns how many requests changed.
async fn merge_duplicates(db: &Database) -> Result<usize> {
    let open: Vec<TakedownRequest> = db
        .fetch_open_takedown_requests()
        .await?
        .into_iter()
        .filter(|request| request.resolved)
        .collect();
    if open.len() < 2 {
        return Ok(0);
    }

    let mut keys: Vec<Vec<String>> = open.iter().map(merge_keys).collect();

    // A shared message counts only while its row exists and is readable: an
    // encrypted message id can be one device's own copy
    let mut holders: HashMap<String, usize> = HashMap::new();
    for key in keys.iter().flatten() {
        *holders.entry(key.clone()).or_default() += 1;
    }
    let mut unusable = HashSet::new();
    for (key, count) in &holders {
        let Some(message) = key.strip_prefix("message:") else {
            continue;
        };
        if *count < 2 {
            continue;
        }
        if !matches!(db.fetch_message(message).await, Ok(row) if row.encrypted.is_none()) {
            unusable.insert(key.clone());
        }
    }
    for request_keys in &mut keys {
        request_keys.retain(|key| !unusable.contains(key));
    }

    let mut merged = 0;
    for plan in plan_merges(&open, &keys) {
        let write = update_request(db, &plan.id, |fresh| {
            if !fresh.status.is_open() {
                return false;
            }

            let mut changed = false;
            for id in &plan.link {
                if *id != fresh.id && !fresh.linked_request_ids.contains(id) {
                    fresh.linked_request_ids.push(id.clone());
                    changed = true;
                }
            }
            if plan.deadline < fresh.deadline_at {
                fresh.deadline_at = plan.deadline;
                changed = true;
            }
            changed
        })
        .await;

        match write {
            Ok(Write::Done(_)) => {
                StaffAuditEntry::record(
                    db,
                    None,
                    StaffAuditAction::TakedownMerged,
                    Some(&plan.id),
                    plan.shared.clone(),
                    Some(plan.link.len() as u64),
                    None,
                )
                .await;
                merged += 1;
            }
            Ok(Write::Unchanged) => {}
            Ok(Write::Contended) => warn!("Take It Down {}: merge write contended", plan.id),
            Err(err) => warn!(
                "Take It Down {}: merge failed: {:?}",
                plan.id, err.error_type
            ),
        }
    }

    Ok(merged)
}

// 3. Alerts

/// One step of the reviewer alert ladder (D3)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rung {
    Overdue,
    FourHoursLeft,
    TwelveHoursLeft,
    DayLeft,
    Unopened,
    New,
}

/// Most urgent first
const LADDER: [Rung; 6] = [
    Rung::Overdue,
    Rung::FourHoursLeft,
    Rung::TwelveHoursLeft,
    Rung::DayLeft,
    Rung::Unopened,
    Rung::New,
];

impl Rung {
    fn marker(self) -> &'static str {
        match self {
            Rung::Overdue => "alert:overdue",
            Rung::FourHoursLeft => "alert:44h",
            Rung::TwelveHoursLeft => "alert:36h",
            Rung::DayLeft => "alert:24h",
            Rung::Unopened => "alert:12h",
            Rung::New => "alert:new",
        }
    }

    /// Fixed text for the alert; never anything a requester wrote
    fn summary(self) -> &'static str {
        match self {
            Rung::Overdue => "OVERDUE",
            Rung::FourHoursLeft => "4 hours left",
            Rung::TwelveHoursLeft => "12 hours left",
            Rung::DayLeft => "24 hours left",
            Rung::Unopened => "not opened after 12 hours",
            Rung::New => "new request",
        }
    }

    /// The deadline rungs count back from `deadline_at`, which for a request
    /// that was never merged is 24, 36 and 44 hours after receipt
    fn is_due(self, request: &TakedownRequest, now: Timestamp) -> bool {
        let hours_left = |hours: i64| now >= request.deadline_at.saturating_sub(Span::hours(hours));
        match self {
            Rung::Overdue => now > request.deadline_at,
            Rung::FourHoursLeft => hours_left(4),
            Rung::TwelveHoursLeft => hours_left(12),
            Rung::DayLeft => hours_left(24),
            Rung::Unopened => {
                request.first_opened_at.is_none()
                    && now >= request.received_at.saturating_add(Span::hours(12))
            }
            Rung::New => true,
        }
    }
}

/// Rungs due at `now` and not sent yet, most urgent first
fn due_rungs(request: &TakedownRequest, now: Timestamp) -> Vec<Rung> {
    if !request.status.is_open() {
        return Vec::new();
    }

    LADDER
        .into_iter()
        .filter(|rung| rung.is_due(request, now) && !has_marker(request, rung.marker()))
        .collect()
}

fn alert_summary(rung: Rung, request: &TakedownRequest) -> String {
    if request.minor_claimed {
        format!("{}, child-safety priority", rung.summary())
    } else {
        rung.summary().to_string()
    }
}

/// Send each open request's most urgent due alert, once. Returns how many
/// alerts were sent.
async fn run_alerts(
    db: &Database,
    cfg: &FeaturesTakedown,
    notifier: &Notifier,
    now: Timestamp,
) -> Result<usize> {
    let mut sent = 0;
    for request in db.fetch_open_takedown_requests().await? {
        match alert_request(db, cfg, notifier, &request, now).await {
            Ok(true) => sent += 1,
            Ok(false) => {}
            Err(err) => warn!(
                "Take It Down {}: alert failed: {:?}",
                request.id, err.error_type
            ),
        }
    }

    Ok(sent)
}

/// Send the most urgent alert due for `request` (as this copy of it reads)
/// if this caller wins its marker; another instance holding the same copy
/// loses the claim and sends nothing. Less urgent rungs due at the same time
/// are marked done without a message of their own. Returns whether this
/// call sent an alert.
async fn alert_request(
    db: &Database,
    cfg: &FeaturesTakedown,
    notifier: &Notifier,
    request: &TakedownRequest,
    now: Timestamp,
) -> Result<bool> {
    let due = due_rungs(request, now);
    let Some((&rung, superseded)) = due.split_first() else {
        return Ok(false);
    };

    let won = db.claim_takedown_marker(&request.id, rung.marker()).await?;
    if won {
        let delivered = notifier
            .alert(
                cfg,
                &reference_for(&request.id),
                &alert_summary(rung, request),
                &request.deadline_at.to_string(),
            )
            .await;
        if delivered == 0 {
            warn!(
                "Take It Down {}: {} reached no alert channel",
                request.id,
                rung.marker()
            );
        }

        StaffAuditEntry::record(
            db,
            None,
            StaffAuditAction::TakedownAlertSent,
            Some(&request.id),
            Vec::new(),
            Some(delivered),
            Some(rung.marker()),
        )
        .await;
    }

    for rung in superseded {
        if let Err(err) = db.claim_takedown_marker(&request.id, rung.marker()).await {
            warn!(
                "Take It Down {}: could not claim {}: {:?}",
                request.id,
                rung.marker(),
                err.error_type
            );
        }
    }

    Ok(won)
}

// 4. Auto-hide (D4)

/// When the request's 48 hours started: its own receipt, or the earliest
/// linked request's after a merge
fn clock_start(request: &TakedownRequest) -> Timestamp {
    request.received_at.min(
        request
            .deadline_at
            .saturating_sub(Span::hours(DEADLINE_HOURS)),
    )
}

/// No reviewer has acted (Received or UnderReview; NeedsInfo means one has)
fn unreviewed(request: &TakedownRequest) -> bool {
    matches!(
        request.status,
        TakedownStatus::Received | TakedownStatus::UnderReview
    )
}

/// Whether `request` is due for its auto-hide at `now`: unreviewed,
/// resolved, not throttled, bad faith or child safety, `hour` into its
/// clock, and not tried before
fn auto_hide_due(request: &TakedownRequest, hour: Span, now: Timestamp) -> bool {
    unreviewed(request)
        && request.resolved
        && !request.throttled
        && !request.bad_faith
        && !request.child_safety
        && !has_marker(request, MARK_AUTOHIDE)
        && now >= clock_start(request).saturating_add(hour)
}

/// A normal Sloga attachment that is still served: tag `attachments`, not
/// deleted, and either not attached yet or attached to a message that is
/// not a protected-channel (encrypted) row
async fn is_plain_attachment(db: &Database, file: &File) -> bool {
    if file.tag != "attachments" || file.deleted == Some(true) {
        return false;
    }

    match &file.used_for {
        None => true,
        Some(used_for) if matches!(used_for.object_type, FileUsedForType::Message) => {
            matches!(db.fetch_message(&used_for.id).await, Ok(row) if row.encrypted.is_none())
        }
        Some(_) => false,
    }
}

/// The plain attachments `request` names directly: linked files, and the
/// attachments of linked messages that are not encrypted rows. Files this
/// request already holds are left out.
async fn hideable_files(db: &Database, request: &TakedownRequest) -> Vec<File> {
    let mut ids: Vec<String> = Vec::new();
    for target in &request.targets {
        match target {
            TakedownTarget::File { file } => ids.push(file.clone()),
            TakedownTarget::Message { message, .. } => {
                if let Ok(row) = db.fetch_message(message).await {
                    if row.encrypted.is_none() {
                        ids.extend(
                            row.attachments
                                .unwrap_or_default()
                                .into_iter()
                                .map(|file| file.id),
                        );
                    }
                }
            }
            _ => {}
        }
    }

    let mut files: Vec<File> = Vec::new();
    for id in ids {
        if files.iter().any(|file| file.id == id)
            || request.held_files.iter().any(|held| held.id == id)
        {
            continue;
        }

        let Ok(file) = db.fetch_attachment_by_id(&id).await else {
            continue;
        };
        if is_plain_attachment(db, &file).await {
            files.push(file);
        }
    }

    files
}

/// What the contact's request history allows
struct ContactHistory {
    /// Any request from this contact, ever, was declined as bad faith
    bad_faith: bool,
    /// Other requests from this contact received since `since` that spent
    /// their auto-hide
    hides: u64,
}

async fn contact_history(
    db: &Database,
    request: &TakedownRequest,
    since: Timestamp,
) -> Result<ContactHistory> {
    let history = db
        .fetch_takedown_requests_by_contact_since(&request.contact_fp, Timestamp::UNIX_EPOCH)
        .await?;

    Ok(ContactHistory {
        bad_faith: history.iter().any(|other| other.bad_faith),
        hides: history
            .iter()
            .filter(|other| {
                other.id != request.id
                    && other.received_at >= since
                    && has_marker(other, MARK_AUTOHIDE)
            })
            .count() as u64,
    })
}

/// Whether the contact may auto-hide one more: no bad-faith request ever,
/// and under the daily cap
async fn contact_may_hide(
    db: &Database,
    cfg: &FeaturesTakedown,
    request: &TakedownRequest,
    since: Timestamp,
) -> Result<bool> {
    let history = contact_history(db, request, since).await?;
    Ok(!history.bad_faith && history.hides < cfg.auto_hide_daily_cap)
}

/// What [`undo_raced_hides`] found and did
#[derive(Default)]
struct RaceUndo {
    /// Hidden files the request no longer tracks as auto-hidden
    dropped: Vec<String>,
    /// Of those, the ones shown again
    shown: Vec<String>,
}

/// After a hide: undo it on any file the request no longer tracks as
/// auto-hidden (a reviewer's decline or unhide raced in between the record
/// and the hide).
///
/// A file still held by any request, this one included, stays hidden. Any
/// other is shown again only while its parent still shows it
/// ([`show_again`]); one whose parent is gone (the uploader deleted the
/// message, say) stays deleted. Either way `reported` is cleared only if it
/// was not reported before, no open report needs it and its parent lookup
/// did not fail; otherwise it stays set (kept, never lost).
///
/// Each write first checks the mutex is still `lock`'s; if not, it stops
/// with the files hidden and `reported` set.
async fn undo_raced_hides(
    db: &Database,
    id: &str,
    held: &[HeldFile],
    lock: &StepLock,
) -> Result<RaceUndo> {
    let fresh = db.fetch_takedown_request(id).await?;
    let gone: Vec<&HeldFile> = held
        .iter()
        .filter(|file| !fresh.auto_hidden_file_ids.contains(&file.id))
        .collect();
    if gone.is_empty() {
        return Ok(RaceUndo::default());
    }
    let dropped: Vec<String> = gone.iter().map(|file| file.id.clone()).collect();

    let requests = db
        .fetch_recent_takedown_requests(Timestamp::UNIX_EPOCH)
        .await?;
    let still_held: HashSet<&str> = requests
        .iter()
        .flat_map(|request| request.held_files.iter().map(|file| file.id.as_str()))
        .collect();

    let undo: Vec<&HeldFile> = gone
        .into_iter()
        .filter(|file| !file.was_deleted && !still_held.contains(file.id.as_str()))
        .collect();
    if undo.is_empty() {
        return Ok(RaceUndo {
            dropped,
            shown: Vec::new(),
        });
    }

    let undo_ids: Vec<String> = undo.iter().map(|file| file.id.clone()).collect();
    let outcome = match show_again(db, &undo_ids, lock).await {
        Ok(Some(outcome)) => outcome,
        // Lost before the unhide: nothing changed, the files stay hidden
        Ok(None) => {
            log_lost("auto-hide");
            return Ok(RaceUndo {
                dropped,
                shown: Vec::new(),
            });
        }
        Err(err) => {
            // The unhide may have gone through before the failure: hide
            // them all again rather than leave an unchecked file served
            if let Err(hide_err) = db.hide_attachments(&undo_ids).await {
                error!(
                    "Take It Down {id}: {} raced file(s) in an unknown state: {:?}",
                    undo_ids.len(),
                    hide_err.error_type
                );
            }
            return Err(err);
        }
    };

    // Lost before clearing `reported`: leave it set (kept, never lost)
    if !lock.is_held() {
        log_lost("auto-hide");
        return Ok(RaceUndo {
            dropped,
            shown: outcome.shown,
        });
    }

    match db.fetch_open_report_file_ids().await {
        Ok(reported) => {
            let release: Vec<String> = undo
                .iter()
                .filter(|file| {
                    !file.was_reported
                        && !reported.contains(&file.id)
                        && !outcome.unsure.contains(&file.id)
                })
                .map(|file| file.id.clone())
                .collect();
            db.release_attachment_hold(&release).await?;
        }
        Err(err) => warn!(
            "Take It Down {id}: open reports unreadable, {} raced file(s) stay reported: {:?}",
            undo_ids.len(),
            err.error_type
        ),
    }

    Ok(RaceUndo {
        dropped,
        shown: outcome.shown,
    })
}

/// Auto-hide every due request's directly linked attachments, each request
/// under its own hold on the takedown mutex (busy or unavailable: that
/// request waits for the next tick). Returns how many requests hid
/// something.
async fn auto_hide<Take, TakeFut>(
    db: &Database,
    cfg: &FeaturesTakedown,
    now: Timestamp,
    take: &Take,
) -> Result<usize>
where
    Take: Fn() -> TakeFut,
    TakeFut: Future<Output = Result<Option<StepLock>>>,
{
    if cfg.auto_hide_hour == 0 {
        return Ok(0);
    }

    let hour = config_hours(cfg.auto_hide_hour);
    let mut hidden = 0;
    let mut skipped = Skipped::default();
    for request in db.fetch_open_takedown_requests().await? {
        // Cheap filters first, so the mutex is taken only when there is
        // something to hide (re-read under it)
        if !auto_hide_due(&request, hour, now) || hideable_files(db, &request).await.is_empty() {
            continue;
        }

        let Some(lock) = lock_request(take, &mut skipped).await else {
            continue;
        };
        let result = auto_hide_request(db, cfg, &request, hour, now, &lock).await;
        lock.release().await;

        match result {
            Ok(true) => hidden += 1,
            Ok(false) => {}
            Err(err) => warn!(
                "Take It Down {}: auto-hide failed: {:?}",
                request.id, err.error_type
            ),
        }
    }

    skipped.log("auto-hide");
    Ok(hidden)
}

/// Hide one request's plain attachments in the hidden-but-kept state. No
/// uploader email, and no removal: a reviewer decides that.
///
/// Runs holding `lock`, and checks it is still held before spending the
/// marker, before saving the record, before the hide and before the race
/// check. Lost before the hide: nothing is hidden (a recorded file that is
/// not hidden is harmless). Lost after it: the files stay hidden and
/// recorded.
async fn auto_hide_request(
    db: &Database,
    cfg: &FeaturesTakedown,
    request: &TakedownRequest,
    hour: Span,
    now: Timestamp,
    lock: &StepLock,
) -> Result<bool> {
    let files = hideable_files(db, request).await;
    if files.is_empty() {
        return Ok(false);
    }

    // Never for a contact with a bad-faith request on record, and at most
    // `auto_hide_daily_cap` hides per contact address per day. A hide
    // happens `hour` into a request's clock, so the day's hides belong to
    // requests received within the last `hour` + 24 hours.
    let since = now.saturating_sub(hour).saturating_sub(Span::hours(24));
    if !contact_may_hide(db, cfg, request, since).await? {
        return Ok(false);
    }

    if !lock.is_held() {
        log_lost("auto-hide");
        return Ok(false);
    }
    if !db.claim_takedown_marker(&request.id, MARK_AUTOHIDE).await? {
        return Ok(false);
    }

    // Another instance may have claimed one for the same address meanwhile.
    // This claim stays spent, so a race can only lower the address's hides.
    if !contact_may_hide(db, cfg, request, since).await? {
        info!(
            "Take It Down {}: auto-hide skipped after the claim",
            request.id
        );
        return Ok(false);
    }

    let held: Vec<HeldFile> = files
        .iter()
        .map(|file| HeldFile {
            id: file.id.clone(),
            was_deleted: file.deleted == Some(true),
            was_reported: file.reported == Some(true),
        })
        .collect();
    let ids: Vec<String> = held.iter().map(|file| file.id.clone()).collect();

    if !lock.is_held() {
        log_lost("auto-hide");
        return Ok(false);
    }

    // Recorded before hiding: a recorded file that then failed to hide is
    // harmless to unhide or release, while a hidden file no request records
    // would never be released
    let write = update_request(db, &request.id, |fresh| {
        if !unreviewed(fresh) || fresh.throttled || fresh.bad_faith || fresh.child_safety {
            return false;
        }

        for file in &held {
            if !fresh
                .held_files
                .iter()
                .any(|existing| existing.id == file.id)
            {
                fresh.held_files.push(file.clone());
            }
            if !fresh.auto_hidden_file_ids.contains(&file.id) {
                fresh.auto_hidden_file_ids.push(file.id.clone());
            }
        }
        true
    })
    .await?;

    match write {
        Write::Done(_) => {}
        Write::Unchanged => {
            info!(
                "Take It Down {}: auto-hide dropped, reviewed meanwhile",
                request.id
            );
            return Ok(false);
        }
        Write::Contended => {
            warn!(
                "Take It Down {}: auto-hide dropped, write contended",
                request.id
            );
            return Ok(false);
        }
    }

    if !lock.is_held() {
        log_lost("auto-hide");
        return Ok(false);
    }

    if let Err(err) = db.hide_attachments(&ids).await {
        error!(
            "Take It Down {}: {} file(s) recorded as auto-hidden but not hidden: {:?}",
            request.id,
            ids.len(),
            err.error_type
        );
        capture_error(&err);
        return Err(err);
    }

    // A decline (or unhide) that landed between the record and the hide has
    // already dropped the files from the request: put those back. Lost
    // here: the files stay hidden and recorded.
    let undone = if lock.is_held() {
        match undo_raced_hides(db, &request.id, &held, lock).await {
            Ok(undone) => undone,
            Err(err) => {
                error!(
                    "Take It Down {}: could not check the hide against the request: {:?}",
                    request.id, err.error_type
                );
                capture_error(&err);
                RaceUndo::default()
            }
        }
    } else {
        log_lost("auto-hide");
        RaceUndo::default()
    };
    if !undone.dropped.is_empty() {
        info!(
            "Take It Down {}: {} file(s) dropped by a review meanwhile, {} shown again",
            request.id,
            undone.dropped.len(),
            undone.shown.len()
        );
    }

    let hidden: Vec<String> = ids
        .into_iter()
        .filter(|id| !undone.dropped.contains(id))
        .collect();
    if hidden.is_empty() {
        return Ok(false);
    }

    StaffAuditEntry::record(
        db,
        None,
        StaffAuditAction::TakedownAutoHidden,
        Some(&request.id),
        hidden.clone(),
        Some(hidden.len() as u64),
        None,
    )
    .await;
    Ok(true)
}

// 5. Deadline bookkeeping

/// For a request that has left review and has no deadline marker yet: met
/// or missed, judged on `removed_at`, else `closed_at`, else `now`
fn deadline_outcome(
    request: &TakedownRequest,
    now: Timestamp,
) -> Option<(&'static str, StaffAuditAction)> {
    if request.status.is_open()
        || has_marker(request, MARK_DEADLINE_MET)
        || has_marker(request, MARK_DEADLINE_MISSED)
    {
        return None;
    }

    let acted_at = request.removed_at.or(request.closed_at).unwrap_or(now);
    Some(if acted_at <= request.deadline_at {
        (MARK_DEADLINE_MET, StaffAuditAction::TakedownDeadlineMet)
    } else {
        (
            MARK_DEADLINE_MISSED,
            StaffAuditAction::TakedownDeadlineMissed,
        )
    })
}

/// Record, once, whether each request that left review met its deadline.
/// Returns how many were recorded.
async fn record_deadlines(db: &Database, now: Timestamp) -> Result<usize> {
    let mut recorded = 0;
    for request in db
        .fetch_recent_takedown_requests(Timestamp::UNIX_EPOCH)
        .await?
    {
        let Some((marker, action)) = deadline_outcome(&request, now) else {
            continue;
        };

        match db.claim_takedown_marker(&request.id, marker).await {
            Ok(true) => {
                StaffAuditEntry::record(
                    db,
                    None,
                    action,
                    Some(&request.id),
                    Vec::new(),
                    None,
                    None,
                )
                .await;
                recorded += 1;
            }
            Ok(false) => {}
            Err(err) => warn!(
                "Take It Down {}: could not claim {marker}: {:?}",
                request.id, err.error_type
            ),
        }
    }

    Ok(recorded)
}

// 6. Hold release

/// End every hold that is due, each request under its own hold on the
/// takedown mutex (busy or unavailable: that request waits for the next
/// tick). Skips the whole step when the open report files can't be read.
/// Returns how many requests were released.
async fn release_holds<Take, TakeFut>(db: &Database, now: Timestamp, take: &Take) -> Result<usize>
where
    Take: Fn() -> TakeFut,
    TakeFut: Future<Output = Result<Option<StepLock>>>,
{
    let due = db.fetch_takedown_requests_hold_due(now).await?;
    if due.is_empty() {
        return Ok(0);
    }

    // Files an open report still needs; no answer means no release
    let reported = db.fetch_open_report_file_ids().await?;

    let mut released = 0;
    let mut skipped = Skipped::default();
    for request in due {
        let Some(lock) = lock_request(take, &mut skipped).await else {
            continue;
        };
        let result = release_hold(db, &request.id, &reported, now, &lock).await;
        lock.release().await;

        match result {
            Ok(true) => released += 1,
            Ok(false) => {}
            Err(err) => warn!(
                "Take It Down {}: hold release failed: {:?}",
                request.id, err.error_type
            ),
        }
    }

    skipped.log("hold release");
    Ok(released)
}

/// What ending one hold does to its files
struct ReleasePlan {
    /// Auto-hidden files (no reviewer removed them) that may be shown again;
    /// [`show_again`] decides
    unhide: Vec<String>,
    /// Auto-hidden files that stay hidden: deleted before the request held
    /// them, or held by another request
    keep_hidden: Vec<String>,
    /// Files whose `reported` flag is cleared
    release: Vec<String>,
}

/// Plan the end of a hold over `taken` (the request's held files) and
/// `taken_auto` (its auto-hidden ids).
///
/// - `release`: files not reported before the request held them, not in an
///   open report, and not held by any other request get `reported` cleared,
///   so a still-deleted one goes to the file deletion task.
/// - `unhide`: a file still auto-hidden at the end that was live before and
///   that no other request holds; it is shown again only while its parent
///   still shows it (checked in [`show_again`]).
/// - `keep_hidden`: every other auto-hidden file.
async fn plan_release(
    db: &Database,
    id: &str,
    taken: &[HeldFile],
    taken_auto: &[String],
    reported: &HashSet<String>,
) -> Result<ReleasePlan> {
    let others = db
        .fetch_recent_takedown_requests(Timestamp::UNIX_EPOCH)
        .await?;
    let covered: HashSet<&str> = others
        .iter()
        .filter(|other| other.id != id)
        .flat_map(|other| other.held_files.iter().map(|held| held.id.as_str()))
        .collect();

    let mut unhide = Vec::new();
    let mut keep_hidden = Vec::new();
    for held in taken.iter().filter(|held| taken_auto.contains(&held.id)) {
        if !held.was_deleted && !covered.contains(held.id.as_str()) {
            unhide.push(held.id.clone());
        } else {
            keep_hidden.push(held.id.clone());
        }
    }

    let release = taken
        .iter()
        .filter(|held| {
            !held.was_reported
                && !reported.contains(&held.id)
                && !covered.contains(held.id.as_str())
        })
        .map(|held| held.id.clone())
        .collect();

    Ok(ReleasePlan {
        unhide,
        keep_hidden,
        release,
    })
}

/// Outcome of [`show_again`]
#[derive(Default)]
struct ShowOutcome {
    /// Unhidden, and still shown after the unhide
    shown: Vec<String>,
    /// Not shown by their parent: hidden
    not_shown: Vec<String>,
    /// Their parent could not be checked: hidden, and `reported` must stay
    /// set
    unsure: Vec<String>,
}

/// Sort one file by `removal::still_shown` into `shown`, `out.not_shown` or
/// `out.unsure` (a failed lookup)
async fn sort_shown(db: &Database, id: String, shown: &mut Vec<String>, out: &mut ShowOutcome) {
    match still_shown(db, &id).await {
        Ok(true) => shown.push(id),
        Ok(false) => out.not_shown.push(id),
        Err(err) => {
            warn!(
                "Take It Down: file {id} kept hidden, its parent could not be checked: {:?}",
                err.error_type
            );
            out.unsure.push(id);
        }
    }
}

/// Show hidden files again only while their parent still shows them
/// (`removal::still_shown`: messages incl. forwarded snapshots, avatars,
/// backgrounds, icons, banners, emojis, stickers). Checked before the
/// unhide, and again after it, since a removal in flight can pull a file in
/// between: any that stopped being shown are hidden again. A failed lookup
/// counts as not shown. Every file not in `shown` ends hidden (`deleted` and
/// `reported` set).
///
/// `None`: the mutex was no longer `lock`'s before the unhide, so nothing
/// was changed. The hide after the unhide only ever hides, so it runs
/// whether or not the mutex is still held.
async fn show_again(db: &Database, ids: &[String], lock: &StepLock) -> Result<Option<ShowOutcome>> {
    let mut out = ShowOutcome::default();
    let mut candidates = Vec::new();
    for id in ids {
        sort_shown(db, id.clone(), &mut candidates, &mut out).await;
    }

    if !lock.is_held() {
        return Ok(None);
    }
    db.unhide_attachments(&candidates).await?;

    let mut shown = Vec::new();
    for id in candidates {
        sort_shown(db, id, &mut shown, &mut out).await;
    }
    out.shown = shown;

    let hide: Vec<String> = out.not_shown.iter().chain(&out.unsure).cloned().collect();
    db.hide_attachments(&hide).await?;
    Ok(Some(out))
}

/// What a carried-out release plan did
struct Applied {
    /// Shown again
    shown: Vec<String>,
    /// Kept hidden and reported because a lookup failed; they go back on the
    /// request for the next tick
    unsure: Vec<String>,
    /// `reported` cleared
    released: Vec<String>,
}

/// Carry out a release plan: hide what stays hidden, show again what is
/// still shown, then clear `reported` (never on an unsure file). Checks the
/// mutex is still `lock`'s before each of the three; `None` when it was
/// lost, after hiding again anything this call had shown, so every file of
/// the plan is left hidden and nothing was released.
async fn apply_release(
    db: &Database,
    plan: &ReleasePlan,
    lock: &StepLock,
) -> Result<Option<Applied>> {
    if !lock.is_held() {
        return Ok(None);
    }
    db.hide_attachments(&plan.keep_hidden).await?;

    let Some(outcome) = show_again(db, &plan.unhide, lock).await? else {
        return Ok(None);
    };

    if !lock.is_held() {
        db.hide_attachments(&outcome.shown).await?;
        return Ok(None);
    }

    let released: Vec<String> = plan
        .release
        .iter()
        .filter(|id| !outcome.unsure.contains(id))
        .cloned()
        .collect();
    db.release_attachment_hold(&released).await?;

    Ok(Some(Applied {
        shown: outcome.shown,
        unsure: outcome.unsure,
        released,
    }))
}

/// End one request's hold.
///
/// The files come off both lists first, under the request's revision check,
/// so a request that turned child-safety or whose hold moved keeps every
/// file. Only then are files hidden, shown again or released (see
/// [`plan_release`], [`show_again`]). If that fails, the files go back on
/// the request for the next tick; so do files whose parent lookup failed.
///
/// The mutex is checked before the files come off and before each file
/// write. Lost on the way: every file of the request is hidden again
/// (`deleted` and `reported` set), the records go back on the request, and
/// nothing is released. Hiding and putting records back only restore the
/// kept state, so they run without the mutex.
async fn release_hold(
    db: &Database,
    id: &str,
    reported: &HashSet<String>,
    now: Timestamp,
    lock: &StepLock,
) -> Result<bool> {
    if !lock.is_held() {
        log_lost("hold release");
        return Ok(false);
    }

    let mut taken: Vec<HeldFile> = Vec::new();
    let mut taken_auto: Vec<String> = Vec::new();
    let mut hold_until: Option<Timestamp> = None;

    let write = update_request(db, id, |fresh| {
        if fresh.child_safety
            || fresh.held_files.is_empty()
            || !fresh.hold_until.is_some_and(|until| until <= now)
        {
            return false;
        }

        taken = std::mem::take(&mut fresh.held_files);
        taken_auto = std::mem::take(&mut fresh.auto_hidden_file_ids);
        hold_until = fresh.hold_until.take();

        // A request that ended without being closed is closed when its hold
        // ends, so the requester purge has a date to count from. A decline
        // keeps its status; the requester still sees it.
        if !fresh.status.is_open() && fresh.closed_at.is_none() {
            fresh.closed_at = Some(now);
            if matches!(
                fresh.status,
                TakedownStatus::Removed | TakedownStatus::PartiallyRemoved
            ) {
                fresh.status = TakedownStatus::Closed;
            }
        }
        true
    })
    .await?;

    match write {
        Write::Done(_) => {}
        Write::Unchanged => return Ok(false),
        Write::Contended => {
            warn!("Take It Down {id}: hold release write contended");
            return Ok(false);
        }
    }

    let applied = match plan_release(db, id, &taken, &taken_auto, reported).await {
        Ok(plan) => match apply_release(db, &plan, lock).await {
            Ok(Some(applied)) => applied,
            Ok(None) => {
                log_lost("hold release");
                let ids: Vec<String> = taken.iter().map(|held| held.id.clone()).collect();
                if let Err(err) = db.hide_attachments(&ids).await {
                    error!(
                        "Take It Down {id}: mutex lost and {} file(s) could not be hidden again: {:?}",
                        ids.len(),
                        err.error_type
                    );
                    capture_error(&err);
                }
                if !restore(db, id, &taken, &taken_auto, hold_until).await {
                    error!(
                        "Take It Down {id}: mutex lost and {} file(s) could not be put back",
                        taken.len()
                    );
                }
                return Ok(false);
            }
            Err(err) => return put_back(db, id, &taken, &taken_auto, hold_until, err).await,
        },
        Err(err) => return put_back(db, id, &taken, &taken_auto, hold_until, err).await,
    };

    if !applied.unsure.is_empty() {
        let unsure_held: Vec<HeldFile> = taken
            .iter()
            .filter(|held| applied.unsure.contains(&held.id))
            .cloned()
            .collect();
        let unsure_auto: Vec<String> = taken_auto
            .iter()
            .filter(|file| applied.unsure.contains(file))
            .cloned()
            .collect();
        if !restore(db, id, &unsure_held, &unsure_auto, hold_until).await {
            error!(
                "Take It Down {id}: {} unsure file(s) stay hidden but could not be put back",
                unsure_held.len()
            );
        }
    }

    StaffAuditEntry::record(
        db,
        None,
        StaffAuditAction::TakedownHoldReleased,
        Some(id),
        applied.released.clone(),
        Some(applied.released.len() as u64),
        None,
    )
    .await;

    if !applied.shown.is_empty() {
        StaffAuditEntry::record(
            db,
            None,
            StaffAuditAction::TakedownUnhidden,
            Some(id),
            applied.shown.clone(),
            Some(applied.shown.len() as u64),
            Some("hold_end"),
        )
        .await;
    }
    Ok(true)
}

/// Put held files back on the request (and its hold end, if it has none).
/// Returns whether that was stored.
async fn restore(
    db: &Database,
    id: &str,
    taken: &[HeldFile],
    taken_auto: &[String],
    hold_until: Option<Timestamp>,
) -> bool {
    let restored = update_request(db, id, |fresh| {
        for file in taken {
            if !fresh.held_files.iter().any(|held| held.id == file.id) {
                fresh.held_files.push(file.clone());
            }
        }
        for file in taken_auto {
            if !fresh.auto_hidden_file_ids.contains(file) {
                fresh.auto_hidden_file_ids.push(file.clone());
            }
        }
        if fresh.hold_until.is_none() {
            fresh.hold_until = hold_until;
        }
        true
    })
    .await;

    matches!(restored, Ok(Write::Done(_)))
}

/// Put files taken for a failed release back on the request, then return
/// the release error
async fn put_back(
    db: &Database,
    id: &str,
    taken: &[HeldFile],
    taken_auto: &[String],
    hold_until: Option<Timestamp>,
    err: revolt_result::Error,
) -> Result<bool> {
    if !restore(db, id, taken, taken_auto, hold_until).await {
        // The files stay `reported`, so they are kept, but no request
        // tracks them any more
        error!(
            "Take It Down {id}: hold release failed and {} file(s) could not be put back",
            taken.len()
        );
        capture_error(&err);
    }

    Err(err)
}

// 7. Requester purge (D7)

/// When a request that left review ended, for the requester purge: its
/// `closed_at`, else its `removed_at`. `None` while open.
fn ended_at(request: &TakedownRequest) -> Option<Timestamp> {
    if request.status.is_open() {
        None
    } else {
        request.closed_at.or(request.removed_at)
    }
}

/// Reduce requests that ended more than `retention_requester_days` ago to
/// ids, dates, targets, markers and the contact fingerprint. Returns how
/// many were purged.
///
/// "Ended" is `closed_at`, or `removed_at` for a request removed but never
/// closed (the purge query only sees `closed_at`, so those come from a scan).
async fn purge_requesters(db: &Database, cfg: &FeaturesTakedown, now: Timestamp) -> Result<usize> {
    let closed_before = now.saturating_sub(config_days(cfg.retention_requester_days));

    let mut due = db.fetch_takedown_requests_to_purge(closed_before).await?;
    for request in db
        .fetch_recent_takedown_requests(Timestamp::UNIX_EPOCH)
        .await?
    {
        if !request.requester_purged
            && request.closed_at.is_none()
            && ended_at(&request).is_some_and(|ended| ended <= closed_before)
            && !due.iter().any(|other| other.id == request.id)
        {
            due.push(request);
        }
    }

    let mut purged = 0;
    for request in due {
        let write = update_request(db, &request.id, |fresh| {
            // A request reopened since keeps its details
            if fresh.requester_purged
                || !ended_at(fresh).is_some_and(|ended| ended <= closed_before)
            {
                return false;
            }

            fresh.sealed = String::new();
            fresh.locations = Vec::new();
            fresh.reviewer_note = None;
            fresh.requester_purged = true;
            true
        })
        .await;

        match write {
            Ok(Write::Done(_)) => {
                StaffAuditEntry::record(
                    db,
                    None,
                    StaffAuditAction::TakedownRequesterPurged,
                    Some(&request.id),
                    Vec::new(),
                    None,
                    None,
                )
                .await;
                purged += 1;
            }
            Ok(Write::Unchanged) => {}
            Ok(Write::Contended) => warn!("Take It Down {}: purge write contended", request.id),
            Err(err) => warn!(
                "Take It Down {}: purge failed: {:?}",
                request.id, err.error_type
            ),
        }
    }

    Ok(purged)
}

// 8. Heartbeat

/// Redis key naming the ISO week of `now`
fn heartbeat_key(now: Timestamp) -> String {
    let (year, week, _) = now.to_iso_week_date();
    format!("takedown:heartbeat:{year}-W{week:02}")
}

/// Once a week, tell the alert channels the queue size, so a silent channel
/// gets noticed
async fn heartbeat(db: &Database, cfg: &FeaturesTakedown, notifier: &Notifier, now: Timestamp) {
    let open = match db.fetch_open_takedown_requests().await {
        Ok(open) => open.len(),
        Err(err) => {
            warn!(
                "Take It Down heartbeat skipped, open requests unreadable: {:?}",
                err.error_type
            );
            return;
        }
    };

    match claim(&heartbeat_key(now), HEARTBEAT_TTL_SECS).await {
        Ok(true) => {}
        // Sent this week, here or on another instance
        Ok(false) => return,
        Err(err) => {
            warn!(
                "Take It Down heartbeat skipped, could not claim the week: {:?}",
                err.error_type
            );
            return;
        }
    }

    let delivered = notifier.heartbeat(cfg, open).await;
    if delivered == 0 {
        warn!("Take It Down heartbeat reached no alert channel");
    }

    StaffAuditEntry::record(
        db,
        None,
        StaffAuditAction::TakedownAlertSent,
        None,
        Vec::new(),
        Some(delivered),
        Some("heartbeat"),
    )
    .await;
}

// Volume alarm (plan §4.1, §4.8)

/// Redis key naming the UTC clock hour of `now` (`yyyy-mm-ddThh`)
fn volume_key(now: Timestamp) -> String {
    format!(
        "takedown:volume:{:04}-{:02}-{:02}T{:02}",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour()
    )
}

/// Alert reviewers, at most once per clock hour, when more than
/// `VOLUME_ALARM_THRESHOLD` requests arrived in the last hour. `claim` takes
/// the hour's key and answers whether this caller won it (Redis `SET NX` in
/// the task). The alert carries a fixed summary, the word "queue" in place
/// of a reference, and the earliest deadline among those requests. Returns
/// whether this call sent it.
async fn volume_alarm<C, F>(
    db: &Database,
    cfg: &FeaturesTakedown,
    notifier: &Notifier,
    now: Timestamp,
    claim: C,
) -> Result<bool>
where
    C: FnOnce(String) -> F,
    F: Future<Output = Result<bool>>,
{
    let recent = db
        .fetch_recent_takedown_requests(now.saturating_sub(Span::hours(1)))
        .await?;
    if recent.len() <= VOLUME_ALARM_THRESHOLD {
        return Ok(false);
    }

    let Some(deadline) = recent.iter().map(|request| request.deadline_at).min() else {
        return Ok(false);
    };

    if !claim(volume_key(now)).await? {
        return Ok(false);
    }

    let delivered = notifier
        .alert(cfg, "queue", VOLUME_SUMMARY, &deadline.to_string())
        .await;
    warn!(
        "Take It Down volume alarm: {} requests in the last hour, alert reached {delivered} channel(s)",
        recent.len()
    );

    StaffAuditEntry::record(
        db,
        None,
        StaffAuditAction::TakedownAlertSent,
        None,
        Vec::new(),
        Some(delivered),
        Some("volume"),
    )
    .await;
    Ok(true)
}

/// `SET {key} 1 NX EX {ttl_secs}`: `true` if this call set it
async fn claim(key: &str, ttl_secs: usize) -> Result<bool> {
    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?;

    conn.set_options(
        key,
        1,
        SetOptions::default()
            .conditional_set(ExistenceCheck::NX)
            .with_expiration(SetExpiry::EX(ttl_secs)),
    )
    .await
    .to_internal_error()
}

// Alert delivery

/// Where staff alerts go
enum Notifier {
    /// `staff_alert_emails`, plus `alert_webhook_url` when set
    Live {
        /// `None` if the HTTP client could not be built
        webhook: Option<reqwest::Client>,
    },
    /// Keeps the alert texts, for tests
    #[cfg(test)]
    Recorder(std::sync::Mutex<Vec<String>>),
}

impl Notifier {
    fn live() -> Self {
        let webhook = reqwest::Client::builder()
            .timeout(WEBHOOK_TIMEOUT)
            .connect_timeout(WEBHOOK_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| error!("Take It Down alert webhook client could not be built"))
            .ok();

        Notifier::Live { webhook }
    }

    /// Send one request alert. Returns how many channels took it.
    async fn alert(
        &self,
        cfg: &FeaturesTakedown,
        reference: &str,
        summary: &str,
        deadline: &str,
    ) -> u64 {
        let text = format!("Take It Down {reference}: {summary}. Deadline {deadline}.");
        let variables = HashMap::from([
            ("reference", reference.to_string()),
            ("summary", summary.to_string()),
            ("deadline", deadline.to_string()),
        ]);

        self.deliver(cfg, false, variables, text).await
    }

    /// Send the weekly heartbeat. Returns how many channels took it.
    async fn heartbeat(&self, cfg: &FeaturesTakedown, open: usize) -> u64 {
        let text = format!("Take It Down queue: {open} open. Alerting works.");
        let variables = HashMap::from([("count", open.to_string())]);

        self.deliver(cfg, true, variables, text).await
    }

    async fn deliver(
        &self,
        cfg: &FeaturesTakedown,
        heartbeat: bool,
        variables: HashMap<&'static str, String>,
        text: String,
    ) -> u64 {
        match self {
            Notifier::Live { webhook } => {
                let templates = email_templates().await;
                let template = if heartbeat {
                    &templates.takedown_heartbeat
                } else {
                    &templates.takedown_alert
                };

                let mut delivered = 0;
                for (index, address) in cfg.staff_alert_emails.iter().enumerate() {
                    match send_email_safe(address, template, variables.clone()).await {
                        Ok(()) => delivered += 1,
                        Err(err) => warn!(
                            "Take It Down staff alert email #{index} failed: {:?}",
                            err.error_type
                        ),
                    }
                }

                if let Some(client) = webhook {
                    if !cfg.alert_webhook_url.is_empty()
                        && post_webhook(client, &cfg.alert_webhook_url, text).await
                    {
                        delivered += 1;
                    }
                }

                delivered
            }
            #[cfg(test)]
            Notifier::Recorder(sent) => {
                sent.lock().unwrap().push(text);
                1
            }
        }
    }
}

/// POST `text` as a plain-text body (ntfy style). Failures are logged
/// without the URL, which can carry a secret topic or token.
async fn post_webhook(client: &reqwest::Client, url: &str, text: String) -> bool {
    match client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(text)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => true,
        Ok(response) => {
            warn!(
                "Take It Down alert webhook answered {}",
                response.status().as_u16()
            );
            false
        }
        Err(err) => {
            warn!(
                "Take It Down alert webhook failed (timeout: {})",
                err.is_timeout()
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use revolt_database::{
        Channel, EncryptedPayload, FileUsedFor, ForwardedSnapshot, Message, Metadata, Report,
        Snapshot, SnapshotContent, TakedownSource,
    };
    use revolt_models::v0::{ReportStatus, ReportedContent, UserReportReason};
    use revolt_result::create_error;
    use ulid::Ulid;

    use super::*;

    impl Notifier {
        fn recorder() -> Self {
            Notifier::Recorder(Default::default())
        }

        fn sent(&self) -> Vec<String> {
            match self {
                Notifier::Recorder(sent) => sent.lock().unwrap().clone(),
                Notifier::Live { .. } => unreachable!("tests use the recorder"),
            }
        }
    }

    fn reference_db() -> Database {
        Database::Reference(Default::default())
    }

    fn cfg() -> FeaturesTakedown {
        FeaturesTakedown {
            enabled: true,
            data_key: "0".repeat(64),
            ..Default::default()
        }
    }

    /// Start of every test clock (whole seconds)
    fn base() -> Timestamp {
        Timestamp::from_unix_timestamp(1_800_000_000)
    }

    fn at_minutes(minutes: i64) -> Timestamp {
        base().saturating_add(Span::minutes(minutes))
    }

    fn at_hours(hours: i64) -> Timestamp {
        at_minutes(hours * 60)
    }

    fn new_id() -> String {
        Ulid::new().to_string()
    }

    /// A resolved, open request received at `received`
    fn request(received: Timestamp) -> TakedownRequest {
        TakedownRequest {
            id: new_id(),
            status: TakedownStatus::Received,
            source: TakedownSource::Web,
            received_at: received,
            deadline_at: received.saturating_add(Span::hours(DEADLINE_HOURS)),
            sealed: "SEALED".to_string(),
            contact_fp: "fp-a".to_string(),
            status_token_hash: "hash".to_string(),
            locations: vec![],
            minor_claimed: false,
            resolved: true,
            targets: vec![],
            linked_request_ids: vec![],
            held_files: vec![],
            auto_hidden_file_ids: vec![],
            hold_until: None,
            child_safety: false,
            bad_faith: false,
            throttled: false,
            decline_reason: None,
            first_opened_at: None,
            removed_at: None,
            closed_at: None,
            requester_purged: false,
            reviewer_note: None,
            revision: 0,
            markers: vec![],
        }
    }

    fn file_target(file: &File) -> TakedownTarget {
        TakedownTarget::File {
            file: file.id.clone(),
        }
    }

    async fn insert(db: &Database, request: TakedownRequest) -> TakedownRequest {
        db.insert_takedown_request(&request).await.unwrap();
        request
    }

    async fn fetch(db: &Database, id: &str) -> TakedownRequest {
        db.fetch_takedown_request(id).await.unwrap()
    }

    async fn actions(db: &Database, id: &str) -> Vec<StaffAuditAction> {
        db.fetch_staff_audit_for_request(id)
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.action)
            .collect()
    }

    fn count(actions: &[StaffAuditAction], action: StaffAuditAction) -> usize {
        actions.iter().filter(|a| **a == action).count()
    }

    fn alert_text(request: &TakedownRequest, summary: &str) -> String {
        format!(
            "Take It Down {}: {summary}. Deadline {}.",
            reference_for(&request.id),
            request.deadline_at
        )
    }

    /// An attachment row; `message` sets `used_for`
    #[allow(clippy::disallowed_methods)]
    async fn attachment(
        db: &Database,
        tag: &str,
        message: Option<&str>,
        reported: bool,
        deleted: bool,
    ) -> File {
        let file = File {
            id: new_id(),
            tag: tag.to_string(),
            filename: "image.png".to_string(),
            hash: None,
            uploaded_at: None,
            uploader_id: None,
            used_for: message.map(|id| FileUsedFor {
                object_type: FileUsedForType::Message,
                id: id.to_string(),
            }),
            deleted: deleted.then_some(true),
            reported: reported.then_some(true),
            metadata: Metadata::File,
            content_type: "image/png".to_string(),
            size: 1,
            message_id: None,
            user_id: None,
            server_id: None,
            object_id: None,
        };
        db.insert_attachment(&file).await.unwrap();
        file
    }

    /// A message row carrying `attachments`; `encrypted` makes it a
    /// protected-channel row, which the driver only accepts in a protected
    /// channel, with a well-formed payload and no plaintext attachments
    #[allow(clippy::disallowed_methods)]
    async fn message(db: &Database, id: &str, attachments: Vec<File>, encrypted: bool) {
        assert!(
            !encrypted || attachments.is_empty(),
            "a protected row carries no plaintext attachments"
        );
        let channel = new_id();
        if encrypted {
            let protected: Channel = serde_json::from_value(serde_json::json!({
                "channel_type": "TextChannel",
                "_id": channel,
                "server": new_id(),
                "name": "protected",
                "protected": true,
            }))
            .unwrap();
            db.insert_channel(&protected).await.unwrap();
        }
        db.insert_message(&Message {
            id: id.to_string(),
            channel,
            author: new_id(),
            nonce: encrypted.then(|| Ulid::new().to_string()),
            attachments: (!encrypted).then_some(attachments),
            encrypted: encrypted.then(|| EncryptedPayload {
                v: EncryptedPayload::VERSION,
                group_id: "ab".repeat(32),
                epoch: 0,
                sender_device_id: "cd".repeat(16),
                // Unpadded standard base64 of 24, 17 and 64 zero bytes
                nonce: "A".repeat(32),
                ciphertext: "A".repeat(23),
                sig: "A".repeat(86),
                franking: None,
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    }

    /// A forward whose snapshot lists `copy` (and has no attachments of its
    /// own)
    #[allow(clippy::disallowed_methods)]
    async fn forward_message(db: &Database, id: &str, copy: File) {
        db.insert_message(&Message {
            id: id.to_string(),
            channel: new_id(),
            author: new_id(),
            forwarded: Some(ForwardedSnapshot {
                message_id: new_id(),
                channel_id: new_id(),
                server_id: None,
                author_id: None,
                content: None,
                attachments: vec![copy],
                original_sent_at: 0,
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    }

    async fn file_row(db: &Database, id: &str) -> File {
        db.fetch_attachment_by_id(id).await.unwrap()
    }

    // Alerts

    /// Two instances ticking at once send each alert once
    #[tokio::test]
    async fn each_alert_is_sent_once_across_concurrent_ticks() {
        let db = reference_db();
        let cfg = cfg();
        let notifier = Notifier::recorder();
        let request = insert(&db, request(base())).await;
        let now = at_minutes(1);

        let (a, b) = tokio::join!(
            run_alerts(&db, &cfg, &notifier, now),
            run_alerts(&db, &cfg, &notifier, now)
        );
        assert_eq!(a.unwrap() + b.unwrap(), 1);
        assert_eq!(notifier.sent(), [alert_text(&request, "new request")]);

        // The same moment again sends nothing
        assert_eq!(run_alerts(&db, &cfg, &notifier, now).await.unwrap(), 0);
        assert_eq!(notifier.sent().len(), 1);

        let audit = actions(&db, &request.id).await;
        assert_eq!(count(&audit, StaffAuditAction::TakedownAlertSent), 1);

        // Two instances holding the same copy (both see the overdue rung
        // unsent): only the claim decides, and one sends
        let snapshot = fetch(&db, &request.id).await;
        let late = at_hours(49);
        let (a, b) = tokio::join!(
            alert_request(&db, &cfg, &notifier, &snapshot, late),
            alert_request(&db, &cfg, &notifier, &snapshot, late)
        );
        assert_eq!(
            [a.unwrap(), b.unwrap()].iter().filter(|won| **won).count(),
            1
        );
        assert_eq!(notifier.sent()[1], alert_text(&request, "OVERDUE"));
        assert_eq!(notifier.sent().len(), 2);

        // A third, still on the stale copy, sends nothing either
        assert!(!alert_request(&db, &cfg, &notifier, &snapshot, late)
            .await
            .unwrap());
        assert_eq!(notifier.sent().len(), 2);
        assert_eq!(
            count(
                &actions(&db, &request.id).await,
                StaffAuditAction::TakedownAlertSent
            ),
            2
        );
    }

    /// arrival, 12 h unopened, 24 h, 36 h, 44 h after receipt, then overdue
    #[tokio::test]
    async fn ladder_follows_the_plan_timings() {
        let db = reference_db();
        let cfg = cfg();
        let notifier = Notifier::recorder();
        let request = insert(&db, request(base())).await;

        let steps: [(i64, Option<&str>); 12] = [
            (1, Some("new request")),
            (11 * 60 + 59, None),
            (12 * 60, Some("not opened after 12 hours")),
            (23 * 60 + 59, None),
            (24 * 60, Some("24 hours left")),
            (35 * 60 + 59, None),
            (36 * 60, Some("12 hours left")),
            (43 * 60 + 59, None),
            (44 * 60, Some("4 hours left")),
            (48 * 60, None),
            (48 * 60 + 1, Some("OVERDUE")),
            (72 * 60, None),
        ];

        let mut expected = Vec::new();
        for (minute, alert) in steps {
            run_alerts(&db, &cfg, &notifier, at_minutes(minute))
                .await
                .unwrap();
            if let Some(summary) = alert {
                expected.push(alert_text(&request, summary));
            }
            assert_eq!(notifier.sent(), expected, "at minute {minute}");
        }

        let markers = fetch(&db, &request.id).await.markers;
        for marker in [
            "alert:new",
            "alert:12h",
            "alert:24h",
            "alert:36h",
            "alert:44h",
            "alert:overdue",
        ] {
            assert!(markers.iter().any(|m| m == marker), "{marker}");
        }
    }

    /// Opened before hour 12: no "not opened" alert
    #[tokio::test]
    async fn opened_request_skips_the_unopened_alert() {
        let db = reference_db();
        let cfg = cfg();
        let notifier = Notifier::recorder();
        let mut opened = request(base());
        opened.first_opened_at = Some(at_hours(2));
        let opened = insert(&db, opened).await;

        for hour in [0, 12, 13, 20] {
            run_alerts(&db, &cfg, &notifier, at_hours(hour))
                .await
                .unwrap();
        }
        assert_eq!(notifier.sent(), [alert_text(&opened, "new request")]);
    }

    /// First seen late: only the most urgent alert goes out; the rest are
    /// marked done and never sent
    #[tokio::test]
    async fn late_first_tick_sends_only_the_most_urgent_alert() {
        let db = reference_db();
        let cfg = cfg();
        let notifier = Notifier::recorder();
        let request = insert(&db, request(base())).await;

        run_alerts(&db, &cfg, &notifier, at_hours(45))
            .await
            .unwrap();
        run_alerts(&db, &cfg, &notifier, at_hours(46))
            .await
            .unwrap();
        assert_eq!(notifier.sent(), [alert_text(&request, "4 hours left")]);

        let markers = fetch(&db, &request.id).await.markers;
        for marker in [
            "alert:new",
            "alert:12h",
            "alert:24h",
            "alert:36h",
            "alert:44h",
        ] {
            assert!(markers.iter().any(|m| m == marker), "{marker}");
        }
        assert!(!markers.iter().any(|m| m == "alert:overdue"));
    }

    #[tokio::test]
    async fn minor_claim_is_marked_and_closed_requests_are_silent() {
        let db = reference_db();
        let cfg = cfg();
        let notifier = Notifier::recorder();

        let mut minor = request(base());
        minor.minor_claimed = true;
        let minor = insert(&db, minor).await;

        let mut closed = request(base());
        closed.status = TakedownStatus::Declined;
        closed.closed_at = Some(at_hours(1));
        insert(&db, closed).await;

        run_alerts(&db, &cfg, &notifier, at_minutes(1))
            .await
            .unwrap();
        assert_eq!(
            notifier.sent(),
            [alert_text(&minor, "new request, child-safety priority")]
        );
    }

    // Auto-hide

    #[tokio::test]
    async fn auto_hide_respects_the_daily_cap_per_contact() {
        let db = reference_db();
        let cfg = FeaturesTakedown {
            auto_hide_daily_cap: 2,
            ..cfg()
        };

        let mut files = Vec::new();
        let mut requests = Vec::new();
        for (minute, contact) in [(0, "fp-a"), (1, "fp-a"), (2, "fp-a"), (3, "fp-b")] {
            let file = attachment(&db, "attachments", None, false, false).await;
            let mut r = request(at_minutes(minute));
            r.contact_fp = contact.to_string();
            r.targets = vec![file_target(&file)];
            requests.push(insert(&db, r).await);
            files.push(file);
        }

        let now = at_minutes(44 * 60 + 3);
        assert_eq!(auto_hide(&db, &cfg, now, &take_free).await.unwrap(), 3);

        for index in [0, 1, 3] {
            let row = file_row(&db, &files[index].id).await;
            assert_eq!((row.deleted, row.reported), (Some(true), Some(true)));
            assert!(has_marker(
                &fetch(&db, &requests[index].id).await,
                MARK_AUTOHIDE
            ));
        }

        // The third from fp-a is over the cap: untouched, and not spent
        let row = file_row(&db, &files[2].id).await;
        assert_eq!((row.deleted, row.reported), (None, None));
        let capped = fetch(&db, &requests[2].id).await;
        assert!(!has_marker(&capped, MARK_AUTOHIDE));
        assert!(capped.held_files.is_empty());

        // Still capped on the next tick
        assert_eq!(auto_hide(&db, &cfg, now, &take_free).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn auto_hide_records_prior_state_and_runs_once() {
        let db = reference_db();
        let cfg = cfg();

        // A message with an attachment an open report already flagged, and
        // a file linked directly
        let message_id = new_id();
        let in_message = attachment(&db, "attachments", Some(&message_id), true, false).await;
        message(&db, &message_id, vec![in_message.clone()], false).await;
        let direct = attachment(&db, "attachments", None, false, false).await;

        let mut r = request(base());
        r.targets = vec![
            TakedownTarget::Message {
                channel: new_id(),
                message: message_id.clone(),
            },
            file_target(&direct),
        ];
        let r = insert(&db, r).await;

        // Not before hour 44
        assert_eq!(
            auto_hide(&db, &cfg, at_minutes(44 * 60 - 1), &take_free)
                .await
                .unwrap(),
            0
        );

        // Two instances holding the same copy: one hides
        let now = at_hours(44);
        let hour = config_hours(cfg.auto_hide_hour);
        let snapshot = fetch(&db, &r.id).await;
        assert!(auto_hide_due(&snapshot, hour, now));
        let (lock_a, lock_b) = (StepLock::free(), StepLock::free());
        let (a, b) = tokio::join!(
            auto_hide_request(&db, &cfg, &snapshot, hour, now, &lock_a),
            auto_hide_request(&db, &cfg, &snapshot, hour, now, &lock_b)
        );
        assert_eq!(
            [a.unwrap(), b.unwrap()].iter().filter(|hid| **hid).count(),
            1
        );

        for file in [&in_message, &direct] {
            let row = file_row(&db, &file.id).await;
            assert_eq!((row.deleted, row.reported), (Some(true), Some(true)));
        }

        let stored = fetch(&db, &r.id).await;
        assert_eq!(
            stored.held_files,
            [
                HeldFile {
                    id: in_message.id.clone(),
                    was_deleted: false,
                    was_reported: true,
                },
                HeldFile {
                    id: direct.id.clone(),
                    was_deleted: false,
                    was_reported: false,
                },
            ]
        );
        assert_eq!(
            stored.auto_hidden_file_ids,
            [in_message.id.clone(), direct.id.clone()]
        );
        // Auto-hide never changes the status and sets no hold end
        assert_eq!(stored.status, TakedownStatus::Received);
        assert_eq!(stored.hold_until, None);

        let entries = db.fetch_staff_audit_for_request(&r.id).await.unwrap();
        let hides: Vec<_> = entries
            .iter()
            .filter(|e| e.action == StaffAuditAction::TakedownAutoHidden)
            .collect();
        assert_eq!(hides.len(), 1);
        assert_eq!(hides[0].count, Some(2));
        assert_eq!(hides[0].actor, None);

        assert_eq!(
            auto_hide(&db, &cfg, at_hours(50), &take_free)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn auto_hide_skips_what_it_must_not_touch() {
        let db = reference_db();
        let cfg = cfg();
        let mut untouched = Vec::new();

        // A contact each, so the cap plays no part
        fn add(mut r: TakedownRequest, contact: usize) -> TakedownRequest {
            r.contact_fp = format!("fp-skip-{contact}");
            r
        }

        // Throttled, bad faith, waiting for information
        let mut rows = Vec::new();
        for flag in 0..3 {
            let file = attachment(&db, "attachments", None, false, false).await;
            let mut r = request(base());
            r.targets = vec![file_target(&file)];
            match flag {
                0 => r.throttled = true,
                1 => r.bad_faith = true,
                _ => r.status = TakedownStatus::NeedsInfo,
            }
            rows.push(add(r, flag));
            untouched.push(file);
        }

        // A private conversation with no stored message
        let mut private = request(base());
        private.targets = vec![TakedownTarget::Unresolvable {
            location_index: 0,
            kind: UnresolvableKind::PrivateConversation,
        }];
        rows.push(add(private, 3));

        // A protected-channel (encrypted) message row, linked as a message
        // and through a file whose `used_for` names it
        let encrypted_id = new_id();
        let in_encrypted = attachment(&db, "attachments", Some(&encrypted_id), false, false).await;
        message(&db, &encrypted_id, vec![], true).await;
        let mut encrypted = request(base());
        encrypted.targets = vec![
            TakedownTarget::Message {
                channel: new_id(),
                message: encrypted_id.clone(),
            },
            file_target(&in_encrypted),
        ];
        rows.push(add(encrypted, 4));
        untouched.push(in_encrypted);

        // Not a message attachment (an avatar)
        let avatar = attachment(&db, "avatars", None, false, false).await;
        let mut not_attachment = request(base());
        not_attachment.targets = vec![file_target(&avatar)];
        rows.push(add(not_attachment, 5));
        untouched.push(avatar);

        // Not resolved yet
        let pending_file = attachment(&db, "attachments", None, false, false).await;
        let mut pending = request(base());
        pending.resolved = false;
        pending.targets = vec![file_target(&pending_file)];
        rows.push(add(pending, 6));
        untouched.push(pending_file);

        for r in rows {
            insert(&db, r).await;
        }

        assert_eq!(
            auto_hide(&db, &cfg, at_hours(47), &take_free)
                .await
                .unwrap(),
            0
        );
        for file in &untouched {
            let row = file_row(&db, &file.id).await;
            assert_eq!((row.deleted, row.reported), (None, None), "{}", file.tag);
        }

        // Off when `auto_hide_hour` is 0
        let mut live = request(base());
        let live_file = attachment(&db, "attachments", None, false, false).await;
        live.contact_fp = "fp-live".to_string();
        live.targets = vec![file_target(&live_file)];
        insert(&db, live).await;
        let off = FeaturesTakedown {
            auto_hide_hour: 0,
            ..cfg.clone()
        };
        assert_eq!(
            auto_hide(&db, &off, at_hours(47), &take_free)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            auto_hide(&db, &cfg, at_hours(47), &take_free)
                .await
                .unwrap(),
            1
        );
    }

    // Hold release

    #[allow(clippy::disallowed_methods)]
    async fn open_report_covering(db: &Database, file: &File) {
        let report_id = new_id();
        db.insert_report(&Report {
            id: report_id.clone(),
            author_id: new_id(),
            content: ReportedContent::User {
                id: new_id(),
                report_reason: UserReportReason::SpamAbuse,
                message_id: None,
            },
            additional_context: String::new(),
            status: ReportStatus::Created {},
            notes: String::new(),
        })
        .await
        .unwrap();
        db.insert_snapshot(&Snapshot {
            id: new_id(),
            report_id,
            content: SnapshotContent::Message {
                prior_context: vec![],
                leading_context: vec![],
                message: Message {
                    id: new_id(),
                    attachments: Some(vec![file.clone()]),
                    ..Default::default()
                },
            },
        })
        .await
        .unwrap();
    }

    fn held(file: &File, was_reported: bool) -> HeldFile {
        HeldFile {
            id: file.id.clone(),
            was_deleted: false,
            was_reported,
        }
    }

    #[tokio::test]
    async fn hold_release_skips_reported_and_covered_files() {
        let db = reference_db();
        let now = at_hours(24 * 40);

        // All hidden (deleted + reported)
        let free = attachment(&db, "attachments", None, true, true).await;
        let was_reported = attachment(&db, "attachments", None, true, true).await;
        let shared = attachment(&db, "attachments", None, true, true).await;
        let in_report = attachment(&db, "attachments", None, true, true).await;
        let child = attachment(&db, "attachments", None, true, true).await;
        open_report_covering(&db, &in_report).await;

        // Auto-hidden and never removed by a reviewer: one still shown by
        // its message, one whose message was deleted, one its message no
        // longer shows (pulled by a removal)
        let shown_id = new_id();
        let auto_shown = attachment(&db, "attachments", Some(&shown_id), true, true).await;
        message(&db, &shown_id, vec![auto_shown.clone()], false).await;
        let auto_orphan = attachment(&db, "attachments", Some(&new_id()), true, true).await;
        let pulled_id = new_id();
        let auto_pulled = attachment(&db, "attachments", Some(&pulled_id), true, true).await;
        message(&db, &pulled_id, vec![], false).await;

        // A forward's copy, still listed in the forward's snapshot
        let forward_id = new_id();
        let auto_forwarded = attachment(&db, "attachments", Some(&forward_id), true, true).await;
        forward_message(&db, &forward_id, auto_forwarded.clone()).await;

        let mut due = request(base());
        due.status = TakedownStatus::Removed;
        due.closed_at = Some(at_hours(1));
        due.hold_until = Some(at_hours(24 * 31));
        due.held_files = vec![
            held(&free, false),
            held(&was_reported, true),
            held(&shared, false),
            held(&in_report, false),
            held(&auto_shown, false),
            held(&auto_orphan, false),
            held(&auto_pulled, false),
            held(&auto_forwarded, false),
        ];
        due.auto_hidden_file_ids = vec![
            shared.id.clone(),
            auto_shown.id.clone(),
            auto_orphan.id.clone(),
            auto_pulled.id.clone(),
            auto_forwarded.id.clone(),
        ];
        let due = insert(&db, due).await;

        // Another request still holds `shared`, until later
        let mut other = request(base());
        other.status = TakedownStatus::Removed;
        other.hold_until = Some(at_hours(24 * 90));
        other.held_files = vec![held(&shared, false)];
        insert(&db, other).await;

        // Child safety: never released, even past its hold
        let mut child_safety = request(base());
        child_safety.status = TakedownStatus::Removed;
        child_safety.child_safety = true;
        child_safety.hold_until = Some(at_hours(24));
        child_safety.held_files = vec![held(&child, false)];
        let child_safety = insert(&db, child_safety).await;

        assert_eq!(release_holds(&db, now, &take_free).await.unwrap(), 1);

        // Still shown (as an attachment, or in a forward's snapshot): back in
        // the app, and an ordinary file
        for file in [&auto_shown, &auto_forwarded] {
            let row = file_row(&db, &file.id).await;
            assert_eq!((row.deleted, row.reported), (Some(false), Some(false)));
        }

        // Parent gone or no longer showing it, or held by a removal: stays
        // deleted and goes to the file deletion task
        for file in [&free, &auto_orphan, &auto_pulled] {
            let row = file_row(&db, &file.id).await;
            assert_eq!((row.deleted, row.reported), (Some(true), Some(false)));
        }

        // Reported before, held by another request (auto-hidden here too),
        // or in an open report: kept as they were
        for file in [&was_reported, &shared, &in_report, &child] {
            let row = file_row(&db, &file.id).await;
            assert_eq!((row.deleted, row.reported), (Some(true), Some(true)));
        }

        let stored = fetch(&db, &due.id).await;
        assert!(stored.held_files.is_empty());
        assert!(stored.auto_hidden_file_ids.is_empty());
        assert_eq!(stored.hold_until, None);

        let entries = db.fetch_staff_audit_for_request(&due.id).await.unwrap();
        assert_eq!(entries.len(), 2);
        let released = entries
            .iter()
            .find(|e| e.action == StaffAuditAction::TakedownHoldReleased)
            .unwrap();
        assert_eq!(released.count, Some(5));
        assert_eq!(
            released.target_ids,
            [
                free.id.clone(),
                auto_shown.id.clone(),
                auto_orphan.id.clone(),
                auto_pulled.id.clone(),
                auto_forwarded.id.clone(),
            ]
        );
        let unhidden = entries
            .iter()
            .find(|e| e.action == StaffAuditAction::TakedownUnhidden)
            .unwrap();
        assert_eq!(
            unhidden.target_ids,
            [auto_shown.id.clone(), auto_forwarded.id.clone()]
        );
        assert_eq!(unhidden.actor, None);

        assert_eq!(fetch(&db, &child_safety.id).await.held_files.len(), 1);

        // Nothing left to release
        assert_eq!(release_holds(&db, now, &take_free).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn hold_release_waits_for_the_hold_end() {
        let db = reference_db();
        let file = attachment(&db, "attachments", None, true, true).await;

        let mut r = request(base());
        r.status = TakedownStatus::Removed;
        r.hold_until = Some(at_hours(100));
        r.held_files = vec![held(&file, false)];
        let r = insert(&db, r).await;

        assert_eq!(
            release_holds(&db, at_hours(99), &take_free).await.unwrap(),
            0
        );
        assert_eq!(file_row(&db, &file.id).await.reported, Some(true));
        let stored = fetch(&db, &r.id).await;
        assert_eq!(stored.held_files.len(), 1);
        assert_eq!(stored.status, TakedownStatus::Removed);
        assert_eq!(stored.closed_at, None);

        assert_eq!(
            release_holds(&db, at_hours(100), &take_free).await.unwrap(),
            1
        );
        assert_eq!(file_row(&db, &file.id).await.reported, Some(false));

        // Removed and never closed: closed when the hold ends
        let stored = fetch(&db, &r.id).await;
        assert_eq!(stored.status, TakedownStatus::Closed);
        assert_eq!(stored.closed_at, Some(at_hours(100)));
    }

    // Purge

    #[tokio::test]
    async fn purge_clears_requester_data_after_retention() {
        let db = reference_db();
        let cfg = cfg();

        let file = attachment(&db, "attachments", None, false, false).await;
        let closed = |closed_at: Timestamp| {
            let mut r = request(base());
            r.status = TakedownStatus::Declined;
            r.closed_at = Some(closed_at);
            r.locations = vec!["https://app.sloga.gg/channel/LOCATION".to_string()];
            r.reviewer_note = Some("NOTE".to_string());
            r.targets = vec![file_target(&file)];
            r
        };

        let old = insert(&db, closed(at_hours(24))).await;
        let recent = insert(&db, closed(at_hours(24 * 300))).await;
        // Reopened after closing: kept
        let mut reopened = closed(at_hours(24));
        reopened.status = TakedownStatus::UnderReview;
        let reopened = insert(&db, reopened).await;

        let now = at_hours(24 * 367);
        assert_eq!(purge_requesters(&db, &cfg, now).await.unwrap(), 1);

        let stored = fetch(&db, &old.id).await;
        assert!(stored.requester_purged);
        assert_eq!(stored.sealed, "");
        assert!(stored.locations.is_empty());
        assert_eq!(stored.reviewer_note, None);
        // Kept: targets, contact fingerprint, dates, status
        assert_eq!(stored.targets, old.targets);
        assert_eq!(stored.contact_fp, old.contact_fp);
        assert_eq!(stored.closed_at, old.closed_at);
        assert_eq!(stored.status, TakedownStatus::Declined);
        assert_eq!(
            count(
                &actions(&db, &old.id).await,
                StaffAuditAction::TakedownRequesterPurged
            ),
            1
        );

        for id in [&recent.id, &reopened.id] {
            let stored = fetch(&db, id).await;
            assert!(!stored.requester_purged);
            assert_eq!(stored.sealed, "SEALED");
            assert_eq!(stored.reviewer_note.as_deref(), Some("NOTE"));
        }

        // Once only
        assert_eq!(purge_requesters(&db, &cfg, now).await.unwrap(), 0);
        assert_eq!(
            count(
                &actions(&db, &old.id).await,
                StaffAuditAction::TakedownRequesterPurged
            ),
            1
        );
    }

    // Resolution

    #[tokio::test]
    async fn resolution_retries_three_times_before_settling_on_not_found() {
        let db = reference_db();
        let mut r = request(base());
        r.resolved = false;
        r.locations = vec![format!(
            "https://app.sloga.gg/channel/{}/{}",
            new_id(),
            new_id()
        )];
        let r = insert(&db, r).await;

        assert_eq!(resolve_pending(&db).await.unwrap(), 0);
        let stored = fetch(&db, &r.id).await;
        assert!(!stored.resolved);
        assert!(has_marker(&stored, "resolve:try1"));

        assert_eq!(resolve_pending(&db).await.unwrap(), 0);
        let stored = fetch(&db, &r.id).await;
        assert!(!stored.resolved);
        assert!(has_marker(&stored, "resolve:try2"));

        assert_eq!(resolve_pending(&db).await.unwrap(), 1);
        let stored = fetch(&db, &r.id).await;
        assert!(stored.resolved);
        assert_eq!(
            stored.targets,
            [TakedownTarget::Unresolvable {
                location_index: 0,
                kind: UnresolvableKind::NotFound,
            }]
        );

        assert_eq!(resolve_pending(&db).await.unwrap(), 0);
        assert_eq!(
            count(
                &actions(&db, &r.id).await,
                StaffAuditAction::TakedownResolved
            ),
            1
        );
    }

    /// A private conversation settles at once, and resolution emails no one
    /// (it has no way to: it takes no notifier)
    #[allow(clippy::disallowed_methods)]
    #[tokio::test]
    async fn private_conversation_and_empty_links_resolve_at_once() {
        let db = reference_db();
        let dm = new_id();
        db.insert_channel(&Channel::DirectMessage {
            id: dm.clone(),
            active: true,
            recipients: vec![new_id(), new_id()],
            last_message_id: None,
        })
        .await
        .unwrap();

        let mut private = request(base());
        private.resolved = false;
        private.locations = vec![format!("https://app.sloga.gg/channel/{dm}/{}", new_id())];
        let private = insert(&db, private).await;

        let mut empty = request(base());
        empty.resolved = false;
        let empty = insert(&db, empty).await;

        assert_eq!(resolve_pending(&db).await.unwrap(), 2);
        assert_eq!(
            fetch(&db, &private.id).await.targets,
            [TakedownTarget::Unresolvable {
                location_index: 0,
                kind: UnresolvableKind::PrivateConversation,
            }]
        );
        let empty = fetch(&db, &empty.id).await;
        assert!(empty.resolved && empty.targets.is_empty());
        assert!(!has_marker(&empty, "resolve:try1"));
    }

    // Merging

    #[tokio::test]
    async fn requests_naming_the_same_file_are_linked_and_share_the_clock() {
        let db = reference_db();
        let file = attachment(&db, "attachments", None, false, false).await;

        let mut first = request(base());
        first.targets = vec![file_target(&file)];
        let first = insert(&db, first).await;

        let mut second = request(at_hours(10));
        second.targets = vec![file_target(&file)];
        let second = insert(&db, second).await;

        // Same unresolvable link: never merged
        let unresolvable = TakedownTarget::Unresolvable {
            location_index: 0,
            kind: UnresolvableKind::NotFound,
        };
        let mut third = request(at_hours(1));
        third.targets = vec![unresolvable.clone()];
        let third = insert(&db, third).await;
        let mut fourth = request(at_hours(2));
        fourth.targets = vec![unresolvable];
        let fourth = insert(&db, fourth).await;

        assert_eq!(merge_duplicates(&db).await.unwrap(), 2);

        let stored_first = fetch(&db, &first.id).await;
        let stored_second = fetch(&db, &second.id).await;
        assert_eq!(stored_first.linked_request_ids, [second.id.clone()]);
        assert_eq!(stored_second.linked_request_ids, [first.id.clone()]);
        assert_eq!(stored_first.deadline_at, first.deadline_at);
        assert_eq!(stored_second.deadline_at, first.deadline_at);

        for id in [&third.id, &fourth.id] {
            assert!(fetch(&db, id).await.linked_request_ids.is_empty());
        }

        assert_eq!(merge_duplicates(&db).await.unwrap(), 0);
        assert_eq!(
            count(
                &actions(&db, &second.id).await,
                StaffAuditAction::TakedownMerged
            ),
            1
        );
    }

    #[tokio::test]
    async fn requests_naming_an_encrypted_message_are_not_merged() {
        let db = reference_db();
        let encrypted = new_id();
        message(&db, &encrypted, vec![], true).await;
        let target = TakedownTarget::Message {
            channel: new_id(),
            message: encrypted,
        };

        let mut first = request(base());
        first.targets = vec![target.clone()];
        insert(&db, first).await;
        let mut second = request(at_hours(1));
        second.targets = vec![target];
        insert(&db, second).await;

        assert_eq!(merge_duplicates(&db).await.unwrap(), 0);
    }

    // Deadlines

    #[tokio::test]
    async fn deadline_met_or_missed_is_recorded_once() {
        let db = reference_db();

        let mut met = request(base());
        met.status = TakedownStatus::Removed;
        met.removed_at = Some(at_hours(47));
        let met = insert(&db, met).await;

        let mut missed = request(base());
        missed.status = TakedownStatus::Declined;
        missed.closed_at = Some(at_hours(49));
        let missed = insert(&db, missed).await;

        let open = insert(&db, request(base())).await;

        assert_eq!(record_deadlines(&db, at_hours(50)).await.unwrap(), 2);
        assert_eq!(record_deadlines(&db, at_hours(50)).await.unwrap(), 0);

        assert!(has_marker(&fetch(&db, &met.id).await, MARK_DEADLINE_MET));
        assert!(has_marker(
            &fetch(&db, &missed.id).await,
            MARK_DEADLINE_MISSED
        ));
        assert!(fetch(&db, &open.id).await.markers.is_empty());
        assert_eq!(
            actions(&db, &met.id).await,
            [StaffAuditAction::TakedownDeadlineMet]
        );
        assert_eq!(
            actions(&db, &missed.id).await,
            [StaffAuditAction::TakedownDeadlineMissed]
        );
    }

    // Write path

    /// Another writer landing between the read and the write: the change is
    /// re-applied on a fresh copy, and never written over the other's
    #[tokio::test]
    async fn lost_revision_race_is_retried_on_a_fresh_copy() {
        let db = reference_db();
        let r = insert(&db, request(base())).await;

        let mut attempts = 0;
        let write = update_request(&db, &r.id, |fresh| {
            attempts += 1;
            if attempts == 1 {
                let mut other = fresh.clone();
                other.bad_faith = true;
                futures::executor::block_on(db.replace_takedown_request(&mut other)).unwrap();
            }
            fresh.throttled = true;
            true
        })
        .await
        .unwrap();
        assert!(matches!(write, Write::Done(_)));
        assert_eq!(attempts, 2);

        let stored = fetch(&db, &r.id).await;
        assert!(stored.throttled);
        assert!(stored.bad_faith, "the other writer's change survives");
        assert_eq!(stored.revision, 2);
    }

    /// Losing every attempt leaves the change for the next tick
    #[tokio::test]
    async fn write_gives_up_after_three_lost_races() {
        let db = reference_db();
        let r = insert(&db, request(base())).await;

        let mut attempts = 0;
        let write = update_request(&db, &r.id, |fresh| {
            attempts += 1;
            let mut other = fresh.clone();
            futures::executor::block_on(db.replace_takedown_request(&mut other)).unwrap();
            fresh.throttled = true;
            true
        })
        .await
        .unwrap();
        assert!(matches!(write, Write::Contended));
        assert_eq!(attempts, WRITE_ATTEMPTS);
        assert!(!fetch(&db, &r.id).await.throttled);
    }

    #[test]
    fn heartbeat_key_names_the_iso_week() {
        let thursday = Timestamp::parse("2026-11-12T12:00:00Z").unwrap();
        assert_eq!(heartbeat_key(thursday), "takedown:heartbeat:2026-W46");

        // 1 January 2027 is in the last ISO week of 2026
        let new_year = Timestamp::parse("2027-01-01T00:00:00Z").unwrap();
        assert_eq!(heartbeat_key(new_year), "takedown:heartbeat:2026-W53");
    }

    #[test]
    fn merge_plans_cover_chains_of_shared_targets() {
        let mut a = request(base());
        a.id = "A".to_string();
        let mut b = request(at_hours(5));
        b.id = "B".to_string();
        let mut c = request(at_hours(9));
        c.id = "C".to_string();

        // A-B share x, B-C share y: one group
        let keys = vec![
            vec!["file:x".to_string()],
            vec!["file:x".to_string(), "file:y".to_string()],
            vec!["file:y".to_string()],
        ];
        let plans = plan_merges(&[a.clone(), b, c], &keys);
        assert_eq!(plans.len(), 3);
        for plan in &plans {
            assert_eq!(plan.deadline, a.deadline_at);
            assert_eq!(plan.link.len(), 2);
        }
        assert_eq!(plans[1].shared, ["x".to_string(), "y".to_string()]);
    }

    // Fix round (W2 audit)

    /// M3: removed but never closed still gets purged, counted from removal
    #[tokio::test]
    async fn removed_request_never_closed_is_purged_after_retention() {
        let db = reference_db();
        let cfg = cfg();

        let mut removed = request(base());
        removed.status = TakedownStatus::Removed;
        removed.removed_at = Some(at_hours(40));
        removed.locations = vec!["https://app.sloga.gg/channel/LOCATION".to_string()];
        removed.reviewer_note = Some("NOTE".to_string());
        let removed = insert(&db, removed).await;

        // Partly removed and never closed, but removed only recently
        let mut recent = request(base());
        recent.status = TakedownStatus::PartiallyRemoved;
        recent.removed_at = Some(at_hours(24 * 300));
        let recent = insert(&db, recent).await;

        // Still under review with a removal date: never purged
        let mut open = request(base());
        open.status = TakedownStatus::UnderReview;
        open.removed_at = Some(at_hours(40));
        let open = insert(&db, open).await;

        // One day short of retention: nothing
        let short = at_hours(40 + 24 * 364);
        assert_eq!(purge_requesters(&db, &cfg, short).await.unwrap(), 0);

        let now = at_hours(40 + 24 * 366);
        assert_eq!(purge_requesters(&db, &cfg, now).await.unwrap(), 1);

        let stored = fetch(&db, &removed.id).await;
        assert!(stored.requester_purged);
        assert_eq!(stored.sealed, "");
        assert!(stored.locations.is_empty());
        assert_eq!(stored.reviewer_note, None);
        assert_eq!(stored.status, TakedownStatus::Removed);

        for id in [&recent.id, &open.id] {
            let stored = fetch(&db, id).await;
            assert!(!stored.requester_purged);
            assert_eq!(stored.sealed, "SEALED");
        }

        assert_eq!(purge_requesters(&db, &cfg, now).await.unwrap(), 0);
        assert_eq!(
            count(
                &actions(&db, &removed.id).await,
                StaffAuditAction::TakedownRequesterPurged
            ),
            1
        );
    }

    /// M3: a hold ending on a request that was never closed closes it
    /// (Removed and PartiallyRemoved become Closed; a decline stays
    /// Declined), and an already-closed one keeps its date
    #[tokio::test]
    async fn hold_release_closes_requests_that_ended_unclosed() {
        let db = reference_db();
        let now = at_hours(24 * 40);

        let mut ids = Vec::new();
        for status in [
            TakedownStatus::Removed,
            TakedownStatus::PartiallyRemoved,
            TakedownStatus::Declined,
        ] {
            let file = attachment(&db, "attachments", None, false, true).await;
            let mut r = request(base());
            r.status = status;
            r.hold_until = Some(at_hours(24 * 31));
            r.held_files = vec![held(&file, false)];
            ids.push(insert(&db, r).await.id);
        }

        let file = attachment(&db, "attachments", None, false, true).await;
        let mut closed = request(base());
        closed.status = TakedownStatus::Removed;
        closed.closed_at = Some(at_hours(50));
        closed.hold_until = Some(at_hours(24 * 31));
        closed.held_files = vec![held(&file, false)];
        let closed = insert(&db, closed).await;

        assert_eq!(release_holds(&db, now, &take_free).await.unwrap(), 4);

        let statuses: Vec<(TakedownStatus, Option<Timestamp>)> = {
            let mut out = Vec::new();
            for id in &ids {
                let stored = fetch(&db, id).await;
                out.push((stored.status, stored.closed_at));
            }
            out
        };
        assert_eq!(
            statuses,
            [
                (TakedownStatus::Closed, Some(now)),
                (TakedownStatus::Closed, Some(now)),
                (TakedownStatus::Declined, Some(now)),
            ]
        );

        let stored = fetch(&db, &closed.id).await;
        assert_eq!(stored.status, TakedownStatus::Removed);
        assert_eq!(stored.closed_at, Some(at_hours(50)));
    }

    /// M5: over the threshold in the last hour, one alert per clock hour
    #[tokio::test]
    async fn volume_alarm_fires_once_per_hour_over_the_threshold() {
        let db = reference_db();
        let cfg = cfg();
        let notifier = Notifier::recorder();
        let claimed = std::sync::Mutex::new(HashSet::new());
        let fake_claim = |key: String| {
            let won = claimed.lock().unwrap().insert(key);
            async move { Ok::<_, revolt_result::Error>(won) }
        };

        let now = at_hours(10);
        let mut inserted = Vec::new();
        for minute in 0..VOLUME_ALARM_THRESHOLD as i64 {
            inserted
                .push(insert(&db, request(now.saturating_sub(Span::minutes(59 - minute)))).await);
        }
        let first = inserted[0].clone();

        // At the threshold: quiet
        assert!(!volume_alarm(&db, &cfg, &notifier, now, &fake_claim)
            .await
            .unwrap());
        assert!(notifier.sent().is_empty());
        assert!(claimed.lock().unwrap().is_empty());

        // One over: one alert, fixed text, earliest deadline, no reference
        insert(&db, request(now.saturating_sub(Span::minutes(1)))).await;
        assert!(volume_alarm(&db, &cfg, &notifier, now, &fake_claim)
            .await
            .unwrap());
        assert_eq!(
            notifier.sent(),
            [format!(
                "Take It Down queue: {VOLUME_SUMMARY}. Deadline {}.",
                first.deadline_at
            )]
        );

        // Same hour, all 21 still in the window: the hour is claimed already
        let later = now.saturating_add(Span::seconds(30));
        assert!(!volume_alarm(&db, &cfg, &notifier, later, &fake_claim)
            .await
            .unwrap());
        assert_eq!(notifier.sent().len(), 1);
        assert_eq!(claimed.lock().unwrap().len(), 1);

        // Next hour, still busy: a new alert
        let next_hour = now.saturating_add(Span::minutes(61));
        for minute in 0..=VOLUME_ALARM_THRESHOLD as i64 {
            insert(
                &db,
                request(next_hour.saturating_sub(Span::minutes(minute))),
            )
            .await;
        }
        assert!(volume_alarm(&db, &cfg, &notifier, next_hour, &fake_claim)
            .await
            .unwrap());
        assert_eq!(notifier.sent().len(), 2);
        assert_eq!(claimed.lock().unwrap().len(), 2);
    }

    #[test]
    fn volume_key_names_the_utc_hour() {
        let at = Timestamp::parse("2026-11-12T09:59:59Z").unwrap();
        assert_eq!(volume_key(at), "takedown:volume:2026-11-12T09");
        let at = Timestamp::parse("2027-01-01T00:00:00Z").unwrap();
        assert_eq!(volume_key(at), "takedown:volume:2027-01-01T00");
    }

    /// Minor 4: a contact with any bad-faith request on record never
    /// auto-hides
    #[tokio::test]
    async fn auto_hide_skips_contacts_with_a_bad_faith_request() {
        let db = reference_db();
        let cfg = cfg();

        let mut old = request(at_hours(-24 * 200));
        old.contact_fp = "fp-bad".to_string();
        old.status = TakedownStatus::Declined;
        old.bad_faith = true;
        old.closed_at = Some(at_hours(-24 * 199));
        insert(&db, old).await;

        let file = attachment(&db, "attachments", None, false, false).await;
        let mut r = request(base());
        r.contact_fp = "fp-bad".to_string();
        r.targets = vec![file_target(&file)];
        let r = insert(&db, r).await;

        let good_file = attachment(&db, "attachments", None, false, false).await;
        let mut good = request(base());
        good.contact_fp = "fp-good".to_string();
        good.targets = vec![file_target(&good_file)];
        insert(&db, good).await;

        assert_eq!(
            auto_hide(&db, &cfg, at_hours(45), &take_free)
                .await
                .unwrap(),
            1
        );

        let row = file_row(&db, &file.id).await;
        assert_eq!((row.deleted, row.reported), (None, None));
        let stored = fetch(&db, &r.id).await;
        assert!(!has_marker(&stored, MARK_AUTOHIDE));
        assert!(stored.held_files.is_empty());

        let row = file_row(&db, &good_file.id).await;
        assert_eq!((row.deleted, row.reported), (Some(true), Some(true)));
    }

    /// Minor 3: a decline that raced in between the record and the hide is
    /// honored; files any request still holds stay hidden
    #[tokio::test]
    async fn raced_decline_is_undone_after_the_hide() {
        let db = reference_db();

        // As the hide left them: all hidden. `dropped` and
        // `dropped_reported` are still shown by their message; the uploader
        // deleted the message of `parent_deleted` meanwhile.
        let shown_id = new_id();
        let dropped = attachment(&db, "attachments", Some(&shown_id), true, true).await;
        let dropped_reported = attachment(&db, "attachments", Some(&shown_id), true, true).await;
        message(
            &db,
            &shown_id,
            vec![dropped.clone(), dropped_reported.clone()],
            false,
        )
        .await;
        let parent_deleted = attachment(&db, "attachments", Some(&new_id()), true, true).await;
        let kept = attachment(&db, "attachments", None, true, true).await;
        let removed = attachment(&db, "attachments", None, true, true).await;
        let elsewhere = attachment(&db, "attachments", None, true, true).await;
        let recorded = vec![
            held(&dropped, false),
            held(&dropped_reported, true),
            held(&parent_deleted, false),
            held(&kept, false),
            held(&removed, false),
            held(&elsewhere, false),
        ];

        // The request after the decline raced in: only `kept` is still
        // auto-hidden; `removed` is still held (a reviewer removed it)
        let mut r = request(base());
        r.auto_hidden_file_ids = vec![kept.id.clone()];
        r.held_files = vec![held(&kept, false), held(&removed, false)];
        let r = insert(&db, r).await;

        // Another request holds `elsewhere`
        let mut other = request(base());
        other.status = TakedownStatus::Removed;
        other.held_files = vec![held(&elsewhere, false)];
        insert(&db, other).await;

        let undone = undo_raced_hides(&db, &r.id, &recorded, &StepLock::free())
            .await
            .unwrap();
        assert_eq!(
            undone.dropped,
            [
                dropped.id.clone(),
                dropped_reported.id.clone(),
                parent_deleted.id.clone(),
                removed.id.clone(),
                elsewhere.id.clone(),
            ]
        );
        assert_eq!(
            undone.shown,
            [dropped.id.clone(), dropped_reported.id.clone()]
        );

        let row = file_row(&db, &dropped.id).await;
        assert_eq!((row.deleted, row.reported), (Some(false), Some(false)));
        // Reported before the hide: shown, still reported
        let row = file_row(&db, &dropped_reported.id).await;
        assert_eq!((row.deleted, row.reported), (Some(false), Some(true)));
        // Its message was deleted: stays deleted, left to the sweep
        let row = file_row(&db, &parent_deleted.id).await;
        assert_eq!((row.deleted, row.reported), (Some(true), Some(false)));
        for file in [&kept, &removed, &elsewhere] {
            let row = file_row(&db, &file.id).await;
            assert_eq!((row.deleted, row.reported), (Some(true), Some(true)));
        }

        // Nothing raced: nothing undone
        let mut calm = request(base());
        calm.auto_hidden_file_ids = vec![kept.id.clone()];
        let calm = insert(&db, calm).await;
        let undone = undo_raced_hides(&db, &calm.id, &[held(&kept, false)], &StepLock::free())
            .await
            .unwrap();
        assert!(undone.dropped.is_empty() && undone.shown.is_empty());
    }

    /// A file in `unhide` whose parent no longer shows it ends hidden (even
    /// if something left it live) and is released to the sweep; one still
    /// shown is shown. The re-check after the unhide closes a race window
    /// this sequential test can't open; it uses the same `still_shown`.
    #[tokio::test]
    async fn apply_release_hides_again_what_is_no_longer_shown() {
        let db = reference_db();

        let shown_id = new_id();
        let shown = attachment(&db, "attachments", Some(&shown_id), true, true).await;
        message(&db, &shown_id, vec![shown.clone()], false).await;

        // Hidden, but un-hidden by a failed earlier attempt, and its parent
        // is gone: must end hidden
        let gone = attachment(&db, "attachments", Some(&new_id()), true, false).await;

        let plan = ReleasePlan {
            unhide: vec![shown.id.clone(), gone.id.clone()],
            keep_hidden: vec![],
            release: vec![shown.id.clone(), gone.id.clone()],
        };
        let applied = apply_release(&db, &plan, &StepLock::free())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(applied.shown, [shown.id.clone()]);
        assert!(applied.unsure.is_empty());
        assert_eq!(applied.released, [shown.id.clone(), gone.id.clone()]);

        let row = file_row(&db, &shown.id).await;
        assert_eq!((row.deleted, row.reported), (Some(false), Some(false)));
        let row = file_row(&db, &gone.id).await;
        assert_eq!((row.deleted, row.reported), (Some(true), Some(false)));
    }

    // Takedown mutex

    impl StepLock {
        /// A fake lock that stays held
        fn free() -> Self {
            StepLock::Fake(Default::default())
        }

        /// A fake lock that reports held for `checks` checks, then lost
        fn held_for(checks: usize) -> (Self, std::sync::Arc<FakeLock>) {
            let fake = std::sync::Arc::new(FakeLock {
                held_checks: Some(checks),
                ..Default::default()
            });
            (StepLock::Fake(fake.clone()), fake)
        }
    }

    async fn take_free() -> Result<Option<StepLock>> {
        Ok(Some(StepLock::free()))
    }

    fn load(counter: &std::sync::atomic::AtomicUsize) -> usize {
        counter.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// One request due for auto-hide and one whose hold has ended, at hour 45
    async fn mutex_fixture(db: &Database) -> (TakedownRequest, File, TakedownRequest, File) {
        let to_hide = attachment(db, "attachments", None, false, false).await;
        let mut auto = request(base());
        auto.targets = vec![file_target(&to_hide)];
        let auto = insert(db, auto).await;

        let held_file = attachment(db, "attachments", None, true, true).await;
        let mut ended = request(base());
        ended.status = TakedownStatus::Removed;
        ended.closed_at = Some(at_hours(1));
        ended.hold_until = Some(at_hours(44));
        ended.held_files = vec![held(&held_file, false)];
        let ended = insert(db, ended).await;

        (auto, to_hide, ended, held_file)
    }

    /// Busy, or Redis down: auto-hide and hold release change nothing this
    /// tick; the steps that never touch files still run
    #[tokio::test]
    async fn busy_or_unavailable_mutex_skips_the_file_steps() {
        let busy = || async { Ok::<Option<StepLock>, revolt_result::Error>(None) };
        let down = || async { Err::<Option<StepLock>, _>(create_error!(InternalError)) };

        for (label, is_busy) in [("busy", true), ("down", false)] {
            let db = reference_db();
            let cfg = cfg();
            let notifier = Notifier::recorder();
            let (auto, to_hide, ended, held_file) = mutex_fixture(&db).await;

            if is_busy {
                tick(&db, &cfg, &notifier, at_hours(45), &busy).await;
            } else {
                tick(&db, &cfg, &notifier, at_hours(45), &down).await;
            }

            // Auto-hide skipped: file live, marker not spent
            let row = file_row(&db, &to_hide.id).await;
            assert_eq!((row.deleted, row.reported), (None, None), "{label}");
            let stored = fetch(&db, &auto.id).await;
            assert!(!has_marker(&stored, MARK_AUTOHIDE), "{label}");
            assert!(stored.held_files.is_empty(), "{label}");

            // Hold release skipped: file still held and kept
            let row = file_row(&db, &held_file.id).await;
            assert_eq!(
                (row.deleted, row.reported),
                (Some(true), Some(true)),
                "{label}"
            );
            let stored = fetch(&db, &ended.id).await;
            assert_eq!(stored.held_files.len(), 1, "{label}");
            assert_eq!(stored.hold_until, Some(at_hours(44)), "{label}");

            // The other steps ran: the open request got its alert
            assert_eq!(
                notifier.sent(),
                [alert_text(&auto, "4 hours left")],
                "{label}"
            );
        }
    }

    /// Free: both file steps run, the mutex taken and released once per
    /// request
    #[tokio::test]
    async fn free_mutex_runs_the_file_steps_one_request_at_a_time() {
        let db = reference_db();
        let cfg = cfg();
        let notifier = Notifier::recorder();
        let (auto, to_hide, ended, held_file) = mutex_fixture(&db).await;

        // A second request due for auto-hide: its own hold of the mutex
        let second_file = attachment(&db, "attachments", None, false, false).await;
        let mut second = request(at_minutes(1));
        second.contact_fp = "fp-b".to_string();
        second.targets = vec![file_target(&second_file)];
        insert(&db, second).await;

        let shared = std::sync::Arc::new(FakeLock::default());
        let taken = std::sync::atomic::AtomicUsize::new(0);
        let free = || {
            taken.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let shared = shared.clone();
            async move { Ok::<_, revolt_result::Error>(Some(StepLock::Fake(shared))) }
        };

        tick(&db, &cfg, &notifier, at_hours(45), &free).await;

        for file in [&to_hide, &second_file] {
            let row = file_row(&db, &file.id).await;
            assert_eq!((row.deleted, row.reported), (Some(true), Some(true)));
        }
        assert!(has_marker(&fetch(&db, &auto.id).await, MARK_AUTOHIDE));

        let row = file_row(&db, &held_file.id).await;
        assert_eq!((row.deleted, row.reported), (Some(true), Some(false)));
        let stored = fetch(&db, &ended.id).await;
        assert!(stored.held_files.is_empty());
        assert_eq!(stored.hold_until, None);

        // Two auto-hides and one hold release: three holds, three releases
        assert_eq!(load(&taken), 3);
        assert_eq!(load(&shared.released), 3);
    }

    /// Auto-hide: the mutex lost after the hide, before the race check. The
    /// files stay hidden and recorded; nothing is unhidden or released.
    #[tokio::test]
    async fn lost_mutex_after_the_hide_keeps_files_hidden_and_recorded() {
        let db = reference_db();
        let cfg = cfg();
        let file = attachment(&db, "attachments", None, false, false).await;
        let mut r = request(base());
        r.targets = vec![file_target(&file)];
        let r = insert(&db, r).await;

        // Held for: the claim, the record save, the hide. Lost at the race
        // check.
        let (lock, fake) = StepLock::held_for(3);
        let hour = config_hours(cfg.auto_hide_hour);
        let snapshot = fetch(&db, &r.id).await;
        assert!(
            auto_hide_request(&db, &cfg, &snapshot, hour, at_hours(45), &lock)
                .await
                .unwrap()
        );
        assert_eq!(load(&fake.checks), 4);

        let row = file_row(&db, &file.id).await;
        assert_eq!((row.deleted, row.reported), (Some(true), Some(true)));
        let stored = fetch(&db, &r.id).await;
        assert_eq!(stored.held_files, [held(&file, false)]);
        assert_eq!(stored.auto_hidden_file_ids, [file.id.clone()]);
        assert!(has_marker(&stored, MARK_AUTOHIDE));
    }

    /// Auto-hide: lost before the marker or before the hide changes no file
    #[tokio::test]
    async fn lost_mutex_before_the_hide_hides_nothing() {
        for (checks, marker_spent) in [(0, false), (1, true), (2, true)] {
            let db = reference_db();
            let cfg = cfg();
            let file = attachment(&db, "attachments", None, false, false).await;
            let mut r = request(base());
            r.targets = vec![file_target(&file)];
            let r = insert(&db, r).await;

            let (lock, _) = StepLock::held_for(checks);
            let hour = config_hours(cfg.auto_hide_hour);
            let snapshot = fetch(&db, &r.id).await;
            assert!(
                !auto_hide_request(&db, &cfg, &snapshot, hour, at_hours(45), &lock)
                    .await
                    .unwrap(),
                "{checks}"
            );

            let row = file_row(&db, &file.id).await;
            assert_eq!((row.deleted, row.reported), (None, None), "{checks}");
            let stored = fetch(&db, &r.id).await;
            assert_eq!(has_marker(&stored, MARK_AUTOHIDE), marker_spent, "{checks}");
            // Recorded only when the loss came after the record save
            assert_eq!(
                stored.held_files.len(),
                usize::from(checks == 2),
                "{checks}"
            );
        }
    }

    /// Hold release: the mutex lost after the files came off the request,
    /// before the unhide (2 checks held) or after it, before the release (3
    /// checks held). Every file ends hidden and reported, the records and
    /// hold end go back on the request, nothing is released or audited.
    #[tokio::test]
    async fn lost_mutex_mid_release_puts_everything_back() {
        for checks in [2, 3] {
            let db = reference_db();

            // Auto-hidden and still shown (would be shown again), and one
            // a removal holds (would be released to the sweep)
            let message_id = new_id();
            let auto_file = attachment(&db, "attachments", Some(&message_id), true, true).await;
            message(&db, &message_id, vec![auto_file.clone()], false).await;
            let removed = attachment(&db, "attachments", None, true, true).await;

            let mut ended = request(base());
            ended.status = TakedownStatus::Removed;
            ended.closed_at = Some(at_hours(1));
            ended.hold_until = Some(at_hours(44));
            ended.held_files = vec![held(&auto_file, false), held(&removed, false)];
            ended.auto_hidden_file_ids = vec![auto_file.id.clone()];
            let ended = insert(&db, ended).await;

            let (lock, fake) = StepLock::held_for(checks);
            assert!(
                !release_hold(&db, &ended.id, &HashSet::new(), at_hours(45), &lock)
                    .await
                    .unwrap(),
                "{checks}"
            );
            assert_eq!(load(&fake.checks), checks + 1, "{checks}");

            for file in [&auto_file, &removed] {
                let row = file_row(&db, &file.id).await;
                assert_eq!(
                    (row.deleted, row.reported),
                    (Some(true), Some(true)),
                    "{checks}"
                );
            }

            let stored = fetch(&db, &ended.id).await;
            assert_eq!(
                stored.held_files,
                [held(&auto_file, false), held(&removed, false)],
                "{checks}"
            );
            assert_eq!(
                stored.auto_hidden_file_ids,
                [auto_file.id.clone()],
                "{checks}"
            );
            assert_eq!(stored.hold_until, Some(at_hours(44)), "{checks}");
            assert!(actions(&db, &ended.id).await.is_empty(), "{checks}");

            // With the mutex back, the next tick finishes the job
            assert!(release_hold(
                &db,
                &ended.id,
                &HashSet::new(),
                at_hours(46),
                &StepLock::free()
            )
            .await
            .unwrap());
            let row = file_row(&db, &auto_file.id).await;
            assert_eq!((row.deleted, row.reported), (Some(false), Some(false)));
            let row = file_row(&db, &removed.id).await;
            assert_eq!((row.deleted, row.reported), (Some(true), Some(false)));
        }
    }

    /// Hold release: lost before anything, nothing changes at all
    #[tokio::test]
    async fn lost_mutex_before_the_release_changes_nothing() {
        let db = reference_db();
        let (_, _, ended, held_file) = mutex_fixture(&db).await;

        let (lock, _) = StepLock::held_for(0);
        assert!(
            !release_hold(&db, &ended.id, &HashSet::new(), at_hours(45), &lock)
                .await
                .unwrap()
        );

        let stored = fetch(&db, &ended.id).await;
        assert_eq!(stored, ended);
        let row = file_row(&db, &held_file.id).await;
        assert_eq!((row.deleted, row.reported), (Some(true), Some(true)));
    }
}
