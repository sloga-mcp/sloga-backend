//! Take It Down removals: hide the files a reviewer picked and every
//! identical copy, take them out of the places that show them, and block
//! re-uploads.
//!
//! A removed file is put in the hidden-but-kept state (`deleted` and
//! `reported`): the upload server stops serving it at once and the deletion
//! sweep skips it until the request's hold ends. Each file's flags from
//! before are recorded on the request first (`held_files`), so an unhide or
//! a hold release never touches a file that was already deleted or reported.
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, LazyLock, OnceLock,
    },
    time::Duration,
};

use iso8601_timestamp::Timestamp;
use redis_kiss::{
    get_connection,
    redis::{cmd, Script},
};
use revolt_result::{Error, ErrorType, Result};

use crate::{
    events::client::EventV1, upload_hash_block_key, AuditLogAction, AuditLogChange, AuditLogDraft,
    AuditLogEntry, AuditValue, Database, EmojiParent, FieldsServer, FieldsUser, File,
    FileUsedForType, HeldFile, Message, PartialMessage, PartialServer, PartialUser,
    ProtectedReadView, TakedownRequest, TakedownTarget, UploadHashBlock,
};

/// What a reviewer chose to remove
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalPlan {
    /// Indexes into `TakedownRequest.targets`
    pub targets: Vec<usize>,
    pub whole_message: bool,
    pub include_copies: bool,
    pub block_reuploads: bool,
}

/// What a removal did
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemovalOutcome {
    pub removed_files: Vec<String>,
    pub deleted_messages: Vec<String>,
    pub copies: u64,
    pub blocked_keys: Vec<String>,
    pub uploader_ids: Vec<String>,
}

/// Redis key of the takedown mutex
const MUTEX_KEY: &str = "takedown:mutex";
/// How often a waiting caller tries again
const MUTEX_POLL: Duration = Duration::from_millis(100);
/// Bound on one Redis round trip; a slower one is an error
const MUTEX_OP_TIMEOUT: Duration = Duration::from_secs(2);
/// Renewal stops after this long in all; the holder then counts as having
/// lost the mutex and must stop
const MUTEX_MAX_HOLD: Duration = Duration::from_secs(15 * 60);

/// Expiry of a hold (renewed while the guard lives), how often the
/// renewal extends it, and how long `acquire_takedown_mutex` waits. Atomics
/// only so tests can shorten them.
static MUTEX_TTL_MS: AtomicU64 = AtomicU64::new(120_000);
static MUTEX_RENEW_MS: AtomicU64 = AtomicU64::new(30_000);
static MUTEX_WAIT_MS: AtomicU64 = AtomicU64::new(10_000);

/// `KEYS[1]` the mutex key; `ARGV[1]` our token. Deletes only our own hold.
const MUTEX_RELEASE_LUA: &str = concat!(
    "if redis.call('GET', KEYS[1]) == ARGV[1] then\n",
    "  return redis.call('DEL', KEYS[1])\n",
    "end\n",
    "return 0\n",
);

/// `KEYS[1]` the mutex key; `ARGV[1]` our token, `ARGV[2]` the expiry in
/// milliseconds. Extends only our own hold: 1 when extended, 0 when the
/// key is gone or someone else's.
const MUTEX_RENEW_LUA: &str = concat!(
    "if redis.call('GET', KEYS[1]) == ARGV[1] then\n",
    "  return redis.call('PEXPIRE', KEYS[1], ARGV[2])\n",
    "end\n",
    "return 0\n",
);

/// `Script` sends EVALSHA and loads the source on NOSCRIPT
static MUTEX_RELEASE: LazyLock<Script> = LazyLock::new(|| Script::new(MUTEX_RELEASE_LUA));
static MUTEX_RENEW: LazyLock<Script> = LazyLock::new(|| Script::new(MUTEX_RENEW_LUA));

static MUTEX_KEY_OVERRIDE: OnceLock<String> = OnceLock::new();

/// For test processes that share one Redis: use a mutex key of their own
/// (first call wins, once per process). Production never calls this.
#[doc(hidden)]
pub fn use_takedown_mutex_key(key: String) {
    let _ = MUTEX_KEY_OVERRIDE.set(key);
}

/// For tests: a shorter hold expiry, renewal interval and acquire wait
/// (defaults 120 s, 30 s and 10 s). Production never calls this.
#[doc(hidden)]
pub fn set_takedown_mutex_timing(ttl: Duration, renew_every: Duration, wait: Duration) {
    MUTEX_TTL_MS.store(ttl.as_millis() as u64, Ordering::SeqCst);
    MUTEX_RENEW_MS.store(renew_every.as_millis() as u64, Ordering::SeqCst);
    MUTEX_WAIT_MS.store(wait.as_millis() as u64, Ordering::SeqCst);
}

fn mutex_key() -> &'static str {
    MUTEX_KEY_OVERRIDE.get().map_or(MUTEX_KEY, String::as_str)
}

/// The answer when the takedown mutex stays busy, or was lost while held:
/// try again
pub fn takedown_busy() -> Error {
    create_error!(FailedValidation {
        error: "TakedownBusy".to_string()
    })
}

/// A Redis failure: logged by kind, `InternalError` to the caller
fn redis_failed(what: &str, error: impl std::fmt::Debug) -> Error {
    error!("Take It Down mutex: {what} failed: {error:?}");
    create_error!(InternalError)
}

/// `SET key token NX PX ttl`: whether we took it
async fn take_mutex(key: &str, token: &str) -> Result<bool> {
    let ttl_ms = MUTEX_TTL_MS.load(Ordering::SeqCst);
    let work = async {
        let mut conn = get_connection()
            .await
            .map_err(|error| redis_failed("connect", error))?
            .into_inner();
        let set: Option<String> = cmd("SET")
            .arg(key)
            .arg(token)
            .arg("NX")
            .arg("PX")
            .arg(ttl_ms)
            .query_async(&mut conn)
            .await
            .map_err(|error| redis_failed("take", error))?;
        Ok::<bool, Error>(set.is_some())
    };

    tokio::time::timeout(MUTEX_OP_TIMEOUT, work)
        .await
        .unwrap_or_else(|_| Err(redis_failed("take", "timed out")))
}

/// Run one of the mutex scripts on `key` with `args`, bounded
async fn run_mutex_script(script: &Script, what: &str, key: &str, args: &[&str]) -> Result<i64> {
    let work = async {
        let mut conn = get_connection()
            .await
            .map_err(|error| redis_failed("connect", error))?
            .into_inner();
        let mut invocation = script.prepare_invoke();
        invocation.key(key);
        for arg in args {
            invocation.arg(*arg);
        }
        invocation
            .invoke_async::<_, i64>(&mut conn)
            .await
            .map_err(|error| redis_failed(what, error))
    };

    tokio::time::timeout(MUTEX_OP_TIMEOUT, work)
        .await
        .unwrap_or_else(|_| Err(redis_failed(what, "timed out")))
}

/// Compare-and-delete: frees the mutex only while `token` holds it
async fn release_mutex(key: &str, token: &str) -> Result<()> {
    run_mutex_script(&MUTEX_RELEASE, "release", key, &[token])
        .await
        .map(|_| ())
}

/// Compare-and-PEXPIRE: whether `token` still held the mutex (now extended)
async fn renew_mutex(key: &str, token: &str) -> Result<bool> {
    let ttl_ms = MUTEX_TTL_MS.load(Ordering::SeqCst).to_string();
    Ok(run_mutex_script(&MUTEX_RENEW, "renew", key, &[token, &ttl_ms]).await? == 1)
}

/// The renewal loop of one hold: extends it every renewal interval while
/// the token still holds it. Sets `lost` when the token is gone, after two
/// failed renewals in a row, or at the 15 minute cap, and stops.
async fn renew_while_held(key: &'static str, token: String, lost: Arc<AtomicBool>) {
    let started = tokio::time::Instant::now();
    let mut failures = 0;
    loop {
        tokio::time::sleep(Duration::from_millis(MUTEX_RENEW_MS.load(Ordering::SeqCst))).await;

        if started.elapsed() >= MUTEX_MAX_HOLD {
            warn!("Take It Down mutex: held for 15 minutes; renewal stops and the holder stops");
            lost.store(true, Ordering::SeqCst);
            return;
        }

        match renew_mutex(key, &token).await {
            Ok(true) => failures = 0,
            Ok(false) => {
                warn!("Take It Down mutex: the hold is gone; the holder stops");
                lost.store(true, Ordering::SeqCst);
                return;
            }
            Err(_) => {
                failures += 1;
                if failures >= 2 {
                    warn!("Take It Down mutex: two renewals failed; the holder stops");
                    lost.store(true, Ordering::SeqCst);
                    return;
                }
            }
        }
    }
}

/// A hold on the takedown mutex.
///
/// While it lives, a renewal task extends the hold every 30 s (compare on
/// our token). Check [`Self::is_held`] before every batch of file-state
/// writes and before a save: it turns false when the hold is gone, two
/// renewals failed, or 15 minutes passed, and the holder must then stop
/// (hide again what it showed or hid, and answer [`takedown_busy`]).
///
/// Release it with [`Self::release`]. A guard dropped without that (an
/// early return, a panic, a cancelled release) stops the renewal and
/// releases in a spawned task; a holder that dies frees it when the hold
/// expires.
#[must_use = "the mutex is held only while the guard lives"]
pub struct TakedownMutexGuard {
    key: &'static str,
    token: String,
    released: bool,
    lost: Arc<AtomicBool>,
    renewal: Option<tokio::task::JoinHandle<()>>,
}

impl TakedownMutexGuard {
    fn new(key: &'static str, token: String) -> TakedownMutexGuard {
        let lost = Arc::new(AtomicBool::new(false));
        let renewal = tokio::runtime::Handle::try_current()
            .ok()
            .map(|handle| handle.spawn(renew_while_held(key, token.clone(), lost.clone())));

        TakedownMutexGuard {
            key,
            token,
            released: false,
            lost,
            renewal,
        }
    }

    /// Whether this guard still holds the mutex, as far as the renewal
    /// knows. False once the hold is gone, two renewals in a row failed, or
    /// 15 minutes passed; then stop changing anything.
    pub fn is_held(&self) -> bool {
        !self.released && !self.lost.load(Ordering::SeqCst)
    }

    /// Stop the renewal and release the mutex (compare-and-delete on our
    /// token). A failure is logged; the hold then expires on its own. The
    /// guard counts as released only once the call returned, so a release
    /// that is cancelled still falls back to the drop.
    pub async fn release(mut self) {
        if let Some(renewal) = self.renewal.take() {
            renewal.abort();
        }
        if let Err(error) = release_mutex(self.key, &self.token).await {
            error!("Take It Down mutex: not released, it expires on its own: {error:?}");
        }
        self.released = true;
    }
}

impl Drop for TakedownMutexGuard {
    fn drop(&mut self) {
        if let Some(renewal) = self.renewal.take() {
            renewal.abort();
        }
        if self.released {
            return;
        }

        let key = self.key;
        let token = std::mem::take(&mut self.token);
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    if let Err(error) = release_mutex(key, &token).await {
                        error!(
                            "Take It Down mutex: not released, it expires on its own: {error:?}"
                        );
                    }
                });
            }
            Err(_) => warn!("Take It Down mutex: dropped outside a runtime; it expires on its own"),
        }
    }
}

/// Take the takedown mutex if it is free, without waiting (for crond: skip
/// the tick when busy). `Ok(None)` = someone else holds it; `Err` = Redis
/// could not answer (`InternalError`), so nothing may change.
///
/// Every change to a takedown request's file state (hide, unhide, release,
/// taking a file out of a message, profile or server) and every save of a
/// request that goes with it runs under this mutex, in delta and crond.
pub async fn try_takedown_mutex() -> Result<Option<TakedownMutexGuard>> {
    let key = mutex_key();
    let token = ulid::Ulid::new().to_string();
    Ok(if take_mutex(key, &token).await? {
        Some(TakedownMutexGuard::new(key, token))
    } else {
        None
    })
}

/// Take the takedown mutex, trying every 100 ms for up to 10 s; still busy
/// then = [`takedown_busy`] (`FailedValidation { error: "TakedownBusy" }`)
pub async fn acquire_takedown_mutex() -> Result<TakedownMutexGuard> {
    let wait = Duration::from_millis(MUTEX_WAIT_MS.load(Ordering::SeqCst));
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        if let Some(guard) = try_takedown_mutex().await? {
            return Ok(guard);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(takedown_busy());
        }
        tokio::time::sleep(MUTEX_POLL).await;
    }
}

/// Run `f` under the takedown mutex ([`acquire_takedown_mutex`]), releasing
/// it afterwards whatever `f` returns. `f` can't see the guard, so it can't
/// check [`TakedownMutexGuard::is_held`]: use it for short work only, and
/// the guard API for anything that may run long.
pub async fn with_takedown_mutex<T, F, Fut>(f: F) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let guard = acquire_takedown_mutex().await?;
    let result = f().await;
    guard.release().await;
    result
}

/// Where a file is shown, and so what has to change there when it goes
#[derive(Debug, Clone, PartialEq, Eq)]
enum Parent {
    Message(String),
    UserAvatar(String),
    UserBackground(String),
    ServerIcon(String),
    ServerBanner(String),
    Emoji(String),
    Sticker(String),
}

/// The files one target shows, and where
#[derive(Default)]
struct Gathered {
    /// Stored rows as they are before anything changes
    files: Vec<File>,
    /// `(where, file id)`, also for files whose row is missing
    parents: Vec<(Parent, String)>,
    /// The message itself, for a message target
    message: Option<String>,
}

impl Gathered {
    /// Add a file shown at `parent`
    async fn add(&mut self, db: &Database, id: &str, parent: Parent) -> Result<()> {
        push_unique(&mut self.parents, (parent, id.to_string()));
        if let Some(row) = stored_row(db, id).await? {
            if !self.files.iter().any(|file| file.id == row.id) {
                self.files.push(row);
            }
        }
        Ok(())
    }
}

/// Hashes that are the same image as some files, and the keys that block it
#[derive(Default)]
struct SameImage {
    /// Original hashes (`attachments.hash`)
    originals: Vec<String>,
    /// `upload_hash_blocks` keys
    keys: Vec<String>,
}

fn push_unique<T: PartialEq>(list: &mut Vec<T>, value: T) {
    if !list.contains(&value) {
        list.push(value);
    }
}

/// Whether an error only says the object is already gone
fn is_gone(error: &Error) -> bool {
    matches!(
        error.error_type,
        ErrorType::NotFound
            | ErrorType::UnknownUser
            | ErrorType::UnknownServer
            | ErrorType::UnknownChannel
            | ErrorType::UnknownMessage
            | ErrorType::UnknownAttachment
    )
}

fn is_live(file: &File) -> bool {
    file.deleted != Some(true)
}

/// Where a file row says it is used
fn parent_of(file: &File) -> Option<Parent> {
    let used_for = file.used_for.as_ref()?;
    let id = used_for.id.clone();
    match used_for.object_type {
        FileUsedForType::Message => Some(Parent::Message(id)),
        FileUsedForType::UserAvatar => Some(Parent::UserAvatar(id)),
        FileUsedForType::UserProfileBackground => Some(Parent::UserBackground(id)),
        FileUsedForType::ServerIcon => Some(Parent::ServerIcon(id)),
        FileUsedForType::ServerBanner => Some(Parent::ServerBanner(id)),
        FileUsedForType::Emoji => Some(Parent::Emoji(id)),
        FileUsedForType::Sticker => Some(Parent::Sticker(id)),
        // Webhook avatars, role, channel and group icons, badges, sounds and
        // calendar images: the hidden file is simply no longer served
        _ => None,
    }
}

/// The stored row of a file, `None` if there is none
async fn stored_row(db: &Database, id: &str) -> Result<Option<File>> {
    match db.fetch_attachment_by_id(id).await {
        Ok(row) => Ok(Some(row)),
        Err(error) if is_gone(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

/// `Some` for a found object, `None` when it is gone
fn found<T>(result: Result<T>) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if is_gone(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Whether a file's `used_for` parent still exists and still shows it: the
/// message still lists it, the avatar, background, icon or banner still
/// points at it, the emoji is still a server's, the sticker still uses it.
/// Showing a file again is only safe then: the upload server serves any
/// file that is not `deleted`, so un-hiding a file whose parent was deleted
/// would publish it again. A file with no parent, or one used where this
/// can't be checked (webhook avatars, role, channel and group icons,
/// badges, sounds, calendar images), counts as not shown.
pub async fn still_shown(db: &Database, file_id: &str) -> Result<bool> {
    let Some(row) = stored_row(db, file_id).await? else {
        return Ok(false);
    };
    let Some(parent) = parent_of(&row) else {
        return Ok(false);
    };

    Ok(match &parent {
        Parent::Message(id) => found(db.fetch_message(id).await)?.is_some_and(|message| {
            let files = message_files(&message);
            files.iter().any(|file| file.id == file_id)
        }),
        Parent::UserAvatar(id) => found(db.fetch_user(id).await)?
            .is_some_and(|user| user.avatar.as_ref().is_some_and(|file| file.id == file_id)),
        Parent::UserBackground(id) => found(db.fetch_user(id).await)?.is_some_and(|user| {
            user.profile
                .as_ref()
                .and_then(|profile| profile.background.as_ref())
                .is_some_and(|file| file.id == file_id)
        }),
        Parent::ServerIcon(id) => found(db.fetch_server(id).await)?
            .is_some_and(|server| server.icon.as_ref().is_some_and(|file| file.id == file_id)),
        Parent::ServerBanner(id) => found(db.fetch_server(id).await)?.is_some_and(|server| {
            server
                .banner
                .as_ref()
                .is_some_and(|file| file.id == file_id)
        }),
        Parent::Emoji(id) => found(db.fetch_emoji(id).await)?.is_some_and(|emoji| {
            emoji.id == file_id && matches!(emoji.parent, EmojiParent::Server { .. })
        }),
        Parent::Sticker(id) => {
            found(db.fetch_sticker(id).await)?.is_some_and(|sticker| sticker.file_id == file_id)
        }
    })
}

/// Every file a message shows: its attachments and a forwarded snapshot's
pub fn message_files(message: &Message) -> Vec<&File> {
    message
        .attachments
        .iter()
        .flatten()
        .chain(
            message
                .forwarded
                .iter()
                .flat_map(|forwarded| forwarded.attachments.iter()),
        )
        .collect()
}

/// The files a target shows, read before anything changes
async fn gather(db: &Database, target: &TakedownTarget) -> Result<Gathered> {
    let mut gathered = Gathered::default();
    match target {
        TakedownTarget::Message { channel, message } => {
            let row = match db.fetch_message(message).await {
                Ok(row) if &row.channel == channel => row,
                Ok(_) => return Ok(gathered),
                Err(error) if is_gone(&error) => return Ok(gathered),
                Err(error) => return Err(error),
            };

            for file in message_files(&row) {
                gathered
                    .add(db, &file.id, Parent::Message(row.id.clone()))
                    .await?;
            }
            gathered.message = Some(row.id);
        }
        TakedownTarget::File { file } => {
            if let Some(row) = stored_row(db, file).await? {
                if let Some(parent) = parent_of(&row) {
                    gathered.parents.push((parent, row.id.clone()));
                }
                gathered.files.push(row);
            }
        }
        TakedownTarget::User { user } => {
            let user = match db.fetch_user(user).await {
                Ok(user) => user,
                Err(error) if is_gone(&error) => return Ok(gathered),
                Err(error) => return Err(error),
            };

            if let Some(avatar) = &user.avatar {
                gathered
                    .add(db, &avatar.id, Parent::UserAvatar(user.id.clone()))
                    .await?;
            }
            if let Some(background) = user
                .profile
                .as_ref()
                .and_then(|profile| profile.background.as_ref())
            {
                gathered
                    .add(db, &background.id, Parent::UserBackground(user.id.clone()))
                    .await?;
            }
        }
        TakedownTarget::Server { server } => {
            let server = match db.fetch_server(server).await {
                Ok(server) => server,
                Err(error) if is_gone(&error) => return Ok(gathered),
                Err(error) => return Err(error),
            };

            if let Some(icon) = &server.icon {
                gathered
                    .add(db, &icon.id, Parent::ServerIcon(server.id.clone()))
                    .await?;
            }
            if let Some(banner) = &server.banner {
                gathered
                    .add(db, &banner.id, Parent::ServerBanner(server.id.clone()))
                    .await?;
            }
        }
        // An emoji's file has the emoji's id
        TakedownTarget::Emoji { emoji } => {
            gathered
                .add(db, emoji, Parent::Emoji(emoji.clone()))
                .await?;
        }
        TakedownTarget::Unresolvable { .. } => {}
    }

    Ok(gathered)
}

/// Original and processed hashes of `files`, every original that processes
/// to the same bytes, and the block keys for all of them
async fn same_image(db: &Database, files: &[File]) -> Result<SameImage> {
    let mut same = SameImage::default();
    for hash in files
        .iter()
        .filter_map(|file| file.hash.as_deref())
        .filter(|hash| !hash.is_empty())
    {
        push_unique(&mut same.originals, hash.to_string());
        push_unique(&mut same.keys, upload_hash_block_key("orig", hash));

        let entry = match db.fetch_attachment_hash(hash).await {
            Ok(entry) => entry,
            Err(error) if is_gone(&error) => continue,
            Err(error) => return Err(error),
        };

        let processed = entry.processed_hash.clone();
        push_unique(&mut same.keys, upload_hash_block_key("proc", &processed));

        let mut related = db.fetch_attachment_hashes_by_processed(&processed).await?;
        related.push(entry);
        for other in related {
            push_unique(&mut same.keys, upload_hash_block_key("orig", &other.id));
            // A chunked upload is stored under its composite hash
            if other.format_version == Some(2) {
                push_unique(&mut same.keys, upload_hash_block_key("chunk", &other.id));
            }
            push_unique(&mut same.originals, other.id);
        }
    }

    Ok(same)
}

/// Files with one of `originals` that are not themselves in `files`, in any state
async fn find_copies(db: &Database, files: &[File], originals: &[String]) -> Result<Vec<File>> {
    if originals.is_empty() {
        return Ok(vec![]);
    }

    let own: HashSet<&str> = files.iter().map(|file| file.id.as_str()).collect();
    Ok(db
        .fetch_attachments_by_hashes(originals)
        .await?
        .into_iter()
        .filter(|copy| !own.contains(copy.id.as_str()))
        .collect())
}

/// The selected targets, each once. No target, or an index past the end,
/// is `InvalidOperation`.
fn selected_targets(request: &TakedownRequest, plan: &RemovalPlan) -> Result<Vec<TakedownTarget>> {
    if plan.targets.is_empty() {
        return Err(create_error!(InvalidOperation));
    }

    let mut targets = Vec::new();
    for index in &plan.targets {
        let target = request
            .targets
            .get(*index)
            .ok_or_else(|| create_error!(InvalidOperation))?;
        push_unique(&mut targets, target.clone());
    }
    Ok(targets)
}

/// Stored files the selected targets show, read before anything changes
async fn gather_all(
    db: &Database,
    targets: &[TakedownTarget],
) -> Result<(Vec<File>, Vec<(Parent, String)>, Vec<String>)> {
    let mut files: Vec<File> = Vec::new();
    let mut parents = Vec::new();
    let mut messages = Vec::new();
    for target in targets {
        let gathered = gather(db, target).await?;
        for file in gathered.files {
            if !files.iter().any(|known| known.id == file.id) {
                files.push(file);
            }
        }
        for parent in gathered.parents {
            push_unique(&mut parents, parent);
        }
        if let Some(message) = gathered.message {
            push_unique(&mut messages, message);
        }
    }
    Ok((files, parents, messages))
}

/// Add this request's auto-hides from a selected message to that message's
/// files, also once the message is gone (its uploader deleted it after the
/// hide): they are removed with it, never shown again
async fn add_auto_hides(
    db: &Database,
    request: &TakedownRequest,
    targets: &[TakedownTarget],
    files: &mut Vec<File>,
    parents: &mut Vec<(Parent, String)>,
) -> Result<()> {
    let selected_messages: Vec<&String> = targets
        .iter()
        .filter_map(|target| match target {
            TakedownTarget::Message { message, .. } => Some(message),
            _ => None,
        })
        .collect();

    for id in &request.auto_hidden_file_ids {
        if files.iter().any(|file| &file.id == id) {
            continue;
        }
        let Some(row) = stored_row(db, id).await? else {
            continue;
        };
        let Some(Parent::Message(message)) = parent_of(&row) else {
            continue;
        };
        if selected_messages.contains(&&message) {
            push_unique(parents, (Parent::Message(message), row.id.clone()));
            files.push(row);
        }
    }

    Ok(())
}

/// Stored files one target shows (a missing row is left out)
pub async fn target_files(db: &Database, target: &TakedownTarget) -> Result<Vec<File>> {
    Ok(gather(db, target).await?.files)
}

/// Identical copies of `files` elsewhere on Sloga (same original hash, or an
/// original that processes to the same bytes), in any state
pub async fn copies_of(db: &Database, files: &[File]) -> Result<Vec<File>> {
    let same = same_image(db, files).await?;
    find_copies(db, files, &same.originals).await
}

/// How many identical copies a removal would also take down: live copies
/// only, 0 when copies are not included
pub async fn plan_copy_count(
    db: &Database,
    request: &TakedownRequest,
    plan: &RemovalPlan,
) -> Result<u64> {
    let targets = selected_targets(request, plan)?;
    if !plan.include_copies {
        return Ok(0);
    }

    let (mut files, mut parents, _) = gather_all(db, &targets).await?;
    add_auto_hides(db, request, &targets, &mut files, &mut parents).await?;
    Ok(copies_of(db, &files)
        .await?
        .iter()
        .filter(|copy| is_live(copy))
        .count() as u64)
}

/// Whether each file was `reported` before any Take It Down request hid it.
///
/// Hiding sets `reported`, so for a file another request already holds the
/// live flag may be nothing but that request's hide. Then the holders'
/// records decide (reported before only if every holder saw it reported);
/// otherwise the live flag does. Without this, two requests holding one file
/// would each take the other's hide for a report, and no hold release would
/// ever let the sweep delete the file.
///
/// Only `reported` is inherited: `was_deleted` stays the live flag, so an
/// unhide can never show a file another request removed.
pub async fn prior_reported(
    db: &Database,
    request_id: &str,
    files: &[File],
) -> Result<HashMap<String, bool>> {
    let others = db
        .fetch_recent_takedown_requests(Timestamp::UNIX_EPOCH)
        .await?;

    Ok(files
        .iter()
        .map(|file| {
            let mut records = others
                .iter()
                .filter(|other| other.id != request_id)
                .flat_map(|other| other.held_files.iter())
                .filter(|held| held.id == file.id)
                .peekable();
            let was_reported = if records.peek().is_some() {
                records.all(|held| held.was_reported)
            } else {
                file.reported == Some(true)
            };
            (file.id.clone(), was_reported)
        })
        .collect())
}

/// Record each file's flags from before on the request, then hide every file
/// (`deleted` and `reported`). A file the request already holds keeps its
/// first record; `reported` comes from [`prior_reported`]. `files` must be
/// rows read before this request changed them. Returns the ids hidden.
pub async fn hold_files(
    db: &Database,
    request: &mut TakedownRequest,
    files: &[File],
) -> Result<Vec<String>> {
    let prior = prior_reported(db, &request.id, files).await?;
    let mut ids: Vec<String> = Vec::new();
    for file in files {
        if ids.contains(&file.id) {
            continue;
        }
        ids.push(file.id.clone());

        if !request.held_files.iter().any(|held| held.id == file.id) {
            request.held_files.push(HeldFile {
                id: file.id.clone(),
                was_deleted: file.deleted == Some(true),
                was_reported: prior
                    .get(&file.id)
                    .copied()
                    .unwrap_or(file.reported == Some(true)),
            });
        }
    }

    db.hide_attachments(&ids).await?;
    Ok(ids)
}

/// Add the held records in `new` that `held` does not have yet (by id)
pub fn merge_held_files(held: &mut Vec<HeldFile>, new: &[HeldFile]) {
    for file in new {
        if !held.iter().any(|known| known.id == file.id) {
            held.push(file.clone());
        }
    }
}

/// Which of `ids` this request may unhide: only its auto-hides (a removal
/// takes the files it removed off `auto_hidden_file_ids`, so a removed file
/// never qualifies) that were live before it hid them, never in a
/// child-safety case. Any other id, or none at all, refuses the whole call
/// with `InvalidOperation`.
pub fn unhide_allowed(request: &TakedownRequest, ids: &[String]) -> Result<Vec<String>> {
    if request.child_safety || ids.is_empty() {
        return Err(create_error!(InvalidOperation));
    }

    let mut allowed = Vec::new();
    for id in ids {
        if !request.auto_hidden_file_ids.contains(id) {
            return Err(create_error!(InvalidOperation));
        }
        match request.held_files.iter().find(|held| &held.id == id) {
            Some(held) if !held.was_deleted => push_unique(&mut allowed, id.clone()),
            _ => return Err(create_error!(InvalidOperation)),
        }
    }
    Ok(allowed)
}

/// Files a restore would bring back: held files that were live before
pub fn restorable_files(request: &TakedownRequest) -> Vec<String> {
    request
        .held_files
        .iter()
        .filter(|held| !held.was_deleted)
        .map(|held| held.id.clone())
        .collect()
}

/// Take `file_id` out of `parent`. A parent that is already gone, or that
/// shows another file by now, is left alone.
async fn detach(
    db: &Database,
    parent: &Parent,
    file_id: &str,
    touched: &mut Vec<String>,
) -> Result<()> {
    match parent {
        // Pulls the file from `attachments` and from a forwarded snapshot;
        // the message is not marked edited
        Parent::Message(id) => {
            db.remove_message_attachment(id, file_id).await?;
            push_unique(touched, id.clone());
        }
        Parent::UserAvatar(id) | Parent::UserBackground(id) => {
            let mut user = match db.fetch_user(id).await {
                Ok(user) => user,
                Err(error) if is_gone(&error) => return Ok(()),
                Err(error) => return Err(error),
            };

            let field = if matches!(parent, Parent::UserAvatar(_)) {
                user.avatar
                    .as_ref()
                    .filter(|file| file.id == file_id)
                    .map(|_| FieldsUser::Avatar)
            } else {
                user.profile
                    .as_ref()
                    .and_then(|profile| profile.background.as_ref())
                    .filter(|file| file.id == file_id)
                    .map(|_| FieldsUser::ProfileBackground)
            };

            // Publishes `UserUpdate`
            if let Some(field) = field {
                user.update(db, PartialUser::default(), vec![field]).await?;
            }
        }
        Parent::ServerIcon(id) | Parent::ServerBanner(id) => {
            let mut server = match db.fetch_server(id).await {
                Ok(server) => server,
                Err(error) if is_gone(&error) => return Ok(()),
                Err(error) => return Err(error),
            };

            let field = if matches!(parent, Parent::ServerIcon(_)) {
                server
                    .icon
                    .as_ref()
                    .filter(|file| file.id == file_id)
                    .map(|_| FieldsServer::Icon)
            } else {
                server
                    .banner
                    .as_ref()
                    .filter(|file| file.id == file_id)
                    .map(|_| FieldsServer::Banner)
            };

            // Publishes `ServerUpdate`
            if let Some(field) = field {
                server
                    .update(db, PartialServer::default(), vec![field])
                    .await?;
            }
        }
        // Publishes `EmojiDelete`; a detached emoji is already out of use
        Parent::Emoji(id) => match db.fetch_emoji(id).await {
            Ok(emoji) => {
                if matches!(emoji.parent, EmojiParent::Server { .. }) {
                    emoji.delete(db).await?;
                }
            }
            Err(error) if is_gone(&error) => {}
            Err(error) => return Err(error),
        },
        // Publishes `StickerDelete`
        Parent::Sticker(id) => match db.fetch_sticker(id).await {
            Ok(sticker) => sticker.delete(db).await?,
            Err(error) if is_gone(&error) => {}
            Err(error) => return Err(error),
        },
    }

    Ok(())
}

/// Whether nothing a reader could see is left on a message
fn nothing_left(message: &Message) -> bool {
    let blank = |text: &Option<String>| text.as_deref().is_none_or(|text| text.trim().is_empty());

    blank(&message.content)
        && message.attachments.as_ref().is_none_or(Vec::is_empty)
        && message.embeds.as_ref().is_none_or(Vec::is_empty)
        && message.sticker_ids.as_ref().is_none_or(Vec::is_empty)
        && message.components.as_ref().is_none_or(Vec::is_empty)
        && message
            .forwarded
            .as_ref()
            .is_none_or(|forwarded| blank(&forwarded.content) && forwarded.attachments.is_empty())
        && message.system.is_none()
        && message.poll.is_none()
        && message.softres.is_none()
        && message.encrypted.is_none()
}

/// Server audit entry for a removal's message delete. No actor, so the app
/// shows it as "System"; ids only. DMs and groups have no audit log.
async fn record_system_delete(db: &Database, message_id: &str, channel_id: &str, author: &str) {
    let Ok(channel) = db.fetch_channel(channel_id).await else {
        return;
    };
    let Some(server) = channel.server().map(str::to_string) else {
        return;
    };

    AuditLogEntry::record(
        db,
        AuditLogDraft {
            server,
            actor: None,
            action: AuditLogAction::MessageDelete,
            target: Some(author.to_string()),
            channel: Some(channel_id.to_string()),
            changes: vec![AuditLogChange::new(
                "message",
                None,
                Some(AuditValue::String(message_id.to_string())),
            )],
            ..Default::default()
        },
    )
    .await;
}

/// Whether `message` is served by its channel's read view (design 7.5 "S4";
/// a thread is judged by its parent). False when either channel read fails.
async fn is_served(db: &Database, message: &Message) -> bool {
    let Ok(channel) = db.fetch_channel(&message.channel).await else {
        return false;
    };
    let Ok(target) = channel.permission_target(db).await else {
        return false;
    };
    message.is_servable(&ProtectedReadView::of_read_target(&channel, &target))
}

/// After files left a message: delete it when asked to or when nothing is
/// left of it, otherwise tell clients what it shows now. `lost_files` is
/// false for a target message nothing was taken from. True when deleted.
async fn finish_message(db: &Database, id: &str, whole: bool, lost_files: bool) -> Result<bool> {
    let message = match db.fetch_message(id).await {
        Ok(message) => message,
        Err(error) if is_gone(&error) => return Ok(false),
        Err(error) => return Err(error),
    };

    if whole || (lost_files && nothing_left(&message)) {
        let (id, channel, author) = (
            message.id.clone(),
            message.channel.clone(),
            message.author.clone(),
        );
        // Publishes `MessageDelete`; never the staff delete route, which
        // would name the reviewer in the server's audit log
        message.delete(db).await?;
        record_system_delete(db, &id, &channel, &author).await;
        return Ok(true);
    }

    // No update for a row its channel no longer serves (S4: a stray, or a
    // row a requested wipe is deleting); clients must not see it again
    if lost_files && is_served(db, &message).await {
        EventV1::MessageUpdate {
            id: message.id.clone(),
            channel: message.channel.clone(),
            data: PartialMessage {
                attachments: Some(message.attachments.clone().unwrap_or_default()),
                forwarded: message.forwarded.clone(),
                ..Default::default()
            }
            .into(),
            clear: vec![],
        }
        .p(message.channel.clone())
        .await;
    }

    Ok(false)
}

/// Carry out a removal.
///
/// Reads every target file and copy first, records each one's flags on
/// `request.held_files` and hides them all, blocks re-uploads, then takes
/// the files out of their messages, profiles, servers, emojis and stickers
/// (publishing the events the normal routes publish). The caller sets the
/// status and `removed_at` and stores the request, also when this fails
/// part way: `held_files` is filled in before anything is hidden.
pub async fn execute_removal(
    db: &Database,
    request: &mut TakedownRequest,
    plan: &RemovalPlan,
    actor: &str,
) -> Result<RemovalOutcome> {
    let mut hidden = Vec::new();
    execute_removal_tracked(db, request, plan, actor, &mut hidden, None).await
}

/// `Err(takedown_busy())` once `mutex` no longer holds the takedown mutex
fn still_held(mutex: Option<&TakedownMutexGuard>) -> Result<()> {
    if mutex.is_some_and(|guard| !guard.is_held()) {
        Err(takedown_busy())
    } else {
        Ok(())
    }
}

/// [`execute_removal`], also reporting in `hidden` the id of every file it
/// is hiding, set just before the hide. On an error after that point the
/// caller knows exactly which files this run hid, and can hide them again
/// and keep their records.
///
/// With `mutex`, it checks [`TakedownMutexGuard::is_held`] before every
/// batch of file-state writes (the hide, the re-upload blocks, each parent,
/// each message) and stops with [`takedown_busy`] once the hold is lost.
pub async fn execute_removal_tracked(
    db: &Database,
    request: &mut TakedownRequest,
    plan: &RemovalPlan,
    actor: &str,
    hidden: &mut Vec<String>,
    mutex: Option<&TakedownMutexGuard>,
) -> Result<RemovalOutcome> {
    let targets = selected_targets(request, plan)?;

    // 1. Read everything before changing anything
    let (mut files, mut parents, target_messages) = gather_all(db, &targets).await?;
    add_auto_hides(db, request, &targets, &mut files, &mut parents).await?;

    let same = same_image(db, &files).await?;
    let copies = if plan.include_copies {
        find_copies(db, &files, &same.originals).await?
    } else {
        vec![]
    };
    let live_copies = copies.iter().filter(|copy| is_live(copy)).count() as u64;
    for copy in &copies {
        if let Some(parent) = parent_of(copy) {
            push_unique(&mut parents, (parent, copy.id.clone()));
        }
    }

    let all: Vec<File> = files.iter().chain(copies.iter()).cloned().collect();
    let mut uploader_ids = Vec::new();
    for file in &all {
        if let Some(uploader) = &file.uploader_id {
            push_unique(&mut uploader_ids, uploader.clone());
        }
    }

    // 2. Record, then hide
    still_held(mutex)?;
    hidden.clear();
    for file in &all {
        push_unique(hidden, file.id.clone());
    }
    let removed_files = hold_files(db, request, &all).await?;

    // 3. Block re-uploads of the same image
    let mut blocked_keys = Vec::new();
    if plan.block_reuploads {
        still_held(mutex)?;
        let created_at = Timestamp::now_utc();
        for key in same.keys {
            db.insert_upload_hash_block(&UploadHashBlock {
                id: key.clone(),
                request_id: request.id.clone(),
                created_at,
                also_request_ids: vec![],
            })
            .await?;
            blocked_keys.push(key);
        }
    }

    // 4. Take the files out of where they are shown
    let mut touched: Vec<String> = Vec::new();
    for (parent, file_id) in &parents {
        still_held(mutex)?;
        detach(db, parent, file_id, &mut touched).await?;
    }

    // 5. Update or delete each message that lost a file
    let mut finish: Vec<String> = touched.clone();
    for message in &target_messages {
        push_unique(&mut finish, message.clone());
    }

    let mut deleted_messages = Vec::new();
    for message in &finish {
        still_held(mutex)?;
        let whole = plan.whole_message && target_messages.contains(message);
        if finish_message(db, message, whole, touched.contains(message)).await? {
            deleted_messages.push(message.clone());
        }
    }

    info!(
        "Take It Down {}: {} removed {} file(s) ({} live copies), deleted {} message(s), blocked {} hash key(s)",
        request.id,
        actor,
        removed_files.len(),
        live_copies,
        deleted_messages.len(),
        blocked_keys.len()
    );

    Ok(RemovalOutcome {
        removed_files,
        deleted_messages,
        copies: live_copies,
        blocked_keys,
        uploader_ids,
    })
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // fixtures are stored directly
mod tests {
    use std::collections::HashMap;

    use iso8601_timestamp::{Duration, Timestamp};

    use super::{execute_removal, plan_copy_count, restorable_files, unhide_allowed, RemovalPlan};
    use crate::{
        upload_hash_block_key, AuditLogAction, Channel, Database, File, FileHash, FileUsedFor,
        FileUsedForType, ForwardedSnapshot, HeldFile, Message, Metadata, TakedownRequest,
        TakedownSource, TakedownStatus, TakedownTarget, UnresolvableKind, User,
    };

    const SERVER: &str = "01TDSERVER0000000000000001";
    const CHANNEL: &str = "01TDCHANNEL000000000000001";
    const AUTHOR: &str = "01TDAUTHOR0000000000000001";
    const FORWARDER: &str = "01TDFORWARDER0000000000001";
    const AVATAR_OWNER: &str = "01TDAVATAROWNER00000000001";

    const HASH_ORIG: &str = "hash-orig";
    const HASH_ALT: &str = "hash-alt";
    const HASH_PROC: &str = "hash-proc";
    const HASH_OTHER: &str = "hash-other";

    const TARGET_MSG: &str = "01TDMSGTARGET0000000000001";
    const COPY_MSG: &str = "01TDMSGCOPY000000000000001";
    const IMAGE_ONLY_MSG: &str = "01TDMSGIMAGEONLY0000000001";
    const FORWARD_MSG: &str = "01TDMSGFORWARD000000000001";
    const GONE_MSG: &str = "01TDMSGGONE000000000000001";
    const OTHER_MSG: &str = "01TDMSGOTHER00000000000001";

    const TARGET_FILE: &str = "01TDFILETARGET000000000001";
    const COPY_SAME: &str = "01TDFILECOPYSAME0000000001";
    const COPY_PROC: &str = "01TDFILECOPYPROC0000000001";
    const COPY_FORWARD: &str = "01TDFILECOPYFORWARD0000001";
    const COPY_AVATAR: &str = "01TDFILECOPYAVATAR00000001";
    const COPY_DELETED: &str = "01TDFILECOPYDELETED0000001";
    const UNRELATED: &str = "01TDFILEUNRELATED000000001";

    fn file(
        id: &str,
        tag: &str,
        hash: &str,
        used_for: (FileUsedForType, &str),
        uploader: &str,
    ) -> File {
        File {
            id: id.to_string(),
            tag: tag.to_string(),
            filename: "image.png".to_string(),
            hash: Some(hash.to_string()),
            uploaded_at: None,
            uploader_id: Some(uploader.to_string()),
            used_for: Some(FileUsedFor {
                object_type: used_for.0,
                id: used_for.1.to_string(),
            }),
            deleted: None,
            reported: None,
            metadata: Metadata::File,
            content_type: "image/png".to_string(),
            size: 1,
            message_id: None,
            user_id: None,
            server_id: None,
            object_id: None,
        }
    }

    fn file_hash(id: &str, processed_hash: &str) -> FileHash {
        FileHash {
            id: id.to_string(),
            processed_hash: processed_hash.to_string(),
            created_at: Timestamp::UNIX_EPOCH,
            bucket_id: "attachments".to_string(),
            path: id.to_string(),
            iv: String::new(),
            format_version: None,
            key_id: None,
            metadata: Metadata::File,
            content_type: "image/png".to_string(),
            size: 1,
        }
    }

    fn message(id: &str, content: Option<&str>, attachments: Vec<File>) -> Message {
        Message {
            id: id.to_string(),
            channel: CHANNEL.to_string(),
            author: AUTHOR.to_string(),
            content: content.map(str::to_string),
            attachments: Some(attachments),
            ..Default::default()
        }
    }

    fn text_channel() -> Channel {
        Channel::TextChannel {
            id: CHANNEL.to_string(),
            server: SERVER.to_string(),
            name: "general".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: HashMap::new(),
            nsfw: false,
            spoiler: false,
            voice: None,
            slowmode: None,
            announcement: None,
            protected: false,
            protected_history: None,
        }
    }

    fn request(targets: Vec<TakedownTarget>) -> TakedownRequest {
        let now = Timestamp::now_utc();
        TakedownRequest {
            id: "01TDREQUEST000000000000001".to_string(),
            status: TakedownStatus::UnderReview,
            source: TakedownSource::Web,
            received_at: now,
            deadline_at: now.checked_add(Duration::hours(48)).unwrap(),
            sealed: String::new(),
            contact_fp: String::new(),
            status_token_hash: String::new(),
            locations: vec![],
            minor_claimed: false,
            resolved: true,
            targets,
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

    async fn flags(db: &Database, id: &str) -> (Option<bool>, Option<bool>) {
        let row = db.fetch_attachment_by_id(id).await.unwrap();
        (row.deleted, row.reported)
    }

    fn attachment_ids(message: &Message) -> Vec<String> {
        message
            .attachments
            .iter()
            .flatten()
            .map(|file| file.id.clone())
            .collect()
    }

    /// The image under removal in a captioned message, plus:
    /// - a re-upload of the same bytes in a captioned message (`COPY_SAME`)
    /// - another original that processed to the same bytes, alone in its
    ///   message (`COPY_PROC`)
    /// - a forward of the image with forwarded text (`COPY_FORWARD`)
    /// - the same bytes as someone's avatar (`COPY_AVATAR`)
    /// - a copy that was already deleted (`COPY_DELETED`)
    /// - an unrelated image (`UNRELATED`)
    async fn seed(db: &Database) {
        db.insert_channel(&text_channel()).await.unwrap();

        db.insert_attachment_hash(&file_hash(HASH_ORIG, HASH_PROC))
            .await
            .unwrap();
        db.insert_attachment_hash(&file_hash(HASH_ALT, HASH_PROC))
            .await
            .unwrap();
        db.insert_attachment_hash(&file_hash(HASH_OTHER, "hash-other-proc"))
            .await
            .unwrap();

        let target = file(
            TARGET_FILE,
            "attachments",
            HASH_ORIG,
            (FileUsedForType::Message, TARGET_MSG),
            AUTHOR,
        );
        let same = file(
            COPY_SAME,
            "attachments",
            HASH_ORIG,
            (FileUsedForType::Message, COPY_MSG),
            FORWARDER,
        );
        let proc = file(
            COPY_PROC,
            "attachments",
            HASH_ALT,
            (FileUsedForType::Message, IMAGE_ONLY_MSG),
            AUTHOR,
        );
        let forward = file(
            COPY_FORWARD,
            "attachments",
            HASH_ORIG,
            (FileUsedForType::Message, FORWARD_MSG),
            FORWARDER,
        );
        let avatar = file(
            COPY_AVATAR,
            "avatars",
            HASH_ORIG,
            (FileUsedForType::UserAvatar, AVATAR_OWNER),
            AVATAR_OWNER,
        );
        let gone = file(
            COPY_DELETED,
            "attachments",
            HASH_ORIG,
            (FileUsedForType::Message, GONE_MSG),
            AUTHOR,
        );
        let unrelated = file(
            UNRELATED,
            "attachments",
            HASH_OTHER,
            (FileUsedForType::Message, OTHER_MSG),
            AUTHOR,
        );

        for row in [&target, &same, &proc, &forward, &avatar, &gone, &unrelated] {
            db.insert_attachment(row).await.unwrap();
        }
        db.mark_attachment_as_deleted(COPY_DELETED).await.unwrap();

        db.insert_message(&message(TARGET_MSG, Some("caption"), vec![target.clone()]))
            .await
            .unwrap();
        db.insert_message(&message(COPY_MSG, Some("again"), vec![same]))
            .await
            .unwrap();
        db.insert_message(&message(IMAGE_ONLY_MSG, None, vec![proc]))
            .await
            .unwrap();
        db.insert_message(&message(OTHER_MSG, Some("unrelated"), vec![unrelated]))
            .await
            .unwrap();
        db.insert_message(&Message {
            id: FORWARD_MSG.to_string(),
            channel: CHANNEL.to_string(),
            author: FORWARDER.to_string(),
            forwarded: Some(ForwardedSnapshot {
                message_id: TARGET_MSG.to_string(),
                channel_id: CHANNEL.to_string(),
                server_id: Some(SERVER.to_string()),
                author_id: Some(AUTHOR.to_string()),
                content: Some("look".to_string()),
                attachments: vec![forward],
                original_sent_at: 0,
            }),
            ..Default::default()
        })
        .await
        .unwrap();

        db.insert_user(&User {
            id: AVATAR_OWNER.to_string(),
            username: "avatarowner".to_string(),
            discriminator: "0001".to_string(),
            avatar: Some(avatar),
            ..Default::default()
        })
        .await
        .unwrap();
    }

    fn plan(whole_message: bool, include_copies: bool, block_reuploads: bool) -> RemovalPlan {
        RemovalPlan {
            targets: vec![0],
            whole_message,
            include_copies,
            block_reuploads,
        }
    }

    #[tokio::test]
    async fn removal_takes_the_image_and_every_copy() {
        database_test!(|db| async move {
            seed(&db).await;
            let mut request = request(vec![
                TakedownTarget::Message {
                    channel: CHANNEL.to_string(),
                    message: TARGET_MSG.to_string(),
                },
                TakedownTarget::Unresolvable {
                    location_index: 1,
                    kind: UnresolvableKind::PrivateConversation,
                },
            ]);

            // The deleted copy is not counted: it is already gone
            let plan = plan(false, true, true);
            assert_eq!(plan_copy_count(&db, &request, &plan).await.unwrap(), 4);
            assert_eq!(
                plan_copy_count(
                    &db,
                    &request,
                    &RemovalPlan {
                        include_copies: false,
                        ..plan.clone()
                    }
                )
                .await
                .unwrap(),
                0
            );

            let outcome = execute_removal(&db, &mut request, &plan, "01TDREVIEWER00000000000001")
                .await
                .unwrap();

            let mut removed = outcome.removed_files.clone();
            removed.sort();
            let mut expected = vec![
                TARGET_FILE.to_string(),
                COPY_SAME.to_string(),
                COPY_PROC.to_string(),
                COPY_FORWARD.to_string(),
                COPY_AVATAR.to_string(),
                COPY_DELETED.to_string(),
            ];
            expected.sort();
            assert_eq!(removed, expected);
            assert_eq!(outcome.copies, 4);
            assert_eq!(outcome.deleted_messages, vec![IMAGE_ONLY_MSG.to_string()]);

            // Hidden but kept, every one of them; the unrelated image untouched
            for id in &expected {
                assert_eq!(flags(&db, id).await, (Some(true), Some(true)), "{id}");
            }
            assert_eq!(flags(&db, UNRELATED).await, (None, None));

            // Prior state recorded once per file, from before the hide
            assert_eq!(request.held_files.len(), expected.len());
            for held in &request.held_files {
                assert_eq!(held.was_deleted, held.id == COPY_DELETED, "{}", held.id);
                assert!(!held.was_reported, "{}", held.id);
            }

            // The captioned messages stay, without the image, and are not edits
            let target = db.fetch_message(TARGET_MSG).await.unwrap();
            assert!(attachment_ids(&target).is_empty());
            assert_eq!(target.content.as_deref(), Some("caption"));
            assert_eq!(target.edited, None);
            let copy = db.fetch_message(COPY_MSG).await.unwrap();
            assert!(attachment_ids(&copy).is_empty());
            assert_eq!(copy.content.as_deref(), Some("again"));

            // The message that was only the image is gone, logged as System
            assert!(db.fetch_message(IMAGE_ONLY_MSG).await.is_err());
            let entries = db
                .fetch_audit_log(SERVER, None, 50, None, None)
                .await
                .unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].action, AuditLogAction::MessageDelete);
            assert_eq!(entries[0].actor, None);
            assert_eq!(entries[0].target.as_deref(), Some(AUTHOR));
            assert_eq!(entries[0].reason, None);

            // The forward keeps its text and loses the image
            let forward = db.fetch_message(FORWARD_MSG).await.unwrap();
            let snapshot = forward.forwarded.expect("snapshot");
            assert!(snapshot.attachments.is_empty());
            assert_eq!(snapshot.content.as_deref(), Some("look"));

            // The avatar is cleared
            let owner = db.fetch_user(AVATAR_OWNER).await.unwrap();
            assert!(owner.avatar.is_none());

            // Re-uploads blocked: both originals and the processed bytes
            for key in [
                upload_hash_block_key("orig", HASH_ORIG),
                upload_hash_block_key("orig", HASH_ALT),
                upload_hash_block_key("proc", HASH_PROC),
            ] {
                assert!(outcome.blocked_keys.contains(&key), "{key}");
                assert!(db.is_hash_blocked(&key).await.unwrap(), "{key}");
            }
            assert!(!db
                .is_hash_blocked(&upload_hash_block_key("orig", HASH_OTHER))
                .await
                .unwrap());

            let mut uploaders = outcome.uploader_ids.clone();
            uploaders.sort();
            let mut expected_uploaders = vec![
                AUTHOR.to_string(),
                FORWARDER.to_string(),
                AVATAR_OWNER.to_string(),
            ];
            expected_uploaders.sort();
            assert_eq!(uploaders, expected_uploaders);

            // A removed file is never unhidden: only auto-hides are
            assert!(unhide_allowed(&request, &[TARGET_FILE.to_string()]).is_err());
            assert!(unhide_allowed(&request, &[UNRELATED.to_string()]).is_err());
            assert!(!restorable_files(&request).contains(&COPY_DELETED.to_string()));

            // Of auto-hides, a pre-deleted file is never unhidden; a live one may be
            let mut auto_hid = request.clone();
            auto_hid.auto_hidden_file_ids = vec![TARGET_FILE.to_string(), COPY_DELETED.to_string()];
            assert!(unhide_allowed(&auto_hid, &[COPY_DELETED.to_string()]).is_err());
            assert!(unhide_allowed(
                &auto_hid,
                &[TARGET_FILE.to_string(), COPY_DELETED.to_string()]
            )
            .is_err());
            assert_eq!(
                unhide_allowed(&auto_hid, &[TARGET_FILE.to_string()]).unwrap(),
                vec![TARGET_FILE.to_string()]
            );
            auto_hid.child_safety = true;
            assert!(unhide_allowed(&auto_hid, &[TARGET_FILE.to_string()]).is_err());

            // Holding a file again keeps its first record: its row now says
            // hidden, and that must not overwrite "was live"
            let held_before = request.held_files.clone();
            let hidden_row = db.fetch_attachment_by_id(TARGET_FILE).await.unwrap();
            assert_eq!(hidden_row.deleted, Some(true));
            super::hold_files(&db, &mut request, &[hidden_row])
                .await
                .unwrap();
            assert_eq!(request.held_files, held_before);

            // A second run finds nothing left to take
            let again = execute_removal(&db, &mut request, &plan, "01TDREVIEWER00000000000001")
                .await
                .unwrap();
            assert!(again.removed_files.is_empty());
            assert!(again.deleted_messages.is_empty());
            assert_eq!(request.held_files, held_before);
        });
    }

    #[tokio::test]
    async fn second_holder_does_not_take_a_hide_for_a_report() {
        database_test!(|db| async move {
            seed(&db).await;

            // A first request hides a live file that was never reported
            let live = db.fetch_attachment_by_id(TARGET_FILE).await.unwrap();
            assert_ne!(live.reported, Some(true));
            let mut first = request(vec![]);
            super::hold_files(&db, &mut first, &[live]).await.unwrap();
            db.insert_takedown_request(&first).await.unwrap();

            // A second request holds the same file: its row now says reported,
            // but only because of the first hide
            let hidden = db.fetch_attachment_by_id(TARGET_FILE).await.unwrap();
            assert_eq!(hidden.reported, Some(true));
            let mut second = request(vec![]);
            second.id = "01TDREQUEST000000000000002".to_string();
            super::hold_files(&db, &mut second, &[hidden])
                .await
                .unwrap();

            let record = second
                .held_files
                .iter()
                .find(|held| held.id == TARGET_FILE)
                .unwrap();
            assert!(!record.was_reported, "a hide is not a report");
            // `was_deleted` stays live, so the second request can never
            // unhide what the first one removed
            assert!(record.was_deleted);

            // The request's own record is never read as another holder's
            let own = super::prior_reported(
                &db,
                &first.id,
                &[db.fetch_attachment_by_id(TARGET_FILE).await.unwrap()],
            )
            .await
            .unwrap();
            assert_eq!(own.get(TARGET_FILE), Some(&true));
        });
    }

    #[tokio::test]
    async fn whole_message_delete_without_copies_or_blocks() {
        database_test!(|db| async move {
            seed(&db).await;
            let mut request = request(vec![TakedownTarget::Message {
                channel: CHANNEL.to_string(),
                message: TARGET_MSG.to_string(),
            }]);

            let outcome = execute_removal(
                &db,
                &mut request,
                &plan(true, false, false),
                "01TDREVIEWER00000000000001",
            )
            .await
            .unwrap();

            assert_eq!(outcome.removed_files, vec![TARGET_FILE.to_string()]);
            assert_eq!(outcome.deleted_messages, vec![TARGET_MSG.to_string()]);
            assert_eq!(outcome.copies, 0);
            assert!(outcome.blocked_keys.is_empty());

            // The captioned message is gone as a whole, logged as System
            assert!(db.fetch_message(TARGET_MSG).await.is_err());
            let entries = db
                .fetch_audit_log(SERVER, None, 50, None, None)
                .await
                .unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].actor, None);
            assert_eq!(entries[0].channel.as_deref(), Some(CHANNEL));

            // Copies and blocks were not asked for
            assert_eq!(flags(&db, TARGET_FILE).await, (Some(true), Some(true)));
            assert_eq!(flags(&db, COPY_SAME).await, (None, None));
            assert!(db.fetch_message(COPY_MSG).await.is_ok());
            assert!(!db
                .is_hash_blocked(&upload_hash_block_key("orig", HASH_ORIG))
                .await
                .unwrap());
        });
    }

    #[tokio::test]
    async fn only_files_their_parent_still_shows_count_as_shown() {
        database_test!(|db| async move {
            seed(&db).await;

            assert!(super::still_shown(&db, TARGET_FILE).await.unwrap());
            assert!(super::still_shown(&db, COPY_FORWARD).await.unwrap());
            assert!(super::still_shown(&db, COPY_AVATAR).await.unwrap());
            // Its message is gone, and an unknown file has no parent at all
            assert!(!super::still_shown(&db, COPY_DELETED).await.unwrap());
            assert!(!super::still_shown(&db, "01TDFILENOSUCHFILE00000001")
                .await
                .unwrap());

            // The uploader deletes the message: its image is no longer shown
            let message = db.fetch_message(TARGET_MSG).await.unwrap();
            message.delete(&db).await.unwrap();
            assert!(!super::still_shown(&db, TARGET_FILE).await.unwrap());

            // A pulled attachment is no longer shown by the message that had it
            db.remove_message_attachment(COPY_MSG, COPY_SAME)
                .await
                .unwrap();
            assert!(!super::still_shown(&db, COPY_SAME).await.unwrap());
        });
    }

    #[tokio::test]
    async fn an_auto_hide_in_a_deleted_target_message_counts_as_removed() {
        database_test!(|db| async move {
            seed(&db).await;
            let mut request = request(vec![TakedownTarget::Message {
                channel: CHANNEL.to_string(),
                message: TARGET_MSG.to_string(),
            }]);

            // Auto-hidden, then the uploader deletes the message
            db.hide_attachments(&[TARGET_FILE.to_string()])
                .await
                .unwrap();
            let auto_hide = HeldFile {
                id: TARGET_FILE.to_string(),
                was_deleted: false,
                was_reported: false,
            };
            request.held_files = vec![auto_hide.clone()];
            request.auto_hidden_file_ids = vec![TARGET_FILE.to_string()];
            let message = db.fetch_message(TARGET_MSG).await.unwrap();
            message.delete(&db).await.unwrap();

            let outcome = execute_removal(
                &db,
                &mut request,
                &plan(false, false, false),
                "01TDREVIEWER00000000000001",
            )
            .await
            .unwrap();

            assert_eq!(outcome.removed_files, vec![TARGET_FILE.to_string()]);
            assert!(outcome.deleted_messages.is_empty());
            // Still hidden and kept, with its first record
            assert_eq!(flags(&db, TARGET_FILE).await, (Some(true), Some(true)));
            assert_eq!(request.held_files, vec![auto_hide]);

            // An auto-hide from a message that was not selected is not taken
            let mut other = TakedownRequest {
                auto_hidden_file_ids: vec![COPY_SAME.to_string()],
                ..request.clone()
            };
            let outcome = execute_removal(
                &db,
                &mut other,
                &plan(false, false, false),
                "01TDREVIEWER00000000000001",
            )
            .await
            .unwrap();
            assert!(!outcome.removed_files.contains(&COPY_SAME.to_string()));
        });
    }

    #[tokio::test]
    async fn bad_plans_are_refused() {
        database_test!(|db| async move {
            seed(&db).await;
            let mut request = request(vec![TakedownTarget::File {
                file: TARGET_FILE.to_string(),
            }]);

            for targets in [vec![], vec![1]] {
                let plan = RemovalPlan {
                    targets,
                    ..plan(false, true, true)
                };
                assert!(plan_copy_count(&db, &request, &plan).await.is_err());
                assert!(
                    execute_removal(&db, &mut request, &plan, "01TDREVIEWER00000000000001")
                        .await
                        .is_err()
                );
            }

            // Nothing was hidden or recorded
            assert_eq!(flags(&db, TARGET_FILE).await, (None, None));
            assert!(request.held_files.is_empty());
        });
    }

    /// A fresh text channel holding one captioned message with one image,
    /// as (channel, message, file). With a history from `protect` (given
    /// the message id) the channel is then protected with it.
    async fn captioned_image(
        db: &Database,
        hash: &str,
        protect: impl FnOnce(&str) -> Option<crate::ProtectedHistory>,
    ) -> (String, String, String) {
        let channel_id = ulid::Ulid::new().to_string();
        let message_id = ulid::Ulid::new().to_string();
        let file_id = ulid::Ulid::new().to_string();

        let mut channel = text_channel();
        if let Channel::TextChannel { id, .. } = &mut channel {
            *id = channel_id.clone();
        }
        db.insert_channel(&channel).await.unwrap();
        db.insert_attachment_hash(&file_hash(hash, &format!("{hash}-proc")))
            .await
            .unwrap();
        let image = file(
            &file_id,
            "attachments",
            hash,
            (FileUsedForType::Message, message_id.as_str()),
            AUTHOR,
        );
        db.insert_attachment(&image).await.unwrap();
        db.insert_message(&Message {
            channel: channel_id.clone(),
            ..message(&message_id, Some("caption"), vec![image])
        })
        .await
        .unwrap();

        if let Some(history) = protect(&message_id) {
            db.update_channel(
                &channel_id,
                &crate::PartialChannel {
                    protected: Some(true),
                    protected_history: Some(Box::new(history)),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .unwrap();
        }

        (channel_id, message_id, file_id)
    }

    /// A removal from a row its channel's S4 read view does not serve (a
    /// requested wipe; a stray above the boundary) still takes the file but
    /// publishes no `MessageUpdate`. A served row's update is published as
    /// before: that is the positive control, which also proves the
    /// subscription receives. Needs Redis at `REDIS_URI`.
    ///
    /// Control: the `is_served` check dropped -> two extra updates.
    #[tokio::test]
    async fn removal_publishes_no_update_for_a_row_its_channel_does_not_serve() {
        database_test!(|db| async move {
            use crate::events::client::EventV1;
            use futures::StreamExt;

            let wiping = captioned_image(&db, "hash-unserved-wipe", |id: &str| {
                Some(crate::ProtectedHistory {
                    boundary: id.to_string(),
                    wipe: crate::HistoryWipe::Requested {
                        at: Timestamp::now_utc(),
                        by: AUTHOR.to_string(),
                    },
                })
            })
            .await;
            let stray = captioned_image(&db, "hash-unserved-stray", |_: &str| {
                Some(crate::ProtectedHistory {
                    boundary: ulid::Ulid::from_parts(0, 1).to_string(),
                    wipe: crate::HistoryWipe::None,
                })
            })
            .await;
            let served = captioned_image(&db, "hash-served", |_: &str| None).await;

            // Fresh channel ids, so nothing else publishes on these topics
            let mut pubsub = redis_kiss::open_pubsub_connection()
                .await
                .expect("pubsub connection");
            for (channel, _, _) in [&wiping, &stray, &served] {
                pubsub.subscribe(channel).await.expect("subscribe");
            }
            let mut stream = pubsub.on_message();

            // The served one last, so its event comes after any other
            for (channel, message, file) in [&wiping, &stray, &served] {
                let mut request = request(vec![TakedownTarget::Message {
                    channel: channel.clone(),
                    message: message.clone(),
                }]);
                let outcome = execute_removal(
                    &db,
                    &mut request,
                    &plan(false, false, false),
                    "01TDREVIEWER00000000000001",
                )
                .await
                .unwrap();
                assert_eq!(outcome.removed_files, vec![file.clone()], "{channel}");
                assert!(outcome.deleted_messages.is_empty(), "{channel}");
                assert_eq!(flags(&db, file).await, (Some(true), Some(true)), "{file}");
                let row = db.fetch_message(message).await.unwrap();
                assert!(attachment_ids(&row).is_empty(), "{message} keeps its file");
            }

            // Wait for the served update, then a second for anything after
            let mut seen: Vec<(String, String)> = Vec::new();
            let mut served_seen = false;
            loop {
                let wait = std::time::Duration::from_secs(if served_seen { 1 } else { 5 });
                let msg = match tokio::time::timeout(wait, stream.next()).await {
                    Ok(Some(msg)) => msg,
                    Ok(None) => break,
                    Err(_) if served_seen => break,
                    Err(_) => panic!(
                        "positive control: no MessageUpdate for the served row (is Redis at REDIS_URI up?)"
                    ),
                };
                let topic = msg.get_channel_name().to_string();
                let event = redis_kiss::decode_payload::<EventV1>(&msg)
                    .expect("undecodable payload on a channel topic");
                match event {
                    EventV1::MessageUpdate { id, .. } => {
                        served_seen |= id == served.1;
                        seen.push((topic, id));
                    }
                    other => seen.push((topic, format!("{other:?}"))),
                }
            }
            assert_eq!(
                seen,
                vec![(served.0.clone(), served.1.clone())],
                "an update for an unserved row, or an unexpected event"
            );
        });
    }
}
