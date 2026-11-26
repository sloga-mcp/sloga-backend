use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use iso8601_timestamp::Timestamp;
use revolt_database::{
    check_history_link_wire, events::client::EventV1, history_link_signature_payload, Database,
    E2EEIdentity, MlsGroup, MlsHistoryLink, Session, User, HISTORY_LINK_PAGE_MAX,
    HISTORY_LINK_PAGE_MIN, PROTECTED_SCOPE_HISTORY,
};
use revolt_models::v0;
use revolt_result::{create_error, ErrorType, Result};
use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;

use super::{GroupDispatch, TextGate};

/// How often one holder group may emit the contest event (design 3.14.6,
/// 7.5 "S4"): at most once per this interval
pub(crate) const CONTEST_EVENT_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// When each holder group last emitted the contest event. Per process: the
/// event is a client-claimed hint (3.14.6), never security-bearing, so a
/// second delta replica may emit one more
static CONTEST_EVENTS: Mutex<BTreeMap<String, Instant>> = Mutex::new(BTreeMap::new());

/// # Store MLS History Link
///
/// Store one history link of a protected channel's Text group (design
/// 3.14.4 to 3.14.6, 7.2 "History links"): the holder is the path's
/// group and `epoch` (G', e'), the body is the link. Answers 204, an
/// identical re-PUT included.
///
/// Text groups only: the route has no Call path. An unknown id, a Call
/// group, a missing channel and a channel the caller cannot view answer
/// exactly like a group id the server does not know. Then, in the 6.1
/// "S4" order: the caller checks, request validation, the available gate
/// AND `history_setting`, the caller's seat, the writer, its membership,
/// the holder epoch, the holder chain and its visibility, the signature
/// under the writer's directory key, and the store's own refusals.
///
/// `?contest=true` (CLIENT-CLAIMED, never security-bearing) changes no
/// rule: it only adds an AUDIT line and the rate-limited
/// `ProtectedChannelChanged { scope: ["history"] }`.
#[openapi(tag = "MLS")]
#[put(
    "/groups/<group_id>/history_links/<epoch>?<options..>",
    data = "<data>"
)]
pub async fn put_history_link(
    db: &State<Database>,
    user: User,
    session: Session,
    group_id: String,
    epoch: i64,
    options: v0::OptionsPutHistoryLink,
    data: Json<v0::HistoryLinkWire>,
) -> Result<EmptyResponse> {
    // Kind dispatch on the stored group comes first (decision 1 (W2)), and
    // nothing about the request is checked before it
    match super::dispatch_group(db, &group_id).await? {
        GroupDispatch::CallOrUnknown(_) => super::as_unknown_group(db, &user, Some(&session)).await,
        GroupDispatch::Text(group) => {
            put_text_history_link(
                db,
                &user,
                &session,
                group,
                epoch,
                options.contest == Some(true),
                data.into_inner(),
            )
            .await
        }
    }
}

/// # Fetch MLS History Links
///
/// One page of the history links held by a protected channel's Text group
/// (design 7.2 "History links", 2.8): newest holder epoch first, every
/// candidate of an epoch on one page. `next_before` is the lowest holder
/// epoch of a non-empty page and is absent on an empty one, so a client
/// pages until it gets an empty page.
///
/// The access of the commit fetch: an unknown id, a Call group, a missing
/// channel and a channel the caller cannot view answer like a group id the
/// server does not know; then the caller checks, the available gate only (a
/// read never needs `history_setting`), the seat. A closed group answers
/// too.
#[openapi(tag = "MLS")]
#[get("/groups/<group_id>/history_links?<options..>")]
pub async fn fetch_history_links(
    db: &State<Database>,
    user: User,
    session: Session,
    group_id: String,
    options: v0::OptionsFetchHistoryLinks,
) -> Result<Json<v0::ResponseHistoryLinks>> {
    match super::dispatch_group(db, &group_id).await? {
        GroupDispatch::CallOrUnknown(_) => super::as_unknown_group(db, &user, Some(&session)).await,
        GroupDispatch::Text(group) => {
            fetch_text_history_links(db, &user, &session, group, options).await
        }
    }
}

/// The Text group path of the PUT, in the design 6.1 "S4" order
async fn put_text_history_link(
    db: &Database,
    user: &User,
    session: &Session,
    group: MlsGroup,
    epoch: i64,
    contest: bool,
    link: v0::HistoryLinkWire,
) -> Result<EmptyResponse> {
    let Ok(channel) = db.fetch_channel(&group.channel_id).await else {
        return super::as_unknown_group(db, user, Some(session)).await;
    };
    if super::require_channel_access(db, user, &channel)
        .await
        .is_err()
    {
        return super::as_unknown_group(db, user, Some(session)).await;
    }

    super::require_mls_caller(db, user, Some(session)).await?;

    // Request validation: the shapes (the ciphertext's encoded length is
    // checked before it is decoded), then the holder named twice
    let size = check_history_link_wire(&link)?;
    if link.group_id != group.id || link.epoch != epoch {
        return Err(create_error!(FailedValidation {
            error: "history_link.group_id and epoch must equal the path".to_string()
        }));
    }

    require_history_gate().await?;
    super::require_seated(db, &group.channel_id, &user.id).await?;

    let writer = require_writer(db, user, session, &link).await?;
    check_writer_held_the_epoch(&group, &link)?;
    if link.epoch > group.current_epoch {
        return Err(create_error!(FailedValidation {
            error: "history_link.epoch is past the group's current epoch".to_string()
        }));
    }
    check_holder_chain(db, &group, &link).await?;

    // A garbage filter (S4-W0): members verify against the leaf-bound key
    if !writer.verify_payload(&history_link_signature_payload(&link), &link.signature) {
        return Err(create_error!(FailedValidation {
            error: "invalid history link signature".to_string()
        }));
    }

    let writer_user_id = link.writer_user_id.clone();
    db.insert_mls_history_link(&MlsHistoryLink::from_wire(link, size, Timestamp::now_utc()))
        .await?;

    if contest {
        log::info!(
            "AUDIT mls_history_link_contest group={} epoch={} writer={}",
            group.id,
            epoch,
            writer_user_id
        );
        let due = {
            let mut last = CONTEST_EVENTS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            contest_event_due(&mut last, &group.id, Instant::now())
        };
        if due {
            EventV1::ProtectedChannelChanged {
                id: group.channel_id.clone(),
                scope: vec![PROTECTED_SCOPE_HISTORY.to_string()],
            }
            .p(group.channel_id.clone())
            .await;
        }
    }

    Ok(EmptyResponse)
}

/// The Text group path of the GET
async fn fetch_text_history_links(
    db: &Database,
    user: &User,
    session: &Session,
    group: MlsGroup,
    options: v0::OptionsFetchHistoryLinks,
) -> Result<Json<v0::ResponseHistoryLinks>> {
    let Ok(channel) = db.fetch_channel(&group.channel_id).await else {
        return super::as_unknown_group(db, user, Some(session)).await;
    };
    if super::require_channel_access(db, user, &channel)
        .await
        .is_err()
    {
        return super::as_unknown_group(db, user, Some(session)).await;
    }

    super::require_mls_caller(db, user, Some(session)).await?;
    super::require_text_gate(TextGate::Available).await?;
    super::require_seated(db, &group.channel_id, &user.id).await?;

    let limit = options
        .limit
        .unwrap_or(HISTORY_LINK_PAGE_MAX)
        .clamp(HISTORY_LINK_PAGE_MIN, HISTORY_LINK_PAGE_MAX);
    let rows = db
        .fetch_mls_history_links(&group.id, options.before, limit)
        .await?;

    Ok(Json(history_links_page(rows)))
}

/// The available gate AND `history_setting` (design 6.1 "S4"): with E2EE
/// off the answer is `e2ee` whatever the history flag says
async fn require_history_gate() -> Result<()> {
    super::require_text_gate(TextGate::Available).await?;
    if !revolt_config::config()
        .await
        .features
        .protected_channels
        .history_setting
    {
        return Err(create_error!(FeatureDisabled {
            feature: "protected_history".to_string()
        }));
    }

    Ok(())
}

/// The writer is the caller, writing from a registered device this session
/// is bound to; anything else is `NotAuthenticated`. Returns the writer's
/// directory row, whose key the signature must verify under.
async fn require_writer(
    db: &Database,
    user: &User,
    session: &Session,
    link: &v0::HistoryLinkWire,
) -> Result<E2EEIdentity> {
    if link.writer_user_id != user.id {
        return Err(create_error!(NotAuthenticated));
    }
    let identity = match db
        .fetch_e2ee_identity(&user.id, &link.writer_device_id)
        .await
    {
        Ok(identity) => identity,
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => {
            return Err(create_error!(NotAuthenticated))
        }
        Err(error) => return Err(error),
    };
    identity.assert_bound_session(&session.id)?;

    Ok(identity)
}

/// The writer device is a current member of the holder group G' (else
/// `ProtectedChannelResecuring { not_member }`) that held epoch e = e' - 1:
/// its `member_added` epoch is below e' (fix F14, fix round 2 LOW 7). A
/// bridge's writer is G''s creator, added at epoch 0. A member with no
/// `member_added` entry is refused (`InvalidOperation`), never assumed to
/// be an old member.
fn check_writer_held_the_epoch(group: &MlsGroup, link: &v0::HistoryLinkWire) -> Result<()> {
    if !group.has_member(&link.writer_user_id, &link.writer_device_id) {
        return Err(create_error!(ProtectedChannelResecuring {
            reason: "not_member".to_string()
        }));
    }

    let added = group
        .member_added
        .iter()
        .filter(|entry| {
            entry.user_id == link.writer_user_id && entry.device_id == link.writer_device_id
        })
        .map(|entry| entry.epoch)
        .max();
    let held = match added {
        Some(added) if link.epoch == 0 => added == 0,
        Some(added) => added < link.epoch,
        None => false,
    };
    if !held {
        return Err(create_error!(InvalidOperation));
    }

    Ok(())
}

/// The holder chain and its visibility (design 6.1 "S4", 3.14.4), else
/// `InvalidOperation`:
///
/// - e' >= 1: G = G' and e = e' - 1, and both transitions INTO e' and
///   INTO e' - 1 are visible;
/// - e' = 0 (a bridge): G is the channel's Text group at generation g - 1,
///   e <= current_epoch(G), the bridge transition is visible (G''s
///   `history_visible_at_create`) and so is G's epoch e.
async fn check_holder_chain(
    db: &Database,
    group: &MlsGroup,
    link: &v0::HistoryLinkWire,
) -> Result<()> {
    let visible = if link.epoch >= 1 {
        link.prev_group_id == group.id
            && link.prev_epoch == link.epoch - 1
            && visibility(db, group, link.epoch).await? == Some(true)
            && visibility(db, group, link.epoch - 1).await? == Some(true)
    } else {
        match predecessor(db, group, &link.prev_group_id).await? {
            Some(previous) => {
                link.prev_epoch <= previous.current_epoch
                    && visibility(db, group, 0).await? == Some(true)
                    && visibility(db, &previous, link.prev_epoch).await? == Some(true)
            }
            None => false,
        }
    };
    if !visible {
        return Err(create_error!(InvalidOperation));
    }

    Ok(())
}

/// The visibility of the transition INTO `epoch` of `group` (design 2.5
/// "S4"): epoch 0 is the group's `history_visible_at_create`; any other is
/// the `history_visible` of its Text-marked commit row. A missing or
/// pruned row is `None`.
async fn visibility(db: &Database, group: &MlsGroup, epoch: i64) -> Result<Option<bool>> {
    if epoch == 0 {
        return Ok(group.history_visible_at_create);
    }

    Ok(db
        .fetch_mls_text_commits_from(&group.id, epoch, 1)
        .await?
        .into_iter()
        .find(|row| row.epoch == epoch)
        .and_then(|row| row.history_visible))
}

/// The group `prev_group_id` names when it is `group`'s channel's Text
/// group at the generation below `group`'s, else `None` (a first group has
/// no predecessor)
async fn predecessor(
    db: &Database,
    group: &MlsGroup,
    prev_group_id: &str,
) -> Result<Option<MlsGroup>> {
    let Some(generation) = group
        .generation
        .and_then(|generation| generation.checked_sub(1))
    else {
        return Ok(None);
    };
    let previous = match db.fetch_mls_group(prev_group_id).await {
        Ok(previous) => previous,
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => return Ok(None),
        Err(error) => return Err(error),
    };

    Ok((previous.is_text()
        && previous.channel_id == group.channel_id
        && previous.generation == Some(generation))
    .then_some(previous))
}

/// A page from the driver's rows. `next_before` is the lowest holder epoch
/// of a non-empty page: the driver drops a trailing epoch that does not fit
/// whole, so a page shorter than `limit` does not mean the end.
fn history_links_page(rows: Vec<MlsHistoryLink>) -> v0::ResponseHistoryLinks {
    let next_before = rows.iter().map(|row| row.epoch).min();

    v0::ResponseHistoryLinks {
        links: rows.into_iter().map(Into::into).collect(),
        next_before,
    }
}

/// Whether a contest on `group_id` at `now` emits the event: not when the
/// group emitted one within [`CONTEST_EVENT_INTERVAL`]. Records `now` when
/// it does, and forgets entries older than the interval.
pub(crate) fn contest_event_due(
    last: &mut BTreeMap<String, Instant>,
    group_id: &str,
    now: Instant,
) -> bool {
    last.retain(|_, at| now.saturating_duration_since(*at) < CONTEST_EVENT_INTERVAL);
    if last.contains_key(group_id) {
        return false;
    }
    last.insert(group_id.to_string(), now);

    true
}

/// The history-link routes (design 6.1 "S4", 7.2 "History links"). Every
/// flag case is its own `#[test]`: `overwrite_config` runs once per
/// process, BEFORE the harness primes the config cache, so these need
/// nextest. `Revolt.test.toml` keeps `history_setting` off; a test that
/// writes turns it on. The routes are called directly, as Rocket calls
/// them, so a bot caller reaches them too. Every database case runs on an
/// 8 MiB stack (the `groups_create` oracle tests reached the 2 MiB one).
#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Mutex, Once};
    use std::time::{Duration, Instant};

    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use iso8601_timestamp::Timestamp;
    use rand::Rng;
    use revolt_database::{
        events::client::EventV1, history_link_signature_payload, BotInformation, Channel, Database,
        MlsCommit, MlsCommitOutcome, MlsGroup, MlsGroupCreateOutcome, MlsGroupKind, MlsHistoryLink,
        MlsMemberDevice, PartialChannel, Session, User, PROTECTED_SCOPE_HISTORY,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use revolt_result::Result;
    use rocket::{serde::json::Json, State};
    use serde_json::{json, Value};
    use ulid::Ulid;

    use super::{contest_event_due, fetch_history_links, put_history_link, CONTEST_EVENT_INTERVAL};
    use crate::util::test::{TestE2EEDevice, TestHarness, MEMBER_DEVICE_SEED};

    const SECOND_DEVICE_SEED: u8 = 0x30;
    const WRITER_SEEDS: [u8; 3] = [0x40, 0x50, 0x60];
    const SIXTH_SEED: u8 = 0x70;
    const LATE_SEED: u8 = 0x90;
    const JOINER_SEED: u8 = 0xa0;
    const UNBOUND_SEED: u8 = 0xb0;
    const UNREGISTERED_SEED: u8 = 0xc0;

    /// Decoded ciphertext bytes of every test link
    const CIPHERTEXT_BYTES: usize = 48;

    fn on_a_big_stack(case: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(case)
            .expect("test thread")
            .join()
            .expect("the case passes")
    }

    /// Turn `history_setting` on (and anything else `extra` sets) for this
    /// process
    async fn with_history(extra: impl FnOnce(&mut revolt_config::Settings)) {
        revolt_config::overwrite_config(|settings| {
            settings.features.protected_channels.history_setting = true;
            extra(settings);
        })
        .await;
    }

    /// The PUT, called as Rocket calls it
    async fn put(
        db: &Database,
        user: &User,
        session: &Session,
        group_id: &str,
        epoch: i64,
        contest: Option<bool>,
        link: &v0::HistoryLinkWire,
    ) -> Result<()> {
        Box::pin(put_history_link(
            State::from(db),
            user.clone(),
            session.clone(),
            group_id.to_string(),
            epoch,
            v0::OptionsPutHistoryLink { contest },
            Json(link.clone()),
        ))
        .await
        .map(|_| ())
    }

    /// The GET, called as Rocket calls it
    async fn get(
        db: &Database,
        user: &User,
        session: &Session,
        group_id: &str,
        before: Option<i64>,
        limit: Option<i64>,
    ) -> Result<v0::ResponseHistoryLinks> {
        Box::pin(fetch_history_links(
            State::from(db),
            user.clone(),
            session.clone(),
            group_id.to_string(),
            v0::OptionsFetchHistoryLinks { before, limit },
        ))
        .await
        .map(|json| json.into_inner())
    }

    fn random_group_id() -> String {
        format!("{:032x}{:032x}", Ulid::new().0, Ulid::new().0)
    }

    fn leaf(device: &TestE2EEDevice) -> MlsMemberDevice {
        MlsMemberDevice {
            user_id: device.user_id.clone(),
            device_id: device.device_id.clone(),
        }
    }

    fn b64_random(length: usize) -> String {
        let mut bytes = vec![0u8; length];
        rand::thread_rng().fill(&mut bytes[..]);
        STANDARD_NO_PAD.encode(bytes)
    }

    /// `wire` with `signer`'s signature over its payload (design 3.14.5)
    fn signed(signer: &TestE2EEDevice, mut wire: v0::HistoryLinkWire) -> v0::HistoryLinkWire {
        wire.signature = signer.sign(&history_link_signature_payload(&wire));
        wire
    }

    /// A link held at (`group_id`, `epoch`) carrying (`prev_group_id`,
    /// `prev_epoch`), written and signed by `writer`: a fresh nonce and
    /// ciphertext each time
    fn link(
        writer: &TestE2EEDevice,
        group_id: &str,
        epoch: i64,
        prev_group_id: &str,
        prev_epoch: i64,
    ) -> v0::HistoryLinkWire {
        signed(
            writer,
            v0::HistoryLinkWire {
                group_id: group_id.to_string(),
                epoch,
                prev_group_id: prev_group_id.to_string(),
                prev_epoch,
                nonce: b64_random(24),
                ciphertext: b64_random(CIPHERTEXT_BYTES),
                writer_user_id: writer.user_id.clone(),
                writer_device_id: writer.device_id.clone(),
                signature: String::new(),
            },
        )
    }

    /// An ordinary link (e' >= 1): G = G' and e = e' - 1
    fn ordinary(writer: &TestE2EEDevice, group_id: &str, epoch: i64) -> v0::HistoryLinkWire {
        link(writer, group_id, epoch, group_id, epoch - 1)
    }

    /// [`ordinary`] with a nonce of 3 bytes: refused by request validation
    fn malformed(writer: &TestE2EEDevice, group_id: &str, epoch: i64) -> v0::HistoryLinkWire {
        let mut wire = ordinary(writer, group_id, epoch);
        wire.nonce = "AAAA".to_string();
        signed(writer, wire)
    }

    /// The response body a refusal serializes to (it carries no `location`)
    #[track_caller]
    fn refusal<T: std::fmt::Debug>(result: Result<T>, case: &str) -> String {
        match result {
            Err(error) => serde_json::to_string(&error).expect("an error body"),
            Ok(accepted) => panic!("{}: accepted {:?}", case, accepted),
        }
    }

    /// The refusal's body, after checking its `type`
    #[track_caller]
    fn assert_refused<T: std::fmt::Debug>(result: Result<T>, expected: &str, case: &str) -> Value {
        let body: Value = serde_json::from_str(&refusal(result, case)).expect("JSON");
        assert_eq!(body["type"], expected, "{}: {}", case, body);
        body
    }

    #[track_caller]
    fn assert_stored(result: Result<()>, case: &str) {
        if let Err(error) = result {
            panic!("{}: refused {:?}", case, error);
        }
    }

    #[track_caller]
    fn assert_won(outcome: Result<MlsCommitOutcome>, what: &str) {
        match outcome {
            Ok(MlsCommitOutcome::Won) => {}
            other => panic!("{}: expected Won, got {:?}", what, other),
        }
    }

    /// A Text commit row by `committer` at `epoch` adding `added`, with
    /// `history_visible` as the commit route stores it (2.5 "S4")
    fn commit(
        group_id: &str,
        epoch: i64,
        committer: &MlsMemberDevice,
        added: Vec<MlsMemberDevice>,
        history_visible: Option<bool>,
    ) -> MlsCommit {
        MlsCommit {
            id: MlsCommit::composite_id(group_id, epoch),
            group_id: group_id.to_string(),
            epoch,
            committer: committer.clone(),
            commit: format!("Y29tbWl0{epoch}"),
            size: 8,
            added,
            removed: vec![],
            created_at: Timestamp::now_utc(),
            rejoin_intents: vec![],
            removed_reasons: vec![],
            welcome: None,
            history_visible,
            added_protocols: vec![],
        }
    }

    /// Set a group's `history_visible_at_create` in the store (the route
    /// tests' lists are v1, whose groups record `Some(false)`)
    async fn set_visible_at_create(db: &Database, group_id: &str, visible: Option<bool>) {
        match db {
            Database::Reference(reference) => {
                reference
                    .mls_groups
                    .lock()
                    .await
                    .get_mut(group_id)
                    .expect("the group")
                    .history_visible_at_create = visible;
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, Document};

                let update = match visible {
                    Some(visible) => doc! { "$set": { "history_visible_at_create": visible } },
                    None => doc! { "$unset": { "history_visible_at_create": 1 } },
                };
                let result = mongo
                    .col::<Document>("mls_groups")
                    .update_one(doc! { "_id": group_id }, update)
                    .await
                    .expect("the group write");
                assert_eq!(result.matched_count, 1, "the group row");
            }
        }
        assert_eq!(
            db.fetch_mls_group(group_id)
                .await
                .expect("the group")
                .history_visible_at_create,
            visible
        );
    }

    /// Delete the commit row at `epoch`, as retention does (R9)
    async fn prune_commit(db: &Database, group_id: &str, epoch: i64) {
        let row_id = MlsCommit::composite_id(group_id, epoch);
        match db {
            Database::Reference(reference) => {
                let mut commits = reference.mls_commits.lock().await;
                let before = commits.len();
                commits.retain(|_, row| row.id != row_id);
                assert_eq!(commits.len() + 1, before, "one row at the id");
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, Document};

                let result = mongo
                    .col::<Document>("mls_commits")
                    .delete_one(doc! { "_id": &row_id })
                    .await
                    .expect("prune the row");
                assert_eq!(result.deleted_count, 1);
            }
        }
    }

    /// (holder epoch, writer user) of every stored link of `group_id`, in
    /// the driver's order
    async fn stored(db: &Database, group_id: &str) -> Vec<(i64, String)> {
        db.fetch_mls_history_links(group_id, None, 200)
            .await
            .expect("the stored links")
            .into_iter()
            .map(|row| (row.epoch, row.writer_user_id))
            .collect()
    }

    /// A user, its harness session, and its device: bound to that session
    /// unless built by [`unbound_caller`]
    struct Caller {
        user: User,
        session: Session,
        device: TestE2EEDevice,
    }

    impl Caller {
        /// This caller's PUT of `wire` at the holder it names
        async fn put(&self, db: &Database, wire: &v0::HistoryLinkWire) -> Result<()> {
            put(
                db,
                &self.user,
                &self.session,
                &wire.group_id,
                wire.epoch,
                None,
                wire,
            )
            .await
        }

        async fn get(
            &self,
            db: &Database,
            group_id: &str,
            before: Option<i64>,
            limit: Option<i64>,
        ) -> Result<v0::ResponseHistoryLinks> {
            get(db, &self.user, &self.session, group_id, before, limit).await
        }
    }

    async fn caller(harness: &TestHarness, seed: u8) -> Caller {
        let (_, session, user) = harness.new_user().await;
        let device = harness.new_e2ee_device(&user, &session.id, seed).await;
        Caller {
            user,
            session,
            device,
        }
    }

    /// A caller whose session is bound to none of its devices
    async fn unbound_caller(harness: &TestHarness, seed: u8) -> Caller {
        let (_, session, user) = harness.new_user().await;
        let device = harness
            .new_e2ee_device(&user, &Ulid::new().to_string(), seed)
            .await;
        Caller {
            user,
            session,
            device,
        }
    }

    struct Fixture {
        harness: TestHarness,
        server_id: String,
        channel: Channel,
        /// Generation 0. Commit rows (`history_visible`): 1 true (Adds every
        /// device but the late one's), 2 true (Adds the late device), 3
        /// true, 4 false, 5 true, 6 `None` (written before S4), 7 pruned, 8
        /// true; its epoch 0 is visible
        g0: String,
        /// Seated, the creator (epoch 0)
        owner: Caller,
        /// Seated; Added at epoch 1
        member: Caller,
        /// The member's second device, Added at epoch 1, bound to ANOTHER
        /// session than the member's
        member_second: TestE2EEDevice,
        /// Seated; Added at epoch 1
        writers: Vec<Caller>,
        /// Seated; Added at epoch 1
        sixth: Caller,
        /// Seated; Added at epoch 2
        late: Caller,
        /// Seated; its bound device was never Added
        joiner: Caller,
    }

    /// A protected channel seating everyone above and its generation-0 Text
    /// group, with eight commits through the real Text commit transaction
    async fn fixture() -> Fixture {
        let harness = Box::pin(TestHarness::new()).await;
        let db = &harness.db;
        let (_, owner_session, owner_user) = harness.new_user().await;
        let member = caller(&harness, MEMBER_DEVICE_SEED).await;
        let member_second = harness
            .new_e2ee_device(&member.user, &Ulid::new().to_string(), SECOND_DEVICE_SEED)
            .await;
        let mut writers = Vec::new();
        for seed in WRITER_SEEDS {
            writers.push(caller(&harness, seed).await);
        }
        let sixth = caller(&harness, SIXTH_SEED).await;
        let late = caller(&harness, LATE_SEED).await;
        let joiner = caller(&harness, JOINER_SEED).await;

        let mut seated = vec![&member.user, &sixth.user, &late.user, &joiner.user];
        seated.extend(writers.iter().map(|writer| &writer.user));
        let protected =
            Box::pin(harness.new_protected_channel(&owner_user, &owner_session, &seated)).await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let hash = group
            .seat_list_ad_sha256
            .clone()
            .expect("the group binds the genesis list");
        let owner_leaf = leaf(&protected.owner_device);

        let mut first_adds = vec![
            leaf(&member.device),
            leaf(&member_second),
            leaf(&sixth.device),
        ];
        first_adds.extend(writers.iter().map(|writer| leaf(&writer.device)));
        for (epoch, added, visible) in [
            (1, first_adds, Some(true)),
            (2, vec![leaf(&late.device)], Some(true)),
            (3, vec![], Some(true)),
            (4, vec![], Some(false)),
            (5, vec![], Some(true)),
            (6, vec![], None),
            (7, vec![], Some(true)),
            (8, vec![], Some(true)),
        ] {
            assert_won(
                db.insert_mls_text_commit(
                    &commit(&group.id, epoch, &owner_leaf, added, visible),
                    &hash,
                    0,
                )
                .await,
                &format!("the epoch {epoch} commit"),
            );
        }
        prune_commit(db, &group.id, 7).await;
        set_visible_at_create(db, &group.id, Some(true)).await;

        // The visibility the route reads is the one stored
        let rows = db
            .fetch_mls_text_commits_from(&group.id, 1, 100)
            .await
            .expect("the commit rows");
        assert_eq!(
            rows.iter()
                .map(|row| (row.epoch, row.history_visible))
                .collect::<Vec<_>>(),
            vec![
                (1, Some(true)),
                (2, Some(true)),
                (3, Some(true)),
                (4, Some(false)),
                (5, Some(true)),
                (6, None),
                (8, Some(true)),
            ]
        );

        Fixture {
            server_id: protected.server.id.clone(),
            channel: protected.channel,
            g0: group.id,
            owner: Caller {
                user: owner_user,
                session: owner_session,
                device: protected.owner_device,
            },
            member,
            member_second,
            writers,
            sixth,
            late,
            joiner,
            harness,
        }
    }

    /// An ordinary link is stored, and each rule of the 6.1 "S4" row
    /// refuses with its own answer. Every refused link is validly signed by
    /// its writer, so only the rule under test refuses it.
    #[test]
    fn an_ordinary_link_is_stored_and_every_rule_refuses() {
        on_a_big_stack(|| {
            crate::util::test::rt().block_on(async {
                with_history(|_| {}).await;
                Box::pin(an_ordinary_link_case()).await
            })
        })
    }

    async fn an_ordinary_link_case() {
        let fixture = Box::pin(fixture()).await;
        let db = &fixture.harness.db;
        let g0 = fixture.g0.as_str();
        let owner = &fixture.owner;
        let member = &fixture.member;
        let late = &fixture.late;
        let peer = &fixture.writers[0];

        // The creator holds e' = 1 (commit 1 and the group's epoch 0
        // visible); a device Added by commit 1 holds e' = 2; the device
        // Added by commit 2 holds e' = 3
        assert_stored(
            owner.put(db, &ordinary(&owner.device, g0, 1)).await,
            "e' = 1",
        );
        assert_stored(
            member.put(db, &ordinary(&member.device, g0, 2)).await,
            "e' = 2",
        );
        assert_stored(late.put(db, &ordinary(&late.device, g0, 3)).await, "e' = 3");

        // member_added < e': a device Added by the commit into e' never
        // held e' - 1
        for (writer, epoch) in [(late, 2), (peer, 1)] {
            assert_refused(
                writer.put(db, &ordinary(&writer.device, g0, epoch)).await,
                "InvalidOperation",
                "Added at e'",
            );
        }

        // Both transitions must be visible, from rows that exist
        for (epoch, case) in [
            (4, "the transition into e' is hidden"),
            (5, "the transition into e' - 1 is hidden"),
            (6, "the row at e' predates S4"),
            (7, "the row at e' is pruned"),
            (8, "the row at e' - 1 is pruned"),
        ] {
            assert_refused(
                owner.put(db, &ordinary(&owner.device, g0, epoch)).await,
                "InvalidOperation",
                case,
            );
        }
        // e' = 1 reads epoch 0 from the group
        for (visible, case) in [
            (Some(false), "epoch 0 is hidden"),
            (None, "the group predates S4"),
        ] {
            set_visible_at_create(db, g0, visible).await;
            assert_refused(
                owner.put(db, &ordinary(&owner.device, g0, 1)).await,
                "InvalidOperation",
                case,
            );
        }
        set_visible_at_create(db, g0, Some(true)).await;

        // e' <= current_epoch(G')
        assert_refused(
            owner.put(db, &ordinary(&owner.device, g0, 9)).await,
            "FailedValidation",
            "past the current epoch",
        );

        // The chain: G = G' and e = e' - 1
        for (case, wire) in [
            (
                "another prev group",
                link(&owner.device, g0, 2, &random_group_id(), 1),
            ),
            ("prev epoch e' - 2", link(&owner.device, g0, 2, g0, 0)),
            ("prev epoch e'", link(&owner.device, g0, 2, g0, 2)),
        ] {
            assert_refused(owner.put(db, &wire).await, "InvalidOperation", case);
        }

        // The writer is the caller, from a device this session is bound to
        let mut as_peer = ordinary(&member.device, g0, 2);
        as_peer.writer_user_id = peer.user.id.clone();
        let as_peer = signed(&member.device, as_peer);
        let unregistered = TestE2EEDevice::new(
            &member.user.id,
            &format!("{:032x}", Ulid::new().0),
            UNREGISTERED_SEED,
            &member.session.id,
        );
        for (case, wire) in [
            ("another user's link", ordinary(&peer.device, g0, 2)),
            ("another user named on an own device", as_peer),
            (
                "an own device bound to another session",
                ordinary(&fixture.member_second, g0, 2),
            ),
            ("an unregistered device", ordinary(&unregistered, g0, 2)),
        ] {
            assert_refused(member.put(db, &wire).await, "NotAuthenticated", case);
        }

        // The writer device is a current member of G'
        let joiner = &fixture.joiner;
        let body = assert_refused(
            joiner.put(db, &ordinary(&joiner.device, g0, 2)).await,
            "ProtectedChannelResecuring",
            "not a member",
        );
        assert_eq!(body["reason"], "not_member", "{}", body);

        // The signature verifies under the writer's directory key (a writer
        // whose slot at e' is still free)
        let foreign = signed(&fixture.member_second, ordinary(&peer.device, g0, 2));
        let mut tampered = ordinary(&peer.device, g0, 2);
        tampered.ciphertext = b64_random(CIPHERTEXT_BYTES);
        for (case, wire) in [
            ("signed by another device", foreign),
            ("changed after signing", tampered),
        ] {
            let body = assert_refused(peer.put(db, &wire).await, "FailedValidation", case);
            assert_eq!(
                body["error"], "invalid history link signature",
                "{}: {}",
                case, body
            );
        }

        // Request validation: the path names the holder, the shapes hold
        let elsewhere = ordinary(&member.device, &random_group_id(), 2);
        let mut oversized = ordinary(&member.device, g0, 2);
        oversized.ciphertext = b64_random(40961);
        let oversized = signed(&member.device, oversized);
        for (case, path_epoch, wire) in [
            ("the body names another group", 2, elsewhere),
            (
                "the body names another epoch",
                3,
                ordinary(&member.device, g0, 2),
            ),
            ("a 3-byte nonce", 2, malformed(&member.device, g0, 2)),
            ("a ciphertext over 40 KiB", 2, oversized),
        ] {
            assert_refused(
                put(
                    db,
                    &member.user,
                    &member.session,
                    g0,
                    path_epoch,
                    None,
                    &wire,
                )
                .await,
                "FailedValidation",
                case,
            );
        }

        // Nothing refused was stored
        assert_eq!(
            stored(db, g0).await,
            vec![
                (3, late.user.id.clone()),
                (2, member.user.id.clone()),
                (1, owner.user.id.clone()),
            ]
        );

        // The seat: a member whose seat was released is refused both verbs
        let released = db
            .release_channel_seats_for_user(
                &peer.user.id,
                Some(&fixture.server_id),
                Timestamp::now_utc(),
            )
            .await
            .expect("release");
        assert_eq!(released, vec![fixture.channel.id().to_string()]);
        assert_refused(
            peer.put(db, &ordinary(&peer.device, g0, 2)).await,
            "NotSeated",
            "an unseated writer",
        );
        assert_refused(
            peer.get(db, g0, None, None).await,
            "NotSeated",
            "an unseated reader",
        );
    }

    /// A bridge (e' = 0) by the successor's creator carries a visible epoch
    /// of the group it supersedes; each e' = 0 rule refuses alone. A closed
    /// G' still takes late ordinary links.
    #[test]
    fn a_bridge_link_follows_the_bridge_rules() {
        on_a_big_stack(|| {
            crate::util::test::rt().block_on(async {
                with_history(|_| {}).await;
                Box::pin(a_bridge_link_case()).await
            })
        })
    }

    async fn a_bridge_link_case() {
        let fixture = Box::pin(fixture()).await;
        let db = &fixture.harness.db;
        let g0 = fixture.g0.as_str();
        let owner = &fixture.owner;
        let member = &fixture.member;

        // Generation 1 supersedes G0 (closing it); the member's device is
        // Added to it at epoch 1
        let successor = fixture
            .harness
            .new_text_group(&fixture.channel, &owner.device, 1, Some(g0))
            .await;
        assert_won(
            db.insert_mls_text_commit(
                &commit(
                    &successor.id,
                    1,
                    &leaf(&owner.device),
                    vec![leaf(&member.device)],
                    Some(true),
                ),
                successor
                    .seat_list_ad_sha256
                    .as_deref()
                    .expect("the successor binds the list"),
                0,
            )
            .await,
            "the successor's epoch 1 Add",
        );
        let g1 = successor.id.as_str();
        set_visible_at_create(db, g1, Some(true)).await;
        assert!(!db.fetch_mls_group(g0).await.expect("G0").open);

        let bridge = |prev_group_id: &str, prev_epoch: i64| {
            link(&owner.device, g1, 0, prev_group_id, prev_epoch)
        };

        // Every refusal first: the creator's one slot stays free
        for (case, wire) in [
            ("G hides the epoch", bridge(g0, 4)),
            ("G's row predates S4", bridge(g0, 6)),
            ("G's row is pruned", bridge(g0, 7)),
            ("past G's current epoch", bridge(g0, 9)),
            ("G is the holder itself", bridge(g1, 0)),
            ("G is no group", bridge(&random_group_id(), 2)),
        ] {
            assert_refused(owner.put(db, &wire).await, "InvalidOperation", case);
        }
        // The bridge transition itself must be visible
        for (visible, case) in [
            (Some(false), "the bridge transition is hidden"),
            (None, "the successor predates S4"),
        ] {
            set_visible_at_create(db, g1, visible).await;
            assert_refused(
                owner.put(db, &bridge(g0, 2)).await,
                "InvalidOperation",
                case,
            );
        }
        set_visible_at_create(db, g1, Some(true)).await;
        // G's epoch 0 is read from G
        set_visible_at_create(db, g0, Some(false)).await;
        assert_refused(
            owner.put(db, &bridge(g0, 0)).await,
            "InvalidOperation",
            "G's epoch 0 is hidden",
        );
        set_visible_at_create(db, g0, Some(true)).await;
        // Only the creator writes a bridge
        assert_refused(
            member.put(db, &link(&member.device, g1, 0, g0, 2)).await,
            "InvalidOperation",
            "a member Added at epoch 1",
        );
        let joiner = &fixture.joiner;
        assert_refused(
            joiner.put(db, &link(&joiner.device, g1, 0, g0, 2)).await,
            "ProtectedChannelResecuring",
            "not a member",
        );
        // A first group has no predecessor
        assert_refused(
            owner
                .put(db, &link(&owner.device, g0, 0, &random_group_id(), 0))
                .await,
            "InvalidOperation",
            "generation 0",
        );
        assert!(stored(db, g1).await.is_empty());

        let stored_bridge = bridge(g0, 2);
        assert_stored(owner.put(db, &stored_bridge).await, "the bridge");
        assert_eq!(stored(db, g1).await, vec![(0, owner.user.id.clone())]);
        let page = member.get(db, g1, None, None).await.expect("the page");
        assert_eq!(page.links, vec![stored_bridge]);

        // The closed G0 still takes a late ordinary link
        assert_stored(
            member.put(db, &ordinary(&member.device, g0, 2)).await,
            "a late link on the closed group",
        );
        assert_eq!(stored(db, g0).await, vec![(2, member.user.id.clone())]);
    }

    /// A bridge's G must be THIS channel's Text group at generation g - 1
    /// (6.1 "S4"): another channel's Text group and a Call group of this
    /// channel are `InvalidOperation`, though each is at generation 0 and
    /// passes every other e' = 0 rule
    #[test]
    fn a_bridge_names_its_own_channels_text_group() {
        on_a_big_stack(|| {
            crate::util::test::rt().block_on(async {
                with_history(|_| {}).await;
                Box::pin(bridge_predecessor_case()).await
            })
        })
    }

    async fn bridge_predecessor_case() {
        let harness = Box::pin(TestHarness::new()).await;
        let db = &harness.db;
        let (_, session, user) = harness.new_user().await;
        let protected = Box::pin(harness.new_protected_channel(&user, &session, &[])).await;
        let creator = &protected.owner_device;
        let g0 = harness
            .new_text_group(&protected.channel, creator, 0, None)
            .await;
        set_visible_at_create(db, &g0.id, Some(true)).await;
        let g1 = harness
            .new_text_group(&protected.channel, creator, 1, Some(&g0.id))
            .await;
        set_visible_at_create(db, &g1.id, Some(true)).await;

        // Another channel's generation-0 Text group, its epoch 0 visible
        let (_, other_session, other_user) = harness.new_user().await;
        let other = Box::pin(harness.new_protected_channel(&other_user, &other_session, &[])).await;
        let foreign = harness
            .new_text_group(&other.channel, &other.owner_device, 0, None)
            .await;
        set_visible_at_create(db, &foreign.id, Some(true)).await;

        // A closed Call group of THIS channel stored at generation 0, its
        // epoch 0 visible
        let creator_leaf = leaf(creator);
        let call = MlsGroup {
            id: random_group_id(),
            channel_id: protected.channel.id().to_string(),
            open: false,
            created_by: creator_leaf.clone(),
            created_at: Timestamp::now_utc(),
            current_epoch: 0,
            members: vec![creator_leaf],
            closed_at: Some(Timestamp::now_utc()),
            superseded_by: None,
            kind: MlsGroupKind::Call,
            generation: Some(0),
            seat_list_ad_sha256: None,
            pending_removals: vec![],
            member_added: vec![],
            pending_device_removals: vec![],
            signer_lost: None,
            rejoin_readd: vec![],
            history_visible_at_create: Some(true),
        };
        assert!(matches!(
            db.create_mls_group(&call, None)
                .await
                .expect("the call group"),
            MlsGroupCreateOutcome::Created
        ));

        // Each differs from G0 in the one field under test
        for (case, group_id, text, channel_id) in [
            (
                "another channel's Text group",
                foreign.id.as_str(),
                true,
                other.channel.id(),
            ),
            (
                "a Call group of this channel",
                call.id.as_str(),
                false,
                protected.channel.id(),
            ),
        ] {
            let previous = db.fetch_mls_group(group_id).await.expect("the group");
            assert_eq!(previous.is_text(), text, "{}", case);
            assert_eq!(previous.channel_id, channel_id, "{}", case);
            assert_eq!(previous.generation, Some(0), "{}", case);
            assert_eq!(previous.history_visible_at_create, Some(true), "{}", case);
            assert_eq!(previous.current_epoch, 0, "{}", case);

            assert_refused(
                put(
                    db,
                    &user,
                    &session,
                    &g1.id,
                    0,
                    None,
                    &link(creator, &g1.id, 0, group_id, 0),
                )
                .await,
                "InvalidOperation",
                case,
            );
        }
        assert!(stored(db, &g1.id).await.is_empty());

        // The same bridge naming G0 is stored
        assert_stored(
            put(
                db,
                &user,
                &session,
                &g1.id,
                0,
                None,
                &link(creator, &g1.id, 0, &g0.id, 0),
            )
            .await,
            "the channel's Text group",
        );
        assert_eq!(stored(db, &g1.id).await, vec![(0, user.id.clone())]);
    }

    /// First write wins per writer USER: an identical re-PUT is a 204 that
    /// writes nothing, other bytes are `HistoryLinkExists`, and a sixth
    /// user at one holder epoch is `HistoryLinkExists`
    #[test]
    fn a_slot_takes_one_link_per_writer_user_and_five_users() {
        on_a_big_stack(|| {
            crate::util::test::rt().block_on(async {
                with_history(|_| {}).await;
                Box::pin(slots_case()).await
            })
        })
    }

    async fn slots_case() {
        let fixture = Box::pin(fixture()).await;
        let db = &fixture.harness.db;
        let g0 = fixture.g0.as_str();
        let member = &fixture.member;

        let first = ordinary(&member.device, g0, 2);
        assert_stored(member.put(db, &first).await, "the first write");
        assert_stored(member.put(db, &first).await, "an identical re-PUT");
        assert_refused(
            member.put(db, &ordinary(&member.device, g0, 2)).await,
            "HistoryLinkExists",
            "other bytes from the same user",
        );

        let mut writers = vec![&fixture.owner];
        writers.extend(fixture.writers.iter());
        for writer in &writers {
            assert_stored(
                writer.put(db, &ordinary(&writer.device, g0, 2)).await,
                "a candidate",
            );
        }
        let sixth = &fixture.sixth;
        assert_refused(
            sixth.put(db, &ordinary(&sixth.device, g0, 2)).await,
            "HistoryLinkExists",
            "a sixth writer user",
        );

        let mut users: BTreeSet<String> = writers
            .iter()
            .map(|writer| writer.user.id.clone())
            .collect();
        users.insert(member.user.id.clone());
        let rows = stored(db, g0).await;
        assert_eq!(rows.len(), 5, "{:?}", rows);
        assert!(rows.iter().all(|(epoch, _)| *epoch == 2), "{:?}", rows);
        assert_eq!(
            rows.into_iter()
                .map(|(_, user)| user)
                .collect::<BTreeSet<_>>(),
            users
        );
        let page = member.get(db, g0, None, None).await.expect("the page");
        assert!(page.links.contains(&first), "the first write is kept");
    }

    /// The byte caps refuse a link that would take the writer user's sum,
    /// or the group's, past its cap
    #[test]
    fn the_byte_caps_refuse() {
        on_a_big_stack(|| {
            crate::util::test::rt().block_on(async {
                with_history(|settings| {
                    let protected = &mut settings.features.protected_channels;
                    protected.history_link_user_cap_bytes = 90;
                    protected.history_link_group_cap_bytes = 150;
                })
                .await;
                Box::pin(byte_caps_case()).await
            })
        })
    }

    async fn byte_caps_case() {
        let fixture = Box::pin(fixture()).await;
        let db = &fixture.harness.db;
        let g0 = fixture.g0.as_str();
        let member = &fixture.member;

        // 48 bytes each. The member's second link would take it to 96 of
        // its 90 (the group to 96 of its 150)
        assert_stored(
            member.put(db, &ordinary(&member.device, g0, 2)).await,
            "under the user cap",
        );
        let body = assert_refused(
            member.put(db, &ordinary(&member.device, g0, 3)).await,
            "FailedValidation",
            "over the user cap",
        );
        assert_eq!(
            body["error"], "history link user byte cap reached",
            "{}",
            body
        );

        // The group reaches 144 of its 150; one more link would be 192
        let owner = &fixture.owner;
        assert_stored(
            owner.put(db, &ordinary(&owner.device, g0, 1)).await,
            "under the group cap",
        );
        let peer = &fixture.writers[0];
        assert_stored(
            peer.put(db, &ordinary(&peer.device, g0, 2)).await,
            "under the group cap",
        );
        let other = &fixture.writers[1];
        let body = assert_refused(
            other.put(db, &ordinary(&other.device, g0, 2)).await,
            "FailedValidation",
            "over the group cap",
        );
        assert_eq!(
            body["error"], "history link group byte cap reached",
            "{}",
            body
        );
        assert_eq!(stored(db, g0).await.len(), 3);
    }

    /// Paging: newest holder epoch first, an epoch never split, `limit`
    /// clamped to 5 ..= 200, and `next_before` the lowest epoch of every
    /// non-empty page, whatever its length
    #[test]
    fn pages_never_split_an_epoch_and_end_on_an_empty_page() {
        on_a_big_stack(|| {
            crate::util::test::rt().block_on(async {
                with_history(|_| {}).await;
                Box::pin(paging_case()).await
            })
        })
    }

    async fn paging_case() {
        let fixture = Box::pin(fixture()).await;
        let db = &fixture.harness.db;
        let g0 = fixture.g0.as_str();
        let (owner, member, peer, late) = (
            &fixture.owner,
            &fixture.member,
            &fixture.writers[0],
            &fixture.late,
        );

        let mut written = Vec::new();
        for (epoch, writers) in [
            (1, vec![owner]),
            (2, vec![owner, member, peer]),
            (3, vec![owner, member, late]),
        ] {
            for writer in writers {
                let wire = ordinary(&writer.device, g0, epoch);
                assert_stored(writer.put(db, &wire).await, "a link");
                written.push(wire);
            }
        }

        let epochs = |page: &v0::ResponseHistoryLinks| {
            page.links.iter().map(|link| link.epoch).collect::<Vec<_>>()
        };
        for (case, before, limit, expected, next_before) in [
            ("every row", None, None, vec![3, 3, 3, 2, 2, 2, 1], Some(1)),
            // Epoch 2 does not fit whole: a short page, and not the end
            ("a page of 5", None, Some(5), vec![3, 3, 3], Some(3)),
            (
                "a page of 6",
                None,
                Some(6),
                vec![3, 3, 3, 2, 2, 2],
                Some(2),
            ),
            ("1 is raised to 5", None, Some(1), vec![3, 3, 3], Some(3)),
            (
                "1000 is lowered to 200",
                None,
                Some(1000),
                vec![3, 3, 3, 2, 2, 2, 1],
                Some(1),
            ),
            ("the next page", Some(3), Some(5), vec![2, 2, 2, 1], Some(1)),
            ("the last page", Some(2), Some(5), vec![1], Some(1)),
            ("the end", Some(1), Some(5), vec![], None),
        ] {
            let page = member
                .get(db, g0, before, limit)
                .await
                .unwrap_or_else(|error| panic!("{}: refused {:?}", case, error));
            assert_eq!(epochs(&page), expected, "{}", case);
            assert_eq!(page.next_before, next_before, "{}", case);
        }

        // Each row is the stored wire, byte for byte; the end has no
        // `next_before` key at all
        let page = member.get(db, g0, None, None).await.expect("every row");
        let served: BTreeSet<String> = page
            .links
            .iter()
            .map(|link| serde_json::to_string(link).expect("JSON"))
            .collect();
        let expected: BTreeSet<String> = written
            .iter()
            .map(|link| serde_json::to_string(link).expect("JSON"))
            .collect();
        assert_eq!(served, expected);
        let end = member.get(db, g0, Some(1), None).await.expect("the end");
        assert_eq!(
            serde_json::to_value(&end).expect("JSON"),
            json!({ "links": [] })
        );
    }

    fn is_history_event(event: &EventV1, channel_id: &str) -> bool {
        matches!(event, EventV1::ProtectedChannelChanged { id, scope }
            if id == channel_id && scope == &vec![PROTECTED_SCOPE_HISTORY.to_string()])
    }

    /// `?contest=true` stores like any PUT and emits ONE
    /// `ProtectedChannelChanged { scope: ["history"] }` per group per 5
    /// minutes on the channel topic; a PUT without it, and a refused
    /// contest, emit nothing
    #[test]
    fn a_contest_emits_one_history_event() {
        on_a_big_stack(|| {
            crate::util::test::rt().block_on(async {
                with_history(|_| {}).await;
                Box::pin(contest_case()).await
            })
        })
    }

    async fn contest_case() {
        let mut fixture = Box::pin(fixture()).await;
        let db = fixture.harness.db.clone();
        let g0 = fixture.g0.clone();
        let channel_id = fixture.channel.id().to_string();

        {
            let owner = &fixture.owner;
            assert_stored(
                put(
                    &db,
                    &owner.user,
                    &owner.session,
                    &g0,
                    1,
                    Some(true),
                    &ordinary(&owner.device, &g0, 1),
                )
                .await,
                "a contest",
            );
        }
        // Taken off the wire, so it is not left in the buffer
        fixture
            .harness
            .wait_for_event(&channel_id, |event| is_history_event(event, &channel_id))
            .await;

        {
            let (member, peer, late) = (&fixture.member, &fixture.writers[0], &fixture.late);
            assert_stored(
                put(
                    &db,
                    &member.user,
                    &member.session,
                    &g0,
                    2,
                    Some(true),
                    &ordinary(&member.device, &g0, 2),
                )
                .await,
                "a second contest within 5 minutes",
            );
            assert_stored(
                member.put(&db, &ordinary(&member.device, &g0, 3)).await,
                "no contest",
            );
            assert_stored(
                put(
                    &db,
                    &peer.user,
                    &peer.session,
                    &g0,
                    2,
                    Some(false),
                    &ordinary(&peer.device, &g0, 2),
                )
                .await,
                "contest=false",
            );
            assert_refused(
                put(
                    &db,
                    &late.user,
                    &late.session,
                    &g0,
                    2,
                    Some(true),
                    &ordinary(&late.device, &g0, 2),
                )
                .await,
                "InvalidOperation",
                "a refused contest",
            );
        }
        assert_eq!(stored(&db, &g0).await.len(), 4);

        // Redis pub/sub is FIFO per subscription: once the marker is seen,
        // any later history event is in the buffer
        EventV1::ProtectedChannelChanged {
            id: channel_id.clone(),
            scope: vec!["marker".to_string()],
        }
        .p(channel_id.clone())
        .await;
        fixture
            .harness
            .wait_for_event(&channel_id, |event| {
                matches!(event, EventV1::ProtectedChannelChanged { scope, .. }
                    if scope == &vec!["marker".to_string()])
            })
            .await;
        fixture
            .harness
            .assert_no_buffered_event(&channel_id, |event| is_history_event(event, &channel_id));
    }

    /// The contest event's rate limit, alone: once per group per interval,
    /// per group, and the record forgets expired entries
    #[test]
    fn a_contest_event_goes_out_once_per_group_per_interval() {
        let mut last = BTreeMap::new();
        let start = Instant::now();
        let second = Duration::from_secs(1);

        assert!(contest_event_due(&mut last, "a", start));
        assert!(!contest_event_due(&mut last, "a", start));
        assert!(!contest_event_due(
            &mut last,
            "a",
            start + CONTEST_EVENT_INTERVAL - second
        ));
        assert!(contest_event_due(&mut last, "b", start + second));
        assert!(contest_event_due(
            &mut last,
            "a",
            start + CONTEST_EVENT_INTERVAL
        ));
        assert!(contest_event_due(
            &mut last,
            "c",
            start + CONTEST_EVENT_INTERVAL * 3
        ));
        assert_eq!(
            last.keys().cloned().collect::<Vec<_>>(),
            vec!["c".to_string()]
        );
    }

    /// Every `AUDIT mls_history_link_contest` line this test binary logged.
    /// The route writes it with `log::info!`, which has no other seam, so a
    /// test installs [`ContestAuditLog`] as the process logger (nothing
    /// else in the binary installs one) and filters by its own group id.
    static CONTEST_AUDIT_LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

    struct ContestAuditLog;

    impl log::Log for ContestAuditLog {
        fn enabled(&self, metadata: &log::Metadata) -> bool {
            metadata.level() <= log::Level::Info
        }

        fn log(&self, record: &log::Record) {
            let line = record.args().to_string();
            if self.enabled(record.metadata())
                && line.starts_with("AUDIT mls_history_link_contest ")
            {
                CONTEST_AUDIT_LINES
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(line);
            }
        }

        fn flush(&self) {}
    }

    /// Start capturing contest AUDIT lines (once per test binary). Panics
    /// if another logger is installed: the assertions would see nothing.
    fn capture_contest_audit_lines() {
        static LOGGER: ContestAuditLog = ContestAuditLog;
        static INSTALL: Once = Once::new();
        INSTALL.call_once(|| {
            log::set_logger(&LOGGER).expect("no other logger in this test binary");
            log::set_max_level(log::LevelFilter::Info);
        });
    }

    /// The captured contest AUDIT lines naming `group_id`, in log order
    fn contest_audit_lines(group_id: &str) -> Vec<String> {
        let needle = format!(" group={group_id} ");
        CONTEST_AUDIT_LINES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter(|line| line.contains(&needle))
            .cloned()
            .collect()
    }

    /// Every stored contest writes its AUDIT line (3.14.6, ids only), the
    /// rate-limited one too (7.5 "S4": a suppressed contest still writes
    /// it); a PUT without `?contest=true`, `contest=false` and a refused
    /// contest write none
    #[test]
    fn a_suppressed_contest_still_writes_its_audit_line() {
        on_a_big_stack(|| {
            crate::util::test::rt().block_on(async {
                with_history(|_| {}).await;
                Box::pin(contest_audit_case()).await
            })
        })
    }

    async fn contest_audit_case() {
        capture_contest_audit_lines();
        let mut fixture = Box::pin(fixture()).await;
        let db = fixture.harness.db.clone();
        let g0 = fixture.g0.clone();
        let channel_id = fixture.channel.id().to_string();
        let audit = |epoch: i64, writer: &User| {
            format!(
                "AUDIT mls_history_link_contest group={} epoch={} writer={}",
                g0, epoch, writer.id
            )
        };
        assert!(contest_audit_lines(&g0).is_empty());

        // The first contest emits the event and writes its line
        let owner = fixture.owner.user.clone();
        {
            let owner = &fixture.owner;
            assert_stored(
                put(
                    &db,
                    &owner.user,
                    &owner.session,
                    &g0,
                    1,
                    Some(true),
                    &ordinary(&owner.device, &g0, 1),
                )
                .await,
                "a contest",
            );
        }
        fixture
            .harness
            .wait_for_event(&channel_id, |event| is_history_event(event, &channel_id))
            .await;
        assert_eq!(contest_audit_lines(&g0), vec![audit(1, &owner)]);

        let member = fixture.member.user.clone();
        {
            let (member, peer, late) = (&fixture.member, &fixture.writers[0], &fixture.late);
            // Within 5 minutes: no event, still a line
            assert_stored(
                put(
                    &db,
                    &member.user,
                    &member.session,
                    &g0,
                    2,
                    Some(true),
                    &ordinary(&member.device, &g0, 2),
                )
                .await,
                "a suppressed contest",
            );
            assert_stored(
                member.put(&db, &ordinary(&member.device, &g0, 3)).await,
                "no contest",
            );
            assert_stored(
                put(
                    &db,
                    &peer.user,
                    &peer.session,
                    &g0,
                    2,
                    Some(false),
                    &ordinary(&peer.device, &g0, 2),
                )
                .await,
                "contest=false",
            );
            assert_refused(
                put(
                    &db,
                    &late.user,
                    &late.session,
                    &g0,
                    2,
                    Some(true),
                    &ordinary(&late.device, &g0, 2),
                )
                .await,
                "InvalidOperation",
                "a refused contest",
            );
        }
        assert_eq!(stored(&db, &g0).await.len(), 4);

        // The second contest really was suppressed: no history event
        // follows the first (the marker orders the buffer, as above)
        EventV1::ProtectedChannelChanged {
            id: channel_id.clone(),
            scope: vec!["marker".to_string()],
        }
        .p(channel_id.clone())
        .await;
        fixture
            .harness
            .wait_for_event(&channel_id, |event| {
                matches!(event, EventV1::ProtectedChannelChanged { scope, .. }
                    if scope == &vec!["marker".to_string()])
            })
            .await;
        fixture
            .harness
            .assert_no_buffered_event(&channel_id, |event| is_history_event(event, &channel_id));

        assert_eq!(
            contest_audit_lines(&g0),
            vec![audit(1, &owner), audit(2, &member)]
        );
    }

    struct Oracle {
        harness: TestHarness,
        /// Owns the visible channel
        owner: Caller,
        /// Seated everywhere, bound; on no Text group's roster
        member: Caller,
        /// Seated everywhere; its session is bound to none of its devices
        unbound: Caller,
        /// The visible channel's Text group, holding [`Oracle::seeded`]
        visible_group_id: String,
        /// Its channel denies `@everyone` ViewChannel
        hidden_group_id: String,
        /// Its channel is deleted
        deleted_group_id: String,
        call_group_id: String,
        /// Stored at the visible group's epoch 0 through the database
        seeded: v0::HistoryLinkWire,
    }

    /// Three protected channels seating the member and the unbound caller
    /// (one visible, one hidden from `@everyone`, one deleted), each with
    /// its Text group, and a Call group on another channel
    async fn oracle_fixture() -> Oracle {
        let harness = Box::pin(TestHarness::new()).await;
        let db = &harness.db;
        let (_, owner_session, owner_user) = harness.new_user().await;
        let member = caller(&harness, MEMBER_DEVICE_SEED).await;
        let unbound = unbound_caller(&harness, UNBOUND_SEED).await;
        let seated = [&member.user, &unbound.user];

        let visible =
            Box::pin(harness.new_protected_channel(&owner_user, &owner_session, &seated)).await;
        let visible_group = harness
            .new_text_group(&visible.channel, &visible.owner_device, 0, None)
            .await;
        let seeded = link(
            &visible.owner_device,
            &visible_group.id,
            0,
            &random_group_id(),
            0,
        );
        db.insert_mls_history_link(&MlsHistoryLink::from_wire(
            seeded.clone(),
            CIPHERTEXT_BYTES as i64,
            Timestamp::now_utc(),
        ))
        .await
        .expect("the seeded link");

        let (_, hidden_owner_session, hidden_owner) = harness.new_user().await;
        let hidden =
            Box::pin(harness.new_protected_channel(&hidden_owner, &hidden_owner_session, &seated))
                .await;
        let hidden_group = harness
            .new_text_group(&hidden.channel, &hidden.owner_device, 0, None)
            .await;
        let mut hidden_channel = hidden.channel.clone();
        hidden_channel
            .update(
                db,
                PartialChannel {
                    default_permissions: Some(OverrideField {
                        a: 0,
                        d: ChannelPermission::ViewChannel as i64,
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("deny view");

        let (_, deleted_owner_session, deleted_owner) = harness.new_user().await;
        let deleted = Box::pin(harness.new_protected_channel(
            &deleted_owner,
            &deleted_owner_session,
            &seated,
        ))
        .await;
        let deleted_group = harness
            .new_text_group(&deleted.channel, &deleted.owner_device, 0, None)
            .await;
        db.delete_channel(&deleted.channel)
            .await
            .expect("delete the channel");
        assert!(db.fetch_channel(deleted.channel.id()).await.is_err());

        let call_channel = harness.new_channel(&visible.server).await;
        let creator = leaf(&visible.owner_device);
        let call_group = MlsGroup {
            id: random_group_id(),
            channel_id: call_channel.id().to_string(),
            open: true,
            created_by: creator.clone(),
            created_at: Timestamp::now_utc(),
            current_epoch: 0,
            members: vec![creator],
            closed_at: None,
            superseded_by: None,
            kind: MlsGroupKind::Call,
            generation: None,
            seat_list_ad_sha256: None,
            pending_removals: vec![],
            member_added: vec![],
            pending_device_removals: vec![],
            signer_lost: None,
            rejoin_readd: vec![],
            history_visible_at_create: None,
        };
        assert!(matches!(
            db.create_mls_group(&call_group, None)
                .await
                .expect("the call group"),
            MlsGroupCreateOutcome::Created
        ));

        Oracle {
            owner: Caller {
                user: owner_user,
                session: owner_session,
                device: visible.owner_device,
            },
            member,
            unbound,
            visible_group_id: visible_group.id,
            hidden_group_id: hidden_group.id,
            deleted_group_id: deleted_group.id,
            call_group_id: call_group.id,
            seeded,
            harness,
        }
    }

    /// The flags a case runs under
    #[derive(Debug, Clone, Copy)]
    struct Flags {
        /// `media_e2ee_enabled` (off with E2EE off too)
        media: bool,
        e2ee: bool,
        history: bool,
    }

    /// The b1 oracle matrix for both verbs (design 6.1 "S4"): for a member,
    /// a bot and an unbound session, with a valid, a malformed and a
    /// contest body, an unknown id, a Call group, a hidden and a deleted
    /// channel's Text group answer exactly like a group id the server does
    /// not know (the full serialized body). Then what a viewer of the
    /// visible group gets.
    async fn hidden_and_missing_answer_alike(flags: Flags) {
        let oracle = Box::pin(oracle_fixture()).await;
        let db = &oracle.harness.db;
        let member = &oracle.member;
        let visible = oracle.visible_group_id.as_str();
        let mut bot = member.user.clone();
        bot.bot = Some(BotInformation {
            owner: oracle.owner.user.id.clone(),
        });
        let unbound = &oracle.unbound;

        for (class, user, session, device) in [
            ("member", &member.user, &member.session, &member.device),
            ("bot", &bot, &member.session, &member.device),
            ("unbound", &unbound.user, &unbound.session, &unbound.device),
        ] {
            let unknown_id = random_group_id();
            let unknown = refusal(
                put(
                    db,
                    user,
                    session,
                    &unknown_id,
                    1,
                    None,
                    &ordinary(device, &unknown_id, 1),
                )
                .await,
                "the unknown answer",
            );
            let expected = match (flags.media, class) {
                (false, _) => "FeatureDisabled",
                (true, "member") => "NotFound",
                (true, "bot") => "IsBot",
                (true, _) => "NotAuthenticated",
            };
            let value: Value = serde_json::from_str(&unknown).expect("JSON");
            assert_eq!(value["type"], expected, "{}: {}", class, unknown);
            assert_eq!(
                refusal(
                    get(db, user, session, &unknown_id, None, None).await,
                    "the unknown GET"
                ),
                unknown,
                "{}: the GET's unknown answer",
                class
            );

            for (target, group_id) in [
                ("another unknown id", random_group_id()),
                ("hidden", oracle.hidden_group_id.clone()),
                ("deleted", oracle.deleted_group_id.clone()),
                ("call", oracle.call_group_id.clone()),
            ] {
                for (body, contest, wire) in [
                    ("valid", None, ordinary(device, &group_id, 1)),
                    ("malformed", None, malformed(device, &group_id, 1)),
                    ("contest", Some(true), ordinary(device, &group_id, 1)),
                ] {
                    let case = format!("{class} {target} {body}");
                    let answer = refusal(
                        put(db, user, session, &group_id, 1, contest, &wire).await,
                        &case,
                    );
                    assert_eq!(answer, unknown, "{}", case);
                }
                let case = format!("{class} {target} GET");
                let answer = refusal(get(db, user, session, &group_id, None, None).await, &case);
                assert_eq!(answer, unknown, "{}", case);
            }

            // A viewer of the visible group past the dispatch: the shared
            // caller checks answer a bot and an unbound session. With the
            // media flag on that is the unknown answer itself; with it off
            // only a viewer can tell (decision 17 (W2))
            if class != "member" {
                let caller_check = if class == "bot" {
                    "IsBot"
                } else {
                    "NotAuthenticated"
                };
                let put_answer = refusal(
                    put(
                        db,
                        user,
                        session,
                        visible,
                        1,
                        None,
                        &ordinary(device, visible, 1),
                    )
                    .await,
                    &format!("{class} viewer PUT"),
                );
                let get_answer = refusal(
                    get(db, user, session, visible, None, None).await,
                    &format!("{class} viewer GET"),
                );
                for answer in [put_answer, get_answer] {
                    if flags.media {
                        assert_eq!(answer, unknown, "{} viewer", class);
                    } else {
                        let value: Value = serde_json::from_str(&answer).expect("JSON");
                        assert_eq!(value["type"], caller_check, "{}: {}", class, answer);
                    }
                }
            }
        }

        // The member, a seated viewer: request validation first, then the
        // available gate AND `history_setting` for the PUT, the available
        // gate alone for the GET
        assert_refused(
            member.put(db, &malformed(&member.device, visible, 1)).await,
            "FailedValidation",
            "a malformed body from a viewer",
        );
        let put_answer = member.put(db, &ordinary(&member.device, visible, 1)).await;
        let get_answer = member.get(db, visible, None, None).await;
        if !flags.e2ee {
            for body in [
                assert_refused(put_answer, "FeatureDisabled", "the viewer's PUT"),
                assert_refused(get_answer, "FeatureDisabled", "the viewer's GET"),
            ] {
                assert_eq!(body["feature"], "e2ee", "{}", body);
            }
            return;
        }
        if flags.history {
            // Past every gate: the member's device is on no roster
            let body = assert_refused(put_answer, "ProtectedChannelResecuring", "the viewer's PUT");
            assert_eq!(body["reason"], "not_member", "{}", body);
        } else {
            let body = assert_refused(put_answer, "FeatureDisabled", "the viewer's PUT");
            assert_eq!(body["feature"], "protected_history", "{}", body);
        }
        // A read never needs `history_setting`
        let page = get_answer.expect("the viewer's GET");
        assert_eq!(page.links, vec![oracle.seeded.clone()]);
        assert_eq!(page.next_before, Some(0));
    }

    #[test]
    fn hidden_and_missing_answer_alike_with_every_flag_on() {
        on_a_big_stack(|| {
            crate::util::test::rt().block_on(async {
                with_history(|_| {}).await;
                Box::pin(hidden_and_missing_answer_alike(Flags {
                    media: true,
                    e2ee: true,
                    history: true,
                }))
                .await
            })
        })
    }

    /// `history_setting` off (as `Revolt.test.toml` leaves it): the PUT is
    /// refused to a viewer, the GET still serves
    #[test]
    fn hidden_and_missing_answer_alike_with_history_off() {
        on_a_big_stack(|| {
            crate::util::test::rt().block_on(Box::pin(hidden_and_missing_answer_alike(Flags {
                media: true,
                e2ee: true,
                history: false,
            })))
        })
    }

    #[test]
    fn hidden_and_missing_answer_alike_with_e2ee_off() {
        on_a_big_stack(|| {
            crate::util::test::rt().block_on(async {
                with_history(|settings| settings.features.e2ee_enabled = false).await;
                Box::pin(hidden_and_missing_answer_alike(Flags {
                    media: false,
                    e2ee: false,
                    history: true,
                }))
                .await
            })
        })
    }

    /// A Text group ignores the media flag; the unknown answer is the media
    /// gate's
    #[test]
    fn hidden_and_missing_answer_alike_with_media_off() {
        on_a_big_stack(|| {
            crate::util::test::rt().block_on(async {
                with_history(|settings| settings.features.media_e2ee_enabled = false).await;
                Box::pin(hidden_and_missing_answer_alike(Flags {
                    media: false,
                    e2ee: true,
                    history: true,
                }))
                .await
            })
        })
    }

    /// The growth flag never stops either verb
    #[test]
    fn hidden_and_missing_answer_alike_with_growth_off() {
        on_a_big_stack(|| {
            crate::util::test::rt().block_on(async {
                with_history(|settings| settings.features.protected_channels.enabled = false).await;
                Box::pin(hidden_and_missing_answer_alike(Flags {
                    media: true,
                    e2ee: true,
                    history: true,
                }))
                .await
            })
        })
    }

    /// Both routes are mounted and in the OpenAPI spec under their path,
    /// method, tag and query (a route left out of
    /// `openapi_get_routes_spec!` is neither)
    #[test]
    fn the_history_link_routes_are_mounted_and_documented() {
        let (routes, spec) = super::super::routes();
        for (path, name, method, query) in [
            (
                "/groups/{group_id}/history_links/{epoch}",
                "put_history_link",
                rocket::http::Method::Put,
                &["contest"][..],
            ),
            (
                "/groups/{group_id}/history_links",
                "fetch_history_links",
                rocket::http::Method::Get,
                &["before", "limit"][..],
            ),
        ] {
            let item = spec.paths.get(path).unwrap_or_else(|| {
                panic!(
                    "{} is missing from the spec: {:?}",
                    path,
                    spec.paths.keys().collect::<Vec<_>>()
                )
            });
            let operation = match method {
                rocket::http::Method::Put => item.put.as_ref(),
                _ => item.get.as_ref(),
            }
            .unwrap_or_else(|| panic!("{}: no {} operation", path, method));
            assert!(
                operation.tags.iter().any(|tag| tag == "MLS"),
                "{:?}",
                operation.tags
            );
            let documented = serde_json::to_string(operation).expect("JSON");
            for parameter in query {
                assert!(
                    documented.contains(&format!("\"name\":\"{parameter}\"")),
                    "{}: {} is not documented: {}",
                    path,
                    parameter,
                    documented
                );
            }
            let route = routes
                .iter()
                .find(|route| route.name.as_deref() == Some(name))
                .unwrap_or_else(|| panic!("{} is not mounted", name));
            assert_eq!(route.method, method);
        }
    }
}
