//! Prot: pack and pay-exact sales, the wallet read, Cipher founding Prot and
//! the admin tools (S5a)
//!
//! Every Prot movement is one ledger posting
//! (`revolt_database::AbstractProtLedger`); this module decides what to post
//! and when. Money rules it keeps:
//! - a paid order is credited once, under `purchase:{order_id}`, and never
//!   refused for the wallet cap or the flags: the money is already taken
//! - a reversal claws back up to what the order credited, from the wallet
//!   only, under `clawback:{order_id}`; Prot already gone is recorded as the
//!   row's shortfall, never taken from anywhere else
//! - after any credit to a wallet commits, the account is checked again: a
//!   deleted one is forfeited (the second pass), so a credit that races an
//!   account deletion is never left in a dead wallet
//! - the wallet balance is published only on its owner's private topic
//! - the wallet cap (D18) is a checkout gate; Cipher grants are exempt and
//!   count only through the balance

use revolt_database::events::client::EventV1;
use revolt_database::{
    cipher_prot_posted, cipher_prot_shortfall, cipher_prot_target, prot_key_admin,
    prot_key_clawback, prot_key_purchase, prot_user_account, CipherMembership, CipherProtSync,
    Database, OrderState, PaymentOrder, PaymentProvider, ProtAmount, ProtApplyOutcome,
    ProtLedgerEntry, ProtPosting, ProtRef, VoidReason, PROT_ACTOR_PAYMENTS, PROT_SYS_ADJUST,
    PROT_SYS_CLAWED, PROT_SYS_ISSUED,
};
use revolt_models::v0::{self, CipherReturnTo, ProductFamily, ProtEntryKind};
use revolt_result::{create_error, Result};
use ulid::Ulid;

use super::{
    acquire, buyer_is_live, release, start_session_with_urls, write, Leased, ReverseKind,
    ReverseOutcome, CREATING_BLOCKS_MS, REGION_REFUSAL_MS,
};
use crate::catalog::{self, ProtChoice};
use crate::settings::{PaymentsSettings, ProtSalesSettings};
use crate::stripe::StripeApi;

/// Ledger rows in `GET /payments/prot/@me`
pub const PROT_RECENT_LIMIT: i64 = 20;

/// Largest amount one admin adjustment moves, either way (the route checks
/// the same bound; repeated here so no caller can post more)
const PROT_ADJUST_MAX: i64 = 1_000_000;

/// Longest admin adjustment nonce, in bytes (the route's bound)
const PROT_ADJUST_NONCE_MAX: usize = 64;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The wallet balance of `user_id` (0 when it has no account)
async fn wallet_balance(db: &Database, user_id: &str) -> Result<i64> {
    Ok(db
        .fetch_prot_account(&prot_user_account(user_id))
        .await?
        .map_or(0, |account| account.balance))
}

/// Publish the wallet's balance and version to its owner only, read after
/// the posting committed. Two postings can publish out of order; the
/// version lets the client keep the newer one. A failed read publishes
/// nothing (the client refetches `/@me`).
async fn publish_balance(db: &Database, user_id: &str) {
    match db.fetch_prot_account(&prot_user_account(user_id)).await {
        Ok(Some(account)) => {
            EventV1::ProtBalanceUpdate {
                balance: account.balance,
                version: account.version,
            }
            .private(user_id.to_string())
            .await
        }
        // A posting that named the wallet created its account
        Ok(None) => log::warn!(
            "payments: the Prot wallet of {user_id} has no account after a posting; nothing \
             published"
        ),
        Err(err) => log::warn!(
            "payments: could not read the Prot wallet of {user_id} to publish it: {err:?}"
        ),
    }
}

/// The second pass (account deletion): after a credit to the wallet of
/// `user_id` has committed, a deleted (or missing) account has its wallet
/// forfeited. Checked after the write, so either the deletion's own forfeit
/// sees the credit, or this sees the deletion.
async fn forfeit_if_deleted(db: &Database, user_id: &str, now_ms: i64) -> Result<()> {
    if buyer_is_live(db, user_id).await? {
        return Ok(());
    }

    if let Some(outcome) = db.forfeit_prot_wallet(user_id, now_ms).await? {
        let entry = outcome.entry();
        log::warn!(
            "payments: Prot credited to deleted account {user_id} was forfeited ({} Prot, key {})",
            entry.amount,
            entry.key
        );
    }
    Ok(())
}

/// One ledger row as the wallet owner sees it, signed from the wallet's side
fn ledger_view(wallet: &str, row: ProtLedgerEntry) -> v0::ProtLedgerView {
    let amount = if row.credit == wallet {
        row.amount
    } else {
        row.amount.saturating_neg()
    };
    v0::ProtLedgerView {
        id: row.id,
        kind: row.kind,
        amount,
        created_at: row.created_at,
        order_id: row.reference.order_id,
    }
}

// ---------------------------------------------------------------------------
// Checkout and standing
// ---------------------------------------------------------------------------

/// Whether `order` is a Prot `RegionUnavailable` void that still keeps its
/// buyer out of a Prot checkout: `region_refusal_holds` against the Prot
/// blocked list. A Cipher region void never blocks a Prot checkout (nor a
/// Prot one a Cipher checkout).
fn prot_region_refusal_holds(ps: &ProtSalesSettings, order: &PaymentOrder, now_ms: i64) -> bool {
    order.sku.family() == ProductFamily::Prot
        && matches!(order.state, OrderState::Voided | OrderState::Paid)
        && order.void_reason == Some(VoidReason::RegionUnavailable)
        && order
            .region_blocked_country
            .as_deref()
            .is_some_and(|country| ps.region_blocked(country))
        && order
            .reversed_at
            .or(order.paid_at)
            .is_some_and(|at| now_ms.saturating_sub(at) < REGION_REFUSAL_MS)
}

/// Start a Prot checkout. Gates, in this order:
/// 1. payments off → `PaymentsDisabled`; Prot off → `ProtDisabled`; Prot
///    sales closed → `ProtSalesClosed`; a bot → `IsBot` (the route refuses
///    bots too);
/// 2. a Prot region void of this buyer that still holds →
///    `ProtRegionUnavailable`;
/// 3. any order of the buyer (either family) in Creating, Pending, Paid or
///    Fulfilled with an open dispute → `ProtNotEligible`. Refunded and
///    Voided orders do not count: a dispute closed after the order was
///    Refunded is never removed from its `open_disputes`, so counting them
///    would lock the buyer out for good;
/// 4. the server's quote (`catalog::quote_prot`; `ProtPackInvalid`);
/// 5. the wallet cap (D18): balance + the Prot of every Paid Prot order of
///    the buyer not credited yet + this order's Prot > `wallet_cap` →
///    `ProtWalletCap`;
/// 6. one live Prot order per buyer: an unexpired Pending one for the same
///    SKU returns its URL, any other live one is `PaymentPending`.
///
/// Then the order is stored (the amount from the catalog and nothing else)
/// and its Stripe session started. Web checkouts return to the success or
/// cancel URL; shells return to the thanks page for both.
// The pinned contract signature: the Cipher checkout's arguments plus the
// Prot settings
#[allow(clippy::too_many_arguments)]
pub async fn create_prot_checkout(
    db: &Database,
    stripe: &dyn StripeApi,
    s: &PaymentsSettings,
    ps: &ProtSalesSettings,
    user_id: &str,
    choice: ProtChoice,
    return_to: CipherReturnTo,
    now_ms: i64,
) -> Result<String> {
    if !s.enabled {
        return Err(create_error!(PaymentsDisabled));
    }
    if !ps.enabled {
        return Err(create_error!(ProtDisabled));
    }
    if !ps.sales_open {
        return Err(create_error!(ProtSalesClosed));
    }
    if db.fetch_user(user_id).await?.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    // One read serves every order gate below
    let orders = db
        .fetch_payment_orders_by_user(
            user_id,
            &[
                OrderState::Creating,
                OrderState::Pending,
                OrderState::Paid,
                OrderState::Fulfilled,
                OrderState::Voided,
            ],
        )
        .await?;

    // Refunded for paying from a country Prot is not sold to, recently and
    // while that country is still blocked: each new checkout would be paid,
    // voided and refunded again, at a Stripe fee each time
    if orders
        .iter()
        .any(|order| prot_region_refusal_holds(ps, order, now_ms))
    {
        return Err(create_error!(ProtRegionUnavailable));
    }

    // No new Prot while a payment of the buyer is under dispute: the Prot
    // could be spent before the dispute is lost
    if orders.iter().any(|order| {
        matches!(
            order.state,
            OrderState::Creating | OrderState::Pending | OrderState::Paid | OrderState::Fulfilled
        ) && !order.open_disputes.is_empty()
    }) {
        return Err(create_error!(ProtNotEligible));
    }

    let sku = catalog::quote_prot(ps, &choice)?;
    let Some(prot) = catalog::sku_prot(&sku) else {
        log::error!("payments: the Prot quote for {user_id} is not a Prot SKU: {sku:?}");
        return Err(create_error!(InternalError));
    };

    // D18. A Paid order is credited whatever the cap says by then, so the
    // ones not credited yet count now. One whose purchase row exists (a
    // crash before its Fulfilled write) is already in the balance.
    let mut uncredited = 0_i64;
    for order in orders
        .iter()
        .filter(|o| o.state == OrderState::Paid && o.sku.family() == ProductFamily::Prot)
    {
        if !purchase_applied(db, &order.id).await? {
            uncredited = uncredited.saturating_add(catalog::sku_prot(&order.sku).unwrap_or(0));
        }
    }
    let balance = wallet_balance(db, user_id).await?;
    if balance.saturating_add(uncredited).saturating_add(prot) > ps.wallet_cap {
        return Err(create_error!(ProtWalletCap { max: ps.wallet_cap }));
    }

    // One live Prot order per buyer (a Cipher one never blocks it).
    // SessionFailed, Expired and stale Creating orders never block.
    for order in orders
        .iter()
        .rev()
        .filter(|o| o.sku.family() == ProductFamily::Prot)
    {
        match order.state {
            OrderState::Pending if order.session_expires_at.is_some_and(|at| at > now_ms) => {
                return match &order.checkout_url {
                    Some(url) if order.sku == sku => Ok(url.clone()),
                    _ => Err(create_error!(PaymentPending)),
                };
            }
            OrderState::Creating
                if now_ms.saturating_sub(order.created_at) < CREATING_BLOCKS_MS =>
            {
                return Err(create_error!(PaymentPending));
            }
            _ => {}
        }
    }

    let order = PaymentOrder {
        id: Ulid::new().to_string(),
        user_id: Some(user_id.to_string()),
        provider: PaymentProvider::Stripe,
        amount_cents: catalog::sku_cents(&sku)?,
        sku,
        currency: "usd".to_string(),
        checkout_session_id: None,
        checkout_url: None,
        session_expires_at: None,
        payment_intent_id: None,
        state: OrderState::Creating,
        void_reason: None,
        region_blocked_country: None,
        reversal_pending: None,
        refund_settling_since: None,
        open_disputes: vec![],
        lease_until: None,
        version: 0,
        created_at: now_ms,
        paid_at: None,
        fulfilled_at: None,
        reversed_at: None,
    };
    db.insert_payment_order(&order).await?;

    let Some(mut leased) = acquire(db, &order.id, now_ms).await? else {
        // Nobody else knows this order id yet
        log::error!("payments: lease on new order {} was already held", order.id);
        return Err(create_error!(InternalError));
    };
    let (success_url, cancel_url) = match return_to {
        CipherReturnTo::Web => (ps.success_url.clone(), ps.cancel_url.clone()),
        CipherReturnTo::Shell => (ps.shell_return_url.clone(), ps.shell_return_url.clone()),
    };
    let result = start_session_with_urls(db, stripe, s, &mut leased, success_url, cancel_url).await;
    release(db, &leased).await;
    result
}

/// The session user's wallet: balance and version from one account read
/// (both 0 without an account), the part of the balance under the D17
/// purchase hold (Purchase credits in the last `contribute_hold_hours`, at
/// most the balance; 0 when the hold is 0), the newest unexpired Prot
/// checkout, and the [`PROT_RECENT_LIMIT`] newest ledger rows
pub async fn prot_me(
    db: &Database,
    ps: &ProtSalesSettings,
    user_id: &str,
    now_ms: i64,
) -> Result<v0::ProtMe> {
    if !ps.enabled {
        return Err(create_error!(ProtDisabled));
    }

    let wallet = prot_user_account(user_id);
    let (balance, version) = db
        .fetch_prot_account(&wallet)
        .await?
        .map_or((0, 0), |account| (account.balance, account.version));

    let hold_ms = ps.hold_ms();
    let held = if hold_ms > 0 && balance > 0 {
        db.sum_prot_credits_since(
            &wallet,
            &[ProtEntryKind::Purchase],
            now_ms.saturating_sub(hold_ms),
        )
        .await?
        .clamp(0, balance)
    } else {
        0
    };

    let pending_order = db
        .fetch_payment_orders_by_user(user_id, &[OrderState::Pending])
        .await?
        .into_iter()
        .filter(|o| o.sku.family() == ProductFamily::Prot)
        .filter_map(|o| {
            let expires_at = o.session_expires_at?;
            (expires_at > now_ms && o.checkout_url.is_some()).then_some(v0::ProtPendingView {
                order_id: o.id,
                sku: o.sku,
                expires_at,
            })
        })
        .next_back();

    let recent = db
        .fetch_prot_entries_by_account(&wallet, None, PROT_RECENT_LIMIT)
        .await?
        .into_iter()
        .map(|row| ledger_view(&wallet, row))
        .collect();

    Ok(v0::ProtMe {
        balance,
        held,
        version,
        pending_order,
        recent,
    })
}

// ---------------------------------------------------------------------------
// Fulfilment and reversal of Prot orders
// ---------------------------------------------------------------------------

/// Whether the ledger row `purchase:{order_id}` exists
pub(super) async fn purchase_applied(db: &Database, order_id: &str) -> Result<bool> {
    Ok(db
        .fetch_prot_entry_by_key(&prot_key_purchase(order_id))
        .await?
        .is_some())
}

/// Credit a paid Prot order: `Exact(sku prot)` under `purchase:{order_id}`,
/// `sys:issued` → the buyer's wallet. Never refused for the wallet cap or
/// the flags (settling money already taken never depends on them);
/// AlreadyApplied is success. Then the balance is published and the second
/// pass runs.
pub(super) async fn apply_purchase(
    db: &Database,
    order: &PaymentOrder,
    user_id: &str,
    now_ms: i64,
) -> Result<()> {
    let Some(prot) = catalog::sku_prot(&order.sku) else {
        log::error!(
            "payments: order {} is not a Prot order ({:?}); nothing credited",
            order.id,
            order.sku
        );
        return Err(create_error!(InternalError));
    };

    let posting = ProtPosting {
        key: prot_key_purchase(&order.id),
        kind: ProtEntryKind::Purchase,
        debit: PROT_SYS_ISSUED.to_string(),
        credit: prot_user_account(user_id),
        amount: ProtAmount::Exact(prot),
        debit_floor: 0,
        actor: PROT_ACTOR_PAYMENTS.to_string(),
        reference: ProtRef {
            order_id: Some(order.id.clone()),
            ..Default::default()
        },
        reason: None,
        created_at: now_ms,
    };

    if let ProtApplyOutcome::Applied(entry) = db.apply_prot_posting(&posting).await? {
        log::info!(
            "payments: order {} credited {} Prot to {user_id} (ledger row {})",
            order.id,
            entry.amount,
            entry.id
        );
        Box::pin(publish_balance(db, user_id)).await;
    }

    forfeit_if_deleted(db, user_id, now_ms).await
}

/// A reversal of a Fulfilled Prot order, after the dispute bookkeeping
/// (`reverse_fulfilled`). An opened or won dispute changes nothing more
/// (NoOp). A refund (full or partial) or a lost dispute claws back up to
/// what the order credited, bonus included, from the wallet only
/// (`clawback:{order_id}`, the shortfall recorded on the row), then records
/// the order Refunded. An order unlinked by an account deletion has no
/// wallet to claw from (the deletion forfeited it); it is only recorded.
pub(super) async fn reverse_prot_fulfilled(
    db: &Database,
    leased: &mut Leased,
    kind: ReverseKind,
    now_ms: i64,
) -> Result<ReverseOutcome> {
    match kind {
        ReverseKind::DisputeOpened | ReverseKind::DisputeWon => return Ok(ReverseOutcome::NoOp),
        ReverseKind::Refund | ReverseKind::DisputeLost => {}
    }

    let order_id = leased.order.id.clone();
    match leased.order.user_id.clone() {
        None => log::info!(
            "payments: {kind:?} on Prot order {order_id}, unlinked by an account deletion; no \
             ledger action"
        ),
        Some(user_id) => clawback_purchase(db, &order_id, &user_id, now_ms).await?,
    }

    write(db, leased, move |o| {
        o.state = OrderState::Refunded;
        o.reversed_at = Some(now_ms);
        o.reversal_pending = None;
    })
    .await?;
    log::info!("payments: Prot order {order_id} reversed ({kind:?})");
    Ok(ReverseOutcome::Applied)
}

/// The clawback of a Prot purchase: `UpTo(what purchase:{order_id}
/// credited)` from the wallet to `sys:clawed`, once. Nothing when the order
/// was never credited or is clawed back already.
pub(super) async fn clawback_purchase(
    db: &Database,
    order_id: &str,
    user_id: &str,
    now_ms: i64,
) -> Result<()> {
    let Some(purchase) = db
        .fetch_prot_entry_by_key(&prot_key_purchase(order_id))
        .await?
    else {
        log::error!(
            "payments: PROT_REVERSAL_WITHOUT_PURCHASE order={order_id} user={user_id}: a \
             Fulfilled Prot order has no purchase row; nothing to claw back"
        );
        return Ok(());
    };

    let key = prot_key_clawback(order_id);
    if db.fetch_prot_entry_by_key(&key).await?.is_some() {
        return Ok(());
    }

    let posting = ProtPosting {
        key,
        kind: ProtEntryKind::Clawback,
        debit: prot_user_account(user_id),
        credit: PROT_SYS_CLAWED.to_string(),
        amount: ProtAmount::UpTo(purchase.amount),
        debit_floor: 0,
        actor: PROT_ACTOR_PAYMENTS.to_string(),
        reference: ProtRef {
            order_id: Some(order_id.to_string()),
            ..Default::default()
        },
        reason: None,
        created_at: now_ms,
    };

    if let ProtApplyOutcome::Applied(entry) = db.apply_prot_posting(&posting).await? {
        let shortfall = entry.shortfall.unwrap_or(0);
        if shortfall > 0 {
            log::warn!(
                "payments: PROT_CLAWBACK_SHORTFALL order={order_id} user={user_id} \
                 clawed={} shortfall={shortfall}",
                entry.amount
            );
        } else {
            log::info!(
                "payments: clawed back {} Prot of order {order_id} from {user_id}",
                entry.amount
            );
        }
        Box::pin(publish_balance(db, user_id)).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Cipher founding Prot (D2)
// ---------------------------------------------------------------------------

/// Upward sync of a member's Cipher Prot while grants are on
/// (`ps.grants_active()`): posts what the membership is owed, publishes the
/// balance after a posting written now, and runs the second pass. An
/// over-posted membership is logged at error level
/// (`PROT_CIPHER_OVERPOSTED`), never clawed back here.
pub async fn sync_cipher_prot(
    db: &Database,
    ps: &ProtSalesSettings,
    user_id: &str,
    now_ms: i64,
) -> Result<()> {
    if !ps.grants_active() {
        return Ok(());
    }

    match db.sync_cipher_prot(user_id, now_ms).await? {
        CipherProtSync::Nothing => Ok(()),
        CipherProtSync::Posted(outcome) => {
            if let ProtApplyOutcome::Applied(entry) = &outcome {
                log::info!(
                    "payments: credited {} Cipher Prot to {user_id} ({})",
                    entry.amount,
                    entry.key
                );
                Box::pin(publish_balance(db, user_id)).await;
            }
            forfeit_if_deleted(db, user_id, now_ms).await
        }
        CipherProtSync::OverPosted { posted, target } => {
            log::error!("PROT_CIPHER_OVERPOSTED user={user_id} posted={posted} target={target}");
            Ok(())
        }
    }
}

/// After a Cipher fulfilment: the upward sync with the loaded Prot settings
/// (closed when they do not validate). Never fails the caller; an error is
/// logged as `PROT_CIPHER_SYNC_FAILED`, and the hourly sweep makes it right.
pub(super) async fn sync_after_cipher_fulfil(db: &Database, user_id: &str, now_ms: i64) {
    let ps = ProtSalesSettings::load_or_closed().await;
    if let Err(err) = sync_cipher_prot(db, &ps, user_id, now_ms).await {
        log::error!(
            "payments: PROT_CIPHER_SYNC_FAILED user={user_id}: {err:?}; the hourly sweep retries"
        );
    }
}

/// The downward sync after a reversal of the Cipher order `order_id`, with
/// the balance published when Prot moved. Runs whatever the flags say (a
/// clawback only ever removes Prot that was posted). Ok(true) when a row was
/// written now: the membership version was bumped, so a caller holding a
/// read of the membership must read it again before its next
/// compare-and-swap.
pub(super) async fn clawback_cipher_order(
    db: &Database,
    user_id: &str,
    order_id: &str,
    now_ms: i64,
) -> Result<bool> {
    let Some(ProtApplyOutcome::Applied(entry)) =
        db.clawback_cipher_prot(user_id, order_id, now_ms).await?
    else {
        return Ok(false);
    };

    let shortfall = entry.shortfall.unwrap_or(0);
    if shortfall > 0 {
        log::warn!(
            "payments: PROT_CLAWBACK_SHORTFALL order={order_id} user={user_id} clawed={} \
             shortfall={shortfall}",
            entry.amount
        );
    } else {
        log::info!(
            "payments: clawed back {} Cipher Prot of order {order_id} from {user_id}",
            entry.amount
        );
    }
    if entry.amount > 0 {
        Box::pin(publish_balance(db, user_id)).await;
    }
    Ok(true)
}

/// The ledger rows of `m`'s current incarnation (base `orders[0]`); none
/// when `orders` is empty
async fn incarnation_rows(db: &Database, m: &CipherMembership) -> Result<Vec<ProtLedgerEntry>> {
    match m.orders.first() {
        Some(base) => db.fetch_prot_entries_by_membership(base).await,
        None => Ok(vec![]),
    }
}

/// Prot of `m`'s incarnation that was already spent when a clawback ran
/// (`cipher_prot_shortfall` over its rows; 0 when `orders` is empty).
/// Membership-wide, never per order: a shortfall recorded on one order's
/// clawback also stops the 14-day undo of another order of the membership.
pub(super) async fn membership_shortfall(db: &Database, m: &CipherMembership) -> Result<i64> {
    Ok(cipher_prot_shortfall(&incarnation_rows(db, m).await?))
}

/// The 14-day "hypothetical clawback", read-only: would clawing `m` back to
/// `target_after` be fully covered? Covered when the membership has no
/// recorded shortfall and the wallet holds what still needs clawing back
/// (`max(0, posted - target_after)`; nothing needed is covered).
pub(super) async fn window_clawback_covered(
    db: &Database,
    m: &CipherMembership,
    target_after: i64,
) -> Result<bool> {
    let rows = incarnation_rows(db, m).await?;
    if cipher_prot_shortfall(&rows) > 0 {
        return Ok(false);
    }

    let needed = cipher_prot_posted(&rows)
        .saturating_sub(target_after)
        .max(0);
    if needed == 0 {
        return Ok(true);
    }
    Ok(wallet_balance(db, &m.user_id).await? >= needed)
}

// ---------------------------------------------------------------------------
// Admin and account deletion
// ---------------------------------------------------------------------------

/// What the ledger says about one order, for support before a refund: the
/// order's credited, clawed-back and shortfall sums (rows with
/// `ref.order_id` = the order), the buyer's current balance, and, for a
/// Cipher order of the buyer's CURRENT membership incarnation
/// (`orders[0] <= order_id`: listed, or removed since by a window
/// downgrade), that membership's posted, target and shortfall. Otherwise (a
/// Prot order, an unlinked one, no membership, an order of a replaced
/// incarnation) those three are None. NotFound when there is no such order.
pub async fn admin_prot_order(db: &Database, order_id: &str) -> Result<v0::ProtAdminOrder> {
    let order = db
        .fetch_payment_order(order_id)
        .await?
        .ok_or_else(|| create_error!(NotFound))?;

    let (mut credited, mut clawed_back, mut shortfall) = (0_i64, 0_i64, 0_i64);
    for row in db.fetch_prot_entries_by_order(order_id).await? {
        match row.kind {
            ProtEntryKind::Purchase
            | ProtEntryKind::CipherFounding
            | ProtEntryKind::CipherUpgrade => credited = credited.saturating_add(row.amount),
            ProtEntryKind::Clawback => {
                clawed_back = clawed_back.saturating_add(row.amount);
                shortfall = shortfall.saturating_add(row.shortfall.unwrap_or(0));
            }
            _ => {}
        }
    }

    let unspent = match &order.user_id {
        Some(user_id) => Some(wallet_balance(db, user_id).await?),
        None => None,
    };

    let (mut m_posted, mut m_target, mut m_shortfall) = (None, None, None);
    if let (ProductFamily::Cipher, Some(user_id)) = (order.sku.family(), &order.user_id) {
        if let Some(m) = db.fetch_cipher_membership(user_id).await? {
            if let Some(base) = m.orders.first().filter(|base| base.as_str() <= order_id) {
                let rows = db.fetch_prot_entries_by_membership(base).await?;
                m_posted = Some(cipher_prot_posted(&rows));
                m_target = Some(cipher_prot_target(&m));
                m_shortfall = Some(cipher_prot_shortfall(&rows));
            }
        }
    }

    Ok(v0::ProtAdminOrder {
        order_id: order.id,
        user_id: order.user_id,
        sku: order.sku,
        credited,
        clawed_back,
        shortfall,
        unspent,
        membership_posted: m_posted,
        membership_target: m_target,
        membership_shortfall: m_shortfall,
    })
}

/// A staff adjustment of a wallet. amount > 0: `sys:adjust` → the wallet;
/// amount < 0: the wallet → `sys:adjust` (`Exact(-amount)`, floor 0,
/// `InsufficientProt` when the wallet is short). Key
/// `admin:{admin_id}:{nonce}`, actor `admin_id`, the reason on the row. The
/// balance is published after a posting written now, and after a credit the
/// second pass forfeits it again if the account was deleted between the
/// route's check and the posting. The route checks privilege, the MFA
/// ticket, the reason and that the target exists.
pub async fn admin_prot_adjust(
    db: &Database,
    admin_id: &str,
    data: &v0::DataProtAdjust,
    reason: String,
    now_ms: i64,
) -> Result<v0::ProtAdjustResponse> {
    if data.amount == 0 || data.amount.unsigned_abs() > PROT_ADJUST_MAX.unsigned_abs() {
        return Err(create_error!(FailedValidation {
            error: format!("amount must be non-zero and at most {PROT_ADJUST_MAX} either way")
        }));
    }
    if data.nonce.is_empty()
        || data.nonce.len() > PROT_ADJUST_NONCE_MAX
        || data.nonce.chars().any(char::is_control)
    {
        return Err(create_error!(FailedValidation {
            error: "nonce must be 1 to 64 printable bytes".to_string()
        }));
    }

    let wallet = prot_user_account(&data.user);
    let (debit, credit, amount) = if data.amount > 0 {
        (PROT_SYS_ADJUST.to_string(), wallet, data.amount)
    } else {
        (wallet, PROT_SYS_ADJUST.to_string(), -data.amount)
    };
    let posting = ProtPosting {
        key: prot_key_admin(admin_id, &data.nonce),
        kind: ProtEntryKind::AdminAdjust,
        debit,
        credit,
        amount: ProtAmount::Exact(amount),
        debit_floor: 0,
        actor: admin_id.to_string(),
        reference: ProtRef::default(),
        reason: Some(reason),
        created_at: now_ms,
    };

    let outcome = db.apply_prot_posting(&posting).await?;
    let applied = matches!(outcome, ProtApplyOutcome::Applied(_));
    if applied {
        log::info!(
            "payments: admin {admin_id} adjusted the Prot wallet of {} by {} (ledger row {})",
            data.user,
            data.amount,
            outcome.entry().id
        );
        Box::pin(publish_balance(db, &data.user)).await;
    }

    if data.amount > 0 {
        forfeit_if_deleted(db, &data.user, now_ms).await?;
    }

    Ok(v0::ProtAdjustResponse {
        entry_id: outcome.entry().id.clone(),
        balance: wallet_balance(db, &data.user).await?,
        already_applied: !applied,
    })
}

/// Account deletion (D11): the whole wallet goes to `sys:forfeited`
/// (`db.forfeit_prot_wallet`: kind Forfeit, `All`, key
/// `forfeit:{user_id}:{n}`, actor `sys:account-deletion`; its passes repeat,
/// bounded, while Prot is still arriving, and end in an error logged as
/// `PROT_FORFEIT_UNSETTLED`). Runs whatever the flags say. A user with no
/// wallet or an empty one never opens a transaction. Nothing is published.
pub async fn forfeit_wallet_on_deletion(db: &Database, user_id: &str, now_ms: i64) -> Result<()> {
    if let Some(outcome) = db.forfeit_prot_wallet(user_id, now_ms).await? {
        let entry = outcome.entry();
        log::info!(
            "payments: account deletion of {user_id} forfeited {} Prot ({})",
            entry.amount,
            entry.key
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    use revolt_config::{FeaturePayments, ProtectionFeatures};
    use revolt_database::test_teardown::TestDatabaseGuard;
    use revolt_database::{
        prot_key_cipher_founding, prot_key_cipher_upgrade, prot_key_forfeit, BotInformation,
        CipherRevokeReason, DatabaseInfo, PartialUser, User, PROT_ACTOR_CIPHER,
        PROT_ACTOR_DELETION, PROT_SYS_FORFEITED,
    };
    use revolt_models::v0::{CipherTier, Sku, UserFlags};
    use revolt_result::ErrorType;

    use super::super::{
        create_cipher_checkout, fulfil_order, reverse_locked, reverse_order, FulfilOutcome,
        RefundFacts, RefundStatus, SESSION_TTL_SECS,
    };
    use super::*;
    use crate::catalog::CIPHER_CAP_MAX;
    use crate::stripe::{
        CheckoutSession, MockStripe, PaymentCharge, PROT_TERMS_ACCEPTANCE_MESSAGE,
    };

    const NOW: i64 = 1_760_000_000_000;
    const MINUTE: i64 = 60_000;
    const HOUR: i64 = 60 * MINUTE;
    const DAY: i64 = 24 * HOUR;
    /// The moment every session opened at NOW has expired
    const EXPIRED: i64 = NOW + SESSION_TTL_SECS * 1000 + 1;
    const ADMIN: &str = "01ADMIN0000000000000000000";

    // Its own range, so no database name here can repeat one the engine
    // tests pick in the same process
    static NEXT_DB: AtomicU64 = AtomicU64::new(900_000);

    /// A throwaway database on the driver `TEST_DB` names (it panics when
    /// unset, so these tests never reach production), plus the guard that
    /// drops it (Mongo) if the test panics before its own `drop_db`
    struct TestDb {
        db: Database,
        guard: Mutex<Option<TestDatabaseGuard>>,
    }

    impl Deref for TestDb {
        type Target = Database;

        fn deref(&self) -> &Database {
            &self.db
        }
    }

    /// Mongo: named `revolt_test_<digits>` like the engine tests' databases,
    /// so `scripts/drop-test-databases.sh` sweeps one a panicking test
    /// leaves. A fresh Mongo database runs init (the payments and Prot
    /// indexes, the cipher_numbers seed); the seed is repeated by hand for
    /// the reference driver.
    async fn test_db() -> TestDb {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or_default();
        let name = format!(
            "revolt_test_{}{:09}{}",
            std::process::id(),
            nanos,
            NEXT_DB.fetch_add(1, Ordering::SeqCst)
        );
        let db = DatabaseInfo::Test(name)
            .connect()
            .await
            .expect("database connection");
        let guard = TestDatabaseGuard::arm(&db).await;
        db.migrate_database().await.expect("schema");
        db.seed_cipher_numbers(CIPHER_CAP_MAX).await.unwrap();
        TestDb {
            db,
            guard: Mutex::new(Some(guard)),
        }
    }

    async fn drop_db(db: &TestDb) {
        if let Database::MongoDb(mongo) = &db.db {
            assert!(mongo.1.starts_with("revolt_test_"));
            mongo.db().drop().await.ok();
        }
        let guard = db.guard.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(guard) = guard {
            guard.disarm();
        }
    }

    fn settings() -> PaymentsSettings {
        PaymentsSettings {
            enabled: true,
            sales_open: true,
            cap: CIPHER_CAP_MAX,
            close_at_ms: None,
            expect_livemode: false,
            tolerance_secs: 300,
            automatic_tax: false,
            blocked_countries: FeaturePayments::default().cipher_blocked_countries,
            secret_key: String::new(),
            webhook_secret: String::new(),
            success_url_web: "https://app.test/settings?cipher=success".to_string(),
            cancel_url_web: "https://app.test/settings?cipher=cancel".to_string(),
            success_url_shell: "https://site.test/cipher/thanks/".to_string(),
            cancel_url_shell: "https://site.test/cipher/".to_string(),
        }
    }

    /// The shipped Prot defaults with Prot on and sales open (grants off)
    fn prot_settings() -> ProtSalesSettings {
        ProtSalesSettings::from_parts(
            &FeaturePayments {
                prot_sales_open: true,
                ..Default::default()
            },
            &ProtectionFeatures {
                enabled: true,
                ..Default::default()
            },
        )
        .expect("the shipped Prot defaults validate")
    }

    fn grants_on() -> ProtSalesSettings {
        ProtSalesSettings {
            cipher_grants_enabled: true,
            ..prot_settings()
        }
    }

    #[allow(clippy::disallowed_methods)]
    async fn insert_account(db: &Database, user: User) {
        db.insert_user(&user).await.unwrap();
    }

    fn user(id: &str) -> User {
        User {
            id: id.to_string(),
            username: id.to_string(),
            discriminator: "0001".to_string(),
            ..Default::default()
        }
    }

    async fn insert_user(db: &Database, id: &str) {
        insert_account(db, user(id)).await;
    }

    async fn insert_deleted_user(db: &Database, id: &str) {
        insert_account(
            db,
            User {
                flags: Some(UserFlags::Deleted as i32),
                ..user(id)
            },
        )
        .await;
    }

    fn error_type<T: std::fmt::Debug>(result: Result<T>) -> ErrorType {
        result.expect_err("expected an error").error_type
    }

    fn pack(id: &str) -> ProtChoice {
        ProtChoice::Pack(id.to_string())
    }

    fn p25() -> Sku {
        Sku::ProtPack {
            pack: "p25".to_string(),
            prot: 2600,
            cents: 2500,
        }
    }

    async fn order(db: &Database, id: &str) -> PaymentOrder {
        db.fetch_payment_order(id).await.unwrap().unwrap()
    }

    async fn balance(db: &Database, user: &str) -> i64 {
        wallet_balance(db, user).await.unwrap()
    }

    async fn entry(db: &Database, key: &str) -> Option<ProtLedgerEntry> {
        db.fetch_prot_entry_by_key(key).await.unwrap()
    }

    async fn wallet_rows(db: &Database, user: &str) -> Vec<ProtLedgerEntry> {
        db.fetch_prot_entries_by_account(&prot_user_account(user), None, 100)
            .await
            .unwrap()
    }

    async fn membership(db: &Database, user: &str) -> CipherMembership {
        db.fetch_cipher_membership(user).await.unwrap().unwrap()
    }

    /// An order stored as it is, for the checkout gates
    fn stored_order(user: &str, sku: Sku, state: OrderState, at: i64) -> PaymentOrder {
        PaymentOrder {
            id: Ulid::new().to_string(),
            user_id: Some(user.to_string()),
            provider: PaymentProvider::Stripe,
            amount_cents: catalog::sku_cents(&sku).unwrap(),
            sku,
            currency: "usd".to_string(),
            checkout_session_id: None,
            checkout_url: None,
            session_expires_at: None,
            payment_intent_id: None,
            state,
            void_reason: None,
            region_blocked_country: None,
            reversal_pending: None,
            refund_settling_since: None,
            open_disputes: vec![],
            lease_until: None,
            version: 0,
            created_at: at,
            paid_at: None,
            fulfilled_at: None,
            reversed_at: None,
        }
    }

    /// Start a Prot checkout from the web at `now`; the Pending order it created
    async fn prot_checkout(
        db: &Database,
        stripe: &MockStripe,
        s: &PaymentsSettings,
        ps: &ProtSalesSettings,
        user: &str,
        choice: ProtChoice,
        now: i64,
    ) -> PaymentOrder {
        let url = create_prot_checkout(db, stripe, s, ps, user, choice, CipherReturnTo::Web, now)
            .await
            .unwrap();
        db.fetch_payment_orders_by_user(user, &[OrderState::Pending])
            .await
            .unwrap()
            .into_iter()
            .find(|o| o.checkout_url.as_deref() == Some(url.as_str()))
            .expect("the checkout's Pending order")
    }

    /// The buyer pays: the order's session becomes complete + paid by
    /// `payment_intent`, as Stripe then reports it
    fn pay(stripe: &MockStripe, order: &PaymentOrder, payment_intent: &str) -> CheckoutSession {
        let id = order.checkout_session_id.clone().expect("session id");
        let mut session = stripe.session(&id).expect("session at Stripe");
        session.status = Some("complete".to_string());
        session.payment_status = Some("paid".to_string());
        session.payment_intent = Some(payment_intent.to_string());
        stripe.set_session(session.clone());
        session
    }

    /// Checkout, pay and fulfil a pack; the Fulfilled order
    #[allow(clippy::too_many_arguments)]
    async fn buy_pack(
        db: &Database,
        stripe: &MockStripe,
        s: &PaymentsSettings,
        ps: &ProtSalesSettings,
        user: &str,
        choice: ProtChoice,
        payment_intent: &str,
        now: i64,
    ) -> PaymentOrder {
        let pending = prot_checkout(db, stripe, s, ps, user, choice, now).await;
        let session = pay(stripe, &pending, payment_intent);
        assert_eq!(
            fulfil_order(db, stripe, s, &pending.id, &session, now)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        let fulfilled = order(db, &pending.id).await;
        assert_eq!(fulfilled.state, OrderState::Fulfilled);
        fulfilled
    }

    /// Checkout, pay and fulfil a Cipher tier; the Fulfilled order
    async fn buy_cipher(
        db: &Database,
        stripe: &MockStripe,
        s: &PaymentsSettings,
        user: &str,
        tier: CipherTier,
        payment_intent: &str,
        now: i64,
    ) -> PaymentOrder {
        let url = create_cipher_checkout(db, stripe, s, user, tier, CipherReturnTo::Web, now)
            .await
            .unwrap();
        let pending = db
            .fetch_payment_orders_by_user(user, &[OrderState::Pending])
            .await
            .unwrap()
            .into_iter()
            .find(|o| o.checkout_url.as_deref() == Some(url.as_str()))
            .expect("the Cipher checkout's Pending order");
        let session = pay(stripe, &pending, payment_intent);
        assert_eq!(
            fulfil_order(db, stripe, s, &pending.id, &session, now)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        order(db, &pending.id).await
    }

    async fn adjust(
        db: &Database,
        user: &str,
        nonce: &str,
        amount: i64,
    ) -> Result<v0::ProtAdjustResponse> {
        let data = v0::DataProtAdjust {
            user: user.to_string(),
            amount,
            nonce: nonce.to_string(),
        };
        admin_prot_adjust(db, ADMIN, &data, "goodwill".to_string(), NOW).await
    }

    /// Apply `kind` for dispute `dispute_id` the way `reverse_dispute` does
    /// once Stripe has told it the dispute's status
    async fn on_dispute(
        db: &Database,
        order_id: &str,
        dispute_id: &str,
        kind: ReverseKind,
        at: i64,
    ) -> Result<ReverseOutcome> {
        let Some(mut leased) = acquire(db, order_id, at).await? else {
            return Ok(ReverseOutcome::Busy);
        };
        let stripe = MockStripe::new();
        let outcome =
            reverse_locked(db, &stripe, &mut leased, kind, Some(dispute_id), None, at).await;
        release(db, &leased).await;
        outcome
    }

    /// Why a web checkout of `choice` at NOW is refused
    async fn refusal(
        db: &Database,
        stripe: &MockStripe,
        s: &PaymentsSettings,
        ps: &ProtSalesSettings,
        user: &str,
        choice: ProtChoice,
    ) -> ErrorType {
        error_type(
            create_prot_checkout(db, stripe, s, ps, user, choice, CipherReturnTo::Web, NOW).await,
        )
    }

    fn refunded(at: i64, full: bool) -> Option<RefundFacts> {
        Some(RefundFacts {
            refunded_at_ms: at,
            full,
            status: RefundStatus::Succeeded,
        })
    }

    // --- checkout gates -----------------------------------------------

    #[tokio::test]
    async fn prot_checkout_refuses_in_gate_order() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        insert_user(&db, "u1").await;
        insert_account(
            &db,
            User {
                bot: Some(BotInformation {
                    owner: "u1".to_string(),
                }),
                ..user("bot1")
            },
        )
        .await;

        let s = settings();
        let ps = prot_settings();
        let payments_off = PaymentsSettings {
            enabled: false,
            ..settings()
        };
        let prot_off = ProtSalesSettings {
            enabled: false,
            sales_open: false,
            ..prot_settings()
        };
        let closed = ProtSalesSettings {
            sales_open: false,
            ..prot_settings()
        };

        // Payments off wins over everything after it
        assert!(matches!(
            refusal(&db, &stripe, &payments_off, &prot_off, "bot1", pack("p25")).await,
            ErrorType::PaymentsDisabled
        ));
        assert!(matches!(
            refusal(&db, &stripe, &s, &prot_off, "bot1", pack("p25")).await,
            ErrorType::ProtDisabled
        ));
        assert!(matches!(
            refusal(&db, &stripe, &s, &closed, "bot1", pack("p25")).await,
            ErrorType::ProtSalesClosed
        ));
        assert!(matches!(
            refusal(&db, &stripe, &s, &ps, "bot1", pack("p25")).await,
            ErrorType::IsBot
        ));

        // Nothing reached Stripe or the store
        assert!(stripe.calls().is_empty());
        assert!(db
            .fetch_payment_orders_by_user(
                "bot1",
                &[
                    OrderState::Creating,
                    OrderState::Pending,
                    OrderState::SessionFailed
                ]
            )
            .await
            .unwrap()
            .is_empty());

        // The same request from a person goes through
        create_prot_checkout(
            &db,
            &stripe,
            &s,
            &ps,
            "u1",
            pack("p25"),
            CipherReturnTo::Web,
            NOW,
        )
        .await
        .unwrap();
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn prot_checkout_prices_packs_and_exact_amounts_on_the_server() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let ps = prot_settings();
        for id in ["u1", "u2", "u3", "u4", "u5"] {
            insert_user(&db, id).await;
        }

        let packed = prot_checkout(&db, &stripe, &s, &ps, "u1", pack("p25"), NOW).await;
        assert_eq!(packed.sku, p25());
        assert_eq!(packed.amount_cents, 2500);
        assert_eq!(packed.currency, "usd");

        let params = stripe.checkout_params();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].order_id, packed.id);
        assert_eq!(params[0].user_id, "u1");
        assert_eq!(params[0].amount_cents, 2500);
        assert_eq!(params[0].success_url, ps.success_url);
        assert_eq!(params[0].cancel_url, ps.cancel_url);
        assert_eq!(params[0].consent_message, PROT_TERMS_ACCEPTANCE_MESSAGE);

        let exact = prot_checkout(
            &db,
            &stripe,
            &s,
            &ps,
            "u2",
            ProtChoice::ExactCents(1234),
            NOW,
        )
        .await;
        assert_eq!(exact.sku, Sku::ProtExact { prot: 1234 });
        assert_eq!(exact.amount_cents, 1234);

        // Both bounds are inclusive
        let low = prot_checkout(
            &db,
            &stripe,
            &s,
            &ps,
            "u3",
            ProtChoice::ExactCents(ps.exact_min_cents),
            NOW,
        )
        .await;
        assert_eq!(low.amount_cents, ps.exact_min_cents);
        let high = prot_checkout(
            &db,
            &stripe,
            &s,
            &ps,
            "u4",
            ProtChoice::ExactCents(ps.exact_max_cents),
            NOW,
        )
        .await;
        assert_eq!(high.amount_cents, ps.exact_max_cents);

        for choice in [
            pack("p7"),
            pack(""),
            ProtChoice::ExactCents(ps.exact_min_cents - 1),
            ProtChoice::ExactCents(ps.exact_max_cents + 1),
            ProtChoice::ExactCents(0),
            ProtChoice::ExactCents(-500),
        ] {
            assert!(
                matches!(
                    error_type(
                        create_prot_checkout(
                            &db,
                            &stripe,
                            &s,
                            &ps,
                            "u5",
                            choice.clone(),
                            CipherReturnTo::Web,
                            NOW
                        )
                        .await
                    ),
                    ErrorType::ProtPackInvalid
                ),
                "{choice:?}"
            );
        }
        assert_eq!(stripe.call_count("create_checkout_session"), 4);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn one_live_prot_order_per_buyer() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let ps = prot_settings();
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;

        let first = prot_checkout(&db, &stripe, &s, &ps, "u1", pack("p25"), NOW).await;
        let again = create_prot_checkout(
            &db,
            &stripe,
            &s,
            &ps,
            "u1",
            pack("p25"),
            CipherReturnTo::Web,
            NOW + MINUTE,
        )
        .await
        .unwrap();
        assert_eq!(Some(again), first.checkout_url);
        assert_eq!(stripe.call_count("create_checkout_session"), 1);

        // Another SKU, even one at the same price, waits for the first
        for choice in [pack("p10"), ProtChoice::ExactCents(2500)] {
            assert!(matches!(
                error_type(
                    create_prot_checkout(
                        &db,
                        &stripe,
                        &s,
                        &ps,
                        "u1",
                        choice,
                        CipherReturnTo::Web,
                        NOW + MINUTE
                    )
                    .await
                ),
                ErrorType::PaymentPending
            ));
        }

        // Once the session has expired, a new order starts
        let later = prot_checkout(&db, &stripe, &s, &ps, "u1", pack("p10"), EXPIRED).await;
        assert_ne!(later.id, first.id);

        // A checkout request still in flight blocks; a stranded one does not
        db.insert_payment_order(&stored_order("u2", p25(), OrderState::Creating, NOW))
            .await
            .unwrap();
        assert!(matches!(
            error_type(
                create_prot_checkout(
                    &db,
                    &stripe,
                    &s,
                    &ps,
                    "u2",
                    pack("p25"),
                    CipherReturnTo::Web,
                    NOW + MINUTE
                )
                .await
            ),
            ErrorType::PaymentPending
        ));
        prot_checkout(&db, &stripe, &s, &ps, "u2", pack("p25"), NOW + 3 * MINUTE).await;
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn prot_and_cipher_checkouts_do_not_block_each_other() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let ps = prot_settings();
        insert_user(&db, "u1").await;

        let cipher = create_cipher_checkout(
            &db,
            &stripe,
            &s,
            "u1",
            CipherTier::T99,
            CipherReturnTo::Web,
            NOW,
        )
        .await
        .unwrap();
        let prot = prot_checkout(&db, &stripe, &s, &ps, "u1", pack("p25"), NOW).await;

        // Each family still finds its own live order
        let cipher_again = create_cipher_checkout(
            &db,
            &stripe,
            &s,
            "u1",
            CipherTier::T99,
            CipherReturnTo::Web,
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(cipher_again, cipher);
        let prot_again = create_prot_checkout(
            &db,
            &stripe,
            &s,
            &ps,
            "u1",
            pack("p25"),
            CipherReturnTo::Web,
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(Some(prot_again), prot.checkout_url);
        assert_eq!(stripe.call_count("create_checkout_session"), 2);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn shell_checkouts_return_to_the_thanks_page_for_both_outcomes() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let ps = prot_settings();
        insert_user(&db, "u1").await;

        create_prot_checkout(
            &db,
            &stripe,
            &s,
            &ps,
            "u1",
            pack("p10"),
            CipherReturnTo::Shell,
            NOW,
        )
        .await
        .unwrap();
        let params = stripe.checkout_params();
        assert_eq!(params[0].success_url, ps.shell_return_url);
        assert_eq!(params[0].cancel_url, ps.shell_return_url);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn prot_checkout_waits_for_open_disputes_on_live_orders_only() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let ps = prot_settings();
        let cipher = Sku::CipherNew {
            tier: CipherTier::T99,
        };

        // Either family, any live state
        for (user, sku, state) in [
            ("a", cipher.clone(), OrderState::Fulfilled),
            ("b", p25(), OrderState::Fulfilled),
            ("c", cipher.clone(), OrderState::Paid),
            ("d", p25(), OrderState::Pending),
            ("e", cipher.clone(), OrderState::Creating),
        ] {
            insert_user(&db, user).await;
            let mut disputed = stored_order(user, sku, state, NOW - DAY);
            disputed.open_disputes = vec![format!("dp_{user}")];
            db.insert_payment_order(&disputed).await.unwrap();
            assert!(
                matches!(
                    error_type(
                        create_prot_checkout(
                            &db,
                            &stripe,
                            &s,
                            &ps,
                            user,
                            pack("p5"),
                            CipherReturnTo::Web,
                            NOW
                        )
                        .await
                    ),
                    ErrorType::ProtNotEligible
                ),
                "{user}"
            );
        }

        // A dispute left on a Refunded or Voided order (closed after the
        // reversal, so never removed) locks nobody out
        insert_user(&db, "f").await;
        for state in [OrderState::Refunded, OrderState::Voided] {
            let mut old = stored_order("f", cipher.clone(), state, NOW - 30 * DAY);
            old.open_disputes = vec!["dp_old".to_string()];
            db.insert_payment_order(&old).await.unwrap();
        }
        prot_checkout(&db, &stripe, &s, &ps, "f", pack("p5"), NOW).await;
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn the_wallet_cap_counts_paid_prot_orders_not_credited_yet() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let ps = ProtSalesSettings {
            wallet_cap: 5_000,
            ..prot_settings()
        };
        insert_user(&db, "u1").await;
        adjust(&db, "u1", "n1", 2_000).await.unwrap();

        // Paid, not credited yet: 2,600 more is on its way
        let mut paid = stored_order("u1", p25(), OrderState::Paid, NOW - MINUTE);
        paid.payment_intent_id = Some("pi_paid".to_string());
        paid.paid_at = Some(NOW - MINUTE);
        db.insert_payment_order(&paid).await.unwrap();

        // 2,000 + 2,600 + 1,000 and 2,000 + 2,600 + 401 are over 5,000
        for choice in [pack("p10"), ProtChoice::ExactCents(401)] {
            assert!(matches!(
                error_type(
                    create_prot_checkout(
                        &db,
                        &stripe,
                        &s,
                        &ps,
                        "u1",
                        choice,
                        CipherReturnTo::Web,
                        NOW
                    )
                    .await
                ),
                ErrorType::ProtWalletCap { max: 5_000 }
            ));
        }

        // Credited (a crash before its Fulfilled write): counted once,
        // through the balance
        apply_purchase(&db, &paid, "u1", NOW).await.unwrap();
        assert_eq!(balance(&db, "u1").await, 4_600);
        assert!(matches!(
            error_type(
                create_prot_checkout(
                    &db,
                    &stripe,
                    &s,
                    &ps,
                    "u1",
                    ProtChoice::ExactCents(401),
                    CipherReturnTo::Web,
                    NOW
                )
                .await
            ),
            ErrorType::ProtWalletCap { max: 5_000 }
        ));

        // Exactly at the cap is allowed
        let at_cap = prot_checkout(
            &db,
            &stripe,
            &s,
            &ps,
            "u1",
            ProtChoice::ExactCents(400),
            NOW,
        )
        .await;
        assert_eq!(at_cap.sku, Sku::ProtExact { prot: 400 });
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_prot_region_void_keeps_the_buyer_out_while_it_holds() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let ps = prot_settings();

        let region_void = |user: &str, sku: Sku, country: &str| {
            let mut o = stored_order(user, sku, OrderState::Voided, NOW - 2 * DAY);
            o.void_reason = Some(VoidReason::RegionUnavailable);
            o.region_blocked_country = Some(country.to_string());
            o.paid_at = Some(NOW - 2 * DAY);
            o.reversed_at = Some(NOW - DAY);
            o
        };

        insert_user(&db, "u1").await;
        db.insert_payment_order(&region_void("u1", p25(), "DE"))
            .await
            .unwrap();
        assert!(matches!(
            error_type(
                create_prot_checkout(
                    &db,
                    &stripe,
                    &s,
                    &ps,
                    "u1",
                    pack("p5"),
                    CipherReturnTo::Web,
                    NOW
                )
                .await
            ),
            ErrorType::ProtRegionUnavailable
        ));
        // Not for long
        prot_checkout(
            &db,
            &stripe,
            &s,
            &ps,
            "u1",
            pack("p5"),
            NOW - DAY + REGION_REFUSAL_MS,
        )
        .await;

        // A void still finishing (Paid, the reason recorded) counts too
        insert_user(&db, "u2").await;
        let mut finishing = stored_order("u2", p25(), OrderState::Paid, NOW - MINUTE);
        finishing.void_reason = Some(VoidReason::RegionUnavailable);
        finishing.region_blocked_country = Some("FR".to_string());
        finishing.paid_at = Some(NOW - MINUTE);
        finishing.payment_intent_id = Some("pi_fr".to_string());
        db.insert_payment_order(&finishing).await.unwrap();
        assert!(matches!(
            error_type(
                create_prot_checkout(
                    &db,
                    &stripe,
                    &s,
                    &ps,
                    "u2",
                    pack("p5"),
                    CipherReturnTo::Web,
                    NOW
                )
                .await
            ),
            ErrorType::ProtRegionUnavailable
        ));

        // A Cipher region void, or a country no longer blocked, does not
        insert_user(&db, "u3").await;
        db.insert_payment_order(&region_void(
            "u3",
            Sku::CipherNew {
                tier: CipherTier::T99,
            },
            "DE",
        ))
        .await
        .unwrap();
        prot_checkout(&db, &stripe, &s, &ps, "u3", pack("p5"), NOW).await;

        insert_user(&db, "u4").await;
        db.insert_payment_order(&region_void("u4", p25(), "US"))
            .await
            .unwrap();
        prot_checkout(&db, &stripe, &s, &ps, "u4", pack("p5"), NOW).await;
        drop_db(&db).await;
    }

    // --- fulfilment ---------------------------------------------------

    #[tokio::test]
    async fn a_pack_is_credited_once_and_shows_in_the_wallet() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let ps = prot_settings();
        insert_user(&db, "u1").await;

        let bought = buy_pack(&db, &stripe, &s, &ps, "u1", pack("p25"), "pi_1", NOW).await;
        let row = entry(&db, &prot_key_purchase(&bought.id))
            .await
            .expect("the purchase row");
        assert_eq!(row.kind, ProtEntryKind::Purchase);
        assert_eq!(row.amount, 2600);
        assert_eq!(row.debit, PROT_SYS_ISSUED);
        assert_eq!(row.credit, prot_user_account("u1"));
        assert_eq!(row.actor, PROT_ACTOR_PAYMENTS);
        assert_eq!(row.reference.order_id.as_deref(), Some(bought.id.as_str()));
        assert!(purchase_applied(&db, &bought.id).await.unwrap());

        // A duplicate delivery credits nothing more
        let session = stripe
            .session(bought.checkout_session_id.as_deref().unwrap())
            .unwrap();
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &bought.id, &session, NOW + MINUTE)
                .await
                .unwrap(),
            FulfilOutcome::AlreadyFulfilled
        );
        assert_eq!(
            db.fetch_prot_entries_by_order(&bought.id)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(balance(&db, "u1").await, 2600);

        // No Cipher side effects, no refund
        assert!(db.fetch_cipher_membership("u1").await.unwrap().is_none());
        assert_eq!(db.fetch_user("u1").await.unwrap().cipher, None);
        assert_eq!(stripe.refund_count(), 0);

        let me = prot_me(&db, &ps, "u1", NOW).await.unwrap();
        assert_eq!((me.balance, me.held, me.version), (2600, 2600, 1));
        assert_eq!(me.pending_order, None);
        assert_eq!(
            me.recent,
            vec![v0::ProtLedgerView {
                id: row.id.clone(),
                kind: ProtEntryKind::Purchase,
                amount: 2600,
                created_at: NOW,
                order_id: Some(bought.id.clone()),
            }]
        );

        // Held for exactly contribute_hold_hours, then free
        assert_eq!(
            prot_me(&db, &ps, "u1", NOW + ps.hold_ms())
                .await
                .unwrap()
                .held,
            2600
        );
        assert_eq!(
            prot_me(&db, &ps, "u1", NOW + ps.hold_ms() + 1)
                .await
                .unwrap()
                .held,
            0
        );
        let no_hold = ProtSalesSettings {
            contribute_hold_hours: 0,
            ..prot_settings()
        };
        assert_eq!(prot_me(&db, &no_hold, "u1", NOW).await.unwrap().held, 0);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_pack_paid_with_the_wrong_amount_is_voided_and_never_credited() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let ps = prot_settings();
        insert_user(&db, "u1").await;

        let pending = prot_checkout(&db, &stripe, &s, &ps, "u1", pack("p100"), NOW).await;
        let mut session = pay(&stripe, &pending, "pi_1");
        session.amount_total = Some(100);
        stripe.set_session(session.clone());
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AmountMismatch)
        );
        assert_eq!(order(&db, &pending.id).await.state, OrderState::Voided);
        assert_eq!(stripe.refund_count(), 1);
        assert!(!purchase_applied(&db, &pending.id).await.unwrap());
        assert_eq!(balance(&db, "u1").await, 0);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_pack_from_a_blocked_country_is_voided_and_never_credited() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let ps = prot_settings();
        insert_user(&db, "u1").await;
        insert_user(&db, "u2").await;

        // A billing country Prot is not sold to
        let pending = prot_checkout(&db, &stripe, &s, &ps, "u1", pack("p25"), NOW).await;
        let mut session = pay(&stripe, &pending, "pi_de");
        session.billing_country = Some("DE".to_string());
        stripe.set_session(session.clone());
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::RegionUnavailable)
        );
        let voided = order(&db, &pending.id).await;
        assert_eq!(voided.state, OrderState::Voided);
        assert_eq!(voided.region_blocked_country.as_deref(), Some("DE"));
        assert!(!purchase_applied(&db, &pending.id).await.unwrap());
        assert_eq!(balance(&db, "u1").await, 0);
        assert_eq!(stripe.refund_count_for("pi_de"), 1);

        // The buyer gets no new Prot checkout for now, but a Prot void
        // never blocks a Cipher one
        assert!(matches!(
            error_type(
                create_prot_checkout(
                    &db,
                    &stripe,
                    &s,
                    &ps,
                    "u1",
                    pack("p25"),
                    CipherReturnTo::Web,
                    NOW + MINUTE
                )
                .await
            ),
            ErrorType::ProtRegionUnavailable
        ));
        create_cipher_checkout(
            &db,
            &stripe,
            &s,
            "u1",
            CipherTier::T99,
            CipherReturnTo::Web,
            NOW + MINUTE,
        )
        .await
        .unwrap();

        // A card issued there, whatever billing country was typed in
        let pending = prot_checkout(&db, &stripe, &s, &ps, "u2", pack("p25"), NOW).await;
        let mut session = pay(&stripe, &pending, "pi_fr");
        session.billing_country = Some("US".to_string());
        stripe.set_session(session.clone());
        stripe.set_payment_charge(PaymentCharge {
            payment_intent: "pi_fr".to_string(),
            method: Some("card".to_string()),
            card_country: Some("FR".to_string()),
        });
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::RegionUnavailable)
        );
        assert!(!purchase_applied(&db, &pending.id).await.unwrap());
        assert_eq!(balance(&db, "u2").await, 0);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_pack_bought_after_the_cipher_sale_closed_is_credited() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = PaymentsSettings {
            close_at_ms: Some(NOW - DAY),
            ..settings()
        };
        let ps = prot_settings();
        insert_user(&db, "u1").await;

        // The Cipher sale is over
        assert!(matches!(
            error_type(
                create_cipher_checkout(
                    &db,
                    &stripe,
                    &s,
                    "u1",
                    CipherTier::T99,
                    CipherReturnTo::Web,
                    NOW
                )
                .await
            ),
            ErrorType::CipherSalesClosed
        ));

        let bought = buy_pack(&db, &stripe, &s, &ps, "u1", pack("p50"), "pi_1", NOW).await;
        assert!(purchase_applied(&db, &bought.id).await.unwrap());
        assert_eq!(balance(&db, "u1").await, 5300);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_dispute_open_at_fulfilment_defers_the_credit_until_it_is_won() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let ps = prot_settings();
        insert_user(&db, "u1").await;

        let pending = prot_checkout(&db, &stripe, &s, &ps, "u1", pack("p25"), NOW).await;
        let session = pay(&stripe, &pending, "pi_1");
        assert_eq!(
            on_dispute(&db, &pending.id, "dp_1", ReverseKind::DisputeOpened, NOW)
                .await
                .unwrap(),
            ReverseOutcome::RecordedPending
        );

        // Paid, but nothing is credited (or refunded) while the dispute is open
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW)
                .await
                .unwrap(),
            FulfilOutcome::VoidDeferred(VoidReason::DisputeOpen)
        );
        assert_eq!(order(&db, &pending.id).await.state, OrderState::Paid);
        assert!(!purchase_applied(&db, &pending.id).await.unwrap());
        assert_eq!(stripe.refund_count(), 0);

        // Nor can the buyer start another Prot checkout meanwhile
        assert!(matches!(
            error_type(
                create_prot_checkout(
                    &db,
                    &stripe,
                    &s,
                    &ps,
                    "u1",
                    pack("p5"),
                    CipherReturnTo::Web,
                    NOW
                )
                .await
            ),
            ErrorType::ProtNotEligible
        ));

        // Won: the next attempt credits it
        on_dispute(&db, &pending.id, "dp_1", ReverseKind::DisputeWon, NOW + DAY)
            .await
            .unwrap();
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + DAY)
                .await
                .unwrap(),
            FulfilOutcome::Fulfilled
        );
        assert!(purchase_applied(&db, &pending.id).await.unwrap());
        assert_eq!(balance(&db, "u1").await, 2600);
        assert_eq!(stripe.refund_count(), 0);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn apply_purchase_forfeits_a_credit_that_lands_on_a_deleted_account() {
        let db = test_db().await;
        insert_deleted_user(&db, "gone").await;

        let mut paid = stored_order("gone", p25(), OrderState::Paid, NOW);
        paid.payment_intent_id = Some("pi_gone".to_string());
        db.insert_payment_order(&paid).await.unwrap();

        apply_purchase(&db, &paid, "gone", NOW).await.unwrap();
        assert!(purchase_applied(&db, &paid.id).await.unwrap());
        let forfeit = entry(&db, &prot_key_forfeit("gone", 1))
            .await
            .expect("the second pass");
        assert_eq!(forfeit.kind, ProtEntryKind::Forfeit);
        assert_eq!(forfeit.amount, 2600);
        assert_eq!(forfeit.credit, PROT_SYS_FORFEITED);
        assert_eq!(balance(&db, "gone").await, 0);

        // Again (a resume): nothing more is written
        apply_purchase(&db, &paid, "gone", NOW + MINUTE)
            .await
            .unwrap();
        assert_eq!(wallet_rows(&db, "gone").await.len(), 2);

        // Not a Prot order: refused, nothing credited
        let cipher = stored_order(
            "gone",
            Sku::CipherNew {
                tier: CipherTier::T99,
            },
            OrderState::Paid,
            NOW,
        );
        assert!(matches!(
            error_type(apply_purchase(&db, &cipher, "gone", NOW).await),
            ErrorType::InternalError
        ));
        assert!(!purchase_applied(&db, &cipher.id).await.unwrap());
        drop_db(&db).await;
    }

    /// A worker passed the live-buyer check, the account was deleted (its
    /// forfeit found the wallet empty), then the credit landed and the
    /// second pass failed. The retry voids and refunds the order, and claws
    /// the credit back first, so it is not left in the dead wallet.
    #[tokio::test]
    async fn a_credit_that_lands_after_the_deletion_forfeit_is_clawed_back_by_the_void() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let ps = prot_settings();
        insert_user(&db, "u1").await;

        let pending = prot_checkout(&db, &stripe, &s, &ps, "u1", pack("p25"), NOW).await;
        let session = pay(&stripe, &pending, "pi_late");

        db.update_user(
            "u1",
            &PartialUser {
                flags: Some(UserFlags::Deleted as i32),
                ..Default::default()
            },
            vec![],
        )
        .await
        .unwrap();
        forfeit_wallet_on_deletion(&db, "u1", NOW).await.unwrap();
        assert!(entry(&db, &prot_key_forfeit("u1", 1)).await.is_none());

        // A row with another payload holds the first forfeit key, so the
        // second pass is refused (as in `delete_accounts`' failed-forfeit test)
        db.apply_prot_posting(&ProtPosting {
            key: prot_key_forfeit("u1", 1),
            kind: ProtEntryKind::Purchase,
            debit: PROT_SYS_ISSUED.to_string(),
            credit: prot_user_account("u1"),
            amount: ProtAmount::Exact(100),
            debit_floor: 0,
            actor: PROT_ACTOR_PAYMENTS.to_string(),
            reference: ProtRef::default(),
            reason: None,
            created_at: NOW,
        })
        .await
        .unwrap();

        // The stalled worker's credit lands; its second pass fails
        assert!(apply_purchase(&db, &pending, "u1", NOW + MINUTE)
            .await
            .is_err());
        assert!(purchase_applied(&db, &pending.id).await.unwrap());
        assert_eq!(balance(&db, "u1").await, 2700);

        // The retry: voided and refunded, the pack's Prot clawed back first
        assert_eq!(
            fulfil_order(&db, &stripe, &s, &pending.id, &session, NOW + 2 * MINUTE)
                .await
                .unwrap(),
            FulfilOutcome::Voided(VoidReason::AccountDeleted)
        );
        let clawback = entry(&db, &prot_key_clawback(&pending.id))
            .await
            .expect("the clawback row");
        assert_eq!(clawback.kind, ProtEntryKind::Clawback);
        assert_eq!(clawback.amount, 2600);
        assert_eq!(clawback.shortfall, Some(0));
        assert_eq!(clawback.debit, prot_user_account("u1"));
        assert_eq!(clawback.credit, PROT_SYS_CLAWED);
        // Only the planted row's Prot is left: none of the refunded pack
        assert_eq!(balance(&db, "u1").await, 100);
        assert_eq!(order(&db, &pending.id).await.state, OrderState::Voided);
        assert_eq!(stripe.refund_count_for("pi_late"), 1);
        drop_db(&db).await;
    }

    // --- reversal -----------------------------------------------------

    #[tokio::test]
    async fn a_refund_claws_back_the_whole_pack_once() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let ps = prot_settings();
        insert_user(&db, "u1").await;

        let bought = buy_pack(&db, &stripe, &s, &ps, "u1", pack("p25"), "pi_1", NOW).await;

        // A partial refund claws back the whole order
        assert_eq!(
            reverse_order(
                &db,
                &stripe,
                &s,
                &bought.id,
                ReverseKind::Refund,
                refunded(NOW + DAY, false),
                NOW + DAY
            )
            .await
            .unwrap(),
            ReverseOutcome::Applied
        );
        let reversed = order(&db, &bought.id).await;
        assert_eq!(reversed.state, OrderState::Refunded);
        assert_eq!(reversed.reversed_at, Some(NOW + DAY));

        let row = entry(&db, &prot_key_clawback(&bought.id))
            .await
            .expect("the clawback row");
        assert_eq!(row.kind, ProtEntryKind::Clawback);
        assert_eq!(
            (row.amount, row.requested, row.shortfall),
            (2600, Some(2600), Some(0))
        );
        assert_eq!(row.debit, prot_user_account("u1"));
        assert_eq!(row.credit, PROT_SYS_CLAWED);
        assert_eq!(row.actor, PROT_ACTOR_PAYMENTS);
        assert_eq!(row.reference.order_id.as_deref(), Some(bought.id.as_str()));
        assert_eq!(balance(&db, "u1").await, 0);

        // A second refund event, then a dispute lost on the refunded
        // payment: nothing more is clawed back
        assert_eq!(
            reverse_order(
                &db,
                &stripe,
                &s,
                &bought.id,
                ReverseKind::Refund,
                refunded(NOW + DAY, true),
                NOW + 2 * DAY
            )
            .await
            .unwrap(),
            ReverseOutcome::NoOp
        );
        on_dispute(
            &db,
            &bought.id,
            "dp_1",
            ReverseKind::DisputeLost,
            NOW + 3 * DAY,
        )
        .await
        .unwrap();
        assert_eq!(
            db.fetch_prot_entries_by_order(&bought.id)
                .await
                .unwrap()
                .len(),
            2
        );

        let me = prot_me(&db, &ps, "u1", NOW + 3 * DAY).await.unwrap();
        assert_eq!((me.balance, me.version), (0, 2));
        let mut amounts: Vec<i64> = me.recent.iter().map(|r| r.amount).collect();
        amounts.sort();
        assert_eq!(amounts, vec![-2600, 2600]);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_lost_dispute_claws_back_up_to_what_is_left() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let ps = prot_settings();
        insert_user(&db, "u1").await;

        let bought = buy_pack(&db, &stripe, &s, &ps, "u1", pack("p25"), "pi_1", NOW).await;
        // 1,000 of it gone already
        adjust(&db, "u1", "n1", -1_000).await.unwrap();

        // Opened: no balance action, and no new Prot checkout
        assert_eq!(
            on_dispute(
                &db,
                &bought.id,
                "dp_1",
                ReverseKind::DisputeOpened,
                NOW + DAY
            )
            .await
            .unwrap(),
            ReverseOutcome::NoOp
        );
        assert_eq!(order(&db, &bought.id).await.open_disputes, vec!["dp_1"]);
        assert_eq!(balance(&db, "u1").await, 1_600);
        assert!(matches!(
            error_type(
                create_prot_checkout(
                    &db,
                    &stripe,
                    &s,
                    &ps,
                    "u1",
                    pack("p5"),
                    CipherReturnTo::Web,
                    NOW + DAY
                )
                .await
            ),
            ErrorType::ProtNotEligible
        ));

        // Lost: what is left is taken, the rest recorded as the shortfall
        assert_eq!(
            on_dispute(
                &db,
                &bought.id,
                "dp_1",
                ReverseKind::DisputeLost,
                NOW + 2 * DAY
            )
            .await
            .unwrap(),
            ReverseOutcome::Applied
        );
        let row = entry(&db, &prot_key_clawback(&bought.id)).await.unwrap();
        assert_eq!(
            (row.amount, row.requested, row.shortfall),
            (1_600, Some(2_600), Some(1_000))
        );
        assert_eq!(balance(&db, "u1").await, 0);
        let reversed = order(&db, &bought.id).await;
        assert_eq!(reversed.state, OrderState::Refunded);
        assert!(reversed.open_disputes.is_empty());

        let view = admin_prot_order(&db, &bought.id).await.unwrap();
        assert_eq!(
            view,
            v0::ProtAdminOrder {
                order_id: bought.id.clone(),
                user_id: Some("u1".to_string()),
                sku: p25(),
                credited: 2_600,
                clawed_back: 1_600,
                shortfall: 1_000,
                unspent: Some(0),
                membership_posted: None,
                membership_target: None,
                membership_shortfall: None,
            }
        );

        // The Refunded order no longer keeps the buyer out
        prot_checkout(&db, &stripe, &s, &ps, "u1", pack("p5"), NOW + 2 * DAY).await;
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_won_dispute_on_a_credited_pack_changes_nothing() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let ps = prot_settings();
        insert_user(&db, "u1").await;

        let bought = buy_pack(&db, &stripe, &s, &ps, "u1", pack("p10"), "pi_1", NOW).await;
        for kind in [ReverseKind::DisputeOpened, ReverseKind::DisputeWon] {
            assert_eq!(
                on_dispute(&db, &bought.id, "dp_1", kind, NOW + DAY)
                    .await
                    .unwrap(),
                ReverseOutcome::NoOp
            );
        }
        let after = order(&db, &bought.id).await;
        assert_eq!(after.state, OrderState::Fulfilled);
        assert!(after.open_disputes.is_empty());
        assert_eq!(balance(&db, "u1").await, 1_000);
        assert!(entry(&db, &prot_key_clawback(&bought.id)).await.is_none());
        prot_checkout(&db, &stripe, &s, &ps, "u1", pack("p5"), NOW + DAY).await;
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn an_unlinked_prot_order_is_recorded_refunded_without_a_ledger_action() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let ps = prot_settings();
        insert_user(&db, "u1").await;

        let bought = buy_pack(&db, &stripe, &s, &ps, "u1", pack("p10"), "pi_1", NOW).await;
        db.unlink_payment_orders_by_user("u1").await.unwrap();

        assert_eq!(
            reverse_order(
                &db,
                &stripe,
                &s,
                &bought.id,
                ReverseKind::Refund,
                refunded(NOW + DAY, true),
                NOW + DAY
            )
            .await
            .unwrap(),
            ReverseOutcome::Applied
        );
        assert_eq!(order(&db, &bought.id).await.state, OrderState::Refunded);
        assert!(entry(&db, &prot_key_clawback(&bought.id)).await.is_none());

        let view = admin_prot_order(&db, &bought.id).await.unwrap();
        assert_eq!(view.user_id, None);
        assert_eq!(view.unspent, None);
        assert_eq!(view.credited, 1_000);
        drop_db(&db).await;
    }

    // --- admin and account deletion ------------------------------------

    #[tokio::test]
    async fn admin_adjust_credits_debits_and_replays_by_nonce() {
        let db = test_db().await;
        insert_user(&db, "u1").await;

        let credit = adjust(&db, "u1", "n1", 500).await.unwrap();
        assert_eq!((credit.balance, credit.already_applied), (500, false));
        let row = entry(&db, &prot_key_admin(ADMIN, "n1")).await.unwrap();
        assert_eq!(row.id, credit.entry_id);
        assert_eq!(row.kind, ProtEntryKind::AdminAdjust);
        assert_eq!((row.debit.as_str(), row.amount), (PROT_SYS_ADJUST, 500));
        assert_eq!(row.credit, prot_user_account("u1"));
        assert_eq!(row.actor, ADMIN);
        assert_eq!(row.reason.as_deref(), Some("goodwill"));

        // The same nonce and amount is the same adjustment
        let replay = adjust(&db, "u1", "n1", 500).await.unwrap();
        assert_eq!(
            (
                replay.entry_id.as_str(),
                replay.balance,
                replay.already_applied
            ),
            (credit.entry_id.as_str(), 500, true)
        );
        // ...and another amount under it is refused
        assert!(matches!(
            error_type(adjust(&db, "u1", "n1", 600).await),
            ErrorType::ProtIdempotencyConflict
        ));

        let debit = adjust(&db, "u1", "n2", -200).await.unwrap();
        assert_eq!(debit.balance, 300);
        let row = entry(&db, &prot_key_admin(ADMIN, "n2")).await.unwrap();
        assert_eq!(
            (row.debit, row.credit.as_str(), row.amount),
            (prot_user_account("u1"), PROT_SYS_ADJUST, 200)
        );

        // Never below zero
        assert!(matches!(
            error_type(adjust(&db, "u1", "n3", -1_000).await),
            ErrorType::InsufficientProt {
                needed: 1_000,
                available: 300
            }
        ));
        assert_eq!(balance(&db, "u1").await, 300);

        for (nonce, amount) in [
            ("n4", 0),
            ("n5", PROT_ADJUST_MAX + 1),
            ("n6", -PROT_ADJUST_MAX - 1),
            ("n7", i64::MIN),
            ("", 10),
            ("bad\nnonce", 10),
        ] {
            assert!(
                matches!(
                    error_type(adjust(&db, "u1", nonce, amount).await),
                    ErrorType::FailedValidation { .. }
                ),
                "{nonce:?} {amount}"
            );
        }
        assert_eq!(balance(&db, "u1").await, 300);
        assert_eq!(wallet_rows(&db, "u1").await.len(), 2);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn an_admin_credit_to_a_deleted_account_is_forfeited_by_the_second_pass() {
        let db = test_db().await;
        insert_deleted_user(&db, "gone").await;

        let credit = adjust(&db, "gone", "n1", 500).await.unwrap();
        assert_eq!((credit.balance, credit.already_applied), (0, false));
        let forfeit = entry(&db, &prot_key_forfeit("gone", 1)).await.unwrap();
        assert_eq!(
            (forfeit.kind, forfeit.amount),
            (ProtEntryKind::Forfeit, 500)
        );
        assert_eq!(forfeit.actor, PROT_ACTOR_DELETION);

        // An account that is not there at all is treated the same way (a new
        // nonce: `admin:{admin}:n1` already names the credit above)
        let ghost = adjust(&db, "ghost", "n2", 300).await.unwrap();
        assert_eq!(ghost.balance, 0);
        assert_eq!(
            entry(&db, &prot_key_forfeit("ghost", 1))
                .await
                .unwrap()
                .amount,
            300
        );
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn forfeit_on_deletion_takes_the_whole_wallet_and_skips_an_empty_one() {
        let db = test_db().await;
        insert_user(&db, "u1").await;

        // No wallet: nothing written
        forfeit_wallet_on_deletion(&db, "u1", NOW).await.unwrap();
        assert!(wallet_rows(&db, "u1").await.is_empty());

        adjust(&db, "u1", "n1", 700).await.unwrap();
        forfeit_wallet_on_deletion(&db, "u1", NOW).await.unwrap();
        let first = entry(&db, &prot_key_forfeit("u1", 1)).await.unwrap();
        assert_eq!(first.kind, ProtEntryKind::Forfeit);
        assert_eq!(first.amount, 700);
        assert_eq!(first.debit, prot_user_account("u1"));
        assert_eq!(first.credit, PROT_SYS_FORFEITED);
        assert_eq!(first.actor, PROT_ACTOR_DELETION);
        assert_eq!(balance(&db, "u1").await, 0);

        // Empty now: a repeat writes nothing
        forfeit_wallet_on_deletion(&db, "u1", NOW + MINUTE)
            .await
            .unwrap();
        assert_eq!(wallet_rows(&db, "u1").await.len(), 2);

        // Prot that arrives later goes in the next pass
        adjust(&db, "u1", "n2", 50).await.unwrap();
        forfeit_wallet_on_deletion(&db, "u1", NOW + 2 * MINUTE)
            .await
            .unwrap();
        assert_eq!(
            entry(&db, &prot_key_forfeit("u1", 2)).await.unwrap().amount,
            50
        );
        assert_eq!(balance(&db, "u1").await, 0);
        drop_db(&db).await;
    }

    // --- standing -----------------------------------------------------

    #[tokio::test]
    async fn prot_me_lists_only_prot_checkouts_and_signs_amounts() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let ps = prot_settings();
        insert_user(&db, "u1").await;

        let off = ProtSalesSettings {
            enabled: false,
            ..prot_settings()
        };
        assert!(matches!(
            error_type(prot_me(&db, &off, "u1", NOW).await),
            ErrorType::ProtDisabled
        ));

        let empty = prot_me(&db, &ps, "u1", NOW).await.unwrap();
        assert_eq!(
            empty,
            v0::ProtMe {
                balance: 0,
                held: 0,
                version: 0,
                pending_order: None,
                recent: vec![],
            }
        );

        // A Cipher checkout is not a Prot one
        create_cipher_checkout(
            &db,
            &stripe,
            &s,
            "u1",
            CipherTier::T99,
            CipherReturnTo::Web,
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(
            prot_me(&db, &ps, "u1", NOW).await.unwrap().pending_order,
            None
        );

        let pending = prot_checkout(&db, &stripe, &s, &ps, "u1", pack("p25"), NOW).await;
        let me = prot_me(&db, &ps, "u1", NOW).await.unwrap();
        assert_eq!(
            me.pending_order,
            Some(v0::ProtPendingView {
                order_id: pending.id.clone(),
                sku: p25(),
                expires_at: pending.session_expires_at.unwrap(),
            })
        );

        // Admin credits are not purchases, so nothing is held
        adjust(&db, "u1", "n1", 300).await.unwrap();
        adjust(&db, "u1", "n2", -100).await.unwrap();
        let me = prot_me(&db, &ps, "u1", EXPIRED).await.unwrap();
        assert_eq!((me.balance, me.held, me.version), (200, 0, 2));
        assert_eq!(me.pending_order, None);
        let mut amounts: Vec<(i64, ProtEntryKind)> =
            me.recent.iter().map(|r| (r.amount, r.kind)).collect();
        amounts.sort_by_key(|(amount, _)| *amount);
        assert_eq!(
            amounts,
            vec![
                (-100, ProtEntryKind::AdminAdjust),
                (300, ProtEntryKind::AdminAdjust)
            ]
        );
        drop_db(&db).await;
    }

    // --- Cipher founding Prot -----------------------------------------

    #[tokio::test]
    async fn cipher_sync_posts_only_while_grants_are_on_and_credits_an_upgrade_once() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;

        // The fulfil hook reads the test config, where grants are off
        let first = buy_cipher(&db, &stripe, &s, "u1", CipherTier::T99, "pi_new", NOW).await;
        assert!(wallet_rows(&db, "u1").await.is_empty());

        // Off, or Prot off with grants on: nothing
        sync_cipher_prot(&db, &prot_settings(), "u1", NOW)
            .await
            .unwrap();
        let prot_off = ProtSalesSettings {
            enabled: false,
            ..grants_on()
        };
        sync_cipher_prot(&db, &prot_off, "u1", NOW).await.unwrap();
        assert!(wallet_rows(&db, "u1").await.is_empty());

        // On: the founding grant, once
        sync_cipher_prot(&db, &grants_on(), "u1", NOW)
            .await
            .unwrap();
        let m = membership(&db, "u1").await;
        let founding = entry(&db, &prot_key_cipher_founding("u1", m.number, &first.id))
            .await
            .expect("the founding row");
        assert_eq!(founding.kind, ProtEntryKind::CipherFounding);
        assert_eq!(founding.amount, 16_500);
        assert_eq!(founding.actor, PROT_ACTOR_CIPHER);
        assert_eq!(balance(&db, "u1").await, 16_500);

        sync_cipher_prot(&db, &grants_on(), "u1", NOW + MINUTE)
            .await
            .unwrap();
        assert_eq!(wallet_rows(&db, "u1").await.len(), 1);
        assert_eq!(
            membership(&db, "u1").await.version,
            m.version,
            "a sync with nothing to do leaves the membership alone"
        );

        // An upgrade is credited its difference under the next sequence
        buy_cipher(
            &db,
            &stripe,
            &s,
            "u1",
            CipherTier::T149,
            "pi_up",
            NOW + HOUR,
        )
        .await;
        sync_cipher_prot(&db, &grants_on(), "u1", NOW + HOUR)
            .await
            .unwrap();
        let upgrade = entry(&db, &prot_key_cipher_upgrade("u1", m.number, &first.id, 1))
            .await
            .expect("the upgrade row");
        assert_eq!(upgrade.kind, ProtEntryKind::CipherUpgrade);
        assert_eq!(upgrade.amount, 16_500);
        assert_eq!(balance(&db, "u1").await, 33_000);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn a_cipher_grant_to_a_deleted_account_is_forfeited_by_the_second_pass() {
        let db = test_db().await;

        // A membership whose account is gone (a grant racing the deletion)
        db.insert_cipher_membership(&CipherMembership {
            user_id: "ghost".to_string(),
            number: 7,
            tier: CipherTier::T99,
            prot_grant: 16_500,
            orders: vec![Ulid::new().to_string()],
            disputed_orders: vec![],
            granted_at: NOW,
            revoked_at: None,
            revoke_reason: None,
            prot_posted_at: None,
            version: 0,
        })
        .await
        .unwrap();

        sync_cipher_prot(&db, &grants_on(), "ghost", NOW)
            .await
            .unwrap();
        let forfeit = entry(&db, &prot_key_forfeit("ghost", 1)).await.unwrap();
        assert_eq!(forfeit.amount, 16_500);
        assert_eq!(balance(&db, "ghost").await, 0);
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn clawback_cipher_order_reports_a_row_written_now() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        let first = buy_cipher(&db, &stripe, &s, "u1", CipherTier::T99, "pi_new", NOW).await;
        sync_cipher_prot(&db, &grants_on(), "u1", NOW)
            .await
            .unwrap();

        // Active and posted to its target: nothing to claw back
        assert!(!clawback_cipher_order(&db, "u1", &first.id, NOW)
            .await
            .unwrap());
        assert!(entry(&db, &prot_key_clawback(&first.id)).await.is_none());

        // Revoked: everything posted comes back, and the membership version moves
        let m = membership(&db, "u1").await;
        let mut revoked = m.clone();
        revoked.revoked_at = Some(NOW + DAY);
        revoked.revoke_reason = Some(CipherRevokeReason::Admin);
        assert!(db
            .update_cipher_membership_if_version(&revoked, m.version)
            .await
            .unwrap());
        let before = membership(&db, "u1").await.version;

        assert!(clawback_cipher_order(&db, "u1", &first.id, NOW + DAY)
            .await
            .unwrap());
        let row = entry(&db, &prot_key_clawback(&first.id)).await.unwrap();
        assert_eq!(
            (row.amount, row.requested, row.shortfall),
            (16_500, Some(16_500), Some(0))
        );
        assert_eq!(balance(&db, "u1").await, 0);
        assert_eq!(membership(&db, "u1").await.version, before + 1);

        // Once
        assert!(!clawback_cipher_order(&db, "u1", &first.id, NOW + 2 * DAY)
            .await
            .unwrap());
        assert_eq!(
            db.fetch_prot_entries_by_order(&first.id)
                .await
                .unwrap()
                .len(),
            2
        );
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn window_clawback_covered_and_membership_shortfall_read_the_whole_membership() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        insert_user(&db, "u1").await;
        let first = buy_cipher(&db, &stripe, &s, "u1", CipherTier::T99, "pi_new", NOW).await;
        sync_cipher_prot(&db, &grants_on(), "u1", NOW)
            .await
            .unwrap();
        let m = membership(&db, "u1").await;

        // The wallet holds the whole grant
        assert!(window_clawback_covered(&db, &m, 0).await.unwrap());
        assert!(window_clawback_covered(&db, &m, 16_500).await.unwrap());
        assert_eq!(membership_shortfall(&db, &m).await.unwrap(), 0);

        // One Prot short of a full undo; a downgrade to the same target
        // needs nothing
        adjust(&db, "u1", "n1", -1).await.unwrap();
        assert!(!window_clawback_covered(&db, &m, 0).await.unwrap());
        assert!(window_clawback_covered(&db, &m, 16_500).await.unwrap());

        // A shortfall recorded on ANOTHER order's clawback of this
        // membership stops every undo, even one that needs nothing
        adjust(&db, "u1", "n2", -16_000).await.unwrap();
        let other = Ulid::new().to_string();
        db.apply_prot_posting(&ProtPosting {
            key: prot_key_clawback(&other),
            kind: ProtEntryKind::Clawback,
            debit: prot_user_account("u1"),
            credit: PROT_SYS_CLAWED.to_string(),
            amount: ProtAmount::UpTo(1_000),
            debit_floor: 0,
            actor: PROT_ACTOR_PAYMENTS.to_string(),
            reference: ProtRef {
                order_id: Some(other),
                membership_number: Some(m.number),
                membership_order_id: Some(first.id.clone()),
                ..Default::default()
            },
            reason: None,
            created_at: NOW + DAY,
        })
        .await
        .unwrap();
        assert_eq!(membership_shortfall(&db, &m).await.unwrap(), 501);
        assert!(!window_clawback_covered(&db, &m, 15_500).await.unwrap());
        assert!(!window_clawback_covered(&db, &m, 16_500).await.unwrap());

        // No incarnation: nothing posted, nothing short
        let bare = CipherMembership {
            orders: vec![],
            ..m.clone()
        };
        assert_eq!(membership_shortfall(&db, &bare).await.unwrap(), 0);
        assert!(window_clawback_covered(&db, &bare, 0).await.unwrap());
        drop_db(&db).await;
    }

    #[tokio::test]
    async fn admin_order_view_reads_the_current_membership_for_cipher_orders() {
        let db = test_db().await;
        let stripe = MockStripe::new();
        let s = settings();
        let ps = prot_settings();
        insert_user(&db, "u1").await;

        let first = buy_cipher(&db, &stripe, &s, "u1", CipherTier::T99, "pi_new", NOW).await;
        sync_cipher_prot(&db, &grants_on(), "u1", NOW)
            .await
            .unwrap();

        assert_eq!(
            admin_prot_order(&db, &first.id).await.unwrap(),
            v0::ProtAdminOrder {
                order_id: first.id.clone(),
                user_id: Some("u1".to_string()),
                sku: Sku::CipherNew {
                    tier: CipherTier::T99
                },
                credited: 16_500,
                clawed_back: 0,
                shortfall: 0,
                unspent: Some(16_500),
                membership_posted: Some(16_500),
                membership_target: Some(16_500),
                membership_shortfall: Some(0),
            }
        );

        // A Prot order of the same buyer shows no membership
        let bought = buy_pack(&db, &stripe, &s, &ps, "u1", pack("p5"), "pi_pack", NOW).await;
        let view = admin_prot_order(&db, &bought.id).await.unwrap();
        assert_eq!((view.credited, view.unspent), (500, Some(17_000)));
        assert_eq!(
            (
                view.membership_posted,
                view.membership_target,
                view.membership_shortfall
            ),
            (None, None, None)
        );

        // Nor does a Cipher order older than the current incarnation
        let mut older = stored_order(
            "u1",
            Sku::CipherNew {
                tier: CipherTier::T149,
            },
            OrderState::Refunded,
            NOW - 30 * DAY,
        );
        older.id = "00000000000000000000000000".to_string();
        db.insert_payment_order(&older).await.unwrap();
        let view = admin_prot_order(&db, &older.id).await.unwrap();
        assert_eq!(view.credited, 0);
        assert_eq!(view.membership_posted, None);

        assert!(matches!(
            error_type(admin_prot_order(&db, "01UNKNOWN0000000000000000").await),
            ErrorType::NotFound
        ));
        drop_db(&db).await;
    }
}
