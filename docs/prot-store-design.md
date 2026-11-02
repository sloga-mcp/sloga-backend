# Prot: in-app purchase design reference (slice S6)

Status: **S6 designed, not implemented** (W0, 2026-11-01). Prot is sold as App Store and Google Play in-app
purchases beside the S5 Stripe checkout. Everything ships dark: both stores closed, no credentials, empty preview and
test lists. This branch runs only against throwaway databases until it lands (its migration number depends on the
blocks that land before it, section 16).

This is the reference that lives with the code, in the same spirit as `docs/prot-design.md` (S5). That document
explains the ledger, keys, payload hash, floors, the 72 h hold (D17), the wallet cap (D18), clawback (D1) and account
deletion (D11, D20); everything in it applies to store-bought Prot unless this document says otherwise. Exact
signatures live in the code and in the pinned contracts (`prot-s6-contracts.md`); this document names the modules
and the rules. Where this document and the code or its tests disagree, treat it as a bug in one of them and fix it;
do not quietly follow either.

Owner decisions are tagged E1 to E12 (S6) and D1 to D20 (S5). Refinements the contracts made against the plan are
tagged R1 to R28. This text follows the contracts as revised after the W0 audit (their section 34).

## 1. Purpose and scope

The owner decided that Prot is also sold through Apple and Google at the stores' small-business rate (15%), with
store packs priced so that Sloga nets at least the web price, and that store refunds are handled like chargebacks
(unspent Prot only). Store builds have so far shown the balance and history but never a purchase link (D5). S6 adds:

- server-side verification of StoreKit 2 transactions (Apple JWS, chained to a pinned Apple root) and of Play Billing
  purchases (the Android Publisher API, read live);
- a one-time purchase **intent** that carries every pre-payment check and binds the store purchase to one Sloga
  account through a random token;
- a purchase-row state machine whose credit and refund moves commit in the SAME transaction as their ledger rows;
- refund generations, so an Apple refund, its reversal and a second refund each settle exactly once;
- Apple App Store Server Notifications (a public signed endpoint), Play Real-time Developer Notifications (pulled
  from Pub/Sub by crond) and a reconcile job that backstops both;
- staff tools: a needs-action list, a purchase read, and an assign route for purchases that arrived without a valid
  token;
- the client side: a `ProtStore` Capacitor plugin (Swift for iOS, Java for the Play flavor), a pure purchase-flow
  state machine, a recovery worker, a store shop in the wallet page and the store-build spending gate.

Not in S6: answering Apple `CONSUMPTION_REQUEST` (E7), any client code for the US web link (E8: only the server flag
and its advert field ship, Q5), subscriptions, Ward,
Protected channels on iOS (S8), answering Play chargeback reviews, regional price overrides, promoted IAP and offer
codes.

**Code map:**

| Area | Path |
|---|---|
| Stored types, state machine, key builders | `crates/core/database/src/models/prot_store/` (`model.rs`, `ops.rs`, `ops/{mongodb,reference}.rs`) |
| The one-transaction store move | `models/prot/ops.rs` + `ops/{mongodb,reference}.rs` (`apply_store_purchase_move`) |
| v0 API types | `crates/core/models/src/v0/prot.rs` (`ProtStore*`) |
| Engine | `crates/core/payments/src/engine/prot_store.rs`; settings in `payments/src/settings.rs` (`ProtStoreSettings`) |
| Store clients | `crates/core/payments/src/store/` (`apple_jws.rs`, `apple_api.rs`, `play_api.rs`, `google_auth.rs`, `mock.rs`) |
| Routes | delta `routes/payments/prot_store.rs`, `routes/payments/apple_notifications.rs`, `routes/admin/prot_store.rs` |
| Alerts | `crates/core/database/src/util/prot_store_alert.rs` |
| crond | `crates/daemons/crond/src/tasks/prot_store_reconcile.rs` |
| Client (frontend repo, `packages/client/`) | `components/client/{protStorePlugin.ts, protStoreFlow.ts, protStoreFacts.ts, ProtStoreWorker.tsx, distribution.ts}`, `settings/user/{protWallet.ts, ProtSettings.tsx}` |
| Native | Android `android/app/src/play/java/com/acutest/app/ProtStorePlugin.java`; iOS `ios/App/SlogaStore/` |

## 2. Money flow

### 2.1 In one picture

```
 app                         Sloga (delta)                         store
  |  POST /payments/prot/store/intent {store, product_id}          |
  |------------------------------>| gates (section 8), new intent  |
  |<------------------------------| {intent_id, token, prot, ...}  |
  |  ProtStore.purchase({product_id, account_token: token})        |
  |---------------------------------------------------------------->| sheet; Apple appAccountToken /
  |<----------------------------------------------------------------| Play obfuscatedAccountId = token
  |  POST /payments/prot/store/verify {signed_transaction | product_id + purchase_token}
  |------------------------------>| verify (section 6), resolve the token to the intent,
  |                               | ONE transaction: row -> Credited + intent -> Used + purchase:{id}
  |<------------------------------| {status: credited, balance, ledger_id}; ProtBalanceUpdate
  |  iOS: finish(transaction_id)  | Play: the SERVER consumes after the credit commits
  |                               |<------ Apple notifications (REFUND, ...) / Play RTDN (voids)
  |                               | crond prot_store_reconcile backstops every notification
```

1. **Intent.** The app asks for an intent. Every check that must happen before money is taken runs here (store open
   or preview, no open Stripe dispute, a known product, at most 3 open intents, the wallet cap). The server issues a
   fresh random one-time token. The intent counts as open for 24 h, or until the app cancels it after a cancelled or
   failed sheet; after that it is `Expired`, but it still binds a purchase that completes late.
2. **Store sheet.** The app opens the store sheet with the token bound to the purchase. Prices are the stores'; the
   server never sees money.
3. **Verify.** The app posts the store's result. The server verifies it cryptographically (Apple) or authoritatively
   (Play), resolves the token to its intent (user + product), stamps the Prot amount on a `prot_store_purchases` row
   and, in one transaction, moves the row to `Credited` (never from `Revoked`), marks the intent `Used` and posts the
   ledger row `purchase:{store purchase id}`, kind `Purchase`, `sys:issued -> user:{id}`.
4. **Finish / consume.** Only after the server answers `credited` or `already_credited` does the iOS app finish the
   transaction. On Play the client never consumes: the server consumes after the credit has committed and records
   it; until then the Prot stays held (section 4.5).
5. **Refunds.** Apple sends signed notifications; Play voids arrive by RTDN and by `voidedpurchases.list`. The server
   acts on the store's CURRENT state (Apple: a fresh Get Transaction Info for every refund notification), never on the
   notification type alone. A refund claws back up to the whole purchase's Prot, unspent only (D1), in the same
   transaction that moves the row to `Revoked`. A refund that arrives before any credit leaves a `Revoked`
   **tombstone**, so no later path can credit.
6. **Reconcile.** crond pulls RTDN, retries consumes, reads voided purchases daily and Apple's notification history
   hourly, credits `Held` rows once the pause is off, expires intents and raises alerts.

At verify the money is already taken, so a verified purchase bound to a valid intent is **always credited** (S5's
rule), even when its intent has expired (a parent approving Ask to Buy days later), even when the store has since
closed (E9), and even above the wallet cap (the stated residual). A deleted buyer's credit is forfeited at once by the
S5 second pass.

### 2.2 Products and prices (E5)

Permanent product ids, the same on both stores: Apple Consumable, Play one-time product with one purchase option,
quantity off. The server maps product id -> Prot only (`prot_store_products`); prices live in the consoles, so a
price change never changes what is credited, and a Prot change is a NEW product id (Apple never allows id reuse).

| Product id | Prot | Store price (USD) | Net at 15% | Net at 30% | Web price | Next-lower .99 at 15% (fails) |
|---|---|---|---|---|---|---|
| `gg.sloga.prot.p5` | 500 | $5.99 | $5.09 | $4.19 | $5.00 | $4.99 -> $4.24 |
| `gg.sloga.prot.p10` | 1,000 | $11.99 | $10.19 | $8.39 | $10.00 | $10.99 -> $9.34 |
| `gg.sloga.prot.p25` | 2,600 | $29.99 | $25.49 | $20.99 | $25.00 | $28.99 -> $24.64 |
| `gg.sloga.prot.p50` | 5,300 | $58.99 | $50.14 | $41.29 | $50.00 | $57.99 -> $49.29 |
| `gg.sloga.prot.p100` | 11,000 | $117.99 | $100.29 | $82.59 | $100.00 | $116.99 -> $99.44 |

The rule: the cheapest price ending in .99 whose 85% net is at least the web price (nets truncated to the cent, e.g.
5.99 x 0.85 = 5.0915 -> $5.09). The Prot amounts are the web packs, bonuses included. The largest single credit,
11,000, is inside the default `wallet_cap` of 100,000. Other storefronts use the stores' own price equalization. No
pay-exact in store builds. Quantity > 1 is off in both consoles; if one arrives, it is credited `prot x quantity`
(E11), never refused.

### 2.3 Purchase ids

| Store | `_id` | Notes |
|---|---|---|
| Apple production | `apple:prod:{transactionId}` | `transactionId` = 1..=20 ASCII digits (a UInt64) |
| Apple sandbox | `apple:sandbox:{transactionId}` | the environment part keeps sandbox and production ids from ever colliding |
| Play | `play:{sha256hex(purchaseToken)}` | 64 lowercase hex; the raw token is stored in the row but never in logs |

`is_store_purchase_id` accepts exactly these three shapes. Logs name purchase ids, never raw tokens.

## 3. Data

Three new collections, NOT `payment_orders`. `payment_orders` is Stripe-only end to end, and a store variant there
would add a rollback floor. Old binaries never read the new collections, and the ledger rows S6 writes are ordinary
`Purchase`, `Clawback` and `ClawbackHold` rows that S5 already decodes. No new `ProtEntryKind`, no new `ProtRef` field
(that would change `prot_payload_hash` for every stored row) and no new event (`ProtBalanceUpdate` carries every store
credit and clawback).

### 3.1 `prot_store_purchases` (`ProtStorePurchase`)

One document per store purchase. `prot` is stamped at first sight (product Prot x quantity from config; 0 for an
unknown product) and never re-derived, so a config edit between two retries changes nothing.

| Field | Meaning |
|---|---|
| `_id`, `store` | section 2.3; `apple` or `play` |
| `user_id` | the intent's user; None when unbound, or once unlinked by account deletion |
| `intent_id` | the binding intent, when there was one |
| `product_id`, `prot`, `quantity` | as seen; `prot` stamped |
| `environment` | `Production` or `Sandbox` (Apple Sandbox, or a Play purchase with `testPurchaseContext`) |
| `storefront`, `country` | as the store sent it (Apple alpha-3, Play alpha-2), and the ISO alpha-2 when known |
| `state`, `reject_reason` | section 4 |
| `refund_gen`, `refunds` | refund generations applied, and one `ProtStoreRefund {gen, at, revocation_date, clawed, shortfall, reason}` for EVERY generation (a tombstone has one entry with gen 0); `revocation_date` is the store's revocation instant and is what detects a replayed refund |
| `unreinstated_reversals` | Apple reversals that re-credited nothing because there was no buyer or no credit (a tombstone) (section 4.3) |
| `apple` / `play` | store details: Apple transaction and original transaction ids, token, signed and purchase dates; Play full token, order id, obfuscated account id, `consumed_at`, `test`, region |
| `credited_at` | when the `purchase:` posting committed |
| `unconsumed` | `true` from a Play credit until the server consumed it; unset at consume |
| `revoked_at`, `revocation_reason`, `assigned_by` | refund facts; the admin id of an E10 assign |
| `needs_action`, `alerted` | the staff work item (one kind at a time; a later set overwrites; section 13) and the alert kinds already sent |
| `created_at`, `updated_at`, `version` | `version` + 1 on EVERY write: moves and bookkeeping alike (section 5.5) |

`unconsumed` is an explicit `true` rather than "no `consumed_at`" because a Mongo partial index cannot select a
missing field (R7).

### 3.2 `prot_store_intents` (`ProtStoreIntent`)

`{_id: ULID, user_id?, store, product_id, prot (per unit, informational), token, state: Open | Used | Expired,
purchase_id?, created_at, expires_at = created_at + 24 h}`.

- Tokens are random per intent: Apple a UUID v4, lowercase and hyphenated (`appAccountToken`); Play 32 random bytes,
  base64url without padding, 43 characters (Play allows 64). They are never derived from the user id or the ULID,
  which would leak the creation time and let the stores' records be linked to Sloga ids.
- A unique index on `token` makes a token one-time. One intent = one purchase: the FIRST write of a purchase row
  marks its intent `Used` (only from `Open` or `Expired`, and only while the intent's user still equals the row's) in
  the same transaction. That first write is a credit, a hold, a reject for `TestPurchase`, `UnknownProduct` or
  `BadPayload`, or a tombstone whose token resolved. A reject for `Unbound` or `NoBuyer` (the intent is already `Used`
  or unlinked) never touches the intent, and no later move on an existing row does. A second purchase carrying a
  `Used` token is `Rejected{Unbound}`; the first intent keeps its `purchase_id`.
- At most `PROT_STORE_MAX_OPEN_INTENTS` = 3 open intents per user. The app cancels its own intent after a cancelled
  or failed sheet (`Open -> Expired`, section 8), which frees the slot and the cap; an `Expired` intent still binds a
  purchase that arrives anyway.
- crond moves `Open` intents past `expires_at` to `Expired`, and deletes `Expired` intents that never got a purchase
  once they are 30 days past expiry (section 7.4). Intents that bound a purchase are kept with it.

### 3.3 `prot_store_cursors` (`ProtStoreCursor`)

`{_id: "apple-history" | "play-voided", cursor (epoch ms as a decimal string), version, updated_at}`. Each reconcile
replica advances a cursor only by a version CAS; the loser skips.

### 3.4 Indexes

| Collection | Name | Key | Options |
|---|---|---|---|
| intents | `prot_store_intents_token_unique` | `{token: 1}` | unique |
| intents | `prot_store_intents_user_state` | `{user_id: 1, state: 1}` | |
| intents | `prot_store_intents_state_expires` | `{state: 1, expires_at: 1}` | |
| purchases | `prot_store_purchases_user_created` | `{user_id: 1, created_at: -1}` | |
| purchases | `prot_store_purchases_state_store` | `{state: 1, store: 1, created_at: 1}` | |
| purchases | `prot_store_purchases_needs_action` | `{needs_action: 1, updated_at: -1}` | partial `{needs_action: {$type: "string"}}` |
| purchases | `prot_store_purchases_unconsumed` | `{unconsumed: 1, user_id: 1, credited_at: 1}` | partial `{unconsumed: {$eq: true}}` |
| purchases | `prot_store_purchases_sandbox_user` | `{user_id: 1, environment: 1, state: 1}` | partial `{environment: "Sandbox"}` |

`prot_store_cursors` has `_id` only. There is no index on `apple.original_transaction_id`: for a consumable it equals
the transaction id and is stored for support only. Indexes come from the migration (section 16), never from ops.

## 4. The purchase-row state machine

### 4.1 States

| State | Meaning | Ledger |
|---|---|---|
| `Credited` | the `purchase:{id}` row exists | credited |
| `Held` | verified and bound, but recorded while `prot_store_credit_paused` (E9); crond credits it when the pause is off | none yet |
| `Rejected{reason}` | not credited: `TestPurchase`, `Unbound`, `UnknownProduct`, `BadPayload`, `NoBuyer` | none |
| `Revoked` | refunded or voided. After a credit: clawed back. Before any credit: a **tombstone** | clawback rows, or none |
| `Reinstated` | an Apple refund reversal re-credited what that generation clawed | `reinstate:{id}:{n}` |

`NoBuyer` (R12) means the intent's user was deleted before the purchase was seen.

### 4.2 Verdicts and events

The engine first decides what it thinks of a verified, not-revoked purchase (binding, environment, product, test cap,
pause), without looking at the row: a `ProtStoreVerdict` of `Credit {user, intent}`, `Hold {user, intent}` or
`Reject {reason, user?, intent?}`. Then it feeds one event to the planner:

| Event | From |
|---|---|
| `Seen(verdict)` | verify, Apple ONE_TIME_CHARGE, Apple history replay, Play RTDN PURCHASED, reconcile |
| `Revoke {revocation_date, reason, user_hint, buyer_live}` | a CURRENT revocation: Apple, a `revocationDate` on the fresh Get Transaction Info (or on any verified JWS); Play, a void (RTDN, `voidedpurchases.list`) or `purchaseState` CANCELLED on a live read |
| `Reverse {buyer_live}` | Apple: a REFUND or REFUND_REVERSED notification whose fresh lookup shows NO `revocationDate` |
| `Unpause {buyer_live}` | crond, once `prot_store_credit_paused` is off AND a fresh store lookup shows the purchase not revoked (a revoked one is fed as `Revoke`) |
| `Assign {user, admin, paused}` | the E10 admin assign, after a fresh store lookup shows the purchase not revoked |

`buyer_live` = the row's user is set, exists and is not deleted. The `revocation_date` is the store's own instant
(Apple `revocationDate`; Play the RTDN `eventTimeMillis` or the list's `voidedTimeMillis`; "now" for a CANCELLED seen
on a live read, when no void time is known yet).

`plan_store_move(row, event, reinstate_amount)` is THE transition function: pure, no I/O, and called by both drivers'
tests, the engine and the admin route. `reinstate_amount` is what the row's latest generation clawed, read from the
ledger (section 5.3); it is 0 for every other event. The result is either an answer (`Credited`, `AlreadyCredited`,
`Held`, `Rejected(r)`, `Refunded`, `Revoked`, `Reinstated`, `Ignored`, `NotAssignable`) or a move: the target state,
the user and intent to record, the ledger plan (`None`, `Credit`, `Clawback {gen}`, `Reinstate {gen}`), the work
item to set (`needs_action`: None KEEPS the row's, a kind sets it), the work items to clear (`clear_needs`), the
`unconsumed` flag (set on a Play credit, unset on every move to `Revoked`, else kept) and the answer.

### 4.3 Transition table

Exhaustive. Anything not listed is `Ignored` and logged `PROT_STORE_EVENT_IGNORED`.

| Row | Event | Plan |
|---|---|---|
| none | `Seen(Credit {u, i})` | -> `Credited`, user u, intent i, ledger Credit; answer Credited |
| none | `Seen(Hold {u, i})` | -> `Held`, user u, intent i; answer Held |
| none | `Seen(Reject {r, u, i})` | -> `Rejected(r)`, user u, intent i; needs_action `unbound` iff r = Unbound; answer Rejected(r) |
| any row | `Revoke {date}` whose `date` equals any `refunds[*].revocation_date` | answer Revoked, NO move: a replayed refund. Checked before every other `Revoke` row |
| none | `Revoke {date, user_hint}` | -> `Revoked` (**tombstone**), user = user_hint, no ledger, `refunds` gains `{gen 0, revocation_date: date, clawed 0, shortfall 0}`, refund_gen stays 0; answer Revoked |
| none | `Reverse` / `Unpause` / `Assign` | Ignored (Assign: NotAssignable) |
| `Held` | `Seen(Credit)` | -> `Credited`, ledger Credit; answer Credited |
| `Held` | `Seen(Hold)` or `Seen(Reject)` | answer Held |
| `Held` | `Unpause {buyer_live: true}` | -> `Credited`, ledger Credit; answer Credited |
| `Held` | `Unpause {buyer_live: false}` | -> `Rejected(NoBuyer)`; answer Rejected(NoBuyer) |
| `Held` | `Assign` | NotAssignable |
| `Held` | `Revoke` | -> `Revoked` (tombstone), gen-0 `refunds` entry as above; answer Revoked |
| `Rejected(r)` | `Seen(*)` | answer Rejected(r): an allow-list or binding change never re-opens a row |
| `Rejected(Unbound)` | `Assign {u, a, paused: false}` | -> `Credited`, user u, ledger Credit, `assigned_by` a, clears `unbound`; answer Credited |
| `Rejected(Unbound)` | `Assign {u, a, paused: true}` | -> `Held`, user u, `assigned_by` a, clears `unbound`; answer Held (R16: the pause wins) |
| `Rejected(other)` | `Assign` | NotAssignable |
| `Rejected(r)` | `Revoke` | -> `Revoked` (tombstone), keeps `reject_reason = r`, gen-0 `refunds` entry as above; answer Revoked |
| `Credited` / `Reinstated` | `Seen(ANY verdict)` | AlreadyCredited; the engine then REQUIRES `purchase:{id}` in the ledger (else `PROT_STORE_ROW_WITHOUT_LEDGER`, InternalError) |
| `Credited` / `Reinstated` | `Revoke {buyer_live: true}` | -> `Revoked`, ledger Clawback {gen: refund_gen + 1}; answer Revoked |
| `Credited` / `Reinstated` | `Revoke {buyer_live: false}` | -> `Revoked`, no ledger, refund_gen + 1, `refunds` entry `{clawed 0, shortfall 0, reason "no_buyer"}`; answer Revoked (the S5 forfeit already took the wallet) |
| `Credited` / `Reinstated` | `Reverse` / `Unpause` / `Assign` | Ignored / Ignored / NotAssignable |
| `Revoked` | `Seen(*)` | answer Refunded: **never a credit path** |
| `Revoked` | `Revoke {new date}` | answer Revoked: already revoked, no second claw without a reversal in between |
| `Revoked` | `Assign` | NotAssignable |
| `Revoked`, refund_gen >= 1 | `Reverse {buyer_live: true}`, reinstate_amount > 0 | -> `Reinstated`, ledger Reinstate {gen: refund_gen}; answer Reinstated |
| `Revoked`, refund_gen >= 1 | `Reverse {buyer_live: true}`, reinstate_amount == 0 | -> `Reinstated`, no ledger; answer Reinstated (E6: nothing was taken, so nothing is given back, and a later refund claws again) |
| `Revoked`, refund_gen >= 1, `unreinstated_reversals == 0` | `Reverse {buyer_live: false}` | stays `Revoked`, `unreinstated_reversals` + 1; answer Ignored |
| `Revoked`, refund_gen == 0 (tombstone), `unreinstated_reversals == 0`, not sandbox | `Reverse` | stays `Revoked`, `unreinstated_reversals` + 1, needs_action `reversed_unpaid`; answer Ignored (owner Q1) |
| `Revoked`, refund_gen == 0 (tombstone), `unreinstated_reversals == 0`, `reject_reason` TestPurchase or environment Sandbox | `Reverse` | stays `Revoked`, `unreinstated_reversals` + 1, NO work item, logged `PROT_STORE_SANDBOX_REVERSAL`; answer Ignored |
| `Revoked`, `unreinstated_reversals >= 1` | `Reverse` (not one of the reinstate rows) | answer Ignored, no move: a history replay never re-opens a resolved `reversed_unpaid` |

Every move to `Revoked` also clears the work items `unbound` and `play_unconsumed_24h` and unsets `unconsumed`.

Notes:
- "For the row's user": verify's caller check (`wrong_account`, section 6.3) runs BEFORE planning, so the planner
  never sees a foreign caller. The caller-less paths (notifications, RTDN, reconcile) credit the intent's user (R11).
- Any `Seen` on a `Credited` or `Reinstated` row is AlreadyCredited, whatever the verdict: the row wins. This covers a
  sandbox cap reached later, a product that has since left the table, and the app replaying an assigned purchase
  whose token resolves to an intent `Used` by another purchase.
- The only plans that credit start from none, `Held`, or a `Rejected(Unbound)` assign. `Revoked` has none.

### 4.4 Invariants

1. **Revoked is terminal for credit.** No sequence of events ever plans `Credit` for a row that was ever `Revoked`
   (property test). A reversal moves `Revoked -> Reinstated` with its own key, never through `purchase:`.
2. **One clawback per generation.** `Clawback {gen}` is planned at most once per generation (property test), and
   a replayed refund (same `revocation_date`) never moves the row (`replayed_refund_is_a_no_op`).
3. **`already_credited` comes from the ledger,** never from the row alone.
4. **A reversal with a live buyer always reinstates** (R14 as revised): to `Reinstated`, re-crediting exactly what
   that generation took, which may be 0 (then no posting). So a later refund opens the next generation and claws
   again (E6). Only a tombstone (`reversed_unpaid`, Q1; no work item for a sandbox purchase) and a reversal for a
   buyer who is gone stay `Revoked`, counted in `unreinstated_reversals`, and only the first such reversal moves the
   row: once the counter is >= 1, a replayed reversal is Ignored, so it never re-opens a resolved work item.
5. **Every write to a store row goes through `apply_store_purchase_move`,** except the bookkeeping writes that move
   no Prot: consume marking, setting and clearing work items, alert claims and unlinking (section 5.5). Every write,
   bookkeeping included, bumps `version`.

### 4.5 The held figure: reinstates and unconsumed Play credits

The held figure (`/@me` `held`, and S5b's contribute and pledge floors) is S5b's ledger-derived figure plus an
unconsumed-Play term. Two S6 rules shape it.

**Reinstated Prot is held 72 h again (N1).** The hold is derived from the ledger row KIND `Purchase` (never a key
prefix), so a `reinstate:{id}:{n}` row counts. S5b's fold nets each held order's purchases against that order's
clawbacks; without a time rule, the generation's own earlier `clawback:` row would cancel the reinstate and it would
read as 0 held. So, per order: `first_held` = the earliest `created_at` among that order's `Purchase` rows inside the
window, and a `Clawback` row of the order is subtracted only if its `created_at >= first_held`. Stripe orders (one
purchase, clawbacks after it) are unaffected. Example 9.2 shows the arithmetic.

**Unconsumed Play credits stay held.** Play auto-refunds a purchase that is not consumed (or acknowledged) within 3
days. If a consume kept failing, the refund would land exactly as the 72 h hold (D17) ended, after the Prot could have
gone into a tank. So the figure adds the Prot of the user's Play rows that are `unconsumed`, in `Credited` or
`Reinstated`, and credited BEFORE the hold window starts (`credited_at < now - contribute_hold_hours`). Newer rows are
already in the ledger fold; counting only older ones avoids a double count (R8). With `contribute_hold_hours = 0` the
ledger part is 0 but the term still applies, to every unconsumed Play row: in `/@me` as below, and in S5b's contribute
and pledge floors with the cutoff `now`.

```
held = 0                                                        if balance <= 0
     = clamp(held_purchase_prot(user, now - hold), 0, balance)  if hold > 0   (ledger fold + term)
     = clamp(sum_unconsumed_play_prot(user, +inf), 0, balance)  if hold == 0
```

## 5. Ledger keys and refund generations

### 5.1 Keys

`ref.order_id` = the store purchase id on every row. Never format keys by hand: `prot_store_key_purchase`,
`prot_store_refund_base`, `prot_store_key_clawback`, `prot_store_key_reinstate`, and S5b's `prot_key_clawback_hold`.

| Entry | Key | Kind | Debit -> credit | Amount | Actor |
|---|---|---|---|---|---|
| Store credit (also an E10 assign) | `purchase:{id}` | Purchase | sys:issued -> user:{u} | Exact(row.prot) | sys:store |
| Refund, wallet part, generation 1 | `clawback:{id}` | Clawback | user:{u} -> sys:clawed | UpTo(total_1) | sys:store |
| Refund, wallet part, generation n >= 2 | `clawback:{id}:r{n}` | Clawback | user:{u} -> sys:clawed | UpTo(total_n) | sys:store |
| Refund, held-pledge part | `clawback-hold:{base}:{pledge_id}` | ClawbackHold | hold:{goal} -> sys:clawed | Exact(x) | sys:payments (S5b's builder) |
| Apple refund reversed, generation n | `reinstate:{id}:{n}` | Purchase | sys:issued -> user:{u} | Exact(clawed_n) | sys:store |

`base` = `{id}` for generation 1 and `{id}:r{n}` for n >= 2, so the pledge rows are `clawback-hold:{id}:{pledge}` and
`clawback-hold:{id}:r{n}:{pledge}`. Store rows are told apart from Stripe rows by the `apple:` / `play:` prefix of
`ref.order_id` (and of their keys), with no new kind (R13). The `purchase:`, `clawback:` and `reinstate:` rows S6
builds also carry the new actor `sys:store`, but the `clawback-hold:` rows keep S5b's `sys:payments`, so the actor
alone does not identify a store row. The actor is not hashed, so the hash format is unchanged. An assign writes the
same `purchase:{id}`
key as a normal credit (the row records `assigned_by`), so a purchase can never be credited twice by any combination of
verify, notification, RTDN, reconcile and assign.

### 5.2 How much a generation takes

```
total_n = row.prot - sum(clawed_g for g < n) + sum(reinstated_g for g < n)      (always == row.prot)
```

- `total_n` always equals `row.prot`: a generation n >= 2 exists only after `Revoked -> Reinstated`, and every
  reinstated generation got back exactly what it clawed (or clawed 0 and got 0). The engine computes it anyway and
  asserts it equals `row.prot` and is > 0; otherwise `InternalError`, logged `PROT_STORE_GENERATION_MISMATCH`, and
  no move.
- Any refund or void claws the WHOLE purchase's Prot, unspent only (the Terms: "even if only part of the payment was
  refunded"; a quantity-partial Play void is treated the same).
- The wallet part is `UpTo(total_n)` from the buyer's wallet. If it falls short, S5b's drain takes the rest from the
  buyer's Held pledges, newest first, one `clawback-hold:` row each, in the same transaction. Prot in a tank is never
  taken back, a balance never goes below 0, and the rest is recorded as the generation's shortfall.
- **No buyer:** a refund of a row whose user was unlinked (or deleted) posts nothing; the row still opens the
  generation (`refund_gen + 1`, entry reason `no_buyer`), and that generation is never reinstated.
- **Every generation has a record** on the row, `ProtStoreRefund {gen, at, revocation_date, clawed, shortfall,
  reason}`. The engine builds it with `clawed` and `shortfall` at 0; for a clawback the driver fills them in the
  same transaction (`clawed` = the sum of that generation's Clawback + ClawbackHold amounts). A tombstone's record has
  gen 0.

S5's `clawback_purchase` is NOT reused for store rows: it claws once and returns early when `clawback:{id}` exists, so
a second refund after a reversal would take nothing.

### 5.3 Reading a generation back

`prot_store_refund_gen_of(key, id)`: strip `clawback:` or `clawback-hold:`, then `id`. The remainder `""` or
`":{ULID}"` (26 characters, no `r`) is generation 1; `":r{n}"` or `":r{n}:{ULID}"` (n >= 2) is generation n; anything
else is not a generation row. The reinstate amount of generation n = the sum of `amount` over the purchase's ledger
rows (`fetch_prot_entries_by_order(id)`) of kind Clawback or ClawbackHold whose generation is n. The ledger is the
source of truth: `refunds[n-1].clawed` must agree, and on a mismatch the engine logs `PROT_STORE_REFUND_MISMATCH` and
uses the ledger.

### 5.4 Key lengths

The S5 limit is 255 bytes. The longest S6 key is `clawback-hold:` (14) + `play:` (5) + 64 hex + `:r` (2) + n +
`:` (1) + a 26-character pledge ULID = 112 + digits(n), so 113 for n < 10. Apple's longest is
`clawback-hold:apple:sandbox:` (28) + 20 digits + `:r9:` (4) + 26 = 78. `purchase:play:{64 hex}` is 78.

### 5.5 One transaction: `apply_store_purchase_move`

S5's `apply_prot_posting` takes no session, so S6 adds one trait method to `AbstractProtLedger`:
`apply_store_purchase_move(&ProtStoreMove) -> Result<ProtStoreMoveOutcome>`. A `ProtStoreMove` is the row exactly as
it must be stored after the move, the expected version (None = insert, no row may exist), an optional intent to mark
`Used`, and the ledger part (`None`, `Credit(posting)` or `Clawback {user, posting, key_base}`). The intent is passed
ONLY on the row's first write and only when the verdict resolved an `Open` or `Expired` intent (section 3.2).

**MongoDB** (inside S5's `run_prot_transaction`, every call on the session):
1. read the row: absent for an insert, `version == v` for a CAS; otherwise "state moved";
2. mark the intent `Used` (with `purchase_id`), only from `Open` or `Expired` and only while its `user_id` still
   equals the row's; no match is "state moved";
3. the ledger: a credit posts in the session; a clawback runs the wallet `UpTo` posting, then S5b's held-pledge drain
   with the generation's key base;
4. write the row: insert (a duplicate `_id` is "state moved") or replace on `{_id, version: v}` with `version + 1`.

"State moved" returns `Conflict`: the engine re-reads and re-plans, at most `PROT_STORE_MOVE_RETRIES` (5) times. A
duplicate ledger key is read back outside the transaction: same payload hash means a racing move committed (Conflict;
the re-read sees it), a different hash is `ProtIdempotencyConflict`. Transactions need a replica set
(`ensure_replica_set`, as S5).

**Reference driver** (tests): one lock section in the complete order **`channels -> messages -> channel_entitlements
-> servers -> server_members -> channel_seat_lists -> channel_seats -> mls_groups -> mls_commits -> mls_join_intents
-> e2ee_identities -> e2ee_queue -> cipher_memberships -> prot_ledger -> prot_accounts -> prot_pledges -> prot_goals ->
prot_tanks -> prot_runtime -> prot_notices -> prot_contributor_prefs -> prot_store_intents -> prot_store_purchases ->
prot_store_cursors`**. The store maps come last (R2: after S5b's real last map), so a store move takes the ledger maps
first. Same rules as S5: take every map at the start in this order, hold to the end, never re-take, never call a trait
method while holding one, every check before the first mutation.

After every committed move with a ledger row, the engine runs `after_store_posting`: publish `ProtBalanceUpdate` to
the buyer, then the S5 second-pass forfeit if the buyer has been deleted meanwhile.

Bookkeeping writes outside the move (no Prot moves): `mark_prot_store_consumed` (a version CAS; it also clears a
`play_unconsumed_24h` work item), `set_prot_store_needs_action`, `clear_prot_store_needs_action` (only the named
kind), `claim_prot_store_alert` (`$addToSet`, one winner across replicas), `unlink_prot_store_user`, and the cursor
CAS. **Every one of them bumps the row's `version`** (both drivers). The move writes the row with a full replace on
`{_id, version}`, so this is what keeps a move planned on a stale copy from overwriting a newer one: it misses its
CAS, re-reads and re-plans. For example, an unlink between a move's read and its write makes the move conflict; the
re-plan sees no user, and the row ends unlinked (`unlink_racing_a_move_stays_unlinked`).

## 6. Verification

Both stores, before anything else: bots are refused (`IsBot`); the managed store client not configured
(`configured()` on the client delta manages, never the raw settings, so route tests run on the mocks; in production
the two are the same) -> `ProtStoreUnavailable`; a body of the wrong shape for its store -> `FailedValidation`.
Verify works whether or not the store is open (E9) and whatever `enabled` says: the money is already taken.

### 6.1 Apple JWS (`verify_apple_jws`, `store/apple_jws.rs`)

StoreKit 2 transactions, App Store Server Notifications and Get Transaction Info answers are all JWS, signed by Apple
with an `x5c` chain to **Apple Root CA - G3**. The verifier is hand-written on crates already in the lock (`x509-cert`,
`der`, `p256`, `p384`, `ecdsa`, `sha2`, `base64`, `const-oid`); no new crate. Checks, in this order, each its own error:

1. At most 65,536 bytes; exactly three `.`-separated, non-empty base64url segments without padding -> else
   `Malformed`.
2. Header: `alg` exactly `"ES256"` (`none`, `HS*`, `ES384` or missing -> `Algorithm`); any `crit`, `jku`, `jwk` or
   `x5u` member -> `Algorithm`; `x5c` an array of exactly 3 strings (standard base64 DER) -> else `ChainShape`.
3. SHA-256 of the third certificate's DER == the pinned root hash -> else `RootMismatch`. A leaf is never trusted
   alone and nothing is ever fetched.
4. The three certificates parse -> else `Malformed`.
5. Leaf carries `1.2.840.113635.100.6.11.1` (receipt signer), intermediate carries `1.2.840.113635.100.6.2.1` (WWDR)
   -> else `MissingOid`. Positions are fixed, so a swapped chain fails here.
6. Intermediate and root have basicConstraints `cA = true`; the leaf has none or `cA = false` -> else `NotCa`.
7. Leaf issuer == intermediate subject and intermediate issuer == root subject (DER equality) -> else
   `IssuerMismatch`.
8. Chain signatures: leaf TBS by the intermediate's key, intermediate TBS by the root's key; P-256 or P-384 keys
   only (else `UnsupportedKey`), ECDSA with SHA-256 or SHA-384 per the certificate's signature algorithm -> else
   `ChainSignature`.
9. The payload's `signedDate` (ms) must be present (else `Malformed`), and each certificate must be valid AT
   `signedDate`, never at "now" -> else `Validity`. Two tests pin this: a leaf already expired by the wall clock but
   valid at `signedDate` is accepted, and a `signedDate` before the leaf's `notBefore` is refused.
10. The leaf key is P-256 (else `UnsupportedKey`); the 64-byte r||s signature over `header_b64 + "." + payload_b64`
    verifies -> else `Signature`.

There is no revocation check (Apple's own library does none). The freshness lookup below covers a JWS whose purchase
was refunded after it was signed. The root hash is pinned in code (`APPLE_ROOT_G3_SHA256_HEX`) and as the config
default `root_ca_g3_sha256`; it is provisional until confirmed against a second copy (the Mac mini's system root
store) before it is committed.

**Transaction checks** (`apple_transaction_checks` on the decoded `AppleTransaction`, after the JWS verifies). One
shared function: verify and the notification path both run it on every transaction JWS.
- `bundleId` != `bundle_id`, or `environment == "Xcode"` -> `ProtStoreVerifyFailed`, no row;
- `type` != `"Consumable"` -> verdict `Reject(BadPayload)` (verify answers `ProtStoreVerifyFailed`);
- **freshness (audit BLOCKER 1):** `now - signedDate > 600,000` ms (10 minutes), or any notification-history replay,
  -> Get Transaction Info for that transaction, and THAT JWS is verified the same way and used. On an API failure
  verify reads the row first: a `Revoked` row answers `rejected/refunded`; anything else is `InternalError` (500):
  the client retries and nothing is written. So a saved pre-refund JWS can never be redeemed after the refund, and a
  tombstone refuses it even within the 10 minutes and even while Apple's API is down;
- `revocationDate` present on either JWS -> event `Revoke {revocation_date: that date}`;
- environment (E4): `Sandbox` is credited only for accounts on `prot_store_test_user_ids`, within
  `prot_store_test_max_prot`, on every deployment (section 6.4). A deployment whose own `[api.appstore]
  environment` is `"Sandbox"` (a test stack) refuses Production transactions with `ProtStoreVerifyFailed` (logged
  `PROT_STORE_ENV_MISMATCH`, R23);
- the storefront is recorded; a purchase from a storefront the web blocks (E1) is credited anyway, because the money
  is taken and Apple gives developers no refund path, and logged `PROT_STORE_BLOCKED_STOREFRONT`.

### 6.2 Google Play

The client posts `{product_id, purchase_token}`. The server ALWAYS reads the purchase live from the Android Publisher
API (`purchases.productsv2.getproductpurchasev2`), with a service-account OAuth token (an RS256 JWT-bearer grant
signed with `jsonwebtoken`, cached until 5 minutes before it expires). Because the answer is live, a voided purchase
is never credited.

- Lookup errors: `NotFound` (for example a forged token) -> `ProtStoreVerifyFailed`, no row; `Transient` or
  `Rejected` -> `InternalError` (500, the app retries); `NotConfigured` -> `ProtStoreUnavailable`.
- `purchaseState` `PENDING` -> answer `pending`, no row (a slow card or Family Link approval; the RTDN PURCHASED
  or the next launch finishes it). `CANCELLED` -> event `Revoke {revocation_date: now}` (a tombstone if there is no
  row; no void time is known yet).
- Not exactly one `productLineItem`, or its `productId` != the posted `product_id` -> `ProtStoreVerifyFailed`.
- Binding: `obfuscatedExternalAccountId` = an issued intent's token. productsv2 has no `purchaseType` (R10): a test
  purchase is one with `testPurchaseContext`, and a promo or rewarded purchase (no token, or a token that is not an
  issued intent) is `Rejected{Unbound}`.
- Quantity from `productOfferDetails.quantity` (absent = 1); `regionCode` recorded; `consumptionState` is not a
  reason to refuse (the ledger key decides whether it was credited).
- **Consume after the credit, by the server.** After the credit commits, the engine calls the consume endpoint and
  then `mark_prot_store_consumed`. The verify answer does not wait for the consume. A failure is logged
  `PROT_STORE_CONSUME_FAILED` and crond retries every 10 minutes; Play's 3-day auto-refund is the deadline, with a
  staff alert at 24 h. Until the consume succeeds the Prot stays held (section 4.5).

### 6.3 Binding and the caller check

1. The token (Apple `appAccountToken` lowercased, Play `obfuscatedExternalAccountId`) is looked up as an intent, in
   any state. No intent, an intent for another store or product, or an intent `Used` by another purchase ->
   `Reject(Unbound)` (E10). An intent whose user was unlinked by deletion -> `Reject(NoBuyer)`.
2. **The caller check runs before any write,** reading the row first:
   - a `Revoked` row -> `{status: rejected, reason: refunded}`, before any caller comparison;
   - a row whose `user_id` is set and is not the caller -> `wrong_account`;
   - no row, and the resolved intent's user is not the caller -> `wrong_account`.

   `wrong_account` answers `{status: rejected, reason: wrong_account}` and writes nothing. This is what stops someone
   redeeming another user's signed transaction or purchase token. The app keeps the transaction unfinished; the
   caller-less paths (Apple ONE_TIME_CHARGE, Play RTDN) later credit the intent's user (R11). For Play, delta also
   logs `PROT_STORE_ALERT kind=wrong_account_play id=play:{sha256}` once per purchase per process (no mail).

### 6.4 Environment, product, pause

- **Sandbox (E4), on every deployment, production and test stacks alike:** allowed iff the user is on
  `prot_store_test_user_ids` AND `sum_sandbox_prot_store(user) + prot <= prot_store_test_max_prot` (25,000). The sum
  counts the user's Sandbox rows in `Credited`, `Reinstated` or `Held`. Otherwise `Reject(TestPurchase)`. Sandbox Prot
  credited on prod is real Prot in the ledger; that is why it is capped. The cap is read outside the move's
  transaction, so two racing purchases can overshoot it by one pack (an accepted residual, R25).
- **Product:** not in the table -> `Reject(UnknownProduct)` with prot 0; else `prot = product.prot x quantity`
  (quantity 0 or an overflow -> `Reject(BadPayload)`).
- **Pause:** `prot_store_credit_paused` -> verdict `Hold`, else `Credit`.

### 6.5 Verify answers

| Planner answer | HTTP 200 body |
|---|---|
| Credited / AlreadyCredited | `{status: credited / already_credited, purchase_id, balance, ledger_id}` (`ledger_id` read from `purchase:{id}`; absent for AlreadyCredited is InternalError) |
| Held, or Play PENDING | `{status: pending}` |
| Rejected(TestPurchase / Unbound / UnknownProduct / NoBuyer) | `{status: rejected, reason: test / unbound / unknown_product / no_buyer}` |
| Refunded / Revoked | `{status: rejected, reason: refunded}` |
| caller check failed | `{status: rejected, reason: wrong_account}` |
| Rejected(BadPayload), bad JWS, wrong bundle, Play `NotFound` or a product mismatch | `ProtStoreVerifyFailed` (400) |
| Apple lookup failure on a `Revoked` row | `{status: rejected, reason: refunded}` |
| Apple lookup failure on any other row (or none), Play `Transient` / `Rejected` | `InternalError` (500; nothing written, the app retries) |

`wrong_account` and `test` are answers, not errors (R11): there is no `ProtStoreWrongAccount` or
`ProtStoreTestPurchase` error.

## 7. Notifications and reconcile

### 7.1 Apple: `POST /payments/apple/notifications`

Public and unauthenticated, `#[openapi(skip)]`, the raw body (at most 64 KiB) verified exactly as received, never
re-serialized (the S5 Stripe webhook pattern). Body `{"signedPayload": "<JWS>"}`, verified with section 6.1.

| Outcome | HTTP | When |
|---|---|---|
| Handled / Ignored | 200 | processed, or not for us (`data.bundleId` mismatch, or `data.appAppleId` present and not ours), or a type we do not act on |
| BadSignature | 400 | the JWS fails, or the body is oversize or unreadable |
| Retry | 500 | a database or API failure, or a config failure: Apple retries |

| `notificationType` | Action |
|---|---|
| `ONE_TIME_CHARGE` | binding, environment, product and pause with no caller (covers an app killed before verify); a history replay forces the freshness lookup |
| `REFUND`, `REFUND_REVERSED` | ALWAYS a fresh Get Transaction Info, then act on the CURRENT state, never on the type: it shows a `revocationDate` -> `Revoke {revocation_date: that date, reason: revocationReason as a decimal string}`; it shows none -> `Reverse` (E6). A lookup failure -> Retry, nothing written |
| `REFUND_DECLINED`, `CONSUMPTION_REQUEST` (E7: not answered), `TEST`, anything else | Ignored |

`data.signedTransactionInfo` always goes through the same `apple_transaction_checks` as verify (bundle, type, Xcode,
`revocationDate`, freshness). Acting on the current state plus the per-generation `revocation_date` makes every
replay harmless: a REFUND replayed after its reversal finds no `revocationDate` and becomes a `Reverse` on a
`Reinstated` row (Ignored); a REFUND replayed while the refund stands carries a date already recorded (no move). A
Sandbox notification follows the E4 rules for its row. Bucket `payments_apple_webhook` (60 per window, keyed by the
sender's address, like `payments_webhook`).

### 7.2 Play: RTDN over Pub/Sub, pulled by crond

There is no public endpoint: crond pulls the subscription (so there is no OIDC verifier to write and no API quota to
abuse). Each message's data is base64 JSON; a `packageName` mismatch is acked and logged. Every message is a hint
only: the handler re-reads the purchase from the API before acting.

| Message | Action |
|---|---|
| `voidedPurchaseNotification` (productType 2, one-time) | `Revoke {revocation_date: the message's eventTimeMillis}` (row or tombstone). Any void, full or quantity-partial, claws the whole purchase. Play has no reversal, so a second void of a `Revoked` row is a no-op |
| `oneTimeProductNotification` type 1 PURCHASED | binding, environment, product, pause and consume with no caller |
| `oneTimeProductNotification` type 2 CANCELED | nothing (a pending purchase the user cancelled) |
| `testNotification` | nothing |
| `pendingRefundReviewNotification` (if present) | needs_action `chargeback_review` + alert; not answered at launch |

A message is acked only after its handler commits; an error leaves it unacked, so Pub/Sub redelivers it.

**Play sales require RTDN.** RTDN is the only path that credits a Play purchase whose verify never arrived (the app
died, or the user signed in to another account). So a Play intent is refused with `ProtStoreUnavailable` unless a
Pub/Sub subscription is configured, and the advert's `play_open` is false without one.

### 7.3 Disputes

S5 refuses new web checkouts while a Stripe dispute is open, and the store intent applies the same predicate to the
user's Stripe orders. The stores give no "dispute opened" signal, so store purchases have no dispute state: a store
refund or void is final and acts at once.

### 7.4 crond `prot_store_reconcile`

Every 10 minutes while store credentials are configured. It is NOT gated on the open flags, because refunds and
consumes must settle after a store closes. With neither store configured, a tick logs at debug level and returns
without touching the database.

1. **Play RTDN** (if a subscription is configured): pull 100, handle each, acknowledge the handled ones once at the
   end.
2. **Play consume retries:** up to 100 rows with `unconsumed: true`, oldest credited first -> consume ->
   `mark_prot_store_consumed` (which clears a `play_unconsumed_24h` work item). A consume answered `Rejected` or
   `NotFound` -> read the purchase: already CONSUMED -> mark it consumed; CANCELLED -> `Revoke {revocation_date: now}`
   (the row goes to `Revoked`, `unconsumed` unset); anything else -> next tick. A `Transient` failure simply retries
   next tick. A row credited more than 24 h ago and still unconsumed -> FIRST set the work item
   `play_unconsumed_24h`, THEN claim and send the alert.
3. **Play voids, daily:** when the `play-voided` cursor is older than 24 h, `voidedpurchases.list` from the cursor
   minus 1 h, all pages -> `Revoke {revocation_date: voidedTimeMillis}` per token (row or tombstone) -> cursor CAS to
   the largest `voidedTimeMillis`.
4. **Apple history, hourly:** when the `apple-history` cursor is older than 1 h, Get Notification History
   (Production; Sandbox only while `prot_store_test_user_ids` is non-empty) from the cursor minus 2 h to now, all
   pages -> each `signedPayload` through section 7.1 with the freshness lookup forced -> cursor CAS to now. The first
   run (no cursor) starts 3 days back.
5. **Unpause:** when `prot_store_credit_paused` is off, up to 100 `Held` rows per store, each with a FRESH store
   lookup first (Apple Get Transaction Info + `apple_transaction_checks`; Play the purchase read), the same as admin
   assign: revoked, voided or CANCELLED -> `Revoke`; not revoked -> `Unpause`; a lookup failure -> skip until the
   next tick. Play credits then consume.
6. **Expire intents:** up to 500 `Open` intents past `expires_at` -> `Expired`.
7. **Day-1 unbound alert:** a Play row with needs_action `unbound` created more than 24 h ago -> alert `unbound_play`
   (support must assign before Play's 3-day refund, E10).
8. **Purge stale intents:** up to 500 `Expired` intents with no `purchase_id` whose `expires_at` is more than 30 days
   ago are deleted.

Multiple replicas are safe without leader election: ledger keys, the row version CAS, the cursor CAS and the alert
claims each have exactly one winner.

## 8. Intents and the wallet cap

`POST /payments/prot/store/intent {store, product_id}` -> `{intent_id, token, prot, product_id, expires_at}`. Bucket
`payments` (3 per window). Gates, in this order, all before any write:

1. payments disabled -> `PaymentsDisabled`; Prot `enabled` false -> `ProtDisabled`; a bot -> `IsBot`;
2. the managed client for that store not configured -> `ProtStoreUnavailable` (503); for Play, also no Pub/Sub
   subscription configured (section 7.2) -> `ProtStoreUnavailable`;
3. the store is not offered to the caller (configured AND (its open flag OR the caller on the preview list, E3)) ->
   `ProtStoreClosed` (403);
4. the Cloudflare country is in `prot_blocked_countries` -> `ProtRegionUnavailable` (advisory: the real block is the
   store availability, E1);
5. any of the caller's Stripe orders in Creating, Pending, Paid or Fulfilled has an open dispute -> `ProtNotEligible`;
6. the product is not in the table -> `ProtStoreProductUnknown` (400);
7. the caller already has 3 open intents -> `PaymentPending`;
8. **the cap (R5):** `balance + uncredited Stripe + Held store rows + open intents + this pack > wallet_cap` ->
   `ProtWalletCap { max: wallet_cap }`.

Then the intent is inserted with a fresh token; a duplicate token re-generates once, then `InternalError`.

**Cancel.** `POST /payments/prot/store/intent/<intent_id>/cancel` (bucket `payments`; not gated on the flags or on
credentials): a bot -> `IsBot`; an id that is not a ULID, absent, or another user's -> `NotFound`; a `Used` intent ->
`InvalidOperation`; `Open -> Expired` or already `Expired` -> 204. The app calls it, best effort, after a cancelled or
failed sheet. A cancel never refuses money: an `Expired` intent still binds a purchase that arrives anyway. It only
frees the open-intent slot and the cap, so a user who abandons three sheets is not locked out for 24 h.

**Races (R25).** The cap and the open-intent count are read outside any transaction, so two racing requests of one
user can each pass once. The `payments` bucket bounds it, and the cap is a soft gate anyway (the E9 residual below).

**Why R5 differs from the plan.** The plan wrote `balance + held + ...`, but `held` (D17) is a PART of `balance`
(`/@me` clamps it to the balance), so adding it double-counts. "Uncredited Stripe" is the S5 checkout's figure: the
Prot of the user's Paid Prot orders whose `purchase:` row does not exist yet. "Held store rows" are rows in state
`Held` (credit paused). "Open intents" are the user's `Open` intents with `expires_at` > now. The web checkout's own
cap is not changed (no S5 edit), so it does not count open store intents (at most 3 x 11,000 = 33,000).

**Example.** `wallet_cap` = 100,000. User U has a balance of 75,500 (including 2,600 from a store purchase yesterday,
still held: it is counted once, inside the balance), a Paid Stripe p50 order not yet credited (5,300), one `Held` store
row (1,000, bought during a pause) and one open intent for p25 (2,600).

| Request | Open intents before | Sum | Result |
|---|---|---|---|
| p100 (11,000) | 1 (2,600) | 75,500 + 5,300 + 1,000 + 2,600 + 11,000 = 95,400 | issued |
| p25 (2,600) | 2 (13,600) | 75,500 + 5,300 + 1,000 + 13,600 + 2,600 = 98,000 | issued (the plan's formula, +2,600 held, gives 100,600 and would wrongly refuse) |
| had that been p50 (5,300) | 2 (13,600) | 75,500 + 5,300 + 1,000 + 13,600 + 5,300 = 100,700 | `ProtWalletCap { max: 100000 }` |
| anything, after the p25 | 3 | not computed | `PaymentPending` (gate 7 runs before the cap) |

Residual, stated in the Terms: the cap is checked only here. A late-approved purchase (Ask to Buy, an expired intent)
is still credited and can take the wallet past the cap.

## 9. Worked examples

Ledger rows are written `key | kind | debit -> credit | amount`. Store rows have actor `sys:store` unless noted. "t0"
is the purchase time; `H` = 3,600,000 ms. Every example starts from the stated balances and nothing else moves.

### 9.1 A normal purchase (Apple, p5)

U's wallet is 0. The App Store is open and configured.

1. **Intent.** The app posts `{store: "apple", product_id: "gg.sloga.prot.p5"}`. Gates pass; cap: 0 + 0 + 0 + 0 + 500
   = 500 <= 100,000. The server inserts intent I1: a ULID, token `3f9c2a64-8e1b-4c0f-9d47-5b6e1a2c7d80` (UUID v4,
   lowercase), prot 500, `created_at` 1,793,577,600,000, `expires_at` 1,793,664,000,000 (+ 86,400,000 ms).
2. **Sheet.** `ProtStore.purchase({product_id, account_token})` opens StoreKit with
   `appAccountToken = 3f9c2a64-...`. U pays $5.99; Sloga nets $5.09 at 15%.
3. **Verify.** The app posts `{store: "apple", signed_transaction}` for transaction 2000000812340001. The JWS
   verifies; bundle, type and environment (Production) pass; `signedDate` is 8 s old, so no lookup; no
   `revocationDate`. The token resolves to I1 (Open, apple, p5), whose user is the caller. Prot 500 x 1; not paused;
   verdict `Credit`. No row exists: plan `none x Seen(Credit) -> Credited`.
4. **The move, one transaction:** insert row `apple:prod:2000000812340001` (Credited, user U, intent I1, prot 500,
   quantity 1, Production, storefront `USA`, country `US`, `credited_at`, version 0); I1 Open -> Used with
   `purchase_id`; post
   `purchase:apple:prod:2000000812340001 | Purchase | sys:issued -> user:U | 500`. Wallet: 500.
5. `ProtBalanceUpdate` to U. Answer `{status: "credited", purchase_id, balance: 500, ledger_id}`.
6. **Finish.** `shouldFinish(credited)` is true, so the app calls `finish({transaction_id})`.
7. Apple's ONE_TIME_CHARGE arrives seconds later: the same path with no caller -> `Credited x Seen(Credit)` ->
   AlreadyCredited (the ledger key exists) -> 200, nothing written.

`/@me` shows `held` 500 until t0 + 72 H.

### 9.2 Refund, reversal, refund, with spending in between (Apple, p25)

`{id}` = `apple:prod:2000000812345678`. P1 and P2 are S5b pledge ULIDs (26 characters) in goal G; T is a tank. U's
wallet is 0 at the start; `contribute_hold_hours` = 72. D5 and D12 are the `revocationDate`s Apple reports for the two
refunds. "Held" is U's `/@me` `held` right after the row (section 4.5).

| Day | Event | Ledger row(s) | Wallet U | Held | hold:G | Tank T | Row |
|---|---|---|---|---|---|---|---|
| 0 | verify credits p25 | `purchase:{id} \| Purchase \| sys:issued -> user:U \| 2,600` | 2,600 | 2,600 | 0 | 0 | Credited, gen 0 |
| 4 | U contributes 1,000 (the day-0 credit left the window on day 3) | S5b `contrib:` row, user:U -> tank:T, 1,000 | 1,600 | 0 | 0 | 1,000 | |
| 4 | U pledges 400 (P1) | S5b `pledge:` row, user:U -> hold:G, 400 | 1,200 | 0 | 400 | 1,000 | |
| 5 | Apple REFUND; the fresh lookup shows D5; gen 1, total_1 = 2,600 - 0 + 0 = 2,600 | `clawback:{id} \| Clawback \| user:U -> sys:clawed \| UpTo(2,600) -> 1,200` | 0 | 0 | 400 | 1,000 | |
| | drain, newest pledge first | `clawback-hold:{id}:P1 \| ClawbackHold \| hold:G -> sys:clawed \| 400` (actor sys:payments) | 0 | 0 | 0 | 1,000 | Revoked, gen 1, refunds[0] = {gen 1, revocation_date D5, clawed 1,600, shortfall 1,000} |
| 7 | Apple REFUND_REVERSED; the fresh lookup shows no `revocationDate` -> `Reverse`, U live, reinstate_amount = 1,200 + 400 = 1,600 | `reinstate:{id}:1 \| Purchase \| sys:issued -> user:U \| 1,600` | 1,600 | 1,600 | 0 | 1,000 | Reinstated |
| 8 | U tries to contribute 500 | refused, `ProtHeldPurchase` (held 1,600 of 1,600) | 1,600 | 1,600 | 0 | 1,000 | |
| 11 | U contributes 800 (the reinstate left the window on day 10) | S5b `contrib:` row, 800 | 800 | 0 | 0 | 1,800 | |
| 11 | U pledges 200 (P2) | S5b `pledge:` row, 200 | 600 | 0 | 200 | 1,800 | |
| 12 | Apple REFUND; the fresh lookup shows D12 (a new date); gen 2, total_2 = 2,600 - 1,600 + 1,600 = 2,600 | `clawback:{id}:r2 \| Clawback \| user:U -> sys:clawed \| UpTo(2,600) -> 600` | 0 | 0 | 200 | 1,800 | |
| | drain | `clawback-hold:{id}:r2:P2 \| ClawbackHold \| hold:G -> sys:clawed \| 200` (actor sys:payments) | 0 | 0 | 0 | 1,800 | Revoked, gen 2, refunds[1] = {gen 2, revocation_date D12, clawed 800, shortfall 1,800} |

Checks:
- Generation 1 asked for 2,600 and took 1,200 + 400 = 1,600; the 1,000 in the tank is spent, so the shortfall is 1,000.
- The reversal re-credits exactly what generation 1 took (1,600, E6), not the shortfall. The pledge is not restored:
  the 400 comes back to the wallet.
- **The reinstate is held (N1).** On days 7 to 10 the only `Purchase` row of `{id}` inside the window is
  `reinstate:{id}:1` (day 7), so `first_held` = day 7. The gen-1 `clawback:{id}` row is from day 5, before
  `first_held`, so it is not subtracted: held = min(1,600, 1,600) = 1,600, and the day-8 contribution is refused.
  Without the N1 rule, S5b's fold would net the reinstate against the generation's own day-5 clawback and show less
  than 1,600 held (0 in the contracts' own test, where the clawback took everything), so U could have put
  just-reinstated Prot straight into a tank.
- **Replays are no-ops.** A history replay of the day-5 REFUND notification during days 5 to 7: the lookup shows D5,
  already in `refunds[0]`, so no move. The same replay during days 7 to 12: the lookup shows no `revocationDate`, so
  it is a `Reverse` on a `Reinstated` row (Ignored). After day 12: the lookup shows D12, already in `refunds[1]`.
- Generation 2 again asks for the whole purchase (2,600): what generation 1 took was given back. It takes 600 + 200
  = 800; the shortfall 1,800 is everything in the tank.
- Generations parse back from the keys: `clawback:{id}` and `clawback-hold:{id}:P1` are generation 1;
  `clawback:{id}:r2` and `clawback-hold:{id}:r2:P2` are generation 2. A reversal of generation 2 would post
  `reinstate:{id}:2`, Exact(800), held again for 72 h.
- Conservation. Wallet U: 2,600 - 1,000 - 400 - 1,200 + 1,600 - 800 - 200 - 600 = 0. hold:G: 400 - 400 + 200 - 200
  = 0. Issued 2,600 + 1,600 = 4,200 = clawed (1,200 + 400 + 600 + 200 = 2,400) + tank (1,800). Total clawed 2,400 =
  1,600 + 800.

### 9.3 Refund before credit: the tombstone (Apple, p10)

1. t0: U buys p10 (transaction 2000000812349999, token of intent I2). The app is killed before it can verify, and
   Apple's ONE_TIME_CHARGE delivery gets a 500 (a database failover), so Apple will retry later.
2. t0 + 2 H: Apple refunds U and sends REFUND. The fresh Get Transaction Info shows `revocationDate` R2; there is no
   row; the token resolves to I2 (Open), whose user is U. Plan `none x Revoke` -> insert row
   `apple:prod:2000000812349999`, `Revoked`, user U, refund_gen 0, `refunds[0]` = {gen 0, revocation_date R2, clawed 0,
   shortfall 0}, **no ledger row**. This is the row's first write and the token resolved, so I2 becomes `Used`.
3. Apple retries ONE_TIME_CHARGE: its `signedDate` is 2 h old, so the freshness lookup runs and shows R2. The event is
   `Revoke {R2}`, a date already recorded: no move, 200. (A history replay forces the lookup too.)
4. U relaunches. The recovery worker posts the saved JWS. Verify runs the freshness lookup, then reads the row:
   `Revoked` -> `{status: rejected, reason: refunded}` -> the app finishes the transaction. If the API were down, the
   failed lookup makes verify read the row first: still `Revoked`, still `refunded`, nothing written. A JWS fresh
   enough to skip the lookup also meets the `Revoked` row: the tombstone alone refuses it.

Ledger: nothing. Wallet unchanged. If Apple later reverses this refund (the lookup shows no `revocationDate`), the
buyer has paid and holds nothing: `Reverse` on a tombstone keeps the row `Revoked`, `unreinstated_reversals` = 1,
needs_action `reversed_unpaid`, alert `reversed_unpaid`. Support credits by the existing admin adjust and then
resolves the work item (`POST /admin/prot/store/:id/resolve {kind: "reversed_unpaid"}`) (owner question Q1).

### 9.4 A Play consume that keeps failing, held past 72 h (Play, p50)

U's wallet is 700 (an old web purchase, long out of its hold). Google's consume endpoint keeps answering 5xx for this
token (`Transient`, so crond only retries and never re-reads the purchase), and the void's RTDN message never
arrives (RTDN is a hint; the daily list is the backstop).

| Time | Event | Wallet | `/@me` held | Contribute allowed |
|---|---|---|---|---|
| t0 | verify credits `purchase:play:{h} \| Purchase \| sys:issued -> user:U \| 5,300`; row Credited, `unconsumed: true`, `credited_at` t0; consume fails (Google 5xx) -> `PROT_STORE_CONSUME_FAILED` | 6,000 | 5,300 (ledger fold) | 700 |
| t0 + 10 min ... | crond retries every 10 minutes; each fails | 6,000 | 5,300 | 700 |
| t0 + 24 H | crond: credited > 24 h ago, still unconsumed -> work item `play_unconsumed_24h`, then claim + `PROT_STORE_ALERT kind=play_unconsumed_24h id=play:{h}` + mail | 6,000 | 5,300 | 700 |
| t0 + 73 H | Play has auto-refunded the unconsumed purchase (3 days). The ledger fold no longer counts the credit; the unconsumed term does (credited before now - 72 H) | 6,000 | 0 + 5,300 = 5,300 | 700 |
| t0 + 90 H | crond's daily `voidedpurchases.list` finds the void -> `Credited x Revoke {voidedTimeMillis}`, U live -> gen 1, total 5,300: `clawback:play:{h} \| Clawback \| user:U -> sys:clawed \| UpTo(5,300) -> 5,300`; the row is `Revoked`, `unconsumed` unset, work item `play_unconsumed_24h` cleared | 700 | 0 | 700 |

The refund takes back all 5,300 with a shortfall of 0, because the Prot could not leave the wallet. Without the
unconsumed term, U could have put 6,000 into a tank at t0 + 73 H. The clawback would then have found 0 (shortfall
5,300), although Google had already returned the money. Once the row is `Revoked` it leaves the consume queue. Had a
consume succeeded, say at t0 + 30 H, `mark_prot_store_consumed` would unset `unconsumed` and clear the work item, and
the normal hold would end at t0 + 72 H. Had the consume been answered `Rejected` after the refund instead of 5xx,
crond would have read the purchase, seen CANCELLED and revoked it on the next tick.

### 9.5 An unbound purchase assigned by support (Play, p10)

A faulty app build re-used the token of intent I3 (already `Used` by U's earlier purchase `play:{h1}`) for a second
p10 purchase, token hash `{h2}`. U's wallet is 1,000 (the first purchase, now out of its hold).

1. t0: the app verifies. The token resolves to I3, `Used` by another purchase -> `Reject(Unbound)`. A reject for
   `Unbound` never touches the intent, so I3 keeps its `purchase_id`. Row `play:{h2}` is inserted:
   `Rejected{Unbound}`, user U (the intent resolved), prot 1,000, needs_action `unbound`. Answer `{status: rejected, reason: unbound}`; the app keeps the purchase and shows
   "This purchase needs our help." Nothing is credited and nothing is consumed, so Play will refund it after 3 days.
2. t0 + 24 H: crond step 7 -> `PROT_STORE_ALERT kind=unbound_play id=play:{h2}` + mail.
3. Support opens `GET /admin/prot/store?needs_action=true`, then `GET /admin/prot/store/play:{h2}` (the row, no ledger
   rows, U's unspent 1,000).
4. t0 + 30 H: admin A posts `POST /admin/prot/store/play:{h2}/assign {user_id: U}` with A's own MFA ticket and an
   `X-Audit-Log-Reason`. U exists, is not deleted, is not a bot and is not A (A assigning to A's own account is
   refused, owner Q4). The engine reads the purchase live: PURCHASED, not voided -> `Assign {U, A, paused: false}` ->
   plan `Rejected(Unbound) -> Credited`: `purchase:play:{h2} | Purchase | sys:issued -> user:U | 1,000`; the row
   gets `assigned_by` A, the `unbound` work item cleared, `unconsumed: true`, `credited_at` t0 + 30 H. The audit line
   is `AUDIT prot_store_assign`, with actor, id, target and reason. Wallet: 2,000.
5. The engine consumes it after the credit commits (crond retries if that fails). On the next launch the app
   verifies again. The token still resolves to I3, `Used` by another purchase, so the verdict is `Reject(Unbound)`
   again, but any `Seen` on a `Credited` row is AlreadyCredited: the answer is `already_credited` and the purchase is
   done.

The assigned 1,000 is held until t0 + 30 H + 72 H, counted from the ledger row. Had the credit pause been on, the
assign would have recorded `Held` (R16). Had the fresh lookup shown a void, the assign would have answered
`InvalidOperation` and the row would have been revoked. On iOS the same row would wait without a deadline: an
unfinished transaction is re-delivered at every launch.

### 9.6 Sandbox purchases on production (E4)

Production runs `[api.appstore] environment = "Production"` and `prot_store_test_max_prot` = 25,000. Review account R
is on `prot_store_test_user_ids` and `prot_store_preview_user_ids`; the stores are closed.

- **R, allow-listed.** R's earlier sandbox purchases total 23,400 (nine p25 rows in `Credited`). R gets an intent (the
  preview list opens the store to R) and buys p25 in the sandbox: transaction environment `Sandbox`, id
  `apple:sandbox:2000000990000010`. 23,400 + 2,600 = 26,000 > 25,000 -> `Reject(TestPurchase)` -> `{status: rejected,
  reason: test}` -> the app finishes the transaction (no money involved). R then buys p5: 23,400 + 500 = 23,900 <=
  25,000 -> `Credited`, `purchase:apple:sandbox:2000000990000011 | Purchase | sys:issued -> user:R | 500`. A sandbox
  refund later moves a row to `Revoked`, which takes it out of the sum.
- **N, not listed.** After launch the App Store is open; N, a TestFlight user, buys p10. TestFlight purchases are
  Sandbox. N's intent was issued normally, the binding and the caller check pass, and the environment step refuses:
  row `apple:sandbox:...` `Rejected{TestPurchase}`, no ledger row, answer `rejected/test`, and the app finishes. On
  Play, a license tester's purchase carries `testPurchaseContext`: the same rejection; it is not consumed, Play voids it
  after 3 days (the pack shows "already owned" on that tester account until then), and the void turns the row into a
  `Revoked` tombstone.

A rejected row never re-opens: putting N on the list later does not credit the old row.

## 10. Routes, errors, buckets

| Route | Bucket | Notes |
|---|---|---|
| `POST /payments/prot/store/intent` | `payments` (3) | section 8 |
| `POST /payments/prot/store/intent/<intent_id>/cancel` | `payments` | the caller's own intent, section 8 |
| `POST /payments/prot/store/verify` | `payments_store` (10) | the app replays every unfinished transaction at launch |
| `POST /payments/apple/notifications` | `payments_apple_webhook` (60, by address) | section 7.1 |
| `GET /payments/prot/@me` | `payments_me` (unchanged) | gains `store_preview` (omitted when false) |
| `GET /admin/prot/store/<id>` | `any` (20) | the row, its ledger rows, the buyer's unspent |
| `GET /admin/prot/store?needs_action=true` | `any` (20) | the work list; without `needs_action` (or false) -> `FailedValidation` |
| `POST /admin/prot/store/<id>/assign {user_id}` | `any` (20) | E10, section 13.3 |
| `POST /admin/prot/store/<id>/resolve {kind}` | `any` (20) | clears a `reversed_unpaid` or `chargeback_review` work item |

The rate-limit resolver names buckets by the third path segment, which is `store` for intent, cancel and verify, so
the verify arm also matches the fourth segment (`verify`); intent and cancel stay on the tight `payments` budget.
Routes load `PaymentsSettings`, `ProtSalesSettings` and `ProtStoreSettings`; an invalid config is `InternalError`
(nothing is sold or credited under a default).

**Admin guards,** in order, the S5 admin pattern: not privileged -> `NotPrivileged`; the MFA ticket is not the
caller's -> `InvalidToken`; no `X-Audit-Log-Reason` -> `FailedValidation`; an id that is not a store purchase id
(checked with `is_store_purchase_id`, never `is_plain_id`, which refuses `:`) -> `NotFound`. Each route writes one
`AUDIT prot_store_<read|list|assign|resolve>` log line with the actor, the id and the reason (assign adds the target).
They are not gated on the Prot or store flags, so support works while sales are closed.

New errors, appended to `ErrorType` after `ProtRegionUnavailable`: `ProtStoreClosed` (403), `ProtStoreProductUnknown`
(400), `ProtStoreVerifyFailed` (400), `ProtStoreUnavailable` (503). Reused: `ProtWalletCap`, `ProtDisabled`,
`PaymentsDisabled`, `ProtNotEligible`, `ProtRegionUnavailable`, `PaymentPending` (too many open intents, R19), `IsBot`,
`NotPrivileged`, `InvalidToken`, `NotFound`, `InvalidOperation`, `FailedValidation`, `InternalError`.

Root advert (`features.prot.store`, memoized): `{apple_open, play_open, products: [{store, product_id, prot}],
us_web_link}`. `apple_open` is the flag AND App Store credentials in config; `play_open` is the flag AND Play
credentials AND a Pub/Sub subscription. A valid config lists every product whether or not a store is open (preview
accounts need them; product ids are not secret); an invalid one advertises everything closed and no products.
Per-user preview access is never in the public advert; it is `/@me` `store_preview`. `us_web_link` is advertised,
but no S6 client reads it (section 11).

## 11. Config and flags

Everything defaults dark. A flip needs a restart of delta AND crond (config is frozen per process).

`[features.payments]` (nothing secret):

| Key | Default | Gates |
|---|---|---|
| `prot_store_apple_open` | false | NEW App Store intents (verify and refunds never read it) |
| `prot_store_play_open` | false | NEW Play intents |
| `prot_store_credit_paused` | false | E9 emergency switch: verified purchases are recorded `Held`; crond credits them when it is off |
| `prot_store_products` | the 10 rows (5 products x 2 stores) of section 2.2 | product id -> Prot per unit |
| `prot_store_preview_user_ids` | [] | E3: accounts that see packs and are credited while a store is closed |
| `prot_store_test_user_ids` | [] | E4: accounts whose sandbox / test purchases are credited |
| `prot_store_test_max_prot` | 25000 | E4 cap of sandbox Prot per account |
| `prot_store_us_web_link` | false | E8: the US iPhone app may link to web checkout (off at launch). S6 ships the flag and the advert field ONLY: no client button or link code exists, because dormant external-purchase code in the iOS binary is a review risk (owner Q5, interim option b) |
| `ops_alert_email` | "" | staff alert mailbox; empty = log only |

`[api.appstore]`: `issuer_id`, `key_id`, `private_key` (the In-App Purchase key, PEM), `bundle_id` (`gg.sloga.app`),
`app_apple_id` (6809989506, from the plan; not yet confirmed in code), `environment` (`"Production"`, the deployment's
own; the API host is chosen per transaction), `root_ca_g3_sha256` (the pinned root). `[api.googleplay]`:
`package_name` (`gg.sloga.app`), `client_email`, `private_key` (service-account RSA PEM), `token_uri`
(`https://oauth2.googleapis.com/token`), `pubsub_subscription` (`projects/{p}/subscriptions/{s}`; empty = RTDN not
pulled).

- Secrets live only in deployment overrides (`Revolt.overrides.toml` on heart1, or `REVOLT__API__APPSTORE__...`
  environment variables). `Debug` is hand-written for both blocks and for `ProtStoreSettings`: a private key prints
  as `<redacted>` or `<unset>`. Never derive it.
- With no credentials: the advert says closed, intent and verify answer `ProtStoreUnavailable`, crond idles. Play
  credentials without `pubsub_subscription`: Play intents still answer `ProtStoreUnavailable` (section 7.2), while
  verify, consumes and the daily void list keep working.
- `ProtStoreSettings::from_parts` refuses (and the routes then refuse everything) a product with Prot outside
  1..=100,000, a bad or duplicate product id, an unknown store string, a bad user id in a list, a negative test cap,
  an alert address without `@`, an unknown environment, or a root hash that is not 64 hex characters.
- `Revolt.test.toml` turns both open flags on for tests, with no credentials: route tests use the managed mock
  clients.

## 12. Privacy

- **Random per-intent tokens.** Apple and Google receive a random token per purchase (UUID v4 / 32 random bytes),
  never the Sloga user id or anything derived from it, so the stores' records cannot be linked to a Sloga account
  without Sloga's database. A token is good for one purchase only.
- **Logs** name purchase ids (`apple:prod:...`, `play:{sha256}`), never raw purchase tokens, private keys, OAuth
  tokens or App Store JWTs.
- **Account deletion.** `unlink_account_payments` (inside the must-succeed cascade that runs before `user.delete`)
  calls `unlink_prot_store_user`: `user_id` is unset on every intent (Open ones become Expired) and every purchase of
  the user. The S5 wallet forfeit is unchanged. A later refund of an unlinked purchase resolves to "no buyer": the row
  moves to `Revoked` and records the generation, the clawback is skipped (`PROT_STORE_REFUND_NO_BUYER`; the forfeit
  already took the Prot) and a reversal re-credits nothing. A purchase seen after its intent was unlinked is
  `Rejected{NoBuyer}`. A move racing the deletion is caught by the version CAS (the unlink bumps `version`), by the
  intent CAS on `user_id`, and by the second-pass forfeit after every credit.
- **Unlinking is partial, by design (D20).** The unlink removes the user id from the store rows and intents only.
  The ledger keeps `user:{id}` with `ref.order_id` = the store purchase id for 7 years, like every S5 row, so a
  deleted account's store purchases stay linkable to its ledger history. The Privacy text must not claim full
  unlinkability.
- **Retention.** Store rows are kept 7 years with the store transaction ids, order ids and storefront country, for
  the books and for refunds. `Expired` intents that never bound a purchase are deleted 30 days after expiry (crond
  step 8); intents that bound one stay with it. The Privacy policy names Apple and Google as recipients of the random
  token and Google Cloud Pub/Sub as a processor (legal drafts, W5).
- **Store metadata.** Play Data safety and App Store App Privacy declare purchase history, collected, linked, for app
  functionality, not shared. No third-party purchase SDK (no RevenueCat).

## 13. Failure modes, alerts and the needs-action list

### 13.1 What happens when something fails

| Failure | Behavior | Owner / support sees |
|---|---|---|
| Apple API down during a freshness lookup | verify 500, the app keeps the transaction and retries with backoff; nothing written | client retry copy; nothing to do |
| Apple notification fails to process (DB, API, config) | 500, Apple retries; the hourly history replay backstops | log lines |
| Notification with a bad signature | 400, ignored | log line |
| Play consume keeps failing | retried every 10 minutes; a `Rejected` consume re-reads the purchase (CONSUMED -> marked, CANCELLED -> revoked); Prot stays held (section 4.5) | `play_unconsumed_24h` work item, then alert, at 24 h; cleared by the consume or a revoke |
| RTDN not configured | Play intents refused (`ProtStoreUnavailable`), the advert's `play_open` false; existing purchases still verify, consume and void through the daily list | log lines |
| RTDN pull failing | unacked messages are redelivered; purchases still credit through verify and the app's recovery worker; voids also arrive through the daily list | log lines |
| Store credentials missing or invalid | advert closed, routes `ProtStoreUnavailable` (503), crond idles; 401/403 from a store API logs `PROT_STORE_API_AUTH` | log lines |
| Store config invalid | routes `InternalError`, advert closed, crond logs `PROT_STORE_CONFIG_INVALID` and idles | log line |
| Credit paused (E9) | verify answers `pending`; rows `Held`; crond credits them when the switch is off. Held Play rows are not consumed, so a pause longer than about 3 days lets Play refund them (Q2) | the switch state |
| A product missing from the server table | `Rejected{UnknownProduct}`, not credited; iOS keeps it unfinished | support credits by admin adjust (Q3) |
| Signed in to the wrong account | `wrong_account`, nothing written, the app keeps the transaction; the ONE_TIME_CHARGE / RTDN credits the intent's user | user copy "Sign in to the account that bought this"; Play: `PROT_STORE_ALERT kind=wrong_account_play` log line, once per purchase per delta process |
| No valid token (E10) | `Rejected{Unbound}`, needs_action `unbound` | work item; `unbound_play` alert at 24 h for Play |
| Buyer deleted | `NoBuyer`, or the credit is forfeited by the second pass; a later refund records a `no_buyer` generation and posts nothing (`PROT_STORE_REFUND_NO_BUYER`) | log line |
| Refund of a purchase whose Prot is spent | the clawback takes what is unspent and records the shortfall | `GET /admin/prot/store/:id` |
| Refund replayed (history overlap, Apple retry) | no move: the current state and the recorded `revocation_date` decide | nothing |
| Generation arithmetic broken (`total_n` != `row.prot`) | `InternalError`, no move | `PROT_STORE_GENERATION_MISMATCH` log line |
| Reversal of a tombstone | stays `Revoked`, `reversed_unpaid`; a sandbox tombstone gets no work item; a replayed reversal is Ignored | work item + alert (Q1); sandbox: `PROT_STORE_SANDBOX_REVERSAL` log line |
| Abandoned sheets | the app cancels the intent; if that fails, it expires in 24 h | nothing |
| Play chargeback review | needs_action `chargeback_review` | work item + alert |
| Repeated verify failures from one user (> 20 in an hour) | each answered `ProtStoreVerifyFailed` | `PROT_STORE_ALERT kind=verify_failures id=user:{id}`, once per hour per user per delta replica, no mail (R15) |
| Mongo without a replica set | `ProtReplicaSetRequired` (S5) | log line |
| Alert mail fails | `PROT_STORE_ALERT_MAIL_FAILED`; the alert log line was written first | log line |

### 13.2 Alerts

`send_ops_alert` always logs `PROT_STORE_ALERT kind=<kind> id=<id>` at warn level, then, when `ops_alert_email` is set
and SMTP is configured, sends a plain-text mail (subject `Sloga store alert: <kind>`) from a blocking task. It never
panics; every failure returns false and is logged. A caller sets the row's work item first (where the kind has one),
then claims the kind on the row (`claim_prot_store_alert`); only the winner sends, so a row is alerted once per kind
across replicas, and a crash between the two still leaves the work item on the list.

| Alert kind | Raised by | Row work item |
|---|---|---|
| `play_unconsumed_24h` | crond step 2 | `play_unconsumed_24h` |
| `unbound_play` | crond step 7 | `unbound` (set at first sight) |
| `chargeback_review` | Play `pendingRefundReviewNotification` | `chargeback_review` |
| `reversed_unpaid` | an Apple reversal on a tombstone | `reversed_unpaid` |
| `wrong_account_play` | verify (log only, once per purchase per delta process) | none |
| `verify_failures` | the delta per-process counter (log only) | none |

### 13.3 The needs-action list

`GET /admin/prot/store?needs_action=true` lists rows with `needs_action` set, newest updated first (at most 100). A
row holds one kind at a time (a later set overwrites; the alert trail is `alerted` plus the log lines). Kinds, what
support does, and what clears each:

| `needs_action` | Meaning | Action | Cleared by |
|---|---|---|---|
| `unbound` | a purchase with no valid token | confirm the buyer, then assign (Play: before day 3) | the assign, or any move to `Revoked` |
| `play_unconsumed_24h` | a Play credit still unconsumed after 24 h | check the service account and the Play API; crond keeps retrying | the successful consume, or any move to `Revoked` |
| `chargeback_review` | Play chargeback review | nothing to answer at launch; watch for the void | `resolve` |
| `reversed_unpaid` | Apple reversed a refund we never credited | credit by `POST /admin/prot/adjust`, then `resolve` (Q1 interim) | `resolve` |

`GET /admin/prot/store/<id>` shows the row, every ledger row with `ref.order_id` = the id (oldest first) and the
buyer's current wallet balance.

**Assign** (`{user_id}`): the target must exist, not be deleted, not be a bot, and not be the acting admin
(self-assign is refused with `InvalidOperation`, owner Q4); else `NotFound` / `InvalidOperation`. Then a fresh store
lookup: `NotFound`, or the purchase shows revoked, voided or CANCELLED -> `InvalidOperation` (a revoked one is also
fed to the row as `Revoke`); `Transient` / `Rejected` -> `InternalError`; not configured -> `ProtStoreUnavailable`.
Then the planner: only `Rejected{Unbound}` moves, and `NotAssignable` -> `InvalidOperation`. It credits through the
same one-transaction move, and a Play credit is then consumed.

**Resolve** (`{kind}`): `kind` must be `reversed_unpaid` or `chargeback_review` AND equal the row's `needs_action`;
it clears that kind only (anything else -> `InvalidOperation`). No ledger effect.

## 14. Client flow and gating

### 14.1 The `ProtStore` plugin

One JS contract, two first-party plugins (Swift `ProtStorePlugin` in the local SPM package `ios/App/SlogaStore/`; Java
`ProtStorePlugin` in the Play flavor only). No npm or Cordova plugin (they would ship billing in every flavor and
bypass the iOS guard) and no third-party purchase service.

| Method | iOS | Play |
|---|---|---|
| `isAvailable()` | `AppStore.canMakePayments` | Play Billing available (the exact call is pinned by the Android lane) |
| `products({ids})` -> `[{id, displayPrice}]` | `Product.products(for:)` | `queryProductDetailsAsync(INAPP)` |
| `purchase({product_id, account_token})` | `purchase(options: [.appAccountToken(UUID)])`; an invalid UUID fails `invalid_token` without opening the sheet | `launchBillingFlow` with `setObfuscatedAccountId(account_token)` |
| `pendingTransactions()` | `Transaction.unfinished` | `queryPurchasesAsync(INAPP)`, PURCHASED only |
| `finish({transaction_id})` | `transaction.finish()`, only when asked | resolves `{finished: false}`; never consumes |
| `storefront()` | alpha-3 country code | alpha-2 country code (display only) |
| event `transactionUpdated` | `Transaction.updates` | `onPurchasesUpdated` |

Results: `purchased` (Apple: `transaction_id`, `product_id`, `signed_transaction`; Play: `product_id`,
`purchase_token`, `order_id?`), `pending`, `cancelled`, or `failed` with `not_available`, `product_not_found`,
`already_owned`, `invalid_token` or `store_error`. On iOS both verified and unverified StoreKit results return
`purchased` with the JWS: the SERVER verifies, the client never decides. The iOS plugin is registered behind
`MainFrameBridgeGuard`, like the E2EE plugin, so an embed frame can never open a store sheet. `ProtStoreNative` is
undefined on web, desktop, sideload and Google-free builds, and on older shells without the plugin.

### 14.2 The flow (`protStoreFlow.ts`, pure)

States: `idle`, `intent`, `sheet`, `pending`, `verifying`, `finishing` (iOS), `done`, `kept` (the purchase stays
unfinished; `why` is `wrong_account`, `unbound`, `unknown_product`, `no_buyer`, `pending` or `retry`),
`cancelling`, `failed`. The happy path is `idle -> intent -> sheet -> verifying -> finishing (iOS) | done (Play) ->
done`.

- **The only finish rule (`shouldFinish`):** finish after `credited`, `already_credited`, `rejected: test` or
  `rejected: refunded` (no money is owed either way, and finishing stops the replay at every launch). Never on an
  error, any 4xx included.
- A `pending` SHEET result never verifies (step `pending`); the purchase arrives later through `transactionUpdated`
  or the next launch.
- A verify answer `status: pending` (Play PENDING, or the credit pause) -> `kept` with `pending`: unfinished, no
  finish.
- `wrong_account`, `unbound`, `unknown_product`, `no_buyer` -> `kept` (unfinished, so the store re-delivers it).
- 5xx, network errors and 429 -> retried with backoff (1 s, 2 s, 4 s, ... capped at 60 s; a 429 waits at least
  10 s), at most 5 attempts, then `kept` with `retry`.
- Any other 4xx (for example `ProtStoreVerifyFailed`) -> `kept` with `retry` at once: no more attempts this launch,
  never a finish.
- A `cancelled` or `failed` sheet result -> `cancelling`: the flow calls the intent cancel route, best effort (a
  failure is ignored; the intent expires in 24 h anyway), then `idle`.
- **Recovery worker** (`ProtStoreWorker.tsx`, mounted beside `ApkUpdateWorker`, after login, store builds only): sets
  the store facts (advert, `/@me` `store_preview`, `isAvailable()`), drains `pendingTransactions()` and
  `transactionUpdated`, verifies each transaction at most once per app launch (keyed by `transaction_id` /
  `purchase_token`), and finishes per `shouldFinish`. Credits reach the wallet page through `ProtBalanceUpdate`.

User copy (EN): "Waiting for approval. Your Prot arrives when the purchase completes." · "Prot added to your wallet." ·
"Sign in to the account that bought this to receive the Prot." · "This purchase needs our help. Contact support and
we'll add the Prot to your account." · "This purchase was refunded, so no Prot was added." · "Test purchases aren't
credited on this server." · "We couldn't reach Sloga to confirm your purchase. It's safe, and we'll try again." On
iOS only (E2): "Protected channels open in Sloga for desktop and Android. On iPhone you can buy Prot and fund
channels."

### 14.3 Gating truth table

`protPurchaseChannel(channel, store, storePreview, pluginAvailable)`; `allowsProtSpendingFor` = not a store build, or
a channel other than `none`. 3.1.3(b) lets web-bought Prot be used in the app only if IAP is offered there too, so an
older store shell without the plugin can never spend.

| Channel | Advert | Preview | Plugin | Result | Spending |
|---|---|---|---|---|---|
| web / sideload / foss (desktop shells resolve to web) | any | any | any | `stripe` | yes |
| appstore | none | any | any | `none` | no |
| appstore | `apple_open` false | false | any | `none` | no |
| appstore | `apple_open` true | any | false | `none` | no |
| appstore | `apple_open` true | any | true | `appstore` | yes |
| appstore | `apple_open` false | true | true | `appstore` | yes |
| appstore | `apple_open` false | true | false | `none` | no |
| play | none | any | any | `none` | no |
| play | `play_open` false | false | any | `none` | no |
| play | `play_open` true | any | false | `none` | no |
| play | `play_open` true | any | true | `play` | yes |
| play | `play_open` false | true | true | `play` | yes |
| appstore with only `play_open`, play with only `apple_open` | | false | true | `none` | no |

With no advert at all the client fails closed, even for a preview account with the plugin (R26): no advert means
the server's store state is unknown. `allowsProtSpending()` stays zero-argument (the signature S5b's call sites use)
and reads a facts signal kept out of `distribution.ts` (R17); its default (no facts) is "no", so the existing store
pins stay true unchanged. The client parses the advert's `store` and `/@me` `store_preview` so that an older server
(neither key) reads as closed and not previewed. There is no web-link path in any S6 client (E8 interim, Q5).
`allowsDonationLinks` is unchanged: Ko-fi, Cipher, Supporter and the login promo stay hidden in store builds, and
Cipher stays web-only.

### 14.4 The store shop

`StoreShop` in `ProtSettings.tsx` is a separate section; the Stripe `Shop` is untouched. It shows only the server's
Prot amount and the store's `displayPrice`, hides packs the store did not return, and carries no web-flow text: no
`formatUsd`, no pay-exact, no "Every US cent buys 1 Prot", no Stripe or sloga.gg, no web-link button, and no
`<Status ` element (an existing test keys on the file's first `<Status `), all pinned by a source scan. The hold
note is the S5 one. Store ledger rows are kind `Purchase`, so the wallet history needs no new kind.

### 14.5 Native builds

- **Android:** `playImplementation 'com.android.billingclient:billing:9.1.0'` (Play requires billing >= 8 for new apps
  and updates since 2026-08-31), play flavor only. `com.android.billingclient` joins the Google-free ban list, and a
  new `verifySideloadClasspathBillingFree` task bans it from sideload. A versioned
  `android/scripts/verify-billing-flavors.sh` checks the SHIPPED artifacts (never `build/intermediates`): the play APK
  and AAB carry `com.android.vending.BILLING` and billing classes, sideload and foss carry neither; a missing artifact
  fails (never a vacuous pass). The Kotlin stdlib that billing 9.1.0 requests is checked against the forced 2.0.21
  before pinning; if it needs newer, the newest fitting 8.x is pinned instead.
- **iOS:** the `SlogaStore` package (Capacitor 8.4.3, iOS 15), tested with `SKTestSession` and a `Prot.storekit`
  file holding the five products. Registration needs the bridge view controller inside the SlogaE2ee package, so
  SlogaE2ee depends on SlogaStore (R18); that diff goes to the iOS E2EE owner for review.

## 15. Testing

### 15.1 Unit and driver tests (no device)

- **State machine (pure):** one test per row of the section 4.3 table; property tests: never `Credit` after
  `Revoked`, `Clawback {gen}` at most once per generation, and a replayed `Revoke` (same date) never moves
  (`replayed_refund_is_a_no_op`).
- **Both drivers** (`TEST_DB=REFERENCE` and `TEST_DB=MONGODB`; Mongo installs the real indexes):
  `store_move_credit_is_one_transaction` (crash injection between the ledger and the row write leaves neither),
  `refund_then_charge_never_credits`, `two_refund_generations_claw_twice`,
  `clawback_drains_held_pledges_for_a_store_row`, `reused_intent_is_conflict`, `concurrent_moves_credit_once` (20
  tasks, one row), `unconsumed_play_credit_stays_held_after_the_window`, `store_lock_order_never_deadlocks`
  (Reference), `unlink_keeps_rows_without_a_user`, `cursor_cas_has_one_winner`, `alert_claim_has_one_winner`,
  `unbound_row_on_a_used_intent_is_written`, `unlink_racing_a_move_stays_unlinked`, `reinstate_is_held_72h` (credit
  2,600 at T - 5 d, refund at T - 2 d claws 2,600, reversal at T reinstates 2,600 -> held 2,600; a gen-2 refund at
  T + 1 h -> held 0), `no_buyer_refund_records_a_generation`.
- **Apple verifier:** a forged-chain fixture set made with openssl by a committed `make-fixtures.sh` (test root,
  intermediate and leaf carrying the two OIDs) and its forgeries, each refused with its own error: wrong root,
  leaf-only and two-certificate `x5c`, missing intermediate OID, swapped OIDs, intermediate without `cA`, `alg: none`,
  `alg: HS256` signed with the leaf's public key bytes, an intermediate expired at `signedDate`, a tampered payload, a
  tampered signature; plus `valid_at_signed_date_expired_now_is_accepted` and
  `not_yet_valid_at_signed_date_is_refused`. The genuine Apple sandbox JWS test stays ignored until the first
  test-stack purchase captures one.
- **Engine** with the mock store clients: wrong account credits nothing; sandbox refused for a non-tester and capped
  for a tester; a config edit between retries keeps the stamped amount; a stale JWS after a refund is refused; Play is
  consumed only after the credit; refund -> reinstate -> refund claws twice; Unpause re-checks the store first;
  account deletion unlinks rows and a late refund takes nothing.
- **Routes, buckets, config, errors, migration:** the bucket split (verify `payments_store`; intent and cancel
  `payments`; notifications `payments_apple_webhook`; an 11th verify gets 429 while intent still answers); the
  notification signature is over the raw body; bots cannot verify; the advert is closed without credentials and lists
  the products; Debug never prints a key; the four error statuses; the migration guard and indexes. Admin: each guard
  refusal, a `:`-bearing id accepted, `foreign_ticket_admin_prot_store`, `assign_refuses_a_revoked_row`,
  `assign_refuses_self`, `assign_refuses_a_bot_or_deleted_target`, `resolve_clears_only_the_named_kind`.
- **Clients:** `protStoreFlow.test.ts` (finish only after credited / already / test / refunded; no finish on 5xx or
  on any 4xx; a verify answer `pending` keeps the transaction; a pending sheet never verifies; a cancelled sheet
  cancels the intent; recovery replay idempotent; wrong account keeps the transaction; backoff table);
  `distribution.store.test.ts` (every truth-table row); the advert and `/@me` parse pins; the StoreShop source scan;
  Swift `SKTestSession` tests; a JVM test of the Play result mapping.
- **Unchanged:** the S5a/S5b payments suite stays green with NO edits. The only sanctioned edits to existing tests
  are the latest-revision pin, two `ProtMe` literals gaining `store_preview: false`, one ticket-binding table row, and
  the root advert's whole-JSON test gaining the `store` object.

Every harness is shown to fail on a known-bad control pinned to a literal commit, for example: trust the `x5c` leaf
without the root pin; accept HS256; skip the account-token binding; accept Sandbox for anyone; re-derive Prot on
retry; skip the freshness lookup; consume before the credit; write the row outside the transaction; answer
`already_credited` from the row; let `clawback:{id}` short-circuit generation 2; accept a `Used` intent; drop the
unconsumed term; drop the N1 time rule from the fold; skip the fresh lookup before Unpause; allow self-assign; finish
on a 5xx; ship billing in foss or sideload.

### 15.2 Sandbox and test tracks

- **Apple:** a Sandbox tester; a TestFlight build pointed at a **test stack** (never prod for a first run) whose
  `[api.appstore] environment` is `"Sandbox"`; refunds from the sandbox account's purchase history and "Request a Test
  Notification"; Ask to Buy in Xcode's StoreKit testing. App Store Connect has ONE sandbox notification URL: it points
  at the test stack during test-stack runs, and at prod only for the production smoke and from the first IAP review
  onward (the owner switches it).
- **Play:** license testers; an internal-testing release of the play flavor; the test stack's own Pub/Sub
  subscription; test cards for success, decline and slow (pending); refunds from Play Console order management (voids
  arrive by RTDN and the daily list).
- The E4 rule has no exception for a Sandbox deployment: on the test stack too, sandbox and test purchases are
  credited only for accounts on `prot_store_test_user_ids`, within the cap, so the test stack lists its testers.

### 15.3 The production smoke (owner go)

With both stores still closed, the review and owner accounts on `prot_store_test_user_ids` and
`prot_store_preview_user_ids`: one sandbox purchase per store credits; a refund claws it back; a sandbox purchase by a
non-listed account is refused (`rejected: test`). Never run test purchases against prod outside the allow-list: they
would mint real Prot.

## 16. Rollout and land order

- **Migration:** its own top-level block `if revision <= 80` with `LATEST_REVISION = 81` (confirmed by the merge
  steward on 2026-11-01). It creates `prot_store_intents`, `prot_store_purchases` and `prot_store_cursors` and the
  indexes of section 3.4 through the shared `PROT_STORE_COLLECTIONS` / `create_prot_store_indexes` (also called from
  `init.rs`), and panics on failure: the unique token index is what makes a token one-time. Every step is idempotent,
  so the next boot re-runs the whole block. A database at 77..=80 runs only the blocks it has not run. S6 adds no
  `prot_ledger` index.
- **Land order:** S2 (`<= 77` / 78) -> S5b (`<= 78` / 79) -> S4 (`<= 79` / 80) -> S6 (`<= 80` / 81). If S6 is ready
  before S4, the steward decides; S6 never renumbers itself. Queue file: "migration block <= 80 / LATEST 81, lands
  after S5b (and S4 if it lands first)", LIVE-PAYMENTS deploy, delta + crond together.
- Until it lands, this branch's binaries run only against throwaway databases: a stamp of 81 would make any lower
  block that has not landed yet never run.
- **S5b coupling:** S6 changes two S5b internals, the held fold (the N1 time rule, section 4.5) and the held-pledge
  drain helpers (a key base parameter, section 5.1). S5b is told about both before S6's W1, and S6's later lanes are
  cut from S5b's committed tips.
- **Deploy:** delta + crond together. No bonfire change (no new event). The new collections add no rollback floor, but
  once any store purchase is credited, a delta below S6 leaves Apple notifications and Play voids unprocessed (the
  reconcile catches up after the roll-forward, Play within its void window): never roll below S6 for longer than a
  day while store sales are open.
- **Ships dark:** both open flags and `us_web_link` false, empty preview and test lists, no credentials on heart1.
- **Each of these is a separate owner go:** any heart1 deploy; putting store credentials on heart1; any flag flip or
  preview/test list entry; publishing the Terms/Privacy changes; any App Store Connect, Play Console or Google Cloud
  change; any store submission; opening sales per store.
- **Store opening:** S5a + S6 deployed, S5b live (spending), S2 (non-admin tanks), the owner's business prerequisites
  done (agreements, tax and banking, small-business enrollment, Play merchant account and 15% tier, the Pub/Sub
  project, the products in both consoles with E1 availability, store metadata, accountant and attorney sign-off) and
  the review approved. **Play opens first (E2).** iOS opens once the open guideline 2.1 rejection is cleared and iOS
  shows tanks with top-up and contribute (the S5b UI), with the honest copy of section 14.2.
- **Public repo:** a later fix to any verification bypass is deployed before its branch is pushed.

## 17. Open items at W0

### 17.1 Owner questions and unconfirmed facts

Owner questions, with the interim behavior already designed in:

1. **Q1, refund reversed on a tombstone.** Interim: no automatic credit; work item `reversed_unpaid` + alert; support
   credits by admin adjust. Alternative: credit `row.prot` automatically.
2. **Q2, a credit pause longer than about 3 days refunds Play buyers** (Held Play rows are not consumed). Interim: the
   pause stays an emergency switch; the 24 h alert fires. Alternative: consume Held Play rows and credit later from the
   stamped row.
3. **Q3, unknown-product purchase with money taken.** Interim: not credited, iOS keeps it unfinished, support uses
   admin adjust. Alternative: allow assign from `Rejected{UnknownProduct}` with a staff-entered amount.
4. **Q4, staff self-assign.** Interim: refused (`InvalidOperation`). Alternative: allow it with the same MFA ticket and
   audit line.
5. **Q5, E8 US web link.** Interim (option b): the server flag and the advert field ship, both off, and S6 ships no
   client web-link code (dormant external-purchase code in the iOS binary is a guideline 2.3.1 risk); the client path
   is built when the owner turns the link on. Alternative (a): ship the client path dark behind the flag.

Not yet confirmed (owed by the implementing lanes): the Apple Root CA - G3 hash against a second copy; the curves and
digests of Apple's real chain and a genuine sandbox JWS; every Apple and Google field name and endpoint against the
live documentation; `app_apple_id`; billing 9.1.0's Kotlin stdlib and transitive modules and its Java API names; the
Android artifact tools on the build box; the price points in both consoles; the Mongo `$eq: true` partial index on
the local replica set.

### 17.2 Contract gaps

The 19 gaps this document raised in its first W0 draft are closed in the contracts' W0 audit fix record (17 fixed;
two merged into others): refund replays (section 4.3), the `use_intent` rule (3.2), the no-buyer generation and a
record for every generation (5.2), work-item keep/clear and the resolve route (13.3), `Revoked` unsetting
`unconsumed` (4.3), `Seen` on a credited row and `Held x Assign` (4.3), the admin routes (10, 13.3), Play requiring
RTDN (7.2), Play lookup errors (6.2), the flow's verify-pending and 4xx states (14.2), the intent purge (3.2), the
cancel route (8), E4 on every deployment and the unconsumed term at hold 0 (6.4, 4.5), and E8 (Q5).

The five items this document raised after that round are closed too, in the final W0 fixes: the
`unreinstated_reversals` comment and the R13 actor wording in the contracts; a failed Apple lookup on a `Revoked`
row answering `refunded` (section 6.1); sandbox tombstone reversals raising no work item (section 4.3); and the
unconsumed term at hold 0 in S5b's floors (section 4.5). No contract gaps are open at the end of W0.
