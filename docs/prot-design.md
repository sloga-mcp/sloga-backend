# Prot: design reference (slice S5)

Status: **S5a in progress** (wallet, Prot packs, Cipher founding Prot, clawback, account-deletion forfeit).
**S5b not started** (tanks, burns, expiry stages, crowdfunding goals, settlement); it is built only after the
Protected channels encryption backend (S1) has landed on `acutest`. Everything ships dark. Until S1 has landed,
this branch runs only against throwaway databases (its migration number depends on S1's, section 4.3).

This is the reference that lives with the code. It explains the money model and the invariants the code must
keep. Exact signatures live in the code; this document names the modules and the rules. Where this document and
the code or its tests disagree, treat it as a bug in one of them and fix it; do not quietly follow either.

Owner decisions are tagged D1 to D20 where they matter. Sections marked **S5b** describe planned behavior that is
NOT implemented yet; their exact names and formulas will be pinned before S5b starts.

## 1. Purpose and scope

Prot is the closed-loop coin that pays for Protected servers and channels (paid, end-to-end encrypted server text
channels).

- 1 Prot = 1 US cent. "Prot" is uncountable: "500 Prot", never "500 Prots".
- Spend-only: no cash-out and no user-to-user transfer. Prot moves into a channel's tank (or a crowdfunding goal)
  only where the user is a member (S5b).
- A protected channel burns 4 Prot per slot per day, a protected server 6, with tier discounts (section 10).

**S5a ships:**
- the double-entry ledger and user wallets (`prot_ledger`, `prot_accounts`);
- buying Prot through the existing Stripe integration (packs and pay-exact);
- Cipher founding Prot (D2), posted from the ledger instead of on paper;
- clawback of unspent Prot on refunds and lost disputes (D1);
- forfeiture of the wallet on account deletion (D11);
- `GET /payments/prot/@me`, the admin order read and admin adjust routes, the `ProtBalanceUpdate` event, and the
  wallet page in the client.

**Flags** (all default false in `Revolt.toml`; a flip needs a restart of delta AND crond, since config is frozen
per process):

| Key | Gates |
|---|---|
| `[features.boosts.protection] enabled` | every Prot read and write route (not the admin routes), and Cipher grants |
| `[features.boosts.protection] cipher_grants_enabled` | Cipher founding Prot (D2), together with `enabled` |
| `[features.payments] prot_sales_open` | NEW Prot checkouts only |
| `[features.boosts.protection] self_serve_enabled` | S5b: non-admin tanks and goals |
| `[features.boosts.protection] burn_enabled` | S5b: the clock job |
| `[features.boosts.protection] deletion_enabled` | S5b: the day-30 purge |

Settling money already taken never depends on `enabled` or `prot_sales_open`: a paid order is credited, a
reversal is clawed back and a deleted account is forfeited whatever the flags say. `Revolt.test.toml` turns on
`enabled` and `prot_sales_open` only; `cipher_grants_enabled` stays off in tests, so the existing Cipher tests
never post Prot.

The protection flags live in their own table, `[features.boosts.protection]` (`ProtectionFeatures`), so turning
Server Boosts on never turns Prot on. Tanks are not boost rows: boosts are user-owned units that leave with their
owner, while contributed Prot is spent and must never walk out with a member.

The server advertises its Prot state in the root config (`features.prot`: `enabled`, `self_serve_enabled`,
`sales_open`, `cipher_grants_enabled`, `packs`, `exact_min_cents`, `exact_max_cents`, `wallet_cap`). Clients key
off that, never a `VITE_CFG_*` flag. Store builds (Play, App Store) show the balance and history but never a
purchase link, until in-app purchase arrives in S6 (D5).

## 2. Money model

Code: `crates/core/database/src/models/prot/` (`model.rs` types and helpers, `ops.rs` the trait
`AbstractProtLedger`, `ops/mongodb.rs` and `ops/reference.rs` the drivers).

### 2.1 Ledger

Every Prot movement is one row of `prot_ledger` (`ProtLedgerEntry`): an append-only, double-entry record with a
unique idempotency `key`, a `kind` (`ProtEntryKind`), a `currency` (`ProtCurrency`, only `Prot` today; Ward can be
added later without a migration, D4), a `debit` and a `credit` account, an `amount`, an `actor`, a `ref`
(`ProtRef`), a `payload_hash`, an optional `reason`, and `created_at`.

- Append-only: the trait has inserts and reads, and no update or delete of a ledger row exists anywhere.
- `amount` is > 0. Only two kinds of posting may write a zero-amount row: an `UpTo` clawback (`Clawback`,
  `ClawbackHold`), so an empty wallet still records its shortfall and settles the membership to its target, and
  an `All` forfeit (`Forfeit`, `ForfeitHold`, `ForfeitTank`). Every other posting is `Exact` and > 0. `UpTo` rows
  also store `requested` and `shortfall` (= `requested - amount`).
- `ProtEntryKind` is complete for all of S5 (S5b kinds included), so the stored enum does not grow mid-slice.
- A posting (`ProtPosting`) is applied with `apply_prot_posting`, which writes the row and both balances in one
  transaction (section 4).

### 2.2 Accounts

| Account id | Document | Floor |
|---|---|---|
| `user:{user_id}` (the wallet) | `prot_accounts` | 0 |
| `hold:{goal_id}` (S5b, a goal's held pledges) | `prot_accounts` | 0 |
| `tank:{tank_id}` (S5b, a protected channel or server) | `prot_accounts` | `-(grace_days x daily_cost)` |
| `sys:issued`, `sys:burned`, `sys:clawed`, `sys:forfeited`, `sys:writeoff`, `sys:adjust` | none | none |

`ProtAccount` holds `balance` (the cached balance), `version` and `updated_at`. System sides have no document: a
single hot document would serialize every burn and every purchase. Their totals come from the ledger.

Account ids are built only through `prot_user_account`, `prot_tank_account` and `prot_hold_account`;
`is_prot_system_account` recognizes `sys:`. The system ids and actors are constants in `model.rs`
(`PROT_SYS_*`, `PROT_ACTOR_PAYMENTS`, `PROT_ACTOR_CIPHER`, `PROT_ACTOR_DELETION`).

### 2.3 Floors

- A user wallet and a hold never go below 0.
- A tank (S5b) may go down to `-(grace_days x daily_cost)`: borrowed grace. With the defaults (5 days, 40 Prot a
  day for 10 channel slots) the floor is -200.
- The floor is enforced in the same write that moves the balance (a conditional decrement), never by a separate
  read. A posting the floor refuses changes nothing.

### 2.4 Conservation

For every account with a document, the cached `balance` equals the sum of the ledger: Prot credited to it minus
Prot debited from it. System sides are ledger-only, so over all accounts (system sides included) the ledger sums
to exactly 0. Prot is never created or destroyed outside a ledger row: issuing it is a row from `sys:issued`,
burning it a row to `sys:burned`, and so on.

`version` is bumped on EVERY posting that names a non-system account, zero-amount postings included. The account
document is the serialization point between any two postings on one wallet.

### 2.5 "Unspent"

The Terms promise that refunds and chargebacks only take back Prot the buyer has not spent (D1). In this model:

- **Unspent** = the user's wallet balance, plus (S5b) the `remaining` of their pledges still Held in a goal.
- **Spent** = anything that has reached a tank. Prot in a tank is never taken back, by a clawback or by anything
  else that targets the buyer.

## 3. Idempotency

### 3.1 Keys

Every posting carries a key that names its target. The unique index `prot_ledger_key_unique` on `key` is what stops
a posting from being applied twice, including across crond replicas: a second writer hits the duplicate and stops.

| Entry | Key | Kind | Debit -> credit | Amount |
|---|---|---|---|---|
| Pack / pay-exact purchase | `purchase:{order_id}` | Purchase | sys:issued -> user | Exact(sku prot) |
| Cipher founding grant | `cipher-founding:{user_id}:{number}:{base_order_id}` | CipherFounding | sys:issued -> user | Exact(target - posted) |
| Cipher later grant | `cipher-upgrade:{user_id}:{number}:{base_order_id}:{seq}` | CipherUpgrade | sys:issued -> user | Exact(target - posted) |
| Contribution / top-up (S5b) | `contrib:{user_id}:{tank_id}:{client_nonce}` | Contribution | user -> tank | |
| Mid-day tier upgrade (S5b) | `tier:{tank_id}:{change_id}` | TierUpgrade | tank -> sys:burned | |
| Pledge hold (S5b) | `pledge:{user_id}:{goal_id}:{client_nonce}` | PledgeHold | user -> hold | |
| Pledge capture (S5b) | `pledge-capture:{pledge_id}` | PledgeCapture | hold -> tank | |
| Pledge return (S5b) | `pledge-return:{pledge_id}` | PledgeReturn | hold -> user | |
| Pledge withdrawal (S5b) | `pledge-withdraw:{pledge_id}` | PledgeWithdraw | hold -> user | |
| Unseated 7-day return (S5b) | `launch-return:{pledge_id}` | LaunchReturn | tank -> user | |
| Daily burn (S5b) | `burn:{tank_id}:{YYYY-MM-DD}` | Burn | tank -> sys:burned | |
| Settlement return (S5b) | `settle:{tank_id}:{user_id}` | Settlement | tank -> user | |
| Grace-debt write-off (S5b) | `writeoff:{tank_id}` | WriteOff | sys:writeoff -> tank | |
| Clawback, wallet part | `clawback:{order_id}` | Clawback | user -> sys:clawed | UpTo (section 7.2) |
| Clawback, pledge part (S5b) | `clawback-hold:{order_id}:{pledge_id}` | ClawbackHold | hold -> sys:clawed | UpTo |
| Account deletion | `forfeit:{user_id}:{n}` | Forfeit | user -> sys:forfeited | All |
| Account deletion, pledge (S5b) | `forfeit-hold:{pledge_id}` | ForfeitHold | hold -> sys:forfeited | |
| Abuse termination (S5b) | `forfeit-tank:{tank_id}` | ForfeitTank | tank -> sys:forfeited | |
| Admin adjust | `admin:{admin_id}:{nonce}` | AdminAdjust | sys:adjust <-> user | Exact |

- `base_order_id` = `CipherMembership.orders[0]`, the CipherNew order of that membership incarnation.
- `seq` = the number of CipherFounding + CipherUpgrade rows already written for that base, so the first later
  grant is `:1`.
- `n` in `forfeit:` = 1 + the number of Forfeit rows already debiting the wallet, counted inside the forfeit
  transaction.
- Key builders: `prot_key_purchase`, `prot_key_cipher_founding`, `prot_key_cipher_upgrade`, `prot_key_clawback`,
  `prot_key_forfeit`, `prot_key_admin` in `model.rs`. Do not format keys by hand.

### 3.2 Why every key names its target

A key that leaves out its target can collide with a different, legitimate posting and read as "already applied",
which silently loses Prot:

- Cipher numbers are claimed lowest-free first, so after a fully covered 14-day refund the same user can buy again
  and get the same number. The base order id in the Cipher keys keeps the new incarnation's grant distinct.
- A later Cipher grant uses a sequence (`:{seq}`), not the target tier or an order id. After a window downgrade and
  a re-upgrade to the same tier, the number and base order are kept; a tier-based key would hit the first
  upgrade's key with an identical payload and the second upgrade would never be credited. An order-based key could
  not serve the backfill sweep, which has no order.
- Client nonces (S5b) are scoped by user and tank or goal, so a reused nonce against another target is a new
  posting, not a replay.

### 3.3 Payload hash

`prot_payload_hash` is the SHA-256 (lowercase hex, 64 characters) of 13 lines joined with `\n`, no trailing
newline, absent values as the empty string:

```
prot-posting/v1
kind=<kind name>
currency=Prot
debit=<debit>
credit=<credit>
amount=<exact:N | upto:N | all>
ref.order_id=<..>
ref.tank_id=<..>
ref.goal_id=<..>
ref.pledge_id=<..>
ref.day=<..>
ref.membership_number=<decimal>
ref.membership_order_id=<..>
```

The key, actor, reason, `created_at` and floor are deliberately not hashed. The hash says what moves where and
why, so a retried request with the same content is "already applied" whatever its metadata. A test pins a fixed
posting to a literal hash; changing the format is a breaking change to every stored row.

### 3.4 Duplicate keys

When the insert hits an existing key, the transaction is aborted and the stored row is read by key OUTSIDE the
transaction:

- same `payload_hash` -> `ProtApplyOutcome::AlreadyApplied(stored)`: success, nothing written, the caller gets
  the stored row;
- different `payload_hash` -> `ProtIdempotencyConflict` (409).

One exception: inside the Cipher sync (section 6.2), a duplicate with a different payload means a racing sync
already posted from an older membership state, so the body is re-run, not refused.

## 4. Transactions and drivers

### 4.1 MongoDB

`prot/ops/mongodb.rs` carries its own transaction helper (the S5 ledger writes are the first committing
transactions in the codebase; the existing ones are read-only).

- Snapshot read concern, majority write concern; every read and write in the body uses the session.
- One posting = insert the ledger row, then the conditional decrement of the debit side
  (`balance >= debit_floor + amount`), then the upsert-increment of the credit side, then any state documents
  (Cipher membership version now; pledges, goals, tanks and entitlements in S5b), all in one transaction.
- Retries run the whole body again from a fresh session, within `PROT_TXN_BUDGET` (10 s) from the first attempt:
  - a body error labeled `TransientTransactionError` -> abort, retry the body;
  - a commit error labeled `UnknownTransactionCommitResult` -> retry the commit only; labeled
    `TransientTransactionError` -> retry the body;
  - a duplicate key on the ledger insert -> abort, then section 3.4 (never retried);
  - a business refusal (`InsufficientProt`, membership version moved) -> abort and return the error, or, for the
    "state moved" cases of the Cipher sync and clawback, re-run the body up to `PROT_STATE_RETRIES` (5) times;
  - a debit that matches nothing -> `InsufficientProt` for `Exact`; for `UpTo` and `All` the snapshot was stale,
    so the body is retried;
  - budget exhausted -> a database error.
- **Replica set required.** Transactions need a replica set. `ensure_replica_set` sends `hello` and refuses with
  `ProtReplicaSetRequired` (503) unless the reply has a `setName`. Only a positive answer is cached; a failed probe
  is retried on the next write. The check is lazy (the first Prot write in the process), not at boot, and reads
  never call it. A Prot write never falls back to a non-transactional path.
- A Cipher reversal with nothing posted never opens a transaction (section 6.3), so a missing replica set can never
  strand a Cipher refund while grants are off.
- Indexes are created by the migration (section 4.3), never in ops.

### 4.2 Reference driver

The Reference driver (tests) uses per-collection `futures::lock::Mutex` maps. Its "transaction" is a lock order
plus check-before-mutate:

- S5a order: **`cipher_memberships` -> `prot_ledger` -> `prot_accounts`**.
- A method takes every map it needs at its start, in that order, holds them to the end, never takes a map it
  already holds, and never calls another trait method while holding a map (the mutex is not re-entrant).
- Every check (duplicate key, floor, membership version) runs before the first mutation, so a refused call changes
  nothing.
- **Rule for S5b:** once S1 has landed, S1's documented maps come FIRST (so `channel_entitlements` precedes every
  map here), then `cipher_memberships`, then `prot_ledger -> prot_accounts -> prot_pledges -> prot_goals ->
  prot_tanks -> prot_runtime -> prot_notices`. S5a's order is a prefix-preserving subsequence of that, so no S5a
  method changes when S5b lands. S1 paths never take `cipher_memberships` or any `prot_*` map.

### 4.3 Migration

Revision block `if revision <= 76` with `LATEST_REVISION = 77` in `admin_migrations/ops/mongodb/scripts.rs`.
Revision 75 is reserved for S1, which lands first; a database at 75 runs block 76 and stores 77. `PROT_COLLECTIONS`
and `create_prot_indexes` are shared by the migration and `init.rs`; the block panics on failure (like revision 74),
since the unique key index is what makes postings idempotent. S5b adds its collections and tank indexes to the SAME
block, which ships once. If S1 ever lands after S5, S1 renumbers, never S5 (a database at 77 would skip a `<= 75`
block forever).

The revision pin tests move with it: `latest_revision_is_75` becomes `latest_revision_is_77`, and two existing
tests (`revision_73_backfills_view_audit_log_onto_manage_server_roles` and
`revision_74_creates_payment_indexes_and_seeds_cipher_numbers`) change their four `run_migrations(..) == 75`
asserts to assert `LATEST_REVISION` instead of a literal, so the next migration does not have to edit them again.
These are pins whose job is to move, not weakened assertions.

S5a `prot_ledger` indexes: `prot_ledger_key_unique`, `prot_ledger_debit_id`, `prot_ledger_credit_id`,
`prot_ledger_credit_kind_created`, `prot_ledger_order` (partial), `prot_ledger_membership` (partial).

## 5. Buying Prot

Code: `crates/core/payments/src/engine/prot.rs` (Prot-only logic), `engine.rs` (the shared paths and their family
branches), `catalog.rs`, `settings.rs` (`ProtSalesSettings`), `stripe/client.rs`.

### 5.1 SKUs and families

Prot orders share `payment_orders` with Cipher, so lease, CAS, dispatch and reconcile are reused.

- `Sku::ProtPack { pack, prot, cents }` and `Sku::ProtExact { prot }` (`prot` Prot for `prot` cents). The server
  stamps `prot` and `cents` from config at checkout, so a later config change never alters what an order credits.
- `Sku::family()` returns `ProductFamily::Cipher` or `ProductFamily::Prot`. Checkout, fulfillment and reversal
  branch on it.
- The rule is **Cipher behavior unchanged**. The Cipher lines that do change are each pinned by a new test, and
  the existing payments tests run unedited against the pre-S5 control (except the single fixture edit noted in
  section 12).

Cross-family isolation:
- the "one live order" rule is per family, so a pending pack never blocks a Cipher checkout and vice versa;
- a Prot region void never blocks a Cipher checkout;
- the Cipher sale's close date (`SalesClosed`) applies to Cipher only; without that, every pack bought after the
  Cipher sale closed would be voided;
- `cipher_me` lists Cipher orders only;
- Stripe Checkout's consent text and tax code come from `sku_consent_message` and `sku_tax_code`; Cipher keeps its
  text and code verbatim. `PROT_TERMS_ACCEPTANCE_MESSAGE` and `PROT_TAX_CODE` are drafts until legal and tax
  review sign off; they gate only `prot_sales_open`.

### 5.2 Checkout

`POST /payments/prot/checkout` with `DataProtCheckout` (`pack` or `exact_cents`, exactly one, plus `return_to`).
`create_prot_checkout` checks, in order:

1. payments disabled -> `PaymentsDisabled`; `enabled` false -> `ProtDisabled`; `prot_sales_open` false ->
   `ProtSalesClosed`;
2. a Prot-family region void of this buyer still holding -> `ProtRegionUnavailable` (the route also refuses a
   blocked Cloudflare country up front);
3. any of the buyer's orders in state Creating, Pending, Paid or Fulfilled with an open dispute ->
   `ProtNotEligible`;
4. `quote_prot`: an unknown pack, or `exact_cents` outside `prot_exact_min_cents..=prot_exact_max_cents`, ->
   `ProtPackInvalid`;
5. wallet balance + the Prot of the buyer's Paid Prot orders not yet credited + this order's Prot > `wallet_cap`
   -> `ProtWalletCap { max }` (D18);
6. one live Prot order: an unexpired Pending order with the same SKU returns its URL, any other live one ->
   `PaymentPending`;
7. insert the order and start the Stripe session.

Bots are refused. The wallet cap is checked at checkout only: a paid order is always credited, even if the
wallet has grown past the cap since, and Cipher grants are exempt.

Return URLs (`prot_success_url`, `prot_cancel_url`, `prot_shell_return_url`) live under `[features.payments]`.
Web checkouts return to `?prot=success` / `?prot=cancel`; desktop and mobile shells return to the thanks page in
the system browser for both outcomes.

### 5.3 Fulfillment: one shared void path, two branch points

`fulfil_locked` keeps ONE path through every void for both families, in this order:

1. amount mismatch void;
2. deleted-buyer voids;
3. "already applied?" (**branch point 1**: Cipher checks the membership's order list; Prot checks whether the
   ledger row `purchase:{order_id}` exists);
4. if not applied: the billing-country and card-country region voids (the blocked list comes from the family:
   `prot_blocked_countries` for Prot), the release-pending void (Cipher only, by its SKU match), the preconditions
   (`precondition_failure`; for Prot, an open dispute defers with `DisputeOpen`, so nothing is credited while a
   dispute is open), and the `reversal_pending` -> Reversed void;
5. apply (**branch point 2**: Cipher `apply_membership` + badge; Prot `apply_purchase`, which posts
   `purchase:{order_id}`, `Exact(sku prot)`, `sys:issued -> user:{user_id}`, actor `sys:payments`, and publishes
   `ProtBalanceUpdate`).

Branching anywhere earlier would let a pack skip the region or reversal voids. The pinning test: an EU billing
country or an EU card buying a pack is voided and refunded, and `purchase:{order_id}` never exists.

`apply_purchase` is never refused for the wallet cap or the flags, and `AlreadyApplied` counts as success.

### 5.4 Reversal of a Prot order

`reverse_fulfilled` branches to `reverse_prot_fulfilled` right after the dispute bookkeeping. Without that
branch a Prot reversal would fall into the membership loop, find no membership and be recorded Refunded with
nothing clawed back. See section 7 for what it does.

### 5.5 The wallet read

`GET /payments/prot/@me` returns `ProtMe`: `balance`, `held` (the D17 figure: min(balance, Purchase credits in the
last `contribute_hold_hours`), 0 when the hold is 0), `version` (the wallet account's `version` when read, 0 when
there is no account), `pending_order` (the latest unexpired Pending Prot order), and `recent` (the newest
`PROT_RECENT_LIMIT` = 20 ledger rows, amounts signed from the wallet's side). The balance is REST-only; the
`ProtBalanceUpdate` event (section 11) tells the client to update and carries the same account `version`, so a
client drops any event whose `version` is not newer than the one it holds (a `/@me` read newer than a late event
wins).

### 5.6 Rollback trap

`fetch_payment_orders_by_*` fail a whole list when one stored row does not decode. Older builds do not know
`ProtPack` or `ProtExact`. **Once a ProtPack/ProtExact order or a ledger row exists, delta and crond must never be
rolled back below the first S5 build**, and they are deployed together.

## 6. Cipher founding Prot (D2)

Each Cipher tier carries a Prot grant: T99 16,500, T149 33,000, T299 75,000 (`catalog::tier_prot`). Before S5 the
grant existed only on paper.

### 6.1 Trigger

Grants are active while `enabled` AND `cipher_grants_enabled` (`ProtSalesSettings::grants_active`). The owner flips
`cipher_grants_enabled` at the public launch of Protected servers and channels. Memberships bought before the
switch are credited by the sweep; Cipher purchases after it are credited at fulfillment.

### 6.2 The ledger is the source of truth (no new membership field)

What a membership has been credited is computed from its ledger rows, never stored on the membership:

- `cipher_prot_target(m)` = the tier's grant while the membership is active, else 0. A dispute does not lower the
  target; it only pauses upward syncs.
- `cipher_prot_posted(rows)` over the rows with `ref.membership_order_id == base`: the sum of `amount` of
  CipherFounding and CipherUpgrade rows minus the sum of `requested` (not `amount`) of Clawback rows. Counting
  `requested` settles a clawback to its target even when it fell short.

Why not a field on `CipherMembership`: a new field breaks every struct literal in the existing payments tests, and
an older binary's full-document replace silently drops an unknown field, so a rollback and roll-forward would read
0 while the Prot sits in the wallet, and the next sync would post it again. `prot_posted_at` stays a legacy marker:
new code never sets it, and the existing gates that read it are extended, not replaced.

The membership `version` is what serializes the ledger against the engine. Every engine membership write is a
version CAS; every Cipher Prot posting (grant or clawback) bumps the version in the same transaction
(`bump_cipher_membership_version_in`). Whichever commits second sees a moved version and re-reads. Only a posting
bumps the version: a sync or sweep that finds nothing to do leaves the membership untouched.

### 6.3 Algorithms

**Upward, `sync_cipher_prot(user_id, now)`** (one transaction, re-run up to `PROT_STATE_RETRIES` times):
1. read the membership; none, or empty `orders` -> Nothing;
2. `base = orders[0]`; `posted` and `target` as above;
3. inactive, or any disputed order listed -> `OverPosted` if `posted > target`, else Nothing;
4. `posted > target` -> `OverPosted { posted, target }` (logged as `PROT_CIPHER_OVERPOSTED`, never clawed here);
   `posted == target` -> Nothing;
5. `target > posted` -> post `Exact(target - posted)` from `sys:issued` to the wallet, actor `sys:cipher`: kind
   CipherFounding with the founding key if no grant row exists yet, else CipherUpgrade with key `seq` = the grant
   row count; `ref.order_id` = the membership's latest order;
6. bump the membership version in the same transaction; a moved version aborts and retries;
7. a duplicate key with a different payload (a racing sync from an older state) re-runs the body; the same payload
   is `Posted(AlreadyApplied)`.

**Downward, `clawback_cipher_prot(user_id, order_id, now)`** (one transaction):
0. outside any transaction: a `clawback:{order_id}` row already exists -> AlreadyApplied; no membership ->
   nothing; the reversed order predates the membership's current incarnation (`order_id < m.orders[0]`; ULIDs
   compare in time order, e.g. a dispute lost on an order of a revoked row that a re-purchase replaced) -> nothing,
   logged at warn level as `PROT_CLAWBACK_OLD_INCARNATION` (that incarnation was settled when it was revoked, and
   the current one must not pay for it); `posted <= target` -> nothing. None of these opens a transaction;
1. in the transaction, re-read; `target` is the membership AFTER the reversal's own write (revoked -> 0; window
   downgrade -> the lower tier's grant); the old-incarnation check runs again on this read; `posted <= target` ->
   nothing;
2. post `clawback:{order_id}`, kind Clawback, `UpTo(posted - target)`, wallet -> `sys:clawed`, actor
   `sys:payments`; the row records `requested` and `shortfall`;
3. bump the membership version in the same transaction.

**Who calls them:**
- the fulfillment hook (`sync_after_cipher_fulfil`, after every Cipher fulfillment; it never fails the caller,
  and errors are logged as `PROT_CIPHER_SYNC_FAILED`);
- the hourly crond sweep `prot_cipher_backfill`, which pages through every membership while grants are active. It
  skips, without opening a transaction, any membership that is inactive, disputed, or already posted to its
  target, and syncs the rest. It is also the backstop for a hook that failed and for a dispute that was later won;
- the engine's reversal paths (`clawback_cipher_order`).

Deleted accounts get nothing: the account-deletion cascade deletes the Cipher membership before the user is
deleted, and the second-pass forfeit (section 8) catches a credit that races the deletion.

### 6.4 The 14-day window

A Cipher refund within the 14-day window normally undoes the purchase (releases the number, or downgrades an
upgrade). Once Prot exists, Terms section 7 allows that only if none of that Cipher's Prot has been spent:

1. **Hypothetical clawback first** (`window_clawback_covered`, read-only). The refund is covered only if BOTH:
   - the membership's recorded shortfall is 0: the sum of `shortfall` over ALL Clawback rows of the membership
     (`ref.membership_order_id == base`), not just this order's; and
   - the wallet covers what still needs clawing back: with `needed = max(0, posted - target_after)`, either
     `needed == 0` or the wallet balance >= `needed`.
2. **Covered** -> today's undo (release or downgrade), with the clawback posted.
3. **Shortfall** -> revoke + retire: the revoke path's clawback takes what it can and records the shortfall, and the
   number stays retired.

The release gate (the check that decides whether a refunded number is released or retired) reads the same
membership-wide sum, so a shortfall recorded on any order of the membership keeps the number retired. A covered
decision that a race turns short is caught there for a release, and recorded on the row for a downgrade (logged
for review). A window `RefundOnly` (an older
upgrade with another stacked on it) leaves the membership unchanged, so nothing is clawed back; it is handled by
hand with `POST /admin/prot/adjust`.

### 6.5 Worked examples

User U, membership number 42.

**(a) Bought before the switch.** U buys T99 (order `o1`) while grants are off: no ledger rows. The owner turns
on `cipher_grants_enabled`. The next sweep runs `sync_cipher_prot`: posted 0, target 16,500, no grant rows, so it
posts `cipher-founding:U:42:o1`, CipherFounding, Exact(16,500). Wallet: 16,500.

**(b) Upgrade after posting.** U then upgrades T99 -> T149 (order `o2`). The engine pushes `o2` onto `orders`
(base stays `o1`) and the fulfillment hook syncs: posted 16,500, target 33,000, one grant row, so it posts
`cipher-upgrade:U:42:o1:1`, CipherUpgrade, Exact(16,500), `ref.order_id = o2`. Wallet: 33,000.

**(c) The race.** As (a), but U upgrades to T149 just after the switch, before the sweep reaches U. The sweep's
sync and the upgrade race:
- the sweep commits first (founding 16,500, version bumped): the engine's upgrade CAS fails, it re-reads and
  applies T149; the fulfillment hook then posts the 16,500 difference as `cipher-upgrade:U:42:o1:1`;
- the upgrade commits first: the sweep's version bump fails, it retries on T149 and posts a founding row of 33,000
  (or finds that the fulfillment hook already did);
- both syncs run on T149 at once: same key, same payload, the loser gets AlreadyApplied; a sync that built 16,500
  from the stale T99 state hits the founding key with a different payload and re-runs, finding posted == target.

Every ordering ends with 33,000 posted for the membership, once.

**(d) 14-day refund, nothing spent.** U holds T99 with 16,500 posted and a wallet of 16,500, and is refunded `o1`
within the window. Needed = 16,500 - 0 = 16,500; the wallet covers it, so the number is released as before. The
release posts `clawback:o1`, UpTo(16,500): amount 16,500, shortfall 0. Wallet: 0; posted for base `o1`: 16,500 -
16,500 = 0. U buys T99 again (order `o3`) and gets number 42 back (lowest free). The new incarnation's base is
`o3`, so `cipher-founding:U:42:o3` is a new key and U is credited 16,500 again.

**(e) 14-day refund after spending 1,000.** As (d), but U's wallet holds 15,500 (1,000 went into a tank in S5b;
in S5a only an admin debit can do this). Needed 16,500 > 15,500: not covered, so the refund revokes and retires.
The revoke posts `clawback:o1`, UpTo(16,500): amount 15,500, shortfall 1,000. Wallet: 0; posted for base `o1`:
16,500 - 16,500 (requested) = 0, so a later reversal of another order of the same membership finds nothing more
to claw back. Number 42 stays retired.

**(f) A shortfall on one order blocks the release of the number.** Grants are on. U buys T99 (`o1`) on day 0 and is
credited 16,500, upgrades to T149 (`o2`) on day 2 and is credited 16,500 more (wallet 33,000), then spends 1,000
(wallet 32,000). On day 5 `o2` is partially refunded. A partial refund is never a window undo: it revokes the
whole membership, so the target drops to 0 and `clawback:o2` posts UpTo(33,000): amount 32,000, shortfall 1,000.
Wallet: 0; posted for base `o1`: 33,000 - 33,000 = 0. On day 6, inside its window, `o1` is refunded. Looking at
`o1` alone, nothing is left to claw back (needed = 0, and there is no `clawback:o1` row), which would release
number 42. The membership-wide recorded shortfall is 1,000, so the refund is NOT covered: the window check alone
handles it as revoke + retire and number 42 stays retired. No release is ever marked, so the release gate is not
reached, and no further clawback row is written (posted 0 <= target 0).

The other order, an upgrade refunded outside its own window and then the CipherNew refunded inside its window, looks
impossible because the upgrade is always the later purchase. It is reachable when the CipherNew refund event is
delivered late (Stripe retries for up to 3 days, or the reconcile sweep picks it up), and the same membership-wide
rule keeps the number retired.

## 7. Clawback (D1)

### 7.1 Rules

On every reversal of a fulfilled Prot or Cipher order (a refund, full or partial, or a lost dispute):

1. remove from the buyer's wallet up to the amount (`clawback:{order_id}`);
2. **S5b:** if short, remove from the buyer's Held pledges, newest first (`clawback-hold:{order_id}:{pledge_id}`;
   the pledge's `remaining` and the goal's `pledged_total` drop; a Funded goal that falls below its target goes
   back to Funding with its deadline unchanged; a Launching goal keeps launching with what it has), all in the same
   transaction, and record the FINAL shortfall on the `clawback:` row;
3. never take Prot from a tank, never take a balance below 0, and record what could not be recovered as the row's
   `shortfall` (for the books and repeat-abuse review).

ONE key per reversal (`clawback:{order_id}`): a refund followed by a lost dispute on the same order claws back once.
S5a writes the wallet part only.

### 7.2 Amount per reversal kind

- **ProtPack / ProtExact:** `UpTo(amount of the purchase:{order_id} row)`, bonus included, on any refund (a partial
  refund claws back the whole order, as Cipher treats a partial refund as a full revoke) or a lost dispute. No
  purchase row -> nothing (never credited). An order unlinked by account deletion -> no ledger action (the wallet
  was already forfeited).
- **Cipher, any reversal:** `UpTo(posted - target)` for the membership incarnation, with the target read after the
  reversal's membership write. A window downgrade claws that upgrade's grant difference; a window release or any
  revoke (a refund outside the window, a partial refund, a lost dispute, of a CipherNew or of an upgrade, since the
  code revokes the whole membership then) claws everything still posted.
- **Cipher order from an older incarnation** (`order_id < m.orders[0]`, e.g. a dispute lost on an order of a
  revoked membership that a re-purchase has since replaced): nothing, logged as `PROT_CLAWBACK_OLD_INCARNATION`.
  That incarnation's Prot was settled when it was revoked; the current incarnation never pays for it.
- **Window RefundOnly:** membership unchanged, no clawback.

### 7.3 Disputes

- **Opened:** no balance action. New Prot checkouts are refused while any of the buyer's orders in Creating,
  Pending, Paid or Fulfilled has an open dispute (`ProtNotEligible`), and a paid Prot order with an open dispute is
  not credited until the dispute closes.
- **Won:** no clawback. A Prot order that was not yet credited (its credit deferred while the dispute was open) is
  credited at the next resume of the order; a Cipher sync that paused for the dispute resumes on the next sweep.
- **Lost:** clawback as above.

### 7.4 The fraud trade-off (D1, D17)

D1 follows the Terms: only unspent Prot is taken back. The cost, stated plainly: a stolen card can buy Prot and put
it straight into a tank, and the chargeback then recovers nothing. The same holds for any refund after spending.

The only mitigation is **D17, the 72-hour hold**: Prot from a purchase in the last `contribute_hold_hours` (72; 0
disables) cannot go into a tank or a pledge, though it stays usable as a wallet balance. In S5a this is the `held`
figure of `/@me` (computed from ledger row times; no "held until" is stored). S5b enforces it on contribute and
pledge (`ProtHeldPurchase`). Cipher grants are not purchases and are never held.

## 8. Account deletion (D11, D20)

In crond's `delete_accounts_with`, per account:

1. the payments cascade (voids, unlinking orders, deleting the Cipher membership);
2. `user.delete`, which cascades the servers the user owns (S5b: each tank is settled and each open goal canceled,
   which can pay the owner's own share back into the wallet);
3. `forfeit_wallet_on_deletion`: the whole wallet, `All`, `user:{id} -> sys:forfeited`, actor
   `sys:account-deletion`, key `forfeit:{user_id}:{n}`; it runs whatever the flags say, and a wallet that is absent
   or 0 never opens a transaction. A pass that returns AlreadyApplied (a racing pass took key `n`) is followed by a
   re-read of the balance outside any transaction: still > 0 -> the next pass (`n` recounted, so `n + 1`), at most
   `PROT_STATE_RETRIES` (5) passes in all, then an error logged as `PROT_FORFEIT_UNSETTLED`;
4. `account.mark_deleted`.

Forfeiture runs AFTER step 2 so nothing paid back by the cascade is left orphaned. It must succeed: on failure the
account stays due and the next run repeats the cascade.

**Second pass.** After any credit to a wallet commits (purchase, grant or admin credit), the engine checks
`buyer_is_live`; if the user is gone it runs `forfeit_prot_wallet` again, with the next `n`. Check-after-write
closes the race: either the deletion's forfeit sees the credit, or the credit path sees the user deleted. Two
racing passes compute the same key; the loser gets AlreadyApplied or retries. An admin credit also refuses a target
that is already deleted before it posts; the check after posting covers an account deleted in between.

**S5b:** held pledges are forfeited too (`forfeit-hold:{pledge_id}`). Contributions already in tanks are spent and
stay. (Abuse termination is different: it forfeits the tank but returns held pledges.)

**Retention (D20):** ledger rows keep the user id after account deletion for 7 years, like payment orders, for the
books and refunds. The Privacy policy states it.

## 9. S5b preview (NOT YET IMPLEMENTED)

This section is the planned design. It depends on S1's protected-channel entitlements and is built only after S1
has landed. Exact names, signatures and rounding are pinned before S5b starts and may refine what is written here.

### 9.1 Data

New collections beside the S5a ones: `prot_pledges` (one document per pledge, with `amount`, `remaining` and
`state`), `prot_tanks`, `prot_goals`, `prot_contributor_prefs` (hide-name), `prot_notices` (warning dedupe) and
`prot_runtime` (the burn pause marker). `channel_entitlements` gains an optional `tank_id`.

- Tank `stage`: Launching | Active | Grace | Frozen | Settling | Deleted | Terminated.
- Goal `state`: Funding | Funded | Launching | Launched | Applied | Expired | Cancelled.
- Pledge `state`: Held | Captured | Returned | Withdrawn | Forfeited.

Every way out of a hold (capture, return, withdraw, clawback, forfeit, launch return) CASes the pledge's `state` and
`remaining` in the same transaction as its ledger row, so a pledge leaves its hold exactly once.

A tank's `daily_cost` is a snapshot taken at the last tier change, so a config edit never moves anyone's date.

### 9.2 The clock

The crond job `prot_tank_clock` (hourly tick, UTC days; a no-op unless `enabled` and `burn_enabled`) owns every
burn, stage move and warning.

- **Charging:** a day is charged at its start (00:00 UTC) for the day ahead, one `burn:{tank_id}:{YYYY-MM-DD}` row
  per tank per day, then `next_burn_day` moves on by one. The unique key is the lock across replicas.
- **Launch day:** charged pro rata in whole hours left, rounded up. Example: launched at 15:20 UTC with 10 slots
  (40 a day): 9 hours left, 40 x 9 / 24 = 15 Prot.
- **Mid-day tier upgrade:** the rest of today's difference, pro rata and rounded up (`tier:{tank_id}:{change_id}`),
  then `daily_cost` is re-priced. Example: 10 -> 25 slots with 12 hours left: (90 - 40) x 12 / 24 = 25 Prot.
- **Protected until** = the next UTC midnight + floor(balance / daily_cost) days. It is derived, never stored.
  Example: 1,000 Prot at 40 a day is protected until next midnight + 25 days.

### 9.3 Stages

`exhausted_at` is the start of the first day the balance could not pay (during a catch-up, that missed day, not
"now").

- **Active -> Grace** when the balance cannot pay the next day. Burns continue into a negative balance down to the
  floor, `-(grace_days x daily_cost)` (borrowed grace). Grace allows everything except new seats: sends, new
  devices for already-seated members and new group generations still work (D14).
- **Grace -> Frozen** at `exhausted_at + 5 days`. Burning stops; frozen days are never charged. Frozen allows
  reading history only: no sends, no new members.
- **Frozen -> Settling -> Deleted** at `exhausted_at + 30 days`, only if `deletion_enabled` AND the day-20 final
  warning was recorded at least 10 days earlier; otherwise deletion is postponed, so a catch-up after an outage can
  never delete without warning. The grace debt is written off (`writeoff:{tank_id}`), the content is purged
  (deleted from Sloga's servers), and the entitlement stays as a Deleted tombstone. A deleted channel cannot be
  re-protected; the owner creates a new one.
- **Reactivation (Grace or Frozen -> Active)** on a top-up that, after repaying the debt, covers at least
  `min_reactivation_days` (1). It sets `next_burn_day = today` (today charged pro rata), so frozen days are never
  billed, clears `exhausted_at` and re-arms the warnings. A smaller top-up repays debt but does not reset the clocks.
  Example at 40 a day: a tank at -120, topped up 200, is back at 80 (two days), so it reactivates; topped up 150 it
  would be at 30, less than a day, so the debt is repaid but the stage and clocks stay.
- **D16 pause:** while `burn_enabled` is off nobody is billed. When burning resumes, every tank's `next_burn_day`
  becomes today and its stage clocks (`exhausted_at`, the final-warning time) shift later by the length of the
  pause. An outage while `burn_enabled` is on is not a pause: the missed days are caught up and billed, under the
  deletion guard above.
- **Never plaintext.** No stage, deletion, termination or flag-off path unprotects a channel. MLS Remove and Update
  commits stay allowed in every stage, so a removed member is always removed.

Warnings (D12) are derived from the tank state shown to members (a banner), plus a generic push with no server or
channel name and no amounts at -7, -3 and -1 days, at grace, freeze, day 20 and deletion, and email to the owner.
No system message is ever posted.

### 9.4 Goals

Only current members with an explicit member row and ViewChannel may contribute or pledge; not bots, not suspended
or timed-out users; at least 50 Prot except a final pledge that completes a goal; only unheld Prot (D6, D17). The
client shows, and the API returns as `notice`, verbatim: "Contributing supports this server. It does not reserve a
seat; the owner chooses members."

- **Launch goal (D9):** `target_prot = days x daily_cost(slots)`, `days >= 30`, frozen at creation with the rate
  snapshot; deadline 30 days. Pledges are held (`pledge:`) and capped at what the goal still needs; the goal is
  Funded when they reach the target. Withdrawal is allowed while Funding until 48 hours before the deadline (D10).
  Expiry or cancel returns every Held pledge (`pledge-return:`).
- **Launch:** once Funded, the owner creates an empty text channel and launches the goal on it (owner only; the
  channel must be in the goal's server, unprotected, empty and without a tank). Pledges stay Held. Only when the
  owner's device has protected the channel are they captured into the tank (`pledge-capture:`), the tank becomes
  Active and burning starts. Not protected within 7 days of Funded -> Cancelled, and the still-held pledges are
  returned.
- **7-day unseated return (D8):** at `launched_at + 7 days`, once, every launch contributor without an active seat
  gets their full pledge back from the tank (`launch-return:`). If the tank cannot cover everyone, each return is
  scaled by tank / due, rounded down with the largest remainder, so the sum never exceeds the tank, and the channel
  enters normal grace. Upgrade pledges never get this.
- **Upgrade goal (D13):** price = (new daily cost - current daily cost) x days left in the tank, fixed at creation;
  applied automatically when Funded.

**Worked example, launch and 7-day return.** A 10-slot channel (40 a day), 30 days: goal 30 x 40 = 1,200. O pledges
600, A 400, C 200; the goal is Funded and launched at 00:00 UTC (a full first day, to keep round numbers). After
seven daily burns (280) the tank holds 920. C has no seat at launch + 7 days, so C gets 200 back. Tank: 720. (Had
B 400 and C 200 both been unseated with only 100 in the tank, the due 600 would be scaled: B 66.67 and C 33.33 round
down to 66 and 33, and the remaining 1 goes to the larger remainder, so B gets 67 and C 33.)

**Worked example, upgrade price.** A channel at 10 slots (40 a day) with 30 days left in the tank, upgraded to 25
slots (90 a day): (90 - 40) x 30 = 1,500 Prot.

### 9.5 Settlement (D7)

When the owner deletes a funded channel or server (or an account deletion deletes their servers), the tank goes to
Settling (burns stop), open goals are canceled with full returns, and each contributor gets back what is left of
their OWN contributions, oldest burned first (`settle:{tank_id}:{user_id}`).

FIFO inputs:
- contributions = the `contrib:` and `pledge-capture:` rows into this tank, in time order;
- minus the `launch-return:` rows (scaled ones included), each against the pledge it returns, so nobody is paid
  twice;
- tanks are never clawed back, so there is nothing else to subtract;
- the total burn is consumed oldest first; ties within one timestamp are split pro rata;
- returns are rounded down with the largest remainder, so they sum exactly to the balance;
- a deleted contributor's share is forfeited, never handed to others; a negative balance is written off and nobody
  is charged.

**Worked example.** Continuing the launch example: after C's return the launch lots are O 600, A 400, C 0
(1,000). On day 20 D tops up 300. The owner deletes the channel after 25 daily burns (1,000 burned in total). The
balance is 1,200 - 200 + 300 - 1,000 = 300. FIFO: the 1,000 burned consumes the launch lots entirely, so D gets 300,
O and A get 0. Splitting by net lifetime totals instead (O 600, A 400, D 300) would give O 139, A 92 and D 69,
moving 231 of D's Prot to O and A.

**Abuse termination** (privileged): the tank's leftover is forfeited (`forfeit-tank:{tank_id}`), held pledges are
returned, the content is purged and the channel stays protected (a Terminated tombstone).

## 10. Pricing and config

Daily cost, from config (a table, not a formula; every value is whole):

| Slots | 10 | 25 | 50 | 100 |
|---|---|---|---|---|
| Channel (4 per slot) | 40 | 90 (-10%) | 160 (-20%) | 280 (-30%) |
| Server (6 per slot) | 60 | 135 (-10%) | 240 (-20%) | 420 (-30%) |

Packs (`prot_packs`):

| Id | Price | Prot | Bonus |
|---|---|---|---|
| `p5` | $5 | 500 | |
| `p10` | $10 | 1,000 | |
| `p25` | $25 | 2,600 | +100 (4%) |
| `p50` | $50 | 5,300 | +300 (6%) |
| `p100` | $100 | 11,000 | +1,000 (10%) |

Pay-exact: `prot_exact_min_cents` (50, Stripe's USD minimum) to `prot_exact_max_cents` (50000, D18), 1 Prot per
cent. Wallet cap: `wallet_cap` = 100,000 (D18, checked at checkout only). Not on sale in
`prot_blocked_countries` (default: the Cipher list, EU27 + GB).

Config lives in `crates/core/config/src/lib.rs`:
- `FeaturePayments`: `prot_sales_open`, `prot_packs` (`ProtPackConfig`), `prot_exact_min_cents`,
  `prot_exact_max_cents`, `prot_blocked_countries`, `prot_success_url`, `prot_cancel_url`,
  `prot_shell_return_url`;
- `BoostFeatures.protection` (`ProtectionFeatures`): `enabled`, `self_serve_enabled`, `burn_enabled`,
  `deletion_enabled`, `cipher_grants_enabled`, `channel_daily_cost` and `server_daily_cost` (`ProtTierCosts`),
  `grace_days`, `freeze_days`, `final_warning_day`, `warn_days`, `min_reactivation_days`,
  `launch_goal_deadline_days`, `launch_window_days`, `launch_seat_window_days`, `min_contribution`,
  `min_launch_goal_days`, `withdraw_cutoff_hours`, `contribute_hold_hours`, `wallet_cap`.

The payments crate reads them through `ProtSalesSettings` (`crates/core/payments/src/settings.rs`), which validates
them; an invalid Prot config fails closed (`load_or_closed` logs `PROT_CONFIG_INVALID` and treats sales as closed
and grants as off). `PaymentsSettings` is unchanged.

## 11. Errors, routes and events

Errors (`crates/core/result/src/lib.rs`, appended to `ErrorType`): `InsufficientProt { needed, available }`,
`ProtDisabled`, `ProtSalesClosed`, `ProtPackInvalid`, `ProtWalletCap { max }`, `ProtHeldPurchase`,
`ProtTankFrozen`, `ProtGoalClosed`, `ProtNotEligible`, `ProtTierBelowSeats`, `ProtIdempotencyConflict`,
`ProtReplicaSetRequired`, `ProtRegionUnavailable`. HTTP statuses are pinned by the `prot_error_statuses` tests.

Routes (S5a):
- `POST /payments/prot/checkout` (`routes/payments/prot.rs`, bucket `payments`);
- `GET /payments/prot/@me` (same file, bucket `payments_me`);
- `GET /admin/prot/orders/<order_id>` and `POST /admin/prot/adjust` (`routes/admin/`): privileged, an MFA ticket
  and an `X-Audit-Log-Reason` are required; the ledger row (actor + reason) and an `AUDIT prot_*` log line are the
  audit record. They are not gated on `enabled`, so support can inspect and correct while Prot is dark. A negative
  adjustment never takes a wallet below 0.

S5b adds tank and goal routes, the `prot_write` bucket (10 per 60 s) and a privileged termination route.

Event: `ProtBalanceUpdate { balance, version }`, published only on the user's private topic after every applied
posting that names a live user's wallet (purchase, grant, clawback, admin adjust), never for forfeits. `version` is
the wallet account's `version` after the posting; events can arrive out of order, so a client ignores one whose
`version` is older than the state it already has. Prot is never on the `User` object other people see. S5b adds
the tank summary to channel updates.

crond: `prot_cipher_backfill` (S5a, hourly); account-deletion forfeit inside `delete_accounts.rs`. S5b adds
`prot_tank_clock` and a goals sweep.

## 12. Tests that pin the invariants

Ledger (both drivers, `TEST_DB=REFERENCE` and `TEST_DB=MONGODB`):
- every key kind applied twice writes one row; the same key with a different payload is
  `ProtIdempotencyConflict`;
- 20 concurrent `Exact` debits of a 100 balance never overspend;
- after a randomized sequence, the ledger sums equal the balances (system sides as signed totals);
- a zero-amount `UpTo` still bumps `version`;
- `fetch_prot_entries_by_account` paging;
- the payload hash of a fixed posting equals a literal 64-character string;
- Reference: `apply_prot_posting` and `sync_cipher_prot` run concurrently under a timeout never deadlock;
- no replica set -> refused: a unit test of the `hello` reply parsing (a reply without `setName` refuses with
  `ProtReplicaSetRequired`, one with it passes), so it needs no standalone Mongo server;
- known-bad controls: dropping `prot_ledger_key_unique` fails the double-apply test; dropping the `$gte` guard
  fails the overspend test.

Payments:
- the existing payments tests unchanged and green; the Cipher checkout form is pinned byte for byte by
  `checkout_form_has_exactly_the_contract_keys` and `checkout_form_with_automatic_tax_adds_inclusive_tax` (the only
  edit is the `params()` fixture gaining the two new fields);
- `prot_skus_are_tagged_by_type`; `DataProtCheckout` and `ProtMe` serialization;
- pack happy path, pay-exact bounds, a forged amount; the wallet cap, counting Paid Prot orders not yet credited;
- a pack after the Cipher sale closes is NOT voided; an EU or GB billing country or card buying a pack is voided and
  never credited (control: branch Prot before the region voids); a refund before fulfillment voids;
- a pending pack does not block Cipher, and vice versa;
- clawback: full, partial, shortfall recorded; one key per reversal (a lost dispute after a refund claws once);
  checkout refused while an order in Creating, Pending, Paid or Fulfilled has an open dispute; a won dispute
  credits a deferred Prot order at the next resume;
- Cipher: a 14-day refund that is covered releases and the re-buy is credited again; a 14-day refund with Prot spent
  revokes and retires; a shortfall recorded on another order of the membership keeps the number retired
  (`a_partial_upgrade_refund_shortfall_stops_the_window_release_of_the_number`, example (f), and
  `a_shortfall_on_an_upgrade_refund_stops_the_window_release_of_the_number`, the late-delivery order); the upgrade
  difference posts with and without the sweep; the sweep racing an upgrade credits the correct
  total once; the sweep leaves an inactive, disputed or fully posted membership's `version` unchanged; a deleted
  member is never credited;
- an admin credit to an account deleted between the check and the posting is forfeited by the second pass;
- `ProtSalesSettings::from_parts` accepts the defaults; `PROT_TERMS_ACCEPTANCE_MESSAGE` fits Stripe's limits.

Errors, routes, migration:
- `prot_error_statuses` (rocket and axum);
- `prot_payments_routes_use_the_payments_buckets`;
- `latest_revision_is_77`, `revision_76_guard_is_a_top_level_sibling_after_the_74_block`,
  `revision_76_creates_the_prot_indexes`, and the four `== 75` asserts in two existing tests that now assert against
  `LATEST_REVISION` (section 4.3).

Clients: `test/protBalanceUpdate.test.ts` (stoat.js); `protWallet.test.ts` (frontend).

S5b (planned): burn idempotent across two replicas; outage catch-up billing with the missed-day `exhausted_at`; a
pause bills nothing and shifts the clocks; pro rata rounding; the stage machine including the day-20 guard;
reactivation never bills frozen days; Frozen sends refused and Remove commits accepted; pledge capped at the target;
withdraw racing capture, exactly one wins; the 7-day return example (tank 720); the upgrade price example (1,500);
the settlement example (D gets 300) with a `launch-return` netted; rounding that sums exactly; abuse termination
returns held pledges. Known-bad controls: drop the pledge-state CAS, remove the Frozen send step, use lifetime
totals in settlement.
