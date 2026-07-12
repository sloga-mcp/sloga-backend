# E2EE media — KeyPackage publish UX (drop call-join MFA) + cap fix

Status: PLAN-AUDITED (media-e2ee-reviewer, 2026-07-12, APPROVE-WITH-FIXES;
all findings folded below — HIGH-1 §3.4, MED-1 §2, MED-2 §3.4, MED-3 §3.2/§4,
LOW-1 §3.1, LOW-2 §4, LOW-3 §3.4).

## 1. Problems

1. **Account-password prompt on first E2EE call join (DAVE-parity UX gap).**
   The FIRST `PUT /mls/key_packages` per device is MFA-gated server-side
   (mirrors the text-E2EE first key publish), so a device's first E2EE call
   join pops the `mfa_flow` modal for the account password. Discord DAVE
   never prompts account credentials at call join. One-time per device, but
   the wrong moment to interrupt (mid join), and repeated in any fresh
   profile/store.
2. **KeyPackage cap-exceeded 400 (step-9 secondary finding).** Fresh app
   start → client `#serverKeyPackages` begins at 0 → native regenerates a
   full batch → publish pushes the directory past `MAX_KEY_PACKAGES = 100` →
   `FailedValidation`, and the device can't replenish until packages are
   consumed/expire.

## 2. Trust analysis (why the MFA gate is droppable)

- **Current reality (audit correction):** the publish route ALREADY verifies
  the request's credential `binding_signature` server-side on EVERY publish
  (first and replenish) against the registered device identity Ed25519 the
  server stores in `e2ee_identities`, and already requires a device-bound
  session (`assert_bound_session`). The MFA gate sits ON TOP of that, only
  on the first-publish arm. §3.1 is therefore "delete the redundant arm",
  not "add verification".
- The directory is UNTRUSTED by design: the real trust decision is the
  admitter's client-side Welcome/Add-time re-verification. **Load-bearing
  dependency (audit MED-1), verified in code:** `verify_leaf_credential`
  (e2ee-core `mls/credential.rs`) resolves the peer from the LOCAL pinned
  peer store, requires `status == Active` and `binding_verified`, and
  compares the leaf's identity key against the PINNED ed25519 — never an
  identity fetched from the directory. Forged directory entries are never
  admitted. If that pinning ever weakens, the whole "MFA is droppable"
  argument collapses.
- **What the server-side signature check does and does not prove (audit
  MED-1):** the binding payload is static (no nonce/timestamp, does not
  cover the key_packages set) and the signature is stored server-side and
  sent on-wire, so the check proves "a valid binding for this (user, device,
  mls_signature_key) existed", NOT per-request proof-of-possession of the
  identity key. An attacker holding BOTH a stolen device-bound session token
  AND a captured binding signature can publish junk blobs (an availability
  nuisance, not a confidentiality/integrity issue — junk fails admitter
  verification loudly). That replenish-path exposure exists TODAY (token
  only, same stored signature); dropping the first-publish MFA arm does not
  widen it.
- The device identity itself was MFA-gated at its own enrollment. Removing
  the publish MFA therefore costs NO confidentiality/integrity — only a
  sliver of defense-in-depth against first-publish directory pollution,
  which was never present on the replenish path anyway.

## 3. Changes

### 3.1 Server: drop the first-publish MFA arm

`PUT /mls/key_packages`: delete the `existing is None → ticket required`
arm and the `ticket: Option<ValidatedTicket>` guard. The request's single
credential `binding_signature` (ONE per request, covering the device's MLS
signature key — the per-KeyPackage credentials are verified at Welcome
time by clients, by design; audit LOW-1) continues to be verified on every
publish, as today. Old clients that still send `X-MFA-Ticket` are
unaffected: the header is simply ignored (their unclaimed ticket TTLs out).

### 3.2 Enrollment pre-publish (UX belt-and-braces — deferred benefit)

Publish the first KeyPackage batch during E2EE device enrollment (`enable()`
and the §6.4 `finishReenroll()` path, where an MFA ticket is already in
hand), so a first call join finds the directory populated. Best-effort and
quiet. **Gating reality (audit MED-3):** the route 400s `FeatureDisabled`
while `media_e2ee_enabled` is FALSE (until 6.5), so pre-publish is a silent
no-op at rollout and devices enrolled before it ships never get one. §3.1
(no-MFA first publish at join) is the ACTUAL fix; §3.2 is polish that starts
paying off once the flag is on. While the flag is off, each pre-publish
generates one native batch whose bookkeeping is never published (re-audit
LOW-4) — bounded to one per enable/re-enroll, no exposure (never claimable),
reclaimed by the expiry prune; the call-join replenish path has the same
property today.

### 3.3 Client MFA plumbing

Keep the `mfa_required` handling in `#apiMls`/`#ensureKeyPackages` as a
harmless fallback (a pre-§3.1 server still works); it should never fire
against an upgraded server. Remove in a later cleanup once deployed.

### 3.4 Cap fix: atomic capped insert (audit HIGH-1)

Replace the cap-exceeded 400 with a NEW driver primitive — the route must
not compose count/prune/insert itself:

```
AbstractMls::insert_mls_key_packages_capped(
    user_id, device_id, packages: &[MlsKeyPackage], max: usize,
) -> Result<u64 /* resulting one-time count */>
```

Semantics (identical across drivers):
- Upsert the batch (same replace-by-id semantics as today), then prune the
  device's OLDEST one-time packages down to `max`, EXCLUDING the batch's own
  refs (the fresh batch always survives) and EXCLUDING the last-resort row
  (outside the cap; its init key is singular — audit LOW-3).
- "Oldest" is pinned to `created_at` ascending, tie-broken by `_id`
  ascending (intra-batch rows share one `now` — audit HIGH-1), the SAME
  ordering in both drivers.
- **Reference:** the whole insert+prune runs under the existing single
  Mutex — atomic outright.
- **MongoDB:** no sort/limit on `delete_many`, so prune is find-oldest-ids
  (sort `created_at, _id`, project `_id`, filter `last_resort: false`,
  `_id $nin` batch ids) → `delete_many({_id: {$in: ids}})`, then re-check
  the count and repeat (bounded, e.g. 3 rounds) so a concurrent publish
  racing the window still converges ≤ `max`. Concurrent claims only ever
  DECREASE the count (their `find_one_and_delete` is atomic), so the loop
  terminates and a transient over-`max` between rounds is the accepted
  worst case.
- Structural pre-check stays: a single batch whose own length exceeds
  `MAX_KEY_PACKAGES` is still a 400 (can't prune your way out of that).
- The route returns the primitive's resulting count as
  `key_package_count`; the client already syncs `#serverKeyPackages` from
  it (shipped in 6.4).

**Prune is content-blind (audit MED-2):** the server cannot distinguish a
victim's legitimate packages from junk published via a stolen device-bound
token + captured binding signature (§2), so prune-by-oldest can evict
legitimate packages in favor of newer junk — a targeted
"can't-be-added-to-calls" DoS. This vector exists today on the replenish
path and is NOT worsened by §3.1/§3.4; the accepted floor is that admission
fails LOUDLY at the admitter (junk never verifies), and the real mitigation
lives at session binding / token theft, not here.

## 4. Failure modes / notes

- Invalid-signature publish (attacker with stolen token, no identity key,
  no captured signature): 400, nothing stored.
- Legacy devices enrolled before §3.2: first join publishes silently via
  §3.1 (no prompt) — the modal simply disappears.
- Mixed versions: old client + new server = old client's MFA ticket header
  is ignored (guard removed); new client + old server = `mfa_required`
  fallback still prompts (acceptable during rollout). A legacy client's
  minted ticket is now never claimed by this route, so it stays live until
  its TTL (re-audit LOW-5) — exposure requires token theft inside that
  short window and vanishes as clients upgrade.
- **Watermark is in-memory (audit LOW-2, accepted):** `#serverKeyPackages`
  resets to 0 each app start, so the first join of each run regenerates a
  batch and rides the prune path (replace-oldest churn, no user-visible
  failure). Non-blocking follow-up: seed the watermark from a server count
  at startup (needs a count endpoint) or persist it natively.
- **Existing test inverts (audit MED-3):**
  `publish_validates_binding_caps_and_immutability` asserts first-publish-
  without-MFA → 401 and cap-overflow → 400; both flip (→ 200 accepted, and
  → 200 with prune-to-cap respectively). Update in place, don't add a
  parallel test.
- REFERENCE + Mongo driver tests: valid-sig publish accepted without MFA;
  invalid sig rejected; capped insert prunes oldest (created_at then _id),
  keeps the fresh batch + last-resort, returns the resulting count;
  replenish after prune consistent; concurrency: claim racing a capped
  insert never yields a duplicate serve and converges ≤ cap.
