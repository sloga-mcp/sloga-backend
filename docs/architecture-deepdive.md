# Architecture deep dive

Covers three subsystems in detail: the
Bonfire WebSocket event protocol, the permission system, and Delta's auth/sessions.
File references are paths within this repo.

## 1. Bonfire — the WebSocket event protocol

Bonfire is a **fan-out relay, not a logic server**. It owns no business logic — it
authenticates a socket, then bridges **Redis Pub/Sub → client**. State changes are
published to Redis by *delta* (the API) via `EventV1::p()`; Bonfire forwards the ones a
client is subscribed to.

### Connection lifecycle (`crates/bonfire/src/websocket.rs::client`, one tokio task per socket)
1. **Handshake** — TCP upgraded to WS; query params (`?format=json|msgpack|bincode&version=1`)
   parsed into a `ProtocolConfiguration` via a handshake callback.
2. **Authenticate** — token from the query string, or the client sends
   `ClientMessage::Authenticate { token }`. Resolved by `User::from_token`. On failure it
   sends `EventV1::Error` and drops. Success → `EventV1::Authenticated`.
3. **Ready** — `state.generate_ready_payload()` bulk-loads the user's
   servers/channels/members/users into one `Ready` snapshot; then any active per-channel
   slowmodes (from Redis).
4. **Presence** — `create_session()`; if first session, broadcast presence "online".
5. **Two concurrent loops** joined via `join!(listener, worker)`, wired to kill each other
   through async channels on exit:
   - **`listener`** owns a Fred Redis subscriber. Each iteration first calls
     `state.apply_state()` to reconcile subscriptions, then `select!`s on incoming Redis
     messages. A message → `EventV1` (format per `REDIS_PAYLOAD_TYPE`), optionally rewritten
     (e.g. a `DeleteSession` matching *this* session becomes `Logout`), filtered through
     `state.handle_incoming_event_v1` (updates local cache, decides `should_send`), then
     encoded and written to the socket.
   - **`worker`** reads *from* the client: `BeginTyping`/`EndTyping` (re-published to the
     channel topic if subscribed), `Subscribe { server_id }` (adds to an LRU of "active
     servers" and pokes the listener), `Ping`→`Pong`.
6. **Teardown** — `delete_session()`; if last session, broadcast "offline".

### Subscription / topic model (`crates/bonfire/src/events/state.rs`)
Redis topics are plain strings keyed by ID:

| Topic | Meaning |
|-------|---------|
| `<user_id>` | events about the user |
| `<user_id>!` | the user's **private** topic |
| `<channel_id>` | a channel the user can see |
| `<server_id>u` | per-server member events |
| `global` | broadcast |

Subscriptions are **diffed, not reset**: `apply_state()` returns a
`SubscriptionStateChange` (`None` / `Reset` / `Change { add, remove }`) so the listener
only issues incremental Redis (un)subscribes. Server member topics (`{id}u`) are
subscribed lazily via a 900s-expiry LRU (`active_servers`) — you only get member events
for servers you've recently interacted with, bounding fan-out.

### Publishing side (`crates/core/database/src/events/client.rs`)
The producer API is small helpers on `EventV1`: `.p(channel)` (raw publish), `.private(id)`
→ `{id}!`, `.server(id)` → `{id}u`, `.p_user(id, db)` (to the user *and* fanned out to
every server they're a member of), `.global()`. In debug builds `.p()` logs + publishes
synchronously; in release it uses fire-and-forget `redis_kiss::p`.

## 2. Permissions — a 64-bit bitfield with a query trait

### Flag enums (`crates/core/permissions/src/models/`)
Both `#[repr(u64)]`, stored as bits in a `u64`:
- `ChannelPermission` — e.g. `ManageChannel=1<<0`, `ViewChannel=1<<20`, `SendMessage=1<<22`,
  voice perms `Connect=1<<30`..`Video=1<<32`. Gaps are intentional ("N bits reserved") and
  it's deliberately kept under 52 bits for JS `Number` safety.
- `UserPermission` — `Access`, `ViewProfile`, `SendMessage`, etc.

### `PermissionValue(u64)` (`models/mod.rs`)
The manipulation wrapper; the algebra is bit ops:
- `allow(v)` = `|= v`, `revoke(v)` = `&= !v`, `restrict(v)` = `&= v` (mask down),
  `revoke_all()` = `0`.
- `apply(Override)` applies an `{ allow, deny }` pair (allow first, then deny).
- `has(v)` = `(self & v) == v`. Plus `throw_if_lacking_*_permission()` returning the shared
  `MissingPermission` error.

### The decoupling trick — `PermissionQuery` trait (`trait.rs`)
Calculation logic (`impl.rs`) is written entirely against an async trait of ~20 questions
("are we privileged?", "are we the server owner?", "get our ordered role overrides", "are
we timed out?"). The calculators never touch the DB directly — they ask the query object.
The same math therefore runs over the real DB and over test mocks, and is reused across
crates. **When adding a permission input, extend the trait and both implementations.**

### Resolution order (`calculate_channel_permissions`)
1. Privileged user → `GrantAllSafe` (short-circuit). Same for server owner.
2. Branch on `ChannelType`:
   - **SavedMessages** → all perms iff you own it.
   - **DirectMessage** → delegates to `calculate_user_permissions`; full DM perms only if
     the relationship grants `SendMessage`, else view-only.
   - **Group** → owner gets all; members get view-only + the group's default allow.
   - **ServerChannel** → start from `calculate_server_permissions` (default server perms +
     role overrides applied low→high rank), apply the channel's default override, then
     channel role overrides, then `restrict(ALLOW_IN_TIMEOUT)` if timed out.
     **Key rule:** if the result lacks `ViewChannel`, `revoke_all()`.

Role overrides are always applied **lowest-rank to highest-rank** (higher roles win).
`throw_permission_override` enforces "you can't grant a permission you don't have yourself"
when editing overrides.

## 3. Delta — auth, sessions & request guards

### Auth is a Rocket request guard, not middleware (`crates/core/database/src/models/users/rocket.rs`)
Any route with a `user: User` parameter triggers `FromRequest for User`:
1. Check `x-bot-token` header → look up bot → its user. *(Bot auth)*
2. Else run the `Session` guard (reads `x-session-token`) → fetch the user. *(User auth)*
3. Result memoized per-request via `local_cache_async`. No user → `401 InvalidSession`.

Guard chain: `Session` (token → session) → `User` (session → user), plus a parallel
bot-token path. `User::from_token(..., UserHint)` is the shared resolver used by both delta
and bonfire.

### Login flow (`crates/delta/src/routes/session/login.rs`) — security-hardened
- **Timing-attack mitigation:** random 0–1000ms sleep at the top of *every* login.
- Email normalised; unverified accounts rejected; password checked for compromise
  (`assert_safe`, HIBP-style) *before* verifying.
- **Account lockout (`Lockout`)**: wrong passwords increment a counter — 3rd = 1min lock,
  4th = 5min, 5th+ = 1hr. Cleared on success.
- **MFA:** if `account.mfa.is_active()`, login returns `ResponseLogin::MFA { ticket,
  allowed_methods }` instead of a session. Client re-calls login with `DataLogin::MFA {
  mfa_ticket, mfa_response }`; the ticket is resolved and the response consumed. MFA
  tickets, TOTP, and recovery codes live under `/auth/mfa`.
- Disabled accounts → `ResponseLogin::Disabled`. Success → `account.create_session()`,
  which also emits an `EventV1::CreateSession` over the event bus.

### Rate limiting
Separate from auth — a Rocket fairing (`revolt-ratelimits` + `util/ratelimits.rs::
DeltaRatelimits`) attached in `main.rs`, exposing `X-Ratelimit-*` headers, independent of
the `User` guard.

## How the three connect

A typical mutating request shows the whole loop: client `POST`s to **delta** → `User` guard
authenticates → permission check via `PermissionValue`/`PermissionQuery` → DB write through
the dual-driver `query!` macro → delta publishes an `EventV1` to a Redis topic
(`.p()`/`.server()`/etc.) → **bonfire** instances subscribed to that topic forward it to
every connected client watching it.
