# Chunked/Resumable Uploads + Streaming Downloads — Implementation Plan

**Status:** Stages 0–5 IMPLEMENTED and committed (backend  6f90d6d0..26284f3d, frontend  355cfcda); §12 amendments applied. Remaining: release deploy + the §9 live-smoke checklist.
**Drafted:** 2026-07-26, against `acutest` @ 7cd69b56 (tag `pre-chunked-uploads-20260726`). Audited by code-reviewer 2026-07-26 (14 findings, verdict: implement with fixes).
**Implements:** `docs/chunked-resumable-uploads-design.md` with the settled decisions applied: 5 GB ceiling, Phases 1+2 shipped together, versioned STREAM-AEAD (v2) at-rest format from day one, legacy whole-GCM read path preserved (absence of version field = legacy), claim-once `File` minting unchanged, 32 MiB chunks, MinIO `AbortIncompleteMultipartUpload` lifecycle + `UploadSession` TTL sweep as hard ship gates.

Verified anchors (current line numbers, `acutest` @ 7cd69b56): `upload_file` at `crates/services/autumn/src/api.rs:208`, `read_to_end` at 332–334, S3_CACHE at 93–110, e2ee routes at 71–79, **CORS `allow_methods([Method::POST])` at 59** (must change — see Stage 2), multipart internals at `crates/core/files/src/implementation/s3_impl.rs:73–202`, `FileHash` at `crates/core/database/src/models/file_hashes/model.rs` (no version field, confirmed), frontend loop at `Draft.ts:366–443`, size clamp at `Composition.tsx:779–781` with `MAX_UPLOAD_REQUEST_SIZE` at `env.ts:112–113`.

---

## 1. The v2 on-S3 format and the key architectural insight

**Constants** (new, in `crates/core/files/src/lib.rs`):
- `CHUNK_SIZE = 32 MiB` (33,554,432) — client-facing part size, plaintext.
- `STREAM_SEGMENT_SIZE = 1 MiB` (1,048,576) — AEAD segment, matching the construction already accounted for in `e2ee.rs:353–359`.
- `CHUNK_SIZE % STREAM_SEGMENT_SIZE == 0` — **load-bearing invariant** (32 segments per part).

**v2 object layout.** No object header. The object is the concatenation, in order, of encrypted segments: segment `i` = `AES-256-GCM(key, nonce_i, plaintext_i)` where `plaintext_i` is 1 MiB (last segment possibly short), producing `1 MiB + 16` bytes per full segment. `nonce_i = prefix(7 bytes) ‖ BE32(i) ‖ last_flag(1 byte)` — exactly the `aead::stream::StreamBE32` nonce schedule over the existing 12-byte-nonce `Aes256Gcm`. The key is the **existing server key** (`config.files.encryption_key`, same as `encryption_impl.rs`); the 7-byte prefix is random per file.

Key insight that makes everything fall out cleanly:

> **Because segment boundaries align with part boundaries (32 MiB = 32 × 1 MiB), encrypting part `p` (1-based) is a pure function of `(server key, nonce_prefix, p, is_final_part, part bytes)` — segments `(p-1)*32 .. p*32-1`, last-flag set only on the final segment of the final part (known from `total_size` declared at create). Encryption is therefore fully out-of-order-safe, restart-safe, and deterministic (same plaintext ⇒ byte-identical ciphertext).**

Implementation: a small `SegmentedStreamCipher` in `crates/core/files/src/implementation/` that builds nonces per the schedule above and calls one-shot `Aes256Gcm` per segment. This is nonce scheduling over a vetted primitive, not hand-rolled crypto — and Stage 0 includes a **differential test proving byte-identity against `aead::stream::EncryptorBE32`/`DecryptorBE32`** (sequential reference) across lengths: 0-remainder, sub-segment, exact-segment, multi-part, 5-part-with-short-tail.

**Version discriminator.** `FileHash` gains `format_version: Option<u32>` with `#[serde(skip_serializing_if = "Option::is_none")]`. `None` (absent in Mongo) = legacy whole-file GCM (or plaintext if `iv == ""`), exactly as today — no migration, no touch of existing rows. `Some(2)` = STREAM format; `iv` then stores base64 of the 7-byte nonce prefix; `size` stores the **plaintext** size; `path` stores the actual S3 key (the field already exists and the read path already uses it — v2 objects live at `chunked/{session_id}`, so no post-assembly S3 rename/copy is ever needed).

**Size accounting for the 5 GB ceiling** (`total_size = 5,000,000,000`):

| Quantity | Value |
|---|---|
| Segments `S = ceil(5e9 / 2^20)` | 4,769 (4,768 full + 389,632 B tail) |
| Tag overhead `S × 16` | 76,304 B |
| Stored object size | 5,000,076,304 B (~5.0001 GB) |
| Parts `N = ceil(5e9 / 32 MiB)` | 150 (149 full + 389,632 B tail) |
| Part request body (plaintext, on the wire) | 33,554,432 B ≈ 33.6 MB — far under Cloudflare's ~100 MB |
| Ciphertext per full part sent to `upload_part` | 33,554,944 B — over S3's 5 MiB min, under its 5 GiB max |
| S3 part-count headroom | 150 of 10,000 (ceiling of this scheme: 320 GB) |
| Part-route `DefaultBodyLimit` | `CHUNK_SIZE + 64 KiB` slack (raw body PUT, no multipart framing) |
| `body_limit_size = 5e9` global | unchanged; only governs the legacy single-POST route; `create`'s size check uses `user.limits().file_upload_size_limit` (already 5e9 in `Revolt.overrides.toml:79–97`) |

RAM per part request: ~32 MiB plaintext + ~32 MiB ciphertext ≈ 64–96 MiB transient; with client concurrency 3 and the ratelimiter, worst case stays in the low hundreds of MB on the 7.7 GB box. `complete` is metadata-only. Download side streams at ~2 MiB resident (§6).

---

## 2. Resolution of the three glossed-over problems

### Problem 1 — out-of-order parts vs. sequential SHA-256 and the STREAM counter

**STREAM counter: dissolved** by the deterministic part-index → segment-index mapping above. No sequential encryptor state exists; nothing to persist, nothing to advance.

**Dedupe hash: replace the sequential whole-file SHA-256 with a composite per-part hash.** `FileHash.id` for v2 = `hex(sha256( "sloga-chunked-v2" ‖ LE64(chunk_size) ‖ LE64(total_size) ‖ sha256(part_1) ‖ … ‖ sha256(part_N) ))`. Each part's SHA-256 is computed inside its own PUT request (no cross-request hasher state) and recorded in the session's `parts` array; the composite is computed at `complete` from the recorded digests.

Why this beats the alternatives weighed:
- **Contiguous-frontier running hash**: requires buffering out-of-order plaintext (disk spool, crash cleanup — S3 will not let you read parts of an incomplete MPU back) — *and* it is not actually persistable: the `sha2` crate exposes no serializable midstate, so the design doc's §4 `hash_state` field cannot be implemented as written; the running hash would live only in autumn's memory and any restart would invalidate every in-flight session. It also creates the entire re-PUT-behind-the-frontier problem (Problem 3).
- **Forcing sequential upload (W=1, pipelined)**: implementable and simple, but costs real throughput — 3-way concurrency is roughly 2–3× on high-latency paths through the Cloudflare tunnel, which at 5 GB is the difference between ~10 and ~30 minutes.
- **What the composite hash gives up**: dedupe between a chunked upload and a *legacy* single-POST upload of the same content. This set is **empty by construction**: the chunked path is only used above the ~90 MB threshold, and no file over ~95 MB has ever been uploadable (Cloudflare wall). Chunked-vs-chunked dedupe works fully (server-fixed `chunk_size` makes the partition, hence the composite, deterministic). The domain-separation prefix keeps the v2 id namespace from ever colliding with a real content SHA-256.

Consequence: parts are accepted **in any order, at any concurrency** the ratelimiter allows.

### Problem 2 — per-session key/nonce material in `UploadSession`

- **Key: never persisted.** All v2 objects use the existing server key from `config.files.encryption_key`, loaded per request exactly as today. Same threat model as legacy at-rest encryption; key rotation story unchanged. No per-file subkey/HKDF — noted as possible future hardening (7-byte random prefix ⇒ multi-file nonce-collision birthday bound ~2^28 files under one key).
- **Nonce prefix: generated once at `create`** (`OsRng`, 7 bytes), stored base64 in `UploadSession.nonce_prefix`. Every part PUT recomputes its segment nonces from `(nonce_prefix, part index, total_size)` — pure function, so an autumn **restart needs nothing but the session row**. At `complete`, the prefix is copied into `FileHash.iv`.
- **Resume semantics**: all authoritative state (`s3_upload_id`, `parts[{n, size, etag, sha256}]`, `nonce_prefix`, `state`, `expires_at`) lives in the `UploadSession` document; autumn holds zero in-memory session state. After a restart (or client reconnect), `GET /:tag/upload/:session_id` returns the recorded part set and the client re-PUTs whatever is missing. Deterministic encryption means a re-upload of the same bytes produces the identical S3 part.

### Problem 3 — re-PUT idempotency with different bytes

With no frontier and complete-time hashing, a re-PUT invalidates no server state — but **divergent bytes under a deterministic nonce schedule are AES-GCM nonce reuse** (audit finding 1): two distinct plaintexts under the same (key, nonce) leak the GHASH key of the shared server key, enabling tag forgery across the whole at-rest corpus. **Rule:**
1. While `state == pending`, a `PUT part/:n` for **any** valid index (1 ≤ n ≤ N; size exactly `CHUNK_SIZE` for n < N, exactly the tail size for n = N — enforced, otherwise the segment mapping breaks) is accepted **iff the part is unrecorded OR the incoming body's sha256 equals the recorded one** (idempotent retry of a lost response — deterministic encryption re-produces the byte-identical ciphertext, so nothing new appears under a reused nonce). A re-PUT with a *different* hash is rejected 409; the client's only path onward is abort + recreate. Residual accepted risk: a crash between `upload_part` and `record_upload_part` followed by a deliberately-different retry. **Bucket versioning must never be enabled on `revolt-uploads`.**
2. **Two concurrent PUTs of the *same* index are rejected**: the handler atomically claims the index (`find_one_and_update` setting an `in_flight.n` marker with a short staleness timeout) and returns **409 Conflict** to the loser. This prevents the one real hazard — S3 keeping writer A's part while the session records writer B's etag/sha.
3. Once `state ∈ {completing, completed, aborted}`, all part PUTs are rejected (409 with state in the body).

**Client-side implication:** the retry loop may freely retry any part (timeout, 5xx, network drop) with backoff — but must never issue two concurrent attempts for one index; on a 409 it re-fetches `GET` status and reconciles (the part may already be recorded from an attempt whose response was lost). On session 404/expired, restart from `create`.

---

## 3. Data model — `UploadSession`

New model dir `crates/core/database/src/models/upload_sessions/` following the house pattern (`mod.rs`, `model.rs`, `ops.rs`, `ops/mongodb.rs`, `ops/reference.rs`):

```
UploadSession {
  _id: String,                 // nanoid(42)
  uploader_id: String,
  tag: String,                 // "attachments" only in v1 (see §4)
  filename: String,
  declared_content_type: String,
  total_size: i64,
  chunk_size: i64,             // frozen at create; composite-hash input
  bucket_id: String,
  path: String,                // "chunked/{_id}" — final object key, no rename
  s3_upload_id: String,
  nonce_prefix: String,        // base64, 7 bytes
  parts: HashMap<partN, { size: i64, etag: String, sha256: String }>,
  in_flight: HashMap<partN, Timestamp>,   // concurrency claims (§2 Problem 3 rule 2)
  head_bytes: Vec<u8>,         // first 8 KiB of part 1, for magic-byte mime sniff at complete
  state: pending | completing | completed | aborted,
  file_id: Option<String>,     // set on completed — makes `complete` retry-idempotent
  created_at: Timestamp,
  expires_at: Timestamp,       // create + 48 h
}
```

`AbstractUploadSessions` trait ops: `insert_upload_session`, `fetch_upload_session`, `try_claim_upload_part` (atomic: pending + not in-flight + index valid → claim), `record_upload_part` (write part record, clear claim), `release_upload_part_claim`, `set_upload_session_state` (with expected-state compare-and-set for `pending→completing`), `set_upload_session_completed(file_id)`, `delete_upload_session`, `fetch_expired_upload_sessions(before)`. Implemented for **both** `MongoDb` (collection `upload_sessions`) and `ReferenceDb` (new field in `drivers/reference.rs`). Registered in `models/mod.rs` and the `Database` dispatch like every other model.

`FileHash` change (`file_hashes/model.rs`): add `format_version: Option<u32>` (+ partial). One new op `update_attachment_hash_location(id, bucket, path, iv, format_version)` in `file_hashes/ops*` for the dedupe empty-iv corner.

---

## 4. New autumn routes

New module `crates/services/autumn/src/upload.rs`, registered in `api.rs::router()` **before** the `/:tag` catch-all, alongside the e2ee routes. Axum's static-over-param precedence makes `/:tag/upload/...` win over `/:tag/:file_id`; file ids are nanoid(42) so the literal `upload` can never be a valid file id.

| Route | Method | Handler behavior |
|---|---|---|
| `/:tag/upload/create` | POST (JSON) | Auth `User` (same extractor as `upload_file`). **Reject `tag != attachments`** — every other tag requires the image pipeline chunked uploads skip (an opaque 5 GB "icon" is nonsense). Validate `0 < total_size ≤ limits.file_upload_size_limit[tag]` and `ceil(total/CHUNK_SIZE) ≤ 10_000`. `create_multipart_upload` → persist session → `{session_id, chunk_size, total_parts, expires_at}`. |
| `/:tag/upload/:session_id/part/:n` | PUT (raw `Bytes`, `application/octet-stream`) | Auth + ownership. Size rule + claim per §2. Compute `sha256(body)`; encrypt segments via `SegmentedStreamCipher`; `upload_part(n)`; `record_upload_part`. If `n == 1`, stash `head_bytes`. `.layer(DefaultBodyLimit::max(CHUNK_SIZE + 64*1024))` on this route only. |
| `/:tag/upload/:session_id` | GET | Auth + ownership. `{state, chunk_size, total_size, parts: [n...], expires_at, file_id?}` — resume source of truth. |
| `/:tag/upload/:session_id/complete` | POST | Auth + ownership. CAS `pending→completing` (409 if completing; if `completed`, return stored `{id}` — idempotent retry). Verify part set complete and sizes sum to `total_size`. Sniff mime from `head_bytes` (fall back declared/octet-stream), check `blocked_mime_types`. Compute composite hash; `fetch_attachment_hash`: **hit with non-empty iv** → `abort_multipart_upload` (drop assembled parts), mint `File` from existing hash, done. **Hit with empty iv or miss** → `complete_multipart_upload` (etags ascending), then insert `FileHash{id: composite, processed_hash: composite, format_version: Some(2), iv: nonce_prefix, path: session.path, bucket_id, metadata: Metadata::File, content_type: sniffed, size: total_size}` (or `update_attachment_hash_location` on the empty-iv row), `insert_attachment(hash.into_file(...))` — `used_for = None`, claimed later by the untouched `find_and_use_attachment` path. Mark session `completed` + `file_id`; on failure roll state back to `pending`. Skips entirely: `strip_metadata`, `generate_metadata`, thumbnails, transcode, ClamAV — `Metadata::File`, opaque store, mirroring the e2ee blob doctrine. |
| `/:tag/upload/:session_id` | DELETE | Auth + ownership. `abort_multipart_upload` + delete session. |

Supporting changes in autumn:
- **`ratelimits.rs`**: new arms — `upload_create` ~5, `upload_part` ~30 (3-way client concurrency + retries; 150 parts must flow), `upload_session` (GET/complete/abort) ~20. Numbers need a sanity pass at implementation.
- **`api.rs:57–67` CORS**: `allow_methods` currently `[Method::POST]` — must become `[POST, PUT, GET, DELETE]` or the browser preflight kills every part PUT and abort.
- **`main.rs`**: register OpenAPI paths/schemas; on startup call `revolt_files::ensure_bucket_lifecycle(&bucket)` (§5).

---

## 5. `revolt-files` crate changes (Stage 0 groundwork)

Refactor `s3_impl.rs:73–202` (create/part/complete currently inside one function, `upload_id` discarded) + extend `FileStorageRepository` with session-oriented primitives, and add public `lib.rs` wrappers:
- `create_multipart(bucket, path) -> upload_id`
- `upload_encrypted_part(bucket, path, upload_id, part_number, ciphertext) -> etag`
- `complete_multipart(bucket, path, upload_id, parts: &[(i32, String)])`
- `abort_multipart(bucket, path, upload_id)` — also used by crond sweep
- `fetch_range_from_s3(bucket, path, byte_range) -> ByteStream` + `fetch_stream_from_s3` (full object)
- `ensure_bucket_lifecycle(bucket)` — idempotent `put_bucket_lifecycle_configuration` with `AbortIncompleteMultipartUpload { days_after_initiation: 1 }` (empty-prefix filter, Enabled). In-code = applied deterministically on every autumn boot, prod and test alike; optionally also `mc ilm` in the compose `createbuckets` job as belt-and-braces (verify flag syntax for the pinned `minio/mc`; check with `mc ilm rule ls minio/revolt-uploads` after boot either way).
- New `implementation/stream_cipher.rs`: `SegmentedStreamCipher { key, prefix }` with `encrypt_part(part_index_1based, is_final_part, plaintext) -> Vec<u8>`, `decrypt_segments(first_segment_index, is_last_included, ciphertext) -> Vec<u8>`, `segment_count(total_size)`, plaintext↔ciphertext offset math. Existing in-RAM `multipart_upload` re-expressed on the new primitives — legacy single-POST behavior untouched.

---

## 6. Download side (Phase 2 — ships in the same release)

Changes in `crates/services/autumn/src/api.rs`:
- **Dispatch in `retrieve_file_by_hash` / `fetch_file`**: `format_version == None` → existing buffered path, byte-for-byte today's behavior for the entire existing corpus. `Some(2)` → streaming path.
- **v2 streaming**: `fetch_range_from_s3` → adapter `Stream` buffering to segment boundaries (≤ ~1 MiB + 16 resident), decrypting each segment, yielding plaintext `Bytes` → `axum::body::Body::from_stream`. Headers: `Content-Length` (plaintext size), `Accept-Ranges: bytes`, existing `CACHE_CONTROL`.
- **Range requests** (v2): single range only (`Range: bytes=a-b`; multi-range → full 200). Map plaintext `[a,b]` → segments `sa = a / 1MiB`, `sb = b / 1MiB` → ciphertext range `[sa·(1MiB+16), (sb+1)·(1MiB+16)−1]` (clamped; last-flag iff `sb == S−1`); decrypt, trim head/tail, `206` + `Content-Range`. Unsatisfiable → 416. Seek is O(range), not O(file) — this is why 1 MiB segmentation is worth it.
- **Legacy + Range**: legacy objects are ≤ ~100 MB; serve ranges by buffered-decrypt-then-slice (bounded, no OOM). Uniform client-visible behavior.
- **S3_CACHE bypass**: v2 objects never enter `S3_CACHE`. Legacy path keeps the cache but adds a size guard (`hash.size > 16 MiB` → fetch without inserting) so bursts of ~95 MB legacy fetches stop evicting the whole cache.
- `fetch_preview` needs no v2 branch: v2 files are `Metadata::File`, which already redirects to `fetch_file` (api.rs:534–545).
- **Nothing OOMs at 5 GB**: upload resident ≈ 96 MiB/part-request; download resident ≈ 2 MiB/stream; `complete` and dedupe are metadata-only.

Deletion/retention interplay (verified, no changes needed): `FileHash.path` is stored per-row, so `delete_from_s3(bucket, path)` in `file_deletion` / `prune_dangling_files` / `prune_large_attachments` works for `chunked/{sid}` keys; v2 `File.size` = plaintext size keeps the >20 MB/24 h prune applying to large uploads exactly as settled.

---

## 7. Cleanup daemon + lifecycle (hard ship gate)

- New crond task `crates/daemons/crond/src/tasks/prune_upload_sessions.rs`, modeled on `prune_e2ee_blobs.rs`: hourly; `fetch_expired_upload_sessions(now)`; for each: `abort_multipart` (treat `NoSuchUpload` as success), then `delete_upload_session`. S3-first-then-row ordering so a failed abort retries next sweep. Completed sessions (kept for complete-idempotency) are deleted by the same sweep via `expires_at`. Register in `tasks/mod.rs` + the `join!` in `crond/src/main.rs`.
- Bucket lifecycle rule applied at autumn startup per §5. Both mechanisms verified before ship (checklist §9).

---

## 8. Frontend (`/home/mcp/frontend`)

- **New module** `packages/client/components/state/stores/chunkedUpload.ts`: `uploadFileChunked(client, file, tag, onProgress): Promise<string /* file id */>`.
  - `create` via `fetch` (JSON; auth from `client.authenticationHeader`).
  - Part loop: `file.slice(start, end)` per part — **never** `arrayBuffer()` the whole file; `xhr.send(blob)` streams from disk. Concurrency 3, one attempt per index at a time. Per-part retry: 3 attempts, backoff 1s/4s/10s; on exhaustion or 409, `GET` status, reconcile recorded parts, continue from the missing set; on session 404/410/expired, restart from `create` once. Per-part `xhr.timeout` fixed (~180 s — part size is constant).
  - Progress: `(bytes of recorded parts + Σ in-flight xhr progress) / total_size` into the existing `uploadProgress` signal; `uploadProcessing` toggles during `complete`.
  - `complete` with retry (idempotent server-side); returns the file id.
  - Resume scope: within-session (network drops, autumn restarts). Page reload loses the `File` handle — resume-across-reload out of scope; the session TTL/sweep absorbs the orphan.
- **`Draft.ts` `sendDraft` (366–443)**: in the plaintext-files branch, `if (file.size > CONFIGURATION.CHUNKED_UPLOAD_THRESHOLD)` → `uploadFileChunked(...)`, else existing single-POST xhr untouched. Same shared try/catch so failures surface (preserving 43caf7de semantics); cache `autumnId` as today.
- **`env.ts`**: add `CHUNKED_UPLOAD_THRESHOLD` (default 90_000_000, override `VITE_CFG_CHUNKED_UPLOAD_THRESHOLD`). Keep `MAX_UPLOAD_REQUEST_SIZE` (still governs single-POST and documents the CDN wall).
- **`Composition.tsx` `onFiles` (~764–800)**: `maxSize` becomes `serverLimit` (5 GB) for plain attachments (files between 95 MB and 5 GB now pass and take the chunked path; under 90 MB still single-POST). **E2EE channels keep their existing ~20 MiB cap** — the E2EE path is untouched (Phase 4), so the gate must still clamp for encrypted conversations.

---

## 9. Stages (each independently buildable, testable, committable)

**Stage 0 — `revolt-files`: multipart primitives + SegmentedStreamCipher + lifecycle helper.** No behavior change.
Files: `s3_impl.rs` (refactor), `implementation/stream_cipher.rs` (new), `implementation/mod.rs`, `repositories/file_storage_repository.rs`, `lib.rs`, `crates/core/files/tests/` (differential STREAM test, cross-request multipart integration vs live MinIO, range-fetch, offset-math property tests).
Test: `cargo test -p revolt-files` (WSL, MinIO up).

**Stage 1 — database: `UploadSession` model (both drivers) + `FileHash.format_version`.**
Files: `models/upload_sessions/*` (new), `models/mod.rs`, `drivers/reference.rs`, `file_hashes/model.rs` + ops (all three files).
Tests: ops round-trip + atomic-claim races under `TEST_DB=REFERENCE` and `TEST_DB=MONGODB` (WSL-only; **test DBs are un-migrated — no unique indexes — don't rely on duplicate-key errors; assert via explicit fetch**). Legacy-compat: deserialize a `FileHash` doc without the field → `None`.

**Stage 2 — autumn upload routes.**
Files: `upload.rs` (new), `api.rs` (registration + CORS fix), `ratelimits.rs`, `main.rs`.
Tests: integration with `TEST_DB=REFERENCE` + live MinIO: create→parts(out-of-order)→complete happy path; re-PUT same/different bytes; concurrent same-index 409; wrong-size part; complete idempotency; dedupe hit drops assembled object; abort; expired-session rejection; tag != attachments rejection.

**Stage 3 — crond sweep.**
Files: `tasks/prune_upload_sessions.rs` (new), `tasks/mod.rs`, `crond/src/main.rs`.
Test: ReferenceDb + MinIO — create session + MPU, backdate `expires_at`, run one sweep, assert MPU aborted (`list_multipart_uploads`) and row gone.

**Stage 4 — streaming download + range + cache bypass.**
Files: `api.rs` (dispatch, streaming/Range/206, legacy cache guard), possibly `autumn/src/stream.rs` for the decrypt-adapter.
Tests: v2 round-trip (upload chunked → fetch full → bytes equal; ranges incl. segment-boundary, mid-segment, tail, 416); legacy fetch unchanged (regression with a whole-GCM object).

**Stage 5 — frontend.**
Files: `chunkedUpload.ts` (new), `Draft.ts`, `env.ts`, `Composition.tsx`.
Test: vitest for the part/retry/reconcile state machine with mocked transport; manual browser test against local backend.

**Stage 6 — docs + smoke.** Update the design doc status (§9 crypto column corrected; Phase 3 dropped), CHANGELOG; run the live checklist.

**Manual live-smoke checklist** (things tests cannot cover):
1. Real >100 MB file from the production frontend **through Cloudflare** (proves parts clear the edge — the 413 wall cannot be reproduced locally).
2. ~1 GB and a full 5 GB upload; watch autumn RSS stays bounded during upload *and* download; download the 5 GB file and diff hashes.
3. Kill autumn mid-upload → restart → client resumes via GET and completes.
4. Kill the client mid-upload → session row + `mc ls --incomplete` shows the MPU → after TTL, sweep + lifecycle reap both (temporarily short TTLs to verify).
5. Video seek in the client on a large v2 file (Range 206 path).
6. Re-upload identical large file → dedupe hit, no second object.
7. Legacy regression: existing avatar/icon/old attachment still renders.
8. `mc ilm rule ls minio/revolt-uploads` shows the abort-incomplete rule after autumn boot.

---

## 10. Rollout order

1. **Backend deploys dark first.** Stages 0–4 merge and deploy as ONE backend release: new routes unreachable by the old frontend (still clamps at 95 MB). Crucially, **Stage 4 (streaming reads) must be in the same deploy as Stage 2 (upload routes)** — the moment a v2 `FileHash` can exist, the read path must serve it without buffering. Staged commits are for review granularity, not separate deploys.
2. Rebuild **release** binaries (autumn AND crond changed — both run from `target/release`) and restart both. Verify the lifecycle rule post-restart.
3. **Frontend deploys second**, any time after — no lockstep: old frontend + new backend fully compatible; new frontend + old backend prevented by ordering. Never roll the backend back past Stage 4 once v2 objects exist (they'd stop being servable); `VITE_CFG_CHUNKED_UPLOAD_THRESHOLD` can be floored to re-clamp quickly in an emergency.
4. **Build discipline**: never run vite and cargo builds concurrently (known WSL crash); sequence frontend build strictly after the release cargo build.

---

## 11. Open questions (defaults will be used unless overridden)

1. **Completed-session retention**: keep completed rows until the 48 h `expires_at` (for complete-idempotency), or a shorter TTL? Default: reuse 48 h.
2. ~~**`mc ilm` exact syntax**~~ **RESOLVED during Stage 0 (2026-07-26): MinIO does not support `AbortIncompleteMultipartUpload` ILM rules at all** — it rejects the rule XML as InvalidArgument, and current `mc` has no abort-incomplete flag. MinIO's equivalent is the server-level `api stale_uploads_expiry` setting, whose **default of 24 h would have purged live day-2 resumable uploads** (the same TTL inversion as amendment 3, via a different mechanism). **Applied to prod: `mc admin config set <alias> api stale_uploads_expiry=72h`** (persisted in MinIO's config backend; verified `stale_uploads_expiry=72h`). `ensure_bucket_lifecycle` still attempts the real ILM rule for AWS-compatible stores and treats MinIO's InvalidArgument as success with an informative log. Any future MinIO reinstall must re-apply the 72 h setting — it is part of the ship gate.
3. **Ratelimit numbers** (`upload_part` = 30 etc.) — sanity pass against `revolt_ratelimits` window semantics during implementation.
4. **Legacy-cache bypass threshold** (16 MiB proposed) — tunable constant; no config plumbing unless wanted in `Revolt.toml`.

---

## 12. Audit amendments (2026-07-26 code-reviewer round — these override earlier sections)

1. **(MAJOR, §2/P3)** Divergent re-PUT = GCM nonce reuse → **reject re-PUT whose body sha256 differs from the recorded one** (409; abort+recreate). Inline fix applied to §2 above. Never enable bucket versioning on `revolt-uploads`.
2. **(MAJOR, §3)** bson 2.15 rejects non-string map keys — `parts` and `in_flight` become `HashMap<String, …>` (stringified part numbers; matches the `$set: {"parts.5": …}` atomic updates anyway). `head_bytes` stored as `bson::Binary` via `serde_bytes` (BSON int-array is ~5× bloat).
3. **(MAJOR, §3/§5/§7)** TTL/lifecycle inversion — invariant: `lifecycle_days > session TTL`. Session `expires_at` = create + 48 h (primary reaper = crond sweep); lifecycle rule `days_after_initiation: 3` (last-line backstop only). A 24 h rule would abort *live* day-2 resumes.
4. **(MAJOR, §4 complete)** Recovery protocol: the `pending→completing` CAS **persists the composite hash** on the session. `complete` is re-entrant for the owner while `completing`: hash-row exists → mint + complete; else `HeadObject(path)` exists → insert FileHash + continue; else re-drive `complete_multipart_upload`. Never roll back to `pending` after S3-complete succeeded. Sweep branches on state: `completed` → delete row; `completing` → resolve via stored composite (hash row → delete row; else `delete_object(path)` + abort + delete row); `pending`/`aborted` → abort + best-effort `delete_object` + delete row.
5. **(MAJOR, §4 create)** Per-user cap on concurrently `pending` sessions (**5**) enforced at `create` via a count op (template: `fetch_active_discord_import_job_for_user`).
6. **(MAJOR, §4 create)** Server-side floor: `total_size > CHUNK_SIZE` (32 MiB) — closes the trivial ClamAV/EXIF/image-validation opt-out for small files; the pipeline exemption exists only where the CDN wall makes single-POST impossible.
7. **(MINOR, §2/§4)** `pending→completing` CAS additionally requires `in_flight == {}` (else 409, client retries); `record_upload_part`'s filter includes `state: pending`. Claim staleness timeout = **10 min** (must exceed worst-case part processing; with divergence rejection the claim is only a politeness lock).
8. **(MINOR, §3)** Drop `update_attachment_hash_location` (dead code — v2 composites can never hit an empty-iv legacy row). Real race handled instead: duplicate-key on `insert_attachment_hash` → re-fetch hash, `delete_from_s3(chunked/{own_sid})`, mint from existing row.
9. **(MINOR, §4 complete)** Dedupe is a plain hit/miss — do NOT transplant `upload_file`'s stale-video branch (`api.rs:300–303`), which would classify every v2 chunked video as a stale record and delete its hash row.
10. **(MINOR, Stage 0)** `aead::stream` is feature-gated: the differential test needs `aes-gcm = { workspace = true, features = ["stream"] }` in dev-dependencies. (Byte-identity itself verified achievable against `aead-0.5.2` source: prefix(7) ‖ BE32(position from 0) ‖ last-flag, empty AAD.)
11. **(MINOR, §8)** No client-side 20 MiB E2EE cap currently exists (server-side only). Raising `maxSize` to 5 GB requires **adding** an encrypted-conversation branch in `Composition.tsx onFiles` (via `e2eeMode()`): clamp to ~20 MB when the conversation is (or may still resolve to) E2EE; fail-closed small cap until mode known; server blob cap remains the backstop.
12. **(NOTE, §4/§8)** Ratelimit windows are fixed 10 s. Client treats 429 distinctly: wait `X-RateLimit-Reset-After`, don't consume a backoff attempt.
13. **(NOTE, §5)** aws-sdk-s3 resolves to **1.137.0** (post checksum-defaults change) — new multipart primitives must mirror the existing working builders (`CompletedPart` = etag + part_number only) exactly; live-MinIO Stage 0 test is the proof. If checksum interop errors appear: `request_checksum_calculation = WhenRequired`, never downgrade.
14. **(NOTE, §4 DELETE)** DELETE handler only sets `state = aborted` (kills further PUTs instantly) and returns; the crond sweep performs the S3 abort + row delete with its S3-first retry semantics — avoids losing the retry row on a failed abort and the in-flight-PUT-vs-abort race.
