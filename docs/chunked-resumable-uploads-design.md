# Chunked / Resumable Uploads — Design & Staged Plan

**Status:** IMPLEMENTED (2026-07-26) — superseded by ,
which carries the audited, as-built decisions (5 GB ceiling, Phases 1+2 shipped together,
versioned STREAM-AEAD v2 from the start; Phase 3 below is DROPPED, the §9 crypto column is
stale). This document remains as the original investigation record.
**Author:** drafted 2026-07-20.
**Problem:** Attachments larger than ~100 MB cannot be uploaded. Config advertises 5 GB
(`Revolt.overrides.toml` `body_limit_size` / `file_upload_size_limit` = 5_000_000_000),
but the real ceiling is ~100 MB and, below that, autumn buffers the whole file in RAM.

---

## 1. Why today's model can't scale — the two walls

Today an attachment is **one HTTP request carrying the whole file**. The client `POST`s the
entire file to `autumn` `/:tag` (`Draft.ts:410` → `api.rs:208 upload_file`), which buffers it,
encrypts it whole, and stores it. Two hard walls fall out of that:

1. **Cloudflare edge caps any single request body at ~100 MB** (Free/Pro plan). Proven by probe:
   95 MB reaches autumn (`401`), 105 MB is rejected at the edge with `413 server: cloudflare`,
   while the *same* 105 MB straight to local Caddy reaches autumn. Everything runs behind the
   named `cloudflared` tunnel, so **all** traffic crosses that edge. One-request-per-file can
   never exceed ~100 MB here.

2. **autumn holds the whole file in RAM.** After the dedupe check it does
   `read_to_end` into a `Vec<u8>` (`api.rs:332-334`), then whole-buffer AES-256-GCM encrypt
   (`encryption_impl.rs:46`). A 5 GB file = 5 GB+ resident on a 7.7 GB box → OOM. So even without
   Cloudflare, the current server cannot do multi-GB.

Big apps (WhatsApp ~2 GB, Telegram ~2–4 GB, Drive/Dropbox = true multi-GB) avoid **both** walls the
same way: they never send the whole file in one request. They **split it into small chunks**,
upload each as its own request, and reassemble server-side — with **resume** so a dropped
connection restarts from the last good chunk, not from zero. That is the technique this plan adopts.

## 2. Design in one picture

```
client                              autumn                         MinIO (S3)
  |  split file into N chunks          |                               |
  |  (each < 100 MB, so each           |                               |
  |   clears Cloudflare)               |                               |
  |                                    |                               |
  |-- POST .../upload/create --------->|  create_multipart_upload ---->|  (returns upload_id)
  |<-- {session_id, chunk_size} -------|  persist UploadSession         |
  |                                    |                               |
  |-- PUT .../part/1 (chunk bytes) --->|  stream chunk -> upload_part 1>|
  |-- PUT .../part/2 --------------->  |  ...                          |   autumn holds at most
  |   (resumable, idempotent)          |  record etag + running hash   |   ONE chunk in RAM
  |-- PUT .../part/N ----------------->|  upload_part N --------------->|
  |                                    |                               |
  |-- POST .../complete -------------->|  complete_multipart_upload --->|  (object assembled in S3)
  |                                    |  final hash, dedupe, mint File |
  |<-- { file_id } --------------------|  (used_for = None)             |
  |                                    |                               |
  |  file_id goes into the message's `attachments: string[]` exactly as today
```

The two key reuses that make this cheap:

- **S3 multipart already exists** (`s3_impl.rs:73-202`) — `create_multipart_upload` →
  `upload_part` (×N) → `complete_multipart_upload`. Today it runs entirely inside one function
  over one in-RAM buffer and the `upload_id` is thrown away. We expose those three phases and
  **persist the `upload_id`** so they can be driven across separate HTTP requests. A client chunk
  becomes an S3 part. This is the heart of the feature.
- **The claim-once `File` model is untouched.** A finished upload mints a normal `File` record
  with `used_for = None` (`files/model.rs:61`); sending the message claims it via the existing
  `attachments: string[]` → `find_and_use_attachment` path (`messages/model.rs:743`,
  `files/ops/mongodb.rs:99`). **Zero message-side changes** — the client just gets a `file_id`
  back and uses it the way it uses today's upload response.

**Chunk size.** Each chunk must be < 100 MB (Cloudflare) and ≥ 5 MiB (S3 min part size, except the
last). S3 allows 10 000 parts. Pick **32 MiB** (aligns with the existing `MULTIPART_PART_SIZE`
= 16 MiB family): 32 MiB × 10 000 = ~320 GB headroom, well clear of any target, and comfortably
under the Cloudflare cap even with multipart-form overhead.

## 3. The upload protocol (new autumn routes, all auth-gated)

Registered before the existing `/:tag` catch-all (like the `/e2ee` static routes at `api.rs:71`):

| Route | Method | Purpose |
|---|---|---|
| `/:tag/upload/create` | POST | Body = `{filename, total_size, content_type}`. Validates size against the per-tag limit (`user.limits()`), calls `create_multipart_upload`, persists an `UploadSession`, returns `{session_id, chunk_size, expires_at}`. |
| `/:tag/upload/:session_id/part/:n` | PUT | Body = raw chunk bytes (< 100 MB). Streams straight to `upload_part n`; records the part ETag + advances the running hash. **Idempotent** — re-`PUT`ting part `n` overwrites it (safe retry/resume). |
| `/:tag/upload/:session_id` | GET | Returns the set of parts already stored → lets a reconnecting client **resume** from the first missing part. |
| `/:tag/upload/:session_id/complete` | POST | `complete_multipart_upload`, finalize hash, run dedupe, mint the `File` (`used_for = None`), return `{file_id}`. |
| `/:tag/upload/:session_id` | DELETE | `abort_multipart_upload` + delete the session (user cancel). |

The `DefaultBodyLimit` on the `part` route is set to `chunk_size + slack`, **not** the 5 GB
global — so a misbehaving client can't stream an unbounded body into one request.

## 4. Data model — `UploadSession`

New collection (no existing session concept — this is greenfield). Fields:

- `_id` — session id (nanoid, like `File._id`)
- `tag`, `filename`, `content_type`, `total_size`, `uploader_id`
- `s3_upload_id`, `bucket_id`, `path` (provisional key)
- `parts: [{ n, etag, size }]` — for resume + `complete`
- `hash_state` — serialized running SHA-256 (see §6)
- `created_at`, `expires_at` — TTL-swept; ties into the **`AbortIncompleteMultipartUpload`
  bucket lifecycle rule** already owed (a crashed client leaves an S3 multipart + a session row;
  both must be reaped).

## 5. The encryption decision — the one genuinely hard part

> **Update 2026-07-20 (major simplifier):** the owner confirmed there is **no attachment corpus
> on this deployment that must be preserved yet**. The entire A-vs-B tradeoff below exists only to
> keep *existing* whole-file-GCM objects decryptable. With no legacy corpus to protect, the right
> move is neither A nor B — it's to adopt a **versioned streaming-AEAD format from the start**
> (the STREAM construction the E2EE path already uses: 1 MiB chunks with per-chunk tags, a vetted
> `aead::stream` primitive — see `e2ee.rs:37-39,354-357`). That gives at-rest encryption **and**
> chunk-by-chunk streaming **and** no hand-rolled crypto, with a `format_version` field on
> `FileHash` so any future change is clean. **Do this before a real attachment corpus accumulates.**
> The A/B discussion below is retained only in case legacy data does need preserving later.


Today autumn encrypts the whole buffer with AES-256-GCM: one random nonce, one 16-byte tag over
the entire plaintext, stored as `ciphertext ‖ tag` in one object; the read path
(`fetch_and_decrypt_file`) does whole-object GCM decrypt. **There is no format-version field**
(`FileHash` has none), so the on-S3 layout is load-bearing — change it and every existing
attachment stops decrypting. Streaming-encrypting chunk-by-chunk without holding the whole file
conflicts with that one-shot format. Two ways forward:

- **Option A — plaintext-at-rest for large chunked uploads (ship v1 fast).** Store the assembled
  object unencrypted (`iv = ""`, which the read path already treats as plaintext passthrough,
  `s3_impl.rs`). Autumn never holds the whole file; chunks stream straight to S3 parts. **Cost:**
  large attachments lose encryption-at-rest (the server-held key, *not* E2EE — this is
  defence-in-depth against someone reading the S3 bucket but not the config). Small uploads keep
  today's behaviour. Lowest risk, no new crypto.

- **Option B — format-preserving streaming GCM (correct, harder).** Re-implement the existing
  one-shot GCM as incremental (`aes` CTR + `ghash` crate), feeding each chunk as it arrives and
  emitting the final tag on the last part. Output is **byte-identical** to today's format, so old
  files still decrypt and encryption-at-rest is preserved for any size. **Cost:** hand-rolled
  crypto assembly — must be differentially fuzzed against `Aes256Gcm` one-shot across many lengths
  before it can be trusted. (This is the "Stage 3" work flagged earlier; it was premature then,
  it's exactly what this needs now.)

**Recommendation:** ship Phase 1 with **Option A**, land **Option B** as a fast-follow so large
files regain at-rest encryption without a format break. Decision needed from you (§10).

## 6. Dedupe, metadata, and what large uploads skip

- **Dedupe** is content-addressed by SHA-256 (`FileHash._id`). With chunking you don't know the
  full hash until the last chunk, so dedupe moves to **`complete`**: hash incrementally as parts
  arrive (persist the running state in the session), and at `complete` check
  `fetch_attachment_hash`. On a hit, drop the just-assembled object and point the `File` at the
  existing hash. Slightly wasteful (you uploaded before knowing), but correct and rare for large
  files.
- **Metadata / thumbnail / transcode / ClamAV** (`api.rs:337-360`) all need the whole file and are
  infeasible at multi-GB (you will not transcode a 2 GB video in-process). **Large chunked uploads
  are stored opaque** — mime from the first chunk's magic bytes only, no thumbnail, no strip, no
  transcode — exactly like the E2EE blob path treats bytes (`e2ee.rs:5-9`). Small uploads keep the
  full pipeline. This is a deliberate, documented behaviour difference, not a regression.

## 7. Client changes (`packages/client`)

The upload loop in `Draft.ts sendDraft` (`366-442`) is rewritten for the chunked path when a file
exceeds a threshold (say 90 MB); small files keep today's single-`POST`:

- Read the `File` in **slices** (`file.slice(start, end)`), never `arrayBuffer()` on the whole
  thing (today's E2EE path reads the whole file into memory at `e2ee.ts:3145` — the same slice
  discipline should apply there eventually).
- `create` → loop `PUT part/n` with limited concurrency + retry/backoff → `complete`; on
  reconnect, `GET` the session and resume from the first missing part.
- Progress becomes real (bytes across all parts), which also fixes the "100%-then-hang" UX — and
  pairs with the already-written frontend error-surfacing fix (commit `43caf7de`, still undeployed).
- `Composition.tsx onFiles` (`764`) already reads the server-advertised limit; keep it, but the
  effective ceiling becomes real instead of aspirational.

E2EE large attachments (`prepareDraftAttachments`, `e2ee.ts:3077`) are **out of scope for v1** —
that path is capped ~20 MiB (`e2ee.rs:40`), one-shot, and its STREAM-AEAD interaction with chunking
is a separate design. Phase 4.

## 8. Download side — the other half nobody sees coming

Uploading is only half the feature. Today `fetch_and_decrypt_file` reads the **whole object into
RAM** and `S3_CACHE` holds decrypted bodies up to **2 GB** (`api.rs:76-89`). Downloading a 2 GB
attachment would OOM/thrash exactly like uploading one. So the feature isn't *usable* end-to-end
until the read path streams (S3 `GetObject` body → response body, HTTP range requests for
seek/resume, and large objects bypass `S3_CACHE`). This is its own phase and gates the real ceiling.

## 9. Staged rollout

| Phase | Scope | Rough size | Unblocks |
|---|---|---|---|
| **0 — Stop the bleeding** | Client hard-cap at ~95 MB with a clear "too large" message; deploy the frontend error-surfacing fix (`43caf7de`). | S | No more mystery hangs *today*. Doesn't enable big files. |
| **1 — Chunked upload (plaintext-at-rest)** | Expose S3 multipart across requests (§3), `UploadSession` model (§4), streaming ingest, Option A crypto, opaque-store large files, chunked client. | **L** | Uploads to ~2 GB; RAM bounded by chunk size; resume. |
| **2 — Streaming download + range** | Stream `GetObject`→response, range requests, large-object cache bypass (§8). | M–L | Large files actually *downloadable*; real end-to-end. |
| **3 — Format-preserving streaming GCM** | Option B incremental GCM + differential fuzz; re-enable at-rest encryption for large files. | M | Encryption-at-rest regained without format break. |
| **4 — E2EE large attachments** | Chunked encrypted-blob path; raise E2EE blob cap. | L | Large files in E2EE DMs. |

**Target ceiling:** aim for **2 GB** through Phases 1–3 (matches WhatsApp/Telegram and keeps the
download side tractable). 5 GB is reachable but should follow once 2 GB is proven — it mostly costs
more storage planning and download-path hardening, not new architecture.

## 10. Decisions needed before Phase 1

1. **Crypto for v1:** Option A (plaintext-at-rest, ship fast) vs wait for Option B (streaming GCM,
   at-rest encryption preserved). Recommendation: A now, B as Phase 3.
2. **Target ceiling:** confirm 2 GB first (recommended) vs push straight for 5 GB.
3. **Storage budget:** multi-GB × users grows the attachment disk fast; large files already fall
   under the >20 MB / 24 h prune rule — does that stay, or do large files get a different retention?

## 11. Risks / notes

- **Bucket lifecycle rule is now a hard dependency** — crashed chunked uploads orphan S3 multipart
  state; the `AbortIncompleteMultipartUpload` rule (already owed) plus the `UploadSession` TTL are
  the cleanup. Must exist before Phase 1 ships.
- **No `tus` crate in the tree** and no axum body-streaming pattern in use — ingest is greenfield.
  Consider whether to adopt the `tus` resumable protocol (interop, client libs) or a minimal custom
  protocol (less surface). Recommendation: custom, modelled on §3 — smaller and fitted to the
  `File`/`FileHash` model.
- **`other services still on debug builds`** and the **Caddy session-token log leak** are unrelated
  but open; neither blocks this, both worth clearing first.
