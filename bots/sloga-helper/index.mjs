#!/usr/bin/env node
// Sloga Helper — the first-party bot daemon.
//
// Deliberately an EXTERNAL-style bot: it only ever talks to the public bot
// APIs (x-bot-token REST + bonfire WebSocket), so it doubles as a living
// proof-of-concept for third-party bot developers. Zero runtime deps;
// requires Node >= 22 (global WebSocket, fetch).
//
// Secrets/state live OUTSIDE the repo (see README.md). The bot token must
// never appear in argv or logs.

import { readFileSync, writeFileSync, renameSync, unlinkSync } from "node:fs";
import { dirname, join } from "node:path";
import { randomInt, randomUUID } from "node:crypto";
import process from "node:process";

// ---------------------------------------------------------------- config --

const ENV_PATH =
  process.env.SLOGA_HELPER_ENV ?? "/home/mcp/secrets/sloga-helper.env";
const ENV_DIR = dirname(ENV_PATH);
const STATE_PATH = join(ENV_DIR, "sloga-helper.state.json");
const LOCK_PATH = join(ENV_DIR, "sloga-helper.lock");

function loadEnvFile(path) {
  const out = {};
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    fatal(`cannot read env file at ${path}`);
  }
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq < 1) continue;
    out[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
  }
  return out;
}

const env = loadEnvFile(ENV_PATH);
const BOT_TOKEN = env.SLOGA_HELPER_TOKEN;
const BOT_ID = env.SLOGA_HELPER_BOT_ID;
const API_URL = env.API_URL ?? "http://127.0.0.1:14702";
const WS_URL = env.WS_URL ?? "ws://127.0.0.1:14703";
if (!BOT_TOKEN || !BOT_ID) {
  fatal("SLOGA_HELPER_TOKEN and SLOGA_HELPER_BOT_ID must be set in the env file");
}

// Pacing/limits. Server buckets: interaction respond 30/10s, messages
// 10/10s PER CHANNEL — one paced global queue keeps us safely under both
// without per-bucket bookkeeping.
const REST_GAP_MS = 400;
const PING_INTERVAL_MS = 20_000;
const PONG_DEADLINE_MS = 45_000;
const SCHEDULER_TICK_MS = 15_000;
// Shared by /remind and /giveaway durations.
const DURATION_MIN_MS = 60_000;
const DURATION_MAX_MS = 30 * 24 * 60 * 60 * 1000;
// Transient send failures (delta restart etc.) retry until the reminder is
// hopelessly stale — a fixed failure count would let ~75s of downtime
// silently destroy every due reminder.
const REMINDER_GIVEUP_MS = 24 * 60 * 60 * 1000;
// Interaction respond tokens die at 15min; warn while there is still slack.
const QUEUE_LATENCY_WARN_MS = 10 * 60 * 1000;
const COMMAND_SYNC_RETRY_MS = 30_000;
const NEVER_READY_WARN_THRESHOLD = 10;
// Giveaway entry-count display edits are content-only PATCHes, throttled to
// at most one edit per giveaway per this window (messages bucket is 10/10s
// per channel — a click-storm degrades to slower counter updates).
const GIVEAWAY_EDIT_THROTTLE_MS = 5_000;
const GIVEAWAY_MAX_WINNERS = 20;
const GIVEAWAY_MAX_PRIZE_LEN = 256;

// ----------------------------------------------------------------- utils --

function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

function fatal(message) {
  console.error(new Date().toISOString(), "FATAL:", message);
  process.exit(1);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// ------------------------------------------------------- single instance --

function pidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function acquireLock() {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      // Single atomic create+write: a concurrent reader can never observe
      // an empty lockfile (pid 0 ≠ alive) and steal the lock.
      writeFileSync(LOCK_PATH, String(process.pid), { flag: "wx" });
      return;
    } catch (error) {
      if (error.code !== "EEXIST") fatal(`cannot create lockfile: ${error.code}`);
      let existing = NaN;
      try {
        existing = Number(readFileSync(LOCK_PATH, "utf8"));
      } catch {}
      if (Number.isInteger(existing) && existing > 0 && pidAlive(existing)) {
        // A double-launched daemon would double-fire reminders — refuse.
        fatal(`another instance is running (pid ${existing})`);
      }
      try {
        unlinkSync(LOCK_PATH);
      } catch {}
    }
  }
  fatal("could not acquire lockfile");
}

function releaseLock() {
  try {
    if (Number(readFileSync(LOCK_PATH, "utf8")) === process.pid) {
      unlinkSync(LOCK_PATH);
    }
  } catch {}
}

// ------------------------------------------------------------------ state --

/**
 * @type {{
 *   version: number,
 *   reminders: Array<{id: string, channelId: string, userId: string, text: string, fireAt: number}>,
 *   giveaways: Array<{id: string, messageId: string, channelId: string, creatorId: string,
 *     prize: string, winnersWanted: number, endAt: number, entrants: string[], lastCountEditAt: number}>,
 *   tombstones: Array<{messageId: string, channelId: string, endedContent: string,
 *     announcement: string, patched: boolean, retired: boolean, announced: boolean}>,
 * }}
 *
 * Tombstones are ended giveaways with unfinished business: `patched` = the
 * message shows the ended content, `retired` = the buttons are gone (only a
 * respond edit:true on a live click can do that — a normal message edit
 * cannot touch components), `announced` = the winner announcement posted.
 * Kept so straggler clicks retire the buttons instead of orphaning the
 * clicker into the 15s timeout, and so a crash mid-end is healed on boot.
 * Dropped once all three flags are true.
 */
let state = { version: 2, reminders: [], giveaways: [], tombstones: [] };

function loadState() {
  try {
    const parsed = JSON.parse(readFileSync(STATE_PATH, "utf8"));
    // v1 (slice 1) had reminders only — migrate by defaulting the new arrays.
    if ((parsed?.version === 1 || parsed?.version === 2) && Array.isArray(parsed.reminders)) {
      state = {
        version: 2,
        reminders: parsed.reminders,
        giveaways: Array.isArray(parsed.giveaways) ? parsed.giveaways : [],
        // Validate tombstone shape: an entry missing channelId/announcement
        // (pre-release dev state) would aim heal legs at /channels/undefined
        // and then prune, silently discarding its retirement duty.
        tombstones: (Array.isArray(parsed.tombstones) ? parsed.tombstones : [])
          .filter(
            (t) =>
              t &&
              typeof t.messageId === "string" &&
              typeof t.channelId === "string" &&
              typeof t.endedContent === "string" &&
              typeof t.announcement === "string"
          )
          .map((t) => ({
            ...t,
            patched: Boolean(t.patched),
            retired: Boolean(t.retired),
            announced: Boolean(t.announced),
          })),
      };
      log(
        `state loaded: ${state.reminders.length} reminder(s), ` +
          `${state.giveaways.length} giveaway(s), ${state.tombstones.length} tombstone(s)`
      );
    } else {
      log("state file has unknown shape — starting fresh");
    }
  } catch {
    log("no state file — starting fresh");
  }
}

function saveState() {
  // Atomic: same-directory temp + rename.
  const tmp = `${STATE_PATH}.tmp`;
  writeFileSync(tmp, JSON.stringify(state));
  renameSync(tmp, STATE_PATH);
}

// ------------------------------------------------------- paced REST queue --

const restQueue = [];
let draining = false;

function api(method, path, body) {
  return new Promise((resolve, reject) => {
    restQueue.push({ method, path, body, resolve, reject, enqueuedAt: Date.now() });
    void drainRestQueue();
  });
}

async function drainRestQueue() {
  if (draining) return;
  draining = true;
  while (restQueue.length > 0) {
    const item = restQueue[0];
    const age = Date.now() - item.enqueuedAt;
    if (age > QUEUE_LATENCY_WARN_MS) {
      // Interaction responds expire at 15min — this queue should never get
      // anywhere near that; if it does, something upstream is storming.
      log(`REST queue latency high: ${Math.round(age / 1000)}s (${restQueue.length} queued)`);
    }
    try {
      const response = await fetch(`${API_URL}${item.path}`, {
        method: item.method,
        headers: {
          "x-bot-token": BOT_TOKEN,
          "content-type": "application/json",
        },
        body: item.body === undefined ? undefined : JSON.stringify(item.body),
      });

      if (response.status === 429) {
        // Honor retry-after and retry the SAME item (never skip ahead —
        // ordering matters for command sync). Delta carries the wait in the
        // X-RateLimit-Reset-After header (ms until bucket reset) — 429
        // bodies are Rocket's default, there is no retry_after JSON field.
        let retryMs = 1000;
        const resetAfter = Number(response.headers.get("x-ratelimit-reset-after"));
        if (Number.isFinite(resetAfter) && resetAfter > 0) retryMs = resetAfter;
        log(`429 on ${item.method} ${item.path} — backing off ${retryMs}ms`);
        await sleep(Math.min(retryMs + 100, 30_000));
        continue;
      }

      restQueue.shift();
      if (!response.ok) {
        const error = new Error(`${item.method} ${item.path} -> ${response.status}`);
        error.status = response.status;
        item.reject(error);
      } else {
        const text = await response.text();
        item.resolve(text ? JSON.parse(text) : null);
      }
    } catch (error) {
      // Network-level failure: reject and move on; callers decide whether
      // to retry (reminders do, interaction responds don't — they expire).
      restQueue.shift();
      item.reject(error);
    }
    await sleep(REST_GAP_MS);
  }
  draining = false;
}

// ---------------------------------------------------------- command table --

const COMMANDS = [
  {
    name: "coinflip",
    description: "Flip a coin",
    options: [],
  },
  {
    name: "8ball",
    description: "Ask the magic 8-ball a question",
    options: [
      {
        name: "question",
        description: "Your yes/no question",
        kind: "String",
        required: true,
      },
    ],
  },
  {
    name: "remind",
    description: "Set a reminder in this channel",
    options: [
      {
        name: "in",
        description: "When to remind you (e.g. 10m, 2h, 3d)",
        kind: "String",
        required: true,
      },
      {
        name: "message",
        description: "What to remind you about",
        kind: "String",
        required: true,
      },
    ],
  },
  {
    name: "giveaway",
    description: "Start a giveaway in this channel",
    options: [
      {
        name: "prize",
        description: "What's being given away",
        kind: "String",
        required: true,
      },
      {
        name: "duration",
        description: "How long it runs (e.g. 10m, 2h, 3d)",
        kind: "String",
        required: true,
      },
      {
        name: "winners",
        description: "Number of winners (default 1, max 20)",
        kind: "Integer",
        required: false,
      },
    ],
  },
];

function normalizeOptions(options) {
  return JSON.stringify(
    (options ?? []).map((option) => ({
      name: option.name,
      description: option.description,
      kind: option.kind,
      required: Boolean(option.required),
      choices: option.choices ?? [],
    }))
  );
}

/** Converge registered GLOBAL commands onto COMMANDS (idempotent). */
async function syncCommands() {
  const registered = await api("GET", `/bots/${BOT_ID}/commands`);
  const globals = registered.filter((command) => !command.server);
  const byName = new Map(globals.map((command) => [command.name, command]));

  for (const desired of COMMANDS) {
    const existing = byName.get(desired.name);
    byName.delete(desired.name);
    if (!existing) {
      await api("POST", `/bots/${BOT_ID}/commands`, desired);
      log(`command registered: /${desired.name}`);
    } else if (
      existing.description !== desired.description ||
      normalizeOptions(existing.options) !== normalizeOptions(desired.options)
    ) {
      await api("PATCH", `/bots/${BOT_ID}/commands/${existing._id}`, {
        description: desired.description,
        options: desired.options,
      });
      log(`command updated: /${desired.name}`);
    }
  }

  // Retire globals we no longer declare. Server-scoped commands (none today)
  // are deliberately left alone.
  for (const [name, stale] of byName) {
    await api("DELETE", `/bots/${BOT_ID}/commands/${stale._id}`);
    log(`command removed: /${name}`);
  }
}

// ------------------------------------------------------------ interactions --

const EIGHT_BALL_ANSWERS = [
  "It is certain.",
  "Without a doubt.",
  "Yes — definitely.",
  "Most likely.",
  "Signs point to yes.",
  "Reply hazy, try again.",
  "Ask again later.",
  "Better not tell you now.",
  "Don't count on it.",
  "My reply is no.",
  "My sources say no.",
  "Very doubtful.",
];

const DURATION_RE = /^(\d{1,4})\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days)$/i;

function parseDuration(input) {
  const match = DURATION_RE.exec(input.trim());
  if (!match) return null;
  const amount = Number(match[1]);
  const unit = match[2][0].toLowerCase();
  const ms = amount * (unit === "m" ? 60_000 : unit === "h" ? 3_600_000 : 86_400_000);
  if (ms < DURATION_MIN_MS || ms > DURATION_MAX_MS) return null;
  return ms;
}

function humanDuration(ms) {
  if (ms >= 86_400_000) return `${Math.round(ms / 86_400_000)} day(s)`;
  if (ms >= 3_600_000) return `${Math.round(ms / 3_600_000)} hour(s)`;
  return `${Math.round(ms / 60_000)} minute(s)`;
}

/** Raw respond — caller handles failures (and needs the returned message). */
function respondRaw(interaction, body) {
  return api("POST", `/interactions/${interaction._id}/respond`, {
    token: interaction.token,
    ...body,
  });
}

async function respond(interaction, content, ephemeral) {
  try {
    await respondRaw(interaction, { content, ephemeral: Boolean(ephemeral) });
  } catch (error) {
    // 410 = interaction expired (e.g. it sat >15min behind a queue stall);
    // nothing to do but log — WITHOUT the token or user content.
    log(`respond failed for interaction ${interaction._id}: ${error.status ?? error.message}`);
  }
}

// -------------------------------------------------------------- giveaways --
//
// KEY PLATFORM CONSTRAINT: a normal message edit (DataEditMessage) is
// content+embeds only — components can ONLY be changed via respond
// edit:true on a live component-interaction token. So: entry counts live in
// content text (plain PATCHes suffice), End-early retires the buttons using
// the creator's own click, and a deadline draw leaves live-looking buttons
// until the first straggler click retires them (tombstones above).

function giveawayRows() {
  return [
    {
      components: [
        { type: "Button", custom_id: "gw_enter", label: "Enter 🎉", style: "Primary" },
        { type: "Button", custom_id: "gw_end", label: "End early", style: "Secondary" },
      ],
    },
  ];
}

function activeContent(gw) {
  const ends = new Date(gw.endAt).toISOString().slice(0, 16).replace("T", " ");
  const entries = gw.entrants.length === 1 ? "1 entry" : `${gw.entrants.length} entries`;
  const winners = gw.winnersWanted === 1 ? "1 winner" : `${gw.winnersWanted} winners`;
  return (
    `🎉 **GIVEAWAY** — ${gw.prize}\n` +
    `**${entries}** · ${winners} · ends **${ends} UTC**\n` +
    `Click **Enter 🎉** to enter — click again to leave.`
  );
}

function endedContent(gw, winners) {
  const header = `🎉 **GIVEAWAY ENDED** — ${gw.prize}\n`;
  if (winners.length === 0) return `${header}No entries — no winner.`;
  const label = winners.length === 1 ? "Winner" : "Winners";
  return `${header}${label}: ${winners.map((id) => `<@${id}>`).join(", ")}`;
}

/** Crypto-random draw of distinct entrants. */
function drawWinners(gw) {
  const pool = [...gw.entrants];
  const count = Math.min(gw.winnersWanted, pool.length);
  const picked = [];
  for (let i = 0; i < count; i++) {
    picked.push(pool.splice(randomInt(pool.length), 1)[0]);
  }
  return picked;
}

// Throttled content-only count edits: at most one PATCH per giveaway per
// GIVEAWAY_EDIT_THROTTLE_MS; content is computed at flush time, so a click
// burst coalesces into a single edit.
const countEditTimers = new Map(); // messageId -> Timeout

function scheduleCountEdit(gw) {
  if (countEditTimers.has(gw.messageId)) return;
  const wait = Math.max(0, GIVEAWAY_EDIT_THROTTLE_MS - (Date.now() - (gw.lastCountEditAt ?? 0)));
  countEditTimers.set(
    gw.messageId,
    setTimeout(() => {
      countEditTimers.delete(gw.messageId);
      void flushCountEdit(gw.messageId);
    }, wait)
  );
}

async function flushCountEdit(messageId) {
  const gw = state.giveaways.find((g) => g.messageId === messageId);
  if (!gw) return; // ended while the edit was pending
  gw.lastCountEditAt = Date.now();
  saveState();
  try {
    await api("PATCH", `/channels/${gw.channelId}/messages/${gw.messageId}`, {
      content: activeContent(gw),
    });
  } catch (error) {
    if (error.status === 404) {
      // Message truly gone — the giveaway can't proceed.
      log(`giveaway ${gw.id} dropped (count edit -> 404)`);
      state.giveaways = state.giveaways.filter((g) => g.id !== gw.id);
      saveState();
    }
    // Anything else (403 while the operator shuffles roles, archived
    // thread, 5xx, network) is transient for a DISPLAY-ONLY counter — the
    // entries themselves are already persisted and the next toggle
    // reschedules. Never destroy an active giveaway over it.
  }
}

/** Drop a tombstone once nothing is left to do for it. */
function pruneTombstone(tombstone) {
  if (tombstone.patched && tombstone.retired && tombstone.announced) {
    state.tombstones = state.tombstones.filter((t) => t !== tombstone);
    saveState();
  }
}

// Reentrancy guards: announce/patch legs are called from the end path, the
// straggler-click path, boot healing AND the scheduler tick — a click racing
// a deadline draw must not double-post the winner announcement (the flag
// only flips after the awaited POST resolves, so a flag check alone races).
const announcingTombstones = new Set();
const patchingTombstones = new Set();

/** Post the winner announcement (reply to the giveaway message, falling
 *  back to a plain message if the reply target is gone). */
async function announceTombstone(tombstone) {
  if (tombstone.announced || announcingTombstones.has(tombstone.messageId)) return;
  announcingTombstones.add(tombstone.messageId);
  try {
    await announceTombstoneInner(tombstone);
  } finally {
    announcingTombstones.delete(tombstone.messageId);
  }
}

async function announceTombstoneInner(tombstone) {
  try {
    await api("POST", `/channels/${tombstone.channelId}/messages`, {
      content: tombstone.announcement,
      replies: [{ id: tombstone.messageId, mention: false }],
    });
  } catch {
    try {
      await api("POST", `/channels/${tombstone.channelId}/messages`, {
        content: tombstone.announcement,
      });
    } catch (error) {
      log(
        `giveaway announcement failed for ${tombstone.messageId}: ${error.status ?? error.message}`
      );
      if (error.status !== 404) return; // transient — boot healing retries
      // 404 on a plain send = channel gone; nothing left to announce into.
    }
  }
  tombstone.announced = true;
  saveState();
  pruneTombstone(tombstone);
}

/** PATCH the ended content onto the giveaway message (content-only — the
 *  buttons stay until a live click retires them). */
async function patchTombstone(tombstone) {
  if (tombstone.patched || patchingTombstones.has(tombstone.messageId)) return;
  patchingTombstones.add(tombstone.messageId);
  try {
    await patchTombstoneInner(tombstone);
  } finally {
    patchingTombstones.delete(tombstone.messageId);
  }
}

async function patchTombstoneInner(tombstone) {
  try {
    await api("PATCH", `/channels/${tombstone.channelId}/messages/${tombstone.messageId}`, {
      content: tombstone.endedContent,
    });
    tombstone.patched = true;
    saveState();
  } catch (error) {
    log(
      `ended-content PATCH failed for ${tombstone.messageId}: ${error.status ?? error.message}`
    );
    if (error.status === 404) {
      // Message truly gone: no content to fix, no buttons left to click.
      tombstone.patched = true;
      tombstone.retired = true;
      saveState();
    }
    // Other 4xx (archived thread, transient 403) / 5xx / network: keep the
    // tombstone as-is — boot healing retries the PATCH, straggler clicks
    // still serve the ended form.
  }
  pruneTombstone(tombstone);
}

/** Boot healing: finish whatever a crash mid-end left undone. (Residual: a
 *  crash after the announcement POST but before its flag persists can
 *  double-post the announcement on the next boot — rarer and more honest
 *  than silently losing winners.) */
async function healTombstone(tombstone) {
  // Both legs no-op when already done or already in flight.
  await patchTombstone(tombstone);
  await announceTombstone(tombstone);
}

/**
 * End a giveaway: draw, tombstone, retire/PATCH the message, announce.
 * `liveInteraction` is the creator's End-early click when present — the only
 * path that can retire the buttons in the same stroke.
 */
async function endGiveaway(gw, liveInteraction) {
  // Re-check membership SYNCHRONOUSLY before drawing: the boot catch-up
  // loop iterates a snapshot and awaits between items, so a giveaway can be
  // ended (e.g. by a creator's End-early click) while its snapshot entry is
  // still queued — a second draw here would announce contradictory winners.
  if (!state.giveaways.some((g) => g.id === gw.id)) return;

  const winners = drawWinners(gw);

  const pending = countEditTimers.get(gw.messageId);
  if (pending) {
    clearTimeout(pending);
    countEditTimers.delete(gw.messageId);
  }

  // Tombstone FIRST (per plan): once this save lands, a crash can no longer
  // re-draw or orphan a click into a timeout, and boot healing finishes the
  // PATCH/announcement legs below.
  const tombstone = {
    messageId: gw.messageId,
    channelId: gw.channelId,
    endedContent: endedContent(gw, winners),
    announcement:
      winners.length > 0
        ? `🎉 Congratulations ${winners.map((id) => `<@${id}>`).join(", ")} — you won **${gw.prize}**!`
        : `🎉 The giveaway for **${gw.prize}** ended with no entries.`,
    patched: false,
    retired: false,
    announced: false,
  };
  state.giveaways = state.giveaways.filter((g) => g.id !== gw.id);
  state.tombstones.push(tombstone);
  saveState();

  if (liveInteraction) {
    try {
      // One shot: ended content + button retirement on the creator's click.
      await respondRaw(liveInteraction, {
        content: tombstone.endedContent,
        components: [],
        edit: true,
      });
      tombstone.patched = true;
      tombstone.retired = true;
      saveState();
    } catch (error) {
      log(
        `giveaway ${gw.id}: End-early retirement failed (${error.status ?? error.message}) — falling back to content PATCH`
      );
    }
  }

  await patchTombstone(tombstone);
  await announceTombstone(tombstone);
  pruneTombstone(tombstone);
}

async function handleComponent(interaction) {
  const messageId = interaction.message_id;
  const gw = state.giveaways.find((g) => g.messageId === messageId);

  if (!gw) {
    const tombstone = state.tombstones.find((t) => t.messageId === messageId);
    if (tombstone) {
      // First click after a deadline draw: use this live token to finally
      // retire the buttons for everyone.
      try {
        await respondRaw(interaction, {
          content: tombstone.endedContent,
          components: [],
          edit: true,
        });
        tombstone.patched = true;
        tombstone.retired = true;
        saveState();
      } catch (error) {
        log(`tombstone retirement failed for ${messageId}: ${error.status ?? error.message}`);
        if (error.status === 404) {
          // Message gone — no future clicks either.
          tombstone.patched = true;
          tombstone.retired = true;
          saveState();
        }
      }
      // Self-heal a still-unposted announcement while we're here (no-ops if
      // done or already in flight from the end path / a tick).
      await announceTombstone(tombstone);
      pruneTombstone(tombstone);
    } else {
      // Raced a just-finished retirement, or state was lost — either way
      // the giveaway is over for the clicker.
      await respond(interaction, "This giveaway has ended.", true);
    }
    return;
  }

  switch (interaction.custom_id) {
    case "gw_enter": {
      const index = gw.entrants.indexOf(interaction.user_id);
      let reply;
      if (index === -1) {
        gw.entrants.push(interaction.user_id);
        reply = "🎉 You're in! Click **Enter 🎉** again to leave.";
      } else {
        gw.entrants.splice(index, 1);
        reply = "Entry removed.";
      }
      saveState();
      scheduleCountEdit(gw);
      await respond(interaction, reply, true);
      return;
    }

    case "gw_end":
      if (interaction.user_id !== gw.creatorId) {
        await respond(interaction, "Only the giveaway creator can end it early.", true);
        return;
      }
      await endGiveaway(gw, interaction);
      return;

    default:
      await respond(interaction, "I can't handle that button.", true);
  }
}

async function handleInteraction(interaction) {
  if (interaction.kind === "Component") {
    await handleComponent(interaction);
    return;
  }

  if (interaction.kind !== "Command") {
    // Autocomplete/modals are later slices; answer rather than leave the
    // user hanging into the 15s client timeout.
    await respond(interaction, "I can't handle that yet.", true);
    return;
  }

  const options = interaction.options ?? {};
  switch (interaction.command_name) {
    case "coinflip":
      await respond(interaction, randomInt(2) === 0 ? "🪙 **Heads**" : "🪙 **Tails**", false);
      return;

    case "8ball":
      // Deliberately does NOT echo the question (no mention amplification);
      // the "used /8ball" header on the reply shows the invocation context.
      await respond(interaction, `🎱 ${EIGHT_BALL_ANSWERS[randomInt(EIGHT_BALL_ANSWERS.length)]}`, false);
      return;

    case "remind": {
      const ms = parseDuration(options.in ?? "");
      if (ms === null) {
        await respond(
          interaction,
          "I couldn't read that duration. Try something like `10m`, `2h` or `3d` (1 minute to 30 days).",
          true
        );
        return;
      }
      state.reminders.push({
        id: randomUUID(),
        channelId: interaction.channel_id,
        userId: interaction.user_id,
        text: (options.message ?? "").slice(0, 1500),
        fireAt: Date.now() + ms,
      });
      saveState();
      // "here": the reminder itself is a PUBLIC channel message — the
      // confirm must not suggest otherwise.
      await respond(
        interaction,
        `⏰ Got it — I'll remind you **here** in ${humanDuration(ms)}. (Reminders are posted in the channel for everyone to see.)`,
        true
      );
      return;
    }

    case "giveaway": {
      const prize = (options.prize ?? "").trim();
      if (!prize || prize.length > GIVEAWAY_MAX_PRIZE_LEN) {
        await respond(
          interaction,
          `Please give the prize a name (up to ${GIVEAWAY_MAX_PRIZE_LEN} characters).`,
          true
        );
        return;
      }
      const ms = parseDuration(options.duration ?? "");
      if (ms === null) {
        await respond(
          interaction,
          "I couldn't read that duration. Try something like `10m`, `2h` or `3d` (1 minute to 30 days).",
          true
        );
        return;
      }
      let winnersWanted = 1;
      if (options.winners !== undefined) {
        winnersWanted = Number(options.winners);
        if (
          !Number.isInteger(winnersWanted) ||
          winnersWanted < 1 ||
          winnersWanted > GIVEAWAY_MAX_WINNERS
        ) {
          await respond(
            interaction,
            `Winners must be a whole number between 1 and ${GIVEAWAY_MAX_WINNERS}.`,
            true
          );
          return;
        }
      }

      const gw = {
        id: randomUUID(),
        messageId: "",
        channelId: interaction.channel_id,
        creatorId: interaction.user_id,
        prize,
        winnersWanted,
        endAt: Date.now() + ms,
        entrants: [],
        lastCountEditAt: 0,
      };
      try {
        // The respond returns the created message — its id is what entry
        // clicks and edits key on, so persist only after we have it.
        const message = await respondRaw(interaction, {
          content: activeContent(gw),
          components: giveawayRows(),
        });
        gw.messageId = message._id;
        state.giveaways.push(gw);
        saveState();
      } catch (error) {
        // The invoker sees the standard 15s timeout; log WITHOUT the prize.
        log(`giveaway create respond failed: ${error.status ?? error.message}`);
      }
      return;
    }

    default:
      await respond(interaction, "I don't know that command.", true);
  }
}

// -------------------------------------------------------------- scheduler --

let schedulerTimer = null;

function startScheduler() {
  if (schedulerTimer) return;
  // A coarse tick instead of per-reminder setTimeout: restart-safe, and
  // immune to the ~24.8-day setTimeout overflow (30d cap > 2^31-1 ms).
  schedulerTimer = setInterval(() => {
    void fireDueReminders();
    void fireDueGiveaways();
    // Retry unfinished tombstone legs (reminder-style tick retry — boot-only
    // healing would leave a winner announcement unposted for days in a
    // quiet channel after a transient failure). Finished tombstones
    // (patched+announced, awaiting a straggler click) no-op here.
    for (const tombstone of [...state.tombstones]) void healTombstone(tombstone);
  }, SCHEDULER_TICK_MS);
  // Catch up anything that came due while down (missed giveaway deadlines
  // draw immediately, through the paced queue).
  void fireDueReminders();
  void fireDueGiveaways();
  // Self-heal entry-count displays that went stale across a restart, and
  // finish any PATCH/announcement legs a crash mid-end left undone.
  for (const gw of state.giveaways) scheduleCountEdit(gw);
  for (const tombstone of [...state.tombstones]) void healTombstone(tombstone);
}

let firing = false;

async function fireDueReminders() {
  if (firing) return;
  firing = true;
  try {
    const now = Date.now();
    for (const reminder of [...state.reminders]) {
      if (reminder.fireAt > now) continue;
      try {
        await api("POST", `/channels/${reminder.channelId}/messages`, {
          content: `<@${reminder.userId}> ⏰ Reminder: ${reminder.text}`,
        });
        state.reminders = state.reminders.filter((r) => r.id !== reminder.id);
        saveState();
      } catch (error) {
        if (error.status && error.status >= 400 && error.status < 500) {
          // Channel gone / bot kicked: drop. Log WITHOUT content.
          log(`reminder ${reminder.id} dropped (${error.status})`);
          state.reminders = state.reminders.filter((r) => r.id !== reminder.id);
          saveState();
        } else if (now - reminder.fireAt > REMINDER_GIVEUP_MS) {
          // Transient failures (network / 5xx / delta restart) retry every
          // tick; only hopeless staleness gives up.
          log(`reminder ${reminder.id} dropped (undeliverable for 24h)`);
          state.reminders = state.reminders.filter((r) => r.id !== reminder.id);
          saveState();
        }
      }
    }
  } finally {
    firing = false;
  }
}

let firingGiveaways = false;

async function fireDueGiveaways() {
  if (firingGiveaways) return;
  firingGiveaways = true;
  try {
    const now = Date.now();
    for (const gw of [...state.giveaways]) {
      if (gw.endAt > now) continue;
      await endGiveaway(gw, null);
    }
  } finally {
    firingGiveaways = false;
  }
}

// ---------------------------------------------------------------- bonfire --

let ws = null;
let lastPong = 0;
let pingTimer = null;
let reconnectAttempt = 0;
let commandsSynced = false;
let syncRetryTimer = null;
let syncInFlight = false;
let shuttingDown = false;
// Consecutive connections that closed without ever reaching Ready — the
// signature of a bad/revoked token (bonfire just drops us). We keep
// retrying (delta may simply be booting) but get LOUD about it.
let connectsWithoutReady = 0;
let sawReadyThisConnection = false;

function connect() {
  log(`connecting to ${WS_URL}`);
  // Capture the socket per connect(): a half-open socket's close event can
  // arrive MINUTES after we've already dialed a replacement (TCP timeout),
  // and without an identity check it would orphan the healthy socket and
  // dial a third — two live sockets then double-handle every interaction
  // (double reminders). Stale-socket events must no-op.
  const socket = new WebSocket(WS_URL);
  ws = socket;
  sawReadyThisConnection = false;
  const isCurrent = () => ws === socket;

  socket.addEventListener("open", () => {
    if (!isCurrent()) {
      try {
        socket.close();
      } catch {}
      return;
    }
    lastPong = Date.now();
    socket.send(JSON.stringify({ type: "Authenticate", token: BOT_TOKEN }));
  });

  socket.addEventListener("message", (event) => {
    if (!isCurrent()) return;
    let payload;
    try {
      payload = JSON.parse(String(event.data));
    } catch {
      return;
    }
    void handleEvent(payload);
  });

  socket.addEventListener("close", () => {
    if (!isCurrent()) return;
    scheduleReconnect("socket closed");
  });
  socket.addEventListener("error", () => {
    if (!isCurrent()) return;
    scheduleReconnect("socket error");
  });

  if (!pingTimer) {
    // Bonfire NEVER pings clients and presence has no TTL: a half-open
    // socket would leave this bot "online" while every invoke times out.
    // WE originate pings and hard-reconnect on a missed pong.
    pingTimer = setInterval(() => {
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      if (Date.now() - lastPong > PONG_DEADLINE_MS) {
        log("pong deadline missed — forcing reconnect");
        const dead = ws;
        ws = null; // detach FIRST so the dead socket's events no-op
        try {
          dead.close();
        } catch {}
        scheduleReconnect("pong deadline");
        return;
      }
      ws.send(JSON.stringify({ type: "Ping", data: Date.now() % 1_000_000 }));
    }, PING_INTERVAL_MS);
  }
}

async function handleEvent(event) {
  switch (event.type) {
    case "Authenticated":
      log("authenticated");
      return;

    case "Ready":
      reconnectAttempt = 0;
      connectsWithoutReady = 0;
      sawReadyThisConnection = true;
      log("ready");
      await ensureCommandsSynced();
      startScheduler();
      return;

    case "Pong":
      lastPong = Date.now();
      return;

    case "InteractionCreate":
      if (event.interaction?.bot_id === BOT_ID) {
        await handleInteraction(event.interaction);
      }
      return;

    case "Error":
      // Bonfire-level error (e.g. auth rejection) — log the TYPE only.
      log(`bonfire error event: ${event.data?.type ?? event.error?.type ?? "unknown"}`);
      return;

    default:
      // Everything else on the topic (messages etc.) is irrelevant to us.
      return;
  }
}

/** Sync commands, retrying on a timer until it succeeds (boot can beat
 *  delta, and with working keepalive the next reconnect may be days away —
 *  "retry on reconnect" alone would leave the bot command-less all that
 *  time). */
async function ensureCommandsSynced() {
  if (commandsSynced || syncInFlight) return;
  syncInFlight = true;
  if (syncRetryTimer) {
    clearTimeout(syncRetryTimer);
    syncRetryTimer = null;
  }
  try {
    await syncCommands();
    commandsSynced = true;
    log("command sync complete");
  } catch (error) {
    log(`command sync failed (${error.status ?? error.message}) — retrying in ${COMMAND_SYNC_RETRY_MS / 1000}s`);
    syncRetryTimer = setTimeout(() => {
      syncRetryTimer = null;
      if (!shuttingDown) void ensureCommandsSynced();
    }, COMMAND_SYNC_RETRY_MS);
  } finally {
    syncInFlight = false;
  }
}

let reconnectPending = false;

function scheduleReconnect(reason) {
  if (shuttingDown || reconnectPending) return;
  reconnectPending = true;
  ws = null;
  if (!sawReadyThisConnection) {
    connectsWithoutReady += 1;
    if (connectsWithoutReady === NEVER_READY_WARN_THRESHOLD) {
      // Bad/revoked token looks like an endless silent redial — get loud
      // (but keep retrying: delta may just be down for a long deploy).
      log(
        `ERROR: ${connectsWithoutReady} consecutive connections without Ready — check the bot token / delta health`,
      );
    }
  }
  reconnectAttempt += 1;
  const base = Math.min(60_000, 1000 * 2 ** Math.min(reconnectAttempt, 6));
  const delay = base + randomInt(1000);
  log(`reconnecting in ${delay}ms (${reason})`);
  setTimeout(() => {
    reconnectPending = false;
    if (!shuttingDown) connect();
  }, delay);
}

// ------------------------------------------------------------------- main --

function shutdown(signal) {
  shuttingDown = true;
  log(`${signal} — shutting down`);
  try {
    ws?.close();
  } catch {}
  releaseLock();
  process.exit(0);
}

acquireLock();
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("exit", releaseLock);

loadState();
connect();
log(`sloga-helper up (bot ${BOT_ID}, api ${API_URL})`);
