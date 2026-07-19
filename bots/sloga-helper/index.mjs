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
const REMINDER_MIN_MS = 60_000;
const REMINDER_MAX_MS = 30 * 24 * 60 * 60 * 1000;
// Transient send failures (delta restart etc.) retry until the reminder is
// hopelessly stale — a fixed failure count would let ~75s of downtime
// silently destroy every due reminder.
const REMINDER_GIVEUP_MS = 24 * 60 * 60 * 1000;
// Interaction respond tokens die at 15min; warn while there is still slack.
const QUEUE_LATENCY_WARN_MS = 10 * 60 * 1000;
const COMMAND_SYNC_RETRY_MS = 30_000;
const NEVER_READY_WARN_THRESHOLD = 10;

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

/** @type {{version: number, reminders: Array<{id: string, channelId: string, userId: string, text: string, fireAt: number}>}} */
let state = { version: 1, reminders: [] };

function loadState() {
  try {
    const parsed = JSON.parse(readFileSync(STATE_PATH, "utf8"));
    if (parsed?.version === 1 && Array.isArray(parsed.reminders)) {
      state = parsed;
      log(`state loaded: ${state.reminders.length} pending reminder(s)`);
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
        // ordering matters for command sync).
        let retryMs = 1000;
        try {
          const body = await response.json();
          if (Number.isFinite(body?.retry_after)) retryMs = body.retry_after;
        } catch {}
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
  if (ms < REMINDER_MIN_MS || ms > REMINDER_MAX_MS) return null;
  return ms;
}

function humanDuration(ms) {
  if (ms >= 86_400_000) return `${Math.round(ms / 86_400_000)} day(s)`;
  if (ms >= 3_600_000) return `${Math.round(ms / 3_600_000)} hour(s)`;
  return `${Math.round(ms / 60_000)} minute(s)`;
}

async function respond(interaction, content, ephemeral) {
  try {
    await api("POST", `/interactions/${interaction._id}/respond`, {
      token: interaction.token,
      content,
      ephemeral: Boolean(ephemeral),
    });
  } catch (error) {
    // 410 = interaction expired (e.g. it sat >15min behind a queue stall);
    // nothing to do but log — WITHOUT the token or user content.
    log(`respond failed for interaction ${interaction._id}: ${error.status ?? error.message}`);
  }
}

async function handleInteraction(interaction) {
  if (interaction.kind !== "Command") {
    // Slice 1 ships no components; answer rather than leave the clicker
    // hanging into the 15s client timeout.
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
  schedulerTimer = setInterval(() => void fireDueReminders(), SCHEDULER_TICK_MS);
  void fireDueReminders(); // catch up anything that came due while down
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
