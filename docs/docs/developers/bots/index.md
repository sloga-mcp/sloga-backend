---
sidebar_position: 1
---

# Bots

A bot is a program you run yourself. It authenticates with a bot token, holds a
WebSocket connection to the events server to hear what is happening, and calls
the REST API to act.

Nothing about a bot runs on our servers. If your process is not connected, your
bot is offline and commands addressed to it are refused immediately.

## Create a bot

Open **Settings → My Bots → Create Bot** in the client, or call the API as
yourself:

```http
POST /bots/create
```

```json
{
  "name": "my-bot"
}
```

The response contains the bot's `_id` and its `token`. The bot also gets a user
account of its own — that is the account other people see in a member list, and
the id you will compare against `bot_id` on incoming interactions.

## Authenticate

Send the token in the `X-Bot-Token` header on every request. See
[Authentication](../api/authentication.md) for how this differs from a user
session.

```http
POST /channels/01ABC.../messages
X-Bot-Token: your-token-here
Content-Type: application/json
```

Keep the token out of your command line and out of your logs — anything that
holds it can act as your bot. If one leaks, reset it from the same settings
page; the old token stops working immediately.

## Connect to the events server

Open a WebSocket to the events endpoint (see [Endpoints](../endpoints.md)) and
send an `Authenticate` event. You will get `Authenticated`, then `Ready`.

```json
{
  "type": "Authenticate",
  "token": "your-token-here"
}
```

Two things behave differently for bots than for user sessions:

- Bots receive events for everything they can see. `Subscribe` has no effect.
- Bots are not sent `policy_changes`.

**The server never pings you.** Presence has no timeout of its own, so if your
socket half-opens the server will still consider your bot online and will keep
accepting commands nothing is listening for. Send a `Ping` every 10–30 seconds
and reconnect if the matching `Pong` does not arrive:

```json
{
  "type": "Ping",
  "data": 1234
}
```

When you do reconnect, make sure the old socket's handlers cannot still fire.
A half-open connection that comes back to life will otherwise hand you the same
interaction twice, and the second response will be rejected as a replay.

## Add it to a server

A bot has to be invited before it can do anything. Anyone with **Manage Server**
can add a public bot from **Server Settings → Add apps**, or via:

```http
POST /bots/{bot_id}/invite
```

```json
{
  "server": "01ABC..."
}
```

Pass `{ "group": "01ABC..." }` instead to add it to a group. Only bots marked
`public` can be added by people other than their owner.

## What to build next

- [Slash commands](./commands.md) — register `/commands` users can run.
- [Interactions](./interactions.md) — respond to commands, add buttons and
  dropdowns, ask for input with a form.

## Limits worth knowing early

| Limit | Value |
| ----- | :---: |
| Bots per account | 5, or 2 while the account is new |
| Global commands per bot | 100 |
| Commands per bot per server | 100 |
| Time to respond to an interaction | 15 minutes, or 1 minute for autocomplete |
| Responses per interaction | 1 |

Rate limits are per bucket and documented in [Rate Limits](../api/ratelimits.md).
The ones a busy bot meets first are messages (10 per 10s **per channel**) and
interaction responses (30 per 10s).
