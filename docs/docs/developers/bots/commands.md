---
sidebar_position: 2
---

# Slash Commands

A command is a typed entry point into your bot. Register it once and it appears
in the `/` picker for everyone who can see a channel your bot is in.

Commands are managed with either the owner's session or the bot's own token, so
a bot can register its own commands on startup. That is usually what you want:
keep the list in code and reconcile it against the server every time you boot.

## Register a command

```http
POST /bots/{bot_id}/commands
```

```json
{
  "name": "8ball",
  "description": "Ask the magic 8-ball a question",
  "options": [
    {
      "name": "question",
      "description": "Your yes/no question",
      "kind": "String",
      "required": true
    }
  ]
}
```

The response is the stored command, including its `_id`. Names must be unique
per bot per scope, so re-registering an existing name is an error — list what
is already there and `PATCH` it instead.

| Field | Rules |
| ----- | ----- |
| `name` | 1–32 characters, matching `^[a-z0-9_-]+$` |
| `description` | 1–100 characters |
| `server` | Optional. Omit for a global command |
| `options` | Up to 10 |

## Scope

A command with no `server` is global: it works anywhere your bot is. A command
with `server` set only appears in that one server, and invoking it anywhere else
is rejected.

Use server scope for things that only make sense in one community, and to
iterate without waiting for a global change to matter everywhere.

## Options

Options are the arguments to your command.

| Field | Rules |
| ----- | ----- |
| `name` | 1–32 characters, same charset as command names, unique within the command |
| `description` | 1–100 characters |
| `kind` | `String`, `Integer`, `Boolean`, `User` or `Channel` |
| `required` | Optional, defaults to `false` |
| `choices` | Optional, up to 25 fixed values |
| `autocomplete` | Optional. Ask your bot for suggestions as the user types |

Values arrive as strings, whatever the kind. The server validates them against
the kind before your bot ever sees them: an `Integer` really parses as an
integer, a `Boolean` is `"true"` or `"false"`, and `User` and `Channel` are ids.

### Fixed choices

When the valid values are a short known list, state them. The client offers them
as a dropdown and the server rejects anything else, so your bot does not need to
handle a bad value at all.

```json
{
  "name": "difficulty",
  "description": "How hard should it be",
  "kind": "String",
  "choices": [
    { "name": "Easy", "value": "easy" },
    { "name": "Hard", "value": "hard" }
  ]
}
```

`choices` is only valid on `String` and `Integer` options.

### Dynamic suggestions

When the list is long, or depends on who is asking, set `autocomplete` instead
and answer as the user types. This is covered in
[Interactions](./interactions.md#autocomplete).

```json
{
  "name": "track",
  "description": "Which track to queue",
  "kind": "String",
  "autocomplete": true
}
```

An option cannot use both `choices` and `autocomplete` — a fixed list is already
the complete set of answers.

## List, edit and delete

```http
GET /bots/{bot_id}/commands
```

Returns every command the bot has registered, global and server-scoped.

```http
PATCH /bots/{bot_id}/commands/{command_id}
```

```json
{
  "description": "Ask the 8-ball anything"
}
```

Send only what changes. Passing `options` replaces the whole list.

```http
DELETE /bots/{bot_id}/commands/{command_id}
```

Deleting the bot deletes its commands too.

## What users see

Commands a user can actually run in a channel are fetched by the client:

```http
GET /channels/{channel_id}/commands
```

This returns the merged global and server-scoped list, filtered to bots that are
actually present in that channel. A command whose bot has been kicked stops
appearing, and stops being invocable.

Commands are not offered in DMs or saved messages at all. See
[Interactions](./interactions.md#where-interactions-do-not-work).

## Limits

| Limit | Value |
| ----- | :---: |
| Global commands per bot | 100 |
| Commands per bot per server | 100 |
| Options per command | 10 |
| Choices per option | 25 |
| Length of a supplied option value | 2000 |

Command registration has its own rate limit bucket (`bot_commands`, 10 per 10
seconds), so a bot that syncs a large command list on boot should expect to
pace itself.
