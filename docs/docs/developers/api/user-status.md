# User Status & Activity

Every user carries a **status** object that is shown to people who can see them
(friends, and others you share a server or DM with). It has three optional parts:

| Field      | Type           | Meaning                                              |
| ---------- | -------------- | ---------------------------------------------------- |
| `text`     | string         | Custom status text (max 128 chars).                  |
| `presence` | enum           | Availability: `Online`, `Idle`, `Focus`, `Busy`, `Invisible`. |
| `activity` | object         | The game or application the user is currently playing. |

All three are edited through `PATCH /users/@me` and are delivered to everyone who
can see you via a `UserUpdate` event — there is no separate endpoint for status.

## Setting a custom status

```http
PATCH /users/@me
Content-Type: application/json

{
  "status": {
    "text": "building things",
    "presence": "Focus"
  }
}
```

Status edits are **partial**: fields you omit are left untouched. To clear a field,
list it in the `remove` array rather than sending `null`:

```http
PATCH /users/@me
{ "remove": ["StatusText", "StatusPresence"] }
```

## Showing what game is being played

Set `status.activity` with the name of the game or application:

```http
PATCH /users/@me
{
  "status": {
    "activity": { "name": "Celeste" }
  }
}
```

The user object returned (and the `UserUpdate` event sent to your friends) then
includes:

```json
{
  "status": {
    "activity": {
      "name": "Celeste",
      "started_at": "2026-06-29T17:42:08.000Z"
    }
  }
}
```

### `started_at` is set by the server

`started_at` lets clients render "playing for 2h"-style timers. It is
**server-authoritative**:

- When you start a game, the server stamps `started_at` to the current time.
- While you keep reporting the **same** `name`, the original `started_at` is
  preserved — editing other status fields will not reset the timer.
- When the `name` changes, `started_at` is re-stamped.

Any `started_at` value sent by the client is ignored. Only send `name`.

### Clearing the activity

```http
PATCH /users/@me
{ "remove": ["StatusActivity"] }
```

## Who can see it

Status (including `activity`) is part of your user object, so it follows the same
visibility rules as the rest of your profile: friends and users who share a server
or DM with you receive `UserUpdate` events as it changes. Users who cannot see your
profile do not receive your status. If your `presence` is `Invisible`, presence is
hidden from others, but other status fields still apply per the usual rules.
