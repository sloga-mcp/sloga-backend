---
sidebar_position: 3
---

# Interactions

An interaction is one exchange between a user and your bot: they run a command,
click a button, or fill in a form, and your bot answers once.

The exchange always has the same shape:

1. The user does something in a channel your bot is in.
2. The server creates an interaction and sends it to your bot as an
   `InteractionCreate` event, **on your bot's connection only**.
3. Your bot answers it by id, within 15 minutes, exactly once.

## Receiving an interaction

`InteractionCreate` arrives over the WebSocket. It is never sent to a channel,
because it carries a response token that only your bot may see.

```json
{
  "type": "InteractionCreate",
  "interaction": {
    "_id": "01ABC...",
    "kind": "Command",
    "channel_id": "01ABC...",
    "user_id": "01ABC...",
    "bot_id": "01ABC...",
    "command_id": "01ABC...",
    "command_name": "8ball",
    "options": { "question": "will it work" },
    "token": "..."
  }
}
```

| Field | Meaning |
| ----- | ------- |
| `kind` | `Command`, `Component`, `Autocomplete` or `ModalSubmit` |
| `channel_id` | Where it happened |
| `user_id` | Who did it |
| `bot_id` | Which of your bots it is for |
| `token` | Single-use response token — never log or forward it |
| `options` | Supplied values, keyed by name |
| `command_name` | Name of the command that was run |
| `custom_id` | Which component was used, or which form was submitted |
| `values` | What was picked, for dropdowns |
| `message_id` | The message a component lives on |
| `focused_option` | The option being typed, for autocomplete |

Check `bot_id` against your own bot id before acting, and ignore anything else.

## Responding

```http
POST /interactions/{interaction_id}/respond
X-Bot-Token: your-token-here
```

```json
{
  "token": "the token from the event",
  "content": "Signs point to yes."
}
```

Both credentials are required: the header proves which bot you are, the body
token proves you are answering *this* interaction. The response is the message
that was created, so this is also how you learn your own message id.

Three rules govern every response:

- **15 minutes.** After that the interaction is expired and the token is dead.
- **Once.** The response slot is claimed atomically; a second attempt fails with
  `InteractionAlreadyResponded`, including when two of your workers race.
- **Still allowed.** Your bot's permissions are re-checked at response time, not
  at invocation time. A bot kicked mid-exchange cannot post.

A reply to a command is a normal channel message, tagged with who ran which
command. That tag is set by the server and cannot be sent by any other route, so
users can trust it.

### Private replies

Set `ephemeral` to answer only the person who asked:

```json
{
  "token": "...",
  "content": "Only you can see this.",
  "ephemeral": true
}
```

Ephemeral replies are never stored. They are delivered to that user's client and
are gone on reload — which is a feature for errors and confirmations, and a trap
for anything the user might want to keep. They cannot be combined with `edit` or
with components.

## Buttons and dropdowns

Attach components to any response:

```json
{
  "token": "...",
  "content": "Are you sure?",
  "components": [
    {
      "components": [
        { "type": "Button", "custom_id": "yes", "label": "Yes", "style": "Danger" },
        { "type": "Button", "custom_id": "no", "label": "No", "style": "Secondary" }
      ]
    }
  ]
}
```

Button styles are `Primary`, `Secondary`, `Success` and `Danger`. A dropdown
looks like this and must be the only component in its row:

```json
{
  "type": "StringSelect",
  "custom_id": "pick_colour",
  "placeholder": "Choose a colour",
  "options": [
    { "label": "Red", "value": "r" },
    { "label": "Blue", "value": "b" }
  ]
}
```

| Limit | Value |
| ----- | :---: |
| Rows per message | 5 |
| Buttons per row | 5 |
| Dropdowns per row | 1 |
| Options per dropdown | 25 |
| `custom_id` length | 64 |
| Button label length | 80 |

`custom_id` must be unique across the whole message. Only bots may attach
components — the normal send route rejects them.

When someone uses one, you get an interaction of kind `Component` carrying that
`custom_id`, the `message_id` it came from, and `values` for a dropdown.

### Updating the original message

Answer a component interaction with `edit` to change the message the component
is on, instead of posting a new one:

```json
{
  "token": "...",
  "content": "Confirmed.",
  "components": [],
  "edit": true
}
```

An empty `components` array removes the buttons, which is how a one-shot flow
retires itself. Note that this is the **only** way to change a message's
components — the ordinary message edit route handles content and embeds only.

## Autocomplete

For options registered with `autocomplete`, the client asks your bot for
suggestions while the user types. You get an interaction of kind `Autocomplete`
with `focused_option` naming the field being edited, and `options` holding
whatever has been typed so far.

Those values are **partial by definition** and are not validated against the
option's type — expect half-written words and a lone `-` in a number field.

Answer with a list of suggestions:

```http
POST /interactions/{interaction_id}/autocomplete
```

```json
{
  "token": "...",
  "choices": [
    { "name": "Blue Monday", "value": "track_1" },
    { "name": "Blue in Green", "value": "track_2" }
  ]
}
```

An empty list is a valid answer meaning nothing matched. At most 25 choices.

Autocomplete interactions expire after **one minute**, not fifteen — by then the
user has typed something else and the suggestions are worthless. Answer quickly
or not at all; a late answer is discarded.

## Forms

Ask for structured input by answering a command or component interaction with a
form instead of a message:

```http
POST /interactions/{interaction_id}/modal
```

```json
{
  "token": "...",
  "modal": {
    "custom_id": "report",
    "title": "Report a problem",
    "inputs": [
      {
        "custom_id": "summary",
        "label": "What happened?",
        "style": "Short",
        "required": true,
        "max_length": 100
      },
      {
        "custom_id": "detail",
        "label": "Any details",
        "style": "Paragraph",
        "placeholder": "Optional"
      }
    ]
  }
}
```

Input styles are `Short` and `Paragraph`. Up to 5 inputs, each with optional
`required`, `min_length`, `max_length`, `placeholder` and a prefilled `value`.

Opening a form **uses up** the interaction's one response, so it is an
alternative to replying, not something you do as well as replying.

The call returns the id of the interaction the completed form will arrive as,
if you want to start tracking it before the user has typed anything. Its token
is not returned — it reaches you only when the form comes back:

```json
{
  "interaction_id": "01XYZ..."
}
```

When the user submits, you receive that interaction:

```json
{
  "type": "InteractionCreate",
  "interaction": {
    "_id": "01XYZ...",
    "kind": "ModalSubmit",
    "custom_id": "report",
    "options": {
      "summary": "the button did nothing",
      "detail": ""
    },
    "token": "..."
  }
}
```

`custom_id` is the form's id and `options` holds what was typed, keyed by input
id. Every field you declared is present — one the user left blank arrives as an
empty string rather than going missing. Submissions are validated server-side
against the form you defined, so a client cannot return fields you did not ask
for, or values longer than you allowed.

Answer it like any other interaction, with its own new token and its own fresh
15-minute window.

**The options from the original command do not carry over.** A submission holds
the form's fields and nothing else, so if `/report reason:harassment` opens a
form, `reason` is not in the submission. Keep whatever you need keyed by the
interaction id the modal call returned.

A form cannot be opened from a form submission. If you need several steps, post
a message with a button and let the user choose to continue.

## Where interactions do not work

Interactions are unavailable in direct messages, saved messages and forum
containers. This is structural: a bot can never be a silent third party to a
private conversation, and conversations that may be end-to-end encrypted have no
usable interaction path at all. The client hides the `/` picker there and the
server refuses the request regardless.

In servers and groups, your bot must actually be present — a member of the
server, or a recipient of the group.

## Errors

| Error | Meaning |
| ----- | ------- |
| `BotOffline` | The bot has no live connection, so nothing would answer |
| `InteractionExpired` | Past the response window |
| `InteractionAlreadyResponded` | The single response slot is already used |
| `IsNotBot` | Only bots respond to interactions |
| `NotFound` | Unknown interaction, or one addressed to a different bot |
| `InvalidOperation` | Wrong kind of response for this interaction |
| `FailedValidation` | The payload broke one of the limits above |

Interactions addressed to another bot return `NotFound` rather than a permission
error, so ids cannot be probed for existence.

## Rate limits

| Bucket | Limit per 10s | Applies to |
| ------ | :-----------: | ---------- |
| `interaction_respond` | 30 | Your responses |
| `interaction_autocomplete` | 40 | Autocomplete, both directions |
| `interaction_create` | 10 | Command invocations, per channel |
| `message_interact` | 20 | Component clicks, per channel |

429s carry the wait in the `X-RateLimit-Reset-After` header, in milliseconds.
See [Rate Limits](../api/ratelimits.md).
