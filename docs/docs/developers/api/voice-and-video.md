# Voice & Video

Acutest provides real-time voice **and video** (camera + screen share) through
[LiveKit](https://livekit.io). The backend handles authorization and room
management; the actual media is published and rendered by the client using a
LiveKit SDK.

## Where calls can happen

Any channel that is "call-capable" can host a voice/video call:

| Channel type | Call-capable? |
| ------------ | ------------- |
| Direct message | Always |
| Group | Off by default; an owner enables calling |
| Server text/voice channel | When voice information is set on the channel |
| Saved messages | Never |

## Joining a call

```http
POST /channels/{channelId}/join_call
{ "node": "worldwide" }
```

The server checks your `Connect` permission for the channel and responds with a
short-lived token and the LiveKit node URL:

```json
{ "token": "<jwt>", "url": "wss://livekit.example" }
```

Connect to `url` with `token` using a LiveKit client. The token's grants are
derived from your channel permissions:

| Permission | Grants |
| ---------- | ------ |
| `Connect`  | Join the room |
| `Speak`    | Publish your **microphone** |
| `Video`    | Publish your **camera** and **screen share** (requires the `video` feature limit) |
| `Listen`   | Subscribe to (hear/see) others |

So a participant publishes video only if they hold `Video` and the deployment's
`limits.video` feature flag is enabled. These permissions are granted out of the
box in DMs and groups, so once a call is available, video works without extra
setup.

## Group call configuration

Group calling is **off by default**. A group's owner (or any member with
`ManageChannel`) configures it through `PATCH /channels/{groupId}` using the
`voice` object.

### Turn calling on

```http
PATCH /channels/{groupId}
{ "voice": {} }
```

Sending an empty `voice` object enables calling with no participant limit.

### Limit the number of participants

```http
PATCH /channels/{groupId}
{ "voice": { "max_users": 10 } }
```

`join_call` then refuses additional participants once the room is full (members
with `ManageChannel` may still join past the limit).

### Turn calling off for a group

```http
PATCH /channels/{groupId}
{ "voice": { "disabled": true } }
```

While disabled, the channel reports as not call-capable and `join_call` returns
`NotAVoiceChannel`; any active call is torn down.

### Reset to defaults (calling off)

```http
PATCH /channels/{groupId}
{ "remove": ["Voice"] }
```

This clears the voice configuration, returning the group to the default state
where calling is off.

## Voice state

While in a call, each participant has a voice state exposing `camera` and
`screensharing` booleans (among others), so clients can show who currently has
their camera on.
