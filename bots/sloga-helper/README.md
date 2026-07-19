# Sloga Helper

First-party bot daemon. Talks ONLY to the public bot APIs (`x-bot-token`
REST + bonfire WebSocket) — it is deliberately shaped like a third-party
bot. Zero runtime dependencies; Node >= 22.

Commands (all global): `/coinflip`, `/8ball`, `/remind` (slice 1);
`/giveaway` (slice 2, not yet implemented).

## One-time provisioning (operator)

1. Create the bot + env file with the token-less ops bin (email verification
   is live, so operator session tokens aren't mintable from scripts; same
   pattern as seed_stickers). From the stoatchat root, in WSL:

       CARGO_BUILD_JOBS=2 cargo run -p revolt-autumn --bin provision_sloga_helper -- \
         <owner_user_id> SlogaHelper /home/mcp/secrets/sloga-helper.env

   This creates the bot (public), and writes the env file 0600 with
   SLOGA_HELPER_BOT_ID + SLOGA_HELPER_TOKEN — the token is never printed.
   Optional overrides in the same file:

       # API_URL=http://127.0.0.1:14702
       # WS_URL=ws://127.0.0.1:14703

2. Add the bot to the client catalog in
   `/home/mcp/stoatchat/Revolt.overrides.toml` (placement matters — this is
   an array-of-tables under `[api]`; keep it grouped with the other
   `[[api.…]]` blocks at the end of the file):

       [[api.apps.catalog]]
       bot_id = "<bot id>"
       tagline = "Reminders, giveaways and fun"

   Then restart delta so the config reloads.

3. Launch (start-sloga.sh does this on boot):

       nohup node /home/mcp/stoatchat/bots/sloga-helper/index.mjs \
         >> /home/mcp/logs/sloga-helper.log 2>&1 &

State (`sloga-helper.state.json`), lockfile and env all live in
`/home/mcp/secrets/`. The daemon self-registers/updates its slash commands
on every boot (requires the "bots manage their own commands" backend
change). Commands self-heal on reconnect if delta was still booting.

The token must never appear in argv or logs — the env file is the only
place it lives. On boot the daemon refuses to start if another instance
holds the lockfile (double-launch would double-fire reminders).
