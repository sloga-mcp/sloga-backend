#!/usr/bin/env bash
#
# Remove Audio embeds from stored messages.
#
# This is the escape hatch for rolling delta, bonfire, crond or pushd back to a
# build that predates Embed::Audio. Those builds cannot decode a message that
# carries an Audio embed: a release build silently drops it from channel
# history, a single fetch errors, and bonfire drops the socket on the append
# event. So before any such rollback:
#
#   1. set REVOLT__JANUARY__AUDIO_EMBEDS=false and restart january
#      (that also empties its 60s embed cache)
#   2. run this script with --apply
#   3. only then roll the other services back
#
# The links themselves stay in the message text; only the player goes away.
#
# Two collections store embeds: `messages`, and `safety_snapshots`, whose
# message snapshots carry the reported message plus its prior and leading
# context. Moderators lose a report's evidence if those are left behind.
#
# There is deliberately no default target. Name the database and exactly one
# of --container or --uri. Prefer --container: a --uri with credentials is
# visible in the process list.
#
# Usage:
#   scripts/scrub-audio-embeds.sh --db revolt --container stoatchat-database-1
#   scripts/scrub-audio-embeds.sh --db revolt --uri mongodb://host:27017 --apply
#
# Without --apply it only counts the affected messages.

set -euo pipefail

DB=""
CONTAINER=""
URI=""
APPLY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --db) DB="${2:-}"; shift 2 ;;
        --container) CONTAINER="${2:-}"; shift 2 ;;
        --uri) URI="${2:-}"; shift 2 ;;
        --apply) APPLY=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ -z "$DB" ]; then
    echo "--db is required" >&2
    exit 2
fi

if [ -n "$CONTAINER" ] && [ -n "$URI" ]; then
    echo "pass --container or --uri, not both" >&2
    exit 2
elif [ -n "$CONTAINER" ]; then
    mongosh_run() { docker exec "$CONTAINER" mongosh --quiet --eval "$1"; }
elif [ -n "$URI" ]; then
    mongosh_run() { mongosh "$URI" --quiet --eval "$1"; }
else
    echo "--container or --uri is required" >&2
    exit 2
fi

if ! [[ "$DB" =~ ^[A-Za-z0-9_-]+$ ]]; then
    echo "invalid database name: $DB" >&2
    exit 2
fi

MESSAGES='{ "embeds.type": "Audio" }'
SNAPSHOTS='{ $or: [
    { "content.embeds.type": "Audio" },
    { "content._prior_context.embeds.type": "Audio" },
    { "content._leading_context.embeds.type": "Audio" }
] }'

check_counts() {
    if ! [[ "$1" =~ ^[0-9]+$ && "$2" =~ ^[0-9]+$ ]]; then
        echo "could not count Audio embeds in '$DB'" >&2
        exit 1
    fi
}

count_all() {
    mongosh_run "
        const d = db.getSiblingDB('$DB');
        print(d.messages.countDocuments($MESSAGES) + ' ' +
              d.safety_snapshots.countDocuments($SNAPSHOTS));
    "
}

# A separate assignment, so a failed mongosh stops the script under `set -e`
# instead of `read` swallowing it and reporting blank counts
counts="$(count_all)"
read -r messages snapshots <<< "$counts"
check_counts "$messages" "$snapshots"

if [ "$APPLY" -eq 0 ]; then
    echo "'$DB': $messages message(s) and $snapshots report snapshot(s) carry an Audio embed; re-run with --apply to remove them"
    exit 0
fi

mongosh_run "
    const d = db.getSiblingDB('$DB');
    const audio = { type: 'Audio' };
    d.messages.updateMany($MESSAGES, { \$pull: { embeds: audio } });
    // Each path gets its own filter: \$[] fails on a document whose array
    // does not exist (user and server snapshots have no context arrays).
    d.safety_snapshots.updateMany(
        { 'content.embeds.type': 'Audio' },
        { \$pull: { 'content.embeds': audio } });
    d.safety_snapshots.updateMany(
        { 'content._prior_context.embeds.type': 'Audio' },
        { \$pull: { 'content._prior_context.\$[].embeds': audio } });
    d.safety_snapshots.updateMany(
        { 'content._leading_context.embeds.type': 'Audio' },
        { \$pull: { 'content._leading_context.\$[].embeds': audio } });
" > /dev/null

counts="$(count_all)"
read -r messages_left snapshots_left <<< "$counts"
check_counts "$messages_left" "$snapshots_left"

echo "'$DB': removed Audio embeds from $messages message(s) and $snapshots report snapshot(s); $messages_left and $snapshots_left left"

if [ "$messages_left" != "0" ] || [ "$snapshots_left" != "0" ]; then
    exit 1
fi
