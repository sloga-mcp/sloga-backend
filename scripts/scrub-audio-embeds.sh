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
# There is deliberately no default target. Name the database and exactly one
# of --container or --uri.
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

FILTER='{ "embeds.type": "Audio" }'

count=$(mongosh_run "db.getSiblingDB('$DB').messages.countDocuments($FILTER)")

if [ "$APPLY" -eq 0 ]; then
    echo "$count message(s) in '$DB' carry an Audio embed; re-run with --apply to remove them"
    exit 0
fi

modified=$(mongosh_run "
    db.getSiblingDB('$DB').messages
      .updateMany($FILTER, { \$pull: { embeds: { type: 'Audio' } } })
      .modifiedCount
")

remaining=$(mongosh_run "db.getSiblingDB('$DB').messages.countDocuments($FILTER)")

echo "removed Audio embeds from $modified message(s) in '$DB'; $remaining left"

if [ "$remaining" != "0" ]; then
    exit 1
fi
