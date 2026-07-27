#!/usr/bin/env bash
#
# Sweep the throwaway databases left behind by the test harnesses.
#
# `TestHarness` (crates/delta/src/util/test.rs) and `database_test!`
# (crates/core/database/src/lib.rs) both delete their own database now, on the
# success path and on the unwind path. Neither can help when nextest SIGKILLs
# a test that overruns `terminate-after` (.config/nextest.toml) — a killed
# process runs no destructors — so leftovers are still possible after a run
# that timed out. This sweeps them.
#
# Why it matters: at 1191 leftover databases (observed 2026-07-27) mongod was
# slow enough that harness boot alone blew the 50s kill threshold, and the
# whole delta suite failed in a way that read as a mass code regression.
#
# Production is `revolt`. This script only ever drops names matching the two
# harness patterns, so `revolt` — and anything else — is left alone.
#
# Usage:
#   scripts/drop-test-databases.sh            # drop them
#   scripts/drop-test-databases.sh --dry-run  # just list them
#
# Override the container with MONGO_CONTAINER, or point at a mongod directly
# with MONGO_URI (requires a local mongosh).

set -euo pipefail

MONGO_CONTAINER="${MONGO_CONTAINER:-stoatchat-database-1}"
DRY_RUN=0

for arg in "$@"; do
    case "$arg" in
        --dry-run|-n) DRY_RUN=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

# `revolt_test_<digits>` from DatabaseInfo::Auto, and `crates_<path>:<line>`
# from database_test!. Anchored at both ends: `revolt` itself cannot match.
FILTER='/^revolt_test_[0-9]+$/.test(n) || /^crates_[A-Za-z0-9_]+:[0-9]+$/.test(n)'

if [ -n "${MONGO_URI:-}" ]; then
    mongosh_run() { mongosh "$MONGO_URI" --quiet --eval "$1"; }
else
    mongosh_run() { docker exec "$MONGO_CONTAINER" mongosh --quiet --eval "$1"; }
fi

names=$(mongosh_run "
    db.adminCommand({ listDatabases: 1, nameOnly: true })
      .databases.map(d => d.name)
      .filter(n => $FILTER)
      .join('\n')
")

if [ -z "$names" ]; then
    echo "no leftover test databases"
    exit 0
fi

count=$(printf '%s\n' "$names" | wc -l)

if [ "$DRY_RUN" -eq 1 ]; then
    printf '%s\n' "$names"
    echo "-- $count leftover test database(s); re-run without --dry-run to drop"
    exit 0
fi

mongosh_run "
    db.adminCommand({ listDatabases: 1, nameOnly: true })
      .databases.map(d => d.name)
      .filter(n => $FILTER)
      .forEach(n => { db.getSiblingDB(n).dropDatabase(); });
" > /dev/null

echo "dropped $count leftover test database(s)"
