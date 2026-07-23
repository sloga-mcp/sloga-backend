#!/bin/bash
# Total downloads from sloga.gg, counted server-side.
#
# Source: /var/log/caddy-downloads.log, written by the /dl/* block in
# /home/mcp/stoatchat/Caddyfile. Only 302s are counted — one per click that was
# handed a real file URL. Rotated logs are included, so this is a running total.
#
# NOT counted: desktop/Linux auto-updaters, which fetch /updates/* directly and
# never pass through /dl/*. These are human downloads only.

python3 - <<'PY'
import glob, gzip, json, sys, collections, datetime

names = {
    "/dl/windows":        "Windows (.exe)",
    "/dl/linux-deb":      "Linux (.deb)",
    "/dl/linux-appimage": "Linux (AppImage)",
    "/dl/android":        "Android (.apk)",
}
counts = collections.Counter()
first = last = None

for path in sorted(glob.glob("/var/log/caddy-downloads.log*")):
    opener = gzip.open if path.endswith(".gz") else open
    try:
        with opener(path, "rt", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                uri = entry.get("request", {}).get("uri", "")
                if not uri.startswith("/dl/") or entry.get("status") != 302:
                    continue
                counts[uri] += 1
                ts = entry.get("ts")
                if ts:
                    first = ts if first is None else min(first, ts)
                    last = ts if last is None else max(last, ts)
    except PermissionError:
        sys.exit("cannot read %s — try: wsl -u root %s" % (path, sys.argv[0]))

if not counts:
    print("No downloads recorded yet.")
    raise SystemExit

stamp = lambda t: datetime.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")
width = max(len(v) for v in names.values()) + 4
print("Downloads since %s   (most recent: %s)\n" % (stamp(first), stamp(last)))

for uri, label in names.items():
    print("  %-*s %6d" % (width, label, counts[uri]))
for uri, n in sorted(counts.items()):
    if uri not in names:
        print("  %-*s %6d" % (width, uri + "  (retired link)", n))

print("  %s" % ("-" * (width + 7)))
print("  %-*s %6d" % (width, "TOTAL", sum(counts.values())))
PY
