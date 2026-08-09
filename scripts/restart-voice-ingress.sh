#!/usr/bin/env bash
# Restart voice-ingress onto the rebuilt binary.
#
# Kill by PID, never by pattern: a `pkill -f <path>` matches the very shell
# running it (the path is in its own command line) and kills the script instead.
#
# 🔴 And never `pgrep -x revolt-voice-ingress`: the name is 21 chars and `comm`
# is truncated to 15, so it matches NOTHING. This script used to do that, which
# meant the kill was a silent no-op -- it "restarted" by leaving the old process
# running and letting the new one die on AddrInUse. Take the pid from the
# LISTENING SOCKET instead, which is unambiguous.
#
# 🔴 And never `setsid nohup ... &`: backgrounding with & inside a `wsl.exe`
# invocation is silently REAPED when the session tears down (this cost real prod
# downtime on delta, 2026-08-07). `setsid --fork` in the FOREGROUND forks, the
# parent exits so the shell returns, and the child survives.
set -uo pipefail
cd /home/mcp/stoatchat || exit 1

LOG=/tmp/svc-voice-ingress.log

port_pid() {
  ss -ltnpH 'sport = :8500' 2>/dev/null | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2
}

old=$(port_pid)
if [ -n "${old:-}" ]; then
  # Never kill a stranger: confirm the pid on :8500 really is voice-ingress.
  exe=$(readlink /proc/"$old"/exe 2>/dev/null)
  case "$exe" in
    *revolt-voice-ingress*) ;;
    *) echo ":8500 held by something else ($exe) -- refusing to kill."; exit 3 ;;
  esac

  echo "stopping old voice-ingress pid $old"
  kill "$old" 2>/dev/null
  for _ in $(seq 1 20); do
    kill -0 "$old" 2>/dev/null || break
    sleep 1
  done
  kill -0 "$old" 2>/dev/null && { echo "still alive, SIGKILL"; kill -9 "$old"; sleep 2; }
fi

# Wait for the PORT to free, not just the process to vanish -- starting into a
# still-bound socket is how this fails.
for _ in $(seq 1 15); do
  [ -z "$(port_pid)" ] && break
  sleep 1
done
if [ -n "$(port_pid)" ]; then
  echo ":8500 still bound by $(port_pid) -- NOT starting a second instance."
  exit 4
fi

setsid --fork ./target/release/revolt-voice-ingress >> "$LOG" 2>&1 < /dev/null
sleep 10

new=$(port_pid)
echo "=== running ==="
if [ -z "${new:-}" ]; then
  echo "  !! NOTHING LISTENING ON :8500 -- start failed, see the log below"
else
  ps -o pid,ppid,lstart,args -p "$new" | sed 's/^/  /'
fi
echo "=== screen_video present in the RUNNING inode (positive control) ==="
[ -n "${new:-}" ] && grep -c -a -m1 screen_video "/proc/$new/exe" 2>/dev/null
echo "=== boot log ==="
tail -8 "$LOG"
echo "=== webhook endpoint (401 = up, auth-gated) ==="
curl -s -o /dev/null -w "  POST /worldwide -> %{http_code}\n" -X POST \
  -H "Content-Type: application/webhook+json" -d '{}' http://127.0.0.1:8500/worldwide
echo "NB: verify from a SECOND, SEPARATE wsl.exe call -- surviving this session proves nothing."
echo INGRESS_RESTART_DONE
