#!/bin/sh
set -eu

# Keep only the active 2 MiB log and one previous segment. The small overshoot
# between checks is bounded by five seconds of traffic. USR1 reopens the file
# without restarting Traefik or dropping connections.
/entrypoint.sh "$@" &
traefik_pid=$!
(
  while kill -0 "$traefik_pid" 2>/dev/null; do
    sleep 5
    if [ -f /shared/access.log ] && [ "$(stat -c %s /shared/access.log)" -ge 2097152 ]; then
      if mv -f /shared/access.log /shared/access.log.1; then
        kill -USR1 "$traefik_pid" 2>/dev/null || true
      else
        echo "PortHub: access log rotation failed; retrying" >&2
      fi
    fi
  done
) &
rotation_pid=$!
trap 'kill -TERM "$traefik_pid" "$rotation_pid" 2>/dev/null || true' TERM INT
status=0
wait "$traefik_pid" || status=$?
kill -TERM "$rotation_pid" 2>/dev/null || true
wait "$rotation_pid" 2>/dev/null || true
exit "$status"
