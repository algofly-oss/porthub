#!/bin/sh
# Traefik for web proxies (80/443) and the PortHub app (8345/8346), with
# access-log rotation at 2 MiB (the API reads it for proxy activity).
set -eu
LOG=/runtime/traefik-access/access.log
traefik --entrypoints.web.address=:80 --entrypoints.websecure.address=:443 \
  --entrypoints.porthub.address=:${APP_HTTP_PORT:-8345} --entrypoints.porthubsecure.address=:${APP_HTTPS_PORT:-8346} \
  --entrypoints.porthub.transport.respondingTimeouts.readTimeout=0 \
  --entrypoints.porthubsecure.transport.respondingTimeouts.readTimeout=0 \
  --providers.file.directory=/runtime/traefik --providers.file.watch=true \
  --accesslog.filepath=$LOG --accesslog.format=json &
pid=$!
trap 'kill -TERM $pid 2>/dev/null' TERM INT
while kill -0 $pid 2>/dev/null; do
  sleep 5
  if [ -f "$LOG" ] && [ "$(stat -c %s "$LOG")" -ge 2097152 ]; then
    mv -f "$LOG" "$LOG.1" && kill -USR1 $pid 2>/dev/null || true
  fi
done
wait $pid
