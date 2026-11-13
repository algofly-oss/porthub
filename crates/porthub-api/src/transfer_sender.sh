#!/usr/bin/env bash
# One-off PortHub sender. No installation, account credentials or server storage.
set -u
porthub_file=${1:-}
porthub_base=${2:-}
porthub_http=${3:-curl}
if [ ! -f "$porthub_file" ] || [ -z "$porthub_base" ]; then
  printf 'Usage: bash sender.sh FILE PORTHUB_URL [curl|wget]\n' >&2; exit 2
fi
porthub_base=${porthub_base%/}
porthub_pids=''
porthub_tmp=''
porthub_id=''
porthub_key=''
porthub_cleanup() {
  trap - EXIT INT TERM
  for porthub_pid in $porthub_pids; do kill "$porthub_pid" 2>/dev/null || true; done
  if [ -n "$porthub_id" ] && [ -n "$porthub_key" ]; then
    if [ "$porthub_http" = wget ]; then
      wget -qO /dev/null --timeout=3 --method=DELETE --header="X-Transfer-Key: $porthub_key" "$porthub_base/api/transfers/$porthub_id" || true
    else
      curl -fsS --max-time 3 -X DELETE -H "X-Transfer-Key: $porthub_key" "$porthub_base/api/transfers/$porthub_id" >/dev/null 2>&1 || true
    fi
  fi
  [ -z "$porthub_tmp" ] || rm -rf -- "$porthub_tmp"
}
trap porthub_cleanup EXIT
trap 'exit 130' INT TERM
porthub_size=$(wc -c < "$porthub_file" | tr -d ' ')
if [ "$porthub_http" = wget ]; then
  porthub_tmp=$(mktemp -d) || exit 1
  porthub_session=$(wget -qO- --timeout=30 --post-data='' --header="X-Transfer-Name: ${porthub_file##*/}" --header="X-Transfer-Size: $porthub_size" "$porthub_base/api/transfers") || exit 1
else
  porthub_session=$(curl -fsS --max-time 30 -X POST -H "X-Transfer-Name: ${porthub_file##*/}" -H "X-Transfer-Size: $porthub_size" "$porthub_base/api/transfers") || exit 1
fi
read -r porthub_id porthub_key <<< "$porthub_session"
[ -n "$porthub_id" ] && [ -n "$porthub_key" ] || exit 1
printf 'Download: %s/api/transfers/%s\nKeep this sender running. Press Ctrl+C to stop.\n' "$porthub_base" "$porthub_id"
porthub_worker() {
  trap - EXIT INT TERM
  porthub_worker_id=$1
  while :; do
    if [ "$porthub_http" = wget ]; then
      porthub_job=$(wget -qSO- --timeout=30 --header="X-Transfer-Key: $porthub_key" "$porthub_base/api/transfers/$porthub_id/next" 2>"$porthub_tmp/$porthub_worker_id.headers"); porthub_code=$?
      porthub_status=$(awk '/^[[:space:]]*HTTP\// {code=$2} END {print code}' "$porthub_tmp/$porthub_worker_id.headers")
    else
      porthub_reply=$(curl -sS --max-time 30 -w '\n%{http_code}' -H "X-Transfer-Key: $porthub_key" "$porthub_base/api/transfers/$porthub_id/next"); porthub_code=$?
      porthub_status=${porthub_reply##*$'\n'}
      porthub_job=${porthub_reply%$'\n'*}
    fi
    case "$porthub_status" in 403|404|410) return;; esac
    [ "$porthub_code" -eq 0 ] && { [ "$porthub_status" = 200 ] || [ "$porthub_status" = 204 ]; } || { sleep 1; continue; }
    [ -n "$porthub_job" ] || continue
    read -r porthub_request porthub_offset porthub_length <<< "$porthub_job"
    case "$porthub_request" in ''|*[!A-Za-z0-9_-]*) continue;; esac
    case "$porthub_offset:$porthub_length" in *[!0-9:]*) continue;; esac
    if [ "$porthub_http" = wget ]; then
      # Wget requires a regular upload file. Only this bounded local chunk is temporary.
      tail -c "+$((porthub_offset + 1))" "$porthub_file" 2>/dev/null | head -c "$porthub_length" > "$porthub_tmp/$porthub_worker_id"
      wget -qO /dev/null --timeout=60 --post-file="$porthub_tmp/$porthub_worker_id" --header="X-Transfer-Key: $porthub_key" "$porthub_base/api/transfers/$porthub_id/chunks/$porthub_request" || true
    else
      tail -c "+$((porthub_offset + 1))" "$porthub_file" 2>/dev/null | head -c "$porthub_length" |
        curl -fsS --max-time 60 -X PUT -H "X-Transfer-Key: $porthub_key" --data-binary @- "$porthub_base/api/transfers/$porthub_id/chunks/$porthub_request" >/dev/null || true
    fi
  done
}
for porthub_worker_id in 1 2 3 4 5 6 7 8; do porthub_worker "$porthub_worker_id" & porthub_pids="$porthub_pids $!"; done
wait
