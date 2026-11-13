#!/usr/bin/env bash
# One-off, four-connection cURL receiver. No account or PortHub installation.
if [ "$#" -lt 1 ]; then printf "Usage: bash receive.sh DOWNLOAD_URL [OUTPUT_FILE]\n" >&2; exit 1; fi
# Run in Bash. Four connections download separate byte ranges.
(
  set -e
  PORTHUB_URL="$1"
  PORTHUB_OUT="${2:-}"
  PORTHUB_AUTO_NAME=0
  PORTHUB_PARTS=4
  PORTHUB_HEADERS=$(curl -fsSI -- "$PORTHUB_URL")
  PORTHUB_SIZE=$(printf '%s\n' "$PORTHUB_HEADERS" | awk 'tolower($1)=="content-length:" {gsub("\r","",$2); print $2}')
  if [ -z "$PORTHUB_OUT" ]; then
    PORTHUB_AUTO_NAME=1
    PORTHUB_OUT=$(printf '%s\n' "$PORTHUB_HEADERS" | sed -n 's/^[Cc]ontent-[Dd]isposition:.*filename="\([^"]*\)".*/\1/p' | tail -n 1)
    PORTHUB_OUT=${PORTHUB_OUT##*/}
    case "$PORTHUB_OUT" in ''|.|..|*\\*|*[[:cntrl:]]*) printf 'Could not read a safe filename. Specify an output file.\n' >&2; exit 1;; esac
    if [ -e "$PORTHUB_OUT" ]; then printf 'File already exists: %s\n' "$PORTHUB_OUT" >&2; exit 1; fi
  fi
  case "$PORTHUB_SIZE" in ''|*[!0-9]*) printf 'Could not read file size\n' >&2; exit 1;; esac
  if [ "$PORTHUB_SIZE" -eq 0 ]; then
    if [ "$PORTHUB_AUTO_NAME" -eq 1 ]; then (set -C; : > "$PORTHUB_OUT"); else : > "$PORTHUB_OUT"; fi
    exit 0
  fi
  PORTHUB_TMP=$(mktemp -d)
  trap 'for PORTHUB_PID in $PORTHUB_PIDS; do kill "$PORTHUB_PID" 2>/dev/null || true; done; rm -rf -- "$PORTHUB_TMP"' EXIT
  PORTHUB_PIDS=""
  PORTHUB_CHUNK=$(( (PORTHUB_SIZE + PORTHUB_PARTS - 1) / PORTHUB_PARTS ))
  for ((i=0; i<PORTHUB_PARTS; i++)); do
    PORTHUB_START=$((i * PORTHUB_CHUNK))
    [ "$PORTHUB_START" -lt "$PORTHUB_SIZE" ] || break
    PORTHUB_END=$((PORTHUB_START + PORTHUB_CHUNK - 1))
    [ "$PORTHUB_END" -lt "$PORTHUB_SIZE" ] || PORTHUB_END=$((PORTHUB_SIZE - 1))
    curl -fSL --retry 3 --range "$PORTHUB_START-$PORTHUB_END" -o "$PORTHUB_TMP/$i" -- "$PORTHUB_URL" &
    PORTHUB_PIDS="$PORTHUB_PIDS $!"
  done
  for PORTHUB_PID in $PORTHUB_PIDS; do wait "$PORTHUB_PID"; done
  PORTHUB_PIDS=""
  : > "$PORTHUB_TMP/combined"
  for ((j=0; j<i; j++)); do cat "$PORTHUB_TMP/$j" >> "$PORTHUB_TMP/combined"; done
  if [ "$PORTHUB_AUTO_NAME" -eq 1 ]; then
    mv -n -- "$PORTHUB_TMP/combined" "$PORTHUB_OUT"
    if [ -e "$PORTHUB_TMP/combined" ]; then printf 'File already exists: %s\n' "$PORTHUB_OUT" >&2; exit 1; fi
  else
    mv -- "$PORTHUB_TMP/combined" "$PORTHUB_OUT"
  fi
)
