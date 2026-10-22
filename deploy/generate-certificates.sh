#!/bin/sh
# Create a local development certificate beside this deployment script.
set -eu
hostname="${1:-localhost}"
case "$hostname" in
  ''|*[!A-Za-z0-9.-]*) printf 'Usage: %s [hostname]\n' "$0" >&2; exit 1 ;;
esac
cert_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/certificates"
mkdir -p "$cert_dir"
if [ -e "$cert_dir/server.crt" ] || [ -e "$cert_dir/server.key" ]; then
  printf 'Certificate files already exist in %s; refusing to overwrite them.\n' "$cert_dir" >&2
  exit 1
fi
umask 077
openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes \
  -out "$cert_dir/server.crt" -keyout "$cert_dir/server.key" \
  -subj "/CN=$hostname" -addext "subjectAltName=DNS:$hostname"
printf 'Created development certificate for %s in %s\n' "$hostname" "$cert_dir"
