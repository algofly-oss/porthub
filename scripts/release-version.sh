#!/bin/sh
# Cargo's workspace version identifies the release carrier and server images.
# The core executable has its own version in crates/porthub-agent/Cargo.toml.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)
if ! printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
    echo 'Workspace release version must use major.minor.patch' >&2
    exit 1
fi
printf '%s\n' "$version"
