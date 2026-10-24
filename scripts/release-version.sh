#!/bin/sh
# Cargo's workspace version is the release version for binaries and images.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)
if ! printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
    echo 'Workspace release version must use major.minor.patch' >&2
    exit 1
fi
printf '%s\n' "$version"
