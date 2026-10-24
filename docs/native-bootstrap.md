# Native enrollment

The Rust API issues short-lived enrollment links, and the native agent can fetch
and save their credential profiles or activate a scoped Linux service. This is
an enrollment milestone; the complete first-install and legacy migration flow
is not ready for registered clients yet.

Owner-authenticated `GET /api/machines/command/{machine_id}` preserves the
machine, command and client-setup response fields. It also supplies
`bootstrap_url` and `native_command`. Commands contain a 16-character capability,
not the machine credential. Links expire after 24 hours and are checked against
the current credential on every use. Disable, credential rotation and retirement
revoke access. Existing valid public Go-issued ticket records remain readable;
private installer tickets are still a separate unfinished workflow.

Each effective setup has its own immutable ticket context. Reopening unchanged
settings reuses its code; different settings receive another code. Returning to
saved settings reuses the saved command without a fetch or a hidden server-side
change. This deliberately differs from Go's single mutable ticket per machine
credential: that behavior could change the settings behind a cached command
when another draft was previewed. Native contexts use a separate database key
space, so rolling back to Go does not mutate them.

`GET /install/{ticket}` with `Accept: application/json` returns a versioned
profile envelope and the enrolled machine ID header. The profile retains its
public authority, up to eight deduplicated HTTPS control fallbacks, and typed
setup overrides for later configuration requests. The native client rejects
redirects, mismatched identities and oversized responses. HTTPS is required;
only an explicit isolated-test flag permits HTTP. A response cannot enable that
flag itself. Credential files are private and exclusively locked while updated.

```sh
porthub setup --ticket https://porthub.algofly.in/install/SHORT_CODE_HERE
porthub setup --user --ticket https://porthub.algofly.in/install/SHORT_CODE_HERE
porthub setup --ticket https://porthub.algofly.in/install/SHORT_CODE_HERE \
  --no-service --profile /existing/private/directory/machine.json
```

System service mutations require administrator access. Without an explicit
profile path, service enrollment keeps an owned source profile beneath the
selected layout's `enrollments` directory and activates the existing native
service installer. Setup also publishes the interactive CLI in `/usr/local/bin`
or, with `--user`, `~/.local/bin`; `--bin-dir` selects another absolute directory.
Source credentials and the previous CLI are restored when activation fails;
foreign enrollments, symlinks and live foreground profile owners are rejected.
The source profile remains after ordinary service removal, as do manually
provided source profiles. Windows credential protection and macOS/Windows service
activation remain unsupported gates.

Without JSON negotiation, the short link renders a small first-download Unix
launcher. It selects a bundled target, downloads it from the ticket-authenticated
`/install/{ticket}/agent/{target}` endpoint and invokes native `setup`. That
one-time launcher uses OS shell/download utilities and `sudo` when needed; it
does not install packages, run the retired shell agent or supervise traffic.
The installed agent handles configuration, logging and service operations in
Rust. Profile responses use no-store, no-referrer and Accept-varying headers.

Legacy `GET /api/machines/{machine_id}/{token}/install.sh` and
`GET /api/install/{token}` authenticate the existing enrollment before issuing
the same native bootstrap response. They support JSON profile negotiation and
reject disabled or retired registrations. The generated launcher contains a
short-lived capability rather than the permanent machine token. Credential
rotation revokes both the old legacy URL and its capability.

The published executable supports native `ls`, ID-based status and scoped
start/stop/restart/remove aliases. It accepts only owned managed release links
or an existing file identical to the selected native binary; other executables,
including unrelated Go/shell executables, are left untouched. The generated
legacy PortHub CLI has an explicit adoption path: root setup verifies its one
matching enrollment and queues an independent systemd worker before the legacy
service is stopped. See [native adoption](native-adoption.md). Ambiguous selectors and
arbitrary profile paths are rejected by tenant commands. Profile removal leaves
the shared CLI available. Setup does not edit shell startup files; it prints
guidance if the selected bin directory is outside PATH.

Existing Unix installations can stage saved enrollment credentials with:

```sh
porthub import-legacy --env-file /etc/porthub/tenants/NAME/client.env \
  --profile /path/to/private-directory/imported.json \
  --fallback-server https://algofly.duckdns.org
```

The destination directory must already be owned by the caller and not writable
by others. This creates a new 0600 profile; existing output is never replaced.
The reader accepts the legacy writer's literal assignments and simple quoted
values, without sourcing a shell, expanding variables or following a source
symlink. Bounded, securely owned 0644 source files are accepted because older
installers created them. Shell expressions, duplicate keys, invalid credentials
and plaintext gateway authorities are rejected without echoing values.

This stages credentials only. It retains the saved authority, machine ID and
token, converts the legacy `/api` base to the native gateway base, and accepts
explicit fallback authorities for the same gateway. It does not infer fallbacks
from the shared shell executable. Existing units, processes, keys, tunnel
configuration and the shared CLI remain untouched. Use explicit adoption for
service takeover; do not run an imported profile alongside its existing agent.

Remaining rollout gates include legacy automatic self-update compatibility,
complete HTTPS first-download/privileged-launcher checks and actual system-service
adoption. Private packet-service activation, crash-safe updates and platform
support also remain required.

Local evidence includes a real CLI fetching and running a native API-issued
profile, actual systemd user-service enrollment with sync and 4 MiB forwarding,
and the production container fixture enrolling its packaged agent before the
32 MiB integrity/policy checks. The actual user-service test also invokes the
published executable for listing, status, start/stop and removal, then confirms
the CLI survives service removal. The launcher is syntax checked; its complete
HTTPS first-download/privileged installation flow has not been exercised.
