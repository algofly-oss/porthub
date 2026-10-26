# Native machine profiles

The Rust agent can run an authenticated public machine profile in the foreground.
It owns the control client and embedded Rathole sessions directly; it starts no
shell client or tunnel subprocess. This is a local migration milestone, not yet
a complete replacement for the installed agent's service/update/private-network
lifecycle.

Create a directory owned by the account that will run the agent, with no group
or other write access. Configure a new profile with its machine token on stdin:

```sh
porthub configure --profile /private/path/machine.json \
  --server https://porthub.algofly.in --machine-id MACHINE_ID \
  --fallback-server https://algofly.duckdns.org < /private/path/token
porthub run --profile /private/path/machine.json
porthub status --profile /private/path/machine.json
```

The primary domain remains the saved gateway authority. Only explicitly saved
control fallbacks are retried; redirects cannot send machine credentials to
another endpoint. Authorization rejection is terminal for that attempt and does
not try another gateway. HTTPS is required unless the isolated-test HTTP option
is explicitly enabled. Configuration reads validate the enrolled machine ID and
service tokens before changing forwarding.

On Unix, profile and state files must be regular, owned by the current account
and private (0600). New profiles refuse to overwrite existing registrations.
Atomic state replacement, exclusive profile ownership and a live lock check keep
status independent of PID reuse. Routine status and control-error output omit
tokens, URL queries and origin addresses. Windows credential ACL behavior and
native Windows/macOS lifecycle still need implementation and target verification.

Presence sync and configuration long polling are native HTTP requests with
bounded sizes, connection timeouts, retry backoff and cancellation. Configuration
changes update the embedded client in memory. Unchanged sessions survive sync and
version-only updates; removing the last service closes forwarding. Rejected
identity/configuration responses retain the current services. Authorization loss
stops forwarding until access is restored. A deletion response stops forwarding,
acknowledges the server and exits; the private profile remains available for the
operator. Process interruption is reported by status after its ownership lock
has been released.

Native machine deletion waits for edge listener closure before it commits the
410 response. Temporary closure failures pause access with 403 and restore the
registration instead of telling the client to uninstall. Interrupted committed
cleanup is journaled, and an early client acknowledgement remains available to
the cleanup worker. Foreground `run` exits normally with status `deleted` after
stopping its forwarding and acknowledging removal. Its private profile and any
installed service configuration remain; complete automatic installed-service
retirement is still a rollout gate.

The tunnel runner also accepts PortHub's existing URL-based TOML files, including
configured fallback endpoints and authenticated direct-origin key pins. Initial
transport checks run concurrently before choosing a session endpoint; data
channels use that same endpoint. A pinned origin retains canonical SNI/Host and
verifies its SPKI SHA256 plus TLS handshake signatures. Unpinned HTTPS uses normal
public-CA/name verification. No reachability probe authenticates or displaces a
forwarding service. A service-free profile creates no probe connections.

Each public registration with multiple configured endpoints also owns one
scheduled reachability worker. At the default 30-second heartbeat interval it
checks the selected endpoint; two failed checks permit a switch to a verified
alternative. When using a domain fallback, it revisits direct-origin candidates
every ten checks. Profiles without services or alternatives create no probe
connections. Checks continue during API retry delays and never run in a visitor
connection or forwarding copy loop. Configuration revisions discard stale probe
results. If every candidate fails, the existing selection and live copies stay
owned rather than being replaced by an unverified endpoint.

Endpoint-only changes drain established TCP copies on both client and gateway.
New control sessions and streams use the selected route. Service removal, token
rotation and explicit shutdown close copies from every retained generation;
route changes cannot change service identities or policy. UDP route changes
release their old pool, so this TCP continuity guarantee does not apply to UDP
associations. The native API supplies configured origin metadata and its key pin.

Installed Linux services process API-requested native updates and acknowledge
only committed matching transactions; see [native releases](native-releases.md).
Private-route bandwidth scoring, legacy updater migration, complete
Windows/macOS lifecycle and private-network support, fleet adoption and physical
performance verification remain rollout gates. Linux enrollment, legacy adoption
and private transport are described in the corresponding native documents.

Local checks include a real saved-profile agent against the production Compose
API, edge and firewall. It receives native API configuration, transfers a 32 MiB
file with a matching SHA256 using built-in file serving and parallel downloads,
and applies a live mapped-port deletion. Other tests cover credential-safe
fallbacks/redirects, invalid machine identity, disabled/deleted access, preserved
active streams, exclusive ownership, origin key mismatch and canonical Host.
These are functional checks, not the required remote 10 GiB benchmarks.

Native `setup --ticket URL` now fetches an expiring enrollment profile, saves it
privately and can invoke the Linux service installer. Advanced setup values are
retained in later configuration requests. The actual user-service check now
starts through that bootstrap command and publishes an interactive CLI.
Legacy tenant adoption and other platform controllers remain incomplete; see
`native-bootstrap.md` before using this with registered machines.

## Linux services

Linux installation and management use native systemd D-Bus calls, without
running a shell or `systemctl`. Each gateway/machine identity has a separate
unit and private credential copy. The executable is copied into an immutable
SHA256 release directory, so closing a terminal or moving the original binary
does not remove the running service.

```sh
porthub service --user install --profile /private/path/machine.json
porthub service --user status --profile /private/path/machine.json
porthub service --user stop --profile /private/path/machine.json
porthub service --user start --profile /private/path/machine.json
porthub service --user restart --profile /private/path/machine.json
porthub service --user uninstall --purge --profile /private/path/machine.json
```

Omit `--user` for a system service; mutations then require administrator access.
User services start with the user manager. Persistence across logout depends
on the host's existing login/linger configuration; installation does not change
that configuration. Multiple profiles can run independently. Uninstall removes
only the selected owned unit; `--purge` also removes its installed profile and
state, preserving the source profile and shared binary releases.

Failed activation restores previous files and attempts to restore the previous
service state. This is not yet a crash-safe agent-update mechanism. Foreign unit
files, symlinks and modified cached binaries are rejected. Unexpected failures
restart with bounded systemd retries; an acknowledged machine deletion exits
normally. Job completion is awaited before reporting a successful operation.

A local opt-in test exercised the real user service manager: CLI installation,
authenticated API sync, 4 MiB forwarding before and after stop/start, status and
scoped removal. No test unit remains. System-service activation with root
privileges has not been exercised. See
`verification/2026-10-24-native-service.json` for scope and artifact identity.

## Interactive CLI and native registrations

Service setup publishes `porthub` as a link to a verified immutable release.
The default location is `/usr/local/bin`, or `~/.local/bin` for user setup;
`setup --bin-dir /absolute/directory` selects another location. The bin directory
must be owned securely and separate from managed service state. Setup leaves
shell configuration unchanged and prints PATH guidance when needed.

Publication accepts an owned link into this installation's verified release
cache or an existing regular file identical to the selected native binary.
Unknown executables, foreign links and the retired Go/shell CLI require an
explicit migration workflow and are not overwritten. Failed activation restores
the old link, or the original file inode with its ownership, permissions and
other metadata. Removing a profile preserves the shared CLI and release cache.

```sh
porthub ls --user
porthub ls --user --json
porthub status ID_FROM_LS --user
porthub stop ID_FROM_LS --user
porthub start ID_FROM_LS --user
porthub restart ID_FROM_LS --user
porthub remove ID_FROM_LS --user
```

Omit `--user` for system registrations. `ls`, `status`, `service status` and
`path show` do not request administrator access. Commands that change system
services or their settings request elevation when needed.
`list`, `up`, `down`, `rm` and `uninstall` are aliases. Selectors accept a unique
native identity or machine-ID prefix of at least six hex characters, or an exact
managed service name. When exactly one registration exists, the selector may be
omitted. Multiple matches fail without changing any service. Service changes use
validated native manifests; display output omits credentials and origin addresses.
Existing `status --profile FILE` and `service ... --profile FILE` remain available.
The agent publishes only display metadata in a separate local status directory:
`/var/lib/porthub-status` on Linux, `/Library/Application Support/PortHub Status`
on macOS, and `%ProgramData%/PortHubStatus` on Windows. Credential profiles retain
their existing private permissions. Read-only commands neither open those profiles
nor contact the gateway. Snapshots reuse existing status updates; no additional
polling process, listener or timer is introduced. Active records older than 90
seconds display unknown activity rather than claiming the agent is still running.
They are never used to authorize service or policy changes.

## Live diagnostics

Saved-profile agents capture tracing output into a process-local buffer bounded
to 256 lines and 128 KiB. Redaction removes the enrolled token (including JSON,
Debug and percent-encoded forms), endpoint URLs, IP addresses and saved gateway
hosts before console output or retention. A formatted event exceeding 16 KiB is
omitted as a whole; individual retained lines are limited to 4000 characters.
Console tracing defaults to `info`; `RUST_LOG` can change its level.

One background task checks the authenticated log-stream endpoint every five
seconds. While the UI requests logs, it sends the most recent three lines, then
batches up to 100 new lines every two seconds. An inactive demand check stops
payload uploads; unsubscribe is observed on the next check. Upload and demand-check failures have independent backoff,
capped at sixty seconds. Pending batches survive upload retries while demand
remains valid; confirmed inactivity resets the cursor for the next viewer.
Deletion stops the task, and cancellation or runtime errors release it with the
profile owner. Forwarding never waits for a log request or upload.

This stream is bounded diagnostics, not a durable archive. Old lines can be
evicted under load, a restart loses the buffer, and reconnection can repeat recent
context. The server accepts retained historical machine credentials for
authentication diagnostics, so a profile awaiting renewed access can still
report its authorization failure. No shell, `tail`, journald reader, log file or
runtime package installation is needed.

Legacy Linux registrations have an explicit native inspection/adoption command,
with retained recovery receipts and activation rollback. See
[native-adoption.md](native-adoption.md) for its verified scope and rollout gates.

## Temporary public exposure

An installed, authenticated registration can expose a local HTTP or TCP service:

```sh
porthub expose 8000
```

The command stays in the foreground. Stop it with Ctrl+C to remove its mapping.
For a background worker, use:

```sh
porthub expose 8000 --detach
```

List workers and stop one using its displayed exposure ID:

```sh
porthub expose list
```

```sh
porthub expose stop EXPOSURE_ID
```

`--port EXTERNAL_PORT` requests a particular gateway port from the configured
pool. `--subdomain NAME` optionally adds a hostname proxy under the configured
proxy suffix. Port and hostname reservations are shared with UI-created entries;
conflicts are rejected. Temporary entries appear in the UI with an agent-managed
indicator and cannot be edited there. The displayed TCP endpoint prefers the
configured service domain.

The worker uses its selected registration’s existing credentials. It cannot
create mappings for an unrelated account. It renews its lease every 30 seconds;
if the process disappears, the gateway removes the expired mapping and proxy.
Repeated create requests with the same session identity return the same mapping.
Normal stopping removes the mapping immediately. System registrations retain
their existing credential permissions; the CLI elevates when access to those
credentials is required.
