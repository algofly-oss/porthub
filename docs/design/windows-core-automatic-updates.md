# Windows core automatic updates (isolated implementation)

This implementation is being developed separately from the frozen native-media
release. It has not been deployed or published. A full native Windows execution gate is
still required; current tests do not establish runtime support. Previously published core32 and the separately frozen core34 candidate support
manual native service installation and optional-component maintenance; those
versions do not automatically replace the main agent executable.

## Authority and release trust

Only the actual registered SYSTEM service can create an automatic update plan.
Its managed manifest, canonical enrollment path, current SCM PID/configuration,
actual process image and immutable executable digest must agree. Copying a
profile or running the same binary in a foreground process grants no maintenance
authority. The existing client-local AutoUpdate setting remains default-on and
controls new preparation independently from keyboard, USB and media policies.

The existing authenticated machine release catalog selects the exact native
Windows target, version, size and SHA256. Downloads use PortHub's existing
source-aware HTTP policy and trusted enrollment authorities; no new network
stack or credential authority is introduced. The integrity-pinned executable is
queried for its exact version, Rust target and 40-hex build revision. That source
revision is an assertion from the SHA-verified artifact, not a separately signed
attestation. Its hidden maintenance protocol probe must match `windows-scm-v1`. All probes are
hidden, bounded and cancelled before staging can lead to an installation.

## Transaction and recovery

The old service launches one temporary maintenance process from the verified new
immutable executable. It inherits the SYSTEM token; it adds no account grants,
service, scheduled task or resident daemon. The protected per-registration journal
binds a nonce, authenticated request, enrollment digest, old/new immutable images,
old manifest/unit bytes, CLI destination, source revision and native target.
Only one worker may hold its journal lease.

The worker invokes the ordinary owned SCM/CLI install transaction. After that
transaction settles, it verifies a fresh running status for the requested version,
actual process image and actual SCM PID. Only then may it persist Committed.
Disabling AutoUpdate before mutation prevents installation; revocation while the
SCM transaction runs requires it to settle and restore the previous release.
Cancellation never abandons a half-completed service operation.

A failed readiness check restores the previous verified service and CLI through
the same transaction and verifies the previous process. Failure to restore leaves
RecoveryRequired. A crash during publication may leave files ahead of SCM: under
the normal installation lock, recovery accepts only exact old/generated-new unit
and manifest bytes and a CLI digest from one of those two images. It reconciles
those files to the SCM endpoint before continuing. Unknown operator changes are
preserved. A service-start hook can resume an already protected journal even when
the manifest is temporarily ahead of the real SCM image; the starting SCM PID and
image must still match a journal endpoint. No startup task is installed.

Idle validation keeps at most eight verified digest/identity records, not open
file handles. Windows volume/file IDs, size, write/change times and current path
identity invalidate the cache; every open permits read/write/delete sharing so
publication is never blocked by the cache. A hash mismatch is never cached.
Staging and every execution/restart boundary still perform uncached verification.
Startup reconciliation tolerates a temporary installed-manifest mismatch only
while the exact journal-old/generated-new snapshots remain authoritative, and
waits at most ten seconds; foreign files fail closed.

Preparation uses exponential retry delays capped at 15 minutes. Attempt cooldown
is also journaled so restarting after rollback cannot create an immediate update
loop. Unrelated feature changes do not bypass a pending delay. Old immutable
images needed by a journal must remain available until recovery/acknowledgment.

## Acknowledgment and legacy Windows transition

Reporting a version or observing an update header is not a completed transaction.
The acknowledgment must match a durable Committed record, request ID, requested
version, running version, verified source and installed candidate image. Turning
off future automatic updates does not prevent truthful acknowledgment of an
already committed operation.

Installing the first supported updater manually over core32/34 does not create a
retroactive OTA receipt. If that new version is strictly newer than a legacy
pending target, the existing server supersession path retires the old request
without claiming it completed. An equal-version pending request without a receipt
remains unacknowledged and performs no installation. It does not latch the queue:
a later, newer authenticated request remains actionable. Fresh enrollment at the
published current version normally has no pending update. No special server
request clearing or manual equal-version receipt is added.

## Required native validation before release

The platform-independent transaction tests and Windows-target metadata checks
are preliminary proof only. The separate disposable native SCM gate must run two
actual versioned agent executables from pinned private commits; it must exercise
the scheduled service-owned update, readiness failure/rollback, recovery and local
policy controls. No Aero upgrade, publishing or installed-account changes are
authorized by this document.
