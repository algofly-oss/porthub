# Opt-in disposable Windows validation plan

This plan is not an executed native proof. The sparse feature remains off by
default and is not ready for release. No workflow override, remote branch,
GitHub dispatch, Windows configuration change, or live Aero operation is part of
this checkpoint. After source review, reuse the existing reviewed controller
branch; do not create another remote ref.

The eventual native job must be dispatch-only, read-only repository permissions,
pinned toolchain/lockfile and exact source/input/artifact receipts. Its runner
must be a disposable Windows 2025 administrator VM with no production PortHub
registration. Require an explicit disposable-host opt-in and abort if an enrolled
service/profile, pre-existing fixture, or unexpected own-prefix resource exists.
All hardware/network tests are ignored by ordinary Cargo runs. Tests cannot
select arbitrary target adapters, profiles or NRPT rules from environment input.

The fixture generates its own nonce, protected dummy private profile and native
ownership record under a fresh managed state directory. It never uses an enrolled
token or contacts a gateway. Choose an unused private host address only after a
complete native route/address inspection; decline when all candidates conflict.
Never install a default route, replace a LAN/VPN route, change global DNS, change
GPOs, or disable a firewall, VPN, policy or Windows setting.

Before mutation, retain bounded metadata baselines of all adapters (GUID, alias,
addresses, MTU), native routes including protocol/flags, interface DNS settings,
local/effective NRPT policy and global DNS configuration. Do not collect user
queries or payloads. Every created resource has an exact GUID/nonce and a pinned
own process handle. Cleanup independently verifies the baseline, own adapter
absence or verified dormant state, own routes/rules absent, journal/lock state,
children reaped and foreign resources unchanged. A controller timeout is never
proof of cleanup; an independent finalizer must check actual OS state.

Required native cases:

1. Fresh protected ownership intent precedes Wintun creation. The returned GUID
   and alias match before address, MTU or session changes. A simultaneous second
   owner is rejected by the separate ownership lease.
2. A fixture-created foreign same-name adapter, including a different-case alias,
   has a different GUID. Attempted open is rejected with its addresses, MTU,
   session and complete route fingerprints unchanged. Close only the fixture's
   pinned creator handle during cleanup.
3. Normal close/reopen, abnormal creator termination, OS restart where practical,
   and stale already-owned adapter recovery preserve the profile identity. A
   dedicated test fixture may retain an inactive adapter handle to model the
   stale-opened case; it must not run two active sessions or bypass the production
   ownership lock. Explicitly distinguish absent-adapter rebind from a live
   adapter configuration change.
4. Missing owned routes can be repaired. A changed gateway/metric, unrecorded
   route, foreign address, changed MTU or GUID is preserved and blocks recovery.
   An unacknowledged route intent cannot be adopted after a failed add or a crash
   between OS acknowledgement and journal checkpoint. Such ambiguous state must
   produce an actionable exact-owned repair error, not broad adapter deletion.
5. Register only a unique `<nonce>.porthub-ci.invalid` namespace with its apex
   and suffix entries, directed to the fixture's deterministic exclusive 127/8 DNS endpoint. Verify
   Windows bind/query support for that alias before treating the case as supported.
   After removing the own TUN address, an intentionally retained own test rule
   must still select only loopback and never a now-overlapping LAN host. Verify the
   actual effective policy and native Windows DNS query result through the real
   listener. Test dynamic suffix expansion/removal without a resolution gap for
   retained suffixes. Use native DNS APIs in a bounded child, bypass the cache,
   and project only the fixture's synthetic query metadata.
6. Native DNS success and a matching effective policy do not alone prove absence
   of parallel public DNS queries. A bounded DNS-client/egress metadata observer
   must correlate only the synthetic nonce and verify no external resolver was
   used; otherwise leave Windows no-leak native validation explicitly open.
7. A fixture-owned foreign local NRPT rule and an effective policy overlap block
   registration without changing their GUID, namespaces, servers or security
   settings. Do not edit domain GPOs to manufacture this test. An incompatible
   effective-policy source can remain a mock-only negative if the disposable
   runner cannot safely produce it.
8. Repeat updates are idempotent. Inject failures before/after native add and
   after removal, plus killed-child recovery, using private test process wrappers
   around real module-qualified cmdlets. The production script bytes stay exact;
   no production environment fault hook or arbitrary shell input is added.
   Restore the committed set with new GUIDs durably recorded when recreation is
   necessary. Preserve foreign or externally changed entries.
9. Cancellation/timeout and shutdown clear only recorded exact local rules.
   No old guard clears a replacement. A failed cleanup retains its protected
   recovery journal and is a failure, not a successful native receipt.

Bound the whole native job and each scenario, limit output and traces, pin only
owned child handles and use hidden bounded processes. Keep the bundled driver
installation and managed file changes inside the disposable runner's baseline;
never run this design against Aero's active profile or a user's DNS environment.

Current portable tests execute the actual NRPT transaction script with only OS
cmdlets/ACL projection mocked. They cover idempotence, additions/removal,
pre-/post-add failures, partial-removal rollback, cold pending-intent recovery,
foreign local/effective overlap, external edits, concurrent journal changes and
clear. Rust contracts cover profile/config/GUID binding, missing-vs-foreign native
routes, absent rebind and unacknowledged intents. Windows metadata checks compile
actual platform sources but do not execute the native cases above. PowerShell 7
mock execution does not establish Windows PowerShell 5.1 cmdlet/provider behavior.

The protected adapter route stamp currently compares address/prefix, gateway and
metric under an exact owned GUID. A native test must additionally audit protocol,
origin and other route flags before asserting complete foreign-edit detection.
Sparse server renumber journaling, Linux policy routing, macOS lifecycle,
exit/Tor coherence and high-latency renewal fairness remain separate blockers.


Primary contracts: the [Wintun adapter API](https://git.zx2c4.com/wintun/tree/api/wintun.h?h=0.14.1)
distinguishes closing a created adapter from closing an opened handle.
[GetIfTable2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getiftable2)
provides the native interface inventory.
[Add-DnsClientNrptRule](https://learn.microsoft.com/en-us/powershell/module/dnsclient/add-dnsclientnrptrule)
and [effective NRPT policy](https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientnrptpolicy)
are the system mechanisms used; these documents do not replace the native cases.

Current explicit source budgets: at most 256 requested NRPT suffixes, 512 owned
rules during replacement, 256 KiB journal, 64 KiB request/stdout/stderr, 25-second
transaction clock, 30-second async child watchdog and five-second cancellation
fallback. The command-line encoding has a separate checked bound below the
Windows process limit. Larger combined private/custom DNS configurations fail
with an actionable bound and are not truncated. The private proxy itself never
forwards a recognized private miss; OS routing after failed namespace admission
needs separate native validation and is not covered by that proxy guarantee.
Completing larger native namespace admission is separate
from the registration/peer-address pool expansion.


## Independent-review follow-up to 6bae7f0

The frozen checkpoint had two source defects; its old evidence is retained.
Broad capture-route removal omitted protected-journal retirement, allowing a later
identical row to be mistaken for the removed owned row. The follow-up requires a
persisted retirement before *any* explicit route deletion (capture, host or
shutdown). Only that acknowledgement issues a non-cloneable removal permit.
Retirement tombstones are diagnostic, never authority for recovery. Deletion
failure/crash therefore preserves ambiguous rows and reports exact-owned repair;
persistence failure issues no permit and leaves the original claim unchanged.
The unshipped adapter record format is version 2, so the old potentially stale
version-1 claims cannot silently be adopted. The native failure fixture must
exercise both sides of this ordering, then recreate the same prefix under the
same adapter and verify that recovery rejects it.

The default Tokio/Winsock bind was not exclusive against another socket owned by
the same Windows account. The follow-up sets and reads back
`SO_EXCLUSIVEADDRUSE` **before** binding UDP and TCP. A failed TCP half drops its
UDP half before any NRPT operation; it never enables address reuse as recovery.
See [Microsoft's socket ownership contract](https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse).

Two ignored Windows socket tests are now present in `dns_windows.rs`, guarded by
`PORTHUB_TEST_DISPOSABLE_WINDOWS_DNS=1`: same-account `SO_REUSEADDR` attackers
against the exact UDP/TCP endpoint, and pre-existing foreign UDP/TCP listeners
with partial-bind cleanup. They compile under metadata but have not run on
Windows. A future approved native job must also use a separate same-account
child, verify real traffic still reaches only the original endpoint, prove no
NRPT state was touched on bind failure, and exercise graceful TCP close/rebind.
TCP TIME_WAIT/active teardown may fail actionably or use a bounded safe retry;
never switch off exclusivity, use unsafe reuse, or reset foreign sockets.

A further audit found an unmerged legacy-compatibility issue: the ownership
ledger's 320-row bound was derived from sparse cache/capture limits, while the
Windows runtime also invokes it for legacy full snapshots. It therefore does
not yet preserve the older 4096-peer route capacity. Before merging, derive a
bounded journal/admission strategy from that existing contract or isolate this
experimental path without altering legacy behavior. Do not solve this by
raising global peer caps or silently dropping routes. No live client has run
this isolated implementation.

After review on an explicitly disposable Windows runner, the socket-only cases
can be selected without NRPT or Wintun activation:

```powershell
$env:PORTHUB_TEST_DISPOSABLE_WINDOWS_DNS = '1'
try {
  cargo test --locked -p porthub-agent --lib --features private-sparse private_network::dns_windows::tests::native_ -- --ignored --test-threads=1
} finally {
  Remove-Item Env:PORTHUB_TEST_DISPOSABLE_WINDOWS_DNS
}
```

This is a proposed invocation, not an execution receipt. Pin the source and
artifact first; do not run it on Aero to substitute for disposable validation.


## Observed-native-absence follow-up to 15d12d3

Independent review found another stale-claim path in frozen `15d12d3`: a fresh
native inventory could prove a route absent, prune only the in-memory cache, and
return with wanted routes empty while leaving the journal's old claim intact.
The retained frozen-source regression reproduces later identical-row adoption.

The follow-up centralizes missing-claim retirement in verified complete native
inventory processing, including startup, normal update/audit reads and shutdown.
It persists missing explicit claims as non-authorizing diagnostics before callers
can prune memory, take an unchanged/wanted-empty exit or mutate native routes.
A failed checkpoint returns an error with record/cache memory unchanged; it is
not acknowledged as an accepted inventory or a completed operation. Actual
persistent-storage-failure behavior remains part of disposable native testing.

A still-wanted missing route is repaired only by a fresh durable pending intent
and an actual successful native add acknowledgement. A failed add leaves no
confirmed claim. Old absent diagnostics can expire on a later complete snapshot;
expiring a diagnostic never recreates authority. Stable snapshots cause no
recurring journal writes. The portable tests cover external removal → empty
wanted set → identical foreign row → restart, checkpoint failure, acknowledged
repair, failed repair and idempotent diagnostic expiry. No native execution or
legacy-capacity resolution is implied; the existing 320/4096 blocker remains.
