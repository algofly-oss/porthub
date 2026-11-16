# Disposable Windows core update gate (not executed)

Run only on an explicitly reviewed disposable GitHub-hosted Windows runner with
an administrator token and no existing PortHub installation. Preserve the final
native artifact SHA/size, source commits, targets and version outputs for THREE real
agent executables A/B/C. All must contain the reviewed Windows updater; B must be
strictly newer than A and C strictly newer than B. C independently exercises a
second enrollment owning the shared CLI and authorized GUI worker. Do not use a tiny inert executable as a substitute for SCM/runtime
readiness. This gate is independent of USB driver prerequisites. The source versions remain
unchanged until separate reviewed private version-only build commits exist.

Use a private loopback HTTP fixture gateway with the existing explicit
allow_insecure_http_for_tests flag. No TLS bypass or authority exception is added
to production. Each scenario gets a random machine ID, random local-only token
and own canonical protected profile. Serve only the exact digest-pinned A/B/C bytes,
correct native catalog/response headers and authenticated configuration. Never
accept a request merely because it arrived on localhost: validate its fixture
token and machine binding. No real user credentials, account grants or physical
USB/audio/camera device are required.

Install A and C for two isolated fixture enrollments via the actual
`service install --profile --publish-cli` path. Normal fresh installation owns the
runner's temporary managed desktop task and publishes C as the higher shared CLI.
Disable all unrelated client features and initially AutoUpdate in canonical split
policy files before startup, except the explicit `default-on` scenario omits A's
AutoUpdate key. Other scenarios enable it only through the ordinary local feature
CLI. SCM must own the same PID and immutable image reported by each runtime.

## Separate scenarios, stop on unexpected failure

1. **Disabled → enabled successful upgrade.** Advertise B while AutoUpdate is off;
   confirm no B download/journal/worker or replacement. Enable it locally. Observe
   the real service-owned authenticated discovery/download, bounded hidden probes,
   independent maintenance worker, actual new SCM/runtime B image and Committed
   record before the first nonempty handled-request acknowledgment. Verify the
   token, profile, policies and other registrations unchanged. No extra scheduled
   task/service may appear. Repeated identical request headers must not reinstall.
2. **Readiness failure and rollback.** Allow B download but make only B's
   authenticated runtime sync unavailable. Observe verified A restoration,
   RolledBack and no success acknowledgment. Confirm journal-based cooldown stops
   immediate reinstallation after A restarts. Turn off AutoUpdate before another
   attempt; do not infer a rollback from process exit status alone.
3. **Revocation during download.** Hold the B response after a bounded first chunk,
   disable AutoUpdate through the local CLI, and verify staging is cancelled and
   no maintenance worker/install starts. Preserve zero installer/mutation counts.
4. **Revocation during readiness.** Delay B configuration until SCM actually owns B and the worker is
   waiting in Applying for runtime readiness, then disable AutoUpdate. Release the configuration barrier; the
   in-flight service transaction must settle and restore A without a Committed
   acknowledgment. New attempts must remain off.
5. **Worker loss/recovery.** Hold B runtime readiness. Identify ONLY the fixture's
   exact B maintenance process by immutable digest, command arguments containing
   the exact protected record path, SYSTEM SID, native creation time and pinned
   native handle. Terminate that worker while Applying with real B runtime readiness
   blocked, not an unrelated agent.
   Release B readiness. The service-owned recovery path must complete one matching
   transaction without duplicate installations or a false precommit acknowledgment.
6. **Service restart recovery.** With the same verified Applying record and no
   maintenance process, restart only the fixture service. Confirm startup recovery
   preserves SCM ownership, resumes the protected journal and waits for real
   runtime readiness. Unit/manifest mixed old/new crash cases are additionally
   exercised against exact known snapshots; unknown changes must fail closed.
7. **Authority/tamper negatives.** A copied-profile foreground process must not
   authorize an update. Reject a worker record outside managed state, wrong
   enrollment/request/target/build, corrupt immutable bytes and unknown unit/CLI
   changes. Preserve those operator changes rather than restoring over them.
8. **Legacy pending request.** No journal + equal-version header produces neither
   installation nor acknowledgment; a later B request still executes. A strictly
   older pending target uses the existing server supersession behavior, never an
   invented client receipt.

9. **Two enrollments and higher shared images.** In separate success and rollback
   cases, enroll A for the updated profile and C for another fixture profile using
   the real publication transaction. Before advertising B to A, prove global CLI
   and the fixture-owned authorized GUI action point at C. Snapshot the other
   registration, both protected policies, and task XML/SDDL. A→B success and
   readiness-failure→A rollback must retain C's global CLI and GUI action, preserve
   the other enrollment byte-for-byte, and hold the ordinary global install lease
   throughout apply/readiness/rollback. A known managed fixture GUI task/grant is
   necessary for this assertion; do not infer GUI preservation from CLI bytes or
   change any real account enrollment. The runner-only task/account fixture must
   receive separate source review before execution. Test interrupted rollback
   where CLI has returned to its prior shared image while SCM still points at B;
   recovery must not republish B over C or over the restored prior CLI.

Use no hardware, models or media capture. Keep all timeouts finite. Archive only
credential-free phase/request/digest/PID/timing/counter projections and bounded
errors. Finally stop/uninstall only the exact fixture registration, independently
verify worker/service absence, and remove only nonce-claimed fixture files.
Do not uninstall system USB drivers or touch another installed PortHub instance.

The real Windows native full-agent compilation and this opt-in SCM execution
require separate review. Metadata-only harnesses with refusing OS stubs cannot
replace either gate.


## Concrete controller checkpoint

`scripts/test-windows-core-update.py` implements the disabled→enabled success and
candidate-sync-failure rollback cases with two actual enrollments. A installs for
the updated enrollment, C installs for the other enrollment using ordinary
`--publish-cli`, then the fixture advertises B only to A. It checks the actual SCM
PID/image, protected transaction journal, acknowledgment order, other enrollment
bytes/process, and exact C GUI XML/SD and CLI bytes. It creates no forged grants:
the ordinary disposable runner enrollment provisions its own managed desktop.
All raw USB/media/input permissions remain locally disabled; only AutoUpdate is
explicitly enabled for A. No installer or hardware execution has occurred yet.

The authenticated private HTTP fixture is in
`scripts/windows-update-fixture-gateway.py`. It binds loopback, checks enrollment
credentials on sync/changes/catalog/binary routes, limits request bodies and
observation counts, streams only the pinned binary, and checks the durable local
journal before accepting a handled-request acknowledgment. No enrollment token is
logged or written to the public receipt.

The input manifest is private gate metadata with these exact keys:

```json
{
  "schema": 1,
  "wrapper_source": "<40 hex checked-out controller commit>",
  "artifacts": [
    {
      "role": "a",
      "path": "<verified native executable A>",
      "version": "1.11.34",
      "source": "<40 hex native source commit>",
      "sha256": "<full executable SHA256>",
      "size": 12345,
      "target": "windows_x86_64",
      "os": "windows",
      "arch": "x86_64",
      "asset": "porthub-windows_x86_64.exe"
    }
  ]
}
```

The artifact array must contain exactly ordered `a`, `b`, `c` entries with strictly
increasing real versions; the example omits B/C to avoid inventing receipts.
Default invocation only verifies the receipt/files and writes `executed:false`:

```powershell
python scripts/test-windows-core-update.py --manifest private-artifacts.json --receipt preparation.json
```

After separate source/artifact review, each actual case must run on its own clean,
explicitly approved GitHub-hosted administrator runner:

```powershell
python scripts/test-windows-core-update.py --manifest private-artifacts.json --receipt success.json --execute-native-scm --scenario success
python scripts/test-windows-core-update.py --manifest private-artifacts.json --receipt rollback.json --execute-native-scm --scenario rollback
```

These are separate-runner commands, not consecutive commands on one possibly
failed installation. Cleanup independently attempts policy disable, maintenance
exit, exact fixture uninstall, verified desktop cleanup, PATH restoration,
process/service absence, nonce/identity-bound directory removal and gateway stop.
Unknown files, modified directory identities, markers or executable bytes are
preserved and make the gate fail. Readable status ownership markers deliberately
use `.owner`, since normal registration discovery parses every `.json` file.

The controller now has these separately selected executable scenarios, each for a
fresh reviewed disposable runner:

| `--scenario` | Required observation |
| --- | --- |
| `success` | Explicit local off→on, B commit and later ordinary acknowledgment |
| `default-on` | A's AutoUpdate policy key is omitted; no enable CLI runs; B updates automatically |
| `rollback` | B sync rejected, actual A restoration, later A heartbeat and no acknowledgment/retry in a measured cooldown window |
| `download-revoke` | HTTP holds after one 64KiB chunk; actual local disable completes before release; no journal, worker, B cache or SCM replacement |
| `readiness-revoke` | Real B SCM runtime is blocked in readiness; local disable then release settles transaction and restores A |
| `worker-loss` | Exact held SYSTEM maintenance process is terminated; independent runtime recovery commits B |
| `restart-recovery` | Stop only fixture SCM, terminate held worker, inject exact known old manifest beside new SCM/unit, then start SCM and require reconciliation/commit |
| `tamper` | Stopped fixture's unit gains one foreign field; attempted native start must preserve those bytes/no acknowledgment for 35 seconds; only explicit fixture restoration permits recovery |
| `legacy-supersession` | Equal unproven A header is selected before any advertisement, observed while disabled, then remains unacknowledged when enabled; later B request executes |
| `foreign-worker` | After a real commit, a copied out-of-layout record passed to B's actual maintenance command must fail without mutating the canonical receipt |
| `foreground-reject` | Copied profile runs actual A under the controller's retained process handle with only its own AutoUpdate enabled; actual runtime sync works but no native update authority is gained |

`windows-update-worker-pin.ps1` is fixture-only. It validates the exact immutable
candidate/record/nonce, SHA, command line and SYSTEM owner while holding a native
process handle. An earlier inspected native FILETIME must match before the same
held process can be terminated. It rejects a changed process instance and waits
for that exact handle to exit. Its embedded C# has been compiled offline without
invoking native APIs; this is not Windows runtime proof.

Rollback receipts retain monotonic sequenced normal sync observations including
the observed protected journal phase. They require a **later** authenticated A
heartbeat with no handled request, then five seconds without new download or
phase change, strictly within the persisted first retry deadline. The controller
checks for invalid acknowledgments again after cleanup and after bounded HTTP
handler drain. Receipts include only hashes, versions, phase/request IDs, fixture
machine IDs, PID/creation metadata and timings, never credentials or executable,
audio/video or native endpoint contents. Unknown third metadata states are never
restored over by fixture cleanup.

All scenarios are **prepared, not executed**. Offline tests mock/refuse OS/task/SCM
boundaries; real loopback HTTP tests validate auth, barrier and acknowledgment
behavior. They cannot substitute for actual Windows native execution. The reviewed
strict desktop-refresh stdin transport fix is carried from `b6ec520`; the combined
source still needs full native compilation and execution review; this checkpoint dispatches no workflow.

## Registration scope

This implementation/gate targets Windows public registrations, including paired
private routing hosted by the public runtime. Private-only network profiles enter
`private_network::runtime` directly and currently have no core update request or
handled-ack integration on any platform. Advancing a shared CLI is not evidence
that a separate private-only SCM registration updated. Extending that mode needs
its own server authority/credential and lifecycle assessment; no capability or
credential bypass is added here. The disposable fixtures use a public-only
loopback configuration; actual paired-private settings preservation remains part
of the separately reviewed installed-host upgrade trial.
