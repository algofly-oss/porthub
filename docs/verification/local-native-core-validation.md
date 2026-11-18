# Local native validation before platform scheduling

Core-only CI can use an available Mac ARM host without scheduling `macos-15`.
The local machine must finish the applicable native checks, not merely compile a
binary. Source-pinned proof is checked on Ubuntu before the hosted matrix is
chosen. Missing, unavailable, timed-out, failed, stale, or incomplete proof leaves
that platform in the ordinary hosted matrix. No failed native test is converted
to success. A full release continues to use all existing hosted lanes.

## Controller configuration

Keep the existing protected SSH host config and depot upload configuration.
For the Mac builder add a `validation_build` argv identical to `build`, with
`--validate-core` and `--timeout 1640`; use `build_timeout_seconds: 1800`:

```json
{
  "target": "aarch64-apple-darwin",
  "probe": ["python3", "{root}/scripts/ssh-native-builder.py", "probe", "--config", "/private/operator/hosts.json", "--host", "nitin-mbp"],
  "build": ["python3", "{root}/scripts/ssh-native-builder.py", "build", "--config", "/private/operator/hosts.json", "--host", "nitin-mbp", "--root", "{root}", "--revision", "{revision}", "--state", "{output}.ssh.json", "--timeout", "1640"],
  "validation_build": ["python3", "{root}/scripts/ssh-native-builder.py", "build", "--config", "/private/operator/hosts.json", "--host", "nitin-mbp", "--root", "{root}", "--revision", "{revision}", "--state", "{output}.ssh.json", "--timeout", "1640", "--validate-core"],
  "fetch": ["python3", "{root}/scripts/ssh-native-builder.py", "fetch", "--config", "/private/operator/hosts.json", "--host", "nitin-mbp", "--revision", "{revision}", "--state", "{output}.ssh.json", "--archive", "{archive}"],
  "build_timeout_seconds": 1800
}
```

`PORTHUB_TRUSTED_NATIVE_DEPOT` remains an operator-controlled repository variable;
workflow inputs cannot supply a download URL or builder command. Existing native
controller timers run the unchanged command:

```
python3 scripts/hybrid-native-release.py --root /trusted/porthub --repository algofly-oss/porthub --branch main --config /private/operator/builders.json --state /private/operator/controller-state
```

A main-branch `agent-platforms.yml` core-only run uploads the tiny
`native-build-request` with purpose `core_only_validation`. Its Ubuntu selector
waits up to 1800 seconds for native proof (one final bounded transfer can take
up to another 150 seconds). The controller checks actual repository, workflow,
branch, source ancestry and request ZIP digest before running the explicit
operator validation command. Validation uses its own checkpoint/output namespace,
so an earlier plain core build cannot suppress native tests. No extra dispatch,
public release or self-hosted GitHub runner registration is required.

After the proof passes, `darwin_arm64` moves to the `local-native-core` matrix
on Ubuntu; the `native` matrix no longer contains that Mac target. The Ubuntu
job rechecks proof and bytes before retaining `porthub-darwin_arm64`. It does not
execute a Mac binary or claim Linux execution as native validation. All other
platform entries remain unchanged. With no trusted depot configured, selection
behaves as before. A prebuilt complete proof can also be consumed immediately.

## Equivalent core-only validation

The shared, versioned command plan executes the Mac-applicable core-only gates:
independent sync/stats/terminal fixtures; complete agent/transfer/tunnel/identity/
mesh/network/IO compilation and tests; packaged terminal runtime and SSH checks;
viewer/direct terminal and opt-in CLI checks; native user-domain launchd service
lifecycle; the exact core build and native packaged executable startup.

The same 240/90-second runtime limits remain on corresponding checks; separate
compilation and total budgets are bounded. It builds the pinned terminal runtime
from the same sources. Temporary optional components and fixture TMPDIR are
private, and the target tree belongs only to this nonce stage. The launchd test
uses its disposable label/profile; an outer cleanup only considers newly created
labels whose `program` is the exact owned test binary, never installed agents.
It never changes a machine agent, audio, TCC settings, physical devices or defaults.

`native-validation.json` binds source, native OS/architecture/kernel, exact
workflow and runner plan hashes, the complete ordered successful step list and
exact packaged binary SHA256. Original logs accompany the proof. The normal
component verifier independently checks raw bytes, recipe, lockfile and compiled
input closure. A plain core ZIP, old proof after a gate change, incomplete steps,
failed step or substituted binary cannot remove a hosted validation entry.

This proves the available machine's native OS/kernel, not equivalence to the
hosted Mac kernel or reproduction of an older kernel-specific PTY failure.

## Remaining full-release coverage

Only Mac ARM core-only validation is implemented here. Windows native installer,
SCM/desktop refresh and privileged route lifecycle still require their existing
hosted disposable machine checks; a Windows build alone does not satisfy them.
Linux privileged prerequisites likewise retain hosted validation. Intel Mac
requires matching available native hardware or the existing hosted worker.

Full publication additionally requires complete packaged optional components,
trusted catalog/version history, packaged HTTP/terminal workspaces, media helpers,
all platform artifacts, and bundle/publication validation. This lane neither
skips those checks nor makes a core-only artifact publishable. Full releases
continue scheduling the existing native jobs until those entire validation
contracts have corresponding local implementations and proofs.

## Local verification

```
python3 scripts/test_local_core_lane.py
python3 scripts/test_hybrid_native_release.py
python3 scripts/test_hybrid_native_build.py
python3 scripts/test_ssh_native_builder.py
```

These tests verify selection, fallback, trust/identity, proof completeness,
request separation and recovery contracts. They do not by themselves constitute
an executed Mac native validation run. Run the frozen source on the available
Mac and retain its successful receipt before reporting that gate passed.
