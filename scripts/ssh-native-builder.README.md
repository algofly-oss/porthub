# Trusted SSH native builders

`ssh-native-builder.py` adapts `hybrid-native-build.py` to an explicitly trusted
SSH host. It never publishes, installs a runtime, changes services, or replaces
installed agents/helpers. Missing SSH authentication, Python >=3.11, native Rust,
Git, or native compiler makes the probe fail; the existing controller then uses
its hosted fallback. Mac discovery includes existing uv Python installations and
`~/.cargo/bin`; Windows discovery excludes Microsoft Store aliases and checks
registered/uv Python plus Visual Studio's `vswhere` capability query.

Copy the adjacent host example to a protected operator config. Host IDs are
explicit entries, never taken from an untrusted request. Configure existing SSH
key authentication or a live owned ControlMaster in both `ssh_options` and
`scp_options`; no password belongs in this JSON. Strict known-host verification
and BatchMode are mandatory. Example live Aero options are `-S /path/to/socket`
for SSH and `-oControlPath=/path/to/socket` for SCP. A disconnected or expired
master falls back instead of prompting. The Mac example uses its retained
`nitin-mbp.phub` known-host identity.

A controller builder entry (add its existing `depot` config separately):

```json
{
  "target": "aarch64-apple-darwin",
  "probe": ["python3", "{root}/scripts/ssh-native-builder.py", "probe", "--config", "/absolute/operator/hosts.json", "--host", "nitin-mbp"],
  "build": ["python3", "{root}/scripts/ssh-native-builder.py", "build", "--config", "/absolute/operator/hosts.json", "--host", "nitin-mbp", "--root", "{root}", "--revision", "{revision}", "--state", "{output}.ssh.json", "--timeout", "1640"],
  "fetch": ["python3", "{root}/scripts/ssh-native-builder.py", "fetch", "--config", "/absolute/operator/hosts.json", "--host", "nitin-mbp", "--revision", "{revision}", "--state", "{output}.ssh.json", "--archive", "{archive}"],
  "build_timeout_seconds": 1800
}
```

Use the corresponding Aero target/host for Windows. The configured remote worker
is core-only; the existing planner retains verified core artifacts and builds
missing helpers through its normal path. Full component builds remain the
worker's separate supported operation.

Staging transfers the exact HEAD commit and its entire tree/blob closure as a
Git pack, without ancestors, untracked files, targets, credentials, or worktree
`.git` metadata. The remote shallow checkout has the original commit identity;
the unchanged worker verifies clean source, builds, verifies receipts and packages
its ZIP. Two build jobs and an isolated target directory bound resource use.
The worker bounds and kills only its owned compiler process tree. Target/source
are removed at worker completion; verified ZIP and logs remain until successful
fetch. Fetch checks revision, target, size and SHA256, then removes the exact
nonce-owned stage. The controller independently checks raw binaries and closure.

On a failed build, preserve the state/logs for diagnosis, then run the same
adapter with `cleanup --config ... --host ... --revision ... --state ...`.
Cleanup checks both the nonce path and ownership marker. It never sweeps other
stages. A same-revision retry resumes only after remotely checking the retained ZIP
SHA256 and identity. A different revision cannot reuse that state. A verified
local ZIP remains successful if cleanup loses SSH; `cleanup_pending` records
that condition and fetch retries verify the existing bytes before retrying
cleanup. Cleanup refuses a live worker or unexpired upload/build lease; it never
kills a worker. Failed-stage provenance is retained for explicit cleanup. No build/fetch command runs implicitly during probe.

Tests: `python3 scripts/test_ssh_native_builder.py`. Real host availability and
actual worker build results must be reported separately from these local tests.
