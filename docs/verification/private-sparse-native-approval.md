# Native lifecycle prerequisite

The compile-time native lifecycle prerequisite is backed by these retained,
immutable hosted results. Default `private-sparse` builds require this typed
prerequisite in addition to the separate release gates below. No
runtime environment variable can waive native ownership or negotiated transport
checks. `NativeReady` still binds the current device, owner lifetime, identity,
IP, fingerprint and authorization epoch; `quic3-credit` still requires server
negotiation.

| OS | Run | Exact source | Artifact | ZIP bytes | ZIP SHA256 | Raw receipt SHA256 |
| --- | --- | --- | --- | --- | --- | --- |
| Linux | 44192464266 | 885f5e082db6fdf2e307af2f17b5b681358cf17c | 14376443819 | 96189 | 64dc3bab890109b74899bed6fd3fb7670c9b1645d432865fd4477aae2a6751fb | 56b666282e155f72bf721eb5756dcc2d1b965355b1146228427a778c56a2d9ca |
| macOS | 44192464266 | 885f5e082db6fdf2e307af2f17b5b681358cf17c | 14376959039 | 84158 | 499f64bee254a64e1d487d14f1071b5c1d5c53d9ec62b11a7b9ae97f4b228cf9 | 1c0525b08a35d62fd69eeea687b6b0bee8a109f457384fc99725137ae82ba2a8 |
| Windows | 44202384966 | 8fa367d58166cb6acc4df7fed6748288305ce0d4 | 14383080434 | 50972 | dde7d0ae454afb90f0f3006c471b1d3fb95cf8ee83a60e37766c8b2a14a46ccb | 0a8211df518e90f1e18bd02fb8d4cbfdac941dfe66fdd2d2c81db5b960fce87e |

Each artifact's source-input closure, named native case logs and independent
cleanup were verified. Linux covers actual resolver and network-namespace
capture/withdrawal; macOS covers native routing, resolver, source retirement and
reallocation; Windows covers two normal binding regressions, two native socket
ownership cases and native routing/resolver retirement/reallocation. These are
cumulative results across the stated sources, not one all-OS run at the final
integration revision. Prior failures remain retained, including the earlier
Windows shutdown failure that did not reproduce in the successful run.

This prerequisite is not proof of ordinary two-agent negotiated stream delivery,
exit selection, scale, release readiness or a production deployment. Those
remain separate actual-runtime gates. The native wrapper continues to execute
its original cases, source closure and independent cleanup after this constant
changes; it accepts a typed compile-time boolean and rejects default activation
of `private-sparse` when native lifecycle approval is false. Enabling the Cargo
defaults does not constitute release approval: the final integrated source must
pass negotiated relay/native delivery, authorization, compatibility, and normal
platform packaging checks before publication.
