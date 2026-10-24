# Ignored integration tests — catalog

Every `#[ignore]` in `crates/nlink/tests/integration/*` MUST appear
in this file. The CI audit script `scripts/audit-ignored-tests.sh`
fails on any ignored test missing a catalog entry — see
`CHANGELOG.md ## [0.17.0]` "CI observability" for the original
rationale.

Three legitimate reasons for `#[ignore]`:

1. **Kernel-build-dependent**: works on some kernels, hangs/zero-
   events on others. The lib code is fine; only the *test
   assertion* is fragile. Use `--ignored` locally on a kernel where
   it works.
2. **Tracking-plan-deferred**: a known bug, tracked by a specific
   plan, will be un-ignored when the plan ships.
3. **Migration candidate**: pre-existing `#[ignore]` on a test
   that should use `nlink::require_root!()` instead. Tracked for
   bulk migration; un-ignore when the migration lands.

If you're adding a new `#[ignore]`, prefer a `reason = "…"` string
(syntax: `#[ignore = "reason"]`) and reference the tracking plan
or this catalog.

## conntrack.rs

| Test | Reason | Tracking |
|---|---|---|
| `ct_subscribe_observes_destroy_event_on_del` | kernel-build-dependent | Synthetic ctnetlink-injected entries don't reliably generate visible Destroy events on every kernel build/config; the lib path works (other conntrack tests cover delete + subscribe independently). Run with `--ignored` locally to verify on a kernel where it works. |

## concurrent_stress.rs

All entries here were un-ignored when the F1 concurrency fix
landed in 0.19 — see `CHANGELOG.md ## [0.19.0]` "F1 — shared
`Arc<Connection>` concurrent ops". The catalog section is kept
as a marker; if a future regression in this file is `#[ignore]`'d,
add a row with a tracking plan.

## nftables_reconcile.rs

All entries here were un-ignored when the `NftablesDiff` body-
bytes false-positive was fixed in 0.17 (see
`CHANGELOG.md ## [0.17.0]` "NftablesConfig::diff body-bytes
false-positive"). The catalog section is kept as a marker —
if a future regression in this
file is `#[ignore]`'d, add a row here with a tracking plan.

## diagnostics.rs

All 12 tests in this file were migrated from `#[ignore] //
Requires root privileges` to `nlink::require_root!()` in 0.17
(Plan 179). They now run in the privileged-CI job and skip
cleanly on non-root developer machines. The catalog section is
kept as a marker — if a future regression here is `#[ignore]`'d,
add a row with a tracking plan.

## xfrm_hotfix.rs

| Test | Reason | Tracking |
|---|---|---|
| `add_sa_with_offload_attr_id_locked_by_constants_gate` | Plan 221 W4 — locked at build time, not kernel-round-trip | The W4 fix (`XFRMA_OFFLOAD_DEV: 26 → 28`) is verified at build time by `scripts/audit-uapi-constants.sh` (xfrm.rs's constants against the kernel headers) + `xfrm.rs::xfrm_offload_kernel_constants`. A kernel-round-trip test would need offload-capable NIC hardware (CI runners lack it); EINVAL from no-offload kernels is indistinguishable from EINVAL on the attribute-size bug without `NETLINK_EXT_ACK` text parsing, which not every kernel emits for this code path. The `#[ignore]`'d skeleton documents the verification sites. |

## How to run locally

Run a specific ignored test on a machine where it's safe:

```bash
sudo cargo test -p nlink --features lab --test integration -- \
    --ignored ct_subscribe_observes_destroy_event_on_del
```

Run *all* ignored tests:

```bash
sudo cargo test -p nlink --features lab --test integration -- --ignored
```

## What the audit script checks

`scripts/audit-ignored-tests.sh`:

1. Greps every `#[ignore]` in `crates/nlink/tests/integration/`.
2. Extracts the test function name following each ignore.
3. Cross-references against the test names in this file.
4. Fails (exit 1) if any ignored test isn't catalogued.

This keeps `#[ignore]` from becoming a backdoor for hidden gaps:
every ignore is either fixed (un-ignored), tracked (in a plan),
or explicitly accepted (in this catalog).
