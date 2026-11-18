# Release validation concurrency

Continuous release prepares one immutable source and verified reuse inputs.
Server validation and client platform validation can then run concurrently;
publication waits for both workflows, including complete server image packaging
and complete ten-platform client bundle verification.

The scheduling policy preserves local-builder preference:

- With no `PORTHUB_TRUSTED_NATIVE_DEPOT`, clients start after preparation.
- With a configured depot, clients keep the previous server-validation head
  start by default, giving intermittent native builders more time to publish.
- An operator can set repository Actions variable
  `PORTHUB_PARALLEL_CLIENT_BUILDS=true` to opt into earlier client starts even
  with a depot. Every other value keeps the quota-sensitive default.

Exactly one client caller executes. Both use the same reusable platform workflow
and identical inputs; neither publishes. The joined publisher runs only when
preparation, server checks and exactly one client lane succeed. Failed, skipped
or cancelled gates, verify-only, skip and already-published runs cannot publish.
The existing default-branch-only publishing restriction remains in force.
Standalone `agent-platforms.yml` publishing remains explicitly opt-in after its
own complete bundle gate, using the same publication workflow.

The publisher downloads `porthub-release-bundle` from the same workflow run;
there is no cross-run fetch or second platform build. Source checkout must match
the exact prepared SHA, and the original asset/catalog verification, publication
concurrency lock, version/tag safeguards and retention checks are unchanged.
Server checks, platform matrices, native checks and component build recipes are
unchanged. Promotion of an existing standalone run remains separate.

## Observed critical path and quota tradeoff

Run `44346631282`, source `70cab87f63a67617decc284fa6dde756bb6a8eed`,
finished preparation at `2026-11-18T16:29:48Z`. Client selection started at
`17:21:06Z`: a **51m18s** serial delay. The first actual platform started at
`17:21:26Z` (**51m38s** after preparation). Server image packaging finished at
`17:21:04Z`. These are job metadata observations, not measured improvement from
the new workflow. In an unconstrained successful run, overlapping these branches
changes their contribution from a sum to approximately their maximum. Hosted
runner queues and account-wide concurrency can substantially reduce the gain;
this run's Intel Mac started another 10m40s after the first platform.

Successful runs perform the same builds/checks; this change does **not** promise
lower GitHub minutes. Earlier client work may be wasted when a server check
fails. It also removes part of the local builder head start: the full-release
platform job checks the trusted depot once at packaging time after native tests.
A missing manifest/target immediately falls back to hosted compilation; there is
no polling retry. Manifest fetch is bounded to 15s, total restoration to 150s
with an outer 170s deadline. A slow local build that misses this moment may
therefore be duplicated on a hosted runner. The configured-depot default avoids
that new risk; opt in only when the latency tradeoff is wanted.

GitHub's documented standard-runner account limits are plan-dependent (Free20,
Pro40, Team60 total concurrent jobs, with five concurrent macOS jobs; enterprise
limits differ). The account's actual plan/custom limits were not inferred here.
See [Actions limits](https://docs.github.com/en/actions/reference/limits) and
[job dependencies](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-jobs).

Local contracts exercise mutually exclusive lane selection, failure/cancellation
truth tables, verify-only and skip paths, default-branch restrictions, same-run
bundle restoration and standalone publication. They run during preparation:

```sh
python3 scripts/test_continuous_release_workflow.py
```
