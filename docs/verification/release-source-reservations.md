# Immutable prepared-source reservations

Publication attempt1 of run44346631282 (source70cab87, version1.11.65,
job135060492515) passed all ten platforms and bundle verification, then failed at
`gh release create` with HTTP403 `Resource not accessible by integration`.
The source had ceased to be a branch head and did not yet have its version tag.

GitHub documents an additional workflow-scope restriction for release creation
at an unreferenced source whose workflow contents require that scope. A generic
403 alone does not establish every permission predicate, and not every older
commit fails. This change prevents that unreferenced-source failure path without
adding workflow-write permission, a PAT, a new branch, or moving any tag.
See [GitHub's release-scope policy](https://github.blog/changelog/2023-11-02-github-actions-enforcing-workflow-scope-when-creating-a-release/).

## Reservation and retry

Production preparation reserves a lightweight tag
`porthub-prepared/vMAJOR.MINOR.PATCH` at the exact prepared commit **before** native
build requests and platform jobs. Creation uses REST POST, never PATCH/force.
An existing identical reservation is idempotent; a different source is rejected.
A missing reservation can be created only while the source is still main head,
or no creation is needed when the exact version tag already exists. Losing the
main-head race therefore fails early, before expensive builds, rather than
silently widening token authority or failing hours later at publication.

Temporary tags are also supplied to the existing version/core reservation logic
as draft-like immutable reservations. A failed build's same-source retry keeps
its versions. A subsequent different source advances past reserved versions,
preventing pre-build version reuse. The actual `vVERSION` tag and public release
are still created only by the fully gated publication path.

Standalone opt-in agent publication has a short write-scoped reservation job
before its read-only selection/native gates. It preserves all-platform and
default-branch checks. Verification-only, core-only diagnostic and ordinary
non-publishing runs skip this job and never reserve tags. Existing promotion of
verified runs remains separate. The publisher checks a matching version tag,
prepared tag or current main head before attempting release writes; an old
unreferenced run receives an actionable error. This does not retroactively patch
old workflow definitions or authorize rebuilding/repinning unrelated historical
artifacts.

## Cleanup and bounds

After a stable release and its exact version tag are verified, publication can
remove its matching temporary tag and older-version reservations. Older releases
are already ineligible to replace latest: publication checks supersession before
any release writes. Future-version failed reservations remain available for
retry. A diverged source not retained in the published history is preserved for
operator review. At most256 temporary pins may be inventoried; capacity failure
is explicit before new builds, never an unbounded tag scan.

Cleanup rechecks latest/tag identity before every deletion. It verifies that
Git origin is the exact repository and uses an expected-SHA lease on a deletion
only (`git push --force-with-lease=EXACT_REF:EXPECTED_SHA origin :EXACT_REF`).
The lease is a compare-and-delete guard, **not permission to move a tag**; a
concurrent ref change leaves the tag intact. No branch or `v*` tag is ever a
cleanup target. Cleanup failure warns/defer-retries rather than undoing a
published release. No cleanup executes in dry-run mode.

## No duplicate tag builds

`porthub-prepared/*` does not match continuous release's `v*` tag trigger.
Component contracts already restrict push branches. Migration preflight was the
one unfiltered-push workflow: it now explicitly ignores prepared tags while
preserving all its previous branch and other tag coverage. There are no new
create/delete/release event handlers. In addition, pins use the existing
`GITHUB_TOKEN`, whose push events normally do not start more workflows. Explicit
filters protect against duplicate platform/Docker builds even if an operator
creates such a tag with a different trusted credential.
See [GitHub event semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
and [push filters](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#onpushbranchestagsbranches-ignoretags-ignore).

Tests use fake GitHub metadata plus a real temporary bare Git repository. They
cover main advancing, failed-source retry, new-source version collision,
read-only preparation, exact source checks, stable-tag cleanup, retained future
pins, diverged history, create races and compare-and-delete races. No real refs,
releases, workflows or deployment state are changed by these tests.
