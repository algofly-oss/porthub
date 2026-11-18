# Native deployment backup retention

`upgrade.py --apply --roles core ...` now automatically keeps two completed-upgrade
core snapshots after activation, health checks and ordinary Compose selection
succeed. `--keep-core-backups N` allows 2–16. No retention runs during preflight,
failed activation or edge/firewall-only upgrades. Cleanup failure reports a
warning; it never rolls back a healthy new core.

The current upgrade's snapshot and the newest other valid recovery snapshot are
always protected. Docker bind sources from **all** containers (including stopped
containers) protect overlapping backups too. The upgrade's existing per-project
lock serializes upgrades across release directories. Other Docker/filesystem
administration should not run concurrently with deployment cleanup.

A private `.porthub-backup-retention-<project>-<state-path-hash>.json` beside the
core state directory remembers exact release roots across later versioned roots.
It is outside `/data`, so restoring a state snapshot cannot rewind that registry.
The registry never changes application data ownership. At most 64 roots are
tracked; roots with unresolved unsafe records remain tracked for later review.
Successful pruning drops roots with no remaining eligible snapshots, so ordinary
upgrades keep the registry small. `--backup-retention-root /exact/old/release`
can add another known root with **marked** snapshots.

Only a snapshot with a private success marker binding its project, exact state
path, record/revision and verified manifest is eligible. Cleanup checks the exact
manifest-declared tree, ownership and permissions, and refuses symlinks, special
files, filesystem boundaries and mountpoints (including bind mounts) before
walking into them. Already verified snapshot payloads are not reread merely to
prune them: work is proportional to directory/manifest metadata, not database
bytes. The success marker is written only by the successful upgrade path after
the existing cold-copy integrity verification.

Only `core-backup` is removed. The release directory, environment, previous image
references, upgrade configuration records, live state, unrelated files and
container images are preserved. An exact-tree durable intent permits cleanup to
resume after partial deletion; any newly introduced undeclared entry stops that
retry. The intent also pins each original inode/type and file metadata, so new
data recreated at an old filename is preserved. At least two valid recovery snapshots must still exist before resuming a
partial prune.

## Existing snapshots

Legacy snapshots have no successful-upgrade marker. Their names or a
`verified.json` alone do not establish that the replacement succeeded or that the
backup is superseded. They are **not** adopted or automatically deleted. Existing
large legacy snapshots need a separate operator review of their deployment and
recovery evidence; this change prevents new unbounded accumulation without
assuming that old backups are disposable. No production cleanup is performed by
the tests or by installing this source change.

Run local filesystem and upgrade regressions with:

```sh
python3 -m unittest discover -s deploy/native -p 'test_*.py' -v
```
