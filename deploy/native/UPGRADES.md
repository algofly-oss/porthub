# Scoped native upgrades

`upgrade.py` upgrades an existing three-role PortHub Compose deployment. It does
not migrate a legacy container, load image archives, change firewall policies,
update host agents, publish releases or modify unrelated services. Run it only
after loading the CI image archive and staging an independent release checkout
with the existing private `.env` and the same persistent volume root.

```
python3 deploy/native/upgrade.py --root /absolute/staged/release \
  --revision FULL_SOURCE_SHA --version VERSION
```

The default is a read-only Docker preflight. It checks each existing role's
Compose ownership and healthy state, candidate source/version/architecture and
UID/GID, reduced capabilities, private core network, unchanged bind sources and
access modes, and availability of the previous Compose configuration. Image
names are `porthub-ci:ROLE-FULL_SOURCE_SHA`, matching the server packaging job.
A different staging directory preserves the previous configuration for rollback.

Use `--roles core edge` for an API/UI/gateway upgrade that does not require a
firewall change. Omitted roles keep their original container IDs and count as
protected running containers during activation and rollback. Each selected role
must have its own recoverable previous Compose configuration. This supports a stable
firewall deployed from an older release directory. The default selects all three
roles; a firewall-only upgrade can use `--roles firewall`.

Add `--apply` to replace the selected roles individually with immutable image
IDs, `--no-deps`, no build/pull and a health wait. A private per-project lock
serializes upgrades across staging directories. The script records candidate
and previous immutable image references under `deploy/native/upgrade-records`
in the staging directory. Keep that directory with the release: Compose records
its override path for subsequent upgrades. It does not retag shared images.

A failed replacement, health check, SIGHUP, SIGTERM or Ctrl+C triggers restoration
of the attempted roles using each role’s previous Compose files. Roles not yet
attempted remain running. Further catchable
termination signals are ignored during restoration. Previously running unrelated
container IDs must still be running after activation or rollback. SIGKILL, machine
failure and Docker daemon failure require operator recovery from those records.
If one restoration fails, the script still attempts the remaining roles and
reports every failed restoration/check instead of claiming rollback succeeded.

Add repeatable `--probe-url https://application.example/health` arguments for
existing application routes. Each must be reachable before upgrading, after all
candidate roles become healthy, and after rollback. A failed candidate probe
triggers rollback even if container health checks pass. Requests have an
eight-second timeout and do not retain response bodies. Failures identify the
probe by position without printing private URLs. Use URLs without credentials or
fragments. HTTP redirects follow the deployment's normal route.

When core is selected, the script first stages independent copies of immutable
component objects while the previous core remains online. Only files under
`agent-releases/components` whose bytes match the SHA-256 in their filename can
be reused. A 15-minute deadline bounds this online preparation; failure leaves
the running core untouched. Live MongoDB files are never copied or hardlinked
in this phase.

Activation then stops core cleanly and captures its complete `/data` directory,
including MongoDB and terminal journals. An unchanged staged object is reused
only when source and copy identities, size, mode, ownership and nanosecond
modification/change timestamps still match. All other files are copied from the
stopped core. Source hashes are computed during the copy and compared with a
readback of the copied file. Those verified hashes form the manifest without a
third full read. Added or removed files are reconciled at this cold boundary;
no live state is hardlinked into a backup.

The private `core-backup` snapshot retains ownership metadata, SHA-256 hashes,
online/cold byte counts and cold-phase timing. Files and directories are synced
before core replacement. The cold phase retains its 90-second deadline. Run
with sudo when deployment data belongs to the service UID. Stage `upgrade.py`,
`native_backup.py`, `backup_retention.py` and `migrate.py` together. A cold-phase failure restores the
attempted core role while edge and firewall remain running. Keep the snapshot
with the upgrade records until it is superseded. After a successful core upgrade,
automatic retention keeps the current snapshot and the newest other verified
recovery point (default two; `--keep-core-backups` accepts 2–16). A private
registry beside core state follows snapshots across versioned release roots.
Only marked successful-upgrade snapshots are pruned; legacy snapshots require
separate review. Configuration/image records and live or container-mounted
backups are preserved. See [backup retention](BACKUP-RETENTION.md) for interrupted
cleanup, filesystem safety and legacy handling.

Rollback restores images and configuration; it does not restore database files.
Assess schema compatibility separately before upgrading. Keep public application probes and a real
terminal/SSH/browser smoke check as deployment gates: container health alone does
not prove the externally forwarded routes work. The automatic authenticated
production workflow and its final deployment/publication gates are still pending.

Offline tests cover incorrect ownership/health/source/version/architecture/user,
changed mounts/capabilities/network exposure, independent rollback configurations,
backup hashes/ownership/deadlines and unsafe backup paths,
partial first-command failure, role scoping and SIGTERM restoration. These tests
use a simulated Docker executor. The migration preflight workflow also runs
`python3 scripts/test-native-upgrade-docker.py`: an isolated real Docker fixture
with private state directories, unique project/image names and no published
ports. It verifies a read-only dry run, partial core/edge upgrade failure,
restoration of their previous images, verified cold backups, a successful healthy upgrade, preservation
of the unselected firewall's exact container ID, and continued operation of
unrelated containers. Cleanup targets only its generated project resources.
This validates orchestration with lightweight test processes; a live PortHub
upgrade and application-level rollback verification remain separate requirements.
