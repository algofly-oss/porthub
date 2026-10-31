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

Add `--apply` to replace firewall, core and edge individually with immutable image
IDs, `--no-deps`, no build/pull and a health wait. A private per-project lock
serializes upgrades across staging directories. The script records candidate
and previous immutable image references under `deploy/native/upgrade-records`
in the staging directory. Keep that directory with the release: Compose records
its override path for subsequent upgrades. It does not retag shared images.

A failed replacement, health check, SIGHUP, SIGTERM or Ctrl+C triggers restoration
of all three previous images using the previous Compose files. Further catchable
termination signals are ignored during restoration. Previously running unrelated
container IDs must still be running after activation or rollback. SIGKILL, machine
failure and Docker daemon failure require operator recovery from those records.

This is an image/configuration rollback, not a database restore. Obtain and verify
a PortHub database/terminal-journal backup before a production rollout and assess
schema compatibility separately. Keep public application probes and a real
terminal/SSH/browser smoke check as deployment gates: container health alone does
not prove the externally forwarded routes work. The automatic authenticated
production workflow and its final deployment/publication gates are still pending.

Offline tests cover incorrect ownership/health/source/version/architecture/user,
changed mounts/capabilities/network exposure, inconsistent rollback configuration,
partial first-command failure, role scoping and SIGTERM restoration. These tests
use a simulated Docker executor; live upgrade/rollback verification remains a
separate requirement.
