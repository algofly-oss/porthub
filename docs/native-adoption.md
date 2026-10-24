# Adopting legacy Linux agents

The native CLI can inspect and adopt the generated Linux public registrations
under `/etc/porthub/tenants`, the older `/etc/porthub/client.env` registration,
and `/etc/porthub/private.json`. It uses systemd D-Bus directly. It never sources
an environment file or runs the old shell agent as a migration helper.

Inspection is read-only. Run the downloaded native executable:

```sh
sudo /path/to/native/porthub adopt-legacy \
  --server https://porthub.algofly.in \
  --fallback-server https://urm2.duckdns.org \
  --fallback-server https://algofly.duckdns.org
```

Adding `--apply` performs the inspected adoption. The command verifies the
generated unit definitions, literal enrollment credentials, shared CLI identity,
and that no omitted service still depends on that CLI. It stages immutable
native releases and private credential copies before stopping old registrations.
The source profiles and old unit files are retained.

When invoked from a legacy service, use `--handoff` instead of `--apply`. This
stages an immutable executable and queues a separate systemd transient service
through D-Bus. The worker survives the caller exiting or stopping its legacy
unit. Arguments are passed literally, without shell or environment expansion.
Inspect the returned unit with `systemctl status UNIT` or `journalctl -u UNIT`;
queueing is not confirmation that adoption succeeded.

Native `setup` also queues this handoff when it finds the generated legacy CLI.
Automatic installer migration requires exactly one matching public enrollment
and, if present, that machine's private registration. A different credential or
multiple public tenants requires explicit operator adoption before setup. The
installer's current setup overrides are retained in a private staged profile.

Active registrations must reach native runtime readiness before the shared CLI
is published. A deliberately stopped registration stays stopped, without
briefly advertising a new private fingerprint. Its boot enablement is also
preserved. Public and private profiles retain their enrollment IDs and tokens;
the explicit server option replaces old HTTP endpoints before validation.
Explicit tunnel/service-domain query overrides are preserved, while a discovered
origin never replaces the saved API authority.

Each attempt keeps a private `adoption-*` directory under
`/etc/porthub/native`, containing a journal, staged credentials and original CLI
and unit backups. Failed activation rolls back the CLI and native registrations,
then restores the old enabled/active states. Recovery also handles a partially
removed native profile by using its retained staged credentials.

The adopted CLI lists receipts without credentials:

```sh
sudo porthub adopt-legacy --receipts
```

To recover an interrupted attempt, use a retained native executable and the
receipt returned by adoption:

```sh
sudo /path/to/native/porthub adopt-legacy --rollback /etc/porthub/native/adoption-EXAMPLE
```

After rollback, the shared `porthub` path again points to its original legacy
CLI. The immutable native release and recovery receipt remain available.
Repeated recovery of a completed rollback does not restart the old services.

## Verification and remaining rollout gates

Isolated manager tests cover a multi-tenant adoption, preserved stopped/disabled
state, private credential continuity, failed runtime readiness, omitted services,
a changed CLI, interrupted retirement and idempotent rollback. Read-only native
inspection found one public and one private legacy registration on each of Luna,
Condor and Miro. These inspections did not activate native services or change
the running registrations.

Production adoption still requires the verified Rust gateway, matching release
artifacts, real system-service activation and public/private transfer checks.
The independent handoff has dedicated live user/system-manager tests. These
exercise a disposable worker, not production adoption. Legacy `reinstall` URLs
now issue authenticated native bootstrap links. The old `/client.sh` and
`/downloads/porthub` endpoints serve an authenticated compatibility CLI because
the old updater replaces its CLI before invoking preflight. This transitional
asset retains legacy operation and becomes the native transaction's rollback
copy. It contains no machine credentials or gateway defaults; the existing
private enrollment files supply those values. Its update/preflight entrypoints
invoke the native installer rather than replacing the tunnel executable.
Preflight deliberately returns failure to the old parent so that it stops
before acknowledging the request. The installed native agent handles the
pending request through its committed update transaction.

The actual old download/install/preflight contract and both API paths have local
tests, including token rotation, disabled machines and deletion. The installer
boundary is stubbed in the shell contract test; a complete production automatic
adoption has not yet run. Multi-tenant mismatches remain a manual adoption gate.
This adoption command is Linux-specific. macOS/Windows lifecycle and private
network support remain separate migration gates.
