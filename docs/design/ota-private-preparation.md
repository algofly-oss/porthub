# Private DNS preparation during native OTA

The native upgrade transaction wraps the platform service manager to preserve
whether a registration was enabled and running. The wrapper must forward
`prepare_private` to its underlying manager. Its inherited default was a no-op,
so OTA could skip the Linux DNS prerequisite setup that fresh enrollment runs.

An affected candidate can report its new version while strict private readiness
prevents the transaction from committing. The shared CLI can consequently still
point to the old executable. Check the committed receipt and CLI target as well
as reported versions when verifying a rollout.

Forwarding the hook uses the same privileged setup and administrator policy
checks as enrollment. It preserves `PORTHUB_PRIVATE_DEPENDENCIES=auto|check`
behavior, resolver preservation, and the strict DNS readiness gate. A setup
failure restores the prior native registrations and CLI rather than publishing
the candidate or bypassing readiness.

The upgrade integration tests cover both migration from paired services and an
already unified private module. They also inject prerequisite failure and check
rollback, unchanged CLI publication, no readiness bypass, and unrelated
registration preservation. Both new tests fail without the forwarding fix; all
15 upgrade tests pass with it. The existing full native platform test step runs
this suite on Linux.

During the UAT investigation the app host reported a running 1.11.0 service with
private DNS unverified, while its shared CLI still reported 1.10.1. Intermittent
SSH resets were also observed. The skipped setup hook is a confirmed defect;
release 1.11.4/core 1.11.2 subsequently committed on all 15 online agents with
matching native acknowledgements. On both RHEL UAT hosts the upgrade automatically
added systemd-resolved to NSS lookup order. Resolver contents, physical addresses,
default routes and routing rules remained unchanged. EC2 SSH sessions to both
hosts completed a 45-second hold without resets. These checks demonstrate repair
and recovery, but do not establish the cause of every historical reset. See the
[final rollout record](../verification/2026-11-06-modular-agent-final-rollout.json).

## Gateway acknowledgement

Native sync must acknowledge the exact update request after the durable worker
commits. A candidate reporting the requested version, an empty acknowledgement,
or an acknowledgement for another request must leave the update pending and must
not stamp it as installed. The older legacy protocol retains its version-based
fallback. Running-version reporting remains separate from committed update state.

The API unit tests cover native and legacy acknowledgement rules. The real
HTTP/Mongo machine-client workflow checks the pending candidate, a stale
acknowledgement, and final commit acknowledgement. Both run in the server gate.
A local opt-in `native_update` test also passed using the verified published
1.11.0 executable and a distinct 1.11.1 candidate: it observed the new version
before acknowledgement, then verified the real user-unit worker's committed
journal and shared CLI target. Its disposable unit and database were cleaned up.
