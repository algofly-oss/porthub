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
live verification after a committed repair is still required before attributing
every reset to upgrade retries.
