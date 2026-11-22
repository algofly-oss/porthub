# Windows service recovery policy

Owned native Windows services reconcile SCM recovery during creation, enable,
start and binary reconfiguration (including rollback and already-current
reconfiguration). Recovery is read back before the operation acknowledges
success. Existing foreign-registration checks still precede configuration.

The policy retries after 5, 30 and 120 seconds, then takes no action. The
failure counter resets after one hour without a failure. The final no-action
entry matters because SCM repeats the last configured action. Recovery never
runs a command or reboots the host; old command/reboot-message settings are
cleared.

Non-crash failure recovery is enabled so an unexpected runtime error reported
as `SERVICE_STOPPED` with a nonzero exit code is eligible. Explicit STOP or
SHUTDOWN cancellation reports zero even when teardown logs an error; the error
is still logged and returned. A normal deliberate stop does not queue recovery.
Microsoft documents that changes to the non-crash flag take effect on the next
system start. Configuring and reading the flag does not prove immediate recovery
of an already running service.

Microsoft also documents that a restart already queued by an earlier crash
cannot be cancelled. Manually starting and stopping before that delay expires
can still cause that old action to run. Explicit service disable prevents it;
plain stop retains the existing AutoStart semantics and does not claim to
cancel an already queued crash action.

The portable tests cover bounded retry policy, explicit-stop exit codes,
idempotent reconciliation, native-write failure and failed readback. The native
ignored test creates a unique, never-started fixture service, verifies actual
SCM persistence and repair of a missing flag, and deletes the fixture on every
exit path. It never opens a production registration or starts a fixture binary.
It proves native configuration/readback, not crash timing or automatic restart.
The full native agent release gate remains required before deployment.

This addresses a missing resilience setting. It does not establish that missing
recovery caused any historical offline period.

References:

- [Failure action sequence and reset](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actionsw)
- [Non-crash failure flag](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actions_flag)
- [Queued restart behavior and access rights](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w)
