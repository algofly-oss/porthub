# Unified native agent

The target is one OS service and one agent process per enrolled gateway/machine
registration. Public forwarding and private networking remain separate internal
modules with their own credentials and policy validation. Other tenants on the
same host retain their own registration and service.

The public registration ID remains canonical. An owned, private
`<public-profile>.private-module.json` file binds its private module to a sibling
private profile. The binding must match both enrolled gateway authority and
machine identity; matching email, LAN address, or fallback URL is insufficient.

The private module runs as a supervised Tokio task in the same process. A
failure retries with bounded exponential backoff without restarting public
forwarding. Replacement and shutdown cancel the module and wait for cleanup
before another instance can start. Idle supervision waits on notifications.
One log buffer redacts both credentials, and one public log uploader and native
update controller serve the registration. Private signaling and policy leases
remain authenticated private control requests; they are not public forwarding
traffic.

Upgrade handover is part of the independent, journaled update transaction:

1. Validate both owned services, credentials, binaries, and unit files.
2. Save recovery copies before changing service state.
3. Stop the private service and confirm that its profile lease is released.
4. Retire its OS unit and service manifest while retaining private credentials
   and path preferences.
5. Bind the module to the canonical registration and start the updated service.
6. Require public readiness and, when enabled, private readiness from the new
   executable before committing the release and acknowledging its request.

An operator-stopped private module remains stopped after migration. Failure or
interruption restores the old service records, units, executable publication,
module binding, and prior running/enabled states. Recovery rejects credentials,
ownership bindings, or units changed after the transaction.

Verification must cover same-process public/private status, public stream
continuity during private control failure, isolated private packet/DNS/exit
behavior, clean paired-service migration, stopped-state preservation, interrupted
migration, failed readiness rollback, subsequent unified updates, and removal.
Linux and macOS require live migration checks; every supported release target
must compile and retain the same release version before deployment.
