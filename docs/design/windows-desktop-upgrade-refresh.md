# Existing Windows desktop workers after native updates

A successful native update now refreshes an existing managed interactive worker.
The old scheduled task could otherwise keep an immutable older executable while
the system service upgraded, leaving new desktop capabilities unavailable.

The refresh reads only the existing `.local-access.json` grants belonging to the
upgraded managed registrations. Missing grants never infer a logged-in account;
SYSTEM and other service identities cannot authorize a desktop worker.

Only an enabled `PortHubKeyboard-<SID>` task with that principal, Interactive
logon, Limited privilege, one verified immutable PortHub executable, known
`keyboard run`/`keyboard startup` arguments and its SID-specific logon trigger
qualifies. Missing, disabled and customized tasks remain unchanged. An enabled
inactive task gets an action update without being started. A task that already
names the current executable also needs a verified current running process before
it is treated as current; a stale image retained by IgnoreNew is refreshed.

The scheduler update uses UPDATE, DONT_ADD_PRINCIPAL_ACE and
IGNORE_REGISTRATION_TRIGGERS. It retains the exact task security descriptor and
all XML other than the executable command and the known legacy `keyboard run`
arguments, which migrate to `keyboard startup` to retain the hidden startup path.
There is no task creation, enablement, credential storage, feature-policy update,
login creation or Session 0 capture.

A previously running worker is stopped only after its interactive process has
been verified against its account, immutable executable and creation time and its
native handle pinned. Restart waits for that process to exit and release its
lease. Failed registration (including failure after writing) or restart restores
the prior exact definition/security descriptor and prior running state when the
snapshot remains unchanged. An intervening user edit is never overwritten.
Refresh failure warns after the native update commits; it does not roll back the
successful system-service update.

Validation includes real PowerShell script control flow with explicit scheduler,
process and filesystem-identity mocks, plus Windows Rust authorization tests and
native compilation. A real installed-task update remains a separate maintenance
check; no Mac helper or Linux refresh behavior is changed.

The scheduler flags and security-descriptor behavior follow Microsoft's
[TASK_CREATION documentation](https://learn.microsoft.com/windows/win32/api/taskschd/ne-taskschd-task_creation)
and [RegisterTaskDefinition documentation](https://learn.microsoft.com/windows/win32/taskschd/taskfolder-registertaskdefinition).
