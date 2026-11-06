# Single upstream recovery

A route with one enabled backend and no active health checks must try that
backend on each new request. A transient transport failure previously put it
into a cooldown with no alternate backend or background probe to recover it.
Subsequent requests could receive `No healthy upstream is available` for ten
seconds even after the backend recovered.

Such routes now allow one additional connection attempt for an empty-body GET
or HEAD, within the configured attempt limit. Writes, upgrades and response
timeouts do not receive this single-backend retry. Existing multiple-backend
selection, cooldowns and explicit active health checks remain in force.

An application HTTP 502, 503 or 504 on a single-backend route is reported as
degraded but does not disable unrelated application paths. Explicit health
probes can still mark that backend unavailable. Connection errors and response
timeouts have separate diagnostic reasons.

The upstream integration suite covers immediate recovery, bounded connection
retry, application errors, timeouts, write/upgrade safety and existing pool
failover. It runs in the native server release gate.

The reported OTSI camera URL and eight paired backend/proxy checks returned 200
during investigation. Its legacy single-backend route matches the old blackout
condition, but the reported live failure was not captured. This fix addresses
that confirmed gateway defect; it does not establish the cause of every earlier
backend error or guarantee availability of the upstream application.
