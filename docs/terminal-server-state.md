# Terminal server persistence

Terminal sharing uses MongoDB for invitation hashes, authorization, recovery leases
and session lifecycle records. Terminal contents are not stored in MongoDB or in
the local journal.

The API also maintains a private end journal on its persistent data volume. By
default it is `/data/terminal/ended`, next to the SSH host key. Setting
`PORTHUB_TERMINAL_HOST_KEY` moves the default journal alongside that key;
`PORTHUB_TERMINAL_END_JOURNAL` overrides it with an absolute path. Use a dedicated
directory owned by the API user. The standard core Compose service already mounts
`/data` persistently. Keep the journal with the database during backups and moves.
Do not put it under `/run`, a temporary container filesystem, or the socket volume.

Before an explicit stop, authorization revocation or configured timeout closes a
workspace at the gateway, the API creates and syncs an end marker containing only
the random session ID. Host registration checks the marker before consulting
MongoDB. A database outage followed by an API restart therefore cannot restore a
marked session. The maintenance task reconciles at most 64 markers per scan,
revokes recovery leases and writes an ended database tombstone before removing
and syncing each marker. A missing database row receives an ended tombstone too.
Markers remain in place when reconciliation fails; later scans retry.

If the journal write fails, the API logs an error and stops admitting new terminal
hosts for that process. It still ends the requested workspace and attempts the
database update; other existing workspaces and unrelated forwarding continue.
This admission latch requires an API restart after storage is repaired. Simultaneous
loss of both writable journal storage and the database cannot provide durable
acknowledgement: preserve the logs and repair/reconcile the affected session before
restarting. This mechanism does not protect against deletion of both the journal
and the database, or against an administrator restoring incompatible backups.

Invitation revocation is acknowledged only after its database update succeeds.
A failed update returns an error rather than claiming that new joins were blocked.
Invitation expiry/revocation does not interrupt already attached participants;
explicit guest removal and session teardown have separate effects.

Verification includes a refused database endpoint, API reconstruction with the same
journal, an invalid journal path with another live workspace, symlink/path isolation,
and reconciliation against an isolated MongoDB instance. Production packaging and
live verification remain separate release requirements.

The authenticated host protocol can rotate the interactive/read-only capability
pair using a monotonic invitation revision. The gateway stores replacement hashes
and expiry separately from the original host identity and workspace options.
Only the next revision is accepted as a new update. A matching retry acknowledges
the existing revision, including any later revocation; it does not clear that
revocation. Conflicting retries and stale revisions fail. The gateway commits
hashes before changing live routes and acknowledges only after installation.

Host reconnection restores the authoritative revision and hashes atomically.
Original invitation links remain invalid after an API restart, and an expired
replacement invitation does not prevent the authenticated workspace host from
reconnecting. Attached guests and their recovery grants retain their roles.
Replacement expiry does not extend a configured workspace lifetime. Raw
replacement capabilities are omitted from Debug output and database records.

The user-facing rotation command is still pending. It must persist a private
pending capability pair before sending an update, recover across a lost
acknowledgement and expose only confirmed invitation URLs. Do not advertise this
protocol implementation as an available CLI/UI rotation command yet.
