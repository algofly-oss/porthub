# Terminal server persistence

The standard Compose edge listens for ordinary terminal SSH guests on TCP 8347
and forwards them to `/run/porthub-api/terminal-ssh.sock` on the existing private
API socket volume. The API provides the SSH server; the machine's system sshd
is not used. The core service publishes no TCP port. Keep API UID/GID
`10001:10001` and edge UID/GID `0:10001` so the private socket is accessible.

`PORTHUB_TERMINAL_SSH_LISTEN` changes the edge bind address; set it to an empty
string to disable ordinary SSH access. Browser sharing uses the existing web
endpoint. Set `PORTHUB_TERMINAL_SSH_HOST` to a directly reachable DNS name/IP if
the web hostname is behind an HTTP-only CDN. `PORTHUB_TERMINAL_SSH_PORT` is the
advertised external port (8347 by default); it does not change the listener.
Forward/allow only that PortHub TCP port through deployment-specific networking.
The Compose update does not alter the host's SSH service or firewall policies.

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

Use `porthub terminal invite NAME --rotate --link-expires 3600` to replace the
links, or `--renew` as an alias. Omitting the lifetime or setting it to zero keeps
new links valid until workspace end. The sharing supervisor saves the pending
capability pair privately with file and directory synchronization before sending
it. After losing acknowledgement or restarting, it retries the same pair and
revision. The CLI prints links only after gateway confirmation; plain `invite`
refuses to display links while rotation is pending. Retrying `--rotate` resumes
that pending operation rather than generating another pair. If a short lifetime
elapsed while offline, confirmation may return already-expired links; rotate
again to issue a new lifetime. This does not extend the workspace lifetime.

A real bundled-supervisor test kills the sharing worker before acknowledgement,
restarts it, verifies the exact saved pair is resent and confirms the same shell
state survives. It also tests explicit renewal after invitation revocation.
A filesystem-failure test verifies that an unsaved update cannot remain in memory
and be sent on a later retry. Browser invitation rotation controls are separate
from this native command and are not implemented yet.
