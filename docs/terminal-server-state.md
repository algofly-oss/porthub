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

When a network permits the existing PortHub HTTPS port but blocks a separate SSH
port, enable `PORTHUB_TERMINAL_SSH_MULTIPLEX=true` on the edge. The same PortHub TLS
listener can then serve HTTPS and ordinary SSH. For public port 443, set
`PORTHUB_TERMINAL_SSH_PORT=443` and use a directly reachable SSH hostname;
`PORTHUB_TERMINAL_SSH_LISTEN=` disables the separate 8347 listener. SSH uses its
own encrypted protocol on that TCP port and requires a standard SSH client.
Networks enforcing HTTPS payloads may still block this SSH route.
An HTTP-only CDN hostname still needs a separate directly reachable hostname.

This mode is opt-in. The edge peeks at the first byte without consuming it,
forwards SSH identification to the fixed private API socket, and leaves TLS
bytes for the existing TLS acceptor. Silent connections have a three-second
identification deadline. SSH forwarding has a shared 64-connection limit across
the TLS listeners; reaching that limit does not reject ordinary TLS requests.
API SSH authentication, invitation revocation and participant permissions remain
the same as on the dedicated listener. Edge shutdown cancels active forwarding.

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

### Production browser packaging

The server workflow builds the static UI once on x86_64, loads the exported
terminal page in Chrome, and verifies that xterm creates its terminal and screen.
The same hashed UI artifact is then packaged into every server architecture;
Docker packaging does not rebuild that UI. Local Docker builds retain the normal
UI build stage. The regression check can also be run independently:

```
python3 scripts/test-terminal-production-ui.py --root /path/to/exported/ui
```

This check must use a production export: development mode did not expose an
xterm 6 ESM lifecycle failure in the production minifier. Terminal imports now
select xterm's published browser bundles explicitly. This initialization check
complements the full browser/API/SSH session tests; it does not authenticate a
guest or prove live shell sharing on its own.

### Explicit live deployment smoke check

After an installed client reaches its expected version and source, an operator
can run the scoped live check through an existing SSH host alias:

```
python3 scripts/test-terminal-live-deployment.py --host HOST_ALIAS \
  --version VERSION --revision FULL_VERIFIED_BUILD_SHA \
  --known-hosts /path/to/previously/verified/gateway/known_hosts
```

It requires Node, Playwright and Chrome locally. It verifies the installed CLI
before creating anything, uses a private temporary XDG root, checks the bundled
100000-line history/mouse/Ctrl+A/F7 configuration, and starts one bounded test
workspace. An anonymous browser and ordinary SSH exercise shared output,
actual retained scrollback, disconnect persistence, invitation revocation,
recovery, owner removal and explicit exit. Invitation secrets stay out of its
printed diagnostics. Cleanup stops only the generated workspace, waits for its
sharing supervisor and removes only its private temporary directory; service
units and unrelated workspaces are unchanged. A running or unconfirmed fixture
is retained for operator review instead of deleting its control sockets.

The same check accepts `--binary /absolute/path/to/verified/candidate/porthub`
to test a CI artifact before installation. The candidate must report the exact
expected version and source revision. It uses the existing registration broker;
the check does not replace the installed executable or restart its service.
Keep the candidate executable until fixture cleanup has confirmed its sharing
supervisor exited, then remove only the candidate's private staging directory.

### Upgrading older sharing supervisors

The 1.9.1 client fixes a PTY writer-drop race: the previous writer could send an
EOF byte during attachment cleanup and accidentally end the shared shell. The
new writer closes its own descriptor without typing into the terminal. Explicit
shell `exit`, Ctrl+D and workspace stop retain their normal meaning.

An existing supervisor keeps its loaded code when the installed binary changes.
Before upgrading a host from an affected version, check for active shared
workspaces and account for those supervisors before restarting the broker.
Installing a new binary alone does not upgrade an already running supervisor.
Do not use `terminal stop` as an upgrade workaround: that explicitly destroys the
workspace. A safe rollout with no active shared sessions avoids this transition
hazard; any supervisor migration needs its own preservation test.

### Development direct-transport policy gate

The experimental browser-compatible direct protocol remains disabled by the
shipped sharing supervisor. Its broker gate reads the securely paired private
registration, rather than a display record or another account's configuration.
A paired registration must have a running owner, a valid policy lease and status
no older than 30 seconds. A selected exit or local system-wide Tor preference
keeps terminal sharing on the gateway. Missing, malformed or disabled paired
policy also declines direct negotiation. A registration without a paired private
module has no such exit policy to override.

The broker rechecks an active direct generation every five seconds. If permission
becomes unavailable it closes that generation; the supervisor retains the shell
and reconnects through relay-only negotiation. This protects the paired PortHub
exit policy; it does not detect arbitrary third-party VPN or proxy software.
The native SDK can be built with the experimental `terminal-direct` Cargo
feature. New shares advertise it only with broker metadata version 1.10.0 or
newer. After compatible gateway negotiation, the OS-authenticated broker supplies
the approved control-source addresses in a local-only envelope. That envelope
is not a gateway event, and the gateway cannot inject or replace it. The SDK
configures attachment actors before accepting guests; a build without the
feature clears an old saved direct capability and continues through the relay.

The current handoff supplies host candidates and no implicit STUN/TURN servers.
Full browser/API/native-supervisor tests require actual bidirectional WebRTC
traffic and pass in Chrome and WebKit alongside ordinary SSH guests, independent
history, recovery, targeted removal and explicit teardown. The stress fixture
waits for each guest's initial PTY screen before starting concurrent output.
Account-scoped traffic reporting, approved NAT traversal configuration and the
native optimized join client still need integration before enabling this in
normal release builds. Ordinary unmodified SSH remains a gateway transport.

The optional native peer engine also creates guest offers and accepts bounded
single-data-channel answers. Its in-memory two-peer test pumps real
ICE/DTLS/SCTP packets and checks bidirectional binary delivery without binding a
socket. Candidate validation and receive-buffer limits are shared with the host
answerer. CLI joins default to SSH. Experimental `terminal-direct` builds also
accept `terminal join URL --transport relay` and policy-controlled `--transport auto`;
the remaining account reporting and release checks still need integration.

The full integration check also accepts `PORTHUB_TEST_TERMINAL_DIRECT=blocked`.
It rejects the browser's direct handshake while keeping the real SDK, broker and
API in the path, verifies sequenced gateway delivery, and requires the writer to
survive pressure without a hidden reconnect. This exposed a 32-message actor
queue that could disconnect healthy guests during fast typing. The queue now
admits the protocol's bounded input, acknowledgement and replay windows, with a
separate 128 KiB payload budget. Acknowledgements do not consume that byte budget;
an acknowledgement-only flood still has a finite message limit. Direct receive
frames are parsed once and remain binary inside the native actor.

### Attaching an existing host tmux session

New workspaces use a scoped patch in the bundled multiplexer to remove its
private `TMUX` and `TMUX_PANE` variables from pane processes. Ordinary host
`tmux attach` therefore finds the host's normal server rather than trying to
attach recursively to PortHub. Initial shells, new windows, split panes and
explicit pane commands use the same spawn boundary. Shell selection, argv and
login behavior retain tmux's normal implementation.

Only a PortHub workspace server started with `PORTHUB_TERMINAL_ISOLATED=1` enables this
behavior. That startup flag is removed from child environments. A separate
`PORTHUB_TERMINAL_SOCKET` marker lets the CLI recognize an attachment to its own
workspace. The private owner-sidebar server keeps normal tmux variables for its
focus controls; ordinary servers outside this mode retain upstream behavior.
The source patch fails closed if the pinned spawn boundary changes, and its
build-script hash automatically invalidates the independent helper cache.

Existing workspaces retain their running helper and shell environment. They are
not restarted or modified by this change. In an older workspace, an explicit
`env -u TMUX -u TMUX_PANE tmux attach` affects only that host-client invocation.
Use PortHub's prefix or `porthub terminal tmux NAME -- COMMAND` to control the
PortHub workspace. The new runtime passes the real nested-attach, pane/window,
CLI self-attachment and full native browser/API/ordinary-SSH tests locally;
cross-platform packaging and deployment remain separate release gates.

### Native viewer delivery state (not yet connected to CLI)

The carrier-independent viewer model buffers input during its first negotiation,
then retains bounded, sequenced input until application acknowledgement. A
carrier change replays only unacknowledged frames with their existing epochs.
Whole-paste preflight checks byte, frame and sequence limits before retaining
any part of a paste. Read-only roles cannot enqueue input in any phase.
Output advances its acknowledgement only after the caller commits terminal
acceptance; duplicate output is not rendered twice. Reoffers preserve epochs,
and a new attachment must start a fresh model rather than replay uncertain old
shell commands. Tests cover negotiation failure, replay, invalid acknowledgements,
reordered output, role enforcement, bounded queues and sequence exhaustion.

This delivery model is not yet used by the CLI relay runner, which uses legacy
gateway frames. Direct-path privacy and traffic reporting, native negotiation,
packaging and live rollout remain required before enabling native direct joins.

The experimental `terminal_guest` module now supplies bounded native WebSocket
signaling. It validates HTTPS invitations, strips query/fragment material from
the gateway URL, verifies public TLS trust, and sends the invitation or recovery
capability only in the first encrypted message. It handles recovery-before-Welcome
ordering and application heartbeats, rejects duplicate welcomes and pre-Welcome
output, and blocks read-only input on both legacy and sequenced carriers.
Recovery credentials remain in memory; their grace deadline starts when the
caller takes the credential after disconnection. Connection, authentication,
signaling writes and missing heartbeats have finite timeouts. Tests use real
WebSocket framing over isolated duplex streams and an untrusted local TLS server;
they do not yet prove a native TTY or direct connection through the live gateway.
This module is compiled only with the experimental `terminal-direct` feature.

The experimental Unix native relay runner now connects signaling to a private,
nonblocking controlling-TTY descriptor. Raw control keys, mouse events, paste and
clipboard escape bytes remain unchanged. Resize polling sends dimensions without
cancelling the absolute gateway heartbeat deadline. Output writes apply bounded
backpressure. Dropping or cancelling the attachment restores termios and makes a
nonblocking best-effort reset of mouse capture, bracketed paste, cursor and screen
modes; SIGKILL and an inaccessible local terminal cannot guarantee that reset.

The read-only history pager is shared by ordinary SSH and the native runner under
the separate `viewer-history` feature, avoiding an SSH server dependency in the
native guest. Read-only F7/navigation issues history requests rather than shell
input. PTY/WebSocket tests cover both roles, exact raw bytes, history rendering,
resize, cancellation and terminal restoration. These tests use isolated framed
WebSockets and a real local PTY. The CLI now selects the experimental runner with
`--transport relay` or experimental `--transport auto`; account reporting and
release/platform validation remain pending. Windows guest TTY support also
remains pending; the new raw descriptor implementation is Unix-only.

### Experimental native CLI relay and bounded recovery

Unix `terminal-direct` builds support `porthub terminal join URL --transport relay`
without invoking an installed SSH executable. The default remains `--transport ssh`.
The native relay runner uses the same browser endpoint and invitation roles.
After a transport failure it closes the old socket and resumes only with the
in-memory recovery credential, within one fixed grace deadline. Failed attempts
back off from 250 ms to 2 s without extending that deadline. A recovery credential
rotated before a lost Welcome is retained. Explicit rejection, local terminal
failure and nonretryable closure stop recovery; the original invitation is never
an automatic fallback.

Unconfirmed old commands are never replayed across attachments. Keystrokes typed
while offline are discarded, including the final queued tail at reconnection;
the reconnect notice explains that input is paused, and Ctrl+C cancels locally.
While connected, Ctrl+C/Ctrl+D remain raw shell input. SIGHUP/SIGTERM/SIGINT detach
the CLI and let its terminal guard restore local state without stopping the shared
workspace. Clipboard escape bytes still depend on the local terminal's clipboard
permissions; relay transport does not add a system clipboard bridge.

The test suite covers forced disconnection, a transient reconnect failure,
credential-only resume, no old/offline command execution, fixed deadline expiry
and immediate rejection. The optional `--native-guest PATH` live smoke exercises
an experimental local CLI against a temporary workspace on the installed stable
host, alongside browser and ordinary SSH participants. The Reid check passed
shared shell I/O, read-only F7, SIGTERM detach and workspace persistence, with the
service PID and restart count unchanged. This is smoke evidence for the relay
candidate, not a published package or a deployed native direct transport.

Native platform CI runs the experimental guest socket/TTY/recovery and CLI-selection
checks on Linux x86_64 and macOS arm64, without enabling the experimental feature
in published binaries. These tests use isolated local fixtures, not production
accounts or live machine credentials.

### Native direct transport controller (experimental auto selection)

The optional native controller now runs real ICE/DTLS/SCTP over a caller-supplied,
concrete bound UDP socket. The caller must approve that socket against its exit
and privacy policy before use. It opens no additional interfaces or implicit
STUN/TURN services. Authorization, SDP and role assignment still use the gateway.
The shared native TTY runner accepts this approved socket through `run_with_udp`;
normal CLI `--transport relay` continues to pass no socket and uses the gateway.
Experimental `--transport auto` now selects a local registration, obtains its
short-lived broker permission, and uses the existing TLS connection's local source
address for UDP. Unknown or ambiguous local policy stays on relay.

The controller uses the bounded viewer delivery journals for both paths. Direct
input ACK stalls switch to sequenced relay after 1 s without resetting epochs or
repeating acknowledged input. Whole input batches are retained before a carrier
attempt, and the TTY reader pauses when the byte/frame window is full. Output ACKs
advance after terminal acceptance; a frozen read-only history view intentionally
discards live-screen updates and redraws when returning. An unanswered offer is
bounded to 15 s, an ICE attempt to 10 s, and input without ACK progress to 15 s.
Failed direct paths release the UDP socket and its polling deadline. The idle
relay does not spin. Malformed authenticated protocol data remains a fatal guest
error, while transport stalls can use the bounded recovery path.

RTC state and the reusable UDP receive buffer live on the heap so introducing
this path does not overflow ordinary test-thread stacks. Per-controller counters
record actual UDP bytes including negotiation, overhead and retransmission; these
are not yet account dashboard reporting. Approved NAT settings,
account-scoped traffic reporting and production release gates remain necessary
before enabling automatic direct joins.

Local tests now exercise two real UDP peers, deferred output ACK, a deliberately
lost input ACK followed by relay replay with exactly one input application, bounded
negotiation/input waits, failed ICE cleanup, and an idle relay. A bundled-shell
integration preserves shell variables across native direct-to-relay switching and
keeps a second participant usable. A separate real-PTY/native-guest loop verifies
terminal output, automatic UDP-to-WebSocket fallback and no repeated input through
the actual TTY runner. Linux x86_64 and macOS arm64 CI include the controller and
bundled-shell native transport checks alongside guest recovery tests. No live
service or published package was changed for this controller work.

The native controller also keeps an unsent input cursor when the SCTP sender
window fills. Healthy transport backpressure waits for capacity rather than
forcing relay; output ACKs may use the gateway while that sender is full. The
real UDP test sends a full 64 KiB binary input window and verifies the direct
path remains active, then deliberately suppresses application ACKs and verifies
relay replay applies the later input only once.

### Native auto selection and revocable local permission

Experimental Unix builds accept `porthub terminal join URL --transport auto`.
The default remains SSH. Auto uses native relay when the gateway/host does not
advertise direct support or a trusted local permission cannot be obtained. It
requires no PortHub login to use the invitation. Direct eligibility requires a
local enrolled agent with a live, enabled, securely paired private identity,
fresh status, valid lease, no selected exit, no system-wide Tor preference and
no prefer-gateway path preference. An unpaired or unknown local policy does not
approve direct UDP. `--registration ID` and `--user` explicitly select the local
policy owner; without them, automatic selection requires exactly one enabled
public registration across the system and user layouts. Display records only
locate that agent and cannot grant permission.

The credential-free `terminal_guest_policy` operation uses the broker's existing
OS-peer authorization. Its only response fields are `allowed` and `expires_at`;
registration tokens, account identities and private profile paths stay inside
the service. Approval expires within 4 s and is renewed every 2 s. The client
checks expiry against wall time and revokes on silence, disconnect, malformed
response or denial. The settings reader remains available when the Tor engine
is compiled out, so that build choice cannot ignore a saved system-wide setting.

The native controller checks the permission before UDP transmission and before
choosing direct delivery, including already queued SCTP data. Revocation releases
the socket and continues with the same sequenced relay journals, without creating
a replacement guest or shell. No cached permission approves a new attachment;
recovery consults the local agent again. Tests cover permission expiry, live
paired-policy revocation, cross-gateway rejection, ambiguous registrations,
Tor-free builds honoring saved settings, queued UDP suppression, and a real PTY
guest surviving privacy revocation without repeated shell input. Linux/macOS CI
includes these policy tests and the no-default-features settings checks.

This path is still experimental and is not enabled in ordinary published builds.
Account-scoped traffic reporting, approved NAT configuration, cross-platform
packaging and authorized production rollout remain release gates.

### Host-side terminal traffic measurements (reporting pipeline pending)

Each attachment now has content-free counters for bytes successfully written to
its PTY, bytes read from its PTY, and UDP bytes observed by the host RTC transport.
The host also keeps aggregate counters. Producers hold the aggregate reference,
so a write completing after guest detachment still contributes without retaining
an ever-growing list of detached guests. Updates are atomic and saturating; a
snapshot reads independent counters rather than a transactional cross-field sum.
No command, output text, invitation, account identifier or credential is stored.

PTY output includes per-participant redraws and can include bytes that have not
yet reached the viewer. UDP observations include RTC protocol overhead and
retransmissions, but exclude separate external candidate-discovery probes and
cannot recover bytes truncated from invalid oversized datagrams. These scopes
must be shown separately; summing PTY payload with UDP would double-count data.
They are operational measurements, not a NIC accounting or billing meter.

The real bundled-shell direct/fallback integration checks exact application input
counts, host UDP observations, an independently measured legacy participant and
host aggregation. Unit tests check concurrent producers after detach, saturation,
and partial PTY write failure counting only accepted bytes. These measurements
are currently available through the host attachment API only. The next reporting
step must bind them to the installed agent's authenticated machine/session before
API persistence and account-scoped dashboard presentation. Guest reports must not
supply authoritative machine identities or metrics. No reporting messages have
been added to older gateway protocols, and no live service was changed here.

### Authenticated local traffic reporting (API persistence pending)

New sharing supervisors negotiate `traffic_reporting` only with a broker version
that supports the local extension. After the gateway accepts the host session,
the broker supplies a fresh local traffic epoch. Cumulative PTY/UDP reports use
that epoch and increasing sequences; exact replays are idempotent, conflicting or
regressing reports fail, and a report cannot choose a machine, account or profile.
The broker binds scope from its existing OS-authorized registration connection.
The traffic policy and reports are local envelopes, not gateway or guest events.
A real-WebSocket regression test verifies an older gateway receives only its
existing protocol, even while the broker consumes repeated local reports.

The service aggregates counters per enrolled profile and process lifetime, with
a random instance ID and a monotonic revision for later idempotent API uploads.
Closed connections clear active gauges but retain cumulative observations. State
is bounded to 128 profile stores and 1024 simultaneous streams per profile. The
host samples approximately every 5 s and on closure/end when possible. Process
crash or connection loss can leave a final unsampled interval; this remains an
operational measurement, not exact billing accounting.

The broker also measures forwarded terminal application payload for legacy
supervisors, without requiring new owner-side messages. It derives participant
gauges from authenticated gateway membership events, rather than trusting guest
reports. Gateway payload excludes control messages and TLS/WebSocket framing;
it includes relayed live output and history pages. PTY observations and direct
UDP remain separate scopes. Do not sum overlapping scopes into one total.

`porthub stats --json` includes a terminal measurements section, and the selected
agent's interactive details show sessions, guests, gateway payload, PTY bytes and
direct UDP. Missing host measurements are labelled as unreported. The 80-column,
24-row layout keeps selection and quit controls visible. Existing mapped sharing
supervisors continue serving; upgrading the service does not inject unknown local
messages into them or stop their jobs. Collecting these counters adds no cloud
request or additional terminal liveness probe.

API persistence, authenticated account-level graph queries and dashboard display
are still pending. No server/client deployment was performed for this step.

The broker also requires local traffic-report negotiation before enabling the
host's direct capability. An older sharing supervisor therefore continues on
relay, where the service observes payload, rather than opening an unmeasured
peer path. This changes no workspace or invitation lifecycle.

For broker rollback or unavailable version metadata, a new supervisor strips the
new hello capabilities from the wire request and omits the reporting extension.
It retains the saved session capabilities, so a later compatible broker can
restore them without replacing the workspace. A boundary test covers this path.

### Account-scoped terminal measurement storage (source only)

The API now accepts strict, content-free cumulative reports at
`POST /api/machines/client/terminal-traffic`, authenticated with the existing
machine credentials. Account and machine ownership come from the authenticated
machine record; callers cannot supply an owner selector. The agent and API use
the same report schema. Counters must fit exact JSON integers, gauges are bounded,
and service-instance revisions cannot advance with regressing cumulative totals.
Repeated identical snapshots and older revisions do not change totals or renew
retention. Conflicting revisions are rejected.

The first snapshot of each service instance establishes a baseline: it does not
invent a rate for traffic predating the first upload. Each subsequent accepted
snapshot atomically updates both the baseline and its rollups in one MongoDB
document, without requiring replica-set transactions. Server receipt time assigns
buckets. The bounded windows are 120 five-second buckets, 1,440 minute buckets,
168 hour buckets and 30 day buckets. Inactive instance documents expire after
30 days. Account and machine deletion remove the corresponding measurement
records. Delayed uploads attribute their accumulated delta to receipt time;
these operational measurements are not billing records.

`GET /api/terminal/traffic` returns at most 120 aggregated points for `10m`, `1h`,
`24h`, `7d` or `30d`, with an optional `machine_id` filter. Aggregation and ownership
filtering run in MongoDB, rather than downloading a fleet's raw records into the
browser. Current machine ownership is checked again during the query: transferred
or deleted machines are excluded, and administrator status does not expose other
accounts. PTY payload, direct UDP observations and gateway relay payload remain
separate scopes and must not be summed as unique application traffic. This endpoint
covers terminal hosts, not all private-network or public-port traffic.

Real standalone MongoDB tests cover authentication, replay, out-of-order reports,
concurrent requests, conflicting counters, ownership transfer, cross-account
queries, midnight transitions and expired buckets. The server packaging workflow
requires these checks. The background agent uploader and capability negotiation
are described below. Dashboard integration and release/deployment validation
remain pending.

### Service-owned reporting and full browser CI (source only)

An authenticated host WebSocket now advertises `x-porthub-terminal-traffic: 1`.
After the gateway accepts the host, the privileged broker starts one reporter per
registered profile, independently of that terminal socket. Machine credentials
come only from the service's control profile. Older gateways without the header
receive no reporting requests; direct hosting also requires this ingestion
capability, alongside local traffic-report negotiation and the existing privacy
checks. Existing relay-only supervisors still get service-observed relay metrics.

The reporter samples at five-second intervals and uploads changed measurements
and gauges. Empty host samples that only advance freshness/revision are coalesced
into at most one heartbeat per thirty seconds while sessions are active.
HTTP attempts have an eight-second deadline. Temporary failures back
off from five to sixty seconds and retry the latest snapshot, without a payload
queue or a terminal reconnect. Lost acknowledgements are safe because the API
accepts idempotent revisions. Invalid/disabled/deleted credentials or conflicting
reports stop that reporter; none of these paths stop a shell, guest or connection.
With no active sessions, reporters send no unchanged snapshots and remain
available for the next session until the broker service cancels them. Cancellation also interrupts a
stuck HTTP request and releases the profile's worker slot. Final measurements can
still be lost if the entire service crashes before upload; this is not a durable
billing journal. Guest-side discovery probes are not included in host counters.

The native integration fixture now publishes explicit test-only 1.10 broker
metadata, so it actually exercises the upcoming history/reporting/direct contract
rather than silently selecting the older relay contract. This does not label a
development binary as a released 1.10 artifact. The fixture checks actual PTY,
relay and direct UDP measurements in MongoDB, final closed-session gauges and a
bounded authenticated graph query after explicit shell teardown.

`scripts/test-terminal-browser-integration.py` serves the exported browser assets
on its own random loopback port and runs real browser/API/broker/bundled-shell
flows. It covers Chrome and WebKit, each with working WebRTC and deliberately
blocked direct transport. Ordinary read-only and interactive SSH guests, anonymous
browser guests, host controls, shared shell state, independent history, recovery,
revocation and teardown run in each case. All four cases pass locally. Server
packaging now depends on this matrix using source-verified exported UI artifacts,
pinned browser tooling and an isolated MongoDB service. This source has not yet
been released or deployed; dashboard display, approved NAT configuration and the
remaining platform/release checks still need completion.

The full browser matrix exposed an intermittent gateway egress failure during a
native-owner redraw with WebKit on the relay path: a 64-message viewer queue filled
with small delivery frames and detached an otherwise healthy guest. Viewer egress
now permits the protocol's 256-frame replay window, its ACKs and 64 control messages
(576 queued events), with a separate 1 MiB quota charged for event storage and heap
capacities. Drain, rejection and receiver shutdown release the permits. Large
payloads still hit the byte limit, and tiny control floods still hit the count
limit; exceeding either budget affects only that participant. The SDK's
`Attachment.events` uses `hub::ViewerEvents`, retaining `recv` and `try_recv`.
A regression test holds a full replay window plus ACKs without draining and checks
that the participant remains attached. Browser diagnostics now record connection
phases without terminal contents or invitation/recovery capabilities, so an
unexpected reconnect cannot silently pass the end-to-end test.

### Terminal account dashboard (source only)

The dashboard now has a separate Terminal traffic card beside the existing
public-port monitoring sections. It defaults to gateway relay payload and offers
separate direct UDP and attachment PTY views. These scopes overlap and are never
added together. Directions are relative to the host. The chart shows byte volumes
per server-receipt interval, rather than inventing instantaneous NIC speeds.
Hover and keyboard navigation expose individual intervals. Missing reports remain
gaps; measured zero values remain visible measurements. Details explain baseline,
redraw, overhead and delayed-upload limits. This card does not claim to cover all
private-network traffic or identify anonymous guests as registered machines.

Machine selection uses the existing bounded remote inventory control. Supported
windows are 10 minutes, 1 hour, 24 hours, 7 days and 30 days, with no more than 120
points returned by the authenticated database aggregation. Scope changes reuse
the same six counters without another request. `terminal_machine`,
`terminal_range` and `terminal_scope` are shallow URL parameters and survive a
reload. Data is cached only in the signed-in workspace's memory. Requests run at
15-second intervals only while the dashboard is active and visible. Pause stops
polling; Refresh dashboard can explicitly request a fresh snapshot. Errors retain
and label the last successful snapshot. Filter changes cancel obsolete requests
and never reuse another selection's graph.

Rollup points now carry server-derived `host_reports` and `unreported_hosts`
coverage markers. Service-observed legacy relay activity alone does not establish
PTY or direct UDP coverage. Old rows without coverage markers are conservatively
unknown in those views. Zero-byte modern reports establish real coverage, and
mixed reporting windows carry an incomplete-measurements notice. Counter storage,
coverage and baseline changes remain one atomic MongoDB operation.

The production export passes responsive dark/light tests at 1512, 402 and 320
pixels in Chrome and WebKit, including URL persistence, keyboard controls, empty,
failed, malformed, legacy and measured-zero states. The real API/broker/bundled
shell matrix now opens this dashboard with the machine owner's actual session
cookie. A loopback-only test-router fault simulates an upstream reporting outage
through the real PWA, verifies retained snapshots and recovery, and counts server
requests to prove Pause stops polling. Those fault endpoints exist only in the
integration test; they are not production routes. The UI tests run automatically
in the existing server packaging gate, and pure data validation runs in prebuild.
Dashboard hover state stays inside the chart instead of rerendering inventory
controls for each pointer movement. No charting dependency was added.

This completes the source integration from local host measurements to account
storage and dashboard display. It is not a release or deployment attestation.
Approved NAT configuration, the upcoming client feature/version selection,
platform packaging validation and authorized live rollout remain outstanding.

## Explicit terminal discovery configuration (source candidate)

Terminal hosts can opt into up to two credential-free UDP STUN endpoints with
repeated `terminal share --stun-server` flags. Native guests independently opt in
with `terminal join --transport auto --stun-server`. Browser participants have
Connection options with the same bounded endpoint list and a relay-only choice,
stored in their own tab's session storage. There are no built-in third-party
endpoints, and gateway messages cannot populate these local settings. Editing
browser options does not join a session or create a discovery peer.

Host endpoints are persisted in the OS user's private sharing state and passed
only over the authenticated local broker connection. They are not part of the
public host hello. An already shared workspace rejects a request to change its
endpoint list or switch an existing direct-capable share to relay-only; existing
guests are left running. Repeating share without flags preserves existing
settings. New shares support `--relay-only`, which conflicts with STUN flags.

Discovery uses each actual bound ICE UDP socket, preserving the reflexive hint
for that socket. Native guests bind the signaling connection's selected source
address (and its interface on macOS) and check the local expiring permission
before each discovery transmission. Host discovery remains inside its cancellable
transport generation; local policy changes invalidate that generation. Existing
privacy restrictions take precedence. Probes share bounded DNS/retry budgets and
are excluded from terminal traffic counters. STUN improves address discovery;
it does not guarantee direct connectivity through every NAT/firewall. Gateway
relay remains the fallback, and ordinary SSH participants continue using relay.

Native connection setup now drains waiting keystrokes instead of allowing them
to become delayed shell commands. Ctrl-C during initial connection/discovery
cancels only the local attachment, preserving the shared workspace.

These are source changes pending packaging and rollout. Local loopback discovery
and simulated NAT tests do not establish public-WAN reachability. The upcoming
1.10 capability metadata, release feature selection, platform builds and scoped
live verification remain required before claiming this version deployed.

Validation for this candidate: 42 agent terminal tests, native CLI parsing, the
minimal no-default-feature agent compile, five mesh discovery tests, the full
85-test terminal SDK suite, and a fresh bundled-shell discovery/fallback test
passed. The rebuilt production UI passed 12 discovery-consent/layout cases and
22 dashboard scenarios across Chrome/WebKit and dark/light desktop/mobile
layouts. All four real API/broker/bundled-shell browser flows (Chrome/WebKit,
direct/blocked) passed, including owner administration, read-only guests,
recovery, history pressure, reporting failure recovery and explicit teardown.
These checks used isolated loopback services and did not restart live clients.

## 1.10 packaging and rollout preparation

Release source `891172f6e87f1cb0c416b48977dde6027a8a101e` enables
`terminal-direct` in default agent builds and advances workspace metadata to
1.10.0. All four server/agent roles compile with the locked dependency set, and
42 terminal agent tests pass with the new default feature configuration.
Client packaging run 41279957114 and server packaging run 41279957045 were
started from that exact revision; these run IDs are not success attestations.

The server measurement job exposed a workflow-only error before checkout: the
runner split the single-quoted MongoDB Docker health command. Commit 2029f1f
uses a double-quoted health command verified with an isolated actual MongoDB
container. Server dispatch now accepts an explicit source revision so workflow
fixes can validate/package the original immutable candidate. The failed gate
must be rerun with that corrected workflow before deployment.

The source checkout is staged at
`/home/ubuntu/algofly/porthub-release-1.10.0-891172f` on urm2, with the existing
private environment copied privately; Compose configuration validates. No live
container or agent was upgraded during staging. IBI, Thor, Home Presence and
Autolycus baseline routes returned HTTP 200. The existing 1.9.1 Reid agent also
passed the scoped browser/stock-SSH live smoke with explicit teardown and cleanup,
without changing its service. The live smoke now has an optional
`--require-modern` gate that requires frozen-history negotiation, a resolved pane
and a stable capture while shell output continues. That gate still requires
execution against the upgraded deployment; its addition is not proof of rollout.

## Packaging gate follow-up

The actual packaged x86-64 1.10 client (source 891172f, SHA256 sidecar and verbose
build metadata checked) passed native relay I/O, read-only F7, clean detach and
workspace persistence against the still-live 1.9.1 Reid/gateway deployment. The
browser/stock-SSH smoke also passed, and its private workspace was cleaned up.
No installed service changed. All five Linux and all three Windows packaging
jobs passed; macOS completion remains a release gate.

The server verification cache needed an absolute root, as already required by
the helper builder and used by client jobs. Workflow commit 9b3dbda corrects it.
The subsequent browser gate reached a shared shell and connected ICE peers,
but its test required setup traffic to have traversed a channel that could open
later. The test now waits for both channels and sends fresh shell output before
requiring bidirectional direct frame counters. This stronger ordering passed the
real API/bundled-host/browser flow using the packaged 1.10 Linux client.

The macOS ARM64 package compiled and passed sharing checks, then timed out in
its final Ctrl+D PTY test; process-group cleanup masked the timeout with EPERM.
Test commit 3554a82 drains PTY output while waiting for exit with the same
three-second deadline and falls back to terminating the owned child when group
signaling is denied. A full-buffer regression and a deliberately stuck child
prove that draining unblocks output while still rejecting deadline violations.
The packaged Linux participant test passes; targeted macOS verification run
41281592532 must still establish the Darwin result. This is a test-harness change,
not a production fix or an assertion that macOS packaging has passed.

Follow-up server verification must use the current test source rather than pin
its checkout to the older test script at 891172f. Product Rust and browser UI
code remain unchanged by these workflow/test follow-ups; record the exact server
build revision separately from the immutable client bundle when deploying.

## Live gateway and attachment-generation fix

Server run 41282736684 passed all build, UI, database, Chrome/WebKit direct and
blocked-path flows and image packaging gates at source
48a47c1707e5e1795e35342b48564568a3466cc6. Its image archive was transferred to urm2
without copying a GitHub token, verified against GitHub's SHA256/size, checked for
canonical entries, and validated against every role checksum and source/version
marker. Only core and edge were loaded for this scoped upgrade.

The read-only upgrade preflight passed. A database audit found zero active
terminal sessions before restarting the gateway. The authorized core/edge
upgrade succeeded with a verified cold backup and retained immutable rollback
references at
`/home/ubuntu/algofly/porthub-release-1.10.0-48a47c1/deploy/native/upgrade-records/48a47c1707e5e1795e35342b48564568a3466cc6-czk1dutr`.
Both selected roles now report healthy 1.10.0/source 48a47c1. The firewall remains
1.8.4/source 9b6c65d, and the upgrade tool confirmed all unselected running
containers remained running. All four public application routes return HTTP 200.
IBI and Thor match baseline body hashes. Home Sense and Autolycus serve newer
static HTML than the original baseline; their expected titles and same-origin
script assets were checked instead of claiming identical response bytes.

The upgraded gateway passed the scoped live anonymous-browser/stock-SSH/native
relay smoke with the unchanged 1.9.1 Reid host, including read-only F7, history,
revocation, recovery, removal, detach persistence and explicit teardown. Its
private test workspace was cleaned up. No installed agent was upgraded.

Client recovery run 41283189259 verified eight eligible Linux/Windows artifacts
for reuse and packaged macOS ARM64 with the corrected PTY test. Its final bundle
was blocked by Intel macOS; retained archives were not yet assembled.
Intel macOS exposed a history-router timeout. Investigating that path revealed a
concrete production race: dropping an old PTY can enqueue Closed after a new
attachment has reused the same public participant identity. The old router then
removes the replacement. A new isolated real-shell regression reproduced that
failure before the fix.

The client SDK now stamps PTY/RTC/history work with a per-admission generation.
Late callbacks cannot close or write into replacements or invalidate their
history ownership. Forwarders are cancelled on detach, EOF reliably emits a
scoped closure even if the producer's best-effort queue was full, and workers
cannot target independent participants. Activity heartbeats retain their scope
and remain valid. The before-fix regression fails and the fixed regression
passes. All 90 terminal SDK tests and all four real browser/API/bundled-agent
flows pass, including the CI-like TERM=dumb parent environment. Agent terminal
checks also pass. History test failures now identify the request and attachment
state instead of hiding a close behind an unexplained timeout.

This is an actual production-input change, so the older client artifacts are
no longer eligible for reuse. Fresh client packaging is required before client
rollout/publication. The earlier uninstalled EC2 staging binary was checksum-
checked and removed, rather than risking its accidental installation. The live
core/edge services do not execute the client host-attachment router; their
validated deployment does not need restarting for this client-only fix.
