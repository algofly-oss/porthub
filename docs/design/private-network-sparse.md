
### Local authenticated flow authority checkpoint (not runtime readiness)

The experimental flow context captures one locked sparse pair view: metadata,
compiled directional ACL, and both original base/pair request witnesses. Each
endpoint has its own local policy epoch; reciprocal epochs need not be equal.
The common digest binds workspace, both exact peer descriptors, both local epoch
labels, nonce, and TCP ports. A received remote label never grants local access:
each endpoint separately checks its own captured epoch, service-direction mask,
identity, and original bounded witness. Renewing a cache entry does not reset an
already captured request start.

Tagged native reads additionally carry their original stack scope, connection
generation, and tuple. Another connection cannot adopt a read even when its TCP
tuple matches. The raw byte sender method is private to the experimental chunk
module. These are admission building blocks only: authenticated flow-open wire
exchange, the native-read-only source facade, DATA/FIN duplex runtime hookup,
multiplexing/fairness, and native three-OS retirement proof remain open. No
production capability or default is enabled by this checkpoint.

### Native source bridge and finite duplex prototype

The private source facade now accepts an authenticated context and an exact
native connection; callers cannot submit arbitrary payload bytes or substitute
an opaque per-body grant. Each read is checked against its native stack,
connection generation, and tuple. Its retained first-origin permit is combined
with the atomic current local pair view, while an idle wait uses only a current
owner veto, without manufacturing a new byte-admission lifetime.

PHO2/PHA2 flow-open uses exact 96-byte bounded pinned-TLS exchanges. PHR2 binds
the response direction to the already established context and initiating service
grant. Each endpoint's own epoch and original request witness authorize its own
half. Received TTLs shorten a start captured before stream credit was issued;
opening response/prepared-transmission fences retain the minimum local and
remote bounds. A two-second opening timeout is a resource limit, never an
authority renewal. PHF2 carries a zero-body FIN; its receipt requires actual
native FIN acknowledgement under the original FIN witness. DATA or another FIN
after terminal admission is rejected.

An actual in-process fixture now routes native application request DATA/FIN and
response DATA/FIN through two pinned-TLS connections and two independent
smoltcp legs. A blocked native ACK plus local source revocation cannot produce
a receipt. One shared budget per endpoint admits exactly one source and one
receiver slot per flow, with unchanged aggregate connection/peer/byte bounds.
These tests do not use host routes, adapters, or OS sockets for private traffic.

Completion ownership remains important: destroying the source generation as
soon as it consumes a terminal receipt can suppress Quinn's queued receipt ACK.
The duplex runner therefore retains both owners after its work completes. It
exposes a conservative drain bounded by the minimum of the two ORIGINAL FIN
witnesses; it never starts a fresh drain lease. The paired test retains both
completed owners until both peers finish, then verifies explicit cleanup. A
production distributed completion/drain controller, idle-credit renewal without
relabeling buffered work, runtime SYN admission/dispatch, multiplexing/fairness,
and native three-OS route/suspend proof remain required. This prototype is not
production-negotiated, advertised, or enabled by default.
