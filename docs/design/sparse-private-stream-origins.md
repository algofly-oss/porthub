# Sparse private stream authority: intermediate safety boundary

This isolated prototype is default OFF. It is not a completed sparse networking,
optimized-stream, migration-readiness, or native suspend/route proof.

Guarded sparse mode currently declines PHT1 and uses the existing independently
authorized raw packet / DTLS / relay path. This does not construct an oversized
legacy snapshot, raise peer limits, truncate policy, or change legacy PHT1.
The controller withholds its PHT1 offer during sparse negotiation. A legacy
gateway declining sparse restores the ordinary legacy offer on the next sync.
The runtime clears PHT1 peer/port admission in sparse mode, closes prior PHT1
connections through the existing owner, and returns false for new optimization
attempts so the packet owner retains its normal path. Existing proxied flows
cannot be transparently converted mid-connection; activation remains unshipped
and must not be advertised as a seamless live protocol migration.

## Why copying guards are insufficient

The pinned dependency is Quinn 0.11.12. Its `SendStream::write`/`write_all` accept
bytes into the QUIC sender. They do not prove acknowledgement. `reset` discards
local buffered bytes and prevents further retransmission; `finish` ends that
stream. `stopped()` can prove acknowledgement of all finished stream bytes, but
cannot provide an arbitrary chunk acknowledgement on an indefinitely open PHT1
stream. A transport acknowledgement also does not establish application/native
TCP delivery at the receiver. PHT1 currently uses one long bi-stream per TCP
flow. The TCP runner separately has a 16 KiB duplex buffer and a 128 KiB send /
unacknowledged buffer. An emission-time datagram guard cannot reconstruct those
bytes' original authority after renewal.

Primary dependency contracts:
- https://docs.rs/quinn/0.11.12/quinn/struct.SendStream.html#method.write
- https://docs.rs/quinn/0.11.12/quinn/struct.SendStream.html#method.reset
- https://docs.rs/quinn/0.11.12/quinn/struct.SendStream.html#method.finish
- https://docs.rs/quinn/0.11.12/quinn/struct.SendStream.html#method.stopped
- https://docs.rs/quinn/0.11.12/quinn/struct.Connection.html#method.close

## Next protocol and implementation boundary (not implemented)

A separate negotiated ACK-chunk protocol must preserve a long-lived native TCP
flow while using finite acknowledged QUIC streams for bounded data chunks.
Opening a new transport connection per chunk is forbidden. Reuse existing
bounded pinned peer connections and lanes. No sparse capability is enabled by
this design document.

Each directional chunk binds the exact workspace/epoch, local and remote node
identities, assignment, certificate fingerprint and instance, TCP tuple, random
non-reused flow nonce, direction, contiguous sequence/byte offset, and chunk
nonce. Header/data bounds and arithmetic must be checked before allocating or
opening a native leg. FIN/reset has explicit ordered semantics. Reject replay,
foreign-flow acknowledgements, overlapping/out-of-order offsets, and nonce
reuse. A failed/expired chunk must not be retried with a newly minted witness.

A pending chunk owns its original immutable base and exact pair witnesses,
including profile, peer and ACL retirement. A proposed initial ceiling is 8 KiB
payload, 128-byte header, 1 MiB per flow, 2 MiB per peer, 8 MiB globally, while
keeping existing flow/peer/connection ceilings. These are upper bounds, not a
throughput claim: credit fairness and RTT/window measurements remain required.
Admission waits/backpressure rather than silently discarding authorized bytes.

Register the chunk before its first QUIC write. Keep its authority alive in a
bounded pending-origin registry until BOTH the finished QUIC stream is fully
acknowledged AND the exact receiver application acknowledgement arrives. The
latter is sent only after the corresponding bytes have left the receiver's
PortHub-owned TCP retransmission queue and have been acknowledged by the local
native TCP peer. It does not claim that a user's application read those bytes.
Token drop/abandonment is not an acknowledgement: it must fence/reset affected
transport ownership before releasing origin state.

The receiver needs an explicit tagged runner API, not a guarded write into an
unlabelled DuplexStream. Track contiguous accepted byte offsets, smoltcp's
acknowledged progress, and original chunk spans through generated IP/TCP
segments and retransmissions. A segment intersecting several chunks retains
all corresponding original permits. Bound tag/reference memory independently;
when credits are exhausted, stall before accepting more chunk bytes. Never
silently truncate spans, mint a current permit for old buffered bytes, or rely
on aggregate process/network counters as acknowledgement evidence.

At QUIC datagram emission, snapshot the original authorities of all outstanding
application chunks that could be represented by that transport's buffers.
Quinn does not expose a public per-byte emission tag. A conservative per-peer
conjunction across its bounded connections can be used initially; expiry may
fence that peer's transports, but must not affect unrelated peers. The emitted
datagram retains this immutable snapshot through PacketIo, carrier, relay,
session and native send. Removing a fully acknowledged chunk from the registry
must never revive already queued datagrams carrying its old permit. On expiry,
retire the applicable binding BEFORE reset/close wakes a driver. Prove that no
old application ciphertext can escape using a newly published emission permit.

Identical pair renewal may authorize NEW chunks without retiring healthy
unchanged flow identity, but cannot extend old chunk clocks. Changed identity,
assignment, epoch, ACL, explicit denial or profile owner retirement fences old
chunks. An idle cancellation-safe read may restart with fresh authority before
it consumed bytes; a write that accepted any prefix cannot be restarted as if
nothing happened. Use actual read/write cancellation contracts and preserve
explicit error/reset behavior.

## Required proof before enabling optimization

- Actual native TCP runner buffers/retransmissions carry original chunk spans;
  a blocked writer/withheld ACK expires without later native delivery.
- Actual Quinn stream retains a chunk pending through finish/ACK; delayed ACK,
  loss/retransmission, cancellation and peer retirement cannot release or
  re-authorize it incorrectly. Metadata may be recorded; no human payloads.
- Two independently renewed peers keep long transfers alive across many lease
  windows without borrowing authority for an old stalled chunk.
- Wrong flow/peer/direction/nonce/offset acknowledgement never releases credit.
- Bounded memory/credits and progress fairness with multiple peers/flows, not
  just a two-node byte counter. Resource pressure must not grow identity state.
- Legacy PHT1 and sparse raw fallback remain usable independently; unsupported
  negotiation is explicit and does not silently downgrade authorization.
- Actual Linux/Windows/macOS native clock, suspend, route-owner and cleanup
  evidence, plus server retirement/non-reuse contracts, remain separate gates.

## Implemented foundation after the PHT1 decline (still not enabled)

`stream_chunks.rs` is a private, experimental sender actor. It reserves shared
credit before queue admission, owns finite QUIC streams, derives non-reused
chunk nonces from a fresh generation and monotonically advancing header, and
requires both Quinn's finished-stream acknowledgement and an exact fixed-size
application receipt. Wrong/reset/trailing receipts, expiry and caller
abandonment retire the generation before reset/close. Cleanup joins the owner
and releases pending/queued credit after local connection closure. Its receiver
in tests emits an application receipt after reading generated bytes; that is
explicitly NOT a native TCP acknowledgement implementation.

The foundation currently serializes one directional flow's chunks per owned
connection generation. It is neither the final multiplexed/windowed transport
nor a throughput/fairness result. The shared budget must be owned once by the
future runtime manager; constructing independent per-connection budgets is not
an aggregate resource proof. Typed admission-busy/retry handling, whole receiver
validation, native runner span tagging/ACKs, cross-direction ordering, production
protocol negotiation and runtime integration remain required.

The mesh now supports an immutable socket-generation factory and a sealed
`FencedConnection` proving the connection's exact generation and authenticated
peer binding. A fresh mutable admission table cannot replace that factory.
The actual Quinn regression exercises 0.11.12 `State::drive_transmit` preparing
application data BEFORE `poll_writable`, then retaining `buffered_transmit` on
Pending. With a deliberately bounded one-record test queue (production remains
256), the test retires the old generation, republishes a fresh current peer
permit, releases pressure and observes the old socket denying the prepared
transmit. The peer opens no application stream. This tests the real prepared
buffer, not only a callback model; it does not establish native OS suspend or
native TCP delivery readiness.

Primary prepared-buffer implementation:
https://github.com/quinn-rs/quinn/blob/quinn-0.11.12/quinn/src/connection.rs

## Tagged native DATA/ACK foundation (initial TX checkpoint; not integrated)

`porthub-network::tcp_stream::tagged` is a separate experimental adapter; the
legacy DuplexStream runner is unchanged. The tagged API has no unlabelled
DuplexStream writer. A chunk keeps its original permit through the existing
128 KiB smoltcp send buffer and every generated/retransmitted payload packet.
Only one chunk is copied into that buffer until its bytes are TCP-acknowledged;
a second bounded chunk may wait without re-authorizing the first. Global
pending payload credit is 8 MiB, chunks are at most 8 KiB, and the existing
512-flow limit remains unchanged. Packet/device and external output queues
remain bounded at 256 entries. These are safety ceilings, not a throughput or
multiplexing result.

A `NativeAck` is issued only after the whole chunk was copied AND smoltcp's
unacknowledged send queue is empty in Established state, with the original
permit and owner still valid. It binds an unforgeable in-process stack scope,
monotonic native-flow generation, tuple, chunk ID, offset and exact length.
A receipt from another stack/registration or retired owner cannot be reused.
Fresh control grants can maintain control traffic but never replace old chunk
origins. Native connect/write abandonment and connection-owner drop retire
queued packet scopes synchronously; command generation IDs reject stale queued
operations. Budget Busy is explicit and does not revoke prior work.

The tests use an independent real smoltcp TCP peer, not an OS kernel: they hold
actual generated ACK packets, demonstrate that copying bytes to the peer is not
receipt completion, release ACKs for positive proof, and show that late ACKs
under fresh control cannot extend an old chunk. An actual TCP retransmission
after the initial one-second RTO retains the old origin too. Queued incoming
control packets retain their own admission and exact owner before parsing; a
fresh control update cannot relabel them. A blocked packet delivery also
cannot resume after expiry/cancellation. All owned simulator tasks, tuple
bindings and payload credits are checked after cleanup.

## Tagged native RX spans (not runtime integrated)

The next isolated checkpoint accepts an owned native SYN or outbound connect,
then records first-admission sequence spans at the actual TCP device parse
boundary. Its 16 KiB receive window and 256-span bound are explicit; sequence
wrapping, out-of-order data and overlapping retransmissions cannot replace the
first grant with a fresh one. Native TCP still performs its own validation and
reassembly. Missing/ambiguous coverage retires the flow. Consumed duplicates do
not leave false pending claims. Incoming FIN has its own ordered EOF origin.

`NativeRead` carries the original span admissions through downstream queued or
blocked work, and abandonment retires its exact flow owner. A read holds bounded
global payload credit until delivery completes. The native input device queue,
command queue and output queues are bounded separately. A source accepts a SYN,
reads native bytes, observes peer EOF, and can return TCP data after that peer
half-close; its return-chunk receipt waits for a real TCP ACK. Completed ACKs
also retain the original chunk permit, preventing a delayed application receipt
from borrowing a new grant after native ACK completion.

Actual independent smoltcp peers exercise native reassembly, overlap under a
first grant, blocked read delivery after expiry, accepted SYN, ordered FIN,
half-close return traffic, abandoned reads and actual ACK/retransmission.
Sequence-wrap/gap/metadata-bound tests supplement those consumer tests. They
are not host OS kernel/TUN or suspend tests.

## Native FIN and receipt publication (not runtime integrated)

`finish` waits for native TCP's FIN ACK state, not just peer EOF/copying. FIN
packets and retransmissions retain their original grant. An admitted
RST is still validated by native TCP; observing it at the parse boundary prevents
its closure from masquerading as the clean LastAck-to-Closed ACK transition. The TCP timeout is disabled for this adapter, so
that clean transition cannot be manufactured by a timeout. A bounded terminal
receipt scope retains its original FIN grant after native closure; fresh control
cannot prolong an unpublished terminal receipt.

`publish_receipt` binds the sealed ACK to this exact stack/owner/tuple/chunk,
offset and length, and guards every asynchronous delivery poll with its original
grant. Failed or abandoned publication retires the native owner. A successfully
published local FIN receipt preserves opposite-direction response reads; it does
not impose the completed FIN's old deadline on a healthy half-closed response.
Callers still own and must close/drop their bounded `Connection` after both
application directions finish. This is not yet a production receipt writer.

Actual smoltcp consumer tests withhold FIN ACK after peer EOF, exercise clean
LastAck-to-Closed and real RST, expire pending FINs under fresh control, block or
cancel DATA/FIN receipt publication, and positively carry response data after a
completed local half-close. They do not establish host OS ACK/suspend behavior.

A production PHC1 receiver, pre-issued bounded receive-credit/origin binding,
complete protocol negotiation, three-OS suspend/route cleanup and whole-process
resource fairness remain open. Current sender-fixture echo receipts still are
not native delivery proof. Optimized sparse streaming stays declined and the
feature remains default OFF.
