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
