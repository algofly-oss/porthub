# Native private packet transport

The Rust `porthub-mesh` crate implements UDP ICE connectivity checks and mutually
certificate-pinned DTLS IP records. It uses the sans-I/O webrtc-rs protocol
components rather than invoking an external WebRTC or Go process. Every peer
connection binds its enrolled ID, process context and exact SHA256 certificate
fingerprint; a LAN address is only a candidate. Replayed DTLS records and a
substituted certificate do not deliver packets.

The Linux agent's private `run --profile` mode owns an exclusive, nonpersistent
TUN, private /32 routes, an expiring allow-only packet policy, stateful TCP/UDP/
ICMP replies and a private authoritative DNS responder. DNS registers the owned
link with systemd-resolved over D-Bus and binds a high port on its assigned
private address. Queries are accepted only from the local host. It does not
claim an application's port 53 or rewrite global resolver files. Dropping the
TUN removes its interface and routes. Existing interface names or conflicting
network routes are refused.

Each peer can advertise up to 16 local IPv4 interfaces. Physical Ethernet/Wi-Fi
interfaces precede existing overlay interfaces in ICE preference. Private sync
and signaling run separately from packet forwarding. Bounded queues isolate
slow peers. Active inner flows retain their established direct or gateway
transport; queue pressure does not cause transport changes. A failed direct
transport can fall back to the already connected gateway.

When both transports are ready, the agent measures them in the background using
authenticated probe frames over the existing peer session and gateway relay.
It attempts a 32-packet measurement for one peer each second, rotating through
up to 64 ready peers; each peer is measured at most once every two minutes. It
skips peers with application traffic in the preceding 20 seconds. The bounded
relay queue is not flooded by probe bursts.
The frames never enter the TUN, and no host or public IP addresses are logged or
advertised by the measurements. The agent estimates each direction's payload
rate and RTT, then uses a route only when its measured rate is at least 20%
better or its RTT is at least 10 ms lower. Scores expire after ten minutes.
Measurements select the route for new flows; established flows stay pinned.
Explicit path settings continue to override automatic selection.

STUN gathering uses each actual bound ICE socket before its receive owner
starts. Up to two operator-provided UDP STUN servers share a 1.5-second budget
per interface; interfaces gather concurrently within the bounded preparation
workers. Responses must match the server address and a fresh random transaction
ID. Reflexive candidates retain their base interface for sends. A protocol NAT simulation verifies mutually pinned
DTLS with only reflexive candidates, separately from a real UDP STUN fixture.
Neither local fixture is evidence of performance through a physical ISP NAT.

The agent also prepares standard TURN allocations over a TLS WebSocket on the
same API port. ICE advertises these alongside LAN host candidates; LAN candidates
retain the higher preference. The selected TURN path carries the same mutually
pinned DTLS records as a direct connection. Gateway allocations only route to
other authorized allocations in memory; they cannot access arbitrary host or
Internet sockets. The transport uses the standard TURN relay protocol. No
additional listening port or helper process is required.

Preparation runs outside packet forwarding and the sync lease loop, with at most
four concurrent preparations and 64 peer sessions. Signals stay unacknowledged
until their prepared session can accept them. Cancelling discovery closes its
WebSocket and TURN timers. Route reports distinguish selected relay and direct
candidate pairs.

Linux underlay discovery subscribes to kernel link, IPv4 address and route
events, coalesces changes for 250 ms and resynchronizes every two minutes.
Unchanged address sets do not wake negotiation. Down interfaces, overlay links
and duplicate addresses are excluded; a link created between address/link
snapshots waits for the next refresh. Starting without an eligible address does
not stop policy sync or relay recovery. New negotiations use current addresses,
and completed preparations with no remaining eligible address are discarded.
Healthy sessions retain their bound sockets; failed sessions are rediscovered
using the refreshed underlay. These operations do not run on packet delivery.

A separate compatibility fallback remains as authenticated WebSocket traffic on
`/api/access/private/relay`, sharing the existing API port. Private sync publishes
15-second credential/instance/policy leases into a bounded in-memory hub.
The gateway checks source/destination peer address bindings and permitted pairs;
receiving agents also enforce their protocol/port policy. The fallback uses TLS
on each gateway connection. It does not claim end-to-end DTLS encryption through
the gateway. Its bounded packet queue relies on the inner IP transport for
reliability and has not yet met the physical bandwidth acceptance benchmark.

`porthub enroll --install-service` can install the Linux system service and
publish the shared CLI. Plain `enroll` continues to stage credentials only.
Public and private native registrations use separate deterministic identities
and scoped lifecycle operations. Windows/macOS private device and service
support remains unfinished.

Verification includes real UDP Rust/Rust peers, certificate substitution and
record replay rejection, real native API/Mongo discovery and packet transfer
after the gateway is shut
down, native gateway relay authentication/source binding/policy revocation,
packet ACLs, route pinning and private DNS responses. Forced gateway-only tests
exchange 256 full-size packets in both directions with native Rust peers.
Background discovery prepares relay candidates before a separate test
confirms LAN selection and transfers 1,024 full-size round trips with the entire
gateway shut down. These are local integration checks, not physical WAN bandwidth
acceptance results. A disposable network
namespace verifies kernel UDP packets through the TUN, route updates and cleanup.
An explicitly authorized root test on Luna verifies systemd-resolved integration
on a temporary PortHub-owned interface.

Remaining acceptance gates include physical NAT connectivity, TURN
credential renewal, sustained failure/recovery, probe accuracy and stability
under production traffic, large-workspace demand scheduling (the current
proactive session cap is 64), physical network-hop validation, full private
runtime/HTTP benchmarks on Luna/Condor/Miro, legacy service adoption, all
platform lifecycle support, native update application and production rollout.
The control loop polls once per second during negotiation and backs off to
five seconds when its discovered peers are ready (or there are no online peers).
Further fleet-wide scheduling validation is still required.
