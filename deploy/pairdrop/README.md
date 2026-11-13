# PortHub's PairDrop integration

PairDrop is served anonymously at `/pairdrop/` and embedded in the Transfers tab.
The API proxies only this namespace to `http://pairdrop:3000`, preserving HTTP
and WebSocket streaming. Portal cookies and authorization headers are removed;
cross-origin browser connections are rejected. No host ports, database volume,
portal configuration secrets or internal control sockets are given to PairDrop.

The service uses the upstream PairDrop **v1.11.2**, commit
`4862ba3067be1a0f2e0d1e94861dc9200b5bfeea`, from
[schlagmichdoch/PairDrop](https://github.com/schlagmichdoch/PairDrop/tree/v1.11.2).
The original multi-architecture image and Node 22 runtime are pinned by digest in
[Dockerfile](Dockerfile). Dependencies are pinned in `package-lock.json`; install
with `npm ci --omit=dev --ignore-scripts`. The dependency lock was audited with no
reported vulnerabilities when introduced.

PairDrop is GPL-3.0; the complete license is [LICENSE](LICENSE). Third-party client
library notices are in [licenses](licenses). The upstream application files come
from the pinned source image. The complete modifications are in [patch.cjs](patch.cjs)
and [porthub.js](porthub.js); the original source can be retrieved using the tag
or commit above. The GPL text is also exposed at `/pairdrop/PAIRDrop-LICENSE.txt`.

The patches add a five-second fallback from failed initial WebRTC negotiation to
PairDrop's own room-authorized WebSocket relay, update its transport indicator,
escape user-chosen names in upstream HTML templates, and bound WebSocket frames
and connected peers. `rtc.json` has no third-party ICE servers: direct local
connections work without an external service; remote peers can use the in-memory
relay. Relay traffic is encrypted in transit by portal HTTPS/WSS and is readable
by the self-hosted relay. Direct WebRTC transfers use the browser's DTLS channel.

The Node service runs as UID/GID 10001 with a read-only root, all capabilities
dropped, a memory/PID/CPU limit, and automatic Docker restart. The PortHub API
continues to run without a Node runtime. Normal `docker compose up -d --build`
includes the service. For a core-only native upgrade, build/start `pairdrop` first
so the existing upgrade helper retains it as an unselected running container.

For development or tests, set `PORTHUB_PAIRDROP_UPSTREAM` to a loopback HTTP
origin running this image. An empty setting disables the proxy. Browser fixtures
use `PORTHUB_TEST_PAIRDROP_UPSTREAM`; tests must never use production account data.
