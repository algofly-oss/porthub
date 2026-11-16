# Private authenticated microphone proof

This is a review plan and ignored-test harness, not a claim that the complete native media pipeline has passed. Camera activation is excluded. The existing Linux/Windows synthetic UAC class-driver proofs remain separate from real source capture.

The actual fixture uses an immutable private source snapshot and isolated target directory. Record the source commit, complete path list, source archive hash, GNU helper executable/archive hashes, agent/API test executable hashes and builder receipt before requesting the physical test window. No private snapshot is pushed or published.

## Isolation

Use a new `/tmp/porthub-native-media-e2e-<32 random hex characters>` root for each endpoint and the gateway. Every configuration/credential file is owned by its actual process user, mode 0600, and bounded. Agent layouts/manifests exist only below that root; the harness does not call service installation, change existing registration files, edit DNS, or replace an installed agent/helper. The desktop runner receives only the public registration identity and never reads the agent credential file.

The ignored API test `native_authenticated_media_private_gateway` creates one fixture owner and two random machine registrations in its own test database, then binds the real API router to `127.0.0.1:0`. An owned `--rm` Mongo container uses a random localhost port and is removed with only its own volumes afterward. Existing databases and containers are not touched.

Set `NO_PROXY=127.0.0.1,localhost` for the private runner processes. The runner
rejects non-loopback profile URLs and all fallback authorities.

The receiver's HTTP/WebSocket control endpoint is forwarded to this loopback listener through an encrypted SSH **control-only** tunnel. SSH carries no PCM. The source and receiver use `allow_insecure_http_for_tests` only in their private profiles. Before transport-ready, capture, or USB attachment, the agent fixture requires the existing negotiated authenticated direct-TLS bulk carrier and verifies its actual remote IP equals the explicitly selected physical LAN peer. Gateway or SCTP fallback aborts this particular proof. Production TLS checks are unchanged.

The private desktop cache contains a checksum-verified helper and namespaced manifest approved for this fixture. `PORTHUB_COMPONENT_CACHE` and `PORTHUB_STATE_DIR` must point inside the fixture root. `PORTHUB_COMPONENT_GATEWAY=https://fixture.invalid` keeps ordinary catalog settings valid; no download is needed or performed. The cache path, manifest, artifact digest and compatible version are checked by the real Manager. Production manifests are not weakened or overwritten.

## Execution gates

1. Start only the ignored API/agent/desktop runners, bounded to at most 180 seconds. This is not authorization to activate hardware. The real exposure broker checks OS peer identity; the actual desktop host enumerates the approved cached helper without capture. The real media worker reports cached sources and receiver capabilities.
2. Verify the exact physical Sennheiser source's stable opaque ID and real desktop UID. Supply both explicitly in the gateway configuration; no default device is selected. The private receiver locally configures the explicitly approved `1209:0001` identity; no production default is introduced.
3. After the parent's physical-test GO, create the gateway `activate` marker. The real owner-authenticated API creates a temporary 45-second plan. Both real report/plan workers authenticate the stream, negotiate the ordinary intelligent direct path, and verify its physical LAN peer before publishing the receiver-local UAC endpoint.
4. Before opening a consumer, verify no source capture helper is active. Identify the new receiver ALSA card by its exact plan serial and explicit owned VHCI mapping; never use ALSA/PipeWire defaults.
5. An ordinary exact-device ALSA consumer reads only three seconds of mono 48 kHz PCM and discards buffers. Do not save, replay or log audio. Record byte/sample count, wall time, startup latency, discontinuities and bounded timing statistics only.
6. Closing the consumer must stop capture. A local `revoke-microphone` marker invokes the real private exposure broker's feature-control operation; verify cancellation, helper exit and endpoint teardown. In a separate fresh session, the gateway `revoke` marker deletes the owner-authenticated plan and must close both streams within the five-second revocation bound. Do not repeatedly capture after known permission denial.

The agent test `native_authenticated_media_fixture_endpoint` runs the actual broker/worker or desktop host; it does not manufacture PCM. Both ignored tests require `PORTHUB_NATIVE_MEDIA_FIXTURE_AUTHORIZED=root-reviewed-microphone-v1` plus their private specification path. The marker prevents accidental invocation; actual authorization still comes from the parent's reviewed test window.

## Cleanup and success criteria

Always create `stop` markers, cancel all fixture tasks, close the owned tunnel, drop the UAC guard and remove only fixture profiles/caches/status/socket files and the isolated database/container. Check that no fixture helper remains, no fixture USB mapping survives, all original microphone driver bindings are present, and all pre-test PipeWire/default-node metadata is identical. Do not kill unrelated processes or alter production feature policies.

A pass requires the **actual** exact source → authenticated API/broker/worker → pinned encrypted direct carrier → receiver-local UAC → ordinary application chain, plus demand/idle, local-policy revocation, API revocation, and cleanup evidence. A successful SSH audio pipeline or synthetic UAC consumer alone cannot satisfy it. This Linux-to-Linux proof does not establish Windows source/receiver or native camera support.

### Authenticated native microphone proof (2026-11-16)

The private v9 fixture completed the full microphone path, rather than the earlier SSH audio adapter test. Exact UID 1000 Sennheiser Profile Mono inventory selection on Luna passed through the isolated authenticated API and desktop broker, PortHub's negotiated direct TLS carrier (`192.168.0.3` to `192.168.0.166`), and Miro's receiver-local UAC endpoint. An ordinary `arecord` consumer selected only the owned endpoint's ALSA card after USB serial, VID/PID, ancestry and device-number verification. It received 144,000 mono samples / 288,000 S16LE bytes in 3.005686 seconds, including 206,407 nonzero bytes. Samples were discarded in memory; none were saved or played.

The source helper was absent before the explicit consumer started. Disabling the temporary source's microphone feature detached the owned endpoint in 0.39228 seconds. The API plan was then deleted. Both machines' PipeWire default metadata remained byte-identical, all physical USB bindings and mounted disks matched their prior inventory, all VHCI slots were free after cleanup, and no helper or USB/IP connection remained. No production enrollment, service, forwarding rule or client policy changed.

This proof uses a per-user source registration and a temporary root receiver. It does not establish managed root-source desktop-worker upgrade integration, gateway/WAN performance, reconnect/hot-unplug behavior, macOS receiver publication, or native camera delivery. An independent API-first revocation proof and exact built-in microphone run are separate follow-up cases. The tested helper/agent/API remain private fixture artifacts, not a published production media release.

The first two attempts failed safely before useful audio: the initial controller activated before the 15-second inventory report; the second consumer's container lacked permission to open ALSA character devices. The final fixture waits for authenticated exact-source and receiver reports, and maps only the owned UAC card's control and capture nodes into the consumer container. It does not grant access to the entire sound-device class.

The separate exact built-in audio **input** run also passed through the same authenticated pipeline: 144,000 samples / 288,000 bytes in 3.006277 seconds, with 193,504 nonzero bytes. This establishes the selected built-in input endpoint, not the presence of a physical internal microphone or intelligible voice quality on a desktop analog jack. The helper was cold before and after the explicit consumer. This case deleted the API plan **first**, without disabling the local microphone feature; the independent authorization monitor detached the endpoint in 0.47726 seconds. Default metadata, physical USB bindings, mounted disks and free VHCI state again matched the baseline, and all temporary processes/containers were removed. No camera source was activated.
