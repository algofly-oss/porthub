# Windows internal camera to a Linux USB video device

A private end-to-end test passed on 2026-11-16: Aero's selected HP internal camera used native Media Foundation capture, authenticated PHV1 transport and Miro's receiver-local UVC device. An exact-device FFmpeg consumer decoded 45 frames to the null sink with exit code zero and no decoder stderr. No pictures, video or raw error payloads were saved. This validates the unpublished implementation and does not claim that its production rollout is complete.

The exact selected source was `media:c3106b307989f9c61951205cf41ea61d3a4b13fc85262fc645a30ef0d5908440`. The source ran in the ordinary Windows user's limited interactive session. Both carrier receipts verified direct TLS between Aero's Wi-Fi address `192.168.0.169` and Miro's Ethernet address `192.168.0.166`. The cold-source check preceded the consumer; no default camera was selected.

## Results and limits

The negotiated profile was 640×480 MJPEG at nominal 15 fps. First reported decoded frames arrived after 1.374062 seconds; the first-to-last reported frame interval was 4.204335 seconds; total consumer wall time was 5.702641 seconds. Observed delivery was approximately 10 fps. Sustained 15 fps, audiovisual latency and long-running quality were not established by this bounded test.

The consumer required exactly 45 decoded frames, end-of-progress, successful exit and zero decoder stderr. Startup was bounded separately to five seconds, the steady delivery interval to 2.5–5 seconds and total execution to twelve seconds. At most 64 numeric progress entries were retained.

## Bugs found and fixed

The first physical attempt exposed a platform validation bug: Windows camera readiness was subjected to microphone-only WASAPI checks and then a Linux V4L2 backend check. Readiness now validates the operation and platform separately. Windows cameras require `windows-mf`, the exact source ID, nonce and requested video format; microphone and Linux endpoint checks remain separate.

After that fix, 45 frames decoded, but strict validation found JPEG application-metadata errors. A test-only observer recorded numeric marker lengths and known constant labels from four accepted frames, without image data or application payloads. All four contained a valid AVI1 APP0 segment of declared length 33 and an unknown APP1 segment of declared length 4. The latter reproduced the decoder error with synthetic images.

The UVC boundary now removes only optional APP segments with declared lengths 2–5 before the JPEG scan. It preserves valid AVI1 and all other supported metadata and encoded image data byte-for-byte. Compaction occurs only after the existing epoch, stream, format and baseline checks; the vacated buffer tail is zeroed. No helper, format fallback, image re-encoding or decoder-error suppression was introduced. Synthetic tests using the actual Rust normalizer confirmed identical decoded pixel hashes and zero decoder errors after removal; valid fixtures remained byte-identical.

## Provenance and restoration

- Windows source and readiness fix: `dcb819a2573b5e1a78da77744f63034b1800ffc7`; native CI `43796108275` passed full compilation, two fixture tests and the operation/platform readiness matrix.
- Packaged optional helper: `e5dab2f07659f673d9160b8cd21b53af02638bf9`.
- Linux receiver and UVC interoperability fix: `7fa2436ccfec950373985e60046c1baacc8f9bab`; 29 pure tests passed and two hardware tests remained ignored during the build.
- API fixture: `a78cd0f96f1b11e4ec0c31a7cb707ebef764c649`.
- Passing outer controller SHA-256: `8a15497327eadbab2a5a8bb82cf21ca4b96265255886597a38eb278c7a329f3f`.
- Aggregate local proof: `/tmp/porthub-windows-native-camera-quality-proof.json`, SHA-256 `9cb5f74ba6733c838e305975b1a2f1cb35e4528f23587d9c8d93a7d2e42f6d10`.

After capture, the source helper retired, the temporary plan was revoked and the owned UVC endpoint detached. Independent checks found no owned task, process, staging root, container or temporary firewall rule. Windows native configuration, all six audio defaults and production firewall/profile snapshots were unchanged. Miro's physical USB bindings, mounts, defaults and protected policy matched its baseline, and all 16 VHCI ports were free. User drives were untouched.
