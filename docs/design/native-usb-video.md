# Receiver-local USB video engine

`agent/src/media/usb_video.rs` is a pure UVC 1.1 device engine. It neither opens a camera nor attaches a USB device. The media module exports it for the authenticated video receiver. Linux and Windows synthetic class capture and the full authenticated Windows generated-frame receiver path have been proven below. Physical HP camera capture from Windows to Miro has also passed 45 decoded frames with zero decoder errors using frozen private builds; observed delivery was about 10 fps under the nominal 15 fps profile. Production installation/publication remains separate. See the [physical camera validation](../verification/2026-11-16-windows-native-camera.md).

The first contract is one baseline MJPEG frame format: 640 × 480, nominal 15 frames/s, one discrete 666666-unit 100 ns frame interval. The source must provide this exact mode; the engine does not resize, decode, transcode, or silently select a different camera. JPEG validation checks bounded framing, baseline SOF and dimensions, not decoded image correctness. Colorimetry is unspecified because the source schema does not attest it. The UVC boundary removes only optional APP segments with declared lengths 2–5, after the existing epoch/mode/baseline guards; valid metadata and encoded image data remain byte-exact, and the vacated buffer tail is zeroed. Actual HP frames contained a valid AVI1 APP0 length 33 plus an unknown APP1 length 4; removing the latter resolved the strict decoder error.

The caller supplies VID, PID and an alphanumeric serial. Test identities do not constitute an allocated production USB identity. The high-speed configuration has a VideoControl interface with an interrupt status endpoint and one VideoStreaming alternate setting with a 512-byte bulk IN endpoint. Each UVC payload is at most 16 KiB, including its two-byte FID/EOF/ERR header. The 34-byte UVC 1.1 PROBE/COMMIT controls normalize probing to the sole supported mode; committing another format, frame or interval stalls. Unsupported controls stall. Endpoint HALT and standard configuration/interface requests have explicit state handling. No unsupported camera controls are advertised.

The outer USB/IP executor must serialize bulk requests in endpoint order, respect `None` as wait/NAK, and preserve explicit zero-length completions as payload boundaries. It must enforce high-speed attachment for the initial integration. A device qualifier and other-speed descriptor are present, but full-speed class operation has not been tested. The engine supplies no interrupt status events when none occurred. Cancellation, USB/IP framing and endpoint request scheduling belong to the separate executor.

There is at most one active frame plus one replaceable latest frame, each at most 2 MiB, and one 16 KiB payload buffer. Replacing the latest frame increments a discard counter. Internal image buffers are zeroed when dropped; bounded response buffers are owned by the caller. A caller-generated 32-hex session epoch separates source lifetimes. Old epochs, non-increasing sequence numbers and regressing delivery timestamps are rejected. An epoch change drops queued image data; if necessary it first terminates a partially delivered payload, then emits an ERR/EOF termination for the old frame before a new frame begins. No old encoded image bytes are replayed after the switch.

Pure unit verification uses the actual shared `VideoFrame` schema and covers descriptor lengths/endpoint contract, PROBE/COMMIT validation, HALT, bounded replacement, malformed/progressive/oversized frames, FID/EOF/ZLP boundaries, and mid-payload epoch switching. Structural JPEG fixtures are not a native image-decoding or class-driver proof. No camera was activated for these tests.

Primary references: [USB-IF UVC 1.1 document set](https://www.usb.org/document-library/video-class-v11-document-set), [Linux UVC descriptor definitions](https://github.com/torvalds/linux/blob/master/include/uapi/linux/usb/video.h), and [Linux UVC bulk receive implementation](https://github.com/torvalds/linux/blob/master/drivers/media/usb/uvc/uvc_video.c). In particular, the bulk receiver detects payload boundaries through short completions or the negotiated maximum payload size; preserving those boundaries is part of the executor contract.

## Video-only executor and gated class fixture

`media/usbip_video.rs` is separate from the audio ISO executor. It accepts an already-imported, receiver-local stream, validates the synthetic namespace/device ID and control direction/setup length, and rejects ISO descriptors and transfers above 64 KiB before reading a body. There are at most 32 outstanding requests and a 1 MiB aggregate transfer budget. Bulk fragments complete in endpoint arrival order. Control requests remain serviceable while video waits for a frame. UNLINK of a pending request returns `-ECONNRESET` and suppresses a later submit completion; unlinking an already-completed target returns zero. Stopping the executor closes its stream and clears engine buffers.

Capture demand is a local `CaptureDemand { active, generation }` watch value, not a network permission. COMMIT alone is insufficient: eligible pending bulk-IN transfers are required. Natural queue drain has a bounded 100 ms grace so normal host refill gaps do not restart the source or discard a partially transmitted JPEG. Explicit cancellation of the last pending bulk request, control resets and session cancellation stop demand immediately. Real idle expiry retires the epoch and discards queued image data while preserving an old-frame error termination when needed. Every real new activation gets a new generation, including after control resets, so a coalesced watch notification cannot accidentally reuse an old source capture. A source controller must cancel the previous capture and rotate its epoch before publishing frames for a new generation. Successful configuration/interface/COMMIT resets atomically retire the previous engine epoch; frames for it are rejected even before the controller observes the reset.

The ignored `usbip_video_fixture.rs` test is gated by `PORTHUB_PRIVATE_UVC_CLASS_TEST=1`, an explicit existing registration profile and root. It uses only the bundled, generated 640 × 480 baseline JPEG color bars (SHA-256 `8e57f890d50c693aac7484e974409f8d28a12e44789ed996aeef9dad0457761c`). It attaches through the existing lifetime-owned virtual receiver, matches the unique test serial through sysfs ancestry and requires the native `uvcvideo` driver before opening its exact index-zero video node. The intended capture is 45 synthetic frames decoded by ffmpeg into the null muxer, with no video file or playback. Teardown cancels producer/executor, drops the native attachment and verifies the owned node disappeared. The surrounding approved test runner must snapshot and compare the ordinary desktop user's PipeWire defaults; a root fixture does not guess that user's identity.

## Native Linux synthetic class validation

A separately reviewed minimal snapshot `c5da5bdc3618fd7a0dc5f9c9191a4d1721dd7058` ran the real Linux adapter through VHCI on kernel `7.0.0-42-generic`. Its native test executable was 90,929,696 bytes, SHA-256 `b6aa9f442894250adcefe5d99943c87ffb2352fd85917e1e0e06e3bc6db2ce7f`. The private high-speed `1209:0001` device with a unique `PortHubPrivateUvc` serial enumerated under `uvcvideo`; the fixture revalidated its exact USB ancestry and opened only its own `/dev/video0` descriptor.

ffmpeg decoded 45 generated colorbar MJPEG frames into the null muxer in **3,083 ms**, consistent with 640 × 480 at 15 frames/s. The engine completed 46 frames, including one extra buffered frame. No physical camera, human video, image file or playback was involved. This proves the Linux receiver class path, not Windows reception or an end-to-end native camera source.

Cleanup verified the owned USB ancestor and every owned V4L2 node absent, the owned process group absent, all 16 VHCI ports free, no saved USB mappings, unchanged protected settings, and byte-identical PipeWire default metadata (eight observed keys, including four configured audio keys and no configured video defaults). The temporary container and its private 128 MiB tmpfs disappeared. Host filesystems remained read-only except the two exact VHCI attachment attributes; no host temporary image data was written. Existing signed kernel UVC drivers were loaded in a separate reviewed one-shot setup; their original loaded set was recorded for conservative cleanup.

The first wrapper attempt stopped before executable startup because Docker's tmpfs defaults to `noexec`; an `exec` option on the private owned tmpfs corrected that harness issue. Identity, defaults and cleanup guards were unchanged. The successful wrapper SHA-256 was `4e60d1eef50050a8a0fa996fe28e84ca2fb50db626543c575ca8772474b3a390`, launcher SHA-256 `e573eccbdf441b1bd37608f7d2977162c2e64f7203da9e953f84e85cc205161b`, and local evidence receipt SHA-256 `4a835a716bb60962a28f705b54621da0a99ee56487a057823fa56dd38f781197`.

The module is integrated into the unpublished media feature. Physical camera capture remains a separate verification gate; generated-source transport and cancellation evidence is recorded below.

## Windows synthetic class test status

The private `84f47af2d54804817a23a60994eec2e8556a3808` fixture reached
its exact synthetic USB camera through the ordinary user's native MJPEG
consumer, but received no complete frames before the valid-frame deadline.
The producer reported zero completed frames. This is a failed class test,
not proof of Windows camera reception. Subsequent bounded diagnostics identified
two defects: read-only controls cancelled pending status requests, and bulk
alternate-zero selection discarded the negotiated commit. Both now have
regressions that reproduce the original failure and pass after the fix.

Cleanup verified the owned device, task, processes and staging absent, with
unchanged native agent state, six audio defaults, camera inventory and camera
policy. No physical camera was activated and no video was saved. Earlier test
wrapper failures occurred before attachment and are separate from this result.

## Authenticated generated-camera pipeline

The private `002ccf8bba8b7c529915ecda9625b3a13459ef7e` test exercised the
actual API authorization/report/plan path, authenticated desktop broker, video
worker and PHV1 transport from Luna to Miro. Both endpoints verified direct TLS
between `192.168.0.3` and `192.168.0.166` before attachment or capture. The
source generated colorbars only; it never opened a physical camera.

Miro's `uvcvideo` receiver decoded 45 MJPEG frames at 640 × 480 and 15 frames/s
to the null muxer in 3.148 seconds. The source entered one capture epoch,
generated 46 frames including the buffered extra frame, then stopped while
idle. Discovery and attachment alone generated no frames. The API plan was
revoked after capture; this run does not prove revocation during active capture.

The controller decoded successfully but initially failed its final cleanup
check: it tried to remove the root of its own writable bind mount through a
read-only parent. After restoring that empty directory to its original owner,
an ordinary SSH session removed it. Independent checks verified the owned
staging and containers absent, all VHCI ports free, and unchanged physical USB,
mounts, desktop defaults, protected configuration and global CLI. Only normal
status/service-health telemetry files changed. No video was saved. This proves
the generated-source authenticated pipeline, not a physical camera source or
Windows reception.


Three further isolated generated-camera runs verified revocation during active
streaming. Each waited for four generated frames before revoking its authority:
source-client CameraShare, desktop-session CameraShare, and the authenticated
API plan respectively. Every case stopped source frame growth, interrupted the
owned decoder and detached the imported camera. The complete observation checks
took 1.043, 1.034 and 1.847 seconds respectively; these include downstream
completion checks and are not precise capture-stop latency measurements. API
revocation preserved both local permissions; the two local revocation cases
disabled only the selected authority. Every run completed cleanup with no
protected baseline differences. These remain generated-source tests, separate
from native physical capture and Windows reception.

The corrected private Windows fixture
`7280c10499e3a96d0cead97182af0b14e28d3322` passed its ordinary-user
Media Foundation native-MJPEG consumer test: exactly 45 frames were byte-equal
to the generated golden JPEG at 640 × 480. The consumer asserted a 2.5–5 second
capture interval; its exact elapsed numeric report was removed with the owned
temporary directory, so only that bound and the 4.36 second total consumer-test
wall time are retained. The producer completed 62 frames in one epoch because
of prefetch. Trace evidence confirms alternate-zero selection now retains the
commit and starts demand without the earlier retry storm.

Independent cleanup verified the device, task, processes and staging absent,
with unchanged native agent state, six audio defaults, camera inventory and
camera consent. No physical camera or saved video was involved. This proves the
Windows USB class path. The later full authenticated receiver proof is described
below; the subsequent physical Windows source proof is recorded separately in the [camera validation](../verification/2026-11-16-windows-native-camera.md).

## Full authenticated Windows generated-frame receiver validation

Private snapshot `af2eaa98fb165ce88f1fbab0383053b27331421a` (based on the coherent
`002ccf8bba8b7c529915ecda9625b3a13459ef7e` generated-source/API contract) passed
45 byte-identical golden MJPEG frames through the actual private API, Linux
source worker and OS-authenticated desktop broker, authenticated direct TLS/PHV1,
Windows receiver worker, receiver-local signed UDE/UVC endpoint and ordinary
Limited Interactive user's Media Foundation consumer. Capture elapsed **4,379 ms**;
the first frame arrived at **164 ms**. The fixed mode was 640 × 480 with nominal
15 fps negotiation. This bounded functional result does not establish sustained
15 fps or physical Windows microphone/camera capture.

The source generated no frames before ordinary consumer use and stopped after
authenticated API revocation. Independent cleanup verified the owned USB node,
task, processes, staging, source Mongo container and signaling tunnel absent;
no saved TCP/USB forwards remained. All six audio defaults, camera inventory and
consent metadata, production agent state, protected configuration/policy files,
CLI hashes/targets, file ownership/modes, source USB/VHCI state and mounts were
unchanged. No physical source, saved frames, driver installation, default-device
selection or privacy setting change occurred.

The top-level controller nevertheless exited **1** after successful capture:
its finalizer attempted to rewrite markers after the Windows outer runner had
already removed its own staging, and its broad baseline compared live telemetry.
Raw before/after evidence identified exactly three changed runtime files:
`732d…json.status.json`, `732d…json.service-health.json` and
`fff3…json.status.json`; all protected configuration rows remained identical.
These bookkeeping errors and original receipts are retained, rather than
reclassified as a clean controller exit. A separate read-only postcheck proved
the cleanup conditions above. The controller's future finalizer skips writes
only after validating the owned durable outer cleanup summary.

Production Windows camera reception now requires the same positive read-only
signed UDE controller preflight used by existing USB/microphone receiving. It is
never advertised unconditionally, and discovery does not attach a device or
activate a camera. macOS native receiving remains unsupported.
