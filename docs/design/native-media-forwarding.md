# Native microphone and camera forwarding

Initial design assessment, 2026-11-15, with validation status updated 2026-11-16.
The implementation remains unpublished; the historical options below are not an
installation/capability matrix. The selected receiver path now uses receiver-local
USB Audio/Video class devices with Linux VHCI or the existing signed Windows UDE
controller, without a new custom media driver.

Actual private Windows built-in microphone→Miro validation passed sustained
source PCM and three-second OS USB audio consumption; samples were silent, so
it does not prove audible speech. Actual HP internal camera→Miro validation
passed 45 decoded MJPEG frames with zero decoder errors; observed delivery was
about 10 fps under its nominal 15 fps profile. These are frozen-fixture proofs,
not installed-agent or release-publication claims. See the
[Windows microphone](../verification/2026-11-16-windows-native-microphone.md),
[Windows camera](../verification/2026-11-16-windows-native-camera.md) and
[current user guide](../native-media-forwarding.md). Native macOS media support
remains unimplemented.

## Required result

A source microphone or camera, including a laptop's built-in devices, becomes a selectable local input on another registered machine. Applications select a named `PortHub — <source> — Microphone/Camera` in their normal device picker. This requires receiver-side OS device publication; playing sound through speakers, showing a browser video, or opening an RTSP URL does not satisfy it.

A virtual microphone/webcam is equivalent for normal application selection, but is not a USB bus device and must not be advertised as a physical USB attachment. Applications requiring hardware identity, protected capture, or biometric authentication are outside the initial compatibility promise. Existing physical USB forwarding remains a separate selectable mode.

## Existing implementation and limits

`crates/porthub-agent/src/usb/{mod,linux,windows,macos,userspace}.rs` implements USB device ownership and forwarding. Linux exports through the kernel and imports through virtual host controllers; Windows requires its USB host/import drivers; the macOS adapter is export-only in code, but successful physical Mac export remains unverified and Mac USB import is unavailable. The macOS exporter explicitly blocks built-in devices and isochronous endpoints. The userspace transfer executor returns unsupported for isochronous transfers. Removing those guards would not implement microphone/camera support.

An internal webcam may actually sit on an internal USB bus. It can use the existing physical USB route only if native enumeration proves a separately claimable device, its interfaces and platform adapter are supported, and capture is safe. Other built-in devices use PCI, I2S, platform-specific camera paths, or shared composites; they have no generic USB device to forward. Never detach an entire shared input/composite device merely to obtain its camera interface.

Physical USB ownership normally removes the device from source applications while forwarded. A native media stream instead captures through the source OS and republishes its content; the source OS decides sharing/exclusivity. Existing LAN microphone success does not establish every USB camera or WAN audio route. See the measured latency limitation in [native device forwarding](native-device-forwarding.md).

## Initial implementation options (historical)

These were architecture alternatives. The selected UAC/UVC implementation and its validation are described above; this table is not the current advertised capability matrix.

| Platform | Source capture in Rust through OS APIs | Receiver microphone | Receiver camera | Installation/session constraints |
| --- | --- | --- | --- | --- |
| Linux desktop | PipeWire audio/video; ALSA and V4L2 adapters where needed | PipeWire `Audio/Source` node for normal desktop applications; optional ALSA loopback for applications that need ALSA capture devices | PipeWire `Video/Source` where consumers support it; V4L2 loopback endpoint for broad webcam application compatibility | Desktop session/audio policy required. V4L2 loopback is an external kernel module; compatible package/module and Secure Boot signing must be checked. ALSA loopback availability varies by kernel. |
| Windows | WASAPI microphone capture; Media Foundation camera capture in the interactive user context | A real virtual capture endpoint requires a signed audio driver plus a bounded user-mode bridge; a render loopback or application audio processor alone is insufficient | Windows 11 build 22000+ Media Foundation software virtual camera with a PortHub media-source COM implementation | Microphone/camera privacy permissions and source-user session required. Camera API has current-user/all-user access and session/system lifetime choices. Kernel audio driver needs production signing and explicit local installation. Older Windows camera receivers require a separate compatibility driver and remain unsupported initially. |
| macOS | Core Audio and AVFoundation through Rust FFI/Objective-C runtime, in a permission-bearing user helper | Core Audio Audio Server plug-in for a virtual capture device, fed through private shared memory/IPC | Core Media I/O camera extension on macOS 12.3+ | Source helper needs appropriate usage descriptions and user microphone/camera authorization. Camera extension needs an app bundle, signing, system-extension installation capability and shared app-group configuration; normal OS activation/approval applies. HAL plug-in distribution and admin installation are separate work. |
| Headless/server session | Enumerate separately from an interactive desktop's usable sources | Only advertise an actually usable receiver backend | Only advertise an actually usable receiver backend | An installed system agent does not itself imply access to a logged-in user's capture devices or media session. Report `requires_user_session`, permission denial, or backend absence explicitly. |

PipeWire's documented source media classes support this desktop publication model. ALSA's in-tree loopback driver offers a separate kernel PCM route. Their compatibility scopes differ; legacy direct-ALSA applications must not be promised a PipeWire source without an actual integration test. [PipeWire node classes](https://pipewire.pages.freedesktop.org/pipewire/page_man_pipewire-props_7.html), [Linux ALSA loopback driver](https://github.com/torvalds/linux/blob/master/sound/drivers/aloop.c).

For broad Linux camera enumeration, the maintained V4L2 loopback project supplies virtual video devices. Its `exclusive_caps` mode is relevant to webcam consumers, and module build/signing must match the running kernel. PortHub should integrate an explicitly installed, verified OS prerequisite rather than hide a shell pipeline or silently weaken Secure Boot. [V4L2 loopback project documentation](https://github.com/v4l2loopback/v4l2loopback/blob/main/README.md).

Windows' supported software-camera API starts at build 22000 and observes camera privacy controls. Stable parameters reopen a previously registered camera. This offers a native user-mode camera path, not an audio endpoint API. [MFCreateVirtualCamera](https://learn.microsoft.com/en-us/windows/win32/api/mfvirtualcamera/nf-mfvirtualcamera-mfcreatevirtualcamera).

Microsoft's SysVAD sample demonstrates virtual audio-device driver structure; it is reference material, not a working network microphone bridge to bundle unchanged. Production kernel-driver distribution requires Microsoft's applicable signing process. The receiver audio backend must remain unavailable until that deliverable exists. [Audio driver samples](https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/sample-audio-drivers), [driver signing policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-).

Apple documents Core Media I/O extensions as the supported selectable-camera mechanism and distinguishes virtual audio plug-ins from hardware AudioDriverKit work. These mechanisms are separate from the USB host-controller entitlement discussed for USB import: inability to import USB does not prohibit native media capture or every virtual media endpoint. A distribution-ready signed extension is still required; an arbitrary certificate does not supply the required identity/capabilities. [Camera extension architecture](https://developer.apple.com/documentation/coremediaio/creating-a-camera-extension-with-core-media-i-o), [audio-driver guidance](https://developer.apple.com/documentation/audiodriverkit/creating-an-audio-device-driver), [capture authorization](https://developer.apple.com/documentation/bundleresources/requesting-authorization-for-media-capture-on-macos).

## Rust module and transport design

Add `media` beside `usb` and `keyboard` in the existing agent, with shared schemas in `porthub-components` and API routes in the existing Rust server. No new containers or resident transcoding service. OS-mandated extensions/drivers are packaged native components, not an excuse to claim a single CLI process can replace an OS device driver. Network framing, policy, scheduling, decoding/encoding orchestration, persistence and CLI/API remain Rust. Driver/COM/Objective-C interfaces need ABI-specific adapters and their own signing/build validation.

Use three explicit interfaces: `SourceBackend` enumerates stable device identities/formats and opens a source only on an authorized active subscription; `MediaSession` transports timestamped frames; `ReceiverBackend` publishes an endpoint and reports application-consumer count. Inventory records microphone/camera kind, physical USB association when proven, permitted formats, source/receive capabilities and exact unavailable reason. Keep stable logical endpoint IDs across reconnects, independent of transient device enumeration indices.

Use PortHub owner/device authentication and negotiated session capabilities. Reuse intelligent path selection from `outbound::Selection` and the authenticated USB direct/private/gateway establishment patterns, not their opaque byte-copy or kernel-URB payload. Prefer direct LAN, then permitted private transport, then gateway fallback. Report actual selected route, latency, loss and jitter. A reliable HTTP byte stream can be a compatibility fallback but must not be called real-time optimized: stale media needs bounded discard, not unlimited retransmission behind newer frames.

Begin with timestamped PCM audio for LAN correctness and bounded low-latency Opus for bandwidth-efficient routes; never enable transcription, models, or GPU processing for media forwarding. Negotiate video source-native compressed frames where compatible; otherwise select a supported hardware encoder when available, with explicit CPU/resolution/frame-rate limits for software fallback. No always-running GPU or CPU encoder. Codec implementation/library licensing and packaging are a release prerequisite, not an assumed dependency.

Keep control messages reliable and media queues bounded. Audio uses a small adaptive jitter buffer, sequence numbers, silence on underrun and gradual clock-drift correction; video discards stale frames and can request a keyframe after reconnect. Carry capture timestamps and a shared clock mapping for audio/video synchronization. A forwarding chain must preserve origin identity and timestamps, limit hops and reject loops. A middle agent should relay a compatible encoded stream without decode/re-encode when possible; any received virtual device can be recaptured only as an explicit new route with loop detection. This is distinct from exclusive physical USB forwarding, which cannot grant two machines ownership simultaneously.

## Local control, persistence and idle cost

Add independently revocable local `microphone-share`, `camera-share` and `media-receive` capability controls. They follow the user's default-enabled capability preference, while **capture remains inactive until an explicit authorized forwarding rule/session exists**. Turning off a local capability immediately stops capture, clears queued frames and blocks server attempts to reopen it. OS denial wins over server policy. Show source capture state and a local stop action; do not change the system default microphone/camera or silently grant TCC/privacy permissions.

Persist stable source identity, destination, endpoint identity and requested format for permanent rules. Restart recovery rechecks policy, session availability, physical device identity and OS permissions before opening. Distinguish configured, waiting for permission/session, endpoint published, streaming and consumer active. Temporary CLI rules use the existing foreground/background job lifecycle; no ambient capture at enrollment. Receiver disconnect emits silence/explicit disconnected frames and exposes status rather than replaying private last frames indefinitely.

Use the existing user-helper trust/IPC model, but do not replace the approved Mac keyboard helper or assume its accessibility approval authorizes media capture. Extend policy storage compatibly so older approved helpers fail safely on new media controls.

## Original delivery sequence and remaining validation

The sequence below predates the selected receiver-local UAC/UVC route. That route does not require the proposed new custom Windows audio driver or Linux media loopback modules; those alternatives are retained as design history. Current validation and release limits are stated above.

1. Implement native inventory/capability reporting and local controls first, without opening devices. Do not list ordinary microphones/cameras as USB devices when they are media sources.
2. Linux-to-Linux microphone publication first; then Linux webcam publication with a verified V4L2 prerequisite. Demonstrate selection and recording in a normal unmodified application, reconnect, hot-unplug and client-disable behavior. Synthetic backend tests do not count as hardware proof.
3. Add Windows source capture and Windows 11 virtual camera publication. Independently deliver/sign/test the Windows virtual microphone driver. Mac capture can be developed separately from its receiver extension packaging.
4. Validate source/destination combinations with actual normal consumers, including browser permission prompts, native conferencing/recording apps, frame-rate/rate negotiation, long-session clock drift, packet loss, direct/private/gateway paths and persistent restart recovery. Test chains with Windows as a middle hop without inferring success from connection establishment.
5. Record measured CPU/RAM/bandwidth, inactive resource use, latency and maximum supported profiles on Luna, Miro, Aero and Mac. Stop all test sessions and preserve existing user device/default settings. Unsupported endpoint publication must be visible before the user saves an unusable rule.

The original assessment established a staged architecture. Later implementation and physical tests are recorded in the current status above; they do not establish production installation or publication.

## Implementation checkpoint: native adapters and experimental USB audio

The agent now has a native Linux ALSA/V4L2 inventory module and separate local microphone-share, camera-share and media-receive policy controls. Policy corruption disables media capabilities without modifying the approved keyboard-helper policy. Inventory does not start capture, and an uninstalled/unverified receiver remains unavailable. These changes are work in progress for a later client revision, not part of the immutable client 28 release.

`porthub-media-helper` is an on-demand GNU Linux executable, separate from the static-musl agent and server. It uses PipeWire Rust bindings and requires both the library and user-session server to be at least 0.3.68. Release builds must use a conservative glibc baseline, with matching x64/arm64 build validation; a locally built developer executable is not a portable release artifact. Requests travel over a parent-owned inherited pipe, require an explicit session identity and explicit source for capture, and never contain enrollment credentials. PCM is mono 48 kHz F32LE, at most 20 ms per frame, with at most 100 ms queued and stale samples discarded. Missing targets never fall back to a default microphone. Receiver nodes have low session priority and do not explicitly alter default-node metadata.

Actual adapter-only checks performed on Luna and Miro:

- A synthetic tone fed a PortHub PipeWire `Audio/Source` and was selected by an ordinary, unmodified `pw-record` consumer using the exact stable node name with fallback disabled.
- The explicitly named Sennheiser Profile source supplied a bounded one-second capture. Only frame counts, RMS and peak were retained; no audio file or playback was produced. Capture ended on control-pipe EOF.
- A SHA-verified development helper on Miro published a virtual microphone. Luna's exact Sennheiser capture reached it through an encrypted **SSH test harness**, and ordinary `pw-record` on Miro received PCM. Miro's default-node metadata was identical before publication, while published and after cleanup. The harness retained statistics only.

These early adapter-only tests established native source capture and selectable OS publication. By themselves they did not prove PortHub transport, path selection, persistent rules, production delivery, Windows/macOS support or camera streaming; later authenticated and Windows physical proofs are linked in the current status above. SSH is a validation harness only and is not the product implementation. A transient numeric PipeWire node ID is not a valid stable `pw-record --target` identity; tests use the node name, and parsing distinguishes raw stdout PCM from a WAV container.

Media helper manifests use `porthub-media-components.json` with a strict `porthub-media` namespace, independently of the legacy component catalog. The namespace manager reuses the existing private file ownership, cancellable locks, transport and SHA-256 validation primitives. It rejects caller-supplied unfetched manifests, untrusted repository/namespace, unsupported targets/protocols, changed published versions and mismatched archive/executable digests. Existing trust is approved HTTPS distribution plus integrity/provenance metadata; this does not invent a detached cryptographic signature scheme. No new component variant is inserted into the catalog parsed by older installed agents.

The selected receiver path now exposes receiver-local USB Audio Class 1 microphones and UVC cameras, with authenticated PCM/JPEG transport between agents. Existing Linux VHCI and the already signed Windows USB/IP virtual host controller use ordinary USB class drivers, avoiding a **new** Windows virtual audio kernel driver. Native class consumers and authenticated fixture paths have been validated; the user guide distinguishes generated-input, physical-source and publication evidence. It does not make macOS USB import available. Native PipeWire publication remains useful on Linux, and macOS still needs a native audio endpoint backend.

The pure Rust experimental function has explicit descriptors for fixed 48 kHz mono S16LE, zero-bandwidth and streaming alternates, one 96-byte isochronous IN packet per full-speed millisecond, bounded PCM conversion, and strict control/range checks. A separate USB/IP executor must preserve per-packet statuses and actual lengths, bound requests and memory, implement unlink/cancellation, pace completions in real time and tie capture to authorized streaming. Immediate synthetic completions would spin the host and starve capture, so they are not an acceptable implementation. Physical macOS USB adapters retain their existing isochronous rejection.

Prototype USB vendor/product identifiers are explicit test inputs, not an assertion of an allocated PortHub vendor ID. A legitimate production identity must be resolved before publishing this as a supported USB product. UVC webcam synthesis has separate descriptors, video framing, capture/codec negotiation and 45-frame class-consumer validation; microphone success is not evidence of webcam support. [USB Audio 1.0 specification](https://www.usb.org/sites/default/files/audio10.pdf), [USB/IP protocol and isochronous return framing](https://docs.kernel.org/usb/usbip_protocol.html).

### Reviewed microphone lifetime boundaries

Linux capture resolves the selected opaque source ID to a fresh PipeWire
`object.serial` on the same core connection that creates the stream. Duplicate
names, duplicate instance serials, stable-ID collisions, missing instance IDs,
or an overflowing graph snapshot are unavailable; none select a default node.
Native endpoint fields are retained locally and replaced with opaque IDs in the
agent's network inventory copy.

The API monitors active authorization independently of socket forwarding. Its
one-second cadence uses concurrent endpoint checks bounded to two seconds and
fails closed on timeout; a nonreading peer cannot postpone revocation. WebSocket
buffers are bounded, and cleanup does not await a blocked close handshake.
The receiver independently watches media/direct/private policy while report HTTP
requests are stalled. Desktop control sends include lock acquisition within a
100 ms deadline, allowing blocked PCM output to terminate the connection.
