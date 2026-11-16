# Native microphone and camera forwarding

Native forwarding makes a selected microphone or camera available as a USB input
device on another registered machine. A receiver application selects that input
as it would select an external device. PortHub starts the selected source only
when the application opens the input. It does not save audio or video recordings.

This feature is under development and has not been published. The adapters use
Linux PipeWire/V4L2 and Windows WASAPI/Media Foundation; native macOS capture and
receiving are not implemented. Linux microphone forwarding has a real-source
end-to-end proof. Linux camera forwarding has a generated-frame end-to-end proof;
Windows camera receiving also has a full generated-frame proof through the
private API, source worker, authenticated direct TLS/PHV1 transport, receiver-local
UDE/UVC endpoint and an ordinary signed-in user's Media Foundation consumer.
The consumer verified 45 byte-identical generated MJPEG frames (640×480, negotiated
15 fps) in 4,379 ms, with the first frame at 164 ms. This is a bounded functional
proof, not a claim of sustained 15 fps or physical Windows source capture.
Windows receiving is advertised only when the existing signed USB receive
controller passes its read-only preflight; discovery does not attach a device.

That private test verified a cold source before application use, source shutdown
after authenticated API revocation, all six audio defaults and camera metadata
unchanged, and removal of its own USB endpoint, task, processes, staging and
signaling tunnel. Its controller exited nonzero after successful capture because
final cleanup tried to rewrite already-removed staging and compared live runtime
telemetry hashes. Independent cleanup passed; the original error and raw receipts
were retained. No physical camera/microphone, driver installation, privacy setting,
default device, production service or saved forwarding rule was changed.
Subsequent private tests also proved actual Windows built-in source capture to
Miro: the microphone delivered 106,080 accepted source PCM samples plus a
three-second USB audio consumer; the HP camera delivered 45 decoded 640×480
MJPEG frames with zero decoder errors. The microphone samples were silent, so
this is transport/OS-device proof rather than audible-speech proof. Camera
observed delivery was about 10 fps under the nominal 15 fps profile. All temporary
devices, tasks, containers and firewall rules were removed, with native settings
and defaults unchanged. See the [Windows microphone validation](verification/2026-11-16-windows-native-microphone.md)
and [Windows camera validation](verification/2026-11-16-windows-native-camera.md).
These used frozen private fixture builds, not the currently installed agent;
production installation and publication remain separate release gates.

## Receiver setup

Configure the receiver's USB identity locally:

```text
porthub media receiver-identity --vendor VID --product PID
```

The values are the receiver integration's 16-bit USB identifiers. This command
saves configuration; it does not start capture. The receiver also needs its
supported native virtual USB controller. Linux uses VHCI; Windows uses the
existing signed USB/IP UDE controller. The portal shows `Receiver setup required`
when receiving has not been configured. macOS receiving is not implemented.

Clear the receiver configuration with:

```text
porthub media receiver-identity --clear
```

Changing or clearing the local identity stops affected receiving sessions. The
server cannot replace this configuration.

## Share from the portal

Open the source machine's popup, choose **USB**, and use **Microphone and camera
sharing**. Choose the input type and refresh sources in the signed-in desktop
session to install the optional native adapter and discover devices. Discovery
does not open a microphone or camera. Choose the source and receiving machine,
then select **Share microphone** or **Share camera**.
The saved rule persists, but capture follows receiver application use.

A source marked `Permission checked on use` supports an explicit capture
request; readonly enumeration has not granted microphone permission. The native
helper checks OS access when capture starts. A denied source stays blocked until
sources are explicitly refreshed after local access is corrected.

## CLI

List authenticated desktop sources or refresh discovery:

```text
porthub media devices --json
porthub media discover
```

A temporary Linux share uses the exact source ID and desktop UID from discovery:

```text
porthub media forward --source-id SOURCE_ID --desktop-uid UID --to MACHINE_ID --name "Source microphone"
```

For a camera, add `--kind camera`. The initial camera profile is 640 × 480,
nominally 15 frames/s, baseline MJPEG. A source that cannot supply the supported
profile reports an error instead of silently choosing another camera or mode.

On Windows use desktop UID `0` and also supply the opaque `--desktop-session`
value from discovery. It identifies the enrolling user without publishing their
SID or transient Windows logon proof. Add `--persistent` to save the rule beyond
the CLI process. Otherwise Ctrl+C closes the temporary session. Stop a rule with:

```text
porthub media stop RULE_ID
```

## Local controls

```text
porthub features disable microphone-share
porthub features disable camera-share
porthub features disable media-receive
```

Disabling a feature revokes its active sessions; the server cannot override it.
Microphone sharing, camera sharing and receiving are independent of keyboard and
raw USB forwarding. Direct/private networking settings still constrain route selection.
The native adapter is on demand and does not load speech models or start an
additional resident service.
