# VKeyboard

VKeyboard is an embedded `/home?view=keyboard` workspace. Its Rust routes run in
`porthub-core`; desktop input is an optional module of the existing `porthub`
executable. There is no additional runtime container, Python speech service, or
second client installation. The desktop module opens its authenticated broker
connection, but creates no input injector until an owner connects and sends input.

## Desktop control and local policy

Install the updated server and agent. Desktop startup metadata is registered
alongside the CLI. Headless machines cannot supply a graphical clipboard or
focused window. On an already logged-in desktop, start the module with:

```sh
porthub keyboard enable
porthub keyboard status
porthub keyboard disable
# Select one account when there are several registrations:
porthub keyboard enable --registration UNIQUE_MACHINE_OR_REGISTRATION_PREFIX
# Per-user agent installations:
porthub keyboard enable --user
```

Capabilities are permitted by default. A local disable is persisted beside the
registration, survives updates, and revokes existing broker streams. The portal
cannot re-enable it. Local broker access is restricted to the enrolled OS user,
service identity, or an OS administrator using PortHub's existing peer checks.

```sh
porthub features list
porthub features disable keyboard
porthub features disable auto-update
porthub features enable auto-update
porthub features disable metrics
porthub features disable images
porthub features disable terminal
porthub features disable expose
porthub features disable public-forwarding
porthub features disable private-network
porthub features disable direct-connections
```

Each command accepts `--registration` and `--user`. These are capability gates;
enabling one does not open a port, grant private-network permission, start a
terminal session, or override the private module's existing enabled setting.
Explicitly requested manual updates remain available when automatic updates are
disabled. Disabling public forwarding stops the managed server-defined mappings;
standalone local `porthub forward` jobs remain explicit OS-user actions.

Only a machine's account owner can control it. A private-network rule or workspace
membership does not grant keyboard access. One portal controls a target at a time.
Keyboard, mouse and clipboard commands are bounded, ephemeral and never stored in
MongoDB or logs. Disconnects release held input; a five-second idle guard releases
keys/buttons whose release was lost. Commands are acknowledged and deduplicated
across direct/relay fallback. An acknowledgement timeout does not blindly repeat
input that may already have executed.

**Type text** enters text directly. **Update clipboard** changes the selected
client's clipboard. **Paste text** updates that clipboard then invokes the normal
paste shortcut in the focused application. **Paste remote clipboard** uses its
existing contents. Paste does not send Enter. Newlines within supplied text retain
the target application's usual paste semantics. Linux X11 terminals use
Ctrl+Shift+V; other applications use Ctrl+V, or Command+V on macOS.

Linux X11 injection uses the native Rust XTest backend. Wayland injection uses a
native Rust uinput device and requires a local OS grant; clipboard updates do not
require uinput. To grant the logged-in local user access through udev:

```sh
printf '%s\n' 'KERNEL=="uinput", TAG+="uaccess"' | sudo tee /etc/udev/rules.d/60-porthub-keyboard.rules
printf '%s\n' uinput | sudo tee /etc/modules-load.d/porthub-keyboard.conf
sudo modprobe uinput
sudo udevadm control --reload
sudo udevadm trigger --name-match=uinput
```

Wayland direct typing uses a US layout; use clipboard paste for Unicode. macOS
requires Accessibility permission. Windows runs input in the logged-in user's
session rather than in the system service's isolated desktop. No local OS grant
is made from a portal request.

## Local discovery

The portal stays on the address where it was opened. It negotiates a reliable
ordered WebRTC data channel using authenticated gateway signaling and local ICE
host candidates. No Wi-Fi detection, browser redirect, LAN scan, or public
STUN/TURN service is involved. DTLS binds the direct connection to the negotiated
peer. If local ICE fails, the existing gateway WebSocket carries the same bounded
input protocol. Losing the authenticated control connection also closes the local
channel. Local direct-network policy gates discovery; it cannot override a
private-network routing policy that requires gateway traffic.

## Dictation and models

The Rust API embeds `transcribe-cpp`, the native ggml engine used by Handy, through
its safe Rust API. Audio is mono 16 kHz PCM; the browser splits speech at pauses,
limits queued segments, and never saves recordings to browser storage. Inference
is serialized and uses at most four CPU threads. It runs in the existing core.

Dictation is enabled on demand by default, using quantized multilingual **Whisper
Tiny Q8**. No model is loaded at server startup or merely by opening the tab.
The model library downloads files only after an administrator selects Download.
Installed models remain on disk. Select any installed model; only one is loaded
at a time. Model or CPU/GPU changes cancel stale queued inference and unload the
previous engine. The Disabled switch and Unload now action release the current
model. Sixty idle seconds also unload it and release its mapped weights and
native allocations. Settings persist independently for each deployment.

The library includes Whisper Tiny, Base, Small and large-v3 Turbo, Moonshine Tiny
and Base, Canary 180M Flash and Parakeet Unified English. The UI lists the exact
download size, languages, translation support, installation state and download
progress. Model weights are obtained from the same pinned Hugging Face URLs as
[Handy's catalog](https://github.com/cjpais/Handy/blob/main/src-tauri/src/catalog/catalog.json).
Every download is streamed, checked against its pinned size and SHA-256, then
atomically published. Model licenses remain those of their respective sources.

Default builds support CPU. GPU builds additionally enable `speech-cuda` or
`speech-vulkan`; the UI offers GPU only when the native engine enumerates an
actual GPU device. CPU can still be selected explicitly in a GPU build. Use CPU
for the final deployments on both URM2 and Luna. GPU is tested separately on Luna;
production uses CPU-only artifacts without GPU passthrough. Other installations
can build GPU support for the same core. No second model server or runtime
container is needed. CUDA may retain driver/context allocations even after
model weights are released; CPU-only builds avoid this overhead.

`PORTHUB_SPEECH_MODEL_DIR` defaults to `/data/speech-models`, within the existing
persistent volume. Keep it writable by the core user. Do not overwrite loaded
model files in place. The existing core privilege and mount restrictions remain.

## Browser flashing

Open **VKeyboard → Flash a board** in desktop Chrome or Edge over HTTPS. Select
a USB board, install ESP32 or ESP32-C3 firmware, and save Wi-Fi and PortHub
settings. Pair the board's Bluetooth name with the target computer, tablet or
phone. It appears among the account's VKeyboard clients. The target needs no
PortHub installation. A board cannot write a computer's clipboard; its supported
text must be entered as Bluetooth HID keystrokes.

Firmware is built from `firmware/keyboard`, adapted from the standalone tool's
ESP-IDF implementation. The backend, ownership, command routing and enrollment
are Rust implementations. Board credentials are unique and revocable, stored
hashed on the server, and provisioned through the chosen serial connection.
Wi-Fi credentials and enrollment tokens are never saved in browser storage.
Disabling/deleting a board revokes its server connection.

Flashing happens in the browser with locally served esptool-js 0.7.0. Firmware
checksums are verified before writing and the connected chip must match the
selected image. Updates preserve the NVS/calibration partition and Bluetooth
pairing by default. Build-time firmware generation adds no runtime service:

```sh
python3 scripts/build-keyboard-firmware.py
# Then build/export the UI; the generated files are bundled into its artifact.
```

The default firmware directory is `<ui_root>/keyboard-firmware`, or
`/data/keyboard-firmware` without a static UI. `PORTHUB_KEYBOARD_FIRMWARE_DIR`
can override it. No physical board is flashed by server deployment or tests.
