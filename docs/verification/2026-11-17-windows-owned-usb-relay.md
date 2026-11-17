# Physical microphone through a Windows relay

On 2026-11-17, the physical Sennheiser Profile microphone on Luna was forwarded
through Aero's managed import alias to Miro. Aero ran the unpublished native Rust
core 1.11.35 candidate from source
`21823b3ab23453ec30e4186a08d039e2977219ea`. Luna and Miro ran core 1.11.34.

The source was USB `1-5`, VID/PID `1377:1100`, serial `0214024304`.
The authenticated owner API confirmed that upstream plan
`2eba8f52fe8d451586035e56759ef9be` terminated at Aero. Aero's report associated
that same plan with alias `0-7532227429158384048`. Miro attached that alias using
temporary child job `f3301a77437a`; this was the managed relay, not an export of
Aero's ordinary USB bus entry.

Miro enumerated the microphone at USB `5-1`, ALSA card 2. A three-second capture
at 48 kHz, mono, signed 16-bit received all **288,000 expected bytes**, including
213,542 nonzero bytes, with exit status 0 and empty stderr. The source identity
was checked before and after capture. No PCM was saved, played back, or logged.
The ordinary SSH account lacked direct ALSA permission, so the bounded consumer
used an existing image in a temporary container with only the selected capture
and control device nodes, read-only libraries, no network, and no capabilities.
This demonstrates transport; it does not establish desktop-user audio permissions.

Cleanup stopped the child first. Aero then regained its local USB and media
devices with status OK. Stopping the upstream removed Aero's microphone endpoint
and restored all three original `snd-usb-audio` interface bindings on Luna.
Luna's original input and output defaults returned automatically; no default,
volume, or mute writes were made. Both forwarding-job lists were empty and the
temporary consumer container was absent afterward. No disk was accessed.

This test proves physical microphone transport through a Windows middle machine
and restoration for this bounded LAN session. It does not prove HID input,
serial or storage relaying, restart recovery, WAN behavior, or long-session audio
quality. Audio/HID are the supported relay classes; other imported classes remain
unsupported. Publication is separate from this candidate test.

The test also exposed two remaining discovery issues: Windows CLI inventory
omitted managed aliases, and ordinary physical inventory showed the imported
device as exportable. These require alias visibility and a controller-ancestry
guard before publication; the successful test used the authenticated alias path.
