# Windows USB prerequisite installation gate

The normal Windows install/SCM fixture intentionally skips USB prerequisites:
its profile enables test-only HTTP on loopback. Passing that fixture does not
prove cold driver installation. Aero's original driver installation was manual.
The native source and receive adapters have since been tested with those drivers.

## Preferred disposable-runner trial (not executed)

Use a new GitHub-hosted Windows x64 runner, administrator token, the final verified
native agent executable and an isolated, owner-scoped registration. Never remove
pre-existing drivers to make a runner appear clean. Record before starting:

- `Get-CimInstance Win32_OperatingSystem | Select Version,BuildNumber`
- `Get-Service usbipd -ErrorAction SilentlyContinue`
- `Test-Path "$env:ProgramFiles/usbipd-win/usbipd.exe"`
- `Get-PnpDevice -PresentOnly` projected to instance/class/status only, and the
  signed-driver inventory for the USB/IP virtual-controller provider.
- `Get-NetFirewallRule` projected to the owned PortHub USB rule and usbipd rules.

Fail the *cold* gate or classify it as preinstalled if host or receive drivers
already exist. Do not change Secure Boot, test signing, certificate stores or
physical-device drivers. A hosted runner may reject the virtual-controller driver
or require reboot; record that result honestly rather than treating installation
exit zero as receiver readiness.

The test must use the actual installer and a managed SYSTEM service profile whose
control origin is HTTPS. An ordinary loopback insecure install fixture bypasses
this path. Use an isolated gateway/owner with no production machine credentials;
never loosen the production loopback bypass merely to make this test run. SCM ownership is mandatory: a fabricated Spec plus a direct call from a test process
is rejected by windows_service_layout. A secrets-free fixture can instead use
`https://fixture.invalid`, a random 24-hex machine ID and a random disposable token;
Control prerequisite downloads contact only pinned public package URLs. Native
readiness does not require successful gateway authentication.

Before starting the real service, securely stage its canonical feature sidecar at
`%ProgramData%/PortHub/native/<identity>.json.client-features.json`, where identity
is SHA256 of `https://fixture.invalid\n<machine-id>`. Disable every feature initially.
The service installer does not copy sidecars beside its input profile. Use
`porthub.exe service install --profile <private-input-profile>` without
`--publish-cli`, so no interactive GUI task or global CLI is installed. Confirm
real SCM owns the immutable executable/PID and that no prerequisites were launched.
Enable MediaReceive alone first (UDE only, no host MSI); enable DirectConnections
next (owned application firewall only); enable Usb last (adds the host MSI). The
normal native feature CLI must perform these transitions against the registered
profile. Keep MicrophoneShare/CameraShare/private network/auto-update disabled.
Observe bounded preparation through the native agent, not by manually invoking
MSI/EXE packages. Allow up to 15 minutes, including package downloads and driver
installation; preserve bounded agent logs without profile tokens.

Required positive proofs:

1. Both native readiness probes become true: host executable present and actual
   receive-controller handle opens. `porthub usb devices` alone is insufficient:
   an empty machine can legitimately enumerate no devices.
2. Cached installers match the architecture-specific pinned SHA256 values in
   `usb/windows_drivers.rs` and Windows validates their Authenticode signatures.
3. Raw usbipd firewall exception is disabled; only the owned PortHub executable
   rule permits TCP from LocalSubnet. No raw TCP3240 listener is exposed by policy.
4. Native agent remains healthy, with no source bind/capture, no attached device,
   no reboot and no UI input. Repeated policy/report ticks do not launch installers.
5. With raw USB and all media features disabled, preparation launches nothing;
   enabling MediaReceive triggers only the receive-controller prerequisite and
   raw USB separately requests the host prerequisite. A microphone/camera sharing
   feature alone requests no driver, only its direct application firewall when
   DirectConnections is on. Enabling a required feature triggers
   preparation without restarting the agent. Transient preparation failure retries
   with bounded backoff. Disabling during download prevents installer launch.
6. Uninstall only the isolated PortHub registration at completion. On a disposable
   runner the OS image is discarded; do not add automatic driver uninstall to the
   product or general install-lifecycle fixture.

Archive the exact agent/source digest, architecture, driver versions/signature
status, cache hashes, readiness and firewall projections, timings and cleanup
receipt. No physical USB device is needed for the prerequisite-only trial.

## Existing-machine fallback

Aero is not a clean-install proof. A future explicitly reviewed maintenance window
could uninstall/reinstall only the two USB/IP prerequisite packages, after all
media/USB jobs stop and exact current signed installers, product IDs and rollback
commands are retained locally. Do not remove physical device function drivers,
change storage mounts or uninstall the live PortHub registration. This is riskier
than a disposable runner and is not authorized by this document.

## Regression coverage

`usb::prerequisite_retry::tests` exercises independent media/USB prerequisite
selection, disabled start, media-only re-enable, transient
failure/backoff, no repeated ready installation, disable while work is pending,
serialized re-enable and cancellation using paused time. The existing native
installer lifecycle gate remains responsible for enrollment/SCM behavior. Neither
pure scheduling tests nor existing-driver physical forwarding proves the cold
signed-driver installation gate above.
