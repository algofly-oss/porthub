# Windows built-in microphone to a Linux USB audio device

A private, exact-source test passed on 2026-11-16: Aero's built-in WASAPI microphone sent authenticated PHM1 PCM to Miro, whose receiver-local USB Audio Class device was consumed through an explicit ALSA hardware endpoint. This is native hardware and transport validation of unpublished fixture sources, not a claim that the feature has been released.

The selected microphone ID was `media:0ccf502b56636bd7f7fef63ef43abff58734e4951cbc17fb22f6d56924ac3197`. The source ran under the existing Windows user's limited interactive token. Both carrier receipts verified direct TLS between Aero's Wi-Fi address `192.168.0.169` and Miro's Ethernet address `192.168.0.166` before the consumer opened. The cold-source check found no capture helper before demand.

The receiver accepted 106,080 source PCM samples in 221 frames at 48 kHz, bound to the exact consumer nonce, plan and live epoch. Source timestamps spanned 2.203747 seconds; receiver arrival timestamps spanned 2.204286 seconds. The explicit receiver-local ALSA device returned 144,000 samples / 288,000 bytes in 3.008071 seconds. Startup silence from the virtual endpoint could not satisfy the separate accepted-source PCM assertion.

A subsequent read-only query of that exact endpoint reported mute disabled and volume scalar 1.0; it did not activate an audio client or change settings. This does not establish why the captured PCM was silent.

All sink bytes were zero. The result proves sustained valid source PCM transport and ordinary OS consumption of the USB microphone. It does not prove audible speech, microphone sensitivity, absence of muting, or end-to-end acoustic latency. Audio was discarded in memory; no recording or playback was created.

## Fixture failures resolved before the passing run

The first attempt had an insufficient 15-second carrier deadline and no temporary-plan renewal. The corrected harness renews the temporary plan through its normal authenticated API and bounds negotiation independently.

A subsequent connection-only diagnostic established that plans and WebSockets worked, but negotiation fell back before the strict direct-carrier proof. Read-only firewall inspection showed that Windows blocked inbound traffic by default and its production PortHub rule allowed only the installed agent's immutable executable. The private test executable had a different path. A unique temporary rule allowed TCP only for that protected, SHA-verified executable and Miro's exact address; it was removed after each test. No production firewall rule or profile was changed.

The next attempt verified both direct carriers but failed before opening audio because the isolated consumer had no writable temporary directory for its private ALSA configuration. A consumer-only 8 MiB tmpfs fixed this without exposing writable host directories. An isolated no-device regression verified configuration creation and removal before the final capture.

## Provenance and restoration

- Windows source diagnostic fixture: `d177ca9152b6e85fde072a23ecd4a47752e0ebd0`; native CI `43791096604`, two pure tests passed.
- Packaged optional helper: `e5dab2f07659f673d9160b8cd21b53af02638bf9`.
- Linux receiver with accepted-source PCM counters: `c5c6921d9b1e2e5448b69f72e2f48d840b8166f1`.
- API fixture: `a78cd0f96f1b11e4ec0c31a7cb707ebef764c649`.
- Passing outer controller SHA-256: `8cc0e1123d9947104554cf1b6af3ff7499153bab7668b53bf2f153c62b002338`.
- Aggregate local proof: `/tmp/porthub-windows-native-mic-capture-run3-proof.json`, SHA-256 `42e9773e9c03953653fbaa6e34ea70953289a47106c2970de9b5be5ae50c0241`.

The source helper retired after demand ended; the API plan was revoked and the owned USB endpoint detached. All six Windows audio defaults, native configuration and production firewall/profile snapshots were unchanged. Independent checks confirmed no owned task, staging root or temporary firewall rule remained. Miro's physical USB bindings, mounts, defaults and protected policy matched its baseline, all 16 VHCI ports were free, and the exact consumer, receiver and Mongo containers were absent. User storage was untouched.
