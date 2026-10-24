# Private path preferences

Inspect or override one private registration using its ID from `porthub list`:

```sh
sudo porthub path show MACHINE_ID
sudo porthub path set prefer-direct MACHINE_ID
sudo porthub path set prefer-gateway MACHINE_ID
sudo porthub path reset MACHINE_ID
```

Use `--profile FILE` for a saved private profile instead of a registration ID.
`--json` provides credential-free machine-readable output. Reset removes the
override and restores `auto`; it does not change enrollment or gateway settings.

Preferences apply to new flows. Existing application connections retain their
selected transport. Both preferences retain an available fallback. Gateway
preference uses an established TURN transport if available, otherwise the packet
relay. Public mounted ports always use the gateway and are unaffected.

The agent watches the private settings file through native filesystem events.
Reads happen outside packet forwarding; event queues are bounded. If filesystem
notifications fail, a slow 60-second refresh keeps overrides usable. Malformed
or unsafe files retain the previous setting; explicit reset repairs a corrupt
but correctly owned private settings file.

Automatic mode currently prefers a ready peer transport. Background measured
capacity/latency comparison, demand-sensitive selection, hysteresis, and seamless
handover remain work in progress. These commands do not establish those features
as complete.
