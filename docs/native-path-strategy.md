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

Automatic mode uses cached capacity and latency measurements collected over
already established peer and gateway transports. Measurements run outside the
application packet path and pause during recent activity. An exit connection
uses the same cached choice and flow pinning as ordinary private IP traffic.
Changing the exit-selection strategy affects which exit owns a new connection;
changing the path strategy affects transport to that exit. These are independent
choices. An active flow retains its transport preference until that transport
becomes unavailable. Carrier fallback keeps the same inner source and exit;
it does not replace a failed exit with a different public IP for an existing TCP
connection. File-transfer concurrency remains an application-level setting.
