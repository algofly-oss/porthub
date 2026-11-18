# Native build depot

The existing Rust API can serve trusted native build inputs without a separate
HTTP container. It is disabled unless `PORTHUB_NATIVE_BUILD_DEPOT_ROOT` is set.
`PORTHUB_NATIVE_BUILD_DEPOT_OWNER_UID` identifies the operator's upload account
(default `0`). This setting is host configuration, not an application setting.

Use a dedicated operator-owned directory outside application data, user uploads,
profiles, and agent releases. Its directories/files must belong to that UID or
root and must not be group/world writable. Mount it read-only into the existing
core; the API must not have write access. A root API or a publisher/API shared UID
requires an actual read-only filesystem mount. Symlinks in the configured path
or any requested component are rejected. Reads stay anchored to verified open
directory descriptors, including across path replacements.

Use the existing optional `docker-compose.native-builds.yml` overlay with the
normal Compose files. It adds only a read-only bind to `core`, requires an
explicit existing host directory (`create_host_path: false`), and does not add a
container. First review the rendered configuration, for example:

```sh
PORTHUB_NATIVE_BUILD_DEPOT_HOST_PATH=/srv/porthub-native-builds \
PORTHUB_NATIVE_BUILD_DEPOT_OWNER_UID=1001 \
docker compose -f docker-compose.yml -f docker-compose.native-builds.yml config
```

Use the actual dedicated publisher UID. On the inspected URM2 deployment this is
`1001`, while the existing API runs as `10001`. The overlay exposes the directory
inside the API as `/native-builds`; its host path must be separate from uploads.

Provide read/traverse permission for the API UID (normally `10001`): directories
`0755`, files `0644`. The separate trusted SSH uploader publishes files atomically;
there is no HTTP upload, delete, listing, or application-user mutation endpoint.
No deployment or directory provisioning is performed automatically.

The public URL contract matches `hybrid-native-build.py`:

- `/native-builds/<source>/manifest.json`: at most 64 KiB, `Cache-Control: no-store`.
- `/native-builds/<source>/<target>/<digest>.zip`: at most 512 MiB,
  `Cache-Control: public, max-age=31536000, immutable` and a digest ETag.

`source` is a lowercase 40-character Git revision, `digest` is a lowercase
64-character SHA-256, and `target` is one of the ten full shipping Rust target
triples in `deploy/component-platforms.toml`. Short artifact aliases are rejected.
Both GET and HEAD are supported; GET streams from the open file rather than
buffering an archive in memory. Ranges are not required by this consumer.
Encoded/traversal paths, extra segments, queries, missing or unsafe files, and
empty/oversized files receive 404. Other methods receive 405.

On first activation, add `--native-build-depot /absolute/host/path` and
`--native-build-depot-owner-uid UID` to the normal native upgrade command.
Run preflight before applying. Subsequent upgrades detect the existing mount
and preserve its source, publisher UID, and read-only mode automatically.

Publish ZIPs through the trusted uploader, which verifies the filename digest,
then publish the manifest atomically. The HTTP reader does not substitute for
consumer verification: the restore client checks the manifest/source contract,
ZIP size/hash, extraction bounds, and actual build receipts before reuse. Replace
ZIP content only under its new digest; never edit a published archive in place.

The depot router is outside application session-renewal middleware. Supplying an
application cookie does not authorize writes or renew a session during a depot
read. Mutable manifests and errors never receive immutable caching.

Focused tests cover streaming/HEAD/cache headers, strict keys and all shipping
targets, symlink and writable-directory replacement, real configuration rejection
of an API-writable mount, and the actual application router's session boundary.
Filesystem fixtures bypass only the read-only-mount check under `cfg(test)`;
production has no environment override for that check. Deployment mount behavior
requires separate operator verification.
