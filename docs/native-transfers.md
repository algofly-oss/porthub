# Built-in agent transfers

The Rust `porthub` agent links file serving and downloading into the executable.
It does not run lighttpd, aria2c, curl, a Python server, a package manager, or an
extracted helper executable for these operations.

```sh
porthub http.server 8000 /path/to/files --bind 0.0.0.0
porthub http.server list
porthub http.server stop 8000
porthub http.receive 8001 /path/to/drop
porthub http.receive list
porthub http.receive stop 8001
porthub get http://machine:8000/file.bin
porthub get http://machine:8000/file.bin --connections 16 --dir ./downloads \
  --sha256 EXPECTED_HEX_DIGEST
porthub get http://machine:8000/dataset/ --dir ./downloads
porthub get http://machine:8000/dataset/ --dir ./dataset-copy --contents-only
porthub push ./archive.bin http://machine:8001/
porthub push ./dataset/ http://machine:8001/ --connections 16
```

Both server commands can create their public mapping in the same invocation:

```sh
porthub http.server ./public --expose
```

```sh
porthub http.receive ./drop --expose --subdomain drop -d
```

Use `--public-port 35000` to request an available gateway port; `--port` still
selects the local listening port. `--subdomain` is optional. Public mappings
use the existing registered account, the normal port pool and conflict checks.
Use `--registration ID` when more than one account is registered. The installed
agent authorizes the local caller and retains the machine credential; the CLI
does not need sudo to create an exposure. Local system administrators and the
account recorded during installation can use a system registration. Existing
Windows installations without a local-account grant need one reinstall by that
account. A stopped agent must be started before exposing a service.

`-d` / `--detach` also works without `--expose`. Without this flag, the command
occupies the terminal. `http.server list` / `http.receive list` show owned running
servers; `stop PORT` stops the selected server and closes its attached temporary
mapping. Ctrl-C has the same effect in foreground mode. If the process or network
fails before cleanup can reach the gateway, the temporary lease expires there.
Jobs run as the invoking OS user; jobs started with sudo must be managed with sudo.
Binding a low-numbered local port or reading protected files can still require
OS privileges. An external public port alone never requires local elevation.

`porthub-transfer` contains the implementation. The native server supports
directory listings, GET/HEAD, byte ranges, validators, and safe document-root
resolution. A separate authenticated control listener binds only to loopback;
its random capability is stored in a private per-user registry for list/stop.
The public file listener is the requested address/port only.

`http.receive` uses the same listener and process registry as `http.server`,
with uploads enabled. It supports ordinary raw HTTP `PUT` and `POST`, as well
as PortHub's resumable transfer protocol. `curl --upload-file file.bin
http://machine:8001/.porthub/raw/file.bin` and
`curl -X POST --data-binary @file.bin
http://machine:8001/.porthub/raw/file.bin`, as well as
`wget --post-file=file.bin
http://machine:8001/.porthub/raw/file.bin` work without extra software. A
configured PortHub public port mapping can point at this listener; an upload
to a private peer URL stays on the private route and under its existing peer
access policy.

`porthub push` accepts a file, archive, binary, or directory. Files use
16 parallel 8 MiB chunks by default and persist a private resume checkpoint. A
directory keeps its top-level folder by default, sends changed files, resumes
interrupted files, and skips files with matching size and modification time.
`--contents-only` puts directory contents directly in the receive root;
`--connections` changes parallelism, and `--force` resends matching files. It
never removes unrelated destination files. The receiver replaces a named file
only after the new upload is complete. PortHub peers query the receiver's state
directly. Payloads bypass the gateway when a direct private route is selected;
public mappings and gateway-selected private routes relay through the gateway.

To keep a directory synchronized, add `-w` / `--watch`. The initial sync runs
immediately, then filesystem notifications trigger debounced incremental syncs.
There is no idle scan timer. Changes during an upload cause another pass;
connection failures retry with a bounded 5–60 second backoff and reuse durable
upload checkpoints. Normal changes check only affected paths; initial sync,
notification overflow, and recovery recheck the full tree. Deletions
are not propagated: destination-only files remain intact. This is one-way sync,
not the native rsync protocol or a two-way conflict resolver.

```sh
porthub push ~/data http://condor.phub:8001/backups/luna/projects/ -w
porthub push ~/data http://condor.phub:8001/backups/luna/projects/ -w -d
porthub sync list
porthub sync status JOB_ID
porthub sync stop JOB_ID
```

The URL path becomes a destination below the receiver root; missing nested
folders and empty source folders are created automatically on current receivers.
By default the example creates `backups/luna/projects/data/`; `--contents-only`
puts the contents directly in `projects/`. Parent traversal and symlinked
receiver directories are rejected. The receiver must be upload-enabled.

The standard system installer publishes a root-owned CLI through
`/usr/local/bin/porthub` on Linux and macOS, so ordinary commands and
`sudo porthub push ...` use the same installation. Use sudo explicitly when a
source needs elevated file access; transfer commands do not request elevation
themselves. Sudo controls its own password prompt and PATH. A deliberately
per-user installation under `~/.local/bin` is not automatically added to sudo's
restricted PATH; use the standard system install when both forms are needed.
Jobs started with sudo belong to root, so manage them with `sudo porthub sync`.

Without `-d` / `--detach`, watch occupies the terminal until Ctrl-C. Detached jobs
run in a separate process session and can be inspected or stopped after the
terminal closes. They belong to the current OS user and need no administrator
permission. They do not automatically restart after a reboot. Job configuration
is private; list/status strip URL credentials, query strings, and fragments.
The control listener is authenticated and loopback-only. A receiver exposed
publicly accepts uploads from anyone who can reach its mapped port; use private
PortHub access rules when access should be restricted.

`get` also defaults to 16 connections. Use `-x 1` or another lower count for
storage-constrained devices. Upload buffers are bounded by the connection
limit; a slow receiver applies backpressure instead of requiring the sender
to buffer the whole file. There is no fixed upload-request deadline (connection
establishment has a five-second timeout). Concurrency does not automatically
adapt to disk speed. Chunk staging and final assembly add disk I/O, so extra
connections do not necessarily improve performance on a slow mechanical disk.

The downloader uses concurrent range workers and a shared queue of missing
pieces, avoiding a fixed assignment that strands finished connections behind
a slow final segment. Files are written to a partial destination, completed
pieces are flushed and checkpointed, and a stopped download resumes only when
the fresh size and validators match. If the server cannot support validated
range transfers, it downloads a single stream. It checks every Content-Range
and rejects changed validators, unexpected lengths and encoded range bodies.
An optional SHA256 check runs before publishing the final file. Existing files
are not overwritten; a completed file is published using a non-overwriting
filesystem operation.

When the URL points to a directory served by `porthub http.server`, `get`
fetches its bounded directory manifest and syncs nested files with the same
parallel range and resume behavior. The default creates or updates a folder
named after the remote directory under `--dir`; `--contents-only` places its
contents directly in `--dir`. Matching file size and modification time skips a
file, changed files replace their old copy only after download completes, and
unrelated local files are preserved. Interrupted work stays in a hidden
`.porthub-download-*` folder and is removed after a successful sync. Other HTTP
servers keep their regular single-file behavior. A symlink or special file in
a PortHub directory makes the directory transfer fail explicitly instead of
following it.

Upstream source reviewed for the design:

- aria2 commit `9e7273583f83e881e3ec067b523ba88724088d2f`:
  `src/SegmentMan.cc`, `DefaultPieceStorage.cc`,
  `InorderStreamPieceSelector.cc`, and `HttpResponseCommand.cc`, covering segment
  checkout, minimum splits, response validation and content encoding.
- lighttpd commit `2ddc51389a139d2b08daf310596c951c1d53dc8d`:
  `src/http_range.c` and `network_write.c`, covering range semantics and bounded
  file sends/platform backends.

These tools are implemented in C/C++. Their transfer behavior informs the Rust
modules; their executables are not agent dependencies. Rathole's Rust source
is linked separately for forwarding, with its provenance under `vendor/rathole`.

Integration checks cover byte integrity, repeated downloads without overwrite,
range and validator responses, cancellation/resume, changed-file restart,
checksum failure without publication, empty/no-range files and document-root
escape prevention. Actual network performance is measured separately; passing
these checks does not prove WAN throughput or private-path selection.

Watch-specific checks cover foreground and detached lifecycle, Ctrl-C,
capability-protected controls, reconnect/resume, empty and nested directories,
subsecond edits, affected-path selection, preservation of receiver-only files,
and rejection of symlinked source or destination ancestors. Native Linux
validation also exercised private and public mapped routes between Condor and
Luna before release publication.
