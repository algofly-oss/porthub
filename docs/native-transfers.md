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
porthub push ./archive.bin http://machine:8001/
porthub push ./dataset/ http://machine:8001/ --connections 8
```

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
parallel 8 MiB chunks by default and persist a private resume checkpoint. A
directory keeps its top-level folder by default, sends changed files, resumes
interrupted files, and skips files with matching size and modification time.
`--contents-only` puts directory contents directly in the receive root;
`--connections` changes parallelism, and `--force` resends matching files. It
never removes unrelated destination files. The receiver replaces a named file
only after the new upload is complete. PortHub peers query the receiver's state
directly; the gateway does not carry file bytes.

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
