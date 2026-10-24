# Native private identity enrollment

The Rust API supports `POST /api/access/private/peers`,
`POST /api/access/private/bootstrap` and
`PUT /api/access/private/peers/{id}/hostname` against the existing collections.
Enrollment preserves an existing peer's ID and address. Workspace permissions,
machine state and hostname conflicts are checked before issuing a ten-minute
capability. Installed private credentials require explicit revocation before
reenrollment. Custom names are unique within a workspace; clearing a custom
name restores the assigned machine name.

Each native enrollment issuance writes a fresh generation marker to both peer
and ticket. A reissued or revoked ticket cannot publish a credential into a newer
enrollment generation. Bootstrap claims the ticket atomically, then publishes
only a credential hash using a conditional peer update. Concurrent redemption
of the same ticket yields one credential. Existing unconsumed Go tickets without
generation fields remain supported when their peers also have no generation.
Current issuer membership, peer-owner membership and machine ownership/state
are required. Old alias-index migration, unique address/custom-name indexes and
ticket expiry indexes are initialized once for enrollment operations.

The short `/install/{code}` capability can return private enrollment metadata
with JSON negotiation or the minimal first-download launcher. Metadata includes
the stable server authority, workspace/peer IDs and the one-time ticket; it uses
no-store/no-referrer headers and carries the machine-ID header. The launcher
selects native `enroll --install-service` for private links and `setup` for public links. Its binary
download is authorized through the same live capability. Consuming the private
ticket also invalidates later access through that short link.

The native agent accepts:

```sh
porthub enroll --ticket https://porthub.example/install/CODE --profile private.json
printf '%s' "$ticket" | porthub enroll --server https://porthub.example --profile private.json
```

Long tickets come from stdin. The first form can choose a managed default path
when `--profile` is omitted: system state under `/etc/porthub/native/private`, or
per-user native state with `--user`. File names are hashes of the authority and
peer ID. Default state-directory creation follows existing native ownership
checks. An explicit profile path requires an existing secure parent directory.

Metadata identity, authority/fallback URLs, destination permissions and existing
output are checked before consuming the ticket. HTTP requires the explicit test
flag; redirects are rejected. Responses have time/size limits and cancellation.
The saved 0600 profile retains the Go private-profile field names, contains no
public machine credential, and cannot overwrite an existing file. Tokens and
gateway addresses are omitted from ordinary CLI output and profile Debug output.

Plain enrollment stages credentials only. `--install-service` activates the
Linux private system service and publishes the CLI; it checks administrator
access before consuming the ticket. The minimal private launcher selects this
activation option. Existing legacy service takeover and Windows/macOS device
and lifecycle support remain required. See `native-private-transport.md` for
the packet implementation and its outstanding acceptance gates.
The one-time exchange is not crash-recoverable after a lost successful response
or a failed credential save; that case requires revoking/reissuing enrollment.
Existing active routes are not replaced by credential staging.
