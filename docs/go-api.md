# Go API

`server/cmd/porthub-api` serves the entire API in Go. It also runs authenticated
Socket.IO events, configuration generation, machine monitoring, proxy analytics,
connection refresh, Telegram workers, and the firewall service. Production and
development process lists start this binary directly. There is no Python proxy;
unknown routes return the existing JSON `404` response.

The generated OpenAPI document is `/api/openapi.json`; Swagger UI is `/api/docs`.
The former `/api/openapi-go.json` address redirects to the canonical document.
The old `PORTHUB_PYTHON_API_URL` environment variable has no effect.

The root `Dockerfile` is the only server build definition and is explicitly
selected by `docker-compose.yml`. The retired Python API, Python firewall,
requirements, entrypoints, and separate component Dockerfiles have been removed.
`api/` now contains only client shell assets under `api/client/`. Historical code
remains available in Git history. Rathole, Traefik, MongoDB, and the Next.js UI
remain separate supervised processes inside the same container.

## Development checks

Use the Go toolchain declared by `server/go.mod`:

```sh
cd server
go test ./...
go vet ./...
```

For the integration tests, point `PORTHUB_TEST_MONGO_URI` at an isolated test
MongoDB. Tests create and drop their own randomly named databases. They cover
private enrollment and revocation, workspace policy, installer codes, and
Socket.IO authentication and machine snapshots.

Shell client lifecycle checks also run with `go test ./...`, in
`internal/clientassets`. They invoke Bash with mocked network and service
commands; no Python test runner is needed.

`cmd/porthub-api/testdata/legacy_routes.json` is an independent manifest extracted
from the original Python route decorators. The API registration test requires
every legacy method and path to exist in Go, allowing parameter names to differ.
It also checks documentation and the JSON response for unknown routes. Model and
policy fixtures preserve compatibility with the original request semantics.

## Deployment audit

The Go binary includes an audit subcommand, so deployment checks work inside the
production image without Python or an extra maintenance container:

```sh
docker exec porthub porthub-api audit > before.json
# Build and recreate only the porthub service.
docker cp before.json porthub:/data/backups/before-go-audit.json
docker exec porthub porthub-api audit \
  --baseline /data/backups/before-go-audit.json > after.json
```

The report contains collection counts and configuration fingerprints, machine
and private-peer health counts, HTTP probes, and authenticated Socket.IO snapshot
checks. It reads existing valid account sessions in memory; session tokens and
machine credentials never appear in the report. Accounts without a valid session
cannot receive authenticated probes. With no sessions, the report records a
warning rather than treating a new or logged-out installation as unhealthy.

The command exits unsuccessfully for failed probes or differences from the
baseline. Heartbeats, activity timestamps, and client version updates do not
change the configuration fingerprints. Review intentional configuration edits
before using a report as the next baseline. Preserve a database backup and a
rollback image separately; the report is not a database backup.

By default the audit connects to `http://127.0.0.1:47080`. An optional
`--base-url` accepts loopback HTTP(S) addresses only. Redirects are not followed,
so audit sessions cannot be sent to an external host by an API redirect.
