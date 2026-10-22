# API

The Go backend lives in this module. Build the deployed server from the repository
root using the root `Dockerfile` and `docker-compose.yml`.

| Path | Responsibility |
| --- | --- |
| `cmd/porthub-api/` | Application wiring, database initialization, deployment audit |
| `internal/routes/` | HTTP handlers grouped by feature: accounts, machines, connections, groups, proxies, and private access |
| `internal/policy/` | Shared private-network rules, address allocation, and hostname logic |
| `internal/validation/` | Shared request parsing and compatibility validation |
| `internal/core/` | Shared application services, configuration generation, serializers, and workers |
| `internal/auth/` | Authentication and MongoDB sessions |
| `internal/httpapi/` | HTTP server setup, errors, OpenAPI, and Swagger UI |
| `internal/realtime/` | Socket.IO events and machine status |
| `internal/firewall/` | Firewall HTTP service, nftables policies, and traffic sampling |
| `internal/config/` | Environment configuration |
| `internal/store/` | MongoDB connection and database encoding |
| `internal/clientassets/` | Go tests for the shell client's service lifecycle |
| `assets/client/` | Shell bootstrap and tenant-management scripts served to machines |

Feature handlers use shared policy and validation packages rather than importing
another feature's handlers. Executable startup belongs in `cmd/`; reusable
backend code belongs in `internal/`. Keep test fixtures beside their package in
`testdata/`.

Run checks from this directory:

```sh
go test ./...
go vet ./...
```

Set `PORTHUB_TEST_MONGO_URI` to an isolated MongoDB for integration tests.
See [development and deployment checks](../docs/go-api.md) for the native audit.
The separate `../client/` module contains the Go agent, tunnel, relay, and
supervisor. Deployment configuration and TLS material belong in `../deploy/`.
