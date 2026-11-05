# Server 1.10.2 traffic-history deployment

Verified 2026-11-05 at 18:12 UTC on `urm2` (`porthub.algofly.in`). This is a
server-only deployment; no new agent was published or rolled out.

All three healthy containers, core/edge/firewall, report version **1.10.2** and
source **5c6fa7b49994ca2cf673636dca5a4f84e7437637**. Native ARM64 binaries,
browser assets, terminal integration and Docker packaging passed in
[run 42077169943](https://github.com/algofly-oss/porthub/actions/runs/42077169943).
[PR #33](https://github.com/algofly-oss/porthub/pull/33) records the isolated patch.

The existing upgrade tool verified source/version/architecture, role privileges,
persistent mounts and rollback configuration before replacing only the PortHub
roles. It verified that unrelated containers remained running. The core backup
and immutable previous image/configuration records are retained under:

`/home/ubuntu/algofly/porthub-release-1.10.2-5c6fa7b/deploy/native/upgrade-records/5c6fa7b49994ca2cf673636dca5a4f84e7437637-6p7u6go5`

A consistent SQLite backup retained all 22 firewall policies before migration.
Its integrity check passed; SHA-256:
`fb265dcfa256393dd5cbc2a602e2f80b4b7f65887d835da89c69b2c0ead1764c`.

Production verification:

- Public HTTPS `/healthz` returned 200 with certificate verification enabled.
- Authenticated public SSH forwarding on gateway port 37012 reached the EC2 host;
  its existing trusted host key was required.
- That EC2 host still resolved `ssd-uat-app.phub` to `10.203.0.230`.
- The MongoDB `firewall_traffic` collection held 12,352 samples, newest age one
  second and oldest age 563 seconds. Its TTL index was present. Credentials were
  passed through a temporary protected environment file and removed afterward.
- Production's 3,600-second traffic request passed window validation and reached
  the normal unauthenticated-user rejection. A 3,601-second request correctly
  failed with the new bounded window error. No user session was impersonated.
  Authenticated hour-long totals and expanded histories passed against isolated
  MongoDB on the exact deployed source; the production signed-in UI was not
  exercised from this environment.
- All **13 online agents** reported **1.10.1**. They were not updated by this
  server patch. GitHub's published client release remains 1.10.1.

The gateway's own Python HTTP client receives Cloudflare HTTP 403 for the public
health URL. Upgrade monitoring used its real loopback HTTP listener on port 8345;
public HTTPS was checked independently from the development host. Certificate
verification and access controls were preserved.

The older firewall retained only five minutes. Earlier discarded history cannot
be recovered; the new one-hour history fills from the preserved buffer and new
measurements. SQLite now remains local policy storage and a bounded replay buffer;
MongoDB is the canonical inventory/chart history database.

Version 1.10.2 is consumed by this source and must not be reused for different
client contents. The modular agent branch is preparing **1.11.0**. Component
package versions remain independent (currently 0.1.0). Its Tor and sync checks
passed Linux/macOS/Windows x64/Windows ARM64 at
[run 42077857231](https://github.com/algofly-oss/porthub/actions/runs/42077857231),
but the modular agent is not yet released or deployed. Terminal/stats extraction,
gateway component delivery, compact publication/build selection, supervised Tor
CLI fallback and the remaining release/install gates are still required.
