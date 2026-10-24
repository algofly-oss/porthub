# Native private-network policies

`porthub-api::domain::private_policy` implements rule-book validation, access
preview and explicit machine-pair grants in Rust. The original Python/Pydantic
fixtures retained by the Go implementation are copied into
`tests/fixtures/private-policy.json`; tests do not execute a legacy policy
runtime. The fixture contains 69 model cases, 21 port expressions, 1,536 access
decisions and ten expected compiled grants.

Policies allow connections only through enabled rules. Groups and group user
membership are selectors, not implicit permissions. A rule book requires an
existing group and applies only within its workspace. Sources/destinations can
select machines, enrolled owners, groups or all workspace machines. Rules
support direction, optional reverse initiation, TCP/UDP port ranges, ICMP and
all protocols. Invalid stored rules are omitted as a whole; malformed port
restrictions cannot become unrestricted grants. Disabled and revoked machines
are excluded from compiled grants.

`compile_for` produces only grants incident to one requested machine. It limits
destination selection before pair expansion, avoiding creation of a full
workspace mesh just to filter it afterward. Fixture checks compare each scoped
result with the corresponding subset of the reference grants. Native private
sync uses this function; its packet transport remains work.

The browser API validates every referenced group/machine against workspace
ownership and every selected user against current membership. Only workspace
administrators can create, update or delete books. Updates and deletes use the
saved revision in the MongoDB predicate; a stale or missing record returns 409.
Database tests race two updates at the same revision and require exactly one to
succeed, then verify that stale deletion also fails. Preview is available to
workspace members and returns `enforcement: policy-preview` and
`transport_ready: false`. It does not establish or enforce a payload path.

Nested validation preserves original field/index paths and error ordering,
including bounded rule/selector lists and duplicate rule IDs. Port syntax
accepts Unicode decimal digits like the original parser and canonicalizes
sorted unique ranges. JSON parsing preserves large integer lexemes, and numeric
string coercion preserves the original Python exponent formatting. Existing
API compatibility vectors are included in workspace verification.

One historical distinction remains explicit: a stored numeric `enabled: 0`
is treated differently by the original preview's strict `is False` check and
the compiler's truthiness check. Fixtures retain the preview behavior; actual
compiled grants exclude it. New API boolean fields normalize to booleans.

No host routes, interfaces, firewall rules, public forwarding, credentials or
service processes are changed by this module. Native private sync, signaling,
relay and agent enforcement must use these policies before production adoption.
