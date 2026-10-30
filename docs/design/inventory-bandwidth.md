# App-wide inventory and search bandwidth

Full-account inventory downloads have been replaced throughout the app,
including proxies. Scope includes machines/ports, proxies, traffic, dashboard,
admin overview, groups/access views and their selectors. Server/UI version 1.8.7 is deployed and verified.

The shared endpoint `/api/inventory/{kind}` performs owner filtering, bounded
text matching, ranking, sorting and paging inside MongoDB. Page sizes are capped
at 100. Selector responses omit credentials and unrelated configuration. Exact,
prefix and substring matches rank before single-edit text matches; numeric
ports/IPs never use typo matching. Query length and database execution time are
bounded. ETags permit unchanged responses without retransmitting JSON. Indexes
are additive and idempotent; old list endpoints remain compatible.

The shared browser resource debounces text queries, cancels abandoned requests,
deduplicates concurrent readers, and keeps an account-lifetime LRU cache. Cache
invalidation cancels pending pre-mutation reads so they cannot restore stale
results. Inactive views no longer preload inventories. Remote selectors fetch
20 options on opening/search and load more only on demand; saved selections can
resolve through a one-ID read.

Machines and proxies now use query pages. Machine status reads are limited to
visible IDs; workspace counts are independent of the loaded page. Machine port
previews are capped at 10 with complete counts; the editor searches/pages five
ports at a time. Saving compares only explicitly loaded baseline IDs, preserves
unloaded ports and temporary exposures, and retains newly created IDs. Group
membership management has separate group and machine pages. Private DNS links
use the established name/collision algorithm and actual workspace suffix.

Traffic Explorer uses server search, ranking and pages of ten ports. Aggregates
cover all matching owned ports. Initial history is bounded to the requested
window, subsequent snapshots use per-row cursors and content-addressed aggregate
deltas, replacing corrected historical buckets instead of adding counters twice.
Scope revisions reset retained history when ports are removed or remapped. Newly ranked rows receive their full
initial window. Source IP lists are returned only for the expanded port.
Machine sparklines aggregate every port on the server, including ports omitted
from previews. Traffic ranking covers the full match before paging. A two-second scoped cache coalesces firewall reads, fetches at most 64 ports
per firewall response, and retains numeric samples within a 64 MiB budget.
Idle entries expire; bounded detail caches keep source IP lists separate.
Machine pages fetch only their machines’ ports, while global traffic aggregates
correctly cover the entire matching inventory.

The dashboard uses compact fleet counts, five busiest ports plus the complete
aggregate, and five most recently requested owned proxies. Proxy activity reads
are limited to visible route IDs and use conditional responses. Admin accounts
are paged summaries; machines and ports load on expansion, with explicit admin
checks before another account can be queried. Account deletion dialogs use
complete counts rather than guessing from loaded children.

The new access read API (`access-*` inventory kinds) checks current workspace
membership before every query. It pages machines, groups, people, entities,
rule books, peers, routes, DNS and invitations using safe serializers. Policy
lists carry two-rule previews and complete counts; a separate one-ID detail
read loads the entire selected book for a revision-checked edit. Group pages
report counts without downloading complete memberships. Entity search unions
only workspace machines, groups and authorized people. All active access screens use these bounded reads. Membership PATCH writes
apply explicit additions/removals and preserve unloaded members; whole-policy
edits first load the full selected book. Workspace, target and entity selectors
load options on demand. The dedicated traffic monitor also queries only its
selected connection.

Local verification: nine Rust integration tests against isolated Mongo cover
ownership, exact/typo/numeric matching, natural pages/totals, child bounds, ETags,
index idempotency, full-match traffic ranking, corrected aggregate deltas and
scope resets, admin authorization, private DNS, bounded activity, membership
revocation, full policy details and preservation of unloaded group members.
All 27 JavaScript utility tests pass. The API library suite passes 46 tests;
69 tests across the affected integration suites pass, including the firewall,
policy, proxy, realtime, status and legacy route contracts. Artifact-download
tests require separate agent executable prerequisites and are not part of this
server/UI validation. Chromium tests cover access policies,
groups, invitations and network preferences in both themes at 1512, 402 and
320 pixels. Inventory edit tests pass at 1440, 402 and 320 pixels, preserving
unloaded ports/firewalls and all proxy bindings. The production UI build passes.

A disposable real API/Mongo dataset contains 400 owned machines, 950 ports,
150 proxies, 125 groups and 45 policies, with foreign records for scope checks.
Measured uncompressed response bytes (full legacy list versus page of 25):

| Inventory | Legacy bytes | Page bytes |
| --- | ---: | ---: |
| Machines | 397749 | 80518 |
| Connections | 837900 | 22589 |
| Proxies | 435012 | 30759 |
| Accounts | 1300180 | 5712 |
| Policies | 265937 | 19980 |

The previous 950-port traffic request failed when a firewall response exceeded
16 MiB; chunked reads now return HTTP 200 with about 103 KB to the UI. These
measurements use the real API/database and an isolated synthetic firewall,
not production latency measurements.

Real browser/API/Mongo checks pass at 1440 and 402 pixels: four rapid
keystrokes produce one debounced typo query, search retains focus, a deliberately
delayed obsolete response cannot replace newer results, and machine/proxy/policy
flows never call legacy full-list endpoints. Captured decoded response totals
were 151179 and 255661 bytes across 32 and 33 requests respectively (including
configuration, status and traffic, without failures). WebKit access and inventory edit flows pass
at 402 and 320 pixels. Real API mutation tests at 1440 and 402 pixels preserve
all 152 ports and their policy fields after editing page three, and retain all
128 bindings after updating a proxy label. A follow-up 950-port traffic response was 21527 bytes
versus 102764 initially; every source request contained at most 64 ports.

Real selector/admin checks pass against the fixture: option pages contain 20
results, explicit load-more reaches subsequent pages, queries retain existing
multiple selections, and expanded account machines use scoped ten-row requests.
The traffic browser test confirms 950-port totals, aggregate tokens, bounded
rows, paused/hidden request suppression, resume, and exact numeric filtering.

Live rollout: the initial 1.8.7 build (`f79e489`) replaced only the core API/UI
container. The edge, firewall and all ten other running containers retained
their identities. A protected pre-rollout snapshot and rollback image remain on
URM2. Exact comparisons preserve all 27 proxy records, 33 mapping IDs and their
configuration, 18 machine configurations, groups, policy books, private network,
DNS, exits, grants and workspace memberships. Agents remain 1.8.5; Reid, Thor
and EC2 continue sending heartbeats. IBI and Thor respond HTTP 200 with unchanged
body hashes. Authenticated Chromium and WebKit production checks pass at 1440
and 402 pixels across machines, dashboard, proxies, policies, traffic and admin,
without legacy full-list calls, failed API requests, runtime errors or overflow.

The final live conditional-response check found that Cloudflare weakens ETags
after compression (`W/"hash"`). The deployed correction, `02b0ff3`, uses HTTP
weak validator comparison, including lists and wildcard, with regression
coverage in the unit and isolated API suites. Its arm64 build passed in
[run 41086376907](https://github.com/algofly-oss/porthub/actions/runs/41086376907);
source revision, checksums and static linkage were verified before the
read-only configuration preflight and core-only rollout. The UI is unchanged
from the verified production export built with `f79e489`.

Unchanged public summary, machine, proxy, account and policy queries now return
HTTP 304. Chromium network instrumentation measured a proxy-page response at
3269 transferred bytes (19064 decoded bytes), followed by 467 transferred bytes
for its conditional response, with no JSON body. Policy responses measured
1030 bytes followed by 466 bytes. These live transfer measurements include
response overhead; larger-fixture comparisons above report decoded JSON bytes.

A final all-field audit found only normal machine heartbeat timestamps and one
connection's automatic-refresh timestamps changing. Configuration and unrelated
container identities remain preserved. Production core health, live IBI/Thor
response hashes and Reid/Thor/EC2 heartbeats were checked after rollout.
The edge and firewall were never restarted, and agent binaries/releases were
not rebuilt or changed. The sole GitHub binary release remains `v1.8.5`.

The disposable local API/firewall fixture, its Mongo test container and the
dedicated frontend review server have been stopped. Protected production
backups and rollback instructions remain available on URM2.
