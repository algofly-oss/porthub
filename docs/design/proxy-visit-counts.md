# Debounced proxy visits

The proxy tiles and dashboard show estimated visits rather than HTTP request totals.
A client starts a new visit for a proxy after 30 minutes without activity. Asset
loads, refreshes and API calls update the inactivity timer without adding visits.
Visits are session starts, not a census of unique people: a shared IP and browser
can group different people, a changed IP/browser can create another estimate, and
bots are included. Calendar-month totals use UTC and count the month a visit starts.
Raw monthly and lifetime HTTP requests remain available in the activity tooltip
and API. Historical requests are preserved and are never relabelled as visits;
visit tracking has its own start timestamp.

## Identity and persistence

HTTP and HTTPS listeners supply the actual TCP peer through ConnectInfo. A direct
client cannot override its identity using Forwarded, X-Forwarded-For or
CF-Connecting-IP. CF-Connecting-IP is used only when the canonical peer belongs
to Cloudflare's published IPv4/IPv6 ingress ranges, checked against
https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6 on
2026-11-06. Other upstream proxy types currently use the socket peer, so their
clients can be grouped; a general trusted-proxy configuration is not introduced.
IPv4-mapped IPv6 addresses normalize to the same identity.

The edge hashes the proxy ID, normalized client IP and at most 512 bytes of
User-Agent with a persistent private 32-byte salt. No raw IP or browser string is
written to the activity journal, and no tracking cookie is added. The salt is
stored beside the journal in a .visitor-key file owned by the edge service with
mode 0600; symlinks, hardlinks, wrong owners and group/other access are rejected.
A key failure leaves request forwarding and request tracking available while
visitor tracking remains unavailable.

The journal contains only counters, opaque route-scoped fingerprints, and first/
last event times in minute buckets. The Mongo revision-guarded write atomically
updates the recent-visitor ledger, visit/request counters, batch IDs and journal
checkpoint. Replay and process/container restart therefore do not add visits.
Aliases of one proxy share its route-scoped identity; different proxies do not.
Old version-1 journals remain readable, and version-2 events add visitor data.

## Bounds and deployment

The edge retains its existing 16,384 pending-record and 512-record batch bounds.
Mongo retains at most 32,768 recent fingerprints across the gateway for up to
61 minutes of event time. This covers the 30-minute inactivity window plus
bounded late-event history, preventing a delayed repeat from being counted again
after another proxy advances the journal clock. When capacity or delayed history makes
uniqueness uncertain, the estimate undercounts and sets coverage_warning rather
than evicting active identities and inflating visits. Raw requests are still
preserved. Very old out-of-order events outside the retained window are not
invented as new visits. The ledger is private Mongo state and is never returned
by the user-facing activity API.

Deploy the new core/API reader before the edge writer. An old edge continues to
supply request totals while the new UI reports that visit tracking is starting.
The updated edge writes version-2 journal records. Core/edge rollback order must
likewise keep a compatible reader for the writer's journal format.

## Verification

Runtime tests cover stable salted identity across restart, route/browser/IP
separation, mapped IPv6, trusted Cloudflare origins, spoofed forwarding headers,
private journal contents, unsafe key files and separated inactivity gaps.
API tests cover rolling inactivity, different clients/routes, BSON rehydration,
replay, UTC month rollover, bounded capacity/recovery and preserving request
history. The real HTTP proxy/Mongo workflow also proves that three requests from
one client produce one visit and a replay still leaves one visit. Chromium and
WebKit checks cover desktop, mobile and 320px layouts and the legacy-history
tracking-start state. These checks gate server release validation.
