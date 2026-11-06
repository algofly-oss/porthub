# Firewall traffic history

The core API stores public-port traffic samples in its existing MongoDB database,
in the `firewall_traffic` collection. Both numeric inventory series and expanded
source-IP histories read this collection. The firewall container receives no
MongoDB credentials and needs no database network access.

An asynchronous core collector reads the existing authenticated firewall Unix
socket. Startup backfills available history; subsequent polls overlap five
seconds to recover delayed measurements. Each measurement is keyed by connection
ID and timestamp. Retries replace the same measurement, and account/connection
filters prevent history from following a public port to another owner. Samples
older than the connection's creation time are rejected.

The dashboard accepts windows from 1 through 3,600 seconds. MongoDB has an indexed
expiry timestamp and a query-time cutoff; TTL cleanup delays cannot expose older
samples. The API and browser retain up to 3,600 merged per-second points. The
collector reads four ports per IPC request and writes upserts in batches of 128.
It runs after API startup, independently of request handling, with cancellation
and 1–30 second retry backoff. A full initial backfill is allowed to finish rather
than being repeatedly cut off at the first ports in a large installation.

SQLite remains the firewall's local policy store and bounded one-hour replay
buffer. It is not the dashboard's canonical history database. Keeping this local
buffer lets firewall enforcement and sampling start before core/MongoDB and lets
core recover samples after an outage. Outages longer than one hour can leave a
history gap; existing samples older than the old five-minute retention cannot be
reconstructed. The low-level firewall snapshot endpoint continues to expose its
local replay buffer for diagnostics and older internal consumers.

No MongoDB port exposure or Compose startup-order change is needed. A core-only
upgrade can collect from the older firewall's five-minute buffer; upgrading the
firewall extends the outage recovery buffer to one hour. MongoDB collection
creation and indexes are idempotent. Existing SQLite files are preserved.

Validation: isolated MongoDB integration covers authenticated collection,
backfill, duplicate retries, corrected samples, expired samples, owner isolation,
fresh API state, expanded source addresses, one-hour totals, and deletion.
Firewall store tests cover retained replay history across restart and pruning;
UI tests cover hour-long chart data and live-delta retention.
