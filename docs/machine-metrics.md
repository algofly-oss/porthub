# Machine resources

PortHub agents report CPU utilization, logical CPU count, used/total RAM, mounted
local disk capacity and optional NVIDIA GPU utilization/VRAM through their existing
authenticated control plane. No process list, filesystem paths or command lines
are collected. GPU uses the installed driver utility with a two-second timeout;
unsupported devices show unavailable, never zero. Collection is allowed by
default and can be disabled locally per registration:

```sh
porthub features disable metrics
porthub features enable metrics
# add --user or --registration PREFIX for the desired installation
```

The portal cannot override a local disable. Disabled collection does not refresh
CPU, memory, disks or invoke the GPU utility. Reports arrive every 15 seconds;
CPU needs two samples, so the first arrives after 15 seconds. No extra service or
container is created. The existing database stores one latest report per machine
and one sample per minute, with a seven-day TTL. History queries return at most
720 time buckets, averaging samples for longer periods. The TTL monitor can lag
physical deletion; queries enforce the selected time window. Account and machine
deletion remove their metric documents.

The host popup has a Resources tab with live readings and CPU/GPU/RAM/disk plots
for one hour, 24 hours or seven days. Missing reports create graph gaps. The
dashboard ranks machines with reports newer than 45 seconds, excluding disabled
and stale machines. Select one or several resources and choose most/least
utilized first. Combined ranking uses the equal-weight mean of utilization
percentages, requiring every selected resource to be available; otherwise the
machine appears after ranked machines. GPU utilization averages reporting GPUs.
This compares utilization rather than absolute hardware performance.

Metrics are visible only to the registering account owner. The fleet endpoint
currently returns at most 1,000 owned machines and states this limit in the UI.
Client machine authentication is required to submit a report; browser sessions
cannot submit a report for a different machine. Payloads and history responses
are bounded, and server timestamps prevent clients inserting arbitrary dates.

Endpoints: `POST /api/machines/client/metrics`, `GET /api/machines/metrics`,
`GET /api/machines/metrics/{id}?hours=24`. API responses never contain machine
tokens. Live browser polling pauses when the view or document is hidden.
