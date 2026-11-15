# Machine resources

The existing native agent reports CPU utilization, logical CPU count, used/total
RAM, mounted local filesystem capacity and available GPU sensors through its
authenticated control plane. NVIDIA sensors use the installed driver utility with
a two-second limit. Without an NVIDIA device, the agent discovers Windows display
adapters, Linux DRM GPUs or Apple graphics devices. Native driver counters are
used when available; unsupported utilization, shared memory, temperature and fan
readings stay unavailable. No inference libraries or additional containers load.
Windows CPU sampling also uses GetSystemTimes so a missing performance-counter
provider cannot suppress the machine's RAM and disk reports.

Windows mounted volumes use their native volume GUID rather than their label;
blank or duplicate labels cannot discard the machine's report or another drive.
On macOS, native physical-device identities group usage by drive. APFS container
capacity/free space is refreshed separately once per minute and counted once,
including independent containers on the same physical drive. Volume quotas,
shared volumes, snapshots and disk images are never added as extra physical
capacity. Slow discovery cannot delay CPU/RAM reports. Unmounted drives and
unproven backing relationships remain unavailable; if physical-drive coverage is
incomplete, the aggregate disk percentage is unavailable while verified per-drive
series remain visible. Native mount metadata is refreshed with ordinary samples.

Collection is enabled by default and remains under the client's control:

```sh
porthub features disable metrics       # all resource collection
porthub features disable drive-health  # physical-drive SMART checks only
porthub features disable drive-tests   # scheduled short self-tests only
porthub features enable drive-health
# Add --user or --registration PREFIX for the desired installation.
```

The portal cannot override a local disable. Disabled metrics do not refresh CPU,
RAM, filesystems, SMART or GPU sensors. Ordinary reports arrive every 15 seconds;
CPU needs two samples, so its first report arrives after 15 seconds. SMART work
runs in a separate, bounded background task and cannot delay ordinary metrics.
The database retains the latest utilization report and one minute point for
seven days; history responses use at most 720 time buckets. Missing observations
leave chart gaps, rather than appearing as idle zero readings.

The dashboard ranks fresh online machines by one selected resource: CPU, GPU,
RAM, disk usage or physical-drive health. The compact card shares the traffic
card's height and keeps all five resource bars visible. Drive health uses the
worst known physical-drive condition, never an average that could hide a failing
drive. Unknown or overdue coverage is explicit and sorts after known readings.
The status bar is a condition indicator, not a failure probability or a generic
SSD lifetime percentage; rated endurance usage is shown separately per drive.

## Physical-drive SMART monitoring

Physical drives are rediscovered every minute, including unmounted drives.
Hardware identities are hashed before upload; raw hardware serials and device
paths are not included in health reports. Added drives receive a reading; removed
drives stop receiving checks and retain their earlier history. A sleeping drive
is not woken solely for SMART polling. A USB device currently owned by USB/IP is
left alone and should be inspected from its receiving machine.

The agent refreshes SMART every 30 minutes, staggering devices between worker
ticks. Linux reads native NVMe health logs and ATA/SAT SMART data, thresholds and
self-test logs. Windows uses native storage-protocol and SMART IOCTLs. Apple
storage drivers expose their native SMART assessment through diskutil, decoded
with CoreFoundation. Apple hardware may provide only Verified/Failing rather
than detailed wear counters. Bridges and native drivers that cannot expose SMART
are reported as unavailable, not healthy.

Findings include drive-reported critical warnings, spare thresholds, rated NVMe
endurance usage, failed ATA attributes, reallocated/pending/uncorrectable sectors,
media errors, temperature and available power-on counters. Supported native
short self-tests are scheduled weekly, one drive at a time, and wait for low CPU
and drive activity. They never format, repair, write filesystem contents, start
extended surface tests, or change device power policy. Some native Windows NVMe
and Apple drivers do not expose short self-tests; monitoring continues and the
unsupported test capability is visible. Disabling drive-tests prevents new tests;
a short test already running in drive firmware may finish normally.

The host Resources popup includes a physical-drive selector, current findings,
self-test state and 7/30/90-day condition history. SMART observations and topology
changes are deduplicated separately from utilization reports and retained for
90 days. Historical unsupported and removed states remain visible. Health reads
cannot guarantee that a drive will not fail; available indicators are preserved
without inventing unsupported measurements.

All reports and history are account-owner scoped. Client credentials are required
to submit reports; browser sessions cannot report for a different machine.
Payloads, drive counts, queries and responses are bounded. Account/machine
deletion removes both utilization and drive-health records.

Endpoints: `POST /api/machines/client/metrics`, `GET /api/machines/metrics`,
`GET /api/machines/metrics/{id}?hours=24` and
`GET /api/machines/metrics/{id}/drives?days=7`. Responses never contain machine
tokens. Browser polling pauses when the view or document is hidden.
