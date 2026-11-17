# Private network traffic acceptance

Replace the dashboard Terminal traffic panel with the signed-in account's private
network traffic. Retain terminal backend measurements. This change is not ready
for release until the checks below cover the actual final implementation.

## Measurement semantics

- A directed flow identifies source and destination machines. A → B and B → A
  are separate rows; selecting either shows that direction's history.
- Direct and relayed carrier bytes are recorded at actual transport boundaries,
  excluding discovery and control signaling. Document whether successful queue
  acceptance or socket delivery is measured. Do not call carrier bytes unique
  file bytes; reliable transport may retransmit.
- Select sender evidence per directed pair and native retained time bucket.
  Use receiver evidence only for buckets without sender evidence. Then aggregate
  into display intervals. Never add sender and receiver observations together.
  Compaction must preserve canonical volume: if minute 0 has sender 100 bytes
  and receiver 150, and minute 1 has only receiver 300, every enclosing history
  range must retain 400 bytes. Coarser retention cannot replace this with 100
  by preferring sender evidence for the whole hour or day.
- Report a recent rate only with a recent measured interval and actual duration.
  A historical range average is a different statistic. Delayed upload must not
  create a current-rate spike or shift old traffic to reconnect time.
- Missing buckets remain unknown, including when machines are offline. Explicit
  observed zero is distinct. Historical totals remain visible with zero currently
  reporting peers. Partial coverage and journal overflow must be visible.

## Resource bounds

- Packet processing updates cached counters; no metric disk or HTTP operation in
  that path. No new runtime container or inference workload.
- Sample independently of HTTP progress. Batch reports at approximately 30 seconds
  and use existing authenticated sync where possible. Do not repeatedly upload an
  unchanged report at the faster signaling cadence.
- Idle state must not rewrite the journal. Journal persistence runs off the async
  packet loop. Set byte, row, peer, history and retry bounds; writer and reader
  accept the same maximum file size. Retire removed peer counters safely.
- Server queries have account/time indexes, bounded work and retention. Browser
  polling stops for hidden/inactive pages and supports pause. Large pair counts
  must not mount thousands of interactive rows at once.

## Required verification

1. Rust counter/journal tests: reset, retry, acknowledgement, restart, delayed
   upload, malformed/oversize journal, clock changes, peer churn and overflow.
2. Real isolated Mongo/API tests: owner isolation including administrator,
   forged destination, revoked membership, removed machine, duplicate batches,
   partial write retry, sender/receiver fallback before coarse rollup, timestamp
   preservation and retention. Verify recent rates for every history range.
3. Probe-only idle transport: exchange direct PHUBQOS1 requests/replies and
   relay-wrapped discovery probes; all payload traffic counters remain unchanged.
   Then send ordinary payload through the same paths and verify counters grow.
4. Real direct and relay transfer: known bounded payload across existing peers;
   compare client reports and authenticated API. Direct traffic must be observable
   even when gateway payload counters do not grow. Restore original path settings.
5. UI tests: range/machine/pair selection, sparse history, offline historical
   totals, stale rates, pause/resume, request cancellation, account cache clearing,
   errors, and no requests to the terminal traffic endpoint from this panel.
6. Render desktop and iPhone 16 Pro size. Check long machine names, readable
   directions, touch targets, chart selection, custom searchable controls,
   scrolling and zero horizontal overflow.
7. Measure idle and active telemetry overhead and journal/request sizes. Report
   measured evidence, not only configured constants.
8. Build and deploy verified server and compatible agents; then inspect actual
   signed-in account data. Legacy agents show unreported until updated.

These checks supplement the active full-project goal; they do not replace the
remaining Windows enrollment, USB throughput or native networking requirements.
