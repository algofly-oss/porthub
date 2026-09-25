import { useMemo, useState } from "react";

const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

const parseEventDate = (value) => {
  if (!value) {
    return null;
  }
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value;
  }
  const normalized =
    typeof value === "string" && /(?:Z|[+-]\d{2}:\d{2})$/.test(value)
      ? value
      : `${value}Z`;
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
};

/**
 * TradingView-style granularity presets. `windowMs` is the default span shown
 * per "page" — finer timeframes page backwards/forwards through history,
 * coarser ones already span the full retained history in one page.
 */
// Each timeframe targets ~90 bars per page, so a bar always has enough
// width to read as its own distinct line no matter the panel size; finer
// timeframes page backwards/forwards through history to cover the rest.
const TIMEFRAMES = [
  { key: "15m", label: "15m", bucketMs: 15 * MINUTE_MS, windowMs: DAY_MS },
  { key: "1h", label: "1H", bucketMs: HOUR_MS, windowMs: 4 * DAY_MS },
  { key: "4h", label: "4H", bucketMs: 4 * HOUR_MS, windowMs: 15 * DAY_MS },
  { key: "1d", label: "1D", bucketMs: DAY_MS, windowMs: 90 * DAY_MS },
  { key: "1w", label: "1W", bucketMs: 7 * DAY_MS, windowMs: 365 * DAY_MS },
];

/** Turns raw ordered status-change events into contiguous [start, end, status) segments. */
const buildStatusSegments = (events) => {
  const sorted = (Array.isArray(events) ? events : [])
    .map((event) => ({ status: event.status, changedAt: parseEventDate(event.changed_at) }))
    .filter((event) => event.changedAt && (event.status === "online" || event.status === "offline"))
    .sort((left, right) => left.changedAt - right.changedAt);

  if (sorted.length === 0) {
    return [];
  }

  const now = new Date();
  const segments = [];
  for (let i = 0; i < sorted.length; i += 1) {
    const start = sorted[i].changedAt;
    const end = i + 1 < sorted.length ? sorted[i + 1].changedAt : now;
    if (end > start) {
      segments.push({ start, end, status: sorted[i].status });
    }
  }
  return segments;
};

/**
 * Buckets [windowStart, windowEnd) into `bucketMs`-wide slots, computing the
 * online/offline/no-data time fraction of each slot via a two-pointer sweep
 * over the (sorted, contiguous) status segments.
 */
const buildBuckets = (segments, windowStart, windowEnd, bucketMs) => {
  const bucketCount = Math.max(1, Math.round((windowEnd - windowStart) / bucketMs));
  const buckets = [];
  let segIndex = 0;
  while (segIndex < segments.length && segments[segIndex].end <= windowStart) {
    segIndex += 1;
  }

  for (let i = 0; i < bucketCount; i += 1) {
    const bucketStart = new Date(windowStart.getTime() + i * bucketMs);
    const bucketEnd = new Date(bucketStart.getTime() + bucketMs);
    let onlineMs = 0;
    let offlineMs = 0;

    let scan = segIndex;
    while (scan < segments.length && segments[scan].start < bucketEnd) {
      const overlapStart = Math.max(segments[scan].start.getTime(), bucketStart.getTime());
      const overlapEnd = Math.min(segments[scan].end.getTime(), bucketEnd.getTime());
      const overlap = overlapEnd - overlapStart;
      if (overlap > 0) {
        if (segments[scan].status === "online") onlineMs += overlap;
        else offlineMs += overlap;
      }
      if (segments[scan].end <= bucketEnd) {
        segIndex = scan + 1;
      }
      scan += 1;
    }

    const bucketSpan = bucketEnd.getTime() - bucketStart.getTime();
    const onlineFrac = bucketSpan > 0 ? onlineMs / bucketSpan : 0;
    const offlineFrac = bucketSpan > 0 ? offlineMs / bucketSpan : 0;
    const noDataFrac = Math.max(0, 1 - onlineFrac - offlineFrac);
    const hasData = onlineFrac + offlineFrac > 0.0001;

    let status = "no-data";
    if (hasData) {
      if (onlineFrac >= 0.999) status = "online";
      else if (offlineFrac >= 0.999) status = "offline";
      else status = "mixed";
    }

    buckets.push({
      start: bucketStart,
      end: bucketEnd,
      onlineFrac,
      offlineFrac,
      noDataFrac,
      hasData,
      status,
    });
  }

  return buckets;
};

const STATUS_COLORS = {
  online: "rgb(52, 211, 153)",
  offline: "rgb(251, 113, 133)",
  mixed: "rgb(251, 191, 36)",
};

const STATUS_LABELS = {
  online: "Online",
  offline: "Offline",
  mixed: "Online & offline",
  "no-data": "No data",
};

const formatTimeLabel = (date, timeframeKey) => {
  if (timeframeKey === "1d" || timeframeKey === "1w") {
    return date.toLocaleDateString(undefined, { day: "2-digit", month: "short", year: "numeric" });
  }
  return date.toLocaleString(undefined, {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
};

const formatExactLabel = (date) =>
  date.toLocaleString(undefined, {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

export default function UptimeHistoryPanel({ isDark, events, isLoading, days = 365 }) {
  const [timeframeKey, setTimeframeKey] = useState("1h");
  const [pageOffset, setPageOffset] = useState(0);
  const [hoveredIndex, setHoveredIndex] = useState(null);

  const timeframe = TIMEFRAMES.find((tf) => tf.key === timeframeKey) || TIMEFRAMES[1];

  const segments = useMemo(() => buildStatusSegments(events), [events]);

  const retentionStart = useMemo(() => {
    const cutoff = new Date();
    cutoff.setTime(cutoff.getTime() - days * DAY_MS);
    return cutoff;
  }, [days]);

  const { windowStart, windowEnd, canGoOlder, canGoNewer } = useMemo(() => {
    const now = new Date();
    const end = new Date(now.getTime() - pageOffset * timeframe.windowMs);
    const start = new Date(end.getTime() - timeframe.windowMs);
    const clampedStart = start < retentionStart ? retentionStart : start;
    return {
      windowStart: clampedStart,
      windowEnd: end,
      canGoOlder: clampedStart > retentionStart,
      canGoNewer: pageOffset > 0,
    };
  }, [pageOffset, timeframe, retentionStart]);

  const buckets = useMemo(
    () => buildBuckets(segments, windowStart, windowEnd, timeframe.bucketMs),
    [segments, windowStart, windowEnd, timeframe]
  );

  const hoveredBucket = hoveredIndex !== null ? buckets[hoveredIndex] : null;
  const hasAnyData = buckets.some((bucket) => bucket.hasData);
  const isPaged = timeframe.windowMs < 365 * DAY_MS;

  const handleTimeframeChange = (key) => {
    setTimeframeKey(key);
    setPageOffset(0);
  };

  return (
    <div
      className={`min-w-0 rounded-lg border p-3 ${
        isDark ? "border-zinc-800 bg-zinc-950/70" : "border-zinc-200 bg-zinc-50/80"
      }`}
    >
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className={`text-sm font-semibold ${isDark ? "text-zinc-100" : "text-zinc-900"}`}>
            Uptime history
          </p>
          <p className="text-[11px] text-zinc-500">Hover a bar for details</p>
        </div>

        <div className="flex items-center gap-1">
          {TIMEFRAMES.map((tf) => (
            <button
              key={tf.key}
              type="button"
              onClick={() => handleTimeframeChange(tf.key)}
              className={`rounded-md px-2 py-1 text-[11px] font-medium transition-colors ${
                tf.key === timeframeKey
                  ? "bg-emerald-500 text-white"
                  : isDark
                    ? "bg-zinc-800 text-zinc-300 hover:bg-zinc-700"
                    : "bg-zinc-200 text-zinc-600 hover:bg-zinc-300"
              }`}
            >
              {tf.label}
            </button>
          ))}
        </div>

        <div className="flex shrink-0 items-center gap-3 text-[11px] text-zinc-500">
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-sm bg-emerald-400" />
            Online
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-sm bg-rose-400" />
            Offline
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-sm bg-amber-400" />
            Mixed
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className={`h-2.5 w-2.5 rounded-sm ${isDark ? "bg-zinc-700" : "bg-zinc-300"}`} />
            No data
          </span>
        </div>
      </div>

      <div
        className={`mb-2 flex h-6 items-center gap-2 rounded-md border px-2 text-[11px] ${
          hoveredBucket
            ? isDark
              ? "border-zinc-700 bg-zinc-950 text-zinc-100 shadow-sm"
              : "border-zinc-200 bg-white text-zinc-900 shadow-sm"
            : "border-transparent"
        }`}
      >
        {hoveredBucket ? (
          <>
            <span>{formatExactLabel(hoveredBucket.start)}</span>
            <span className="text-zinc-500">
              {STATUS_LABELS[hoveredBucket.status]}
              {hoveredBucket.status === "mixed"
                ? ` (${Math.round(hoveredBucket.onlineFrac * 100)}% online)`
                : ""}
            </span>
          </>
        ) : null}
      </div>

      <div className="flex min-w-0 items-stretch gap-2">
        {isPaged ? (
          <button
            type="button"
            disabled={!canGoOlder}
            onClick={() => setPageOffset((prev) => prev + 1)}
            className={`shrink-0 rounded-md px-1.5 text-xs ${
              canGoOlder
                ? isDark
                  ? "text-zinc-300 hover:bg-zinc-800"
                  : "text-zinc-600 hover:bg-zinc-200"
                : "cursor-not-allowed text-zinc-600/30"
            }`}
            aria-label="Older"
          >
            ‹
          </button>
        ) : null}

        <div
          className="grid h-32 min-w-0 flex-1 gap-px overflow-hidden"
          style={{ gridTemplateColumns: `repeat(${buckets.length}, minmax(0, 1fr))` }}
          onMouseLeave={() => setHoveredIndex(null)}
        >
          {buckets.map((bucket, index) => (
            <div
              key={bucket.start.toISOString()}
              onMouseEnter={() => setHoveredIndex(index)}
              className="h-full min-w-0 rounded-[1px] transition-opacity hover:opacity-80"
              style={{
                backgroundColor:
                  STATUS_COLORS[bucket.status] || (isDark ? "#27272a" : "#e4e4e7"),
              }}
            />
          ))}
        </div>

        {isPaged ? (
          <button
            type="button"
            disabled={!canGoNewer}
            onClick={() => setPageOffset((prev) => Math.max(0, prev - 1))}
            className={`shrink-0 rounded-md px-1.5 text-xs ${
              canGoNewer
                ? isDark
                  ? "text-zinc-300 hover:bg-zinc-800"
                  : "text-zinc-600 hover:bg-zinc-200"
                : "cursor-not-allowed text-zinc-600/30"
            }`}
            aria-label="Newer"
          >
            ›
          </button>
        ) : null}
      </div>

      <div className="mt-2 flex items-center justify-between text-[10px] text-zinc-500">
        <span>{formatTimeLabel(windowStart, timeframeKey)}</span>
        <span>{pageOffset === 0 ? "Now" : formatTimeLabel(windowEnd, timeframeKey)}</span>
      </div>

      {isLoading ? (
        <p className="mt-2 text-xs text-zinc-500">Loading uptime history...</p>
      ) : !hasAnyData ? (
        <p className="mt-2 text-xs text-zinc-500">No status history recorded yet for this machine.</p>
      ) : null}
    </div>
  );
}
