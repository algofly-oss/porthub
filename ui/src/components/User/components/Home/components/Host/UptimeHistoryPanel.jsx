import { useEffect, useMemo, useState } from "react";

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

// Each option is the total span the chart shows, ending now. The chart always
// has BAR_COUNT bars, so bars keep the same width and each bar covers
// span / BAR_COUNT (e.g. 1 minute per bar for the last hour).
const BAR_COUNT = 60;

const TIMEFRAMES = [
  { key: "15m", label: "15m", spanMs: 15 * MINUTE_MS },
  { key: "1h", label: "1H", spanMs: HOUR_MS },
  { key: "6h", label: "6H", spanMs: 6 * HOUR_MS },
  { key: "24h", label: "24H", spanMs: DAY_MS },
  { key: "7d", label: "7D", spanMs: 7 * DAY_MS },
  { key: "30d", label: "30D", spanMs: 30 * DAY_MS },
  { key: "1y", label: "1Y", spanMs: 365 * DAY_MS },
];

const DEFAULT_TIMEFRAME_KEY = "24h";

/** Turns raw ordered status-change events into contiguous [start, end, status) segments. */
const buildStatusSegments = (events, now) => {
  const sorted = (Array.isArray(events) ? events : [])
    .map((event) => ({ status: event.status, changedAt: parseEventDate(event.changed_at) }))
    .filter((event) => event.changedAt && (event.status === "online" || event.status === "offline"))
    .sort((left, right) => left.changedAt - right.changedAt);

  const segments = [];
  for (let i = 0; i < sorted.length; i += 1) {
    // Skip repeated events of the same status so segments stay contiguous.
    if (segments.length && segments[segments.length - 1].status === sorted[i].status) {
      continue;
    }
    if (segments.length) {
      segments[segments.length - 1].end = sorted[i].changedAt;
    }
    segments.push({ start: sorted[i].changedAt, end: now, status: sorted[i].status });
  }
  return segments.filter((segment) => segment.end > segment.start);
};

/** Splits [windowStart, windowEnd) into BAR_COUNT bars measuring online/offline time in each. */
const buildBuckets = (segments, windowStart, windowEnd, now) => {
  const bucketMs = (windowEnd - windowStart) / BAR_COUNT;
  const buckets = [];

  for (let i = 0; i < BAR_COUNT; i += 1) {
    const start = new Date(windowStart.getTime() + i * bucketMs);
    const end = new Date(start.getTime() + bucketMs);
    const measuredEnd = end > now ? now : end;
    let onlineMs = 0;
    let offlineMs = 0;

    for (const segment of segments) {
      if (segment.end <= start || segment.start >= measuredEnd) continue;
      const overlap =
        Math.min(segment.end.getTime(), measuredEnd.getTime()) -
        Math.max(segment.start.getTime(), start.getTime());
      if (overlap <= 0) continue;
      if (segment.status === "online") onlineMs += overlap;
      else offlineMs += overlap;
    }

    const knownMs = onlineMs + offlineMs;
    let status = "no-data";
    if (knownMs > 0) {
      if (offlineMs === 0) status = "online";
      else if (onlineMs === 0) status = "offline";
      else status = "mixed";
    }

    buckets.push({
      start,
      end,
      onlineMs,
      offlineMs,
      uptime: knownMs > 0 ? onlineMs / knownMs : null,
      hasData: knownMs > 0,
      status,
    });
  }

  return buckets;
};

const formatDuration = (ms) => {
  if (ms < MINUTE_MS) return `${Math.max(1, Math.round(ms / 1000))}s`;
  const totalMinutes = Math.round(ms / MINUTE_MS);
  const days = Math.floor(totalMinutes / (24 * 60));
  const hours = Math.floor((totalMinutes % (24 * 60)) / 60);
  const minutes = totalMinutes % 60;
  return [days && `${days}d`, hours && `${hours}h`, minutes && `${minutes}m`]
    .filter(Boolean)
    .join(" ");
};

const formatPercent = (fraction) => {
  const percent = fraction * 100;
  return `${percent >= 99.95 || percent <= 0.05 ? percent.toFixed(0) : percent.toFixed(1)}%`;
};

const ONLINE_COLOR = "rgb(52, 211, 153)";
const OFFLINE_COLOR = "rgb(251, 113, 133)";
const LIVE_REFRESH_MS = 15 * 1000;

const formatBarTime = (date, spanMs) => {
  if (spanMs >= 7 * DAY_MS) {
    return date.toLocaleString(undefined, {
      day: "2-digit",
      month: "short",
      year: spanMs >= 30 * DAY_MS ? "numeric" : undefined,
      hour: spanMs >= 30 * DAY_MS ? undefined : "2-digit",
      minute: spanMs >= 30 * DAY_MS ? undefined : "2-digit",
    });
  }
  return date.toLocaleString(undefined, {
    day: spanMs >= DAY_MS ? "2-digit" : undefined,
    month: spanMs >= DAY_MS ? "short" : undefined,
    hour: "2-digit",
    minute: "2-digit",
    second: spanMs <= HOUR_MS ? "2-digit" : undefined,
  });
};

const describeBucket = (bucket) => {
  if (!bucket.hasData) return "No data";
  if (bucket.status === "online") return `Online · ${formatDuration(bucket.onlineMs)}`;
  if (bucket.status === "offline") return `Offline · ${formatDuration(bucket.offlineMs)}`;
  return `${formatPercent(bucket.uptime)} uptime · online ${formatDuration(
    bucket.onlineMs
  )}, offline ${formatDuration(bucket.offlineMs)}`;
};

export default function UptimeHistoryPanel({
  isDark,
  events,
  isLoading,
  currentStatus,
  days = 365,
}) {
  const [timeframeKey, setTimeframeKey] = useState(DEFAULT_TIMEFRAME_KEY);
  const [pageOffset, setPageOffset] = useState(0);
  const [hoveredIndex, setHoveredIndex] = useState(null);
  const [now, setNow] = useState(() => new Date());

  // Keep the window sliding with the clock so the latest bars stay live.
  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), LIVE_REFRESH_MS);
    return () => clearInterval(timer);
  }, []);

  const timeframe =
    TIMEFRAMES.find((tf) => tf.key === timeframeKey) ||
    TIMEFRAMES.find((tf) => tf.key === DEFAULT_TIMEFRAME_KEY);

  const segments = useMemo(() => buildStatusSegments(events, now), [events, now]);

  const retentionStart = new Date(now.getTime() - days * DAY_MS);
  const windowEnd = new Date(now.getTime() - pageOffset * timeframe.spanMs);
  const windowStart = new Date(windowEnd.getTime() - timeframe.spanMs);
  const canGoOlder = windowStart > retentionStart;
  const canGoNewer = pageOffset > 0;

  const buckets = useMemo(
    () => buildBuckets(segments, windowStart, windowEnd, now),
    // windowStart/windowEnd are derived from these values.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [segments, timeframe, pageOffset, now]
  );

  const hoveredBucket = hoveredIndex !== null ? buckets[hoveredIndex] : null;
  const totals = buckets.reduce(
    (acc, bucket) => ({
      onlineMs: acc.onlineMs + bucket.onlineMs,
      offlineMs: acc.offlineMs + bucket.offlineMs,
    }),
    { onlineMs: 0, offlineMs: 0 }
  );
  const knownMs = totals.onlineMs + totals.offlineMs;
  const hasAnyData = knownMs > 0;
  const windowUptime = hasAnyData ? totals.onlineMs / knownMs : null;
  const isOnline = currentStatus === "online";

  const handleTimeframeChange = (key) => {
    setTimeframeKey(key);
    setPageOffset(0);
    setHoveredIndex(null);
  };

  const pagerClassName = (enabled) =>
    `shrink-0 rounded-md px-1.5 text-xs ${
      enabled
        ? isDark
          ? "text-zinc-300 hover:bg-zinc-800"
          : "text-zinc-600 hover:bg-zinc-200"
        : "cursor-not-allowed text-zinc-600/30"
    }`;

  return (
    <div
      className={`min-w-0 rounded-lg border p-3 ${
        isDark ? "border-zinc-800 bg-zinc-950/70" : "border-zinc-200 bg-zinc-50/80"
      }`}
    >
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <p className={`text-sm font-semibold ${isDark ? "text-zinc-100" : "text-zinc-900"}`}>
            Uptime history
          </p>
          {currentStatus ? (
            <span
              className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium ${
                isOnline
                  ? "bg-emerald-500/15 text-emerald-500"
                  : "bg-rose-500/15 text-rose-500"
              }`}
            >
              <span
                className={`h-2 w-2 rounded-full ${isOnline ? "bg-emerald-400" : "bg-rose-400"}`}
              />
              {isOnline ? "Online now" : "Offline now"}
            </span>
          ) : null}
          {windowUptime !== null ? (
            <span className={`text-[11px] ${isDark ? "text-zinc-300" : "text-zinc-700"}`}>
              <span className="font-semibold">{formatPercent(windowUptime)}</span> uptime
              {totals.offlineMs > 0 ? ` · ${formatDuration(totals.offlineMs)} offline` : ""}
            </span>
          ) : null}
        </div>

        <div className="flex flex-wrap items-center gap-1">
          {TIMEFRAMES.map((tf) => (
            <button
              key={tf.key}
              type="button"
              onClick={() => handleTimeframeChange(tf.key)}
              className={`rounded-md px-2 py-1 text-[11px] font-medium transition-colors ${
                tf.key === timeframe.key
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
      </div>

      <div
        className={`mb-2 flex h-6 items-center gap-2 overflow-hidden whitespace-nowrap rounded-md border px-2 text-[11px] ${
          hoveredBucket
            ? isDark
              ? "border-zinc-700 bg-zinc-950 text-zinc-100 shadow-sm"
              : "border-zinc-200 bg-white text-zinc-900 shadow-sm"
            : "border-transparent text-zinc-500"
        }`}
      >
        {hoveredBucket ? (
          <>
            <span>
              {formatBarTime(hoveredBucket.start, timeframe.spanMs)} –{" "}
              {formatBarTime(hoveredBucket.end > now ? now : hoveredBucket.end, timeframe.spanMs)}
            </span>
            <span className="text-zinc-500">{describeBucket(hoveredBucket)}</span>
          </>
        ) : (
          <span>
            {BAR_COUNT} bars · {formatDuration(timeframe.spanMs / BAR_COUNT)} each · hover a bar
            for details
          </span>
        )}
      </div>

      <div className="flex min-w-0 items-stretch gap-2">
        <button
          type="button"
          disabled={!canGoOlder}
          onClick={() => setPageOffset((prev) => prev + 1)}
          className={pagerClassName(canGoOlder)}
          aria-label="Older"
        >
          ‹
        </button>

        <div
          className="grid h-32 min-w-0 flex-1 gap-px overflow-hidden"
          style={{ gridTemplateColumns: `repeat(${BAR_COUNT}, minmax(0, 1fr))` }}
          onMouseLeave={() => setHoveredIndex(null)}
        >
          {buckets.map((bucket, index) => (
            <div
              key={index}
              onMouseEnter={() => setHoveredIndex(index)}
              className={`flex h-full min-w-0 flex-col overflow-hidden rounded-[1px] transition-opacity hover:opacity-80 ${
                bucket.hasData ? "" : isDark ? "bg-zinc-800" : "bg-zinc-200"
              }`}
            >
              {bucket.hasData ? (
                <>
                  <div style={{ flexGrow: bucket.onlineMs, backgroundColor: ONLINE_COLOR }} />
                  <div
                    style={{
                      flexGrow: bucket.offlineMs,
                      // Keep short outages visible even inside long bars.
                      minHeight: bucket.offlineMs > 0 ? "15%" : 0,
                      backgroundColor: OFFLINE_COLOR,
                    }}
                  />
                </>
              ) : null}
            </div>
          ))}
        </div>

        <button
          type="button"
          disabled={!canGoNewer}
          onClick={() => setPageOffset((prev) => Math.max(0, prev - 1))}
          className={pagerClassName(canGoNewer)}
          aria-label="Newer"
        >
          ›
        </button>
      </div>

      <div className="mt-2 flex items-center justify-between px-6 text-[10px] text-zinc-500">
        <span>{formatBarTime(windowStart, timeframe.spanMs)}</span>
        <span className="flex items-center gap-3">
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-sm bg-emerald-400" />
            Online
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-sm bg-rose-400" />
            Offline
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className={`h-2 w-2 rounded-sm ${isDark ? "bg-zinc-700" : "bg-zinc-300"}`} />
            No data
          </span>
        </span>
        <span>{pageOffset === 0 ? "Now" : formatBarTime(windowEnd, timeframe.spanMs)}</span>
      </div>

      {isLoading && !hasAnyData ? (
        <p className="mt-2 text-xs text-zinc-500">Loading uptime history...</p>
      ) : !hasAnyData ? (
        <p className="mt-2 text-xs text-zinc-500">No status recorded for this period yet.</p>
      ) : null}
    </div>
  );
}
