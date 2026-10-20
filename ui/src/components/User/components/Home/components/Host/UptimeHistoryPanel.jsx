import { useEffect, useMemo, useState } from "react";
import { IconChevronLeft, IconChevronRight } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { StatusTabs } from "@/components/ui/status-tabs";

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

  return (
    <section
      aria-label="Uptime History"
      className="min-w-0 rounded-lg bg-surface p-4 [--uptime-online:5_150_105] [--uptime-offline:225_29_72] dark:[--uptime-online:52_211_153] dark:[--uptime-offline:251_113_133]"
    >
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-sm font-semibold text-foreground">Uptime History</h2>
          {currentStatus ? (
            <span
              className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium ${
                isOnline
                  ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
                  : "bg-rose-500/10 text-rose-700 dark:text-rose-300"
              }`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${isOnline ? "bg-[rgb(var(--uptime-online))]" : "bg-[rgb(var(--uptime-offline))]"}`}
              />
              {isOnline ? "Online now" : "Offline now"}
            </span>
          ) : null}
          {windowUptime !== null ? (
            <span className="text-xs text-muted-foreground">
              <span className="font-semibold">{formatPercent(windowUptime)}</span> uptime
              {totals.offlineMs > 0 ? ` · ${formatDuration(totals.offlineMs)} offline` : ""}
            </span>
          ) : null}
        </div>

        <div className="max-w-full overflow-x-auto pb-1">
          <StatusTabs label="Uptime history timeframe" value={timeframe.key} onChange={handleTimeframeChange} options={TIMEFRAMES.map(tf => ({value:tf.key,label:tf.label}))} />
        </div>
      </div>

      <div
        aria-live="polite"
        className={`mb-3 flex min-h-[44px] flex-wrap items-center gap-x-3 gap-y-1 rounded-md px-3 py-2 text-xs leading-5 ${
          hoveredBucket
            ? "bg-control text-foreground"
            : "text-muted-foreground"
        }`}
      >
        {hoveredBucket ? (
          <>
            <span>
              {formatBarTime(hoveredBucket.start, timeframe.spanMs)} –{" "}
              {formatBarTime(hoveredBucket.end > now ? now : hoveredBucket.end, timeframe.spanMs)}
            </span>
            <span className={hoveredBucket.status === "online" ? "text-emerald-700 dark:text-emerald-400" : hoveredBucket.status === "offline" ? "text-rose-700 dark:text-rose-300" : "text-muted-foreground"}>{describeBucket(hoveredBucket)}</span>
          </>
        ) : (
          <span>
            {BAR_COUNT} bars · {formatDuration(timeframe.spanMs / BAR_COUNT)} each · hover a bar
            for details
          </span>
        )}
      </div>

      <div className="flex min-w-0 items-stretch gap-2">
        <Button
          type="button"
          variant="secondary"
          size="icon"
          disabled={!canGoOlder}
          onClick={() => setPageOffset((prev) => prev + 1)}
          className="h-9 w-7 self-center"
          aria-label="Older"
        >
          <IconChevronLeft size={16} />
        </Button>

        <div
          className="grid h-24 min-w-0 flex-1 gap-px overflow-hidden sm:h-32"
          style={{ gridTemplateColumns: `repeat(${BAR_COUNT}, minmax(0, 1fr))` }}
          onMouseLeave={() => setHoveredIndex(null)}
        >
          {buckets.map((bucket, index) => (
            <div
              key={index}
              data-uptime-status={bucket.status}
              onMouseEnter={() => setHoveredIndex(index)}
              className={`flex h-full min-w-0 flex-col overflow-hidden rounded-sm hover:opacity-75 ${
                bucket.hasData ? "" : "bg-border"
              }`}
            >
              {bucket.hasData ? (
                <>
                  <div className="bg-[rgb(var(--uptime-online))]" style={{ flexGrow: bucket.onlineMs }} />
                  <div
                    style={{
                      flexGrow: bucket.offlineMs,
                      // Keep short outages visible even inside long bars.
                      minHeight: bucket.offlineMs > 0 ? "15%" : 0,
                    }}
                    className="bg-[rgb(var(--uptime-offline))]"
                  />
                </>
              ) : null}
            </div>
          ))}
        </div>

        <Button
          type="button"
          variant="secondary"
          size="icon"
          disabled={!canGoNewer}
          onClick={() => setPageOffset((prev) => Math.max(0, prev - 1))}
          className="h-9 w-7 self-center"
          aria-label="Newer"
        >
          <IconChevronRight size={16} />
        </Button>
      </div>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-x-3 gap-y-2 text-[11px] text-muted-foreground">
        <span>{formatBarTime(windowStart, timeframe.spanMs)}</span>
        <span className="order-3 flex w-full flex-wrap justify-center gap-3 sm:order-none sm:w-auto">
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-sm bg-[rgb(var(--uptime-online))]" />
            Online
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-sm bg-[rgb(var(--uptime-offline))]" />
            Offline
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-sm bg-border" />
            No data
          </span>
        </span>
        <span>{pageOffset === 0 ? "Now" : formatBarTime(windowEnd, timeframe.spanMs)}</span>
      </div>

      {isLoading && !hasAnyData ? (
        <p className="mt-2 text-xs text-muted-foreground">Loading uptime history...</p>
      ) : !hasAnyData ? (
        <p className="mt-2 text-xs text-muted-foreground">No status recorded for this period yet.</p>
      ) : null}
    </section>
  );
}
