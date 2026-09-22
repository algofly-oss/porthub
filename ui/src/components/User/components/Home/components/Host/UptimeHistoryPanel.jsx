import { useMemo, useState } from "react";

const DAY_MS = 24 * 60 * 60 * 1000;

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
 * Buckets status-change events into one online/offline/no-data status per day,
 * for the last `days` days ending today (inclusive).
 */
const buildDayBuckets = (events, days) => {
  const sortedEvents = (Array.isArray(events) ? events : [])
    .map((event) => ({ status: event.status, changedAt: parseEventDate(event.changed_at) }))
    .filter((event) => event.changedAt && (event.status === "online" || event.status === "offline"))
    .sort((left, right) => left.changedAt - right.changedAt);

  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const startDay = new Date(today.getTime() - (days - 1) * DAY_MS);

  let statusBeforeWindow = null;
  for (const event of sortedEvents) {
    if (event.changedAt < startDay) {
      statusBeforeWindow = event.status;
    } else {
      break;
    }
  }

  const buckets = [];
  let eventIndex = sortedEvents.findIndex((event) => event.changedAt >= startDay);
  if (eventIndex === -1) {
    eventIndex = sortedEvents.length;
  }
  let currentStatus = statusBeforeWindow;

  for (let dayOffset = 0; dayOffset < days; dayOffset += 1) {
    const dayStart = new Date(startDay.getTime() + dayOffset * DAY_MS);
    const dayEnd = new Date(dayStart.getTime() + DAY_MS);
    let sawOffline = false;
    let sawOnline = false;

    while (eventIndex < sortedEvents.length && sortedEvents[eventIndex].changedAt < dayEnd) {
      currentStatus = sortedEvents[eventIndex].status;
      if (currentStatus === "offline") sawOffline = true;
      if (currentStatus === "online") sawOnline = true;
      eventIndex += 1;
    }

    let dayStatus = "no-data";
    if (sawOffline && sawOnline) {
      dayStatus = "mixed";
    } else if (sawOffline) {
      dayStatus = "offline";
    } else if (sawOnline) {
      dayStatus = "online";
    } else if (currentStatus) {
      dayStatus = currentStatus;
    }

    buckets.push({ date: dayStart, status: dayStatus });
  }

  return buckets;
};

const STATUS_COLORS = {
  online: "rgb(52, 211, 153)",
  offline: "rgb(251, 113, 133)",
  mixed: "rgb(251, 191, 36)",
  "no-data": null,
};

const formatDayLabel = (date) =>
  date.toLocaleDateString(undefined, { day: "2-digit", month: "short", year: "numeric" });

export default function UptimeHistoryPanel({ isDark, events, isLoading, days = 365 }) {
  const [hoveredIndex, setHoveredIndex] = useState(null);
  const buckets = useMemo(() => buildDayBuckets(events, days), [events, days]);
  const hoveredBucket = hoveredIndex !== null ? buckets[hoveredIndex] : null;

  const hasAnyData = buckets.some((bucket) => bucket.status !== "no-data");

  return (
    <div
      className={`rounded-lg border p-3 ${
        isDark ? "border-zinc-800 bg-zinc-950/70" : "border-zinc-200 bg-zinc-50/80"
      }`}
    >
      <div className="mb-3 flex items-center justify-between gap-3">
        <div>
          <p className={`text-sm font-semibold ${isDark ? "text-zinc-100" : "text-zinc-900"}`}>
            Uptime history
          </p>
          <p className="text-[11px] text-zinc-500">Last {days} days · hover a day for details</p>
        </div>
        <div className="flex shrink-0 items-center gap-3 text-[11px] text-zinc-500">
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-400" />
            Online
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-rose-400" />
            Offline
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span
              className={`h-2.5 w-2.5 rounded-full ${isDark ? "bg-zinc-700" : "bg-zinc-300"}`}
            />
            No data
          </span>
        </div>
      </div>

      {hoveredBucket ? (
        <div
          className={`mb-2 inline-flex items-center gap-2 rounded-md border px-2 py-1 text-[11px] shadow-sm ${
            isDark
              ? "border-zinc-700 bg-zinc-950 text-zinc-100"
              : "border-zinc-200 bg-white text-zinc-900"
          }`}
        >
          <span
            className="h-2 w-2 rounded-full"
            style={{
              backgroundColor:
                STATUS_COLORS[hoveredBucket.status] || (isDark ? "#3f3f46" : "#d4d4d8"),
            }}
          />
          <span>{formatDayLabel(hoveredBucket.date)}</span>
          <span className="text-zinc-500">
            {hoveredBucket.status === "no-data"
              ? "No data"
              : hoveredBucket.status === "mixed"
                ? "Online & offline"
                : hoveredBucket.status === "online"
                  ? "Online"
                  : "Offline"}
          </span>
        </div>
      ) : null}

      <div
        className="grid w-full gap-[1.5px]"
        style={{ gridTemplateColumns: `repeat(${buckets.length}, minmax(0, 1fr))` }}
        onMouseLeave={() => setHoveredIndex(null)}
      >
        {buckets.map((bucket, index) => (
          <div
            key={bucket.date.toISOString()}
            onMouseEnter={() => setHoveredIndex(index)}
            className="h-8 rounded-[2px] transition-opacity hover:opacity-80"
            style={{
              backgroundColor:
                STATUS_COLORS[bucket.status] || (isDark ? "#27272a" : "#e4e4e7"),
            }}
          />
        ))}
      </div>

      <div className="mt-2 flex items-center justify-between text-[10px] text-zinc-500">
        <span>{formatDayLabel(buckets[0]?.date || new Date())}</span>
        <span>Today</span>
      </div>

      {isLoading ? (
        <p className="mt-2 text-xs text-zinc-500">Loading uptime history...</p>
      ) : !hasAnyData ? (
        <p className="mt-2 text-xs text-zinc-500">
          No status history recorded yet for this machine.
        </p>
      ) : null}
    </div>
  );
}
