import { useMemo, useState } from "react";
import { BsCircleFill } from "react-icons/bs";
import { IconFolder } from "@tabler/icons-react";

const normalizeMachineTrafficSamples = (samples) =>
  (Array.isArray(samples) ? samples : [])
    .map((sample) => ({
      timestamp: Number(sample?.timestamp) || 0,
      in_bytes: Math.max(0, Number(sample?.in_bytes) || 0),
      out_bytes: Math.max(0, Number(sample?.out_bytes) || 0),
      drop_bytes: Math.max(0, Number(sample?.drop_bytes) || 0),
    }))
    .filter((sample) => sample.timestamp > 0)
    .sort((left, right) => left.timestamp - right.timestamp)
    .slice(-30);

const buildMiniTrafficWindow = (samples, windowSeconds = 30) => {
  const byTimestamp = new Map();
  const normalizedSamples = normalizeMachineTrafficSamples(samples);

  normalizedSamples.forEach((sample) => {
    const timestamp = Math.floor(sample.timestamp);
    const current = byTimestamp.get(timestamp) || {
      timestamp,
      in_bytes: 0,
      out_bytes: 0,
      drop_bytes: 0,
    };

    byTimestamp.set(timestamp, {
      timestamp,
      in_bytes: current.in_bytes + sample.in_bytes,
      out_bytes: current.out_bytes + sample.out_bytes,
      drop_bytes: current.drop_bytes + sample.drop_bytes,
    });
  });

  const now = Math.floor(Date.now() / 1000);
  const earliestTimestamp = normalizedSamples[0]?.timestamp
    ? Math.floor(normalizedSamples[0].timestamp)
    : null;
  const latestTimestamp = normalizedSamples[normalizedSamples.length - 1]?.timestamp
    ? Math.floor(normalizedSamples[normalizedSamples.length - 1].timestamp)
    : now;
  const windowEndTimestamp = Math.max(now, latestTimestamp);

  return Array.from({ length: windowSeconds }, (_, index) => {
    const timestamp = windowEndTimestamp - (windowSeconds - 1 - index);
    const existing = byTimestamp.get(timestamp);
    if (existing) {
      return existing;
    }

    if (earliestTimestamp !== null && timestamp < earliestTimestamp) {
      const earliestSample = byTimestamp.get(earliestTimestamp);
      if (earliestSample) {
        return {
          ...earliestSample,
          timestamp,
        };
      }
    }

    return {
      timestamp,
      in_bytes: 0,
      out_bytes: 0,
      drop_bytes: 0,
    };
  });
};

const buildMiniTrafficPath = (samples, valueKey, width, height, maxValue) => {
  if (!samples.length || maxValue <= 0) {
    return "";
  }

  const lastIndex = Math.max(1, samples.length - 1);
  const points = samples
    .map((sample, index) => {
      const x = (index / lastIndex) * width;
      const y = height - (Number(sample[valueKey]) / maxValue) * height;
      return { x, y };
    })
    .filter((point) => Number.isFinite(point.x) && Number.isFinite(point.y));

  if (points.length === 0) {
    return "";
  }

  if (points.length === 1) {
    return `M ${points[0].x.toFixed(2)} ${points[0].y.toFixed(2)}`;
  }

  const path = [`M ${points[0].x.toFixed(2)} ${points[0].y.toFixed(2)}`];

  for (let index = 0; index < points.length - 1; index += 1) {
    const current = points[index];
    const next = points[index + 1];
    const controlX = ((current.x + next.x) / 2).toFixed(2);

    path.push(
      `C ${controlX} ${current.y.toFixed(2)}, ${controlX} ${next.y.toFixed(2)}, ${next.x.toFixed(2)} ${next.y.toFixed(2)}`
    );
  }

  return path.join(" ");
};

function MachineTrafficSparkline({ samples = [], isDark }) {
  const chartWidth = 120;
  const chartHeight = 28;
  const windowedSamples = useMemo(() => buildMiniTrafficWindow(samples), [samples]);
  const peakValue = windowedSamples.reduce(
    (maxValue, sample) =>
      Math.max(maxValue, sample.in_bytes, sample.out_bytes, sample.drop_bytes),
    0
  );
  const chartMax = peakValue > 0 ? peakValue * 1.12 : 1;
  const incomingPath = buildMiniTrafficPath(
    windowedSamples,
    "in_bytes",
    chartWidth,
    chartHeight,
    chartMax
  );
  const outgoingPath = buildMiniTrafficPath(
    windowedSamples,
    "out_bytes",
    chartWidth,
    chartHeight,
    chartMax
  );
  const blockedPath = buildMiniTrafficPath(
    windowedSamples,
    "drop_bytes",
    chartWidth,
    chartHeight,
    chartMax
  );

  return (
    <div className="px-1 py-1">
      <svg
        viewBox={`0 0 ${chartWidth} ${chartHeight}`}
        preserveAspectRatio="none"
        className="h-7 w-full"
      >
        <line
          x1="0"
          x2={chartWidth}
          y1={chartHeight}
          y2={chartHeight}
          stroke={isDark ? "rgba(63,63,70,0.55)" : "rgba(228,228,231,1)"}
          strokeWidth="1"
        />
        {incomingPath ? (
          <path
            d={incomingPath}
            fill="none"
            stroke="rgb(52, 211, 153)"
            strokeWidth="1"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        ) : null}
        {outgoingPath ? (
          <path
            d={outgoingPath}
            fill="none"
            stroke="rgb(56, 189, 248)"
            strokeWidth="1"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        ) : null}
        {blockedPath ? (
          <path
            d={blockedPath}
            fill="none"
            stroke="rgb(251, 113, 133)"
            strokeWidth="1"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        ) : null}
      </svg>
    </div>
  );
}

export default function HostItem({
  machineId,
  draggable = false,
  dndMimeType = "application/x-porthub-machine-id",
  onMachineDragEnd,
  name,
  hostname,
  groupLabels = [],
  localIp,
  publicIp,
  isActive,
  connectionStatus,
  isDark,
  lastSeen,
  showGroupColumn = false,
  showPublicIp = true,
  showLastSeen = true,
  showStatus = true,
  numPorts,
  trafficSamples = [],
  onClick,
}) {
  const [isDragging, setIsDragging] = useState(false);
  const resolvedStatus = connectionStatus || (isActive ? "online" : "offline");
  const isDisabled = resolvedStatus === "disabled";
  const isAuthRequired = resolvedStatus === "auth_required";
  const isOnline = resolvedStatus === "online";
  const canDrag = Boolean(draggable && machineId);
  const labels = Array.isArray(groupLabels) ? groupLabels.filter(Boolean) : [];

  const handleDragStart = (event) => {
    if (!canDrag) {
      return;
    }
    event.dataTransfer.setData(dndMimeType, machineId);
    event.dataTransfer.setData("text/plain", machineId);
    event.dataTransfer.effectAllowed = "move";
    setIsDragging(true);
  };

  const handleDragEnd = () => {
    setIsDragging(false);
    onMachineDragEnd?.();
  };

  return (
    <button
      type="button"
      draggable={canDrag}
      onDragStart={handleDragStart}
      onDragEnd={handleDragEnd}
      onClick={onClick}
      className={`w-full bg-white py-4 pl-6 pr-6 text-left hover:bg-zinc-50 focus:outline-none focus:ring-0 focus-visible:outline-none focus-visible:ring-0 dark:bg-zinc-900 dark:hover:bg-zinc-800/70 ${
        canDrag ? "cursor-grab active:cursor-grabbing" : ""
      } ${isDragging ? "opacity-60" : ""}`}
    >
        <div
        className={`grid gap-4 md:items-center md:gap-4 ${
          showLastSeen
            ? showPublicIp
              ? "md:grid-cols-[minmax(0,1.3fr)_110px_minmax(0,0.85fr)_minmax(0,0.85fr)_120px_160px]"
            : showGroupColumn
                ? showStatus
                  ? "md:grid-cols-[repeat(6,minmax(0,1fr))]"
                  : "md:grid-cols-[minmax(0,1.2fr)_minmax(5.75rem,0.9fr)_minmax(8.5rem,1fr)_minmax(9.5rem,1fr)]"
                : "md:grid-cols-[minmax(0,1.5fr)_110px_minmax(0,1fr)_120px_160px]"
            : showPublicIp
              ? "md:grid-cols-5"
              : showGroupColumn
                ? "md:grid-cols-[repeat(5,minmax(0,1fr))]"
                : "md:grid-cols-4"
        }`}
      >
        <div className="grid min-w-0 grid-cols-[8px_minmax(0,1fr)] items-start gap-x-2">
          <BsCircleFill
            size={8}
            className={`row-span-2 mt-1 ${
              isOnline
                ? "text-emerald-500"
                : isDisabled
                  ? "text-zinc-400"
                  : isAuthRequired
                    ? "text-amber-500"
                    : "text-red-400"
            }`}
            aria-label={
              isOnline
                ? "Online"
                : isDisabled
                  ? "Disabled"
                  : isAuthRequired
                    ? "Auth required"
                    : "Offline"
            }
          />
          <span className="truncate font-medium text-zinc-900 dark:text-zinc-100">
            {name}
          </span>
          <div className="text-xs font-mono text-zinc-400">
            {hostname || "Awaiting hostname"}
          </div>
          {labels.length > 0 && !showGroupColumn ? (
            <div className="col-start-2 mt-1 flex flex-wrap gap-1">
              {labels.slice(0, 4).map((label, idx) => (
                <span
                  key={`${label}-${idx}`}
                  className="inline-flex max-w-full truncate rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-blue-700/95 ring-1 ring-blue-500/25 dark:text-blue-200/90 dark:ring-blue-400/30"
                >
                  {label}
                </span>
              ))}
              {labels.length > 4 ? (
                <span className="text-[10px] font-medium text-zinc-500 dark:text-zinc-400">
                  +{labels.length - 4}
                </span>
              ) : null}
            </div>
          ) : null}
        </div>

        <div className="text-center text-xs font-mono text-zinc-500 dark:text-zinc-400">
          {numPorts} ports
        </div>

        {showGroupColumn ? (
          <div className="min-w-0">
            {labels.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                <span
                  className="inline-flex max-w-full items-center gap-1.5 truncate rounded-md bg-zinc-100/80 px-2.5 py-2 text-[10px] font-medium tracking-wide text-zinc-600 ring-1 ring-zinc-200 dark:bg-zinc-800/70 dark:text-zinc-300 dark:ring-zinc-700"
                >
                  <IconFolder size={12} stroke={1.8} />
                  <span className="truncate">{labels[0]}</span>
                </span>
                {labels.length > 1 ? (
                  <span
                    className="inline-flex items-center rounded-md bg-zinc-100/80 px-2.5 py-2 text-[10px] font-medium tracking-wide text-zinc-600 ring-1 ring-zinc-200 dark:bg-zinc-800/70 dark:text-zinc-300 dark:ring-zinc-700"
                  >
                    +{labels.length - 1}
                  </span>
                ) : null}
              </div>
            ) : (
              <div className="text-xs text-zinc-400">No groups</div>
            )}
          </div>
        ) : null}

        {showGroupColumn ? (
          <div className="min-w-0">
            <MachineTrafficSparkline
              samples={trafficSamples}
              isDark={isDark}
            />
          </div>
        ) : null}

        {showPublicIp ? (
          <div className="text-xs font-mono text-zinc-500 dark:text-zinc-400">
            {publicIp || "Awaiting public IP"}
          </div>
        ) : null}

        {showStatus ? (
          <div className="text-center">
            <span
              className={`inline-flex whitespace-nowrap rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.12em] ${
                isOnline
                  ? isDark
                    ? "border-emerald-400/30 bg-emerald-400/18 text-emerald-200"
                    : "border-emerald-200 bg-emerald-50 text-emerald-700"
                  : isDisabled
                    ? isDark
                      ? "border-zinc-500/25 bg-zinc-500/14 text-zinc-200"
                      : "border-zinc-300 bg-zinc-100 text-zinc-700"
                    : isAuthRequired
                      ? isDark
                        ? "border-amber-400/30 bg-amber-400/18 text-amber-200"
                        : "border-amber-200 bg-amber-50 text-amber-700"
                      : isDark
                        ? "border-red-400/25 bg-red-400/14 text-red-200"
                        : "border-red-200 bg-red-50 text-red-700"
              }`}
            >
              {isOnline
                ? "Online"
                : isDisabled
                  ? "Disabled"
                  : isAuthRequired
                    ? "Auth Req"
                    : "Offline"}
            </span>
          </div>
        ) : null}

        {showLastSeen && !(showGroupColumn && !showPublicIp) ? (
          <div className="text-xs font-mono text-zinc-400 md:text-right">
            {lastSeen || "Never seen"}
          </div>
        ) : null}
      </div>
    </button>
  );
}
