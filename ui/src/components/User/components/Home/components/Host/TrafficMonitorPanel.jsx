import { useMemo, useState } from "react";
import { ActionIcon, Badge, Tooltip } from "@mantine/core";
import { IconExternalLink } from "@tabler/icons-react";

export const normalizeTrafficSamples = (samples) =>
  (Array.isArray(samples) ? samples : [])
    .map((sample) => ({
      timestamp: Number(sample?.timestamp) || 0,
      in_bytes: Math.max(0, Number(sample?.in_bytes) || 0),
      out_bytes: Math.max(0, Number(sample?.out_bytes) || 0),
      drop_bytes: Math.max(0, Number(sample?.drop_bytes) || 0),
      blocked_ips: Array.isArray(sample?.blocked_ips)
        ? sample.blocked_ips
            .map((value) => String(value || "").trim())
            .filter(Boolean)
        : [],
      incoming_ips: Array.isArray(sample?.incoming_ips)
        ? sample.incoming_ips
            .map((value) => String(value || "").trim())
            .filter(Boolean)
        : [],
      outgoing_ips: Array.isArray(sample?.outgoing_ips)
        ? sample.outgoing_ips
            .map((value) => String(value || "").trim())
            .filter(Boolean)
        : [],
    }))
    .filter((sample) => sample.timestamp > 0)
    .sort((left, right) => left.timestamp - right.timestamp)
    .slice(-120);

const buildTrafficWindow = (samples, windowSeconds = 60) => {
  const byTimestamp = new Map();
  const normalizedSamples = normalizeTrafficSamples(samples);

  normalizedSamples.forEach((sample) => {
    const timestamp = Math.floor(sample.timestamp);
    const current = byTimestamp.get(timestamp) || {
      timestamp,
      in_bytes: 0,
      out_bytes: 0,
      drop_bytes: 0,
      blocked_ips: [],
      incoming_ips: [],
      outgoing_ips: [],
    };

    byTimestamp.set(timestamp, {
      timestamp,
      in_bytes: current.in_bytes + sample.in_bytes,
      out_bytes: current.out_bytes + sample.out_bytes,
      drop_bytes: current.drop_bytes + sample.drop_bytes,
      blocked_ips: [...new Set([...current.blocked_ips, ...sample.blocked_ips])],
      incoming_ips: [...new Set([...current.incoming_ips, ...sample.incoming_ips])],
      outgoing_ips: [...new Set([...current.outgoing_ips, ...sample.outgoing_ips])],
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

  const samplesWindow = Array.from({ length: windowSeconds }, (_, index) => {
    const timestamp = windowEndTimestamp - (windowSeconds - 1 - index);
    const existing = byTimestamp.get(timestamp);
    if (existing) {
      return existing;
    }

    if (earliestTimestamp !== null && timestamp < earliestTimestamp) {
      const earliestSample = byTimestamp.get(earliestTimestamp);
      if (earliestSample) {
        return {
          timestamp,
          in_bytes: earliestSample.in_bytes,
          out_bytes: earliestSample.out_bytes,
          drop_bytes: earliestSample.drop_bytes,
          blocked_ips: [],
          incoming_ips: [],
          outgoing_ips: [],
        };
      }
    }

    return {
      timestamp,
      in_bytes: 0,
      out_bytes: 0,
      drop_bytes: 0,
      blocked_ips: [],
      incoming_ips: [],
      outgoing_ips: [],
    };
  });

  return {
    samples: samplesWindow,
    windowEndTimestamp,
  };
};

const formatTrafficRate = (value) => {
  const normalized = Math.max(0, Number(value) || 0);
  if (normalized >= 1024 * 1024) {
    return `${(normalized / (1024 * 1024)).toFixed(normalized >= 10 * 1024 * 1024 ? 0 : 1)} MB/s`;
  }
  if (normalized >= 1024) {
    return `${(normalized / 1024).toFixed(normalized >= 10 * 1024 ? 0 : 1)} KB/s`;
  }
  return `${Math.round(normalized)} B/s`;
};

const formatIpLabel = (ips) => {
  const normalized = (Array.isArray(ips) ? ips : [])
    .map((value) => String(value || "").trim())
    .filter(Boolean);

  if (normalized.length === 0) {
    return null;
  }

  if (normalized.length === 1) {
    return normalized[0];
  }

  return `${normalized[0]} +${normalized.length - 1} other${
    normalized.length - 1 === 1 ? "" : "s"
  }`;
};

const buildTrafficLinePath = (samples, valueKey, width, height, maxValue) => {
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

/**
 * @param {{
 *   isDark: boolean,
 *   samples: any[],
 *   isLoading: boolean,
 *   title?: string,
 *   subtitle?: string,
 *   onOpenExternal?: (() => void) | undefined,
 *   hostName?: string,
 *   serviceName?: string,
 *   externalPort?: string,
 *   mode?: string,
 *   windowSeconds?: number,
 *   showStandaloneMeta?: boolean,
 * }} props
 */
export default function TrafficMonitorPanel({
  isDark,
  samples,
  isLoading,
  title = "Traffic monitor",
  subtitle = "Live incoming and outgoing traffic for this forwarded port",
  onOpenExternal,
  hostName,
  serviceName,
  externalPort,
  mode = "compact",
  windowSeconds = 60,
  showStandaloneMeta = true,
}) {
  const chartWidth = mode === "standalone" ? 960 : 560;
  const chartHeight = mode === "standalone" ? 340 : 132;
  const [hoveredIndex, setHoveredIndex] = useState(null);
  const [showIncoming, setShowIncoming] = useState(true);
  const [showOutgoing, setShowOutgoing] = useState(true);
  const [showBlocked, setShowBlocked] = useState(true);

  const normalizedSamples = useMemo(() => normalizeTrafficSamples(samples), [samples]);
  const { samples: windowedSamples, windowEndTimestamp } = useMemo(
    () => buildTrafficWindow(samples, windowSeconds),
    [samples, windowSeconds]
  );

  const peakValue = windowedSamples.reduce((maxValue, sample) => {
    const nextValues = [];
    if (showIncoming) {
      nextValues.push(sample.in_bytes);
    }
    if (showOutgoing) {
      nextValues.push(sample.out_bytes);
    }
    if (showBlocked) {
      nextValues.push(sample.drop_bytes);
    }
    return Math.max(maxValue, ...nextValues, 0);
  }, 0);

  const chartMax = peakValue > 0 ? peakValue * 1.15 : 1;
  const incomingPath = showIncoming
    ? buildTrafficLinePath(windowedSamples, "in_bytes", chartWidth, chartHeight, chartMax)
    : "";
  const outgoingPath = showOutgoing
    ? buildTrafficLinePath(windowedSamples, "out_bytes", chartWidth, chartHeight, chartMax)
    : "";
  const blockedPath = showBlocked
    ? buildTrafficLinePath(windowedSamples, "drop_bytes", chartWidth, chartHeight, chartMax)
    : "";
  const yAxisLabels = [chartMax, chartMax / 2, 0].map((value) => formatTrafficRate(value));
  const activeIndex =
    hoveredIndex !== null
      ? Math.min(Math.max(hoveredIndex, 0), windowedSamples.length - 1)
      : null;
  const activeSample = activeIndex !== null ? windowedSamples[activeIndex] : null;
  const incomingHoverIps =
    activeSample &&
    Number(activeSample.in_bytes) > 0 &&
    Array.isArray(activeSample.incoming_ips) &&
    activeSample.incoming_ips.length > 0
      ? activeSample.incoming_ips
      : null;
  const outgoingHoverIps =
    activeSample &&
    Number(activeSample.out_bytes) > 0 &&
    Array.isArray(activeSample.outgoing_ips) &&
    activeSample.outgoing_ips.length > 0
      ? activeSample.outgoing_ips
      : null;
  const blockedHoverIps =
    activeSample &&
    Number(activeSample.drop_bytes) > 0 &&
    Array.isArray(activeSample.blocked_ips) &&
    activeSample.blocked_ips.length > 0
      ? activeSample.blocked_ips
      : null;
  const incomingHoverLabel = incomingHoverIps ? formatIpLabel(incomingHoverIps) : null;
  const outgoingHoverLabel = outgoingHoverIps ? formatIpLabel(outgoingHoverIps) : null;
  const blockedHoverLabel = blockedHoverIps ? formatIpLabel(blockedHoverIps) : null;
  const shouldShowOutgoingLabel =
    Boolean(outgoingHoverLabel) && outgoingHoverLabel !== incomingHoverLabel;
  const activeX =
    activeIndex !== null && windowedSamples.length > 1
      ? (activeIndex / (windowedSamples.length - 1)) * chartWidth
      : 0;
  const secondsSinceWindowEnd = Math.max(
    0,
    Math.floor(Date.now() / 1000) - windowEndTimestamp
  );
  const endLabel = secondsSinceWindowEnd <= 1 ? "Now" : `${secondsSinceWindowEnd}s ago`;
  const midpointSecondsAgo = secondsSinceWindowEnd + Math.floor(windowSeconds / 2);
  const startSecondsAgo = secondsSinceWindowEnd + windowSeconds;

  return (
    <div
      className={`rounded-lg border p-3 ${
        isDark ? "border-zinc-800 bg-zinc-950/70" : "border-zinc-200 bg-zinc-50/80"
      }`}
    >
      <div
        className={`mb-3 flex ${
          mode === "standalone"
            ? "items-start justify-between gap-3"
            : "items-start justify-between gap-3"
        }`}
      >
        <div className="flex min-w-0 flex-1 items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <p className={`text-sm font-semibold ${isDark ? "text-zinc-100" : "text-zinc-900"}`}>
                {title}
              </p>
              {onOpenExternal ? (
                <Tooltip
                  label="Open monitor in a separate window"
                  withArrow
                  styles={{
                    tooltip: {
                      backgroundColor: isDark ? "#09090b" : "#ffffff",
                      color: isDark ? "#f4f4f5" : "#18181b",
                      border: `1px solid ${isDark ? "#3f3f46" : "#e4e4e7"}`,
                      boxShadow: isDark
                        ? "0 8px 24px rgba(0, 0, 0, 0.45)"
                        : "0 8px 24px rgba(15, 23, 42, 0.08)",
                    },
                    arrow: {
                      backgroundColor: isDark ? "#09090b" : "#ffffff",
                      border: `1px solid ${isDark ? "#3f3f46" : "#e4e4e7"}`,
                    },
                  }}
                >
                  <ActionIcon
                    type="button"
                    size="sm"
                    variant="subtle"
                    aria-label="Open traffic monitor in a separate window"
                    onClick={onOpenExternal}
                    className={
                      isDark
                        ? "!text-zinc-400 hover:!bg-zinc-800 hover:!text-blue-200"
                        : "!text-zinc-500 hover:!bg-zinc-100 hover:!text-blue-700"
                    }
                  >
                    <IconExternalLink size={16} />
                  </ActionIcon>
                </Tooltip>
              ) : null}
            </div>
            {subtitle ? <p className="text-[11px] text-zinc-500">{subtitle}</p> : null}
          </div>

          {mode === "compact" ? (
            <div className="flex shrink-0 items-center gap-3 text-[11px] text-zinc-500">
              <span className="inline-flex items-center gap-1.5">
                <span className="h-2.5 w-2.5 rounded-full bg-emerald-400" />
                Incoming
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="h-2.5 w-2.5 rounded-full bg-sky-400" />
                Outgoing
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="h-2.5 w-2.5 rounded-full bg-rose-400" />
                Blocked
              </span>
            </div>
          ) : null}
        </div>

        {mode === "standalone" && showStandaloneMeta ? (
          <div className="flex flex-wrap items-center gap-2">
            {hostName ? (
              <Badge variant="light" color="gray">
                Host: {hostName}
              </Badge>
            ) : null}
            {serviceName ? (
              <Badge variant="light" color="blue">
                Service: {serviceName}
              </Badge>
            ) : null}
            {externalPort ? (
              <Badge variant="light" color="teal">
                External port: {externalPort}
              </Badge>
            ) : null}
          </div>
        ) : null}
      </div>

      <div className="grid grid-cols-[auto_minmax(0,1fr)] gap-2">
        <div
          className="flex flex-col justify-between pb-6 text-[10px] text-zinc-500"
          style={{ height: `${chartHeight}px` }}
        >
          {yAxisLabels.map((label) => (
            <span key={label}>{label}</span>
          ))}
        </div>

        <div>
          <div
            className="relative w-full overflow-hidden rounded-md"
            style={{ height: `${chartHeight}px` }}
          >
            {activeSample ? (
              <div
                className={`pointer-events-none absolute left-2 top-2 z-10 rounded-md border px-2 py-1 text-[11px] shadow-md backdrop-blur-sm ${
                  isDark
                    ? "border-zinc-700 bg-zinc-950 text-zinc-100"
                    : "border-zinc-200 bg-white text-zinc-900"
                }`}
              >
                <div className="text-zinc-500">
                  {Math.max(0, Math.floor(Date.now() / 1000) - activeSample.timestamp)}s ago
                </div>
                <div className="mt-0.5 flex items-center gap-3">
                  {showIncoming ? (
                    <span className="inline-flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-full bg-emerald-400" />
                      In {formatTrafficRate(activeSample.in_bytes)}
                    </span>
                  ) : null}
                  {showOutgoing ? (
                    <span className="inline-flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-full bg-sky-400" />
                      Out {formatTrafficRate(activeSample.out_bytes)}
                    </span>
                  ) : null}
                </div>
                {showIncoming && incomingHoverLabel ? (
                  <div className="mt-1 grid grid-cols-[0.5rem_minmax(0,1fr)] items-start gap-x-1.5">
                    <span className="mt-[0.28rem] h-2 w-2 rounded-full bg-emerald-400" />
                    <span className="break-all leading-4">
                      From {incomingHoverLabel}
                    </span>
                  </div>
                ) : null}
                {showOutgoing && shouldShowOutgoingLabel ? (
                  <div className="mt-1 grid grid-cols-[0.5rem_minmax(0,1fr)] items-start gap-x-1.5">
                    <span className="mt-[0.28rem] h-2 w-2 rounded-full bg-sky-400" />
                    <span className="break-all leading-4">
                      To {outgoingHoverLabel}
                    </span>
                  </div>
                ) : null}
                {showBlocked && blockedHoverLabel ? (
                  <div className="mt-1 grid grid-cols-[0.5rem_minmax(0,1fr)] items-start gap-x-1.5">
                    <span className="mt-[0.28rem] h-2 w-2 rounded-full bg-rose-400" />
                    <span className="break-all leading-4">
                      Blocked {blockedHoverLabel}
                    </span>
                  </div>
                ) : null}
              </div>
            ) : null}
            <svg
              viewBox={`0 0 ${chartWidth} ${chartHeight}`}
              preserveAspectRatio="none"
              className="h-full w-full"
              onMouseLeave={() => setHoveredIndex(null)}
              onMouseMove={(event) => {
                const bounds = event.currentTarget.getBoundingClientRect();
                if (!bounds.width || windowedSamples.length <= 1) {
                  return;
                }
                const x = Math.min(Math.max(event.clientX - bounds.left, 0), bounds.width);
                const nextIndex = Math.round((x / bounds.width) * (windowedSamples.length - 1));
                setHoveredIndex(nextIndex);
              }}
            >
              {[0, 0.5, 1].map((ratio) => (
                <line
                  key={ratio}
                  x1="0"
                  x2={chartWidth}
                  y1={chartHeight * ratio}
                  y2={chartHeight * ratio}
                  stroke={isDark ? "rgba(63,63,70,0.65)" : "rgba(228,228,231,1)"}
                  strokeDasharray="4 4"
                  strokeWidth="1"
                />
              ))}
              {incomingPath ? (
                <path
                  d={incomingPath}
                  fill="none"
                  stroke="rgb(52, 211, 153)"
                  strokeWidth={mode === "standalone" ? "2.75" : "2.5"}
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              ) : null}
              {outgoingPath ? (
                <path
                  d={outgoingPath}
                  fill="none"
                  stroke="rgb(56, 189, 248)"
                  strokeWidth={mode === "standalone" ? "2.75" : "2.5"}
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              ) : null}
              {blockedPath ? (
                <path
                  d={blockedPath}
                  fill="none"
                  stroke="rgb(251, 113, 133)"
                  strokeWidth={mode === "standalone" ? "2.75" : "2.5"}
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              ) : null}
              {activeSample ? (
                <>
                  <line
                    x1={activeX}
                    x2={activeX}
                    y1="0"
                    y2={chartHeight}
                    stroke={isDark ? "rgba(244,244,245,0.22)" : "rgba(24,24,27,0.15)"}
                    strokeDasharray="4 4"
                    strokeWidth="1"
                  />
                  {showIncoming ? (
                    <circle
                      cx={activeX}
                      cy={chartHeight - (activeSample.in_bytes / chartMax) * chartHeight}
                      r={mode === "standalone" ? "4" : "3.5"}
                      fill="rgb(52, 211, 153)"
                    />
                  ) : null}
                  {showOutgoing ? (
                    <circle
                      cx={activeX}
                      cy={chartHeight - (activeSample.out_bytes / chartMax) * chartHeight}
                      r={mode === "standalone" ? "4" : "3.5"}
                      fill="rgb(56, 189, 248)"
                    />
                  ) : null}
                  {showBlocked ? (
                    <circle
                      cx={activeX}
                      cy={chartHeight - (activeSample.drop_bytes / chartMax) * chartHeight}
                      r={mode === "standalone" ? "4" : "3.5"}
                      fill="rgb(251, 113, 133)"
                    />
                  ) : null}
                </>
              ) : null}
            </svg>

            {isLoading && !normalizedSamples.length ? (
              <div className="absolute inset-0 flex items-center justify-center text-xs text-zinc-500">
                Loading live traffic...
              </div>
            ) : null}
          </div>

          <div className="mt-2 flex items-center justify-between text-[10px] text-zinc-500">
            <span>{startSecondsAgo}s ago</span>
            <span>{midpointSecondsAgo}s ago</span>
            <span>{endLabel}</span>
          </div>

          {mode === "standalone" ? (
            <div className="mt-3 flex flex-wrap items-center justify-center gap-x-5 gap-y-2 text-[11px]">
              <button
                type="button"
                onClick={() => setShowIncoming((current) => !current)}
                className={`inline-flex items-center gap-2 transition ${
                  showIncoming
                    ? isDark
                      ? "text-zinc-100"
                      : "text-zinc-900"
                    : isDark
                      ? "text-zinc-500"
                      : "text-zinc-500"
                }`}
              >
                <span className="h-2.5 w-2.5 rounded-full bg-emerald-400" />
                Incoming
              </button>
              <button
                type="button"
                onClick={() => setShowOutgoing((current) => !current)}
                className={`inline-flex items-center gap-2 transition ${
                  showOutgoing
                    ? isDark
                      ? "text-zinc-100"
                      : "text-zinc-900"
                    : isDark
                      ? "text-zinc-500"
                      : "text-zinc-500"
                }`}
              >
                <span className="h-2.5 w-2.5 rounded-full bg-sky-400" />
                Outgoing
              </button>
              <button
                type="button"
                onClick={() => setShowBlocked((current) => !current)}
                className={`inline-flex items-center gap-2 transition ${
                  showBlocked
                    ? isDark
                      ? "text-zinc-100"
                      : "text-zinc-900"
                    : isDark
                      ? "text-zinc-500"
                      : "text-zinc-500"
                }`}
              >
                <span className="h-2.5 w-2.5 rounded-full bg-rose-400" />
                Blocked
              </button>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
