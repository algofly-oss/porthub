import { useMemo } from "react";
import { buildTrafficWindow, trafficLinePath, trafficSummary, formatBytes } from "@/shared/utils/traffic.mjs";

export default function TrafficSparkline({ samples = [], now, showRates = true, dense = false, className = "", label = "Traffic" }) {
  const windowed = useMemo(() => buildTrafficWindow(samples, 30, now).samples, [samples, now]);
  const summary = trafficSummary(samples, 30, now);
  const peak = Math.max(1, ...windowed.flatMap(sample => [sample.in_rate, sample.out_rate, sample.drop_rate])) * 1.12;
  const series = [["in_rate", "stroke-emerald-600 dark:stroke-emerald-400"], ["out_rate", "stroke-blue-600 dark:stroke-blue-400"], ["drop_rate", "stroke-rose-500"]];
  return <div className={`min-w-0 ${className}`} aria-label={`${label}: incoming ${formatBytes(summary.incoming)}/s, outgoing ${formatBytes(summary.outgoing)}/s`}>
    <svg aria-hidden="true" viewBox="0 0 120 26" preserveAspectRatio="none" className={`${dense ? "h-[18px]" : "h-6"} w-full`}>
      <line x1="0" y1="25" x2="120" y2="25" className="stroke-border" strokeWidth="1" />
      {series.map(([key, color]) => <path key={key} d={trafficLinePath(windowed, key, 120, 24, peak)} fill="none" className={color} strokeWidth="1.5" vectorEffect="non-scaling-stroke" strokeLinecap="round" strokeLinejoin="round" />)}
    </svg>
    {showRates && <div className="mt-1 flex items-center justify-between gap-2 whitespace-nowrap text-[11px] tabular-nums"><span className="text-emerald-700 dark:text-emerald-400" title="Incoming">↓ {formatBytes(summary.incoming)}/s</span><span className="text-blue-700 dark:text-blue-400" title="Outgoing">↑ {formatBytes(summary.outgoing)}/s</span></div>}
  </div>;
}
