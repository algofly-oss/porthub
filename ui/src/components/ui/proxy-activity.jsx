export function activityAge(value) {
  const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(value))/1000));
  if (!Number.isFinite(seconds)) return "Not requested yet";
  if (seconds < 60) return "Just now";
  if (seconds < 3600) return `${Math.floor(seconds/60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds/3600)}h ago`;
  return `${Math.floor(seconds/86400)}d ago`;
}

export function compactRequests(value) {
  return new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(Math.max(0, Number(value) || 0));
}

export default function ProxyActivity({metric,activity,group,compact=false}) {
  const monthly = Number(metric?.monthly_requests || 0), lifetime = Number(metric?.requests || 0);
  const title = activity.tracking_since ? `${monthly.toLocaleString()} requests this calendar month (UTC); ${lifetime.toLocaleString()} lifetime requests observed since ${new Date(activity.tracking_since).toLocaleString()}. Monthly tracking available since ${new Date(activity.monthly_tracking_since || activity.tracking_since).toLocaleString()}. ${metric?.last_requested_at ? `Last requested ${new Date(metric.last_requested_at).toLocaleString()}. ` : ""}Includes bots and repeat requests; not unique visitors.${activity.coverage_warning ? " Some requests during a logging interruption may not be counted." : ""}` : "Request tracking is starting";
  return <div title={title} className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
    {group && <><span>{group}</span><span aria-hidden="true">·</span></>}
    {activity.error ? <span>Usage unavailable</span> : !activity.available ? <span>{activity.loading ? "Loading usage…" : "Tracking unavailable"}</span> : <>
      <span className="whitespace-nowrap tabular-nums" aria-label={compact ? `${compactRequests(monthly)} this month` : undefined}>{compactRequests(monthly)}{compact ? "/mo" : " this month"}</span><span aria-hidden="true">·</span><span className="whitespace-nowrap tabular-nums">{compactRequests(lifetime)} lifetime</span>{!compact && <><span aria-hidden="true">·</span><span className="whitespace-nowrap">{metric?.last_requested_at ? activityAge(metric.last_requested_at) : "Not requested yet"}</span></>}
    </>}
  </div>;
}
