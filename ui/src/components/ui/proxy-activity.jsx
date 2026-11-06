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
  const monthly = Number(metric?.monthly_visits || 0), lifetime = Number(metric?.visits || 0);
  const minutes = Math.round(Number(activity.visit_window_seconds || 1800)/60);
  const title = `${activity.visits_tracking_since ? `${monthly.toLocaleString()} estimated visits this calendar month (UTC); ${lifetime.toLocaleString()} total visits since ${new Date(activity.visits_tracking_since).toLocaleString()}. A new visit starts after ${minutes} minutes without activity from the same client IP and browser. Shared network/browser combinations may be grouped; bots are included. ` : "Visit tracking is starting; past request totals cannot be converted into visitors. "}${Number(metric?.monthly_requests || 0).toLocaleString()} raw requests this month; ${Number(metric?.requests || 0).toLocaleString()} lifetime requests. ${metric?.last_requested_at ? `Last requested ${new Date(metric.last_requested_at).toLocaleString()}. ` : ""}${activity.coverage_warning ? " Counts may be incomplete during tracking interruptions." : ""}`;
  return <div title={title} className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
    {group && <><span>{group}</span><span aria-hidden="true">·</span></>}
    {activity.error ? <span>Usage unavailable</span> : !activity.available ? <span>{activity.loading ? "Loading usage…" : "Tracking unavailable"}</span> : !activity.visits_tracking_since ? <span>Visit tracking starting</span> : <>
      <span className="whitespace-nowrap tabular-nums" aria-label={compact ? `${compactRequests(monthly)} visits this month` : undefined}>{compactRequests(monthly)}{compact ? "/mo" : " visits this month"}</span><span aria-hidden="true">·</span><span className="whitespace-nowrap tabular-nums">{compactRequests(lifetime)}{compact ? " visits" : " total visits"}</span>{!compact && <><span aria-hidden="true">·</span><span className="whitespace-nowrap">{metric?.last_requested_at ? activityAge(metric.last_requested_at) : "Not requested yet"}</span></>}
    </>}
  </div>;
}
