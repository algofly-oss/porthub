export function activityAge(value) {
  const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(value))/1000));
  if (!Number.isFinite(seconds)) return "Not requested yet";
  if (seconds < 60) return "Just now";
  if (seconds < 3600) return `${Math.floor(seconds/60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds/3600)}h ago`;
  return `${Math.floor(seconds/86400)}d ago`;
}

export default function ProxyActivity({metric,activity,group}) {
  const title = activity.tracking_since ? `HTTP requests observed since ${new Date(activity.tracking_since).toLocaleString()}. Includes bots and repeat requests; not unique visitors.${activity.coverage_warning ? " Some requests during a logging interruption may not be counted." : ""}` : "Request tracking is starting";
  return <div title={title} className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
    {group && <><span>{group}</span><span aria-hidden="true">·</span></>}
    {activity.coverage_warning && <span className="text-amber-700 dark:text-amber-400">Partial history</span>}
    {activity.error ? <span>Usage unavailable</span> : !activity.available ? <span>{activity.loading ? "Loading usage…" : "Tracking unavailable"}</span> : <>
      <span>{Number(metric?.requests||0).toLocaleString()} requests</span><span aria-hidden="true">·</span><span>{metric?.last_requested_at ? activityAge(metric.last_requested_at) : "Not requested yet"}</span>
    </>}
  </div>;
}
