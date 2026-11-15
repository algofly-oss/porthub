export default function RecentSourceIPs({ hits = [], status = {}, isDark, onRetry }) {
  const rows = hits.filter(item => typeof item?.ip === "string" && item.ip.trim());
  return <section aria-label="Recent source IPs" className={`min-w-0 overflow-hidden rounded-xl border ${isDark ? "border-white/10 bg-white/[0.02] text-slate-200" : "border-slate-200 bg-white text-slate-700"}`}>
    <div className="flex items-center justify-between gap-3 px-3 py-2">
      <div className="min-w-0"><h3 className="text-sm font-semibold">Recent source IPs</h3><p className={`mt-0.5 text-xs ${isDark ? "text-slate-400" : "text-slate-500"}`}>Observed IPv4 connection attempts</p></div>
      {status.error && <button type="button" onClick={onRetry} disabled={status.loading} className="min-h-[44px] shrink-0 rounded-lg px-3 text-xs font-medium hover:bg-slate-500/10 focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-500">Retry</button>}
    </div>
    {status.error && <p role="status" className="px-3 pb-2 text-xs text-amber-500">{status.received ? "Couldn’t refresh. Showing previous observations." : "Couldn’t load recent observations."}</p>}
    {rows.length > 0 ? <div className="max-h-44 overflow-y-auto"><table className="w-full table-fixed text-xs" aria-label="Observed source addresses"><thead className={isDark ? "text-slate-400" : "text-slate-500"}><tr><th className="px-3 pb-2 text-left font-normal">Source IP</th><th className="px-3 pb-2 text-right font-normal">Last observed</th></tr></thead><tbody>{rows.map((item, index) => {
      const seconds = Number(item.last_seen);
      const valid = typeof item.last_seen === "number" && Number.isFinite(seconds) && seconds > 0 && seconds < 8640000000000;
      const date = valid ? new Date(seconds * 1000) : null;
      return <tr key={`${item.ip}-${index}`} className={isDark ? "border-t border-white/5" : "border-t border-slate-100"}><td className="break-all px-3 py-2 font-mono">{item.ip}</td><td className="px-3 py-2 text-right tabular-nums">{date ? <time dateTime={date.toISOString()} title={date.toLocaleString()}>{date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}<span className={`ml-1.5 ${isDark ? "text-slate-400" : "text-slate-500"}`}>{date.toLocaleDateString([], { month: "short", day: "numeric" })}</span></time> : "Time unavailable"}</td></tr>;
    })}</tbody></table></div> : <p role="status" className={`px-3 pb-3 text-xs ${isDark ? "text-slate-400" : "text-slate-500"}`}>{status.loading || (!status.received && !status.error) ? "Loading recent observations…" : status.received && !status.error ? "No recent connection attempts observed." : "Observations unavailable."}</p>}
  </section>;
}
