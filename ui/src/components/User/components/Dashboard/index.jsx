import useInventoryPage from "@/shared/hooks/useInventoryPage";
import useTrafficPage from "@/shared/hooks/useTrafficPage";
import { externalEndpoint, internalEndpoint } from "@/shared/utils/endpoints.mjs";
import { useWorkspaceState } from "@/shared/contexts/workspaceCache";
import { useMemo, useState } from "react";
import { useRouter } from "next/router";
import { IconArrowUpRight, IconCheck, IconRefresh, IconServer, IconWorld, IconAlertCircle, IconPlus } from "@tabler/icons-react";
import { useMantineColorScheme } from "@mantine/core";
import { trafficSummary, formatBytes } from "@/shared/utils/traffic.mjs";
import TrafficMonitorPanel from "../Home/components/Host/TrafficMonitorPanel";
import TrafficSparkline from "@/components/ui/traffic-sparkline";
import { Button } from "@/components/ui/button";
import { PageHeader, EmptyState } from "@/components/ui/workspace";
import useProxyActivity from "@/shared/hooks/useProxyActivity";
import ProxyActivity from "@/components/ui/proxy-activity";

// Placeholder cards shaped like the dashboard so the layout does not jump.
function DashboardSkeleton() {
  const bar = "animate-pulse rounded bg-muted dark:bg-control";
  const card = (rows, tall) => <section className="flex min-w-0 flex-col gap-3 rounded-xl bg-surface p-5">
    <div className={`${bar} h-4 w-40`} /><div className={`${bar} h-3 w-56 max-w-full opacity-70`} />
    {tall ? <div className={`${bar} mt-2 h-[180px] w-full opacity-60`} /> : Array.from({ length: rows }, (_, i) => <div key={i} className="flex items-center gap-3 pt-2"><div className="min-w-0 flex-1 space-y-2"><div className={`${bar} h-3 w-3/5`} /><div className={`${bar} h-3 w-2/5 opacity-70`} /></div><div className={`${bar} h-6 w-20 opacity-60`} /></div>)}
  </section>;
  return <div role="status" aria-label="Loading your workspace" className="space-y-4 pb-1">
    <span className="sr-only">Loading your workspace…</span>
    <div className="grid items-stretch gap-4 lg:grid-cols-[minmax(0,1.8fr)_minmax(290px,1fr)]">{card(0, true)}{card(3)}</div>
    <div className="grid items-stretch gap-4 lg:grid-cols-[minmax(0,1.8fr)_minmax(290px,1fr)]">{card(4)}{card(4)}</div>
  </div>;
}

export default function Dashboard({ active = true }) {
  const router = useRouter();
  const { colorScheme } = useMantineColorScheme();
  const [counts] = useWorkspaceState("inventory.summary", null);
  const [seconds, setSeconds] = useState(300);
  const [refresh, setRefresh] = useState(0);
  const rangeLabel = seconds === 3600 ? "hour" : `${seconds / 60} minutes`;
  const traffic = useTrafficPage({sort:"traffic",page_size:5,seconds}, {enabled:active,refresh});
  const activity = useProxyActivity({ recent: 5, enabled: active });
  const data = { proxies: activity.routes };
  const loading = !counts || activity.loading;
  const error = activity.error;
  const activityById = useMemo(()=>new Map(activity.data.map(metric=>[metric.route_id,metric])),[activity.data]);
  const summaryResource = useInventoryPage("summary", {}, {enabled:active,ttl:15000});
  const load = () => { summaryResource.resource.invalidate("proxy-activity"); summaryResource.refresh(); setRefresh(value => value + 1); };
  const navigate = (view, query = {}) => router.push({ pathname: "/home", query: { ...(router.query.demo ? { demo: router.query.demo } : {}), view, ...query } }, undefined, { shallow: true });
  const online = counts?.machines?.online || 0;
  const attention = (counts?.machines?.offline || 0) + (counts?.machines?.auth_required || 0);
  const disabled = counts?.machines?.disabled || 0;
  const machineTotal = counts?.machines?.total || 0;
  const samples = traffic.aggregate;
  const trafficById = useMemo(() => new Map(traffic.rows.map(row => [row.connection?._id, row.traffic])), [traffic.rows]);
  const summary = trafficSummary(samples, Number(seconds), (traffic.updated || Date.now()) / 1000);
  const busiest = useMemo(() => traffic.rows.map(row => ({ ...row, summary: trafficSummary(row.traffic, Number(seconds), (traffic.updated || Date.now()) / 1000) })).sort((a,b) => b.summary.volume - a.summary.volume).slice(0, 5), [traffic.rows, seconds, traffic.updated]);
  const peak = Math.max(1, ...busiest.map(row => row.summary.volume));
  const ratio = machineTotal ? online / machineTotal : 0;
  const recentlyVisited = useMemo(() => data.proxies.filter(proxy=>activityById.get(proxy._id)?.last_requested_at).sort((a,b) => Date.parse(activityById.get(b._id).last_requested_at)-Date.parse(activityById.get(a._id).last_requested_at)).slice(0,5),[data.proxies,activityById]);
  return <div className="h-full min-h-0 overflow-y-auto overscroll-contain" aria-label="Dashboard content"><div className="workspace-page mx-auto max-w-[1600px] !h-auto !min-h-full !overflow-visible">
    <PageHeader title="Dashboard" actions={<div className="flex items-center gap-2"><span className="hidden items-center gap-1.5 text-xs text-muted-foreground sm:flex"><span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />{traffic.error ? "Traffic unavailable" : traffic.updated ? "Live workspace" : "Connecting…"}</span><Button variant="ghost" size="icon" aria-label="Refresh dashboard" onClick={()=>load()}><IconRefresh size={17} /></Button></div>} />
    {error && <p role="alert" className="mb-3 rounded-lg bg-amber-500/10 p-3 text-sm text-amber-700 dark:text-amber-300">{error}</p>}
    {loading ? <DashboardSkeleton /> : !machineTotal && !counts?.proxies ? <EmptyState icon={IconServer} title="Your workspace starts here" description="Enroll a machine to expose its ports, or create a standalone web proxy." action={<div className="flex flex-wrap justify-center gap-2"><Button onClick={()=>navigate("machines", {create:"1"})}><IconPlus size={16} />Enroll a Machine</Button><Button variant="secondary" onClick={()=>navigate("proxies", {create:"1"})}>Create a Proxy</Button></div>} /> : <div className="space-y-4 pb-1">
      <div aria-label="Workspace overview" className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <OverviewCard label="Registered machines" value={machineTotal} detail={`${online} online · ${disabled} disabled`} onClick={()=>navigate("machines")} />
        <OverviewCard label="Needs attention" value={attention} detail={attention ? "Review connectivity and authentication" : "All enabled clients connected"} onClick={()=>navigate("machines",{status:"offline"})} tone={attention ? "text-amber-600 dark:text-amber-400" : "text-emerald-600 dark:text-emerald-400"} />
        <OverviewCard label="Web proxies" value={counts?.proxies ?? 0} detail="Manage addresses and fallback routes" onClick={()=>navigate("proxies")} />
        <OverviewCard label="Public port transfer" value={traffic.updated ? formatBytes(summary.volume) : "—"} detail={`Last ${rangeLabel} · gateway only`} onClick={()=>navigate("traffic")} />
      </div>
      <div className="grid items-stretch gap-4 lg:grid-cols-[minmax(0,1.8fr)_minmax(290px,1fr)]">
        <section className="flex min-w-0 flex-col overflow-hidden rounded-xl bg-surface">
          <div className="flex flex-wrap items-start justify-between gap-3 px-5 pt-5"><div><h2 className="text-base font-semibold">Public port traffic</h2><p className="mt-1 text-xs text-muted-foreground">Gateway public ports · bytes per second</p></div><div role="group" aria-label="Traffic time range" className="flex gap-1 rounded-lg bg-muted/60 p-1">{[[300,"5m"],[900,"15m"],[3600,"1h"]].map(([value,label])=><button key={value} type="button" aria-pressed={seconds===value} onClick={()=>setSeconds(value)} className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary ${seconds===value ? "bg-surface text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"}`}>{label}</button>)}</div></div>
          <div className="grid grid-cols-3 gap-3 px-5 py-4"><Metric label="Incoming Speed" value={formatBytes(summary.incoming)} suffix="/s" color="text-emerald-700 dark:text-emerald-400" /><Metric label="Outgoing Speed" value={formatBytes(summary.outgoing)} suffix="/s" color="text-blue-600 dark:text-blue-400" /><Metric label="Transferred" value={formatBytes(summary.volume)} /></div>
          <TrafficMonitorPanel isDark={colorScheme === "dark"} samples={samples} isLoading={traffic.loading} title="Public port traffic" showTitle={false} plotHeight={160} className="!px-5 !pt-0" windowSeconds={Number(seconds)} />
          {traffic.error && <p role="status" className="px-5 pb-3 text-xs text-amber-600">{traffic.error}</p>}
          <button onClick={()=>navigate("traffic")} className="mt-auto flex w-full items-center justify-between border-t border-border px-5 py-3 text-xs text-muted-foreground hover:bg-muted hover:text-foreground">Inspect ports and source addresses<IconArrowUpRight size={15} /></button>
        </section>
        <section className="flex min-w-0 flex-col rounded-xl bg-surface p-5">
          <div className="flex items-center justify-between gap-2"><h2 className="text-base font-semibold">Fleet Health</h2><IconServer size={18} className="text-muted-foreground" /></div>
          <div className="my-5 grid grid-cols-[100px_minmax(0,1fr)] items-center gap-4"><div className="relative h-[100px] w-[100px]"><svg aria-hidden="true" viewBox="0 0 120 120" className="h-full w-full -rotate-90"><circle cx="60" cy="60" r="50" fill="none" className="stroke-muted" strokeWidth="9" /><circle cx="60" cy="60" r="50" fill="none" className="stroke-emerald-500" strokeWidth="9" strokeDasharray={`${ratio * 314.16} 314.16`} strokeLinecap="round" /></svg><div className="absolute inset-0 flex flex-col items-center justify-center"><p className="text-2xl font-semibold tabular-nums">{Math.round(ratio*100)}<span className="text-sm text-muted-foreground">%</span></p><p className="mt-1 text-[11px] text-muted-foreground">online</p></div></div><div className="space-y-1">{[["online","Online",online,"bg-emerald-500"],["offline","Attention",attention,"bg-amber-500"],["disabled","Disabled",disabled,"bg-zinc-500"]].map(([filter,label,count,color])=><button key={filter} onClick={()=>navigate("machines",{status:filter})} className="flex w-full items-center gap-2 rounded-md px-2 py-2 text-sm hover:bg-muted"><span className={`h-1.5 w-1.5 rounded-full ${color}`} /><span>{label}</span><span className="ml-auto font-medium tabular-nums">{count}</span><IconArrowUpRight size={13} className="text-muted-foreground" /></button>)}</div></div>
          {attention ? <button onClick={()=>navigate("machines",{status:"offline"})} className="mb-4 flex items-start gap-2.5 rounded-lg bg-amber-500/5 p-3 text-left hover:bg-amber-500/10"><IconAlertCircle size={18} className="mt-0.5 shrink-0 text-amber-700 dark:text-amber-400" /><span><span className="block text-sm font-medium">{attention} {attention===1 ? "machine needs" : "machines need"} attention</span><span className="mt-1 block text-xs leading-5 text-muted-foreground">Review offline clients and authentication issues.</span></span></button> : <div className="mb-4 flex items-start gap-2 rounded-lg bg-emerald-500/5 p-3"><IconCheck size={18} className="shrink-0 text-emerald-600" /><p className="text-sm">All enabled machines are connected.</p></div>}
          <div className="mt-auto"><Button variant="secondary" className="w-full" onClick={()=>navigate("machines",{create:"1"})}><IconPlus size={16} />Enroll a Machine</Button></div>
        </section>
      </div>
      <div className="grid items-stretch gap-4 lg:grid-cols-[minmax(0,1.8fr)_minmax(290px,1fr)]">
        <section className="min-w-0 overflow-hidden rounded-xl bg-surface"><PanelHeading title="Busiest Ports" description={`Transferred in the last ${rangeLabel}`} onClick={()=>navigate("traffic")} />
          <div className="grid grid-cols-[minmax(0,1fr)_100px_80px] gap-3 bg-muted/40 px-5 py-2 text-[11px] text-muted-foreground"><span>Service / machine</span><span>Activity</span><span className="text-right">Transferred</span></div>
          <div>{busiest.length ? busiest.map(row=><button key={row.connection._id} onClick={()=>navigate("machines",{machine:row.connection.machine_id})} className="grid w-full grid-cols-[minmax(0,1fr)_100px_80px] items-center gap-3 px-5 py-3 text-left hover:bg-muted/50"><div className="min-w-0"><p className="truncate text-sm font-medium">{row.connection.service_name || `Port ${row.connection.external_port}`}</p><p className="mt-1 truncate text-xs text-muted-foreground">{row.connection.machine_name} · {externalEndpoint(row.connection)} → {internalEndpoint(row.connection)}</p></div><div><TrafficSparkline samples={row.traffic} showRates={true} label={row.connection.service_name} /><div className="mt-1 h-0.5 rounded-full bg-muted"><div className="h-full rounded-full bg-primary/50" style={{width:`${row.summary.volume / peak * 100}%`}} /></div></div><p className="text-right text-xs font-medium tabular-nums">{formatBytes(row.summary.volume)}</p></button>) : <p className="p-5 text-sm text-muted-foreground">Traffic appears when a forwarded port is used.</p>}</div>
        </section>
        <section aria-label="Recent Web Addresses" className="flex min-w-0 flex-col overflow-hidden rounded-xl bg-surface">
          <PanelHeading title="Web Addresses" description="Most recently requested services" onClick={()=>navigate("proxies")} />
          <div>{recentlyVisited.map(proxy=><a key={proxy._id} href={`${proxy.entry_points?.includes("websecure")?"https":"http"}://${proxy.hosts?.includes(activityById.get(proxy._id)?.last_host)?activityById.get(proxy._id).last_host:proxy.hosts?.[0]}`} target="_blank" rel="noreferrer" className="flex w-full min-w-0 items-center gap-2 px-3 py-3 text-left hover:bg-accent/40 sm:gap-3 sm:px-5">
            <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-muted"><IconWorld size={19} className="text-muted-foreground" /></span>
            <div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{activityById.get(proxy._id)?.last_host || proxy.hosts?.[0] || proxy.name}</p><ProxyActivity compact metric={activityById.get(proxy._id)} activity={activity} /></div>
            <div className="w-12 shrink-0 sm:w-24" title={proxy.connection ? "Linked port traffic · may include other services on this port" : "Bandwidth is not measured for standalone targets"}>
              {trafficById.has(proxy.connection?.data_id || proxy.connection?._id) ? <TrafficSparkline samples={trafficById.get(proxy.connection.data_id || proxy.connection._id)} now={(traffic.updated || Date.now()) / 1000} dense showRates={false} label="Linked port traffic" /> : <span className="block text-center text-[11px] leading-4 text-muted-foreground">Traffic unavailable</span>}
            </div>
            <IconArrowUpRight size={14} className="hidden shrink-0 text-muted-foreground sm:block" />
          </a>)}</div>
          {recentlyVisited.length ? <button type="button" onClick={()=>navigate("proxies")} className="mt-auto flex w-full items-center justify-between border-t border-border px-5 py-3 text-left text-xs font-medium text-muted-foreground hover:bg-accent/40 hover:text-foreground">View All Proxies<IconArrowUpRight size={15} /></button> : <p className="p-5 text-sm text-muted-foreground">{activity.error ? "Request activity is temporarily unavailable." : activity.available ? "No proxy requests recorded yet. Counts start when tracking is enabled." : "Request tracking is starting. Recent addresses will appear here."}</p>}
        </section>
      </div>
    </div>}
  </div></div>;
}

function Metric({label,value,suffix,color=""}) {
  return <div className="min-w-0"><p className="truncate text-xs text-muted-foreground">{label}</p><p className={`mt-1 whitespace-nowrap text-lg font-semibold tabular-nums ${color}`}>{value}{suffix && <span className="ml-1 text-xs font-normal text-muted-foreground">{suffix}</span>}</p></div>;
}

function PanelHeading({ title, description, onClick }) {
  return <div className="flex items-start justify-between gap-3 px-5 pb-3 pt-5"><div><h2 className="text-base font-semibold">{title}</h2><p className="mt-1 text-xs leading-5 text-muted-foreground">{description}</p></div><Button variant="ghost" size="icon" aria-label={`Open ${title}`} onClick={onClick}><IconArrowUpRight size={18} /></Button></div>;
}

function OverviewCard({ label, value, detail, onClick, tone = "" }) {
  return <button type="button" onClick={onClick} className="group flex min-w-0 flex-col rounded-xl bg-surface p-4 text-left transition-colors hover:bg-accent/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary sm:p-5">
    <span className="flex w-full items-start justify-between gap-2 text-xs text-muted-foreground"><span>{label}</span><IconArrowUpRight aria-hidden="true" size={14} className="shrink-0 opacity-50 group-hover:opacity-100" /></span>
    <span className={`my-2 text-2xl font-semibold tracking-tight tabular-nums ${tone}`}>{value}</span>
    <span className="text-xs leading-5 text-muted-foreground">{detail}</span>
  </button>;
}
