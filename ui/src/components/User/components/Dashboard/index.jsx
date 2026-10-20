import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/router";
import axios from "axios";
import { IconArrowUpRight, IconCheck, IconRefresh, IconServer, IconWorld, IconAlertCircle, IconPlus } from "@tabler/icons-react";
import { useMantineColorScheme } from "@mantine/core";
import apiRoutes from "@/shared/routes/apiRoutes";
import useTrafficSnapshot from "@/shared/hooks/useTrafficSnapshot";
import { aggregateTraffic, trafficSummary, formatBytes } from "@/shared/utils/traffic.mjs";
import TrafficMonitorPanel from "../Home/components/Host/TrafficMonitorPanel";
import TrafficSparkline from "@/components/ui/traffic-sparkline";
import { Button } from "@/components/ui/button";
import { PageHeader, EmptyState } from "@/components/ui/workspace";
import useProxyActivity from "@/shared/hooks/useProxyActivity";
import ProxyActivity from "@/components/ui/proxy-activity";

export default function Dashboard() {
  const router = useRouter();
  const { colorScheme } = useMantineColorScheme();
  const [data, setData] = useState({ machines: [], proxies: [], ports: [] });
  const [loading, setLoading] = useState(true), [error, setError] = useState("");
  const seconds = 300;
  const traffic = useTrafficSnapshot();
  const activity = useProxyActivity();
  const activityById = useMemo(()=>new Map(activity.data.map(metric=>[metric.route_id,metric])),[activity.data]);
  async function load(signal) {
    try {
      const responses = await Promise.all([apiRoutes.listMachines, apiRoutes.listTrafficRoutes, apiRoutes.listConnections].map(url => axios.get(url, { signal })));
      setData({ machines: responses[0].data?.data || [], proxies: responses[1].data?.data || [], ports: responses[2].data?.data || [] });
      setError("");
    } catch (error) { if (!axios.isCancel(error)) setError("Could not refresh the workspace. Try again."); }
    finally { if (!signal?.aborted) setLoading(false); }
  }
  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    const timer = setInterval(() => { if (!document.hidden) load(controller.signal); }, 15000);
    return () => { controller.abort(); clearInterval(timer); };
  }, []);
  const navigate = (view, query = {}) => router.push({ pathname: "/home", query: { ...(router.query.demo ? { demo: router.query.demo } : {}), view, ...query } }, undefined, { shallow: true });
  const status = machine => machine.connection_status || (machine.enabled === false ? "disabled" : machine.is_active ? "online" : "offline");
  const online = data.machines.filter(machine => status(machine) === "online");
  const attention = data.machines.filter(machine => status(machine) === "offline" || status(machine) === "auth_required");
  const disabled = data.machines.filter(machine => status(machine) === "disabled");
  const samples = useMemo(() => aggregateTraffic(traffic.rows), [traffic.rows]);
  const summary = trafficSummary(samples, Number(seconds), (traffic.updated || Date.now()) / 1000);
  const busiest = useMemo(() => traffic.rows.map(row => ({ ...row, summary: trafficSummary(row.traffic, Number(seconds), (traffic.updated || Date.now()) / 1000) })).sort((a,b) => b.summary.volume - a.summary.volume).slice(0, 5), [traffic.rows, seconds, traffic.updated]);
  const peak = Math.max(1, ...busiest.map(row => row.summary.volume));
  const ratio = data.machines.length ? online.length / data.machines.length : 0;
  const recentlyVisited = useMemo(() => data.proxies.filter(proxy=>activityById.get(proxy._id)?.last_requested_at).sort((a,b) => Date.parse(activityById.get(b._id).last_requested_at)-Date.parse(activityById.get(a._id).last_requested_at)).slice(0,5),[data.proxies,activityById]);
  return <div className="workspace-page"><div className="data-scroll pb-1" aria-label="Dashboard content">
    <PageHeader title="Dashboard" actions={<div className="flex items-center gap-2"><span className="hidden items-center gap-1.5 text-xs text-muted-foreground sm:flex"><span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />Live workspace</span><Button variant="ghost" size="icon" aria-label="Refresh dashboard" onClick={()=>load()}><IconRefresh size={17} /></Button></div>} />
    {error && <p role="alert" className="mb-3 rounded-lg bg-amber-500/10 p-3 text-sm text-amber-700 dark:text-amber-300">{error}</p>}
    {loading ? <p role="status" className="p-6 text-sm text-muted-foreground">Loading your workspace…</p> : !data.machines.length && !data.proxies.length ? <EmptyState icon={IconServer} title="Your workspace starts here" description="Enroll a machine to expose its ports, or create a standalone web proxy." action={<div className="flex flex-wrap justify-center gap-2"><Button onClick={()=>navigate("machines", {create:"1"})}><IconPlus size={16} />Enroll a Machine</Button><Button variant="secondary" onClick={()=>navigate("proxies", {create:"1"})}>Create a Proxy</Button></div>} /> : <div className="space-y-4 pb-1">
      <div className="grid items-stretch gap-4 lg:grid-cols-[minmax(0,1.8fr)_minmax(290px,1fr)]">
        <section className="flex min-w-0 flex-col overflow-hidden rounded-xl bg-surface">
          <div className="px-5 pt-5"><h2 className="text-base font-semibold">Network Activity</h2><p className="mt-1 text-xs text-muted-foreground">Last 5 minutes · all forwarded ports · bytes per second</p></div>
          <div className="grid grid-cols-3 gap-3 px-5 py-4"><Metric label="Incoming" value={formatBytes(summary.incoming)} suffix="/s" color="text-emerald-700 dark:text-emerald-400" /><Metric label="Outgoing" value={formatBytes(summary.outgoing)} suffix="/s" color="text-blue-600 dark:text-blue-400" /><Metric label="Transferred" value={formatBytes(summary.volume)} /></div>
          <TrafficMonitorPanel isDark={colorScheme === "dark"} samples={samples} isLoading={traffic.loading} title="Network Activity" showTitle={false} plotHeight={160} className="!px-5 !pt-0" windowSeconds={Number(seconds)} />
          {traffic.error && <p role="status" className="px-5 pb-3 text-xs text-amber-600">{traffic.error}</p>}
          <button onClick={()=>navigate("traffic")} className="mt-auto flex w-full items-center justify-between border-t border-border px-5 py-3 text-xs text-muted-foreground hover:bg-muted hover:text-foreground">Inspect ports and source addresses<IconArrowUpRight size={15} /></button>
        </section>
        <section className="flex min-w-0 flex-col rounded-xl bg-surface p-5">
          <div className="flex items-center justify-between gap-2"><h2 className="text-base font-semibold">Fleet Health</h2><IconServer size={18} className="text-muted-foreground" /></div>
          <div className="my-5 grid grid-cols-[100px_minmax(0,1fr)] items-center gap-4"><div className="relative h-[100px] w-[100px]"><svg aria-hidden="true" viewBox="0 0 120 120" className="h-full w-full -rotate-90"><circle cx="60" cy="60" r="50" fill="none" className="stroke-muted" strokeWidth="9" /><circle cx="60" cy="60" r="50" fill="none" className="stroke-emerald-500" strokeWidth="9" strokeDasharray={`${ratio * 314.16} 314.16`} strokeLinecap="round" /></svg><div className="absolute inset-0 flex flex-col items-center justify-center"><p className="text-2xl font-semibold tabular-nums">{Math.round(ratio*100)}<span className="text-sm text-muted-foreground">%</span></p><p className="mt-1 text-[11px] text-muted-foreground">online</p></div></div><div className="space-y-1">{[["online","Online",online.length,"bg-emerald-500"],["offline","Attention",attention.length,"bg-amber-500"],["disabled","Disabled",disabled.length,"bg-zinc-500"]].map(([filter,label,count,color])=><button key={filter} onClick={()=>navigate("machines",{status:filter})} className="flex w-full items-center gap-2 rounded-md px-2 py-2 text-sm hover:bg-muted"><span className={`h-1.5 w-1.5 rounded-full ${color}`} /><span>{label}</span><span className="ml-auto font-medium tabular-nums">{count}</span><IconArrowUpRight size={13} className="text-muted-foreground" /></button>)}</div></div>
          {attention.length ? <button onClick={()=>navigate("machines",{status:"offline"})} className="mb-4 flex items-start gap-2.5 rounded-lg bg-amber-500/5 p-3 text-left hover:bg-amber-500/10"><IconAlertCircle size={18} className="mt-0.5 shrink-0 text-amber-700 dark:text-amber-400" /><span><span className="block text-sm font-medium">{attention.length} {attention.length===1 ? "machine needs" : "machines need"} attention</span><span className="mt-1 block text-xs leading-5 text-muted-foreground">Review offline clients and authentication issues.</span></span></button> : <div className="mb-4 flex items-start gap-2 rounded-lg bg-emerald-500/5 p-3"><IconCheck size={18} className="shrink-0 text-emerald-600" /><p className="text-sm">All enabled machines are connected.</p></div>}
          <div className="mt-auto"><Button variant="secondary" className="w-full" onClick={()=>navigate("machines",{create:"1"})}><IconPlus size={16} />Enroll a Machine</Button></div>
        </section>
      </div>
      <div className="grid items-stretch gap-4 lg:grid-cols-[minmax(0,1.8fr)_minmax(290px,1fr)]">
        <section className="min-w-0 overflow-hidden rounded-xl bg-surface"><PanelHeading title="Busiest Ports" description="Transferred in the last 5 minutes" onClick={()=>navigate("traffic")} />
          <div className="grid grid-cols-[minmax(0,1fr)_100px_80px] gap-3 bg-muted/40 px-5 py-2 text-[11px] text-muted-foreground"><span>Service / machine</span><span>Activity</span><span className="text-right">Transferred</span></div>
          <div>{busiest.length ? busiest.map(row=><button key={row.connection._id} onClick={()=>navigate("machines",{machine:row.connection.machine_id})} className="grid w-full grid-cols-[minmax(0,1fr)_100px_80px] items-center gap-3 px-5 py-3 text-left hover:bg-muted/50"><div className="min-w-0"><p className="truncate text-sm font-medium">{row.connection.service_name || `Port ${row.connection.external_port}`}</p><p className="mt-1 truncate text-xs text-muted-foreground">{row.connection.machine_name} · :{row.connection.external_port}</p></div><div><TrafficSparkline samples={row.traffic} showRates={false} label={row.connection.service_name} /><div className="mt-1 h-0.5 rounded-full bg-muted"><div className="h-full rounded-full bg-primary/50" style={{width:`${row.summary.volume / peak * 100}%`}} /></div></div><p className="text-right text-xs font-medium tabular-nums">{formatBytes(row.summary.volume)}</p></button>) : <p className="p-5 text-sm text-muted-foreground">Traffic appears when a forwarded port is used.</p>}</div>
        </section>
        <section aria-label="Recent Web Addresses" className="flex min-w-0 flex-col overflow-hidden rounded-xl bg-surface">
          <PanelHeading title="Web Addresses" description="Most recently requested services" onClick={()=>navigate("proxies")} />
          <div>{recentlyVisited.map(proxy=><a key={proxy._id} href={`${proxy.entry_points?.includes("websecure")?"https":"http"}://${proxy.hosts?.includes(activityById.get(proxy._id)?.last_host)?activityById.get(proxy._id).last_host:proxy.hosts?.[0]}`} target="_blank" rel="noreferrer" className="flex w-full min-w-0 items-center gap-3 px-5 py-3 text-left hover:bg-accent/40">
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-muted"><IconWorld size={17} className="text-muted-foreground" /></span>
            <div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{activityById.get(proxy._id)?.last_host || proxy.hosts?.[0] || proxy.name}</p><ProxyActivity metric={activityById.get(proxy._id)} activity={activity} /></div>
            <IconArrowUpRight size={14} className="shrink-0 text-muted-foreground" />
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
