import ResultsPagination from "@/components/ui/results-pagination";
import SearchSelect from "@/components/ui/search-select";
import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import { useMantineColorScheme } from "@mantine/core";
import { IconActivity, IconArrowDownLeft, IconArrowUpRight, IconShieldLock, IconPlayerPause, IconPlayerPlay, IconChevronDown, IconRefresh } from "@tabler/icons-react";
import { PageHeader, SearchField, EmptyState } from "@/components/ui/workspace";
import apiRoutes from "@/shared/routes/apiRoutes";
import { searchScore } from "@/shared/utils/search.mjs";
import { aggregateTraffic, trafficSummary, formatBytes } from "@/shared/utils/traffic.mjs";
import TrafficMonitorPanel from "../Home/components/Host/TrafficMonitorPanel";
import { Button } from "@/components/ui/button";
import TrafficSparkline from "@/components/ui/traffic-sparkline";
import { useDemo } from "@/shared/demo/DemoProvider";
import uiRoutes from "@/shared/routes/uiRoutes";

export default function Traffic() {
  const demo = useDemo();
  const { colorScheme } = useMantineColorScheme();
  const [rows, setRows] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [paused, setPaused] = useState(false);
  const [query, setQuery] = useState("");
  const [machine, setMachine] = useState("all");
  const [sort, setSort] = useState("traffic");
  const [seconds, setSeconds] = useState(60);
  const [expanded, setExpanded] = useState("");
  const [page, setPage] = useState(1);
  const [refresh, setRefresh] = useState(0);
  const [updated, setUpdated] = useState(null);
  useEffect(() => {
    if (paused) return;
    let active = true, timeout;
    const controller = new AbortController();
    async function poll() {
      try {
        if (!document.hidden) {
          const response = await axios.post(apiRoutes.trafficSnapshot, {}, { signal: controller.signal });
          if (!active) return;
          setRows(response.data?.data || []); setUpdated(Date.now()); setError("");
        }
      } catch (err) {
        if (active) setError(err?.response?.data?.detail || "Could not load traffic. Check the firewall service and try again.");
      } finally {
        if (active) { setLoading(false); timeout = setTimeout(poll, 2000); }
      }
    }
    poll();
    return () => { active = false; clearTimeout(timeout); controller.abort(); };
  }, [paused, refresh]);
  useEffect(() => { setPage(1); }, [query, machine, sort]);
  const machines = [...new Map(rows.map(r => [r.connection.machine_id, r.connection.machine_name || "Unknown machine"]))];
  const filtered = useMemo(() => rows.filter(r => (machine === "all" || r.connection.machine_id === machine)
    && Number.isFinite(searchScore(query, Object.values(r.connection))))
    .map(r => ({ ...r, summary: trafficSummary(r.traffic, seconds, (updated || Date.now()) / 1000) }))
    .sort((a, b) => sort === "name" ? (a.connection.service_name || "").localeCompare(b.connection.service_name || "")
      : sort === "blocked" ? b.summary.blockedVolume - a.summary.blockedVolume : b.summary.volume - a.summary.volume),
  [rows, machine, query, sort, seconds, updated]);
  const samples = useMemo(() => aggregateTraffic(filtered), [filtered]);
  const summary = trafficSummary(samples, seconds, (updated || Date.now()) / 1000);
  const pages = Math.max(1, Math.ceil(filtered.length / 10));
  const currentPage = Math.min(page, pages);
  return <div className="workspace-page">
    <PageHeader title="Traffic Explorer" />
    <div className="toolbar"><div className="flex flex-wrap items-center gap-2">
      <div className="min-w-0 basis-full lg:flex-1 lg:basis-48"><SearchField label="Search traffic" value={query} onChange={setQuery} placeholder="Search ports…" /></div>
      <SearchSelect className="min-w-0 flex-1 basis-[calc(50%-4px)] sm:w-40 sm:flex-none sm:basis-auto" label="Traffic machine" value={machine} onChange={setMachine} options={[{value:"all",label:"All machines"},...machines.map(([id,name])=>({value:id,label:name}))]} />
      <SearchSelect className="min-w-0 flex-1 basis-[calc(50%-4px)] sm:w-40 sm:flex-none sm:basis-auto" label="Sort traffic" value={sort} onChange={setSort} options={[{value:"traffic",label:"Most traffic"},{value:"blocked",label:"Most blocked"},{value:"name",label:"Service A–Z"}]} />
      <SearchSelect className="min-w-0 flex-1 basis-[calc(50%-4px)] sm:w-40 sm:flex-none sm:basis-auto" label="Traffic window" value={seconds} onChange={value=>setSeconds(Number(value))} options={[{value:60,label:"Last 60 seconds"},{value:120,label:"Last 2 minutes"}]} />
      <div className="ml-auto flex shrink-0 items-center gap-2">
        <Button type="button" variant="secondary" size="icon" onClick={() => setRefresh(v => v + 1)} disabled={paused} aria-label="Refresh traffic"><IconRefresh size={17} /></Button>
        <Button type="button" variant="secondary" onClick={() => setPaused(v => !v)}>{paused ? <IconPlayerPlay size={17} /> : <IconPlayerPause size={17} />}{paused ? "Resume" : "Pause"}</Button>
      </div>
    </div><p role="status" className="text-xs text-muted-foreground">{paused ? "Paused · showing the last snapshot" : "Live · refreshes every 2 seconds"}{updated ? ` · Updated ${new Date(updated).toLocaleTimeString()}` : ""}</p></div>
    {error && rows.length > 0 && <div role="alert" className="mb-3 rounded-lg bg-amber-500/10 p-3 text-sm text-amber-800 dark:text-amber-300">{error} Showing the last successful snapshot.</div>}
    {loading ? <div role="status" className="surface p-8 text-sm text-muted-foreground">Loading traffic…</div>
      : error && !rows.length ? <div role="alert"><EmptyState icon={IconActivity} title="Traffic Unavailable" description={error} action={<Button type="button" variant="secondary" onClick={()=>setRefresh(value=>value+1)}><IconRefresh size={16} />Try Again</Button>} /></div>
      : !filtered.length ? <EmptyState icon={IconActivity} title={rows.length ? "No matching services" : "No port traffic to explore yet"} description={rows.length ? "Change your search or machine filter." : "Traffic appears here when a machine has a forwarded port and the firewall service is available."} />
      : <section aria-label="Traffic results" className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-xl bg-surface"><div className="data-scroll"><details className="border-b border-border"><summary className="cursor-pointer px-4 py-3 text-sm font-medium">Combined traffic · {filtered.length} ports</summary><div className="p-3"><TrafficMonitorPanel isDark={colorScheme === "dark"} samples={samples} isLoading={false} title="Combined traffic" subtitle="Bytes per second" windowSeconds={seconds} /></div></details>
      <section><div className="border-b border-border px-4 py-3"><h2 className="text-sm font-semibold">Port Activity</h2></div>
      <div className="divide-y divide-border/60">{filtered.slice((currentPage - 1) * 10, currentPage * 10).map(row => {
        const c = row.connection, s = row.summary, open = expanded === c._id;
        return <div key={c._id}>
          <button type="button" aria-expanded={open} aria-controls={`traffic-${c._id}`} onClick={() => setExpanded(open ? "" : c._id)} className="relative grid w-full grid-cols-3 items-center gap-3 px-4 py-3 text-left hover:bg-accent/40 md:grid-cols-[minmax(0,1.4fr)_minmax(70px,120px)_repeat(3,minmax(0,1fr))_20px]">
            <div className="col-span-2 min-w-0 md:col-span-1"><p className="truncate text-sm font-medium">{c.service_name || `Port ${c.external_port}`}</p><p className="mt-1 truncate text-xs text-muted-foreground">{c.machine_name || "Unknown machine"} · :{c.external_port} → :{c.internal_port}</p></div>
            <TrafficSparkline samples={row.traffic} now={(updated || Date.now()) / 1000} showRates={false} label={`${c.machine_name || "Machine"} · ${c.service_name || `Port ${c.external_port}`}`} className="mr-5 md:mr-0" />
            <div><p className="text-[11px] text-muted-foreground">Incoming</p><p className="mt-1 font-mono text-xs text-emerald-700 dark:text-emerald-400">{formatBytes(s.incoming)}/s</p></div>
            <div><p className="text-[11px] text-muted-foreground">Outgoing</p><p className="mt-1 font-mono text-xs text-blue-700 dark:text-blue-400">{formatBytes(s.outgoing)}/s</p></div>
            <div><p className="text-[11px] text-muted-foreground">Transferred / blocked</p><p className="mt-1 font-mono text-xs">{formatBytes(s.volume)} / <span className="text-rose-700 dark:text-rose-300">{formatBytes(s.blockedVolume)}</span></p></div>
            <IconChevronDown size={16} className={`absolute right-3 top-3 text-zinc-400 transition-transform md:static ${open ? "rotate-180" : ""}`} />
          </button>
          {open && <div id={`traffic-${c._id}`} className="space-y-4 border-t border-border/60 p-4 sm:p-5">
            <TrafficMonitorPanel isDark={colorScheme === "dark"} samples={row.traffic} isLoading={false} title={`${c.service_name || "Port"} · :${c.external_port}`} windowSeconds={seconds} />
            <div className="grid gap-3 sm:grid-cols-2"><IpList title="Observed IP addresses" ips={s.ips} /><IpList title="Blocked IP addresses" ips={s.blockedIps} /></div>
            <Button asChild variant="secondary"><a href={uiRoutes.getTrafficMonitor({dataId:c._id,demo})} target="_blank" rel="noreferrer">Open Dedicated Monitor<IconArrowUpRight size={15} /></a></Button>
          </div>}
        </div>;
      })}</div></section></div><ResultsPagination count={filtered.length} noun="Ports" page={currentPage} pages={pages} pageSize={10} onPage={setPage} /></section>}
  </div>;
}

function IpList({ title, ips }) {
  return <div className="rounded-lg bg-control p-4"><h3 className="text-xs font-semibold">{title}</h3><div className="mt-2 flex max-h-32 flex-wrap gap-2 overflow-y-auto">{ips.length ? ips.map(ip => <span className="rounded bg-muted px-2 py-1 font-mono text-xs" key={ip}>{ip}</span>) : <p className="text-xs text-muted-foreground">None observed in this window.</p>}</div></div>;
}
