import useBackgroundRefresh from "@/shared/hooks/useBackgroundRefresh";
import { useWorkspaceState } from "@/shared/contexts/workspaceCache";
import ResultsPagination from "@/components/ui/results-pagination";
import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import { useRouter } from "next/router";
import { IconPlus, IconWorld, IconPlugConnected, IconFolder, IconArrowUpRight, IconRefresh, IconCheck, IconCopy } from "@tabler/icons-react";
import apiRoutes from "@/shared/routes/apiRoutes";
import useToast from "@/shared/hooks/useToast";
import { PageHeader, SearchField, EmptyState } from "@/components/ui/workspace";
import { selectProxies } from "@/shared/utils/search.mjs";
import { INVENTORY_SORT_OPTIONS, isTrafficSort } from "@/shared/utils/inventory-sort.mjs";
import { trafficSummary } from "@/shared/utils/traffic.mjs";
import InventoryToolbar from "@/components/ui/inventory-toolbar";
import ProxyConfigModal from "./ProxyConfigModal";
import { Button } from "@/components/ui/button";
import SearchSelect from "@/components/ui/search-select";
import { StatusTabs } from "@/components/ui/status-tabs";
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from "@/components/ui/table";
import useTrafficSnapshot from "@/shared/hooks/useTrafficSnapshot";
import TrafficSparkline from "@/components/ui/traffic-sparkline";
import useCreateFromUrl from "@/shared/hooks/useCreateFromUrl";
import useProxyActivity from "@/shared/hooks/useProxyActivity";
import ProxyActivity from "@/components/ui/proxy-activity";
import { externalEndpoint, internalEndpoint } from "@/shared/utils/endpoints.mjs";

export default function Proxy({ machineId = "", compact = false, connectionId = "", onEditorOpenChange, active = true }) {
  const router = useRouter();
  const activity = useProxyActivity({ enabled: active, preload: false });
  const activityById = new Map(activity.data.map(metric=>[metric.route_id,metric]));
  const { success, error } = useToast();
  const [proxies, setProxies] = useWorkspaceState("proxies.routes", []);
  const [connections, setConnections] = useWorkspaceState("proxies.connections", []);
  const [machines, setMachines] = useWorkspaceState("proxies.machines", []);
  const [settings, setSettings] = useWorkspaceState("proxies.settings", {});
  const [loading, setLoading] = useWorkspaceState("proxies.loading", true);
  const [loadError, setLoadError] = useState("");
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [group, setGroup] = useState("all");
  const [machine, setMachine] = useState("all");
  const [sort, setSort] = useState("name");
  const [groupBy, setGroupBy] = useState("none");
  const [pageSize, setPageSize] = useState(25);
  const [page, setPage] = useState(1);
  const [editing, setEditing] = useState(null);
  const [opened, setOpened] = useState(false);
  function changeEditor(nextOpened) {
    onEditorOpenChange?.(nextOpened);
    setOpened(nextOpened);
  }

  async function load(signal) {
    const options = signal instanceof AbortSignal ? { signal } : {};
    try {
      const [routes, ports, clients, defaults] = await Promise.all([
        axios.get(apiRoutes.listTrafficRoutes, options), axios.get(apiRoutes.listConnections, options),
        axios.get(apiRoutes.listMachines, options), axios.get(apiRoutes.authSettings, options),
      ]);
      setProxies(routes.data?.data || []); setConnections(ports.data?.data || []);
      setMachines(clients.data?.data || []); setSettings(defaults.data || {}); setLoadError("");
    } catch (error) { if (axios.isCancel(error)) return; setLoadError("Could not load proxies. Check your connection and try again."); }
    finally { if (!options.signal?.aborted) setLoading(false); }
  }
  useBackgroundRefresh(load, { enabled: active });
  useCreateFromUrl("proxies", create, active && !compact && !loading);
  useEffect(() => { if (!active) { onEditorOpenChange?.(false); setOpened(false); } }, [active, onEditorOpenChange]);
  useEffect(() => {
    if (!compact && typeof router.query.search === "string") setQuery(router.query.search);
  }, [router.query.search, compact]);
  useEffect(() => { setPage(1); }, [query, status, group, machine, sort, groupBy, pageSize, machineId, connectionId]);
  const scoped = useMemo(() => proxies.filter(p => (!machineId || p.connection?.machine_id === machineId)
    && (!connectionId || p.connection?.data_id === connectionId)), [proxies, machineId, connectionId]);
  const groups = [...new Set(scoped.map(p => p.group || "").filter(Boolean))].sort();
  const candidates = useMemo(() => selectProxies(scoped, { query, status, group, machine, sort: isTrafficSort(sort) ? "name" : sort }), [scoped, query, status, group, machine, sort]);
  const totalPages = Math.max(1, Math.ceil(candidates.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const trafficTargets = isTrafficSort(sort) ? candidates : candidates.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const traffic = useTrafficSnapshot({ ids: trafficTargets.map(proxy => proxy.connection?.data_id || proxy.connection?._id), enabled: active && !loading });
  const trafficById = new Map(traffic.rows.map(row=>[row.connection?._id,row.traffic]));
  const trafficMetrics = useMemo(()=>new Map(traffic.rows.map(row=>[row.connection?._id,trafficSummary(row.traffic,30)])),[traffic.rows]);
  const filtered = useMemo(()=>isTrafficSort(sort) ? selectProxies(scoped,{query,status,group,machine,sort,trafficById:trafficMetrics}) : candidates,[sort,scoped,query,status,group,machine,trafficMetrics,candidates]);
  const visible = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const sections = new Map();
  const rowInteraction = proxy => ({
    tabIndex: 0,
    "aria-label": `Edit proxy ${proxy.hosts?.[0] || proxy.name}`,
    onClick: event => { if (!event.target.closest("a,button,input")) edit(proxy); },
    onKeyDown: event => {
      if (event.target === event.currentTarget && ["Enter", " "].includes(event.key)) {
        event.preventDefault(); edit(proxy);
      }
    },
  });
  const copyProxyUrl = async (event, proxy) => {
    event.stopPropagation();
    const url = `${proxy.entry_points?.includes("websecure") ? "https" : "http"}://${proxy.hosts?.[0] || proxy.name}`;
    try { await navigator.clipboard.writeText(url); success("Proxy URL copied"); }
    catch { error("Could not copy proxy URL"); }
  };
  const host = proxy => <ProxyHost proxy={proxy} connection={connections.find(connection => connection._id === (proxy.connection?.data_id || proxy.connection?._id))} machine={machines.find(machine => machine._id === proxy.connection?.machine_id)} onCopy={event => copyProxyUrl(event, proxy)} />;
  visible.forEach(p => {
    const key = groupBy === "group" ? p.group || "Ungrouped" : groupBy === "machine" ? p.connection?.machine_name || "Manual targets"
      : groupBy === "domain" ? (p.hosts?.[0] || "").split(".").slice(-2).join(".") : "All proxies";
    sections.set(key, [...(sections.get(key) || []), p]);
  });
  function create() {
    const port = connections.find(c => c._id === connectionId) || connections.find(c => c.machine_id === machineId);
    setEditing(machineId && port ? { target_mode: "connection", connection: { data_id: port._id } } : null);
    changeEditor(true);
  }
  async function save(payload) {
    setSaving(true);
    try {
      const response = payload.data_id ? await axios.put(apiRoutes.updateTrafficRoute, payload) : await axios.post(apiRoutes.addTrafficRoute, payload);
      const route = response.data.data;
      setProxies(current => [...current.filter(p => p._id !== route._id), route]);
      setEditing(route); success(`Proxy ${payload.data_id ? "updated" : "created"}`); changeEditor(false);
      return route;
    } catch (err) { error(err?.response?.data?.detail || "Could not save proxy"); return null; }
    finally { setSaving(false); }
  }
  async function remove(id) {
    setDeleting(true);
    try {
      await axios.post(apiRoutes.deleteTrafficRoute, { data_id: id });
      setProxies(current => current.filter(p => p._id !== id)); success("Proxy deleted"); return true;
    } catch (err) { error(err?.response?.data?.detail || "Could not delete proxy"); return false; }
    finally { setDeleting(false); }
  }
  const createButton = <Button type="button" aria-label="Create proxy" onClick={create} disabled={loading}><IconPlus size={16} /><span className="md:hidden">Create</span><span className="hidden md:inline">Create proxy</span></Button>;
  const edit = p => { setEditing(p); changeEditor(true); };
  const reset = () => { setQuery(""); setStatus("all"); setGroup("all"); setMachine("all"); };
  return <div className={compact ? "flex min-h-0 max-h-[75dvh] flex-col gap-3" : "workspace-page"}>
    {compact ? <div className="flex flex-wrap items-center justify-between gap-3"><div><h3 className="text-sm font-semibold">Linked web proxies</h3><p className="mt-1 text-xs text-muted-foreground">Create and edit addresses for this {connectionId ? "port" : "machine"} here.</p></div>{createButton}</div>
      : <PageHeader eyebrow="Routing" title="Public Web Proxies" description="Manage publicly reachable web addresses separately from private machine access." actions={<Button variant="ghost" size="icon" aria-label="Refresh proxies" onClick={load} disabled={loading}><IconRefresh size={17} /></Button>} />}
    {!compact ? <InventoryToolbar label="Proxy tools"
      search={<SearchField value={query} onChange={setQuery} label="Search proxies" placeholder="Search proxies…" />}
      status={<StatusTabs label="Proxy status" value={status} onChange={setStatus} options={[{value:"all",label:"All"},{value:"enabled",label:"Enabled"},{value:"disabled",label:"Disabled"}]} />}
      filtered={group !== "all" || machine !== "all" || sort !== "name" || groupBy !== "none"}
      filters={[
        {label:"Group",control:<SearchSelect label="Filter proxy group" value={group} onChange={setGroup} options={[{value:"all",label:"All groups"},{value:"",label:"Ungrouped"},...groups.map(g=>({value:g,label:g}))]} />},
        {label:"Sort proxies",control:<SearchSelect label="Sort proxies" value={sort} onChange={setSort} options={[...INVENTORY_SORT_OPTIONS,{value:"updated",label:"Recently updated"},{value:"status",label:"Enabled first"}]} />},
        {label:"Machine",advanced:true,control:<SearchSelect label="Filter proxy machine" value={machine} onChange={setMachine} options={[{value:"all",label:"All machines"},{value:"manual",label:"Manual targets"},...machines.map(m=>({value:m._id,label:m.name}))]} />},
        {label:"Group rows",advanced:true,control:<SearchSelect label="Group proxies by" value={groupBy} onChange={setGroupBy} options={[{value:"none",label:"No grouping"},{value:"group",label:"Group by project"},{value:"machine",label:"Group by machine"},{value:"domain",label:"Group by domain"}]} />},
      ]}
      primaryActions={createButton}
    /> : <div className="mb-2 flex shrink-0 flex-wrap items-center gap-2">
      <div className="contents">
        <div className="min-w-0 basis-full md:flex-1 md:basis-48"><SearchField value={query} onChange={setQuery} label="Search proxies" placeholder="Search proxies…" /></div>
        <StatusTabs label="Proxy status" value={status} onChange={setStatus} options={[{value:"all",label:"All"},{value:"enabled",label:"Enabled"},{value:"disabled",label:"Disabled"}]} />
      </div>
    </div>}
    {loadError ? <EmptyState icon={IconWorld} title="Proxies unavailable" description={loadError} action={<button className="action-secondary" onClick={load}>Try again</button>} />
      : loading ? <div role="status" className="surface p-8 text-sm text-muted-foreground">Loading proxies…</div>
      : !filtered.length ? <EmptyState icon={IconWorld} title={scoped.length ? "No matching proxies" : "Your services, one address away"} description={scoped.length ? "Try another hostname, service, machine, or port, or clear your filters." : "Create a public address linked to a machine port or an HTTP target."} action={scoped.length ? <button className="action-secondary" onClick={reset}>Clear filters</button> : undefined} />
      : <div className="proxy-results overflow-hidden rounded-xl bg-surface"><div className="data-scroll">{[...sections].map(([label, entries]) => <section key={label}>
        {groupBy !== "none" && <h2 className="flex items-center gap-2 bg-muted px-4 py-2 text-xs font-semibold"><IconFolder size={14} />{label}<span className="ml-auto text-muted-foreground">{entries.length}</span></h2>}
        <div className="hidden md:block"><Table aria-label="Web proxies"><TableHeader><TableRow><TableHead className="w-[30%]">Hostname</TableHead><TableHead className="w-[25%]">Machine / service</TableHead><TableHead>Target</TableHead><TableHead className="hidden w-48 lg:table-cell"><span title="All traffic on the linked machine port; not individual HTTP requests">Linked port traffic</span></TableHead></TableRow></TableHeader><TableBody>{entries.map(p => <TableRow key={p._id} {...rowInteraction(p)} className="cursor-pointer focus-visible:bg-accent/40">
          <TableCell>{host(p)}<div className="pl-4"><ProxyActivity group={p.group} metric={activityById.get(p._id)} activity={activity} /></div></TableCell>
          <TableCell><p className="truncate font-medium">{p.connection?.machine_name || "Manual target"}</p><p className="mt-0.5 truncate text-[13px] text-muted-foreground">{p.connection?.service_name || p.description || "HTTP endpoint"}</p></TableCell>
          <TableCell>{p.connection ? <p className="truncate font-mono text-xs" title={`${externalEndpoint(p.connection)} → ${internalEndpoint(p.connection)}`}>{externalEndpoint(p.connection)} → {internalEndpoint(p.connection)}</p> : <p className="truncate font-mono text-[13px]" title={p.target_url}>{p.target_url}</p>}</TableCell>
          <TableCell className="hidden lg:table-cell">{p.connection ? <TrafficSparkline samples={trafficById.get(p.connection.data_id || p.connection._id) || []} label="Linked port traffic" /> : <span className="text-xs text-muted-foreground">Standalone target</span>}</TableCell>
        </TableRow>)}</TableBody></Table></div>
        <div className="md:hidden">{entries.map(p => <div className="proxy-row-mobile cursor-pointer focus-visible:bg-accent/40" key={p._id} {...rowInteraction(p)}><div className="min-w-0 flex-1">{host(p)}<div className="pl-4"><ProxyActivity metric={activityById.get(p._id)} activity={activity} /></div><p className="mt-1 truncate pl-4 font-mono text-[13px] text-muted-foreground">{p.connection ? `${externalEndpoint(p.connection)} → ${internalEndpoint(p.connection)}` : p.target_url}</p></div></div>)}</div>
      </section>)}</div>
      <ResultsPagination count={filtered.length} noun="Proxies" page={currentPage} pages={totalPages} pageSize={pageSize} onPage={setPage} onPageSize={setPageSize} />
    </div>}
    <ProxyConfigModal opened={opened} onClose={() => changeEditor(false)} onSubmit={save} onDelete={remove} proxy={editing} connections={machineId ? connections.filter(c => c.machine_id === machineId) : connections} machines={machineId ? machines.filter(m => m._id === machineId) : machines} defaultDomainSuffix={settings.web_proxy_domain_suffix || ""} serviceDomain={settings.port_hub_service_domain || ""} isSaving={saving} isDeleting={deleting} />
  </div>;
}

function ProxyHost({ proxy: p, connection, machine, onCopy }) {
  const port = connection || p.connection;
  const machineStatus = machine?.connection_status || port?.machine_connection_status;
  let status = "Enabled · Target health is not monitored", color = "bg-emerald-600 dark:bg-emerald-400";
  if (p.enabled === false) { status = "Disabled"; color = "bg-zinc-500 dark:bg-zinc-400"; }
  else if (machine?.enabled === false || port?.machine_enabled === false) { status = "Machine disabled"; color = "bg-zinc-500 dark:bg-zinc-400"; }
  else if (port?.enabled === false) { status = "Port disabled"; color = "bg-amber-600 dark:bg-amber-400"; }
  else if (machineStatus === "offline") { status = "Machine offline"; color = "bg-red-600 dark:bg-red-400"; }
  else if (machineStatus === "auth_required") { status = "Machine authentication required"; color = "bg-amber-600 dark:bg-amber-400"; }
  else if (machineStatus === "online") status = "Enabled · Machine online";
  else if (port) { status = "Machine status unknown"; color = "bg-amber-600 dark:bg-amber-400"; }
  const url = `${p.entry_points?.includes("websecure") ? "https" : "http"}://${p.hosts?.[0] || p.name}`;
  return <div className="flex min-w-0 items-center gap-2"><span role="img" aria-label={status} title={status} className={`h-2 w-2 shrink-0 rounded-full ${color}`} /><a className="inline-flex min-w-0 max-w-full items-center gap-1 truncate text-[15px] font-medium text-blue-600 hover:underline dark:text-blue-400" href={url} target="_blank" rel="noreferrer"><span className="truncate">{p.hosts?.[0] || p.name}</span>{p.hosts?.length > 1 && <span className="text-[10px] text-muted-foreground">+{p.hosts.length - 1}</span>}<IconArrowUpRight size={12} className="shrink-0 opacity-60" /></a><button type="button" onClick={onCopy} aria-label={`Copy proxy URL ${url}`} title="Copy proxy URL" className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2"><IconCopy size={14} /></button></div>;
}
