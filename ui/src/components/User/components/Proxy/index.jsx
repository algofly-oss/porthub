import Pagination from "@/components/ui/pagination";
import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import { useRouter } from "next/router";
import { Popover } from "@mantine/core";
import { IconPlus, IconWorld, IconPlugConnected, IconFolder, IconArrowUpRight, IconRefresh, IconCheck } from "@tabler/icons-react";
import apiRoutes from "@/shared/routes/apiRoutes";
import useToast from "@/shared/hooks/useToast";
import { PageHeader, SearchField, EmptyState } from "@/components/ui/workspace";
import { selectProxies } from "@/shared/utils/search.mjs";
import ProxyConfigModal from "./ProxyConfigModal";
import { Button } from "@/components/ui/button";
import SearchSelect from "@/components/ui/search-select";
import { StatusTabs } from "@/components/ui/status-tabs";
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from "@/components/ui/table";
import useTrafficSnapshot from "@/shared/hooks/useTrafficSnapshot";
import TrafficSparkline from "@/components/ui/traffic-sparkline";
import useCreateFromUrl from "@/shared/hooks/useCreateFromUrl";

export default function Proxy({ machineId = "", compact = false, connectionId = "", onEditorOpenChange }) {
  const router = useRouter();
  const { success, error } = useToast();
  const [proxies, setProxies] = useState([]);
  const [connections, setConnections] = useState([]);
  const [machines, setMachines] = useState([]);
  const [settings, setSettings] = useState({});
  const [loading, setLoading] = useState(true);
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
  const [showFilters, setShowFilters] = useState(false);
  const [page, setPage] = useState(1);
  const [editing, setEditing] = useState(null);
  const [opened, setOpened] = useState(false);
  function changeEditor(nextOpened) {
    onEditorOpenChange?.(nextOpened);
    setOpened(nextOpened);
  }

  async function load() {
    setLoading(true);
    try {
      const [routes, ports, clients, defaults] = await Promise.all([
        axios.get(apiRoutes.listTrafficRoutes), axios.get(apiRoutes.listConnections),
        axios.get(apiRoutes.listMachines), axios.get(apiRoutes.authSettings),
      ]);
      setProxies(routes.data?.data || []); setConnections(ports.data?.data || []);
      setMachines(clients.data?.data || []); setSettings(defaults.data || {}); setLoadError("");
    } catch { setLoadError("Could not load proxies. Check your connection and try again."); }
    finally { setLoading(false); }
  }
  useEffect(() => { load(); }, []);
  useCreateFromUrl("proxies", create, !compact && !loading);
  useEffect(() => {
    if (!compact && typeof router.query.search === "string") setQuery(router.query.search);
  }, [router.query.search, compact]);
  useEffect(() => { setPage(1); }, [query, status, group, machine, sort, groupBy, pageSize, machineId, connectionId]);
  const scoped = useMemo(() => proxies.filter(p => (!machineId || p.connection?.machine_id === machineId)
    && (!connectionId || p.connection?.data_id === connectionId)), [proxies, machineId, connectionId]);
  const groups = [...new Set(scoped.map(p => p.group || "").filter(Boolean))].sort();
  const filtered = useMemo(() => selectProxies(scoped, { query, status, group, machine, sort }), [scoped, query, status, group, machine, sort]);
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const visible = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const traffic = useTrafficSnapshot({ ids: visible.map(proxy => proxy.connection?.data_id || proxy.connection?._id), enabled: !loading });
  const trafficById = new Map(traffic.rows.map(row=>[row.connection?._id,row.traffic]));
  const sections = new Map();
  visible.forEach(p => {
    const key = groupBy === "group" ? p.group || "Ungrouped" : groupBy === "machine" ? p.connection?.machine_name || "Manual targets"
      : groupBy === "domain" ? (p.hosts?.[0] || "").split(".").slice(-2).join(".") : "All proxies";
    sections.set(key, [...(sections.get(key) || []), p]);
  });
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
  const host = proxy => <ProxyHost proxy={proxy} connection={connections.find(connection => connection._id === (proxy.connection?.data_id || proxy.connection?._id))} machine={machines.find(machine => machine._id === proxy.connection?.machine_id)} />;
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
  const createButton = <Button type="button" onClick={create} disabled={loading}><IconPlus size={16} />Create proxy</Button>;
  const edit = p => { setEditing(p); changeEditor(true); };
  const reset = () => { setQuery(""); setStatus("all"); setGroup("all"); setMachine("all"); };
  return <div className={compact ? "flex min-h-0 max-h-[75dvh] flex-col gap-3" : "workspace-page"}>
    {compact ? <div className="flex flex-wrap items-center justify-between gap-3"><div><h3 className="text-sm font-semibold">Linked web proxies</h3><p className="mt-1 text-xs text-muted-foreground">Create and edit addresses for this {connectionId ? "port" : "machine"} here.</p></div>{createButton}</div>
      : <PageHeader eyebrow="Routing" title="Web Proxies" description="Find, organize, and route your services from one place." />}
    <div className="mb-2 flex shrink-0 flex-wrap items-center gap-2">
      <div className="contents">
        <div className="min-w-0 basis-full md:flex-1 md:basis-48"><SearchField value={query} onChange={setQuery} label="Search proxies" placeholder="Search proxies…" /></div>
        <StatusTabs label="Proxy status" value={status} onChange={setStatus} options={[{value:"all",label:"All"},{value:"enabled",label:"Enabled"},{value:"disabled",label:"Disabled"}]} />
      </div>
      {!compact && <>
        <SearchSelect className="w-40" label="Filter proxy group" value={group} onChange={setGroup} options={[{value:"all",label:"All groups"},{value:"",label:"Ungrouped"},...groups.map(g=>({value:g,label:g}))]} />
        <Popover opened={showFilters} onChange={setShowFilters} position="bottom-end" width={280} shadow="sm">
          <Popover.Target><Button variant="secondary" aria-expanded={showFilters} onClick={()=>setShowFilters(value=>!value)}>Filters{(machine !== "all" || sort !== "name" || groupBy !== "none") && <span className="h-1.5 w-1.5 rounded-full bg-primary" />}</Button></Popover.Target>
          <Popover.Dropdown className="!rounded-xl !border-border !bg-dialog !p-4 !text-foreground"><div className="space-y-4">
            <div><p className="mb-2 text-xs font-medium text-muted-foreground">Machine</p><SearchSelect label="Filter proxy machine" value={machine} onChange={setMachine} withinPortal={false} options={[{value:"all",label:"All machines"},{value:"manual",label:"Manual targets"},...machines.map(m=>({value:m._id,label:m.name}))]} /></div>
            <div><p className="mb-2 text-xs font-medium text-muted-foreground">Sort</p><SearchSelect label="Sort proxies" value={sort} onChange={setSort} withinPortal={false} options={[{value:"name",label:"Hostname A–Z"},{value:"updated",label:"Recently updated"},{value:"status",label:"Enabled first"}]} /></div>
            <div><p className="mb-2 text-xs font-medium text-muted-foreground">Group rows</p><SearchSelect label="Group proxies by" value={groupBy} onChange={setGroupBy} withinPortal={false} options={[{value:"none",label:"No grouping"},{value:"group",label:"Group by project"},{value:"machine",label:"Group by machine"},{value:"domain",label:"Group by domain"}]} /></div>
            <Button variant="ghost" onClick={()=>{setMachine("all");setSort("name");setGroupBy("none");}}>Reset filters</Button>
          </div></Popover.Dropdown>
        </Popover>
      </>}
      {!compact && <div className="ml-auto flex items-center gap-2"><Button variant="secondary" size="icon" aria-label="Refresh proxies" onClick={load} disabled={loading}><IconRefresh size={17} /></Button>{createButton}</div>}
    </div>
    {loadError ? <EmptyState icon={IconWorld} title="Proxies unavailable" description={loadError} action={<button className="action-secondary" onClick={load}>Try again</button>} />
      : loading ? <div role="status" className="surface p-8 text-sm text-muted-foreground">Loading proxies…</div>
      : !filtered.length ? <EmptyState icon={IconWorld} title={scoped.length ? "No matching proxies" : "Your services, one address away"} description={scoped.length ? "Try another hostname, service, machine, or port, or clear your filters." : "Create a public address linked to a machine port or an HTTP target."} action={scoped.length ? <button className="action-secondary" onClick={reset}>Clear filters</button> : undefined} />
      : <div className="proxy-results overflow-hidden rounded-xl bg-surface"><div className="data-scroll">{[...sections].map(([label, entries]) => <section key={label}>
        {groupBy !== "none" && <h2 className="flex items-center gap-2 bg-muted px-4 py-2 text-xs font-semibold"><IconFolder size={14} />{label}<span className="ml-auto text-muted-foreground">{entries.length}</span></h2>}
        <div className="hidden md:block"><Table aria-label="Web proxies"><TableHeader><TableRow><TableHead className="w-[30%]">Hostname</TableHead><TableHead className="w-[25%]">Machine / service</TableHead><TableHead>Target</TableHead><TableHead className="hidden w-48 lg:table-cell"><span title="All traffic on the linked machine port; not individual HTTP requests">Linked port traffic</span></TableHead></TableRow></TableHeader><TableBody>{entries.map(p => <TableRow key={p._id} {...rowInteraction(p)} className="cursor-pointer focus-visible:bg-accent/40">
          <TableCell>{host(p)}{p.group && <p className="mt-1 truncate pl-4 text-[13px] text-muted-foreground">{p.group}</p>}</TableCell>
          <TableCell><p className="truncate font-medium">{p.connection?.machine_name || "Manual target"}</p><p className="mt-0.5 truncate text-[13px] text-muted-foreground">{p.connection?.service_name || p.description || "HTTP endpoint"}</p></TableCell>
          <TableCell><p className="truncate font-mono text-[13px]" title={p.target_url}>{p.target_url}</p></TableCell>
          <TableCell className="hidden lg:table-cell">{p.connection ? <TrafficSparkline samples={trafficById.get(p.connection.data_id || p.connection._id) || []} label="Linked port traffic" /> : <span className="text-xs text-muted-foreground">Standalone target</span>}</TableCell>
        </TableRow>)}</TableBody></Table></div>
        <div className="md:hidden">{entries.map(p => <div className="proxy-row-mobile cursor-pointer focus-visible:bg-accent/40" key={p._id} {...rowInteraction(p)}><div className="min-w-0 flex-1">{host(p)}<p className="mt-1 truncate pl-4 text-[13px] text-muted-foreground">{p.connection?.machine_name || "Manual target"} · {p.connection?.service_name || p.target_url}</p></div></div>)}</div>
      </section>)}</div>
      <footer className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-t border-border px-3 py-2"><p className="text-[13px] text-muted-foreground">{filtered.length} proxies · {currentPage}/{totalPages}</p><SearchSelect className="w-36 sm:ml-auto" label="Proxies per page" value={pageSize} onChange={value=>setPageSize(Number(value))} options={[10,25,50].map(n=>({value:n,label:`${n} per page`}))} /><Pagination value={currentPage} onChange={setPage} total={totalPages} size="sm" siblings={0} /></footer>
    </div>}
    <ProxyConfigModal opened={opened} onClose={() => changeEditor(false)} onSubmit={save} onDelete={remove} proxy={editing} connections={machineId ? connections.filter(c => c.machine_id === machineId) : connections} machines={machineId ? machines.filter(m => m._id === machineId) : machines} defaultDomainSuffix={settings.web_proxy_domain_suffix || ""} serviceDomain={settings.port_hub_service_domain || ""} isSaving={saving} isDeleting={deleting} />
  </div>;
}

function ProxyHost({ proxy: p, connection, machine }) {
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
  return <div className="flex min-w-0 items-center gap-2"><span role="img" aria-label={status} title={status} className={`h-2 w-2 shrink-0 rounded-full ${color}`} /><a className="inline-flex min-w-0 max-w-full items-center gap-1 truncate text-[15px] font-medium text-blue-600 hover:underline dark:text-blue-400" href={`${p.entry_points?.includes("websecure") ? "https" : "http"}://${p.hosts?.[0]}`} target="_blank" rel="noreferrer"><span className="truncate">{p.hosts?.[0] || p.name}</span>{p.hosts?.length > 1 && <span className="text-[10px] text-muted-foreground">+{p.hosts.length - 1}</span>}<IconArrowUpRight size={12} className="shrink-0 opacity-60" /></a></div>;
}
