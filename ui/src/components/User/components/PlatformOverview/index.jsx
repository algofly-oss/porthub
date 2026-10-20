import SearchSelect from "@/components/ui/search-select";
import Pagination from "@/components/ui/pagination";
import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import { IconChevronDown, IconRefresh, IconUsers, IconServer } from "@tabler/icons-react";
import { motion, useReducedMotion } from "framer-motion";
import apiRoutes from "@/shared/routes/apiRoutes";
import { PageHeader, SearchField, EmptyState } from "@/components/ui/workspace";
import { Button } from "@/components/ui/button";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { searchScore } from "@/shared/utils/search.mjs";

export default function PlatformOverview() {
  const [overview, setOverview] = useState([]), [loading, setLoading] = useState(true), [error, setError] = useState("");
  const [query, setQuery] = useState(""), [role, setRole] = useState("all"), [sort, setSort] = useState("name"), [expanded, setExpanded] = useState("");
  const [page, setPage] = useState(1), [pageSize, setPageSize] = useState(25);
  const reduced = useReducedMotion();
  async function load() {
    setLoading(true);
    try { const response = await axios.get(apiRoutes.adminOverview); setOverview(response.data?.data || []); setError(""); }
    catch (err) { setError(err?.response?.data?.detail || "Could not load platform overview."); }
    finally { setLoading(false); }
  }
  useEffect(() => { load(); }, []);
  useEffect(() => { setPage(1); }, [query, role, sort, pageSize]);
  const filtered = useMemo(() => overview.filter(entry => (role === "all" || entry.user.role === role) && Number.isFinite(searchScore(query, [entry.user.name, entry.user.email, ...entry.machines.flatMap(m => [m.name, m.hostname, m.local_ip, m.public_ip, ...(m.ports || []).flatMap(p => [p.service_name, p.external_port])])]))).sort((a, b) => sort === "machines" ? b.machines.length - a.machines.length : (a.user.name || a.user.email).localeCompare(b.user.name || b.user.email)), [overview, query, role, sort]);
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const visibleStart = (currentPage - 1) * pageSize;
  const visible = filtered.slice(visibleStart, visibleStart + pageSize);
  return <div className="workspace-page">
    <PageHeader title="Platform Overview" />
    <div className="toolbar flex-row flex-wrap items-center"><div className="min-w-0 basis-full sm:mr-auto sm:basis-72"><SearchField value={query} onChange={setQuery} label="Search platform" placeholder="Search users or machines…" /></div><SearchSelect className="min-w-0 flex-1 sm:w-44 sm:flex-none" label="Filter account role" value={role} onChange={setRole} options={[{value:"all",label:"All roles"},{value:"admin",label:"Administrators"},{value:"user",label:"Members"}]} /><SearchSelect className="min-w-0 flex-1 sm:w-44 sm:flex-none" label="Sort accounts" value={sort} onChange={setSort} options={[{value:"name",label:"Name A–Z"},{value:"machines",label:"Most machines"}]} /><Button type="button" variant="outline" onClick={load} disabled={loading} aria-label="Refresh platform"><IconRefresh size={15} /><span className="hidden sm:inline">Refresh</span></Button></div>
    {error ? <EmptyState icon={IconServer} title="Platform unavailable" description={error} action={<Button onClick={load}>Try again</Button>} /> : loading ? <p role="status" className="p-6 text-xs text-muted-foreground">Loading accounts…</p> : !filtered.length ? <EmptyState icon={IconUsers} title="No matching accounts" description="Try a different name, email, machine, or port." /> : <section aria-label="Platform results" className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-xl bg-surface">
      <div className="data-scroll">
        <div className="hidden lg:block"><Table aria-label="Platform accounts"><TableHeader><TableRow><TableHead className="w-[40%]">Account</TableHead><TableHead>Role</TableHead><TableHead>Machines</TableHead><TableHead>Online</TableHead><TableHead className="w-40"><span className="sr-only">Details</span></TableHead></TableRow></TableHeader><TableBody>{visible.map(entry => <AccountRow key={entry.user.id} entry={entry} expanded={expanded === entry.user.id} toggle={() => setExpanded(expanded === entry.user.id ? "" : entry.user.id)} reduced={reduced} />)}</TableBody></Table></div>
        <div className="lg:hidden">{visible.map(entry => <div key={entry.user.id} className="border-b border-border/60"><button type="button" aria-label={`View machines for ${entry.user.name || entry.user.email}`} aria-expanded={expanded === entry.user.id} className="flex w-full items-center justify-between gap-3 p-3 text-left hover:bg-accent/40" onClick={() => setExpanded(expanded === entry.user.id ? "" : entry.user.id)}><div className="min-w-0"><p className="truncate text-sm font-medium">{entry.user.name}</p><p className="mt-1 truncate text-[11px] text-muted-foreground">{entry.user.email}</p><p className="mt-1 text-[11px] text-muted-foreground">{entry.user.role === "admin" ? "Admin" : "Member"} · {entry.machines.length} machines</p></div><IconChevronDown size={16} className={`shrink-0 transition-transform ${expanded === entry.user.id ? "rotate-180" : ""}`} /></button>{expanded === entry.user.id && <Fleet machines={entry.machines} />}</div>)}</div>
      </div>
      <footer className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-t border-border px-3 py-2">
        <p className="text-xs text-muted-foreground">Showing {visibleStart + 1} to {Math.min(visibleStart + pageSize, filtered.length)} of {filtered.length} accounts</p>
        <SearchSelect className="w-36 sm:ml-auto" label="Accounts per page" value={pageSize} onChange={value => setPageSize(Number(value))} options={[10,25,50].map(value => ({value,label:`${value} per page`}))} />
        <Pagination value={currentPage} onChange={setPage} total={totalPages} size="sm" siblings={0} />
      </footer>
    </section>}
  </div>;
}

function AccountRow({ entry, expanded, toggle, reduced }) {
  const online = entry.machines.filter(machine => machine.connection_status === "online").length;
  return <>
    <TableRow>
      <TableCell>
        <div className="flex items-center gap-3">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-medium">{(entry.user.name || entry.user.email || "U").slice(0, 1)}</span>
          <div className="min-w-0"><p className="truncate font-medium">{entry.user.name}</p><p className="mt-0.5 truncate text-[11px] text-muted-foreground">{entry.user.email}</p></div>
        </div>
      </TableCell>
      <TableCell>{entry.user.role === "admin" ? "Administrator" : "Member"}</TableCell>
      <TableCell>{entry.machines.length}</TableCell>
      <TableCell><span className={online ? "text-emerald-700 dark:text-emerald-400" : "text-muted-foreground"}>{online}</span></TableCell>
      <TableCell>
        <Button type="button" size="sm" variant="outline" aria-label={`View machines for ${entry.user.name || entry.user.email}`} aria-expanded={expanded} onClick={toggle}>
          Machines<IconChevronDown size={13} className={expanded ? "rotate-180" : ""} />
        </Button>
      </TableCell>
    </TableRow>
    {expanded && <TableRow><TableCell colSpan={5} className="p-0"><motion.div initial={reduced ? false : { opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.15 }}><Fleet machines={entry.machines} /></motion.div></TableCell></TableRow>}
  </>;
}

function Fleet({ machines }) {
  return <div className="bg-muted/40 px-3 py-2 sm:px-6">{!machines.length ? <p className="py-4 text-xs text-muted-foreground">No registered machines.</p> : machines.map(m => <details key={m._id} className="border-b border-border/50 last:border-0"><summary className="flex cursor-pointer list-none items-center justify-between gap-3 py-3"><div className="min-w-0"><p className="truncate text-xs font-medium">{m.name}</p><p className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground">{m.hostname || m.local_ip || "Awaiting client"}</p></div><div className="flex shrink-0 items-center gap-2 text-[10px] text-muted-foreground"><span className={`h-1.5 w-1.5 rounded-full ${m.connection_status === "online" ? "bg-emerald-500" : "bg-zinc-500"}`} />{m.connection_status === "online" ? "Online" : m.connection_status === "disabled" ? "Disabled" : "Offline"}<span className="hidden sm:inline">· {m.ports?.length || 0} ports</span><IconChevronDown size={13} /></div></summary><div className="pb-3">{(m.ports || []).map(p => <div key={p._id} className="flex flex-wrap items-center justify-between gap-2 rounded-md px-2 py-2 text-[11px] hover:bg-muted"><span className="font-medium">{p.service_name || "Unnamed service"}</span><span className="font-mono text-muted-foreground">:{p.external_port} → {p.internal_ip}:{p.internal_port}</span><span className="text-muted-foreground">{p.enabled ? "Enabled" : "Disabled"}</span></div>)}{!m.ports?.length && <p className="text-xs text-muted-foreground">No mapped ports.</p>}</div></details>)}</div>;
}
