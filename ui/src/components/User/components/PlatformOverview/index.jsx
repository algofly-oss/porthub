import useInventoryPage from "@/shared/hooks/useInventoryPage";
import { useSelector } from "react-redux";
import { authSelector } from "@/redux/features/authSlice";
import { CreateUser, DeleteUser } from "./UserManagement";
import useBackgroundRefresh from "@/shared/hooks/useBackgroundRefresh";
import { externalEndpoint, internalEndpoint } from "@/shared/utils/endpoints.mjs";
import { useWorkspaceState } from "@/shared/contexts/workspaceCache";
import SearchSelect from "@/components/ui/search-select";
import ResultsPagination from "@/components/ui/results-pagination";
import { useEffect, useMemo, useState } from "react";
import { Popover } from "@mantine/core";
import axios from "axios";
import { IconChevronDown, IconRefresh, IconUsers, IconServer } from "@tabler/icons-react";
import { motion, useReducedMotion } from "framer-motion";
import apiRoutes from "@/shared/routes/apiRoutes";
import { PageHeader, SearchField, EmptyState } from "@/components/ui/workspace";
import { Button } from "@/components/ui/button";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { searchScore } from "@/shared/utils/search.mjs";

export default function PlatformOverview({ active = true }) {
  const currentUser = useSelector(authSelector);
  const [query, setQuery] = useState(""), [role, setRole] = useState("all"), [sort, setSort] = useState("name"), [expanded, setExpanded] = useState("");
  const [page, setPage] = useState(1), [pageSize, setPageSize] = useState(25);
  const [signup, setSignup] = useState(null), [signupBusy, setSignupBusy] = useState(false), [signupError, setSignupError] = useState("");
  const [docs, setDocs] = useState(null), [docsBusy, setDocsBusy] = useState(false), [docsError, setDocsError] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const reduced = useReducedMotion();
  const inventory = useInventoryPage("accounts", {q:query,role,sort,page,page_size:pageSize}, {enabled:active});
  const loading=inventory.loading, error=inventory.error;
  useEffect(()=>{if(!inventory.loading && page>inventory.pagination.pages)setPage(inventory.pagination.pages);},[page,inventory.loading,inventory.pagination.pages]);
  const load=inventory.refresh;
  useBackgroundRefresh(load, {enabled:active,interval:15000});
  async function loadSignup() {
    try { const response = await axios.get(apiRoutes.adminSignupSettings); setSignup(response.data); setSignupError(""); }
    catch (err) { setSignupError(err?.response?.data?.detail || "Could not load signup settings."); }
  }
  async function loadDocs() {
    try { const response = await axios.get(apiRoutes.adminDocsSettings); setDocs(response.data); setDocsError(""); }
    catch (err) { setDocsError(err?.response?.data?.detail || "Could not load API documentation settings."); }
  }
  useEffect(() => { if (active && settingsOpen) { loadSignup(); loadDocs(); } }, [active, settingsOpen]);
  async function setSignupEnabled(enabled) {
    setSignupBusy(true); setSignupError("");
    try { const response = await axios.patch(apiRoutes.adminSignupSettings, { signup_enabled: enabled }); setSignup(response.data); }
    catch (err) { setSignupError(err?.response?.data?.detail || "Could not update signup settings."); }
    finally { setSignupBusy(false); }
  }
  async function resetSignup() {
    setSignupBusy(true); setSignupError("");
    try { const response = await axios.delete(apiRoutes.adminSignupSettings); setSignup(response.data); }
    catch (err) { setSignupError(err?.response?.data?.detail || "Could not reset signup settings."); }
    finally { setSignupBusy(false); }
  }
  async function setDocsEnabled(enabled) {
    setDocsBusy(true); setDocsError("");
    try { const response = await axios.patch(apiRoutes.adminDocsSettings, { api_docs_enabled: enabled }); setDocs(response.data); }
    catch (err) { setDocsError(err?.response?.data?.detail || "Could not update API documentation settings."); }
    finally { setDocsBusy(false); }
  }
  async function resetDocs() {
    setDocsBusy(true); setDocsError("");
    try { const response = await axios.delete(apiRoutes.adminDocsSettings); setDocs(response.data); }
    catch (err) { setDocsError(err?.response?.data?.detail || "Could not reset API documentation settings."); }
    finally { setDocsBusy(false); }
  }
  useEffect(() => { setPage(1); }, [query, role, sort, pageSize]);
  const filtered=inventory.rows;
  const totalPages=inventory.pagination.pages;
  const currentPage=Math.min(page,totalPages);
  const visible=filtered;
  return <div className="workspace-page">
    <PageHeader title="Platform Overview" actions={<CreateUser onChanged={load} />} />
    <div className="toolbar grid grid-cols-2 sm:flex sm:flex-row sm:flex-wrap sm:items-center"><div className="col-span-2 min-w-0 sm:mr-auto sm:basis-72"><SearchField value={query} onChange={setQuery} label="Search platform" placeholder="Search users or machines…" /></div><SearchSelect className="min-w-0 w-full sm:w-44" label="Filter account role" value={role} onChange={setRole} options={[{value:"all",label:"All roles"},{value:"admin",label:"Administrators"},{value:"user",label:"Members"}]} /><SearchSelect className="min-w-0 w-full sm:w-44" label="Sort accounts" value={sort} onChange={setSort} options={[{value:"name",label:"Name A–Z"},{value:"machines",label:"Most machines"}]} />
      <div className="col-span-2 flex min-w-0 items-center gap-2 sm:contents"><Popover opened={settingsOpen} onChange={setSettingsOpen} withinPortal position="bottom-end" width={360} zIndex={420} shadow="sm" transitionProps={{ duration: 0 }}>
        <Popover.Target>
        <button type="button" aria-expanded={settingsOpen} onClick={() => setSettingsOpen(open => !open)} className="flex h-11 flex-1 cursor-pointer md:h-10 items-center justify-between gap-2 rounded-lg border border-transparent bg-control px-3 text-sm text-foreground sm:flex-none hover:bg-accent/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
          Platform settings
          <IconChevronDown size={14} className="text-muted-foreground" />
        </button>
        </Popover.Target>
        <Popover.Dropdown className="!max-w-[calc(100vw-2rem)] !rounded-xl !border-border !bg-dialog !p-3 !text-foreground shadow-lg">
          <div className="flex items-center justify-between gap-3">
            <div><p className="text-sm font-medium">New signups</p><p className="mt-1 text-[11px] text-muted-foreground">{signup ? signup.configured ? "Custom admin setting" : `Environment default: ${signup.env_default ? "enabled" : "disabled"}` : "Loading setting…"}</p></div>
            <button type="button" role="switch" aria-label="Enable new signups" aria-checked={signup?.signup_enabled ?? false} disabled={!signup || signupBusy} onClick={() => setSignupEnabled(!signup.signup_enabled)} className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 ${signup?.signup_enabled ? "bg-primary" : "bg-muted-foreground/40"}`}><span className={`pointer-events-none block h-5 w-5 rounded-full bg-white shadow-sm transition-transform ${signup?.signup_enabled ? "translate-x-[22px]" : "translate-x-0.5"}`} /></button>
          </div>
          <div className="mt-3 flex items-center justify-between border-t border-border/60 pt-3">
            <p className="min-w-0 pr-2 text-[11px] text-muted-foreground">{signup?.configured ? "Using the saved override" : "Uses SIGNUP_DISABLED on startup"}</p>
            <Button type="button" size="sm" variant="outline" disabled={!signup?.configured || signupBusy} onClick={resetSignup}><IconRefresh size={13} />Reset</Button>
          </div>
          {signupError && <p role="alert" className="mt-2 text-xs text-red-600 dark:text-red-400">{signupError}</p>}
          <div className="mt-3 border-t border-border/60 pt-3">
            <div className="flex items-center justify-between gap-3">
              <div><p className="text-sm font-medium">API documentation</p><p className="mt-1 text-[11px] text-muted-foreground">{docs ? docs.configured ? "Custom admin setting" : `Environment default: ${docs.env_default ? "enabled" : "disabled"}` : "Loading setting…"}</p></div>
              <button type="button" role="switch" aria-label="Enable API documentation" aria-checked={docs?.api_docs_enabled ?? false} disabled={!docs || docsBusy} onClick={() => setDocsEnabled(!docs.api_docs_enabled)} className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 ${docs?.api_docs_enabled ? "bg-primary" : "bg-muted-foreground/40"}`}><span className={`pointer-events-none block h-5 w-5 rounded-full bg-white shadow-sm transition-transform ${docs?.api_docs_enabled ? "translate-x-[22px]" : "translate-x-0.5"}`} /></button>
            </div>
            <div className="mt-3 flex items-center justify-between gap-3">
              <p className="min-w-0 pr-2 text-[11px] text-muted-foreground">Hides /api, Swagger UI, and the OpenAPI JSON</p>
              <Button type="button" size="sm" variant="outline" disabled={!docs?.configured || docsBusy} onClick={resetDocs}><IconRefresh size={13} />Reset</Button>
            </div>
            {docsError && <p role="alert" className="mt-2 text-xs text-red-600 dark:text-red-400">{docsError}</p>}
          </div>
        </Popover.Dropdown>
      </Popover>
      <Button type="button" variant="outline" onClick={load} disabled={loading} aria-label="Refresh platform"><IconRefresh size={15} /><span className="hidden sm:inline">Refresh</span></Button></div></div>
    {error ? <EmptyState icon={IconServer} title="Platform unavailable" description={error} action={<Button onClick={load}>Try again</Button>} /> : loading ? <p role="status" className="p-6 text-xs text-muted-foreground">Loading accounts…</p> : !filtered.length ? <EmptyState icon={IconUsers} title="No matching accounts" description="Try a different name, email, machine, or port." /> : <section aria-label="Platform results" className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-xl bg-surface">
      <div className="data-scroll">
        <div className="hidden lg:block"><Table aria-label="Platform accounts"><TableHeader><TableRow><TableHead className="w-[40%]">Account</TableHead><TableHead>Role</TableHead><TableHead>Machines</TableHead><TableHead>Online</TableHead><TableHead className="w-28"><span className="sr-only">Account actions</span></TableHead></TableRow></TableHeader><TableBody>{visible.map(entry => <AccountRow key={entry.user.id} entry={entry} expanded={expanded === entry.user.id} toggle={() => setExpanded(expanded === entry.user.id ? "" : entry.user.id)} reduced={reduced} onChanged={load} currentEmail={currentUser.username} />)}</TableBody></Table></div>
        <div className="lg:hidden">{visible.map(entry => <div key={entry.user.id} className="border-b border-border/60"><button type="button" aria-label={`View machines for ${entry.user.name || entry.user.email}`} aria-expanded={expanded === entry.user.id} className="flex w-full items-center justify-between gap-3 p-3 text-left hover:bg-accent/40" onClick={() => setExpanded(expanded === entry.user.id ? "" : entry.user.id)}><div className="min-w-0"><p className="truncate text-sm font-medium">{entry.user.name}</p><p className="mt-1 truncate text-[11px] text-muted-foreground">{entry.user.email}</p><p className="mt-1 text-[11px] text-muted-foreground">{entry.user.role === "admin" ? "Admin" : "Member"} · {entry.machine_count} machines</p></div><IconChevronDown size={16} className={`shrink-0 transition-transform ${expanded === entry.user.id ? "rotate-180" : ""}`} /></button><div className="flex items-center justify-between px-3 pb-2"><span className="text-[11px] text-muted-foreground">{entry.user.deleting ? "Deletion pending" : "Account management"}</span><DeleteUser entry={entry} onChanged={load} currentEmail={currentUser.username}/></div>{expanded === entry.user.id && <Fleet account={entry.user.id} />}</div>)}</div>
      </div>
      <ResultsPagination count={inventory.pagination.total} noun="Accounts" page={currentPage} pages={totalPages} pageSize={pageSize} onPage={setPage} onPageSize={setPageSize} />
    </section>}
  </div>;
}

function AccountRow({ entry, expanded, toggle, reduced, onChanged, currentEmail }) {
  const online = entry.online_count;
  return <>
    <TableRow className="cursor-pointer hover:bg-accent/30 focus-visible:bg-accent/40" aria-expanded={expanded} tabIndex={0} onClick={toggle} onKeyDown={event => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); toggle(); } }}>
      <TableCell>
        <div className="flex items-center gap-3">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-medium">{(entry.user.name || entry.user.email || "U").slice(0, 1)}</span>
          <div className="min-w-0"><p className="truncate font-medium">{entry.user.name}</p><p className="mt-0.5 truncate text-[11px] text-muted-foreground">{entry.user.email}</p>{entry.user.deleting && <span className="mt-1 inline-block text-[10px] font-medium text-amber-700 dark:text-amber-400">Cleanup pending</span>}</div>
        </div>
      </TableCell>
      <TableCell>{entry.user.role === "admin" ? "Administrator" : "Member"}</TableCell>
      <TableCell>{entry.machine_count}</TableCell>
      <TableCell><span className={online ? "text-emerald-700 dark:text-emerald-400" : "text-muted-foreground"}>{online}</span></TableCell>
      <TableCell className="!pl-2 !pr-4" onClick={event=>event.stopPropagation()} onKeyDown={event=>event.stopPropagation()}><div className="flex items-center justify-end gap-2"><DeleteUser entry={entry} onChanged={onChanged} currentEmail={currentEmail}/><button type="button" aria-label={`View machines for ${entry.user.name || entry.user.email}`} aria-expanded={expanded} onClick={toggle} className="flex h-9 w-8 shrink-0 items-center justify-center rounded-lg text-muted-foreground hover:bg-accent"><IconChevronDown size={16} className={`transition-transform ${expanded ? "rotate-180" : ""}`}/></button></div></TableCell>
    </TableRow>
    {expanded && <TableRow className="hover:bg-transparent"><TableCell colSpan={5} className="!p-0"><motion.div initial={reduced ? false : { opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.15 }}><Fleet account={entry.user.id} /></motion.div></TableCell></TableRow>}
  </>;
}

function Fleet({ account }) {
  const [query,setQuery]=useState("");
  const [page,setPage]=useState(1);
  const inventory=useInventoryPage("machines",{account,q:query,page,page_size:10,options:true});
  useEffect(()=>setPage(1),[query,account]);
  useEffect(()=>{if(!inventory.loading && page>inventory.pagination.pages)setPage(inventory.pagination.pages);},[page,inventory.loading,inventory.pagination.pages]);
  return <div className="min-w-0 bg-surface">
    <div className="px-4 py-3"><SearchField label="Search account machines" value={query} onChange={setQuery} placeholder="Find a machine or port…" /></div>
    {inventory.loading && <p role="status" className="px-5 py-4 text-xs text-muted-foreground">Loading machines…</p>}
    {inventory.error && <p role="alert" className="px-5 py-4 text-xs text-red-600 dark:text-red-400">{inventory.error}</p>}
    {!inventory.loading && !inventory.rows.length && <p className="px-5 py-4 text-xs text-muted-foreground">{query ? "No matching machines." : "No registered machines."}</p>}
    {inventory.rows.map(machine=><FleetMachine key={machine._id} account={account} machine={machine} />)}
    <ResultsPagination count={inventory.pagination.total} noun="Machines" page={page} pages={inventory.pagination.pages} pageSize={10} onPage={setPage} />
  </div>;
}
function FleetMachine({account,machine}) {
  const [open,setOpen]=useState(false);
  return <details className="group min-w-0 border-b border-border/60 last:border-0" onToggle={event=>{if(event.target===event.currentTarget)setOpen(event.currentTarget.open);}}>
    <summary className="flex min-w-0 cursor-pointer list-none items-center justify-between gap-3 px-5 py-3.5 hover:bg-accent/40 sm:px-6 [&::-webkit-details-marker]:hidden">
      <div className="flex min-w-0 items-center gap-3"><span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-muted/60 text-muted-foreground"><IconServer size={16}/></span><div className="min-w-0"><p className="break-words text-sm font-medium">{machine.name}</p><p className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{machine.hostname || "Awaiting client"}</p></div></div>
      <div className="flex shrink-0 items-center gap-2 text-[11px] text-muted-foreground"><span className={`h-1.5 w-1.5 rounded-full ${machine.connection_status === "online" ? "bg-emerald-500" : "bg-zinc-500"}`} /><span>{machine.connection_status === "online" ? "Online" : machine.connection_status === "disabled" ? "Disabled" : machine.connection_status === "auth_required" ? "Authentication required" : "Offline"}</span><IconChevronDown size={14} className="ml-1 transition-transform group-open:rotate-180" /></div>
    </summary>
    {open && <FleetPorts account={account} machine={machine._id} />}
  </details>;
}
function FleetPorts({account,machine}) {
  const [page,setPage]=useState(1);
  const [query,setQuery]=useState("");
  const inventory=useInventoryPage("connections",{account,machine,q:query,page,page_size:10,options:true});
  useEffect(()=>setPage(1),[query]);
  useEffect(()=>{if(!inventory.loading && page>inventory.pagination.pages)setPage(inventory.pagination.pages);},[page,inventory.loading,inventory.pagination.pages]);
  return <div className="min-w-0">
    <div className="px-5 py-3"><SearchField label="Search account machine ports" value={query} onChange={setQuery} placeholder="Find a service or port…" /></div>
    {inventory.loading && <p role="status" className="px-5 py-3 text-xs text-muted-foreground">Loading ports…</p>}
    {inventory.error && <p role="alert" className="px-5 py-3 text-xs text-red-600">{inventory.error}</p>}
    {inventory.rows.map(port=><div key={port._id} className="grid min-w-0 grid-cols-[minmax(0,1fr)_auto] items-start gap-x-4 gap-y-2 border-t border-border/40 px-5 py-3 text-xs hover:bg-accent/20 sm:grid-cols-[minmax(0,1fr)_minmax(0,1.8fr)_auto] sm:px-6">
      <span className="min-w-0 break-words font-medium leading-6">{port.service_name || "Unnamed service"}</span>
      <span className="col-span-2 row-start-2 min-w-0 break-all font-mono text-[11px] leading-6 text-muted-foreground sm:col-span-1 sm:col-start-2 sm:row-start-1">{externalEndpoint(port)} → {internalEndpoint(port)}</span>
      <span className={`col-start-2 row-start-1 justify-self-end whitespace-nowrap rounded-full px-2 py-1 text-[10px] font-medium sm:col-start-3 ${port.enabled ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400" : "bg-zinc-500/10 text-zinc-600 dark:text-zinc-400"}`}>{port.enabled ? "Enabled" : "Disabled"}</span>
    </div>)}
    {!inventory.loading && !inventory.rows.length && <p className="border-t border-border/40 px-5 py-3 text-xs text-muted-foreground">{query ? "No matching ports." : "No mapped ports."}</p>}
    <ResultsPagination count={inventory.pagination.total} noun="Ports" page={page} pages={inventory.pagination.pages} pageSize={10} onPage={setPage} />
  </div>;
}
