import useInventoryPage from "@/shared/hooks/useInventoryPage";
import InventorySelect from "@/components/ui/inventory-select";
import InventoryMultiSelect from "@/components/ui/inventory-multi-select";
import ResultsPagination from "@/components/ui/results-pagination";
import { SearchField } from "@/components/ui/workspace";
import { useCallback, useEffect, useState } from "react";
import { Switch } from "@mantine/core";
import { IconChevronDown, IconChevronRight, IconPlus, IconWorld, IconCopy, IconCheck } from "@tabler/icons-react";
import axios from "axios";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import SearchSelect from "@/components/ui/search-select";
import SearchMultiSelect from "@/components/ui/search-multi-select";
import { copyText } from "@/shared/utils/clipboard";
import { API, errorText } from "./shared";

const empty = () => ({ name: "", target_kind: "gateway", target_machine_id: "", client_machine_ids: [], enabled: true, allow_lan: false });
export default function ProxyGrants({ data, manage, params }) {
  const [editing, setEditing] = useState(null);
  const [removing, setRemoving] = useState(false);
  const [copied, setCopied] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [form, setForm] = useState(empty);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [query,setQuery]=useState(""),[page,setPage]=useState(1);
  const inventory=useInventoryPage("access-proxy-grants",{...params,q:query,page,page_size:25},{enabled:expanded || !!editing});
  const grants=inventory.rows;
  const gatewayLanAllowed=inventory.data?.can_allow_gateway_lan===true;
  const load=inventory.refresh;
  useEffect(()=>setPage(1),[query]);
  useEffect(()=>{if(!inventory.loading && page>inventory.pagination.pages)setPage(inventory.pagination.pages);},[page,inventory.loading,inventory.pagination.pages]);
  const targetIds=[...new Set(grants.map(grant=>grant.target_machine_id).filter(Boolean))].sort().join(",");
  const targets=useInventoryPage("access-machines",{...params,ids:targetIds,page_size:100},{enabled:!!targetIds && expanded});
  const names=new Map(targets.rows.map(machine=>[machine._id,machine.name]));
  const canEdit=manage && !(form.target_kind==="gateway" && form.allow_lan && !gatewayLanAllowed);
  function open(grant) {
    setForm(grant ? { ...empty(), ...grant } : empty());
    setEditing(grant?._id || "new"); setRemoving(false); setCopied(false); setError(""); setExpanded(true);
  }
  async function save(event) {
    event.preventDefault(); setBusy(true);
    try {
      const payload = { ...form, name: form.name.trim() };
      if (editing === "new") await axios.post(`${API}/proxy-grants`, payload, { params });
      else await axios.put(`${API}/proxy-grants/${editing}`, payload, { params });
      setEditing(null); await load();
    } catch (cause) { setError(errorText(cause)); }
    finally { setBusy(false); }
  }
  async function remove() {
    setBusy(true);
    try {
      await axios.delete(`${API}/proxy-grants/${editing}`, { params });
      setRemoving(false); setEditing(null); await load();
    } catch (cause) { setError(errorText(cause)); }
    finally { setBusy(false); }
  }
  return <section className="mt-3 max-h-[40dvh] shrink-0 overflow-auto rounded-xl border border-border bg-surface px-3 py-2">
    <div className="flex min-h-10 items-center gap-2">
      <button type="button" aria-expanded={expanded} onClick={() => setExpanded(value => !value)} className="flex min-w-0 flex-1 items-center gap-2 rounded-md text-left hover:text-foreground">
        {expanded ? <IconChevronDown size={16} className="shrink-0 text-muted-foreground" /> : <IconChevronRight size={16} className="shrink-0 text-muted-foreground" />}
        <IconWorld size={17} className="shrink-0 text-primary" />
        <span className="truncate text-sm font-semibold">Application proxies</span>
        <span className="rounded-full bg-control px-2 py-0.5 text-xs text-muted-foreground">{inventory.data ? inventory.pagination.total : "…"}</span>
      </button>
      {manage && <Button size="sm" variant="outline" onClick={() => open(null)}><IconPlus size={15} />Add</Button>}
    </div>
    {error && !editing && <p role="alert" className="mt-2 text-sm text-red-500">{error}</p>}
    {expanded && <div className="pb-2 pt-2">
      <p className="mb-2 text-xs text-muted-foreground">Shared proxy permissions. No listener starts until an authorized client requests one.</p>
      <SearchField label="Search proxy grants" value={query} onChange={setQuery} placeholder="Find a proxy grant…"/>
      {inventory.loading && <p role="status" className="py-3 text-sm text-muted-foreground">Loading proxy grants…</p>}
      {inventory.error && <p role="alert" className="py-3 text-sm text-red-600">{inventory.error}</p>}
      {!inventory.loading && !grants.length && <p className="py-3 text-sm text-muted-foreground">No shared proxies authorized.</p>}
      <div className="space-y-1">{grants.map(grant => <button type="button" key={grant._id} onClick={() => open(grant)} className="flex w-full items-center gap-3 rounded-lg border border-border px-3 py-2 text-left hover:bg-accent/30"><IconWorld size={17} className="shrink-0 text-primary" /><div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{grant.name}</p><p className="mt-0.5 truncate text-xs text-muted-foreground">{grant.target_kind === "gateway" ? "Gateway" : names.get(grant.target_machine_id) || "Unavailable machine"} · {grant.client_machine_ids.length} machines · {grant.enabled ? "Enabled" : "Disabled"}</p></div><IconChevronRight size={16} className="shrink-0 text-muted-foreground" /></button>)}</div>
      <ResultsPagination count={inventory.pagination.total} noun="Proxy grants" page={page} pages={inventory.pagination.pages} pageSize={25} onPage={setPage}/>
    </div>}
    <Dialog opened={Boolean(editing)} onClose={() => { if (!busy) setEditing(null); }} title={editing === "new" ? "Create proxy grant" : "Proxy grant"} size="lg">
      {error && <p role="alert" className="mb-3 text-sm text-red-500">{error}</p>}
      <form onSubmit={save} className="space-y-3"><fieldset disabled={busy || !canEdit} className="space-y-3">
        <Input aria-label="Proxy grant name" placeholder="Proxy grant name" required maxLength={80} value={form.name} onChange={event => setForm(current => ({ ...current, name: event.target.value }))} />
        <InventorySelect kind="access-machines" filters={params} label="Proxy runs through" value={form.target_kind === "gateway" ? "gateway" : form.target_machine_id} extraOptions={[{value:"gateway",label:"PortHub gateway"}]} onChange={value => setForm(current => ({ ...current, target_kind: value === "gateway" ? "gateway" : "machine", target_machine_id: value === "gateway" ? "" : value, allow_lan: value === "gateway" && !gatewayLanAllowed ? false : current.allow_lan, client_machine_ids: current.client_machine_ids.filter(id => id !== value) }))} />
        <InventoryMultiSelect kind="access-machines" filters={params} label="Machines allowed to use this proxy" placeholder="Search machines…" value={form.client_machine_ids} onChange={ids => setForm(current => ({ ...current, client_machine_ids:ids.filter(id=>id!==current.target_machine_id) }))} />
        <div className="rounded-lg border border-border p-3"><Switch label="Allow access to the target’s LAN" disabled={form.target_kind==="gateway" && !gatewayLanAllowed} checked={form.allow_lan} onChange={event => { const allow_lan = event.currentTarget.checked; setForm(current => ({ ...current, allow_lan })); }} /><p className="mt-2 text-xs text-muted-foreground">Off by default. Enabling this grants the selected clients access to private destinations reachable by this proxy target. {form.target_kind==="gateway" && "Gateway LAN access requires a platform administrator."}</p></div>
        <Switch label="Enabled" checked={form.enabled} onChange={event => { const enabled = event.currentTarget.checked; setForm(current => ({ ...current, enabled })); }} />
      </fieldset>
      {editing && editing !== "new" && <div className="space-y-2"><div className="flex min-w-0 items-start gap-3 rounded-lg border border-border bg-control/40 p-3"><pre className="m-0 min-w-0 flex-1 whitespace-pre-wrap break-all py-1 font-mono text-xs leading-6"><code>{`porthub proxy start --via ${editing}`}</code></pre><Button type="button" variant="outline" size="sm" aria-label="Copy proxy command" onClick={async () => { try { await copyText(`porthub proxy start --via ${editing}`); setCopied(true); } catch { setError("Could not copy the command."); } }}>{copied ? <IconCheck size={14} /> : <IconCopy size={14} />}{copied ? "Copied" : "Copy"}</Button></div><p className="text-xs leading-5 text-muted-foreground">Run on an authorized machine. Add -d to run in the background. The CLI checks permission before starting and prints the local proxy address and private credential-file location.</p></div>}
      <div className="flex flex-wrap justify-end gap-2">{manage && editing !== "new" && <Button type="button" variant="outline" disabled={busy} onClick={() => setRemoving(true)}>Delete grant</Button>}<Button type="button" variant="outline" disabled={busy} onClick={() => setEditing(null)}>Close</Button>{canEdit && <Button disabled={busy || !form.client_machine_ids.length}>Save grant</Button>}</div></form>
    </Dialog>
    <Dialog opened={removing} onClose={() => { if (!busy) setRemoving(false); }} title="Delete proxy grant?" size="sm"><p className="mb-4 text-sm text-muted-foreground">The selected machines will lose permission to use this shared proxy.</p><div className="flex justify-end gap-2"><Button variant="outline" disabled={busy} onClick={() => setRemoving(false)}>Cancel</Button><Button disabled={busy} onClick={remove}>Delete grant</Button></div></Dialog>
  </section>;
}
