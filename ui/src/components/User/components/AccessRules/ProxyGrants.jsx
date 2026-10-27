import { useCallback, useEffect, useState } from "react";
import { Switch } from "@mantine/core";
import { IconChevronRight, IconPlus, IconWorld, IconCopy, IconCheck } from "@tabler/icons-react";
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
  const [grants, setGrants] = useState([]);
  const [gatewayLanAllowed,setGatewayLanAllowed]=useState(false);
  const [editing, setEditing] = useState(null);
  const [removing, setRemoving] = useState(false);
  const [copied, setCopied] = useState(false);
  const [form, setForm] = useState(empty);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const load = useCallback(async signal => {
    try {
      const result = await axios.get(`${API}/proxy-grants`, { params, signal });
      setGrants(result.data.data || []);
      setGatewayLanAllowed(result.data.can_allow_gateway_lan===true);
      setError("");
    } catch (cause) { if (!axios.isCancel(cause)) setError(errorText(cause)); }
  }, [params]);
  useEffect(() => {
    setGrants([]); setEditing(null);
    const controller = new AbortController(); load(controller.signal);
    return () => controller.abort();
  }, [load]);
  const canEdit=manage && !(form.target_kind==="gateway" && form.allow_lan && !gatewayLanAllowed);
  const machines = data.machines.map(machine => ({ value: machine._id, label: machine.name }));
  const names = new Map(machines.map(machine => [machine.value, machine.label]));
  function open(grant) {
    setForm(grant ? { ...empty(), ...grant } : empty());
    setEditing(grant?._id || "new"); setRemoving(false); setCopied(false); setError("");
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
  return <section className="mt-3 rounded-xl bg-surface p-4">
    <div className="mb-4 flex flex-wrap items-start justify-between gap-3"><div><h2 className="text-base font-semibold">Application proxies</h2><p className="mt-1 max-w-3xl text-sm leading-6 text-muted-foreground">Authorize machines to use a gateway or peer as an authenticated HTTP/SOCKS5 proxy. A grant does not start a listener; clients start their local proxy when needed.</p></div>{manage && <Button onClick={() => open(null)}><IconPlus size={16} />Proxy grant</Button>}</div>
    {error && !editing && <p role="alert" className="mb-3 text-sm text-red-500">{error}</p>}
    {!grants.length && <p className="py-5 text-center text-sm text-muted-foreground">No shared proxies authorized.</p>}
    <div className="space-y-2">{grants.map(grant => <button type="button" key={grant._id} onClick={() => open(grant)} className="flex w-full items-center gap-3 rounded-lg border border-border p-3 text-left hover:bg-accent/30"><IconWorld size={18} className="shrink-0 text-primary" /><div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{grant.name}</p><p className="mt-1 truncate text-xs text-muted-foreground">{grant.target_kind === "gateway" ? "Gateway" : names.get(grant.target_machine_id) || "Unavailable machine"} · {grant.client_machine_ids.length} authorized machines · {grant.enabled ? "Enabled" : "Disabled"}</p></div><IconChevronRight size={16} className="shrink-0 text-muted-foreground" /></button>)}</div>
    <Dialog opened={Boolean(editing)} onClose={() => { if (!busy) setEditing(null); }} title={editing === "new" ? "Create proxy grant" : "Proxy grant"} size="lg">
      {error && <p role="alert" className="mb-3 text-sm text-red-500">{error}</p>}
      <form onSubmit={save} className="space-y-3"><fieldset disabled={busy || !canEdit} className="space-y-3">
        <Input aria-label="Proxy grant name" placeholder="Proxy grant name" required maxLength={80} value={form.name} onChange={event => setForm(current => ({ ...current, name: event.target.value }))} />
        <SearchSelect label="Proxy runs through" value={form.target_kind === "gateway" ? "gateway" : form.target_machine_id} options={[{ value: "gateway", label: "PortHub gateway" }, ...machines]} onChange={value => setForm(current => ({ ...current, target_kind: value === "gateway" ? "gateway" : "machine", target_machine_id: value === "gateway" ? "" : value, allow_lan: value === "gateway" && !gatewayLanAllowed ? false : current.allow_lan, client_machine_ids: current.client_machine_ids.filter(id => id !== value) }))} />
        <SearchMultiSelect label="Machines allowed to use this proxy" placeholder="Search machines…" options={machines.filter(machine => machine.value !== form.target_machine_id)} value={form.client_machine_ids} onChange={client_machine_ids => setForm(current => ({ ...current, client_machine_ids }))} />
        <div className="rounded-lg border border-border p-3"><Switch label="Allow access to the target’s LAN" disabled={form.target_kind==="gateway" && !gatewayLanAllowed} checked={form.allow_lan} onChange={event => { const allow_lan = event.currentTarget.checked; setForm(current => ({ ...current, allow_lan })); }} /><p className="mt-2 text-xs text-muted-foreground">Off by default. Enabling this grants the selected clients access to private destinations reachable by this proxy target. {form.target_kind==="gateway" && "Gateway LAN access requires a platform administrator."}</p></div>
        <Switch label="Enabled" checked={form.enabled} onChange={event => { const enabled = event.currentTarget.checked; setForm(current => ({ ...current, enabled })); }} />
      </fieldset>
      {editing && editing !== "new" && <div className="space-y-2"><div className="flex min-w-0 items-start gap-3 rounded-lg border border-border bg-control/40 p-3"><pre className="m-0 min-w-0 flex-1 whitespace-pre-wrap break-all py-1 font-mono text-xs leading-6"><code>{`porthub proxy start --via ${editing}`}</code></pre><Button type="button" variant="outline" size="sm" aria-label="Copy proxy command" onClick={async () => { try { await copyText(`porthub proxy start --via ${editing}`); setCopied(true); } catch { setError("Could not copy the command."); } }}>{copied ? <IconCheck size={14} /> : <IconCopy size={14} />}{copied ? "Copied" : "Copy"}</Button></div><p className="text-xs leading-5 text-muted-foreground">Run on an authorized machine. Add -d to run in the background. The CLI checks permission before starting and prints the local proxy address and private credential-file location.</p></div>}
      <div className="flex flex-wrap justify-end gap-2">{manage && editing !== "new" && <Button type="button" variant="outline" disabled={busy} onClick={() => setRemoving(true)}>Delete grant</Button>}<Button type="button" variant="outline" disabled={busy} onClick={() => setEditing(null)}>Close</Button>{canEdit && <Button disabled={busy || !form.client_machine_ids.length}>Save grant</Button>}</div></form>
    </Dialog>
    <Dialog opened={removing} onClose={() => { if (!busy) setRemoving(false); }} title="Delete proxy grant?" size="sm"><p className="mb-4 text-sm text-muted-foreground">The selected machines will lose permission to use this shared proxy.</p><div className="flex justify-end gap-2"><Button variant="outline" disabled={busy} onClick={() => setRemoving(false)}>Cancel</Button><Button disabled={busy} onClick={remove}>Delete grant</Button></div></Dialog>
  </section>;
}
