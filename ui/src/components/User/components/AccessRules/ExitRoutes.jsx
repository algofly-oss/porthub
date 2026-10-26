import { useState } from "react";
import axios from "axios";
import { IconPlus, IconRoute, IconTrash, IconEdit } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import SearchSelect from "@/components/ui/search-select";
import { Input } from "@/components/ui/input";
import { Dialog } from "@/components/ui/dialog";
import { API, errorText } from "./shared";

function selected(selectors = []) {
  return new Set(selectors.map(({ kind, id }) => `${kind}:${id}`));
}

export default function ExitRoutes({ data, manage, params, onSaved }) {
  const [editing, setEditing] = useState(null);
  const [busy, setBusy] = useState(false);
  const [removing, setRemoving] = useState(null);
  const [error, setError] = useState("");
  const [form, setForm] = useState({ name: "", routing: new Set(), clients: new Set(), enabled: true, selection: "sticky" });

  function open(route = null) {
    setEditing(route?._id || "new");
    setForm({
      name: route?.name || "",
      routing: selected(route?.routing_selectors),
      clients: selected(route?.distribution_selectors),
      enabled: route?.enabled ?? true,
      selection: route?.selection || "sticky",
    });
    setError("");
  }

  function toggle(field, key) {
    setForm(current => {
      const next = new Set(current[field]);
      next.has(key) ? next.delete(key) : next.add(key);
      return { ...current, [field]: next };
    });
  }

  async function save(event) {
    event.preventDefault();
    const selectors = values => [...values].map(value => {
      const [kind, id] = value.split(":");
      return { kind, id };
    });
    setBusy(true);
    try {
      const body = { name: form.name.trim(), routing_selectors: selectors(form.routing), distribution_selectors: selectors(form.clients), enabled: form.enabled, selection: form.selection };
      if (editing === "new") await axios.post(`${API}/exit-nodes`, body, { params });
      else await axios.put(`${API}/exit-nodes/${editing}`, body, { params });
      setEditing(null);
      await onSaved();
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy(false);
    }
  }

  async function remove(route) {
    setBusy(true);
    try {
      await axios.delete(`${API}/exit-nodes/${route._id}`, { params });
      setRemoving(null);
      await onSaved();
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy(false);
    }
  }

  const selectors = (field, title) => (
    <fieldset className="rounded-lg border border-border p-3">
      <legend className="px-1 text-sm font-medium">{title}</legend>
      <div className="max-h-44 space-y-1 overflow-y-auto">
        {data.groups.map(group => {
          const key = `group:${group._id}`;
          return <label key={key} className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-sm hover:bg-accent/40"><input type="checkbox" checked={form[field].has(key)} onChange={() => toggle(field, key)} />Group · {group.name}</label>;
        })}
        {data.machines.map(machine => {
          const key = `machine:${machine._id}`;
          return <label key={key} className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-sm hover:bg-accent/40"><input type="checkbox" checked={form[field].has(key)} onChange={() => toggle(field, key)} />Machine · {machine.name}</label>;
        })}
        {!data.groups.length && !data.machines.length && <p className="text-xs text-muted-foreground">No groups or machines available.</p>}
      </div>
    </fieldset>
  );

  return (
    <section className="rounded-xl bg-surface p-4">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold">Exit nodes</h2>
          <p className="mt-1 max-w-3xl text-sm leading-6 text-muted-foreground">Send a selected machine’s internet traffic through a routing peer. The peer must be online and able to forward and masquerade traffic.</p>
        </div>
        {manage && <Button onClick={() => open()} disabled={busy}><IconPlus size={16} />Exit node</Button>}
      </div>
      <p className="mb-4 rounded-lg bg-amber-500/10 p-3 text-sm text-amber-800 dark:text-amber-200">Exit routing currently requires compatible Linux agents and handles IPv4 traffic. New IPv6 internet connections are blocked while an exit is active so applications can use IPv4. Local IPv6 and established connections remain available.</p>
      {error && !editing && !removing && <p role="alert" className="mb-3 text-sm text-red-500">{error}</p>}
      {!data.exit_nodes?.length && <p className="py-5 text-center text-sm text-muted-foreground">No exit nodes configured.</p>}
      <div className="space-y-2">
        {data.exit_nodes?.map(route => <article key={route._id} className="flex flex-wrap items-center gap-3 rounded-lg border border-border p-3">
          <IconRoute size={18} className="text-primary" />
          <div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{route.name}</p><p className="mt-1 text-xs text-muted-foreground">{route.enabled ? "Enabled" : "Paused"} · {route.routing_selectors.length} routing selections · {route.distribution_selectors.length} client selections</p></div>
          {manage && <><Button size="icon" variant="ghost" aria-label={`Edit ${route.name}`} onClick={() => open(route)}><IconEdit size={16} /></Button><Button size="icon" variant="ghost" aria-label={`Delete ${route.name}`} onClick={() => { setError(""); setRemoving(route); }}><IconTrash size={16} /></Button></>}
        </article>)}
      </div>
      <Dialog opened={Boolean(editing)} onClose={() => !busy && setEditing(null)} title={editing === "new" ? "Create exit node" : "Edit exit node"} size="lg">
        {error && <p role="alert" className="mb-3 text-sm text-red-500">{error}</p>}
        <form className="space-y-3" onSubmit={save}>
          <Input aria-label="Exit node name" placeholder="Exit node name" maxLength={80} required value={form.name} onChange={event => setForm(current => ({ ...current, name: event.target.value }))} />
          <div className="grid gap-3 lg:grid-cols-2">{selectors("routing", "Routing peers")}{selectors("clients", "Machines using this exit node")}</div>
          <div><p className="mb-2 text-sm font-medium">Exit selection</p><SearchSelect label="Exit selection" value={form.selection} onChange={selection => setForm(current => ({ ...current, selection }))} options={[{value:"sticky",label:"Sticky · stable client hash (default)"},{value:"round_robin",label:"Round robin · alternate new connections"},{value:"random",label:"Random · choose per new connection"}]} /><p className="mt-2 text-xs text-muted-foreground">Sticky keeps new connections on the same available exit for each client. Round robin alternates exits; random chooses independently for each new connection. Established connections keep their selected exit. Equal connection counts do not guarantee equal bandwidth.</p></div>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={form.enabled} onChange={event => setForm(current => ({ ...current, enabled: event.target.checked }))} />Enabled</label>
          <div className="flex justify-end gap-2"><Button type="button" variant="outline" disabled={busy} onClick={() => setEditing(null)}>Cancel</Button><Button type="submit" disabled={busy}>Save exit node</Button></div>
        </form>
      </Dialog>
      <Dialog opened={Boolean(removing)} onClose={() => !busy && setRemoving(null)} title="Remove exit node">
        <p className="text-sm leading-6 text-muted-foreground">Remove {removing?.name}? Machines assigned to this exit node will lose this route.</p>
        {error && <p role="alert" className="mt-3 text-sm text-red-500">{error}</p>}
        <div className="mt-5 flex justify-end gap-2">
          <Button variant="ghost" disabled={busy} onClick={() => setRemoving(null)}>Cancel</Button>
          <Button variant="destructive" disabled={busy} onClick={() => remove(removing)}>Remove</Button>
        </div>
      </Dialog>
    </section>
  );
}
