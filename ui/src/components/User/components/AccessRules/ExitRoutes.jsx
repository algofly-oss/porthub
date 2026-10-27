import { Switch } from "@mantine/core";
import SearchMultiSelect from "@/components/ui/search-multi-select";
import { useState } from "react";
import axios from "axios";
import { IconPlus, IconRoute, IconTrash, IconArrowRight, IconChevronRight } from "@tabler/icons-react";
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
  const [form, setForm] = useState({ name: "", routing: new Set(), clients: new Set(), enabled: true, selection: "sticky", allow_direct_fallback: false });

  function open(route = null) {
    setEditing(route?._id || "new");
    setForm({
      name: route?.name || "",
      routing: selected(route?.routing_selectors),
      clients: selected(route?.distribution_selectors),
      enabled: route?.enabled ?? true,
      selection: route?.selection || "sticky",
      allow_direct_fallback: route?.allow_direct_fallback === true,
    });
    setError("");
  }

  async function save(event) {
    event.preventDefault();
    const selectors = values => [...values].map(value => {
      const [kind, id] = value.split(":");
      return { kind, id };
    });
    setBusy(true);
    try {
      const body = { name: form.name.trim(), routing_selectors: selectors(form.routing), distribution_selectors: selectors(form.clients), enabled: form.enabled, selection: form.selection, allow_direct_fallback: form.allow_direct_fallback };
      if (editing === "new") await axios.post(`${API}/exit-nodes`, body, { params });
      else await axios.put(`${API}/exit-nodes/${editing}`, body, { params });
      setEditing(null);
      await onSaved();
    } catch (cause) { setError(errorText(cause)); }
    finally { setBusy(false); }
  }

  async function toggleEnabled(route) {
    setBusy(true); setError("");
    try {
      const { name, routing_selectors, distribution_selectors, selection } = route;
      await axios.put(`${API}/exit-nodes/${route._id}`, { name, routing_selectors, distribution_selectors, selection: selection || "sticky", enabled: !route.enabled, allow_direct_fallback: route.allow_direct_fallback === true }, { params });
      await onSaved();
    } catch (cause) { setError(errorText(cause)); }
    finally { setBusy(false); }
  }

  async function remove(route) {
    setBusy(true);
    try {
      await axios.delete(`${API}/exit-nodes/${route._id}`, { params });
      setRemoving(null); await onSaved();
    } catch (cause) { setError(errorText(cause)); }
    finally { setBusy(false); }
  }

  const options = [
    ...data.groups.map(group => ({ value: `group:${group._id}`, label: group.name, group: "Groups" })),
    ...data.machines.map(machine => ({ value: `machine:${machine._id}`, label: machine.name, group: "Machines" })),
  ];
  const selectors = (field, title) => <SearchMultiSelect label={title} placeholder="Search machines or groups…"
    value={[...form[field]]} options={options} disabled={busy || !manage}
    onChange={values => setForm(current => ({ ...current, [field]: new Set(values) }))} />;

  const names = new Map(options.map(option => [option.value, `${option.group === "Groups" ? "Group: " : ""}${option.label}`]));
  const entityNames = selectors => selectors.map(item => names.get(`${item.kind}:${item.id}`) || "Unavailable selection").join(", ");
  return (
    <section className="rounded-xl bg-surface p-4">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold">Exit nodes</h2>
          <p className="mt-1 max-w-3xl text-sm leading-6 text-muted-foreground">Send a selected machine’s internet traffic through a routing peer. The peer must be online and able to forward and masquerade traffic.</p>
        </div>
        {manage && <Button onClick={() => open()} disabled={busy}><IconPlus size={16} />Exit node</Button>}
      </div>
      {error && !editing && !removing && <p role="alert" className="mb-3 text-sm text-red-500">{error}</p>}
      {!data.exit_nodes?.length && <p className="py-5 text-center text-sm text-muted-foreground">No exit nodes configured.</p>}
      <div className="space-y-2">
        {data.exit_nodes?.map(route => <article key={route._id} tabIndex={0} aria-label={`${manage ? "Edit" : "View"} exit node ${route.name}`}
          onClick={event => { if (!busy && !event.target.closest("button,input,label")) open(route); }}
          onKeyDown={event => { if (!busy && event.target === event.currentTarget && ["Enter", " "].includes(event.key)) { event.preventDefault(); open(route); } }}
          className="flex cursor-pointer flex-wrap items-center gap-3 rounded-lg border border-border p-3 hover:bg-accent/30">
          <IconRoute size={18} className="shrink-0 text-primary" />
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium">{route.name}</p>
            <p className="mt-1 flex min-w-0 items-center gap-2 text-xs text-muted-foreground" title={`${entityNames(route.distribution_selectors)} → ${entityNames(route.routing_selectors)}`}>
              <span className="min-w-0 truncate">{entityNames(route.distribution_selectors)}</span><IconArrowRight size={15} className="shrink-0 text-primary" aria-label="via" /><span className="min-w-0 truncate">{entityNames(route.routing_selectors)}</span>
            </p>
            <p className="mt-1 text-xs text-muted-foreground">All exits offline: {route.allow_direct_fallback ? "Use normal internet" : "Block traffic"}</p>
          </div>
          <span onClick={event => event.stopPropagation()}><Switch aria-label={`Enable exit node ${route.name}`} checked={route.enabled} disabled={busy || !manage} onChange={() => toggleEnabled(route)} /></span>
          {manage && <Button size="icon" variant="ghost" disabled={busy} aria-label={`Delete ${route.name}`} onClick={() => { setError(""); setRemoving(route); }}><IconTrash size={16} /></Button>}
          <IconChevronRight size={17} className="shrink-0 text-muted-foreground" aria-hidden="true" />
        </article>)}
      </div>
      <Dialog opened={Boolean(editing)} onClose={() => !busy && setEditing(null)} title={editing === "new" ? "Create exit node" : manage ? "Edit exit node" : "Exit node"} size="lg">
        {error && <p role="alert" className="mb-3 text-sm text-red-500">{error}</p>}
        <form className="space-y-3" onSubmit={save}>
          <fieldset disabled={busy || !manage} className="space-y-3">
          <Input aria-label="Exit node name" placeholder="Exit node name" maxLength={80} required value={form.name} onChange={event => setForm(current => ({ ...current, name: event.target.value }))} />
          <div className="grid gap-3 lg:grid-cols-2">{selectors("routing", "Routing peers")}{selectors("clients", "Machines using this exit node")}</div>
          <div><p className="mb-2 text-sm font-medium">Exit selection</p><SearchSelect label="Exit selection" value={form.selection} onChange={selection => setForm(current => ({ ...current, selection }))} options={[{value:"sticky",label:"Sticky · stable client hash (default)"},{value:"round_robin",label:"Round robin · alternate new connections"},{value:"random",label:"Random · choose per new connection"}]} /><p className="mt-2 text-xs text-muted-foreground">Sticky keeps new connections on the same available exit for each client. Round robin alternates exits; random chooses independently for each new connection. Established connections keep their selected exit. Equal connection counts do not guarantee equal bandwidth.</p></div>
          <div className="rounded-lg border border-border p-3">
            <Switch label="Use normal internet if all exits are offline" checked={form.allow_direct_fallback} disabled={busy}
              onChange={event => { const checked = event.currentTarget.checked; setForm(current => ({ ...current, allow_direct_fallback: checked })); }} />
            <p className="mt-2 text-xs leading-5 text-muted-foreground">Off: keep internet traffic blocked until an exit returns. On: allow new connections through the client’s normal internet connection, using its own public IP. Existing connections are not moved. New connections return to exit routing once an exit is available again.</p>
          </div>
          <Switch label="Enabled" checked={form.enabled} disabled={busy} onChange={event => { const checked = event.currentTarget.checked; setForm(current => ({ ...current, enabled: checked })); }} />
          </fieldset>
          <div className="flex justify-end gap-2"><Button type="button" variant="outline" disabled={busy} onClick={() => setEditing(null)}>Cancel</Button>{manage && <Button type="submit" disabled={busy}>Save exit node</Button>}</div>
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
