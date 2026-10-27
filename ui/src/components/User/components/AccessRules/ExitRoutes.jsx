import { Switch } from "@mantine/core";
import SearchMultiSelect from "@/components/ui/search-multi-select";
import { useState } from "react";
import axios from "axios";
import { IconPlus, IconRoute, IconTrash, IconArrowRight, IconChevronRight, IconChevronUp, IconChevronDown } from "@tabler/icons-react";
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
  const [form, setForm] = useState({ name: "", routing: new Set(), clients: new Set(), enabled: true, selection: "sticky", traffic_mode: "internet_only", allow_direct_fallback: false, tor_enabled: false, tor_circuit_groups: 4 });

  function open(route = null) {
    setEditing(route?._id || "new");
    setForm({
      name: route?.name || "",
      routing: selected(route?.routing_selectors),
      clients: selected(route?.distribution_selectors),
      enabled: route?.enabled ?? true,
      selection: route?.selection || "sticky",
      traffic_mode: route?.traffic_mode || "internet_only",
      allow_direct_fallback: route?.allow_direct_fallback === true,
      tor_enabled: route?.traffic_mode !== "lan_only" && route?.tor_enabled === true,
      tor_circuit_groups: route?.tor_circuit_groups || 4,
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
      const body = { name: form.name.trim(), routing_selectors: selectors(form.routing), distribution_selectors: selectors(form.clients), enabled: form.enabled, selection: form.selection, traffic_mode: form.traffic_mode, allow_direct_fallback: form.allow_direct_fallback, tor_enabled: form.tor_enabled, tor_circuit_groups: form.tor_circuit_groups };
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
      await axios.put(`${API}/exit-nodes/${route._id}`, { name, routing_selectors, distribution_selectors, selection: selection || "sticky", traffic_mode: route.traffic_mode || "internet_only", enabled: !route.enabled, allow_direct_fallback: route.allow_direct_fallback === true, tor_enabled: route.tor_enabled === true, tor_circuit_groups: route.tor_circuit_groups || 4 }, { params });
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

  function moveRoutingPeer(index, offset) {
    setForm(current => {
      const routing = [...current.routing];
      const next = index + offset;
      if (next < 0 || next >= routing.length) return current;
      [routing[index], routing[next]] = [routing[next], routing[index]];
      return { ...current, routing: new Set(routing) };
    });
  }

  const names = new Map(options.map(option => [option.value, `${option.group === "Groups" ? "Group: " : ""}${option.label}`]));
  const entityNames = selectors => selectors.map(item => names.get(`${item.kind}:${item.id}`) || "Unavailable selection").join(", ");
  const exitNames = route => [entityNames(route.routing_selectors), route.tor_enabled ? "Local Tor" : ""].filter(Boolean).join(", ");
  return (
    <section className="rounded-xl bg-surface p-4">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold">Exit nodes</h2>
          <p className="mt-1 max-w-3xl text-sm leading-6 text-muted-foreground">Send internet traffic through selected peers or each machine’s own embedded Tor client. Existing connections retain their selected exit.</p>
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
            <p className="mt-1 flex min-w-0 items-center gap-2 text-xs text-muted-foreground" title={`${entityNames(route.distribution_selectors)} → ${exitNames(route)}`}>
              <span className="min-w-0 truncate">{entityNames(route.distribution_selectors)}</span><IconArrowRight size={15} className="shrink-0 text-primary" aria-label="via" /><span className="min-w-0 truncate">{exitNames(route)}</span>
            </p>
            <p className="mt-1 text-xs text-muted-foreground">{route.traffic_mode === "lan_only" ? "LAN only · internet uses the normal connection" : `${route.traffic_mode === "all" ? "All" : "Internet only"} · All exits offline: ${route.allow_direct_fallback ? "Use normal internet" : "Block internet traffic"}`}</p>
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
          <div><p className="mb-2 text-sm font-medium">Exit mode</p><SearchSelect label="Exit mode" value={form.traffic_mode} onChange={traffic_mode => setForm(current => ({ ...current, traffic_mode, tor_enabled: traffic_mode === "lan_only" ? false : current.tor_enabled }))} options={[{ value: "all", label: "All" }, { value: "internet_only", label: "Internet only" }, { value: "lan_only", label: "LAN only" }]} /><p className="mt-2 text-xs text-muted-foreground">{form.traffic_mode === "all" ? "Internet and matching remote LAN destinations use the configured exits." : form.traffic_mode === "lan_only" ? "Matching remote LAN destinations use the configured peers. Internet uses this machine’s normal connection." : "Internet uses the configured exits. Local network access stays normal."}</p></div>
          <div className="grid gap-3 lg:grid-cols-2">{selectors("routing", "Routing peers")}{selectors("clients", "Machines using this exit node")}</div>
          {form.traffic_mode !== "internet_only" && form.routing.size > 1 && <div className="rounded-lg border border-border p-3"><p className="mb-2 text-sm font-medium">LAN peer priority</p><p className="mb-2 text-xs text-muted-foreground">The most specific network wins. For matching networks of equal size, the first available peer wins.</p><div className="space-y-1">{[...form.routing].map((value, index) => <div key={value} className="flex items-center gap-2"><span className="min-w-0 flex-1 truncate text-sm">{index + 1}. {names.get(value) || "Unavailable selection"}</span><Button type="button" variant="ghost" size="sm" aria-label={`Move ${names.get(value) || "peer"} up`} disabled={busy || index === 0} onClick={() => moveRoutingPeer(index, -1)}><IconChevronUp size={16} /></Button><Button type="button" variant="ghost" size="sm" aria-label={`Move ${names.get(value) || "peer"} down`} disabled={busy || index === form.routing.size - 1} onClick={() => moveRoutingPeer(index, 1)}><IconChevronDown size={16} /></Button></div>)}</div></div>}
          {form.traffic_mode !== "lan_only" && <div className="rounded-lg border border-border p-3">
            <Switch label="Include local Tor as an exit" checked={form.tor_enabled} disabled={busy || form.traffic_mode === "lan_only"}
              onChange={event => { const checked = event.currentTarget.checked; setForm(current => ({ ...current, tor_enabled: checked })); }} />
            <p className="mt-2 text-xs leading-5 text-muted-foreground">Tor runs inside each assigned machine’s agent. It needs no listening port and does not relay through the PortHub gateway. Select Tor alone or combine it with routing peers. Tor supports TCP; unsupported traffic is blocked when Tor is the selected exit.</p>
            {form.tor_enabled && <div className="mt-3"><SearchSelect label="Tor circuit groups" value={String(form.tor_circuit_groups)} onChange={value => setForm(current => ({ ...current, tor_circuit_groups: Number(value) }))} options={[1, 2, 4, 8, 16].map(value => ({ value: String(value), label: `${value}${value === 4 ? " (default)" : ""}` }))} /><p className="mt-2 text-xs text-muted-foreground">Separate circuit groups allow concurrent connections to use independent circuits. More groups do not guarantee higher throughput or unique public IPs.</p></div>}
          </div>}
          {form.traffic_mode !== "lan_only" && <div><p className="mb-2 text-sm font-medium">Exit selection</p><SearchSelect label="Exit selection" value={form.selection} onChange={selection => setForm(current => ({ ...current, selection }))} options={[{value:"sticky",label:"Sticky · stable client hash (default)"},{value:"round_robin",label:"Round robin · alternate new connections"},{value:"random",label:"Random · choose per new connection"}]} /><p className="mt-2 text-xs text-muted-foreground">Sticky keeps new connections on the same available exit for each client. Round robin alternates exits; random chooses independently for each new connection. Established connections keep their selected exit. Equal connection counts do not guarantee equal bandwidth.</p></div>}
          {form.traffic_mode !== "lan_only" && <div className="rounded-lg border border-border p-3">
            <Switch label="Use normal internet if all exits are offline" checked={form.allow_direct_fallback} disabled={busy || form.traffic_mode === "lan_only"}
              onChange={event => { const checked = event.currentTarget.checked; setForm(current => ({ ...current, allow_direct_fallback: checked })); }} />
            <p className="mt-2 text-xs leading-5 text-muted-foreground">Off: keep internet traffic blocked until an exit returns. On: allow new connections through the client’s normal internet connection, using its own public IP. Existing connections are not moved. New connections return to exit routing once an exit is available again.</p>
          </div>}
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
