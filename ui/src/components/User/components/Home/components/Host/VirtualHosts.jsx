import { useEffect, useState } from "react";
import axios from "axios";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import WorkspaceDrawer from "@/components/ui/workspace-drawer";
import { errorText } from "../../../AccessRules/shared";

const sectionStyle = "space-y-4 px-4 py-4";
const errorStyle = "text-sm text-red-600 dark:text-red-400";

function Addresses({ host }) {
  return (
    <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-3">
      {[
        ["Private DNS", host.hostname],
        ["Private IP", host.private_ip],
        ["LAN IP", host.target_ip],
      ].map(([label, value]) => (
        <div key={label} className="min-w-0">
          <dt className="text-xs text-muted-foreground">{label}</dt>
          <dd className="mt-1 break-all font-mono text-[13px]">{value || "Unavailable"}</dd>
        </div>
      ))}
    </dl>
  );
}

function ProviderNotice({ name, online, supported }) {
  let message;
  if (online === false) {
    message = `${name} is offline. Connections through this agent require it to reconnect. You can save virtual hosts now.`;
  } else if (online === true && supported === false) {
    message = `Update the agent on ${name} to enable connections to its virtual hosts. You can configure them now.`;
  }
  return message ? <p role="status" className="text-sm text-amber-700 dark:text-amber-400">{message}</p> : null;
}

export function VirtualHostDetails({ host, privateDomain, onClose, onManage }) {
  return (
    <WorkspaceDrawer opened title={host.name} onClose={onClose} size="lg">
      <div className="space-y-5 pb-4">
        <div>
          <p className="text-sm font-medium">Virtual host via {host.via?.name || "serving agent"}</p>
          <p className="mt-1 text-sm text-muted-foreground">Access rules control connections to the LAN device. Shells, client updates and device metrics require an agent on that device.</p>
        </div>
        <Addresses host={{ hostname: privateDomain, private_ip: host.privateIps?.[0], target_ip: host.localIp }} />
        <div className="space-y-1 text-sm text-muted-foreground">
          <p>Serving agent {host.via?.online === true ? "online" : host.via?.online === false ? "offline" : "status unavailable"}.</p>
          <p>This virtual host reports {host.via?.name || "the serving machine"}’s connection. PortHub cannot verify the LAN device’s status through this entry.</p>
          <ProviderNotice name={host.via?.name || "The serving machine"} online={host.via?.online} supported={host.via?.supports_virtual_hosts} />
        </div>
        <div className="flex flex-wrap justify-end gap-2">
          <Button type="button" variant="secondary" onClick={onClose}>Close</Button>
          {host.via?.id && <Button type="button" onClick={() => onManage(host.via.id)}>Manage on {host.via.name || "serving agent"}</Button>}
        </div>
      </div>
    </WorkspaceDrawer>
  );
}

export default function VirtualHosts({ host, onChanged }) {
  const resource = `/api/machines/${encodeURIComponent(host.id)}/virtual-hosts`;
  const [hosts, setHosts] = useState([]);
  const [provider, setProvider] = useState({});
  const [loading, setLoading] = useState(true);
  const [revision, reload] = useState(0);
  const [loadError, setLoadError] = useState("");
  const [name, setName] = useState("");
  const [targetIp, setTargetIp] = useState("");
  const [removing, setRemoving] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setLoadError("");
    axios.get(resource, { signal: controller.signal })
      .then(({ data }) => {
        if (controller.signal.aborted) return;
        setHosts(data.virtual_hosts);
        setProvider({ online: data.provider_online, supported: data.provider_supported });
      })
      .catch(e => { if (!controller.signal.aborted) setLoadError(errorText(e)); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [resource, revision]);

  async function create(event) {
    event.preventDefault();
    event.stopPropagation();
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      const { data } = await axios.post(resource, { name: name.trim(), target_ip: targetIp.trim() });
      setHosts(current => [...current.filter(row => row.id !== data.virtual_host.id), data.virtual_host]);
      if (data.virtual_host.via) {
        const via = data.virtual_host.via;
        setProvider(current => ({
          online: via.online ?? current.online,
          supported: via.supports_virtual_hosts ?? current.supported,
        }));
      }
      setName("");
      setTargetIp("");
      onChanged();
    } catch (e) { setError(errorText(e)); }
    finally { setBusy(false); }
  }

  async function remove() {
    if (busy || !removing) return;
    setBusy(true);
    setError("");
    try {
      await axios.delete(`${resource}/${encodeURIComponent(removing)}`);
      setHosts(current => current.filter(row => row.id !== removing));
      setRemoving(null);
      onChanged();
    } catch (e) { setError(errorText(e)); }
    finally { setBusy(false); }
  }

  return (
    <section className={sectionStyle} aria-label="Virtual hosts">
      <div>
        <h2 className="text-base font-semibold">Virtual hosts</h2>
        <p className="mt-1 text-sm text-muted-foreground">Give a device on {host.name}’s directly attached IPv4 LAN a private IP and DNS name. Select the virtual host in Access Rules to allow private TCP and UDP connections through {host.name}.</p>
      </div>
      {loading ? <p role="status" className="text-sm text-muted-foreground">Loading virtual hosts…</p> : loadError ? (
        <div className="flex items-center gap-3"><p className={errorStyle} role="alert">{loadError}</p><Button type="button" size="sm" variant="secondary" onClick={() => reload(v => v + 1)}>Retry</Button></div>
      ) : <>
        {hosts.length > 0 && <ul className="divide-y divide-border/60 rounded-lg bg-surface px-3">
          {hosts.map(row => <li key={row.id} className="space-y-2 py-3">
            <div className="flex items-center justify-between gap-2">
              <h3 className="min-w-0 break-all text-sm font-semibold">{row.name}</h3>
              {removing !== row.id && <Button type="button" size="sm" variant="ghost" disabled={busy} aria-label={`Remove ${row.name}`} onClick={() => { setRemoving(row.id); setError(""); }}>Remove</Button>}
            </div>
            <Addresses host={row} />
            {removing === row.id && <div className="space-y-2">
              <p className="text-sm">Remove private access to {row.name} through {host.name}?</p>
              <div className="flex gap-2"><Button type="button" variant="secondary" size="sm" disabled={busy} onClick={() => setRemoving(null)}>Cancel</Button><Button type="button" variant="destructive" size="sm" disabled={busy} onClick={remove}>Remove virtual host</Button></div>
            </div>}
          </li>)}
        </ul>}
        <ProviderNotice name={host.name} online={provider.online} supported={provider.supported} />
        <form onSubmit={create} className="grid items-end gap-3 sm:grid-cols-[1fr_1fr_auto]">
          <label className="min-w-0 text-sm font-medium">Name<Input className="mt-1.5" value={name} onChange={e => setName(e.target.value)} disabled={busy} required autoComplete="off" placeholder="miro-lan" /></label>
          <label className="min-w-0 text-sm font-medium">LAN IPv4 address<Input className="mt-1.5 font-mono" value={targetIp} onChange={e => setTargetIp(e.target.value)} disabled={busy} required autoComplete="off" inputMode="decimal" placeholder="192.168.1.20" /></label>
          <Button type="submit" disabled={busy || !name.trim() || !targetIp.trim()}>Add virtual host</Button>
        </form>
      </>}
      {error && <p role="alert" className={errorStyle}>{error}</p>}
    </section>
  );
}
