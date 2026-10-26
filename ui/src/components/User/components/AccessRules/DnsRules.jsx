import { useState } from "react";
import axios from "axios";
import { IconPlus, IconTrash } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import SearchSelect from "@/components/ui/search-select";
import useToast from "@/shared/hooks/useToast";
import { API, errorText } from "./shared";

function Editor({ machine, initial, manage, params, onSaved }) {
  const [rules, setRules] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const toast = useToast();
  const change = (index, patch) => setRules(current => current.map((rule, i) => i === index ? { ...rule, ...patch } : rule));
  async function save(event) {
    event.preventDefault(); setBusy(true); setError("");
    try {
      const response = await axios.put(`${API}/dns-rules/${machine}`, { rules: rules.map(rule => ({
        domain: rule.domain, include_subdomains: true,
        action: rule.mode === "override" ? { type: "override", addresses: rule.addresses.split(/[\s,]+/).filter(Boolean) } : { type: "block" },
      })) }, { params });
      setRules(toForm(response.data.data.rules));
      await onSaved(); toast.success("DNS rules saved");
    } catch (cause) { setError(errorText(cause)); }
    finally { setBusy(false); }
  }
  return <form onSubmit={save} className="mt-4 space-y-3">
    {rules.map((rule, index) => <div key={index} className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-2 rounded-lg bg-control/40 p-3 sm:grid-cols-[minmax(0,1fr)_12rem_auto]">
      <Input required aria-label={`Domain ${index + 1}`} placeholder="example.com" value={rule.domain} disabled={!manage || busy} onChange={event => change(index, { domain: event.target.value })} />
      <SearchSelect className="col-start-1 row-start-2 sm:col-start-auto sm:row-start-auto" label={`DNS action ${index + 1}`} value={rule.mode} disabled={!manage || busy} onChange={mode => change(index, { mode })} options={[{value:"block",label:"Block domain"},{value:"override",label:"Override addresses"}]} />
      {manage && <Button type="button" variant="ghost" size="icon" className="col-start-2 row-start-1 sm:col-start-auto" aria-label={`Remove rule ${index + 1}`} disabled={busy} onClick={() => setRules(current => current.filter((_, i) => i !== index))}><IconTrash size={16} /></Button>}
      {rule.mode === "override" && <Input className="col-span-full" required aria-label={`Replacement addresses ${index + 1}`} placeholder="192.0.2.10, 2001:db8::10" value={rule.addresses} disabled={!manage || busy} onChange={event => change(index, { addresses: event.target.value })} />}
    </div>)}
    {!rules.length && <p className="text-sm text-muted-foreground">No DNS rules for this machine.</p>}
    {error && <p role="alert" className="text-sm text-red-600 dark:text-red-400">{error}</p>}
    {manage && <div className="flex flex-wrap justify-between gap-2"><Button type="button" variant="outline" disabled={busy || rules.length >= 256} onClick={() => setRules(current => [...current, {domain:"",mode:"block",addresses:""}])}><IconPlus size={15} />Domain rule</Button><Button type="submit" disabled={busy}>{busy ? "Saving…" : "Save DNS rules"}</Button></div>}
  </form>;
}

function toForm(rules) {
  return rules.map(rule => ({ domain: rule.domain, mode: rule.action.type, addresses: (rule.action.addresses || []).join(", ") }));
}

export default function DnsRules({ data, manage, params, onSaved }) {
  const [machine, setMachine] = useState("");
  const current = data.machines.some(item => item._id === machine) ? machine : "";
  const existing = data.dns_rules?.find(item => item.machine_id === current)?.rules || [];
  return <section className="mt-3 rounded-xl bg-surface p-4 sm:p-6">
    <h2 className="text-base font-semibold">DNS controls</h2>
    <p className="mb-4 mt-2 text-sm leading-6 text-muted-foreground">Block domains or replace their IP addresses on a selected machine. Rules include subdomains and apply through its system DNS resolver while the private agent is running.</p>
    <SearchSelect label="Machine for DNS controls" value={current} onChange={setMachine} options={[{value:"",label:"Choose a machine"},...data.machines.map(item => ({value:item._id,label:item.name}))]} />
    {current && <Editor key={`${data.workspace_id}:${current}`} machine={current} initial={toForm(existing)} manage={manage} params={params} onSaved={onSaved} />}
    <p className="mt-4 text-xs leading-5 text-muted-foreground">Apps using their own encrypted DNS can bypass system DNS rules. Address overrides keep the original hostname: HTTPS still requires a certificate for that hostname. A DNS rule cannot redirect a URL path.</p>
  </section>;
}
