import { useEffect, useState } from "react";
import axios from "axios";
import { IconPlus, IconTrash } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import SearchSelect from "@/components/ui/search-select";
import useToast from "@/shared/hooks/useToast";
import { API, errorText } from "./shared";

function Editor({ machine, initial, manage, params }) {
  const [rules, setRules] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const toast = useToast();
  const change = (index, patch) => setRules(current => current.map((rule, i) => i === index ? { ...rule, ...patch } : rule));
  async function save(event) {
    event.preventDefault(); setError("");
    setBusy(true);
    try {
      const response = await axios.put(`${API}/dns-rules/${machine}`, { rules: rules.map(rule => ({
        domain: rule.domain, include_subdomains: rule.scope !== "exact",
        action: { type: "block" },
      })) }, { params });
      setRules(toForm(response.data.data.rules));
      toast.success("DNS rules saved");
    } catch (cause) { setError(errorText(cause)); }
    finally { setBusy(false); }
  }
  return <div className="mt-4 space-y-3" role="group" aria-label="DNS rules">
    {rules.map((rule, index) => <div key={index} className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-2 rounded-lg bg-control/40 p-3">
      <Input required aria-label={`Domain ${index + 1}`} placeholder="example.com" value={rule.domain} disabled={!manage || busy} onChange={event => change(index, { domain: event.target.value })} />
      {manage && <Button type="button" variant="ghost" size="icon" className="col-start-2 row-start-1 sm:col-start-auto" aria-label={`Remove rule ${index + 1}`} disabled={busy} onClick={() => setRules(current => current.filter((_, i) => i !== index))}><IconTrash size={16} /></Button>}
      <SearchSelect className="col-span-full" label={`DNS scope ${index + 1}`} value={rule.domain.trim().startsWith("*.") ? "wildcard" : rule.scope} disabled={!manage || busy || rule.domain.trim().startsWith("*.")} onChange={scope => change(index, { scope })} options={rule.domain.trim().startsWith("*.") ? [{value:"wildcard",label:"Subdomains only (apex excluded)"}] : [{value:"all",label:"This domain and all subdomains"},{value:"exact",label:"Only this exact domain"}]} />
    </div>)}
    {!rules.length && <p className="text-sm text-muted-foreground">No DNS rules for this machine.</p>}
    {error && <p role="alert" className="text-sm text-red-600 dark:text-red-400">{error}</p>}
    {manage && <div className="flex flex-wrap justify-between gap-2"><Button type="button" variant="outline" disabled={busy || rules.length >= 256} onClick={() => setRules(current => [...current, {domain:"",scope:"all"}])}><IconPlus size={15} />Domain rule</Button><Button type="button" onClick={save} disabled={busy}>{busy ? "Saving…" : "Save DNS rules"}</Button></div>}
  </div>;
}

function toForm(rules) {
  return rules.filter(rule => rule.action.type === "block").map(rule => ({ domain: rule.domain, scope: rule.include_subdomains === false ? "exact" : "all" }));
}

export default function DnsRules({ machine, opened, workspace = "" }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => {
    if (!opened || !machine) return;
    const controller = new AbortController();
    setData(null); setError("");
    axios.get(`${API}/dns-rules/${machine}`, { params: { workspace }, signal: controller.signal })
      .then(response => {
        if (controller.signal.aborted) return;
        setData(response.data.data);
      }).catch(cause => { if (!controller.signal.aborted) setError(errorText(cause)); });
    return () => controller.abort();
  }, [machine, opened, workspace]);
  return <section className="p-4">
    <h2 className="text-base font-semibold">DNS filtering</h2>
    <p className="mt-2 text-sm leading-6 text-muted-foreground">Block domains through this machine’s system DNS resolver while its private agent is running.</p>
    {error && <p role="alert" className="mt-3 text-sm text-red-600 dark:text-red-400">{error}</p>}
    {!data && !error && <p className="mt-3 text-sm text-muted-foreground">Loading DNS rules…</p>}
    {data && <Editor key={`${workspace}:${machine}`} machine={machine} initial={toForm(data.rules)} manage={data.can_manage} params={{ workspace }} />}
    <p className="mt-4 text-xs leading-5 text-muted-foreground">Use *.example.com for subdomains only, or choose exact matching for a specific name. Apps using their own encrypted DNS can bypass system DNS rules.</p>
  </section>;
}
