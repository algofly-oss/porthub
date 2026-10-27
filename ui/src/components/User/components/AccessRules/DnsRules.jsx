import { useEffect, useState } from "react";
import axios from "axios";
import { IconPlus, IconTrash } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import SearchSelect from "@/components/ui/search-select";
import useToast from "@/shared/hooks/useToast";
import { API, errorText } from "./shared";

function isAddress(value) {
  if (value.includes(":")) {
    if (!/^[0-9a-f:.]+$/i.test(value)) return false;
    try { return Boolean(new URL(`http://[${value}]/`).hostname); } catch { return false; }
  }
  const parts = value.split(".");
  return parts.length === 4 && parts.every(part => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
}

function Editor({ machine, initial, manage, params }) {
  const [rules, setRules] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const toast = useToast();
  const change = (index, patch) => setRules(current => current.map((rule, i) => i === index ? { ...rule, ...patch } : rule));
  async function save(event) {
    event.preventDefault(); setError("");
    for (const rule of rules) {
      if (rule.mode !== "override") continue;
      const addresses = rule.addresses.split(/[\s,]+/).filter(Boolean);
      if (!addresses.length || addresses.some(address => !isAddress(address))) {
        setError("Enter IPv4 or IPv6 addresses for the override. Domain names and website URLs are not supported; DNS overrides do not redirect browsers.");
        return;
      }
    }
    setBusy(true);
    try {
      const response = await axios.put(`${API}/dns-rules/${machine}`, { rules: rules.map(rule => ({
        domain: rule.domain, include_subdomains: rule.scope !== "exact",
        action: rule.mode === "override" ? { type: "override", addresses: rule.addresses.split(/[\s,]+/).filter(Boolean) } : { type: "block" },
      })) }, { params });
      setRules(toForm(response.data.data.rules));
      toast.success("DNS rules saved");
    } catch (cause) { setError(errorText(cause)); }
    finally { setBusy(false); }
  }
  return <div className="mt-4 space-y-3" role="group" aria-label="DNS rules">
    {rules.map((rule, index) => <div key={index} className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-2 rounded-lg bg-control/40 p-3 sm:grid-cols-[minmax(0,1fr)_12rem_auto]">
      <Input required aria-label={`Domain ${index + 1}`} placeholder="example.com" value={rule.domain} disabled={!manage || busy} onChange={event => change(index, { domain: event.target.value })} />
      <SearchSelect className="col-start-1 row-start-2 sm:col-start-auto sm:row-start-auto" label={`DNS action ${index + 1}`} value={rule.mode} disabled={!manage || busy} onChange={mode => change(index, { mode })} options={[{value:"block",label:"Block domain"},{value:"override",label:"Override addresses"}]} />
      {manage && <Button type="button" variant="ghost" size="icon" className="col-start-2 row-start-1 sm:col-start-auto" aria-label={`Remove rule ${index + 1}`} disabled={busy} onClick={() => setRules(current => current.filter((_, i) => i !== index))}><IconTrash size={16} /></Button>}
      <SearchSelect className="col-span-full" label={`DNS scope ${index + 1}`} value={rule.domain.trim().startsWith("*.") ? "wildcard" : rule.scope} disabled={!manage || busy || rule.domain.trim().startsWith("*.")} onChange={scope => change(index, { scope })} options={rule.domain.trim().startsWith("*.") ? [{value:"wildcard",label:"Subdomains only (apex excluded)"}] : [{value:"all",label:"This domain and all subdomains"},{value:"exact",label:"Only this exact domain"}]} />
      {rule.mode === "override" && <div className="col-span-full space-y-1.5"><Input className="placeholder:!text-muted-foreground placeholder:!opacity-60" required aria-label={`Replacement addresses ${index + 1}`} aria-describedby={`dns-address-help-${index}`} placeholder="192.0.2.10, 2001:db8::10" value={rule.addresses} disabled={!manage || busy} onChange={event => change(index, { addresses: event.target.value })} /><p id={`dns-address-help-${index}`} className="text-xs text-muted-foreground">IPv4 or IPv6 addresses only, separated by commas. This changes DNS answers; it does not redirect to another website.</p></div>}
    </div>)}
    {!rules.length && <p className="text-sm text-muted-foreground">No DNS rules for this machine.</p>}
    {error && <p role="alert" className="text-sm text-red-600 dark:text-red-400">{error}</p>}
    {manage && <div className="flex flex-wrap justify-between gap-2"><Button type="button" variant="outline" disabled={busy || rules.length >= 256} onClick={() => setRules(current => [...current, {domain:"",mode:"block",addresses:"",scope:"all"}])}><IconPlus size={15} />Domain rule</Button><Button type="button" onClick={save} disabled={busy}>{busy ? "Saving…" : "Save DNS rules"}</Button></div>}
  </div>;
}

function toForm(rules) {
  return rules.map(rule => ({ domain: rule.domain, scope: rule.include_subdomains === false ? "exact" : "all", mode: rule.action.type, addresses: (rule.action.addresses || []).join(", ") }));
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
    <h2 className="text-base font-semibold">DNS controls</h2>
    <p className="mt-2 text-sm leading-6 text-muted-foreground">Rules for this machine apply through its system DNS resolver while its private agent is running.</p>
    {error && <p role="alert" className="mt-3 text-sm text-red-600 dark:text-red-400">{error}</p>}
    {!data && !error && <p className="mt-3 text-sm text-muted-foreground">Loading DNS rules…</p>}
    {data && <Editor key={`${workspace}:${machine}`} machine={machine} initial={toForm(data.rules)} manage={data.can_manage} params={{ workspace }} />}
    <p className="mt-4 text-xs leading-5 text-muted-foreground">Use *.example.com for subdomains only, or choose exact matching for a specific name. Apps using their own encrypted DNS can bypass system DNS rules. Address overrides keep the original hostname; HTTPS still requires a matching certificate.</p>
  </section>;
}
