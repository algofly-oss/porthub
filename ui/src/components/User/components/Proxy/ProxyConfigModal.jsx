import axios from "axios";
import apiRoutes from "@/shared/routes/apiRoutes";
import { inventoryUrl } from "@/shared/utils/inventory-resource.mjs";
import useBackgroundRefresh from "@/shared/hooks/useBackgroundRefresh";
import { useEffect, useRef, useState } from "react";
import { Switch } from "@mantine/core";
import { IconDotsVertical, IconPlus, IconTrash, IconRoute } from "@tabler/icons-react";
import WorkspaceDrawer from "@/components/ui/workspace-drawer";
import { Dialog } from "@/components/ui/dialog";
import { Menu } from "@/components/ui/menu";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { StatusTabs } from "@/components/ui/status-tabs";
import ProxyBindings from "./ProxyBindings";
import { RoutingMode, HealthSettings } from "./ProxyRouting";
import { newBinding, proxyBindings, proxyRouting, routingLabel, validateBindings, bindingPayload } from "@/shared/utils/proxy-bindings.mjs";
const hostnameRe = /^(?=.{1,253}$)(?:localhost|(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-))(?:\.(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)))*)$/i;
let aliasIdCounter = 0;

const createAliasId = () => {
  aliasIdCounter += 1;
  return `alias-${aliasIdCounter}`;
};

const createEmptyAlias = (domainSuffix = "") => ({
  id: createAliasId(),
  subdomainKey: "",
  domainSuffix: String(domainSuffix || "").trim().toLowerCase(),
});

const splitHostForForm = (host) => {
  const normalized = String(host || "").trim().toLowerCase();
  if (!normalized) {
    return { subdomainKey: "", domainSuffix: "" };
  }

  const segments = normalized.split(".");
  if (segments.length >= 3) {
    return {
      subdomainKey: segments.slice(0, -2).join("."),
      domainSuffix: segments.slice(-2).join("."),
    };
  }

  if (segments.length === 2) {
    return {
      subdomainKey: segments[0],
      domainSuffix: segments[1],
    };
  }

  return {
    subdomainKey: normalized,
    domainSuffix: "",
  };
};

const normalizeHostList = (values) =>
  [...new Set(
    (Array.isArray(values) ? values : [])
      .map((value) => String(value || "").trim().toLowerCase())
      .filter(Boolean)
  )];

const buildHostsFromForm = ({ subdomainKey, domainSuffix }) => {
  const normalizedSubdomainKey = String(subdomainKey || "").trim().toLowerCase();
  const normalizedDomainSuffix = String(domainSuffix || "").trim().toLowerCase();
  return normalizeHostList([
    normalizedSubdomainKey
    ? normalizedDomainSuffix
      ? `${normalizedSubdomainKey}.${normalizedDomainSuffix}`
      : normalizedSubdomainKey
    : normalizedDomainSuffix,
  ]);
};

const buildHostFromEntry = ({ subdomainKey, domainSuffix }) =>
  buildHostsFromForm({ subdomainKey, domainSuffix })[0] || "";

const collectHostsFromForm = (form) =>
  normalizeHostList([
    buildHostFromEntry(form),
    ...(Array.isArray(form?.aliases)
      ? form.aliases.map((alias) => buildHostFromEntry(alias))
      : []),
  ]);

const validateHostEntry = ({ subdomainKey, domainSuffix }) => {
  const normalizedSubdomainKey = String(subdomainKey || "").trim().toLowerCase();
  const normalizedDomainSuffix = String(domainSuffix || "").trim().toLowerCase();

  if (!normalizedSubdomainKey && !normalizedDomainSuffix) {
    return null;
  }

  if (
    normalizedSubdomainKey &&
    !normalizedDomainSuffix &&
    !normalizedSubdomainKey.includes(".")
  ) {
    return "Domain suffix is required when using a subdomain key";
  }

  const host = buildHostFromEntry({ subdomainKey, domainSuffix });
  if (!host) {
    return "At least one hostname is required";
  }

  if (!hostnameRe.test(host)) {
    return `Invalid hostname: ${host}`;
  }

  return null;
};

const initialForm=(proxy,suffix)=>{
  const hosts=proxy?.hosts || [], bindings=proxyBindings(proxy);
  return {dataId:proxy?._id || "",...splitHostForForm(hosts[0] || ""),domainSuffix:splitHostForForm(hosts[0] || "").domainSuffix || suffix || "",
    aliases:hosts.slice(1).map(host=>({id:createAliasId(),...splitHostForForm(host)})),description:proxy?.description || "",group:proxy?.group || "",enabled:proxy?.enabled ?? true,
    bindings:bindings.length ? bindings : [newBinding()],routing:proxyRouting(proxy)};
};
const sections=[{value:"address",label:"Address"},{value:"bindings",label:"Bindings"},{value:"health",label:"Health"},{value:"options",label:"Options"}];

function LoadedProxyConfigModal({ opened,onClose,onSubmit,onDelete,proxy=null,connections=[],machines=[],defaultDomainSuffix="",isSaving=false,isDeleting=false,health=null }) {
  const [form,setForm]=useState(()=>initialForm(proxy,defaultDomainSuffix));
  const [section,setSection]=useState("address"),[errors,setErrors]=useState({}),[confirmDelete,setConfirmDelete]=useState(false);
  const initialized=useRef(null),scrollArea=useRef(null);
  useEffect(()=>{
    if(!opened){initialized.current=null;return;}
    const key=proxy?._id || `new:${proxy?.connection?.data_id || ""}`;
    if(initialized.current===key)return;
    initialized.current=key;setForm(initialForm(proxy,defaultDomainSuffix));setErrors({});setSection("address");setConfirmDelete(false);
  },[opened,proxy,defaultDomainSuffix]);
  useEffect(()=>{if(scrollArea.current)scrollArea.current.scrollTop=0;},[section]);
  const change=(key,value)=>{setForm(current=>({...current,[key]:value}));setErrors({});};
  const persisted=!!form.dataId, hosts=collectHostsFromForm(form), preview=hosts[0] || "your-app.example.com";
  async function submit(event){
    event.preventDefault();event.stopPropagation();
    const problems=validateBindings(form.bindings,form.routing);
    if(!hosts.length)problems.address="Enter a public hostname.";
    for(const entry of [form,...form.aliases]){const problem=validateHostEntry(entry);if(problem)problems.address=problem;}
    if(form.aliases.some(a=>!buildHostFromEntry(a)))problems.address="Complete or remove the empty alias.";
    setErrors(problems);
    if(Object.keys(problems).length){setSection(problems.address ? "address" : problems.health ? "health" : "bindings");return;}
    const saved=await onSubmit({data_id:form.dataId || undefined,name:preview,hosts,description:form.description.trim(),group:form.group.trim(),enabled:form.enabled,entryPoints:proxy?.entry_points || ["web"],bindings:bindingPayload(form.bindings),routing:form.routing});
    if(saved)setForm(initialForm(saved,defaultDomainSuffix));
  }
  const sectionIndex=sections.findIndex(s=>s.value===section);
  return <><WorkspaceDrawer opened={opened} onClose={onClose} zIndex={220} trapFocus={!confirmDelete} size={800} fixedHeight="min(800px, calc(100dvh - 48px))" closeOnEscape={!isSaving && !confirmDelete} closeOnClickOutside={!isSaving && !confirmDelete} title={<div className="flex w-full items-center justify-between gap-3 pr-2"><div><p className="text-base font-semibold">{persisted ? "Edit Proxy Route" : "Create Proxy Route"}</p><p className="mt-0.5 text-xs font-normal text-muted-foreground">One address. Multiple routes to your application.</p></div>{persisted && <Menu position="bottom-end" withinPortal={false}><Menu.Target><Button type="button" size="icon" variant="ghost" aria-label="Proxy actions"><IconDotsVertical size={17} /></Button></Menu.Target><Menu.Dropdown><Menu.Item color="red" onClick={()=>setConfirmDelete(true)}>Delete proxy</Menu.Item></Menu.Dropdown></Menu>}</div>} classNames={{title:"flex-1",body:"!pt-0"}}>
    <form onSubmit={submit} noValidate className={`flex min-h-0 flex-1 flex-col ${confirmDelete ? "pointer-events-none blur-sm" : ""}`}>
      <div className="mb-4 overflow-x-auto pb-1"><StatusTabs label="Proxy configuration sections" value={section} onChange={setSection} options={sections} /></div>
      <div ref={scrollArea} data-proxy-scroll className="min-h-0 flex-1 overflow-y-auto pr-1"><fieldset disabled={isSaving} className="min-w-0 space-y-5 pb-2">
        {section === "address" && <><div><h2 className="text-base font-semibold">Public address</h2><p className="mt-2 text-sm leading-6 text-muted-foreground">Keep one hostname while routing to machine ports, standalone URLs, or both.</p></div><div className="grid gap-4 sm:grid-cols-2"><label className="block text-xs font-medium">Primary subdomain<Input aria-label="Primary subdomain" className="mt-2" placeholder="app" value={form.subdomainKey} onChange={event=>change("subdomainKey",event.target.value)} /></label><label className="block text-xs font-medium">Domain suffix<Input aria-label="Domain suffix" className="mt-2" placeholder="example.com" value={form.domainSuffix} onChange={event=>change("domainSuffix",event.target.value)} /></label></div><div className="rounded-xl border border-primary/20 bg-primary/[0.04] p-4"><p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Public URL</p><p className="mt-2 break-all font-mono text-sm text-blue-700 dark:text-blue-300">https://{preview}</p><p className="mt-2 text-xs leading-5 text-muted-foreground">Point this hostname at your PortHub gateway. DNS and TLS configuration still apply.</p></div><div className="space-y-3"><div className="flex items-center justify-between gap-3"><h3 className="text-sm font-medium">Additional hostnames</h3><Button type="button" variant="ghost" size="sm" onClick={()=>change("aliases",[...form.aliases,createEmptyAlias(form.domainSuffix)])}><IconPlus size={14} />Add alias</Button></div>{form.aliases.map((alias,index)=><div key={alias.id} className="grid grid-cols-[1fr_1fr_auto] items-end gap-2"><label className="min-w-0 text-xs text-muted-foreground">Subdomain<Input aria-label={`Alias ${index+1} subdomain`} className="mt-1" value={alias.subdomainKey} onChange={event=>change("aliases",form.aliases.map(a=>a.id===alias.id ? {...a,subdomainKey:event.target.value}:a))} /></label><label className="min-w-0 text-xs text-muted-foreground">Suffix<Input aria-label={`Alias ${index+1} suffix`} className="mt-1" value={alias.domainSuffix} onChange={event=>change("aliases",form.aliases.map(a=>a.id===alias.id ? {...a,domainSuffix:event.target.value}:a))} /></label><Button type="button" variant="ghost" size="icon" aria-label={`Remove alias ${index+1}`} onClick={()=>change("aliases",form.aliases.filter(a=>a.id!==alias.id))}><IconTrash size={15} /></Button></div>)}</div>{errors.address && <p role="alert" className="text-sm text-red-600 dark:text-red-400">{errors.address}</p>}</>}
        {section === "bindings" && <><RoutingMode value={form.routing} onChange={value=>change("routing",value)} /><div className="border-t border-border pt-5"><ProxyBindings bindings={form.bindings} routing={form.routing} onChange={bindings=>change("bindings",bindings)} connections={connections} machines={machines} errors={errors} savedBindings={proxyBindings(proxy)} statuses={health?.data?.[proxy?._id] || []} healthAvailable={health?.available} disabled={isSaving} /></div></>}
        {section === "health" && <HealthSettings value={form.routing} onChange={value=>change("routing",value)} error={errors.health} />}
        {section === "options" && <><div><h2 className="text-base font-semibold">Proxy options</h2><p className="mt-2 text-sm leading-6 text-muted-foreground">Organize this address and control whether it accepts requests.</p></div><label className="block text-xs font-medium">Project group<Input aria-label="Project group" maxLength={80} className="mt-2" value={form.group} onChange={event=>change("group",event.target.value)} placeholder="Production" /></label><label className="block text-xs font-medium">Description<textarea aria-label="Description" rows={3} className="mt-2 w-full rounded-lg border-0 bg-control p-3 text-sm text-foreground outline-none ring-0 transition-colors focus:bg-accent/40 focus:outline-none focus:ring-0" value={form.description} onChange={event=>change("description",event.target.value)} /></label><div className="flex items-center justify-between gap-4 rounded-xl border border-border bg-surface p-4"><div><p className="text-sm font-medium">Routing enabled</p><p className="mt-1 text-xs text-muted-foreground">Accept requests for this proxy&apos;s hostnames.</p></div><Switch aria-label="Proxy enabled" checked={form.enabled} onChange={event=>change("enabled",event.currentTarget.checked)} size="sm" /></div></>}
      </fieldset></div>
      <div className="mt-4 shrink-0 border-t border-border pt-3"><div className="mb-3 flex min-w-0 items-center gap-2 text-[11px] text-muted-foreground"><IconRoute size={14} className="shrink-0" /><span className="truncate">{form.bindings.filter(b=>b.enabled).length} enabled {form.bindings.filter(b=>b.enabled).length === 1 ? "binding" : "bindings"} · {routingLabel(form.routing)}</span></div><div className="flex items-center justify-between gap-2"><Button type="button" variant="secondary" onClick={onClose} disabled={isSaving}>Cancel</Button><div className="flex gap-2">{sectionIndex>0 && <Button type="button" variant="ghost" onClick={()=>setSection(sections[sectionIndex-1].value)}>Back</Button>}{!persisted && sectionIndex<sections.length-1 ? <Button key="continue" type="button" onClick={()=>setSection(sections[sectionIndex+1].value)}>Continue</Button> : <Button key="save" type="submit" disabled={isSaving}>{isSaving ? "Saving…" : persisted ? "Save Proxy" : "Create Proxy"}</Button>}</div></div></div>
    </form>
  </WorkspaceDrawer><Dialog opened={confirmDelete} onClose={()=>setConfirmDelete(false)} zIndex={230} size="sm" title="Delete proxy" closeOnEscape={!isDeleting} closeOnClickOutside={!isDeleting}><p className="text-sm leading-6 text-muted-foreground">Remove this public address and all its bindings? The underlying machine ports and applications remain available.</p><div className="mt-5 flex justify-end gap-2"><Button type="button" variant="secondary" onClick={()=>setConfirmDelete(false)} disabled={isDeleting}>Cancel</Button><Button type="button" variant="destructive" disabled={isDeleting} onClick={async()=>{if(await onDelete(form.dataId)){setConfirmDelete(false);onClose();}}}>{isDeleting ? "Deleting…" : "Delete proxy"}</Button></div></Dialog></>;
}

export default function ProxyConfigModal(props) {
  const [source,setSource]=useState(null),[error,setError]=useState(""),[retry,setRetry]=useState(0),[health,setHealth]=useState({available:false,data:{}});
  const id=props.proxy?._id;
  useEffect(()=>{
    setSource(null);setError("");
    if(!props.opened || !id)return;
    const controller=new AbortController();
    axios.get(inventoryUrl("proxies",{ids:id,detail:true,page_size:1}),{signal:controller.signal}).then(response=>{if(!controller.signal.aborted){const row=response.data.data?.[0];if(row)setSource(row);else setError("Proxy no longer exists.");}}).catch(error=>{if(!controller.signal.aborted)setError(error.response?.data?.detail || "Could not load the complete proxy.");});
    return()=>controller.abort();
  },[props.opened,id,retry]);
  useBackgroundRefresh(async signal=>{try{const response=await axios.get(`${apiRoutes.proxyHealth}?${new URLSearchParams({ids:id})}`,{signal});setHealth(response.data);}catch(error){if(!signal.aborted)setHealth({available:false,data:{}});}},{enabled:props.opened && !!id,refreshKey:id,interval:10000});
  if(!props.opened)return null;
  if(!id)return <LoadedProxyConfigModal {...props} health={health}/>;
  if(!source || source._id!==id)return <WorkspaceDrawer opened onClose={props.onClose} title="Proxy" size="xl"><p role={error ? "alert" : "status"} className="p-4 text-sm text-muted-foreground">{error || "Loading complete proxy…"}</p>{error && <Button type="button" variant="secondary" onClick={()=>setRetry(value=>value+1)}>Try again</Button>}</WorkspaceDrawer>;
  return <LoadedProxyConfigModal {...props} proxy={source} health={health}/>;
}
