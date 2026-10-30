import { useEffect, useState } from "react";
import axios from "axios";
import { IconUser, IconServer } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { SearchField } from "@/components/ui/workspace";
import ResultsPagination from "@/components/ui/results-pagination";
import useInventoryPage from "@/shared/hooks/useInventoryPage";
import WorkspaceDrawer from "@/components/ui/workspace-drawer";
import { API, errorText, DirtyGuard } from "./shared";

// Only explicit checkbox changes are saved; unseen membership stays untouched.
export default function GroupEditor({group,manage,params,onClose,onSaved}) {
  const [query,setQuery]=useState(""),[section,setSection]=useState("machines"),[page,setPage]=useState(1);
  const [changes,setChanges]=useState({machines:{},people:{}}),[busy,setBusy]=useState(false),[error,setError]=useState("");
  const inventory=useInventoryPage(`access-${section}`,{...params,q:query,page,page_size:25,membership:group._id});
  useEffect(()=>setPage(1),[query,section]);
  useEffect(()=>{if(!inventory.loading && page>inventory.pagination.pages)setPage(inventory.pagination.pages);},[page,inventory.loading,inventory.pagination.pages]);
  const dirty=Object.values(changes).some(values=>Object.keys(values).length>0);
  function toggle(row,checked) {
    setChanges(old=>{const values={...old[section]};if(checked===row.member)delete values[row._id];else values[row._id]=checked;return {...old,[section]:values};});
  }
  async function save() {
    setBusy(true);setError("");
    const ids=(kind,value)=>Object.entries(changes[kind]).filter(([,checked])=>checked===value).map(([id])=>id);
    try {await axios.patch(`${API}/groups/${group._id}/members`,{machine_add:ids("machines",true),machine_remove:ids("machines",false),user_add:ids("people",true),user_remove:ids("people",false)},{params});await onSaved();}
    catch(error){setError(errorText(error));}finally{setBusy(false);}
  }
  return <DirtyGuard dirty={dirty && manage} busy={busy} onClose={onClose}>{close=><WorkspaceDrawer opened onClose={close} title={`${group.name} · Members`} fixedHeight="min(640px, 85dvh)" animate={false}>
    <div className="mb-3 flex shrink-0 gap-1 rounded-lg bg-surface p-1">{[["machines","Machines",IconServer],["people","People",IconUser]].map(([id,label,Icon])=><Button key={id} type="button" variant={section===id ? "secondary" : "ghost"} aria-pressed={section===id} onClick={()=>setSection(id)}><Icon size={15}/>{label}</Button>)}</div>
    <SearchField label="Search group entities" placeholder={`Search ${section}…`} value={query} onChange={setQuery}/>
    <div className="data-scroll mt-3">
      {inventory.loading && <p role="status" className="p-3 text-sm text-muted-foreground">Loading members…</p>}
      {inventory.error && <p role="alert" className="p-3 text-sm text-red-600 dark:text-red-400">{inventory.error}</p>}
      {inventory.rows.map(row=><label key={row._id} className="flex cursor-pointer items-center gap-3 rounded-lg px-2 py-3 hover:bg-accent/35"><Checkbox aria-label={`Include ${row.name || row.email}`} disabled={!manage || busy} checked={changes[section][row._id] ?? row.member} onCheckedChange={checked=>toggle(row,checked===true)}/><span className="min-w-0"><span className="block truncate text-sm font-medium">{row.name || row.email}</span>{row.email && <span className="block truncate text-xs text-muted-foreground">{row.email}</span>}</span></label>)}
      {!inventory.loading && !inventory.rows.length && <p className="p-3 text-sm text-muted-foreground">No matching {section}.</p>}
    </div>
    <ResultsPagination count={inventory.pagination.total} noun={section==="machines" ? "Machines" : "People"} page={page} pages={inventory.pagination.pages} pageSize={25} onPage={setPage}/>
    {error && <p role="alert" className="mt-3 text-sm text-red-600 dark:text-red-400">{error}</p>}
    <div data-dialog-footer className="mt-4 flex justify-end gap-2"><Button type="button" variant="secondary" disabled={busy} onClick={close}>Close</Button>{manage && <Button type="button" disabled={busy || !dirty} onClick={save}>{busy ? "Saving…" : "Save Members"}</Button>}</div>
  </WorkspaceDrawer>}</DirtyGuard>;
}
