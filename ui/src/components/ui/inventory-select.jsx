import { searchScore } from "@/shared/utils/search.mjs";
import { createContext, forwardRef, useContext, useEffect, useMemo, useState } from "react";
import { Select, Loader } from "@mantine/core";
import { IconChevronDown } from "@tabler/icons-react";
import useInventoryPage from "@/shared/hooks/useInventoryPage";
const Paging=createContext(null);
const Dropdown=forwardRef(function Dropdown({children,...props},ref){
 const page=useContext(Paging);
 return <div ref={ref} {...props}>{children}{page && <div className="border-t border-border px-2 py-2"><p className="mb-1 text-[11px] text-muted-foreground">{page.count} of {page.total} matches</p>{page.more && <button type="button" onMouseDown={e=>e.preventDefault()} onClick={page.load} className="w-full rounded-md bg-control px-3 py-2 text-xs font-medium text-foreground hover:bg-accent" disabled={page.loading}>{page.loading ? "Loading…" : "Load more results"}</button>}{page.error && <p role="alert" className="text-xs text-red-600 dark:text-red-400">{page.error}</p>}</div>}</div>;
});
const labels={machines:m=>m.name || m.hostname || "Unnamed machine",connections:c=>`${c.machine_name || "Machine"} · ${c.service_name || "Port"} · ${c.internal_port} → ${c.external_port}`,groups:g=>g.name,"proxy-groups":g=>g.name,proxies:p=>p.hosts?.[0] || p.name};
const defaultLabel = row => row.name;
/** Bounded remote combobox; it fetches only when opened or searched. */
export default function InventorySelect({kind,label,value,onChange,filters={},selected,extraOptions=[],format,disabled=false,...props}){
 const [open,setOpen]=useState(false),[query,setQuery]=useState(""),[page,setPage]=useState(1),[loaded,setLoaded]=useState([]),[chosen,setChosen]=useState(null);
 const filterKey=JSON.stringify(filters);
 useEffect(()=>{setPage(1);setLoaded([]);},[query,filterKey]);
 const inventory=useInventoryPage(kind,{...filters,q:query,page,page_size:20,options:true},{enabled:open});
 useEffect(()=>{if(!inventory.loading && !inventory.searchPending && inventory.data){setLoaded(old=>{const values=page===1 ? [] : old;const seen=new Set(values.map(v=>v._id));return [...values,...inventory.rows.filter(v=>!seen.has(v._id))];});}},[inventory.data,inventory.rows,page,inventory.loading,inventory.searchPending]);
 const selectedId=selected && typeof selected!=="string" ? selected._id || selected.data_id || selected.dataId : null;
 const preferred=!selectedId || selectedId===value ? selected : null;
 const matchingChosen=chosen && (chosen._id || chosen.data_id || chosen.dataId)===value ? chosen : null;
 useEffect(()=>{if(!inventory.loading && page>inventory.pagination.pages)setPage(inventory.pagination.pages);},[page,inventory.loading,inventory.pagination.pages]);
 const hasSelection = preferred && (typeof preferred === "string" || (kind === "machines" ? preferred.name && preferred.name!=="Selected machine" || preferred.hostname : kind === "connections" ? preferred.internal_port !== undefined : preferred.name));
 const needsSelection = /^[a-f0-9]{24}$/i.test(String(value || "")) && !hasSelection && !matchingChosen && !loaded.some(row => row._id === value);
 const detail=useInventoryPage(kind,{ids:value || "",page_size:1,options:true},{enabled:needsSelection});
 const renderLabel=format || labels[kind] || defaultLabel;
 const options=useMemo(()=>{
  const rows=[...extraOptions,...loaded.map(row=>({value:row._id,label:renderLabel(row),row}))];
  const fallback=(hasSelection ? preferred : null) || matchingChosen || detail.rows.find(row=>row._id===value) || preferred;
  if(value && !rows.some(r=>r.value===value) && fallback)rows.unshift({value,label:typeof fallback==="string" ? fallback : renderLabel(fallback),row:fallback});
  const seen=new Set();return rows.filter(row=>{if(seen.has(row.value))return false;seen.add(row.value);return true;});
 },[extraOptions,loaded,renderLabel,preferred,matchingChosen,value,detail.rows,hasSelection]);
 const paging={count:loaded.length,total:inventory.pagination.total,more:page<inventory.pagination.pages,loading:inventory.refreshing || inventory.searchPending,error:inventory.error,load:()=>setPage(p=>p+1)};
 return <Paging.Provider value={paging}><Select {...props} aria-label={label} value={String(value || "")} data={options.map(({value,label,disabled})=>({value,label,disabled}))} searchable searchValue={open ? query : options.find(o=>o.value===String(value))?.label || ""} onSearchChange={text=>{if(open)setQuery(text);}} filter={(text,item)=>loaded.some(row=>row._id===item.value) || Number.isFinite(searchScore(text,[item.label]))} dropdownOpened={open} onDropdownOpen={()=>{setQuery("");setPage(1);setOpen(true);}} onDropdownClose={()=>setOpen(false)} onChange={id=>{if(id!=null){setChosen(options.find(o=>o.value===id)?.row || null);onChange(id,options.find(o=>o.value===id)?.row);}}} nothingFound={inventory.searchPending ? "Searching…" : inventory.loading ? "Loading…" : inventory.error || "No matching options"} withinPortal zIndex={400} dropdownComponent={Dropdown} maxDropdownHeight={260} dropdownPosition="flip" disabled={disabled} rightSection={inventory.refreshing || inventory.searchPending ? <Loader size={13} /> : <IconChevronDown size={15} />} rightSectionWidth={32} classNames={{input:"!h-11 md:!h-10 !cursor-pointer !rounded-lg !border-transparent !bg-control !pr-9 !text-sm !text-foreground",dropdown:"!rounded-lg !border-border !bg-dialog !p-1 shadow-lg",item:"!cursor-pointer !rounded-md !text-sm !text-foreground data-[hovered]:!bg-accent data-[selected]:!bg-primary/10",rightSection:"pointer-events-none text-muted-foreground"}} /></Paging.Provider>;
}
