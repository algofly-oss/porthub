import { searchScore } from "@/shared/utils/search.mjs";
import { createContext, forwardRef, useContext, useEffect, useMemo, useState } from "react";
import { MultiSelect } from "@mantine/core";
import axios from "axios";
import useInventoryPage from "@/shared/hooks/useInventoryPage";
import { inventoryUrl } from "@/shared/utils/inventory-resource.mjs";
const Paging=createContext(null);
const Dropdown=forwardRef(function Dropdown({children,...props},ref){const page=useContext(Paging);return <div ref={ref} {...props}>{children}{page.more && <button type="button" disabled={page.loading} onMouseDown={event=>event.preventDefault()} onClick={page.next} className="w-full border-t border-border px-3 py-2 text-sm text-primary">{page.loading ? "Loading…" : `Load more · ${page.total} matches`}</button>}{page.error && <p role="alert" className="p-2 text-xs text-red-600 dark:text-red-400">{page.error}</p>}</div>;});
const labelFor=row=>row.kind ? `${{machine:"Machine",group:"Group",user:"Person"}[row.kind] || row.kind} · ${row.name}` : row.name || row.email;

/** Remote multiple choice, preserving every selected ID across query pages. */
export default function InventoryMultiSelect({kind,label,value=[],onChange,filters={},extraOptions=[],disabled=false,placeholder="Search…",format=labelFor,...props}) {
  const [open,setOpen]=useState(false),[query,setQuery]=useState(""),[page,setPage]=useState(1),[loaded,setLoaded]=useState([]),[resolved,setResolved]=useState({});
  const filterKey=JSON.stringify(filters);
  const selectedKey=value.filter(id=>!extraOptions.some(option=>option.value===id)).slice().sort().join(",");
  const inventory=useInventoryPage(kind,{...filters,q:query,page,page_size:20,options:true},{enabled:open});
  useEffect(()=>{setPage(1);setLoaded([]);},[query,filterKey]);
  useEffect(()=>{if(!inventory.loading && !inventory.searchPending && inventory.data)setLoaded(old=>{const rows=page===1 ? [] : old;const seen=new Set(rows.map(row=>row._id));return [...rows,...inventory.rows.filter(row=>!seen.has(row._id))];});},[inventory.data,inventory.rows,inventory.loading,inventory.searchPending,page]);
  useEffect(()=>{if(!inventory.loading && page>inventory.pagination.pages)setPage(inventory.pagination.pages);},[page,inventory.loading,inventory.pagination.pages]);
  useEffect(()=>{
    let active=true,request;
    const ids=selectedKey ? selectedKey.split(",") : [];
    setResolved({});
    async function resolve(){
      for(let start=0;start<ids.length && active;start+=100){
        const key=inventoryUrl(kind,{...JSON.parse(filterKey),ids:ids.slice(start,start+100).join(","),page_size:100,options:true});
        const cached=inventory.resource.get(key);
        let data=cached?.data;
        if(!cached || cached.stale || Date.now()-cached.updated>60000){
          request=inventory.resource.acquire(key,async({signal,etag})=>{const response=await axios.get(key,{signal,headers:etag ? {"If-None-Match":etag} : {},validateStatus:status=>status===200 || status===304});return {status:response.status,data:response.data,etag:response.headers?.etag};});
          try {data=(await request.promise).data;}catch(error){if(active && !axios.isCancel(error) && error.name!=="AbortError")return;}finally{request.release();}
        }
        if(active)setResolved(old=>({...old,...Object.fromEntries((data?.data || []).map(row=>[row._id,row]))}));
      }
    }
    resolve();return()=>{active=false;request?.release();};
  },[kind,selectedKey,filterKey,inventory.resource]);
  const options=useMemo(()=>{
    const rows=[...extraOptions,...loaded.map(row=>({value:row._id,label:format(row)})),...Object.values(resolved).map(row=>({value:row._id,label:format(row)}))];
    const seen=new Set();const unique=rows.filter(row=>{if(seen.has(row.value))return false;seen.add(row.value);return true;});
    for(const id of value)if(!seen.has(id))unique.push({value:id,label:`Selected ${id.split(":").pop().slice(-8)}`});
    return unique;
  },[extraOptions,loaded,resolved,format,value]);
  return <Paging.Provider value={{more:page<inventory.pagination.pages,total:inventory.pagination.total,loading:inventory.refreshing || inventory.searchPending,error:inventory.error,next:()=>setPage(current=>current+1)}}><MultiSelect {...props} aria-label={label} searchable clearable disabled={disabled} value={value} onChange={onChange} data={options} filter={(text,selected,item)=>!selected && (loaded.some(row=>row._id===item.value) || Number.isFinite(searchScore(text,[item.label])))} searchValue={query} onSearchChange={setQuery} onDropdownOpen={()=>setOpen(true)} onDropdownClose={()=>setOpen(false)} onKeyDown={event=>{if(event.key==="Escape" && open)event.stopPropagation();}} placeholder={placeholder} nothingFound={inventory.searchPending ? "Searching…" : inventory.loading ? "Loading…" : "No matching options"} withinPortal zIndex={400} maxDropdownHeight={230} dropdownPosition="flip" dropdownComponent={Dropdown} classNames={{input:"!min-h-[40px] !rounded-lg !border-transparent !bg-control !text-foreground",searchInput:"!border-0 !bg-transparent !text-foreground !shadow-none !outline-none",dropdown:"!rounded-lg !border-border !bg-dialog !p-1",item:"!cursor-pointer !rounded-md !text-sm !text-foreground data-[hovered]:!bg-accent data-[selected]:!bg-primary/10",value:"!bg-surface !text-foreground",values:"max-h-20 overflow-auto"}} /></Paging.Provider>;
}
