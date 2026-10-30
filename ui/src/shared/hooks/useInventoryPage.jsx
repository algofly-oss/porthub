import { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";
import { useWorkspaceState } from "@/shared/contexts/workspaceCache";
import { createInventoryResource, inventoryUrl } from "@/shared/utils/inventory-resource.mjs";

const EMPTY_ROWS = [];
export function useDebouncedSearch(value,delay=250){
  const [search,setSearch]=useState(value);
  useEffect(()=>{const timer=setTimeout(()=>setSearch(value),delay);return()=>clearTimeout(timer);},[value,delay]);
  return search;
}
export default function useInventoryPage(kind,params={}, {enabled=true,ttl=60000}={}) {
  const [resource]=useWorkspaceState("inventory.resource",createInventoryResource);
  const search=useDebouncedSearch(params.q || "");
  const key=inventoryUrl(kind,{...params,q:search});
  const [revision,setRevision]=useState(0),[state,setState]=useState(()=>({key,data:resource.get(key)?.data,loading:!resource.get(key),error:""}));
  const refresh=useCallback(()=>{resource.invalidate(kind);},[resource,kind]);
  useEffect(()=>resource.subscribe(changed=>{if(!changed||changed===kind)setRevision(v=>v+1);}),[resource,kind]);
  useEffect(()=>{
    if(!enabled)return;
    const cached=resource.get(key);let active=true;
    setState({key,data:cached?.data,loading:!cached,error:"",refreshing:true});
    if(cached && !cached.stale && Date.now()-cached.updated<ttl){setState({key,data:cached.data,loading:false,error:"",refreshing:false});return;}
    const request=resource.acquire(key,async({signal,etag})=>{
      const response=await axios.get(key,{signal,headers:etag ? {"If-None-Match":etag} : {},validateStatus:status=>status===200 || status===304});
      return {status:response.status,data:response.data,etag:response.headers?.etag};
    });
    request.promise.then(result=>{if(active)setState({key,data:result.data,loading:false,refreshing:false,error:""});}).catch(error=>{
      if(active && !axios.isCancel(error) && error.name!=="AbortError")setState({key,data:cached?.data,loading:false,refreshing:false,error:typeof error.response?.data?.detail==="string" ? error.response.data.detail : "Could not load inventory. Try again."});
    });
    return()=>{active=false;request.release();};
  },[enabled,key,resource,revision,ttl]);
  const current=useMemo(()=>state.key===key ? state : {key,data:resource.get(key)?.data,loading:true,error:"",refreshing:true},[state,key,resource]);
  return useMemo(()=>({...current,rows:Array.isArray(current.data?.data) ? current.data.data : EMPTY_ROWS,pagination:current.data?.pagination || {page:params.page || 1,page_size:params.page_size || 25,total:0,pages:1},refresh,resource,searchPending:search!==(params.q || "")}),[current,params.page,params.page_size,params.q,refresh,resource,search]);
}
