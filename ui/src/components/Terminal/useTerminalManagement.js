import { useEffect, useRef, useState } from "react";

// Management authority comes only from the authenticated API. Guest invitation
// and recovery capabilities are never sent as administrative credentials.
export default function useTerminalManagement(session, enabled) {
  const [allowed,setAllowed]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState("");
  const active=useRef(null);
  useEffect(()=>{
    setAllowed(false);setError("");setBusy(false);active.current=enabled ? session : null;
    if(!enabled || !/^[a-f0-9]{32}$/.test(session || ""))return;
    let alive=true,checking=false,timer,deadline,controller;
    async function check(){
      if(checking)return;
      if(document.hidden){timer=setTimeout(check,15000);return;}
      checking=true;controller=new AbortController();deadline=setTimeout(()=>controller.abort(),5000);
      try {
        const response=await fetch(`/api/terminal/${session}/participants`,{credentials:"same-origin",cache:"no-store",signal:controller.signal});
        const result=response.ok ? await response.json() : null;
        if(alive)setAllowed(result?.can_manage===true);
      }catch{if(alive)setAllowed(false);}
      finally{checking=false;clearTimeout(deadline);if(alive)timer=setTimeout(check,15000);}
    }
    const visible=()=>{if(!document.hidden && !checking){clearTimeout(timer);check();}};
    document.addEventListener("visibilitychange",visible);
    check();
    return()=>{alive=false;document.removeEventListener("visibilitychange",visible);if(active.current===session)active.current=null;clearTimeout(timer);clearTimeout(deadline);controller?.abort();};
  },[session,enabled]);
  async function remove(client){
    if(!allowed || busy) return null;
    setBusy(true);setError("");const id=session;
    const controller=new AbortController(),deadline=setTimeout(()=>controller.abort(),5000);
    try{
      const response=await fetch(`/api/terminal/${id}/kick`,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({client}),signal:controller.signal});
      if(!response.ok){if(response.status===400 || response.status===401 || response.status===403)setAllowed(false);throw new Error("The guest could not be removed. Check your management access and try again.");}
      const result=await response.json();
      return active.current===id && Array.isArray(result.members) ? result.members : null;
    }catch(error){if(active.current===id)setError(error.name==="AbortError" ? "Removal could not be confirmed. Refresh the participant list before retrying." : error.message);return null;}
    finally{clearTimeout(deadline);if(active.current===id)setBusy(false);}
  }
  return {allowed:allowed && enabled,busy,error,remove};
}
