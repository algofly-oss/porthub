import { useEffect, useRef, useState } from "react";

// Management authority comes only from the authenticated API. Guest invitation
// and recovery capabilities are never sent as administrative credentials.
export default function useTerminalManagement(session, enabled) {
  const [allowed,setAllowed]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState("");
  const active=useRef(null);
  const [invitationsRevoked,setInvitationsRevoked]=useState(false);
  useEffect(()=>{
    setAllowed(false);setError("");setBusy(false);setInvitationsRevoked(false);active.current=enabled ? session : null;
    if(!enabled || !/^[a-f0-9]{32}$/.test(session || ""))return;
    let alive=true,checking=false,timer,deadline,controller;
    async function check(){
      if(checking)return;
      if(document.hidden){timer=setTimeout(check,15000);return;}
      checking=true;controller=new AbortController();deadline=setTimeout(()=>controller.abort(),5000);
      try {
        const response=await fetch(`/api/terminal/${session}/participants`,{credentials:"same-origin",cache:"no-store",signal:controller.signal});
        const result=response.ok ? await response.json() : null;
        if(alive){setAllowed(result?.can_manage===true);setInvitationsRevoked(previous=>previous || result?.invitations_revoked===true);}
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
  async function revokeInvitations(){
    if(!allowed || busy)return false;
    setBusy(true);setError("");const id=session;
    const controller=new AbortController(),deadline=setTimeout(()=>controller.abort(),5000);
    try{
      const response=await fetch(`/api/terminal/${id}/invitations/revoke`,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:"{}",signal:controller.signal});
      if(!response.ok){if([400,401,403].includes(response.status))setAllowed(false);throw new Error("New joins could not be blocked. Check your management access and try again.");}
      const result=await response.json();
      if(active.current===id && result.invitations_revoked===true){setInvitationsRevoked(true);return true;}
      return false;
    }catch(error){if(active.current===id)setError(error.name==="AbortError" ? "The invitation change could not be confirmed. Check its status before retrying." : error.message);return false;}
    finally{clearTimeout(deadline);if(active.current===id)setBusy(false);}
  }
  return {allowed:allowed && enabled,busy,error,remove,invitationsRevoked,revokeInvitations};
}
