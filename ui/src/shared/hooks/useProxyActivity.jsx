import { useWorkspaceState } from "@/shared/contexts/workspaceCache";
import { useEffect, useRef } from "react";
import axios from "axios";
import apiRoutes from "@/shared/routes/apiRoutes";

export default function useProxyActivity({ enabled = true, preload = true } = {}) {
  const [state, setState] = useWorkspaceState("snapshots.proxyActivity", {data:[],available:false,loading:true,error:"",updated:null});
  const requested = useRef(state.updated !== null);
  useEffect(() => {
    if (!enabled && (!preload || requested.current)) return;
    const controller = new AbortController(); let timer;
    async function poll() {
      if (document.hidden) return;
      requested.current = true;
      try {
        const response = await axios.get(apiRoutes.proxyActivity, {signal:controller.signal});
        if (!controller.signal.aborted) setState({...response.data,loading:false,error:"",updated:Date.now()});
      } catch (error) {
        if (!controller.signal.aborted) setState(previous=>({...previous,loading:false,error:"Request activity unavailable",updated:Date.now()}));
      } finally { if (!controller.signal.aborted && enabled) timer=setTimeout(poll,15000); }
    }
    const visible = () => { if (!document.hidden && (enabled || !requested.current)) poll(); };
    poll(); document.addEventListener("visibilitychange", visible);
    return () => {controller.abort();clearTimeout(timer);document.removeEventListener("visibilitychange", visible);};
  }, [enabled, preload]);
  return state;
}
