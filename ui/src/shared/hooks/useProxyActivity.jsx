import { useWorkspaceState } from "@/shared/contexts/workspaceCache";
import { useEffect } from "react";
import axios from "axios";
import apiRoutes from "@/shared/routes/apiRoutes";

export default function useProxyActivity() {
  const [state, setState] = useWorkspaceState("snapshots.proxyActivity", {data:[],available:false,loading:true,error:""});
  useEffect(() => {
    const controller = new AbortController(); let timer;
    async function poll() {
      try {
        const response = await axios.get(apiRoutes.proxyActivity, {signal:controller.signal});
        if (!controller.signal.aborted) setState({...response.data,loading:false,error:""});
      } catch (error) {
        if (!controller.signal.aborted) setState(previous=>({...previous,loading:false,error:"Request activity unavailable"}));
      } finally {
        if (!controller.signal.aborted) timer=setTimeout(poll,15000);
      }
    }
    poll(); return () => {controller.abort();clearTimeout(timer);};
  }, []);
  return state;
}
