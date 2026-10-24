import { useWorkspaceState } from "@/shared/contexts/workspaceCache";
import { useEffect } from "react";
import axios from "axios";
import apiRoutes from "@/shared/routes/apiRoutes";

// One request at a time: a slow response cannot overwrite a newer snapshot.
export default function useTrafficSnapshot({ ids, enabled = true, interval = 2000 } = {}) {
  const key = ids === undefined ? "all" : [...new Set(ids.filter(Boolean))].sort().join(",");
  const [state, setState] = useWorkspaceState(`snapshots.traffic:${key}`, { rows: [], loading: true, error: "", updated: null });
  useEffect(() => {
    if (!enabled) return;
    if (key === "") { setState({ rows: [], loading: false, error: "", updated: null }); return; }
    let active = true, timeout;
    const controller = new AbortController();
    async function poll() {
      try {
        if (!document.hidden) {
          const response = await axios.post(apiRoutes.trafficSnapshot, key === "all" ? {} : { data_ids: key.split(",") }, { signal: controller.signal });
          if (active) setState({ rows: response.data?.data || [], loading: false, error: "", updated: Date.now() });
        }
      } catch (error) {
        if (active) setState(current => ({ ...current, loading: false, error: error?.response?.data?.detail || "Traffic is temporarily unavailable." }));
      } finally { if (active) timeout = setTimeout(poll, interval); }
    }
    poll();
    return () => { active = false; controller.abort(); clearTimeout(timeout); };
  }, [key, enabled, interval]);
  return state;
}
