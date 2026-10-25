import { useWorkspaceState } from "@/shared/contexts/workspaceCache";
import { useEffect, useRef } from "react";
import axios from "axios";
import apiRoutes from "@/shared/routes/apiRoutes";

// One request at a time: a slow response cannot overwrite a newer snapshot.
export default function useTrafficSnapshot({ ids, enabled = true, preload = true, interval = 2000 } = {}) {
  const key = ids === undefined ? "all" : [...new Set(ids.filter(Boolean))].sort().join(",");
  const [state, setState] = useWorkspaceState(`snapshots.traffic:${key}`, { rows: [], loading: true, error: "", updated: null });
  const requested = useRef({ key, value: state.updated !== null });
  if (requested.current.key !== key) requested.current = { key, value: state.updated !== null };
  useEffect(() => {
    if (!enabled && (!preload || requested.current.value)) return;
    if (key === "") { setState({ rows: [], loading: false, error: "", updated: null }); return; }
    let active = true, timeout;
    const controller = new AbortController();
    async function poll() {
      if (document.hidden) return;
      requested.current.value = true;
      try {
        const response = await axios.post(apiRoutes.trafficSnapshot, key === "all" ? {} : { data_ids: key.split(",") }, { signal: controller.signal });
        if (active) setState({ rows: response.data?.data || [], loading: false, error: "", updated: Date.now() });
      } catch (error) {
        if (active) setState(current => ({ ...current, loading: false, error: error?.response?.data?.detail || "Traffic is temporarily unavailable." }));
      } finally { if (active && enabled) timeout = setTimeout(poll, interval); }
    }
    const visible = () => { if (!document.hidden && (enabled || !requested.current.value)) poll(); };
    poll();
    document.addEventListener("visibilitychange", visible);
    return () => { active = false; controller.abort(); clearTimeout(timeout); document.removeEventListener("visibilitychange", visible); };
  }, [key, enabled, preload, interval]);
  return state;
}
