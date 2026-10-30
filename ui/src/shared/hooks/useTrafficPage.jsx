import { useEffect, useRef, useState } from "react";
import axios from "axios";
import { useWorkspaceState } from "@/shared/contexts/workspaceCache";
import { useDebouncedSearch } from "./useInventoryPage";
import { inventoryUrl } from "@/shared/utils/inventory-resource.mjs";
import { mergeTrafficPage, trafficRowCursors } from "@/shared/utils/traffic-delta.mjs";

const EMPTY = [];
export default function useTrafficPage(params = {}, { enabled = true, live = true, refresh = 0, kind = "traffic" } = {}) {
  const query = useDebouncedSearch(params.q || "");
  const key = inventoryUrl(kind, { ...params, q: query });
  const [cached, setCached] = useWorkspaceState(`traffic.page:${kind}`, null);
  const cachedRef=useRef(cached);
  cachedRef.current=cached;
  const [state, setState] = useState(() => cached?.key === key ? cached : { key, rows: [], aggregate: [], loading: true, error: "", updated: null });
  useEffect(() => {
    if (!enabled) return;
    let alive = true, timer, busy = false;
    const controller = new AbortController();
    const saved=cachedRef.current;
    let current = saved?.key === key ? saved : { key, rows: [], aggregate: [], loading: true, error: "", updated: null, cursor: 0 };
    setState(current);
    async function poll() {
      if (!alive || busy || document.hidden) return;
      clearTimeout(timer); busy = true;
      try {
        const cursors=trafficRowCursors(current.rows,kind==="machine-traffic");
        const delta=new URLSearchParams({since:String(current.cursor || 0),scope_revision:current.scopeRevision || "",aggregate_token:current.aggregateToken || "",[kind==="machine-traffic" ? "row_tokens" : "row_cursors"]:cursors});
        const response=await axios.get(`${key}&${delta}`,{signal:controller.signal});
        if(!alive)return;
        current=mergeTrafficPage(current,response.data,key);
        setState(current); setCached(current);
      } catch (error) {
        if (alive && !axios.isCancel(error)) {
          current = { ...current, loading: false, error: error.response?.data?.detail || "Traffic is temporarily unavailable." };
          setState(current);
        }
      } finally { busy = false; if (alive && live) timer = setTimeout(poll, 2000); }
    }
    const visible = () => { if (!document.hidden && (live || !current.updated)) poll(); };
    if (live || !current.updated) poll(); document.addEventListener("visibilitychange", visible);
    return () => { alive = false; controller.abort(); clearTimeout(timer); document.removeEventListener("visibilitychange", visible); };
  }, [key, kind, enabled, live, refresh, setCached]);
  return state.key === key ? state : { key, rows: EMPTY, aggregate: EMPTY, loading: true, error: "", updated: null };
}
