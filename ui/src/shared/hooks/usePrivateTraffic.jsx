import { useEffect, useRef, useState } from "react";
import axios from "axios";
import { useWorkspaceState } from "@/shared/contexts/workspaceCache";
import { normalizePrivateTraffic, privateTrafficRequest, privateTrafficForRequest } from "@/shared/utils/private-traffic.mjs";

export default function usePrivateTraffic({ range, machine, search, page, selected, enabled, paused, refresh }) {
  const { key, listKey } = privateTrafficRequest({ range, machine, search, page, selected });
  const request = useRef(); request.current = { range, machine, search, page, selected };
  const pending = cached => ({ key, listKey, data: cached?.listKey === listKey && cached.data ? { ...cached.data, selected_flow: null } : null, loading: true, error: "", updated: cached?.listKey === listKey ? cached.updated : null });
  const [cached, setCached] = useWorkspaceState("private.traffic", null);
  const cache = useRef(cached); cache.current = cached;
  const lastRefresh = useRef(refresh);
  const [state, setState] = useState(() => cached?.key === key ? cached : pending(cached));
  useEffect(() => {
    if (!enabled) return;
    let alive = true, timer, busy = false;
    const controller = new AbortController();
    const expected = request.current;
    let current = cache.current?.key === key ? cache.current : pending(cache.current);
    setState(current);
    const forced = lastRefresh.current !== refresh; lastRefresh.current = refresh;
    async function poll() {
      if (!alive || busy || document.hidden) return;
      clearTimeout(timer); busy = true;
      try {
        const reply = await axios.get(key, { signal: controller.signal, timeout: 10000 });
        const data = privateTrafficForRequest(normalizePrivateTraffic(reply.data), expected);
        if (!alive) return;
        current = { key, listKey, data, loading: false, error: "", updated: Date.now() };
        setState(current); setCached(current);
      } catch (error) {
        if (alive && !axios.isCancel(error)) {
          current = { ...current, loading: false, error: error.response?.status === 404 ? "This gateway does not support private traffic yet." : "Private traffic is temporarily unavailable." };
          setState(current); setCached(current);
        }
      } finally { busy = false; if (alive && !paused) timer = setTimeout(poll, 30000); }
    }
    const visible = () => { if (!document.hidden && !paused) poll(); };
    if (forced || !paused || !current.data) poll();
    document.addEventListener("visibilitychange", visible);
    return () => { alive = false; controller.abort(); clearTimeout(timer); document.removeEventListener("visibilitychange", visible); };
  }, [key, listKey, enabled, paused, refresh, setCached]);
  return state.key === key ? state : pending(cache.current);
}
