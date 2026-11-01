import { useEffect, useRef, useState } from "react";
import axios from "axios";
import { useWorkspaceState } from "@/shared/contexts/workspaceCache";
import { normalizeTerminalTraffic } from "@/shared/utils/terminal-traffic.mjs";

export default function useTerminalTraffic({ range, machine, enabled, paused, refresh }) {
  const key = `/api/terminal/traffic?${new URLSearchParams({ range, ...(machine === "all" ? {} : { machine_id: machine }) })}`;
  const [cached, setCached] = useWorkspaceState("terminal.traffic", null);
  const cache = useRef(cached); cache.current = cached;
  const lastRefresh = useRef(refresh);
  const [state, setState] = useState(() => cached?.key === key ? cached : { key, data: null, loading: true, error: "", updated: null });
  useEffect(() => {
    if (!enabled) return;
    let alive = true, timer, busy = false;
    const controller = new AbortController();
    let current = cache.current?.key === key ? cache.current : { key, data: null, loading: true, error: "", updated: null };
    setState(current);
    const forced = lastRefresh.current !== refresh; lastRefresh.current = refresh;
    async function poll() {
      if (!alive || busy || document.hidden) return;
      clearTimeout(timer); busy = true;
      try {
        const reply = await axios.get(key, { signal: controller.signal, timeout: 10000 });
        const data = normalizeTerminalTraffic(reply.data);
        if (data.range !== range) throw Error("Mismatched measurement range");
        if (!alive) return;
        current = { key, data, loading: false, error: "", updated: Date.now() };
        setState(current); setCached(current);
      } catch (error) {
        if (alive && !axios.isCancel(error)) {
          current = { ...current, loading: false, error: error.response?.status === 404 ? "This gateway does not support terminal measurements yet." : "Terminal measurements are temporarily unavailable." };
          setState(current); setCached(current);
        }
      } finally { busy = false; if (alive && !paused) timer = setTimeout(poll, 15000); }
    }
    const visible = () => { if (!document.hidden && !paused) poll(); };
    if (forced || !paused || !current.data) poll();
    document.addEventListener("visibilitychange", visible);
    return () => { alive = false; controller.abort(); clearTimeout(timer); document.removeEventListener("visibilitychange", visible); };
  }, [key, range, enabled, paused, refresh, setCached]);
  return state.key === key ? state : { key, data: null, loading: true, error: "", updated: null };
}
