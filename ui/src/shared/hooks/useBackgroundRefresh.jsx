import { useEffect, useRef } from "react";

// Revalidate mounted views without polling inactive tabs or overlapping slow
// requests. Keep the callback fresh without restarting the polling interval.
export default function useBackgroundRefresh(refresh, { enabled = true, interval = 15000, refreshKey } = {}) {
  const callback = useRef(refresh);
  callback.current = refresh;
  useEffect(() => {
    if (!enabled) return;
    let disposed = false, busy = false, timer;
    const controller = new AbortController();
    async function run() {
      if (disposed || busy || document.hidden) return;
      clearTimeout(timer);
      busy = true;
      try { await callback.current(controller.signal); }
      catch (error) { if (!controller.signal.aborted) console.error("Background refresh failed", error); }
      finally {
        busy = false;
        if (!disposed) timer = setTimeout(run, interval);
      }
    }
    const visible = () => { if (!document.hidden) run(); };
    run();
    document.addEventListener("visibilitychange", visible);
    return () => {
      disposed = true;
      controller.abort();
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", visible);
    };
  }, [enabled, interval, refreshKey]);
}
