import { useEffect, useRef } from "react";

// Revalidate mounted views without polling inactive tabs or overlapping slow
// requests. Keep the callback fresh without restarting the polling interval.
export default function useBackgroundRefresh(refresh, { enabled = true, preload = false, interval = 15000, refreshKey } = {}) {
  const callback = useRef(refresh);
  const preloaded = useRef({ key: refreshKey, done: false });
  callback.current = refresh;
  useEffect(() => {
    if (preloaded.current.key !== refreshKey) preloaded.current = { key: refreshKey, done: false };
    let disposed = false, busy = false, timer;
    const controller = new AbortController();
    async function run() {
      if (disposed || busy || document.hidden || (!enabled && (!preload || preloaded.current.done))) return;
      clearTimeout(timer);
      preloaded.current.done = true;
      busy = true;
      try { await callback.current(controller.signal); }
      catch (error) { if (!controller.signal.aborted) console.error("Background refresh failed", error); }
      finally {
        busy = false;
        if (!disposed && enabled) timer = setTimeout(run, interval);
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
  }, [enabled, preload, interval, refreshKey]);
}
