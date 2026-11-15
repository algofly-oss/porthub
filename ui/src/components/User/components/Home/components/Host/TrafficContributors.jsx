import { useEffect, useRef, useState } from "react";
import axios from "axios";

const rate = value => {
  const n = Math.max(0, Number(value) || 0);
  return n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB/s` : n >= 1024 ? `${(n / 1024).toFixed(1)} KB/s` : `${Math.round(n)} B/s`;
};

export default function TrafficContributors({ timestamp }) {
  const cache = useRef(new Map());
  const [state, setState] = useState({ timestamp, loading: true });
  useEffect(() => {
    let alive = true, timer;
    let controller = new AbortController();
    setState({ timestamp, loading: true });
    const load = async () => {
      if (document.hidden) return;
      const saved = cache.current.get(timestamp);
      if (saved && Date.now() - saved.time < 2000) {
        setState({ timestamp, data: saved.data });
        return;
      }
      controller.abort();
      controller = new AbortController();
      try {
        const { data } = await axios.get(`/api/traffic/hover?timestamp=${Math.floor(timestamp)}&limit=6`, { signal: controller.signal });
        if (!alive) return;
        cache.current.set(timestamp, { time: Date.now(), data });
        while (cache.current.size > 64) cache.current.delete(cache.current.keys().next().value);
        setState({ timestamp, data });
      } catch (error) {
        if (alive && !axios.isCancel(error)) setState({ timestamp, error: true });
      }
    };
    const visibility = () => {
      if (document.hidden) controller.abort();
      else load();
    };
    timer = setTimeout(load, 120);
    document.addEventListener("visibilitychange", visibility);
    return () => { alive = false; clearTimeout(timer); controller.abort(); document.removeEventListener("visibilitychange", visibility); };
  }, [timestamp]);
  const current = state.timestamp === timestamp ? state : { loading: true };
  return <div aria-label="Public traffic destinations" aria-live="polite" className="mt-2 max-h-[min(50vh,340px)] overflow-y-auto border-t border-border pt-2">
    {current.loading ? <p className="text-muted-foreground">Loading destinations…</p> : current.error ? <p className="text-muted-foreground">Traffic details unavailable.</p> : <>
      {!current.data?.contributors?.length && <p className="text-muted-foreground">No measured port traffic at this time.</p>}
      {current.data?.contributors?.map(row => <div key={row.connection_id} className="border-b border-border py-2 last:border-0">
        <p className="break-words font-medium">{row.machine_name || "Unnamed machine"} · {row.service_name || "Forwarded port"}</p>
        <p className="break-all">Public :{row.public_port ?? "unavailable"} → {row.configured_target?.host || "unavailable"}:{row.configured_target?.port ?? "—"}</p>
        <p className="text-muted-foreground">Current destination · In {rate(row.incoming_bytes_per_second)} · Out {rate(row.outgoing_bytes_per_second)}</p>
        <p className="mt-1 break-all">{row.source_status === "observed" ? `From ${row.accepted_incoming_ips?.length ? row.accepted_incoming_ips.join(", ") : "no accepted sources observed"}${row.source_ips_truncated ? " …" : ""}` : row.source_status === "outside_observation_window" ? "Source IPs outside observation window" : "Source IPs unavailable for this sample"}</p>
        {row.source_status === "observed" && <p className="text-muted-foreground">Accepted packets · {row.accepted_incoming_ips_window_seconds}s observation · port totals, not per-IP rates</p>}
      </div>)}
      {current.data?.truncated && <p className="pt-1 text-muted-foreground">Showing {current.data.contributors.length} of {current.data.total_contributors} active ports</p>}
    </>}
  </div>;
}
