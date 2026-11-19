import axios from "axios";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";

export default function HostShellSessions({ machineId }) {
  const [sessions, setSessions] = useState(null);
  const [error, setError] = useState("");
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let timer;
    async function refresh() {
      try {
        const { data } = await axios.get(`/api/machines/${encodeURIComponent(machineId)}/terminal-sessions`, {
          signal: controller.signal,
        });
        if (controller.signal.aborted) return;
        setSessions(data.sessions);
        setError("");
      } catch {
        if (controller.signal.aborted) return;
        setSessions(null);
        setError("Could not load shell sessions for this machine.");
      }
      timer = window.setTimeout(refresh, 5000);
    }
    refresh();
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [machineId, revision]);

  return (
    <section className="space-y-3 p-4" aria-label="Shell sessions">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-sm font-semibold">Shell sessions</h2>
        <Button type="button" size="sm" variant="ghost" onClick={() => setRevision(value => value + 1)}>Refresh</Button>
      </div>
      {error ? <p role="alert">{error}</p> : sessions?.length ? (
        <ul className="divide-y divide-border">
          {sessions.map(session => (
            <li key={session.id} className="flex items-center justify-between gap-3 py-2">
              <span className="break-words font-medium">{session.name}</span>
              {session.read_only && <span className="text-sm text-muted-foreground">Read only</span>}
            </li>
          ))}
        </ul>
      ) : <p role="status" className="text-sm text-muted-foreground">{sessions ? "No active browser shells." : "Loading sessions…"}</p>}
    </section>
  );
}
