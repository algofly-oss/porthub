import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";

export default function DashboardGuestLinks({ machineId, workspaceId, blocked, onIssued }) {
  const [links, setLinks] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const controller = useRef(null);
  useEffect(() => () => controller.current?.abort(), []);
  useEffect(() => { if (blocked) setLinks(null); }, [blocked]);
  useEffect(() => {
    if (!links) return;
    const timer = setTimeout(() => setLinks(null), Math.max(0, links.expires_at * 1000 - Date.now()));
    return () => clearTimeout(timer);
  }, [links]);
  async function issue() {
    if (busy) return;
    const request = new AbortController();
    controller.current = request;
    setBusy(true);
    setError("");
    try {
      const response = await fetch(`/api/machines/${machineId}/terminal-sessions/${workspaceId}/guest-links`, {
        method:"POST", headers:{"Content-Type":"application/json"}, body:"{}", signal:request.signal
      });
      if (!response.ok) throw new Error();
      const data = await response.json();
      if (!/^[a-f0-9]{64}$/.test(data.read) || (data.write && !/^[a-f0-9]{64}$/.test(data.write)) || !Number.isSafeInteger(data.expires_at)) throw new Error();
      if (!request.signal.aborted) { setLinks(data); onIssued(); }
    } catch { if (!request.signal.aborted) setError("Could not issue guest links. Check your access and retry."); }
    finally { if (!request.signal.aborted) setBusy(false); }
  }
  return <details className="mt-3 text-xs">
    <summary className="cursor-pointer font-medium">Invite guests</summary>
    <p className="my-2">Anyone with a link can join for the next 15 minutes. Creating links replaces the previous pair.</p>
    <Button type="button" size="sm" variant="secondary" disabled={busy} onClick={issue}>{busy ? "Creating…" : "Create guest links"}</Button>
    {error && <p role="alert">{error}</p>}
    {links && ["read","write"].filter(mode=>links[mode]).map(mode=>
      <label key={mode} className="mt-2 block">{mode === "read" ? "Read-only link" : "Interactive link"}
        <input className="mt-1 block w-full rounded border border-border bg-control px-2 py-1"
          readOnly spellCheck={false} autoComplete="off" onFocus={event=>event.target.select()}
          value={`${window.location.origin}/terminal#${links[mode]}`} />
      </label>)}
  </details>;
}
