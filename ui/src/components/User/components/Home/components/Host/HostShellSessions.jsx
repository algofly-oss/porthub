import axios from "axios";
import { sessionRows } from "@/shared/utils/host-shell-catalog.mjs";
import dynamic from "next/dynamic";
import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";

const SharedTerminal = dynamic(() => import("@/components/Terminal/SharedTerminal"), { ssr: false });

function invitationToken(value) {
  try {
    const link = new URL(value.trim());
    if (link.origin === window.location.origin && link.pathname.replace(/\/$/, "") === "/terminal" &&
        /^[a-f0-9]{64}$/.test(link.hash.slice(1))) return link.hash.slice(1);
  } catch { /* The field expects a complete link. */ }
  return null;
}

function InvitationForm({ session, onJoin }) {
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const request = useRef(null);
  useEffect(() => () => request.current?.abort(), []);
  async function join() {
    if (busy) return;
    const token = invitationToken(value);
    if (!token) { setError("Enter a terminal invitation link from this PortHub server."); return; }
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    try {
      const { data } = await axios.post("/api/terminal/info", { token }, { signal: controller.signal });
      if (data.id !== session.id || data.access === "ssh") {
        setError("This invitation does not grant browser access to the selected shell.");
        return;
      }
      if (!controller.signal.aborted) onJoin(token);
    } catch {
      if (!controller.signal.aborted) setError("The invitation has expired or the shell is unavailable.");
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }
  return <div className="space-y-2">
    <label className="block text-sm font-medium" htmlFor="host-shell-invitation">Invitation for {session.name}</label>
    <div className="flex flex-wrap gap-2">
      <input id="host-shell-invitation" type="password" autoComplete="off" spellCheck={false}
        className="min-w-40 flex-1 rounded-md border border-border bg-control px-3 py-2 text-sm"
        onKeyDown={event => { if (event.key === "Enter") { event.preventDefault(); join(); } }}
        value={value} onChange={event => { setValue(event.target.value); setError(""); }} required />
      <Button type="button" size="sm" onClick={join} disabled={busy}>{busy ? "Connecting…" : "Connect"}</Button>
    </div>
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
  </div>;
}

export default function HostShellSessions({ machineId, platform }) {
  const [owner, setOwner] = useState(null);
  const [canOpen, setCanOpen] = useState(false);
  const [opening, setOpening] = useState(false);
  const openRequest = useRef(null);
  const [sessions, setSessions] = useState(null);
  const [error, setError] = useState("");
  const [revision, setRevision] = useState(0);
  const [selected, select] = useState(null);
  const [invitations, setInvitations] = useState({});

  useEffect(() => {
    const controller = new AbortController();
    let timer;
    async function refresh() {
      try {
        const { data } = await axios.get(`/api/machines/${encodeURIComponent(machineId)}/terminal-sessions`, {
          signal: controller.signal,
        });
        if (controller.signal.aborted) return;
        const rows = sessionRows(data);
        setSessions(rows);
        setCanOpen(data.can_open === true);
        setOwner(/^[a-f0-9]{24}$/.test(data.owner_id) ? data.owner_id : null);
        select(current => rows.some(session => session.id === current) ? current : null);
        setInvitations(current => Object.fromEntries(rows.filter(s => current[s.id]).map(s => [s.id, current[s.id]])));
        setError("");
      } catch (failure) {
        if (controller.signal.aborted) return;
        if ([401,403,404].includes(failure.response?.status)) { setSessions(null); setCanOpen(false); select(null); setInvitations({}); }
        setError("Could not load shell sessions for this machine.");
      }
      timer = window.setTimeout(refresh, 5000);
    }
    refresh();
    return () => { controller.abort(); window.clearTimeout(timer); };
  }, [machineId, revision]);

  async function openShell() {
    if (opening) return;
    setOpening(true);
    try {
      openRequest.current ||= Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2,"0")).join("");
      const { data } = await axios.post(`/api/machines/${machineId}/terminal-sessions`, { request_id: openRequest.current });
      if (!/^[a-f0-9]{32}$/.test(data?.id)) throw new Error("Invalid shell response");
      openRequest.current = null;
      select(data.id);
      setRevision(value => value + 1);
    } catch (failure) {
      const detail = failure.response?.data?.detail;
      setError(typeof detail === "string" ? detail : "Could not open the shell. Try again.");
    } finally { setOpening(false); }
  }
  const active = sessions?.find(session => session.id === selected);
  return <section className="space-y-3 p-4" aria-label="Shell sessions">
    <div className="flex items-center justify-between gap-3">
      <h2 className="text-sm font-semibold">Shell sessions</h2>
      {canOpen && <Button type="button" size="sm" disabled={opening} onClick={openShell}>{opening ? "Opening…" : "New shell"}</Button>}
      <Button type="button" size="sm" variant="ghost" onClick={() => setRevision(value => value + 1)}>Refresh</Button>
    </div>
    {error && <p role="alert" className="text-sm">{error}</p>}
    {sessions?.length ? <div className="flex flex-wrap gap-2" role="group" aria-label="Choose shell">
      {sessions.map(session => <Button key={session.id} type="button" size="sm"
        aria-pressed={selected === session.id} variant={selected === session.id ? "secondary" : "outline"}
        onClick={() => select(session.id)}>{session.name}{session.read_only && " · Read only"}</Button>)}
    </div> : !error && <p role="status" className="text-sm text-muted-foreground">
      {sessions ? (canOpen ? "Choose New shell to start a workspace." : "No active browser shells.") : "Loading sessions…"}
    </p>}
    {!canOpen && owner && /^[a-f0-9]{24}$/.test(machineId) && <details className="rounded-md border border-border px-3 py-2 text-sm">
      <summary className="cursor-pointer font-medium">Enable browser shells on this machine</summary>
      {String(platform || "").toLowerCase() === "windows"
        ? <p className="mt-2">The native Windows agent does not host interactive shells. Install PortHub in a WSL distribution, enroll that Linux agent, then enable browser shells on its registration.</p>
        : <><p className="mt-2">Run this once as the local user whose shell you want to open. PortHub starts the shell service when that user logs in.</p>
          <code className="mt-2 block select-all break-all rounded bg-muted p-2">porthub terminal dashboard enable --owner {owner} --registration {machineId}</code>
          <p className="mt-2 text-muted-foreground">Replace <code>enable</code> with <code>status</code> to check hosting or <code>disable</code> to close its workspaces and remove the service. For a user-installed agent, add <code>--user</code>. If the dashboard command is missing, update PortHub first.</p></>}
    </details>}
    {active && (active.dashboard ? <SharedTerminal key={active.id} machineId={machineId} workspaceId={active.id} embedded /> : invitations[active.id]
      ? <SharedTerminal key={active.id} invitation={invitations[active.id]} embedded />
      : <InvitationForm key={active.id} session={active} onJoin={token => setInvitations(current => ({...current, [active.id]: token}))} />)}
  </section>;
}
