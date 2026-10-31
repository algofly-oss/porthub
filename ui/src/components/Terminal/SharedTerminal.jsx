import { useEffect, useRef, useState } from "react";
import { IconCopy, IconPlugConnected, IconPlugConnectedX, IconTerminal2, IconUsers, IconUserMinus } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import HistoryPanel from "./HistoryPanel";
import useTerminalManagement from "./useTerminalManagement";

const MAX_PENDING = 1024 * 1024;
function bytesToBase64(bytes) {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
}

export default function SharedTerminal() {
  const container = useRef(null), terminal = useRef(null), connection = useRef(null);
  const permission = useRef(true), copySelection = useRef(false);
  const recovery = useRef(null), manualDisconnect = useRef(false), retryTimer = useRef(null);
  const retryDeadline = useRef(null), retryCount = useRef(0);
  const [participant, setParticipant] = useState(null);
  const [sessionId,setSessionId]=useState(null),[confirmRemoval,setConfirmRemoval]=useState(null),[confirmInvitations,setConfirmInvitations]=useState(false);
  const history = useRef({serial:0,pending:null,timer:null}), historyAction=useRef(null), historyVisible=useRef(false);
  const [historyOpen,setHistoryOpen]=useState(false),[historyPane,setHistoryPane]=useState(""),[historyPageSize,setHistoryPageSize]=useState(200);
  historyVisible.current=historyOpen;
  const [historyText,setHistoryText]=useState(""),[historyBusy,setHistoryBusy]=useState(false),[historyError,setHistoryError]=useState("");
  const [historyMeta,setHistoryMeta]=useState({total:0,before:0,lines:0,truncated:false});
  const [ready, setReady] = useState(false), [attempt, setAttempt] = useState(0);
  const [status, setStatus] = useState("Not connected"), [error, setError] = useState("");
  const [session, setSession] = useState(null), [members, setMembers] = useState([]);
  const [autoCopy, setAutoCopy] = useState(false);
  const [clipboardStatus, setClipboardStatus] = useState("");
  const management=useTerminalManagement(sessionId,status==="Connected");

  useEffect(() => {
    let alive = true, instance, observer, resizeFrame, wheelSurface, wheelListener;
    Promise.all([import("@xterm/xterm"), import("@xterm/addon-fit")]).then(([{ Terminal }, { FitAddon }]) => {
      if (!alive) return;
      instance = new Terminal({
        cursorBlink: true, disableStdin: true, scrollback: 100000, fontSize: 14,
        fontFamily: '"SFMono-Regular", Consolas, "Liberation Mono", monospace',
        theme: { background: "#101214", foreground: "#e4e7eb", cursor: "#a3e635", selectionBackground: "#334155" },
        allowProposedApi: false,
      });
      const fit = new FitAddon(); instance.loadAddon(fit); instance.open(container.current);
      wheelSurface=container.current;
      wheelListener=event=>{
        if(permission.current && connection.current?.readyState===WebSocket.OPEN && event.deltaY<0 && !historyVisible.current){
          event.preventDefault();event.stopPropagation();historyAction.current?.();
        }
      };
      wheelSurface.addEventListener("wheel",wheelListener,{passive:false,capture:true});
      const resize = () => {
        cancelAnimationFrame(resizeFrame);
        resizeFrame = requestAnimationFrame(() => {
          if (!alive || !container.current?.clientWidth) return;
          fit.fit();
          if (instance.cols > 500 || instance.rows > 200 || instance.cols < 20 || instance.rows < 5)
            instance.resize(Math.max(20, Math.min(500, instance.cols)), Math.max(5, Math.min(200, instance.rows)));
        });
      };
      observer = new ResizeObserver(resize); observer.observe(container.current); resize();
      instance.attachCustomKeyEventHandler(event=>{
        if (event.key==="F7") {if(event.type==="keydown"){event.preventDefault();event.stopPropagation();historyAction.current?.();}return false;}
        return true;
      });
      instance.onResize(({ cols, rows }) => {
        const socket = connection.current;
        if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: "resize", cols, rows }));
      });
      instance.onData(data => {
        const socket = connection.current;
        if (permission.current || socket?.readyState !== WebSocket.OPEN) return;
        const bytes = new TextEncoder().encode(data);
        if (bytes.length > 65536 || socket.bufferedAmount > 262144) {
          setError("Input is too large or the connection is busy. Wait, then paste a smaller section."); return;
        }
        for (let offset = 0; offset < bytes.length; offset += 16384)
          socket.send(JSON.stringify({ type: "input", data: bytesToBase64(bytes.subarray(offset, offset + 16384)) }));
      });
      instance.onSelectionChange(() => {
        const text = instance.getSelection();
        if (copySelection.current && text) {
          if (!navigator.clipboard?.writeText) { setClipboardStatus("Clipboard unavailable. Use your browser’s Copy command."); return; }
          navigator.clipboard.writeText(text).then(() => { if (alive) setClipboardStatus("Selection copied"); })
            .catch(() => { if (alive) setClipboardStatus("Clipboard permission denied. Use your browser’s Copy command."); });
        }
      });
      terminal.current = instance; setReady(true);
    }).catch(() => { if (alive) setError("The terminal could not load. Reload this page to try again."); });
    return () => { alive = false; cancelAnimationFrame(resizeFrame); observer?.disconnect(); wheelSurface?.removeEventListener("wheel",wheelListener,true); clearTimeout(history.current.timer); terminal.current = null; instance?.dispose(); };
  }, []);

  useEffect(() => {
    if (!ready || !attempt) return;
    const token = window.location.hash.slice(1);
    if (!/^[a-f0-9]{64}$/.test(token)) { setError("This terminal invitation is incomplete or invalid."); return; }
    const storageKey = `porthub:terminal:recovery:${token}`;
    if (recovery.current?.invitation !== token) recovery.current = null;
    try {
      const saved = JSON.parse(sessionStorage.getItem(storageKey));
      recovery.current = saved && /^[a-f0-9]{64}$/.test(saved.token) && Number.isInteger(saved.reconnect_timeout) && saved.reconnect_timeout >= 10 && saved.reconnect_timeout <= 300 ? {...saved, invitation: token} : recovery.current;
    } catch { /* Use in-memory recovery when session storage is unavailable. */ }
    manualDisconnect.current = false;
    const endpoint = new URL("/api/terminal/join", window.location.origin);
    endpoint.protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(endpoint);
    const instance = terminal.current;
    let alive = true, pending = 0, closedReason = "", welcome = false, retryable = true;
    connection.current = socket; permission.current = true; instance.options.disableStdin = true;
    setStatus("Connecting…"); setError(""); setMembers([]); setSession(null);
    const handshake = setTimeout(() => { if (alive && !welcome) { closedReason = "Host unavailable or invitation expired. Try connecting again."; socket.close(); } }, 10000);
    socket.onopen = () => {
      if (!alive) return;
      socket.send(JSON.stringify({ ...(recovery.current ? {resume_token: recovery.current.token} : {token}), cols: Math.max(20, Math.min(500, instance.cols)), rows: Math.max(5, Math.min(200, instance.rows)), term: "xterm-256color" }));
    };
    socket.onmessage = ({ data }) => {
      if (!alive) return;
      try {
        if (typeof data !== "string" || data.length > 32768) throw new Error("Invalid terminal frame");
        const event = JSON.parse(data);
        if (event.type === "history") {
          const page=event.page, pending=history.current.pending;
          if (!pending || page?.request!==pending.request) return;
          if (typeof page.data!=="string" || page.data.length>21848 || typeof page.done!=="boolean" || !Number.isInteger(page.total) || page.total<0 || page.total>200000 || !Number.isInteger(page.before) || page.before<0 || page.before>200000 || !Number.isInteger(page.lines) || page.lines<0 || page.lines>512 || page.error!=null && (typeof page.error!=="string" || page.error.length>256)) throw new Error("Invalid history response");
          const decoded=atob(page.data),bytes=Uint8Array.from(decoded,char=>char.charCodeAt(0));
          pending.size+=bytes.length;if(pending.size>131072) throw new Error("History capture exceeds limit");pending.chunks.push(bytes);
          if (page.done) {
            clearTimeout(history.current.timer);history.current.pending=null;
            const data=new Uint8Array(pending.size);let offset=0;for(const chunk of pending.chunks){data.set(chunk,offset);offset+=chunk.length;}
            if(page.error){setHistoryError(page.error);setHistoryBusy(false);return;}
            setHistoryText(new TextDecoder().decode(data).replace(/[\x00-\x08\x0b-\x1f\x7f]/g,""));
            setHistoryMeta({total:page.total,before:page.before,lines:page.lines,truncated:page.truncated===true});
            setHistoryError(page.error || "");setHistoryBusy(false);
          }
        } else if (event.type === "recovery") {
          if (!/^[a-f0-9]{64}$/.test(event.token) || !Number.isSafeInteger(event.participant) || !Number.isInteger(event.reconnect_timeout) || event.reconnect_timeout < 10 || event.reconnect_timeout > 300) throw new Error("Invalid recovery credential");
          recovery.current = {token: event.token, reconnect_timeout: event.reconnect_timeout, invitation: token};
          setParticipant(event.participant);
          if(typeof event.session==="string" && /^[a-f0-9]{32}$/.test(event.session))setSessionId(event.session);
          try { sessionStorage.setItem(storageKey, JSON.stringify(recovery.current)); } catch { /* Memory recovery still works when tab storage is unavailable. */ }
        } else if (event.type === "welcome") {
          if (typeof event.name !== "string" || typeof event.read_only !== "boolean") throw new Error("Invalid session");
          welcome = true; retryDeadline.current = null; retryCount.current = 0; clearTimeout(handshake); setSession(event); setStatus("Connected");
          permission.current = event.read_only; instance.options.disableStdin = event.read_only;
          instance.reset(); instance.focus();
        } else if (event.type === "output") {
          if (!welcome || typeof event.data !== "string" || event.data.length > 21848) throw new Error("Invalid terminal output");
          const decoded = atob(event.data), bytes = Uint8Array.from(decoded, char => char.charCodeAt(0));
          pending += bytes.length;
          if (pending > MAX_PENDING) { closedReason = "This browser cannot keep up with output. Reconnect to redraw the current terminal."; socket.close(); return; }
          instance.write(bytes, () => { pending -= bytes.length; });
        } else if (event.type === "presence") {
          if (!Array.isArray(event.members) || event.members.length > 32 || event.members.some(member => !Number.isSafeInteger(member.id) || typeof member.read_only !== "boolean")) throw new Error("Invalid participant list");
          setMembers(event.members);
        } else if (event.type === "closed") {
          retryable = event.retryable === true;
          closedReason = typeof event.reason === "string" ? event.reason.slice(0, 200) : "Session ended"; socket.close();
        } else if (event.type === "ping") socket.send(JSON.stringify({ type: "pong" }));
      } catch { retryable = false; closedReason = "Invalid terminal response. The connection was closed."; socket.close(); }
    };
    socket.onclose = () => {
      if (!alive) return;
      clearTimeout(handshake); permission.current = true; instance.options.disableStdin = true;
      setMembers([]);
      if(history.current.pending){clearTimeout(history.current.timer);history.current.pending=null;setHistoryBusy(false);setHistoryError("Connection changed. Refresh history after reconnecting.");}
      if (!manualDisconnect.current && retryable && recovery.current) {
        if (!retryDeadline.current) retryDeadline.current = Date.now() + recovery.current.reconnect_timeout * 1000;
        if (Date.now() < retryDeadline.current) {
          setStatus("Reconnecting…");
          const delay = Math.min(5000, 500 * 2 ** Math.min(4, retryCount.current++));
          retryTimer.current = setTimeout(() => setAttempt(value => value + 1), delay);
          return;
        }
      }
      setStatus("Disconnected");
      if (closedReason) setError(closedReason);
    };
    socket.onerror = () => { if (alive) setError("Could not reach the terminal host. Check the connection and try again."); };
    return () => { alive = false; clearTimeout(handshake); clearTimeout(retryTimer.current); socket.close(); if (connection.current === socket) connection.current = null; };
  }, [ready, attempt]);

  useEffect(()=>{
    const key=event=>{if(event.key==="F7"){event.preventDefault();historyAction.current?.();}};
    window.addEventListener("keydown",key);return()=>window.removeEventListener("keydown",key);
  },[]);
  async function copy() {
    const selected = historyOpen ? window.getSelection()?.toString() : terminal.current?.getSelection();
    if (!selected) { setClipboardStatus("Select terminal text first."); return; }
    try { await navigator.clipboard.writeText(selected); setClipboardStatus("Selection copied"); }
    catch { setClipboardStatus("Clipboard unavailable. Use your browser’s Copy command."); }
  }
  function loadHistory(before=0) {
    const socket=connection.current;
    if(socket?.readyState!==WebSocket.OPEN || status!=="Connected"){setHistoryError("Connect to read retained history.");return;}
    if(history.current.pending)return;
    if(historyPane && !/^%[0-9]{1,19}$/.test(historyPane)){setHistoryError("Choose a pane ID such as %0, or leave it blank for the active pane.");return;}
    const request=(history.current.serial+1)>>>0;history.current.serial=request;
    history.current.pending={request,chunks:[],size:0};setHistoryBusy(true);setHistoryError("");
    socket.send(JSON.stringify({type:"history",request,pane:historyPane,before,lines:historyPageSize}));
    history.current.timer=setTimeout(()=>{history.current.pending=null;setHistoryBusy(false);setHistoryError("History request timed out. The live terminal is still available; try Refresh history.");},5000);
  }
  historyAction.current=()=>{setHistoryOpen(!historyOpen);if(!historyOpen)loadHistory(0);else requestAnimationFrame(()=>terminal.current?.focus());};
  const connected = status === "Connected", connecting = (status === "Connecting…" || status === "Reconnecting…");
  return <main className="flex h-[100dvh] min-h-0 flex-col bg-background text-foreground" aria-label="Shared terminal">
    <header className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3">
      <div className="flex min-w-0 items-center gap-3"><IconTerminal2 size={23} className="shrink-0 text-primary" /><div className="min-w-0"><h1 className="truncate text-sm font-semibold">{session?.name || "PortHub shared terminal"}</h1><p role="status" className="mt-0.5 text-xs text-muted-foreground">{status}{session ? ` · ${session.read_only ? "Read-only" : "Interactive"}` : " · Join with an invitation"}</p></div></div>
      <div className="flex flex-wrap items-center gap-2"><Button variant="secondary" size="sm" disabled={!connected} onClick={()=>historyAction.current()}>History</Button><Button variant="secondary" size="sm" onClick={copy}><IconCopy size={15} />Copy selection</Button>{connected || connecting ? <Button variant="secondary" size="sm" onClick={()=>{manualDisconnect.current=true;clearTimeout(retryTimer.current);retryDeadline.current=null;connection.current?.close();setStatus("Disconnected");}}><IconPlugConnectedX size={15} />Disconnect</Button> : <Button size="sm" disabled={!ready} onClick={()=>{clearTimeout(retryTimer.current);retryDeadline.current=null;setAttempt(value=>value+1);}}><IconPlugConnected size={15} />{attempt ? "Reconnect" : "Connect"}</Button>}</div>
    </header>
    {error && <p role="alert" className="shrink-0 bg-amber-500/10 px-4 py-2 text-sm text-amber-700 dark:text-amber-300">{error}</p>}
    <div className="flex min-h-0 flex-1 flex-col md:flex-row">
      {historyOpen && <HistoryPanel text={historyText} meta={historyMeta} pane={historyPane} setPane={setHistoryPane} pageSize={historyPageSize} setPageSize={setHistoryPageSize} busy={historyBusy} error={historyError} load={loadHistory} close={()=>{setHistoryOpen(false);requestAnimationFrame(()=>terminal.current?.focus());}} onSelection={()=>{if(autoCopy)copy();}} />}
      <section className={`${historyOpen ? "hidden" : ""} min-h-0 min-w-0 flex-1 bg-[#101214] p-2`} aria-label="Terminal output"><div ref={container} className="h-full min-h-0 w-full overflow-hidden" /></section>
      <aside aria-label="Session participants" className="flex max-h-[45dvh] shrink-0 flex-col overflow-hidden border-t border-border bg-surface p-4 md:max-h-none md:w-72 md:border-l md:border-t-0">
        <h2 className="flex items-center gap-2 text-xs font-semibold"><IconUsers size={16} />Participants <span className="ml-auto tabular-nums text-muted-foreground">{members.length}</span></h2>
        <div className="mt-3 min-h-0 flex-1 overflow-auto">{members.length ? <ul className="space-y-3">{members.map(member=><li key={member.id} className="flex items-center justify-between gap-2 text-xs"><span className="min-w-0 truncate" title={`Guest ${member.id}`}>Guest {member.id}{member.id === participant ? " (you)" : ""}</span><span className="shrink-0 rounded bg-muted px-2 py-1 text-muted-foreground">{member.read_only ? "Read-only" : "Interactive"}</span>{management.allowed && <button type="button" aria-label={`Remove Guest ${member.id}`} title="Remove participant" disabled={management.busy} onClick={()=>{setConfirmInvitations(false);setConfirmRemoval(member.id);}} className="shrink-0 rounded p-1 text-muted-foreground hover:bg-rose-500/10 hover:text-rose-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"><IconUserMinus size={15} /></button>}</li>)}</ul> : <p className="text-xs leading-5 text-muted-foreground">{connected ? "Waiting for participant details…" : "Connect to see who is attached."}</p>}</div>
        {management.allowed && <div className="mt-3 space-y-2"><p className="text-[11px] text-muted-foreground">Machine administrator · manage guests</p>{management.invitationsRevoked ? <p role="status" className="text-xs text-amber-600 dark:text-amber-300">New invitation joins blocked</p> : <Button size="sm" variant="secondary" disabled={management.busy} onClick={()=>{setConfirmRemoval(null);setConfirmInvitations(true);}}>Block new joins</Button>}</div>}
        {management.allowed && confirmInvitations && <div role="alertdialog" aria-label="Block new invitation joins" className="mt-3 rounded-lg bg-amber-500/10 p-3 text-xs"><p>Block new joins through the invitation URLs? Attached guests, their recovery access and the workspace will keep running.</p><div className="mt-2 flex gap-2"><Button size="sm" variant="secondary" disabled={management.busy} onClick={()=>setConfirmInvitations(false)}>Cancel</Button><Button size="sm" disabled={management.busy} onClick={async()=>{if(await management.revokeInvitations())setConfirmInvitations(false);}}>{management.busy ? "Blocking…" : "Block invitation URLs"}</Button></div></div>}
        {management.allowed && confirmRemoval!==null && <div role="alertdialog" aria-label={`Remove Guest ${confirmRemoval}`} className="mt-3 rounded-lg bg-amber-500/10 p-3 text-xs"><p>Remove Guest {confirmRemoval}? Their recovery access will be revoked.</p><div className="mt-2 flex gap-2"><Button size="sm" variant="secondary" disabled={management.busy} onClick={()=>setConfirmRemoval(null)}>Cancel</Button><Button size="sm" disabled={management.busy} onClick={async()=>{const remaining=await management.remove(confirmRemoval);if(remaining){setMembers(remaining);setConfirmRemoval(null);}}}>{management.busy ? "Removing…" : "Remove guest"}</Button></div></div>}
        {management.error && <p role="alert" className="mt-2 text-xs text-amber-600 dark:text-amber-300">{management.error}</p>}
      </aside>
    </div>
    <footer className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-t border-border px-4 py-2 text-[11px] text-muted-foreground"><span>{session?.read_only ? "Read-only viewing · F7 history" : "Ctrl+A prefix · F7 history"} · Disconnect leaves the workspace running</span><label className="flex items-center gap-2"><input type="checkbox" checked={autoCopy} onChange={event=>{setAutoCopy(event.target.checked);copySelection.current=event.target.checked;}} />Copy selected text automatically</label><span role="status" aria-live="polite">{clipboardStatus}</span></footer>
  </main>;
}
