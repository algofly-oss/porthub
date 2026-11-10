import { useCallback, useEffect, useState } from "react";
import axios from "axios";
import toast from "react-hot-toast";
import { IconCopy, IconDotsVertical, IconPhoto, IconPlus, IconRefresh } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Menu } from "@/components/ui/menu";
import { Table, TableHeader, TableHead, TableRow, TableBody, TableCell } from "@/components/ui/table";
import { EmptyState, PageHeader } from "@/components/ui/workspace";
import ResultsPagination from "@/components/ui/results-pagination";
import { copyText } from "@/shared/utils/clipboard";
import Gallery from "./Gallery";
const ENDPOINT = "/api/image-rooms";
function link(room) { return new URL(room.url, location.origin).href; }
function message(error) { return error?.response?.data?.detail || "Could not update the room. Try again."; }

export default function ImageRooms({ active }) {
  const [rooms, setRooms] = useState([]), [loading, setLoading] = useState(false), [error, setError] = useState("");
  const [edit, setEdit] = useState(null), [inspect, setInspect] = useState(null), [deleting, setDeleting] = useState(null);
  const [busy, setBusy] = useState(false), [latest, setLatest] = useState(null), [page, setPage] = useState(1), [pageSize, setPageSize] = useState(10);
  const [name, setName] = useState(""), [minutes, setMinutes] = useState(60);
  const load = useCallback(async signal => {
    setLoading(true);
    try { const { data } = await axios.get(ENDPOINT, { signal }); setRooms(data.rooms); setError(""); }
    catch (error) { if (!axios.isCancel(error)) setError("Could not load rooms. Try refreshing."); }
    finally { if (!signal?.aborted) setLoading(false); }
  }, []);
  useEffect(() => {
    if (!active) return;
    const controller = new AbortController(); load(controller.signal);
    const timer = setInterval(() => { if (!document.hidden && !busy) load(controller.signal); }, 15000);
    return () => { controller.abort(); clearInterval(timer); };
  }, [active, busy, load]);
  useEffect(() => { if (!active) { setEdit(null); setInspect(null); setDeleting(null); } }, [active]);
  const pages = Math.max(1, Math.ceil(rooms.length / pageSize)), current = Math.min(page, pages);
  const copy = async room => {
    try { await copyText(link(room)); toast.success("Room link copied"); }
    catch { setLatest(room); toast.error("Select and copy the room link below."); }
  };
  function settings(room) { setName(room?.name || ""); setMinutes((room?.image_ttl_seconds || 3600) / 60); setEdit(room || {}); }
  async function save(event) {
    event.preventDefault(); setBusy(true);
    try {
      const body = { name, image_ttl_seconds: Math.round(Number(minutes) * 60) };
      const { data } = edit.id ? await axios.patch(`${ENDPOINT}/${edit.id}`, body) : await axios.post(ENDPOINT, body);
      const created = !edit.id; setEdit(null); setLatest(data); setPage(1); await load();
      if (created) { try { await copyText(link(data)); toast.success("Room created. Link copied."); } catch { toast.success("Room created. Click Copy link to share."); } }
      else toast.success("Room settings saved. New uploads use the updated lifetime.");
    } catch (error) { toast.error(message(error)); }
    finally { setBusy(false); }
  }
  async function toggle(room) {
    setBusy(true);
    try { await axios.patch(`${ENDPOINT}/${room.id}`, { enabled: !room.enabled }); await load(); toast.success(room.enabled ? "Room uploads paused" : "Room uploads enabled"); }
    catch (error) { toast.error(message(error)); }
    finally { setBusy(false); }
  }
  async function remove() {
    setBusy(true);
    try { await axios.delete(`${ENDPOINT}/${deleting.id}`); setLatest(value => value?.id === deleting.id ? null : value); setDeleting(null); await load(); toast.success("Room and its images deleted"); }
    catch (error) { toast.error(message(error)); }
    finally { setBusy(false); }
  }
  return <div className="workspace-page">
    <PageHeader title="Public rooms" actions={<><Button variant="secondary" size="icon" aria-label="Refresh rooms" disabled={loading || busy} onClick={() => load()}><IconRefresh size={18} /></Button><Button disabled={busy} onClick={() => settings(null)}><IconPlus size={18} />New room</Button></>} />
    <p className="mb-3 shrink-0 text-xs leading-5 text-muted-foreground">Anyone with a room link can drop images without an account. Each room has its own 512 MiB; your personal images stay separate.</p>
    {latest && <div className="mb-3 flex shrink-0 flex-wrap items-center gap-3 rounded-lg border border-primary/20 bg-primary/5 px-4 py-3"><span className="text-xs">Room link</span><input readOnly aria-label="Latest room URL" value={link(latest)} onFocus={event => event.target.select()} className="min-w-0 flex-1 bg-transparent font-mono text-xs outline-none" /><Button variant="secondary" size="sm" onClick={() => copy(latest)}><IconCopy size={15} />Copy link</Button></div>}
    {error && <p role="alert" className="mb-3 text-sm text-red-500">{error}</p>}
    <div className="flex min-h-0 flex-col overflow-hidden rounded-xl border border-border bg-surface" style={{ flex: "0 1 auto" }}><div className="data-scroll">
      {!rooms.length ? <EmptyState icon={IconPhoto} title={loading ? "Loading rooms…" : "Create your first public room"} description="Create once, share the link, and let anyone drop images." /> : <Table aria-label="Public image rooms"><TableHeader><TableRow><TableHead>Room</TableHead><TableHead className="hidden sm:table-cell">Images expire after</TableHead><TableHead className="hidden md:table-cell">Usage</TableHead><TableHead>Status</TableHead><TableHead className="text-right">Actions</TableHead></TableRow></TableHeader><TableBody>{rooms.slice((current - 1) * pageSize, current * pageSize).map(room => <TableRow key={room.id}>
        <TableCell><button type="button" className="block max-w-full truncate text-left text-sm font-medium hover:text-primary" onClick={() => setInspect(room)}>{room.name}</button><span className="mt-1 block text-xs text-muted-foreground sm:hidden">{room.image_ttl_seconds / 60} min per image</span></TableCell>
        <TableCell className="hidden text-xs text-muted-foreground sm:table-cell">{room.image_ttl_seconds / 60} minutes per upload</TableCell><TableCell className="hidden text-xs text-muted-foreground md:table-cell">{room.image_count} images · {(room.used / 1024 / 1024).toFixed(1)} / 512 MiB</TableCell><TableCell className="text-xs">{room.enabled ? "Enabled" : "Disabled"}</TableCell>
        <TableCell><div className="flex items-center justify-end gap-1"><Button variant="secondary" size="sm" aria-label={`Copy room link for ${room.name}`} onClick={() => copy(room)}><IconCopy size={15} /><span className="hidden sm:inline">Copy link</span></Button><Menu withinPortal position="bottom-end"><Menu.Target><Button variant="ghost" size="icon" aria-label={`Room actions for ${room.name}`} disabled={busy}><IconDotsVertical size={17} /></Button></Menu.Target><Menu.Dropdown><Menu.Item onClick={() => setInspect(room)}>Inspect images</Menu.Item><Menu.Item onClick={() => settings(room)}>Room settings</Menu.Item><Menu.Item onClick={() => toggle(room)}>{room.enabled ? "Disable room" : "Enable room"}</Menu.Item><Menu.Item component="a" href={link(room)} target="_blank" rel="noreferrer">Open public room</Menu.Item><Menu.Item color="red" onClick={() => setDeleting(room)}>Delete room</Menu.Item></Menu.Dropdown></Menu></div></TableCell>
      </TableRow>)}</TableBody></Table>}
    </div><ResultsPagination count={rooms.length} noun="Rooms" page={current} pages={pages} pageSize={pageSize} onPage={setPage} onPageSize={value => { setPageSize(value); setPage(1); }} /></div>
    <Dialog opened={Boolean(edit)} onClose={() => { if (!busy) setEdit(null); }} title={edit?.id ? "Room settings" : "New public room"} size="sm">
      <form onSubmit={save} className="space-y-4"><label className="block text-sm">Name<Input autoFocus value={name} maxLength={80} onChange={event => setName(event.target.value)} placeholder="Image room" className="mt-2" /></label><label className="block text-sm">Image lifetime (minutes)<Input type="number" min="1" max="43200" step="1" required value={minutes} onChange={event => setMinutes(event.target.value)} className="mt-2" /></label><p className="text-xs leading-5 text-muted-foreground">The timer starts separately for each upload. The room stays live until you delete it. Disabling pauses new uploads. Oldest images are removed when its storage fills.</p><div className="flex justify-end gap-2"><Button type="button" variant="secondary" disabled={busy} onClick={() => setEdit(null)}>Cancel</Button><Button type="submit" disabled={busy}>{busy ? "Saving…" : edit?.id ? "Save settings" : "Create room"}</Button></div></form>
    </Dialog>
    <Dialog opened={Boolean(inspect)} onClose={() => { setInspect(null); load(); }} title="Inspect room" size="90%" closeButtonProps={{ "aria-label": "Close room inspection" }}><div className="h-[70vh] min-h-0">{inspect && <Gallery key={inspect.id} active={active} endpoint={`${ENDPOINT}/${inspect.id}/images`} roomMode ownerView />}</div></Dialog>
    <Dialog opened={Boolean(deleting)} onClose={() => { if (!busy) setDeleting(null); }} title="Delete room" size="sm"><p className="text-sm text-muted-foreground">Delete {deleting?.name} and all its images? The room link and its image links will stop working.</p><div className="mt-6 flex justify-end gap-2"><Button variant="secondary" disabled={busy} onClick={() => setDeleting(null)}>Cancel</Button><Button variant="destructive" disabled={busy} onClick={remove}>{busy ? "Deleting…" : "Delete room"}</Button></div></Dialog>
  </div>;
}
