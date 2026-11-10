import { useCallback, useEffect, useRef, useState } from "react";
import axios from "axios";
import { Popover } from "@mantine/core";
import apiRoutes from "@/shared/routes/apiRoutes";
import toast from "react-hot-toast";
import { IconPhoto, IconUpload, IconCopy, IconTrash, IconRefresh, IconArrowUpRight, IconKeyboard } from "@tabler/icons-react";
import { PageHeader, EmptyState } from "@/components/ui/workspace";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from "@/components/ui/table";
import ResultsPagination from "@/components/ui/results-pagination";
import { copyText } from "@/shared/utils/clipboard";

const ENDPOINT = apiRoutes.hostedImages;
const MAX_BYTES = 8 * 1024 * 1024;
const TYPES = new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);
function readImage(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",")[1]);
    reader.onerror = () => reject(new Error("Could not read image"));
    reader.readAsDataURL(file);
  });
}
function absoluteLink(image) { return { ...image, url: new URL(image.url, window.location.origin).href }; }
function errorMessage(error, fallback) {
  return typeof error?.response?.data?.detail === "string" ? error.response.data.detail : fallback;
}

export default function HostedImages({ active = true }) {
  const [images, setImages] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [uploading, setUploading] = useState(false);
  const [deleting, setDeleting] = useState("");
  const [dragging, setDragging] = useState(false);
  const [latest, setLatest] = useState(null);
  const [preview, setPreview] = useState(null);
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [helpOpen, setHelpOpen] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const busy = useRef(false);
  const mutation = useRef(0);
  const input = useRef(null);
  const dragDepth = useRef(0);
  const load = useCallback(async (signal) => {
    setLoading(true);
    const generation = mutation.current;
    try {
      const { data } = await axios.get(ENDPOINT, { signal });
      if (generation === mutation.current) setImages(data.images.map(absoluteLink));
      setLoadError("");
    } catch (error) {
      if (!axios.isCancel(error)) setLoadError("Could not load images. Try refreshing.");
    } finally { if (!signal?.aborted) setLoading(false); }
  }, []);
  useEffect(() => {
    if (!active) return;
    const controller = new AbortController();
    load(controller.signal);
    const refresh = () => { if (!document.hidden && !busy.current) load(controller.signal); };
    window.addEventListener("focus", refresh);
    return () => { controller.abort(); window.removeEventListener("focus", refresh); };
  }, [active, load]);

  const copy = async (image) => {
    try { await copyText(image.url); toast.success("Link copied"); }
    catch { toast.error("Could not copy. Select and copy the link below."); setLatest(image); }
  };
  const upload = useCallback(async (files) => {
    const chosen = Array.from(files || []);
    if (!chosen.length) return;
    if (busy.current) { toast.error("An upload is already running"); return; }
    busy.current = true; mutation.current++; setUploading(true);
    let last = null;
    try {
      for (const file of chosen) {
        if (!TYPES.has(file.type) || file.size === 0 || file.size > MAX_BYTES) {
          toast.error(`${file.name || "Image"}: use PNG, JPEG, WebP or GIF up to 8 MiB`); continue;
        }
        try {
          const image = await readImage(file);
          const { data } = await axios.post(ENDPOINT, { image, name: file.name || "Clipboard image" }, { timeout: 90000 });
          last = absoluteLink(data);
          const hosted = last;
          setImages(current => [hosted, ...current.filter(row => row.id !== hosted.id)]);
          setLatest(hosted);
          setPage(1);
        } catch (error) { toast.error(errorMessage(error, `Could not upload ${file.name || "image"}. Try again.`)); }
      }
      if (last) {
        try { await copyText(last.url); toast.success(chosen.length > 1 ? "Images uploaded. Last link copied." : "Image uploaded. Link copied.", { id: "hosted-image-upload" }); }
        catch { toast.success("Image uploaded. Click Copy link to share.", { id: "hosted-image-upload" }); }
      }
      if (last) await load(); // Reflect any oldest images evicted by storage admission.
    } finally { busy.current = false; setUploading(false); }
  }, [load]);

  useEffect(() => {
    if (!active) return;
    const paste = (event) => {
      if (event.target?.closest?.("input:not([type='file']):not([readonly]), textarea:not([readonly]), [contenteditable='true']")) return;
      const files = Array.from(event.clipboardData?.items || []).filter(item => item.kind === "file" && item.type.startsWith("image/")).map(item => item.getAsFile()).filter(Boolean);
      if (files.length) { event.preventDefault(); upload(files); }
    };
    window.addEventListener("paste", paste);
    return () => window.removeEventListener("paste", paste);
  }, [active, upload]);

  const remove = async (image) => {
    mutation.current++; setDeleting(image.id);
    try {
      await axios.delete(`${ENDPOINT}/${image.id}`);
      setImages(current => current.filter(row => row.id !== image.id));
      setLatest(current => current?.id === image.id ? null : current);
      setPreview(current => current?.id === image.id ? null : current);
      setDeleteTarget(null);
      toast.success("Image deleted. Public link disabled.");
    } catch (error) { toast.error(errorMessage(error, "Could not delete image. Try again.")); }
    finally { setDeleting(""); }
  };
  const used = images.reduce((sum, image) => sum + image.size, 0);
  const pages = Math.max(1, Math.ceil(images.length / pageSize));
  const currentPage = Math.min(page, pages);
  const visibleImages = images.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  useEffect(() => { if (page > pages) setPage(pages); }, [page, pages]);
  useEffect(() => { if (!active) { setPreview(null); setDeleteTarget(null); setHelpOpen(false); } }, [active]);
  return <div className="workspace-page" onDragEnter={event => {
    if (!Array.from(event.dataTransfer.types).includes("Files")) return;
    event.preventDefault(); dragDepth.current++; setDragging(true);
  }} onDragOver={event => { if (Array.from(event.dataTransfer.types).includes("Files")) { event.preventDefault(); event.dataTransfer.dropEffect = "copy"; } }} onDragLeave={event => {
    event.preventDefault(); dragDepth.current = Math.max(0, dragDepth.current - 1); if (!dragDepth.current) setDragging(false);
  }} onDrop={event => { event.preventDefault(); dragDepth.current = 0; setDragging(false); upload(event.dataTransfer.files); }}>
    <PageHeader title="Hosted images" actions={<>
      <Button variant="secondary" size="icon" aria-label="Refresh images" onClick={() => load()} disabled={loading || uploading}><IconRefresh size={18} /></Button>
      <Button onClick={() => input.current?.click()} disabled={uploading}><IconUpload size={18} />{uploading ? "Uploading…" : "Add images"}</Button>
    </>} />
    <input ref={input} type="file" accept="image/png,image/jpeg,image/webp,image/gif" multiple className="sr-only" aria-label="Choose images" onChange={event => { upload(event.target.files); event.target.value = ""; }} />
    <button type="button" onClick={() => input.current?.click()} disabled={uploading} className={`mb-4 flex w-full shrink-0 items-center gap-4 rounded-xl border border-dashed px-4 py-4 text-left transition-colors ${dragging ? "border-primary bg-primary/10" : "border-border bg-surface hover:border-primary/60 hover:bg-accent/40"}`}>
      <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary"><IconUpload size={21} stroke={1.7} /></span>
      <span className="min-w-0"><span className="block text-sm font-medium">{uploading ? "Uploading your images…" : dragging ? "Drop to upload" : "Paste a screenshot, drop images, or click to choose"}</span><span className="mt-1 block text-xs leading-5 text-muted-foreground">Your link is copied automatically. PNG, JPEG, WebP or GIF · Up to 8 MiB</span></span>
      <kbd className="ml-auto hidden shrink-0 rounded-md border border-border bg-control px-2 py-1 text-xs text-muted-foreground md:block">Ctrl / ⌘ + V</kbd>
    </button>
    {latest && <div className="mb-3 flex shrink-0 flex-wrap items-center gap-3 rounded-lg border border-primary/20 bg-primary/5 px-4 py-3" role="status">
      <span className="text-xs font-medium">Latest link</span>
      <input aria-label="Latest public image URL" readOnly value={latest.url} onFocus={event => event.target.select()} className="min-w-0 flex-1 bg-transparent font-mono text-xs outline-none" />
      <Button variant="secondary" size="sm" onClick={() => copy(latest)}><IconCopy size={15} />Copy link</Button>
    </div>}
    <div className="mb-2 flex shrink-0 flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground"><span>{images.length} {images.length === 1 ? "image" : "images"}<span className="mx-2 text-border">/</span>{(used / 1024 / 1024).toFixed(1)} of 512 MiB used</span><span>Oldest images are deleted automatically when storage is full.</span></div>
    {loadError && <p role="alert" className="mb-3 text-sm text-red-500">{loadError}</p>}
    <div className="flex min-h-0 flex-col overflow-hidden rounded-xl border border-border bg-surface" style={{ flex: "0 1 auto" }}>
    <div className="data-scroll">
    {loading && !images.length ? <p role="status" className="p-8 text-center text-sm text-muted-foreground">Loading images…</p> : !images.length && !loadError ? <EmptyState icon={IconPhoto} title="Your images will appear here" description="Take a screenshot and paste it here. Uploading starts immediately, and your public link is copied." /> : <Table aria-label="Hosted images">
      <TableHeader><TableRow><TableHead>Image</TableHead><TableHead className="hidden w-28 md:table-cell">Resolution</TableHead><TableHead className="hidden w-24 sm:table-cell">Size</TableHead><TableHead className="hidden w-32 lg:table-cell">Uploaded</TableHead><TableHead className="hidden w-40 xl:table-cell">Public link</TableHead><TableHead className="w-32 text-right sm:w-40">Actions</TableHead></TableRow></TableHeader>
      <TableBody>{visibleImages.map(image => <TableRow key={image.id}>
        <TableCell><div className="flex min-w-0 items-center gap-3"><button type="button" onClick={() => setPreview(image)} aria-label={`Preview ${image.name}`} title="View full image" className="flex h-12 w-16 shrink-0 items-center justify-center overflow-hidden rounded-md border border-border bg-background transition-colors hover:border-primary focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary"><img src={image.path} alt="" loading="lazy" className="max-h-full max-w-full object-contain" /></button><div className="min-w-0"><button type="button" title={image.name} className="block max-w-full truncate text-left text-sm font-medium hover:text-primary" onClick={() => setPreview(image)}>{image.name}</button><p className="mt-1 truncate text-xs text-muted-foreground md:hidden">{image.width} × {image.height} · {Math.ceil(image.size / 1024)} KiB</p></div></div></TableCell>
        <TableCell className="hidden text-xs tabular-nums text-muted-foreground md:table-cell">{image.width} × {image.height}</TableCell>
        <TableCell className="hidden text-xs tabular-nums text-muted-foreground sm:table-cell">{Math.ceil(image.size / 1024)} KiB</TableCell>
        <TableCell className="hidden text-xs text-muted-foreground lg:table-cell">{new Date(`${image.created_at}Z`).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })}</TableCell>
        <TableCell className="hidden xl:table-cell"><a href={image.path} target="_blank" rel="noreferrer" className="inline-flex max-w-full items-center gap-1.5 font-mono text-xs text-muted-foreground hover:text-primary"><span className="truncate">{image.path.split("/").pop()}</span><IconArrowUpRight className="shrink-0" size={13} /></a></TableCell>
        <TableCell><div className="flex items-center justify-end gap-1"><Button variant="secondary" size="sm" onClick={() => copy(image)} aria-label={`Copy link for ${image.name}`}><IconCopy size={15} /><span className="hidden sm:inline">Copy link</span></Button><Button variant="ghost" size="icon" aria-label={`Delete ${image.name}`} disabled={Boolean(deleting)} onClick={() => setDeleteTarget(image)}><IconTrash size={16} /></Button></div></TableCell>
      </TableRow>)}</TableBody>
    </Table>}
    </div>
    <ResultsPagination count={images.length} noun="Images" page={currentPage} pages={pages} pageSize={pageSize} onPage={setPage} onPageSize={size => { setPageSize(size); setPage(1); }} />
    </div>
    <div className="mt-3 flex shrink-0 items-center gap-2 text-xs text-muted-foreground"><IconKeyboard size={15} /><span>Ctrl+Shift+U</span><Popover opened={helpOpen} onChange={setHelpOpen} width={340} position="top-start" withinPortal zIndex={350}><Popover.Target><button type="button" aria-label="Desktop shortcut setup" className="text-primary hover:underline" onClick={() => setHelpOpen(value => !value)}>Setup</button></Popover.Target><Popover.Dropdown className="!rounded-xl !border-border !bg-dialog !p-4 !text-foreground"><p className="text-sm font-medium">Desktop shortcut</p><p className="mb-3 mt-1 text-xs text-muted-foreground">Off by default. Run in your desktop terminal:</p>{[
      ["Enable", "porthub image shortcut enable"],
      ["Disable", "porthub image shortcut disable"],
      ["Tenant", "porthub image tenant set <ID>"],
    ].map(([label, command]) => <div key={label} className="mb-2 flex items-center gap-2 last:mb-0"><code className="min-w-0 flex-1 select-all text-[11px]">{command}</code><button type="button" aria-label={`Copy ${label.toLowerCase()} command`} className="rounded p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground" onClick={() => copyText(command).then(() => toast.success("Command copied")).catch(() => toast.error("Select and copy the command"))}><IconCopy size={14} /></button></div>)}<p className="mt-3 text-[11px] text-muted-foreground">Automatic setup: GNOME Linux. Algofly is the default tenant.</p></Popover.Dropdown></Popover></div>
    <Dialog opened={Boolean(deleteTarget)} onClose={() => { if (!deleting) setDeleteTarget(null); }} title="Delete image" size="sm" closeOnEscape={!deleting} closeOnClickOutside={!deleting} closeButtonProps={{ disabled: Boolean(deleting) }}>
      <p className="text-sm leading-6 text-muted-foreground">Delete <span className="break-all font-medium text-foreground">{deleteTarget?.name}</span>? Its public link will stop working.</p>
      <div className="mt-6 flex justify-end gap-2"><Button variant="secondary" onClick={() => setDeleteTarget(null)} disabled={Boolean(deleting)}>Cancel</Button><Button variant="destructive" onClick={() => deleteTarget && remove(deleteTarget)} disabled={Boolean(deleting)}>{deleting ? "Deleting…" : "Delete image"}</Button></div>
    </Dialog>
    <Dialog opened={Boolean(preview)} onClose={() => setPreview(null)} title={preview?.name || "Image preview"} size="90%">
      {preview && <><div className="flex max-h-[70vh] min-h-[160px] items-center justify-center overflow-auto rounded-lg bg-background p-3"><img src={preview.path} alt={preview.name} className="h-auto max-h-[70vh] max-w-full object-contain" /></div><div className="mt-4 flex flex-wrap items-center justify-between gap-3"><span className="text-xs text-muted-foreground">{preview.width} × {preview.height} · {Math.ceil(preview.size / 1024)} KiB · Original resolution</span><div className="flex items-center gap-2"><Button variant="secondary" size="sm" asChild><a href={preview.path} target="_blank" rel="noreferrer"><IconArrowUpRight size={15} />Open original</a></Button><Button size="sm" onClick={() => copy(preview)}><IconCopy size={15} />Copy link</Button></div></div></>}
    </Dialog>
  </div>;
}
