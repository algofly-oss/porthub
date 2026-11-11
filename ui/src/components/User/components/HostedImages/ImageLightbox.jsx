import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { IconX, IconPlus, IconMinus, IconCopy, IconArrowUpRight, IconChevronLeft, IconChevronRight } from "@tabler/icons-react";
import { ImageFocusScope } from "./ImageDialog";

const clamp = value => Math.max(0.25, Math.min(8, value));
const origin = { zoom: 1, x: 0, y: 0 };
const control = "flex h-10 min-w-[40px] items-center justify-center rounded-lg bg-neutral-900/90 px-2 text-white hover:bg-neutral-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-400 disabled:opacity-30";

// Full-screen original-resolution viewer, following DataHub's anchored zoom and
// pan interaction. Pointer events also support one-finger drag and pinch zoom.
export default function ImageLightbox({ image, images, onClose, onChange, onCopy }) {
  const stage = useRef(null);
  const pointers = useRef(new Map());
  const transform = useRef(origin);
  const [view, setView] = useState(origin);
  const [failed, setFailed] = useState(false);
  const update = next => { transform.current = next; setView(next); };
  const zoomAt = (zoom, clientX, clientY) => {
    const rect = stage.current.getBoundingClientRect();
    const current = transform.current, next = clamp(zoom), ratio = next / current.zoom;
    const x = clientX - rect.left - rect.width / 2, y = clientY - rect.top - rect.height / 2;
    update({ zoom: next, x: x - ratio * (x - current.x), y: y - ratio * (y - current.y) });
  };
  const zoomCenter = factor => {
    const rect = stage.current.getBoundingClientRect();
    zoomAt(transform.current.zoom * factor, rect.left + rect.width / 2, rect.top + rect.height / 2);
  };
  const index = images.findIndex(item => item.id === image.id);
  const previous = index > 0, next = index >= 0 && index < images.length - 1;
  useEffect(() => { update(origin); pointers.current.clear(); setFailed(false); }, [image.id]);
  useEffect(() => {
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const handleWheel = event => {
      event.preventDefault();
      zoomAt(transform.current.zoom * Math.exp(-event.deltaY * 0.002), event.clientX, event.clientY);
    };
    const element = stage.current;
    element.addEventListener("wheel", handleWheel, { passive: false });
    const resize = () => update(origin);
    window.addEventListener("resize", resize);
    return () => { document.body.style.overflow = overflow; element.removeEventListener("wheel", handleWheel); window.removeEventListener("resize", resize); };
  }, []);
  const key = event => {
    if (["ArrowLeft", "ArrowRight", "+", "=", "-", "0"].includes(event.key)) event.preventDefault();
    if (event.key === "ArrowLeft" && previous) onChange(images[index - 1]);
    if (event.key === "ArrowRight" && next) onChange(images[index + 1]);
    if (["+", "="].includes(event.key)) zoomCenter(1.25);
    if (event.key === "-") zoomCenter(0.8);
    if (event.key === "0") update(origin);
  };
  const pointerMove = event => {
    const points = pointers.current;
    if (!points.has(event.pointerId)) return;
    const before = [...points.values()];
    points.set(event.pointerId, { x: event.clientX, y: event.clientY });
    const after = [...points.values()];
    if (after.length === 1) {
      const current = transform.current;
      update({ ...current, x: current.x + after[0].x - before[0].x, y: current.y + after[0].y - before[0].y });
    } else if (after.length === 2) {
      const distance = p => Math.hypot(p[1].x - p[0].x, p[1].y - p[0].y);
      const center = p => ({ x: (p[0].x + p[1].x) / 2, y: (p[0].y + p[1].y) / 2 });
      const start = center(before), end = center(after);
      if (distance(before) > 0) zoomAt(transform.current.zoom * distance(after) / distance(before), start.x, start.y);
      const current = transform.current;
      update({ ...current, x: current.x + end.x - start.x, y: current.y + end.y - start.y });
    }
  };
  return createPortal(<div role="dialog" aria-modal="true" aria-label={image.name || "Image preview"} tabIndex={-1} onKeyDown={key} className="fixed inset-0 flex flex-col bg-black/90 text-white backdrop-blur-md" style={{ zIndex: 3010 }}>
    <ImageFocusScope active escape={onClose}>
      <header className="z-10 flex shrink-0 items-center gap-2 p-3 sm:px-5">
        <div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{image.name}</p><p className="text-xs text-neutral-400">{image.width} × {image.height} · Original resolution</p></div>
        <button className={control} aria-label="Copy image link" onClick={() => onCopy(image)}><IconCopy size={19} /></button>
        <a className={control} aria-label="Open original" href={image.path} target="_blank" rel="noreferrer"><IconArrowUpRight size={19} /></a>
        <button className={control} aria-label="Close image preview" onClick={onClose}><IconX size={22} /></button>
      </header>
      <div ref={stage} data-testid="image-stage" className="relative flex min-h-0 flex-1 touch-none select-none items-center justify-center overflow-hidden" style={{ cursor: view.zoom > 1 ? "grab" : "default" }}
        onDoubleClick={event => view.zoom === 1 ? zoomAt(2, event.clientX, event.clientY) : update(origin)}
        onPointerDown={event => { if (event.button !== 0) return; event.preventDefault(); event.currentTarget.setPointerCapture(event.pointerId); pointers.current.set(event.pointerId, { x: event.clientX, y: event.clientY }); }}
        onPointerMove={pointerMove} onPointerUp={event => pointers.current.delete(event.pointerId)} onPointerCancel={event => pointers.current.delete(event.pointerId)} onLostPointerCapture={event => pointers.current.delete(event.pointerId)}>
        {failed ? <p role="alert" className="text-sm text-neutral-300">This image is no longer available.</p> : <img key={image.id} src={image.path} alt={image.name} draggable={false} onError={() => setFailed(true)} className="max-h-full max-w-full object-contain" style={{ transform: `translate(${view.x}px, ${view.y}px) scale(${view.zoom})`, transformOrigin: "center", willChange: "transform" }} />}
      </div>
      <footer className="z-10 flex shrink-0 flex-wrap items-center justify-center gap-2 p-3 pb-[max(12px,env(safe-area-inset-bottom))]">
        <button className={control} aria-label="Previous image" disabled={!previous} onClick={() => onChange(images[index - 1])}><IconChevronLeft size={21} /></button>
        <button className={control} aria-label="Zoom out" onClick={() => zoomCenter(0.8)}><IconMinus size={19} /></button>
        <button className={`${control} min-w-[68px] text-xs tabular-nums`} aria-label="Reset zoom" title="Fit image (0)" onClick={() => update(origin)}>{Math.round(view.zoom * 100)}%</button>
        <button className={control} aria-label="Zoom in" onClick={() => zoomCenter(1.25)}><IconPlus size={19} /></button>
        <span className="px-1 text-xs tabular-nums text-neutral-400">{index + 1} / {images.length}</span>
        <button className={control} aria-label="Next image" disabled={!next} onClick={() => onChange(images[index + 1])}><IconChevronRight size={21} /></button>
      </footer>
    </ImageFocusScope>
  </div>, document.body);
}
