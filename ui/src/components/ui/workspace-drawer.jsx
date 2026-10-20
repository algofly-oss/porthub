import { Drawer } from "@mantine/core";
import { Dialog, dialogSurface, dialogHeader } from "./dialog";
import { useMediaQuery } from "@mantine/hooks";
import { useReducedMotion } from "framer-motion";
import { useRef } from "react";

// Mantine's default autosizing scroll wrapper prevents a fixed-height editor's
// body from stretching. The editor owns its scrolling; keep its footer pinned.
function FixedDialogLayout({ children }) {
  return <div className="flex min-h-0 flex-1 flex-col overflow-hidden">{children}</div>;
}

// Shared editing surface: retain list context, constrain scrolling to the drawer.
export default function WorkspaceDrawer({ centered, classNames = {}, size, fixedHeight, animate = true, ...props }) {
  const reducedMotion = useReducedMotion();
  const mobile = useMediaQuery("(max-width: 767px)");
  const drag = useRef(null);
  if (!mobile) return <Dialog {...props} zIndex={props.zIndex ?? 200} size={size || "lg"} scrollAreaComponent={fixedHeight ? FixedDialogLayout : undefined} styles={fixedHeight ? { content: { height: fixedHeight, display: "flex", flexDirection: "column" }, header: { flexShrink: 0 }, body: { display: "flex", flexDirection: "column", flex: 1, minHeight: 0, overflow: "hidden" } } : undefined} classNames={{ ...classNames, body: `workspace-dialog-body ${classNames.body || ""}` }} transitionProps={{ transition: "pop", duration: reducedMotion || !animate ? 0 : 160 }} />;
  const title = <div className="w-full"><div aria-hidden="true" className="sheet-grab" onPointerDown={event => { if (props.closeOnEscape === false) return; const panel = event.currentTarget.closest(".workspace-drawer-content"); drag.current = { y: event.clientY, panel }; event.currentTarget.setPointerCapture(event.pointerId); panel.style.transition = "none"; }} onPointerMove={event => { if (drag.current) drag.current.panel.style.transform = `translateY(${Math.max(0, event.clientY - drag.current.y)}px)`; }} onPointerUp={event => { if (!drag.current) return; const { y, panel } = drag.current; drag.current = null; panel.style.transition = ""; panel.style.transform = ""; if (event.clientY - y > 110) props.onClose?.(); }} onPointerCancel={() => { if (drag.current) { drag.current.panel.style.transition = ""; drag.current.panel.style.transform = ""; drag.current = null; } }}><span /></div>{props.title}</div>;
  return <Drawer {...props} zIndex={props.zIndex ?? 200} title={title} position="bottom" size="min(88dvh, 720px)" scrollAreaComponent={FixedDialogLayout}
    transitionProps={{ transition: "slide-up", duration: reducedMotion || !animate ? 0 : 320, timingFunction: "cubic-bezier(.22,1,.36,1)" }}
    overlayProps={{ opacity: 0.42, blur: 5 }}
    classNames={{ ...classNames, inner: "workspace-drawer-inner", content: `workspace-drawer-content ${dialogSurface} !rounded-b-none !rounded-t-2xl`, header: `workspace-drawer-header ${dialogHeader}`, title: "workspace-drawer-title", body: `workspace-drawer-body !bg-dialog ${fixedHeight ? "flex flex-col" : ""}`, close: "workspace-drawer-close" }} />;
}
