import { useCallback, useEffect, useRef, useState } from "react";
import { hideOthers } from "aria-hidden";
import { Dialog } from "@/components/ui/dialog";

// Mantine 6's focus trap can snapshot already-hidden page state during ref
// updates. Keep one balanced accessibility scope per open image dialog instead.
const scopes = [];
const selector = "button:not([disabled]), a[href], input:not([disabled]):not([type=hidden]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])";
function focusable(node) {
  return Array.from(node.querySelectorAll(selector)).filter(element => element.getClientRects().length && getComputedStyle(element).visibility !== "hidden");
}
function Scope({ active, escape, children }) {
  const [node, setNode] = useState(null);
  const escapeRef = useRef(escape);
  escapeRef.current = escape;
  const attach = useCallback(element => setNode(element?.closest("[role=dialog]") || null), []);
  useEffect(() => {
    if (!active || !node) return;
    const previous = document.activeElement;
    const restore = hideOthers(node);
    scopes.push(node);
    const top = () => scopes[scopes.length - 1] === node;
    const focus = () => (focusable(node)[0] || node).focus({ preventScroll: true });
    if (!node.contains(document.activeElement)) focus();
    const onFocus = event => { if (top() && !node.contains(event.target)) focus(); };
    const onKey = event => {
      if (!top()) return;
      if (event.key === "Escape") {
        event.preventDefault(); event.stopPropagation(); escapeRef.current(); return;
      }
      if (event.key !== "Tab") return;
      const items = focusable(node), first = items[0], last = items[items.length - 1];
      if (!first) { event.preventDefault(); node.focus(); }
      else if (event.shiftKey && (document.activeElement === first || document.activeElement === node)) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && (document.activeElement === last || document.activeElement === node)) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener("focusin", onFocus);
    node.addEventListener("keydown", onKey);
    return () => {
      const wasTop = top();
      const index = scopes.lastIndexOf(node); if (index >= 0) scopes.splice(index, 1);
      document.removeEventListener("focusin", onFocus); node.removeEventListener("keydown", onKey);
      restore();
      if (wasTop && previous?.isConnected && typeof previous.focus === "function") previous.focus({ preventScroll: true });
    };
  }, [active, node]);
  return <div ref={attach} className="contents">{children}</div>;
}
export default function ImageDialog({ opened, onClose, closeOnEscape = true, closeButtonProps = {}, children, ...props }) {
  return <Dialog {...props} opened={opened} onClose={onClose} trapFocus={false} returnFocus={false} closeOnEscape={false} closeButtonProps={{ "aria-label": "Close dialog", ...closeButtonProps }}>
    <Scope active={opened} escape={() => { if (closeOnEscape) onClose(); }}>{children}</Scope>
  </Dialog>;
}
