import { useEffect, useLayoutEffect } from "react";

const useBrowserLayoutEffect = typeof window === "undefined" ? useEffect : useLayoutEffect;

export default function useWorkspaceViewport() {
  useBrowserLayoutEffect(() => {
    const root = document.documentElement;
    const viewport = window.visualViewport;
    const standalone = window.matchMedia("(display-mode: standalone)");
    let frame;
    const update = () => {
      if (window.innerWidth >= 768) {
        root.classList.remove("workspace-standalone", "workspace-keyboard");
        root.style.removeProperty("--workspace-height");
        root.style.removeProperty("--workspace-top");
        return;
      }
      // Leave pinch zoom to the browser rather than resizing the application.
      if (viewport && Math.abs(viewport.scale - 1) > 0.01) return;
      const installed = standalone.matches || window.navigator.standalone === true;
      const typing = document.activeElement?.matches("input, textarea, [contenteditable=true]");
      const layoutHeight = Math.max(window.innerHeight, root.clientHeight);
      const keyboardOpen = Boolean(typing && viewport && viewport.height < layoutHeight - 120);
      root.classList.toggle("workspace-standalone", installed);
      root.classList.toggle("workspace-keyboard", keyboardOpen);
      // Installed iOS can retain a shortened innerHeight as well as an
      // undersized visualViewport. Anchor the shell to all four viewport edges
      // in CSS instead of trusting either cached number for its bottom edge.
      if (installed && !keyboardOpen) {
        root.style.removeProperty("--workspace-height");
        root.style.removeProperty("--workspace-top");
        return;
      }
      const height = viewport?.height || window.innerHeight;
      const top = viewport?.offsetTop || 0;
      root.style.setProperty("--workspace-height", `${height}px`);
      root.style.setProperty("--workspace-top", `${top}px`);
    };
    const schedule = () => { cancelAnimationFrame(frame); frame = requestAnimationFrame(update); };
    root.classList.add("workspace-active");
    update();
    window.addEventListener("resize", schedule);
    window.addEventListener("orientationchange", schedule);
    window.addEventListener("pageshow", schedule);
    document.addEventListener("visibilitychange", schedule);
    document.addEventListener("focusin", schedule);
    document.addEventListener("focusout", schedule);
    standalone.addEventListener("change", schedule);
    viewport?.addEventListener("resize", schedule);
    viewport?.addEventListener("scroll", schedule);
    return () => {
      cancelAnimationFrame(frame);
      root.classList.remove("workspace-active", "workspace-standalone", "workspace-keyboard");
      root.style.removeProperty("--workspace-height");
      root.style.removeProperty("--workspace-top");
      window.removeEventListener("resize", schedule);
      window.removeEventListener("orientationchange", schedule);
      window.removeEventListener("pageshow", schedule);
      document.removeEventListener("visibilitychange", schedule);
      document.removeEventListener("focusin", schedule);
      document.removeEventListener("focusout", schedule);
      standalone.removeEventListener("change", schedule);
      viewport?.removeEventListener("resize", schedule);
      viewport?.removeEventListener("scroll", schedule);
    };
  }, []);
}
