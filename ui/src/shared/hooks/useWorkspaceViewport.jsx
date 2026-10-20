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
        root.style.removeProperty("--workspace-height");
        root.style.removeProperty("--workspace-top");
        return;
      }
      // Leave pinch zoom to the browser rather than resizing the application.
      if (viewport && Math.abs(viewport.scale - 1) > 0.01) return;
      const installed = standalone.matches || window.navigator.standalone === true;
      const typing = document.activeElement?.matches("input, textarea, [contenteditable=true]");
      const keyboardOpen = typing && viewport && viewport.height < window.innerHeight - 120;
      // iOS standalone dvh can exclude the home-indicator area at launch.
      // Use the full window there, but the visible viewport for the keyboard.
      const fullWindow = installed && !keyboardOpen;
      const height = fullWindow ? window.innerHeight : viewport?.height || window.innerHeight;
      const top = fullWindow ? 0 : viewport?.offsetTop || 0;
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
    viewport?.addEventListener("resize", schedule);
    viewport?.addEventListener("scroll", schedule);
    return () => {
      cancelAnimationFrame(frame);
      root.classList.remove("workspace-active");
      root.style.removeProperty("--workspace-height");
      root.style.removeProperty("--workspace-top");
      window.removeEventListener("resize", schedule);
      window.removeEventListener("orientationchange", schedule);
      window.removeEventListener("pageshow", schedule);
      document.removeEventListener("visibilitychange", schedule);
      viewport?.removeEventListener("resize", schedule);
      viewport?.removeEventListener("scroll", schedule);
    };
  }, []);
}
