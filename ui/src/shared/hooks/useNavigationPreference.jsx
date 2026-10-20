import { useCallback, useEffect, useLayoutEffect, useState } from "react";
import { useDemo } from "@/shared/demo/DemoProvider";

const useBrowserLayoutEffect = typeof window === "undefined" ? useEffect : useLayoutEffect;

export default function useNavigationPreference(user) {
  const demo = useDemo();
  const key = demo ? "porthub-demo-navigation-v1" : "porthub-navigation-v1";
  const [collapsed, setValue] = useState(null);
  const username = user?.username;
  const serverCollapsed = user?.preferences?.nav_collapsed === true;

  const setCollapsed = useCallback(value => {
    setValue(value);
    try { localStorage.setItem(key, JSON.stringify({ username, collapsed: value })); } catch {}
  }, [key, username]);

  useBrowserLayoutEffect(() => {
    // Read before painting the workspace; the first server/client render stays
    // identical, so restoring this preference cannot cause hydration errors.
    if (username) {
      setCollapsed(serverCollapsed);
      return;
    }
    let cached;
    try { cached = JSON.parse(localStorage.getItem(key)); } catch {}
    setValue(typeof cached?.collapsed === "boolean" ? cached.collapsed : false);
  }, [key, username, serverCollapsed, setCollapsed]);

  return { collapsed: collapsed === true, ready: collapsed !== null, setCollapsed };
}
