import { createContext, useCallback, useContext, useRef, useSyncExternalStore } from "react";

const WorkspaceCacheContext = createContext(null);

function createCache() {
  return { values: new Map(), listeners: new Map() };
}

// This cache lives only for the current signed-in workspace. It is never
// written to browser storage and disappears on sign-out/account changes.
export function WorkspaceCacheProvider({ children }) {
  const cache = useRef(null);
  if (!cache.current) cache.current = createCache();
  return <WorkspaceCacheContext.Provider value={cache.current}>{children}</WorkspaceCacheContext.Provider>;
}

export function useWorkspaceState(key, initialValue) {
  const provided = useContext(WorkspaceCacheContext);
  const local = useRef(null);
  if (!local.current) local.current = createCache();
  const cache = provided || local.current;
  if (!cache.values.has(key)) {
    cache.values.set(key, typeof initialValue === "function" ? initialValue() : initialValue);
  }
  const subscribe = useCallback(listener => {
    if (!cache.listeners.has(key)) cache.listeners.set(key, new Set());
    const listeners = cache.listeners.get(key);
    listeners.add(listener);
    return () => listeners.delete(listener);
  }, [cache, key]);
  const snapshot = useCallback(() => cache.values.get(key), [cache, key]);
  const state = useSyncExternalStore(subscribe, snapshot, snapshot);
  const setState = useCallback(update => {
    const previous = cache.values.get(key);
    const next = typeof update === "function" ? update(previous) : update;
    if (Object.is(previous, next)) return;
    cache.values.set(key, next);
    cache.listeners.get(key)?.forEach(listener => listener());
  }, [cache, key]);
  return [state, setState];
}
