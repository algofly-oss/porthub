import axios from "axios";
import { SocketContext } from "./socket";
import { createInventoryResource } from "@/shared/utils/inventory-resource.mjs";
import { createContext, useCallback, useContext, useEffect, useRef, useSyncExternalStore } from "react";

const WorkspaceCacheContext = createContext(null);

function createCache() {
  return { values: new Map([["inventory.resource", createInventoryResource()]]), listeners: new Map() };
}

// This cache lives only for the current signed-in workspace. It is never
// written to browser storage and disappears on sign-out/account changes.
export function WorkspaceCacheProvider({ children }) {
  const cache = useRef(null);
  if (!cache.current) cache.current = createCache();
  const socket=useContext(SocketContext);
  useEffect(()=>{
    const resource=cache.current.values.get("inventory.resource");
    const machine=()=>{resource.invalidate("summary");};
    const config=()=>{resource.invalidate("machines");resource.invalidate("summary");};
    const ports=()=>{resource.invalidate("summary");resource.invalidate("machines");resource.invalidate("connections");resource.invalidate("proxies");};

    socket?.on("/stc/machines/config-changed",config);
    socket?.on("/stc/machines/connections-changed",ports);
    const interceptor=axios.interceptors.response.use(response=>{
      const method=response.config?.method || "get",url=response.config?.url || "";
      if(!["get","head"].includes(method)){
        if (/\/api\/access\/(books|groups|network|members|invitations|private|exit-nodes|proxy-grants)(?:[/?]|$)/.test(url)) {
          for(const suffix of ["summary","books","groups","machines","people","entities","peers","exits","proxy-grants","invitations","workspaces"])resource.invalidate(`access-${suffix}`);
          resource.invalidate("machines");resource.invalidate("groups");
        }
        if (/\/api\/machines\/groups\/(add|remove)/.test(url)) { resource.invalidate("machines");resource.invalidate("groups");resource.invalidate("proxies"); }
        const match=url.match(/\/api\/(machines|connections|traffic-routes|groups)\/(add|update|delete|refresh|enable|disable)(?:[/?]|$)/);
        if(match){const kind={"traffic-routes":"proxies",groups:"groups",machines:"machines",connections:"connections"}[match[1]];resource.invalidate(kind);resource.invalidate("summary");if(kind==="proxies"){resource.invalidate("proxy-groups");resource.invalidate("proxy-tags");}if(kind==="groups" || kind==="machines")resource.invalidate("proxies");if(kind==="connections")resource.invalidate("machines");}
      }
      return response;
    });
    return()=>{axios.interceptors.response.eject(interceptor);socket?.off("/stc/machines/config-changed",config);socket?.off("/stc/machines/connections-changed",ports);};
  },[socket]);
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
