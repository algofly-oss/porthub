import { createContext, useContext, useEffect, useState } from "react";
import { useRouter } from "next/router";
import axios from "axios";
import { SocketContext } from "@/shared/contexts/socket";
import { makeDemoData, handleDemoRequest } from "./data.mjs";

const DemoContext = createContext(false);
const quietSocket = { on() {}, off() {}, emit() {} };
const key = "porthub-demo-v1";
export const useDemo = () => useContext(DemoContext);

export default function DemoProvider({ children }) {
  const router = useRouter();
  const requested = router.isReady && router.query.demo === "1";
  const [ready, setReady] = useState(false);
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  useEffect(() => {
    if (!requested) { setReady(false); return; }
    let state;
    try { state = JSON.parse(sessionStorage.getItem(key)); } catch {}
    if (!state || state.version !== 1) state = makeDemoData();
    const interceptor = axios.interceptors.request.use(config => {
      // Every API request is intercepted; unsupported demo actions fail locally.
      if (!String(config.url).includes("/api/")) return config;
      config.adapter = async () => {
        try {
          const data = handleDemoRequest(state, config.method || "get", config.url, config.data);
          sessionStorage.setItem(key, JSON.stringify(state));
          return { data: structuredClone(data), status: 200, statusText: "OK", headers: {}, config };
        } catch (error) { throw { response: { status: 400, data: { detail: error.message } }, config }; }
      };
      return config;
    });
    setReady(true);
    return () => axios.interceptors.request.eject(interceptor);
  }, [requested]);
  // isReady can differ between SSR and the browser's first render on /home.
  // Keep that first render identical; mount the workspace after hydration.
  if (!mounted || !router.isReady || requested !== ready) return null;
  return <DemoContext.Provider value={requested}>{requested ? <SocketContext.Provider value={quietSocket}>{children}</SocketContext.Provider> : children}</DemoContext.Provider>;
}

export function DemoNotice() {
  if (!useDemo()) return null;
  return <div className="flex min-h-[28px] shrink-0 items-center justify-between gap-2 bg-blue-600/10 px-4 py-1 text-[10px] text-blue-700 dark:text-blue-300"><span>Demo workspace · changes stay in this browser</span><div className="flex shrink-0 gap-3"><button type="button" className="hover:underline" onClick={() => { sessionStorage.removeItem(key); location.reload(); }}>Reset</button><button type="button" className="hover:underline" onClick={() => location.assign("/home")}>Exit demo</button></div></div>;
}
