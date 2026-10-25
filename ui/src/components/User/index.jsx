import { useContext, useEffect, useState } from "react";
import { SocketContext } from "@/shared/contexts/socket";
import UserNavBar from "./components/NavBar";
import { VscRemoteExplorer } from "react-icons/vsc";
import Home from "./components/Home";
import Proxy from "./components/Proxy";
import Settings from "./components/Settings";
import PlatformOverview from "./components/PlatformOverview";
import Traffic from "./components/Traffic";
import Dashboard from "./components/Dashboard";
import AccessRules from "./components/AccessRules";
import { useRouter } from "next/router";
import axios from "axios";
import toast from "react-hot-toast";
import { useDispatch } from "react-redux";
import { authActions } from "@/redux/features/authSlice";
import apiRoutes from "@/shared/routes/apiRoutes";
import useAuth from "@/shared/hooks/useAuth";
import useNavigationPreference from "@/shared/hooks/useNavigationPreference";
import useWorkspaceViewport from "@/shared/hooks/useWorkspaceViewport";
import { motion, useReducedMotion } from "framer-motion";
import { DemoNotice } from "@/shared/demo/DemoProvider";
import { WorkspaceCacheProvider } from "@/shared/contexts/workspaceCache";

export default function UserHome() {
  useWorkspaceViewport();
  const dispatch = useDispatch();
  const router = useRouter();
  const reducedMotion = useReducedMotion();
  const { user } = useAuth();
  const socket = useContext(SocketContext);
  const demo = router.query.demo === "1";
  useEffect(() => {
    if (!user?.username || demo || typeof socket?.connect !== "function") return;
    let retry;
    const reconnect = (reason) => {
      if (reason === "io server disconnect") {
        window.clearTimeout(retry);
        retry = window.setTimeout(() => socket.connect(), 1000);
      }
    };
    socket.on("disconnect", reconnect);
    socket.disconnect().connect();
    return () => {
      window.clearTimeout(retry);
      socket.off("disconnect", reconnect);
      socket.disconnect();
    };
  }, [socket, user?.username, demo]);
  const { collapsed, ready: navigationReady, setCollapsed } = useNavigationPreference(user);
  const [savingNavigation, setSavingNavigation] = useState(false);
  const toggleNavigation = async () => {
    const previousPreferences = user?.preferences || {};
    const previousCollapsed = collapsed;
    setSavingNavigation(true);
    setCollapsed(!collapsed);
    dispatch(authActions.updateAccountInfo({
      preferences: { ...previousPreferences, nav_collapsed: !collapsed },
    }));
    try {
      await axios.patch(apiRoutes.userPreferences, { nav_collapsed: !collapsed });
    } catch {
      setCollapsed(previousCollapsed);
      dispatch(authActions.updateAccountInfo({ preferences: previousPreferences }));
      toast.error("Could not save navigation preference. Please try again.");
    } finally {
      setSavingNavigation(false);
    }
  };
  const isAdmin = user?.role === "admin";
  const views = { dashboard: "Dashboard", machines: "Home", access: "Access", proxies: "Proxy", traffic: "Traffic", settings: "Settings", platform: "Platform" };
  const tab = views[router.query.view] || "Dashboard";
  const setTab = (nextTab) => {
    const view = Object.keys(views).find(key => views[key] === nextTab) || "machines";
    router.push({ pathname: "/home", query: { ...(router.query.demo === "1" ? { demo: "1" } : {}), view } }, undefined, { shallow: true, scroll: false });
  };
  const [machineStats, setMachineStats] = useState(null);

  if (!router.isReady || !navigationReady) {
    return <div className="workspace flex items-center justify-center text-sm text-zinc-500" role="status">Loading workspace…</div>;
  }

  return (
    <div className="workspace flex flex-col-reverse md:flex-row">
      <a href="#workspace-content" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-blue-600 focus:p-3 focus:text-white">Skip to content</a>
      <aside
        aria-label="Main navigation"
        className={`workspace-sidebar relative z-20 flex w-full shrink-0 items-center md:fixed md:inset-y-0 md:left-0 md:flex-col md:items-stretch md:h-dvh md:py-5 md:overflow-y-auto md:light-scrollbar dark:md:dark-scrollbar ${collapsed ? "md:w-16 md:px-2" : "md:w-56 md:px-4"}`}
      >
        <button
          type="button"
          className={`hidden md:flex h-10 flex-shrink-0 items-center mb-5 dark:text-neutral-200 cursor-pointer rounded-md focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-500 ${collapsed ? "justify-center" : "space-x-3"}`}
          onClick={toggleNavigation}
          disabled={savingNavigation || !user?.username}
          aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
          aria-expanded={!collapsed}
          aria-controls="user-navigation"
          title={collapsed ? "Expand navigation" : "Collapse navigation"}
        >
          <VscRemoteExplorer size={30} className="shrink-0" />
          {!collapsed && <span className="text-lg font-bold">PortHub</span>}
        </button>
        <UserNavBar
          collapsed={collapsed}
          tab={tab}
          setTab={setTab}
          machineStats={machineStats}
          isAdmin={isAdmin}
        />
      </aside>
      <div className={`workspace-body w-full min-w-0 ${collapsed ? "md:ml-16" : "md:ml-56"}`}>
        <DemoNotice />
        <main id="workspace-content" tabIndex={-1}>
        <WorkspaceCacheProvider key={`${user?.username || "anonymous"}:${router.query.demo === "1"}`}>
        <motion.div initial={reducedMotion ? false : { opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.16 }} className="h-full min-h-0">
        <div hidden={tab !== "Dashboard"} aria-hidden={tab !== "Dashboard"} className="h-full min-h-0"><Dashboard active={tab === "Dashboard"} /></div>
        <div hidden={tab !== "Home"} aria-hidden={tab !== "Home"} className="h-full min-h-0"><Home active={tab === "Home"} onStatsChange={setMachineStats} /></div>
        <div hidden={tab !== "Access"} aria-hidden={tab !== "Access"} className="h-full min-h-0"><AccessRules active={tab === "Access"} /></div>
        <div hidden={tab !== "Proxy"} aria-hidden={tab !== "Proxy"} className="h-full min-h-0"><Proxy active={tab === "Proxy"} /></div>
        <div hidden={tab !== "Traffic"} aria-hidden={tab !== "Traffic"} className="h-full min-h-0"><Traffic active={tab === "Traffic"} /></div>
        <div hidden={tab !== "Settings"} aria-hidden={tab !== "Settings"} className="h-full min-h-0"><Settings /></div>
        {isAdmin && <div hidden={tab !== "Platform"} aria-hidden={tab !== "Platform"} className="h-full min-h-0"><PlatformOverview active={tab === "Platform"} /></div>}
        </motion.div>
        </WorkspaceCacheProvider>
        </main>
      </div>
    </div>
  );
}
