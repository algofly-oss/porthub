import { IconServer, IconWorld, IconActivity, IconSettings, IconShieldLock, IconLayoutDashboard } from "@tabler/icons-react";
import DarkThemeToggle from "./components/DarkThemeToggle";
import Logout from "./components/Logout";
import { Fragment } from "react";

export default function UserNavBar({ tab, setTab, isAdmin, collapsed = false }) {
  const items = [
    ["Dashboard", "Dashboard", IconLayoutDashboard],
    ["Home", "Machines", IconServer], ["Proxy", "Proxies", IconWorld],
    ["Traffic", "Traffic", IconActivity], ["Settings", "Settings", IconSettings],
    ...(isAdmin ? [["Platform", "Platform", IconShieldLock]] : []),
  ];
  return <div id="user-navigation" className="flex w-full md:min-h-0 md:flex-1 md:flex-col md:justify-between">
    <nav aria-label="Workspace pages" className="flex w-full justify-around gap-1 md:flex-col">
      {items.map(([id, label, Icon]) => <Fragment key={id}>{id === "Platform" && <><div role="separator" aria-orientation="horizontal" className="mx-2 my-2 hidden h-px bg-border/70 md:block" /><div role="separator" aria-orientation="vertical" className="h-6 w-px shrink-0 self-center bg-border/70 md:hidden" /></>}<button type="button" title={label} aria-label={label} aria-current={tab === id ? "page" : undefined} onClick={() => setTab(id)}
        className={`nav-item ${collapsed ? "nav-item-collapsed" : ""} ${tab === id ? "is-current" : ""}`}>
        <Icon size={21} stroke={1.7} /><span className={collapsed ? "md:hidden" : ""}>{label}</span>
      </button></Fragment>)}
    </nav>
    <div className="hidden shrink-0 flex-col gap-2 pt-4 md:flex">
      {collapsed ? <DarkThemeToggle collapsed /> : <div className="rounded-lg bg-muted/50 p-2"><Logout /></div>}
    </div>
  </div>;
}
