import {
  IconServer,
  IconWorld,
  IconActivity,
  IconSettings,
  IconShieldLock,
  IconLayoutDashboard,
  IconRoute,
  IconDots,
} from "@tabler/icons-react";
import DarkThemeToggle from "./components/DarkThemeToggle";
import Logout from "./components/Logout";
import Workspaces from "./components/Workspaces";
import { Fragment, useState } from "react";
import { Popover } from "@mantine/core";

export default function UserNavBar({
  tab,
  setTab,
  isAdmin,
  collapsed = false,
}) {
  const [moreOpen, setMoreOpen] = useState(false);
  const items = [
    ["Dashboard", "Dashboard", IconLayoutDashboard],
    ["Home", "Machines", IconServer],
    ["Access", "Rules", IconRoute],
    ["Proxy", "Proxies", IconWorld],
    ["Traffic", "Traffic", IconActivity],
    ["Settings", "Settings", IconSettings],
    ...(isAdmin ? [["Platform", "Platform", IconShieldLock]] : []),
  ];
  return (
    <div
      id="user-navigation"
      className="flex w-full md:min-h-0 md:flex-1 md:flex-col md:justify-between"
    >
      <nav
        aria-label="Workspace pages"
        className="hidden w-full gap-1 md:flex md:flex-col"
      >
        {items.map(([id, label, Icon]) => (
          <Fragment key={id}>
            {id === "Platform" && (
              <>
                <div
                  role="separator"
                  aria-orientation="horizontal"
                  className="mx-2 my-2 hidden h-px bg-border/70 md:block"
                />
                <div
                  role="separator"
                  aria-orientation="vertical"
                  className="h-6 w-px shrink-0 self-center bg-border/70 md:hidden"
                />
              </>
            )}
            <button
              type="button"
              title={label}
              aria-label={label}
              aria-current={tab === id ? "page" : undefined}
              onClick={() => setTab(id)}
              className={`nav-item ${collapsed ? "nav-item-collapsed" : ""} ${tab === id ? "is-current" : ""}`}
            >
              <Icon size={21} stroke={1.7} />
              <span
                className={`${collapsed ? "md:hidden" : ""} text-center leading-3 md:text-left md:leading-5`}
              >
                {label}
              </span>
            </button>
          </Fragment>
        ))}
      </nav>
      <nav
        aria-label="Mobile workspace pages"
        className="flex w-full justify-around gap-1 md:hidden"
      >
        {items.slice(0, 4).map(([id, label, Icon]) => (
          <button
            key={id}
            type="button"
            title={label}
            aria-label={label}
            aria-current={tab === id ? "page" : undefined}
            onClick={() => setTab(id)}
            className={`nav-item ${tab === id ? "is-current" : ""}`}
          >
            <Icon size={21} stroke={1.7} />
            <span className="text-center leading-3">
                {label}
            </span>
          </button>
        ))}
        <Popover
          opened={moreOpen}
          onChange={setMoreOpen}
          position="top-end"
          withinPortal
          zIndex={400}
          width={230}
          shadow="sm"
          transitionProps={{ duration: 0 }}
        >
          <Popover.Target>
            <button
              type="button"
              className={`nav-item ${items.slice(4).some(([id]) => id === tab) ? "is-current" : ""}`}
              aria-label="More navigation"
              aria-expanded={moreOpen}
              aria-current={
                items.slice(4).some(([id]) => id === tab) ? "page" : undefined
              }
              onClick={() => setMoreOpen((value) => !value)}
            >
              <IconDots size={21} />
              <span>More</span>
            </button>
          </Popover.Target>
          <Popover.Dropdown className="!rounded-xl !border-border !bg-dialog !p-2 !text-foreground">
            <p className="px-3 py-2 text-xs font-medium text-muted-foreground">
              More Pages
            </p>
            {items.slice(4).map(([id, label, Icon]) => (
              <Fragment key={id}>
                {id === "Platform" && (
                  <div role="separator" className="my-1 h-px bg-border" />
                )}
                <button
                  type="button"
                  aria-label={label}
                  aria-current={tab === id ? "page" : undefined}
                  className={`flex min-h-[44px] w-full items-center gap-3 rounded-lg px-3 text-left text-sm hover:bg-accent/50 ${tab === id ? "bg-control font-medium" : ""}`}
                  onClick={() => {
                    setTab(id);
                    setMoreOpen(false);
                  }}
                >
                  <Icon size={18} />
                  {label}
                </button>
              </Fragment>
            ))}
            <div className="mt-1 border-t border-border pt-1"><Workspaces withinPortal={false} onSelected={() => setMoreOpen(false)} /></div>
          </Popover.Dropdown>
        </Popover>
      </nav>
      <div className="hidden shrink-0 flex-col gap-2 pt-4 md:flex">
        <Workspaces collapsed={collapsed} />
        {collapsed ? (
          <DarkThemeToggle collapsed />
        ) : (
          <div className="rounded-lg bg-muted/50 p-2">
            <Logout />
          </div>
        )}
      </div>
    </div>
  );
}
