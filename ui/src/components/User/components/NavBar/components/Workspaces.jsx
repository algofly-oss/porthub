import { useState } from "react";
import { useRouter } from "next/router";
import axios from "axios";
import { Popover } from "@mantine/core";
import { IconBuildingCommunity } from "@tabler/icons-react";
import { SearchField } from "@/components/ui/workspace";

export default function Workspaces({ collapsed = false, withinPortal = true, onSelected }) {
  const router = useRouter();
  const [opened, setOpened] = useState(false);
  const [items, setItems] = useState([]);
  const [error, setError] = useState(false);
  const [query, setQuery] = useState("");
  async function open(value) {
    setOpened(value);
    if (!value) return;
    setError(false);
    setQuery("");
    try {
      setItems((await axios.get("/api/access/workspaces")).data.data || []);
    } catch {
      setError(true);
    }
  }
  const value = String(
    router.query.workspace ||
      items.find((item) => item.role === "owner")?.id ||
      items[0]?.id ||
      "",
  );
  return (
    <Popover
      opened={opened}
      onChange={open}
      withinPortal={withinPortal}
      position="top-start"
      width={280}
      zIndex={410}
      transitionProps={{ duration: 0 }}
    >
      <Popover.Target>
        <button
          type="button"
          aria-label="Workspaces"
          title="Workspaces"
          onClick={() => open(!opened)}
          className={`flex h-10 items-center gap-2 rounded-lg text-sm text-muted-foreground hover:bg-control hover:text-foreground ${collapsed ? "w-10 justify-center" : "w-full px-3"}`}
        >
          <IconBuildingCommunity size={18} />
          {!collapsed && "Workspaces"}
        </button>
      </Popover.Target>
      <Popover.Dropdown className="!rounded-xl !border-border !bg-dialog !p-3 !text-foreground">
        <p className="mb-2 text-sm font-medium">Private workspace</p>
        <SearchField
          label="Search workspaces"
          placeholder="Find a workspace…"
          value={query}
          onChange={setQuery}
        />
        <div className="mt-2 max-h-52 overflow-y-auto">
          {error ? (
            <button
              type="button"
              className="p-2 text-sm text-muted-foreground"
              onClick={() => open(true)}
            >
              Could not load. Retry
            </button>
          ) : (
            items
              .filter((item) =>
                item.name.toLowerCase().includes(query.toLowerCase()),
              )
              .map((item) => (
                <button
                  key={item.id}
                  type="button"
                  aria-current={item.id === value ? "true" : undefined}
                  className={`flex min-h-11 w-full items-center justify-between gap-2 rounded-md px-2 py-2 text-left text-sm hover:bg-control ${item.id === value ? "bg-primary/10 text-primary" : ""}`}
                  onClick={() => {
                    setOpened(false);
                    onSelected?.();
                    router.push(
                      {
                        pathname: "/home",
                        query: {
                          ...(router.query.demo
                            ? { demo: router.query.demo }
                            : {}),
                          view: "access",
                          workspace: item.id,
                        },
                      },
                      undefined,
                      { shallow: true },
                    );
                  }}
                >
                  <span className="min-w-0 truncate">{item.name}</span>
                  <span className="shrink-0 text-xs capitalize text-muted-foreground">
                    {item.role}
                  </span>
                </button>
              ))
          )}
          {!error &&
            items.length > 0 &&
            !items.some((item) =>
              item.name.toLowerCase().includes(query.toLowerCase()),
            ) && (
              <p className="p-2 text-sm text-muted-foreground">
                No matching workspaces
              </p>
            )}
        </div>
      </Popover.Dropdown>
    </Popover>
  );
}
