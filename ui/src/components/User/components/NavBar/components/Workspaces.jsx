import useInventoryPage from "@/shared/hooks/useInventoryPage";
import { useEffect } from "react";
import { useState } from "react";
import { useRouter } from "next/router";
import axios from "axios";
import { Popover } from "@mantine/core";
import { IconBuildingCommunity } from "@tabler/icons-react";
import { SearchField } from "@/components/ui/workspace";

export default function Workspaces({ collapsed = false, withinPortal = true, onSelected }) {
  const router = useRouter();
  const [opened, setOpened] = useState(false);
  const [query, setQuery] = useState("");
  const [page,setPage]=useState(1);
  const inventory=useInventoryPage("access-workspaces",{q:query,page,page_size:20},{enabled:opened});
  const items=inventory.rows, error=inventory.error;
  useEffect(()=>setPage(1),[query]);
  useEffect(()=>{if(!inventory.loading && page>inventory.pagination.pages)setPage(inventory.pagination.pages);},[page,inventory.loading,inventory.pagination.pages]);
  function open(value){setOpened(value);if(value){setQuery("");setPage(1);}}
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
              onClick={inventory.refresh}
            >
              Could not load. Retry
            </button>
          ) : (
            items
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
          {inventory.loading && <p role="status" className="p-2 text-sm text-muted-foreground">Loading workspaces…</p>}
          {!inventory.loading && !error && !items.length && <p className="p-2 text-sm text-muted-foreground">No matching workspaces</p>}
        </div>
        {inventory.pagination.pages>1 && <div className="mt-2 flex items-center justify-between gap-2 border-t border-border pt-2 text-xs"><button type="button" onClick={()=>setPage(p=>p-1)} disabled={page<=1} className="rounded px-2 py-2 hover:bg-control disabled:opacity-40">Previous</button><span>{page} / {inventory.pagination.pages}</span><button type="button" onClick={()=>setPage(p=>p+1)} disabled={page>=inventory.pagination.pages} className="rounded px-2 py-2 hover:bg-control disabled:opacity-40">Next</button></div>}
      </Popover.Dropdown>
    </Popover>
  );
}
