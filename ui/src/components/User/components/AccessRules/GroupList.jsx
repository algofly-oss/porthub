import useInventoryPage from "@/shared/hooks/useInventoryPage";
import ResultsPagination from "@/components/ui/results-pagination";
import { useEffect, useState } from "react";
import axios from "axios";
import {
  IconPlus,
  IconFolder,
  IconChevronRight,
} from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SearchField } from "@/components/ui/workspace";
import { API, errorText } from "./shared";

export default function GroupList({
  data,
  manage,
  params,
  onSaved,
  onOpen,
}) {
  const [name, setName] = useState(""),
    [query, setQuery] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const [page,setPage]=useState(1);
  const inventory=useInventoryPage("access-groups",{...params,q:query,page,page_size:25});
  useEffect(()=>setPage(1),[query]);
  useEffect(()=>{if(!inventory.loading && page>inventory.pagination.pages)setPage(inventory.pagination.pages);},[page,inventory.loading,inventory.pagination.pages]);
  async function create(event) {
    event.preventDefault();
    setBusy(true);
    try {
      await axios.post(`${API}/groups`, { name }, { params });
      setName("");
      setError("");
      await onSaved();
    } catch (error) {
      setError(errorText(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="flex min-h-0 flex-1 flex-col">
      <div className="mb-4">
        <h2 className="text-base font-semibold">Groups & Tags</h2>
        <p className="mt-1 text-sm leading-6 text-muted-foreground">
          Reuse your machine groups. People and machines can belong to several
          groups.
        </p>
      </div>
      <div className="mb-3">
        <SearchField
          label="Search access groups"
          placeholder="Find a group…"
          value={query}
          onChange={setQuery}
        />
      </div>
      {manage && (
        <form className="mb-3 flex gap-2" onSubmit={create}>
          <Input
            aria-label="New access group"
            placeholder="New group name"
            maxLength={80}
            required
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
          <Button type="submit" disabled={busy}>
            <IconPlus size={16} />
            Group
          </Button>
        </form>
      )}
      {error && (
        <p role="alert" className="mb-3 text-sm text-red-500">
          {error}
        </p>
      )}
      {inventory.loading && <p role="status" className="p-3 text-sm text-muted-foreground">Loading groups…</p>}
      {inventory.error && <p role="alert" className="p-3 text-sm text-red-600">{inventory.error}</p>}
      <div className="data-scroll rounded-xl bg-surface px-4">
        {inventory.rows
          .map((group) => (
            <div key={group._id} className="flex items-center gap-1">
              <button
                key={group._id}
                type="button"
                aria-label={`${manage ? "Manage" : "View"} members of ${group.name}`}
                className="flex w-full items-center gap-3 rounded-lg px-2 py-3 text-left hover:bg-accent/35"
                onClick={() => onOpen(group)}
              >
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-control">
                  <IconFolder size={18} className="text-primary" />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-medium">
                    {group.name}
                  </span>
                  <span className="mt-1 block text-xs text-muted-foreground">
                    {group.machine_count} machines · {group.user_count} {group.user_count===1 ? "person" : "people"} · {group.book_count}{" "}
                    policies
                  </span>
                </span>
                <IconChevronRight size={17} className="text-muted-foreground" />
              </button>
            </div>
          ))}
        {!inventory.loading && !inventory.rows.length && (
          <p className="p-4 text-sm text-muted-foreground">
            Create your first group to organise policies.
          </p>
        )}
      </div>
      <ResultsPagination count={inventory.pagination.total} noun="Groups" page={page} pages={inventory.pagination.pages} pageSize={25} onPage={setPage}/>
    </section>
  );
}
