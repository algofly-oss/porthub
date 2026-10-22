import { useState } from "react";
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
    <section className="flex min-h-0 flex-1 flex-col rounded-xl bg-surface p-4">
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
      <div className="data-scroll">
        {data.groups
          .filter((g) => g.name.toLowerCase().includes(query.toLowerCase()))
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
                    {
                      data.machines.filter((m) =>
                        m.group_ids.includes(group._id),
                      ).length
                    }{" "}
                    machines · {group.user_ids.length}{" "}
                    {group.user_ids.length === 1 ? "person" : "people"} ·{" "}
                    {data.books.filter((b) => b.group_id === group._id).length}{" "}
                    policies
                  </span>
                </span>
                <IconChevronRight size={17} className="text-muted-foreground" />
              </button>
            </div>
          ))}
        {!data.groups.length && (
          <p className="p-4 text-sm text-muted-foreground">
            Create your first group to organise policies.
          </p>
        )}
      </div>
    </section>
  );
}
