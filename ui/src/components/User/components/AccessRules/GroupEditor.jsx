import { useState } from "react";
import axios from "axios";
import { IconUser, IconServer } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { SearchField } from "@/components/ui/workspace";
import WorkspaceDrawer from "@/components/ui/workspace-drawer";
import { API, errorText, DirtyGuard } from "./shared";

export default function GroupEditor({
  group,
  data,
  manage,
  params,
  onClose,
  onSaved,
}) {
  const initial = {
    machine_ids: data.machines
      .filter((m) => m.group_ids.includes(group._id))
      .map((m) => m._id),
    user_ids: group.user_ids,
  };
  const [form, setForm] = useState(initial),
    [query, setQuery] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const dirty = JSON.stringify(form) !== JSON.stringify(initial);
  const toggle = (field, value) =>
    setForm((old) => ({
      ...old,
      [field]: old[field].includes(value)
        ? old[field].filter((item) => item !== value)
        : [...old[field], value],
    }));
  async function save() {
    setBusy(true);
    try {
      await axios.put(`${API}/groups/${group._id}/members`, form, { params });
      await onSaved();
    } catch (error) {
      setError(errorText(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <DirtyGuard dirty={dirty && manage} busy={busy} onClose={onClose}>
      {(close) => (
        <WorkspaceDrawer
          opened
          onClose={close}
          title={`${group.name} · Members`}
          fixedHeight="min(640px, 85dvh)"
          animate={false}
        >
          <div className="mb-3">
            <SearchField
              label="Search group entities"
              placeholder="Search people or machines…"
              value={query}
              onChange={setQuery}
            />
          </div>
          <div className="data-scroll">
            {[
              ["user_ids", "People", data.users, IconUser],
              ["machine_ids", "Machines", data.machines, IconServer],
            ].map(([field, label, items, Icon]) => (
              <section key={field} className="mb-4">
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  {label}
                </h3>
                {items
                  .filter((item) =>
                    `${item.name} ${item.email || ""}`
                      .toLowerCase()
                      .includes(query.toLowerCase()),
                  )
                  .map((item) => (
                    <label
                      key={item._id}
                      className="flex cursor-pointer items-center gap-3 rounded-lg px-2 py-3 hover:bg-accent/35"
                    >
                      <Checkbox
                        aria-label={`Tag ${item.name || item.email}`}
                        checked={form[field].includes(item._id)}
                        disabled={!manage}
                        onCheckedChange={() => toggle(field, item._id)}
                      />
                      <Icon
                        size={16}
                        className="shrink-0 text-muted-foreground"
                      />
                      <span className="min-w-0">
                        <span className="block truncate text-sm">
                          {item.name || item.email}
                        </span>
                        {field === "user_ids" && (
                          <span className="mt-1 block truncate text-xs text-muted-foreground">
                            Includes their enrolled devices
                          </span>
                        )}
                      </span>
                    </label>
                  ))}
              </section>
            ))}
          </div>
          {error && (
            <p role="alert" className="my-2 text-sm text-red-500">
              {error}
            </p>
          )}
          <div className="mt-3 flex shrink-0 justify-end gap-2 border-t border-border pt-3">
            <Button variant="ghost" onClick={close}>
              {manage ? "Cancel" : "Close"}
            </Button>
            {manage && (
              <Button disabled={busy} onClick={save}>
                {busy ? "Saving…" : "Save Members"}
              </Button>
            )}
          </div>
        </WorkspaceDrawer>
      )}
    </DirtyGuard>
  );
}
