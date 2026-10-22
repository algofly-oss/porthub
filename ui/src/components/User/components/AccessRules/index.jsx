import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/router";
import axios from "axios";
import {
  IconPlus,
  IconShieldLock,
  IconTrash,
  IconFolder,
  IconUsers,
  IconSettings,
} from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import SearchSelect from "@/components/ui/search-select";
import { PageHeader, SearchField, EmptyState } from "@/components/ui/workspace";
import { Dialog } from "@/components/ui/dialog";
import useToast from "@/shared/hooks/useToast";
import { API, blankRule, errorText, key } from "./shared";
import BookEditor from "./BookEditor";
import GroupList from "./GroupList";
import GroupEditor from "./GroupEditor";
import NetworkSettings from "./NetworkSettings";
import InviteEditor from "./InviteEditor";
import PolicyTable from "./PolicyTable";
import PrivateMachines from "./PrivateMachines";

export default function AccessRules() {
  const router = useRouter(),
    toast = useToast();
  const [workspaces, setWorkspaces] = useState([]),
    [workspace, setWorkspace] = useState("");
  const [data, setData] = useState(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const [section, setSection] = useState("rules"),
    [query, setQuery] = useState(""),
    [group, setGroup] = useState("all");
  const [editor, setEditor] = useState(null),
    [confirmation, setConfirmation] = useState(null);
  const [invite, setInvite] = useState(false);
  const params = useMemo(() => (workspace ? { workspace } : {}), [workspace]);
  const load = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/snapshot`, { params });
      setData(response.data);
      setError("");
    } catch (error) {
      setError(errorText(error));
    }
  }, [params]);
  useEffect(() => {
    let alive = true;
    axios
      .get(`${API}/workspaces`)
      .then((response) => {
        if (!alive) return;
        const items = response.data.data || [];
        setWorkspaces(items);
        const requested = String(router.query.workspace || "");
        setWorkspace(
          items.some((item) => item.id === requested)
            ? requested
            : items.find((item) => item.role === "owner")?.id ||
                items[0]?.id ||
                "",
        );
      })
      .catch((error) => {
        if (alive) setError(errorText(error));
      });
    return () => {
      alive = false;
    };
  }, [router.query.workspace]);
  useEffect(() => {
    if (workspace) {
      setData(null);
      setGroup("all");
      setQuery("");
      load();
    }
  }, [workspace, load]);
  const manage = data?.role === "owner" || data?.role === "admin";
  const options = useMemo(
    () =>
      data
        ? [
            // Every machine in the workspace, including ones added later.
            { value: "all:machines", label: "All machines" },
            ...data.groups.map((g) => ({
              value: `group:${g._id}`,
              label: `Group · ${g.name}`,
            })),
            ...data.machines.map((m) => ({
              value: `machine:${m._id}`,
              label: `Machine · ${m.name}`,
            })),
            ...data.users.map((u) => ({
              value: `user:${u._id}`,
              label: `Person · ${u.name || u.email}`,
            })),
          ]
        : [],
    [data],
  );
  const names = new Map(
    options.map((item) => [item.value, item.label.replace(/^[^·]+· /, "")]),
  );
  const filtered =
    data?.books.filter(
      (book) =>
        (group === "all" || book.group_id === group) &&
        `${book.name} ${book.rules.map((rule) => `${rule.name} ${[...rule.sources, ...rule.destinations].map((item) => names.get(key(item))).join(" ")}`).join(" ")}`
          .toLowerCase()
          .includes(query.toLowerCase()),
    ) || [];
  async function mutate(action, success) {
    setBusy(true);
    try {
      await action();
      await load();
      if (success) toast.success(success);
      return true;
    } catch (error) {
      toast.error(errorText(error));
      return false;
    } finally {
      setBusy(false);
    }
  }
  async function toggle(book) {
    const { name, group_id, rules, revision } = book;
    await mutate(
      () => axios.put(`${API}/books/${book._id}`, { name, group_id, rules, revision, enabled: !book.enabled }, { params }),
      book.enabled ? `Paused ${book.name}` : `Resumed ${book.name}`,
    );
  }
  async function remove(item) {
    const ok = await mutate(
      () =>
        axios.delete(
          item.kind === "book"
            ? `${API}/books/${item.id}`
            : item.kind === "member"
              ? `${API}/members/${item.id}`
              : `${API}/invitations/${item.id}`,
          {
            params,
            ...(item.kind === "book"
              ? { data: { revision: item.revision } }
              : {}),
          },
        ),
      "Removed",
    );
    if (ok) setConfirmation(null);
  }
  return (
    <div className="workspace-page">
      <PageHeader title="Access Rules" />
      {data && data.role !== "owner" && (
        <p className="mb-3 text-xs text-muted-foreground">
          {workspaces.find((item) => item.id === workspace)?.name} · {data.role}
        </p>
      )}
      <nav
        aria-label="Access sections"
        className="mb-3 flex shrink-0 gap-1 overflow-x-auto rounded-lg bg-surface p-1 sm:self-start"
      >
        {[
          ["rules", "Policies", IconShieldLock],
          ["groups", "Groups", IconFolder],
          ["people", "People", IconUsers],
          ["network", "Network", IconSettings],
        ].map(([value, label, Icon]) => (
          <button
            key={value}
            type="button"
            aria-pressed={section === value}
            className={`flex min-h-[36px] flex-1 items-center justify-center gap-2 whitespace-nowrap rounded-md px-2 text-sm sm:flex-none sm:px-4 ${section === value ? "bg-primary/10 font-medium text-primary" : "text-muted-foreground hover:bg-control hover:text-foreground"}`}
            onClick={() => {
              setSection(value);
              setQuery("");
            }}
          >
            <Icon size={15} className="hidden sm:block" />
            {label}
          </button>
        ))}
      </nav>
      {error && (
        <div
          role="alert"
          className="mb-3 flex items-center justify-between gap-3 rounded-lg bg-red-500/10 p-3 text-sm text-red-700 dark:text-red-300"
        >
          {error}
          <Button variant="ghost" onClick={load}>
            Retry
          </Button>
        </div>
      )}
      {!data ? (
        !error && (
          <p role="status" className="p-5 text-sm text-muted-foreground">
            Loading access controls…
          </p>
        )
      ) : (
        <>
          {section === "rules" && (
            <>
              <div className="mb-3 grid shrink-0 grid-cols-[minmax(0,1fr)_auto] gap-2 sm:flex sm:items-center">
                <div className="min-w-0 sm:flex-1">
                  <SearchField
                    label="Search policies"
                    placeholder="Search rules or entities…"
                    value={query}
                    onChange={setQuery}
                  />
                </div>
                {manage && (
                  <Button
                    onClick={() =>
                      setEditor({
                        kind: "book",
                        data: {
                          name: "",
                          group_id:
                            group === "all" ? data.groups[0]?._id || "" : group,
                          enabled: true,
                          rules: [blankRule()],
                          revision: 0,
                        },
                      })
                    }
                  >
                    <IconPlus size={16} />
                    <span>Policy</span>
                  </Button>
                )}
                <SearchSelect
                  className="min-w-0 sm:w-44"
                  label="Filter rule group"
                  value={group}
                  onChange={setGroup}
                  options={[
                    { value: "all", label: "All groups" },
                    ...data.groups.map((g) => ({
                      value: g._id,
                      label: g.name,
                    })),
                  ]}
                />
              </div>
              <section
                aria-label="Private policies"
                className="data-scroll rounded-xl bg-surface"
              >
                {!filtered.length ? (
                  <EmptyState
                    icon={IconShieldLock}
                    title={
                      query || group !== "all" || data.books.length
                        ? "No matching policies"
                        : "Choose who can connect"
                    }
                    description={
                      query || group !== "all" || data.books.length
                        ? "Try another search or group filter."
                        : "Create a group → Add members → Add a policy."
                    }
                    action={
                      manage && !data.groups.length ? (
                        <Button onClick={() => setSection("groups")}>
                          <IconPlus size={15} />
                          Create a Group
                        </Button>
                      ) : null
                    }
                  />
                ) : (
                  <PolicyTable
                    books={filtered}
                    groups={data.groups}
                    names={names}
                    manage={manage}
                    busy={busy}
                    onOpen={(book) => setEditor({ kind: "book", data: book })}
                    onToggle={toggle}
                    onDelete={(book) =>
                      setConfirmation({ kind: "book", id: book._id, revision: book.revision, name: book.name })
                    }
                  />
                )}
              </section>
            </>
          )}
          {section === "groups" && (
            <GroupList
              data={data}
              manage={manage}
              params={params}
              onSaved={load}
              onOpen={(group) => setEditor({ kind: "group", data: group })}
            />
          )}
          {section === "people" && (
            <section className="data-scroll overflow-auto rounded-xl bg-surface p-4">
              <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="text-base font-semibold">Workspace People</h2>
                  <p className="mt-1 text-sm text-muted-foreground">
                    Joining does not grant network access. Assign groups and
                    explicit rules.
                  </p>
                </div>
                {manage && (
                  <Button onClick={() => setInvite(true)}>
                    <IconPlus size={16} />
                    Invite Person
                  </Button>
                )}
              </div>
              {data.users.map((person) => (
                <div
                  key={person._id}
                  className="flex items-center gap-3 border-b border-border/70 py-3 last:border-0"
                >
                  <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-control text-sm font-medium">
                    {(person.name || person.email).slice(0, 1)}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium">
                      {person.name}
                    </p>
                    <p className="mt-1 truncate text-xs text-muted-foreground">
                      {person.email}
                    </p>
                  </div>
                  <span className="text-xs capitalize text-muted-foreground">
                    {person.role}
                  </span>
                  {manage &&
                    person.role !== "owner" &&
                    (data.role === "owner" || person.role === "member") && (
                      <Button
                        size="icon"
                        variant="ghost"
                        aria-label={`Remove ${person.name || person.email}`}
                        onClick={() =>
                          setConfirmation({
                            kind: "member",
                            id: person._id,
                            name: person.name || person.email,
                          })
                        }
                      >
                        <IconTrash size={16} />
                      </Button>
                    )}
                </div>
              ))}
              {data.invitations.length > 0 && (
                <h3 className="mb-1 mt-6 text-sm font-semibold">
                  Pending Invitations
                </h3>
              )}
              {data.invitations.map((item) => (
                <div
                  key={item._id}
                  className="flex items-center gap-3 border-b border-border/70 py-3"
                >
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm">{item.email}</p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {item.role} · expires{" "}
                      {new Date(item.expires_at).toLocaleDateString()}
                    </p>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() =>
                      setConfirmation({
                        kind: "invite",
                        id: item._id,
                        name: `invitation for ${item.email}`,
                      })
                    }
                  >
                    Revoke
                  </Button>
                </div>
              ))}
            </section>
          )}
          {section === "network" && (
            <div className="data-scroll overflow-auto">
              <PrivateMachines
                data={data}
                manage={manage}
                params={params}
                onSaved={load}
              />
              <NetworkSettings
                data={data}
                manage={manage}
                params={params}
                onSaved={load}
              />
            </div>
          )}
        </>
      )}
      {editor?.kind === "book" && (
        <BookEditor
          book={editor.data}
          initialIndex={editor.index || 0}
          groups={data.groups}
          options={options}
          manage={manage}
          params={params}
          onClose={() => setEditor(null)}
          onSaved={async () => {
            await load();
            setEditor(null);
          }}
        />
      )}
      {editor?.kind === "group" && (
        <GroupEditor
          group={editor.data}
          data={data}
          manage={manage}
          params={params}
          onClose={() => setEditor(null)}
          onSaved={async () => {
            await load();
            setEditor(null);
          }}
        />
      )}
      {invite && (
        <InviteEditor
          role={data.role}
          params={params}
          onClose={() => setInvite(false)}
          onSaved={load}
        />
      )}
      <Dialog
        opened={Boolean(confirmation)}
        onClose={() => !busy && setConfirmation(null)}
        title="Confirm removal"
      >
        <p className="text-sm leading-6 text-muted-foreground">
          Remove {confirmation?.name}?{" "}
          {confirmation?.kind === "book"
            ? "Connections allowed only by this policy will no longer be permitted."
            : "Their workspace permissions will be revoked."}
        </p>
        <div className="mt-5 flex justify-end gap-2">
          <Button
            variant="ghost"
            disabled={busy}
            onClick={() => setConfirmation(null)}
          >
            Cancel
          </Button>
          <Button
            variant="destructive"
            disabled={busy}
            onClick={() => remove(confirmation)}
          >
            Remove
          </Button>
        </div>
      </Dialog>
    </div>
  );
}
