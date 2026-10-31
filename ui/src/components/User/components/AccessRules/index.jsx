import useUrlTab from "@/shared/hooks/useUrlTab";
import useInventoryPage from "@/shared/hooks/useInventoryPage";
import InventorySelect from "@/components/ui/inventory-select";
import ResultsPagination from "@/components/ui/results-pagination";
import { inventoryUrl } from "@/shared/utils/inventory-resource.mjs";
import useBackgroundRefresh from "@/shared/hooks/useBackgroundRefresh";
import { useWorkspaceState } from "@/shared/contexts/workspaceCache";
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
  IconRoute,
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
import ExitRoutes from "./ExitRoutes";
import ProxyGrants from "./ProxyGrants";

export default function AccessRules({ active = true }) {
  const router = useRouter(),
    toast = useToast();
  const workspace=String(router.query.workspace || "");
  const [manualError,setError]=useState("");
  const [busy,setBusy]=useState(false);
  const [section, setSection] = useUrlTab("tab",["policies","routes","groups","people","network"],"policies",{enabled:active});
  const [query, setQuery] = useState(""),
    [group, setGroup] = useState("all");
  const [editor, setEditor] = useState(null),
    [confirmation, setConfirmation] = useState(null);
  const [invite, setInvite] = useState(false);
  const [page,setPage]=useState(1),[peoplePage,setPeoplePage]=useState(1),[invitePage,setInvitePage]=useState(1);
  const params=useMemo(()=>({workspace}),[workspace]);
  const metadata=useInventoryPage("access-summary",params,{enabled:active});
  const manage=["owner","admin"].includes(metadata.data?.data?.role);
  const books=useInventoryPage("access-books",{...params,q:query,group,page,page_size:25},{enabled:active && section==="policies"});
  const people=useInventoryPage("access-people",{...params,q:query,page:peoplePage,page_size:25},{enabled:active && section==="people"});
  const invitations=useInventoryPage("access-invitations",{...params,page:invitePage,page_size:25},{enabled:active && section==="people" && manage});
  useEffect(()=>{if(!books.loading && page>books.pagination.pages)setPage(books.pagination.pages);},[page,books.loading,books.pagination.pages]);
  useEffect(()=>{if(!people.loading && peoplePage>people.pagination.pages)setPeoplePage(people.pagination.pages);},[peoplePage,people.loading,people.pagination.pages]);
  useEffect(()=>{if(!invitations.loading && invitePage>invitations.pagination.pages)setInvitePage(invitations.pagination.pages);},[invitePage,invitations.loading,invitations.pagination.pages]);
  const load=useCallback(()=>{
    for(const kind of ["summary","books","groups","machines","people","entities","peers","exits","proxy-grants","invitations"])metadata.resource.invalidate(`access-${kind}`);
    setError("");
  },[metadata.resource]);
  useBackgroundRefresh(load,{enabled:active,refreshKey:workspace,interval:30000});
  useEffect(()=>{setQuery("");setGroup("all");setPage(1);setPeoplePage(1);setInvitePage(1);setEditor(null);setInvite(false);setError("");},[workspace]);
  useEffect(()=>{setPage(1);setPeoplePage(1);},[query,group]);
  useEffect(()=>{if(!active){setEditor(null);setInvite(false);}},[active]);
  const data=metadata.data?.data && !metadata.error ? {...metadata.data.data,groups:[],machines:[],users:people.rows,books:books.rows,invitations:invitations.rows,exit_nodes:[]} : null;
  const error=manualError || metadata.error || (section==="policies" ? books.error : section==="people" ? people.error || (manage ? invitations.error : "") : "");
  const names=new Map(Object.entries(books.data?.labels || {}));
  const filtered=books.rows;
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
    await mutate(async()=>{
      const response=await axios.get(inventoryUrl("access-books",{...params,ids:book._id,detail:true,page_size:1}));
      const full=response.data.data?.[0];
      if(!full)throw Error("Policy no longer exists");
      const {name,group_id,rules,revision}=full;
      await axios.put(`${API}/books/${book._id}`,{name,group_id,rules,revision,enabled:!book.enabled},{params});
    },book.enabled ? `Paused ${book.name}` : `Resumed ${book.name}`);
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
          {data.workspace_name} · {data.role}
        </p>
      )}
      <nav
        aria-label="Access sections"
        className="mb-3 flex shrink-0 gap-1 overflow-x-auto rounded-lg bg-surface p-1 sm:self-start"
      >
        {[
          ["policies", "Policies", IconShieldLock],
          ["routes", "Routes", IconRoute],
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
          {section === "policies" && (
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
                            group === "all" ? "" : group,
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
                <InventorySelect kind="access-groups" className="col-span-2 min-w-0 sm:w-44" label="Filter rule group" value={group} onChange={setGroup} filters={params} extraOptions={[{value:"all",label:"All groups"}]}/>
              </div>
              <section
                aria-label="Private policies"
                className="data-scroll rounded-xl bg-surface"
              >
                {books.loading ? <p role="status" className="p-5 text-sm text-muted-foreground">Loading policies…</p> : !filtered.length ? (
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
                      manage && !data.counts.groups ? (
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
              <ResultsPagination count={books.pagination.total} noun="Policies" page={page} pages={books.pagination.pages} pageSize={25} onPage={setPage}/>
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
          {section === "routes" && (
            <div className="flex min-h-0 flex-1 flex-col"><ExitRoutes data={data} manage={manage} params={params} onSaved={load} /><ProxyGrants data={data} manage={manage} params={params} /></div>
          )}
          {section === "people" && (
            <section className="flex min-h-0 flex-1 flex-col">
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
              <div className="mb-3 shrink-0"><SearchField label="Search workspace people" value={query} onChange={setQuery} placeholder="Find a person…"/></div>
              <div className="data-scroll rounded-xl bg-surface px-4">
              {people.loading && <p role="status" className="py-3 text-sm text-muted-foreground">Loading people…</p>}
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
              {!people.loading && !data.users.length && <EmptyState icon={IconUsers} title="No matching people" description="Try another name or email address." />}
              </div>
              {manage && invitations.pagination.total > 0 && <section className="mt-3 shrink-0 rounded-xl bg-surface">
              <div className="max-h-[24dvh] overflow-auto px-4">
              {data.invitations.length > 0 && (
                <h3 className="mb-1 mt-3 text-sm font-semibold">
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
              </div>
              {manage && <ResultsPagination count={invitations.pagination.total} noun="Invitations" page={invitePage} pages={invitations.pagination.pages} pageSize={25} onPage={setInvitePage}/>}
              </section>}
              <ResultsPagination count={people.pagination.total} noun="People" page={peoplePage} pages={people.pagination.pages} pageSize={25} onPage={setPeoplePage}/>
            </section>
          )}
          {section === "network" && (
            <div className="data-scroll overflow-auto">
              <NetworkSettings
                key={workspace}
                data={data}
                manage={manage}
                params={params}
                onSaved={load}
              />
            </div>
          )}
        </>
      )}
      {data && editor?.kind === "book" && (
        <BookEditor
          book={editor.data}
          initialIndex={editor.index || 0}
          groups={data.groups}
          manage={manage}
          params={params}
          onClose={() => setEditor(null)}
          onSaved={async () => {
            await load();
            setEditor(null);
          }}
        />
      )}
      {data && editor?.kind === "group" && (
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
      {data && invite && (
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
