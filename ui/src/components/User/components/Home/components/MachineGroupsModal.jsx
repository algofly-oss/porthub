import useInventoryPage from "@/shared/hooks/useInventoryPage";
import InventorySelect from "@/components/ui/inventory-select";
import ResultsPagination from "@/components/ui/results-pagination";
import { useWorkspaceState } from "@/shared/contexts/workspaceCache";
import { useEffect, useMemo, useRef, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { IconFolder, IconTrash } from "@tabler/icons-react";
import WorkspaceDrawer from "@/components/ui/workspace-drawer";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import SearchSelect from "@/components/ui/search-select";

export default function MachineGroupsModal({ opened, onClose, groups: initialGroups = [], machines: initialMachines = [], onCreateGroup, onRenameGroup, onDeleteGroup, onAddMachineToGroup, onRemoveMachineFromGroup }) {
  const [selectedId, setSelectedId] = useState(null);
  const [name, setName] = useState("");
  const [newName, setNewName] = useState("");
  const [query, setQuery] = useState("");
  const [groupQuery, setGroupQuery] = useState("");
  const [busy, setBusy] = useState(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [error, setError] = useState("");
  const reducedMotion = useReducedMotion();
  const groupList = useRef(null);
  const [groupPage, setGroupPage] = useState(1);
  const [machinePage, setMachinePage] = useState(1);
  const [chosenGroup, setChosenGroup] = useState(null);
  const [summary] = useWorkspaceState("inventory.summary", null);
  const groupInventory = useInventoryPage("groups", { q: groupQuery, page: groupPage, page_size: 25 }, { enabled: opened });
  const machineInventory = useInventoryPage("machines", { q: query, page: machinePage, page_size: 25, options: true }, { enabled: opened && !!selectedId });
  useEffect(() => { if (!groupInventory.loading && groupPage > groupInventory.pagination.pages) setGroupPage(groupInventory.pagination.pages); }, [groupPage, groupInventory.loading, groupInventory.pagination.pages]);
  useEffect(() => { if (!machineInventory.loading && machinePage > machineInventory.pagination.pages) setMachinePage(machineInventory.pagination.pages); }, [machinePage, machineInventory.loading, machineInventory.pagination.pages]);
  const groups = groupInventory.rows;
  const machines = machineInventory.rows.map(row => ({ id: row._id, name: row.name, hostname: row.hostname, groupIds: row.group_ids || [] }));
  const selected = groups.find(group => group._id === selectedId) || (chosenGroup?._id === selectedId ? chosenGroup : initialGroups.find(group => group._id === selectedId));
  useEffect(() => { setGroupPage(1); }, [groupQuery]);
  useEffect(() => { setMachinePage(1); }, [query, selectedId]);
  useEffect(() => { const selected = groups.find(group => group._id === selectedId); if (selected) setChosenGroup(selected); }, [groupInventory.data, groups, selectedId]);
  useEffect(() => {
    if (opened && !groupInventory.loading && !groupInventory.refreshing && !selected) setSelectedId(groups[0]?._id || null);
  }, [opened, groups, selectedId, selected, groupInventory.loading, groupInventory.refreshing]);
  useEffect(() => { setName(selected?.name || ""); setConfirmDelete(false); setError(""); }, [selected?._id, selected?.name]);
  const assigned = selected?.machineCount || 0;
  const visible = machines;
  const visibleGroups = groups;
  const groupCounts = new Map(groups.map(group => [group._id, group.machineCount || 0]));
  const run = async (key, action) => {
    const focused = document.activeElement;
    setBusy(key); setError("");
    try { await action(); } catch (err) { setError(err?.response?.data?.detail || "Could not save. Please try again."); }
    finally {
      setBusy(null);
      requestAnimationFrame(() => {
        const dialog = groupList.current?.closest('[role="dialog"]');
        if (focused?.isConnected && dialog?.contains(focused)) focused.focus();
        else dialog?.focus();
      });
    }
  };
  return <WorkspaceDrawer opened={opened} onClose={onClose} title="Machine Groups" size="xl" closeOnEscape={!busy} closeOnClickOutside={!busy}>
    <p className="mb-4 text-sm text-muted-foreground">Choose a group and check the machines that belong to it.</p>
    <div className="group-workspace">
      <aside className="flex min-h-0 min-w-0 flex-col gap-3 p-3">
        <form className="space-y-2" onSubmit={event => { event.preventDefault(); if (newName.trim()) run("create", async () => { const created = await onCreateGroup(newName.trim()); if (created?._id) { setSelectedId(created._id); setChosenGroup(created); setNewName(""); setGroupQuery(""); } }); }}>
          <label htmlFor="new-group-name" className="text-xs font-medium text-muted-foreground">Create a group</label>
          <Input id="new-group-name" aria-label="New group name" placeholder="Group name…" maxLength={80} value={newName} onChange={event => setNewName(event.target.value)} />
          <Button type="submit" size="sm" className="w-full" disabled={!!busy || !newName.trim()}>Create group</Button>
        </form>
        <div className="md:hidden"><InventorySelect kind="groups" label="Choose a group" value={selectedId || ""} selected={selected} onChange={(id,row) => {setSelectedId(id); setChosenGroup(row);}} disabled={!!busy} /></div>
        <Input aria-label="Search groups" placeholder="Search groups…" className="hidden md:flex" value={groupQuery} onChange={event=>setGroupQuery(event.target.value)} />
        <nav ref={groupList} aria-label="Machine groups" className="hidden min-h-0 flex-1 flex-col gap-1 overflow-y-auto overscroll-contain md:flex">
          {visibleGroups.map(group => <button key={group._id} type="button" title={group.name} disabled={!!busy} onClick={() => setSelectedId(group._id)} aria-pressed={selectedId === group._id} className={`flex shrink-0 items-center gap-2 rounded-md px-3 py-2 text-left text-sm ${selectedId === group._id ? "bg-control text-foreground" : "text-muted-foreground hover:bg-accent"}`}><IconFolder size={16} className="shrink-0" /><span className="min-w-0 flex-1 truncate">{group.name}</span><span className="text-xs text-muted-foreground">{groupCounts.get(group._id) || 0}</span></button>)}
          {!visibleGroups.length && <p className="p-2 text-sm text-muted-foreground">No matching groups.</p>}
        </nav>
        <div className="hidden md:block"><ResultsPagination count={groupInventory.pagination.total} noun="Groups" page={groupPage} pages={groupInventory.pagination.pages} pageSize={25} onPage={setGroupPage} /></div>
        {groupInventory.error && <p role="alert" className="text-xs text-red-600">{groupInventory.error}</p>}
      </aside>
      {selected ? <motion.section key={selectedId} initial={{ opacity: reducedMotion ? 1 : 0, y: reducedMotion ? 0 : 4 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .2 }} className="flex min-h-0 min-w-0 flex-col gap-3">
        <form className="flex items-center gap-2" onSubmit={event => { event.preventDefault(); if (name.trim()) run("rename", () => onRenameGroup(selectedId, name.trim())); }}>
          <Input aria-label="Group name" value={name} maxLength={80} onChange={event => setName(event.target.value)} />
          {name.trim() !== selected.name && <Button variant="secondary" disabled={!!busy || !name.trim()} type="submit">Save</Button>}
          <Button type="button" variant="ghost" size="icon" aria-label="Delete group" onClick={() => setConfirmDelete(value => !value)} disabled={!!busy}><IconTrash size={17} /></Button>
        </form>
        {confirmDelete && <div className="rounded-lg bg-red-500/10 p-3 text-sm"><p className="mb-2">Delete this group? Its machines and ports will stay untouched.</p><div className="flex gap-2"><Button variant="destructive" disabled={!!busy} onClick={() => run("delete", async () => { await onDeleteGroup(selectedId); setSelectedId(null); setChosenGroup(null); setConfirmDelete(false); requestAnimationFrame(() => groupList.current?.closest('[role="dialog"]')?.focus()); })}>Delete group</Button><Button variant="ghost" onClick={() => setConfirmDelete(false)}>Cancel</Button></div></div>}
        <div className="flex flex-wrap items-center justify-between gap-1 text-xs text-muted-foreground"><span>{assigned} of {summary?.machines?.total ?? machineInventory.pagination.total} machines selected</span><span role="status">{busy ? "Saving…" : "Changes save automatically"}</span></div>
        <Input aria-label="Search group machines" placeholder="Find a machine…" value={query} onChange={event => setQuery(event.target.value)} />
        <div className="data-scroll" aria-label="Group membership">
          {visible.map(machine => { const checked = (machine.groupIds || []).includes(selectedId); return <label key={machine.id} className="flex cursor-pointer items-center gap-3 rounded-md px-2 py-3 transition-colors hover:bg-muted"><Checkbox aria-label={`Include ${machine.name || machine.hostname}`} checked={checked} disabled={!!busy} onCheckedChange={() => run(machine.id, () => checked ? onRemoveMachineFromGroup(machine.id, selectedId) : onAddMachineToGroup(machine.id, selectedId))} /><span className="min-w-0"><span className="block truncate text-sm font-medium">{machine.name || machine.hostname}</span><span className="block truncate text-xs text-muted-foreground">{machine.hostname}</span></span></label>; })}
          {!visible.length && <p className="p-4 text-sm text-muted-foreground">No machines found.</p>}
        </div>
        <ResultsPagination count={machineInventory.pagination.total} noun="Machines" page={machinePage} pages={machineInventory.pagination.pages} pageSize={25} onPage={setMachinePage} />
        {machineInventory.error && <p role="alert" className="text-xs text-red-600">{machineInventory.error}</p>}
      </motion.section> : <div className="flex items-center justify-center text-sm text-muted-foreground">Create a group to organize your machines.</div>}
    </div>
    {error && <p role="alert" className="mt-3 text-sm text-red-600 dark:text-red-400">{error}</p>}
  </WorkspaceDrawer>;
}
