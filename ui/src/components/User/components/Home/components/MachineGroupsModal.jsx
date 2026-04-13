import { useEffect, useMemo, useState } from "react";
import {
  Button,
  Modal,
  Pagination,
  Stack,
  Text,
  TextInput,
  Group,
} from "@mantine/core";
import { useMantineColorScheme } from "@mantine/core";
import {
  IconTrash,
  IconArrowLeft,
  IconFolder,
  IconUsers,
} from "@tabler/icons-react";
import { BsCircleFill } from "react-icons/bs";

const GROUPS_PER_PAGE = 5;
const MACHINES_PER_PAGE = 5;

const getInputClassName = (isDark) =>
  `w-full rounded-md !border-0 px-3 py-2 text-sm !shadow-none !outline-none !ring-0 transition-colors focus:!border-0 focus:!shadow-none focus:!outline-none focus:!ring-0 ${
    isDark
      ? "!bg-zinc-800 !text-zinc-100 placeholder:!text-zinc-500"
      : "!bg-zinc-50 !text-zinc-900 placeholder:!text-zinc-400"
  }`;

const getLabelClassName = (isDark) =>
  `mb-1.5 block text-sm font-semibold ${isDark ? "text-zinc-100" : "text-zinc-900"}`;

export default function MachineGroupsModal({
  opened,
  onClose,
  groups,
  machines = [],
  onCreateGroup,
  onRenameGroup,
  onDeleteGroup,
  onAddMachineToGroup,
  onRemoveMachineFromGroup,
}) {
  const { colorScheme } = useMantineColorScheme();
  const isDark = colorScheme === "dark";
  const [selectedGroupId, setSelectedGroupId] = useState(null);
  const [isCreatingGroupView, setIsCreatingGroupView] = useState(false);
  const [editName, setEditName] = useState("");
  const [savingId, setSavingId] = useState(null);
  const [deletingId, setDeletingId] = useState(null);
  const [groupPendingDelete, setGroupPendingDelete] = useState(null);
  const [machineQuery, setMachineQuery] = useState("");
  const [groupQuery, setGroupQuery] = useState("");
  const [membershipSavingMachineId, setMembershipSavingMachineId] = useState(null);
  const [groupsPage, setGroupsPage] = useState(1);
  const [machinesPage, setMachinesPage] = useState(1);

  useEffect(() => {
    if (!opened) {
      setSelectedGroupId(null);
      setIsCreatingGroupView(false);
      setEditName("");
      setGroupPendingDelete(null);
      setMachineQuery("");
      setGroupQuery("");
      setMembershipSavingMachineId(null);
      setGroupsPage(1);
      setMachinesPage(1);
    }
  }, [opened]);

  useEffect(() => {
    if (
      selectedGroupId &&
      !groups.some((group) => group._id === selectedGroupId)
    ) {
      setSelectedGroupId(null);
      setIsCreatingGroupView(false);
      setEditName("");
      setMachineQuery("");
      setGroupQuery("");
      setMachinesPage(1);
    }
  }, [groups, selectedGroupId]);

  const modalClassNames = isDark
    ? {
        content: "!border !border-zinc-700 !bg-zinc-900",
        header: "!border-b !border-zinc-800 !bg-zinc-900",
        title: "font-bold !text-zinc-100",
        close: "!text-zinc-400 hover:!bg-zinc-800",
        body: "!bg-zinc-900 !pt-3",
      }
    : {
        content: "!border !border-zinc-200 !bg-white",
        header: "!border-b !border-zinc-200 !bg-white",
        title: "font-bold !text-zinc-900",
        close: "!text-zinc-500 hover:!bg-zinc-100",
        body: "!bg-white !pt-3",
      };

  const btnSecondary = isDark
    ? "!border-zinc-700 !bg-zinc-800 !text-zinc-100 hover:!bg-zinc-700"
    : "!border-zinc-300 !bg-white !text-zinc-900 hover:!bg-zinc-50";

  const selectedGroup =
    groups.find((group) => group._id === selectedGroupId) || null;
  const groupMachineCountById = useMemo(
    () =>
      Object.fromEntries(
        groups.map((group) => [
          group._id,
          machines.filter((machine) => (machine.groupIds || []).includes(group._id)).length,
        ])
      ),
    [groups, machines]
  );
  const filteredMachines = useMemo(() => {
    const normalizedQuery = machineQuery.trim().toLowerCase();
    if (!normalizedQuery) {
      return machines;
    }

    return machines.filter((machine) => {
      const name = (machine.name || "").toLowerCase();
      const hostname = (machine.hostname || "").toLowerCase();
      return name.includes(normalizedQuery) || hostname.includes(normalizedQuery);
    });
  }, [machineQuery, machines]);
  const filteredGroups = useMemo(() => {
    const normalizedQuery = groupQuery.trim().toLowerCase();
    if (!normalizedQuery) {
      return groups;
    }

    return groups.filter((group) =>
      (group.name || "").toLowerCase().includes(normalizedQuery)
    );
  }, [groupQuery, groups]);
  const totalGroupPages = Math.max(1, Math.ceil(filteredGroups.length / GROUPS_PER_PAGE));
  const paginatedGroups = filteredGroups.slice(
    (groupsPage - 1) * GROUPS_PER_PAGE,
    groupsPage * GROUPS_PER_PAGE
  );
  const totalMachinePages = Math.max(
    1,
    Math.ceil(filteredMachines.length / MACHINES_PER_PAGE)
  );
  const paginatedMachines = filteredMachines.slice(
    (machinesPage - 1) * MACHINES_PER_PAGE,
    machinesPage * MACHINES_PER_PAGE
  );

  useEffect(() => {
    if (groupsPage > totalGroupPages) {
      setGroupsPage(totalGroupPages);
    }
  }, [groupsPage, totalGroupPages]);

  useEffect(() => {
    if (machinesPage > totalMachinePages) {
      setMachinesPage(totalMachinePages);
    }
  }, [machinesPage, totalMachinePages]);

  const startEdit = (g) => {
    setSelectedGroupId(g._id);
    setIsCreatingGroupView(false);
    setEditName(g.name || "");
    setMachineQuery("");
    setMachinesPage(1);
  };

  const startCreate = () => {
    setSelectedGroupId(null);
    setIsCreatingGroupView(true);
    setEditName("");
    setMachineQuery("");
    setMachinesPage(1);
  };

  const cancelEdit = () => {
    setSelectedGroupId(null);
    setIsCreatingGroupView(false);
    setEditName("");
    setMachineQuery("");
    setMachinesPage(1);
  };

  const saveEdit = async () => {
    const trimmed = editName.trim();
    if (!trimmed) {
      return;
    }
    setSavingId(selectedGroupId || "__new__");
    try {
      if (!selectedGroupId) {
        const createdGroup = await onCreateGroup(trimmed);
        if (createdGroup?._id) {
          setSelectedGroupId(createdGroup._id);
          setIsCreatingGroupView(false);
          setEditName(createdGroup.name || trimmed);
        }
        return;
      }

      const ok = await onRenameGroup(selectedGroupId, trimmed);
      if (ok && selectedGroupId) {
        setEditName(trimmed);
      }
    } finally {
      setSavingId(null);
    }
  };

  const handleToggleMachineMembership = async (machineId, isAssigned) => {
    if (!selectedGroupId || membershipSavingMachineId) {
      return;
    }

    setMembershipSavingMachineId(machineId);
    try {
      if (isAssigned) {
        await onRemoveMachineFromGroup(machineId, selectedGroupId);
      } else {
        await onAddMachineToGroup(machineId, selectedGroupId);
      }
    } finally {
      setMembershipSavingMachineId(null);
    }
  };

  const handleDelete = async () => {
    if (!groupPendingDelete?._id) {
      return;
    }

    setDeletingId(groupPendingDelete._id);
    try {
      await onDeleteGroup(groupPendingDelete._id);
      setGroupPendingDelete(null);
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title={
        selectedGroup
          ? `Edit ${selectedGroup.name}`
          : isCreatingGroupView
            ? "Create group"
            : "Machine groups"
      }
      centered
      radius="md"
      size="md"
      overlayProps={{ blur: 3 }}
      classNames={modalClassNames}
      closeOnEscape={false}
    >
      <div
        className={`transition-all duration-150 ${
          groupPendingDelete ? "pointer-events-none scale-[0.985] blur-[2px] opacity-60" : ""
        }`}
      >
        <Stack spacing="xs">
        {selectedGroup || isCreatingGroupView ? (
          <>
            <div className="flex items-center justify-between gap-3">
              <Button
                type="button"
                variant="subtle"
                leftIcon={<IconArrowLeft size={14} />}
                onClick={cancelEdit}
                classNames={{
                  root: isDark
                    ? "!px-0 !text-zinc-400 hover:!bg-transparent hover:!text-zinc-200"
                    : "!px-0 !text-zinc-600 hover:!bg-transparent hover:!text-zinc-900",
                }}
                >
                  Back to groups
                </Button>
              {selectedGroup ? (
                <Button
                  type="button"
                  color="red"
                  variant="subtle"
                  leftIcon={<IconTrash size={14} />}
                onClick={() => setGroupPendingDelete(selectedGroup)}
                classNames={{
                  root: isDark
                    ? "!px-0 !text-red-700 hover:!bg-transparent hover:!text-red-600"
                    : "!px-0 !text-red-700 hover:!bg-transparent hover:!text-red-800",
                }}
              >
                  Delete group
                </Button>
              ) : <span />}
            </div>

            <div>
              <label htmlFor="edit-group-name" className={getLabelClassName(isDark)}>
                Group name
              </label>
              <Group spacing="xs" align="flex-end" noWrap>
                <TextInput
                  id="edit-group-name"
                  value={editName}
                  onChange={(e) => setEditName(e.currentTarget.value)}
                  classNames={{ input: getInputClassName(isDark) }}
                  className="flex-1 min-w-0"
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      saveEdit();
                    }
                  }}
                />
                <Button
                  type="button"
                  onClick={saveEdit}
                  loading={savingId === (selectedGroup?._id || "__new__")}
                  disabled={
                    !editName.trim() ||
                    (selectedGroup ? editName.trim() === (selectedGroup.name || "") : false)
                  }
                  classNames={{
                    root:
                      isDark
                        ? "!bg-blue-600 !text-blue-50 hover:!bg-blue-700 disabled:!border disabled:!border-zinc-700 disabled:!bg-zinc-900 disabled:!text-zinc-500 disabled:!opacity-100 shrink-0"
                        : "!bg-blue-600 !text-blue-50 hover:!bg-blue-700 disabled:!border disabled:!border-zinc-300 disabled:!bg-zinc-100 disabled:!text-zinc-500 disabled:!opacity-100 shrink-0",
                  }}
                >
                  {selectedGroup ? "Save" : "Create"}
                </Button>
              </Group>
            </div>

            <div>
              <label htmlFor="group-machine-search" className={getLabelClassName(isDark)}>
                Machines
              </label>
              <TextInput
                id="group-machine-search"
                placeholder="Search machines"
                value={machineQuery}
                onChange={(e) => {
                  setMachineQuery(e.currentTarget.value);
                  setMachinesPage(1);
                }}
                classNames={{ input: getInputClassName(isDark) }}
              />
            </div>

            <div
              className={`rounded-lg border ${
                isDark ? "border-zinc-700 divide-zinc-800" : "border-zinc-200 divide-zinc-200"
              } divide-y max-h-80 overflow-y-auto pr-1`}
              style={{ scrollbarGutter: "stable" }}
            >
              {!selectedGroup ? (
                <p className={`px-3 py-4 text-sm ${isDark ? "text-zinc-500" : "text-zinc-500"}`}>
                  Create the group first, then you can assign machines here.
                </p>
              ) : filteredMachines.length === 0 ? (
                <p className={`px-3 py-4 text-sm ${isDark ? "text-zinc-500" : "text-zinc-500"}`}>
                  No machines match this search.
                </p>
              ) : (
                paginatedMachines.map((machine) => {
                  const isAssigned = (machine.groupIds || []).includes(selectedGroup._id);
                  const isWorking = membershipSavingMachineId === machine.id;
                  const resolvedStatus =
                    machine.connectionStatus ||
                    (machine.enabled === false
                      ? "disabled"
                      : machine.isActive
                        ? "online"
                        : "offline");
                  const isDisabled = resolvedStatus === "disabled";
                  const isAuthRequired = resolvedStatus === "auth_required";
                  const isOnline = resolvedStatus === "online";

                  return (
                    <div
                      key={machine.id}
                      className={`flex items-center gap-3 px-3 py-2.5 ${
                        isDark ? "bg-zinc-900/50" : "bg-white"
                      }`}
                    >
                      <div className="min-w-0 flex-1">
                        <div className="grid min-w-0 grid-cols-[8px_minmax(0,1fr)] items-start gap-x-2">
                          <BsCircleFill
                            size={8}
                            className={`row-span-2 mt-1.5 ${
                              isOnline
                                ? "text-emerald-500"
                                : isDisabled
                                  ? "text-zinc-400"
                                  : isAuthRequired
                                    ? "text-amber-500"
                                    : "text-red-400"
                            }`}
                            aria-label={
                              isOnline
                                ? "Online"
                                : isDisabled
                                  ? "Disabled"
                                  : isAuthRequired
                                    ? "Auth required"
                                : "Offline"
                            }
                          />
                          <div
                            className={`truncate text-sm font-medium ${
                              isDark ? "text-zinc-100" : "text-zinc-900"
                            }`}
                          >
                            {machine.name || "Untitled machine"}
                          </div>
                          <div
                            className={`truncate text-xs ${
                              isDark ? "text-zinc-500" : "text-zinc-500"
                            }`}
                          >
                          {machine.hostname || "No hostname"}
                          </div>
                        </div>
                      </div>
                      <div className="flex shrink-0 flex-col items-end gap-2">
                        <Button
                          type="button"
                          size="xs"
                          variant="filled"
                          loading={isWorking}
                          onClick={() =>
                            handleToggleMachineMembership(machine.id, isAssigned)
                          }
                          classNames={{
                            root: isAssigned
                              ? isDark
                                ? "!min-w-[5.5rem] !justify-center !bg-red-800 !text-red-50 hover:!bg-red-700"
                                : "!min-w-[5.5rem] !justify-center !bg-red-200 !text-red-800 hover:!bg-red-300"
                              : isDark
                                ? "!min-w-[5.5rem] !justify-center !bg-blue-800 !text-blue-50 hover:!bg-blue-700"
                                : "!min-w-[5.5rem] !justify-center !bg-blue-200 !text-blue-800 hover:!bg-blue-300",
                          }}
                        >
                          {isAssigned ? "Remove" : "Add"}
                        </Button>
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {selectedGroup && filteredMachines.length > MACHINES_PER_PAGE ? (
              <div className="flex justify-end">
                <Pagination
                  value={machinesPage}
                  onChange={setMachinesPage}
                  total={totalMachinePages}
                  size="sm"
                  radius="md"
                  withEdges
                  siblings={1}
                  classNames={{
                    control:
                      "!border-zinc-300 !bg-white !text-zinc-700 hover:!bg-zinc-50 data-[active=true]:!border-blue-600 data-[active=true]:!bg-blue-600 data-[active=true]:!text-blue-50 dark:!border-zinc-700 dark:!bg-zinc-900 dark:!text-zinc-200 dark:hover:!bg-zinc-800 dark:data-[active=true]:!border-blue-500 dark:data-[active=true]:!bg-blue-600",
                  }}
                />
              </div>
            ) : null}

            <div className="flex justify-end">
              <Button
                type="button"
                variant="default"
                onClick={cancelEdit}
                classNames={{ root: btnSecondary }}
              >
                Done
              </Button>
            </div>
          </>
        ) : (
          <>
        <Text size="sm" className={isDark ? "!text-zinc-400" : "!text-zinc-600"}>
          Groups help organize machines. Deleting a group does not delete machines; they
          become ungrouped.
        </Text>

        <div className="flex items-center justify-between gap-3">
          <Text size="sm" className={isDark ? "!text-zinc-500" : "!text-zinc-500"}>
            Select a group to manage its machines.
          </Text>
          <Button
            type="button"
            onClick={startCreate}
            classNames={{
              root:
                "!bg-blue-600 !text-blue-50 hover:!bg-blue-700",
            }}
          >
            Create group
          </Button>
        </div>

        <TextInput
          placeholder="Search groups"
          value={groupQuery}
          onChange={(e) => {
            setGroupQuery(e.currentTarget.value);
            setGroupsPage(1);
          }}
          classNames={{ input: getInputClassName(isDark) }}
        />

        <div
          className={`rounded-lg border ${
            isDark ? "border-zinc-700 divide-zinc-800" : "border-zinc-200 divide-zinc-200"
          } divide-y max-h-80 overflow-y-auto pr-1`}
          style={{ scrollbarGutter: "stable" }}
        >
          {filteredGroups.length === 0 ? (
            <p className={`px-3 py-4 text-sm ${isDark ? "text-zinc-500" : "text-zinc-500"}`}>
              {groups.length === 0 ? "No groups yet. Create one above." : "No groups match this search."}
            </p>
          ) : (
            paginatedGroups.map((g) => (
              <button
                key={g._id}
                type="button"
                onClick={() => startEdit(g)}
                className={`flex w-full items-center justify-between gap-3 px-3 py-3 text-left transition ${
                  isDark
                    ? "bg-transparent hover:bg-zinc-800/50"
                    : "bg-transparent hover:bg-zinc-50"
                }`}
              >
                <span className="flex min-w-0 items-center gap-2 truncate">
                  <span
                    className={`inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md ${
                      isDark ? "bg-zinc-800/80 text-zinc-300" : "bg-zinc-100 text-zinc-500"
                    }`}
                  >
                    <IconFolder size={15} />
                  </span>
                  <span
                    className={`truncate text-sm font-medium ${
                      isDark ? "text-zinc-100" : "text-zinc-900"
                    }`}
                  >
                    {g.name}
                  </span>
                </span>
                <span className="flex shrink-0 items-center gap-1.5 text-xs text-zinc-500">
                  <IconUsers size={13} />
                  <span>{groupMachineCountById[g._id] || 0} Peer(s)</span>
                </span>
              </button>
            ))
          )}
        </div>

        {filteredGroups.length > GROUPS_PER_PAGE ? (
          <div className="flex justify-end">
            <Pagination
              value={groupsPage}
              onChange={setGroupsPage}
              total={totalGroupPages}
              size="sm"
              radius="md"
              withEdges
              siblings={1}
              classNames={{
                control:
                  "!border-zinc-300 !bg-white !text-zinc-700 hover:!bg-zinc-50 data-[active=true]:!border-blue-600 data-[active=true]:!bg-blue-600 data-[active=true]:!text-blue-50 dark:!border-zinc-700 dark:!bg-zinc-900 dark:!text-zinc-200 dark:hover:!bg-zinc-800 dark:data-[active=true]:!border-blue-500 dark:data-[active=true]:!bg-blue-600",
              }}
            />
          </div>
        ) : null}

        <div className="flex justify-end">
          <Button
            type="button"
            variant="default"
            onClick={onClose}
            classNames={{ root: btnSecondary }}
          >
            Close
          </Button>
        </div>
          </>
        )}
        </Stack>
      </div>

      <Modal
        opened={Boolean(groupPendingDelete)}
        onClose={() => {
          if (!deletingId) {
            setGroupPendingDelete(null);
          }
        }}
        closeOnClickOutside={!deletingId}
        closeOnEscape={!deletingId}
        title="Delete group"
        centered
        radius="md"
        size="sm"
        overlayProps={{ blur: 3 }}
        classNames={modalClassNames}
        withinPortal
      >
        {groupPendingDelete ? (
          <Stack spacing="md">
            <Text size="sm" className={isDark ? "!text-zinc-300" : "!text-zinc-700"}>
              Delete{" "}
              <span className="font-semibold text-zinc-900 dark:text-zinc-100">
                {groupPendingDelete.name}
              </span>
              ?
            </Text>
            <Text size="sm" className={isDark ? "!text-zinc-400" : "!text-zinc-600"}>
              This deletes only the group. Machines inside it are not deleted, but they
              will become ungrouped.
            </Text>
            <div className="flex justify-end gap-2">
              <Button
                type="button"
                variant="default"
                disabled={Boolean(deletingId)}
                onClick={() => setGroupPendingDelete(null)}
                classNames={{ root: btnSecondary }}
              >
                Cancel
              </Button>
              <Button
                type="button"
                color="red"
                loading={Boolean(deletingId)}
                onClick={handleDelete}
                classNames={{
                  root:
                    "!bg-red-600 !text-red-50 hover:!bg-red-700 disabled:!bg-red-400",
                }}
              >
                Delete group
              </Button>
            </div>
          </Stack>
        ) : null}
      </Modal>
    </Modal>
  );
}
