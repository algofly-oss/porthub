import { useEffect, useState } from "react";
import {
  Button,
  Modal,
  Stack,
  Text,
  TextInput,
  ActionIcon,
  Group,
} from "@mantine/core";
import { useMantineColorScheme } from "@mantine/core";
import { IconTrash, IconPencil, IconCheck, IconX } from "@tabler/icons-react";

const getInputClassName = (isDark) =>
  `w-full rounded-md border px-3 py-2 text-sm outline-none transition-colors focus:!border-blue-500 focus:ring-0 ${
    isDark
      ? "!border-zinc-600 !bg-zinc-800 !text-zinc-100 placeholder:!text-zinc-500"
      : "!border-zinc-300 !bg-zinc-50 !text-zinc-900 placeholder:!text-zinc-400"
  }`;

const getLabelClassName = (isDark) =>
  `mb-1.5 block text-sm font-semibold ${isDark ? "text-zinc-100" : "text-zinc-900"}`;

export default function MachineGroupsModal({
  opened,
  onClose,
  groups,
  onCreateGroup,
  onRenameGroup,
  onDeleteGroup,
}) {
  const { colorScheme } = useMantineColorScheme();
  const isDark = colorScheme === "dark";
  const [newName, setNewName] = useState("");
  const [creating, setCreating] = useState(false);
  const [editingId, setEditingId] = useState(null);
  const [editName, setEditName] = useState("");
  const [savingId, setSavingId] = useState(null);
  const [deletingId, setDeletingId] = useState(null);

  useEffect(() => {
    if (!opened) {
      setNewName("");
      setEditingId(null);
      setEditName("");
    }
  }, [opened]);

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

  const handleCreate = async () => {
    const trimmed = newName.trim();
    if (!trimmed) {
      return;
    }
    setCreating(true);
    try {
      const ok = await onCreateGroup(trimmed);
      if (ok) {
        setNewName("");
      }
    } finally {
      setCreating(false);
    }
  };

  const startEdit = (g) => {
    setEditingId(g._id);
    setEditName(g.name || "");
  };

  const cancelEdit = () => {
    setEditingId(null);
    setEditName("");
  };

  const saveEdit = async () => {
    const trimmed = editName.trim();
    if (!trimmed || !editingId) {
      return;
    }
    setSavingId(editingId);
    try {
      const ok = await onRenameGroup(editingId, trimmed);
      if (ok) {
        cancelEdit();
      }
    } finally {
      setSavingId(null);
    }
  };

  const handleDelete = async (id) => {
    setDeletingId(id);
    try {
      await onDeleteGroup(id);
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title="Machine groups"
      centered
      radius="md"
      size="md"
      overlayProps={{ blur: 3 }}
      classNames={modalClassNames}
    >
      <Stack spacing="md">
        <Text size="sm" className={isDark ? "!text-zinc-400" : "!text-zinc-600"}>
          Groups help organize machines. Deleting a group does not delete machines; they
          become ungrouped.
        </Text>

        <div>
          <label htmlFor="new-group-name" className={getLabelClassName(isDark)}>
            New group
          </label>
          <Group spacing="xs" align="flex-end" noWrap>
            <TextInput
              id="new-group-name"
              placeholder="e.g. Production"
              value={newName}
              onChange={(e) => setNewName(e.currentTarget.value)}
              classNames={{
                input: getInputClassName(isDark),
              }}
              className="flex-1 min-w-0"
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  handleCreate();
                }
              }}
            />
            <Button
              type="button"
              onClick={handleCreate}
              loading={creating}
              disabled={!newName.trim()}
              classNames={{
                root:
                  "!bg-blue-600 !text-blue-50 hover:!bg-blue-700 disabled:!bg-blue-400 shrink-0",
              }}
            >
              Add
            </Button>
          </Group>
        </div>

        <div
          className={`rounded-lg border ${
            isDark ? "border-zinc-700 divide-zinc-800" : "border-zinc-200 divide-zinc-200"
          } divide-y max-h-64 overflow-y-auto`}
        >
          {groups.length === 0 ? (
            <p className={`px-3 py-4 text-sm ${isDark ? "text-zinc-500" : "text-zinc-500"}`}>
              No groups yet. Create one above.
            </p>
          ) : (
            groups.map((g) => (
              <div
                key={g._id}
                className={`flex items-center gap-2 px-3 py-2.5 ${
                  isDark ? "bg-zinc-900/50" : "bg-white"
                }`}
              >
                {editingId === g._id ? (
                  <>
                    <TextInput
                      value={editName}
                      onChange={(e) => setEditName(e.currentTarget.value)}
                      classNames={{ input: getInputClassName(isDark) }}
                      className="flex-1 min-w-0"
                      size="xs"
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          saveEdit();
                        }
                        if (e.key === "Escape") {
                          cancelEdit();
                        }
                      }}
                    />
                    <ActionIcon
                      type="button"
                      variant="subtle"
                      color="green"
                      onClick={saveEdit}
                      loading={savingId === g._id}
                      aria-label="Save name"
                    >
                      <IconCheck size={16} />
                    </ActionIcon>
                    <ActionIcon
                      type="button"
                      variant="subtle"
                      onClick={cancelEdit}
                      aria-label="Cancel edit"
                    >
                      <IconX size={16} />
                    </ActionIcon>
                  </>
                ) : (
                  <>
                    <span
                      className={`flex-1 min-w-0 truncate text-sm font-medium ${
                        isDark ? "text-zinc-100" : "text-zinc-900"
                      }`}
                    >
                      {g.name}
                    </span>
                    <ActionIcon
                      type="button"
                      variant="subtle"
                      onClick={() => startEdit(g)}
                      aria-label={`Rename ${g.name}`}
                      className={isDark ? "!text-zinc-400" : "!text-zinc-600"}
                    >
                      <IconPencil size={16} />
                    </ActionIcon>
                    <ActionIcon
                      type="button"
                      variant="subtle"
                      color="red"
                      onClick={() => handleDelete(g._id)}
                      loading={deletingId === g._id}
                      aria-label={`Delete ${g.name}`}
                    >
                      <IconTrash size={16} />
                    </ActionIcon>
                  </>
                )}
              </div>
            ))
          )}
        </div>

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
      </Stack>
    </Modal>
  );
}
