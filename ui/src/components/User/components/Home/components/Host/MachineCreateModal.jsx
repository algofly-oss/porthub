import { useEffect, useState } from "react";
import { Button, Modal, Select, Stack, Text } from "@mantine/core";
import { useMantineColorScheme } from "@mantine/core";

const getInputClassName = (isDark) =>
  `w-full rounded-md border px-3 py-2 text-sm outline-none transition-colors focus:!border-blue-500 focus:ring-0 ${
    isDark
      ? "!border-zinc-600 !bg-zinc-800 !text-zinc-100 placeholder:!text-zinc-500"
      : "!border-zinc-300 !bg-zinc-50 !text-zinc-900 placeholder:!text-zinc-400"
  }`;

const getLabelClassName = (isDark) =>
  `mb-1.5 block text-sm font-semibold ${isDark ? "text-zinc-100" : "text-zinc-900"}`;

const errorClassName = "mt-1 text-xs text-red-600 dark:text-red-400";

const initialForm = {
  name: "",
  hostname: "",
  groupId: "",
};

export default function MachineCreateModal({
  opened,
  onClose,
  onCreate,
  isCreating,
  groups = [],
}) {
  const { colorScheme } = useMantineColorScheme();
  const isDark = colorScheme === "dark";
  const [form, setForm] = useState(initialForm);
  const [errors, setErrors] = useState({});

  useEffect(() => {
    if (!opened) {
      setForm(initialForm);
      setErrors({});
    }
  }, [opened]);

  const handleSubmit = async (event) => {
    event.preventDefault();
    const nextErrors = {};

    if (!form.name.trim()) {
      nextErrors.name = "Machine name is required";
    }

    if (Object.keys(nextErrors).length > 0) {
      setErrors(nextErrors);
      return;
    }

    const created = await onCreate({
      name: form.name.trim(),
      hostname: form.hostname.trim(),
      group_ids: form.groupId ? [form.groupId] : [],
    });

    if (created) {
      setForm(initialForm);
      setErrors({});
    }
  };

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

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title="Create machine"
      centered
      radius="md"
      size="md"
      overlayProps={{ blur: 3 }}
      classNames={modalClassNames}
      closeOnClickOutside={!isCreating}
    >
      <form onSubmit={handleSubmit}>
        <Stack spacing="md">
          <Text size="sm" className={isDark ? "!text-zinc-400" : "!text-zinc-600"}>
            Create a machine record now. The client will publish its local and public
            IPs automatically after it connects.
          </Text>

          <div>
            <label htmlFor="machine-name" className={getLabelClassName(isDark)}>
              Machine name
            </label>
            <input
              id="machine-name"
              type="text"
              placeholder="edge-node-1"
              className={getInputClassName(isDark)}
              value={form.name}
              onChange={(event) =>
                setForm((current) => ({ ...current, name: event.currentTarget.value }))
              }
            />
            {errors.name && <p className={errorClassName}>{errors.name}</p>}
          </div>

          <div>
            <label htmlFor="machine-hostname" className={getLabelClassName(isDark)}>
              Hostname
            </label>
            <input
              id="machine-hostname"
              type="text"
              placeholder="edge-node-1.local"
              className={getInputClassName(isDark)}
              value={form.hostname}
              onChange={(event) =>
                setForm((current) => ({
                  ...current,
                  hostname: event.currentTarget.value,
                }))
              }
            />
          </div>

          {groups.length > 0 ? (
            <div>
              <label htmlFor="machine-group" className={getLabelClassName(isDark)}>
                Group (optional)
              </label>
              <Select
                id="machine-group"
                placeholder="Ungrouped"
                clearable
                data={groups.map((g) => ({ value: g._id, label: g.name }))}
                value={form.groupId || null}
                onChange={(value) =>
                  setForm((current) => ({ ...current, groupId: value || "" }))
                }
                classNames={{
                  input: getInputClassName(isDark),
                  dropdown: isDark
                    ? "!border-zinc-700 !bg-zinc-900"
                    : "!border-zinc-200 !bg-white",
                  item: isDark
                    ? "!text-zinc-100 hover:!bg-zinc-800"
                    : "!text-zinc-900 hover:!bg-zinc-100",
                }}
              />
            </div>
          ) : null}

          <div className="flex justify-end gap-3">
            <Button
              type="button"
              variant="default"
              onClick={onClose}
              disabled={isCreating}
              classNames={{ root: btnSecondary }}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              loading={isCreating}
              classNames={{
                root:
                  "!bg-blue-600 !text-blue-50 hover:!bg-blue-700 disabled:!bg-blue-400",
              }}
            >
              Create machine
            </Button>
          </div>
        </Stack>
      </form>
    </Modal>
  );
}
