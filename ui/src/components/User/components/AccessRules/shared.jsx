import { useState } from "react";
import { MultiSelect } from "@mantine/core";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";

export const API = "/api/access";
export const id = () =>
  globalThis.crypto?.randomUUID?.() ||
  `rule-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
export const blankRule = () => ({
  id: id(),
  name: "",
  sources: [],
  destinations: [],
  protocol: "tcp",
  ports: "",
  bidirectional: false,
  enabled: true,
});
export const message = (error) => error?.response?.data?.detail;
export const errorText = (error) =>
  typeof message(error) === "string"
    ? message(error)
    : Array.isArray(message(error))
      ? message(error)
          .map((item) => item.msg)
          .join(". ")
      : "Could not save changes. Please try again.";
export const key = (selector) => `${selector.kind}:${selector.id}`;
export const selector = (value) => ({
  kind: value.split(":")[0],
  id: value.slice(value.indexOf(":") + 1),
});

export function MultiEntities({ label, value, onChange, options, disabled }) {
  const [opened, setOpened] = useState(false);
  return (
    <label className="block text-sm font-medium">
      {label}
      <MultiSelect
        aria-label={label}
        className="mt-2"
        searchable
        onDropdownOpen={() => setOpened(true)}
        onDropdownClose={() => setOpened(false)}
        onKeyDown={(event) => {
          if (event.key === "Escape" && opened) event.stopPropagation();
        }}
        clearable
        disabled={disabled}
        value={value.map(key)}
        onChange={(values) => onChange(values.map(selector))}
        data={options}
        placeholder="Search machines, people or groups…"
        nothingFound="No matching entities"
        withinPortal
        zIndex={400}
        maxDropdownHeight={210}
        dropdownPosition="flip"
        classNames={{
          input:
            "!min-h-[40px] !rounded-lg !border-transparent !bg-control !text-foreground",
          searchInput:
            "!border-0 !bg-transparent !text-foreground !shadow-none !outline-none",
          dropdown: "!rounded-lg !border-border !bg-dialog !p-1",
          item: "!cursor-pointer !rounded-md !text-sm !text-foreground data-[hovered]:!bg-accent data-[selected]:!bg-primary/10",
          value: "!bg-surface !text-foreground",
          values: "max-h-20 overflow-auto",
        }}
      />
    </label>
  );
}

export function DirtyGuard({ dirty, busy, onClose, children }) {
  const [confirm, setConfirm] = useState(false);
  const close = () => {
    if (busy) return;
    if (dirty) setConfirm(true);
    else onClose();
  };
  return (
    <>
      {children(close)}
      <Dialog
        opened={confirm}
        onClose={() => setConfirm(false)}
        zIndex={450}
        title="Discard unsaved changes?"
      >
        <p className="text-sm leading-6 text-muted-foreground">
          Your saved policies will stay unchanged.
        </p>
        <div className="mt-5 flex justify-end gap-2">
          <Button variant="ghost" onClick={() => setConfirm(false)}>
            Keep Editing
          </Button>
          <Button variant="destructive" onClick={onClose}>
            Discard Changes
          </Button>
        </div>
      </Dialog>
    </>
  );
}
