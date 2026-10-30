import InventoryMultiSelect from "@/components/ui/inventory-multi-select";
import { useState } from "react";
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

export function MultiEntities({label,value,onChange,disabled,params}) {
  return <label className="block text-sm font-medium">{label}<InventoryMultiSelect className="mt-2" kind="access-entities" label={label} filters={params} disabled={disabled} value={value.map(key)} onChange={values=>onChange(values.map(selector))} extraOptions={[{value:"all:machines",label:"All machines"}]} placeholder="Search machines, people or groups…"/></label>;
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
