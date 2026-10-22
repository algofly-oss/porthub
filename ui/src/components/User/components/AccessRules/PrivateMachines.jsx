import { useState } from "react";
import axios from "axios";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import useToast from "@/shared/hooks/useToast";
import { API, errorText } from "./shared";

// Private names default to the registered machine name and follow renames.
// A custom name may not reuse another machine's name; the API enforces it.
function status(peer) {
  if (!peer.installed) return ["Not installed", "text-muted-foreground"];
  if (!peer.enabled) return ["Disabled", "text-muted-foreground"];
  if (!peer.online) return ["Offline", "text-muted-foreground"];
  if (peer.paths.includes("direct")) return ["Online · direct", "text-emerald-700 dark:text-emerald-400"];
  if (peer.paths.includes("relay")) return ["Online · relayed", "text-amber-700 dark:text-amber-400"];
  return ["Online", "text-emerald-700 dark:text-emerald-400"];
}

function Row({ peer, suffix, editable, params, onSaved }) {
  const [value, setValue] = useState(peer.hostname),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const toast = useToast();
  const [label, tone] = status(peer);
  async function save(hostname) {
    setBusy(true);
    setError("");
    try {
      const response = await axios.put(`${API}/private/peers/${encodeURIComponent(peer._id)}/hostname`, { hostname }, { params });
      setValue(response.data.hostname);
      await onSaved();
      toast.success(`${peer.machine_name} is now ${response.data.hostname}.${suffix}`);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  const dirty = value.trim().toLowerCase() !== peer.hostname;
  return (
    <div className="border-b border-border/60 px-3 py-3 last:border-0 sm:px-4">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <div className="min-w-0 flex-1 basis-40">
          <p className="truncate text-sm font-medium">{peer.machine_name || "Deleted machine"}</p>
          <p className="mt-0.5 font-mono text-xs text-muted-foreground">{peer.ip}</p>
        </div>
        <form
          className="flex min-w-0 basis-64 items-center gap-2 sm:flex-none"
          onSubmit={(event) => { event.preventDefault(); if (dirty) save(value); }}
        >
          <div className="flex min-w-0 flex-1 items-center rounded-lg bg-control pr-2">
            <Input
              aria-label={`Private name for ${peer.machine_name}`}
              className="min-w-0 border-0 bg-transparent font-mono text-[13px]"
              value={value}
              disabled={!editable || busy}
              onChange={(event) => setValue(event.target.value)}
            />
            <span className="shrink-0 font-mono text-[13px] text-muted-foreground">.{suffix}</span>
          </div>
          {editable && dirty && <Button type="submit" size="sm" disabled={busy}>Save</Button>}
          {editable && !dirty && peer.custom_hostname && (
            <Button type="button" variant="ghost" size="sm" disabled={busy} onClick={() => save("")} aria-label={`Reset private name for ${peer.machine_name}`} title="Use the registered machine name">Reset</Button>
          )}
        </form>
        <span className={`w-28 shrink-0 text-xs ${tone}`}>{label}</span>
      </div>
      {error && <p role="alert" className="mt-2 text-xs text-red-500">{error}</p>}
    </div>
  );
}

export default function PrivateMachines({ data, manage, params, onSaved }) {
  const peers = data.private_peers || [];
  return (
    <section aria-label="Private machines" className="mb-3 rounded-xl bg-surface">
      <div className="px-3 pb-2 pt-4 sm:px-4">
        <h2 className="text-base font-semibold">Private Machines</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Names follow each machine&apos;s registered name unless you set one. A name already used by another machine is not allowed.
        </p>
      </div>
      {peers.length ? (
        peers.map((peer) => (
          <Row key={`${peer._id}:${peer.hostname}`} peer={peer} suffix={data.network.dns_suffix} editable={manage} params={params} onSaved={onSaved} />
        ))
      ) : (
        <p className="px-3 pb-4 text-sm text-muted-foreground sm:px-4">No machines have joined the private network yet.</p>
      )}
    </section>
  );
}
