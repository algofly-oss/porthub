import { useState } from "react";
import axios from "axios";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import useToast from "@/shared/hooks/useToast";
import { API, errorText } from "./shared";

export default function NetworkSettings({ data, manage, params, onSaved }) {
  const [form, setForm] = useState(data.network),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const toast = useToast();
  async function save(event) {
    event.preventDefault();
    setBusy(true);
    try {
      await axios.put(`${API}/network`, { cidr: form.cidr, dns_suffix: form.dns_suffix }, { params });
      await onSaved();
      toast.success("Network preferences saved. No machine routes changed.");
    } catch (error) {
      setError(errorText(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="rounded-xl bg-surface p-4 sm:p-6">
      <h2 className="text-base font-semibold">Private Network Preferences</h2>
      <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
        Addressing and names for this workspace. Every workspace has its own
        suffix; machines follow the workspace they joined. Address pools grow
        automatically as machines join, while existing addresses and communication rules stay in place.
      </p>
      <form onSubmit={save} className="mt-6 max-w-xl space-y-5">
        <label className="block text-sm font-medium">
          Private IPv4 range
          <Input
            className="mt-2 font-mono"
            aria-label="Private IPv4 range"
            value={form.cidr}
            onChange={(event) =>
              setForm((old) => ({ ...old, cidr: event.target.value }))
            }
            disabled={!manage}
          />
          <span className="mt-2 block text-xs font-normal leading-5 text-muted-foreground">
            PortHub expands this range when needed. If a neighbouring range is
            reserved, it adds another pool to the same private network.
          </span>
        </label>
        {data.network.auto_expand && (
          <div className="rounded-lg bg-control p-3 text-xs leading-5 text-muted-foreground">
            <p className="font-medium text-foreground">Automatic address allocation</p>
            <p>{Number(data.network.address_capacity || 0).toLocaleString()} addresses across the current pools.</p>
            <p className="mt-1 break-words font-mono">{(data.network.cidrs || [data.network.cidr]).join(", ")}</p>
            <p className="mt-1">Machines in different pools can communicate when your rules allow it.</p>
          </div>
        )}
        <label className="block text-sm font-medium">
          Private DNS suffix
          <Input
            className="mt-2 font-mono"
            aria-label="Private DNS suffix"
            value={form.dns_suffix}
            onChange={(event) =>
              setForm((old) => ({ ...old, dns_suffix: event.target.value }))
            }
            disabled={!manage}
          />
          <span className="mt-2 block text-xs font-normal leading-5 text-muted-foreground">
            Example: luna.{form.dns_suffix || "phub"}. Only names under this
            suffix are answered privately; every other name keeps the
            machine&apos;s normal DNS.
          </span>
        </label>
        {error && (
          <p role="alert" className="text-sm text-red-500">
            {error}
          </p>
        )}
        {manage && (
          <Button type="submit" disabled={busy}>
            {busy ? "Saving…" : "Save Preferences"}
          </Button>
        )}
      </form>
    </section>
  );
}
