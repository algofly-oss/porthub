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
      await axios.put(`${API}/network`, form, { params });
      await onSaved();
      toast.success("Network preferences saved. No machine routes changed.");
    } catch (error) {
      setError(errorText(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="data-scroll rounded-xl bg-surface p-4 sm:p-6">
      <h2 className="text-base font-semibold">Private Network Preferences</h2>
      <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
        Prepare addressing and names. Activation remains unavailable until the
        compiled agent and transport pass isolation and coexistence tests.
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
            Suggested range only. Client-side conflict checks are required
            before any routes can be installed.
          </span>
        </label>
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
            Example: luna.{form.dns_suffix || "ph.io"}. Only exact registered
            names resolve privately. Unknown names keep normal DNS; known
            offline names never fall back publicly.
          </span>
        </label>
        <div className="rounded-lg bg-control p-4 text-sm leading-6 text-muted-foreground">
          <p className="font-medium text-foreground">
            Coexistence is a requirement
          </p>
          <p className="mt-1">
            No default-route changes. No whole-network DNS takeover. No
            automatic overlay activation during a client update. Publicly
            trusted certificates for private names require a separate
            certificate strategy.
          </p>
        </div>
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
