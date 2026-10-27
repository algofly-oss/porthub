import { IconCopy } from "@tabler/icons-react";
import useToast from "@/shared/hooks/useToast";
import { useEffect, useState } from "react";
import axios from "axios";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import SearchSelect from "@/components/ui/search-select";

function CurlExample({ title, command }) {
  const toast = useToast();
  const copy = async () => {
    try { await navigator.clipboard.writeText(command); toast.success("Command copied"); }
    catch { toast.error("Could not copy. Select the command to copy it."); }
  };
  return <div className="space-y-2"><p className="text-xs font-medium">{title}</p><div className="flex items-start gap-2 rounded-lg bg-control p-3"><code className="min-w-0 flex-1 whitespace-pre-wrap break-all text-xs leading-5">{command}</code><Button type="button" variant="ghost" size="icon" aria-label={`Copy ${title}`} onClick={copy}><IconCopy size={15} /></Button></div></div>;
}

export default function PublicAccessLock({ id, initialMode = "off", temporary, onSaved }) {
  const [mode, setMode] = useState(initialMode);
  const [saved, setSaved] = useState(initialMode);
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  useEffect(() => { setMode(initialMode); setSaved(initialMode); setSecret(""); setError(""); setMessage(""); }, [id, initialMode]);
  const save = async () => {
    setBusy(true); setError(""); setMessage("");
    try {
      await axios.put(`${process.env.API_PREFIX || "/api"}/connections/access/${id}`, { mode, ...(secret ? { secret } : {}) });
      setSaved(mode); setSecret(""); onSaved?.(mode); setMessage("Access lock saved.");
    } catch (error) {
      setError(typeof error.response?.data?.detail === "string" ? error.response.data.detail : "Could not save the access lock.");
    } finally { setBusy(false); }
  };
  return <section className="space-y-3 rounded-lg bg-surface p-4">
    <div><h3 className="text-sm font-medium">Public access lock</h3><p className="mt-1 text-xs leading-5 text-muted-foreground">Protect this HTTP service on both its public port and proxy address. HTTPS proxy addresses are supported. This setting is not for SSH, databases, or TLS passthrough.</p></div>
    {!id ? <p className="text-sm text-muted-foreground">Save the port mapping first to configure an access lock.</p> : temporary ? <p className="text-sm text-muted-foreground">Temporary mappings are managed by the agent.</p> : <>
      <SearchSelect label="Public access lock" value={mode} onChange={value => { setMode(value); setSecret(""); setMessage(""); }} options={[{value:"off",label:"Off"},{value:"pin",label:"Six-digit PIN"},{value:"key",label:"API key"}]} />
      {mode !== "off" && <div><label className="mb-2 block text-sm" htmlFor={`public-key-${id}`}>{mode === "pin" ? "PIN" : "API key"}</label><Input id={`public-key-${id}`} type="password" autoComplete="new-password" inputMode={mode === "pin" ? "numeric" : "text"} maxLength={mode === "pin" ? 6 : 72} value={secret} onChange={event => setSecret(event.target.value)} placeholder={saved === mode ? "Leave blank to keep the current value" : mode === "pin" ? "Enter six digits" : "Enter 16–72 characters"} /><p className="mt-2 text-xs text-muted-foreground">Browser visitors sign in at the service. For scripts, use X-PortHub-Key. This leaves your application’s Authorization header unchanged.</p></div>}
      {mode !== "off" && <details className="rounded-lg border border-border p-3"><summary className="cursor-pointer text-sm font-medium">Access with curl</summary><div className="mt-3 space-y-4">
        <p className="text-xs leading-5 text-muted-foreground">Replace YOUR_PORTHUB_KEY with the configured {mode === "pin" ? "six-digit PIN" : "API key"} and YOUR_SERVICE with the public address, including its port if needed. These examples work with both the direct port and proxy URL.</p>
        <CurlExample title="PortHub access" command={`curl -H 'X-PortHub-Key: YOUR_PORTHUB_KEY' 'https://YOUR_SERVICE/'`} />
        <CurlExample title="Application also requires a Bearer token" command={`curl -H 'X-PortHub-Key: YOUR_PORTHUB_KEY' -H 'Authorization: Bearer YOUR_APP_TOKEN' 'https://YOUR_SERVICE/'`} />
        <CurlExample title="Bearer alternative for PortHub only" command={`curl -H 'Authorization: Bearer YOUR_PORTHUB_KEY' 'https://YOUR_SERVICE/'`} />
        <p className="text-xs leading-5 text-muted-foreground">Use the Bearer alternative only when the application does not need that header. PortHub removes credentials used to unlock its gate before forwarding. With X-PortHub-Key, the application’s Authorization header passes through unchanged. Use http:// if that is how your direct endpoint is served.</p>
      </div></details>}
      {error && <p role="alert" className="text-sm text-red-500">{error}</p>}{message && <p role="status" className="text-sm text-muted-foreground">{message}</p>}
      <Button type="button" variant="secondary" disabled={busy || (mode === saved && !secret) || (mode !== "off" && mode !== saved && !secret)} onClick={save}>{busy ? "Saving…" : "Save access lock"}</Button>
    </>}
  </section>;
}
