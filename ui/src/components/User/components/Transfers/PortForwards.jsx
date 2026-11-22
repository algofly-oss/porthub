import { useEffect, useRef, useState } from "react";
import { IconChevronDown, IconCopy, IconPlus, IconServer, IconPlugConnected, IconTerminal2, IconTrash } from "@tabler/icons-react";
import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { copyText } from "@/shared/utils/clipboard";
import {
  expandPortRange,
  forwardCommand,
  downloadForwardProfile,
  forwardProfileCommand,
} from "@/shared/transfers/port-forwards.mjs";
import toast from "react-hot-toast";
import { useDemo } from "@/shared/demo/DemoProvider";
import uiRoutes from "@/shared/routes/uiRoutes";
import ResultsPagination from "@/components/ui/results-pagination";
import SearchDropdown from "@/components/ui/search-dropdown";
import SearchMultiSelect from "@/components/ui/search-multi-select";

const api = "/api/port-forwards";
const field =
  "mt-1 block h-11 w-full min-w-0 rounded-lg border border-input bg-background px-3 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary";
const label = "block min-w-0 text-sm font-medium";
const directionNames = {
  remote: "Share a port from this computer",
  local: "Access a PortHub machine",
};
const emptyMapping = () => ({
  direction: "remote",
  ports: "22",
  service: "22",
  machine: "",
});

async function request(suffix = "", method = "GET", body, signal) {
  const response = await fetch(api + suffix, {
    method,
    signal,
    credentials: "same-origin",
    cache: "no-store",
    ...(body && {
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  });
  if (response.status === 204) return;
  const data = await response.json().catch(() => ({}));
  if (!response.ok)
    throw new Error(
      typeof data.detail === "string"
        ? data.detail
        : "Could not reach the forwarding service.",
    );
  return data;
}

function Commands({ credentials, profileName }) {
  const [downloadError, setDownloadError] = useState("");
  const [client, setClient] = useState(() =>
    navigator.userAgent.includes("Windows") ? "powershell" : "openssh",
  );
  const [draft, setDraft] = useState(null);
  let generated, problem;
  try {
    generated = forwardCommand(credentials, client);
  } catch (err) {
    problem = err.message;
  }
  const command = draft ?? generated ?? "";
  const downloadKey = () => {
    const url = URL.createObjectURL(
      new Blob([credentials.privateKey], { type: "application/octet-stream" }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = credentials.username;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return (
    <div className="mt-3 space-y-3 rounded-lg border border-border bg-background p-3">
      <p className="text-xs text-muted-foreground">
        Download and extract the SSH profile into a private folder, then run
        this command from that folder.
      </p>
      <div>
        <p className={label}>SSH command</p>
        <pre
          aria-label="SSH command"
          tabIndex={0}
          className="mt-1 min-w-0 select-text whitespace-pre-wrap break-words rounded-lg border border-input bg-background px-3 py-3 font-mono text-xs leading-5 text-foreground focus-visible:outline-primary"
        >
          {forwardProfileCommand}
        </pre>
      </div>
      <div className="flex flex-wrap gap-2">
        <Button
          size="sm"
          onClick={async () => {
            try {
              await downloadForwardProfile(credentials, profileName);
              setDownloadError("");
            } catch (error) {
              setDownloadError(error.message);
            }
          }}
        >
          Download SSH profile
        </Button>
        <Button
          size="sm"
          variant="outline"
          onClick={async () => {
            try {
              await copyText(forwardProfileCommand);
              toast.success("SSH command copied");
            } catch {
              toast.error("Select and copy the command above.");
            }
          }}
        >
          <IconCopy size={16} />
          Copy command
        </Button>
      </div>
      {downloadError && (
        <p role="alert" className="text-sm text-red-600 dark:text-red-400">
          {downloadError}
        </p>
      )}
      <details>
        <summary className="cursor-pointer py-2 text-sm text-muted-foreground">
          Advanced: self-contained command
        </summary>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <label className={label}>
            Command for
            <SearchDropdown
              className={field}
              value={client}
              onChange={(e) => {
                setClient(e.target.value);
                setDraft(null);
              }}
            >
              <option value="openssh">Linux / macOS · OpenSSH</option>
              <option value="powershell">Windows · PowerShell / OpenSSH</option>
            </SearchDropdown>
          </label>
        </div>
        {problem ? (
          <p role="alert">{problem}</p>
        ) : (
          <>
            <label className={label}>
              Self-contained SSH command
              <textarea
                className="mt-1 block min-h-[7rem] w-full resize-y rounded-lg border border-input bg-surface p-3 font-mono text-xs leading-5 focus-visible:outline-primary"
                aria-label="Self-contained SSH command"
                spellCheck={false}
                value={command}
                onChange={(e) => setDraft(e.target.value)}
              />
            </label>
            <p className="text-xs text-muted-foreground">
              Paste into a terminal on the computer sharing or receiving the
              port. Keep it running. This command contains the private key for
              this forward.
            </p>
            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                disabled={!command.trim()}
                onClick={async () => {
                  try {
                    await copyText(command);
                    toast.success("SSH command copied");
                  } catch {
                    toast.error("Select and copy the command above.");
                  }
                }}
              >
                <IconCopy size={16} />
                Copy self-contained command
              </Button>
              {draft !== null && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setDraft(null)}
                >
                  Reset edits
                </Button>
              )}
            </div>
          </>
        )}
      </details>
      <details className="text-sm">
        <summary className="cursor-pointer text-muted-foreground">
          Credentials for another SSH client
        </summary>
        <dl className="my-3 grid gap-2 text-xs sm:grid-cols-[max-content_1fr]">
          {[
            ["Gateway", credentials.gateway],
            ["SSH port", credentials.sshPort],
            ["Username", credentials.username],
            ["Server fingerprint", credentials.fingerprint],
          ].map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-muted-foreground">{k}</dt>
              <dd className="break-all font-mono">{v}</dd>
            </div>
          ))}
        </dl>
        <Button variant="outline" size="sm" onClick={downloadKey}>
          Download OpenSSH key
        </Button>
      </details>
    </div>
  );
}

function MappingAddress({ entry, mapping, machines, copyable = true }) {
  const local = mapping.direction === "local";
  const wholeHost = mapping.direction === "host";
  const published =
    wholeHost ? !!entry.machineIds?.length || !!entry.groupIds?.length : entry.published ??
    (entry.public || !!entry.machineIds?.length || !!entry.groupIds?.length);
  const host = local
    ? "127.0.0.1"
    : wholeHost ? entry.status?.privateHost : !published
      ? null
      : entry.public
        ? entry.status?.publicHost
        : entry.status?.privateHost;
  const port = local ? mapping.clientPort : mapping.gatewayPort;
  const address =
    host && (wholeHost ? host : host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`);
  const destination = local
    ? machines.find((x) => x.id === mapping.machineId)?.name || mapping.target
    : null;
  return (
    <li className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5">
      {!wholeHost && <span className="text-muted-foreground">
        {local
          ? `Access ${destination}:${mapping.servicePort} from`
          : `${!published ? "Client" : entry.public ? "Public access to" : "Private access to"} port ${mapping.clientPort}`}
      </span>}
      {!local && !published && !wholeHost ? (
        <span>Not published</span>
      ) : address ? (
        <>
          <code className="min-w-0 max-w-full break-all font-mono text-xs text-foreground">{address}</code>
          {copyable && <Button
            size="sm"
            variant="ghost"
            className="h-8 px-1.5 md:h-8"
            aria-label={`Copy address ${address}`}
            title="Copy address"
            onClick={async () => {
              try {
                await copyText(address);
                toast.success("Address copied");
              } catch {
                toast.error("Select and copy the address.");
              }
            }}
          >
            <IconCopy size={14} />
          </Button>}
          {wholeHost && <p className="basis-full text-xs text-muted-foreground">{published
            ? <>Append the service port, e.g. <code>:8888</code>.</>
            : "Choose machines or groups in Access to use this hostname."}</p>}
        </>
      ) : (
        <span>{published ? "Address pending" : "Not published"}</span>
      )}
    </li>
  );
}

function Builder({ machines, onCreated, onCancel, saving, setSaving }) {
  const [name, setName] = useState("");
  const [mappings, setMappings] = useState([emptyMapping()]);
  const [kind, setKind] = useState("host");
  const [advanced, setAdvanced] = useState(false);
  const [error, setError] = useState("");
  const update = (index, key, value) =>
    setMappings((rows) =>
      rows.map((row, i) => (i === index ? { ...row, [key]: value } : row)),
    );
  async function submit(event) {
    event.preventDefault();
    if (saving) return;
    setSaving(true);
    setError("");
    try {
      const rows = kind === "host" ? [{ direction: "host" }] : mappings.flatMap((mapping) => {
        const ports = expandPortRange(mapping.ports);
        if (mapping.direction === "remote")
          return ports.map((clientPort) => ({
            direction: "remote",
            clientPort,
          }));
        const services = expandPortRange(mapping.service);
        if (ports.length !== services.length)
          throw new Error(
            "Use the same number of local and destination ports.",
          );
        if (!mapping.machine) throw new Error("Select a destination machine.");
        return ports.map((clientPort, i) => ({
          direction: "local",
          clientPort,
          machineId: mapping.machine,
          servicePort: services[i],
        }));
      });
      if (rows.length > 32)
        throw new Error("Choose up to 32 port mappings per command.");
      const result = await request("", "POST", {
        name: name.trim() || (kind === "host" ? "Private host" : `Port ${mappings[0].ports.trim()}`),
        mappings: rows,
      });
      onCreated(result.id);
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }
  return (
    <form onSubmit={submit} className="space-y-4">
      <div className="grid gap-3">
      <label className={label}>
        Profile name{" "}
        <span className="font-normal text-muted-foreground">
          (optional)
        </span>
        <input
          data-autofocus
          maxLength={80}
          value={name}
          onChange={(event) => setName(event.target.value)}
          className={field}
          placeholder="e.g. devbox"
        />
      </label>
      </div>
      {kind === "host" && (
        <p className="text-sm leading-relaxed text-muted-foreground">
          The profile name supplies the private hostname. For example, <code>devbox.forwards.phub:8888</code> reaches port 8888 on this computer from an allowed machine.
        </p>
      )}
      {!advanced && kind === "ports" && (
        <p className="text-sm">{mappings.length} configured port mapping{mappings.length === 1 ? "" : "s"}. Open advanced settings to review them.</p>
      )}
      <Button
        type="button"
        variant="ghost"
        size="sm"
        aria-expanded={advanced}
        aria-controls="advanced-port-mappings"
        onClick={() => setAdvanced((open) => !open)}
      >
        <IconChevronDown size={16} aria-hidden="true" className={advanced ? "rotate-180" : ""} />
        Advanced ports and direction
      </Button>
      {advanced && (
        <div
          id="advanced-port-mappings"
          className="space-y-4 border-t border-border pt-3"
        >
          <label className={label}>
            Forwarding mode
            <SearchDropdown aria-label="Forwarding mode" className={field} value={kind} onChange={event => setKind(event.target.value)}>
              <option value="host">Private host</option>
              <option value="ports">Specific ports</option>
            </SearchDropdown>
          </label>
          {kind === "ports" && <>
          {mappings.map((mapping, index) => (
            <fieldset key={index} className="border-t border-border pt-3">
              <legend className="pr-2 text-sm font-semibold">
                {mappings.length === 1
                  ? "Port mapping"
                  : `Port mapping ${index + 1}`}
              </legend>
              <div className="grid items-end gap-3 sm:grid-cols-2">
                <label className={label}>
                  Direction
                  <SearchDropdown
                    aria-label="Direction"
                    className={field}
                    value={mapping.direction}
                    onChange={(event) => {
                      const direction = event.target.value;
                      setMappings((rows) =>
                        rows.map((row, i) =>
                          i === index
                            ? {
                                ...row,
                                direction,
                                ports:
                                  direction === "local" && row.ports === "22"
                                    ? "2222"
                                    : row.ports,
                              }
                            : row,
                        ),
                      );
                    }}
                  >
                    {Object.entries(directionNames).map(([key, text]) => (
                      <option key={key} value={key}>
                        {text}
                      </option>
                    ))}
                  </SearchDropdown>
                </label>
                <label className={label}>
                  {mapping.direction === "remote"
                    ? "Port on this computer"
                    : "Local listening port"}
                  <input
                    className={field}
                    value={mapping.ports}
                    required
                    placeholder="22 or 8000-8003"
                    onChange={(event) =>
                      update(index, "ports", event.target.value)
                    }
                  />
                </label>
                {mapping.direction === "local" && (
                  <>
                    <label className={label}>
                      Destination machine
                      <SearchDropdown
                        aria-label="Destination machine"
                        className={field}
                        value={mapping.machine}
                        required
                        onChange={(event) =>
                          update(index, "machine", event.target.value)
                        }
                      >
                        <option value="">Choose a machine</option>
                        {machines.map((machine) => (
                          <option key={machine.id} value={machine.id}>
                            {machine.name}
                          </option>
                        ))}
                      </SearchDropdown>
                    </label>
                    <label className={label}>
                      Destination port
                      <input
                        required
                        className={field}
                        value={mapping.service}
                        onChange={(event) =>
                          update(index, "service", event.target.value)
                        }
                      />
                    </label>
                  </>
                )}
              </div>
              {mappings.length > 1 && (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="mt-1"
                  onClick={() =>
                    setMappings((rows) => rows.filter((_, i) => i !== index))
                  }
                >
                  Remove mapping
                </Button>
              )}
            </fieldset>
          ))}
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={mappings.length >= 32}
            onClick={() => setMappings((rows) => [...rows, emptyMapping()])}
          >
            <IconPlus size={16} />
            Add mapping
          </Button>
          </>}
        </div>
      )}
      {error && (
        <p className="text-sm text-red-600 dark:text-red-400" role="alert">
          {error}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2 border-t border-border pt-3">
        <Button disabled={saving} type="submit">
          <IconTerminal2 size={16} aria-hidden="true" />
          {saving ? "Creating…" : "Generate command"}
        </Button>
        {onCancel && (
          <Button
            type="button"
            variant="ghost"
            disabled={saving}
            onClick={onCancel}
          >
            Cancel
          </Button>
        )}
      </div>
    </form>
  );
}

function AudienceEditor({
  entry,
  machines,
  groups,
  onSaved,
  onCancel,
  onBusy,
}) {
  const [audience, setAudience] = useState(
    entry.public ? "public" : entry.machineIds?.length || entry.groupIds?.length ? "private" : "isolated",
  );
  const [selected, setSelected] = useState([
    ...(entry.machineIds || []).map((id) => "m:" + id),
    ...(entry.groupIds || []).map((id) => "g:" + id),
  ]);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  async function save(event) {
    event.preventDefault();
    if (saving) return;
    setError("");
    if (audience === "private" && !selected.length) {
      setError("Select at least one machine or group.");
      return;
    }
    setSaving(true);
    onBusy(true);
    try {
      await request("/" + entry.id + "/audience", "PUT", {
        public: audience === "public",
        machineIds:
          audience === "private"
            ? selected
                .filter((id) => id.startsWith("m:"))
                .map((id) => id.slice(2))
            : [],
        groupIds:
          audience === "private"
            ? selected
                .filter((id) => id.startsWith("g:"))
                .map((id) => id.slice(2))
            : [],
      });
      onSaved();
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
      onBusy(false);
    }
  }
  return (
    <form
      onSubmit={save}
      aria-label={`Edit access for ${entry.name}`}
      onKeyDown={event => {
        if (event.key === "Escape" && event.target.matches("input")) event.stopPropagation();
      }}
      className="space-y-3"
    >
      <fieldset disabled={saving}>
        <legend className="mb-1 text-sm font-medium">
          {entry.mappings.some(m => m.direction === "host") ? "Who can reach this host?" : "Who can reach this port?"}
        </legend>
        <SearchDropdown
          aria-label="Access mode"
          value={audience}
          disabled={saving}
          onChange={(event) => setAudience(event.target.value)}
        >
          <option value="isolated">Not published</option>
          <option value="private">Selected PortHub machines and groups</option>
          {!entry.mappings.some(m => m.direction === "host") && <option value="public">Public address and port</option>}
        </SearchDropdown>
        {audience === "private" && (
          <div className="my-2">
            <SearchMultiSelect
              label="Allowed machines and groups"
              maxDropdownHeight={120}
              placeholder="Search machines or groups…"
              value={selected}
              onChange={setSelected}
              disabled={saving}
              options={[
                ...machines.map((machine) => ({
                  value: "m:" + machine.id,
                  label: machine.name,
                })),
                ...groups.map((group) => ({
                  value: "g:" + group.id,
                  label: group.name + " · Group",
                })),
              ]}
            />
            {!machines.length && !groups.length && (
              <p className="py-2 text-sm text-muted-foreground">
                Register a machine or create a group to allow private access.
              </p>
            )}
          </div>
        )}
      </fieldset>
      {audience === "public" && (
        <p className="text-xs text-muted-foreground">
          Publishes the assigned address and port. Your existing SSH command and
          key stay the same.
        </p>
      )}
      {audience === "isolated" && (
        <p className="text-xs text-muted-foreground">
          No private or public address is published.
        </p>
      )}
      {error && (
        <p role="alert" className="text-sm text-red-600 dark:text-red-400">
          {error}
        </p>
      )}
      <div className="flex gap-2">
        <Button size="sm" type="submit" disabled={saving}>
          {saving ? "Saving…" : "Save access"}
        </Button>
        <Button
          size="sm"
          type="button"
          variant="ghost"
          disabled={saving}
          onClick={onCancel}
        >
          Cancel
        </Button>
      </div>
    </form>
  );
}

function PublicPorts({ entry }) {
  const [ports, setPorts] = useState(null);
  const [port, setPort] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const [retry, setRetry] = useState(0);
  const url = "/" + entry.id + "/public-ports";

  useEffect(() => {
    const controller = new AbortController();
    setPorts(null);
    setError("");
    request(url, "GET", null, controller.signal)
      .then(data => { if (!controller.signal.aborted) setPorts(data.ports); })
      .catch(err => { if (!controller.signal.aborted) setError(err.message); });
    return () => controller.abort();
  }, [url, retry]);

  async function change(clientPort, remove) {
    if (pending) return;
    setPending(true);
    setError("");
    try {
      const data = await request(remove ? url + "/" + clientPort : url, remove ? "DELETE" : "POST", remove ? undefined : { clientPort });
      setPorts((data ?? await request(url)).ports);
      if (!remove) setPort("");
    } catch (err) {
      setError(err.message);
    } finally {
      setPending(false);
    }
  }
  return <section className="space-y-4">
    <p className="text-sm text-muted-foreground">Publish individual TCP services on this computer to a public gateway address.</p>
    {ports && <>
      <form className="flex flex-wrap items-end gap-2" onSubmit={e => { e.preventDefault(); void change(Number(port), false); }}>
        <label className={label}>Port on this computer
          <input type="number" min={1} max={65535} required value={port} onChange={e => setPort(e.target.value)} className={field} placeholder="e.g. 8888" />
        </label>
        <Button type="submit" disabled={pending || !port}>Publish port</Button>
      </form>
      {!ports.length ? <p className="py-1 text-sm text-muted-foreground">No public ports.</p> :
        <ul className="divide-y divide-border border-y border-border">{ports.map(item => {
          const address = item.host.includes(":") && !item.host.startsWith("[") ? `[${item.host}]:${item.gatewayPort}` : `${item.host}:${item.gatewayPort}`;
          return <li key={item.clientPort} className="flex flex-wrap items-center gap-2 py-2.5">
            <div className="min-w-0 flex-1"><p className="text-xs text-muted-foreground">TCP {item.clientPort}</p><code className="break-all text-sm">{address}</code></div>
            <Button variant="ghost" size="icon" aria-label={`Copy public address ${address}`} onClick={() => copyText(address).then(() => toast.success("Address copied")).catch(() => toast.error("Select and copy the address."))}><IconCopy size={16}/></Button>
            <Button type="button" size="sm" variant="outline" disabled={pending} onClick={() => change(item.clientPort, true)}>Unpublish</Button>
          </li>;
        })}</ul>}
    </>}
    {!ports && !error && <p role="status">Loading public ports…</p>}
    {error && <div role="alert" className="text-sm text-destructive">{error}{ports === null && <Button type="button" size="sm" variant="ghost" onClick={() => setRetry(n => n + 1)}>Retry</Button>}</div>}
  </section>;
}

function ProfileSettings({ entry, machines, busy, onSaved, onRemove }) {
  const [name, setName] = useState(entry.name);
  const address = entry.status?.privateHost || "";
  const [currentLabel, ...suffix] = address.split(".");
  const [hostname, setHostname] = useState(currentLabel);
  const hostnameChanged = Boolean(address) && hostname !== currentLabel;
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [confirm, setConfirm] = useState(false);
  async function save(event) {
    event.preventDefault();
    if (!name.trim() || saving) return;
    setSaving(true);
    setError("");
    try {
      await request("/" + entry.id, "PATCH", { name: name.trim(), ...(hostnameChanged ? { hostname } : {}) });
      onSaved(name.trim());
      toast.success("Profile saved");
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }
  return <section className="space-y-5">
    <form className="flex flex-wrap items-end gap-2" onSubmit={save}>
      <label className={label + " flex-1"}>Profile name<input className={field} maxLength={80} required value={name} onChange={e => setName(e.target.value)} /></label>
      {address && <label className={label + " w-full"}>Private address
        <span className="flex items-center gap-1"><input className={field + " min-w-0"} required maxLength={63}
          aria-label="Private hostname" value={hostname} onChange={e => setHostname(e.target.value.toLowerCase())} />
          <span className="text-sm text-muted-foreground">.{suffix.join(".")}</span></span>
      </label>}
      <Button type="submit" disabled={saving || !name.trim() || (!hostnameChanged && name.trim() === entry.name)}>Save changes</Button>
    </form>
    <div><h3 className="mb-1 text-sm font-medium">Address</h3>
      <ul className="space-y-1 text-sm">{entry.mappings.map((mapping, i) => <MappingAddress key={i} entry={entry} mapping={mapping} machines={machines} />)}</ul>
    </div>
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {entry.mappings.every(m => m.direction !== "host") && (
      <p className="text-sm text-muted-foreground">This profile shares the ports listed above. To reach other services on their original ports, create a private host profile and run its SSH command.</p>
    )}
    <div className="border-t border-border pt-3">
      {confirm ? <div role="group" aria-label="Confirm deletion" className="flex flex-wrap items-center gap-2">
        <p className="w-full text-sm">Delete this forward and disconnect its client?</p>
        <Button size="sm" variant="destructive" disabled={busy} onClick={onRemove}>Delete forward</Button>
        <Button size="sm" variant="ghost" disabled={busy} onClick={() => setConfirm(false)}>Keep forward</Button>
      </div> : <Button size="sm" variant="ghost" className="text-destructive" disabled={busy} onClick={() => setConfirm(true)}><IconTrash size={15} />Delete profile</Button>}
    </div>
  </section>;
}

export default function PortForwards() {
  const demo = useDemo();
  if (demo)
    return (
      <div className="space-y-3 p-4 sm:p-5">
        <h2 className="text-base font-semibold">Port forwards</h2>
        <p className="text-sm text-muted-foreground">
          Sign in to create SSH credentials for your machines.
        </p>
        <Button asChild size="sm">
          <a href={uiRoutes.signIn}>Sign in</a>
        </Button>
      </div>
    );
  return <SavedForwards />;
}

function SavedForwards() {
  const [data, setData] = useState(null),
    [error, setError] = useState(""),
    [building, setBuilding] = useState(false);
  const [shown, setShown] = useState(null),
    [selectedId, setSelectedId] = useState(null),
    [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const [section, setSection] = useState("Profile");
  const [creating, setCreating] = useState(false);
  const createButton = useRef(null);
  function closeBuilder() {
    if (creating) return;
    setBuilding(false);
    requestAnimationFrame(() => createButton.current?.focus());
  }
  const selected = data?.entries.find(entry => entry.id === selectedId);
  function closeProfile() {
    sequence.current++;
    setSelectedId(null);
    setShown(null);
    setBusy(false);
    requestAnimationFrame(() => (document.getElementById("forward-row-" + selectedId) ?? createButton.current)?.focus());
  }
  function openProfile(id, sectionName = "Profile") {
    setSelectedId(id);
    setSection(sectionName);
    if (sectionName === "SSH command" && shown?.id !== id) void reveal(id);
  }
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const query = search.trim().toLowerCase();
  const matches = (data?.entries || []).filter(entry =>
    [entry.name, entry.status?.privateHost, entry.status?.publicHost, ...entry.mappings.flatMap(m => [m.clientPort, m.gatewayPort, m.servicePort])]
      .some(value => value != null && String(value).toLowerCase().includes(query))
  );
  const pages = Math.max(1, Math.ceil(matches.length / pageSize));
  const current = Math.min(page, pages);
  const sequence = useRef(0);
  useEffect(() => {
    const controller = new AbortController();
    let pending = false;
    async function refresh() {
      if (pending || document.hidden) return;
      pending = true;
      try {
        const next = await request("", "GET", null, controller.signal);
        if (!controller.signal.aborted) {
          setData(next);
          setError("");
        }
      } catch (err) {
        if (!controller.signal.aborted) setError(err.message);
      } finally {
        pending = false;
      }
    }
    refresh();
    const timer = setInterval(refresh, 20000);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      controller.abort();
      clearInterval(timer);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, [revision]);
  useEffect(
    () => () => {
      sequence.current++;
    },
    [],
  );
  async function reveal(id) {
    const seq = ++sequence.current;
    setShown(null);
    setBusy(true);
    setError("");
    try {
      const credentials = await request("/" + id + "/credentials", "POST");
      if (seq === sequence.current) setShown({ id, credentials });
    } catch (err) {
      if (seq === sequence.current) setError(err.message);
    } finally {
      if (seq === sequence.current) setBusy(false);
    }
  }
  async function remove(id) {
    setBusy(true);
    setError("");
    try {
      await request("/" + id, "DELETE");
      closeProfile();
      setData((d) => ({ ...d, entries: d.entries.filter((x) => x.id !== id) }));
      setRevision((r) => r + 1);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="flex min-h-0 w-full flex-1 flex-col">
      <header className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-b border-border px-3 py-3 sm:px-4">
        <div className="flex min-w-0 flex-1 items-center justify-end gap-2">
          {!!data?.entries.length && <input type="search" aria-label="Search forwards" placeholder="Search forwards…" value={search}
            onChange={event => { setSearch(event.target.value); setPage(1); }}
            className="h-9 w-full min-w-20 max-w-64 rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-primary" />}
          <Button ref={createButton} size="sm" className="shrink-0" disabled={!data || busy} onClick={() => setBuilding(true)}><IconPlus size={16} />New forward</Button>
        </div>
      </header>
      {error && (
        <div
          role="alert"
          className="mb-3 flex flex-wrap items-center gap-2 text-sm text-red-600 dark:text-red-400"
        >
          {error}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setRevision((r) => r + 1)}
          >
            Refresh
          </Button>
        </div>
      )}
      {!data && !error && (
        <p role="status" className="text-sm text-muted-foreground">
          Loading forwards…
        </p>
      )}
      {data &&
        (!data.entries.length ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-2 px-5 py-10 text-center">
            <IconPlugConnected size={24} className="text-muted-foreground" aria-hidden="true" />
            <h3 className="text-sm font-semibold">No saved forwards</h3>
            <p className="max-w-sm text-sm text-muted-foreground">Create a forward to connect a computer with an SSH command.</p>
          </div>
        ) : (
          <div className="flex min-h-0 w-full flex-1 flex-col">
            <div className="data-scroll">
            <table aria-label="Saved port forwards" className="block w-full text-left text-sm lg:table">
              <thead className="hidden border-y border-border text-xs text-muted-foreground lg:table-header-group">
                <tr>{["Profile", "Connection", "Address"].map(heading =>
                  <th key={heading} scope="col" className="px-3 py-2 font-medium">{heading}</th>)}</tr>
              </thead>
              <tbody className="block lg:table-row-group">
              {!matches.length && <tr><td colSpan={3} className="p-3 text-muted-foreground">No matching forwards.</td></tr>}
              {matches.slice((current - 1) * pageSize, current * pageSize).map(entry => {
                const connected = entry.status?.connected ?? (entry.status?.ready ? true : null);
                return <tr key={entry.id} id={`forward-row-${entry.id}`} tabIndex={0} aria-haspopup="dialog" aria-label={`Configure ${entry.name}`}
                  onClick={() => openProfile(entry.id)} onKeyDown={event => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      openProfile(entry.id);
                    }
                  }}
                  className="block cursor-pointer border-t border-border hover:bg-accent/20 focus-visible:bg-accent/30 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-primary lg:table-row">
                  <td className="block px-3 pt-3 align-middle lg:table-cell lg:py-3">
                    <div className="flex items-center gap-2.5">
                      <span className="hidden h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border text-muted-foreground lg:flex" aria-hidden="true">
                        {entry.mappings.some(m => m.direction === "host") ? <IconServer size={17} /> : <IconPlugConnected size={17} />}
                      </span>
                      <div className="min-w-0">
                        <h3 className="break-words font-semibold">{entry.name}</h3>
                        <p className="mt-0.5 text-xs text-muted-foreground">{entry.mappings.some(m => m.direction === "host") ? "Private host" : "Port mapping"}</p>
                      </div>
                    </div>
                  </td>
                  <td className="block px-3 py-1.5 align-middle lg:table-cell lg:py-2">
                    <span className="inline-flex items-center gap-2 text-xs font-medium">
                      <span aria-hidden="true" className={"h-2 w-2 shrink-0 rounded-full " + (connected ? "bg-emerald-500" : "bg-muted-foreground/50")} />
                      {connected ? "Connected" : connected === false ? "Disconnected" : "Status unavailable"}
                    </span>
                    {entry.status?.reason && !/waiting for .*ssh/i.test(entry.status.reason) && <p className="mt-1 text-xs text-muted-foreground">{entry.status.reason}</p>}
                  </td>
                  <td className="block px-3 py-1.5 align-middle lg:table-cell lg:py-2">
                    <ul className="space-y-1 text-xs">{entry.mappings.map((mapping, index) =>
                      <MappingAddress key={index} entry={entry} mapping={mapping} machines={data.machines} copyable={false} />)}</ul>
                  </td>
                </tr>;
              })}
              </tbody>
            </table>
            </div>
            <ResultsPagination noun="Forwards" count={matches.length} page={current} pages={pages} pageSize={pageSize}
              onPage={setPage} onPageSize={size => { setPageSize(size); setPage(1); }} />
          </div>
        ))}
      {building && data && <Dialog opened onClose={closeBuilder} size="md" title="New port forward"
        closeButtonProps={{ "aria-label": "Close new forward" }} withCloseButton={!creating} closeOnClickOutside={!creating} closeOnEscape={!creating}>
        <Builder machines={data.machines} onCancel={closeBuilder} saving={creating} setSaving={setCreating}
          onCreated={id => {
            setBuilding(false);
            setSearch("");
            setPage(1);
            setRevision(r => r + 1);
            openProfile(id, "SSH command");
          }} />
      </Dialog>}
      {selected && <Dialog opened onClose={closeProfile} size="lg" title={selected.name} closeButtonProps={{ "aria-label": "Close forward settings" }}>
        <div className="mb-4 flex flex-wrap gap-1 border-b border-border pb-2" role="group" aria-label="Forward settings sections">
          {["Profile", ...(selected.mappings.some(m => m.direction !== "local") ? ["Access"] : []), ...(selected.mappings.some(m => m.direction === "host") ? ["Public ports"] : []), "SSH command"].map(title =>
            <Button key={title} size="sm" variant={section === title ? "secondary" : "ghost"} aria-pressed={section === title} onClick={() => openProfile(selected.id, title)}>{title}</Button>)}
        </div>
        {section === "Profile" && <ProfileSettings key={selected.id + (selected.status?.privateHost || "")} entry={selected} machines={data.machines} busy={busy} onRemove={() => remove(selected.id)}
          onSaved={name => { setData(old => ({ ...old, entries: old.entries.map(e => e.id === selected.id ? { ...e, name } : e) })); setRevision(n => n + 1); }} />}
        {section === "Access" && <AudienceEditor key={selected.id} entry={selected} machines={data.machines} groups={data.groups} onBusy={setBusy}
          onCancel={() => setSection("Profile")} onSaved={() => { setSection("Profile"); setRevision(n => n + 1); }} />}
        {section === "Public ports" && <PublicPorts key={selected.id} entry={selected} />}
        {section === "SSH command" && (shown?.id === selected.id
          ? <Commands credentials={shown.credentials} profileName={selected.name} />
          : busy ? <p role="status" className="text-sm">Loading command…</p>
          : <Button onClick={() => reveal(selected.id)}>Load SSH command</Button>)}
        {error && <p role="alert" className="mt-2 text-sm text-destructive">{error}</p>}
      </Dialog>}
    </div>
  );
}
