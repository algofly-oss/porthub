import { useEffect, useRef, useState } from "react";
import { IconCopy, IconPlus, IconTrash } from "@tabler/icons-react";
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

function Commands({ credentials }) {
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
              await downloadForwardProfile(credentials);
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

function MappingAddress({ entry, mapping, machines }) {
  const local = mapping.direction === "local";
  const published =
    entry.published ??
    (entry.public || !!entry.machineIds?.length || !!entry.groupIds?.length);
  const host = local
    ? "127.0.0.1"
    : !published
      ? null
      : entry.public
        ? entry.status?.publicHost
        : entry.status?.privateHost;
  const port = local ? mapping.clientPort : mapping.gatewayPort;
  const address =
    host && (host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`);
  const destination = local
    ? machines.find((x) => x.id === mapping.machineId)?.name || mapping.target
    : null;
  return (
    <li className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5">
      <span className="text-muted-foreground">
        {local
          ? `Access ${destination}:${mapping.servicePort} from`
          : `${!published ? "Client" : entry.public ? "Public access to" : "Private access to"} port ${mapping.clientPort}`}
      </span>
      {!local && !published ? (
        <span>Not published</span>
      ) : address ? (
        <>
          <code className="min-w-0 break-all">{address}</code>
          <Button
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
          </Button>
        </>
      ) : (
        <span>Address pending</span>
      )}
    </li>
  );
}

function Builder({ machines, onCreated, onCancel }) {
  const [name, setName] = useState("");
  const [mappings, setMappings] = useState([emptyMapping()]);
  const [advanced, setAdvanced] = useState(false);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
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
      const rows = mappings.flatMap((mapping) => {
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
        name: name.trim() || `Port ${mappings[0].ports.trim()}`,
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
    <form onSubmit={submit} className="max-w-2xl space-y-4">
      {!advanced &&
        mappings.length === 1 &&
        mappings[0].direction === "remote" && (
          <label className={label}>
            Port on this computer
            <input
              autoFocus
              className={field}
              value={mappings[0].ports}
              required
              placeholder="22 or 8000-8003"
              onChange={(event) => update(0, "ports", event.target.value)}
            />
          </label>
        )}
      <p className="text-sm text-muted-foreground">
        Run the generated command on the computer sharing the port. Choose who
        can reach it afterward.
      </p>
      {!advanced &&
        (mappings.length > 1 || mappings[0].direction !== "remote") && (
          <p className="text-sm">
            {mappings.length} configured port mapping
            {mappings.length === 1 ? "" : "s"}. Open advanced settings to review
            them.
          </p>
        )}
      <Button
        type="button"
        variant="ghost"
        size="sm"
        aria-expanded={advanced}
        aria-controls="advanced-port-mappings"
        onClick={() => setAdvanced((open) => !open)}
      >
        Advanced ports and direction
      </Button>
      {advanced && (
        <div
          id="advanced-port-mappings"
          className="space-y-4 border-t border-border pt-3"
        >
          <label className={label}>
            Forward name{" "}
            <span className="font-normal text-muted-foreground">
              (optional)
            </span>
            <input
              maxLength={80}
              value={name}
              onChange={(event) => setName(event.target.value)}
              className={field}
              placeholder="e.g. Support laptop"
            />
          </label>
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
        </div>
      )}
      {error && (
        <p className="text-sm text-red-600 dark:text-red-400" role="alert">
          {error}
        </p>
      )}
      <div className="flex gap-2">
        <Button disabled={saving} type="submit">
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
    entry.public ? "public" : entry.published ? "private" : "isolated",
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
      className="mt-3 space-y-3 border-t border-border pt-3"
    >
      <fieldset disabled={saving}>
        <legend className="mb-1 text-sm font-medium">
          Who can reach this port?
        </legend>
        <SearchDropdown
          aria-label="Access mode"
          value={audience}
          disabled={saving}
          onChange={(event) => setAudience(event.target.value)}
        >
          <option value="isolated">Not published</option>
          <option value="private">Selected PortHub machines and groups</option>
          <option value="public">Public address and port</option>
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

export default function PortForwards() {
  const demo = useDemo();
  if (demo)
    return (
      <div className="space-y-3">
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
    [confirm, setConfirm] = useState(null),
    [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const [editing, setEditing] = useState(null);
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
      setConfirm(null);
      setEditing(null);
      setShown(null);
      setData((d) => ({ ...d, entries: d.entries.filter((x) => x.id !== id) }));
      setRevision((r) => r + 1);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="min-w-0">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold">
            {building ? "New port forward" : "Port forwards"}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            {building
              ? "Share a client port with one SSH command."
              : "Connect a computer using SSH. The computer running the command does not need a PortHub agent."}
          </p>
        </div>
        {!building && data?.entries.length > 0 && (
          <Button
            size="sm"
            disabled={busy}
            onClick={() => {
              setBuilding(true);
              setShown(null);
              setConfirm(null);
            }}
          >
            <IconPlus size={16} />
            New forward
          </Button>
        )}
      </div>
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
        (building || !data.entries.length ? (
          <Builder
            machines={data.machines}
            groups={data.groups}
            onCancel={
              data.entries.length ? () => setBuilding(false) : undefined
            }
            onCreated={(id) => {
              setBuilding(false);
              setRevision((r) => r + 1);
              void reveal(id);
            }}
          />
        ) : (
          <ul className="divide-y divide-border border-t border-border">
            {data.entries.map((entry) => (
              <li key={entry.id} className="py-4">
                <div className="flex flex-wrap justify-between gap-3">
                  <div className="min-w-0">
                    <h3 className="break-words text-sm font-semibold">
                      {entry.name}
                    </h3>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {entry.status?.ready
                        ? "Connected"
                        : entry.status?.reason || "Waiting for SSH connection"}
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={busy}
                      onClick={() =>
                        shown?.id === entry.id
                          ? setShown(null)
                          : reveal(entry.id)
                      }
                    >
                      {shown?.id === entry.id
                        ? "Hide credentials"
                        : "Show command"}
                    </Button>
                    {entry.mappings.some(
                      (mapping) => mapping.direction === "remote",
                    ) && (
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={busy}
                        onClick={() =>
                          setEditing(editing === entry.id ? null : entry.id)
                        }
                      >
                        Edit access
                      </Button>
                    )}
                    <Button
                      variant="ghost"
                      size="sm"
                      aria-label={`Delete ${entry.name}`}
                      disabled={busy}
                      onClick={() => setConfirm(entry.id)}
                    >
                      <IconTrash size={16} />
                    </Button>
                  </div>
                </div>
                <ul className="mt-2 space-y-1 text-xs">
                  {entry.mappings.map((m, i) => (
                    <MappingAddress
                      key={i}
                      entry={entry}
                      mapping={m}
                      machines={data.machines}
                    />
                  ))}
                </ul>
                {editing === entry.id && (
                  <AudienceEditor
                    entry={entry}
                    machines={data.machines}
                    groups={data.groups}
                    onBusy={setBusy}
                    onCancel={() => setEditing(null)}
                    onSaved={() => {
                      setEditing(null);
                      setRevision((value) => value + 1);
                    }}
                  />
                )}
                {confirm === entry.id && (
                  <div
                    className="mt-3 flex flex-wrap items-center gap-2 text-sm"
                    role="group"
                    aria-label="Confirm deletion"
                  >
                    <span>Delete this forward and disconnect its clients?</span>
                    <Button
                      variant="destructive"
                      size="sm"
                      disabled={busy}
                      onClick={() => remove(entry.id)}
                    >
                      Delete forward
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setConfirm(null)}
                    >
                      Keep forward
                    </Button>
                  </div>
                )}
                {shown?.id === entry.id && (
                  <Commands credentials={shown.credentials} />
                )}
              </li>
            ))}
          </ul>
        ))}
    </div>
  );
}
