import { useEffect, useRef, useState } from "react";
import {
  IconCopy,
  IconLock,
  IconPlus,
  IconTrash,
  IconWorld,
} from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { copyText } from "@/shared/utils/clipboard";
import {
  expandPortRange,
  forwardCommand,
} from "@/shared/transfers/port-forwards.mjs";
import toast from "react-hot-toast";
import { useDemo } from "@/shared/demo/DemoProvider";
import uiRoutes from "@/shared/routes/uiRoutes";

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

function Commands({ credentials, panelId }) {
  const [client, setClient] = useState(() =>
    navigator.userAgent.includes("Windows") ? "powershell" : "openssh",
  );
  const [draft, setDraft] = useState(null);
  const editor = useRef(null);
  const resetDraft = () => {
    setDraft(null);
    editor.current?.setSelectionRange(0, 0);
    if (editor.current) editor.current.scrollLeft = 0;
  };
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
    <section
      id={panelId}
      aria-labelledby={`${panelId}-label`}
      className="mt-3 space-y-3 rounded-lg border border-border bg-background p-3 sm:p-4"
    >
      <div className="grid min-w-0 gap-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
        <label className={label}>
          Command for
          <select
            className={field}
            value={client}
            onChange={(e) => {
              setClient(e.target.value);
              resetDraft();
            }}
          >
            <option value="openssh">Linux / macOS · OpenSSH</option>
            <option value="powershell">Windows · PowerShell / OpenSSH</option>
          </select>
        </label>
        <Button
          className="min-h-11 self-end sm:w-auto"
          disabled={Boolean(problem) || !command.trim()}
          onClick={async () => {
            try {
              await copyText(command);
              toast.success("SSH command copied");
            } catch {
              toast.error("Select and copy the SSH command.");
            }
          }}
        >
          <IconCopy size={16} aria-hidden="true" />
          Copy command
        </Button>
      </div>
      {problem ? (
        <p
          id={`${panelId}-label`}
          role="alert"
          className="text-sm text-destructive"
        >
          {problem}
        </p>
      ) : (
        <>
          <div>
            <div className="flex min-h-8 flex-wrap items-center justify-between gap-2">
              <label
                className={label}
                id={`${panelId}-label`}
                htmlFor={`${panelId}-editor`}
              >
                SSH command
              </label>
              {draft !== null && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    resetDraft();
                    editor.current?.focus();
                  }}
                >
                  Reset edits
                </Button>
              )}
            </div>
            <textarea
              ref={editor}
              id={`${panelId}-editor`}
              aria-describedby={`${panelId}-help`}
              className="block w-full min-w-0 resize-y rounded-lg border border-input bg-surface p-3 font-mono text-xs leading-5 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary"
              rows={3}
              wrap="off"
              dir="ltr"
              autoCapitalize="off"
              autoComplete="off"
              spellCheck={false}
              value={command}
              onChange={(e) => setDraft(e.target.value)}
            />
          </div>
          <p
            id={`${panelId}-help`}
            className="max-w-prose text-xs text-muted-foreground"
          >
            Paste the command on the computer sharing or receiving the port,
            then keep it running. Share it only with the person running the
            forward. It contains a private key.
          </p>
        </>
      )}
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
    </section>
  );
}

function MappingAddress({ entry, mapping, machines }) {
  const local = mapping.direction === "local";
  const host = local
    ? "127.0.0.1"
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
          : `${entry.public ? "Public" : "Private"} access to port ${mapping.clientPort}`}
      </span>
      {address ? (
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

function Builder({ machines, groups, onCreated, onCancel }) {
  const [name, setName] = useState("");
  const [mappings, setMappings] = useState([emptyMapping()]);
  const [isPublic, setPublic] = useState(false);
  const [selected, setSelected] = useState([]);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [accessRequired, setAccessRequired] = useState(false);
  const accessChoices = useRef(null);
  const remote = mappings.some((m) => m.direction === "remote");
  const recipients = [
    ...machines.map((machine) => ({ ...machine, key: "m:" + machine.id })),
    ...groups.map((group) => ({ ...group, key: "g:" + group.id })),
  ];
  const access = recipients.filter((recipient) =>
    selected.includes(recipient.key),
  );
  const update = (index, key, value) =>
    setMappings((ms) =>
      ms.map((m, i) => (i === index ? { ...m, [key]: value } : m)),
    );
  async function submit(e) {
    e.preventDefault();
    if (saving) return;
    setError("");
    if (remote && !isPublic && !access.length) {
      setAccessRequired(true);
      const choices = accessChoices.current;
      (
        choices?.querySelector('input[type="checkbox"]') ??
        choices?.querySelector("input")
      )?.focus();
      return;
    }
    setSaving(true);
    try {
      const rows = mappings.flatMap((m) => {
        const local = expandPortRange(m.ports);
        if (m.direction === "remote")
          return local.map((clientPort) => ({
            direction: "remote",
            clientPort,
          }));
        const service = expandPortRange(m.service);
        if (local.length !== service.length)
          throw new Error(
            "Use the same number of local and destination ports.",
          );
        if (!m.machine) throw new Error("Select a destination machine.");
        return local.map((clientPort, i) => ({
          direction: "local",
          clientPort,
          machineId: m.machine,
          servicePort: service[i],
        }));
      });
      if (rows.length > 32)
        throw new Error("Choose up to 32 port mappings per command.");
      const scope =
        remote && !isPublic ? access.map((recipient) => recipient.key) : [];
      const result = await request("", "POST", {
        name: name.trim(),
        public: remote && isPublic,
        mappings: rows,
        machineIds: scope
          .filter((v) => v.startsWith("m:"))
          .map((v) => v.slice(2)),
        groupIds: scope
          .filter((v) => v.startsWith("g:"))
          .map((v) => v.slice(2)),
      });
      onCreated(result.id);
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }
  return (
    <form onSubmit={submit} className="max-w-6xl">
      <div className="grid items-start gap-x-8 gap-y-7 xl:grid-cols-[minmax(0,1.65fr)_minmax(17rem,1fr)]">
        <div className="min-w-0 space-y-5">
          <label className={label}>
            Forward name
            <input
              autoFocus
              required
              maxLength={80}
              value={name}
              onChange={(e) => setName(e.target.value)}
              className={field}
              placeholder="e.g. Support laptop"
            />
          </label>
          {mappings.map((m, index) => (
            <fieldset key={index} className="border-t border-border pt-3">
              <legend className="pr-2 text-sm font-semibold">
                {mappings.length === 1
                  ? "Port mapping"
                  : `Port mapping ${index + 1}`}
              </legend>
              <div className="grid items-start gap-3 sm:grid-cols-2">
                <label className={label}>
                  Direction
                  <select
                    aria-label="Direction"
                    className={field}
                    value={m.direction}
                    onChange={(e) => {
                      const direction = e.target.value;
                      setMappings((ms) =>
                        ms.map((row, i) =>
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
                    {Object.entries(directionNames).map(([k, v]) => (
                      <option key={k} value={k}>
                        {v}
                      </option>
                    ))}
                  </select>
                </label>
                <label className={label}>
                  {m.direction === "remote"
                    ? "Port on this computer"
                    : "Local listening port"}
                  <input
                    className={field}
                    value={m.ports}
                    required
                    aria-describedby={`forward-port-help-${index}`}
                    placeholder="22 or 8000-8003"
                    onChange={(e) => update(index, "ports", e.target.value)}
                  />
                  <span
                    id={`forward-port-help-${index}`}
                    className="mt-1 block text-xs text-muted-foreground"
                  >
                    A port or range, such as 22 or 8000–8003.
                  </span>
                </label>
                {m.direction === "local" && (
                  <>
                    <label className={label}>
                      Destination machine
                      <select
                        aria-label="Destination machine"
                        className={field}
                        value={m.machine}
                        required
                        onChange={(e) =>
                          update(index, "machine", e.target.value)
                        }
                      >
                        <option value="">Choose a machine</option>
                        {machines.map((x) => (
                          <option key={x.id} value={x.id}>
                            {x.name}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className={label}>
                      Destination port
                      <input
                        required
                        className={field}
                        value={m.service}
                        onChange={(e) =>
                          update(index, "service", e.target.value)
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
                    setMappings((ms) => ms.filter((_, i) => i !== index))
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
            onClick={() => setMappings((ms) => [...ms, emptyMapping()])}
          >
            <IconPlus size={16} />
            Add mapping
          </Button>
        </div>
        {remote && (
          <fieldset
            ref={accessChoices}
            className="min-w-0 rounded-xl border border-border bg-background/50 px-4 pb-4 pt-2"
          >
            <legend className="px-1.5 text-sm font-semibold">
              Who can reach the shared ports?
            </legend>
            <label className="flex min-h-11 cursor-pointer items-start gap-2 py-2 text-sm">
              <input
                type="radio"
                name="forward-access"
                checked={!isPublic}
                aria-describedby="forward-private-help"
                className="mt-1 accent-primary"
                onChange={() => setPublic(false)}
              />
              <span>
                <span className="font-medium">Private network</span>
                <span
                  id="forward-private-help"
                  className="mt-0.5 block text-xs text-muted-foreground"
                >
                  Allow the PortHub machines and groups you select below.
                </span>
              </span>
            </label>
            {!isPublic && (
              <div className="mx-0.5 mb-3 mt-1 rounded-lg border border-input">
                <p
                  className="border-b border-border px-3 py-2 text-xs font-medium"
                  role="status"
                >
                  {access.length} selected
                </p>
                <div className="max-h-44 divide-y divide-border overflow-y-auto px-3">
                  {recipients.map((recipient) => (
                    <label
                      key={recipient.key}
                      className="flex min-h-11 cursor-pointer items-center gap-2 text-sm"
                    >
                      <input
                        type="checkbox"
                        className="shrink-0 accent-primary"
                        checked={selected.includes(recipient.key)}
                        onChange={(e) => {
                          setAccessRequired(false);
                          setSelected((current) =>
                            e.target.checked
                              ? [...current, recipient.key]
                              : current.filter((key) => key !== recipient.key),
                          );
                        }}
                      />
                      <span className="min-w-0 break-words">
                        {recipient.name}
                      </span>
                      {recipient.key.startsWith("g:") && (
                        <span className="ml-auto text-xs text-muted-foreground">
                          Group
                        </span>
                      )}
                    </label>
                  ))}
                  {!recipients.length && (
                    <p className="py-3 text-sm text-muted-foreground">
                      Register a machine or create a group to allow private
                      access.
                    </p>
                  )}
                </div>
              </div>
            )}
            {!isPublic && accessRequired && (
              <p
                className="mb-3 text-sm text-red-600 dark:text-red-400"
                role="alert"
              >
                Select at least one machine or group for private access.
              </p>
            )}
            <label className="flex min-h-11 cursor-pointer items-start gap-2 border-t border-border pt-3 text-sm">
              <input
                type="radio"
                name="forward-access"
                checked={isPublic}
                aria-describedby="forward-public-help"
                className="mt-1 accent-primary"
                onChange={() => {
                  setAccessRequired(false);
                  setPublic(true);
                }}
              />
              <span>
                <span className="font-medium">Public internet</span>
                <span
                  id="forward-public-help"
                  className="mt-0.5 block text-xs text-muted-foreground"
                >
                  Anyone with the public address and port can connect.
                </span>
              </span>
            </label>
          </fieldset>
        )}
      </div>
      {error && (
        <p className="mt-4 text-sm text-red-600 dark:text-red-400" role="alert">
          {error}
        </p>
      )}
      <div className="mt-6 flex flex-wrap gap-2 border-t border-border pt-4">
        <Button disabled={saving} type="submit">
          {saving ? "Creating…" : "Generate command"}
        </Button>
        <Button
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
              ? "Choose which TCP ports this SSH command can forward."
              : "Connect a computer using SSH. The computer running the command does not need a PortHub agent."}
          </p>
        </div>
        {!building && data && (
          <Button
            size="sm"
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
        (building ? (
          <Builder
            machines={data.machines}
            groups={data.groups}
            onCancel={() => setBuilding(false)}
            onCreated={(id) => {
              setBuilding(false);
              setRevision((r) => r + 1);
              void reveal(id);
            }}
          />
        ) : !data.entries.length ? (
          <div className="border-t border-border py-6 text-sm text-muted-foreground">
            <p className="font-medium text-foreground">
              No saved forwards yet.
            </p>
            <p className="mt-1">
              Create a forward to get a reusable SSH command.
            </p>
          </div>
        ) : (
          <ul className="divide-y divide-border border-t border-border">
            {data.entries.map((entry) => (
              <li key={entry.id} className="py-4">
                <div className="flex flex-wrap justify-between gap-3">
                  <div className="min-w-0">
                    <h3 className="break-words text-sm font-semibold">
                      {entry.name}
                    </h3>
                    <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
                      <p role="status" className="flex items-center gap-1.5">
                        <span
                          aria-hidden="true"
                          className={`h-2 w-2 shrink-0 rounded-full ${entry.status?.ready ? "bg-emerald-500" : "border border-current text-muted-foreground"}`}
                        />
                        {entry.status?.ready
                          ? "Connected"
                          : entry.status?.reason ||
                            "Waiting for SSH connection"}
                      </p>
                      <p className="flex items-center gap-1.5 text-muted-foreground">
                        {entry.public ? (
                          <IconWorld size={14} aria-hidden="true" />
                        ) : (
                          <IconLock size={14} aria-hidden="true" />
                        )}
                        {entry.public
                          ? "Public internet"
                          : entry.mappings.some(
                                (mapping) => mapping.direction === "remote",
                              )
                            ? "Private network"
                            : "Local access"}
                      </p>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={busy}
                      aria-expanded={shown?.id === entry.id}
                      aria-controls={
                        shown?.id === entry.id
                          ? `port-forward-command-${entry.id}`
                          : undefined
                      }
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
                  <Commands
                    key={entry.id}
                    panelId={`port-forward-command-${entry.id}`}
                    credentials={shown.credentials}
                  />
                )}
              </li>
            ))}
          </ul>
        ))}
    </div>
  );
}
