import { useEffect, useRef, useState } from "react";
import { IconCopy, IconPlus, IconTrash } from "@tabler/icons-react";
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

function Commands({ credentials }) {
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
      <div className="flex flex-wrap items-center justify-between gap-3">
        <label className={label}>
          Command for
          <select
            className={field}
            value={client}
            onChange={(e) => {
              setClient(e.target.value);
              setDraft(null);
            }}
          >
            <option value="openssh">Linux / macOS · OpenSSH</option>
            <option value="powershell">Windows · PowerShell / OpenSSH</option>
          </select>
        </label>
      </div>
      {problem ? (
        <p role="alert">{problem}</p>
      ) : (
        <>
          <label className={label}>
            SSH command
            <textarea
              className="mt-1 block min-h-[7rem] w-full resize-y rounded-lg border border-input bg-surface p-3 font-mono text-xs leading-5 focus-visible:outline-primary"
              aria-label="SSH command"
              spellCheck={false}
              value={command}
              onChange={(e) => setDraft(e.target.value)}
            />
          </label>
          <p className="text-xs text-muted-foreground">
            Paste into a terminal on the computer sharing or receiving the port.
            Keep it running. This command contains the private key for this
            forward.
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
              Copy command
            </Button>
            {draft !== null && (
              <Button variant="ghost" size="sm" onClick={() => setDraft(null)}>
                Reset edits
              </Button>
            )}
          </div>
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
    </div>
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
  const remote = mappings.some((m) => m.direction === "remote");
  const update = (index, key, value) =>
    setMappings((ms) =>
      ms.map((m, i) => (i === index ? { ...m, [key]: value } : m)),
    );
  async function submit(e) {
    e.preventDefault();
    if (saving) return;
    setSaving(true);
    setError("");
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
      if (remote && !isPublic && !selected.length)
        throw new Error(
          "Select at least one machine or group for private access.",
        );
      const access = remote && !isPublic ? selected : [];
      const result = await request("", "POST", {
        name: name.trim(),
        public: remote && isPublic,
        mappings: rows,
        machineIds: access
          .filter((v) => v.startsWith("m:"))
          .map((v) => v.slice(2)),
        groupIds: access
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
    <form onSubmit={submit} className="max-w-4xl space-y-5">
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
          <div className="grid items-end gap-3 sm:grid-cols-2">
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
                placeholder="22 or 8000-8003"
                onChange={(e) => update(index, "ports", e.target.value)}
              />
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
                    onChange={(e) => update(index, "machine", e.target.value)}
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
                    onChange={(e) => update(index, "service", e.target.value)}
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
      {remote && (
        <fieldset className="border-t border-border pt-3">
          <legend className="pr-2 text-sm font-semibold">
            Who can reach the shared ports?
          </legend>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="radio"
              checked={!isPublic}
              onChange={() => setPublic(false)}
            />
            Selected PortHub machines and groups
          </label>
          {!isPublic && (
            <div className="my-2 max-h-44 overflow-y-auto rounded-lg border border-input px-3 py-1">
              {[
                ...machines.map((x) => ({ ...x, key: "m:" + x.id })),
                ...groups.map((x) => ({ ...x, key: "g:" + x.id })),
              ].map((x) => (
                <label
                  key={x.key}
                  className="flex min-h-9 items-center gap-2 text-sm"
                >
                  <input
                    type="checkbox"
                    checked={selected.includes(x.key)}
                    onChange={(e) =>
                      setSelected((s) =>
                        e.target.checked
                          ? [...s, x.key]
                          : s.filter((k) => k !== x.key),
                      )
                    }
                  />
                  {x.name}
                  {x.key.startsWith("g:") && (
                    <span className="text-xs text-muted-foreground">Group</span>
                  )}
                </label>
              ))}
              {!machines.length && !groups.length && (
                <p className="py-2 text-sm text-muted-foreground">
                  Register a machine or create a group to allow private access.
                </p>
              )}
            </div>
          )}
          <label className="mt-2 flex items-center gap-2 text-sm">
            <input
              type="radio"
              checked={isPublic}
              onChange={() => setPublic(true)}
            />
            Anyone with the public address and port
          </label>
        </fieldset>
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
            No saved forwards yet.
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
                  <Commands key={entry.id} credentials={shown.credentials} />
                )}
              </li>
            ))}
          </ul>
        ))}
    </div>
  );
}
