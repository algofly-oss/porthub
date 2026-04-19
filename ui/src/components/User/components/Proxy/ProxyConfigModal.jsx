import { useEffect, useMemo, useState } from "react";
import {
  ActionIcon,
  Button,
  Group,
  Menu,
  Modal,
  Pagination,
  Switch,
  Text,
  useMantineColorScheme,
} from "@mantine/core";
import { IconArrowLeft, IconDotsVertical, IconFilter, IconTrash } from "@tabler/icons-react";

const getInputClassName = (isDark) =>
  `w-full rounded-md border px-3 py-2 text-sm outline-none transition-colors focus:!border-blue-500 focus:ring-0 ${
    isDark
      ? "!border-zinc-700 !bg-zinc-900 !text-zinc-100 placeholder:!text-zinc-500"
      : "!border-zinc-300 !bg-white !text-zinc-900 placeholder:!text-zinc-400"
  }`;

const getLabelClassName = (isDark) =>
  `mb-1.5 block text-sm font-semibold ${isDark ? "text-zinc-100" : "text-zinc-900"}`;

const getPanelClassName = (isDark) =>
  `rounded-lg border p-3 ${
    isDark ? "border-zinc-700 bg-zinc-900/70" : "border-zinc-200 bg-zinc-50"
  }`;

const getSectionTitleClassName = (isDark) =>
  `text-[11px] font-semibold uppercase tracking-[0.18em] ${
    isDark ? "text-zinc-500" : "text-zinc-500"
  }`;

const errorClassName = "mt-1 text-xs text-red-600 dark:text-red-400";
const MACHINE_PAGE_SIZE = 5;
const SERVICE_PAGE_SIZE = 6;
const TARGET_SCHEME_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//;
const HTTP_TARGET_SCHEME_RE = /^https?:\/\//i;

const hostnameRe =
  /^(?=.{1,253}$)(?:localhost|(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-))(?:\.(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)))*)$/i;

const buildTargetHost = () => {
  const configuredBaseUrl =
    (process.env.NEXT_PUBLIC_PORT_HUB_PUBLIC_BASE_URL ||
      process.env.PORT_HUB_PUBLIC_BASE_URL ||
      "").trim();

  if (configuredBaseUrl) {
    try {
      return new URL(configuredBaseUrl).hostname;
    } catch {
      return "";
    }
  }

  if (typeof window === "undefined") {
    return "";
  }

  return window.location.hostname || "";
};

const buildConnectionTargetUrl = (connection) => {
  const host = buildTargetHost();
  const externalPort = Number(connection?.external_port);
  if (!host || !Number.isInteger(externalPort) || externalPort < 1 || externalPort > 65535) {
    return "";
  }
  return `http://${host}:${externalPort}`;
};

const getStatusTextClassName = (isDark, tone) => {
  if (tone === "success") {
    return isDark
      ? "text-xs font-medium text-emerald-300"
      : "text-xs font-medium text-emerald-700";
  }
  if (tone === "warning") {
    return isDark
      ? "text-xs font-medium text-amber-300"
      : "text-xs font-medium text-amber-700";
  }
  return isDark
    ? "text-xs font-medium text-zinc-300"
    : "text-xs font-medium text-zinc-700";
};

const getMachineStatusMeta = (machine) => {
  const status = machine?.machine_connection_status || "unknown";
  if (machine?.machine_enabled === false) {
    return { label: "Disabled", tone: "neutral" };
  }
  if (status === "online") {
    return { label: "Online", tone: "success" };
  }
  if (status === "auth_required") {
    return { label: "Auth required", tone: "warning" };
  }
  if (status === "offline") {
    return { label: "Offline", tone: "neutral" };
  }
  return { label: "Unknown", tone: "neutral" };
};

const getConnectionStatusMeta = (connection) => {
  if (!connection?.enabled) {
    return { label: "Disabled", tone: "neutral" };
  }
  if (connection?.machine_enabled === false) {
    return { label: "Machine disabled", tone: "neutral" };
  }
  if (connection?.machine_connection_status === "online") {
    return { label: "Active", tone: "success" };
  }
  if (connection?.machine_connection_status === "auth_required") {
    return { label: "Auth required", tone: "warning" };
  }
  if (connection?.machine_connection_status === "offline") {
    return { label: "Machine offline", tone: "warning" };
  }
  return { label: "Unknown", tone: "neutral" };
};

const normalizeIdentityValue = (value) =>
  String(value || "").trim().toLowerCase();

const splitHostForForm = (host) => {
  const normalized = String(host || "").trim().toLowerCase();
  if (!normalized) {
    return { subdomainKey: "", domainSuffix: "" };
  }

  const segments = normalized.split(".");
  if (segments.length >= 3) {
    return {
      subdomainKey: segments.slice(0, -2).join("."),
      domainSuffix: segments.slice(-2).join("."),
    };
  }

  if (segments.length === 2) {
    return {
      subdomainKey: segments[0],
      domainSuffix: segments[1],
    };
  }

  return {
    subdomainKey: normalized,
    domainSuffix: "",
  };
};

const normalizeHostList = (values) =>
  [...new Set(
    (Array.isArray(values) ? values : [])
      .map((value) => String(value || "").trim().toLowerCase())
      .filter(Boolean)
  )];

const buildHostsFromForm = ({ subdomainKey, domainSuffix }) => {
  const normalizedSubdomainKey = String(subdomainKey || "").trim().toLowerCase();
  const normalizedDomainSuffix = String(domainSuffix || "").trim().toLowerCase();
  return normalizeHostList([
    normalizedSubdomainKey
    ? normalizedDomainSuffix
      ? `${normalizedSubdomainKey}.${normalizedDomainSuffix}`
      : normalizedSubdomainKey
    : normalizedDomainSuffix,
  ]);
};

const createInitialForm = (proxy, defaultDomainSuffix = "") => {
  const hosts = Array.isArray(proxy?.hosts) ? proxy.hosts : [];
  const primaryHost = hosts[0] || "";
  const splitHost = splitHostForForm(primaryHost);

  return {
    dataId: proxy?._id || "",
    subdomainKey: splitHost.subdomainKey,
    domainSuffix: splitHost.domainSuffix || String(defaultDomainSuffix || "").trim().toLowerCase(),
    description: proxy?.description || "",
    targetMode: proxy?.target_mode || (proxy?.connection?.data_id ? "connection" : "manual"),
    connectionDataId: proxy?.connection?.data_id || "",
    targetUrl: proxy?.target_url || "",
    enabled: proxy?.enabled ?? true,
  };
};

export default function ProxyConfigModal({
  opened,
  onClose,
  onSubmit,
  onDelete,
  proxy = null,
  connections = [],
  machines = [],
  defaultDomainSuffix = "",
  isSaving = false,
  isDeleting = false,
}) {
  const { colorScheme } = useMantineColorScheme();
  const isDark = colorScheme === "dark";
  const [form, setForm] = useState(createInitialForm(proxy, defaultDomainSuffix));
  const [errors, setErrors] = useState({});
  const [selectedMachineId, setSelectedMachineId] = useState("");
  const [machinePage, setMachinePage] = useState(1);
  const [servicePage, setServicePage] = useState(1);
  const [machinePortFilter, setMachinePortFilter] = useState("with_ports");
  const [machineOnlineFilter, setMachineOnlineFilter] = useState("online_only");
  const [isDeleteConfirmOpen, setIsDeleteConfirmOpen] = useState(false);

  useEffect(() => {
    if (!opened) {
      return;
    }
    setForm(createInitialForm(proxy, defaultDomainSuffix));
    setErrors({});
    setIsDeleteConfirmOpen(false);
  }, [opened, proxy, defaultDomainSuffix]);

  const machineOptions = useMemo(() => {
    const grouped = new Map();

    machines.forEach((machine) => {
      const machineId = machine._id || "";
      grouped.set(machineId || `legacy-machine:${machine.name}`, {
        machine_id: machineId,
        machine_name: machine.name || "Unknown machine",
        machine_hostname: machine.hostname || "",
        machine_local_ip: machine.local_ip || "",
        machine_public_ip: machine.public_ip || "",
        machine_enabled: machine.enabled ?? true,
        machine_is_active: machine.is_active ?? false,
        machine_connection_status: machine.connection_status || "unknown",
        connections: [],
      });
    });

    connections.forEach((connection) => {
      const identityCandidates = [
        normalizeIdentityValue(connection.machine_name),
        normalizeIdentityValue(connection.machine_hostname),
        normalizeIdentityValue(connection.machine_local_ip),
        normalizeIdentityValue(connection.machine_public_ip),
      ].filter(Boolean);
      const machineKey =
        connection.machine_id ||
        [...grouped.keys()].find((key) => {
          const machine = grouped.get(key);
          if (!machine) {
            return false;
          }
          const machineCandidates = [
            normalizeIdentityValue(machine.machine_name),
            normalizeIdentityValue(machine.machine_hostname),
            normalizeIdentityValue(machine.machine_local_ip),
            normalizeIdentityValue(machine.machine_public_ip),
          ].filter(Boolean);
          return identityCandidates.some((candidate) => machineCandidates.includes(candidate));
        }) ||
        `legacy:${identityCandidates.join("|") || connection._id}`;
      const existing = grouped.get(machineKey);

      if (existing) {
        existing.connections.push(connection);
        return;
      }

      grouped.set(machineKey, {
        machine_id: connection.machine_id || machineKey,
        machine_name: connection.machine_name || "Unknown machine",
        machine_hostname: connection.machine_hostname || "",
        machine_local_ip: connection.machine_local_ip || "",
        machine_public_ip: connection.machine_public_ip || "",
        machine_enabled: connection.machine_enabled ?? true,
        machine_is_active: connection.machine_is_active ?? false,
        machine_connection_status: connection.machine_connection_status || "unknown",
        connections: [connection],
      });
    });

    return [...grouped.values()]
      .map((machine) => ({
        ...machine,
        connections: [...machine.connections].sort((left, right) => {
          if ((left.service_name || "") !== (right.service_name || "")) {
            return (left.service_name || "").localeCompare(right.service_name || "");
          }
          return Number(left.external_port || 0) - Number(right.external_port || 0);
        }),
      }))
      .sort((left, right) => {
        if ((left.machine_name || "") !== (right.machine_name || "")) {
          return (left.machine_name || "").localeCompare(right.machine_name || "");
        }
        return (left.machine_hostname || "").localeCompare(right.machine_hostname || "");
      });
  }, [connections, machines]);

  const selectedConnection = useMemo(
    () =>
      connections.find(
        (connection) => connection._id === form.connectionDataId
      ) || null,
    [connections, form.connectionDataId]
  );

  const derivedConnectionTargetUrl = useMemo(
    () => buildConnectionTargetUrl(selectedConnection),
    [selectedConnection]
  );

  const selectedMachineFromConnection = useMemo(
    () =>
      machineOptions.find((machine) =>
        machine.connections.some(
          (connection) => connection._id === form.connectionDataId
        )
      ) || null,
    [form.connectionDataId, machineOptions]
  );

  const selectedMachine = useMemo(
    () =>
      machineOptions.find((machine) => machine.machine_id === selectedMachineId) ||
      selectedMachineFromConnection ||
      null,
    [machineOptions, selectedMachineFromConnection, selectedMachineId]
  );

  const filteredMachineOptions = useMemo(
    () =>
      machineOptions.filter((machine) => {
        const isSelectedMachine =
          machine.machine_id === selectedMachineId ||
          machine.connections.some(
            (connection) => connection._id === form.connectionDataId
          );

        if (isSelectedMachine) {
          return true;
        }
        if (machinePortFilter === "with_ports" && machine.connections.length === 0) {
          return false;
        }
        if (
          machineOnlineFilter === "online_only" &&
          !["online", "auth_required"].includes(machine.machine_connection_status)
        ) {
          return false;
        }
        return true;
      }),
    [form.connectionDataId, machineOnlineFilter, machineOptions, machinePortFilter, selectedMachineId]
  );

  const machineTotalPages = Math.max(
    1,
    Math.ceil(filteredMachineOptions.length / MACHINE_PAGE_SIZE)
  );
  const visibleMachines = useMemo(
    () =>
      filteredMachineOptions.slice(
        (machinePage - 1) * MACHINE_PAGE_SIZE,
        machinePage * MACHINE_PAGE_SIZE
      ),
    [filteredMachineOptions, machinePage]
  );
  const serviceTotalPages = Math.max(
    1,
    Math.ceil((selectedMachine?.connections.length || 0) / SERVICE_PAGE_SIZE)
  );
  const visibleServices = useMemo(
    () =>
      (selectedMachine?.connections || []).slice(
        (servicePage - 1) * SERVICE_PAGE_SIZE,
        servicePage * SERVICE_PAGE_SIZE
      ),
    [selectedMachine, servicePage]
  );

  useEffect(() => {
    if (form.targetMode !== "connection") {
      return;
    }
    setForm((current) =>
      current.targetUrl === derivedConnectionTargetUrl
        ? current
        : { ...current, targetUrl: derivedConnectionTargetUrl }
    );
  }, [derivedConnectionTargetUrl, form.targetMode]);

  useEffect(() => {
    if (!opened) {
      return;
    }

    const initialConnection =
      connections.find((connection) => connection._id === createInitialForm(proxy, defaultDomainSuffix).connectionDataId) ||
      null;
    const nextMachineId =
      initialConnection?.machine_id ||
      machineOptions.find((machine) =>
        machine.connections.some(
          (connection) => connection._id === initialConnection?._id
        )
      )?.machine_id ||
      "";
    setSelectedMachineId(nextMachineId);
    setMachinePage(1);
    setServicePage(1);
    setMachinePortFilter("with_ports");
    setMachineOnlineFilter("online_only");
  }, [opened, proxy, connections, machineOptions, defaultDomainSuffix]);

  useEffect(() => {
    if (!selectedConnection?.machine_id) {
      return;
    }
    setSelectedMachineId((current) => current || selectedConnection.machine_id);
  }, [selectedConnection]);

  useEffect(() => {
    if (machinePage > machineTotalPages) {
      setMachinePage(machineTotalPages);
    }
  }, [machinePage, machineTotalPages]);

  useEffect(() => {
    setMachinePage(1);
  }, [machineOnlineFilter, machinePortFilter]);

  useEffect(() => {
    if (servicePage > serviceTotalPages) {
      setServicePage(serviceTotalPages);
    }
  }, [servicePage, serviceTotalPages]);

  useEffect(() => {
    if (!selectedMachineId) {
      setServicePage(1);
      return;
    }

    const selectedIndex = filteredMachineOptions.findIndex(
      (machine) => machine.machine_id === selectedMachineId
    );
    if (selectedIndex >= 0) {
      setMachinePage(Math.floor(selectedIndex / MACHINE_PAGE_SIZE) + 1);
    }
  }, [filteredMachineOptions, selectedMachineId]);

  useEffect(() => {
    if (!selectedMachine || !form.connectionDataId) {
      setServicePage(1);
      return;
    }

    const selectedIndex = selectedMachine.connections.findIndex(
      (connection) => connection._id === form.connectionDataId
    );
    if (selectedIndex >= 0) {
      setServicePage(Math.floor(selectedIndex / SERVICE_PAGE_SIZE) + 1);
    }
  }, [form.connectionDataId, selectedMachine]);

  const modalClassNames = isDark
    ? {
        content: "!border !border-zinc-700 !bg-zinc-900",
        header: "!border-b !border-zinc-800 !bg-zinc-900",
        title: "flex-1 font-bold !text-zinc-100",
        close: "!h-7 !w-7 !text-zinc-400 hover:!bg-zinc-800",
        body: "!bg-zinc-900 !pt-3",
      }
    : {
        content: "!border !border-zinc-200 !bg-white",
        header: "!border-b !border-zinc-200 !bg-white",
        title: "flex-1 font-bold !text-zinc-900",
        close: "!h-7 !w-7 !text-zinc-500 hover:!bg-zinc-100",
        body: "!bg-white !pt-3",
      };

  const btnSecondary = isDark
    ? "!border-zinc-700 !bg-zinc-800 !text-zinc-100 hover:!bg-zinc-700"
    : "!border-zinc-300 !bg-white !text-zinc-900 hover:!bg-zinc-50";

  const handleChange = (field, value) => {
    setForm((current) => ({ ...current, [field]: value }));
    setErrors((current) => {
      if (!current[field]) {
        return current;
      }
      const next = { ...current };
      delete next[field];
      return next;
    });
  };

  const handleSelectMachine = (machineId) => {
    setSelectedMachineId(machineId);
    setServicePage(1);
    setForm((current) => {
      const currentConnection = connections.find(
        (connection) => connection._id === current.connectionDataId
      );
      if (!currentConnection || currentConnection.machine_id === machineId) {
        return current;
      }
      return { ...current, connectionDataId: "", targetUrl: "" };
    });
    setErrors((current) => {
      const next = { ...current };
      delete next.connectionDataId;
      delete next.targetUrl;
      return next;
    });
  };

  const handleSelectConnection = (connection) => {
    setSelectedMachineId(connection.machine_id || selectedMachineId);
    handleChange("connectionDataId", connection._id);
    handleChange("targetUrl", buildConnectionTargetUrl(connection));
  };

  const validate = () => {
    const nextErrors = {};
    const hosts = buildHostsFromForm(form);

    if (!form.subdomainKey.trim() && !form.domainSuffix.trim()) {
      nextErrors.subdomainKey = "Enter a subdomain key or full hostname";
    }

    if (form.subdomainKey.trim() && !form.domainSuffix.trim() && !form.subdomainKey.includes(".")) {
      nextErrors.domainSuffix = "Domain suffix is required when using a subdomain key";
    }

    if (hosts.length === 0) {
      nextErrors.subdomainKey = "At least one hostname is required";
    } else {
      const invalidHost = hosts.find((host) => !hostnameRe.test(host));
      if (invalidHost) {
        nextErrors.subdomainKey = `Invalid hostname: ${invalidHost}`;
      }
    }

    if (form.targetMode === "connection") {
      if (!form.connectionDataId) {
        nextErrors.connectionDataId = "Select a mapped port-pair service";
      }
      if (!derivedConnectionTargetUrl) {
        nextErrors.targetUrl = "Could not derive the target URL for this connection";
      }
    } else {
      const normalizedTargetUrl = String(form.targetUrl || "").trim();
      if (!normalizedTargetUrl) {
        nextErrors.targetUrl = "Target URL is required";
      } else if (!TARGET_SCHEME_RE.test(normalizedTargetUrl)) {
        nextErrors.targetUrl = "Target URL must include http:// or https://";
      } else if (!HTTP_TARGET_SCHEME_RE.test(normalizedTargetUrl)) {
        nextErrors.targetUrl = "Target URL must use http:// or https://";
      }
    }

    setErrors(nextErrors);
    return {
      isValid: Object.keys(nextErrors).length === 0,
      hosts,
    };
  };

  const handleSubmit = async (event) => {
    event.preventDefault();

    const { isValid, hosts } = validate();
    if (!isValid) {
      return;
    }

    const payload = {
      data_id: form.dataId || undefined,
      name: primaryPreviewHost,
      description: form.description.trim(),
      hosts,
      targetMode: form.targetMode,
      targetUrl:
        form.targetMode === "connection"
          ? derivedConnectionTargetUrl
          : form.targetUrl.trim(),
      entryPoints: ["web"],
      enabled: form.enabled,
      connectionDataId:
        form.targetMode === "connection" ? form.connectionDataId : undefined,
    };

    const savedProxy = await onSubmit(payload);
    if (savedProxy) {
      setForm(createInitialForm(savedProxy, defaultDomainSuffix));
    }
  };

  const handleDelete = async () => {
    const proxyId = form.dataId || proxy?._id;
    if (!proxyId || !onDelete) {
      return;
    }
    const deleted = await onDelete(proxyId);
    if (deleted) {
      setIsDeleteConfirmOpen(false);
      onClose();
    }
  };

  const previewHosts = buildHostsFromForm(form);
  const primaryPreviewHost = previewHosts[0] || "preview.domain";
  const isPersisted = Boolean(form.dataId || proxy?._id);

  return (
    <>
      <Modal
        opened={opened}
        onClose={onClose}
        title={
          <div className="flex w-full items-center justify-between gap-2 pr-2">
            <span className="truncate">
              {isPersisted ? "Edit Proxy Route" : "Create Proxy Route"}
            </span>

            {isPersisted ? (
              <Menu position="bottom-end" withinPortal>
                <Menu.Target>
                  <ActionIcon
                    type="button"
                    variant="subtle"
                    aria-label="Proxy actions"
                    className={
                      isDark
                        ? "!h-7 !w-7 !text-zinc-300 hover:!bg-zinc-800"
                        : "!h-7 !w-7 !text-zinc-600 hover:!bg-zinc-100"
                    }
                  >
                    <IconDotsVertical size={16} />
                  </ActionIcon>
                </Menu.Target>

                <Menu.Dropdown
                  className={
                    isDark
                      ? "!border-zinc-700 !bg-zinc-900"
                      : "!border-zinc-200 !bg-white"
                  }
                >
                  <Menu.Item
                    color="red"
                    onClick={() => setIsDeleteConfirmOpen(true)}
                  >
                    Delete proxy
                  </Menu.Item>
                </Menu.Dropdown>
              </Menu>
            ) : null}
          </div>
        }
        centered
        closeOnClickOutside={false}
        closeOnEscape={false}
        radius="md"
        size={760}
        overlayProps={{ blur: 3 }}
        classNames={modalClassNames}
      >
        <div className={isDeleteConfirmOpen ? "pointer-events-none blur-sm" : ""}>
          <form onSubmit={handleSubmit} className="space-y-4">
        <div className={getPanelClassName(isDark)}>
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className={getSectionTitleClassName(isDark)}>Public Address</p>
              <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
                Choose the domain people will open in their browser.
              </p>
            </div>

            <Switch
              id="proxy-enabled"
              size="sm"
              checked={form.enabled}
              onChange={(event) => handleChange("enabled", event.currentTarget.checked)}
              label="Enabled"
              classNames={{
                track: isDark ? "!border-zinc-700" : "!border-zinc-300",
                label: isDark ? "!text-zinc-200" : "!text-zinc-800",
              }}
            />
          </div>

          <div className="mt-3 grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,0.9fr)]">
            <div>
              <label className={getLabelClassName(isDark)} htmlFor="proxy-subdomain">
                Subdomain
              </label>
              <input
                id="proxy-subdomain"
                type="text"
                placeholder="app"
                className={getInputClassName(isDark)}
                value={form.subdomainKey}
                onChange={(event) => handleChange("subdomainKey", event.currentTarget.value)}
              />
              {errors.subdomainKey ? (
                <p className={errorClassName}>{errors.subdomainKey}</p>
              ) : null}
            </div>

            <div>
              <label className={getLabelClassName(isDark)} htmlFor="proxy-domain">
                Domain suffix
              </label>
              <input
                id="proxy-domain"
                type="text"
                placeholder="luna.lan"
                className={getInputClassName(isDark)}
                value={form.domainSuffix}
                onChange={(event) => handleChange("domainSuffix", event.currentTarget.value)}
              />
              {errors.domainSuffix ? (
                <p className={errorClassName}>{errors.domainSuffix}</p>
              ) : null}
            </div>
          </div>

          <div className="mt-3">
            <label className={getLabelClassName(isDark)} htmlFor="proxy-description">
              Description
            </label>
            <textarea
              id="proxy-description"
              rows={3}
              placeholder="Short note about this web proxy"
              className={getInputClassName(isDark)}
              value={form.description}
              onChange={(event) => handleChange("description", event.currentTarget.value)}
            />
          </div>

          <p className="mt-3 text-xs text-zinc-500 dark:text-zinc-400">
            Final address:
            <span className="ml-1 break-all font-medium text-zinc-900 dark:text-zinc-100">
              {`http://${primaryPreviewHost}`}
            </span>
          </p>
        </div>

        <div className={getPanelClassName(isDark)}>
          <p className={getSectionTitleClassName(isDark)}>Destination</p>
          <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
            Choose where requests for this domain should be sent.
          </p>

          <div className="mt-3 grid gap-2 md:grid-cols-2">
            <button
              type="button"
              onClick={() => handleChange("targetMode", "connection")}
              aria-pressed={form.targetMode === "connection"}
              className={`rounded-md border px-3 py-3 text-left transition ${
                form.targetMode === "connection"
                  ? isDark
                    ? "border-blue-500 bg-blue-500/10"
                    : "border-blue-500 bg-blue-50"
                  : isDark
                    ? "border-zinc-700 bg-zinc-900 hover:bg-zinc-800"
                    : "border-zinc-300 bg-white hover:bg-zinc-50"
              }`}
            >
              <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                Existing mapped service
              </p>
              <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                Use a service that already has an external port.
              </p>
            </button>
            <button
              type="button"
              onClick={() => handleChange("targetMode", "manual")}
              aria-pressed={form.targetMode === "manual"}
              className={`rounded-md border px-3 py-3 text-left transition ${
                form.targetMode === "manual"
                  ? isDark
                    ? "border-blue-500 bg-blue-500/10"
                    : "border-blue-500 bg-blue-50"
                  : isDark
                    ? "border-zinc-700 bg-zinc-900 hover:bg-zinc-800"
                    : "border-zinc-300 bg-white hover:bg-zinc-50"
              }`}
            >
              <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                Custom target address
              </p>
              <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                Send traffic to any HTTP or HTTPS endpoint.
              </p>
            </button>
          </div>

          {form.targetMode === "connection" ? (
            <div className="mt-3 space-y-3">
              {machineOptions.length === 0 ? (
                <div
                  className={`rounded-md border px-3 py-4 text-sm ${
                    isDark ? "border-zinc-700 bg-zinc-950 text-zinc-300" : "border-zinc-200 bg-white text-zinc-600"
                  }`}
                >
                  No mapped services are available yet.
                </div>
              ) : (
                <>
                  {!selectedMachine ? (
                    <div>
                      <div className="mb-3 flex items-center gap-1.5">
                        <p className={`text-sm font-semibold ${isDark ? "text-zinc-100" : "text-zinc-900"}`}>
                          Step 1: Choose a machine
                        </p>
                        <Menu
                          withinPortal={false}
                          position="bottom-end"
                          shadow="md"
                          offset={6}
                          classNames={{
                            dropdown:
                              "!min-w-[10rem] !border !border-zinc-200 !bg-white !p-2 dark:!border-zinc-700 dark:!bg-zinc-900",
                          }}
                        >
                          <Menu.Target>
                            <button
                              type="button"
                              className={`inline-flex h-5 w-5 items-center justify-center ${
                                isDark
                                  ? "text-zinc-400 hover:text-zinc-200"
                                  : "text-zinc-500 hover:text-zinc-700"
                              }`}
                              aria-label="Filter machines"
                            >
                              <IconFilter size={16} />
                            </button>
                          </Menu.Target>
                          <Menu.Dropdown>
                            <div className="space-y-2 text-sm">
                              <div>
                                <p className="mb-1 text-[11px] text-zinc-500">
                                  Ports
                                </p>
                                <div className="flex gap-2">
                                  <button
                                    type="button"
                                    onClick={() => setMachinePortFilter("all")}
                                    className={`rounded-md px-2 py-1 text-xs ${
                                      machinePortFilter === "all"
                                        ? "bg-blue-600 text-blue-50"
                                        : isDark
                                          ? "bg-zinc-800 text-zinc-200"
                                          : "bg-zinc-100 text-zinc-700"
                                    }`}
                                  >
                                    All
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => setMachinePortFilter("with_ports")}
                                    className={`rounded-md px-2 py-1 text-xs ${
                                      machinePortFilter === "with_ports"
                                        ? "bg-blue-600 text-blue-50"
                                        : isDark
                                          ? "bg-zinc-800 text-zinc-200"
                                          : "bg-zinc-100 text-zinc-700"
                                    }`}
                                  >
                                    With ports
                                  </button>
                                </div>
                              </div>
                              <div>
                                <p className="mb-1 text-[11px] text-zinc-500">
                                  Status
                                </p>
                                <div className="flex gap-2">
                                  <button
                                    type="button"
                                    onClick={() => setMachineOnlineFilter("all")}
                                    className={`rounded-md px-2 py-1 text-xs ${
                                      machineOnlineFilter === "all"
                                        ? "bg-blue-600 text-blue-50"
                                        : isDark
                                          ? "bg-zinc-800 text-zinc-200"
                                          : "bg-zinc-100 text-zinc-700"
                                    }`}
                                  >
                                    All
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => setMachineOnlineFilter("online_only")}
                                    className={`rounded-md px-2 py-1 text-xs ${
                                      machineOnlineFilter === "online_only"
                                        ? "bg-blue-600 text-blue-50"
                                        : isDark
                                          ? "bg-zinc-800 text-zinc-200"
                                          : "bg-zinc-100 text-zinc-700"
                                    }`}
                                  >
                                    Online
                                  </button>
                                </div>
                              </div>
                            </div>
                          </Menu.Dropdown>
                        </Menu>
                      </div>
                      <div className={`overflow-hidden rounded-md border ${
                        isDark ? "border-zinc-700 bg-zinc-950" : "border-zinc-200 bg-white"
                      }`}>
                        <div className="hidden border-b border-zinc-200 px-3 py-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-zinc-500 dark:border-zinc-800 md:grid md:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_minmax(6rem,0.7fr)_minmax(6rem,0.7fr)] md:gap-3">
                          <span>Machine</span>
                          <span>Host</span>
                          <span>Mapped ports</span>
                          <span>Status</span>
                        </div>
                        {visibleMachines.length > 0 ? (
                          <div className="divide-y divide-zinc-200 dark:divide-zinc-800">
                            {visibleMachines.map((machine) => {
                              const machineStatus = getMachineStatusMeta(machine);
                              const activePortCount = machine.connections.filter(
                                (connection) => connection.enabled
                              ).length;
                              return (
                                <button
                                  key={machine.machine_id}
                                  type="button"
                                  onClick={() => handleSelectMachine(machine.machine_id)}
                                  className={`grid w-full gap-2 px-3 py-3 text-left transition-colors duration-150 md:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_minmax(6rem,0.7fr)_minmax(6rem,0.7fr)] md:items-center md:gap-3 ${
                                    isDark ? "hover:bg-zinc-800/80" : "hover:bg-zinc-100"
                                  }`}
                                >
                                  <div className="min-w-0">
                                    <p className="truncate text-sm font-medium text-zinc-900 dark:text-zinc-100">
                                      {machine.machine_name}
                                    </p>
                                    <p className="truncate text-xs text-zinc-500 dark:text-zinc-400">
                                      {machine.machine_local_ip || machine.machine_public_ip || "No IP recorded"}
                                    </p>
                                  </div>
                                  <div className="min-w-0">
                                    <p className="truncate text-sm text-zinc-900 dark:text-zinc-100">
                                      {machine.machine_hostname || "No hostname"}
                                    </p>
                                    <p className="truncate text-xs text-zinc-500 dark:text-zinc-400">
                                      {machine.machine_public_ip || "No public IP"}
                                    </p>
                                  </div>
                                  <div className="text-sm text-zinc-900 dark:text-zinc-100">
                                    {activePortCount}/{machine.connections.length}
                                  </div>
                                  <div>
                                    <span className={getStatusTextClassName(isDark, machineStatus.tone)}>
                                      {machineStatus.label}
                                    </span>
                                  </div>
                                </button>
                              );
                            })}
                          </div>
                        ) : (
                          <div className="px-3 py-6 text-sm text-zinc-500 dark:text-zinc-400">
                            No machines match the current filters.
                          </div>
                        )}
                      </div>
                      {machineTotalPages > 1 ? (
                        <div className="mt-3 flex justify-end">
                          <Pagination
                            value={machinePage}
                            onChange={setMachinePage}
                            total={machineTotalPages}
                            size="sm"
                            radius="md"
                            siblings={1}
                            classNames={{
                              control:
                                "!border-zinc-300 !bg-white !text-zinc-700 hover:!bg-zinc-50 data-[active=true]:!border-blue-600 data-[active=true]:!bg-blue-600 data-[active=true]:!text-blue-50 dark:!border-zinc-700 dark:!bg-zinc-900 dark:!text-zinc-200 dark:hover:!bg-zinc-800 dark:data-[active=true]:!border-blue-500 dark:data-[active=true]:!bg-blue-600",
                            }}
                          />
                        </div>
                      ) : null}
                    </div>
                  ) : (
                    <div>
                      <div className="mb-3 flex items-center justify-between gap-3">
                        <p className={getLabelClassName(isDark)}>Step 2: Choose a mapped port</p>
                        <Button
                          type="button"
                          variant="subtle"
                          size="xs"
                          onClick={() => handleSelectMachine("")}
                          leftIcon={<IconArrowLeft size={14} />}
                        >
                          Back to machines
                        </Button>
                      </div>
                      <div className={`overflow-hidden rounded-md border ${
                        isDark ? "border-zinc-700 bg-zinc-950" : "border-zinc-200 bg-white"
                      }`}>
                        <div className="hidden border-b border-zinc-200 px-3 py-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-zinc-500 dark:border-zinc-800 md:grid md:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_minmax(6rem,0.7fr)_minmax(8rem,0.8fr)] md:gap-3">
                          <span>Service</span>
                          <span>Internal</span>
                          <span>External</span>
                          <span>Status</span>
                        </div>
                        <div className="divide-y divide-zinc-200 dark:divide-zinc-800">
                          {visibleServices.map((connection) => {
                            const connectionStatus = getConnectionStatusMeta(connection);
                            return (
                              <button
                                key={connection._id}
                                type="button"
                                onClick={() => handleSelectConnection(connection)}
                                className={`grid w-full gap-2 px-3 py-3 text-left transition-colors duration-150 md:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_minmax(6rem,0.7fr)_minmax(8rem,0.8fr)] md:items-center md:gap-3 ${
                                  form.connectionDataId === connection._id
                                    ? isDark
                                      ? "bg-blue-500/10"
                                      : "bg-blue-50"
                                    : isDark
                                      ? "hover:bg-zinc-800/80"
                                      : "hover:bg-zinc-100"
                                }`}
                              >
                                <div className="min-w-0">
                                  <p className="truncate text-sm font-medium text-zinc-900 dark:text-zinc-100">
                                    {connection.service_name || "Unnamed service"}
                                  </p>
                                  <p className="truncate text-xs text-zinc-500 dark:text-zinc-400">
                                    {connection.service_description || "No description"}
                                  </p>
                                </div>
                                <div className="min-w-0">
                                  <p className="truncate text-sm text-zinc-900 dark:text-zinc-100">
                                    {connection.internal_ip || "0.0.0.0"}:{connection.internal_port || "-"}
                                  </p>
                                </div>
                                <div className="text-sm text-zinc-900 dark:text-zinc-100">
                                  :{connection.external_port || "-"}
                                </div>
                                <div>
                                  <span className={getStatusTextClassName(isDark, connectionStatus.tone)}>
                                    {connectionStatus.label}
                                  </span>
                                </div>
                              </button>
                            );
                          })}
                        </div>
                      </div>
                      {serviceTotalPages > 1 ? (
                        <div className="mt-3 flex justify-end">
                          <Pagination
                            value={servicePage}
                            onChange={setServicePage}
                            total={serviceTotalPages}
                            size="sm"
                            radius="md"
                            siblings={1}
                            classNames={{
                              control:
                                "!border-zinc-300 !bg-white !text-zinc-700 hover:!bg-zinc-50 data-[active=true]:!border-blue-600 data-[active=true]:!bg-blue-600 data-[active=true]:!text-blue-50 dark:!border-zinc-700 dark:!bg-zinc-900 dark:!text-zinc-200 dark:hover:!bg-zinc-800 dark:data-[active=true]:!border-blue-500 dark:data-[active=true]:!bg-blue-600",
                            }}
                          />
                        </div>
                      ) : null}
                    </div>
                  )}
                </>
              )}
              {errors.targetUrl ? <p className={errorClassName}>{errors.targetUrl}</p> : null}
              {errors.connectionDataId ? (
                <p className={errorClassName}>{errors.connectionDataId}</p>
              ) : null}
            </div>
          ) : (
            <div className="mt-3">
              <label className={getLabelClassName(isDark)} htmlFor="proxy-target-url">
                Target URL
              </label>
              <input
                id="proxy-target-url"
                type="text"
                placeholder="http://192.168.0.3:8089"
                className={getInputClassName(isDark)}
                value={form.targetUrl}
                onChange={(event) => handleChange("targetUrl", event.currentTarget.value)}
              />
              {errors.targetUrl ? <p className={errorClassName}>{errors.targetUrl}</p> : null}
            </div>
          )}
        </div>

        <Group position="apart" className="px-1">
          <div />
          <Group>
            <Button type="button" variant="default" onClick={onClose} classNames={{ root: btnSecondary }}>
              Cancel
            </Button>
            <Button
              type="submit"
              loading={isSaving}
              classNames={{
                root:
                  "!bg-blue-600 !text-blue-50 hover:!bg-blue-700 disabled:!bg-blue-400",
              }}
            >
              {isPersisted ? "Save proxy" : "Create proxy"}
            </Button>
          </Group>
        </Group>
          </form>
        </div>
      </Modal>

      <Modal
        opened={isDeleteConfirmOpen}
        onClose={() => setIsDeleteConfirmOpen(false)}
        title="Delete proxy"
        centered
        radius="md"
        size="sm"
        overlayProps={{ backgroundOpacity: 0, blur: 0 }}
        classNames={modalClassNames}
        closeOnClickOutside={!isDeleting}
        closeOnEscape={!isDeleting}
      >
        <div className={isDark ? "text-zinc-100" : "text-zinc-900"}>
          <Text
            size="sm"
            className={isDark ? "!text-zinc-300" : "!text-zinc-700"}
          >
            Delete this web proxy and remove its routing rule.
          </Text>
          <Text
            size="sm"
            className={isDark ? "!mt-2 !text-zinc-400" : "!mt-2 !text-zinc-600"}
          >
            This action cannot be undone.
          </Text>

          <div className="mt-5 flex justify-end gap-3">
            <Button
              type="button"
              variant="default"
              onClick={() => setIsDeleteConfirmOpen(false)}
              disabled={isDeleting}
              classNames={{ root: btnSecondary }}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="filled"
              onClick={handleDelete}
              loading={isDeleting}
              classNames={{
                root:
                  "!bg-red-600 !text-red-50 hover:!bg-red-700 disabled:!bg-red-400",
              }}
            >
              Delete proxy
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
}
