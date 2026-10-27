import { externalEndpoint, internalEndpoint } from "@/shared/utils/endpoints.mjs";
import WorkspaceDrawer from "@/components/ui/workspace-drawer";
import { Dialog as Modal } from "@/components/ui/dialog";
import { Menu } from "@/components/ui/menu";
import { Button as WorkspaceButton } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import SearchSelect from "@/components/ui/search-select";
import { StatusTabs } from "@/components/ui/status-tabs";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  ActionIcon,
  Switch,
  Text,
  useMantineColorScheme,
} from "@mantine/core";
import {
  IconDotsVertical,
  IconPlus,
  IconTrash,
} from "@tabler/icons-react";

const MACHINE_PAGE_SIZE = 5;
const SERVICE_PAGE_SIZE = 6;
const TARGET_SCHEME_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//;
const HTTP_TARGET_SCHEME_RE = /^https?:\/\//i;

const hostnameRe =
  /^(?=.{1,253}$)(?:localhost|(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-))(?:\.(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)))*)$/i;

const buildTargetHost = (serviceDomain = "") => {
  const normalizedServiceDomain = String(serviceDomain || "").trim();
  if (normalizedServiceDomain) {
    try {
      const rootUrl = /^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(normalizedServiceDomain)
        ? normalizedServiceDomain
        : `${typeof window !== "undefined" ? window.location.protocol : "http:"}//${normalizedServiceDomain}`;
      return new URL(rootUrl).hostname;
    } catch {
      // Fall back to the existing public base URL / current host resolution below.
    }
  }

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

const buildConnectionTargetUrl = (connection, serviceDomain = "") => {
  const host = buildTargetHost(serviceDomain);
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

let aliasIdCounter = 0;

const createAliasId = () => {
  aliasIdCounter += 1;
  return `alias-${aliasIdCounter}`;
};

const createEmptyAlias = (domainSuffix = "") => ({
  id: createAliasId(),
  subdomainKey: "",
  domainSuffix: String(domainSuffix || "").trim().toLowerCase(),
});

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

const buildHostFromEntry = ({ subdomainKey, domainSuffix }) =>
  buildHostsFromForm({ subdomainKey, domainSuffix })[0] || "";

const collectHostsFromForm = (form) =>
  normalizeHostList([
    buildHostFromEntry(form),
    ...(Array.isArray(form?.aliases)
      ? form.aliases.map((alias) => buildHostFromEntry(alias))
      : []),
  ]);

const validateHostEntry = ({ subdomainKey, domainSuffix }) => {
  const normalizedSubdomainKey = String(subdomainKey || "").trim().toLowerCase();
  const normalizedDomainSuffix = String(domainSuffix || "").trim().toLowerCase();

  if (!normalizedSubdomainKey && !normalizedDomainSuffix) {
    return null;
  }

  if (
    normalizedSubdomainKey &&
    !normalizedDomainSuffix &&
    !normalizedSubdomainKey.includes(".")
  ) {
    return "Domain suffix is required when using a subdomain key";
  }

  const host = buildHostFromEntry({ subdomainKey, domainSuffix });
  if (!host) {
    return "At least one hostname is required";
  }

  if (!hostnameRe.test(host)) {
    return `Invalid hostname: ${host}`;
  }

  return null;
};

const createInitialForm = (proxy, defaultDomainSuffix = "") => {
  const hosts = Array.isArray(proxy?.hosts) ? proxy.hosts : [];
  const primaryHost = hosts[0] || "";
  const splitHost = splitHostForForm(primaryHost);
  const aliasHosts = hosts.slice(1).map((host) => ({
    id: createAliasId(),
    ...splitHostForForm(host),
  }));

  return {
    dataId: proxy?._id || "",
    subdomainKey: splitHost.subdomainKey,
    domainSuffix: splitHost.domainSuffix || String(defaultDomainSuffix || "").trim().toLowerCase(),
    aliases: aliasHosts,
    description: proxy?.description || "",
    group: proxy?.group || "",
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
  serviceDomain = "",
  isSaving = false,
  isDeleting = false,
}) {
  const { colorScheme } = useMantineColorScheme();
  const isDark = colorScheme === "dark";
  const [form, setForm] = useState(createInitialForm(proxy, defaultDomainSuffix));
  const [errors, setErrors] = useState({});
  const [section, setSection] = useState("address");
  const [selectedMachineId, setSelectedMachineId] = useState("");
  const [machinePage, setMachinePage] = useState(1);
  const [servicePage, setServicePage] = useState(1);
  const [machinePortFilter, setMachinePortFilter] = useState("with_ports");
  const [machineOnlineFilter, setMachineOnlineFilter] = useState("online_only");
  const [isDeleteConfirmOpen, setIsDeleteConfirmOpen] = useState(false);

  const initializedEditor = useRef(null);

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
    () => buildConnectionTargetUrl(selectedConnection, serviceDomain),
    [selectedConnection, serviceDomain]
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
      initializedEditor.current = null;
      return;
    }
    const editorKey = proxy?._id || `new:${proxy?.connection?.data_id || ""}`;
    if (initializedEditor.current === editorKey) return;
    initializedEditor.current = editorKey;
    // Inventory refreshes update the options, not the user's open draft.
    // Initialize again only when opening the editor or choosing another proxy.
    setForm(createInitialForm(proxy, defaultDomainSuffix));
    setErrors({});
    setSection("address");
    setIsDeleteConfirmOpen(false);

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

  const modalClassNames = { title: "flex-1", body: "!pt-0" };

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

  const handleAliasChange = (index, field, value) => {
    setForm((current) => ({
      ...current,
      aliases: current.aliases.map((alias, aliasIndex) =>
        aliasIndex === index ? { ...alias, [field]: value } : alias
      ),
    }));
    setErrors((current) => {
      if (!current.aliases) {
        return current;
      }
      const next = { ...current };
      delete next.aliases;
      return next;
    });
  };

  const handleAddAlias = () => {
    setForm((current) => ({
      ...current,
      aliases: [...current.aliases, createEmptyAlias(current.domainSuffix)],
    }));
  };

  const handleRemoveAlias = (index) => {
    setForm((current) => ({
      ...current,
      aliases: current.aliases.filter((_, aliasIndex) => aliasIndex !== index),
    }));
    setErrors((current) => {
      if (!current.aliases) {
        return current;
      }
      const next = { ...current };
      delete next.aliases;
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
      if (currentConnection?.machine_id === machineId) {
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
    handleChange("targetUrl", buildConnectionTargetUrl(connection, serviceDomain));
  };

  const validate = () => {
    const nextErrors = {};
    const hosts = collectHostsFromForm(form);

    const primaryError = validateHostEntry(form);
    if (primaryError) {
      if (primaryError.includes("Domain suffix is required")) {
        nextErrors.domainSuffix = primaryError;
      } else {
        nextErrors.subdomainKey = primaryError;
      }
    }

    const aliasErrorIndex = (Array.isArray(form.aliases) ? form.aliases : []).findIndex(
      (alias) => Boolean(validateHostEntry(alias))
    );
    if (aliasErrorIndex >= 0) {
      nextErrors.aliases = `Alias ${aliasErrorIndex + 1}: ${validateHostEntry(form.aliases[aliasErrorIndex])}`;
    }

    if (hosts.length === 0) {
      nextErrors.subdomainKey = "At least one hostname is required";
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
      validationErrors: nextErrors,
    };
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    // This editor can be rendered from a machine form through a portal. React
    // still bubbles submit events through that parent: never save its port draft.
    event.stopPropagation();

    const { isValid, hosts, validationErrors } = validate();
    if (!isValid) {
      setSection(validationErrors.subdomainKey || validationErrors.domainSuffix || validationErrors.aliases ? "address" : "destination");
      return;
    }

    const payload = {
      data_id: form.dataId || undefined,
      name: primaryPreviewHost,
      description: form.description.trim(),
      group: form.group.trim(),
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

  const previewHosts = collectHostsFromForm(form);
  const primaryPreviewHost = previewHosts[0] || "preview.domain";
  const isPersisted = Boolean(form.dataId || proxy?._id);

  return (
    <>
      <WorkspaceDrawer
        opened={opened}
        zIndex={220}
        trapFocus={!isDeleteConfirmOpen}
        onClose={onClose}
        title={
          <div className="flex w-full items-center justify-between gap-2 pr-2">
            <span className="truncate">
              {isPersisted ? "Edit Proxy Route" : "Create Proxy Route"}
            </span>

            {isPersisted ? (
              <Menu position="bottom-end" withinPortal={false}>
                <Menu.Target>
                  <ActionIcon
                    type="button"
                    variant="subtle"
                    aria-label="Proxy actions"
                    className={
                      isDark
                        ? "!h-7 !w-7 !text-zinc-300 hover:!bg-accent"
                        : "!h-7 !w-7 !text-zinc-600 hover:!bg-accent"
                    }
                  >
                    <IconDotsVertical size={16} />
                  </ActionIcon>
                </Menu.Target>

                <Menu.Dropdown
                  className={
                    isDark
                      ? "!border-border !bg-dialog"
                      : "!border-border !bg-dialog"
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
        closeOnClickOutside={!isSaving && !isDeleteConfirmOpen}
        closeOnEscape={!isSaving && !isDeleteConfirmOpen}
        radius="md"
        size={760}
        fixedHeight="min(680px, calc(100dvh - 64px))"
        classNames={modalClassNames}
      >
        <div className={`flex min-h-0 flex-1 flex-col ${isDeleteConfirmOpen ? "pointer-events-none blur-sm" : ""}`}>
          <form onSubmit={handleSubmit} className="flex h-full min-h-0 flex-col">
            <div className="mb-5 overflow-x-auto"><StatusTabs label="Proxy configuration sections" value={section} onChange={setSection} options={[{value:"address",label:"Address"},{value:"destination",label:"Destination"},{value:"options",label:"Options"}]} /></div>
            <div className="min-h-0 flex-1 overflow-y-auto pr-1">
              {section === "address" && <div className="space-y-5"><div><h2 className="text-base font-semibold">Public Address</h2><p className="mt-2 text-sm leading-6 text-muted-foreground">Choose the hostname people use to open this service.</p></div><div className="grid gap-4 sm:grid-cols-2"><label className="block text-sm font-medium" htmlFor="proxy-subdomain">Primary subdomain<Input id="proxy-subdomain" className="mt-2 bg-control" placeholder="app" value={form.subdomainKey} onChange={event=>handleChange("subdomainKey",event.target.value)} />{errors.subdomainKey && <p className="mt-1 text-xs text-red-500">{errors.subdomainKey}</p>}</label><label className="block text-sm font-medium" htmlFor="proxy-domain">Domain suffix<Input id="proxy-domain" className="mt-2 bg-control" placeholder="example.com" value={form.domainSuffix} onChange={event=>handleChange("domainSuffix",event.target.value)} />{errors.domainSuffix && <p className="mt-1 text-xs text-red-500">{errors.domainSuffix}</p>}</label></div>
              <div className="rounded-lg bg-control p-4"><p className="text-xs text-muted-foreground">Address preview</p><p className="mt-2 break-all text-sm font-medium">http://{primaryPreviewHost}</p></div>
              <div><div className="mb-3 flex items-center justify-between gap-3"><div><h3 className="text-sm font-medium">Additional Hostnames</h3><p className="mt-1 text-xs text-muted-foreground">Aliases route to the same destination.</p></div><WorkspaceButton type="button" size="sm" variant="secondary" onClick={handleAddAlias}><IconPlus size={14} />Add Alias</WorkspaceButton></div><div className="space-y-3">{form.aliases.map((alias,index)=><div key={alias.id} className="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)_36px] items-end gap-2"><label className="block text-xs font-medium" htmlFor={`proxy-alias-subdomain-${index}`}>Alias {index+1}<Input id={`proxy-alias-subdomain-${index}`} className="mt-2 bg-control" value={alias.subdomainKey} onChange={event=>handleAliasChange(index,"subdomainKey",event.target.value)} /></label><label className="block text-xs font-medium" htmlFor={`proxy-alias-domain-${index}`}>Domain suffix<Input id={`proxy-alias-domain-${index}`} className="mt-2 bg-control" value={alias.domainSuffix} onChange={event=>handleAliasChange(index,"domainSuffix",event.target.value)} /></label><WorkspaceButton type="button" variant="ghost" size="icon" aria-label={`Remove alias ${index+1}`} onClick={()=>handleRemoveAlias(index)}><IconTrash size={15} /></WorkspaceButton></div>)}</div>{errors.aliases && <p className="mt-2 text-xs text-red-500">{errors.aliases}</p>}</div></div>}
              {section === "destination" && <div className="space-y-5"><div><h2 className="text-base font-semibold">Destination</h2><p className="mt-2 text-sm leading-6 text-muted-foreground">Route to a machine’s forwarded port or an independent HTTP service.</p></div><StatusTabs label="Proxy destination type" value={form.targetMode} onChange={value=>handleChange("targetMode",value)} options={[{value:"connection",label:"Machine Port"},{value:"manual",label:"Standalone URL"}]} />
                {form.targetMode === "connection" ? <div className="space-y-4"><div><label className="mb-2 block text-sm font-medium">Machine</label><SearchSelect label="Proxy machine" value={selectedMachine?.machine_id || ""} onChange={handleSelectMachine} options={machineOptions.map(machine=>({value:machine.machine_id,label:machine.machine_name}))} placeholder="Search machines…" /></div><div><label className="mb-2 block text-sm font-medium">Forwarded port</label><SearchSelect label="Proxy port" value={form.connectionDataId} onChange={value=>{const connection=connections.find(connection=>connection._id===value);if(connection)handleSelectConnection(connection);}} disabled={!selectedMachine} options={(selectedMachine?.connections || []).map(connection=>({value:connection._id,label:`${connection.service_name || "Port"} · ${externalEndpoint(connection)} → ${internalEndpoint(connection)}`}))} placeholder={selectedMachine ? "Search ports…" : "Choose a machine first"} />{errors.connectionDataId && <p className="mt-2 text-xs text-red-500">{errors.connectionDataId}</p>}</div>{selectedConnection && <div className="rounded-lg bg-control p-4"><p className="text-xs text-muted-foreground">Resolved target</p><p className="mt-2 break-all font-mono text-sm">{derivedConnectionTargetUrl}</p><p className="mt-2 text-xs text-muted-foreground">{getMachineStatusMeta(selectedMachine || {}).label} · {selectedConnection.service_description || "Forwarded machine port"}</p></div>}</div> : <label className="block text-sm font-medium" htmlFor="proxy-target-url">Target URL<Input aria-label="Target URL" id="proxy-target-url" className="mt-2 bg-control" placeholder="http://192.168.1.10:8080" value={form.targetUrl} onChange={event=>handleChange("targetUrl",event.target.value)} /><span className="mt-2 block text-xs font-normal text-muted-foreground">Include http:// or https:// and a port if required.</span></label>}{errors.targetUrl && <p className="text-xs text-red-500">{errors.targetUrl}</p>}
              </div>}
              {section === "options" && <div className="space-y-5"><div><h2 className="text-base font-semibold">Proxy Options</h2><p className="mt-2 text-sm leading-6 text-muted-foreground">Organise the address and choose whether routing is enabled.</p></div><label className="block text-sm font-medium" htmlFor="proxy-group">Project group<Input id="proxy-group" className="mt-2 bg-control" maxLength={80} value={form.group} onChange={event=>handleChange("group",event.target.value)} placeholder="e.g. Production or Internal tools" /></label><label className="block text-sm font-medium" htmlFor="proxy-description">Description<textarea aria-label="Description" id="proxy-description" rows={3} className="mt-2 w-full rounded-lg border-0 bg-control p-3 text-sm text-foreground !outline-none" value={form.description} onChange={event=>handleChange("description",event.target.value)} placeholder="What is this address used for?" /></label><div className="flex items-center justify-between gap-3 rounded-lg bg-control p-4"><div><p className="text-sm font-medium">Routing Enabled</p><p className="mt-1 text-xs text-muted-foreground">Accept requests for this hostname.</p></div><Switch aria-label="Proxy enabled" checked={form.enabled} onChange={event=>handleChange("enabled",event.currentTarget.checked)} size="sm" /></div></div>}
            </div>
            <div className="mt-5 flex shrink-0 flex-wrap items-center justify-between gap-2 border-t border-border pt-4"><WorkspaceButton type="button" variant="secondary" onClick={onClose} disabled={isSaving}>Cancel</WorkspaceButton><div className="flex gap-2">{section !== "address" && <WorkspaceButton type="button" variant="secondary" onClick={()=>setSection(section === "options" ? "destination" : "address")}>Back</WorkspaceButton>}{!isPersisted && section !== "options" ? <WorkspaceButton key="continue" type="button" onClick={event=>{event.preventDefault();setSection(section === "address" ? "destination" : "options");}}>Continue</WorkspaceButton> : <WorkspaceButton key="submit" type="submit" disabled={isSaving}>{isSaving ? "Saving…" : isPersisted ? "Save Proxy" : "Create Proxy"}</WorkspaceButton>}</div></div>
          </form>
        </div>
      </WorkspaceDrawer>

      <Modal
        opened={isDeleteConfirmOpen}
        zIndex={230}
        onClose={() => setIsDeleteConfirmOpen(false)}
        title="Delete proxy"
        centered
        radius="md"
        size="sm"
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
            <WorkspaceButton
              type="button"
              variant="secondary"
              onClick={() => setIsDeleteConfirmOpen(false)}
              disabled={isDeleting}
            >
              Cancel
            </WorkspaceButton>
            <WorkspaceButton
              type="button"
              variant="destructive"
              onClick={handleDelete}
              disabled={isDeleting}
            >
              Delete proxy
            </WorkspaceButton>
          </div>
        </div>
      </Modal>
    </>
  );
}
