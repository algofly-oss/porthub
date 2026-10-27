import { useWorkspaceState } from "@/shared/contexts/workspaceCache";
import ResultsPagination from "@/components/ui/results-pagination";
import { normalizeTrafficSamples, trafficSummary } from "@/shared/utils/traffic.mjs";
import { compareInventoryEntries, INVENTORY_SORT_OPTIONS, isTrafficSort } from "@/shared/utils/inventory-sort.mjs";
import { preserveNewerClientVersion } from "@/shared/utils/client-version.mjs";
import { useContext, useEffect, useMemo, useState } from "react";
import axios from "axios";
import { useRouter } from "next/router";
import { Button as WorkspaceButton } from "@/components/ui/button";
import { StatusTabs } from "@/components/ui/status-tabs";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
import utc from "dayjs/plugin/utc";
import {
  Button,
  Menu,
  SegmentedControl,
  useMantineColorScheme,
} from "@mantine/core";
import {
  IconChevronDown,
  IconPlus,
  IconSettings,
} from "@tabler/icons-react";
import HostItem from "./components/Host/HostItem";
import HostConfigPopup from "./components/Host/HostConfigPopup";
import MachineCreateModal from "./components/Host/MachineCreateModal";
import MachineGroupsModal from "./components/MachineGroupsModal";
import useCreateFromUrl from "@/shared/hooks/useCreateFromUrl";
import useToast from "@/shared/hooks/useToast";
import { SocketContext } from "@/shared/contexts/socket";
import apiRoutes from "@/shared/routes/apiRoutes";
import socketRoutes from "@/shared/routes/socketRoutes";
import { PageHeader, SearchField } from "@/components/ui/workspace";
import { searchScore } from "@/shared/utils/search.mjs";
import SearchSelect from "@/components/ui/search-select";
import InventoryToolbar from "@/components/ui/inventory-toolbar";
import { Table, TableHeader, TableHead, TableRow, TableBody } from "@/components/ui/table";
import { IconServer, IconCircleCheck, IconPlugConnected, IconFolder } from "@tabler/icons-react";

dayjs.extend(relativeTime);
dayjs.extend(utc);

const parseServerTimestamp = (value) => {
  if (!value) {
    return null;
  }

  if (typeof value === "string") {
    const hasTimezone = /(?:Z|[+-]\d{2}:\d{2})$/.test(value);
    return hasTimezone ? dayjs(value) : dayjs.utc(value);
  }

  return dayjs(value);
};

const formatRelativeFromNow = (parsed) => {
  if (!parsed) {
    return "Never seen";
  }

  const secondsAgo = Math.max(0, dayjs().diff(parsed, "second"));
  if (secondsAgo <= 30) {
    return "Just now";
  }

  const minutesAgo = Math.floor(secondsAgo / 60);
  if (minutesAgo < 60) {
    return minutesAgo <= 1 ? "1 min ago" : `${minutesAgo} min ago`;
  }

  const hoursAgo = Math.floor(minutesAgo / 60);
  if (hoursAgo < 24) {
    return hoursAgo === 1 ? "1 hr ago" : `${hoursAgo} hr ago`;
  }

  const daysAgo = Math.floor(hoursAgo / 24);
  return daysAgo === 1 ? "1 day ago" : `${daysAgo} days ago`;
};

const readConnectionValue = (connection, snakeKey, camelKey, fallback = "") => {
  const snakeValue = connection[snakeKey];
  if (snakeValue !== undefined && snakeValue !== null && snakeValue !== "") {
    return snakeValue;
  }

  const camelValue = connection[camelKey];
  if (camelValue !== undefined && camelValue !== null && camelValue !== "") {
    return camelValue;
  }

  return fallback;
};

const mapConnectionToForwardingConfig = (connection) => {
  const autoRefreshIntervalMinutes =
    connection.autoRefreshIntervalMinutes ??
    connection.auto_refresh_interval_minutes;

  return {
    dataId: connection._id || connection.dataId,
    serviceName: connection.service_name || connection.serviceName || "",
    serviceDescription:
      connection.service_description || connection.serviceDescription || "",
    internalIp: connection.internal_ip || connection.internalIp || "0.0.0.0",
    internalPort: readConnectionValue(connection, "internal_port", "internalPort"),
    externalPort: readConnectionValue(connection, "external_port", "externalPort"),
    externalBindIp: connection.external_bind_ip || connection.externalBindIp || "0.0.0.0",
    temporary: connection.temporary === true,
    publicAccess: connection.public_access || connection.publicAccess || { mode: "off" },
    managedBy: connection.managed_by || connection.managedBy || "",
    enabled: connection.enabled ?? true,
    autoRefreshEnabled:
      connection.autoRefreshEnabled ?? connection.auto_refresh_enabled ?? false,
    autoRefreshIntervalMinutes:
      autoRefreshIntervalMinutes === undefined ||
      autoRefreshIntervalMinutes === null ||
      autoRefreshIntervalMinutes === ""
        ? 60
        : autoRefreshIntervalMinutes,
    autoRefreshedAt:
      connection.autoRefreshedAt || connection.auto_refreshed_at || null,
    autoRefreshNextAt:
      connection.autoRefreshNextAt || connection.auto_refresh_next_at || null,
    firewall: {
      isPublic:
        connection.firewall?.isPublic ?? connection.firewall?.is_public ?? true,
      allowedIps: Array.isArray(connection.firewall?.allowedIps)
        ? connection.firewall.allowedIps
        : Array.isArray(connection.firewall?.allowed_ips)
          ? connection.firewall.allowed_ips
          : [],
    },
  };
};

const mergeMachineTrafficSamples = samples => normalizeTrafficSamples(samples, 30);

const normalizeFirewallPolicy = (config) => {
  const allowedIps = Array.isArray(config?.firewall?.allowedIps)
    ? [...config.firewall.allowedIps]
    : Array.isArray(config?.firewall?.allowed_ips)
      ? [...config.firewall.allowed_ips]
      : [];

  const normalizedAllowedIps = [...new Set(
    allowedIps
      .map((value) => String(value || "").trim())
      .filter(Boolean)
  )].sort((left, right) => left.localeCompare(right));

  const isPublic =
    typeof config?.firewall?.isPublic === "boolean"
      ? config.firewall.isPublic
      : typeof config?.firewall?.is_public === "boolean"
        ? config.firewall.is_public
        : normalizedAllowedIps.length === 0;

  return {
    isPublic: isPublic || normalizedAllowedIps.length === 0,
    allowedIps: isPublic ? [] : normalizedAllowedIps,
  };
};

const normalizeForwardingConfig = (config) => ({
  serviceName: (config.serviceName || "").trim(),
  serviceDescription: (config.serviceDescription || "").trim(),
  internalIp:
    (config.internalIp || config.internal_ip || "").trim() || "0.0.0.0",
  internalPort: Number(config.internalPort),
  externalPort: Number(config.externalPort),
  enabled: config.enabled ?? true,
  autoRefreshEnabled: config.autoRefreshEnabled ?? config.auto_refresh_enabled ?? false,
  autoRefreshIntervalMinutes:
    Number(
      config.autoRefreshIntervalMinutes ??
        config.auto_refresh_interval_minutes ??
        60
    ) || 60,
  firewall: normalizeFirewallPolicy(config),
});

const forwardingConfigChanged = (currentConfig, nextConfig) => {
  if (!currentConfig) {
    return true;
  }

  const currentNormalized = normalizeForwardingConfig(currentConfig);
  const nextNormalized = normalizeForwardingConfig(nextConfig);

  return (
    currentNormalized.serviceName !== nextNormalized.serviceName ||
    currentNormalized.serviceDescription !== nextNormalized.serviceDescription ||
    currentNormalized.internalIp !== nextNormalized.internalIp ||
    currentNormalized.internalPort !== nextNormalized.internalPort ||
    currentNormalized.externalPort !== nextNormalized.externalPort ||
    currentNormalized.enabled !== nextNormalized.enabled ||
    currentNormalized.autoRefreshEnabled !== nextNormalized.autoRefreshEnabled ||
    currentNormalized.autoRefreshIntervalMinutes !==
      nextNormalized.autoRefreshIntervalMinutes ||
    currentNormalized.firewall.isPublic !== nextNormalized.firewall.isPublic ||
    JSON.stringify(currentNormalized.firewall.allowedIps) !==
      JSON.stringify(nextNormalized.firewall.allowedIps)
  );
};

const formatLastSeen = (machine) => {
  const parsed = parseServerTimestamp(machine.last_seen_at);
  return formatRelativeFromNow(parsed);
};

const mapMachineToHost = (machine) => ({
  id: machine._id,
  name: machine.name || "Untitled machine",
  aliases: machine.aliases || [],
  createdAt: machine.created_at || "",
  hostname: machine.hostname || "",
  clientHostname: machine.client_hostname || "",
  clientOs: machine.client_os || "",
  clientOsId: machine.client_os_id || "",
  clientOsName: machine.client_os_name || "",
  clientArch: machine.client_arch || "",
  clientCountry: machine.client_country || "",
  privateDomains: Array.isArray(machine.private_domains) ? machine.private_domains : [],
  hostnameOverride: machine.hostname_override || "",
  clientSetupPublicBaseUrl: machine.client_setup_public_base_url || "",
  clientSetupRatholeServerAddress:
    machine.client_setup_rathole_server_address || "",
  clientSetupServiceDomain: machine.client_setup_service_domain || "",
  groupIds: Array.isArray(machine.group_ids)
    ? machine.group_ids
    : machine.group_id
      ? [machine.group_id]
      : [],
  enabled: machine.enabled ?? true,
  telegramAlertsExcluded: machine.telegram_alerts_excluded ?? false,
  localIp: machine.local_ip || "",
  publicIp: machine.public_ip || "",
  ...(Array.isArray(machine.private_ips) ? { privateIps: machine.private_ips } : {}),
  token: machine.token || "",
  connectionStatus:
    machine.connection_status ||
    (machine.enabled === false
      ? "disabled"
      : machine.is_active
        ? "online"
        : "offline"),
  authRequired: machine.auth_required ?? false,
  isActive: machine.is_active ?? false,
  clientVersion: machine.client_version || "",
  latestClientVersion: machine.latest_client_version || "",
  clientUpdateAvailable: machine.client_update_available ?? false,
  clientUpdateRequested: machine.client_update_requested ?? false,
  clientUpdateTargetVersion: machine.client_update_target_version || "",
  numPorts: 0,
  lastSeenAt: machine.last_seen_at || null,
  lastSeen: formatLastSeen(machine),
  forwardingConfigs: [],
});

const mergeMachineIntoHost = (host, machine) => {
  const mappedHost = mapMachineToHost(machine);
  const currentVersionState = preserveNewerClientVersion(host, mappedHost);

  return {
    ...currentVersionState,
    privateIps: Array.isArray(machine.private_ips) ? machine.private_ips : (host?.privateIps || []),
    numPorts: host?.numPorts ?? 0,
    forwardingConfigs: host?.forwardingConfigs ?? [],
  };
};

const upsertHostWithMachine = (hosts, machine) => {
  const existingHostIndex = hosts.findIndex((host) => host.id === machine._id);

  if (existingHostIndex === -1) {
    return [...hosts, mergeMachineIntoHost(null, machine)];
  }

  return hosts.map((host) =>
    host.id === machine._id ? mergeMachineIntoHost(host, machine) : host
  );
};

const MACHINE_PAGE_SIZE_OPTIONS = [
  { value: "10", label: "10" },
  { value: "25", label: "25" },
  { value: "50", label: "50" },
  { value: "100", label: "100" },
];

const ALL_GROUPS_FILTER = "all";
export default function Home({ onStatsChange, active = true }) {
  const router = useRouter();
  const { colorScheme } = useMantineColorScheme();
  const isDark = colorScheme === "dark";
  const socket = useContext(SocketContext);
  const [hosts, setHosts] = useWorkspaceState("machines.hosts", []);
  const [privateAccess] = useWorkspaceState("access.data", null);
  const [selectedHostId, setSelectedHostId] = useState(null);
  const [configStartSection, setConfigStartSection] = useState("groups");
  const [isLoading, setIsLoading] = useWorkspaceState("machines.loading", true);
  const [isSaving, setIsSaving] = useState(false);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isCreatingMachine, setIsCreatingMachine] = useState(false);
  const [pageSize, setPageSize] = useState("25");
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState("name");
  const [groupFilter, setGroupFilter] = useState(ALL_GROUPS_FILTER);
  const [machineGroups, setMachineGroups] = useWorkspaceState("machines.groups", []);
  const [isGroupsModalOpen, setIsGroupsModalOpen] = useState(false);
  const [lastSeenRefreshTick, setLastSeenRefreshTick] = useState(0);
  const [machineTrafficByHostId, setMachineTrafficByHostId] = useWorkspaceState("machines.traffic", {});
  const { success, error } = useToast();
  useCreateFromUrl("machines", () => setIsCreateModalOpen(true), active);
  useEffect(() => {
    if (router.query.machine) setSelectedHostId(String(router.query.machine));
    if (["online", "offline", "disabled"].includes(router.query.status)) setStatusFilter(String(router.query.status));
  }, [router.query.machine, router.query.status]);

  const selectedHost = hosts.find((host) => host.id === selectedHostId) || null;
  const selectedGroupFilterLabel = useMemo(() => {
    if (groupFilter === ALL_GROUPS_FILTER) {
      return "All groups";
    }
    return machineGroups.find((group) => group._id === groupFilter)?.name || "Group";
  }, [groupFilter, machineGroups]);
  const groupLabelById = useMemo(
    () => Object.fromEntries(machineGroups.map((group) => [group._id, group.name])),
    [machineGroups]
  );
  const groupsWithMachineCounts = useMemo(
    () =>
      machineGroups.map((group) => ({
        ...group,
        machineCount: hosts.filter((host) =>
          (host.groupIds || []).includes(group._id)
        ).length,
      })),
    [hosts, machineGroups]
  );

  const machineTrafficMetrics = useMemo(() => isTrafficSort(sort)
    ? new Map(hosts.map(host => [host.id, trafficSummary(machineTrafficByHostId[host.id] || [], 30)]))
    : new Map(), [hosts, machineTrafficByHostId, sort]);
  const filteredHosts = useMemo(
    () =>
      hosts.filter((host) => {
        if (!Number.isFinite(searchScore(query, [host.name, host.hostname, host.localIp, host.publicIp, ...(host.privateIps || []), ...(host.forwardingConfigs || []).flatMap(c => [c.serviceName, c.internalPort, c.externalPort])]))) return false;
        const disabled = host.enabled === false || host.connectionStatus === "disabled";
        const matchesStatus =
          statusFilter === "all"
            ? !disabled
            : statusFilter === "disabled"
              ? disabled
              : statusFilter === "online"
                ? host.isActive
                : !host.isActive;

        if (!matchesStatus) {
          return false;
        }

        if (groupFilter === ALL_GROUPS_FILTER) {
          return true;
        }

        const hostGroupIds = Array.isArray(host.groupIds) ? host.groupIds : [];
        return hostGroupIds.includes(groupFilter);
      }).sort((a, b) => {
        const entry = host => ({ id: host.id, name: host.name, createdAt: host.createdAt, traffic: machineTrafficMetrics.get(host.id) });
        return compareInventoryEntries(entry(a), entry(b), sort);
      }),
    [groupFilter, hosts, statusFilter, query, sort, machineTrafficMetrics]
  );

  const numericPageSize = Number(pageSize);
  const totalPages = Math.max(1, Math.ceil(filteredHosts.length / numericPageSize));
  const paginatedHosts = useMemo(
    () =>
      filteredHosts.slice(
        (page - 1) * numericPageSize,
        page * numericPageSize
      ),
    [filteredHosts, numericPageSize, page]
  );

  useEffect(() => {
    if (page > totalPages) {
      setPage(totalPages);
    }
  }, [page, totalPages]);

  useEffect(() => {
    if (!active) return undefined;
    const intervalId = window.setInterval(() => {
      setLastSeenRefreshTick((current) => current + 1);
    }, 60 * 1000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [active]);

  useEffect(() => {
    if (!active) {
      setSelectedHostId(null);
      setIsCreateModalOpen(false);
      setIsGroupsModalOpen(false);
    }
  }, [active]);

  useEffect(() => {
    setHosts((currentHosts) =>
      currentHosts.map((host) => ({
        ...host,
        lastSeen: host.lastSeenAt
          ? formatRelativeFromNow(parseServerTimestamp(host.lastSeenAt))
          : "Never seen",
      }))
    );
  }, [lastSeenRefreshTick]);

  useEffect(() => {
    setPage(1);
  }, [groupFilter, pageSize, statusFilter, query, sort]);

  useEffect(() => {
    if (
      groupFilter !== ALL_GROUPS_FILTER &&
      !machineGroups.some((group) => group._id === groupFilter)
    ) {
      setGroupFilter(ALL_GROUPS_FILTER);
    }
  }, [groupFilter, machineGroups]);

  useEffect(() => {
    if (!onStatsChange) {
      return;
    }

    let online = 0;
    let offline = 0;

    hosts.forEach((host) => {
      if (host.isActive) {
        online += 1;
      } else {
        offline += 1;
      }
    });

    onStatsChange({
      registered: hosts.length,
      online,
      offline,
    });
  }, [hosts, onStatsChange]);

  useEffect(() => {
    const controller = new AbortController();
    const loadData = async () => {
      try {
        const [machinesResponse, connectionsResponse, groupsResponse] = await Promise.all([
          axios.get(apiRoutes.listMachines, { signal: controller.signal }),
          axios.get(apiRoutes.listConnections, { signal: controller.signal }),
          axios.get(apiRoutes.listGroups, { signal: controller.signal }).catch(() => ({ data: { data: [] } })),
        ]);

        if (controller.signal.aborted) return;

        const machines = machinesResponse.data?.data || [];
        const connections = connectionsResponse.data?.data || [];
        setMachineGroups(groupsResponse.data?.data || []);

        setHosts((currentHosts) => {
          const previousHosts = new Map(currentHosts.map((host) => [host.id, host]));
          return machines.map((machine) => {
            const hostConnections = connections.filter(
              (item) => item.machine_id === machine._id
            );

            return {
              ...mergeMachineIntoHost(previousHosts.get(machine._id), machine),
              numPorts: hostConnections.filter((item) => item.enabled !== false).length,
              forwardingConfigs: hostConnections.map(mapConnectionToForwardingConfig),
            };
          });
        });
      } catch (loadError) {
        if (axios.isCancel(loadError)) return;
        if (loadError?.response?.data?.detail !== "User not logged in") {
          error("Could not load saved machines");
        }
      } finally {
        if (!controller.signal.aborted) setIsLoading(false);
      }
    };

    loadData();
    return () => controller.abort();
  }, []);

  useEffect(() => {
    if (!socket) {
      return undefined;
    }

    const requestMachineStatusSnapshot = () => {
      socket.emit(socketRoutes.ctsMachineStatusSnapshot);
    };

    const handleMachineStatusSnapshot = (payload) => {
      const machines = payload?.machines || [];

      if (machines.length === 0) {
        return;
      }

      setHosts((currentHosts) =>
        machines.reduce(
          (nextHosts, machine) => upsertHostWithMachine(nextHosts, machine),
          currentHosts
        )
      );
    };

    const handleMachineStatusChanged = (payload) => {
      const machine = payload?.machine;

      if (!machine?._id) {
        return;
      }

      setHosts((currentHosts) => upsertHostWithMachine(currentHosts, machine));
    };

    if (socket.connected) {
      requestMachineStatusSnapshot();
    }

    const snapshotIntervalId = active ? window.setInterval(() => {
      if (socket.connected) requestMachineStatusSnapshot();
    }, 30 * 1000) : null;

    socket.on("connect", requestMachineStatusSnapshot);
    socket.on(socketRoutes.stcMachineStatusSnapshot, handleMachineStatusSnapshot);
    socket.on(socketRoutes.stcMachineStatusChanged, handleMachineStatusChanged);

    return () => {
      window.clearInterval(snapshotIntervalId);
      socket.off("connect", requestMachineStatusSnapshot);
      socket.off(socketRoutes.stcMachineStatusSnapshot, handleMachineStatusSnapshot);
      socket.off(socketRoutes.stcMachineStatusChanged, handleMachineStatusChanged);
    };
  }, [socket, active]);

  // Port inventory changes independently of presence (CLI exposures, expiry,
  // and edits in another browser). Coalesce bursts without polling while idle.
  useEffect(() => {
    if (!socket) return;
    const controller = new AbortController();
    let running = false;
    let pending = false;
    let timer;
    const refresh = async () => {
      pending = true;
      if (running) return;
      running = true;
      try {
        while (pending && !controller.signal.aborted) {
          pending = false;
          const response = await axios.get(apiRoutes.listConnections, { signal: controller.signal });
          if (controller.signal.aborted) return;
          const byMachine = new Map();
          for (const connection of response.data?.data || []) {
            const entries = byMachine.get(connection.machine_id) || [];
            entries.push(mapConnectionToForwardingConfig(connection));
            byMachine.set(connection.machine_id, entries);
          }
          setHosts(current => current.map(host => {
            const configs = byMachine.get(host.id) || [];
            if (JSON.stringify(configs) === JSON.stringify(host.forwardingConfigs)) return host;
            return { ...host, forwardingConfigs: configs, numPorts: configs.filter(config => config.enabled !== false).length };
          }));
        }
      } catch (cause) {
        // Reconnect, tab activation, or the next notification refreshes again.
      } finally { running = false; }
    };
    const schedule = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(refresh, 100);
    };
    const visible = () => { if (active && !document.hidden) schedule(); };
    socket.on(socketRoutes.stcMachineConnectionsChanged, schedule);
    socket.on("connect", schedule);
    document.addEventListener("visibilitychange", visible);
    if (active && !isLoading) schedule();
    return () => {
      controller.abort();
      window.clearTimeout(timer);
      socket.off(socketRoutes.stcMachineConnectionsChanged, schedule);
      socket.off("connect", schedule);
      document.removeEventListener("visibilitychange", visible);
    };
  }, [socket, active, isLoading]);

  // Traffic ordering must rank the entire fleet, not only the current page.
  // Key requests by stable IDs so sorting a fresh snapshot cannot restart polls.
  const trafficTargets = (isTrafficSort(sort) ? hosts : paginatedHosts).flatMap(host =>
    (host.forwardingConfigs || []).filter(config => config.dataId).map(config => [config.dataId, host.id]));
  const trafficTargetKey = JSON.stringify(trafficTargets.sort(([a], [b]) => a.localeCompare(b)));
  const privateDnsSuffix = String(privateAccess?.network?.dns_suffix || "").trim().replace(/^\.+|\.+$/g, "");
  const defaultPrivateDomain = host => {
    if (!privateDnsSuffix) return "";
    const peer = (privateAccess?.private_peers || []).find(item => item.machine_id === host.id);
    const label = String(peer?.hostname || "").trim();
    return label ? `${label}.${privateDnsSuffix}` : "";
  };
  const privateDomain = host => {
    const configured = Array.isArray(host.privateDomains) ? host.privateDomains : [];
    const first = configured[0];
    return first?.default ? defaultPrivateDomain(host) : first?.host && first?.suffix
      ? `${first.host}.${first.suffix}`
      : defaultPrivateDomain(host);
  };
  useEffect(() => {
    const targets = JSON.parse(trafficTargetKey);
    if (targets.length === 0) {
      setMachineTrafficByHostId({});
      return;
    }

    const hostIdByConnectionId = {};
    const dataIds = [];

    targets.forEach(([connectionId, hostId]) => {
      hostIdByConnectionId[connectionId] = hostId;
      dataIds.push(connectionId);
    });

    if (dataIds.length === 0) {
      setMachineTrafficByHostId(
        {}
      );
      return;
    }

    let isActive = true;
    const controller = new AbortController();
    let timeout;

    const loadMachineTraffic = async () => {
      try {
        const response = await axios.post(apiRoutes.trafficSnapshot, {
          data_ids: dataIds,
        }, { signal: controller.signal });

        if (!isActive) {
          return;
        }

        const nextTrafficByHostId = Object.fromEntries(
          [...new Set(targets.map(([, hostId]) => hostId))].map(id => [id, []])
        );

        (Array.isArray(response.data?.data) ? response.data.data : []).forEach((item) => {
          const connectionId = item?.connection?._id;
          const hostId = hostIdByConnectionId[connectionId];
          if (!hostId) {
            return;
          }

          nextTrafficByHostId[hostId] = mergeMachineTrafficSamples([
            ...(nextTrafficByHostId[hostId] || []),
            ...(Array.isArray(item?.traffic) ? item.traffic : []),
          ]);
        });

        setMachineTrafficByHostId(nextTrafficByHostId);
      } catch {
        if (!isActive) {
          return;
        }

        setMachineTrafficByHostId((current) =>
          Object.fromEntries(
            [...new Set(targets.map(([, hostId]) => hostId))].map(id => [id, current[id] || []])
          )
        );
      } finally {
        if (isActive && active) timeout = setTimeout(loadMachineTraffic, 2000);
      }
    };

    loadMachineTraffic();

    return () => {
      isActive = false;
      clearTimeout(timeout);
      controller.abort();
    };
  }, [trafficTargetKey, active]);

  const handleOpenConfig = (hostId) => { setConfigStartSection("groups"); setSelectedHostId(hostId); };

  const handleCloseConfig = () => { setSelectedHostId(null); setConfigStartSection("groups"); };

  const handleCreateMachine = async (machine) => {
    setIsCreatingMachine(true);

    try {
      const payload = {
        name: machine.name,
        hostname: machine.hostname || "",
      };
      if (machine.group_ids?.length) {
        payload.group_ids = machine.group_ids;
      }
      const response = await axios.post(apiRoutes.addMachine, payload);
      const createdHost = mapMachineToHost(response.data.data);

      setHosts((currentHosts) => [...currentHosts, createdHost]);
      setConfigStartSection("credentials");
      setSelectedHostId(createdHost.id);
      setIsCreateModalOpen(false);
      success(`Machine ${createdHost.name} created`);
      return true;
    } catch (createError) {
      error(createError?.response?.data?.detail || "Could not create machine");
      return false;
    } finally {
      setIsCreatingMachine(false);
    }
  };

  const handleSaveConfig = async (hostId, forwardingConfigs) => {
    const currentHost = hosts.find((host) => host.id === hostId);
    if (!currentHost) {
      return false;
    }

    const currentConfigs = currentHost.forwardingConfigs || [];
    const currentConfigsById = new Map(
      currentConfigs.filter((config) => config.dataId).map((config) => [config.dataId, config])
    );
    const nextConfigIds = new Set(
      forwardingConfigs.filter((config) => config.dataId).map((config) => config.dataId)
    );
    const configsToDelete = currentConfigs.filter(
      (config) => config.dataId && !config.temporary && !nextConfigIds.has(config.dataId)
    );
    const configsToCreate = forwardingConfigs.filter((config) => !config.dataId && !config.temporary);
    const configsToUpdate = forwardingConfigs.filter(
      (config) =>
        config.dataId &&
        !config.temporary &&
        forwardingConfigChanged(currentConfigsById.get(config.dataId), config)
    );

    setIsSaving(true);

    try {
      const machineResponse = {
        data: {
          data: {
            _id: currentHost.id,
            name: currentHost.name,
            hostname: currentHost.hostname,
            client_hostname: currentHost.clientHostname,
            hostname_override: currentHost.hostnameOverride,
            local_ip: currentHost.localIp,
            public_ip: currentHost.publicIp,
            token: currentHost.token,
            is_active: currentHost.isActive,
            connection_status:
              currentHost.connectionStatus ||
              (currentHost.enabled === false
                ? "disabled"
                : currentHost.isActive
                  ? "online"
                  : "offline"),
            auth_required: currentHost.authRequired ?? false,
            last_seen_at: currentHost.lastSeenAt,
            group_ids: currentHost.groupIds || [],
          },
        },
      };

      for (const config of configsToDelete) {
        await axios.post(apiRoutes.deleteConnection, {
          data_id: config.dataId,
        });
      }

      const savedConfigsById = new Map();
      const createdSavedConfigs = [];

      forwardingConfigs
        .filter((config) => config.dataId && !configsToDelete.some((deleted) => deleted.dataId === config.dataId))
        .filter((config) => !configsToUpdate.some((updated) => updated.dataId === config.dataId))
        .forEach((config) => {
          const normalizedFirewall = normalizeFirewallPolicy(config);

          savedConfigsById.set(config.dataId, {
            dataId: config.dataId,
            serviceName: config.serviceName,
            serviceDescription: config.serviceDescription,
            internalIp: config.internalIp,
            internalPort: Number(config.internalPort),
            externalPort: Number(config.externalPort),
            enabled: config.enabled,
            temporary: config.temporary === true,
            managedBy: config.managedBy || "",
            autoRefreshEnabled: config.autoRefreshEnabled ?? false,
            autoRefreshIntervalMinutes: Number(config.autoRefreshIntervalMinutes) || 60,
            autoRefreshedAt: config.autoRefreshedAt || null,
            autoRefreshNextAt: config.autoRefreshNextAt || null,
            firewall: {
              isPublic: normalizedFirewall.isPublic,
              allowedIps: normalizedFirewall.allowedIps,
            },
          });
        });

      for (const config of configsToUpdate) {
        const payload = {
          data_id: config.dataId,
          machine_id: currentHost.id,
          service_name: config.serviceName,
          service_description: config.serviceDescription,
          internalIp: config.internalIp,
          internal_port: Number(config.internalPort),
          external_port: Number(config.externalPort),
          enabled: config.enabled,
          autoRefreshEnabled: config.autoRefreshEnabled ?? false,
          autoRefreshIntervalMinutes:
            Number(config.autoRefreshIntervalMinutes) || 60,
          auto_refresh_enabled: config.autoRefreshEnabled ?? false,
          auto_refresh_interval_minutes: Number(config.autoRefreshIntervalMinutes) || 60,
        };

        const response = config.dataId
          ? await axios.put(apiRoutes.updateConnection, payload)
          : await axios.post(apiRoutes.addConnection, payload);

        const savedConfig = mapConnectionToForwardingConfig(response.data.data);
        const normalizedFirewall = normalizeFirewallPolicy(config);
        const firewallResponse = await axios.put(apiRoutes.updateConnectionFirewallPolicy, {
          data_id: savedConfig.dataId,
          is_public: normalizedFirewall.isPublic,
          allowed_ips: normalizedFirewall.allowedIps,
        });

        savedConfigsById.set(savedConfig.dataId, {
          ...savedConfig,
          autoRefreshEnabled:
            config.autoRefreshEnabled ?? savedConfig.autoRefreshEnabled ?? false,
          autoRefreshIntervalMinutes:
            Number(config.autoRefreshIntervalMinutes) ||
            Number(savedConfig.autoRefreshIntervalMinutes) ||
            60,
          firewall: {
            isPublic: firewallResponse.data?.data?.firewall?.is_public ?? normalizedFirewall.isPublic,
            allowedIps:
              firewallResponse.data?.data?.firewall?.allowed_ips ??
              normalizedFirewall.allowedIps,
          },
        });
      }

      for (const config of configsToCreate) {
        const payload = {
          data_id: config.dataId,
          machine_id: currentHost.id,
          service_name: config.serviceName,
          service_description: config.serviceDescription,
          internalIp: config.internalIp,
          internal_port: Number(config.internalPort),
          external_port: Number(config.externalPort),
          enabled: config.enabled,
          autoRefreshEnabled: config.autoRefreshEnabled ?? false,
          autoRefreshIntervalMinutes:
            Number(config.autoRefreshIntervalMinutes) || 60,
          auto_refresh_enabled: config.autoRefreshEnabled ?? false,
          auto_refresh_interval_minutes: Number(config.autoRefreshIntervalMinutes) || 60,
        };

        const response = await axios.post(apiRoutes.addConnection, payload);
        const savedConfig = mapConnectionToForwardingConfig(response.data.data);
        const normalizedFirewall = normalizeFirewallPolicy(config);
        const firewallResponse = await axios.put(apiRoutes.updateConnectionFirewallPolicy, {
          data_id: savedConfig.dataId,
          is_public: normalizedFirewall.isPublic,
          allowed_ips: normalizedFirewall.allowedIps,
        });

        createdSavedConfigs.push({
          ...savedConfig,
          autoRefreshEnabled:
            config.autoRefreshEnabled ?? savedConfig.autoRefreshEnabled ?? false,
          autoRefreshIntervalMinutes:
            Number(config.autoRefreshIntervalMinutes) ||
            Number(savedConfig.autoRefreshIntervalMinutes) ||
            60,
          firewall: {
            isPublic: firewallResponse.data?.data?.firewall?.is_public ?? normalizedFirewall.isPublic,
            allowedIps:
              firewallResponse.data?.data?.firewall?.allowed_ips ??
              normalizedFirewall.allowedIps,
          },
        });
      }

      let createdConfigIndex = 0;
      const savedConfigs = forwardingConfigs
        .map((config) => {
          if (config.dataId) {
            return savedConfigsById.get(config.dataId);
          }

          const createdConfig = createdSavedConfigs[createdConfigIndex];
          createdConfigIndex += 1;
          return createdConfig;
        })
        .filter(Boolean);

      setHosts((currentHosts) =>
        currentHosts.map((host) =>
          host.id === hostId
            ? {
              ...mergeMachineIntoHost(host, machineResponse.data.data),
              numPorts: savedConfigs.filter((config) => config.enabled !== false).length,
              forwardingConfigs: savedConfigs,
            }
            : host
        )
      );

      success(`Saved port forwarding config for ${currentHost.name}`);
      return true;
    } catch (saveError) {
      error(saveError?.response?.data?.detail || "Could not save port config");
      return false;
    } finally {
      setIsSaving(false);
    }
  };

  const handleDeleteMachine = async (hostId) => {
    const currentHost = hosts.find((host) => host.id === hostId);
    if (!currentHost) {
      return false;
    }

    try {
      await axios.post(apiRoutes.deleteMachine, {
        data_id: hostId,
      });

      setHosts((currentHosts) =>
        currentHosts.filter((host) => host.id !== hostId)
      );
      setSelectedHostId(null);
      success(`Machine ${currentHost.name} deleted`);
      return true;
    } catch (deleteError) {
      error(deleteError?.response?.data?.detail || "Could not delete machine");
      return false;
    }
  };

  const handleRefreshMachineToken = async (hostId) => {
    try {
      const response = await axios.post(apiRoutes.refreshMachineToken, {
        data_id: hostId,
      });
      const refreshedHost = mapMachineToHost(response.data.data);

      setHosts((currentHosts) =>
        currentHosts.map((host) =>
          host.id === hostId
            ? {
              ...host,
              token: refreshedHost.token,
            }
            : host
        )
      );

      success(`Machine token refreshed for ${refreshedHost.name}`);
      return refreshedHost;
    } catch (refreshError) {
      error(refreshError?.response?.data?.detail || "Could not refresh machine token");
      return null;
    }
  };

  const handleToggleMachine = async (hostId, nextEnabled) => {
    const currentHost = hosts.find((host) => host.id === hostId);
    if (!currentHost) {
      return false;
    }

    try {
      const response = await axios.put(apiRoutes.updateMachine, {
        data_id: currentHost.id,
        name: currentHost.name,
        hostname: currentHost.hostnameOverride || "",
        enabled: nextEnabled,
      });
      const updatedHost = mapMachineToHost(response.data.data);

      setHosts((currentHosts) =>
        currentHosts.map((host) =>
          host.id === hostId
            ? {
              ...host,
              ...updatedHost,
              numPorts: host.numPorts,
              forwardingConfigs: host.forwardingConfigs,
            }
            : host
        )
      );

      success(
        `Machine ${currentHost.name} ${nextEnabled ? "enabled" : "disabled"}`
      );
      return true;
    } catch (toggleError) {
      error(
        toggleError?.response?.data?.detail ||
        `Could not ${nextEnabled ? "enable" : "disable"} machine`
      );
      return false;
    }
  };

  const handleToggleTelegramAlerts = async (hostId, nextExcluded) => {
    const currentHost = hosts.find((host) => host.id === hostId);
    if (!currentHost) {
      return false;
    }

    try {
      const response = await axios.put(apiRoutes.updateMachine, {
        data_id: currentHost.id,
        name: currentHost.name,
        hostname: currentHost.hostnameOverride || "",
        enabled: currentHost.enabled,
        telegram_alerts_excluded: nextExcluded,
      });
      const updatedHost = mapMachineToHost(response.data.data);

      setHosts((currentHosts) =>
        currentHosts.map((host) =>
          host.id === hostId
            ? {
              ...host,
              ...updatedHost,
              numPorts: host.numPorts,
              forwardingConfigs: host.forwardingConfigs,
            }
            : host
        )
      );

      success(
        `Telegram alerts ${nextExcluded ? "excluded" : "included"} for ${currentHost.name}`
      );
      return true;
    } catch (toggleError) {
      error(
        toggleError?.response?.data?.detail || "Could not update Telegram alert settings"
      );
      return false;
    }
  };

  const handleUpdateMachineDetails = async (hostId, details) => {
    const currentHost = hosts.find((host) => host.id === hostId);
    if (!currentHost) {
      return false;
    }

    try {
      const response = await axios.put(apiRoutes.updateMachine, {
        data_id: currentHost.id,
        name: details.name,
        hostname: details.hostname,
        private_domains: details.privateDomains,
        enabled: currentHost.enabled,
      });
      const updatedHost = mapMachineToHost(response.data.data);

      setHosts((currentHosts) =>
        currentHosts.map((host) =>
          host.id === hostId
            ? {
                ...host,
                ...updatedHost,
                numPorts: host.numPorts,
                forwardingConfigs: host.forwardingConfigs,
              }
            : host
        )
      );

      success(`Updated machine details for ${details.name}`);
      return true;
    } catch (updateError) {
      error(updateError?.response?.data?.detail || "Could not update machine details");
      return false;
    }
  };

  const handleUpdateClientSetup = async (hostId, clientSetup) => {
    const currentHost = hosts.find((host) => host.id === hostId);
    if (!currentHost) {
      return null;
    }

    try {
      const response = await axios.put(apiRoutes.updateMachine, {
        data_id: currentHost.id,
        name: currentHost.name,
        hostname: currentHost.hostnameOverride || "",
        enabled: currentHost.enabled,
        client_setup_public_base_url: clientSetup.publicBaseUrl || "",
        client_setup_rathole_server_address:
          clientSetup.ratholeServerAddress || "",
        client_setup_service_domain: clientSetup.serviceDomain || "",
      });
      const updatedHost = mapMachineToHost(response.data.data);

      setHosts((currentHosts) =>
        currentHosts.map((host) =>
          host.id === hostId
            ? {
                ...host,
                ...updatedHost,
                numPorts: host.numPorts,
                forwardingConfigs: host.forwardingConfigs,
              }
            : host
        )
      );

      success(`Updated client setup for ${currentHost.name}`);
      return updatedHost;
    } catch (updateError) {
      error(updateError?.response?.data?.detail || "Could not update client setup");
      return null;
    }
  };

  const handleRequestClientUpdate = async (hostId) => {
    const currentHost = hosts.find((host) => host.id === hostId);
    if (!currentHost) {
      return null;
    }

    try {
      const response = await axios.post(apiRoutes.requestClientUpdate, {
        data_id: hostId,
      });
      const updatedHost = mapMachineToHost(response.data.data);

      setHosts((currentHosts) =>
        currentHosts.map((host) =>
          host.id === hostId
            ? {
              ...host,
              ...updatedHost,
              numPorts: host.numPorts,
              forwardingConfigs: host.forwardingConfigs,
            }
            : host
        )
      );

      success(`Requested client update for ${currentHost.name}`);
      return updatedHost;
    } catch (requestError) {
      error(
        requestError?.response?.data?.detail || "Could not request client update"
      );
      return null;
    }
  };

  const handleRefreshConnection = async (hostId, connectionId) => {
    const currentHost = hosts.find((host) => host.id === hostId);
    if (!currentHost || !connectionId) {
      return null;
    }

    try {
      const response = await axios.post(apiRoutes.refreshConnection, {
        data_id: connectionId,
      });
      const refreshedConfig = mapConnectionToForwardingConfig(response.data.data);

      setHosts((currentHosts) =>
        currentHosts.map((host) =>
          host.id === hostId
            ? {
              ...host,
              numPorts: (host.forwardingConfigs || []).filter((config) =>
                config.dataId === refreshedConfig.dataId
                  ? refreshedConfig.enabled !== false
                  : config.enabled !== false
              ).length,
              forwardingConfigs: (host.forwardingConfigs || []).map((config) =>
                config.dataId === refreshedConfig.dataId ? refreshedConfig : config
              ),
            }
            : host
        )
      );

      success(`Refreshed ${refreshedConfig.serviceName || "service"}`);
      return refreshedConfig;
    } catch (refreshError) {
      error(refreshError?.response?.data?.detail || "Could not refresh service");
      return null;
    }
  };

  const mergeHostAfterMachineResponse = (hostId, machinePayload) => {
    const updated = mapMachineToHost(machinePayload);
    setHosts((currentHosts) =>
      currentHosts.map((host) =>
        host.id === hostId
          ? {
            ...host,
            ...updated,
            numPorts: host.numPorts,
            forwardingConfigs: host.forwardingConfigs,
          }
          : host
      )
    );
  };

  const handleAddMachineToGroup = async (hostId, groupId) => {
    const response = await axios.post(apiRoutes.addMachineToGroup, {
      machine_id: hostId,
      group_id: groupId,
    });
    mergeHostAfterMachineResponse(hostId, response.data.data);
  };

  const handleRemoveMachineFromGroup = async (hostId, groupId) => {
    const response = await axios.post(apiRoutes.removeMachineFromGroup, {
      machine_id: hostId,
      group_id: groupId,
    });
    mergeHostAfterMachineResponse(hostId, response.data.data);
  };

  const reloadMachineGroups = async () => {
    const res = await axios.get(apiRoutes.listGroups);
    setMachineGroups(res.data?.data || []);
  };

  const handleCreateGroup = async (name) => {
    try {
      const response = await axios.post(apiRoutes.addGroup, { name });
      await reloadMachineGroups();
      success(`Group "${name}" created`);
      return response.data?.data || { name };
    } catch (createGroupError) {
      error(createGroupError?.response?.data?.detail || "Could not create group");
      return false;
    }
  };

  const handleRenameGroup = async (groupId, name) => {
    try {
      await axios.put(apiRoutes.updateGroup, { data_id: groupId, name });
      await reloadMachineGroups();
      success("Group renamed");
      return true;
    } catch (renameError) {
      error(renameError?.response?.data?.detail || "Could not rename group");
      return false;
    }
  };

  const handleDeleteGroup = async (groupId) => {
    try {
      await axios.post(apiRoutes.deleteGroup, { data_id: groupId });
      setHosts((currentHosts) =>
        currentHosts.map((host) => ({
          ...host,
          groupIds: (host.groupIds || []).filter((id) => id !== groupId),
        }))
      );
      await reloadMachineGroups();
      success("Group deleted");
    } catch (deleteGroupError) {
      error(deleteGroupError?.response?.data?.detail || "Could not delete group");
    }
  };

  return (
    <div className="flex h-full min-h-0 justify-center">
      <div className="workspace-page">
        <PageHeader eyebrow="Infrastructure" title="Machines" description="Your fleet at a glance. Manage ports, public addresses, and client connections." />

        <div className="machine-list-pane flex min-h-0 flex-1 flex-col">
          {isLoading ? (
            <p className="text-sm text-zinc-500 dark:text-zinc-400">
              Loading machines...
            </p>
          ) : (
            <>
              {hosts.length === 0 ? (
                <div className="rounded-2xl border border-dashed border-zinc-300 bg-zinc-50 px-6 py-10 text-center dark:border-zinc-700 dark:bg-zinc-900/60">
                  <p className="text-lg font-medium text-zinc-900 dark:text-zinc-100">
                    No machines yet
                  </p>
                  <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">
                    Create the first machine, copy its token or bootstrap command, then
                    start adding port pairs.
                  </p>
                  <WorkspaceButton className="mt-4" onClick={() => setIsCreateModalOpen(true)}><IconPlus size={16} />Create machine</WorkspaceButton>
                </div>
              ) : (
                <>
                  <InventoryToolbar label="Machine tools"
                    search={<SearchField label="Search machines" value={query} onChange={setQuery} placeholder="Search machines…" />}
                    status={<StatusTabs label="Machine status" value={statusFilter} onChange={setStatusFilter} options={[{value:"all",label:"All"},{value:"online",label:"Online"},{value:"offline",label:"Offline"}]} />}
                    filtered={groupFilter !== ALL_GROUPS_FILTER || sort !== "name"}
                    filters={[
                      {label:"Group",control:<SearchSelect label="Filter machine group" value={groupFilter} onChange={setGroupFilter} options={[{value:ALL_GROUPS_FILTER,label:"All groups"},...machineGroups.map(group=>({value:group._id,label:group.name}))]} />},
                      {label:"Sort machines",control:<SearchSelect label="Sort machines" value={sort} onChange={setSort} options={INVENTORY_SORT_OPTIONS} />},
                    ]}
                    secondaryActions={<WorkspaceButton variant="secondary" aria-label="Groups" onClick={()=>setIsGroupsModalOpen(true)}><IconFolder size={16} />Groups</WorkspaceButton>}
                    primaryActions={<WorkspaceButton aria-label="Create machine" onClick={()=>setIsCreateModalOpen(true)}><IconPlus size={16} /><span className="md:hidden">Create</span><span className="hidden md:inline">Create machine</span></WorkspaceButton>}
                  />

                  <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-xl bg-surface">

                    {paginatedHosts.length > 0 ? (
                      <div
                        className="data-scroll"
                        style={{ scrollbarGutter: "stable" }}
                      >
                        <Table aria-label="Machines"><TableHeader><TableRow><TableHead>Machine</TableHead><TableHead className="hidden w-[22%] lg:table-cell">Connection</TableHead><TableHead className="hidden w-[20%] md:table-cell">Group</TableHead><TableHead className="w-20 text-right">Ports</TableHead><TableHead className="hidden w-56 text-right lg:table-cell">Traffic · 30s</TableHead></TableRow></TableHeader><TableBody>
                          {paginatedHosts.map((host) => (
                            <HostItem
                              key={host.id}
                              machineId={host.id}
                              name={host.name}
                              privateDomain={privateDomain(host)}
                              defaultPrivateDomain={defaultPrivateDomain(host)}
                              hostname={host.hostname}
                              clientOs={host.clientOs}
                              clientOsId={host.clientOsId}
                              clientOsName={host.clientOsName}
                              clientArch={host.clientArch}
                              clientCountry={host.clientCountry}
                              groupLabels={(host.groupIds || [])
                                .map((id) => groupLabelById[id])
                                .filter(Boolean)}
                              localIp={host.localIp}
                              privateIps={host.privateIps}
                              clientVersion={host.clientVersion}
                              clientUpdateAvailable={host.clientUpdateAvailable}
                              latestClientVersion={host.latestClientVersion}
                              forwardingConfigs={host.forwardingConfigs}
                              isActive={host.isActive}
                              connectionStatus={host.connectionStatus}
                              isDark={isDark}
                              numPorts={host.numPorts}
                              showGroupColumn
                              showPublicIp={false}
                              showStatus={false}
                              showLastSeen
                              lastSeen={host.lastSeen}
                              trafficSamples={machineTrafficByHostId[host.id] || []}
                              onClick={() => handleOpenConfig(host.id)}
                            />
                          ))}
                        </TableBody></Table>
                      </div>
                    ) : (
                      <div className="px-5 py-10 text-center">
                        <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">
                          No machines match the current filters
                        </p>
                        <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">
                          Adjust the status filter to see more machines.
                        </p>
                      </div>
                    )}

                    {filteredHosts.length > 0 ? (
                      <ResultsPagination count={filteredHosts.length} noun="Machines" page={page} pages={totalPages} pageSize={numericPageSize} onPage={setPage} onPageSize={setPageSize} sizes={MACHINE_PAGE_SIZE_OPTIONS.map(option => Number(option.value))} />
                    ) : null}
                  </div>
                </>
              )}
            </>
          )}
        </div>
      </div>
      <MachineCreateModal
        opened={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onCreate={handleCreateMachine}
        isCreating={isCreatingMachine}
        groups={machineGroups}
      />
      <MachineGroupsModal
        opened={isGroupsModalOpen}
        onClose={() => setIsGroupsModalOpen(false)}
        groups={machineGroups}
        machines={hosts}
        onCreateGroup={handleCreateGroup}
        onRenameGroup={handleRenameGroup}
        onDeleteGroup={handleDeleteGroup}
        onAddMachineToGroup={handleAddMachineToGroup}
        onRemoveMachineFromGroup={handleRemoveMachineFromGroup}
      />
      <HostConfigPopup
        initialSection={configStartSection}
        host={selectedHost}
        privateDomain={selectedHost ? privateDomain(selectedHost) : ""}
        defaultPrivateDomain={selectedHost ? defaultPrivateDomain(selectedHost) : ""}
        privateDnsSuffix={privateDnsSuffix || "phub"}
        opened={Boolean(selectedHost)}
        onClose={handleCloseConfig}
        onSave={handleSaveConfig}
        onUpdateMachineDetails={handleUpdateMachineDetails}
        onUpdateClientSetup={handleUpdateClientSetup}
        onDeleteMachine={handleDeleteMachine}
        onToggleMachine={handleToggleMachine}
        onToggleTelegramAlerts={handleToggleTelegramAlerts}
        onRefreshMachineToken={handleRefreshMachineToken}
        onRequestClientUpdate={handleRequestClientUpdate}
        onRefreshConnection={handleRefreshConnection}
        onCreateGroup={handleCreateGroup}
        onAddMachineToGroup={handleAddMachineToGroup}
        onRemoveMachineFromGroup={handleRemoveMachineFromGroup}
        groups={groupsWithMachineCounts}
        isSaving={isSaving}
      />
    </div>
  );
}
