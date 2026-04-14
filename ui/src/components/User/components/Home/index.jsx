import { useContext, useEffect, useMemo, useState } from "react";
import axios from "axios";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
import utc from "dayjs/plugin/utc";
import {
  Button,
  Menu,
  Pagination,
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
import useToast from "@/shared/hooks/useToast";
import { SocketContext } from "@/shared/contexts/socket";
import apiRoutes from "@/shared/routes/apiRoutes";
import socketRoutes from "@/shared/routes/socketRoutes";

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

const mapConnectionToForwardingConfig = (connection) => ({
  dataId: connection._id,
  serviceName: connection.service_name || "",
  serviceDescription: connection.service_description || "",
  internalIp: connection.internal_ip || connection.internalIp || "0.0.0.0",
  internalPort: connection.internal_port || 3000,
  externalPort: connection.external_port || 3000,
  enabled: connection.enabled ?? true,
  firewall: {
    isPublic: connection.firewall?.is_public ?? true,
    allowedIps: Array.isArray(connection.firewall?.allowed_ips)
      ? connection.firewall.allowed_ips
      : [],
  },
});

const normalizeMachineTrafficSample = (sample) => ({
  timestamp: Number(sample?.timestamp) || 0,
  in_bytes: Math.max(0, Number(sample?.in_bytes) || 0),
  out_bytes: Math.max(0, Number(sample?.out_bytes) || 0),
  drop_bytes: Math.max(0, Number(sample?.drop_bytes) || 0),
});

const mergeMachineTrafficSamples = (samples) => {
  const byTimestamp = new Map();

  (Array.isArray(samples) ? samples : []).forEach((sample) => {
    const normalized = normalizeMachineTrafficSample(sample);
    if (normalized.timestamp <= 0) {
      return;
    }

    const timestamp = Math.floor(normalized.timestamp);
    const current = byTimestamp.get(timestamp) || {
      timestamp,
      in_bytes: 0,
      out_bytes: 0,
      drop_bytes: 0,
    };

    byTimestamp.set(timestamp, {
      timestamp,
      in_bytes: current.in_bytes + normalized.in_bytes,
      out_bytes: current.out_bytes + normalized.out_bytes,
      drop_bytes: current.drop_bytes + normalized.drop_bytes,
    });
  });

  return [...byTimestamp.values()]
    .sort((left, right) => left.timestamp - right.timestamp)
    .slice(-30);
};

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
  hostname: machine.hostname || "",
  clientHostname: machine.client_hostname || "",
  hostnameOverride: machine.hostname_override || "",
  groupIds: Array.isArray(machine.group_ids)
    ? machine.group_ids
    : machine.group_id
      ? [machine.group_id]
      : [],
  enabled: machine.enabled ?? true,
  localIp: machine.local_ip || "",
  publicIp: machine.public_ip || "",
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

  return {
    ...mappedHost,
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
export default function Home({ onStatsChange }) {
  const { colorScheme } = useMantineColorScheme();
  const isDark = colorScheme === "dark";
  const socket = useContext(SocketContext);
  const [hosts, setHosts] = useState([]);
  const [selectedHostId, setSelectedHostId] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isCreatingMachine, setIsCreatingMachine] = useState(false);
  const [pageSize, setPageSize] = useState("10");
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState("all");
  const [groupFilter, setGroupFilter] = useState(ALL_GROUPS_FILTER);
  const [machineGroups, setMachineGroups] = useState([]);
  const [isGroupsModalOpen, setIsGroupsModalOpen] = useState(false);
  const [lastSeenRefreshTick, setLastSeenRefreshTick] = useState(0);
  const [machineTrafficByHostId, setMachineTrafficByHostId] = useState({});
  const { success, error } = useToast();

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

  const filteredHosts = useMemo(
    () =>
      hosts.filter((host) => {
        const matchesStatus =
          statusFilter === "all" ||
          (statusFilter === "online" ? host.isActive : !host.isActive);

        if (!matchesStatus) {
          return false;
        }

        if (groupFilter === ALL_GROUPS_FILTER) {
          return true;
        }

        const hostGroupIds = Array.isArray(host.groupIds) ? host.groupIds : [];
        return hostGroupIds.includes(groupFilter);
      }),
    [groupFilter, hosts, statusFilter]
  );

  const numericPageSize = Number(pageSize);
  const totalPages = Math.max(1, Math.ceil(filteredHosts.length / numericPageSize));
  const visibleStart = filteredHosts.length === 0 ? 0 : (page - 1) * numericPageSize + 1;
  const visibleEnd = Math.min(page * numericPageSize, filteredHosts.length);
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
    const intervalId = window.setInterval(() => {
      setLastSeenRefreshTick((current) => current + 1);
    }, 60 * 1000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, []);

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
  }, [groupFilter, pageSize, statusFilter]);

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
      const resolvedStatus =
        host.connectionStatus ||
        (host.enabled === false
          ? "disabled"
          : host.isActive
            ? "online"
            : "offline");

      if (resolvedStatus === "disabled") {
        return;
      }

      if (resolvedStatus === "online" || resolvedStatus === "auth_required") {
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
    const loadData = async () => {
      setIsLoading(true);

      try {
        const [machinesResponse, connectionsResponse, groupsResponse] = await Promise.all([
          axios.get(apiRoutes.listMachines),
          axios.get(apiRoutes.listConnections),
          axios.get(apiRoutes.listGroups).catch(() => ({ data: { data: [] } })),
        ]);

        const machines = machinesResponse.data?.data || [];
        const connections = connectionsResponse.data?.data || [];
        setMachineGroups(groupsResponse.data?.data || []);

        setHosts(
          machines.map((machine) => {
            const hostConnections = connections.filter(
              (item) => item.machine_id === machine._id
            );

            return {
              ...mapMachineToHost(machine),
              numPorts: hostConnections.filter((item) => item.enabled !== false).length,
              forwardingConfigs: hostConnections.map(mapConnectionToForwardingConfig),
            };
          })
        );
      } catch (loadError) {
        if (loadError?.response?.data?.detail !== "User not logged in") {
          error("Could not load saved machines");
        }
      } finally {
        setIsLoading(false);
      }
    };

    loadData();
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

    const snapshotIntervalId = window.setInterval(() => {
      if (socket.connected) {
        requestMachineStatusSnapshot();
      }
    }, 30 * 1000);

    socket.on("connect", requestMachineStatusSnapshot);
    socket.on(socketRoutes.stcMachineStatusSnapshot, handleMachineStatusSnapshot);
    socket.on(socketRoutes.stcMachineStatusChanged, handleMachineStatusChanged);

    return () => {
      window.clearInterval(snapshotIntervalId);
      socket.off("connect", requestMachineStatusSnapshot);
      socket.off(socketRoutes.stcMachineStatusSnapshot, handleMachineStatusSnapshot);
      socket.off(socketRoutes.stcMachineStatusChanged, handleMachineStatusChanged);
    };
  }, [socket]);

  useEffect(() => {
    if (paginatedHosts.length === 0) {
      setMachineTrafficByHostId({});
      return;
    }

    const hostIdByConnectionId = {};
    const dataIds = [];

    paginatedHosts.forEach((host) => {
      (host.forwardingConfigs || []).forEach((config) => {
        if (!config.dataId) {
          return;
        }
        hostIdByConnectionId[config.dataId] = host.id;
        dataIds.push(config.dataId);
      });
    });

    if (dataIds.length === 0) {
      setMachineTrafficByHostId(
        Object.fromEntries(paginatedHosts.map((host) => [host.id, []]))
      );
      return;
    }

    let isActive = true;

    const loadMachineTraffic = async () => {
      try {
        const response = await axios.post(apiRoutes.trafficSnapshot, {
          data_ids: dataIds,
        });

        if (!isActive) {
          return;
        }

        const nextTrafficByHostId = Object.fromEntries(
          paginatedHosts.map((host) => [host.id, []])
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
            paginatedHosts.map((host) => [host.id, current[host.id] || []])
          )
        );
      }
    };

    loadMachineTraffic();
    const intervalId = window.setInterval(loadMachineTraffic, 2000);

    return () => {
      isActive = false;
      window.clearInterval(intervalId);
    };
  }, [paginatedHosts]);

  const handleOpenConfig = (hostId) => setSelectedHostId(hostId);

  const handleCloseConfig = () => setSelectedHostId(null);

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
      (config) => config.dataId && !nextConfigIds.has(config.dataId)
    );
    const configsToCreate = forwardingConfigs.filter((config) => !config.dataId);
    const configsToUpdate = forwardingConfigs.filter(
      (config) =>
        config.dataId &&
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

      const savedConfigs = forwardingConfigs
        .filter((config) => config.dataId && !configsToDelete.some((deleted) => deleted.dataId === config.dataId))
        .filter((config) => !configsToUpdate.some((updated) => updated.dataId === config.dataId))
        .map((config) => ({
          dataId: config.dataId,
          serviceName: config.serviceName,
          serviceDescription: config.serviceDescription,
          internalIp: config.internalIp,
          internalPort: Number(config.internalPort),
          externalPort: Number(config.externalPort),
          enabled: config.enabled,
        }));

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

        savedConfigs.push({
          ...savedConfig,
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
        };

        const response = await axios.post(apiRoutes.addConnection, payload);
        const savedConfig = mapConnectionToForwardingConfig(response.data.data);
        const normalizedFirewall = normalizeFirewallPolicy(config);
        const firewallResponse = await axios.put(apiRoutes.updateConnectionFirewallPolicy, {
          data_id: savedConfig.dataId,
          is_public: normalizedFirewall.isPublic,
          allowed_ips: normalizedFirewall.allowedIps,
        });

        savedConfigs.push({
          ...savedConfig,
          firewall: {
            isPublic: firewallResponse.data?.data?.firewall?.is_public ?? normalizedFirewall.isPublic,
            allowedIps:
              firewallResponse.data?.data?.firewall?.allowed_ips ??
              normalizedFirewall.allowedIps,
          },
        });
      }

      savedConfigs.sort((left, right) => {
        if (left.externalPort !== right.externalPort) {
          return left.externalPort - right.externalPort;
        }
        return (left.dataId || "").localeCompare(right.dataId || "");
      });

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
    <div className="flex justify-center">
      <div className="m-4 pb-16 md:pb-6 xl:m-8 relative overflow-y-auto overflow-x-hidden 2xl:w-[80rem] w-full">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="text-sm font-semibold uppercase tracking-[0.2em] text-zinc-500">
              Machines
            </p>
            <h1 className="mt-1 text-2xl font-semibold text-zinc-900 dark:text-zinc-100">
              Registered clients
            </h1>
          </div>
          <div className="flex flex-wrap items-center justify-end gap-2">
            <Button
              type="button"
              leftIcon={<IconPlus size={16} />}
              onClick={() => setIsCreateModalOpen(true)}
              classNames={{
                root:
                  "!bg-blue-600 !text-blue-50 hover:!bg-blue-700 disabled:!bg-blue-400",
              }}
            >
              Create machine
            </Button>
          </div>
        </div>

        <div className="mt-6">
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
                </div>
              ) : (
                <>
                  <div className="mb-1">
                    <p className="text-sm font-semibold uppercase tracking-[0.2em] text-zinc-500 dark:text-zinc-500">
                      All machines
                    </p>
                  </div>
                  <div className="mb-4 flex flex-col gap-3">
                    <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                      <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
                        <SegmentedControl
                          value={statusFilter}
                          onChange={setStatusFilter}
                          data={[
                            { value: "all", label: "All" },
                            { value: "online", label: "Online" },
                            { value: "offline", label: "Offline" },
                          ]}
                          classNames={{
                            root:
                              "!rounded-lg !bg-zinc-100 !p-1 dark:!bg-zinc-800",
                            control:
                              "!border-transparent",
                            label:
                              "!text-zinc-600 dark:!text-zinc-300 data-[active=true]:!text-blue-50",
                            indicator:
                              "!rounded-md !bg-blue-600 !shadow-sm dark:!bg-blue-600",
                          }}
                        />
                      </div>
                      <div className="flex flex-wrap items-center justify-start gap-2 lg:justify-end">
                        <div
                          className={`inline-flex items-stretch overflow-hidden rounded-md border ${
                            isDark
                              ? "border-zinc-700 bg-zinc-900"
                              : "border-zinc-300 bg-white"
                          }`}
                        >
                          <Menu
                            withinPortal
                            position="bottom-end"
                            shadow="md"
                            offset={6}
                            classNames={{
                              dropdown:
                                "!min-w-[11rem] !border !border-zinc-200 !bg-white !p-1 dark:!border-zinc-700 dark:!bg-zinc-900",
                              item:
                                "!rounded-md !text-zinc-900 hover:!bg-zinc-100 dark:!text-zinc-100 dark:hover:!bg-zinc-800",
                            }}
                          >
                            <Menu.Target>
                              <button
                                type="button"
                                className={`inline-flex items-center gap-2 px-3 py-2 text-sm ${
                                  isDark
                                    ? "text-zinc-100 hover:bg-zinc-800"
                                    : "text-zinc-900 hover:bg-zinc-50"
                                }`}
                              >
                                <span>{selectedGroupFilterLabel}</span>
                                <IconChevronDown
                                  size={14}
                                  className={isDark ? "text-zinc-500" : "text-zinc-400"}
                                />
                              </button>
                            </Menu.Target>
                            <Menu.Dropdown>
                              <Menu.Item
                                onClick={() => setGroupFilter(ALL_GROUPS_FILTER)}
                                className={
                                  groupFilter === ALL_GROUPS_FILTER
                                    ? "!bg-blue-600 !text-blue-50 hover:!bg-blue-600 dark:!bg-blue-600 dark:!text-blue-50 dark:hover:!bg-blue-600"
                                    : undefined
                                }
                            >
                              All groups
                            </Menu.Item>
                            {machineGroups.length > 0 ? <Menu.Divider /> : null}
                              {machineGroups.map((group) => (
                                <Menu.Item
                                  key={group._id}
                                  onClick={() => setGroupFilter(group._id)}
                                  className={
                                    groupFilter === group._id
                                      ? "!bg-blue-600 !text-blue-50 hover:!bg-blue-600 dark:!bg-blue-600 dark:!text-blue-50 dark:hover:!bg-blue-600"
                                      : undefined
                                  }
                                >
                                  {group.name}
                                </Menu.Item>
                              ))}
                            </Menu.Dropdown>
                          </Menu>
                          <Button
                            type="button"
                            variant="default"
                            onClick={() => setIsGroupsModalOpen(true)}
                            aria-label="Manage groups"
                            title="Manage groups"
                            classNames={{
                              root: isDark
                                ? "!min-w-0 !rounded-none !border-0 !border-l !border-zinc-700 !bg-zinc-900 !px-3 !text-zinc-100 hover:!bg-zinc-800"
                                : "!min-w-0 !rounded-none !border-0 !border-l !border-zinc-300 !bg-white !px-3 !text-zinc-900 hover:!bg-zinc-50",
                            }}
                          >
                            <IconSettings size={16} />
                          </Button>
                        </div>
                        <Menu
                          withinPortal
                          position="bottom-end"
                          shadow="md"
                          offset={6}
                          classNames={{
                            dropdown:
                              "!min-w-[7rem] !border !border-zinc-200 !bg-white !p-1 dark:!border-zinc-700 dark:!bg-zinc-900",
                            item:
                              "!rounded-md !text-zinc-900 hover:!bg-zinc-100 dark:!text-zinc-100 dark:hover:!bg-zinc-800",
                          }}
                        >
                          <Menu.Target>
                            <button
                              type="button"
                              className="inline-flex items-center gap-2 rounded-md border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 hover:bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:hover:bg-zinc-800"
                            >
                              <span>{pageSize} rows per page</span>
                              <IconChevronDown
                                size={14}
                                className={isDark ? "text-zinc-500" : "text-zinc-400"}
                              />
                            </button>
                          </Menu.Target>
                          <Menu.Dropdown>
                            {MACHINE_PAGE_SIZE_OPTIONS.map((option) => (
                              <Menu.Item
                                key={option.value}
                                onClick={() => setPageSize(option.value)}
                                className={
                                  option.value === pageSize
                                    ? "!bg-blue-600 !text-blue-50 hover:!bg-blue-600 dark:!bg-blue-600 dark:!text-blue-50 dark:hover:!bg-blue-600"
                                    : undefined
                                }
                              >
                                {option.value}
                              </Menu.Item>
                            ))}
                          </Menu.Dropdown>
                        </Menu>
                      </div>
                    </div>

                  </div>

                  <div className="overflow-hidden rounded-xl border border-zinc-200 bg-white shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
                    <div className="hidden min-h-16 border-b border-zinc-200 bg-zinc-50/80 py-4 pl-6 pr-6 text-[11px] font-semibold uppercase tracking-[0.18em] text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-500 md:grid md:grid-cols-[minmax(0,1.2fr)_minmax(5.75rem,0.9fr)_minmax(8.5rem,1fr)_minmax(9.5rem,1fr)] md:items-center md:gap-4">
                      <span>Machine</span>
                      <span className="text-center">Ports</span>
                      <span>Groups</span>
                      <span>Traffic</span>
                    </div>

                    {paginatedHosts.length > 0 ? (
                      <div
                        className="max-h-[calc(100dvh-22rem)] overflow-y-auto"
                        style={{ scrollbarGutter: "stable" }}
                      >
                        <div className="divide-y divide-zinc-200 dark:divide-zinc-800">
                          {paginatedHosts.map((host) => (
                            <HostItem
                              key={host.id}
                              machineId={host.id}
                              name={host.name}
                              hostname={host.hostname}
                              groupLabels={(host.groupIds || [])
                                .map((id) => groupLabelById[id])
                                .filter(Boolean)}
                              localIp={host.localIp}
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
                        </div>
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
                      <div className="flex min-h-16 flex-col gap-3 border-t border-zinc-200 px-5 py-4 dark:border-zinc-800 md:flex-row md:items-center md:justify-between">
                        <p className="text-sm text-zinc-500 dark:text-zinc-400">
                          Showing {visibleStart} to {visibleEnd} of {filteredHosts.length} machines
                        </p>

                        <Pagination
                          value={page}
                          onChange={setPage}
                          total={totalPages}
                          size="sm"
                          radius="md"
                          withEdges
                          siblings={1}
                          classNames={{
                            control:
                              "!border-zinc-300 !bg-white !text-zinc-700 hover:!bg-zinc-50 data-[active=true]:!border-blue-600 data-[active=true]:!bg-blue-600 data-[active=true]:!text-blue-50 dark:!border-zinc-700 dark:!bg-zinc-900 dark:!text-zinc-200 dark:hover:!bg-zinc-800 dark:data-[active=true]:!border-blue-500 dark:data-[active=true]:!bg-blue-600",
                          }}
                        />
                      </div>
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
        host={selectedHost}
        opened={Boolean(selectedHost)}
        onClose={handleCloseConfig}
        onSave={handleSaveConfig}
        onUpdateMachineDetails={handleUpdateMachineDetails}
        onDeleteMachine={handleDeleteMachine}
        onToggleMachine={handleToggleMachine}
        onRefreshMachineToken={handleRefreshMachineToken}
        onRequestClientUpdate={handleRequestClientUpdate}
        onCreateGroup={handleCreateGroup}
        onAddMachineToGroup={handleAddMachineToGroup}
        onRemoveMachineFromGroup={handleRemoveMachineFromGroup}
        groups={groupsWithMachineCounts}
        isSaving={isSaving}
      />
    </div>
  );
}
