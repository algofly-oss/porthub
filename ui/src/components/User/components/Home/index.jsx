import { useContext, useEffect, useMemo, useRef, useState } from "react";
import axios from "axios";
import toast from "react-hot-toast";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
import utc from "dayjs/plugin/utc";
import {
  Button,
  Group,
  Menu,
  Modal,
  Pagination,
  SegmentedControl,
  Text,
  useMantineColorScheme,
} from "@mantine/core";
import {
  IconChevronDown,
  IconFolder,
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

const DND_MACHINE_ID_MIME = "application/x-porthub-machine-id";

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
  if (secondsAgo < 60) {
    return secondsAgo === 1 ? "1 second ago" : `${secondsAgo} seconds ago`;
  }

  return parsed.fromNow();
};

const mapConnectionToForwardingConfig = (connection) => ({
  dataId: connection._id,
  serviceName: connection.service_name || "",
  serviceDescription: connection.service_description || "",
  internalIp: connection.internal_ip || connection.internalIp || "0.0.0.0",
  internalPort: connection.internal_port || 3000,
  externalPort: connection.external_port || 3000,
  enabled: connection.enabled ?? true,
});

const normalizeForwardingConfig = (config) => ({
  serviceName: (config.serviceName || "").trim(),
  serviceDescription: (config.serviceDescription || "").trim(),
  internalIp:
    (config.internalIp || config.internal_ip || "").trim() || "0.0.0.0",
  internalPort: Number(config.internalPort),
  externalPort: Number(config.externalPort),
  enabled: config.enabled ?? true,
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
    currentNormalized.enabled !== nextNormalized.enabled
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
  { value: "5", label: "5" },
  { value: "10", label: "10" },
  { value: "20", label: "20" },
  { value: "50", label: "50" },
];

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
  const [selectedBrowseGroupId, setSelectedBrowseGroupId] = useState(null);
  const [machineGroups, setMachineGroups] = useState([]);
  const [isGroupsModalOpen, setIsGroupsModalOpen] = useState(false);
  const [lastSeenRefreshTick, setLastSeenRefreshTick] = useState(0);
  const [dragOverGroupId, setDragOverGroupId] = useState(null);
  const [addToGroupConfirm, setAddToGroupConfirm] = useState(null);
  const [removeFromGroupConfirm, setRemoveFromGroupConfirm] = useState(null);
  const [moveSubmitting, setMoveSubmitting] = useState(false);
  const suppressFolderClickRef = useRef(false);
  const { success, error } = useToast();

  const groupLabelById = useMemo(
    () => Object.fromEntries(machineGroups.map((g) => [g._id, g.name])),
    [machineGroups]
  );

  const selectedHost = hosts.find((host) => host.id === selectedHostId) || null;
  const filteredHosts = hosts.filter((host) => {
    return (
      statusFilter === "all" ||
      (statusFilter === "online" ? host.isActive : !host.isActive)
    );
  });

  const hostsInSelectedBrowseGroup = useMemo(() => {
    if (!selectedBrowseGroupId) {
      return [];
    }
    return hosts.filter((host) =>
      (host.groupIds || []).includes(selectedBrowseGroupId)
    );
  }, [hosts, selectedBrowseGroupId]);

  const selectedBrowseGroup = useMemo(
    () => machineGroups.find((g) => g._id === selectedBrowseGroupId) || null,
    [machineGroups, selectedBrowseGroupId]
  );
  const numericPageSize = Number(pageSize);
  const totalPages = Math.max(1, Math.ceil(filteredHosts.length / numericPageSize));
  const visibleStart = filteredHosts.length === 0 ? 0 : (page - 1) * numericPageSize + 1;
  const visibleEnd = Math.min(page * numericPageSize, filteredHosts.length);
  const paginatedHosts = filteredHosts.slice(
    (page - 1) * numericPageSize,
    page * numericPageSize
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
  }, [pageSize, statusFilter]);

  useEffect(() => {
    if (
      selectedBrowseGroupId &&
      !machineGroups.some((g) => g._id === selectedBrowseGroupId)
    ) {
      setSelectedBrowseGroupId(null);
    }
  }, [machineGroups, selectedBrowseGroupId]);

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

        savedConfigs.push(mapConnectionToForwardingConfig(response.data.data));
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
        savedConfigs.push(mapConnectionToForwardingConfig(response.data.data));
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
        hostname: currentHost.hostname,
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

  const readDragMachineId = (dataTransfer) => {
    const fromMime = dataTransfer.getData(DND_MACHINE_ID_MIME);
    if (fromMime) {
      return fromMime;
    }
    return dataTransfer.getData("text/plain") || "";
  };

  const handleMachineRowDragEnd = () => {
    setDragOverGroupId(null);
  };

  const handleFolderDragOver = (event, groupId) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = "move";
    setDragOverGroupId(groupId);
  };

  const handleFolderDragLeave = (event) => {
    const next = event.relatedTarget;
    if (next && event.currentTarget.contains(next)) {
      return;
    }
    setDragOverGroupId(null);
  };

  const handleFolderDrop = (event, group) => {
    event.preventDefault();
    event.stopPropagation();
    suppressFolderClickRef.current = true;
    setDragOverGroupId(null);

    const machineId = readDragMachineId(event.dataTransfer);
    if (!machineId) {
      return;
    }

    const host = hosts.find((h) => h.id === machineId);
    if (!host) {
      error("Could not find that machine.");
      return;
    }

    if ((host.groupIds || []).includes(group._id)) {
      toast(`"${host.name}" is already in "${group.name}".`);
      return;
    }

    setAddToGroupConfirm({
      hostId: machineId,
      groupId: group._id,
      machineName: host.name || "Machine",
      groupName: group.name || "Group",
    });
  };

  const handleFolderClick = (groupId) => {
    if (suppressFolderClickRef.current) {
      suppressFolderClickRef.current = false;
      return;
    }
    setSelectedBrowseGroupId((prev) => (prev === groupId ? null : groupId));
  };

  const handleConfirmAddMachineToGroup = async () => {
    if (!addToGroupConfirm) {
      return;
    }
    setMoveSubmitting(true);
    try {
      await handleAddMachineToGroup(
        addToGroupConfirm.hostId,
        addToGroupConfirm.groupId
      );
      success(
        `Added "${addToGroupConfirm.machineName}" to "${addToGroupConfirm.groupName}".`
      );
      setAddToGroupConfirm(null);
    } catch (moveErr) {
      error(moveErr?.response?.data?.detail || "Could not add machine to group");
    } finally {
      setMoveSubmitting(false);
    }
  };

  const handleConfirmRemoveFromGroup = async () => {
    if (!removeFromGroupConfirm) {
      return;
    }
    setMoveSubmitting(true);
    try {
      await handleRemoveMachineFromGroup(
        removeFromGroupConfirm.hostId,
        removeFromGroupConfirm.groupId
      );
      success(
        `Removed "${removeFromGroupConfirm.machineName}" from "${removeFromGroupConfirm.groupName}".`
      );
      setRemoveFromGroupConfirm(null);
    } catch (removeErr) {
      error(
        removeErr?.response?.data?.detail || "Could not remove machine from group"
      );
    } finally {
      setMoveSubmitting(false);
    }
  };

  const reloadMachineGroups = async () => {
    const res = await axios.get(apiRoutes.listGroups);
    setMachineGroups(res.data?.data || []);
  };

  const handleCreateGroup = async (name) => {
    try {
      await axios.post(apiRoutes.addGroup, { name });
      await reloadMachineGroups();
      success(`Group "${name}" created`);
      return true;
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
      setSelectedBrowseGroupId((current) =>
        current === groupId ? null : current
      );
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
              variant="default"
              leftIcon={<IconFolder size={16} />}
              onClick={() => setIsGroupsModalOpen(true)}
              classNames={{
                root: isDark
                  ? "!border-zinc-700 !bg-zinc-900 !text-zinc-100 hover:!bg-zinc-800"
                  : "!border-zinc-300 !bg-white !text-zinc-900 hover:!bg-zinc-50",
              }}
            >
              Groups
            </Button>
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
              {machineGroups.length > 0 ? (
                <section
                  className={`mb-10 rounded-2xl border px-5 py-5 sm:px-6 ${isDark
                      ? "border-zinc-700 bg-zinc-900/40"
                      : "border-zinc-200 bg-zinc-50/80"
                    }`}
                >
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    <div>
                      <h2 className="text-lg font-semibold text-zinc-900 dark:text-zinc-100">
                        Groups
                      </h2>
                      <div className="flex flex-col">
                        <Text size="sm" className="max-w-xl text-zinc-600 dark:text-zinc-400">
                          Open a group to see machines in that group here.
                        </Text>
                        <Text size="xs" className="max-w-xl text-zinc-500 dark:text-zinc-600">Tip: You can also drag a row from the table below onto a group to move it.</Text>
                      </div>
                    </div>
                    <Button
                      type="button"
                      variant="default"
                      size="xs"
                      leftIcon={<IconSettings size={14} />}
                      onClick={() => setIsGroupsModalOpen(true)}
                      classNames={{
                        root: isDark
                          ? "!shrink-0 !border-zinc-600 !bg-zinc-800 !text-zinc-100"
                          : "!shrink-0 !border-zinc-300 !bg-white !text-zinc-900",
                      }}
                    >
                      Manage groups
                    </Button>
                  </div>

                  <div className="mt-4 flex flex-wrap gap-2">
                    {machineGroups.map((g) => {
                      const isOpen = selectedBrowseGroupId === g._id;
                      const isDropTarget = dragOverGroupId === g._id;
                      return (
                        <button
                          key={g._id}
                          type="button"
                          onClick={() => handleFolderClick(g._id)}
                          onDragOver={(event) => handleFolderDragOver(event, g._id)}
                          onDragLeave={handleFolderDragLeave}
                          onDrop={(event) => handleFolderDrop(event, g)}
                          className={`inline-flex min-h-[2.75rem] items-center gap-2 rounded-xl border px-4 py-2 text-left text-sm font-medium transition ${isDropTarget
                              ? isDark
                                ? "border-amber-400/70 bg-amber-950/40 text-amber-100 ring-2 ring-amber-500/50"
                                : "border-amber-400 bg-amber-50 text-amber-950 ring-2 ring-amber-400/60"
                              : isOpen
                                ? isDark
                                  ? "border-blue-500/60 bg-blue-950/50 text-blue-100 shadow-sm ring-1 ring-blue-500/40"
                                  : "border-blue-400 bg-blue-50 text-blue-900 shadow-sm ring-1 ring-blue-400/50"
                                : isDark
                                  ? "border-zinc-600 bg-zinc-900 text-zinc-100 hover:border-zinc-500 hover:bg-zinc-800"
                                  : "border-zinc-200 bg-white text-zinc-800 hover:border-zinc-300 hover:bg-zinc-50"
                            }`}
                        >
                          <IconFolder
                            size={18}
                            className={
                              isOpen
                                ? isDark
                                  ? "text-blue-300"
                                  : "text-blue-600"
                                : isDark
                                  ? "text-zinc-400"
                                  : "text-zinc-500"
                            }
                          />
                          <span className="max-w-[12rem] truncate">{g.name}</span>
                        </button>
                      );
                    })}
                  </div>

                  {selectedBrowseGroupId && selectedBrowseGroup ? (
                    <div
                      className={`mt-6 overflow-hidden rounded-xl border ${isDark
                          ? "border-zinc-600 bg-zinc-950/60"
                          : "border-zinc-200 bg-white"
                        }`}
                    >
                      <div
                        className={`border-b px-4 py-3 sm:px-5 ${isDark
                            ? "border-zinc-700 bg-zinc-900/80"
                            : "border-zinc-200 bg-zinc-50/90"
                          }`}
                      >
                        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                          <div>
                            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-zinc-500">
                              Open folder
                            </p>
                            <p className="text-base font-semibold text-zinc-900 dark:text-zinc-100">
                              {selectedBrowseGroup.name}
                            </p>
                            <p className="text-sm text-zinc-500 dark:text-zinc-400">
                              {hostsInSelectedBrowseGroup.length} machine
                              {hostsInSelectedBrowseGroup.length === 1 ? "" : "s"} in
                              this group
                            </p>
                          </div>
                          <Button
                            type="button"
                            variant="subtle"
                            size="xs"
                            onClick={() => setSelectedBrowseGroupId(null)}
                            classNames={{
                              root: isDark
                                ? "!text-zinc-400 hover:!bg-zinc-800"
                                : "!text-zinc-600 hover:!bg-zinc-100",
                            }}
                          >
                            Close folder
                          </Button>
                        </div>
                      </div>

                      {hostsInSelectedBrowseGroup.length === 0 ? (
                        <div className="px-4 py-10 text-center sm:px-5">
                          <p className="text-sm text-zinc-600 dark:text-zinc-400">
                            No machines in this group yet. Drag a machine here, use host
                            settings &quot;Groups&quot;, or pick an initial group when creating a
                            machine.
                          </p>
                        </div>
                      ) : (
                        <div className="divide-y divide-zinc-200 dark:divide-zinc-700">
                          {hostsInSelectedBrowseGroup.map((host) => (
                            <div
                              key={`browse-${host.id}`}
                              className={`flex w-full items-stretch ${isDark ? "bg-zinc-950/40" : "bg-white"
                                }`}
                            >
                              <div className="min-w-0 flex-1">
                                <HostItem
                                  machineId={host.id}
                                  draggable={machineGroups.length > 0}
                                  dndMimeType={DND_MACHINE_ID_MIME}
                                  onMachineDragEnd={handleMachineRowDragEnd}
                                  name={host.name}
                                  hostname={host.hostname}
                                  groupLabels={[]}
                                  localIp={host.localIp}
                                  publicIp={host.publicIp}
                                  isActive={host.isActive}
                                  connectionStatus={host.connectionStatus}
                                  isDark={isDark}
                                  numPorts={host.numPorts}
                                  lastSeen={host.lastSeen}
                                  onClick={() => handleOpenConfig(host.id)}
                                />
                              </div>
                              <div
                                className={`flex shrink-0 items-center border-l px-2 py-2 sm:px-3 ${isDark ? "border-zinc-700" : "border-zinc-200"
                                  }`}
                              >
                                <Button
                                  type="button"
                                  variant="subtle"
                                  color="red"
                                  size="xs"
                                  compact
                                  onClick={(e) => {
                                    e.preventDefault();
                                    e.stopPropagation();
                                    if (!selectedBrowseGroup) {
                                      return;
                                    }
                                    setRemoveFromGroupConfirm({
                                      hostId: host.id,
                                      groupId: selectedBrowseGroup._id,
                                      machineName: host.name || "Machine",
                                      groupName: selectedBrowseGroup.name || "Group",
                                    });
                                  }}
                                  classNames={{
                                    root: isDark
                                      ? "!text-red-300 hover:!bg-red-950/50"
                                      : "!text-red-700 hover:!bg-red-50",
                                  }}
                                >
                                  Remove from group
                                </Button>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ) : null}
                </section>
              ) : null}

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
                      <div className="flex items-center justify-start lg:justify-end">
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

                    <div className="hidden border-b border-zinc-200 bg-zinc-50/80 px-5 py-3 text-[11px] font-semibold uppercase tracking-[0.18em] text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-500 md:grid md:grid-cols-[minmax(0,1.3fr)_110px_minmax(0,0.85fr)_minmax(0,0.85fr)_120px_160px] md:items-center md:gap-3">
                      <span>Machine</span>
                      <span className="text-center">Ports</span>
                      <span>Local IP</span>
                      <span>Public IP</span>
                      <span className="text-center">Status</span>
                      <span className="text-right">Last seen</span>
                    </div>

                    {paginatedHosts.length > 0 ? (
                      <div className="divide-y divide-zinc-200 dark:divide-zinc-800">
                        {paginatedHosts.map((host) => (
                          <HostItem
                            key={host.id}
                            machineId={host.id}
                            draggable={machineGroups.length > 0}
                            dndMimeType={DND_MACHINE_ID_MIME}
                            onMachineDragEnd={handleMachineRowDragEnd}
                            name={host.name}
                            hostname={host.hostname}
                            groupLabels={(host.groupIds || [])
                              .map((id) => groupLabelById[id])
                              .filter(Boolean)}
                            localIp={host.localIp}
                            publicIp={host.publicIp}
                            isActive={host.isActive}
                            connectionStatus={host.connectionStatus}
                            isDark={isDark}
                            numPorts={host.numPorts}
                            lastSeen={host.lastSeen}
                            onClick={() => handleOpenConfig(host.id)}
                          />
                        ))}
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

                  </div>

                  {filteredHosts.length > 0 ? (
                    <div className="mt-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
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
                </>
              )}
            </>
          )}
        </div>
      </div>
      <Modal
        opened={Boolean(addToGroupConfirm)}
        onClose={() => {
          if (!moveSubmitting) {
            setAddToGroupConfirm(null);
          }
        }}
        closeOnClickOutside={!moveSubmitting}
        closeOnEscape={!moveSubmitting}
        title="Add machine to group"
        centered
        radius="md"
        overlayProps={{ blur: 3 }}
        classNames={{
          content: isDark
            ? "!border !border-zinc-700 !bg-zinc-900"
            : "!border !border-zinc-200 !bg-white",
          header: isDark ? "!bg-zinc-900" : "!bg-white",
          title: isDark ? "!text-zinc-100" : "!text-zinc-900",
          body: isDark ? "!bg-zinc-900" : "!bg-white",
        }}
      >
        {addToGroupConfirm ? (
          <>
            <Text size="sm" className={isDark ? "!text-zinc-300" : "!text-zinc-600"}>
              Add{" "}
              <span className="font-semibold text-zinc-900 dark:text-zinc-100">
                {addToGroupConfirm.machineName}
              </span>{" "}
              to{" "}
              <span className="font-semibold text-zinc-900 dark:text-zinc-100">
                {addToGroupConfirm.groupName}
              </span>
              ? It can stay in other groups as well.
            </Text>
            <Group justify="flex-end" mt="lg" spacing="sm">
              <Button
                type="button"
                variant="default"
                disabled={moveSubmitting}
                onClick={() => setAddToGroupConfirm(null)}
                classNames={{
                  root: isDark
                    ? "!border-zinc-600 !bg-zinc-800 !text-zinc-100"
                    : "!border-zinc-300 !bg-white !text-zinc-900",
                }}
              >
                Cancel
              </Button>
              <Button
                type="button"
                loading={moveSubmitting}
                onClick={handleConfirmAddMachineToGroup}
                classNames={{
                  root:
                    "!bg-blue-600 !text-blue-50 hover:!bg-blue-700 disabled:!bg-blue-400",
                }}
              >
                Add to group
              </Button>
            </Group>
          </>
        ) : null}
      </Modal>

      <Modal
        opened={Boolean(removeFromGroupConfirm)}
        onClose={() => {
          if (!moveSubmitting) {
            setRemoveFromGroupConfirm(null);
          }
        }}
        closeOnClickOutside={!moveSubmitting}
        closeOnEscape={!moveSubmitting}
        title="Remove from group"
        centered
        radius="md"
        overlayProps={{ blur: 3 }}
        classNames={{
          content: isDark
            ? "!border !border-zinc-700 !bg-zinc-900"
            : "!border !border-zinc-200 !bg-white",
          header: isDark ? "!bg-zinc-900" : "!bg-white",
          title: isDark ? "!text-zinc-100" : "!text-zinc-900",
          body: isDark ? "!bg-zinc-900" : "!bg-white",
        }}
      >
        {removeFromGroupConfirm ? (
          <>
            <Text size="sm" className={isDark ? "!text-zinc-300" : "!text-zinc-600"}>
              Remove{" "}
              <span className="font-semibold text-zinc-900 dark:text-zinc-100">
                {removeFromGroupConfirm.machineName}
              </span>{" "}
              from{" "}
              <span className="font-semibold text-zinc-900 dark:text-zinc-100">
                {removeFromGroupConfirm.groupName}
              </span>
              ? Other groups for this machine stay unchanged.
            </Text>
            <Group justify="flex-end" mt="lg" spacing="sm">
              <Button
                type="button"
                variant="default"
                disabled={moveSubmitting}
                onClick={() => setRemoveFromGroupConfirm(null)}
                classNames={{
                  root: isDark
                    ? "!border-zinc-600 !bg-zinc-800 !text-zinc-100"
                    : "!border-zinc-300 !bg-white !text-zinc-900",
                }}
              >
                Cancel
              </Button>
              <Button
                type="button"
                color="red"
                variant="filled"
                loading={moveSubmitting}
                onClick={handleConfirmRemoveFromGroup}
                classNames={{
                  root:
                    "!bg-red-600 !text-red-50 hover:!bg-red-700 disabled:!bg-red-400",
                }}
              >
                Remove from group
              </Button>
            </Group>
          </>
        ) : null}
      </Modal>

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
        onCreateGroup={handleCreateGroup}
        onRenameGroup={handleRenameGroup}
        onDeleteGroup={handleDeleteGroup}
      />
      <HostConfigPopup
        host={selectedHost}
        opened={Boolean(selectedHost)}
        onClose={handleCloseConfig}
        onSave={handleSaveConfig}
        onDeleteMachine={handleDeleteMachine}
        onToggleMachine={handleToggleMachine}
        onRefreshMachineToken={handleRefreshMachineToken}
        onRequestClientUpdate={handleRequestClientUpdate}
        onAddMachineToGroup={handleAddMachineToGroup}
        onRemoveMachineFromGroup={handleRemoveMachineFromGroup}
        groups={machineGroups}
        isSaving={isSaving}
      />
    </div>
  );
}
