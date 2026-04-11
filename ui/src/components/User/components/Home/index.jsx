import { useContext, useEffect, useState } from "react";
import axios from "axios";
import dayjs from "dayjs";
import {
  Button,
  Menu,
  Pagination,
  SegmentedControl,
  useMantineColorScheme,
} from "@mantine/core";
import { IconChevronDown, IconPlus } from "@tabler/icons-react";
import HostItem from "./components/Host/HostItem";
import HostConfigPopup from "./components/Host/HostConfigPopup";
import MachineCreateModal from "./components/Host/MachineCreateModal";
import useToast from "@/shared/hooks/useToast";
import { SocketContext } from "@/shared/contexts/socket";
import apiRoutes from "@/shared/routes/apiRoutes";
import socketRoutes from "@/shared/routes/socketRoutes";

const mapConnectionToForwardingConfig = (connection) => ({
  dataId: connection._id,
  serviceName: connection.service_name || "",
  serviceDescription: connection.service_description || "",
  internalPort: connection.internal_port || 3000,
  externalPort: connection.external_port || 3000,
  enabled: connection.enabled ?? true,
});

const formatLastSeen = (machine) => {
  if (machine.is_active) {
    return "Connected";
  }

  if (!machine.last_seen_at) {
    return "Never seen";
  }

  return dayjs(machine.last_seen_at).format("DD MMM YYYY HH:mm");
};

const mapMachineToHost = (machine) => ({
  id: machine._id,
  name: machine.name || "Untitled machine",
  hostname: machine.hostname || "",
  localIp: machine.local_ip || "",
  publicIp: machine.public_ip || "",
  token: machine.token || "",
  isActive: machine.is_active ?? false,
  numPorts: 0,
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

export default function Home() {
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
  const { success, error } = useToast();

  const selectedHost = hosts.find((host) => host.id === selectedHostId) || null;
  const filteredHosts = hosts.filter((host) => {
    return (
      statusFilter === "all" ||
      (statusFilter === "online" ? host.isActive : !host.isActive)
    );
  });
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
    setPage(1);
  }, [pageSize, statusFilter]);

  useEffect(() => {
    const loadData = async () => {
      setIsLoading(true);

      try {
        const [machinesResponse, connectionsResponse] = await Promise.all([
          axios.get(apiRoutes.listMachines),
          axios.get(apiRoutes.listConnections),
        ]);

        const machines = machinesResponse.data?.data || [];
        const connections = connectionsResponse.data?.data || [];

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

    socket.on("connect", requestMachineStatusSnapshot);
    socket.on(socketRoutes.stcMachineStatusSnapshot, handleMachineStatusSnapshot);
    socket.on(socketRoutes.stcMachineStatusChanged, handleMachineStatusChanged);

    return () => {
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
      const response = await axios.post(apiRoutes.addMachine, machine);
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
    const nextConfigIds = new Set(
      forwardingConfigs.filter((config) => config.dataId).map((config) => config.dataId)
    );
    const configsToDelete = currentConfigs.filter(
      (config) => config.dataId && !nextConfigIds.has(config.dataId)
    );

    setIsSaving(true);

    try {
      const machineResponse = await axios.put(apiRoutes.updateMachine, {
        data_id: currentHost.id,
        name: currentHost.name,
        hostname: currentHost.hostname,
        is_active: currentHost.isActive,
      });

      for (const config of configsToDelete) {
        await axios.post(apiRoutes.deleteConnection, {
          data_id: config.dataId,
        });
      }

      const savedConfigs = [];

      for (const config of forwardingConfigs) {
        const payload = {
          data_id: config.dataId,
          machine_id: currentHost.id,
          service_name: config.serviceName,
          service_description: config.serviceDescription,
          internal_port: Number(config.internalPort),
          external_port: Number(config.externalPort),
          enabled: config.enabled,
        };

        const response = config.dataId
          ? await axios.put(apiRoutes.updateConnection, payload)
          : await axios.post(apiRoutes.addConnection, payload);

        savedConfigs.push(mapConnectionToForwardingConfig(response.data.data));
      }

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
          <div className="flex items-center gap-3">
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
          ) : hosts.length === 0 ? (
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
              <div className="mb-4 flex flex-col gap-3">
                <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
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
                  <div className="flex items-center justify-start md:justify-end">
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
                        name={host.name}
                        hostname={host.hostname}
                        localIp={host.localIp}
                        publicIp={host.publicIp}
                        isActive={host.isActive}
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
                      Adjust the name filter or status filter to see more machines.
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
        </div>
      </div>
      <MachineCreateModal
        opened={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onCreate={handleCreateMachine}
        isCreating={isCreatingMachine}
      />
      <HostConfigPopup
        host={selectedHost}
        opened={Boolean(selectedHost)}
        onClose={handleCloseConfig}
        onSave={handleSaveConfig}
        onDeleteMachine={handleDeleteMachine}
        onRefreshMachineToken={handleRefreshMachineToken}
        isSaving={isSaving}
      />
    </div>
  );
}
