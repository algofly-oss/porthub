import { useEffect, useState } from "react";
import axios from "axios";
import HostItem from "./components/Host/HostItem";
import HostConfigPopup from "./components/Host/HostConfigPopup";
import useToast from "@/shared/hooks/useToast";
import apiRoutes from "@/shared/routes/apiRoutes";

const initialHosts = [
  {
    id: "luna",
    name: "luna",
    ip: "192.168.0.3",
    isActive: true,
    numPorts: 0,
    lastSeen: "Connected",
    forwardingConfigs: [],
  },
  {
    id: "miro",
    name: "miro",
    ip: "192.168.0.4",
    isActive: true,
    numPorts: 0,
    lastSeen: "Connected",
    forwardingConfigs: [],
  },
  {
    id: "clearsight",
    name: "clearsight",
    ip: "192.168.0.22",
    isActive: false,
    numPorts: 0,
    lastSeen: "10 minutes ago",
    forwardingConfigs: [],
  },
];

const mapConnectionToForwardingConfig = (connection) => ({
  dataId: connection._id,
  serviceName: connection.service_name || "",
  serviceDescription: connection.service_description || "",
  internalPort: connection.internal_port || 3000,
  externalPort: connection.external_port || 3000,
  enabled: connection.enabled ?? true,
});

export default function Home() {
  const [hosts, setHosts] = useState(initialHosts);
  const [selectedHostId, setSelectedHostId] = useState(null);
  const [isSaving, setIsSaving] = useState(false);
  const { success, error } = useToast();

  const selectedHost = hosts.find((host) => host.id === selectedHostId) || null;

  useEffect(() => {
    const loadConnections = async () => {
      try {
        const response = await axios.get(apiRoutes.listConnections);
        const connections = response.data?.data || [];

        setHosts((currentHosts) =>
          currentHosts.map((host) => {
            const hostConnections = connections.filter(
              (item) => (item.host_id || item.host_name) === host.id
            );
            const connection = hostConnections[0];
            const numPorts = hostConnections.filter(
              (item) => item.enabled !== false
            ).length;

            if (!connection) {
              return {
                ...host,
                numPorts,
                forwardingConfigs: [],
              };
            }

            return {
              ...host,
              numPorts,
              forwardingConfigs: hostConnections.map(mapConnectionToForwardingConfig),
            };
          })
        );
      } catch (loadError) {
        if (loadError?.response?.data?.detail !== "User not logged in") {
          error("Could not load saved forwarding configs");
        }
      }
    };

    loadConnections();
  }, []);

  const handleOpenConfig = (hostId) => setSelectedHostId(hostId);

  const handleCloseConfig = () => setSelectedHostId(null);

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
      for (const config of configsToDelete) {
        await axios.post(apiRoutes.deleteConnection, {
          data_id: config.dataId,
        });
      }

      const savedConfigs = [];

      for (const config of forwardingConfigs) {
        const payload = {
          data_id: config.dataId,
          host_id: currentHost.id,
          host_name: currentHost.name,
          host_ip: currentHost.ip,
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
                ...host,
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

  return (
    <div className="flex justify-center">
      <div className="m-4 pb-16 md:pb-6 xl:m-8 relative overflow-y-auto overflow-x-hidden 2xl:w-[80rem] w-full">
        <div>
          <>Hosts</>
          <div className="flex flex-wrap items-center mt-2 gap-2 cursor-pointer">
            {hosts.map((host) => (
              <HostItem
                key={host.id}
                name={host.name}
                ip={host.ip}
                isActive={host.isActive}
                numPorts={host.numPorts}
                lastSeen={host.lastSeen}
                onClick={() => handleOpenConfig(host.id)}
              />
            ))}
          </div>
        </div>
      </div>
      <HostConfigPopup
        host={selectedHost}
        opened={Boolean(selectedHost)}
        onClose={handleCloseConfig}
        onSave={handleSaveConfig}
        isSaving={isSaving}
      />
    </div>
  );
}
