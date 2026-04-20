import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import {
  Button,
  Menu,
  Pagination,
  SegmentedControl,
  useMantineColorScheme,
} from "@mantine/core";
import { IconChevronDown, IconPlus } from "@tabler/icons-react";
import apiRoutes from "@/shared/routes/apiRoutes";
import useToast from "@/shared/hooks/useToast";
import ProxyConfigModal from "./ProxyConfigModal";

const PAGE_SIZE_OPTIONS = [
  { value: "10", label: "10" },
  { value: "25", label: "25" },
  { value: "50", label: "50" },
];

const mapConnectionOption = (connection) => ({
  _id: connection._id,
  machine_id: connection.machine_id || "",
  machine_name: connection.machine_name || "",
  machine_hostname: connection.machine_hostname || "",
  machine_local_ip: connection.machine_local_ip || "",
  machine_public_ip: connection.machine_public_ip || "",
  machine_enabled: connection.machine_enabled ?? true,
  machine_is_active: connection.machine_is_active ?? false,
  machine_connection_status: connection.machine_connection_status || "unknown",
  service_name: connection.service_name || "",
  service_description: connection.service_description || "",
  internal_ip: connection.internal_ip || "0.0.0.0",
  internal_port: connection.internal_port || null,
  external_port: connection.external_port || null,
  enabled: connection.enabled ?? true,
});

const mapMachineOption = (machine) => ({
  _id: machine._id,
  name: machine.name || "Untitled machine",
  hostname: machine.hostname || "",
  local_ip: machine.local_ip || "",
  public_ip: machine.public_ip || "",
  enabled: machine.enabled ?? true,
  is_active: machine.is_active ?? false,
  connection_status: machine.connection_status || "unknown",
});

const mapProxy = (route) => ({
  _id: route._id,
  name: route.name || "",
  description: route.description || "",
  hosts: Array.isArray(route.hosts) ? route.hosts : [],
  target_mode: route.target_mode || "manual",
  target_url: route.target_url || "",
  entry_points: Array.isArray(route.entry_points) ? route.entry_points : ["web"],
  enabled: route.enabled ?? true,
  connection: route.connection || null,
  created_at: route.created_at || null,
  updated_at: route.updated_at || null,
});

const formatUpdatedAt = (value) => {
  if (!value) {
    return "Unknown";
  }
  const parsed = new Date(typeof value === "string" && !/[z+-]\d*$/i.test(value) ? `${value}Z` : value);
  if (Number.isNaN(parsed.getTime())) {
    return "Unknown";
  }
  return parsed.toLocaleString();
};

export default function Proxy() {
  const { colorScheme } = useMantineColorScheme();
  const isDark = colorScheme === "dark";
  const { success, error } = useToast();
  const [proxies, setProxies] = useState([]);
  const [connections, setConnections] = useState([]);
  const [machines, setMachines] = useState([]);
  const [defaultDomainSuffix, setDefaultDomainSuffix] = useState("");
  const [serviceDomain, setServiceDomain] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [statusFilter, setStatusFilter] = useState("all");
  const [pageSize, setPageSize] = useState("10");
  const [page, setPage] = useState(1);
  const [selectedProxyId, setSelectedProxyId] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  useEffect(() => {
    const loadData = async () => {
      setIsLoading(true);
      try {
        const [trafficRoutesResponse, connectionsResponse, machinesResponse, authSettingsResponse] = await Promise.all([
          axios.get(apiRoutes.listTrafficRoutes),
          axios.get(apiRoutes.listConnections),
          axios.get(apiRoutes.listMachines),
          axios.get(apiRoutes.authSettings).catch(() => ({ data: {} })),
        ]);

        setProxies(
          (Array.isArray(trafficRoutesResponse.data?.data)
            ? trafficRoutesResponse.data.data
            : []
          ).map(mapProxy)
        );
        setConnections(
          (Array.isArray(connectionsResponse.data?.data)
            ? connectionsResponse.data.data
            : []
          )
            .map(mapConnectionOption)
            .sort((left, right) => {
              if ((left.machine_name || "") !== (right.machine_name || "")) {
                return (left.machine_name || "").localeCompare(right.machine_name || "");
              }
              if ((left.service_name || "") !== (right.service_name || "")) {
                return (left.service_name || "").localeCompare(right.service_name || "");
              }
              return Number(left.external_port || 0) - Number(right.external_port || 0);
            })
        );
        setMachines(
          (Array.isArray(machinesResponse.data?.data)
            ? machinesResponse.data.data
            : []
          )
            .map(mapMachineOption)
            .sort((left, right) => (left.name || "").localeCompare(right.name || ""))
        );
        setDefaultDomainSuffix(
          String(authSettingsResponse.data?.web_proxy_domain_suffix || "")
            .trim()
            .toLowerCase()
        );
        setServiceDomain(
          String(authSettingsResponse.data?.port_hub_service_domain || "").trim()
        );
      } catch (loadError) {
        if (loadError?.response?.data?.detail !== "User not logged in") {
          error("Could not load proxies");
        }
      } finally {
        setIsLoading(false);
      }
    };

    loadData();
  }, []);

  useEffect(() => {
    setPage(1);
  }, [pageSize, statusFilter]);

  const filteredProxies = useMemo(
    () =>
      proxies.filter((proxy) => {
        if (statusFilter === "all") {
          return true;
        }
        return statusFilter === "enabled" ? proxy.enabled : !proxy.enabled;
      }),
    [proxies, statusFilter]
  );

  const numericPageSize = Number(pageSize);
  const totalPages = Math.max(1, Math.ceil(filteredProxies.length / numericPageSize));
  const visibleStart = filteredProxies.length === 0 ? 0 : (page - 1) * numericPageSize + 1;
  const visibleEnd = Math.min(page * numericPageSize, filteredProxies.length);
  const paginatedProxies = useMemo(
    () =>
      filteredProxies.slice(
        (page - 1) * numericPageSize,
        page * numericPageSize
      ),
    [filteredProxies, numericPageSize, page]
  );

  useEffect(() => {
    if (page > totalPages) {
      setPage(totalPages);
    }
  }, [page, totalPages]);

  const selectedProxy =
    proxies.find((proxy) => proxy._id === selectedProxyId) || null;

  const handleOpenCreate = () => {
    setSelectedProxyId(null);
    setIsModalOpen(true);
  };

  const handleOpenEdit = (proxyId) => {
    setSelectedProxyId(proxyId);
    setIsModalOpen(true);
  };

  const handleSubmit = async (payload) => {
    setIsSaving(true);
    try {
      const response = payload.data_id
        ? await axios.put(apiRoutes.updateTrafficRoute, payload)
        : await axios.post(apiRoutes.addTrafficRoute, payload);
      const savedProxy = mapProxy(response.data?.data || {});

      setProxies((current) => {
        const exists = current.some((proxy) => proxy._id === savedProxy._id);
        if (!exists) {
          return [...current, savedProxy];
        }
        return current.map((proxy) =>
          proxy._id === savedProxy._id ? savedProxy : proxy
        );
      });
      setSelectedProxyId(savedProxy._id);

      success(`Proxy ${payload.data_id ? "updated" : "created"} successfully`);
      return savedProxy;
    } catch (saveError) {
      error(saveError?.response?.data?.detail || "Could not save proxy");
      return null;
    } finally {
      setIsSaving(false);
    }
  };

  const handleDelete = async (proxyId) => {
    setIsDeleting(true);
    try {
      await axios.post(apiRoutes.deleteTrafficRoute, { data_id: proxyId });
      setProxies((current) => current.filter((proxy) => proxy._id !== proxyId));
      setSelectedProxyId(null);
      success("Proxy deleted");
      return true;
    } catch (deleteError) {
      error(deleteError?.response?.data?.detail || "Could not delete proxy");
      return false;
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div className="flex justify-center">
      <div className="m-4 pb-16 md:pb-6 xl:m-8 relative overflow-y-auto overflow-x-hidden 2xl:w-[80rem] w-full">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="text-sm font-semibold uppercase tracking-[0.2em] text-zinc-500">
              Web Proxy
            </p>
            <h1 className="mt-1 text-2xl font-semibold text-zinc-900 dark:text-zinc-100">
              Web proxy entries
            </h1>
          </div>
          <div className="flex flex-wrap items-center justify-end gap-2">
            <Button
              type="button"
              leftIcon={<IconPlus size={16} />}
              onClick={handleOpenCreate}
              classNames={{
                root:
                  "!bg-blue-600 !text-blue-50 hover:!bg-blue-700 disabled:!bg-blue-400",
              }}
            >
              Create proxy
            </Button>
          </div>
        </div>

        <div className="mt-6">
          {isLoading ? (
            <p className="text-sm text-zinc-500 dark:text-zinc-400">
              Loading proxies...
            </p>
          ) : proxies.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-zinc-300 bg-zinc-50 px-6 py-10 text-center dark:border-zinc-700 dark:bg-zinc-900/60">
              <p className="text-lg font-medium text-zinc-900 dark:text-zinc-100">
                No proxies yet
              </p>
              <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">
                Create a subdomain proxy and point it at either an existing mapped port-pair service or a manual HTTP target.
              </p>
            </div>
          ) : (
            <>
              <div className="mb-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <SegmentedControl
                  value={statusFilter}
                  onChange={setStatusFilter}
                  data={[
                    { value: "all", label: "All" },
                    { value: "enabled", label: "Enabled" },
                    { value: "disabled", label: "Disabled" },
                  ]}
                  classNames={{
                    root: "!rounded-lg !bg-zinc-100 !p-1 dark:!bg-zinc-800",
                    control: "!border-transparent",
                    label:
                      "!text-zinc-600 dark:!text-zinc-300 data-[active=true]:!text-blue-50",
                    indicator:
                      "!rounded-md !bg-blue-600 !shadow-sm dark:!bg-blue-600",
                  }}
                />

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
                    {PAGE_SIZE_OPTIONS.map((option) => (
                      <Menu.Item
                        key={option.value}
                        onClick={() => setPageSize(option.value)}
                        className={
                          option.value === pageSize
                            ? "!bg-blue-600 !text-blue-50 hover:!bg-blue-600 dark:!bg-blue-600 dark:!text-blue-50 dark:hover:!bg-blue-600"
                            : undefined
                        }
                      >
                        {option.label}
                      </Menu.Item>
                    ))}
                  </Menu.Dropdown>
                </Menu>
              </div>

              <div className="overflow-hidden rounded-xl border border-zinc-200 bg-white shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
                <div className="hidden min-h-16 border-b border-zinc-200 bg-zinc-50/80 py-4 pl-6 pr-6 text-[11px] font-semibold uppercase tracking-[0.18em] text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-500 md:grid md:grid-cols-[minmax(0,1.1fr)_minmax(0,1.2fr)_minmax(0,1fr)_minmax(0,1.1fr)_minmax(7rem,0.7fr)] md:items-center md:gap-4">
                  <span>Hostname</span>
                  <span>Source</span>
                  <span>Internal mapping</span>
                  <span>Target</span>
                  <span>Status</span>
                </div>

                {paginatedProxies.length > 0 ? (
                  <div
                    className="max-h-[calc(100dvh-22rem)] overflow-y-auto"
                    style={{ scrollbarGutter: "stable" }}
                  >
                    <div className="divide-y divide-zinc-200 dark:divide-zinc-800">
                      {paginatedProxies.map((proxy) => {
                        const primaryHost = proxy.hosts[0] || "No hostname";
                        const sourceConnection = proxy.connection;
                        return (
                          <button
                            key={proxy._id}
                            type="button"
                            onClick={() => handleOpenEdit(proxy._id)}
                            className="grid w-full gap-4 bg-white px-6 py-4 text-left hover:bg-zinc-50 dark:bg-zinc-900 dark:hover:bg-zinc-800/70 md:grid-cols-[minmax(0,1.1fr)_minmax(0,1.2fr)_minmax(0,1fr)_minmax(0,1.1fr)_minmax(7rem,0.7fr)] md:items-center"
                          >
                            <div className="min-w-0">
                              <a
                                href={`http://${primaryHost}`}
                                target="_blank"
                                rel="noreferrer"
                                onClick={(event) => event.stopPropagation()}
                                className="inline-block max-w-full truncate font-medium text-blue-600 hover:underline dark:text-blue-400"
                              >
                                {primaryHost}
                              </a>
                              <p className="truncate text-xs text-zinc-500 dark:text-zinc-400">
                                {proxy.description || "No description"}
                              </p>
                            </div>

                            <div className="min-w-0">
                              <p className="truncate text-sm text-zinc-900 dark:text-zinc-100">
                                {sourceConnection?.service_name || "Manual target"}
                              </p>
                              <p className="truncate text-xs text-zinc-500 dark:text-zinc-400">
                                {sourceConnection
                                  ? `${sourceConnection.machine_name || "Unknown machine"} • :${sourceConnection.external_port || "-"}`
                                  : "Custom web target"}
                              </p>
                            </div>

                            <div className="min-w-0">
                              {sourceConnection ? (
                                <>
                                  <p className="truncate font-mono text-sm text-zinc-900 dark:text-zinc-100">
                                    {sourceConnection.internal_ip || "0.0.0.0"}:{sourceConnection.internal_port || "-"}
                                  </p>
                                  <p className="truncate text-xs text-zinc-500 dark:text-zinc-400">
                                    External port {sourceConnection.external_port || "-"}
                                  </p>
                                </>
                              ) : (
                                <>
                                  <p className="truncate text-sm text-zinc-500 dark:text-zinc-400">
                                    Not applicable
                                  </p>
                                  <p className="truncate text-xs text-zinc-500 dark:text-zinc-400">
                                    Not using a mapped port
                                  </p>
                                </>
                              )}
                            </div>

                            <div className="min-w-0">
                              <p className="truncate font-mono text-xs text-zinc-700 dark:text-zinc-300">
                                {proxy.target_url || "-"}
                              </p>
                              <p className="truncate text-xs text-zinc-500 dark:text-zinc-400">
                                Updated {formatUpdatedAt(proxy.updated_at)}
                              </p>
                            </div>

                            <div>
                              <span
                                className={`inline-flex items-center rounded-md px-2 py-1 text-xs font-semibold ${
                                  proxy.enabled
                                    ? isDark
                                      ? "bg-emerald-500/14 text-emerald-200/80"
                                      : "bg-emerald-100/55 text-emerald-900/70"
                                    : isDark
                                      ? "bg-zinc-500/14 text-zinc-200/78"
                                      : "bg-zinc-100/80 text-zinc-900/62"
                                }`}
                              >
                                {proxy.enabled ? "Enabled" : "Disabled"}
                              </span>
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                ) : (
                  <div className="px-5 py-10 text-center">
                    <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">
                      No proxies match the current filters
                    </p>
                    <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">
                      Adjust the status filter to see more proxy entries.
                    </p>
                  </div>
                )}

                {filteredProxies.length > 0 ? (
                  <div className="flex min-h-16 flex-col gap-3 border-t border-zinc-200 px-5 py-4 dark:border-zinc-800 md:flex-row md:items-center md:justify-between">
                    <p className="text-sm text-zinc-500 dark:text-zinc-400">
                      Showing {visibleStart} to {visibleEnd} of {filteredProxies.length} proxies
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
        </div>
      </div>

      <ProxyConfigModal
        opened={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onSubmit={handleSubmit}
        onDelete={handleDelete}
        proxy={selectedProxy}
        connections={connections}
        machines={machines}
        defaultDomainSuffix={defaultDomainSuffix}
        serviceDomain={serviceDomain}
        isSaving={isSaving}
        isDeleting={isDeleting}
      />
    </div>
  );
}
