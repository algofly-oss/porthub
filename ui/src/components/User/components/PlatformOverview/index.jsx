import { useEffect, useState } from "react";
import axios from "axios";
import { FiChevronDown, FiChevronUp, FiRefreshCw } from "react-icons/fi";
import apiRoutes from "@/shared/routes/apiRoutes";
import useToast from "@/shared/hooks/useToast";

const panelClass =
  "overflow-hidden rounded-xl border border-zinc-200 bg-white shadow-sm dark:border-zinc-700 dark:bg-zinc-900";
const secondaryButtonClass =
  "inline-flex items-center justify-center gap-2 rounded-md border border-zinc-300 bg-white px-3 py-2 text-sm font-medium text-zinc-700 transition hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-60 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200 dark:hover:bg-zinc-800";

const STATUS_BADGE_CLASSES = {
  online: "bg-emerald-100 text-emerald-800 dark:bg-emerald-500/10 dark:text-emerald-300",
  offline: "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  disabled: "bg-amber-100 text-amber-800 dark:bg-amber-500/10 dark:text-amber-300",
  auth_required: "bg-sky-100 text-sky-800 dark:bg-sky-500/10 dark:text-sky-300",
};

const formatStatusLabel = (status) => {
  switch (status) {
    case "online":
      return "Online";
    case "auth_required":
      return "Auth required";
    case "disabled":
      return "Disabled";
    default:
      return "Offline";
  }
};

const StatusBadge = ({ status }) => (
  <span
    className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${
      STATUS_BADGE_CLASSES[status] || STATUS_BADGE_CLASSES.offline
    }`}
  >
    {formatStatusLabel(status)}
  </span>
);

export default function PlatformOverview() {
  const toast = useToast();
  const [overview, setOverview] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [expandedUserIds, setExpandedUserIds] = useState(new Set());
  const [expandedMachineIds, setExpandedMachineIds] = useState(new Set());

  const loadOverview = async () => {
    setIsLoading(true);
    try {
      const response = await axios.get(apiRoutes.adminOverview);
      setOverview(response?.data?.data || []);
    } catch (requestError) {
      toast.error(
        requestError?.response?.data?.detail || "Failed to load platform overview."
      );
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadOverview();
  }, []);

  const toggleUserExpanded = (userId) => {
    setExpandedUserIds((current) => {
      const next = new Set(current);
      if (next.has(userId)) {
        next.delete(userId);
      } else {
        next.add(userId);
      }
      return next;
    });
  };

  const toggleMachineExpanded = (machineId) => {
    setExpandedMachineIds((current) => {
      const next = new Set(current);
      if (next.has(machineId)) {
        next.delete(machineId);
      } else {
        next.add(machineId);
      }
      return next;
    });
  };

  const totalMachines = overview.reduce((sum, entry) => sum + entry.machines.length, 0);
  const totalOnline = overview.reduce(
    (sum, entry) =>
      sum + entry.machines.filter((machine) => machine.connection_status === "online").length,
    0
  );

  return (
    <div className="flex justify-center">
      <div className="m-4 flex w-full flex-col gap-5 pb-16 md:pb-6 xl:m-8 2xl:w-[80rem]">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-sm font-semibold uppercase tracking-[0.2em] text-zinc-500">
              Admin
            </p>
            <h1 className="mt-1 text-2xl font-semibold text-zinc-900 dark:text-zinc-100">
              Platform overview
            </h1>
            <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">
              {overview.length} users · {totalMachines} machines · {totalOnline} online
            </p>
          </div>
          <button
            type="button"
            className={secondaryButtonClass}
            onClick={loadOverview}
            disabled={isLoading}
          >
            <FiRefreshCw size={14} />
            Refresh
          </button>
        </div>

        {isLoading ? (
          <div className={`${panelClass} px-5 py-6 text-sm text-zinc-500 dark:text-zinc-400`}>
            Loading platform overview...
          </div>
        ) : overview.length === 0 ? (
          <div className={`${panelClass} px-5 py-6 text-sm text-zinc-500 dark:text-zinc-400`}>
            No users found.
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            {overview.map((entry) => {
              const isExpanded = expandedUserIds.has(entry.user.id);
              const onlineCount = entry.machines.filter(
                (machine) => machine.connection_status === "online"
              ).length;

              return (
                <section key={entry.user.id} className={panelClass}>
                  <button
                    type="button"
                    onClick={() => toggleUserExpanded(entry.user.id)}
                    className="flex w-full items-center justify-between gap-4 px-5 py-4 text-left"
                  >
                    <div>
                      <p className="text-sm font-semibold">
                        {entry.user.name || entry.user.email}
                        {entry.user.role === "admin" ? (
                          <span className="ml-2 rounded-full bg-blue-100 px-2 py-0.5 text-[11px] font-medium text-blue-700 dark:bg-blue-500/10 dark:text-blue-300">
                            Admin
                          </span>
                        ) : null}
                      </p>
                      <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
                        {entry.user.email}
                      </p>
                    </div>
                    <div className="flex items-center gap-4 text-sm text-zinc-500 dark:text-zinc-400">
                      <span>
                        {entry.machines.length} machine{entry.machines.length === 1 ? "" : "s"}
                        {" · "}
                        {onlineCount} online
                      </span>
                      {isExpanded ? <FiChevronUp size={16} /> : <FiChevronDown size={16} />}
                    </div>
                  </button>

                  {isExpanded ? (
                    <div className="divide-y divide-zinc-100 border-t border-zinc-200 dark:divide-zinc-800 dark:border-zinc-700">
                      {entry.machines.length === 0 ? (
                        <div className="px-5 py-4 text-sm text-zinc-500 dark:text-zinc-400">
                          No machines registered.
                        </div>
                      ) : (
                        entry.machines.map((machine) => {
                          const isMachineExpanded = expandedMachineIds.has(machine._id);
                          const ports = machine.ports || [];

                          return (
                            <div key={machine._id}>
                              <button
                                type="button"
                                onClick={() => toggleMachineExpanded(machine._id)}
                                disabled={ports.length === 0}
                                className="flex w-full flex-wrap items-center justify-between gap-3 px-5 py-3 text-left disabled:cursor-default"
                              >
                                <div className="min-w-0">
                                  <p className="truncate text-sm font-medium">{machine.name}</p>
                                  <p className="mt-0.5 truncate text-xs text-zinc-500 dark:text-zinc-400">
                                    {machine.hostname || "No hostname"}
                                  </p>
                                </div>
                                <div className="flex items-center gap-3 text-xs text-zinc-500 dark:text-zinc-400">
                                  <span>
                                    {ports.length} port{ports.length === 1 ? "" : "s"}
                                  </span>
                                  <StatusBadge status={machine.connection_status} />
                                  {ports.length > 0 ? (
                                    isMachineExpanded ? (
                                      <FiChevronUp size={14} />
                                    ) : (
                                      <FiChevronDown size={14} />
                                    )
                                  ) : null}
                                </div>
                              </button>

                              {isMachineExpanded && ports.length > 0 ? (
                                <div className="overflow-x-auto px-5 pb-3">
                                  <table className="w-full min-w-[480px] border-collapse text-xs">
                                    <thead>
                                      <tr className="text-left text-zinc-500 dark:text-zinc-400">
                                        <th className="py-1.5 pr-4 font-medium">Service</th>
                                        <th className="py-1.5 pr-4 font-medium">External port</th>
                                        <th className="py-1.5 pr-4 font-medium">Internal target</th>
                                        <th className="py-1.5 pr-4 font-medium">State</th>
                                      </tr>
                                    </thead>
                                    <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800">
                                      {ports.map((port) => (
                                        <tr key={port._id}>
                                          <td className="py-1.5 pr-4 text-zinc-700 dark:text-zinc-300">
                                            {port.service_name || "Unnamed"}
                                          </td>
                                          <td className="py-1.5 pr-4 font-mono text-zinc-700 dark:text-zinc-300">
                                            {port.external_port ?? "—"}
                                          </td>
                                          <td className="py-1.5 pr-4 font-mono text-zinc-700 dark:text-zinc-300">
                                            {port.internal_ip}:{port.internal_port ?? "—"}
                                          </td>
                                          <td className="py-1.5 pr-4">
                                            <span
                                              className={`inline-flex rounded-full px-2 py-0.5 text-[11px] font-medium ${
                                                port.enabled
                                                  ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-500/10 dark:text-emerald-300"
                                                  : "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
                                              }`}
                                            >
                                              {port.enabled ? "Enabled" : "Disabled"}
                                            </span>
                                          </td>
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                </div>
                              ) : null}
                            </div>
                          );
                        })
                      )}
                    </div>
                  ) : null}
                </section>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
