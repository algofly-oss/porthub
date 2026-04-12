import { useState } from "react";
import { BsCircleFill } from "react-icons/bs";

export default function HostItem({
  machineId,
  draggable = false,
  dndMimeType = "application/x-porthub-machine-id",
  onMachineDragEnd,
  name,
  hostname,
  groupLabels = [],
  localIp,
  publicIp,
  isActive,
  connectionStatus,
  isDark,
  lastSeen,
  numPorts,
  onClick,
}) {
  const [isDragging, setIsDragging] = useState(false);
  const resolvedStatus = connectionStatus || (isActive ? "online" : "offline");
  const isDisabled = resolvedStatus === "disabled";
  const isAuthRequired = resolvedStatus === "auth_required";
  const isOnline = resolvedStatus === "online";
  const canDrag = Boolean(draggable && machineId);
  const labels = Array.isArray(groupLabels) ? groupLabels.filter(Boolean) : [];

  const handleDragStart = (event) => {
    if (!canDrag) {
      return;
    }
    event.dataTransfer.setData(dndMimeType, machineId);
    event.dataTransfer.setData("text/plain", machineId);
    event.dataTransfer.effectAllowed = "move";
    setIsDragging(true);
  };

  const handleDragEnd = () => {
    setIsDragging(false);
    onMachineDragEnd?.();
  };

  return (
    <button
      type="button"
      draggable={canDrag}
      onDragStart={handleDragStart}
      onDragEnd={handleDragEnd}
      onClick={onClick}
      className={`w-full bg-white px-5 py-4 text-left hover:bg-zinc-50 focus:outline-none focus:ring-0 focus-visible:outline-none focus-visible:ring-0 dark:bg-zinc-900 dark:hover:bg-zinc-800/70 ${
        canDrag ? "cursor-grab active:cursor-grabbing" : ""
      } ${isDragging ? "opacity-60" : ""}`}
    >
      <div className="grid gap-3 md:grid-cols-[minmax(0,1.3fr)_110px_minmax(0,0.85fr)_minmax(0,0.85fr)_120px_160px] md:items-center">
        <div className="grid min-w-0 grid-cols-[8px_minmax(0,1fr)] items-start gap-x-2">
          <BsCircleFill
            size={8}
            className={`row-span-2 mt-1 ${
              isOnline
                ? "text-emerald-500"
                : isDisabled
                  ? "text-zinc-400"
                  : isAuthRequired
                    ? "text-amber-500"
                    : "text-red-400"
            }`}
            aria-label={
              isOnline
                ? "Online"
                : isDisabled
                  ? "Disabled"
                  : isAuthRequired
                    ? "Auth required"
                    : "Offline"
            }
          />
          <span className="truncate font-medium text-zinc-900 dark:text-zinc-100">
            {name}
          </span>
          <div className="text-xs font-mono text-zinc-400">
            {hostname || "Awaiting hostname"}
          </div>
          {labels.length > 0 ? (
            <div className="col-start-2 mt-1 flex flex-wrap gap-1">
              {labels.slice(0, 4).map((label, idx) => (
                <span
                  key={`${label}-${idx}`}
                  className="inline-flex max-w-full truncate rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-blue-700/95 ring-1 ring-blue-500/25 dark:text-blue-200/90 dark:ring-blue-400/30"
                >
                  {label}
                </span>
              ))}
              {labels.length > 4 ? (
                <span className="text-[10px] font-medium text-zinc-500 dark:text-zinc-400">
                  +{labels.length - 4}
                </span>
              ) : null}
            </div>
          ) : null}
        </div>

        <div className="text-center text-xs font-mono text-zinc-500 dark:text-zinc-400">
          {numPorts} ports
        </div>

        <div className="text-xs font-mono text-zinc-500 dark:text-zinc-400">
          {localIp || "Awaiting local IP"}
        </div>

        <div className="text-xs font-mono text-zinc-500 dark:text-zinc-400">
          {publicIp || "Awaiting public IP"}
        </div>

        <div className="text-center">
          <span
            className={`inline-flex whitespace-nowrap rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.12em] ${
              isOnline
                ? isDark
                  ? "border-emerald-400/30 bg-emerald-400/18 text-emerald-200"
                  : "border-emerald-200 bg-emerald-50 text-emerald-700"
                : isDisabled
                  ? isDark
                    ? "border-zinc-500/25 bg-zinc-500/14 text-zinc-200"
                    : "border-zinc-300 bg-zinc-100 text-zinc-700"
                  : isAuthRequired
                    ? isDark
                      ? "border-amber-400/30 bg-amber-400/18 text-amber-200"
                      : "border-amber-200 bg-amber-50 text-amber-700"
                    : isDark
                      ? "border-red-400/25 bg-red-400/14 text-red-200"
                      : "border-red-200 bg-red-50 text-red-700"
            }`}
          >
            {isOnline
              ? "Online"
              : isDisabled
                ? "Disabled"
                : isAuthRequired
                  ? "Auth Req"
                  : "Offline"}
          </span>
        </div>

        <div className="text-xs font-mono text-zinc-400 md:text-right">
          {lastSeen || "Never seen"}
        </div>
      </div>
    </button>
  );
}
