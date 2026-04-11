import { BsCircleFill } from "react-icons/bs";

export default function HostItem({
  name,
  hostname,
  localIp,
  publicIp,
  isActive,
  lastSeen,
  numPorts,
  onClick,
}) {
  return (
      <button
        type="button"
        onClick={onClick}
        className="w-full bg-white px-5 py-4 text-left hover:bg-zinc-50 focus:outline-none focus:ring-0 focus-visible:outline-none focus-visible:ring-0 dark:bg-zinc-900 dark:hover:bg-zinc-800/70"
      >
      <div className="grid gap-3 md:grid-cols-[minmax(0,1.3fr)_110px_minmax(0,0.85fr)_minmax(0,0.85fr)_120px_160px] md:items-center">
        <div className="grid min-w-0 grid-cols-[8px_minmax(0,1fr)] items-start gap-x-2">
          <BsCircleFill
            size={8}
            className={`row-span-2 mt-1 ${
              isActive ? "text-emerald-500" : "text-red-400"
            }`}
            aria-label={isActive ? "Online" : "Offline"}
          />
          <span className="truncate font-medium text-zinc-900 dark:text-zinc-100">
            {name}
          </span>
          <div className="text-xs font-mono text-zinc-400">
            {hostname || "Awaiting hostname"}
          </div>
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
            className={`inline-flex rounded-full px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.12em] ${
              isActive
                ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300"
                : "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-300"
            }`}
          >
            {isActive ? "Connected" : "Offline"}
          </span>
        </div>

        <div className="text-xs font-mono text-zinc-400 md:text-right">
          {lastSeen || "Never seen"}
        </div>
      </div>
    </button>
  );
}
