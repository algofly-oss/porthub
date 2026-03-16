import { BsCircleFill } from "react-icons/bs";

export default function HostItem({
  name,
  ip,
  isActive,
  lastSeen,
  numPorts,
  onClick,
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex flex-col bg-white dark:bg-zinc-900 border border-zinc-100 dark:border-zinc-800 rounded-lg p-4 w-52 text-left transition-shadow hover:shadow-md focus:outline-none focus:ring-0 focus-visible:outline-none focus-visible:ring-0"
    >
      <div className="flex items-center mb-2 space-x-2">
        <BsCircleFill
          size={8}
          className={isActive ? "text-emerald-500" : "text-red-400"}
          aria-label={isActive ? "Online" : "Offline"}
        />
        <span className="font-medium">{name}</span>
      </div>
      <div className="flex items-center justify-between">
        <span className="text-xs text-zinc-400 font-mono">
          {ip} {numPorts > 0 && `(${numPorts} ports)`}
        </span>
      </div>
      <div className="flex items-center justify-between mt-0.5">
        <span className="text-xs text-zinc-400 font-mono">
          {lastSeen || "Never seen"}
        </span>
      </div>
    </button>
  );
}
