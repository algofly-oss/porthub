import { TableRow, TableCell } from "@/components/ui/table";
import { IconFolder } from "@tabler/icons-react";
import TrafficSparkline from "@/components/ui/traffic-sparkline";

export default function HostItem({ name, hostname, groupLabels = [], localIp, publicIp, clientVersion, forwardingConfigs = [], isActive, connectionStatus, lastSeen, trafficSamples = [], onClick }) {
  const status = connectionStatus || (isActive ? "online" : "offline");
  const statusLabel = { online: "Online", offline: "Offline", disabled: "Disabled", auth_required: "Auth required" }[status] || "Offline";
  const labels = groupLabels.filter(Boolean);
  const activePorts = forwardingConfigs.filter(port => port.enabled !== false).length;
  return <TableRow className="group cursor-pointer" data-machine-status={status} onClick={onClick}>
    <TableCell className="py-3">
      <button type="button" className="flex w-full min-w-0 items-start gap-3 rounded text-left" aria-label={`Configure ${name}`}>
        <span aria-label={statusLabel} className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${status === "online" ? "bg-emerald-500" : status === "offline" ? "bg-red-600 dark:bg-red-400" : status === "auth_required" ? "bg-amber-400" : "bg-zinc-500"}`} />
        <span className="min-w-0"><span className="block truncate text-[15px] font-medium">{name}</span><span className="mt-1 block truncate text-xs text-muted-foreground"><span className={status === "online" ? "text-emerald-700 dark:text-emerald-400" : status === "offline" ? "text-red-700 dark:text-red-400" : status === "auth_required" ? "text-amber-700 dark:text-amber-400" : ""}>{statusLabel}</span> · {status !== "online" && lastSeen ? lastSeen : hostname || "Awaiting client"}{clientVersion ? ` · v${clientVersion}` : ""}</span></span>
      </button>
      <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 pl-5 text-xs text-muted-foreground lg:hidden">{localIp && <span className="font-mono">{localIp}</span>}{labels.length > 0 && <span>{labels.join(" · ")}</span>}</div>
    </TableCell>
    <TableCell className="hidden lg:table-cell"><p className="truncate font-mono text-xs"><span className="mr-2 font-sans text-[11px] text-muted-foreground">LAN</span>{localIp || "Pending"}</p><p className="mt-1.5 truncate font-mono text-xs text-muted-foreground"><span className="mr-2 font-sans text-[11px]">WAN</span>{publicIp || "Pending"}</p></TableCell>
    <TableCell className="hidden md:table-cell"><span className="inline-flex max-w-full items-center gap-2 text-xs text-muted-foreground" title={labels.join(", ")}>{labels.length ? <><IconFolder size={15} className="shrink-0" /><span className="truncate">{labels[0]}</span>{labels.length > 1 && <span>+{labels.length - 1}</span>}</> : "—"}</span></TableCell>
    <TableCell className="text-right" aria-label={`${activePorts} enabled ports`}><p className="text-sm font-medium tabular-nums">{activePorts}</p></TableCell>
    <TableCell className="hidden lg:table-cell"><div className="ml-auto w-40"><TrafficSparkline samples={trafficSamples} label={`${name} traffic`} /></div></TableCell>
  </TableRow>;
}
