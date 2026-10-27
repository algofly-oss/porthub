import MachineOsIcon from "@/components/ui/machine-os-icon";
import { countryDetails, platformLabel } from "@/shared/utils/machine-platform.mjs";
import { TableRow, TableCell } from "@/components/ui/table";
import { IconCopy, IconFolder } from "@tabler/icons-react";
import useToast from "@/shared/hooks/useToast";
import TrafficSparkline from "@/components/ui/traffic-sparkline";
import { formatClientVersion } from "@/shared/utils/client-version.mjs";

export default function HostItem({ name, hostname, privateDomain = "", groupLabels = [], localIp, privateIps = [], clientVersion, clientUpdateAvailable, latestClientVersion, clientOs = "", clientOsId = "", clientOsName = "", clientArch = "", clientCountry = "", forwardingConfigs = [], isActive, connectionStatus, lastSeen, trafficSamples = [], onClick }) {
  const { success, error } = useToast();
  const copyValue = async (event, value, label) => {
    event.stopPropagation();
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
      } else {
        const input = document.createElement("textarea");
        input.value = value;
        input.style.position = "fixed";
        input.style.top = "-9999px";
        document.body.appendChild(input);
        try {
          input.select();
          if (!document.execCommand("copy")) throw new Error("Copy failed");
        } finally { input.remove(); }
      }
      success(`${label} copied`);
    } catch { error(`Could not copy ${label.toLowerCase()}`); }
  };
  const privateAddress = privateIps.length ? privateIps.map(ip => (
    <span key={ip} className="inline-flex min-w-0 items-center gap-1">
      <span className="truncate">{ip}</span>
      <button type="button" onClick={event => copyValue(event, ip, "Private IP")}
        aria-label={`Copy private IP ${ip}`} title="Copy private IP"
        className="inline-flex shrink-0 items-center rounded p-1 hover:bg-accent hover:text-foreground focus-visible:outline focus-visible:outline-2">
        <IconCopy size={12} />
      </button>
    </span>
  )) : "Not enrolled";
  const status = connectionStatus || (isActive ? "online" : "offline");
  const statusLabel = { online: "Online", offline: "Offline", disabled: "Disabled", auth_required: "Auth required" }[status] || "Offline";
  const labels = groupLabels.filter(Boolean);
  const activePorts = forwardingConfigs.filter(port => port.enabled !== false).length;
  const clientVersionLabel = formatClientVersion(clientVersion, "");
  const latestClientVersionLabel = formatClientVersion(latestClientVersion);
  const osLabel = platformLabel(clientOs, clientOsName, clientArch);
  const { flag, name: countryName } = countryDetails(clientCountry);
  return <TableRow className="group cursor-pointer" data-machine-status={status} onClick={onClick}>
    <TableCell className="py-3">
      <div className="flex min-w-0 items-start gap-3">
        <span aria-label={statusLabel} className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${status === "online" ? "bg-emerald-500" : status === "offline" ? "bg-red-600 dark:bg-red-400" : status === "auth_required" ? "bg-amber-400" : "bg-zinc-500"}`} />
        <span className="min-w-0 flex-1">
          <span className="flex min-w-0 items-center gap-1">
            <button type="button" className="min-w-0 truncate rounded text-left text-[15px] font-medium" aria-label={`Configure ${name}`}>{name}</button>
            {osLabel && <span className="inline-flex shrink-0 items-center text-muted-foreground" title={osLabel} aria-label={osLabel}><MachineOsIcon os={clientOs} distribution={clientOsId} size={15} /></span>}
            {flag && <span className="shrink-0 text-sm" title={countryName} aria-label={countryName}>{flag}</span>}
            {privateDomain && <button type="button" onClick={event => copyValue(event, `http://${privateDomain}`, "PortHub domain address")}
              aria-label={`Copy PortHub address http://${privateDomain}`} title={`Copy http://${privateDomain}`}
              className="inline-flex shrink-0 items-center rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline focus-visible:outline-2">
              <IconCopy size={14} />
            </button>}
          </span>
          <span className="mt-1 block truncate text-xs text-muted-foreground"><span className={status === "online" ? "text-emerald-700 dark:text-emerald-400" : status === "offline" ? "text-red-700 dark:text-red-400" : status === "auth_required" ? "text-amber-700 dark:text-amber-400" : ""}>{statusLabel}</span> · {status !== "online" && lastSeen ? lastSeen : hostname || "Awaiting client"}{clientVersionLabel ? <> · <span className={clientUpdateAvailable ? "text-amber-700 dark:text-amber-400" : ""} title={clientUpdateAvailable ? `Update available: ${latestClientVersionLabel}` : "Latest client version"}>{clientVersionLabel}</span></> : ""}</span>
        </span>
      </div>
      <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 pl-5 text-xs text-muted-foreground lg:hidden">{localIp && <span className="inline-flex items-center gap-1 font-mono">LAN {localIp}<button type="button" onClick={event => copyValue(event, localIp, "LAN IP")} aria-label={`Copy LAN IP ${localIp}`} title="Copy LAN IP" className="inline-flex shrink-0 items-center rounded p-1 hover:bg-accent hover:text-foreground focus-visible:outline focus-visible:outline-2"><IconCopy size={12} /></button></span>}{privateIps.length > 0 && <span className="inline-flex items-center gap-2 font-mono">PAN {privateAddress}</span>}{labels.length > 0 && <span>{labels.join(" · ")}</span>}</div>
    </TableCell>
    <TableCell className="hidden lg:table-cell"><p className="inline-flex max-w-full items-center gap-1 truncate font-mono text-xs"><span className="mr-2 font-sans text-[11px] text-muted-foreground">LAN</span>{localIp || "Not reported"}{localIp && <button type="button" onClick={event => copyValue(event, localIp, "LAN IP")} aria-label={`Copy LAN IP ${localIp}`} title="Copy LAN IP" className="inline-flex shrink-0 items-center rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline focus-visible:outline-2"><IconCopy size={12} /></button>}</p><div className="mt-1.5 flex flex-wrap items-center gap-x-2 font-mono text-xs text-muted-foreground"><span className="font-sans text-[11px]">PAN</span>{privateAddress}</div></TableCell>
    <TableCell className="hidden md:table-cell"><span className="inline-flex max-w-full items-center gap-2 text-xs text-muted-foreground" title={labels.join(", ")}>{labels.length ? <><IconFolder size={15} className="shrink-0" /><span className="truncate">{labels[0]}</span>{labels.length > 1 && <span>+{labels.length - 1}</span>}</> : "—"}</span></TableCell>
    <TableCell className="text-right" aria-label={`${activePorts} of ${forwardingConfigs.length} ports enabled`}><p className="text-sm font-medium tabular-nums" title={`${activePorts} active of ${forwardingConfigs.length} registered ports`}>{activePorts}{forwardingConfigs.length > activePorts && <span className="font-normal text-muted-foreground"> / {forwardingConfigs.length}</span>}</p></TableCell>
    <TableCell className="hidden lg:table-cell"><div className="ml-auto w-40"><TrafficSparkline samples={trafficSamples} label={`${name} traffic`} /></div></TableCell>
  </TableRow>;
}
