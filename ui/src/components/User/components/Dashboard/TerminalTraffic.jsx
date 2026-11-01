import { useMemo, useState } from "react";
import { useRouter } from "next/router";
import { IconTerminal2, IconPlayerPause, IconPlayerPlay } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import InventorySelect from "@/components/ui/inventory-select";
import useTerminalTraffic from "@/shared/hooks/useTerminalTraffic";
import { formatBytes } from "@/shared/utils/traffic.mjs";
import { terminalScopes, terminalRanges, terminalWindow } from "@/shared/utils/terminal-traffic.mjs";

const ALL_MACHINES = [{ value: "all", label: "All machines" }];

export default function TerminalTraffic({ active, refresh }) {
  const router = useRouter();
  const range = Object.hasOwn(terminalRanges, router.query.terminal_range) ? router.query.terminal_range : "1h";
  const scope = Object.hasOwn(terminalScopes, router.query.terminal_scope) ? router.query.terminal_scope : "relay";
  const machine = /^[a-f0-9]{24}$/.test(router.query.terminal_machine || "") ? router.query.terminal_machine : "all";
  const [paused, setPaused] = useState(false);
  const resource = useTerminalTraffic({ range, machine, enabled: active && router.isReady, paused, refresh });
  const rows = useMemo(() => terminalWindow(resource.data, scope), [resource.data, scope]);
  const selected = terminalScopes[scope], observed = rows.filter(row => row.incoming !== null);
  const incoming = observed.reduce((sum, row) => sum + row.incoming, 0), outgoing = observed.reduce((sum, row) => sum + row.outgoing, 0);
  const update = (key, value) => router.push({ pathname: router.pathname, query: { ...router.query, [key]: value } }, undefined, { shallow: true });
  const interval = resource.data?.interval_seconds || terminalRanges[range][1];
  const intervalLabel = interval < 60 ? `${interval} seconds` : interval === 60 ? "minute" : interval < 3600 ? `${interval / 60} minutes` : interval < 86400 ? `${interval / 3600} hours` : "day";
  return <section aria-label="Terminal traffic" className="min-w-0 overflow-hidden rounded-xl bg-surface">
    <div className="flex flex-wrap items-start justify-between gap-4 p-5 pb-3">
      <div><h2 className="flex items-center gap-2 text-base font-semibold"><IconTerminal2 size={18} className="text-muted-foreground" />Terminal traffic</h2><p className="mt-1 text-xs text-muted-foreground">Your terminal hosts · separate from public port traffic</p></div>
      <div className="flex w-full flex-wrap gap-2 sm:w-auto">
        <InventorySelect kind="machines" label="Terminal traffic machine" className="min-w-0 flex-1 basis-full sm:w-48 sm:flex-none sm:basis-auto" value={machine} onChange={value => update("terminal_machine", value)} extraOptions={ALL_MACHINES} />
        <label className="sr-only" htmlFor="terminal-traffic-range">Terminal traffic range</label><select id="terminal-traffic-range" value={range} onChange={event => update("terminal_range", event.target.value)} className="h-11 min-w-0 flex-1 rounded-lg border-0 bg-control px-3 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary sm:h-10 sm:flex-none">{Object.keys(terminalRanges).map(value => <option key={value} value={value}>{value}</option>)}</select>
        <Button variant="secondary" size="icon" aria-label={paused ? "Resume terminal measurements" : "Pause terminal measurements"} onClick={() => setPaused(value => !value)}>{paused ? <IconPlayerPlay size={17} /> : <IconPlayerPause size={17} />}</Button>
      </div>
    </div>
    <div role="tablist" aria-label="Terminal measurement scope" className="mx-5 flex flex-wrap gap-1 rounded-lg bg-muted/60 p-1">{Object.entries(terminalScopes).map(([value, item]) => <button key={value} id={`terminal-scope-${value}`} role="tab" type="button" aria-selected={scope === value} aria-controls="terminal-measurement-panel" tabIndex={scope === value ? 0 : -1} onKeyDown={event => {
        if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
        event.preventDefault();
        const keys = Object.keys(terminalScopes), index = keys.indexOf(value);
        const target = event.key === "Home" ? keys[0] : event.key === "End" ? keys[keys.length - 1] : keys[(index + (event.key === "ArrowRight" ? 1 : -1) + keys.length) % keys.length];
        update("terminal_scope", target); document.getElementById(`terminal-scope-${target}`)?.focus();
      }} onClick={() => update("terminal_scope", value)} className={`min-w-0 flex-1 rounded-md px-2 py-2 text-xs font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary ${scope === value ? "bg-surface text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"}`}>{item.label}</button>)}</div>
    <div id="terminal-measurement-panel" role="tabpanel" aria-labelledby={`terminal-scope-${scope}`} className="p-5 pt-4">
      <p className="min-h-[32px] text-xs leading-5 text-muted-foreground">{selected.detail}</p>
      {resource.error && <p role="alert" className="mt-3 rounded-lg bg-amber-500/10 p-3 text-xs text-amber-800 dark:text-amber-300">{resource.error}{resource.data ? " Showing the last successful snapshot." : ""}</p>}
      <div className="my-4 grid grid-cols-2 gap-3 sm:grid-cols-3"><div><p className="text-[11px] text-muted-foreground">Received by host</p><p className="mt-1 text-xl font-semibold tabular-nums text-emerald-700 dark:text-emerald-400">{observed.length ? formatBytes(incoming) : "—"}</p></div><div><p className="text-[11px] text-muted-foreground">Sent by host</p><p className="mt-1 text-xl font-semibold tabular-nums text-blue-700 dark:text-blue-400">{observed.length ? formatBytes(outgoing) : "—"}</p></div><div className="col-span-2 sm:col-span-1"><p className="text-[11px] text-muted-foreground">Reported intervals</p><p className="mt-1 text-xl font-semibold tabular-nums">{resource.data ? `${observed.length} / ${rows.length}` : "—"}</p></div></div>
      {resource.loading ? <div role="status" className="flex h-48 items-center justify-center rounded-lg bg-muted/30 text-sm text-muted-foreground">Loading terminal measurements…</div> : !observed.length ? <div role="status" className="flex h-48 flex-col items-center justify-center gap-2 rounded-lg bg-muted/30 px-4 text-center"><p className="text-sm font-medium">{resource.error ? "No snapshot available" : "No terminal measurements in this window"}</p><p className="max-w-lg text-xs leading-5 text-muted-foreground">{resource.error ? "Use Refresh dashboard to try again." : "Measurements appear when a compatible agent reports a shared terminal. Missing reports do not mean zero traffic."}</p></div> : <TerminalTrafficChart key={`${range}:${scope}:${machine}`} rows={rows} data={resource.data} />}
      {scope !== "relay" && resource.data?.points.some(point => point.unreported_hosts > 0) && <p role="status" className="mt-3 text-xs leading-5 text-muted-foreground">Some terminal hosts have incomplete measurements. Totals include only reporting hosts.</p>}
      <div className="mt-3 flex flex-wrap justify-between gap-2 text-[11px] leading-5 text-muted-foreground"><span>Bytes per {intervalLabel} · gaps are unreported · current interval may be partial</span><span>{paused ? "Paused" : resource.updated ? `Checked ${new Date(resource.updated).toLocaleTimeString()}` : "Waiting for measurements"}</span></div>
      <details className="mt-2 text-[11px] leading-5 text-muted-foreground"><summary className="cursor-pointer py-1 text-xs hover:text-foreground">About these measurements</summary><p className="mt-1">Directions are relative to the host. These views overlap; do not add them together. Uploads are bucketed by server receipt time; delayed uploads can create peaks. The first sample establishes a baseline. This chart covers terminal hosts, not all private-network traffic.</p></details>
    </div>
  </section>;
}


function TerminalTrafficChart({ rows, data }) {
  const [hover, setHover] = useState(null);
  const peak = Math.max(0, ...rows.flatMap(row => [row.incoming || 0, row.outgoing || 0]));
  const activeIndex = Math.min(hover ?? rows.length - 1, rows.length - 1);
  const current = rows[activeIndex];
  return <div role="group" tabIndex={0} aria-label="Terminal traffic chart. Use left and right arrows to inspect intervals." onKeyDown={event => { if (["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) { event.preventDefault(); setHover(index => event.key === "Home" ? 0 : event.key === "End" ? rows.length - 1 : Math.max(0, Math.min(rows.length - 1, (index ?? rows.length - 1) + (event.key === "ArrowLeft" ? -1 : 1)))); } }} onMouseMove={event => { const rect = event.currentTarget.getBoundingClientRect(); setHover(Math.max(0, Math.min(rows.length - 1, Math.floor((event.clientX - rect.left) / rect.width * rows.length)))); }} className="rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary">
        <div aria-hidden="true" className="mb-2 flex justify-between gap-2 text-[10px] text-muted-foreground"><span>{formatBytes(peak)} peak</span><span>Hover or use ← →</span></div>
        <svg viewBox="0 0 720 160" preserveAspectRatio="none" aria-hidden="true" className="h-40 w-full"><line x1="0" y1="159" x2="720" y2="159" className="stroke-border" />{rows.map((row, index) => row.incoming !== null && <g key={row.at} opacity={hover == null || activeIndex === index ? 1 : .55}>{[[row.incoming, "fill-emerald-600 dark:fill-emerald-400"], [row.outgoing, "fill-blue-600 dark:fill-blue-400"]].map(([value, color], direction) => { const height = Math.max(1, value / Math.max(1, peak) * 148); return <rect key={direction} x={(index + direction / 2) / rows.length * 720} y={159 - height} width={Math.max(1, 720 / rows.length / 2 - 1)} height={height} className={color} />; })}</g>)}</svg>
        <div className="mt-2 flex justify-between text-[10px] text-muted-foreground"><span>{new Date(data.start).toLocaleString()}</span><span className="text-right">{new Date(data.end).toLocaleString()}</span></div>
        <p role="status" className="mt-3 min-h-[32px] text-xs tabular-nums text-muted-foreground">{current && `${new Date(current.at).toLocaleString()} · ${current.incoming === null ? "No report for this interval" : `Received ${formatBytes(current.incoming)} · Sent ${formatBytes(current.outgoing)}`}`}</p>
      </div>;
}
