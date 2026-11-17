import { useEffect, useMemo, useRef, useState } from 'react';
import { IconArrowRight, IconNetwork, IconPlayerPause, IconPlayerPlay } from '@tabler/icons-react';
import InventorySelect from '@/components/ui/inventory-select';
import SearchDropdown from '@/components/ui/search-dropdown';
import { Button } from '@/components/ui/button';
import usePrivateTraffic from '@/shared/hooks/usePrivateTraffic';
import { formatBytes } from '@/shared/utils/traffic.mjs';
import { privateRanges, privateFlowKey, privateTrafficWindow } from '@/shared/utils/private-traffic.mjs';

export default function PrivateTraffic({ active, refresh }) {
  const [range, setRange] = useState('1h');
  const [machine, setMachine] = useState('all');
  const [paused, setPaused] = useState(false);
  const [selected, setSelected] = useState(null);
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  useEffect(() => { const timer = setTimeout(() => { setSearch(query.trim()); setPage(1); }, 250); return () => clearTimeout(timer); }, [query]);
  const resource = usePrivateTraffic({ range, machine, search, page, selected, enabled: active, paused, refresh });
  const flows = resource.data?.flows || [];
  const totals = resource.data?.totals;
  const pagination = resource.data?.pagination;
  const current = resource.data?.selected_flow;
  const selectedKey = selected ? privateFlowKey(selected) : null;
  useEffect(() => { setSelected(null); setPage(1); }, [range, machine]);
  const rows = useMemo(() => selected && !current ? [] : privateTrafficWindow(resource.data, current), [resource.data, current, selected]);
  const coverage = resource.data?.coverage;
  return <section aria-label="Private network traffic" className="min-w-0 overflow-hidden rounded-xl bg-surface">
    <div className="flex flex-wrap items-start justify-between gap-3 p-5">
      <div><h2 className="flex items-center gap-2 text-base font-semibold"><IconNetwork size={18} />Private network traffic</h2><p className="mt-1 text-xs text-muted-foreground">Sender-reported machine-to-machine transfers</p></div>
      <div className="flex w-full flex-wrap gap-2 sm:w-auto">
        <InventorySelect kind="machines" label="Private traffic machine" className="min-w-0 flex-1 basis-full sm:w-48 sm:flex-none sm:basis-auto" value={machine} onChange={setMachine} extraOptions={[{ value:'all', label:'All machines' }]} />
        <SearchDropdown aria-label="Private traffic history range" value={range} onChange={event => setRange(event.target.value)} className="h-11 rounded-lg bg-control px-3 text-sm">{Object.keys(privateRanges).map(value => <option key={value} value={value}>{value === '1h' ? 'Last hour' : value === '24h' ? 'Last 24 hours' : value === '7d' ? 'Last 7 days' : 'Last 30 days'}</option>)}</SearchDropdown>
        <Button variant="secondary" size="icon" aria-label={paused ? 'Resume private traffic updates' : 'Pause private traffic updates'} onClick={() => setPaused(value=>!value)}>{paused ? <IconPlayerPlay size={18} /> : <IconPlayerPause size={18} />}</Button>
      </div>
    </div>
    {resource.error && <p role="alert" className="mx-5 mb-4 rounded-lg bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-300">{resource.error}{resource.data ? ' Showing the last successful snapshot.' : ''}</p>}
    <div className="grid grid-cols-2 gap-4 border-y border-border px-5 py-4 sm:grid-cols-4">{[['Sender-reported',totals?.total_bytes],['Direct',totals?.direct_bytes],['Relayed',totals?.relay_bytes],['Range average',totals?.bytes_per_second]].map(([label,value])=><div key={label}><p className="text-xs text-muted-foreground">{label}</p><p className="mt-1 text-lg font-semibold tabular-nums">{resource.data && resource.data.points.length ? formatBytes(value) : '—'}{label==='Range average' && <span className="ml-1 text-xs font-normal text-muted-foreground">/s</span>}</p></div>)}</div>
    <div className="p-5"><HistoryChart key={`${range}:${machine}:${selectedKey || "all"}`} rows={rows} interval={resource.data?.interval_seconds || privateRanges[range]} label={selected ? `${(current || selected).source_name} → ${(current || selected).destination_name}` : "All directions"} selected={!!selected} />
      {selected && !current && <p role="status" className="mt-2 text-xs text-muted-foreground">{resource.loading ? 'Loading the selected direction’s sender history…' : resource.error ? 'Selected history is unavailable; no previous pair is shown.' : 'No sender-reported history is available for this direction.'}</p>}
      {selected && <button type="button" className="mt-2 min-h-11 text-xs text-primary" onClick={()=>setSelected(null)}>Show all machine pairs</button>}
    </div>
    {coverage?.history_incomplete && <p role="status" className="mx-5 mb-4 rounded-lg bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-300">History is incomplete{coverage.dropped_rows ? `: ${coverage.dropped_rows.toLocaleString()} observations were dropped before upload` : ''}.{coverage.missing_sender_pairs > 0 ? ` ${coverage.missing_sender_pairs} directions have incomplete sender coverage; receiver observations are excluded from totals.` : ''} Available sender measurements remain shown.</p>}
    {coverage?.unreported_peers > 0 && <p role="status" className="px-5 pb-4 text-xs text-muted-foreground">Partial reporting: historical totals include sender reports received; unreported traffic is unknown.</p>}
    <div className="border-t border-border px-5 py-3"><label className="block text-xs text-muted-foreground">Find a machine pair<input aria-label="Find a private traffic pair" type="search" value={query} maxLength={128} onChange={event=>setQuery(event.target.value)} className="mt-2 h-11 w-full rounded-lg bg-control px-3 text-sm text-foreground" placeholder="Search machine names" /></label></div>
    <div className="flex justify-between gap-2 border-t border-border px-5 py-2 text-[11px] text-muted-foreground"><span>Direction · reported volume</span><span>Recent sender rate</span></div>
    <div className="max-h-[360px] overflow-auto border-t border-border">
      {resource.loading && !resource.data ? <p role="status" className="p-5 text-sm text-muted-foreground">Loading private traffic…</p> : !flows.length ? <div role="status" className="p-5"><p className="text-sm font-medium">{resource.error ? 'Private traffic unavailable' : search ? 'No machine pairs match your search.' : 'No reported transfers on this page'}</p><p className="mt-2 text-xs leading-5 text-muted-foreground">Direct and relayed transfers appear when compatible agents report them. Missing reports do not mean zero traffic.</p></div> : flows.map(flow=> {
        const key=privateFlowKey(flow);
        return <button key={key} type="button" aria-pressed={selectedKey===key} onClick={()=>setSelected(selectedKey===key ? null : flow)} className={`grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-3 border-b border-border px-5 py-3 text-left last:border-0 hover:bg-muted/50 sm:grid-cols-[minmax(0,1fr)_100px_100px] ${selectedKey===key ? 'bg-muted/60' : ''}`}>
          <div className="min-w-0"><div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-sm font-medium"><span className="min-w-0 break-words">{flow.source_name}</span><IconArrowRight size={16} className="shrink-0 text-muted-foreground" aria-label="sends to" /><span className="min-w-0 break-words">{flow.destination_name}</span></div><p className="mt-1 text-xs text-muted-foreground">{flow.coverage==='missing_sender' ? 'Sender report missing' : `Direct ${formatBytes(flow.direct_bytes)} · Relay ${formatBytes(flow.relay_bytes)}`}{!flow.sender_coverage_complete && flow.coverage!=='missing_sender' ? ' · Partial sender coverage' : ''}{flow.received_total_bytes > 0 ? ` · Receiver observed ${formatBytes(flow.received_total_bytes)} (not added)` : ''}</p></div>
          <div className="text-right text-xs tabular-nums"><span className="block font-medium">{flow.coverage==='missing_sender' ? '—' : formatBytes(flow.total_bytes)}</span><span className="mt-1 block text-muted-foreground sm:hidden">{flow.recent_bytes_per_second === null ? 'No recent sender report' : `${formatBytes(flow.recent_bytes_per_second)}/s · ${flow.recent_interval_seconds}s`}</span></div><span title={flow.rate_at === null ? 'No fresh observed interval' : `Observed ${new Date(flow.rate_at).toLocaleString()}`} className="hidden text-right text-xs tabular-nums text-muted-foreground sm:block">{flow.recent_bytes_per_second === null ? 'No recent sender report' : `${formatBytes(flow.recent_bytes_per_second)}/s · ${flow.recent_interval_seconds}s`}</span>
        </button>;
      })}
    </div>
    {pagination && <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border px-5 py-3"><span className="text-xs text-muted-foreground">Page {pagination.page} · {pagination.filtered_pairs} matching of {pagination.total_pairs} directions · totals cover all directions</span><div className="flex gap-2"><Button variant="secondary" disabled={resource.loading || pagination.page===1} onClick={()=>setPage(pagination.page-1)}>Previous</Button><Button variant="secondary" disabled={resource.loading || pagination.page*pagination.page_size>=pagination.filtered_pairs} onClick={()=>setPage(pagination.page+1)}>Next</Button></div></div>}
    <div className="flex flex-wrap justify-between gap-2 border-t border-border px-5 py-3 text-[11px] leading-5 text-muted-foreground"><span>{coverage ? `${coverage.reporting_peers} of ${coverage.eligible_peers} peers reporting${coverage.unreported_peers ? ` · ${coverage.unreported_peers} unreported` : ''}` : 'Waiting for agent reports'}</span><span>{paused ? 'Updates paused' : resource.updated ? `Updated ${new Date(resource.updated).toLocaleTimeString()}` : 'Batched agent reports'}</span></div>
    <details className="px-5 pb-4 text-xs leading-5 text-muted-foreground"><summary className="flex min-h-[44px] cursor-pointer items-center py-2">How traffic is measured</summary><p>Agents count private transport bytes locally and publish batched summaries, including direct connections that bypass the server. Only sender-reported transport bytes contribute to volume, rates and history. Receiver observations are separate diagnostics and are never substituted or added, because the two agents may sample at different times. Carrier bytes include transport retries and are not unique file sizes. Gaps indicate missing reports. Range averages cover the selected window. Pair rates use the actual observed interval (1–120 seconds), independently of the history range. Stale observations show no recent rate, even if uploaded later. Queue acceptance does not prove socket delivery. A missing sender report means unknown traffic, not an observed zero. Missing reports leave gaps even when a receiver observed bytes.</p></details>
  </section>;
}
function HistoryChart({ rows, interval, label, selected }) {
  const [hover,setHover]=useState(null);
  const keyboardSelection = useRef(false);
  const lastPointer = useRef(null);
  const peak=Math.max(1,...rows.filter(row=>row.direct!==null).map(row=>row.direct+row.relay));
  const current=rows[Math.min(hover ?? rows.length-1,rows.length-1)];
  const observed=rows.some(row=>row.direct!==null);
  return <div role="group" tabIndex={0} aria-label={`${selected ? 'Selected machine pair' : 'Account private'} traffic history. Use left and right arrows to inspect intervals.`} className="rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary" onKeyDown={event=>{if(['ArrowLeft','ArrowRight','Home','End'].includes(event.key)){event.preventDefault();keyboardSelection.current=true;setHover(index=>event.key==='Home'?0:event.key==='End'?rows.length-1:Math.max(0,Math.min(rows.length-1,(index??rows.length-1)+(event.key==='ArrowRight'?1:-1))));}}} onMouseMove={event=>{const previous=lastPointer.current;lastPointer.current={x:event.clientX,y:event.clientY};if(keyboardSelection.current && (!previous || (previous.x===event.clientX && previous.y===event.clientY)))return;keyboardSelection.current=false;const rect=event.currentTarget.getBoundingClientRect();setHover(Math.max(0,Math.min(rows.length-1,Math.floor((event.clientX-rect.left)/rect.width*rows.length))));}}>
    <div className="mb-3 flex flex-wrap justify-between gap-2 text-xs text-muted-foreground"><span className="min-w-0 break-words font-medium text-foreground">{label} · transfer history</span><span><span className="text-emerald-600 dark:text-emerald-400">Direct</span> · <span className="text-blue-600 dark:text-blue-400">Relayed</span></span></div>
    {observed ? <><div className="mb-1 text-[11px] text-muted-foreground">{formatBytes(peak)} peak per interval</div><svg viewBox="0 0 720 140" preserveAspectRatio="none" className="h-36 w-full" aria-hidden="true">{rows.map((row,index)=>{const width=720/rows.length;if(row.direct===null)return <line key={row.at} x1={index*width+width/2} x2={index*width+width/2} y1="136" y2="140" className="stroke-muted-foreground/40"/>;const direct=row.direct/peak*136,relay=row.relay/peak*136;return <g key={row.at} opacity={hover==null||hover===index?1:.55}>{direct>0 && <rect x={index*width} y={140-direct} width={Math.max(1,width-1)} height={direct} className="fill-emerald-600 dark:fill-emerald-400"/>}{direct===0 && relay===0 && <rect x={index*width} y="139" width={Math.max(1,width-1)} height="1" className="fill-muted-foreground"/>}{relay>0 && <rect x={index*width} y={140-direct-relay} width={Math.max(1,width-1)} height={relay} className="fill-blue-600 dark:fill-blue-400"/>}</g>;})}</svg><div className="mt-2 flex justify-between gap-2 text-[11px] text-muted-foreground"><span>{new Date(rows[0].at).toLocaleString()}</span><span className="text-right">{new Date(rows[rows.length-1].at).toLocaleString()}</span></div></> : <div className="flex h-36 items-center justify-center rounded-lg bg-muted/30 text-xs text-muted-foreground">No sender-reported history</div>}
    <p role="status" className="mt-3 min-h-5 text-xs tabular-nums text-muted-foreground">{current ? `${new Date(current.at).toLocaleString()} · ${current.direct === null ? 'No report for this interval (sender missing)' : `Direct ${formatBytes(current.direct)} · Relayed ${formatBytes(current.relay)}${current.sender_coverage_complete === false ? ' · Partial sender coverage' : ''}`} · ${interval}s interval` : 'Waiting for reported history.'}</p>
    <p className="mt-2 text-[11px] text-muted-foreground">Gaps are unreported intervals; reported zero is not a missing report. Current interval may be partial.</p>
  </div>;
}
