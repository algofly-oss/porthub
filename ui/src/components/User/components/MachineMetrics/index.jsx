import { useEffect, useState } from 'react';
import { RESOURCES, utilization, rankedMachines, metricSegments } from '@/lib/machineMetrics.mjs';
import { formatBytes } from '@/shared/utils/traffic.mjs';

function useMetrics(url, active) {
  const [state, setState] = useState({ data: null, error: '', loading: true });
  useEffect(() => {
    setState({ data: null, error: '', loading: true });
    if (!active) return;
    let disposed = false, timer, request;
    const load = async () => {
      clearTimeout(timer);
      if (disposed || document.hidden) return;
      request?.abort(); request = new AbortController();
      try {
        const response = await fetch(url, { signal: request.signal, credentials: 'same-origin' });
        if (!response.ok) throw new Error('Resource metrics are temporarily unavailable.');
        const data = await response.json();
        if (!disposed) setState({ data, error: '', loading: false });
      } catch (error) {
        if (!disposed && error.name !== 'AbortError') setState(old => ({ ...old, error: error.message, loading: false }));
      } finally { if (!disposed) timer = setTimeout(load, 15000); }
    };
    const visibility = () => { clearTimeout(timer); if (document.hidden) request?.abort(); else load(); };
    document.addEventListener('visibilitychange', visibility); load();
    return () => { disposed = true; clearTimeout(timer); request?.abort(); document.removeEventListener('visibilitychange', visibility); };
  }, [url, active]);
  return state;
}
const time = at => at ? new Date(at).toLocaleString() : 'No reading';
function Usage({ value, label }) {
  return <div className="min-w-0"><div className="mb-1 flex justify-between gap-2 text-xs"><span className="text-muted-foreground">{label}</span><span className="tabular-nums">{value === null ? 'Unavailable' : `${value.toFixed(1)}%`}</span></div><div role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={value ?? undefined} className="h-1.5 overflow-hidden rounded-full bg-muted"><div className={value > 90 ? 'h-full bg-amber-500' : 'h-full bg-primary/70'} style={{ width: `${value ?? 0}%` }} /></div></div>;
}
export function MachineRanking({ active, onSelect }) {
  const { data, error, loading } = useMetrics('/api/machines/metrics', active);
  const [selected, setSelected] = useState(['cpu']);
  const [ascending, setAscending] = useState(false);
  const machines = rankedMachines(data?.machines || [], selected, ascending);
  return <section aria-label="Machine resource utilization" className="min-w-0 rounded-xl bg-surface p-5">
    <div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="text-base font-semibold">Machine utilization</h2><p className="mt-1 text-xs text-muted-foreground">Live readings every 15 seconds · Open a machine for history</p></div><select aria-label="Resource sort order" className="rounded-md bg-control p-2 text-xs" value={ascending ? 'low' : 'high'} onChange={event => setAscending(event.target.value === 'low')}><option value="high">Most utilized first</option><option value="low">Least utilized first</option></select></div>
    <fieldset className="my-4 flex flex-wrap gap-x-5 gap-y-2"><legend className="sr-only">Combine resources for ranking</legend>{RESOURCES.map(([key, label]) => <label key={key} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={selected.includes(key)} onChange={event => setSelected(old => event.target.checked ? [...old, key] : old.length > 1 ? old.filter(item => item !== key) : old)} />{label}</label>)}</fieldset>
    <p className="mb-3 text-xs text-muted-foreground">{selected.length > 1 ? 'Combined score is the equal-weight average of selected utilization percentages. All selected readings must be available.' : 'Ranked by resource utilization percentage.'} GPU is the average across reporting GPUs.</p>
    {error && <p role="status" className="py-2 text-sm text-amber-600">{error}</p>}
    {loading ? <p role="status" className="py-5 text-sm text-muted-foreground">Loading resource readings…</p> : !machines.length ? <p className="py-5 text-sm text-muted-foreground">No fresh readings yet. Update the client and enable its metrics feature. Offline, disabled and stale machines are excluded.</p> : <ol className="divide-y divide-border">{machines.map((machine, index) => <li key={machine.id}><button onClick={() => onSelect(machine.id)} className="w-full rounded-lg px-1 py-4 text-left hover:bg-muted/40"><div className="mb-3 flex items-center gap-3"><span className="w-5 text-xs tabular-nums text-muted-foreground">{index + 1}</span><span className="min-w-0 flex-1 truncate text-sm font-medium">{machine.name}</span><span className="text-xs tabular-nums">{machine.score === null ? 'Missing selected reading' : `${machine.score.toFixed(1)}%${selected.length > 1 ? ' combined' : ''}`}</span></div><div className="grid grid-cols-2 gap-4 sm:grid-cols-4">{RESOURCES.map(([key, label]) => <Usage key={key} label={label} value={utilization(machine.reading?.sample, key)} />)}</div><p className="mt-2 text-[11px] text-muted-foreground">Updated {time(machine.reading?.at)}</p></button></li>)}</ol>}
    {data?.machines?.length >= data?.limit && <p className="text-xs text-muted-foreground">Showing up to {data.limit} owned machines.</p>}
  </section>;
}
function HistoryChart({ history, resource, label, interval, intervalMs }) {
  const [hover, setHover] = useState(null);
  const segments = metricSegments(history, resource, intervalMs);
  const start = history[0]?.at || 0, end = history[history.length - 1]?.at || start + 1;
  const x = at => 34 + (at - start) / Math.max(1, end - start) * 466;
  const y = value => 130 - value * 1.1;
  const point = hover === null ? null : history.reduce((best, p) => Math.abs(p.at - hover) < Math.abs((best?.at ?? Infinity) - hover) ? p : best, null);
  const value = point ? utilization(point.sample, resource) : null;
  return <div className="min-w-0 rounded-lg bg-control/40 p-3"><h3 className="text-sm font-medium">{label}</h3><p className="mt-1 min-h-[18px] text-xs text-muted-foreground">{point ? `${time(point.at)} · ${value === null ? 'Unavailable' : `${value.toFixed(1)}%`}` : `${interval} · hover or tap to inspect`}</p><svg role="img" aria-label={`${label} utilization history from 0 to 100 percent`} viewBox="0 0 510 160" className="mt-2 w-full touch-pan-y" onPointerMove={event => { const box = event.currentTarget.getBoundingClientRect(); setHover(start + Math.max(0, Math.min(1, ((event.clientX - box.left) / box.width * 510 - 34) / 466)) * (end - start)); }} onPointerLeave={() => setHover(null)}>
    {[0, 50, 100].map(tick => <g key={tick}><line x1="34" x2="500" y1={y(tick)} y2={y(tick)} stroke="currentColor" opacity=".1" /><text x="27" y={y(tick) + 3} textAnchor="end" fill="currentColor" opacity=".6" fontSize="9">{tick}%</text></g>)}
    {segments.map((segment, i) => <polyline key={i} points={segment.map(p => `${x(p.at)},${y(p.value)}`).join(' ')} fill="none" stroke="currentColor" strokeWidth="2" className="text-primary" />)}
    {segments.flat().length === 1 && <circle cx={x(segments[0][0].at)} cy={y(segments[0][0].value)} r="3" className="fill-primary" />}
    {value !== null && <circle cx={x(point.at)} cy={y(value)} r="4" className="fill-primary" />}
    <text x="34" y="151" fill="currentColor" opacity=".6" fontSize="9">{start ? new Date(start).toLocaleString() : 'No samples yet'}</text><text x="500" y="151" textAnchor="end" fill="currentColor" opacity=".6" fontSize="9">{end && start ? new Date(end).toLocaleString() : ''}</text>
  </svg>{!segments.length && <p className="text-xs text-muted-foreground">{resource === 'gpu' ? 'GPU metrics are unavailable on this host.' : 'No readings in this period.'}</p>}</div>;
}
export default function MachineMetrics({ machineId, active }) {
  const [hours, setHours] = useState(24);
  const { data, error, loading } = useMetrics(`/api/machines/metrics/${encodeURIComponent(machineId || '')}?hours=${hours}`, active && !!machineId);
  const latest = data?.latest, sample = latest?.sample;
  const fresh = latest?.at && Date.now() - latest.at < 45000;
  return <section aria-label="Machine health and resource history" className="space-y-4 p-4"><div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-base font-semibold">Resources</h2><p className="mt-1 text-xs text-muted-foreground">{latest ? `${fresh ? 'Live' : 'Stale reading'} · ${time(latest.at)}` : 'Waiting for the client’s first report'}</p></div><select aria-label="Resource history period" className="rounded-md bg-control p-2 text-sm" value={hours} onChange={event => setHours(Number(event.target.value))}><option value={1}>Last hour</option><option value={24}>Last 24 hours</option><option value={168}>Last 7 days</option></select></div>
    {error && <p role="alert" className="text-sm text-amber-600">{error}</p>}
    {loading && <p role="status" className="text-sm text-muted-foreground">Loading metrics…</p>}
    <div className="grid grid-cols-2 gap-4">{RESOURCES.map(([key, label]) => <div key={key}><Usage label={label} value={utilization(sample, key)} /><p className="mt-2 text-xs text-muted-foreground">{key === 'cpu' ? sample ? `${sample.cores} logical CPUs` : '' : key === 'gpu' ? sample?.gpus?.map(gpu => `${gpu.name}${gpu.memory ? ` · ${formatBytes(gpu.memory.used)} / ${formatBytes(gpu.memory.total)} VRAM` : ''}`).join(' · ') : sample?.[key] ? `${formatBytes(sample[key].used)} / ${formatBytes(sample[key].total)}` : ''}</p></div>)}</div>
    <div className="grid gap-3 xl:grid-cols-2">{RESOURCES.map(([key, label]) => <HistoryChart key={key} history={data?.history || []} resource={key} label={label} intervalMs={data?.interval_ms || 60000} interval={`Last ${hours} ${hours === 1 ? 'hour' : 'hours'}`} />)}</div>
    <p className="text-xs leading-5 text-muted-foreground">Readings arrive every 15 seconds. History retains minute samples for seven days; chart gaps indicate missing reports. Disk combines mounted local filesystems. Client owners can disable reporting with <code>porthub features disable metrics</code>.</p>
  </section>;
}
