import SeriesChart from './SeriesChart';
import SearchDropdown from '@/components/ui/search-dropdown';
import { useEffect, useRef, useState } from 'react';
import { RESOURCES, utilization, rankedMachines, metricSegments, gpuDevices, gpuReading, capacityPercent, diskDevices, diskReading } from '@/lib/machineMetrics.mjs';
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
function Usage({ value, label, memory }) {
  return <div className="min-w-0"><div className="mb-1 flex justify-between gap-2 text-xs"><span className="text-muted-foreground">{label}</span><span className="tabular-nums">{value === null ? '—' : `${value.toFixed(1)}%`}</span></div><div role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={value ?? undefined} aria-valuetext={value === null ? 'Unavailable' : `${value.toFixed(1)}% · ${value >= 90 ? 'High' : value >= 70 ? 'Elevated' : 'Low'} utilization`} className="h-1.5 overflow-hidden rounded-full bg-muted"><div className={value >= 90 ? 'h-full bg-red-500' : value >= 70 ? 'h-full bg-amber-500' : 'h-full bg-emerald-500'} style={{ width: `${value ?? 0}%` }} /></div>{memory && <p className="mt-1 text-[10px] leading-3 tabular-nums text-muted-foreground">{formatBytes(memory.used)} / {formatBytes(memory.total)}</p>}</div>;
}
export function MachineRanking({ active, onSelect }) {
  const { data, error, loading } = useMetrics('/api/machines/metrics', active);
  const [selected, setSelected] = useState('cpu');
  const [ascending, setAscending] = useState(false);
  const machines = rankedMachines(data?.machines || [], [selected], ascending);
  const viewport = useRef(null);
  useEffect(() => {
    const element = viewport.current;
    if (!element) return;
    const contents = [...element.querySelectorAll('[data-ranking-row-content]')];
    const measure = () => {
      const height = element.clientHeight;
      element.parentElement.style.setProperty('--ranking-scrollbar', `${element.offsetWidth-element.clientWidth}px`);
      const minimum = Math.max(0, ...contents.map(content => content.getBoundingClientRect().height + 1));
      if (!height || !minimum) return;
      const count = Math.max(1, Math.min(contents.length, Math.floor(height / minimum)));
      element.style.setProperty('--ranking-row-height', `${height / count}px`);
    };
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    contents.forEach(content => observer.observe(content));
    measure();
    return () => observer.disconnect();
  }, [data, selected, ascending, loading]);
  return <section aria-label="Machine resource utilization" className="absolute inset-0 flex min-w-0 flex-col overflow-hidden rounded-xl bg-surface">
    <div className="px-4 pt-4"><div className="flex items-center justify-between gap-2"><h2 className="text-base font-semibold">Machine utilization</h2><span className="text-xs tabular-nums text-muted-foreground">{machines.length} live</span></div>
      <div className="mt-2 flex flex-wrap items-center justify-between gap-2"><fieldset className="flex gap-1"><legend className="sr-only">Sort machines by resource</legend>{RESOURCES.map(([key, label]) => <label key={key} className="relative cursor-pointer"><input className="peer absolute inset-0 z-10 m-0 h-full w-full cursor-pointer opacity-0" type="radio" name="hardware-sort" checked={selected === key} onChange={() => setSelected(key)}/><span className="flex min-h-[36px] items-center rounded-lg border border-transparent px-2 text-xs font-medium text-muted-foreground transition-colors hover:bg-control peer-checked:border-primary/20 peer-checked:bg-primary/10 peer-checked:text-primary peer-focus-visible:ring-2 peer-focus-visible:ring-primary">{label}</span></label>)}</fieldset>
      <SearchDropdown aria-label="Resource sort order" className="min-w-0 text-xs" value={ascending ? 'low' : 'high'} onChange={event => setAscending(event.target.value === 'low')}><option value="high">Most utilized first</option><option value="low">Least utilized first</option></SearchDropdown></div>
      {error && <p role="status" className="py-2 text-xs text-amber-600">{error}</p>}
      <p className="mb-2 text-[11px] leading-4 text-muted-foreground">Ranked by utilization · Select for history</p>
      <div aria-hidden="true" style={{paddingRight:'var(--ranking-scrollbar, 0px)'}} className="grid grid-cols-[minmax(80px,1.4fr)_repeat(4,minmax(0,1fr))] gap-2 border-b border-border pb-2 text-[10px] font-medium text-muted-foreground"><span>Machine</span>{RESOURCES.map(([key,label])=><span key={key}>{label}</span>)}</div>
    </div>
    <div ref={viewport} className="min-h-0 flex-1 overflow-y-auto overscroll-contain px-4" tabIndex={0} role="region" aria-label="Live machine rankings" style={{scrollbarGutter:'stable',scrollbarWidth:'thin',scrollSnapType:'y mandatory'}}>
      {loading ? <p role="status" className="py-5 text-sm text-muted-foreground">Loading resource readings…</p> : !machines.length ? <p className="py-5 text-sm text-muted-foreground">No fresh readings. Enable metrics on an online client.</p> : <ol className="divide-y divide-border">{machines.map((machine, index) => <li key={machine.id} style={{height:'var(--ranking-row-height, 104px)',scrollSnapAlign:'start'}}><button type="button" onClick={() => onSelect(machine.id)} className="flex h-full w-full items-center rounded-lg text-left hover:bg-muted/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-primary" title={`Updated ${time(machine.reading?.at)}`}><div data-ranking-row-content className="grid w-full grid-cols-[minmax(80px,1.4fr)_repeat(4,minmax(0,1fr))] items-start gap-2 py-1.5"><span className="min-w-0 self-center truncate text-xs font-medium" title={`${index+1}. ${machine.name} · ${machine.score === null ? 'Unavailable' : machine.score.toFixed(1)+'% ranked usage'}`}>{machine.name}</span>{RESOURCES.map(([key,label])=>{const value=utilization(machine.reading?.sample,key);const memory=machine.reading?.sample?.[key]?.total ? machine.reading.sample[key] : null;return <span key={key} className="min-w-0" title={`${label}: ${value === null ? 'Unavailable' : value.toFixed(1)+'%'}${memory ? ' · '+formatBytes(memory.used)+' / '+formatBytes(memory.total) : ''}`}><span className="block text-[11px] tabular-nums">{value === null ? '—' : `${value.toFixed(1)}%`}</span><span role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={value ?? undefined} className="mt-1 block h-1 overflow-hidden rounded-full bg-muted"><span className={`block h-full ${value>=90?'bg-red-500':value>=70?'bg-amber-500':'bg-emerald-500'}`} style={{width:`${value??0}%`}} /></span>{memory && <span className="mt-1 block truncate text-[10px] leading-3 tabular-nums text-muted-foreground">{formatBytes(memory.used)}</span>}</span>;})}</div></button></li>)}</ol>}
    </div>
    <p className="border-t border-border px-4 py-2 text-[11px] text-muted-foreground">Updates every 15s{machines.length > 2 ? ` · ${machines.length} machines` : ''}{data?.machines?.length >= data?.limit ? ` · Up to ${data.limit} machines` : ''}</p>
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
  return <div className="min-w-0 rounded-lg bg-control/40 p-3"><h3 className="text-sm font-medium">{label}</h3><p className="mt-1 min-h-[18px] text-xs text-muted-foreground">{point ? `${time(point.at)} · ${value === null ? '—' : `${value.toFixed(1)}%`}${point.sample?.[resource]?.total ? ` · ${formatBytes(point.sample[resource].used)} / ${formatBytes(point.sample[resource].total)}` : ''}` : `${interval} · hover or tap to inspect`}</p><svg role="img" aria-label={`${label} utilization history from 0 to 100 percent`} viewBox="0 0 510 160" className="mt-2 w-full touch-pan-y" onPointerMove={event => { const box = event.currentTarget.getBoundingClientRect(); setHover(start + Math.max(0, Math.min(1, ((event.clientX - box.left) / box.width * 510 - 34) / 466)) * (end - start)); }} onPointerLeave={() => setHover(null)}>
    {[0, 50, 100].map(tick => <g key={tick}><line x1="34" x2="500" y1={y(tick)} y2={y(tick)} stroke="currentColor" opacity=".1" /><text x="27" y={y(tick) + 3} textAnchor="end" fill="currentColor" opacity=".6" fontSize="9">{tick}%</text></g>)}
    {segments.map((segment, i) => <polyline key={i} points={segment.map(p => `${x(p.at)},${y(p.value)}`).join(' ')} fill="none" stroke="currentColor" strokeWidth="2" className="text-primary" />)}
    {segments.filter(segment=>segment.length===1).map((segment,index)=><circle key={index} cx={x(segment[0].at)} cy={y(segment[0].value)} r="3" className="fill-primary" />)}
    {value !== null && <circle cx={x(point.at)} cy={y(value)} r="4" className="fill-primary" />}
    <text x="34" y="151" fill="currentColor" opacity=".6" fontSize="9">{start ? new Date(start).toLocaleString() : 'No samples yet'}</text><text x="500" y="151" textAnchor="end" fill="currentColor" opacity=".6" fontSize="9">{end && start ? new Date(end).toLocaleString() : ''}</text>
  </svg>{!segments.length && <p className="text-xs text-muted-foreground">{resource === 'gpu' ? 'GPU metrics are unavailable on this host.' : 'No readings in this period.'}</p>}</div>;
}
export default function MachineMetrics({ machineId, active }) {
  const [hours, setHours] = useState(24);
  const [gpuId,setGpuId]=useState('');
  const { data, error, loading } = useMetrics(`/api/machines/metrics/${encodeURIComponent(machineId || '')}?hours=${hours}`, active && !!machineId);
  const latest = data?.latest, sample = latest?.sample;
  const history=data?.history||[];
  const devices=gpuDevices(history,sample),gpu=devices.find(d=>d.id===gpuId)||devices[0];
  const readGpu=s=>gpuReading(s,gpu?.id,gpu?.name,gpu?.allowLegacy);
  const percentText=v=>v==null?'Unavailable':`${v.toFixed(1)}%`;
  const memoryText=m=>m?`${formatBytes(m.used)} / ${formatBytes(m.total)}`:'Unavailable';
  const gpuSeries=[
   {id:'util',label:'GPU utilization',read:s=>readGpu(s)?.utilization??null,format:s=>percentText(readGpu(s)?.utilization)},
   {id:'vram',label:'VRAM',read:s=>capacityPercent(readGpu(s)?.memory),format:s=>memoryText(readGpu(s)?.memory)},
   {id:'temp',label:'Temperature',read:s=>readGpu(s)?.temperature??null,scale:v=>v/150*100,format:s=>readGpu(s)?.temperature==null?'Unavailable':`${readGpu(s).temperature.toFixed(1)}°C`},
   {id:'fan',label:'Fan speed',read:s=>readGpu(s)?.fan_speed??null,format:s=>percentText(readGpu(s)?.fan_speed)}];
  const drives=diskDevices(history,sample);
  const diskSeries=drives.map(d=>({id:d.id,label:d.name,read:s=>capacityPercent(diskReading(s,d.id)),format:s=>memoryText(diskReading(s,d.id))}));
  if(history.some(p=>!p.sample.disks?.length))diskSeries.push({id:'legacy',label:'All drives (older reports)',read:s=>s?.disks?.length?null:capacityPercent(s?.disk),format:s=>s?.disks?.length?'Unavailable':memoryText(s?.disk)});
  const fresh = latest?.at && Date.now() - latest.at < 45000;
  return <section aria-label="Machine health and resource history" className="space-y-4 p-4"><div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-base font-semibold">Resources</h2><p className="mt-1 text-xs text-muted-foreground">{latest ? `${fresh ? 'Live' : 'Stale reading'} · ${time(latest.at)}` : 'Waiting for the client’s first report'}</p></div><SearchDropdown aria-label="Resource history period" className="rounded-md bg-control p-2 text-sm" value={hours} onChange={event => setHours(Number(event.target.value))}><option value={1}>Last hour</option><option value={24}>Last 24 hours</option><option value={168}>Last 7 days</option></SearchDropdown></div>
    {error && <p role="alert" className="text-sm text-amber-600">{error}</p>}
    {loading && <p role="status" className="text-sm text-muted-foreground">Loading metrics…</p>}
    <div className="grid grid-cols-2 gap-4">{RESOURCES.map(([key, label]) => <div key={key}><Usage label={label} value={utilization(sample, key)} /><p className="mt-2 text-xs text-muted-foreground">{key === 'cpu' ? sample ? `${sample.cores} logical CPUs` : '' : key === 'gpu' ? sample?.gpus?.map(gpu => `${gpu.name}${gpu.memory ? ` · ${formatBytes(gpu.memory.used)} / ${formatBytes(gpu.memory.total)} VRAM` : ''}`).join(' · ') : sample?.[key] ? `${formatBytes(sample[key].used)} / ${formatBytes(sample[key].total)}` : ''}</p></div>)}</div>
    <div className="grid gap-3 xl:grid-cols-2">{RESOURCES.filter(([key])=>key==='cpu'||key==='ram').map(([key, label]) => <HistoryChart key={key} history={data?.history || []} resource={key} label={label} intervalMs={data?.interval_ms || 60000} interval={`Last ${hours} ${hours === 1 ? 'hour' : 'hours'}`} />)}<div>{devices.length>1&&<SearchDropdown aria-label="GPU device" value={gpu?.id||''} onChange={e=>setGpuId(e.target.value)}>{devices.map(d=><option key={d.id} value={d.id}>{d.name} · {d.id}</option>)}</SearchDropdown>}<SeriesChart label={gpu?`GPU · ${gpu.name}`:'GPU'} history={history} series={gpuSeries} intervalMs={data?.interval_ms||60000}/></div><SeriesChart label="Disk usage by drive" history={history} series={diskSeries} intervalMs={data?.interval_ms||60000}/></div>
    <p className="text-xs leading-5 text-muted-foreground">Readings arrive every 15 seconds. History retains minute samples for seven days; chart gaps indicate missing reports. Disk combines mounted local filesystems. Client owners can disable reporting with <code>porthub features disable metrics</code>.</p>
  </section>;
}
