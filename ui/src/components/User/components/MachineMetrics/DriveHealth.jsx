import {useMemo} from 'react';
import SearchDropdown from '@/components/ui/search-dropdown';
import {driveTimeline,driveAssessment,metricSegments} from '@/lib/machineMetrics.mjs';
import {formatBytes} from '@/shared/utils/traffic.mjs';
const states={healthy:{label:'Healthy',color:'text-emerald-500'},warning:{label:'Needs attention',color:'text-amber-500'},critical:{label:'Critical',color:'text-red-500'},unavailable:{label:'Unavailable',color:'text-muted-foreground'},sleeping:{label:'Sleeping',color:'text-muted-foreground'},removed:{label:'Removed',color:'text-muted-foreground'}};
const tests={not_run:'Not yet run',running:'Running',passed:'Passed',failed:'Failed',aborted:'Aborted',unsupported:'Not supported',deferred:'Deferred until idle'};
const number=value=>value==null?'Unavailable':new Intl.NumberFormat().format(value);
const date=value=>value?new Date(value).toLocaleString():'Not yet checked';
function Status({value}){const state=states[value]||states.unavailable;return <span className={`text-xs font-medium ${state.color}`}>{state.label}</span>;}
function ConditionHistory({history}){
 const first=history[0]?.at||0,last=history.at(-1)?.at||first+1;
 const level=sample=>sample.drive?.present?({healthy:100,warning:50,critical:0}[sample.drive.status]??null):null;
 const points=history.map(p=>({at:p.at,sample:{drive:p.snapshot}}));
 const segments=metricSegments(points,level,7*24*60*60*1000);
 const x=at=>68+(at-first)/Math.max(1,last-first)*396,y=value=>68-value*.5;
 return <div className="mt-4 rounded-lg bg-control/40 p-3"><h4 className="text-xs font-medium">SMART condition history</h4>{segments.length?<svg role="img" aria-label="Drive SMART condition history" viewBox="0 0 480 94" className="mt-2 w-full">
  {[[100,'Healthy'],[50,'Warning'],[0,'Critical']].map(([value,label])=><g key={label}><line x1="68" x2="464" y1={y(value)} y2={y(value)} stroke="currentColor" opacity=".1"/><text x="60" y={y(value)+3} textAnchor="end" fill="currentColor" fontSize="9">{label}</text></g>)}
  {segments.map((segment,i)=><g key={i}>{segment.length>1&&<polyline fill="none" stroke="currentColor" opacity=".35" strokeWidth="1.5" points={segment.map(p=>`${x(p.at)},${y(p.value)}`).join(' ')}/>} {segment.map((p,j)=><circle key={j} cx={x(p.at)} cy={y(p.value)} r="3" fill={p.value===0?'#ef4444':p.value===50?'#f59e0b':'#22a866'}><title>{date(p.at)} · {p.value===100?'Healthy':p.value===50?'Needs attention':'Critical'}</title></circle>)}</g>)}
  <text x="68" y="89" fill="currentColor" fontSize="8">{new Date(first).toLocaleDateString()}</text><text x="464" y="89" textAnchor="end" fill="currentColor" fontSize="8">{new Date(last).toLocaleDateString()}</text>
 </svg>:<p className="py-4 text-xs text-muted-foreground">No supported SMART readings in this period.</p>}<p className="mt-1 text-[10px] leading-4 text-muted-foreground">Unavailable and removed drives leave gaps. Condition reflects SMART findings, not a predicted failure percentage.</p></div>;
}
export default function DriveHealthPanel({data,latest,enabled,testsEnabled,error,loading,days,onDays,selected,onDrive}){
 const drives=useMemo(()=>{const map=new Map();for(const p of data?.history||[])if(p.snapshot?.id)map.set(p.snapshot.id,p.snapshot);for(const d of [...(data?.drives||[]),...(latest||[])])map.set(d.id,d);return [...map.values()].sort((a,b)=>Number(b.present)-Number(a.present)||a.name.localeCompare(b.name));},[data,latest]);
 const drive=drives.find(d=>d.id===selected)||drives[0];
 const history=driveTimeline(data?.history||[],drive?.id);
 const assessment=driveAssessment({drive_health:latest?.length?latest:data?.drives,drive_health_enabled:enabled});
 const isNvme=drive?.protocol?.includes('nvme')&&drive?.checked_at!=null;
 const missing=(value,applies=true)=>value==null?(applies?'Not reported':'Not applicable'):number(value);
 const overdue=drive?.present&&drive?.checked_at&&Date.now()-drive.checked_at>75*60*1000;
 return <section aria-label="Physical drive health and history" className="min-w-0 rounded-xl border border-border p-3 sm:p-4">
  <div className="flex flex-wrap items-start justify-between gap-3"><div><h3 className="text-sm font-semibold">Drive health</h3><p className="mt-1 text-xs text-muted-foreground">{assessment.total?assessment.detail:'Waiting for physical-drive SMART reports'}</p></div><SearchDropdown aria-label="Drive health history period" className="min-w-0 text-xs" value={days} onChange={e=>onDays(Number(e.target.value))}><option value="7">Last 7 days</option><option value="30">Last 30 days</option><option value="90">Last 90 days</option></SearchDropdown></div>
  {loading&&!drives.length&&<p role="status" className="py-4 text-xs text-muted-foreground">Reading drive health…</p>}
  {data?.truncated&&<p className="mt-3 text-xs text-amber-500">Showing the newest health observations. Select a physical drive to inspect its complete retained period.</p>}
  {error&&<p role="status" className="mt-3 text-xs text-amber-500">{error}</p>}
  {!drives.length&&!loading&&<p className="mt-4 text-xs leading-5 text-muted-foreground">No drive health report is available. Update the agent and enable drive-health reporting. Unsupported native SMART access is reported explicitly.</p>}
  {enabled===false&&<p className="mt-3 text-xs text-muted-foreground">Drive-health reporting is disabled on this client. Previously recorded readings remain available in history.</p>}
  {testsEnabled===false&&enabled!==false&&<p className="mt-3 text-xs text-muted-foreground">Automatic short self-tests are disabled on this client. SMART monitoring continues.</p>}
  {drive&&<>
   <div className="mt-4"><SearchDropdown aria-label="Physical drive" value={drive.id} onChange={e=>onDrive(e.target.value)}>{drives.map(d=><option key={d.id} value={d.id}>{d.name} · {formatBytes(d.capacity)}{d.present?'':' · Removed'}</option>)}</SearchDropdown></div>
   <div className="mt-3 flex flex-wrap items-center justify-between gap-2"><Status value={enabled===false?'unavailable':drive.status}/><span className="text-[10px] text-muted-foreground">{drive.protocol==='os_smart'?'Native OS SMART assessment':drive.protocol.toUpperCase()} · {formatBytes(drive.capacity)}</span></div>
   <p className="mt-1 text-[10px] leading-4 text-muted-foreground">Last SMART check: {date(drive.checked_at)}{overdue?' · Check overdue':''}{!drive.present?` · Removed ${date(drive.observed_at)}`:''}</p>
   {drive.reasons?.length>0&&<ul className="mt-3 space-y-1 text-xs text-muted-foreground">{drive.reasons.map(reason=><li key={reason}>{reason}</li>)}</ul>}
   <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-3 sm:grid-cols-3">
    {[['Temperature',drive.temperature==null?'Unavailable':`${drive.temperature.toFixed(1)}°C`],['Rated endurance used',drive.percentage_used==null?'Not reported':`${drive.percentage_used}%`],['Available spare',drive.available_spare==null?'Not reported':`${drive.available_spare}%${drive.spare_threshold==null?'':` · threshold ${drive.spare_threshold}%`}`],['Power-on hours',number(drive.power_on_hours)],['Media / data errors',missing(drive.media_errors)],['Pending sectors',missing(drive.pending_sectors,!isNvme)],['Reallocated sectors',missing(drive.reallocated_sectors,!isNvme)],['Uncorrectable sectors',missing(drive.uncorrectable_sectors,!isNvme)],['Reported uncorrectable events',missing(drive.reported_uncorrectable_errors,!isNvme)],['Lifetime host reads',drive.lifetime_read_bytes==null?'Not reported':`≈ ${formatBytes(drive.lifetime_read_bytes)}`],['Lifetime host writes',drive.lifetime_written_bytes==null?'Not reported':`≈ ${formatBytes(drive.lifetime_written_bytes)}`],['Power cycles',missing(drive.power_cycles)],['Unsafe shutdowns',missing(drive.unsafe_shutdowns)],['Short self-test',tests[drive.self_test]||'Unavailable']].map(([label,value])=><div key={label} className="min-w-0"><dt className="text-[10px] leading-4 text-muted-foreground">{label}</dt><dd className="mt-0.5 break-words text-xs tabular-nums">{value}</dd></div>)}
   </dl>
   {drive.short_test_supported&&testsEnabled!==false&&<p className="mt-3 text-[10px] leading-4 text-muted-foreground">Last short test started: {date(drive.last_test_started)} · Next eligible check: {date(drive.next_test_at)}. Tests wait until the drive and machine are idle.</p>}
   <ConditionHistory history={history}/>
   <ol aria-label="Drive health observations" className="mt-3 max-h-52 divide-y divide-border overflow-y-auto overscroll-contain">{history.slice(-12).reverse().map((point,index)=><li key={`${point.at}:${index}`} className="py-2"><div className="flex items-center justify-between gap-3"><time className="text-[10px] text-muted-foreground" dateTime={new Date(point.at).toISOString()}>{date(point.at)}</time><Status value={point.snapshot.status}/></div><p className="mt-1 text-[10px] leading-4 text-muted-foreground">{point.snapshot.reasons?.join(' · ')||`Short test: ${tests[point.snapshot.self_test]||'Unavailable'}`}{point.snapshot.percentage_used!=null?` · Endurance used ${point.snapshot.percentage_used}%`:''}{point.snapshot.temperature!=null?` · ${point.snapshot.temperature.toFixed(1)}°C`:''}</p></li>)}</ol>
  </>}
  <p className="mt-4 text-[10px] leading-4 text-muted-foreground">Physical drives are rediscovered every minute. SMART refreshes every 30 minutes; supported short self-tests run weekly when idle. Sleeping drives are not woken for checks. Health and topology history is retained for 90 days.</p>
 </section>;
}
