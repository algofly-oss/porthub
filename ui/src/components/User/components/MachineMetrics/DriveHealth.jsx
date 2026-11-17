import {useEffect,useRef} from 'react';
import SearchDropdown from '@/components/ui/search-dropdown';
import {driveTimeline,driveInventoryView,driveCatalog,driveConditionSeries,visibleDriveEntries} from '@/lib/machineMetrics.mjs';
import {formatBytes} from '@/shared/utils/traffic.mjs';
const states={historical:{label:'Historical',color:'text-muted-foreground'},unknown:{label:'Current status unknown',color:'text-muted-foreground'},healthy:{label:'Healthy',color:'text-emerald-500'},warning:{label:'Needs attention',color:'text-amber-500'},critical:{label:'Critical',color:'text-red-500'},unavailable:{label:'Unavailable',color:'text-muted-foreground'},sleeping:{label:'Sleeping',color:'text-muted-foreground'},removed:{label:'Removed',color:'text-muted-foreground'}};
const tests={not_run:'Not yet run',running:'Running',passed:'Passed',failed:'Failed',aborted:'Aborted',unsupported:'Not supported',deferred:'Deferred until idle'};
const number=value=>value==null?'Unavailable':new Intl.NumberFormat().format(value);
const date=value=>value?new Date(value).toLocaleString():'Not yet checked';
function Status({value}){const state=states[value]||states.unavailable;return <span className={`text-xs font-medium ${state.color}`}>{state.label}</span>;}
const lineColors=['#0284c7','#d97706','#db2777','#059669','#dc2626','#0891b2','#475569','#a16207'];
function currentState(drive){return drive.reportMembership==='historical'?'historical':drive.reportMembership==='unknown'?'unknown':drive.status;}
function ConditionHistory({history,drives,selected,onDrive}){
 const series=driveConditionSeries(history,drives);
 const times=history.map(p=>p.at).filter(Number.isFinite),first=times.length?Math.min(...times):0,last=times.length?Math.max(...times):first+1;
 const x=at=>8+(at-first)/Math.max(1,last-first)*384,y=value=>110-value*50;
 const supported=series.some(s=>s.segments.length);
 return <div className="mt-4 min-w-0 rounded-lg bg-control/40 p-3" aria-label="All physical drives SMART condition">
  <h4 className="text-xs font-medium">SMART condition · All drives</h4>
  {supported?<div className="mt-3 grid grid-cols-[3rem_minmax(0,1fr)] gap-x-2">
   <div data-condition-axis className="relative h-32 text-[10px] text-muted-foreground">{[[2,'Healthy'],[1,'Warning'],[0,'Critical']].map(([value,label])=><span key={label} className="absolute right-0 -translate-y-1/2" style={{top:`${y(value)/1.2}%`}}>{label}</span>)}</div>
   <svg role="img" aria-label="All-drive SMART condition history" viewBox="0 0 400 120" preserveAspectRatio="none" className="h-32 w-full">
   {[2,1,0].map(value=><line key={value} x1="8" x2="392" y1={y(value)} y2={y(value)} stroke="currentColor" opacity=".12"/>)}
   {series.map(({drive,segments},i)=><g key={drive.id} data-drive-id={drive.id} aria-label={drive.name}>{segments.map((segment,j)=><g key={j}>{segment.length>1&&<polyline fill="none" stroke={lineColors[i%lineColors.length]} strokeWidth={drive.id===selected?2.5:1.75} strokeDasharray={i%2?'5 3':undefined} points={segment.map(p=>`${x(p.at)},${y(p.value)}`).join(' ')}/>} {segment.map((p,k)=><circle key={k} cx={x(p.at)} cy={y(p.value)} r="3" fill={lineColors[i%lineColors.length]}><title>{drive.name} · {date(p.at)} · {['Critical','Warning','Healthy'][p.value]}</title></circle>)}</g>)}</g>)}
   </svg><div data-condition-dates className="col-start-2 mt-1 flex justify-between gap-2 text-[10px] text-muted-foreground"><span>{new Date(first).toLocaleDateString()}</span><span>{new Date(last).toLocaleDateString()}</span></div></div>:<p className="py-4 text-xs text-muted-foreground">No supported SMART readings in this period.</p>}
  <ul aria-label="Drive condition legend" className="mt-3 max-h-40 space-y-1 overflow-y-auto overscroll-contain">{series.map(({drive},i)=><li key={drive.id}><button type="button" onClick={()=>onDrive(drive.id)} aria-pressed={drive.id===selected} className="flex min-h-[44px] w-full items-center gap-2 rounded-md px-1 text-left hover:bg-control focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary"><span aria-hidden="true" className="h-0.5 w-5 shrink-0" style={{backgroundColor:lineColors[i%lineColors.length]}}/><span className="min-w-0 flex-1 break-words text-xs">{drive.name}</span><Status value={currentState(drive)}/></button></li>)}</ul>
  <p className="mt-2 text-[10px] leading-4 text-muted-foreground">Unknown, unavailable and removed observations leave gaps. SMART condition is categorical, not a predicted failure percentage.</p>
 </div>;
}
export default function DriveHealthPanel({data,selectedData,latest,reportedAt,enabled,testsEnabled,error,loading,days,onDays,selected,onDrive}){
 const catalog=useRef([]);
 catalog.current=driveCatalog(catalog.current,data?.history,data?.drives,latest);
 const inventory=driveInventoryView({drives:catalog.current,latest,reportedAt,enabled});
 const drives=visibleDriveEntries(inventory.entries);
 const drive=drives.find(d=>d.id===selected)||drives[0];
 useEffect(()=>{if(selected&&selected!==drive?.id)onDrive(drive?.id||'');},[selected,drive?.id,onDrive]);
 const history=driveTimeline(selectedData?.history||data?.history||[],drive?.id);
 const attention=drives.filter(d=>d.reportMembership==='current'&&d.present&&['warning','critical'].includes(d.status));
 const critical=attention.some(d=>d.status==='critical');
 const assessment=inventory.assessment;
 const membership=drive?.reportMembership;
 const status=membership==='historical'?'historical':membership==='unknown'?'unknown':drive?.status;
 const isNvme=drive?.protocol?.includes('nvme')&&drive?.checked_at!=null;
 const missing=(value,applies=true)=>value==null?(applies?'Not reported':'Not applicable'):number(value);
 const overdue=membership==='current'&&drive?.present&&drive?.checked_at&&Date.now()-drive.checked_at>75*60*1000;
 return <section aria-label="Physical drive health and history" className="min-w-0 rounded-xl border border-border p-3 sm:p-4">
  <div className="flex flex-wrap items-start justify-between gap-3"><div><h3 className="text-sm font-semibold">Drive health</h3><p className="mt-1 text-xs text-muted-foreground">{assessment.detail}</p></div><SearchDropdown aria-label="Drive health history period" className="min-w-0 text-xs" value={days} onChange={e=>onDays(Number(e.target.value))}><option value="7">Last 7 days</option><option value="30">Last 30 days</option><option value="90">Last 90 days</option></SearchDropdown></div>
  {loading&&!drives.length&&<p role="status" className="py-4 text-xs text-muted-foreground">Reading drive health…</p>}
  {data?.truncated&&<p className="mt-3 text-xs text-amber-500">Showing the newest health observations. The all-drive chart may omit older observations. Select a drive for its detailed retained history.</p>}
  {error&&<p role="status" className="mt-3 text-xs text-amber-500">{error}</p>}
  {!drives.length&&!loading&&<p className="mt-4 text-xs leading-5 text-muted-foreground">{inventory.authoritative?'No physical drives are reported by this client.':'No current drive inventory is available. Previously recorded health remains available when reporting resumes.'}</p>}
  {enabled===false&&<p className="mt-3 text-xs text-muted-foreground">Drive-health reporting is disabled on this client. Previously recorded readings remain available in history.</p>}
  {testsEnabled===false&&enabled!==false&&<p className="mt-3 text-xs text-muted-foreground">Automatic short self-tests are disabled on this client. SMART monitoring continues.</p>}
  {attention.length>0&&<div role="status" aria-label="Drives needing attention" className={`mt-4 rounded-lg border p-3 ${critical?'border-red-500/30 bg-red-500/5':'border-amber-500/30 bg-amber-500/5'}`}><h4 className="text-xs font-semibold">{critical?'Critical drive condition':'Drives need attention'}</h4><ul className="mt-2 space-y-2">{attention.map(d=><li key={d.id} className="text-xs"><div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1"><span className="min-w-0 break-words font-medium">{d.name}</span><Status value={d.status}/></div>{d.reasons?.length>0&&<p className="mt-1 break-words text-[11px] leading-4 text-muted-foreground">{d.reasons.join(' · ')}</p>}</li>)}</ul></div>}
  {drives.length>0&&<ConditionHistory history={data?.history||[]} drives={drives} selected={drive?.id} onDrive={onDrive}/>}
  {drive&&<>
   <div className="mt-4"><SearchDropdown aria-label="Physical drive" value={drive.id} onChange={e=>onDrive(e.target.value)}>{drives.map(d=><option key={d.id} value={d.id}>{d.name} · {formatBytes(d.capacity)}{d.reportMembership==='current'?'':d.reportMembership==='historical'?' · Historical':d.reportMembership==='removed'?' · Removed':' · Last recorded'}</option>)}</SearchDropdown></div>
   <div className="mt-3 flex flex-wrap items-center justify-between gap-2"><Status value={status}/><span className="text-[10px] text-muted-foreground">{drive.protocol==='os_smart'?'Native OS SMART assessment':drive.protocol.toUpperCase()} · {formatBytes(drive.capacity)}</span></div>
   {membership==='historical'&&<p className="mt-2 text-xs text-muted-foreground">Not in the current report. Last recorded health: {states[drive.status]?.label||'Unavailable'}.</p>}
   {membership==='unknown'&&<p className="mt-2 text-xs text-muted-foreground">Current presence is unknown. Last recorded health: {states[drive.status]?.label||'Unavailable'}.</p>}
   <p className="mt-1 text-[10px] leading-4 text-muted-foreground">{membership==='current'?'Last SMART check:':'Last recorded SMART check:'} {date(drive.checked_at)}{overdue?' · Check overdue':''}{membership==='removed'?` · Removed ${date(drive.observed_at)}`:''}</p>
   {drive.reasons?.length>0&&<ul className="mt-3 space-y-1 text-xs text-muted-foreground">{drive.reasons.map(reason=><li key={reason}>{reason}</li>)}</ul>}
   <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-3 sm:grid-cols-3">
    {[['Temperature',drive.temperature==null?'Unavailable':`${drive.temperature.toFixed(1)}°C`],['Rated endurance used',drive.percentage_used==null?'Not reported':`${drive.percentage_used}%`],['Available spare',drive.available_spare==null?'Not reported':`${drive.available_spare}%${drive.spare_threshold==null?'':` · threshold ${drive.spare_threshold}%`}`],['Power-on hours',number(drive.power_on_hours)],['Media / data errors',missing(drive.media_errors)],['Pending sectors',missing(drive.pending_sectors,!isNvme)],['Reallocated sectors',missing(drive.reallocated_sectors,!isNvme)],['Uncorrectable sectors',missing(drive.uncorrectable_sectors,!isNvme)],['Reported uncorrectable events',missing(drive.reported_uncorrectable_errors,!isNvme)],['Lifetime host reads',drive.lifetime_read_bytes==null?'Not reported':`≈ ${formatBytes(drive.lifetime_read_bytes)}`],['Lifetime host writes',drive.lifetime_written_bytes==null?'Not reported':`≈ ${formatBytes(drive.lifetime_written_bytes)}`],['Power cycles',missing(drive.power_cycles)],['Unsafe shutdowns',missing(drive.unsafe_shutdowns)],['Short self-test',tests[drive.self_test]||'Unavailable']].map(([label,value])=><div key={label} className="min-w-0"><dt className="text-[10px] leading-4 text-muted-foreground">{label}</dt><dd className="mt-0.5 break-words text-xs tabular-nums">{value}</dd></div>)}
   </dl>
   {membership==='current'&&drive.short_test_supported&&testsEnabled!==false&&<p className="mt-3 text-[10px] leading-4 text-muted-foreground">Last short test started: {date(drive.last_test_started)} · Next eligible check: {date(drive.next_test_at)}. Tests wait until the drive and machine are idle.</p>}
   <ol aria-label="Drive health observations" className="mt-3 max-h-52 divide-y divide-border overflow-y-auto overscroll-contain">{history.slice(-12).reverse().map((point,index)=><li key={`${point.at}:${index}`} className="py-2"><div className="flex items-center justify-between gap-3"><time className="text-[10px] text-muted-foreground" dateTime={new Date(point.at).toISOString()}>{date(point.at)}</time><Status value={point.snapshot.status}/></div><p className="mt-1 text-[10px] leading-4 text-muted-foreground">{point.snapshot.reasons?.join(' · ')||`Short test: ${tests[point.snapshot.self_test]||'Unavailable'}`}{point.snapshot.percentage_used!=null?` · Endurance used ${point.snapshot.percentage_used}%`:''}{point.snapshot.temperature!=null?` · ${point.snapshot.temperature.toFixed(1)}°C`:''}</p></li>)}</ol>
  </>}
  <p className="mt-4 text-[10px] leading-4 text-muted-foreground">Physical drives are rediscovered every minute. SMART refreshes every 30 minutes; supported short self-tests run weekly when idle. Sleeping drives are not woken for checks. Health and topology history is retained for 90 days.</p>
 </section>;
}
