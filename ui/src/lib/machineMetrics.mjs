import { formatBytes } from "../shared/utils/traffic.mjs";
export const RESOURCES = [['cpu', 'CPU'], ['gpu', 'GPU'], ['ram', 'RAM'], ['disk', 'Disk']];
const percent = value => Number.isFinite(value) && value >= 0 && value <= 100 ? value : null;
export function utilization(sample, key) {
  if (!sample) return null;
  if (key === 'cpu') return sample.cpu_available===false?null:percent(sample.cpu);
  if (key === 'health') return driveAssessment(sample).risk;
  if (key === 'gpu') {
    const values = (sample.gpus || []).map(gpu => percent(gpu.utilization)).filter(value => value !== null);
    return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : null;
  }
  const memory = sample[key];
  return memory?.total > 0 ? percent(memory.used / memory.total * 100) : null;
}
export function rankedMachines(machines, selected, ascending = false) {
  return machines.filter(machine => machine.live).map(machine => {
    const values = selected.map(key => utilization(machine.reading?.sample, key));
    const score = selected.length && values.every(value => value !== null) ? values.reduce((sum, value) => sum + value, 0) / values.length : null;
    return { ...machine, score };
  }).sort((a, b) => a.score === null ? b.score === null ? a.name.localeCompare(b.name) : 1 : b.score === null ? -1 : (ascending ? a.score - b.score : b.score - a.score) || a.name.localeCompare(b.name));
}
export function metricSegments(history, key, intervalMs = 60000) {
  const segments = []; let current = []; let previous = null;
  for (const point of history) {
    const value = typeof key === 'function' ? key(point.sample) : utilization(point.sample, key);
    if (value === null || (previous !== null && point.at - previous > intervalMs * 1.5)) { if (current.length) segments.push(current); current = []; }
    if (value !== null) current.push({ at: point.at, value });
    previous = point.at;
  }
  if (current.length) segments.push(current);
  return segments;
}

export const gpuIdentity = (gpu, index) => gpu.id || `${gpu.name}:${index}`;
export function gpuReading(sample, id, name, allowLegacy=false) {
  const exact=sample?.gpus?.find((gpu,index)=>gpuIdentity(gpu,index)===id);
  if(exact)return exact;
  const older=allowLegacy?sample?.gpus?.filter(g=>!g.id&&g.name===name):[];
  return older?.length===1?older[0]:null;
}
export function memoryText(memory) { return memory?.total > 0 ? `${formatBytes(memory.used)} / ${formatBytes(memory.total)}` : 'Unavailable'; }
export function sharedGpuMemoryText(gpu) {
  if (gpu?.shared_memory?.total > 0) return `${memoryText(gpu.shared_memory)} max`;
  if (gpu?.shared_memory_capacity > 0) return `Up to ${formatBytes(gpu.shared_memory_capacity)} · usage unavailable`;
  return 'Unavailable';
}
export function gpuMemorySummary(gpu) {
  const parts = [gpu.name];
  if (gpu.integrated === true) parts.push('Integrated graphics');
  if (gpu.memory?.total > 0) parts.push(`${memoryText(gpu.memory)} dedicated`);
  if (gpu.shared_memory?.total > 0 || gpu.shared_memory_capacity > 0) parts.push(`${sharedGpuMemoryText(gpu)} shared`);
  return parts.join(' · ');
}

export function capacityPercent(memory) { return memory?.total > 0 ? percent(memory.used / memory.total * 100) : null; }
export function gpuDevices(history, latest) {
  const samples=[latest,...history.slice().reverse().map(p=>p.sample)].filter(Boolean);
  const identities=new Map();
  for(const sample of samples)for(const gpu of sample.gpus||[])if(gpu.id){if(!identities.has(gpu.name))identities.set(gpu.name,new Set());identities.get(gpu.name).add(gpu.id);}
  const devices=new Map();
  for(const sample of samples)(sample.gpus||[]).forEach((g,i)=>{
    const known=identities.get(g.name),unique=known?.size===1;
    const id=!g.id&&unique?[...known][0]:gpuIdentity(g,i);
    devices.set(id,{id,name:!g.id&&known?.size>1?`${g.name} · Older reports`:g.name,allowLegacy:unique});
  });
  return [...devices.values()];
}
export function diskIdentity(disk) {
  const id = disk.id;
  if (/^\/dev\/(?:nvme\d+n\d+|mmcblk\d+)p\d+$/.test(id)) return id.replace(/p\d+$/, '');
  if (/^\/dev\/(?:sd|hd|vd|xvd)[a-z]+\d+$/.test(id)) return id.replace(/\d+$/, '');
  return id;
}
export function diskReading(sample, id) {
  const parts=sample?.disks?.filter(d=>diskIdentity(d)===id);
  return parts?.length ? parts.reduce((sum,d)=>({used:sum.used+d.used,total:sum.total+d.total}),{used:0,total:0}) : null;
}
export function diskDevices(history, latest) {
  const devices = new Map();
  for (const sample of [...history.map(p=>p.sample), latest].filter(Boolean)) sample.disks?.forEach(d=>{
    const id=diskIdentity(d);devices.set(id,{id,name:id===d.id?d.name:id});
  });
  return [...devices.values()];
}

export const RANKING_RESOURCES=[...RESOURCES,['health','Health']];
export const DRIVE_STATUS_LABELS={healthy:'Healthy',warning:'Needs attention',critical:'Critical',unavailable:'Unavailable',sleeping:'Sleeping',removed:'Removed'};
export function driveAssessment(sample,now=Date.now()) {
 if(sample?.drive_health_enabled===false)return {status:'unavailable',label:'Disabled',score:null,risk:null,total:0,checked:0,critical:0,warning:0,incomplete:true,detail:'Drive-health reporting disabled on this client'};
 const drives=(sample?.drive_health||[]).filter(drive=>drive.present);
 if(!drives.length)return {status:'unavailable',label:'Unknown',score:null,risk:null,total:0,checked:0,critical:0,warning:0,incomplete:true,detail:'No physical-drive SMART readings'};
 const current=drive=>drive.checked_at&&drive.checked_at<=now+5*60*1000&&now-drive.checked_at<=75*60*1000;
 const critical=drives.filter(d=>d.status==='critical').length;
 const warning=drives.filter(d=>d.status==='warning').length;
 const checked=drives.filter(d=>current(d)&&['healthy','warning','critical'].includes(d.status)).length;
 const incomplete=checked<drives.length;
 const status=critical?'critical':warning?'warning':incomplete?'unavailable':'healthy';
 const risk=critical?100:warning?50:incomplete?null:0;
 const label=critical?'Critical':warning?'Warning':incomplete?'Unknown':'Healthy';
 return {status,label,score:risk===null?null:100-risk,risk,total:drives.length,checked,critical,warning,incomplete,
  detail:`${critical?`${critical} critical · `:''}${warning?`${warning} need attention · `:''}${checked}/${drives.length} drives have current SMART readings${incomplete?' · Incomplete coverage':''}`};
}
export function driveTimeline(points,id) {return points.filter(point=>point.snapshot?.id===id).sort((a,b)=>a.at-b.at);}

// Historical observations retain their original presence/status. Only an explicit,
// fresh current report can establish current inventory membership.
export function driveInventoryView({history=[],drives=[],latest,reportedAt,enabled,now=Date.now()}={}) {
 const hasCurrent=Array.isArray(latest);
 const current=hasCurrent?latest:[];
 const fresh=Number.isFinite(reportedAt)&&reportedAt<=now+5*60*1000&&now-reportedAt<45000;
 const authoritative=hasCurrent&&enabled===true&&fresh;
 const ids=new Set(current.map(drive=>drive.id));
 const records=new Map();
 for(const point of history)if(point.snapshot?.id)records.set(point.snapshot.id,point.snapshot);
 for(const drive of [...(Array.isArray(drives)?drives:[]),...current])if(drive?.id)records.set(drive.id,drive);
 const entries=[...records.values()].map(drive=>({
  ...drive,
  reportMembership:!authoritative?'unknown':drive.present===false&&drive.status==='removed'?'removed':ids.has(drive.id)?'current':'historical'
 })).sort((a,b)=>Number(b.reportMembership==='current')-Number(a.reportMembership==='current')||a.name.localeCompare(b.name));
 const assessment=enabled===false?driveAssessment({drive_health_enabled:false}):authoritative?driveAssessment({drive_health:current,drive_health_enabled:true},now):{
  status:'unavailable',label:'Unknown',score:null,risk:null,total:0,checked:0,critical:0,warning:0,incomplete:true,detail:'Current drive inventory is unknown · Showing last-recorded health'
 };
 if(authoritative&&!current.some(drive=>drive.present))assessment.detail='No physical drives in the current report';
 return {entries,authoritative,current,assessment};
}

// Keep a bounded host-local picker catalog while a selected-drive query narrows history.
export function driveCatalog(previous=[],history=[],drives=[],latest=[]) {
 const records=new Map(previous.map(drive=>[drive.id,drive]));
 for(const drive of [...(history||[]).map(point=>point.snapshot),...(drives||[]),...(latest||[])])if(drive?.id)records.set(drive.id,drive);
 return [...records.values()].sort((a,b)=>(b.observed_at||0)-(a.observed_at||0)||a.id.localeCompare(b.id)).slice(0,512);
}

// Categorical SMART states, never a health percentage. Unknown/removed samples
// deliberately break each physical drive's line; identities never cross drives.
export function driveConditionSeries(history=[],drives=[]) {
 const groups=new Map();
 for(const point of history)if(point.snapshot?.id&&Number.isFinite(point.at)){
  const id=point.snapshot.id;if(!groups.has(id))groups.set(id,[]);groups.get(id).push(point);
 }
 return drives.map(drive=>{
  const points=(groups.get(drive.id)||[]).sort((a,b)=>a.at-b.at).map(p=>({at:p.at,sample:p.snapshot}));
  const segments=metricSegments(points,s=>s.present?({healthy:2,warning:1,critical:0}[s.status]??null):null,7*24*60*60*1000);
  return {drive,segments};
 });
}

// Presentation only: retained removal observations remain in the catalog/API.
export function visibleDriveEntries(entries=[]) {
 return entries.filter(drive=>drive.present!==false&&drive.status!=='removed'&&drive.reportMembership!=='removed');
}
