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
