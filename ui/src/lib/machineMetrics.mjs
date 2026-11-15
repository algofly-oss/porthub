export const RESOURCES = [['cpu', 'CPU'], ['gpu', 'GPU'], ['ram', 'RAM'], ['disk', 'Disk']];
const percent = value => Number.isFinite(value) && value >= 0 && value <= 100 ? value : null;
export function utilization(sample, key) {
  if (!sample) return null;
  if (key === 'cpu') return percent(sample.cpu);
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
export function gpuReading(sample, id) { return sample?.gpus?.find((gpu,index) => gpuIdentity(gpu,index) === id); }
export function capacityPercent(memory) { return memory?.total > 0 ? percent(memory.used / memory.total * 100) : null; }
export function gpuDevices(history, latest) {
  const devices = new Map();
  for (const sample of [...history.map(p=>p.sample), latest].filter(Boolean)) sample.gpus?.forEach((g,i)=>devices.set(gpuIdentity(g,i),{id:gpuIdentity(g,i),name:g.name}));
  return [...devices.values()];
}
export function diskDevices(history, latest) {
  const devices = new Map();
  for (const sample of [...history.map(p=>p.sample), latest].filter(Boolean)) sample.disks?.forEach(d=>devices.set(d.id,{id:d.id,name:d.name}));
  return [...devices.values()];
}
