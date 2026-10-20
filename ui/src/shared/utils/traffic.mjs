export function formatBytes(value) {
  const bytes = Math.max(0, Number(value) || 0);
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  const unit = Math.min(4, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / 1024 ** unit).toFixed(1)} ${["B", "KB", "MB", "GB", "TB"][unit]}`;
}

const byteKeys = ["in_bytes", "out_bytes", "drop_bytes"];
const rateKeys = ["in_rate", "out_rate", "drop_rate"];
const ipKeys = ["incoming_ips", "outgoing_ips", "blocked_ips"];
const nonnegative = value => Number.isFinite(Number(value)) ? Math.max(0, Number(value)) : 0;
const emptySample = timestamp => ({ timestamp, in_bytes: 0, out_bytes: 0, drop_bytes: 0, in_rate: 0, out_rate: 0, drop_rate: 0, incoming_ips: [], outgoing_ips: [], blocked_ips: [] });

// Old firewalls send one record per direction. Combine those records before
// limiting history, and keep byte volume separate from bytes/second.
export function normalizeTrafficSamples(samples, limit = 300) {
  const buckets = new Map();
  for (const sample of Array.isArray(samples) ? samples : []) {
    const timestamp = Math.floor(Number(sample?.timestamp));
    if (!Number.isFinite(timestamp) || timestamp <= 0) continue;
    const bucket = buckets.get(timestamp) || emptySample(timestamp);
    const duration = nonnegative(sample.interval_seconds) || 1;
    // Preserve coverage through repeated per-port/per-machine aggregation.
    // Durations overlap across ports; unlike bytes, they must not be added.
    bucket.interval_seconds = Math.max(bucket.interval_seconds || 0, duration);
    byteKeys.forEach((key, index) => {
      bucket[key] += nonnegative(sample[key]);
      bucket[rateKeys[index]] += sample[rateKeys[index]] === undefined ? nonnegative(sample[key]) / duration : nonnegative(sample[rateKeys[index]]);
    });
    ipKeys.forEach(key => {
      const ips = Array.isArray(sample[key]) ? sample[key].map(ip => String(ip || "").trim()).filter(Boolean) : [];
      bucket[key] = [...new Set([...bucket[key], ...ips])];
    });
    buckets.set(timestamp, bucket);
  }
  return [...buckets.values()].sort((a, b) => a.timestamp - b.timestamp).slice(-limit);
}

export function buildTrafficWindow(samples, windowSeconds = 60, now) {
  const normalized = normalizeTrafficSamples(samples);
  // Plot the most recent completed measurements, rather than leaving the last
  // few seconds blank while a snapshot is in transit. Labels show its real age.
  const windowEndTimestamp = Math.floor(now ?? normalized[normalized.length - 1]?.timestamp ?? Date.now() / 1000);
  const buckets = new Map(normalized.map(sample => [sample.timestamp, sample]));
  for (const sample of normalized) {
    // A delayed counter read still measures ALL bytes since the previous read.
    // Render its measured average across that interval. This is not a zero-fill
    // or interpolation across an outage: uncovered history remains unknown.
    const span = Math.min(windowSeconds, Math.ceil(sample.interval_seconds || 1));
    for (let offset = 1; offset < span; offset++) {
      const timestamp = sample.timestamp - offset;
      if (timestamp <= windowEndTimestamp - windowSeconds || timestamp > windowEndTimestamp || buckets.has(timestamp)) continue;
      buckets.set(timestamp, { ...emptySample(timestamp), in_rate: sample.in_rate, out_rate: sample.out_rate, drop_rate: sample.drop_rate,
        interval_seconds: sample.interval_seconds, intervalAverage: true });
    }
  }
  return {
    windowEndTimestamp,
    samples: Array.from({ length: windowSeconds }, (_, index) => {
      const timestamp = windowEndTimestamp - windowSeconds + 1 + index;
      const sample = buckets.get(timestamp);
      // Missing history is unknown, never a copy of the first observed value.
      return { ...(sample || emptySample(timestamp)), observed: !!sample };
    }),
  };
}

export function trafficLinePath(samples, key, width, height, maxValue) {
  if (!samples.some(sample => sample.observed !== false && sample[key] > 0) || maxValue <= 0) return "";
  let previous = null;
  const commands = [];
  samples.forEach((sample, index) => {
    if (sample.observed === false) { previous = null; return; }
    const point = { x: index / Math.max(1, samples.length - 1) * width, y: height - nonnegative(sample[key]) / maxValue * height };
    if (!previous) commands.push(`M ${point.x.toFixed(2)} ${point.y.toFixed(2)}`);
    else {
      const middle = ((previous.x + point.x) / 2).toFixed(2);
      commands.push(`C ${middle} ${previous.y.toFixed(2)}, ${middle} ${point.y.toFixed(2)}, ${point.x.toFixed(2)} ${point.y.toFixed(2)}`);
    }
    previous = point;
  });
  return commands.join(" ");
}

export function trafficSummary(samples, seconds = 60, now = Date.now() / 1000) {
  const recent = normalizeTrafficSamples(samples).filter(s => s.timestamp > now - seconds && s.timestamp <= now + 1);
  const latest = recent[recent.length - 1];
  const live = latest && now - Number(latest.timestamp) <= 5 ? latest : {};
  return {
    incoming: live.in_rate || 0, outgoing: live.out_rate || 0,
    blocked: live.drop_rate || 0,
    volume: recent.reduce((sum, s) => sum + (Number(s.in_bytes) || 0) + (Number(s.out_bytes) || 0), 0),
    incomingVolume: recent.reduce((sum, s) => sum + s.in_bytes, 0),
    outgoingVolume: recent.reduce((sum, s) => sum + s.out_bytes, 0),
    blockedVolume: recent.reduce((sum, s) => sum + (Number(s.drop_bytes) || 0), 0),
    ips: [...new Set(recent.flatMap(s => [...(s.incoming_ips || []), ...(s.outgoing_ips || [])]))],
    blockedIps: [...new Set(recent.flatMap(s => s.blocked_ips || []))],
  };
}

export function aggregateTraffic(rows) {
  return normalizeTrafficSamples(rows.flatMap(row => row.traffic || []));
}
