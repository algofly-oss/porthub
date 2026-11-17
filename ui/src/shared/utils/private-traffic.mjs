export const privateRanges = { '1h': 60, '24h': 900, '7d': 7200, '30d': 86400 };
const durations = { '1h': 3600, '24h': 86400, '7d': 604800, '30d': 2592000 };
const count = value => Number.isSafeInteger(value) && value >= 0;
const text = value => typeof value === 'string' && value.length > 0 && value.length <= 512;
const machineId = value => typeof value === 'string' && /^[a-f0-9]{24}$/.test(value);
const rate = value => typeof value === 'number' && Number.isFinite(value) && value >= 0;
const fail = () => { throw Error('Invalid private traffic response'); };
export const privateFlowKey = flow => JSON.stringify([flow.source_peer_id, flow.destination_peer_id]);

function pointsInWindow(points, fields, start, end, step, fallbackCoverage = null) {
  if (!Array.isArray(points) || points.length > (end - start) / step + 1) fail();
  const seen = new Set();
  return points.map(point => {
    if (!point || !count(point.at) || point.at < start || point.at > end || point.at % step || seen.has(point.at) || fields.some(field => !count(point[field]))) fail();
    seen.add(point.at);
    if (!Number.isSafeInteger(point[fields[0]] + point[fields[1]])) fail();
    const result = Object.fromEntries(['at', ...fields].map(field => [field, point[field]]));
    if (fallbackCoverage !== null) {
      const coverage = point.coverage ?? fallbackCoverage;
      if (!['sender_reported', 'receiver_only'].includes(coverage)) fail();
      result.coverage = coverage;
    }
    return result;
  }).sort((a, b) => a.at - b.at);
}
function normalizeFlow(flow, window, history) {
  if (!flow || !['source_peer_id', 'destination_peer_id', 'source_name', 'destination_name'].every(key => text(flow[key])) || !['source_machine_id', 'destination_machine_id'].every(key => machineId(flow[key])) || flow.source_peer_id === flow.destination_peer_id || !['direct_bytes', 'relay_bytes', 'total_bytes'].every(key => count(flow[key])) || flow.total_bytes !== flow.direct_bytes + flow.relay_bytes || !rate(flow.bytes_per_second) || !['sender_reported', 'receiver_only'].includes(flow.coverage) || !Number.isSafeInteger(flow.recent_interval_seconds) || flow.recent_interval_seconds < 1 || flow.recent_interval_seconds > 120 || !count(flow.latest_report_at) || flow.latest_report_at <= 0 || (flow.recent_bytes_per_second !== null && !rate(flow.recent_bytes_per_second)) || typeof flow.rate_stale !== 'boolean' || flow.rate_stale !== (flow.recent_bytes_per_second === null) || (flow.rate_stale ? flow.rate_at !== null : (!count(flow.rate_at) || flow.rate_at <= 0))) fail();
  if (!history) {
    if (Object.hasOwn(flow, 'points')) fail(); // List polling must never download every pair's history.
    return { ...flow };
  }
  const points = pointsInWindow(flow.points, ['direct_bytes', 'relay_bytes'], window.start, window.end, window.step, flow.coverage);
  const direct = points.reduce((sum, point) => sum + point.direct_bytes, 0), relay = points.reduce((sum, point) => sum + point.relay_bytes, 0);
  if (!count(direct) || !count(relay) || direct !== flow.direct_bytes || relay !== flow.relay_bytes) fail();
  return { ...flow, points };
}
export function normalizePrivateTraffic(value) {
  const step = privateRanges[value?.range] * 1000;
  if (value?.scope !== 'private_peer_carrier_payload' || !Object.hasOwn(privateRanges, value.range) || value.interval_seconds * 1000 !== step || !count(value.start) || value.start <= 0 || !count(value.end) || value.end - value.start !== durations[value.range] * 1000 - step || value.start % step || value.end % step || !Array.isArray(value.flows) || value.flows.length > 40) fail();
  const coverage = value.coverage;
  if (!coverage || !['reporting_peers', 'eligible_peers', 'unreported_peers', 'dropped_rows'].every(key => count(coverage[key])) || !Number.isSafeInteger(coverage.reporting_peers + coverage.unreported_peers) || coverage.reporting_peers + coverage.unreported_peers !== coverage.eligible_peers || typeof coverage.history_incomplete !== 'boolean' || (coverage.dropped_rows > 0 && !coverage.history_incomplete)) fail();
  const pagination = value.pagination;
  if (!pagination || pagination.page_size !== 40 || !count(pagination.page) || pagination.page < 1 || !count((pagination.page - 1) * 40) || !count(pagination.total_pairs) || !count(pagination.filtered_pairs) || pagination.filtered_pairs > pagination.total_pairs || value.flows.length !== Math.min(40, Math.max(0, pagination.filtered_pairs - (pagination.page - 1) * 40))) fail();
  const totals = value.totals;
  if (!totals || !['direct_bytes', 'relay_bytes', 'total_bytes'].every(key => count(totals[key])) || totals.total_bytes !== totals.direct_bytes + totals.relay_bytes || !rate(totals.bytes_per_second)) fail();
  const points = pointsInWindow(value.points, ['direct_sent', 'relay_sent', 'direct_received', 'relay_received'], value.start, value.end, step);
  if (points.reduce((sum, point) => sum + point.direct_sent, 0) !== totals.direct_bytes || points.reduce((sum, point) => sum + point.relay_sent, 0) !== totals.relay_bytes) fail();
  const window = { start: value.start, end: value.end, step }, seen = new Set();
  const flows = value.flows.map(flow => {
    const result = normalizeFlow(flow, window, false), key = privateFlowKey(result);
    if (seen.has(key)) fail();
    seen.add(key);
    return result;
  });
  const pageTotals = privateTrafficTotals(flows);
  if (pageTotals.direct > totals.direct_bytes || pageTotals.relay > totals.relay_bytes) fail();
  const selected_flow = value.selected_flow === null ? null : normalizeFlow(value.selected_flow, window, true);
  if (selected_flow && (selected_flow.direct_bytes > totals.direct_bytes || selected_flow.relay_bytes > totals.relay_bytes)) fail();
  return { ...value, flows, points, selected_flow, totals: { ...totals }, coverage: { ...coverage }, pagination: { ...pagination } };
}
export function privateTrafficTotals(flows) {
  return flows.reduce((total, flow) => {
    const next = { bytes: total.bytes + flow.total_bytes, average: total.average + flow.bytes_per_second, direct: total.direct + flow.direct_bytes, relay: total.relay + flow.relay_bytes, recent: total.recent + (flow.recent_bytes_per_second ?? 0), recentFlows: total.recentFlows + (flow.recent_bytes_per_second === null ? 0 : 1) };
    if (![next.bytes, next.direct, next.relay].every(count) || !rate(next.average) || !rate(next.recent)) fail();
    return next;
  }, { bytes: 0, average: 0, direct: 0, relay: 0, recent: 0, recentFlows: 0 });
}
export function privateTrafficWindow(data, flow = null) {
  if (!data) return [];
  const step = data.interval_seconds * 1000;
  const byTime = new Map((flow ? flow.points : data.points).map(point => [point.at, point]));
  return Array.from({ length: (data.end - data.start) / step + 1 }, (_, index) => {
    const at = data.start + index * step, point = byTime.get(at);
    // Account SENT is already canonical, including receiver-only fallback.
    // Observed RX is informational and must never be summed with it.
    return { at, direct: point ? point[flow ? 'direct_bytes' : 'direct_sent'] : null, relay: point ? point[flow ? 'relay_bytes' : 'relay_sent'] : null, ...(flow && point ? { coverage: point.coverage } : {}) };
  });
}
export function privateFlowSelection(flows, selected) {
  return flows.find(flow => privateFlowKey(flow) === selected) || null;
}

export function privateTrafficRequest({ range, machine = 'all', search = '', page = 1, selected = null }) {
  if (!Object.hasOwn(privateRanges, range) || (machine !== 'all' && !machineId(machine)) || typeof search !== 'string' || search.length > 128 || !count(page) || page < 1) fail();
  const params = new URLSearchParams({ range, page: String(page), ...(machine === 'all' ? {} : { machine_id: machine }), ...(search ? { search } : {}) });
  const listKey = `/api/private/traffic?${params}`;
  if (selected) {
    if (!text(selected.source_peer_id) || !text(selected.destination_peer_id) || selected.source_peer_id === selected.destination_peer_id) fail();
    params.set('source_peer_id', selected.source_peer_id); params.set('destination_peer_id', selected.destination_peer_id);
  }
  return { key: `/api/private/traffic?${params}`, listKey };
}
export function privateTrafficForRequest(data, request) {
  if (data.range !== request.range || data.pagination.page !== request.page || (request.machine !== 'all' && [...data.flows, ...(data.selected_flow ? [data.selected_flow] : [])].some(flow => flow.source_machine_id !== request.machine && flow.destination_machine_id !== request.machine))) fail();
  if (data.selected_flow && (!request.selected || privateFlowKey(data.selected_flow) !== privateFlowKey(request.selected))) fail();
  return data;
}
