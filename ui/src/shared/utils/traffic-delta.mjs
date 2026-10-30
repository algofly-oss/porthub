// A delta replaces an observed second. Summing old and new snapshots would
// double counters when the server overlaps the cursor for a late measurement.
export function mergeTrafficDelta(previous = [], delta = [], limit = 300, removed = []) {
  const deleted=new Set(removed || []);
  const rows = new Map(previous.filter(row=>!deleted.has(Number(row.timestamp))).map(row => [Number(row.timestamp), row]));
  for (const row of delta) rows.set(Number(row.timestamp), row);
  return [...rows.values()].filter(row => Number.isFinite(Number(row.timestamp)))
    .sort((a, b) => Number(a.timestamp) - Number(b.timestamp)).slice(-limit);
}

export function mergeTrafficPage(previous, data, key, now = Date.now()) {
  const rows = new Map((data.reset ? [] : previous.rows || []).map(row => [row.connection._id, row.traffic]));
  return {
    key,
    rows: (data.data || []).map(row => ({ ...row, traffic: mergeTrafficDelta(row.replace ? [] : rows.get(row.connection._id), row.traffic, 300, row.removed) })),
    aggregate: mergeTrafficDelta(data.reset || data.aggregate_replace ? [] : previous.aggregate, data.aggregate, 300, data.aggregate_removed),
    pagination: data.pagination, cursor: data.cursor, scopeRevision: data.scope_revision || "", aggregateToken: data.aggregate_token || "",
    loading: false, error: "", updated: now,
  };
}
export function trafficRowCursors(rows, aggregated = false) {
  return rows.map(row => {
    const value = aggregated ? row.token : row.traffic?.[row.traffic.length - 1]?.timestamp;
    return value === undefined || value === "" ? null : `${row.connection._id}:${value}`;
  }).filter(Boolean).join(",");
}
