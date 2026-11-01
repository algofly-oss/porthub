export const terminalScopes = {
  relay: { label: "Gateway relay", incoming: "relay_received", outgoing: "relay_sent", detail: "Decoded terminal payload through the gateway. Excludes control messages and TLS framing." },
  direct: { label: "Direct UDP", incoming: "udp_received", outgoing: "udp_sent", detail: "Host-observed WebRTC datagrams, including protocol overhead. Excludes external discovery probes." },
  pty: { label: "Terminal payload", incoming: "pty_input", outgoing: "pty_output", detail: "Bytes written to and read from attachment PTYs, including redraws for each guest." },
};
export const terminalRanges = { "10m": [600, 5], "1h": [3600, 60], "24h": [86400, 900], "7d": [604800, 7200], "30d": [2592000, 86400] };
const fields = ["relay_received", "relay_sent", "udp_received", "udp_sent", "pty_input", "pty_output"];
export function normalizeTerminalTraffic(value) {
  const expected = terminalRanges[value?.range];
  if (!expected || value.scope !== "terminal_host_measurements" || value.interval_seconds !== expected[1] ||
    !Number.isSafeInteger(value.start) || !Number.isSafeInteger(value.end) || value.start <= 0 ||
    value.end - value.start !== (expected[0] - expected[1]) * 1000 || !Array.isArray(value.points) || value.points.length > 120)
    throw Error("Invalid terminal measurements");
  const seen = new Set();
  const points = value.points.map(point => {
    if (!Number.isSafeInteger(point?.at) || point.at < value.start || point.at > value.end ||
      point.at % (expected[1] * 1000) || seen.has(point.at) || fields.some(field => !Number.isSafeInteger(point[field]) || point[field] < 0))
      throw Error("Invalid terminal measurements");
    if (![0,1].includes(point.host_reports ?? 0) || !Number.isSafeInteger(point.unreported_hosts ?? 0) || (point.unreported_hosts ?? 0) < 0)
      throw Error("Invalid terminal reporting coverage");
    seen.add(point.at);
    return { ...Object.fromEntries(["at", ...fields].map(field => [field, point[field]])), host_reports: point.host_reports ?? 0, unreported_hosts: point.unreported_hosts ?? 0 };
  }).sort((a, b) => a.at - b.at);
  return { range: value.range, start: value.start, end: value.end, interval_seconds: expected[1], points };
}
export function terminalWindow(data, scope) {
  if (!data) return [];
  const selected = terminalScopes[scope], byTime = new Map(data.points.map(point => [point.at, point]));
  return Array.from({ length: Math.round((data.end - data.start) / (data.interval_seconds * 1000)) + 1 }, (_, index) => {
    const at = data.start + index * data.interval_seconds * 1000, candidate = byTime.get(at), point = scope === "relay" || candidate?.host_reports ? candidate : null;
    return { at, incoming: point ? point[selected.incoming] : null, outgoing: point ? point[selected.outgoing] : null };
  });
}
export function demoTerminalTraffic(range = "1h", machine = "all", known = true, now = Date.now()) {
  const [seconds, step] = terminalRanges[range] || terminalRanges["1h"];
  const end = Math.floor(now / (step * 1000)) * step * 1000, start = end - (seconds - step) * 1000;
  return { scope: "terminal_host_measurements", range, start, end, interval_seconds: step,
    points: !known ? [] : Array.from({ length: Math.min(12, seconds / step) }, (_, index) => {
      const factor = machine === "all" ? 3 : 1, bytes = (index % 4 + 1) * 2048 * factor;
      return { at: end - (11 - index) * step * 1000, host_reports: 1, unreported_hosts: 0, relay_received: bytes, relay_sent: bytes * 4, udp_received: bytes * 2, udp_sent: bytes * 7, pty_input: bytes, pty_output: bytes * 5 };
    }) };
}
