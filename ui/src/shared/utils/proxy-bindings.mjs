export const newBinding = (index = 0) => ({ id: `binding-${globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2)}`}`, label: "", target_mode: "manual", target_url: "", connection_data_id: "", enabled: true, priority: index + 1, weight: 1, pass_host: null, health_path: null });
export const defaultRouting = () => ({ mode: "priority", priority_policy: "manual", strategy: "round_robin", sticky_sessions: false, max_attempts: 4, response_timeout_seconds: 310,
  health: { enabled: true, path: "/", interval_seconds: 10, timeout_seconds: 3, unhealthy_after: 2, healthy_after: 2, cooldown_seconds: 10, expected_status_min: 200, expected_status_max: 399 } });
export function proxyBindings(proxy) {
  if (Array.isArray(proxy?.bindings) && proxy.bindings.length) return proxy.bindings.map(b => ({ ...b, connection_data_id: b.connection_data_id || b.connection?.data_id || b.connection?._id || "" }));
  if (!proxy) return [];
  return [{ ...newBinding(), id: "primary", target_mode: proxy.target_mode || (proxy.connection ? "connection" : "manual"), target_url: proxy.target_url || "", connection_data_id: proxy.connection?.data_id || proxy.connection?._id || "", connection: proxy.connection || null }];
}
export function proxyRouting(proxy) {
  const defaults = defaultRouting();
  if (!proxy?.routing) { if (proxy?._id) defaults.health.enabled = false; return defaults; }
  return { ...defaults, ...proxy.routing, health: { ...defaults.health, ...proxy.routing.health } };
}
export function routingLabel(routing) {
  if (routing?.mode !== "balance") return routing?.priority_policy === "health" ? "Health priority" : "Manual priority";
  return ({ round_robin: "Round robin", weighted_round_robin: "Weighted round robin", least_connections: "Least connections" })[routing.strategy] || "Round robin";
}
export function bindingTitle(binding, connections = []) {
  const c = connections.find(c => c._id === binding.connection_data_id) || binding.connection;
  return binding.label || (binding.target_mode === "connection" ? c ? `${c.machine_name || "Machine"} · ${c.service_name || c.internal_port || "Port"}` : "Choose a machine port" : binding.target_url || "New standalone URL");
}
export function validateBindings(bindings, routing) {
  const errors = {};
  if (!bindings.length) errors.bindings = "Add at least one binding.";
  if (bindings.length > 128) errors.bindings = "A proxy supports up to 128 bindings.";
  const targets = new Set();
  bindings.forEach((b, i) => {
    const key = `binding-${b.id}`, prefix = `Binding ${i + 1}: `;
    if (b.target_mode === "connection") {
      if (!b.connection_data_id) errors[key] = prefix + "Choose a machine port.";
    } else {
      try { const u = new URL(b.target_url); if (!["http:", "https:"].includes(u.protocol) || !u.hostname || u.hash) throw Error(); }
      catch { errors[key] = prefix + "Enter a valid http:// or https:// URL without a fragment."; }
    }
    const target = b.target_mode === "connection" ? `port:${b.connection_data_id}` : `url:${b.target_url.trim()}`;
    if (targets.has(target)) errors[key] = prefix + "This target is already in the list.";
    targets.add(target);
    if (!Number.isInteger(Number(b.priority)) || b.priority < 1 || b.priority > 10000) errors[key] = prefix + "Priority must be 1–10000.";
    if (!Number.isInteger(Number(b.weight)) || b.weight < 1 || b.weight > 100) errors[key] = prefix + "Weight must be 1–100.";
    if (b.health_path && (!b.health_path.startsWith("/") || b.health_path.startsWith("//") || /[\r\n#]/.test(b.health_path))) errors[key] = prefix + "Health path must start with a single /.";
  });
  const h = routing.health;
  for (const [key, min, max] of [["interval_seconds",1,300],["timeout_seconds",1,30],["unhealthy_after",1,10],["healthy_after",1,10],["cooldown_seconds",1,300],["expected_status_min",200,599],["expected_status_max",200,599]]) {
    if (!Number.isInteger(Number(h[key])) || h[key] < min || h[key] > max) errors.health = "Check the health settings: a value is outside its allowed range.";
  }
  if (!h.path.startsWith("/") || h.path.startsWith("//") || /[\r\n#]/.test(h.path)) errors.health = "Health path must start with a single /.";
  if (Number(h.expected_status_min) > Number(h.expected_status_max)) errors.health = "Healthy status range must run from a lower to a higher status.";
  if (!Number.isInteger(Number(routing.max_attempts)) || routing.max_attempts < 1 || routing.max_attempts > 128) errors.health = "Attempt limit must be 1–128.";
  if (!Number.isInteger(Number(routing.response_timeout_seconds)) || routing.response_timeout_seconds < 1 || routing.response_timeout_seconds > 310) errors.health = "Response timeout must be 1–310 seconds.";
  return errors;
}
export function bindingPayload(bindings) {
  return bindings.map(({ id, label, target_mode, target_url, connection_data_id, enabled, priority, weight, pass_host, health_path }) => ({ id, label: (label || "").trim(), target_mode, target_url: target_mode === "manual" ? target_url.trim() : null, connection_data_id: target_mode === "connection" ? connection_data_id : null, enabled, priority: Number(priority), weight: Number(weight), pass_host: pass_host ?? null, health_path: health_path || null }));
}
