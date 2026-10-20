const id = value => value.toString(16).padStart(24, "0");
const stamp = () => new Date().toISOString();

export function makeDemoData() {
  const groups = ["Production", "Development", "Personal"].map((name, i) => ({ _id: id(100 + i), name, created_at: stamp() }));
  const machines = Array.from({ length: 36 }, (_, i) => {
    const environment = i % 3, online = i % 7 !== 0, enabled = i % 13 !== 0;
    const name = `${["atlas", "orion", "luna", "nova", "edge", "worker"][i % 6]}-${["prod", "dev", "home"][environment]}-${String(i + 1).padStart(2, "0")}`;
    return { _id: id(1000 + i), name, hostname: `${name}.local`, group_ids: [groups[environment]._id], enabled, is_active: online && enabled,
      connection_status: !enabled ? "disabled" : online ? "online" : "offline", local_ip: `192.168.${environment + 1}.${20 + i}`, public_ip: `203.0.113.${i + 1}`,
      client_version: "1.2.0", latest_client_version: "1.2.0", token: "demo-token-not-valid-for-real-clients", created_at: stamp(), updated_at: stamp(), last_seen_at: new Date(Date.now() - (online ? 2000 : 3600000 * (i + 1))).toISOString() };
  });
  const connections = machines.flatMap((m, i) => [0, 1].map(index => ({ _id: id(2000 + i * 2 + index), machine_id: m._id, machine_name: m.name, machine_hostname: m.hostname,
    machine_enabled: m.enabled, machine_is_active: m.is_active, machine_connection_status: m.connection_status,
    service_name: index ? ["Web app", "API", "Dashboard"][i % 3] : "SSH", service_description: index ? "Internal web service" : "Secure shell access", internal_ip: "127.0.0.1", internal_port: index ? 8080 : 22,
    external_port: 20000 + i * 2 + index, enabled: m.enabled, created_at: stamp(), updated_at: stamp(), firewall: { is_public: true, allowed_ips: [] } })));
  const proxies = connections.filter(c => c.internal_port === 8080).map((c, i) => ({ _id: id(3000 + i), name: `${machines[i].name}.preview.invalid`, hosts: [`${machines[i].name}.preview.invalid`], group: groups[i % 3].name,
    description: c.service_description, target_mode: "connection", target_url: `http://127.0.0.1:${c.external_port}`, entry_points: ["web"], enabled: c.enabled,
    connection: { ...c, data_id: c._id }, created_at: stamp(), updated_at: stamp() }));
  return { version: 1, user: { name: "Demo Workspace", username: "demo@porthub.local", email: "demo@porthub.local", role: "admin", has_password: true, created_at: stamp(), preferences: { nav_collapsed: false } }, machines, connections, proxies, groups, nextId: 10000 };
}

function traffic(connection, index) {
  const now = Math.floor(Date.now() / 1000);
  return { connection, traffic: Array.from({ length: 120 }, (_, i) => {
    const timestamp = now - 119 + i;
    const signal = Math.max(0.05, 0.55 + Math.sin((timestamp + index * 17) / 7) * 0.3 + Math.sin(timestamp / 2) * 0.12);
    const scale = connection.enabled && connection.machine_is_active ? (index % 9 + 1) * 24000 : 0;
    const blocked = scale && index % 5 === 0 ? 64 : 0;
    return { timestamp, interval_seconds: 1, in_bytes: Math.round(signal * scale), out_bytes: Math.round(signal * scale * 0.4), drop_bytes: blocked, incoming_ips: scale ? ["192.0.2.25"] : [], outgoing_ips: scale ? ["198.51.100.8"] : [], blocked_ips: blocked ? ["192.0.2.99"] : [] };
  }) };
}

export function handleDemoRequest(state, method, rawPath, payload = {}) {
  const path = rawPath.split("?")[0].replace(/^.*\/api/, "");
  const read = method === "get";
  const body = typeof payload === "string" ? JSON.parse(payload) : payload || {};
  if (path === "/auth/me") return state.user;
  if (path === "/traffic-routes/activity") return state.proxyActivity || {available:true,tracking_since:new Date(Date.now()-86400000).toISOString(),data:state.proxies.map((proxy,index)=>({route_id:proxy._id,requests:(index+1)*27,last_requested_at:new Date(Date.now()-index*60000).toISOString(),last_host:proxy.hosts[0]}))};
  if (path === "/auth/settings") return { signup_disabled: true, web_proxy_domain_suffix: "preview.invalid", port_hub_service_domain: "preview.invalid" };
  if (path === "/auth/preferences") { state.user.preferences = { ...state.user.preferences, ...body }; return state.user.preferences; }
  if (path === "/auth/account") { Object.assign(state.user, { name: body.name || state.user.name, email: body.email || state.user.email }); if(body.profile_picture)state.user.profile_picture=body.profile_picture; if(body.remove_profile_picture)delete state.user.profile_picture; return state.user; }
  if (path === "/auth/sessions") return { data: [{ id: "demo-session", device_name: "Current browser · Demo", current: true, ip: "127.0.0.1", created_at: stamp(), last_accessed_at: stamp() }] };
  if (path === "/auth/telegram") {
    state.telegram ||= { has_bot_token: false, bot_token_masked: "", chat_ids: [], alerts_enabled: false, instant_alerts_enabled: true, digest_enabled: false, digest_interval_hours: 6 };
    if (!read) {
      const {bot_token,...settings} = body;
      Object.assign(state.telegram, settings);
      if(bot_token)Object.assign(state.telegram,{has_bot_token:true,bot_token_masked:`••••••${String(bot_token).slice(-4)}`});
    }
    return state.telegram;
  }
  if (path.startsWith("/auth/")) return { msg: "success" };
  if (path === "/admin/overview") return { data: state.platformAccounts || [{ user: { ...state.user, id: "demo-user" }, machines: state.machines.map(m => ({ ...m, num_ports: state.connections.filter(c => c.machine_id === m._id).length, ports: state.connections.filter(c => c.machine_id === m._id) })) }] };
  if (path === "/connections/firewall/traffic/snapshot") return { data: state.connections.filter(c => !body.data_ids?.length || body.data_ids.includes(c._id)).map(traffic) };
  if (path.includes("/recent-ip-hits/")) return { data: [{ ip: "192.0.2.25", hits: 24, last_seen: stamp() }] };
  if (path.includes("/status-history")) return { data: [{ status: "online", changed_at: new Date(Date.now() - 3600000).toISOString() }], current_status: "online" };
  if (path.includes("/availability")) return { available: true, message: "Available in demo" };
  if (path === "/connections/random") return { port: 30000 + state.nextId++ % 10000 };
  if (path.includes("/command/")) {
    const machine = state.machines.find(machine => machine._id === path.split("/command/")[1]);
    return { data: { command: "# Demo workspace — no client installation is needed.", client_setup: {
      defaults: { public_base_url: "https://preview.invalid", rathole_server_address: "preview.invalid:2334", service_domain: "preview.invalid" },
      overrides: { public_base_url: machine?.client_setup_public_base_url || "", rathole_server_address: machine?.client_setup_rathole_server_address || "", service_domain: machine?.client_setup_service_domain || "" },
    } } };
  }
  if (path.includes("/firewall/policy")) {
    const connection = state.connections.find(c => c._id === (body.data_id || path.split("/").pop()));
    if (connection && !read) connection.firewall = { is_public: body.is_public ?? true, allowed_ips: body.allowed_ips || [] };
    return { data: { connection, firewall: { ...(connection?.firewall || {}), applied: true } } };
  }
  if (path.includes("/machines/groups/")) {
    const m = state.machines.find(m => m._id === body.machine_id);
    if (m) m.group_ids = path.endsWith("/add") ? [...new Set([...(m.group_ids || []), body.group_id])] : (m.group_ids || []).filter(g => g !== body.group_id);
    return { data: m, msg: "success" };
  }
  const key = path.startsWith("/machines/") ? "machines" : path.startsWith("/connections/") ? "connections" : path.startsWith("/traffic-routes/") ? "proxies" : path.startsWith("/groups/") ? "groups" : null;
  if (!key) throw new Error("This action is not available in the demo workspace.");
  if (path.endsWith("/list")) return { data: state[key] };
  if (read) return { data: [] };
  const existing = state[key].find(item => item._id === body.data_id);
  if (path.endsWith("/delete")) {
    state[key] = state[key].filter(item => item._id !== body.data_id);
    if (key === "machines") { state.connections = state.connections.filter(c => c.machine_id !== body.data_id); state.proxies = state.proxies.filter(p => p.connection?.machine_id !== body.data_id); }
    if (key === "groups") state.machines.forEach(machine => { machine.group_ids = (machine.group_ids || []).filter(groupId => groupId !== body.data_id); });
    return { data: existing, msg: "success" };
  }
  const item = { ...existing, ...body, _id: existing?._id || id(state.nextId++), updated_at: stamp(), created_at: existing?.created_at || stamp() };
  delete item.data_id;
  if (key === "proxies") {
    const c = state.connections.find(c => c._id === (body.connectionDataId || body.connection_data_id));
    Object.assign(item, { group: body.group || "", target_mode: body.targetMode || body.target_mode || "manual", target_url: body.targetUrl || body.target_url || "", entry_points: body.entryPoints || ["web"], connection: c ? { ...c, data_id: c._id } : null });
  }
  if (key === "machines") Object.assign(item, { hostname: item.hostname || "", enabled: item.enabled ?? true, is_active: item.is_active ?? false, connection_status: item.enabled === false ? "disabled" : item.connection_status || "offline", token: "demo-token-not-valid-for-real-clients" });
  if (key === "connections") {
    const m = state.machines.find(m => m._id === item.machine_id);
    Object.assign(item, { machine_name: m?.name, machine_hostname: m?.hostname, internal_ip: item.internalIp || item.internal_ip || "127.0.0.1" });
  }
  state[key] = [...state[key].filter(current => current._id !== item._id), item];
  return { data: item, msg: "success" };
}
