function project(state, row) {
  const provider = state.machines.find(m => m._id === row.provider);
  const name = state.access?.hostnames?.[row.id] || row.name;
  return {
    id: row.id, peer_id: `demo-user:${row.id}`, name, target_ip: row.target_ip, private_ip: row.ip,
    hostname: `${name}.${state.access?.network?.dns_suffix || "phub"}`,
    kind: "virtual_host",
    via: { id: row.provider, name: provider?.name, online: provider?.connection_status === "online", supports_virtual_hosts: provider?.supports_virtual_hosts ?? true },
  };
}

export function demoVirtualMachines(state) {
  return (state.virtualHosts || []).map(row => {
    const host = project(state, row);
    return { ...host, name: row.name, _id: host.id, default_private_domain: host.hostname, private_ips: [host.private_ip], local_ip: host.target_ip, group_ids: [], enabled: true };
  });
}

export function demoVirtualHosts(state, method, provider, id, body, makeId) {
  const agent = state.machines.find(m => m._id === provider);
  if (!agent) throw Error("Serving machine not found");
  const hosts = state.virtualHosts ||= [];
  if (method === "get") return { provider_online: agent.connection_status === "online", provider_supported: agent.supports_virtual_hosts ?? true, virtual_hosts: hosts.filter(m => m.provider === provider).map(m => project(state, m)) };
  if (method === "delete") {
    const index = hosts.findIndex(m => m.provider === provider && m.id === id);
    if (index < 0) throw Error("Virtual host not found");
    hosts.splice(index, 1);
    if (state.access?.hostnames) delete state.access.hostnames[id];
    return {};
  }
  if (method !== "post" || id) throw Error("Unsupported virtual host action");
  const name = String(body.name || "").trim().toLowerCase();
  if (!/^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/.test(name)) throw Error("Enter a DNS label with up to 48 letters, digits or hyphens");
  const same = hosts.find(m => m.provider === provider && project(state, m).name === name);
  if (same && same.target_ip === body.target_ip) return { virtual_host: project(state, same) };
  if (hosts.some(m => m.name === name || project(state, m).name === name) || state.machines.some(m => m.name.toLowerCase() === name)) throw Error("Private name already in use");
  const target = String(body.target_ip || ""), parts = target.split(".").map(Number);
  if (parts.length !== 4 || parts.join(".") !== target || parts.some(v => v < 0 || v > 255 || !Number.isInteger(v)) ||
    !(parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168))) throw Error("Enter a private LAN IPv4 address");
  let slot = 100;
  while (slot < 255 && hosts.some(m => m.ip === `10.203.0.${slot}`)) slot++;
  if (slot === 255) throw Error("Demo address pool is full");
  const row = { id: makeId(state.nextId++), name, target_ip: target, ip: `10.203.0.${slot}`, provider };
  hosts.push(row);
  return { virtual_host: project(state, row) };
}
