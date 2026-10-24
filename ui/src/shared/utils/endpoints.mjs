export function formatEndpoint(host, port) {
  const address = String(host || "0.0.0.0").trim();
  const normalized = address.includes(":") && !address.startsWith("[") ? `[${address}]` : address;
  return `${normalized}:${port === undefined || port === null || port === "" ? "—" : port}`;
}

export function externalEndpoint(connection = {}) {
  return formatEndpoint(connection.external_bind_ip || connection.externalBindIp || "0.0.0.0", connection.external_port ?? connection.externalPort);
}

export function internalEndpoint(connection = {}) {
  return formatEndpoint(connection.internal_ip || connection.internalIp || "0.0.0.0", connection.internal_port ?? connection.internalPort);
}
