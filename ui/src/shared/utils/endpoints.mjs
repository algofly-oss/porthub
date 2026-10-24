export function formatEndpoint(host, port) {
  const address = String(host || "0.0.0.0").trim();
  const normalized = address.includes(":") && !address.startsWith("[") ? `[${address}]` : address;
  return `${normalized}:${port === undefined || port === null || port === "" ? "—" : port}`;
}

export function externalEndpoint(connection = {}) {
  const port = connection.external_port ?? connection.externalPort;
  return port === undefined || port === null || port === "" ? "—" : String(port);
}

export function internalEndpoint(connection = {}) {
  return formatEndpoint(connection.internal_ip || connection.internalIp || "0.0.0.0", connection.internal_port ?? connection.internalPort);
}
