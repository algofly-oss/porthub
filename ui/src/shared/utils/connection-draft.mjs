const readConnectionValue = (connection, snakeKey, camelKey, fallback = "") => {
  const snakeValue = connection[snakeKey];
  if (snakeValue !== undefined && snakeValue !== null && snakeValue !== "") {
    return snakeValue;
  }

  const camelValue = connection[camelKey];
  if (camelValue !== undefined && camelValue !== null && camelValue !== "") {
    return camelValue;
  }

  return fallback;
};

export const mapConnectionToForwardingConfig = (connection) => {
  const autoRefreshIntervalMinutes =
    connection.autoRefreshIntervalMinutes ??
    connection.auto_refresh_interval_minutes;

  return {
    dataId: connection._id || connection.dataId,
    serviceName: connection.service_name || connection.serviceName || "",
    serviceDescription:
      connection.service_description || connection.serviceDescription || "",
    internalIp: connection.internal_ip || connection.internalIp || "0.0.0.0",
    internalPort: readConnectionValue(connection, "internal_port", "internalPort"),
    externalPort: readConnectionValue(connection, "external_port", "externalPort"),
    externalBindIp: connection.external_bind_ip || connection.externalBindIp || "0.0.0.0",
    temporary: connection.temporary === true,
    publicAccess: connection.public_access || connection.publicAccess || { mode: "off" },
    managedBy: connection.managed_by || connection.managedBy || "",
    enabled: connection.enabled ?? true,
    autoRefreshEnabled:
      connection.autoRefreshEnabled ?? connection.auto_refresh_enabled ?? false,
    autoRefreshIntervalMinutes:
      autoRefreshIntervalMinutes === undefined ||
      autoRefreshIntervalMinutes === null ||
      autoRefreshIntervalMinutes === ""
        ? 60
        : autoRefreshIntervalMinutes,
    autoRefreshedAt:
      connection.autoRefreshedAt || connection.auto_refreshed_at || null,
    autoRefreshNextAt:
      connection.autoRefreshNextAt || connection.auto_refresh_next_at || null,
    firewall: {
      isPublic:
        connection.firewall?.isPublic ?? connection.firewall?.is_public ?? true,
      allowedIps: Array.isArray(connection.firewall?.allowedIps)
        ? connection.firewall.allowedIps
        : Array.isArray(connection.firewall?.allowed_ips)
          ? connection.firewall.allowed_ips
          : [],
    },
  };
};
