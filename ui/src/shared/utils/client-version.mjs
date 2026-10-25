const RELEASE_VERSION = /^v?\d+\.\d+\.\d+$/;

export function formatClientVersion(value, fallback = "Unknown") {
  const version = typeof value === "string" ? value.trim() : "";
  if (!version) return fallback;
  if (!RELEASE_VERSION.test(version)) return "Legacy build";
  return version.startsWith("v") ? version : `v${version}`;
}

export function preserveNewerClientVersion(current, incoming) {
  if (!current?.lastSeenAt || !incoming?.lastSeenAt) return incoming;
  const currentSeen = Date.parse(current.lastSeenAt);
  const incomingSeen = Date.parse(incoming.lastSeenAt);
  if (!Number.isFinite(currentSeen) || !Number.isFinite(incomingSeen) || incomingSeen >= currentSeen) {
    return incoming;
  }
  return {
    ...incoming,
    clientVersion: current.clientVersion,
    latestClientVersion: current.latestClientVersion,
    clientUpdateAvailable: current.clientUpdateAvailable,
    clientUpdateRequested: current.clientUpdateRequested,
    clientUpdateTargetVersion: current.clientUpdateTargetVersion,
    lastSeenAt: current.lastSeenAt,
    lastSeen: current.lastSeen,
  };
}
