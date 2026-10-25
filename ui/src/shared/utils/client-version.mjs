const RELEASE_VERSION = /^v?\d+\.\d+\.\d+$/;

export function formatClientVersion(value, fallback = "Unknown") {
  const version = typeof value === "string" ? value.trim() : "";
  if (!version) return fallback;
  if (!RELEASE_VERSION.test(version)) return "Legacy build";
  return version.startsWith("v") ? version : `v${version}`;
}
