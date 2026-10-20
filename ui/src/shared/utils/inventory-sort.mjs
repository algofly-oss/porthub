export const INVENTORY_SORT_OPTIONS = [
  { value: "name", label: "Name A–Z" },
  { value: "name-desc", label: "Name Z–A" },
  { value: "newest", label: "Newest Registered" },
  { value: "oldest", label: "Oldest Registered" },
  { value: "traffic", label: "Total Traffic · 30s" },
  { value: "incoming", label: "Incoming Traffic · 30s" },
  { value: "outgoing", label: "Outgoing Traffic · 30s" },
];

export const isTrafficSort = value => ["traffic", "incoming", "outgoing"].includes(value);

// Shared by machine and proxy inventories. Missing dates/traffic have a stable
// zero value; ID/name tie-breakers prevent rows jumping around on equal values.
export function compareInventoryEntries(a, b, sort) {
  let difference = 0;
  if (sort === "newest" || sort === "oldest") difference = ((Date.parse(a.createdAt) || 0) - (Date.parse(b.createdAt) || 0)) * (sort === "newest" ? -1 : 1);
  if (isTrafficSort(sort)) {
    const key = { traffic: "volume", incoming: "incomingVolume", outgoing: "outgoingVolume" }[sort];
    difference = (b.traffic?.[key] || 0) - (a.traffic?.[key] || 0);
  }
  return difference || String(a.name || "").localeCompare(String(b.name || ""), undefined, { numeric: true, sensitivity: "base" }) * (sort === "name-desc" ? -1 : 1)
    || String(a.id || "").localeCompare(String(b.id || ""));
}
