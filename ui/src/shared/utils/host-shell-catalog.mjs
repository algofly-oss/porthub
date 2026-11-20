export function sessionRows(response) {
  const rows = response?.sessions;
  if (!Array.isArray(rows) || rows.some(row =>
    !row || typeof row.id !== "string" || !/^[a-f0-9]{32}$/.test(row.id) ||
    typeof row.name !== "string" || !row.name || row.name.length > 64 || typeof row.read_only !== "boolean"
  )) throw new Error("Invalid shell session list");
  return rows;
}
