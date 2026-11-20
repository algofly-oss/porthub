export function sessionRows(response) {
  const rows = response?.sessions;
  if (!Array.isArray(rows) || rows.some(row =>
    !row || typeof row.id !== "string" || !row.id || typeof row.name !== "string" || typeof row.read_only !== "boolean"
  )) throw new Error("Invalid shell session list");
  return rows;
}
