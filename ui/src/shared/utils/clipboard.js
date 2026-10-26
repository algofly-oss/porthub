// Clipboard API on HTTPS, with a user-initiated fallback for local HTTP gateways.
export async function copyText(value) {
  if (navigator.clipboard?.writeText) {
    try { await navigator.clipboard.writeText(value); return; } catch { /* local fallback */ }
  }
  const previous = document.activeElement;
  const field = document.createElement("textarea");
  field.value = value;
  field.setAttribute("readonly", "");
  field.style.cssText = "position:fixed;left:-9999px;top:0;opacity:0";
  document.body.appendChild(field);
  try { field.select(); if (!document.execCommand("copy")) throw new Error("Copy unavailable"); }
  finally { field.remove(); previous?.focus?.({preventScroll:true}); }
}
