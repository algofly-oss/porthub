const normalize = value => String(value ?? "").normalize("NFKD").replace(/[\u0300-\u036f]/g, "").toLowerCase();

// A single-edit match catches missing, extra, substituted and transposed letters.
function oneEditAway(left, right) {
  if (Math.abs(left.length - right.length) > 1) return false;
  if (left.length > right.length) return oneEditAway(right, left);
  let i = 0, j = 0, edits = 0;
  while (i < left.length && j < right.length) {
    if (left[i] === right[j]) { i++; j++; continue; }
    if (++edits > 1) return false;
    if (left.length === right.length) {
      if (left[i] === right[j + 1] && left[i + 1] === right[j]) { i += 2; j += 2; }
      else { i++; j++; }
    } else j++;
  }
  return edits + (right.length - j) <= 1;
}

export function searchScore(query, values) {
  const terms = normalize(query).trim().split(/\s+/).filter(Boolean);
  if (!terms.length) return 0;
  const fields = values.flat(Infinity).map(normalize).filter(Boolean);
  let total = 0;
  for (const term of terms) {
    let best = Infinity;
    for (const field of fields) {
      if (field === term) best = Math.min(best, 0);
      else if (field.startsWith(term)) best = Math.min(best, 1);
      else if (field.includes(term)) best = Math.min(best, 2);
      // Typo tolerance is useful for names, but a nearby numeric port/IP is a
      // different target. Numeric queries retain exact/prefix/substring search.
      else if (term.length >= 4 && /\p{L}/u.test(term) && field.split(/[^\p{L}\p{N}]+/u).some(word => oneEditAway(term, word))) best = Math.min(best, 3);
    }
    if (!Number.isFinite(best)) return Infinity;
    total += best;
  }
  return total;
}

export function proxySearchValues(proxy) {
  return [proxy.name, proxy.description, proxy.group, proxy.hosts || [], proxy.target_url,
    ...Object.values(proxy.connection || {})];
}

export function selectProxies(proxies, { query = "", status = "all", group = "all", machine = "all", sort = "name" } = {}) {
  return proxies.map(proxy => ({ proxy, score: searchScore(query, proxySearchValues(proxy)) }))
    .filter(({ proxy, score }) => Number.isFinite(score)
      && (status === "all" || (status === "enabled" ? proxy.enabled : !proxy.enabled))
      && (group === "all" || (proxy.group || "") === group)
      && (machine === "all" || (proxy.connection?.machine_id || "manual") === machine))
    .sort((a, b) => {
      if (query.trim() && a.score !== b.score) return a.score - b.score;
      if (sort === "updated") return (Date.parse(b.proxy.updated_at) || 0) - (Date.parse(a.proxy.updated_at) || 0);
      if (sort === "status" && a.proxy.enabled !== b.proxy.enabled) return Number(b.proxy.enabled) - Number(a.proxy.enabled);
      return (a.proxy.hosts?.[0] || a.proxy.name || "").localeCompare(b.proxy.hosts?.[0] || b.proxy.name || "", undefined, { numeric: true });
    }).map(({ proxy }) => proxy);
}
