import { useCallback } from "react";
import { useRouter } from "next/router";

// URL is the source of truth: no effect writes a stale default over a deep
// link, and browser history restores the selected tab without synchronization.
export default function useUrlTab(key, values, fallback, { context = {}, enabled = true } = {}) {
  const router = useRouter();
  const raw = router.query[key];
  const selected = enabled && typeof raw === "string" && values.includes(raw) ? raw : fallback;
  const contextKey = JSON.stringify(context);
  const valuesKey = values.join("|");
  const select = useCallback(value => {
    if (!enabled || !valuesKey.split("|").includes(value)) return;
    const query = { ...router.query, ...JSON.parse(contextKey), [key]: value };
    if (router.query[key] === value && Object.entries(JSON.parse(contextKey)).every(([name, entry]) => router.query[name] === entry)) return;
    router.push({ pathname: router.pathname, query }, undefined, { shallow: true, scroll: false });
  }, [router, key, enabled, contextKey, valuesKey]);
  return [selected, select];
}
