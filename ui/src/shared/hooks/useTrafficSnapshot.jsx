import useTrafficPage from "./useTrafficPage";

// Charts request only their visible port IDs and merge incremental samples.
// Empty selection means no request, never an implicit full-workspace snapshot.
export default function useTrafficSnapshot({ ids = [], enabled = true } = {}) {
  const selected = [...new Set(ids.filter(Boolean))].sort().join(",");
  return useTrafficPage({ ids: selected, page_size: 100, seconds: 300, options: true }, { enabled: enabled && !!selected });
}
