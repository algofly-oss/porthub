import useInventoryPage from "./useInventoryPage";
import useBackgroundRefresh from "./useBackgroundRefresh";

export default function useProxyActivity({ ids = [], recent, enabled = true } = {}) {
  const selected = [...new Set(ids.filter(Boolean))].sort().join(",");
  const inventory = useInventoryPage("proxy-activity", recent ? {recent} : {ids:selected}, {enabled:enabled && (!!recent || !!selected),ttl:15000});
  useBackgroundRefresh(inventory.refresh, { enabled: enabled && (!!recent || !!selected), refreshKey: recent || selected, interval: 15000 });
  return { available:false, data:[], routes:[], ...inventory.data, loading:inventory.loading, error:inventory.error };
}
