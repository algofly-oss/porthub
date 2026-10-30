import { useEffect } from "react";
import useInventoryPage from "./useInventoryPage";
import useBackgroundRefresh from "./useBackgroundRefresh";
import { useWorkspaceState } from "@/shared/contexts/workspaceCache";

// Mount once per signed-in workspace. Counts are independent of loaded pages.
export function WorkspaceInventorySummary({ onStatsChange }) {
  const inventory = useInventoryPage("summary", {}, { ttl: 15000 });
  const [, setSummary] = useWorkspaceState("inventory.summary", null);
  useBackgroundRefresh(inventory.refresh, { preload: false, interval: 15000 });
  useEffect(() => {
    const summary = inventory.data?.data;
    if (!summary) return;
    setSummary(summary);
    const counts = summary.machines;
    onStatsChange?.({
      registered: counts.total,
      online: counts.online + counts.auth_required,
      offline: counts.offline + counts.disabled,
    });
  }, [inventory.data, onStatsChange, setSummary]);
  return null;
}
