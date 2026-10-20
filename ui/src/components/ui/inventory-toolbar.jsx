import { useState } from "react";
import { Popover } from "@mantine/core";
import { useMediaQuery } from "@mantine/hooks";
import { IconAdjustmentsHorizontal } from "@tabler/icons-react";
import { Button } from "./button";

// Two deliberate rows on phones: search/create, then status/filters. Advanced
// controls live in one searchable filter panel rather than wrapping at random.
export default function InventoryToolbar({ label, search, status, filters = [], secondaryActions, primaryActions, filtered = false }) {
  const mobile = useMediaQuery("(max-width: 767px)");
  const [opened, setOpened] = useState(false);
  const panelFilters = mobile ? filters : filters.filter(filter => filter.advanced);
  return <div aria-label={label} className="mb-3 grid shrink-0 grid-cols-[minmax(0,1fr)_auto] items-center gap-2 md:flex md:flex-wrap">
    <div className="col-start-1 row-start-1 min-w-0 [&_.search-field]:h-11 md:flex-1 md:basis-48 md:[&_.search-field]:h-10">{search}</div>
    <div className="col-span-2 col-start-1 row-start-2 min-w-0 pr-[108px] [&>div]:h-11 [&>div]:w-full [&>div]:justify-between [&_button]:h-9 [&_button]:min-w-0 [&_button]:flex-auto [&_button]:shrink [&_button]:px-2 md:pr-0 md:[&>div]:h-10 md:[&>div]:w-auto md:[&_button]:h-8">{status}</div>
    {!mobile && filters.filter(filter => !filter.advanced).map(filter => <div key={filter.label} className="w-40 shrink-0">{filter.control}</div>)}
    {(mobile || panelFilters.length > 0) && <Popover opened={opened} onChange={setOpened} position="bottom-end" withinPortal zIndex={400} width={mobile ? "min(340px, calc(100vw - 24px))" : 300} shadow="sm">
      <Popover.Target><Button type="button" variant="secondary" aria-label="Filters" aria-expanded={opened} onClick={() => setOpened(value => !value)} className="col-start-2 row-start-2 h-11 justify-self-end gap-1.5 px-2.5 md:h-10 md:gap-2 md:px-3"><IconAdjustmentsHorizontal size={17} /><span>Filters</span>{filtered && <span aria-label="Filters applied" className="h-1.5 w-1.5 rounded-full bg-primary" />}</Button></Popover.Target>
      <Popover.Dropdown className="!rounded-xl !border-border !bg-dialog !p-4 !text-foreground">
        <div className="max-h-[65dvh] space-y-4 overflow-y-auto overscroll-contain">
          {panelFilters.map(filter => <div key={filter.label}><p className="mb-2 text-xs font-medium text-muted-foreground">{filter.label}</p>{filter.control}</div>)}
          {mobile && secondaryActions && <div className="border-t border-border pt-3 [&_button]:w-full">{secondaryActions}</div>}
        </div>
      </Popover.Dropdown>
    </Popover>}
    {!mobile && secondaryActions}
    <div className="col-start-2 row-start-1 flex shrink-0 items-center gap-2 [&_button]:h-11 md:ml-auto md:[&_button]:h-10">{primaryActions}</div>
  </div>;
}
