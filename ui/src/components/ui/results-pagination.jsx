import { IconChevronLeft, IconChevronRight } from "@tabler/icons-react";
import Pagination from "./pagination";
import SearchSelect from "./search-select";
import { Button } from "./button";

// One attached footer for every inventory. Phones keep navigation on one row.
export default function ResultsPagination({ count, noun, page, pages, pageSize, onPage, onPageSize, sizes = [10, 25, 50] }) {
  const current = Math.max(1, Math.min(page, pages));
  const start = count ? (current - 1) * pageSize + 1 : 0;
  const end = Math.min(current * pageSize, count);
  return <footer aria-label={`${noun} pagination`} className="flex shrink-0 items-center justify-between gap-2 border-t border-border px-2 py-1 sm:gap-3 sm:px-3 sm:py-2">
    <p className="hidden text-xs text-muted-foreground sm:block">{start}–{end} of {count.toLocaleString()} {noun.toLowerCase()}</p>
    {onPageSize ? <SearchSelect className="w-28 shrink-0 sm:ml-auto sm:w-32" label={`${noun} per page`} value={pageSize} onChange={value => onPageSize(Number(value))} options={sizes.map(value => ({ value, label: `${value} / page` }))} /> : <span className="text-xs text-muted-foreground sm:hidden">{count.toLocaleString()} {noun.toLowerCase()}</span>}
    {pages > 1 ? <div className="flex items-center gap-1 sm:hidden">
      <Button variant="ghost" className="h-11 w-11 p-0" aria-label="Previous page" disabled={current <= 1} onClick={() => onPage(current - 1)}><IconChevronLeft size={18} /></Button>
      <span aria-live="polite" aria-label={`Page ${current} of ${pages}`} className="min-w-[42px] text-center text-xs tabular-nums text-muted-foreground">{current} / {pages}</span>
      <Button variant="ghost" className="h-11 w-11 p-0" aria-label="Next page" disabled={current >= pages} onClick={() => onPage(current + 1)}><IconChevronRight size={18} /></Button>
    </div> : <span className="text-xs text-muted-foreground sm:hidden">{onPageSize ? `${count.toLocaleString()} ${noun.toLowerCase()}` : "1 page"}</span>}
    {pages > 1 && <div className="hidden sm:block"><Pagination value={current} onChange={onPage} total={pages} size="sm" siblings={0} /></div>}
  </footer>;
}
