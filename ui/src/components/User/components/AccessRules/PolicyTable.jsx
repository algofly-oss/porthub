import { IconArrowRight, IconArrowsLeftRight, IconTrash } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from "@/components/ui/table";
import { key } from "./shared";

// One compact row per policy. A row opens the editor; the switch pauses or
// resumes the whole policy without leaving the list.
const entityText = (selectors, names) =>
  selectors.map((s) => s.kind === "all" ? "All machines" : `${s.kind === "group" ? "#" : s.kind === "user" ? "@" : ""}${names.get(key(s)) || "Deleted entity"}`).join(", ");

export const protocolText = (rule) =>
  rule.protocol === "any" ? (rule.ports ? `Any · ${rule.ports}` : "Any traffic")
    : rule.protocol === "icmp" ? "ICMP"
      : `${rule.protocol.toUpperCase()} · ${rule.ports || "all ports"}`;

function Flow({ rule, names }) {
  const Arrow = rule.bidirectional ? IconArrowsLeftRight : IconArrowRight;
  const source = entityText(rule.sources, names), destination = entityText(rule.destinations, names);
  return (
    <p className={`flex min-w-0 items-center gap-2 text-[13px] ${rule.enabled ? "" : "opacity-55"}`} title={`${source} ${rule.bidirectional ? "⇄" : "→"} ${destination}`}>
      <span className="min-w-0 truncate">{source}</span>
      <Arrow size={15} className="shrink-0 text-primary" aria-label={rule.bidirectional ? "both directions" : "to"} />
      <span className="min-w-0 truncate">{destination}</span>
    </p>
  );
}

function Rules({ book, names, limit = 2 }) {
  return (
    <div className="min-w-0 space-y-1">
      {book.rules.slice(0, limit).map((rule) => <Flow key={rule.id} rule={rule} names={names} />)}
      {(book.rules_count ?? book.rules.length) > limit && <p className="text-xs text-muted-foreground">+{(book.rules_count ?? book.rules.length) - limit} more rules</p>}
      {!book.rules.length && <p className="text-xs text-muted-foreground">No rules yet</p>}
    </div>
  );
}

function Protocols({ book }) {
  const labels = [...new Set(book.rules.map(protocolText))];
  return (
    <p className="truncate font-mono text-xs text-muted-foreground" title={labels.join(", ")}>
      {labels.slice(0, 2).join(", ")}{labels.length > 2 ? ` +${labels.length - 2}` : ""}
    </p>
  );
}

function StatusSwitch({ book, manage, busy, onToggle }) {
  const label = book.enabled ? "Enabled" : "Paused";
  if (!manage) return <span className={`text-xs ${book.enabled ? "text-emerald-700 dark:text-emerald-400" : "text-muted-foreground"}`}>{label}</span>;
  return (
    <button
      type="button" role="switch" aria-checked={book.enabled} disabled={busy}
      aria-label={`${book.enabled ? "Pause" : "Resume"} policy ${book.name}`}
      onClick={() => onToggle(book)}
      className="group inline-flex items-center gap-2 rounded-md px-1 py-1 text-xs disabled:opacity-60"
    >
      <span className={`relative h-[18px] w-8 rounded-full transition-colors ${book.enabled ? "bg-emerald-600" : "bg-input dark:bg-control group-hover:bg-accent"}`}>
        <span className={`absolute top-[2px] h-[14px] w-[14px] rounded-full bg-white shadow transition-[left] ${book.enabled ? "left-[16px]" : "left-[2px]"}`} />
      </span>
      <span className={book.enabled ? "text-emerald-700 dark:text-emerald-400" : "text-muted-foreground"}>{label}</span>
    </button>
  );
}

export default function PolicyTable({ books, groups, names, manage, busy, onOpen, onToggle, onDelete }) {
  const groupName = (book) => book.group_name || groups.find((g) => g._id === book.group_id)?.name || "Deleted group · inactive";
  const interaction = (book) => ({
    tabIndex: 0,
    "aria-label": `${manage ? "Edit" : "View"} policy ${book.name}`,
    onClick: (event) => { if (!event.target.closest("a,button,input")) onOpen(book); },
    onKeyDown: (event) => {
      if (event.target === event.currentTarget && ["Enter", " "].includes(event.key)) { event.preventDefault(); onOpen(book); }
    },
  });
  const remove = (book) => manage && (
    <Button variant="ghost" size="icon" aria-label={`Delete ${book.name}`} onClick={() => onDelete(book)}>
      <IconTrash size={16} />
    </Button>
  );
  return (
    <>
      <div className="hidden md:block">
        <Table aria-label="Private policies">
          <TableHeader>
            <TableRow>
              <TableHead className="w-[28%]">Policy</TableHead>
              <TableHead>Who can connect</TableHead>
              <TableHead className="w-[17%]">Traffic</TableHead>
              <TableHead className="w-32">Status</TableHead>
              {manage && <TableHead className="w-14"><span className="sr-only">Actions</span></TableHead>}
            </TableRow>
          </TableHeader>
          <TableBody>
            {books.map((book) => (
              <TableRow key={book._id} {...interaction(book)} className={`cursor-pointer focus-visible:bg-accent/40 ${book.enabled ? "" : "text-muted-foreground"}`}>
                <TableCell className="py-2.5">
                  <p className="truncate font-medium text-foreground">{book.name}</p>
                  <p className="mt-0.5 truncate text-xs text-muted-foreground">{groupName(book)}{(book.rules_count ?? book.rules.length) > 1 ? ` · ${book.rules_count ?? book.rules.length} rules` : ""}</p>
                </TableCell>
                <TableCell className="py-2.5"><Rules book={book} names={names} /></TableCell>
                <TableCell className="py-2.5"><Protocols book={book} /></TableCell>
                <TableCell className="py-2.5"><StatusSwitch book={book} manage={manage} busy={busy} onToggle={onToggle} /></TableCell>
                {manage && <TableCell className="py-1.5 text-right">{remove(book)}</TableCell>}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <div className="md:hidden">
        {books.map((book) => (
          <div key={book._id} {...interaction(book)} className="flex cursor-pointer items-center gap-2 border-b border-border/60 px-3 py-2.5 transition-colors last:border-0 hover:bg-accent/40 focus-visible:bg-accent/40">
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-medium">{book.name}</p>
              <div className="mt-1 flex min-w-0 items-center gap-2 text-muted-foreground">
                <div className="min-w-0 flex-1"><Rules book={book} names={names} limit={1} /></div>
              </div>
              <div className="mt-0.5"><Protocols book={book} /></div>
            </div>
            <StatusSwitch book={book} manage={manage} busy={busy} onToggle={onToggle} />
            {remove(book)}
          </div>
        ))}
      </div>
    </>
  );
}
