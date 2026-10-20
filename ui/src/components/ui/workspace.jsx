import { IconSearch, IconX } from "@tabler/icons-react";
import { Input } from "./input";

export function PageHeader({ eyebrow, title, description, actions }) {
  return (
    <header className="page-heading">
      <div className="min-w-0">
        <h1>{title}</h1>
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}

export function SummaryCards({ items }) {
  return <div className="workspace-counts" aria-label="Overview">{items.map(({ label, value, onClick, active }) => {
    const Tag = onClick ? "button" : "div";
    return <Tag key={label} type={onClick ? "button" : undefined} onClick={onClick} aria-pressed={onClick ? Boolean(active) : undefined} className={`workspace-count ${onClick ? "cursor-pointer hover:text-foreground" : ""}`}>
      <span>{label}</span><span className="font-semibold tabular-nums text-foreground">{value}</span>
    </Tag>;
  })}</div>;
}

export function SearchField({ value, onChange, placeholder = "Search…", label = "Search", ...props }) {
  return <div className="search-field">
    <IconSearch size={18} className="shrink-0 text-zinc-400" />
    <Input aria-label={label} placeholder={placeholder} value={value} onChange={event => onChange(event.target.value)} {...props} />
    {value && <button type="button" aria-label={`Clear ${label.toLowerCase()}`} onClick={() => onChange("")}><IconX size={16} /></button>}
  </div>;
}

export function EmptyState({ icon: Icon, title, description, action }) {
  return <div className="empty-state">
    {Icon && <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-blue-50 text-blue-600 dark:bg-blue-500/10 dark:text-blue-400"><Icon size={24} stroke={1.5} /></div>}
    <h2 className="text-base font-semibold">{title}</h2>
    <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-zinc-500 dark:text-zinc-400">{description}</p>
    {action && <div className="mt-5">{action}</div>}
  </div>;
}
