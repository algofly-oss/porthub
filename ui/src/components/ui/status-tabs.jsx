import { Button } from "./button";

export function StatusTabs({ label, value, onChange, options }) {
  return <div role="group" aria-label={label} className="inline-flex h-10 shrink-0 items-center gap-0.5 rounded-lg bg-control p-1">
    {options.map(option => <Button key={option.value} type="button" size="sm" variant={value === option.value ? "default" : "ghost"} aria-pressed={value === option.value} onClick={() => onChange(option.value)} className="h-8 rounded-md px-2.5 shadow-none transition-none">{option.label}</Button>)}
  </div>;
}
