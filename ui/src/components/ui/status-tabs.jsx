import { useEffect, useRef } from "react";
import { revealSelectedTab } from "./status-tabs-scroll.mjs";
import { Button } from "./button";
import { cn } from "@/shared/utils/cn";

export function StatusTabs({ label, value, onChange, options, className }) {
  const group = useRef(null);
  useEffect(() => {
    const reveal = () => revealSelectedTab(group.current);
    reveal();
    const observer = new ResizeObserver(reveal);
    if (group.current) observer.observe(group.current);
    if (group.current?.parentElement) observer.observe(group.current.parentElement);
    return () => observer.disconnect();
  }, [value]);
  return <div ref={group} role="group" aria-label={label} className={cn("inline-flex h-10 shrink-0 items-center gap-0.5 rounded-lg bg-white p-1 dark:bg-control", className)}>
    {options.map(option => <Button key={option.value} type="button" size="sm" variant={value === option.value ? "default" : "ghost"} aria-pressed={value === option.value} onClick={() => onChange(option.value)} className="h-8 rounded-md px-2.5 shadow-none transition-none">{option.label}</Button>)}
  </div>;
}
