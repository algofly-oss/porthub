import * as React from "react";
import { cn } from "@/shared/utils/cn";

// Semantic table primitives based on shadcn/ui's Tailwind 3 component API.
export const Table = React.forwardRef(({ className, ...props }, ref) => <table ref={ref} className={cn("w-full table-fixed caption-bottom bg-surface text-sm text-foreground", className)} {...props} />);
export const TableHeader = React.forwardRef(({ className, ...props }, ref) => <thead ref={ref} className={cn("sticky top-0 z-[1] bg-muted [&_tr]:border-b [&_tr:hover]:bg-transparent", className)} {...props} />);
export const TableBody = React.forwardRef(({ className, ...props }, ref) => <tbody ref={ref} className={cn("[&_tr:last-child]:border-0", className)} {...props} />);
export const TableRow = React.forwardRef(({ className, ...props }, ref) => <tr ref={ref} className={cn("border-b border-border/60 transition-colors hover:bg-accent/40 data-[state=selected]:bg-muted", className)} {...props} />);
export const TableHead = React.forwardRef(({ className, ...props }, ref) => <th ref={ref} className={cn("h-11 px-4 text-left align-middle text-[13px] font-medium text-muted-foreground first:pl-5 last:pr-5", className)} {...props} />);
export const TableCell = React.forwardRef(({ className, ...props }, ref) => <td ref={ref} className={cn("px-4 py-3 align-middle first:pl-5 last:pr-5", className)} {...props} />);
Table.displayName = "Table";
TableHeader.displayName = "TableHeader";
TableBody.displayName = "TableBody";
TableRow.displayName = "TableRow";
TableHead.displayName = "TableHead";
TableCell.displayName = "TableCell";
