import * as React from "react";
import * as CheckboxPrimitive from "@radix-ui/react-checkbox";
import { IconCheck, IconMinus } from "@tabler/icons-react";
import { cn } from "@/shared/utils/cn";

// shadcn-style Radix control: identical rendering across browsers, keyboard accessible.
export const Checkbox = React.forwardRef(({ className, checked, ...props }, ref) => (
  <CheckboxPrimitive.Root ref={ref} checked={checked} className={cn(
    "inline-flex h-4 w-4 shrink-0 items-center justify-center rounded border border-muted-foreground/40 bg-surface text-white !outline-none focus-visible:ring-2 focus-visible:ring-muted-foreground focus-visible:ring-offset-2 focus-visible:ring-offset-surface disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:border-primary data-[state=checked]:bg-primary data-[state=indeterminate]:border-primary data-[state=indeterminate]:bg-primary", className,
  )} {...props}>
    <CheckboxPrimitive.Indicator>{checked === "indeterminate" ? <IconMinus size={12} stroke={3} /> : <IconCheck size={12} stroke={3} />}</CheckboxPrimitive.Indicator>
  </CheckboxPrimitive.Root>
));
Checkbox.displayName = "Checkbox";
