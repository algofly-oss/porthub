import * as React from "react";
import { cn } from "@/shared/utils/cn";

// Type-specific legacy form rules must not turn the resting border blue on focus.
export const Input = React.forwardRef(({ className, type, ...props }, ref) => <input ref={ref} type={type} className={cn("flex h-10 w-full rounded-lg border !border-transparent bg-control px-3 py-1 text-sm text-foreground !outline-none !shadow-none placeholder:text-muted-foreground disabled:cursor-not-allowed disabled:opacity-50", className)} {...props} />);
Input.displayName = "Input";
