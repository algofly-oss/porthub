import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva } from "class-variance-authority";
import { cn } from "@/shared/utils/cn";

// shadcn/ui button pattern, with the existing PortHub blue accent.
export const buttonVariants = cva(
  "inline-flex shrink-0 items-center justify-center gap-2 whitespace-nowrap rounded-lg text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-zinc-400 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 [&_svg]:shrink-0",
  { variants: {
    variant: {
      default: "bg-primary text-white shadow-sm hover:bg-primary-hover",
      outline: "border border-transparent bg-control text-foreground hover:bg-accent",
      secondary: "bg-control text-foreground hover:bg-accent",
      ghost: "text-muted-foreground hover:bg-accent hover:text-foreground",
      destructive: "bg-red-600 text-white hover:bg-red-700",
    },
    size: { default: "h-10 px-3", sm: "h-9 px-3", icon: "h-9 w-9", lg: "h-10 px-4" },
  }, defaultVariants: { variant: "default", size: "default" } }
);
/** @typedef {React.ButtonHTMLAttributes<HTMLButtonElement> & {variant?: "default" | "outline" | "secondary" | "ghost" | "destructive", size?: "default" | "sm" | "icon" | "lg", asChild?: boolean}} ButtonProps */
export const Button = React.forwardRef(/** @param {ButtonProps} buttonProps */ (buttonProps, ref) => {
  const { className, variant, size, asChild = false, ...props } = buttonProps;
  const Comp = asChild ? Slot : "button";
  return <Comp ref={ref} className={cn(buttonVariants({ variant, size }), className)} {...props} />;
});
Button.displayName = "Button";
