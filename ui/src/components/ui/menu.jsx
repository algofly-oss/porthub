import { forwardRef } from "react";
import { Menu as MantineMenu } from "@mantine/core";
import { cn } from "@/shared/utils/cn";

export function Menu(props) { return <MantineMenu {...props} />; }
Menu.Target = MantineMenu.Target;
Menu.Dropdown = forwardRef(({ className, onKeyDown, ...props }, ref) => <MantineMenu.Dropdown ref={ref} {...props} onKeyDown={event => { if (event.key === "Escape") event.stopPropagation(); onKeyDown?.(event); }} className={cn(className, "!rounded-lg !border-border !bg-dialog !p-1 !text-foreground !shadow-lg")} />);
Menu.Dropdown.displayName = "MenuDropdown";
Menu.Item = forwardRef(({ className, color, ...props }, ref) => <MantineMenu.Item ref={ref} {...props} color={color} className={cn("!rounded-md hover:!bg-accent data-[hovered]:!bg-accent", color === "red" ? "!text-red-700 dark:!text-red-300" : "!text-foreground", className)} />);
Menu.Item.displayName = "MenuItem";
