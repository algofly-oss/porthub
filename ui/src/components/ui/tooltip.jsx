import { Tooltip as MantineTooltip } from "@mantine/core";
import { cn } from "@/shared/utils/cn";

export function Tooltip({ classNames = {}, ...props }) {
  return <MantineTooltip {...props} classNames={{ ...classNames,
    tooltip: cn(classNames.tooltip, "!rounded-lg !border !border-border !bg-dialog !text-foreground !shadow-md"),
    arrow: cn(classNames.arrow, "!border-border !bg-dialog"),
  }} />;
}
