import { Select } from "@mantine/core";
import { IconChevronDown } from "@tabler/icons-react";

export default function SearchSelect({ label, value, onChange, options, className = "", withinPortal = true, zIndex = 400, ...props }) {
  return <Select {...props} aria-label={label} searchable value={String(value)} onChange={next => next !== null && onChange(next)} data={options.map(option => ({ ...option, value: String(option.value) }))}
    nothingFound="No matching options" maxDropdownHeight={260} withinPortal={withinPortal} zIndex={zIndex} dropdownPosition="flip" rightSection={<IconChevronDown size={15} />} rightSectionWidth={32}
    className={className} classNames={{
      input: "!h-11 md:!h-10 !cursor-pointer !rounded-lg !border-transparent !bg-control !pr-9 !text-sm !text-foreground text-ellipsis [&::-webkit-search-cancel-button]:hidden [&::-webkit-search-decoration]:hidden",
      dropdown: "!rounded-lg !border-border !bg-dialog !p-1 shadow-lg",
      item: "!cursor-pointer !rounded-md !text-sm !text-foreground data-[hovered]:!bg-accent data-[selected]:!bg-primary/10 data-[selected]:!text-blue-700 dark:data-[selected]:!text-blue-300",
      rightSection: "pointer-events-none text-muted-foreground",
    }} />;
}
