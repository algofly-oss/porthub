import { MultiSelect } from "@mantine/core";
import { IconChevronDown } from "@tabler/icons-react";

export default function SearchMultiSelect({ label, value, onChange, options, ...props }) {
  return <MultiSelect {...props} label={label} aria-label={label} searchable clearable value={value} onChange={onChange} data={options}
    nothingFound="No matching machines or groups" maxDropdownHeight={240} withinPortal zIndex={400} dropdownPosition="flip"
    rightSection={<IconChevronDown size={15} />} rightSectionWidth={32} classNames={{
      label: "!mb-2 !text-sm !font-medium !text-foreground",
      input: "!min-h-11 !rounded-lg !border-transparent !bg-control !text-sm !text-foreground",
      searchInput: "!bg-transparent !text-foreground placeholder:!text-muted-foreground",
      dropdown: "!rounded-lg !border-border !bg-dialog !p-1 shadow-lg",
      item: "!cursor-pointer !rounded-md !text-sm !text-foreground data-[hovered]:!bg-accent data-[selected]:!bg-primary/10",
      value: "!rounded-md !bg-accent !text-foreground",
      rightSection: "pointer-events-none text-muted-foreground",
    }} />;
}
