import { Pagination as MantinePagination } from "@mantine/core";

export default function Pagination({ classNames = {}, ...props }) {
  return <MantinePagination {...props} classNames={{ ...classNames,
    control: "!h-8 !min-w-[32px] !rounded-md !border-transparent !bg-control !text-xs !text-foreground hover:!bg-accent data-[active]:!bg-primary data-[active]:!text-white disabled:!opacity-40",
    dots: "!text-muted-foreground",
  }} />;
}
