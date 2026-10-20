import { Modal } from "@mantine/core";
import { cn } from "@/shared/utils/cn";

export const dialogSurface = "!rounded-xl !border-0 !bg-dialog !text-foreground !shadow-lg [--surface:220_14%_96%] dark:[--surface:223_7%_18%] [--control:220_14%_94%] dark:[--control:225_6%_13%]";
export const dialogHeader = "!border-0 !bg-dialog !px-5 !py-4 !text-foreground dark:!bg-dialog";

// All desktop editors and confirmations share the same surface and controls.
export function Dialog({ classNames = {}, overlayProps = {}, zIndex = 300, ...props }) {
  return <Modal {...props} zIndex={zIndex} centered radius="lg" overlayProps={{ opacity: .42, blur: 5, ...overlayProps }} classNames={{
    ...classNames,
    content: cn(classNames.content, dialogSurface),
    header: cn(classNames.header, dialogHeader),
    title: cn(classNames.title, "!text-[15px] !font-semibold !text-foreground"),
    body: cn(classNames.body, "!bg-dialog !px-5 !pb-5 !text-foreground"),
    close: "!text-muted-foreground hover:!bg-accent hover:!text-foreground",
  }} />;
}
