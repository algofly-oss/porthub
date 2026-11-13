import { useEffect, useState } from "react";
import toast from "react-hot-toast";
import { IconCopy, IconCheck, IconTerminal2 } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { copyText } from "@/shared/utils/clipboard";

export default function Command({ title, command, ready, language, empty }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => setCopied(false), [command]);
  const copy = async () => {
    try { await copyText(command); setCopied(true); }
    catch { toast.error("Select and copy the command below."); }
  };
  return <div className="overflow-hidden rounded-lg border border-border bg-background">
    <div className="flex min-h-[52px] items-center justify-between gap-2 border-b border-border px-4">
      <span className="flex items-center gap-2 text-xs text-muted-foreground"><IconTerminal2 size={15}/>{language}</span>
      <Button size="sm" className="min-h-[44px]" variant={copied ? "secondary" : "default"} disabled={!ready} onClick={copy} aria-label={`Copy ${title.toLowerCase()} command`}>
        {copied ? <IconCheck size={15}/> : <IconCopy size={15}/>}{copied ? "Copied" : "Copy command"}
      </Button>
    </div>
    <pre className="m-0 min-h-[64px] overflow-x-auto whitespace-pre p-4 text-[13px] leading-6 text-foreground" tabIndex={ready ? 0 : undefined} aria-label={title}>
      <code className={ready ? "" : "text-muted-foreground"}>{ready ? command : empty}</code>
    </pre>
  </div>;
}

