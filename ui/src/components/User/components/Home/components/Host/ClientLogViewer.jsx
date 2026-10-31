import { memo, useState } from "react";
import { Switch } from "@mantine/core";
import { IconArrowDown, IconTerminal2 } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";

// Render text as React text nodes, never HTML. Strip terminal control sequences
// so ANSI escapes and OSC links cannot disturb alignment or create active links.
function clean(line) {
  return line.replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, "")
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "");
}

const LogText = memo(function LogText({ text }) {
  const parts = clean(text).split(/(\b\d{4}-\d{2}-\d{2}[T ][\d:.]+Z?|(?:\[(?:TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL)\]|\b(?:TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL)\b)|\b[A-Za-z_][\w.-]*=)/g);
  return parts.map((part, index) => {
    const level = part.replace(/[\[\]]/g, "");
    const color = /^(ERROR|FATAL)$/.test(level) ? "text-red-700 dark:text-red-400"
      : /^(WARN|WARNING)$/.test(level) ? "text-amber-700 dark:text-amber-300"
      : level === "INFO" ? "text-emerald-700 dark:text-emerald-400"
      : /^(DEBUG|TRACE)$/.test(level) || /^\d{4}-/.test(part) ? "text-muted-foreground"
      : part.endsWith("=") ? "text-sky-700 dark:text-sky-300" : "";
    return color ? <span key={index} className={color}>{part}</span> : part;
  });
});

export default function ClientLogViewer({ lines, total, status, numbers, onNumbers, verbose, onVerbose, following, onFollow, containerRef, onScroll }) {
  const [wrap, setWrap] = useState(false);
  const digits = String(lines.at(-1)?.number || 1).length;
  const message = total ? "Verbose logs are hidden. Enable Verbose to view them."
    : status === "offline" ? "The client must be online to stream logs."
    : status === "connecting" ? "Connecting to the client log stream…"
    : status === "idle" ? "Waiting for the client log stream…" : "Connected. Waiting for client logs…";
  return <section className="flex min-h-0 flex-1 flex-col gap-3" aria-label="Client log terminal">
    <div className="flex shrink-0 flex-wrap items-center justify-between gap-3">
      <div className="flex items-center gap-2"><IconTerminal2 size={17} className="text-muted-foreground" /><h2 className="text-sm font-semibold">Client Logs</h2><span className="text-xs text-muted-foreground">{status === "streaming" ? "Live" : status === "offline" ? "Offline" : "Connecting"}</span></div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <Switch size="xs" checked={numbers} onChange={event => onNumbers(event.currentTarget.checked)} label="Line numbers" labelPosition="left" />
        <Switch size="xs" checked={wrap} onChange={event => setWrap(event.currentTarget.checked)} label="Wrap" labelPosition="left" />
        <Switch size="xs" checked={verbose} onChange={event => onVerbose(event.currentTarget.checked)} label="Verbose" labelPosition="left" />
      </div>
    </div>
    <div ref={containerRef} onScroll={onScroll} tabIndex={0} aria-label="Client log output"
      className="min-h-0 flex-1 overflow-auto rounded-lg bg-control font-mono text-[12px] leading-5 text-foreground outline-none focus-visible:ring-1 focus-visible:ring-border"
      style={{ fontVariantLigatures: "none", tabSize: 4, scrollbarGutter: "stable" }}>
      {lines.length ? <table className={`min-w-full border-collapse ${wrap ? "w-full table-fixed" : "w-max"}`} aria-label="Log lines">
        {numbers && <colgroup><col style={{ width: `${digits + 2}ch` }} /><col /></colgroup>}
        <tbody>{lines.map(entry => <tr key={entry.number} className="align-top hover:bg-accent/30">
          {numbers && <td aria-hidden="true" className="sticky left-0 select-none bg-control px-2 text-right text-muted-foreground" style={{ width: `${digits + 2}ch` }}>{entry.number}</td>}
          <td className={`${numbers ? "pr-3" : "px-3"} ${wrap ? "whitespace-pre-wrap [overflow-wrap:anywhere]" : "whitespace-pre"}`}><LogText text={entry.text} /></td>
        </tr>)}</tbody>
      </table> : <p className="p-4 text-xs text-muted-foreground">{message}</p>}
    </div>
    <div className="flex shrink-0 items-center justify-between gap-3 text-xs text-muted-foreground">
      <span>{lines.length.toLocaleString()} lines · <code>porthub logs</code></span>
      <Button type="button" variant="ghost" size="sm" onClick={onFollow} aria-pressed={following}><IconArrowDown size={14} />{following ? "Following live" : "Jump to latest"}</Button>
    </div>
  </section>;
}
