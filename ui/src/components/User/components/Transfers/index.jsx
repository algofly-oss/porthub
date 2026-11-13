import { useEffect, useState } from "react";
import toast from "react-hot-toast";
import { IconCopy, IconCheck, IconArrowUpRight, IconArrowDownLeft, IconTerminal2 } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { copyText } from "@/shared/utils/clipboard";

const quote = value => `'${value.replace(/'/g, "'\\''")}'`;
const inputClass = "mt-1.5 block h-11 w-full rounded-lg border border-input bg-background px-3 text-sm text-foreground outline-none transition-colors focus:border-primary focus:ring-1 focus:ring-primary";
const tools = { curl: "cURL", wget: "Wget", aria2: "aria2" };

function Command({ title, command, ready, language, empty }) {
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

export default function Transfers() {
  const [base, setBase] = useState("");
  const [mode, setMode] = useState("send");
  const [file, setFile] = useState("./file.zip");
  const [url, setUrl] = useState("");
  const [out, setOut] = useState("");
  const [sendTool, setSendTool] = useState("curl");
  const [downloadTool, setDownloadTool] = useState("curl");
  const [connections, setConnections] = useState("1");
  useEffect(() => setBase(window.location.origin), []);
  const tool = mode === "send" ? sendTool : downloadTool;
  const download = url.trim();
  let validUrl = false;
  try { validUrl = ["http:", "https:"].includes(new URL(download).protocol); } catch {}
  const sender = sendTool === "curl"
    ? `bash <(curl -fsS ${quote(`${base}/api/transfers/sender`)}) ${quote(file)} ${quote(base)}`
    : `bash <(wget -qO- ${quote(`${base}/api/transfers/sender`)}) ${quote(file)} ${quote(base)} wget`;
  const parallel = `bash <(curl -fsS ${quote(`${base}/transfers/receive.sh`)}) ${quote(download)} ${quote(out)}`;

  const directory = out.includes("/") ? out.slice(0, out.lastIndexOf("/")) || "/" : ".";
  const filename = out.split("/").pop();
  const customName = !!out.trim();
  const receiver = downloadTool === "wget"
    ? `wget -c${customName ? ` -O ${quote(out)}` : " --content-disposition"} -- ${quote(download)}`
    : downloadTool === "aria2"
      ? `aria2c -x 8 -s 8 --file-allocation=none${customName && directory !== "." ? ` -d ${quote(directory)}` : ""}${customName ? ` -o ${quote(filename)}` : ""} -- ${quote(download)}`
      : connections === "4" ? parallel : customName ? `curl -fL -o ${quote(out)} -- ${quote(download)}` : `curl -fLOJ -- ${quote(download)}`;
  const sending = mode === "send";
  const title = sending ? `Send with ${tools[tool]}` : tool === "curl" && connections === "4" ? "Parallel download with cURL" : `Download with ${tools[tool]}`;
  const ready = sending ? !!base && !!file.trim() : validUrl && (!customName || !!filename.trim());
  return <div className="h-full min-h-0 overflow-y-auto px-4 py-5 sm:px-6">
    <div className="mx-auto w-full max-w-5xl">
      <header className="mb-5">
        <h1 className="text-lg font-semibold tracking-tight">Transfers</h1>
        <p className="mt-1 text-sm text-muted-foreground">Share files between terminals. No login or PortHub installation needed.</p>
      </header>
      <div className="overflow-hidden rounded-xl border border-border bg-surface">
        <div role="tablist" aria-label="Transfer direction" className="flex gap-5 border-b border-border px-5">
          {[["send", "Send a file", IconArrowUpRight], ["download", "Download a file", IconArrowDownLeft]].map(([value, label, Icon]) =>
            <button key={value} id={`transfer-${value}-tab`} role="tab" aria-selected={mode === value} aria-controls="transfer-panel" tabIndex={mode === value ? 0 : -1}
              onClick={() => setMode(value)} onKeyDown={event => { if (["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) { event.preventDefault(); const next = event.key === "Home" ? "send" : event.key === "End" ? "download" : mode === "send" ? "download" : "send"; setMode(next); document.getElementById(`transfer-${next}-tab`)?.focus(); } }}
              className={`relative flex min-h-[52px] items-center gap-2 border-b-2 px-0.5 text-sm font-medium outline-none transition-colors focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-primary ${mode === value ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"}`}><Icon size={17}/>{label}</button>)}
        </div>
        <section id="transfer-panel" role="tabpanel" aria-labelledby={`transfer-${mode}-tab`} className="p-4 sm:p-5">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-muted-foreground">{sending ? "Run this on the machine that has your file." : "Paste the link printed by the sender."}</p>
            <div role="group" aria-label={sending ? "Sender tool" : "Download tool"} className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-border bg-background p-1">
              {(sending ? ["curl", "wget"] : ["curl", "wget", "aria2"]).map(value => <button type="button" key={value} aria-pressed={tool === value}
                onClick={() => sending ? setSendTool(value) : setDownloadTool(value)}
                className={`h-11 min-w-[64px] rounded-md px-3 text-xs font-medium outline-none transition-colors focus-visible:ring-2 focus-visible:ring-primary ${tool === value ? "bg-primary/10 text-primary dark:text-blue-300 ring-1 ring-inset ring-primary/30" : "text-muted-foreground hover:text-foreground"}`}>{tools[value]}</button>)}
            </div>
          </div>
          {sending ? <label className="mb-4 block text-xs font-medium text-muted-foreground" htmlFor="transfer-file">File path <span id="transfer-file-hint" className="ml-2 font-normal">Replace with your file’s path</span>
            <input id="transfer-file" aria-label="File path" aria-describedby="transfer-file-hint" value={file} spellCheck={false} onChange={event => setFile(event.target.value)} className={inputClass} placeholder="./backup.zip"/>
          </label> : <div className="mb-4 grid gap-3 sm:grid-cols-[minmax(0,1fr)_200px]">
            <label className="min-w-0 text-xs font-medium text-muted-foreground" htmlFor="transfer-url">Download URL
              <input id="transfer-url" aria-label="Download URL" type="url" value={url} spellCheck={false} onChange={event => setUrl(event.target.value)} className={inputClass} placeholder="Paste the sender’s download link" aria-invalid={!!download && !validUrl} aria-describedby={download && !validUrl ? "transfer-url-error" : undefined}/>
              {download && !validUrl && <span id="transfer-url-error" role="alert" className="mt-1 block text-xs text-red-500">Enter an http:// or https:// download link.</span>}
            </label>
            <label className="min-w-0 text-xs font-medium text-muted-foreground" htmlFor="transfer-output">Save as <span className="font-normal">(optional)</span>
              <input id="transfer-output" aria-label="Save as" placeholder="Original filename" value={out} spellCheck={false} onChange={event => setOut(event.target.value)} className={inputClass}/>
            </label>
          </div>}
          <Command title={title} command={sending ? sender : receiver} ready={ready} language={sending || tool === "curl" && connections === "4" ? "Bash" : tools[tool]}
            empty={sending ? "Enter the path of the file to share." : "Paste a download URL above to generate your command."}/>
          <div className="mt-3 flex flex-wrap items-center justify-between gap-x-4 gap-y-2 text-xs text-muted-foreground">
            <p>{sending ? "Copy the command, run it in Bash, then share the printed link." : tool === "aria2" ? "Up to 8 connections. Requires aria2." : tool === "wget" ? "Resumes an interrupted download while the sender stays online." : connections === "4" ? "Up to 4 connections. Run the full script in Bash." : "Run this on the machine receiving the file."}</p>
            {!sending && tool === "curl" && <label className="flex items-center gap-2" htmlFor="transfer-connections">Connections
              <select id="transfer-connections" aria-label="Connections" value={connections} onChange={event => setConnections(event.target.value)} className="h-11 rounded-md border border-border bg-background px-2 text-xs text-foreground"><option value="1">1 · Standard</option><option value="4">4 · Parallel (Bash)</option></select>
            </label>}
          </div>
          {sending && <p className="mt-2 text-xs text-muted-foreground">Keep the sender running and the file unchanged. Ctrl+C stops sharing.</p>}
        </section>
      </div>
      <div className="mt-4 flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
        <p>Free · No server storage · Multiple downloaders</p>

      </div>
    </div>
  </div>;
}
