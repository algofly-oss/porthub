import { useEffect, useState, useSyncExternalStore } from 'react';
import toast from 'react-hot-toast';
import { IconUpload, IconCopy, IconCheck, IconX, IconRefresh, IconLink, IconTerminal2, IconFile } from '@tabler/icons-react';
import { Button } from '@/components/ui/button';
import { copyText } from '@/shared/utils/clipboard';
import { shareFile, stopShare, retryShare, subscribe, getSnapshot, getServerSnapshot } from '@/shared/transfers/browser-shares';
import Command from './Command';
const quote = value => `'${value.replace(/'/g,"'\\''")}'`;
const bytes = count => count < 1024 ? `${count} B` : count < 1024 ** 2 ? `${(count/1024).toFixed(1)} KiB` : count < 1024 ** 3 ? `${(count/1024**2).toFixed(1)} MiB` : `${(count/1024**3).toFixed(1)} GiB`;
function Share({ share }) {
  const [tool,setTool] = useState('curl'),[copied,setCopied] = useState(false);
  const ready = !!share.url && share.status !== 'error';
  const command = tool === 'curl' ? `curl -fL -o ${quote(share.name)} -- ${quote(share.url)}` : `wget -c -O ${quote(share.name)} -- ${quote(share.url)}`;
  const copy = async () => { try { await copyText(share.url);setCopied(true); } catch { toast.error('Select and copy the link below.'); } };
  return <article className="mt-4 overflow-hidden rounded-lg border border-border bg-background p-4" aria-label={`Share ${share.name}`}>
    <div className="mb-3 flex min-w-0 items-center justify-between gap-3">
      <div className="min-w-0"><h2 className="truncate text-sm font-medium" title={share.name}>{share.name}</h2><p className="mt-1 text-xs text-muted-foreground">{bytes(share.size)} · {share.status === 'starting' ? 'Preparing link…' : share.status === 'reconnecting' ? 'Reconnecting…' : share.status === 'error' ? 'Sharing stopped' : `Sharing · ${bytes(share.sent)} transferred`}</p></div>
      <Button variant="ghost" size="icon" aria-label={`Stop sharing ${share.name}`} onClick={() => stopShare(share.localId)}><IconX size={16}/></Button>
    </div>
    {share.error && <div className="mb-3 flex items-center justify-between gap-2"><p role="alert" className="text-xs text-muted-foreground">{share.error}</p>{share.status === 'error' && <Button variant="secondary" size="sm" onClick={() => { void retryShare(share.localId)?.catch(error => toast.error(error.message)); }}><IconRefresh size={14}/>Retry</Button>}</div>}
    <div className="mb-3 flex min-w-0 gap-2"><input aria-label={`Public URL for ${share.name}`} readOnly value={share.url} placeholder="Preparing your link…" onFocus={event=>event.target.select()} className="h-11 min-w-0 flex-1 rounded-lg border border-input bg-surface px-3 text-xs"/><Button disabled={!ready} variant="secondary" onClick={copy} aria-label={`Copy URL for ${share.name}`}>{copied ? <IconCheck size={15}/> : <IconCopy size={15}/>}Copy link</Button></div>
    <div className="mb-2 flex items-center justify-between gap-2"><span className="text-xs text-muted-foreground">Download on another machine</span><div role="group" aria-label={`Download tool for ${share.name}`} className="flex gap-1">{['curl','wget'].map(value=><Button key={value} variant={tool===value?'secondary':'ghost'} size="sm" aria-pressed={tool===value} onClick={()=>setTool(value)}>{value==='curl'?'cURL':'Wget'}</Button>)}</div></div>
    <Command title={`Browser download with ${tool}`} command={command} ready={ready} language={tool === 'curl' ? 'cURL' : 'Wget'} empty="The download command will appear here."/>
  </article>;
}
export default function BrowserShare({ active }) {
  const shares = useSyncExternalStore(subscribe,getSnapshot,getServerSnapshot);
  const [dragging,setDragging] = useState(false);
  const add = async files => {
    for (const file of Array.from(files)) {
      try { const url = await shareFile(file);if (url) { try { await copyText(url);toast.success('File link copied'); } catch {} } }
      catch (error) { toast.error(error.message); }
    }
  };
  useEffect(()=>{
    if(!active)return;
    const paste = event=>{if(event.clipboardData?.files?.length){event.preventDefault();void add(event.clipboardData.files);}};
    document.addEventListener('paste',paste);return()=>document.removeEventListener('paste',paste);
  },[active]);
  return <div onDragOver={event=>{event.preventDefault();setDragging(true);}} onDragLeave={event=>{if(!event.currentTarget.contains(event.relatedTarget))setDragging(false);}} onDrop={event=>{event.preventDefault();event.stopPropagation();setDragging(false);void add(event.dataTransfer.files);}}>
    <div className={shares.length ? '' : 'grid gap-6 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)] lg:gap-8'}>
      <label htmlFor="browser-share-files" className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed px-5 text-center transition-colors focus-within:ring-2 focus-within:ring-primary ${shares.length?'min-h-32 py-5':'min-h-64 py-8 sm:min-h-72'} ${dragging?'border-primary bg-primary/10':'border-input bg-background/40 hover:border-primary hover:bg-primary/5'}`}>
        <span className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 text-primary dark:text-blue-300"><IconUpload size={24}/></span>
        <span className="text-base font-medium">Drop files to share</span>
        <span className="mt-1.5 text-xs text-muted-foreground">Any file type · Original quality</span>
        <span className="mt-5 inline-flex h-10 items-center justify-center gap-2 rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground"><IconFile size={16}/>Choose files</span>
        <span className="mt-3 text-xs text-muted-foreground">or paste a file from your clipboard</span>
        <input id="browser-share-files" aria-label="Choose files to share" type="file" multiple className="sr-only" onChange={event=>{void add(event.target.files);event.target.value='';}}/>
      </label>
      {!shares.length&&<aside aria-label="Browser sharing guide" className="flex flex-col justify-center py-2 lg:pr-3">
        <h2 className="text-sm font-semibold">Share a file in three steps</h2>
        <ol className="mt-5 space-y-5">
          {[[IconUpload,'Choose your file','Drag it here or browse your files. Nothing is stored on the server.'],[IconLink,'Copy the temporary link','Share it with anyone. No account or PortHub client needed.'],[IconTerminal2,'Download on another machine','Copy a ready-to-run cURL or Wget command, or open the link.']].map(([Icon,title,detail])=><li key={title} className="flex gap-3"><Icon size={18} className="mt-0.5 shrink-0 text-muted-foreground"/><div><h3 className="text-sm font-medium">{title}</h3><p className="mt-1 text-xs leading-relaxed text-muted-foreground">{detail}</p></div></li>)}
        </ol>
        <p className="mt-6 border-t border-border pt-4 text-xs leading-relaxed text-muted-foreground">Keep this tab open while people download. Closing it ends sharing.</p>
      </aside>}
    </div>
    {!!shares.length&&<div className="mt-5 flex items-center justify-between border-b border-border pb-3"><h2 className="text-sm font-semibold">Shared from this browser</h2><span className="text-xs text-muted-foreground">{shares.length} {shares.length===1?'file':'files'}</span></div>}
    {shares.map(share=><Share key={share.localId} share={share}/>)}
  </div>;
}
