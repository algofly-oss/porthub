import { useEffect, useState, useSyncExternalStore } from 'react';
import toast from 'react-hot-toast';
import { IconUpload, IconCopy, IconCheck, IconX, IconRefresh } from '@tabler/icons-react';
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
    <label htmlFor="browser-share-files" className={`flex min-h-[136px] cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed px-4 py-5 text-center transition-colors focus-within:ring-2 focus-within:ring-primary ${dragging?'border-primary bg-primary/10':'border-input hover:border-primary'}`}>
      <IconUpload size={22} className="text-muted-foreground"/><span className="text-sm font-medium">Drop a file here, or choose a file</span><span className="text-xs text-muted-foreground">Files stay on this device. Keep this tab open to share.</span>
      <input id="browser-share-files" aria-label="Choose files to share" type="file" multiple className="sr-only" onChange={event=>{void add(event.target.files);event.target.value='';}}/>
    </label>
    {shares.map(share=><Share key={share.localId} share={share}/>)}
  </div>;
}
