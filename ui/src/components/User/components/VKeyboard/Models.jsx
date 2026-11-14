import { useCallback, useEffect, useState } from 'react';
import axios from 'axios';
import toast from 'react-hot-toast';
import { IconDownload, IconCpu } from '@tabler/icons-react';
const button='min-h-11 rounded-lg border border-border px-3 text-xs font-medium hover:bg-control disabled:opacity-40';
export default function Models({active,status,setStatus,isAdmin}){
  const [busy,setBusy]=useState(false),[open,setOpen]=useState(false);
  const load=useCallback(async()=>{try{const {data}=await axios.get('/api/keyboard/speech');setStatus(data);}catch(error){toast.error(error.response?.data?.detail||'Could not load speech settings');}},[setStatus]);
  useEffect(()=>{if(!active)return;void load();},[active,load]);
  const changing=!!status?.download||!!status?.busy;
  useEffect(()=>{if(!active||!changing)return;const timer=setInterval(()=>void load(),2000);return()=>clearInterval(timer);},[active,changing,load]);
  useEffect(()=>{if(!active||!status?.loaded||status?.busy)return;const timer=setTimeout(()=>void load(),(status.idle_seconds+2)*1000);return()=>clearTimeout(timer);},[active,status,load]);
  const change=async(next)=>{setBusy(true);try{const {data}=await axios.patch('/api/keyboard/speech',{...status.settings,...next});setStatus(data);}catch(error){toast.error(error.response?.data?.detail||'Could not change speech engine');}finally{setBusy(false);}};
  const download=async(id)=>{setBusy(true);try{await axios.post(`/api/keyboard/speech/models/${encodeURIComponent(id)}/download`);await load();}catch(error){toast.error(error.response?.data?.detail||'Model download failed');}finally{setBusy(false);}};
  const selected=status?.models?.find(m=>m.id===status.settings.model);
  const size=bytes=>`${Math.round(bytes/1e6)} MB`;
  return <section aria-label="Dictation models" className="rounded-xl border border-border bg-surface p-4 sm:p-5">
    <div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="flex items-center gap-2 text-sm font-medium"><IconCpu size={18}/>Speech engine</h2><p className="mt-1 text-xs text-muted-foreground">{status?.loaded?'Model loaded':status?'No model in memory':'Loading engine settings…'}{status?.busy?' · Transcribing':''}</p></div>
      <label className="flex min-h-11 items-center gap-2 text-sm"><input type="checkbox" role="switch" aria-label="Enable dictation" checked={!!status?.settings.enabled} disabled={!status||!isAdmin||busy} onChange={e=>change({enabled:e.target.checked})}/>Dictation enabled</label>
    </div>
    <div className="mt-4 flex flex-wrap items-end gap-3"><label className="min-w-0 flex-1 text-xs text-muted-foreground">Active model<select aria-label="Active speech model" value={status?.settings.model||''} disabled={!status||!isAdmin||busy} onChange={e=>change({model:e.target.value})} className="mt-1 block h-11 w-full rounded-lg border border-input bg-background px-3 text-sm text-foreground">{status?.models?.filter(m=>m.installed||m.id===status.settings.model).map(m=><option key={m.id} value={m.id} disabled={!m.installed}>{m.name}{m.installed?'':' · Download required'}</option>)}</select></label>
      <div role="group" aria-label="Inference engine" className="flex h-11 rounded-lg border border-border p-1">{['cpu','gpu'].map(engine=><button type="button" key={engine} aria-pressed={status?.settings.engine===engine} disabled={!status||!isAdmin||busy||engine==='gpu'&&!status.gpu_available} title={engine==='gpu'&&!status?.gpu_available?'GPU is unavailable on this deployment':undefined} className={`rounded-md px-4 text-xs font-medium disabled:opacity-40 ${status?.settings.engine===engine?'bg-primary/10 text-primary':'hover:bg-control'}`} onClick={()=>change({engine})}>{engine.toUpperCase()}</button>)}</div>
      <button type="button" className={button} onClick={()=>{setOpen(v=>!v);void load();}} aria-expanded={open} aria-controls="keyboard-model-library">{open?'Hide model library':'Model library'}</button>
      {status?.loaded&&isAdmin&&<button type="button" disabled={busy} className={button} onClick={async()=>{setBusy(true);try{const {data}=await axios.post('/api/keyboard/speech/unload');setStatus(data);}catch{toast.error('Could not unload model');}finally{setBusy(false);}}}>Unload now</button>}
    </div>
    <p className="mt-3 text-xs text-muted-foreground">Loads when used. Unloads after {status?.idle_seconds||60} seconds idle. One model at a time. {selected?`${size(selected.size)} download; runtime memory varies.`:''}</p>
    {!isAdmin&&<p className="mt-2 text-xs text-muted-foreground">Administrators manage this deployment’s shared model and compute settings.</p>}
    {status?.error&&<p role="alert" className="mt-3 text-xs text-red-600 dark:text-red-400">{status.error}</p>}
    {status?.download&&<div className="mt-4"><div className="mb-2 flex justify-between gap-2 text-xs"><span>Downloading {status.download.model}</span><span>{size(status.download.bytes)} / {size(status.download.total)}</span></div><progress aria-label="Model download progress" className="h-2 w-full accent-blue-600" value={status.download.bytes} max={status.download.total}/></div>}
    {open&&<div id="keyboard-model-library" className="mt-4 divide-y divide-border border-t border-border">
      <p className="py-3 text-xs text-muted-foreground">Downloads use Handy’s model sources and verified checksums. Installed files stay on this server’s disk until removed; selecting a model does not load it.</p>
      {status?.models?.map(model=><div key={model.id} className="flex flex-wrap items-center justify-between gap-3 py-3"><div className="min-w-0 flex-1"><p className="text-sm font-medium">{model.name} <span className="ml-1 text-xs font-normal text-muted-foreground">{size(model.size)}</span></p><p className="mt-1 text-xs text-muted-foreground">{model.languages.length===1?`Language: ${model.languages[0].toUpperCase()}`:`${model.languages.length} languages`} · {model.description}</p><a href={model.source} target="_blank" rel="noreferrer" className="mt-1 inline-block text-xs text-primary hover:underline">Model source · {model.license}</a></div>
        {model.installed?<button type="button" disabled={!isAdmin||busy||status.settings.model===model.id} onClick={()=>change({model:model.id})} className={button}>{status.settings.model===model.id?'Selected':'Use model'}</button>:<button type="button" disabled={!isAdmin||busy||!!status.download} onClick={()=>download(model.id)} className={`${button} flex items-center gap-2`}><IconDownload size={16}/>Download</button>}
      </div>)}
    </div>}
  </section>;
}
