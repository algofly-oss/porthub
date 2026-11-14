import SearchDropdown from '@/components/ui/search-dropdown';
import {useCallback,useEffect,useState} from 'react';
import axios from 'axios';
const button='min-h-11 rounded-lg border border-border px-3 text-sm hover:bg-control disabled:opacity-40';
const input='mt-2 h-11 w-full rounded-lg border border-border bg-control px-3 text-sm';
export default function UsbForwarding({machineId,active}){
 const [machines,setMachines]=useState([]),[forwards,setForwards]=useState([]),[device,setDevice]=useState(''),[destination,setDestination]=useState(''),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 const load=useCallback(async()=>{try{const [inventory,rules]=await Promise.all([axios.get('/api/usb/inventory'),axios.get('/api/usb/forwards')]);setMachines(inventory.data.machines);setForwards(rules.data.forwards);setError('');}catch(e){setError(e.response?.data?.detail||'Could not load USB forwarding');}},[]);
 useEffect(()=>{if(!active)return;void load();const timer=setInterval(load,10000);return()=>clearInterval(timer);},[active,load]);
 useEffect(()=>{setDevice('');setDestination('');},[machineId]);
 const source=machines.find(m=>m.id===machineId),devices=source?.report?.devices||[],owned=!!source;
 const act=async operation=>{setBusy(true);setError('');try{await operation();await load();}catch(e){setError(e.response?.data?.detail||'Could not update USB forwarding');}finally{setBusy(false);}};
 const status=(rule,id)=>machines.find(m=>m.id===id)?.report?.states?.find(s=>s.id===rule.id);
 return <section aria-label="USB forwarding" className="space-y-4 p-1">
  <div><h3 className="text-sm font-semibold">USB forwarding</h3><p className="mt-2 text-xs text-muted-foreground">Use a USB device on another registered machine. Saved rules reconnect after restarts and use an authenticated direct path when available.</p></div>
  {error&&<p role="alert" className="text-sm text-red-600 dark:text-red-400">{error}</p>}
  {source&&!source.online&&<p className="text-xs text-muted-foreground">USB module offline. Update and start this machine’s PortHub agent to discover devices.</p>}
  {source?.report?.supported===false&&<p className="text-xs text-muted-foreground">This machine’s operating system does not support the native USB module yet. Linux USB/IP is required.</p>}
  {source?.report?.enabled===false&&<p className="text-xs text-muted-foreground">USB forwarding is disabled on this client. Enable it locally with <code>porthub features enable usb</code>.</p>}
  {!owned&&machines.length>0&&<p className="text-xs text-muted-foreground">Only the machine owner can configure USB forwarding.</p>}
  {owned&&<div className="space-y-3" role="group" aria-label="Create USB forward">
   <label className="block text-xs text-muted-foreground">USB device on this machine<SearchDropdown aria-label="USB device" value={device} className={input} onChange={e=>setDevice(e.target.value)} required><option value="">Choose a device</option>{devices.map(d=><option key={d.busid} value={d.busid} disabled={!!d.blocked||forwards.some(f=>f.source===machineId&&f.device.busid===d.busid)}>{d.name||`${d.vendor}:${d.product}`} · {d.busid}{d.blocked?` · ${d.blocked}`:''}</option>)}</SearchDropdown></label>
   <label className="block text-xs text-muted-foreground">Use on machine<SearchDropdown aria-label="USB destination machine" value={destination} className={input} onChange={e=>setDestination(e.target.value)} required><option value="">Choose a destination</option>{machines.filter(m=>m.id!==machineId&&m.report?.supported!==false).map(m=><option key={m.id} value={m.id}>{m.name}{m.online?'':' · Offline'}</option>)}</SearchDropdown></label>
   <p className="text-xs text-muted-foreground">While forwarded, the device is controlled by the destination. Mounted disks and active network adapters cannot be shared.</p>
   <button type="button" onClick={()=>act(()=>axios.post('/api/usb/forwards',{source:machineId,destination,busid:device}))} className={button} disabled={busy||!device||!destination||!source.online||source.report?.enabled!==true||source.report?.supported!==true}>Save USB forward</button>
  </div>}
  <ul className="divide-y divide-border">{forwards.filter(f=>f.source===machineId||f.destination===machineId).map(f=>{const a=status(f,f.source),b=status(f,f.destination);const state=a?.state?.startsWith('active')&&b?.state?.startsWith('active')?(a.state==='active-direct'?'Direct connection':'Gateway relay'):(a?.error||b?.error||'Waiting for both machines');return <li key={f.id} className="space-y-2 py-4"><div className="flex items-center justify-between gap-3"><p className="min-w-0 break-words text-sm font-medium">{f.device.name||f.device.busid}</p><button type="button" className={button} disabled={busy||!f.persistent} onClick={()=>act(()=>axios.delete(`/api/usb/forwards/${f.id}`))}>Remove</button></div><p className="text-xs text-muted-foreground">{machines.find(m=>m.id===f.source)?.name||f.source} → {machines.find(m=>m.id===f.destination)?.name||f.destination}</p><p role="status" className="break-words text-xs text-muted-foreground">{state}</p><p className="text-xs text-muted-foreground">{f.persistent?'Persistent rule':`Temporary CLI session · stop with porthub usb stop ${f.id.slice(0,12)}`}</p></li>;})}</ul>
  <details className="text-xs text-muted-foreground"><summary className="min-h-11 cursor-pointer py-3">CLI and client permissions</summary><div className="space-y-3"><p>List hardware: <code>porthub usb devices</code></p><p>Temporary share: <code>porthub usb expose BUSID --to MACHINE_ID</code>. Add <code>--detach</code> for background operation with restart recovery.</p><p>Attach from this machine: <code>porthub usb attach --from MACHINE_ID --device BUSID</code></p><p>List or stop sessions: <code>porthub usb list</code>, <code>porthub usb stop ID</code>.</p><p>Block USB sharing and attaching locally: <code>porthub features disable usb</code>. The server cannot override this switch.</p></div></details>
 </section>;
}
