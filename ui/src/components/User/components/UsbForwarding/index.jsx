import { Button } from '@/components/ui/button';
import SearchDropdown from '@/components/ui/search-dropdown';
import {useCallback,useEffect,useState} from 'react';
import axios from 'axios';
import {matchesSavedUsbDevice,usbLineage,usbOriginLabel} from '@/lib/usbLineage.mjs';
const button='inline-flex items-center justify-center min-h-[44px] rounded-lg border border-border px-3 text-sm hover:bg-control disabled:opacity-40';
const input='mt-2 h-11 w-full rounded-lg border border-border bg-control px-3 text-sm';
export default function UsbForwarding({machineId,active}){
 const [machines,setMachines]=useState([]),[forwards,setForwards]=useState([]),[device,setDevice]=useState(''),[destination,setDestination]=useState(''),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 const load=useCallback(async()=>{try{const [inventory,rules]=await Promise.all([axios.get('/api/usb/inventory'),axios.get('/api/usb/forwards')]);setMachines(inventory.data.machines);setForwards(rules.data.forwards);setError('');}catch(e){setError(e.response?.data?.detail||'Could not load USB forwarding');}},[]);
 useEffect(()=>{if(!active)return;void load();const timer=setInterval(load,10000);return()=>clearInterval(timer);},[active,load]);
 useEffect(()=>{setDevice('');setDestination('');},[machineId]);
 const source=machines.find(m=>m.id===machineId),devices=(source?.report?.devices||[]).filter(d=>!d.blocked?.toLowerCase().includes('usb hub')),owned=!!source;
 const selected=devices.find(d=>d.busid===device),lineage=usbLineage(machines,forwards,machineId,selected);
 const machineName=id=>machines.find(m=>m.id===id)?.name||'Unknown machine';
 const chain=[...(lineage.imported&&!lineage.known?['Original source unknown']:[]),...lineage.path.map(machineName),destination?machineName(destination):'Choose a destination'];
 const outgoing=d=>forwards.filter(f=>f.source===machineId&&matchesSavedUsbDevice(f.device,d)).map(f=>`In use on ${machineName(f.destination)}`).join(' · ');
 const act=async operation=>{setBusy(true);setError('');try{await operation();setDevice('');await load();}catch(e){setError(e.response?.data?.detail||'Could not update USB forwarding');}finally{setBusy(false);}};
 const status=(rule,id)=>machines.find(m=>m.id===id)?.report?.states?.find(s=>s.id===rule.id);
 const hostForwards=forwards.filter(f=>f.source===machineId||f.destination===machineId);
 return <section aria-label="USB forwarding" className="space-y-5 p-4 sm:p-5">
  <div><h3 className="text-sm font-semibold">Share USB from {source?.name || 'this machine'}</h3><p className="mt-2 text-xs text-muted-foreground">Use a USB device on another registered machine. Linux and Windows support sending and receiving; macOS supports sending devices only. Unsupported machines remain visible in the destination list. Add one rule per device. You can forward multiple devices to the same machine or different machines. Saved rules reconnect after restarts and use an authenticated direct path when available.</p></div>
  {error&&<p role="alert" className="text-sm text-red-600 dark:text-red-400">{error}</p>}
  {source&&!source.online&&<p className="text-xs text-muted-foreground">USB module offline. Update and start this machine’s PortHub agent to discover devices.</p>}
  {source?.report?.supported===false&&<p className="text-xs text-muted-foreground">This machine’s operating system does not support the native USB module yet. The native USB backend is unavailable.</p>}
  {source?.report?.enabled===false&&<p className="text-xs text-muted-foreground">USB forwarding is disabled on this client. Enable it locally with <code>porthub features enable usb</code>.</p>}
  {!owned&&machines.length>0&&<p className="text-xs text-muted-foreground">Only the machine owner can configure USB forwarding.</p>}
  {owned&&<div className="space-y-3" role="group" aria-label="Create USB forward">
   <label className="block text-xs text-muted-foreground">Device available on {source?.name || 'this machine'}<SearchDropdown aria-label="USB device" value={device} className={input} onChange={e=>setDevice(e.target.value)} required><option value="">Choose a device</option>{devices.map(d=>{const lineage=usbLineage(machines,forwards,machineId,d),origin=usbOriginLabel(lineage,machines),name=(d.name||`${d.vendor}:${d.product}`),displayName=lineage.imported&&lineage.known?name.replace(/\s*\(forwarded\)\s*$/i,''):name;return <option key={d.busid} value={d.busid} disabled={!!d.blocked||forwards.some(f=>f.source===machineId&&matchesSavedUsbDevice(f.device,d))}>{[origin,displayName,d.busid,outgoing(d),d.blocked].filter(Boolean).join(' · ')}</option>;})}</SearchDropdown></label>
   {source.online&&source.report?.enabled===true&&devices.length===0&&<p role="status" className="text-xs text-muted-foreground">No USB devices are available on this machine. For WSL, first forward the device from the Windows agent to this WSL machine; Windows hardware does not appear in WSL automatically.</p>}
   <label className="block text-xs text-muted-foreground">Use this device on<SearchDropdown aria-label="USB destination machine" value={destination} className={input} onChange={e=>setDestination(e.target.value)} required><option value="">Choose a destination</option>{machines.filter(m=>m.id!==machineId).map(m=><option key={m.id} value={m.id} disabled={m.report?.supported===false||m.report?.can_import===false}>{m.name}{m.report?.can_import===false?' · Cannot receive USB':m.report?.supported===false?' · USB forwarding unsupported':m.online?'':' · Offline'}</option>)}</SearchDropdown></label>
   <div className="rounded-lg border border-border bg-control/40 p-3 text-sm" aria-label="USB forwarding direction"><p className="break-words font-medium">{chain.join(' → ')}</p><p className="mt-1 text-xs text-muted-foreground">{lineage.imported?(lineage.known?`The device is physically connected to ${machineName(lineage.origin)} and forwarded through ${source?.name || 'this machine'}.`:'This is a forwarded device. Its original physical source cannot be verified from the current reports.'):`The device stays physically connected to ${source?.name || 'this machine'}.`} The final destination gets exclusive use.</p>{lineage.imported&&<p className="mt-1 text-xs text-muted-foreground">Onward forwarding supports compatible audio and HID devices, not storage or serial devices. Stop the child forward before its parent.</p>}<p className="mt-1 text-xs text-muted-foreground">Forwarding a storage device does not mount its filesystem automatically.</p></div>
   {devices.some(d=>d.blocked)&&<div className="space-y-1 text-xs text-muted-foreground" aria-label="Unavailable USB devices">{devices.filter(d=>d.blocked).map(d=><p key={d.busid}><span className="font-medium text-foreground">{d.name || d.busid}</span>: {d.blocked}.{d.blocked.toLowerCase().includes('mounted') ? ` Unmount it on ${source?.name || 'the source machine'} before forwarding.` : d.blocked.toLowerCase().includes('hub') ? ' Forward devices connected to this hub individually.' : ''}</p>)}</div>}
   <p className="text-xs text-muted-foreground">While forwarded, the device is controlled by the destination. Mounted disks and active network adapters cannot be shared.</p>
   <Button type="button" onClick={()=>act(()=>axios.post('/api/usb/forwards',{source:machineId,destination,busid:device}))} className="min-h-[44px] px-5" disabled={busy||!device||!destination||!source.online||source.report?.enabled!==true||source.report?.supported!==true||source.report?.can_export===false}>Forward device</Button>
  </div>}
  {hostForwards.length>0&&<div>
   <h4 className="mb-1 text-xs font-semibold">Forwarded USB devices</h4>
   <ul className="divide-y divide-border border-y border-border">
    {hostForwards.map(f=>{
     const sourceState=status(f,f.source),destinationState=status(f,f.destination);
     const active=sourceState?.state?.startsWith('active')&&destinationState?.state?.startsWith('active');
     const state=active?(sourceState.state==='active-direct'?'Direct connection':'Gateway relay'):(sourceState?.error||destinationState?.error||'Waiting for both machines');
     const lineage=usbLineage(machines,forwards,f.source,f.device);
     const route=[...(lineage.imported&&!lineage.known?['Original source unknown']:[]),...lineage.path.map(machineName),machineName(f.destination)].join(' → ');
     const currentDevice=machines.find(m=>m.id===f.source)?.report?.devices?.find(d=>
      matchesSavedUsbDevice(f.device,d)
     );
     const hardwareId=[f.device.vendor,f.device.product].filter(Boolean).join(':');
     const name=currentDevice?.name||f.device.name||(hardwareId?`USB device ${hardwareId}`:`USB port ${f.device.busid}`);
     return <li key={f.id} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 py-2.5">
      <div className="min-w-0">
       <p className="break-words text-sm font-medium">{name}</p>
       <p className="mt-0.5 break-words text-xs text-muted-foreground">{route}</p>
       <div className="mt-1 flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-xs text-muted-foreground">
        <span role="status" className={`break-words ${active?'font-medium text-foreground':''}`}>{state}</span>
        <span>{f.persistent?'Persistent rule':`Temporary CLI session · stop with porthub usb stop ${f.id.slice(0,12)}`}</span>
       </div>
      </div>
      {f.persistent&&<button type="button" className={button} disabled={busy} title={`Remove ${name} forward`} onClick={()=>act(()=>axios.delete(`/api/usb/forwards/${f.id}`))}>Remove</button>}
     </li>;
    })}
   </ul>
  </div>}
  <details className="text-xs text-muted-foreground"><summary className="min-h-[44px] cursor-pointer py-3">CLI and client permissions</summary><div className="space-y-3"><p>List hardware: <code>porthub usb devices</code></p><p>Temporary share: <code>porthub usb expose BUSID --to MACHINE_ID</code>. Add <code>--detach</code> for background operation with restart recovery.</p><p>Attach from this machine: <code>porthub usb attach --from MACHINE_ID --device BUSID</code></p><p>List or stop sessions: <code>porthub usb list</code>, <code>porthub usb stop ID</code>.</p><p>Block USB sharing and attaching locally: <code>porthub features disable usb</code>. The server cannot override this switch.</p></div></details>
 </section>;
}
