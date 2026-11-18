import {useCallback,useEffect,useState} from 'react';
import axios from 'axios';
import {IconRefresh} from '@tabler/icons-react';
import SearchSelect from '@/components/ui/search-select';
import {Button} from '@/components/ui/button';
const canRequest=device=>['permission-unknown','ready'].includes(device?.capture_state);
const labels={'permission-denied':'Permission denied',connecting:'Connecting',starting:'Starting capture',idle:'Waiting for an application',unavailable:'Unavailable',stopped:'Stopped'};
const statusLabel=(state,camera)=>labels[state]||({ready:camera?'Camera input ready':'Microphone input ready',capturing:camera?'Capturing selected camera':'Capturing selected microphone',receiving:camera?'Receiving camera frames':'Receiving microphone audio'}[state])||'Waiting for client report';
export default function NativeMediaForwarding({machineId,active}){
 const [machines,setMachines]=useState([]),[plans,setPlans]=useState([]),[source,setSource]=useState(''),[destination,setDestination]=useState(''),[kind,setKind]=useState('microphone'),[modes,setModes]=useState([]),[error,setError]=useState(''),[busy,setBusy]=useState(false),[available,setAvailable]=useState(true),[notice,setNotice]=useState('');
 const camera=kind==='camera',speaker=kind==='speaker',noun=kind,plural=kind+'s';
 const kindLabel=kind[0].toUpperCase()+kind.slice(1);
 const speakerMode='phs1-speaker-v1';
 const load=useCallback(async()=>{try{const [inventory,forwards]=await Promise.all([axios.get('/api/media/inventory'),axios.get('/api/media/forwards')]);setMachines(inventory.data.machines||[]);setModes(inventory.data.modes||['phm1-microphone-v1']);setPlans(forwards.data.plans||[]);setAvailable(true);setError('');}catch(e){if(e.response?.status===404)setAvailable(false);else setError(e.response?.data?.detail||'Device sharing is unavailable.');}},[]);
 useEffect(()=>{if(!active)return;load();const timer=setInterval(load,15000);return()=>clearInterval(timer);},[active,load]);
 const hostPlans=plans.filter(plan=>plan.source===machineId||plan.destination===machineId);
 const host=machines.find(m=>m.id===machineId),sources=(host?.report?.sources||[]).filter(s=>s.device.kind===kind);
 const chosen=sources.find(s=>`${s.uid}:${s.device.id}`===source),receiver=machines.find(m=>m.id===destination),enabled=!!host?.report?.[kind+'_enabled'];
 const supported=speaker?modes.includes(speakerMode):!camera||modes.includes('phv1-camera-mjpeg-v1')&&host?.report?.protocol===2;
 const sourceReason=host?.report?.[kind+'_unavailable_reason'];
 const eligible=m=>speaker?!!(m.live&&m.report?.receive_enabled&&m.report?.speaker_receiver_available):m.live&&m.report?.receive_enabled&&m.report?.[camera?'camera_receiver_available':'receiver_available']&&m.report?.receiver_identity&&(!camera||m.report?.protocol===2);
 const receiverReason=m=>!m.report?'Update this client to receive devices':!m.live?'Media connection unavailable':!m.report.receive_enabled?'Receiving disabled on this client':speaker?(m.report.speaker_receiver_unavailable_reason||'System playback unavailable'):m.report[camera?'camera_receiver_unavailable_reason':'receiver_unavailable_reason']||(!m.report.receiver_identity?'Receiver setup required':camera?'Camera receiving unavailable':'Microphone receiving unavailable');
 const update=async action=>{setBusy(true);try{await action();await load();}catch(e){setError(e.response?.data?.detail||'Could not update device sharing.');}finally{setBusy(false);}};
 return <section aria-label="Built-in microphone and camera forwarding" className="space-y-4 border-t border-border p-4 sm:p-5 [&_input]:!min-h-[44px]">
  <div><h3 className="text-sm font-semibold">{modes.includes(speakerMode)?'Audio and camera sharing':'Microphone and camera sharing'}</h3><p className="mt-1 text-xs leading-5 text-muted-foreground">{speaker?'Choose where audio from this host’s selected output will play.':'Use a selected input device in applications on another machine. Capture starts when an application opens it.'}</p></div>
  <div className="flex items-center justify-between gap-3">
   <div role="radiogroup" aria-label="Input device type" className="inline-flex max-w-full rounded-lg border border-border bg-control p-1">{(modes.includes(speakerMode)?['microphone','camera','speaker']:['microphone','camera']).map(value=><button key={value} type="button" role="radio" aria-checked={kind===value} disabled={busy} onClick={()=>{setKind(value);setSource('');setDestination('');setNotice('');}} className={`min-h-[44px] rounded-md px-2 sm:px-4 text-sm font-medium transition-colors ${kind===value?'bg-background text-foreground shadow-sm':'text-muted-foreground hover:text-foreground'}`}>{value[0].toUpperCase()+value.slice(1)}</button>)}</div>
   {available&&<Button variant="outline" type="button" aria-label={`Refresh ${plural}`} title={`Refresh ${plural}`} className="min-h-[44px] min-w-[44px] shrink-0 gap-2 px-2 sm:px-3" disabled={busy||!host?.live||!enabled||!supported} onClick={()=>update(async()=>{await axios.post(`/api/media/machines/${machineId}/discover`,{});setNotice('Discovery requested. Keep the desktop session signed in; the source list refreshes automatically.');})}><IconRefresh size={18} aria-hidden="true" /><span className="hidden sm:inline">Refresh {plural}</span></Button>}
  </div>
  {error&&<p role="alert" className="text-xs text-red-500">{error}</p>}{notice&&<p role="status" className="text-xs text-muted-foreground">{notice}</p>}
  {host?.report&&!enabled&&<p className="text-xs text-muted-foreground">Sharing is disabled on this client. Enable it locally with <code>porthub features enable {speaker?'media-receive':camera?'camera-share':'microphone-share'}</code>.</p>}

  {!available?<p className="text-xs text-muted-foreground">Update the gateway and client to enable native device sharing.</p>:!supported?<p className="text-xs text-muted-foreground">Update this client to use camera sharing.</p>:<>
   {!host?.report?<p className="text-xs text-muted-foreground">Update this client to use device sharing.</p>:!host.live?<p className="text-xs text-muted-foreground">The media connection is unavailable. Wait for the client to reconnect.</p>:!sources.length?<p className="text-xs leading-5 text-muted-foreground">{sourceReason||`No desktop ${plural} have been discovered.`} Refresh {plural} to check the optional native adapter in the signed-in desktop session. Discovery does not start capture.</p>:<div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
    <label className="min-w-0 text-xs font-medium">{kindLabel}<SearchSelect label={kindLabel} className="mt-1" value={source} onChange={setSource} placeholder={`Choose a ${noun}`} options={sources.map(s=>({value:`${s.uid}:${s.device.id}`,label:`${s.device.name||`${kindLabel} input`}${canRequest(s.device)?'':` · ${s.device.unavailable_reason||'Unavailable'}`}`, disabled:!canRequest(s.device)}))}/></label>
    <label className="min-w-0 text-xs font-medium">{speaker?'Play audio on':'Use on'}<SearchSelect label={speaker?'Play audio on':'Receiving machine'} className="mt-1" value={destination} onChange={setDestination} placeholder="Choose a receiving machine" options={machines.filter(m=>m.id!==machineId).map(m=>({value:m.id,label:`${m.name}${eligible(m)?'':` · ${receiverReason(m)}`}`, disabled:!eligible(m)}))}/></label>
    <Button type="button" className="min-h-[44px] px-5 sm:col-span-2 sm:justify-self-start" disabled={busy||!host?.live||!enabled||!chosen||!canRequest(chosen.device)||!eligible(receiver||{})} onClick={()=>update(()=>axios.post('/api/media/forwards',{source:machineId,destination,desktop_uid:chosen.uid,desktop_session:chosen.desktop_session||null,source_id:chosen.device.id,mode:speaker?speakerMode:camera?'phv1-camera-mjpeg-v1':'phm1-microphone-v1',name:Array.from(`${host?.name||'Source'} · ${chosen.device.name||noun}`).slice(0,60).join(''),persistent:true}))}>{speaker?'Forward audio':`Share ${noun}`}</Button>
   </div>}
   {hostPlans.length>0&&<div>
    <h4 className="mb-1 text-xs font-semibold">Shared devices</h4>
    <ul className="divide-y divide-border border-y border-border">
     {hostPlans.map(plan=>{
      const endpoints=[plan.source,plan.destination].map(id=>machines.find(m=>m.id===id));
      const playback=plan.mode===speakerMode;
      const states=endpoints.map(endpoint=>playback?({receiving:'Playing audio',capturing:'Sending system audio',ready:'Ready'}[endpoint?.report?.states?.find(s=>s.id===plan.id)?.state]||labels[endpoint?.report?.states?.find(s=>s.id===plan.id)?.state]||'Waiting for client report'):statusLabel(endpoint?.report?.states?.find(s=>s.id===plan.id)?.state,plan.mode==='phv1-camera-mjpeg-v1'));
      return <li key={plan.id} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 py-2.5">
       <div className="min-w-0">
        <p className="break-words text-sm font-medium">{plan.name}</p>
        <p className="mt-0.5 break-words text-xs text-muted-foreground">{playback?`Audio from ${endpoints[0]?.name||plan.source} → ${endpoints[1]?.name||plan.destination}`:`${endpoints[0]?.name||'Source'} → ${endpoints[1]?.name||'Receiver'}`}</p>
        <div className="mt-1 flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-xs text-muted-foreground">
         <span role="status" className="break-words font-medium text-foreground">{Array.from(new Set(states)).join(' · ')}</span>
         <span>{plan.persistent?'Persistent configuration':'Temporary CLI session'}{!playback&&' · Capture follows application use'}</span>
        </div>
       </div>
       <Button variant="outline" title={`Remove ${plan.name} share`} className="min-h-[44px] shrink-0" disabled={busy} onClick={()=>update(()=>axios.delete(`/api/media/forwards/${plan.id}`))}>Remove</Button>
      </li>;
     })}
    </ul>
   </div>}
   {!speaker&&<details className="text-xs leading-5 text-muted-foreground"><summary className="min-h-[44px] cursor-pointer py-3">Receiver setup and local permissions</summary><p>Receiver setup: run <code>porthub media receiver-identity --vendor VID --product PID</code> locally. <a href="https://github.com/algofly-oss/porthub/blob/main/docs/native-media-forwarding.md" className="underline underline-offset-2" target="_blank" rel="noreferrer">Setup instructions</a>.</p><p className="mt-2">Microphone, camera and receiving permissions are independent of keyboard and raw USB sharing. Disable them locally with <code>porthub features disable microphone-share</code>, <code>porthub features disable camera-share</code> or <code>porthub features disable media-receive</code>. The gateway cannot override them.</p></details>}
  </>}
 </section>;
}
