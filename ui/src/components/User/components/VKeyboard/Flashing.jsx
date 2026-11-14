import { useEffect,useRef,useState } from 'react';
import axios from 'axios';
import toast from 'react-hot-toast';
import { IconUsb,IconRefresh } from '@tabler/icons-react';
import { BoardLink,flashBoard } from '@/lib/keyboardFlash.mjs';
const button='min-h-11 rounded-lg border border-border px-4 text-sm font-medium hover:bg-control disabled:opacity-40';
const input='mt-1 block h-11 w-full rounded-lg border border-input bg-background px-3 text-sm text-foreground outline-none focus:border-primary';
export default function Flashing({active,onRegistered}){
  const [supported,setSupported]=useState(false),[port,setPort]=useState(null),[info,setInfo]=useState(null),[status,setStatus]=useState(null),[firmware,setFirmware]=useState([]),[chip,setChip]=useState('esp32c3'),[name,setName]=useState('PortHub keyboard'),[ssid,setSsid]=useState(''),[password,setPassword]=useState(''),[networks,setNetworks]=useState([]),[busy,setBusy]=useState(false),[message,setMessage]=useState(''),[progress,setProgress]=useState(null),[keep,setKeep]=useState(true),[target,setTarget]=useState(null);
  const link=useRef(null),portRef=useRef(null),busyRef=useRef(false),mounted=useRef(true);
  useEffect(()=>{mounted.current=true;setSupported('serial'in navigator);return()=>{mounted.current=false;if(!busyRef.current)void link.current?.close();};},[]);
  useEffect(()=>{if(!active)return;void axios.get('/api/keyboard/firmware').then(({data})=>setFirmware(data.images)).catch(()=>setMessage('Could not load firmware.'));},[active]);
  const event=value=>{if(!mounted.current)return;if(value.ev==='status')setStatus(value);if(value.ev==='info'){setInfo(value);setChip(value.chip);if(value.ssid)setSsid(value.ssid);if(value.name)setName(value.name);}};
  const open=async chosen=>{const next=new BoardLink(chosen,event);await next.open();link.current=next;portRef.current=chosen;setPort(chosen);let found=null;for(let i=0;i<4;i++){try{found=await next.request({cmd:'info'},'info',900);break;}catch{}}setInfo(found);return next;};
  const disconnect=async()=>{await link.current?.close();link.current=null;portRef.current=null;setPort(null);setInfo(null);setStatus(null);};
  const connect=async()=>{let chosen;try{chosen=await navigator.serial.requestPort();}catch{return;}setBusy(true);try{await disconnect();await open(chosen);setMessage('USB connected. Choose firmware and configure your board.');}catch{setMessage('Could not open the USB port. Close other serial monitors and reconnect the board.');}finally{setBusy(false);}};
  const action=async fn=>{setBusy(true);busyRef.current=true;setMessage('');try{await fn();}catch(error){setMessage(error.message||'Board action failed');}finally{busyRef.current=false;if(mounted.current)setBusy(false);else void link.current?.close();}};
  const configure=async()=>{
    if(!ssid.trim()||new TextEncoder().encode(ssid).length>32)throw Error('Enter a Wi-Fi name of up to 32 bytes.');
    if(new TextEncoder().encode(password).length>63)throw Error('Wi-Fi password is too long.');
    if(!name.trim()||new TextEncoder().encode(name).length>40)throw Error('Use a Bluetooth name up to 40 bytes.');
    let enrollment=target;
    const saved=new URL(info?.server||window.location.origin,window.location.origin);
    const savedId=saved.origin===window.location.origin?saved.pathname.match(/^\/api\/keyboard\/device\/(board-[a-f0-9-]+)$/)?.[1]:null;
    if(!enrollment&&savedId&&info?.has_token){const {data}=await axios.get('/api/keyboard/targets');if(data.targets.some(t=>t.id===savedId))enrollment={id:savedId};}
    if(!enrollment){const {data}=await axios.post('/api/keyboard/devices',{name:name.trim()});enrollment=data;setTarget(data);}
    const config={cmd:'config',server:`${window.location.origin}/api/keyboard/device/${enrollment.id}`,ssid:ssid.trim(),name:name.trim()};
    if(enrollment.token)config.token=enrollment.token;
    else await axios.patch(`/api/keyboard/devices/${enrollment.id}`,{name:name.trim()});
    if(password||!info?.has_pass)config.pass=password;
    await link.current.request(config);setPassword('');setTarget(null);setMessage('Settings saved. Pair the Bluetooth device, then select it in VKeyboard.');await onRegistered?.();
    try{await link.current.request({cmd:'status'},'status');}catch{}
  };
  const flash=async()=>{
    const image=firmware.find(f=>f.chip===chip);if(!image)throw Error('Firmware for this chip is not installed on the server.');
    const chosen=portRef.current;await link.current.close();link.current=null;setProgress(0);setMessage('Flashing firmware. Keep this tab open and the USB cable connected.');
    try{await flashBoard(chosen,image,{keepSettings:keep,progress:setProgress});}finally{setProgress(null);}
    // Native-USB boards may re-enumerate; use only ports already granted by the user.
    let reopened=false;for(let i=0;i<20&&!reopened;i++){await new Promise(r=>setTimeout(r,500));const ports=await navigator.serial.getPorts();for(const candidate of [chosen,...ports.filter(p=>p!==chosen&&p.getInfo().usbVendorId===chosen.getInfo().usbVendorId&&p.getInfo().usbProductId===chosen.getInfo().usbProductId)]){try{await open(candidate);reopened=true;break;}catch{}}}
    if(!reopened)throw Error('Firmware installed. Reconnect the USB board to save Wi-Fi settings.');
    setMessage('Firmware installed. Save your Wi-Fi and PortHub settings below.');
  };
  return <section aria-label="Flash a Bluetooth keyboard" className="rounded-xl border border-border bg-surface p-4 sm:p-5">
    <header className="mb-5"><h2 className="flex items-center gap-2 text-sm font-medium"><IconUsb size={18}/>Bluetooth keyboard board</h2><p className="mt-1 text-sm text-muted-foreground">Flash an ESP32 or ESP32-C3, connect it to Wi-Fi, then pair it with the computer, tablet, or phone you want to control.</p></header>
    {!supported&&<p className="mb-4 text-sm text-muted-foreground">USB flashing requires Chrome or Edge on a computer over HTTPS. Keyboard and mouse control remain available in other browsers.</p>}
    <div className="flex flex-wrap gap-3"><button type="button" className={button} onClick={connect} disabled={!supported||busy}>{port?'Choose another USB board':'Connect USB board'}</button>{port&&<button type="button" disabled={busy} className={button} onClick={disconnect}>Disconnect USB</button>}</div>
    {port&&<div className="mt-5 space-y-5"><p className="text-xs text-muted-foreground">{info?`${info.chip.toUpperCase()} · ${info.mac} · firmware ${info.version}`:'No PortHub firmware detected. Install firmware first.'}</p>
      <div className="flex flex-wrap items-end gap-3"><label className="text-xs text-muted-foreground">Board chip<select className={input} value={chip} disabled={busy||!!info} onChange={e=>setChip(e.target.value)}><option value="esp32c3">ESP32-C3</option><option value="esp32">ESP32</option></select></label><button type="button" className={button} disabled={busy||!firmware.some(f=>f.chip===chip)} onClick={()=>action(flash)}>{info?'Update firmware':'Install firmware'}</button><label className="flex min-h-11 items-center gap-2 text-xs"><input type="checkbox" checked={keep} onChange={e=>setKeep(e.target.checked)} disabled={busy}/>Preserve saved settings and Bluetooth pairing</label></div>
      <form onSubmit={e=>{e.preventDefault();void action(configure);}} className="grid gap-3 sm:grid-cols-2"><label className="text-xs text-muted-foreground">Bluetooth name<input className={input} maxLength={40} value={name} onChange={e=>setName(e.target.value)} required disabled={busy||!info}/></label>
        <label className="text-xs text-muted-foreground">Wi-Fi network<input className={input} list="keyboard-wifi-networks" value={ssid} onChange={e=>setSsid(e.target.value)} required disabled={busy||!info}/><datalist id="keyboard-wifi-networks">{networks.map(n=><option key={n.ssid} value={n.ssid}/>)}</datalist></label>
        <label className="text-xs text-muted-foreground">Wi-Fi password<input className={input} type="password" autoComplete="new-password" value={password} onChange={e=>setPassword(e.target.value)} placeholder={info?.has_pass?'Leave blank to retain password':'Open network if blank'} disabled={busy||!info}/></label>
        <div className="flex flex-wrap items-end gap-2"><button type="button" disabled={busy||!info} className={button} onClick={()=>action(async()=>{const data=await link.current.request({cmd:'scan'},'scan',20000);setNetworks(data.networks||[]);setMessage('Wi-Fi scan complete. Choose a network in the network field.');})}>Scan Wi-Fi</button><button type="submit" className={`${button} bg-primary text-primary-foreground`} disabled={busy||!info}>Save board settings</button></div>
      </form>
      {status&&<p className="text-xs text-muted-foreground" role="status">Wi-Fi: {status.wifi} · PortHub: {status.server} · Bluetooth: {status.ble}</p>}
      {info&&<div className="flex flex-wrap gap-2"><button type="button" disabled={busy} className={button} onClick={()=>action(async()=>{const s=await link.current.request({cmd:'status'},'status');setStatus(s);})}>Check connection</button><button type="button" disabled={busy} className={button} onClick={()=>action(async()=>{await link.current.request({cmd:'type',text:'PortHub keyboard test'});setMessage('Test text queued over Bluetooth.');})}>Type test text</button></div>}
    </div>}
    {progress!==null&&<progress className="mt-4 w-full accent-blue-600" aria-label="Firmware flashing progress" max={1} value={progress}/>}
    {message&&<p className="mt-4 text-sm text-muted-foreground" role="status">{message}</p>}
  </section>;
}
