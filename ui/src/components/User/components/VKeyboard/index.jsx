import { useCallback,useEffect,useMemo,useRef,useState } from 'react';
import axios from 'axios';
import { IconKeyboard,IconRefresh,IconMicrophone,IconPlayerStop,IconPlugConnected,IconPlugConnectedX,IconSettings,IconX,IconPointer,IconClipboard } from '@tabler/icons-react';
import useAuth from '@/shared/hooks/useAuth';
import { KeyboardTransport } from '@/lib/keyboardTransport.mjs';
import { VoiceRecorder } from '@/lib/keyboardRecorder.mjs';
import Controls from './Controls';
import styles from './Surface.module.css';
import Models from './Models';
import Flashing from './Flashing';
import DeviceSettings from './DeviceSettings';
const button='min-h-11 rounded-lg border border-border px-4 text-sm font-medium hover:bg-control disabled:opacity-40 focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary';
const input='mt-1 block h-11 w-full rounded-lg border border-input bg-background px-3 text-sm text-foreground outline-none focus:border-primary';
const names={en:'English',hi:'Hindi',hinglish:'Hinglish (Hindi in Latin letters)',te:'Telugu',ta:'Tamil',kn:'Kannada',ml:'Malayalam',mr:'Marathi',gu:'Gujarati',bn:'Bengali',pa:'Punjabi',ur:'Urdu',es:'Spanish',fr:'French',de:'German',ja:'Japanese',zh:'Chinese',ko:'Korean',auto:'Detect language'};
export default function VKeyboard({active=true}){
  const {user}=useAuth();const isAdmin=user?.role==='admin';
  const [targets,setTargets]=useState([]),[selected,setSelected]=useState(''),[connection,setConnection]=useState({state:'disconnected'}),[error,setError]=useState(''),[status,setStatus]=useState(null),[text,setText]=useState(''),[recording,setRecording]=useState(false),[processing,setProcessing]=useState(false),[level,setLevel]=useState(0),[language,setLanguage]=useState('en'),[translate,setTranslate]=useState(false),[live,setLive]=useState(true),[after,setAfter]=useState('space'),[failedAudio,setFailedAudio]=useState(null),[loading,setLoading]=useState(false);
  const transport=useRef(null),recorder=useRef(null),queue=useRef(Promise.resolve()),pending=useRef(0),alive=useRef(true),latest=useRef({});
  latest.current={live,after,language,translate,active,connected:connection.state==='connected'};
  const refresh=useCallback(async()=>{setLoading(true);try{const {data}=await axios.get('/api/keyboard/targets');if(alive.current){setTargets(data.targets);setSelected(current=>current||data.targets.find(t=>t.online)?.id||data.targets[0]?.id||'');}}catch(e){if(alive.current)setError(e.response?.data?.detail||'Could not load keyboard clients');}finally{if(alive.current)setLoading(false);}},[]);
  const stop=useCallback(async()=>{const current=recorder.current;recorder.current=null;setRecording(false);await current?.stop();},[]);
  const speechEnabled=status?.settings.enabled;
  useEffect(()=>{if(speechEnabled===false&&recorder.current){const current=recorder.current;recorder.current=null;setRecording(false);void current.stop(false);}},[speechEnabled]);
  const disconnect=useCallback(()=>{void stop();transport.current?.close();transport.current=null;setConnection({state:'disconnected'});},[stop]);
  useEffect(()=>{alive.current=true;return()=>{alive.current=false;void recorder.current?.stop(false);transport.current?.close();};},[]);
  useEffect(()=>{if(active){void refresh();}else{disconnect();setText('');setFailedAudio(null);}},[active,refresh,disconnect]);
  useEffect(()=>{if(!active)return;const hidden=()=>{if(document.hidden){void stop();void transport.current?.send({type:'release_all'}).catch(()=>{});}};document.addEventListener('visibilitychange',hidden);return()=>document.removeEventListener('visibilitychange',hidden);},[active,stop]);
  const send=useCallback(command=>{const promise=transport.current?.send(command)||Promise.reject(Error('Connect to a client first'));return promise.catch(e=>{if(alive.current)setError(e.message);});},[]);
  const target=targets.find(t=>t.id===selected),connected=connection.state==='connected';
  const connect=()=>{disconnect();setError('');setConnection({state:'connecting'});const next=new KeyboardTransport({target:selected,changed:update=>{if(alive.current)setConnection(c=>({...c,...update}));},failed:message=>{if(alive.current){setError(message);void stop();}}});transport.current=next;next.connect();};
  const transcribe=async(bytes,settings)=>{
    const {data}=await axios.post(`/api/keyboard/speech/transcribe?language=${encodeURIComponent(settings.language==='hinglish'?'hi':settings.language)}&romanize=${['en','hinglish'].includes(settings.language)?'true':'false'}&translate=${settings.translate?'true':'false'}`,bytes,{headers:{'Content-Type':'application/octet-stream'},timeout:180000});
    if(!alive.current||!latest.current.active)return;
    if(!data.text)return;
    const suffix=settings.after==='space'?' ':settings.after==='newline'?'\n':'';
    setText(old=>(old+data.text+suffix).slice(-8192));
    if(settings.live&&latest.current.connected&&transport.current===settings.transport&&transport.current.session===settings.session){await transport.current.send({type:'text',text:data.text+suffix});}
    const response=await axios.get('/api/keyboard/speech');if(alive.current)setStatus(response.data);
  };
  const segment=bytes=>{
    if(pending.current>=3){setError('Transcription is falling behind. Recording paused; wait for queued speech.');void stop();return;}
    const settings={...latest.current,transport:transport.current,session:transport.current?.session};pending.current++;setProcessing(true);
    queue.current=queue.current.then(()=>transcribe(bytes,settings)).catch(e=>{if(alive.current){setFailedAudio({bytes,settings});setError(e.response?.data?.detail||e.message||'Transcription failed. Your last audio segment is available to retry.');}}).finally(()=>{pending.current--;if(alive.current)setProcessing(pending.current>0);});
  };
  const start=async()=>{
    setError('');if(!navigator.mediaDevices?.getUserMedia){setError('Microphone recording requires HTTPS or localhost.');return;}
    const next=new VoiceRecorder({segment,level:setLevel,failed:message=>{setError(message);setRecording(false);}});recorder.current=next;
    try{await next.start();if(recorder.current===next)setRecording(true);}catch(e){setError(e.name==='NotAllowedError'?'Microphone permission was denied. Allow it in your browser settings.':e.message);recorder.current=null;setRecording(false);}
  };
  const model=status?.models?.find(m=>m.id===status.settings.model);
  const languages=useMemo(()=>model?[...(model.auto_language?['auto']:[]),...model.languages,...(model.languages.includes('hi')?['hinglish']:[])]:['en'],[model]);
  useEffect(()=>{if(model&&!languages.includes(language))setLanguage(model.languages.includes('en')?'en':model.languages[0]);if(model&&!model.translate)setTranslate(false);},[model,languages,language]);
  const clientAction=async type=>{try{transport.current.device(type==='pairing'?{type,seconds:120}:type==='bluetooth'?{type,on:true}:{type});}catch(e){setError(e.message);}};
  const [sheet,setSheet]=useState('general'),[padView,setPadView]=useState(false),[preferences,setPreferences]=useState({touchpad:true,mouseButtons:true,functionKeys:false,reverseScroll:false});
  const dialog=useRef(null),dragStart=useRef(null);
  useEffect(()=>{try{const saved=JSON.parse(localStorage.getItem('porthub.keyboard.preferences')||'{}');setPreferences(current=>({...current,...Object.fromEntries(Object.entries(saved).filter(([key,value])=>['touchpad','mouseButtons','functionKeys','reverseScroll'].includes(key)&&typeof value==='boolean'))}));setPadView(localStorage.getItem('porthub.keyboard.padView')==='true');}catch{}},[]);
  const preference=(key,value)=>setPreferences(current=>{const next={...current,[key]:value};try{localStorage.setItem('porthub.keyboard.preferences',JSON.stringify(next));}catch{}return next;});
  const openSheet=tab=>{setSheet(tab);void transport.current?.send({type:'release_all'}).catch(()=>{});dialog.current?.showModal();};
  useEffect(()=>{if(!active)dialog.current?.close();},[active]);
  const micDisabled=!recording&&(!status?.settings.enabled||!model?.installed||processing);
  const speechMessage=recording?'Listening…':processing?'Transcribing…':!status?.settings.enabled?'Dictation off':!model?.installed?'Choose a dictation model in Settings':'Ready';
  return <div className="relative h-full min-h-0" aria-label="VKeyboard content">
    <Controls send={send} connected={connected} preferences={preferences} platform={target?.platform} microphone={()=>{if(!micDisabled)recording?stop():start();}} padView={padView}
      header={<header className={styles.header}>
        <select aria-label="Keyboard client" value={selected} disabled={connected||connection.state==='connecting'} onChange={e=>{disconnect();setSelected(e.target.value);setError('');}}><option value="" disabled>Choose a client</option>{targets.map(t=><option key={t.id} value={t.id}>{t.name}{t.online?'':' · Offline'}</option>)}</select>
        <button type="button" title={connected?`Disconnect · ${connection.route==='local'?'Local connection':'Gateway relay'}`:'Connect'} aria-label={connected?'Disconnect':connection.state==='connecting'?'Connecting…':'Connect'} className={`${styles.iconButton} ${connected?styles.connected:''}`} disabled={!selected||!target?.online||connection.state==='connecting'} onClick={connected?disconnect:connect}>{connected?<IconPlugConnectedX size={20}/>:<IconPlugConnected size={20}/>}</button>
        <button type="button" aria-label={padView?'Show the keyboard':'Show the touchpad'} className={styles.iconButton} onClick={()=>setPadView(current=>{try{localStorage.setItem('porthub.keyboard.padView',String(!current));}catch{}return !current;})}>{padView?<IconKeyboard size={20}/>:<IconPointer size={20}/>}</button>
        <button type="button" aria-label="Text and clipboard" className={styles.iconButton} onClick={()=>openSheet('text')}><IconClipboard size={20}/></button>
        <button type="button" aria-label="VKeyboard settings" className={styles.iconButton} onClick={()=>openSheet('general')}><IconSettings size={20}/></button>
      </header>}
      caption={<div className={styles.caption}>
        <button type="button" className={styles.captionText} onClick={()=>openSheet(text?'text':'models')} title={text||speechMessage}>{text||speechMessage}</button>
        {recording&&<meter aria-label="Microphone level" min={0} max={1} value={level} className="h-2 w-12"/>}
        <button type="button" aria-label={recording?'Stop recording':'Start dictation'} disabled={micDisabled} className={`${styles.mic} ${recording?styles.recording:''}`} onClick={()=>recording?stop():start()}>{recording?<IconPlayerStop size={20}/>:<IconMicrophone size={20}/>}</button>
      </div>}/>
    {error&&<div role="alert" className={styles.alert}><span>{error}</span><button type="button" aria-label="Dismiss error" onClick={()=>setError('')}><IconX size={20}/></button></div>}
    <dialog ref={dialog} className={styles.sheet} aria-label="VKeyboard settings" onClose={()=>document.querySelector('[aria-label="Capture physical keyboard"]')?.focus({preventScroll:true})} onClick={e=>{if(e.target===dialog.current)dialog.current.close();}}>
      <div className={styles.sheetContent}>
        <div className={styles.grip} onPointerDown={e=>{dragStart.current=e.clientY;e.currentTarget.setPointerCapture(e.pointerId);}} onPointerMove={e=>{if(dragStart.current!==null)dialog.current.style.transform=`translateY(${Math.max(0,e.clientY-dragStart.current)}px)`;}} onPointerUp={e=>{if(dragStart.current!==null&&e.clientY-dragStart.current>110)dialog.current.close();dragStart.current=null;dialog.current.style.transform='';}} onPointerCancel={()=>{dragStart.current=null;dialog.current.style.transform='';}}><span/></div>
        <header className={styles.sheetHeader}><h2>VKeyboard</h2><button type="button" className={styles.iconButton} aria-label="Close VKeyboard settings" onClick={()=>dialog.current.close()}><IconX size={20}/></button></header>
        <div role="tablist" aria-label="VKeyboard settings sections" className={styles.tabs}>{[['general','General'],['clients','Clients'],['models','Models'],['text','Text'],['flash','Flash']].map(([key,label])=><button type="button" role="tab" key={key} aria-selected={sheet===key} aria-controls={`keyboard-panel-${key}`} id={`keyboard-tab-${key}`} onClick={()=>setSheet(key)}>{label}</button>)}</div>
        <div className={styles.sheetBody}>
          <section id="keyboard-panel-general" role="tabpanel" aria-labelledby="keyboard-tab-general" hidden={sheet!=='general'} className="space-y-4 p-2">
            <h3 className="text-sm font-medium">Controls</h3>
            {Object.entries({touchpad:'Touchpad',mouseButtons:'Mouse buttons',functionKeys:'Function keys',reverseScroll:'Reverse scrolling'}).map(([key,label])=><label key={key} className="flex min-h-11 items-center justify-between gap-4 text-sm">{label}<input type="checkbox" checked={preferences[key]} onChange={e=>preference(key,e.target.checked)}/></label>)}
            <p className="text-xs text-muted-foreground">Tap to click. Two fingers scroll or tap to right-click. Tap, then touch and move to drag. Hold a mouse button for precise dragging.</p>
            <p className="text-xs text-muted-foreground">Tap Ctrl, Alt or Shift for the next key; hold for combinations. Double-tap Shift to lock capitals. Hold arrows or Backspace to repeat.</p>
            <h3 className="pt-2 text-sm font-medium">Dictation</h3>
<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"><label className="text-xs text-muted-foreground">Language<select aria-label="Dictation language" className={input} value={language} disabled={recording} onChange={e=>setLanguage(e.target.value)}>{languages.map(value=><option value={value} key={value}>{names[value]||value.toUpperCase()}</option>)}</select></label><label className="text-xs text-muted-foreground">After each segment<select className={input} value={after} disabled={recording} onChange={e=>setAfter(e.target.value)}><option value="space">Space</option><option value="none">Nothing</option><option value="newline">New line (Enter)</option></select></label><label className="flex min-h-11 items-center gap-2 self-end text-sm"><input type="checkbox" checked={live} onChange={e=>setLive(e.target.checked)} disabled={recording}/>Type while dictating</label><label className="flex min-h-11 items-center gap-2 self-end text-sm"><input type="checkbox" checked={translate} disabled={recording||!model?.translate} onChange={e=>setTranslate(e.target.checked)}/>Translate to English</label></div>

          </section>
          <section id="keyboard-panel-clients" role="tabpanel" aria-labelledby="keyboard-tab-clients" hidden={sheet!=='clients'} className="space-y-3 p-2">
            <button type="button" className={button} disabled={loading} onClick={refresh}><IconRefresh size={18} className="mr-2 inline"/>Refresh keyboard clients</button>
            <p role="status" className="text-xs text-muted-foreground">{connected?`Connected to ${target?.name}. ${connection.route==='local'?'Local connection':'Gateway relay'}.${connection.bluetooth?` Bluetooth: ${connection.bluetooth}.`:''}`:'Local connections are discovered without changing this page’s URL.'}</p>
{target&&!target.online&&<div className="mt-3 rounded-lg bg-background p-3 text-xs text-muted-foreground">{target.kind==='esp32'?'Connect the board to Wi-Fi and check its PortHub settings.':<>On this machine’s desktop, run <code className="select-all rounded bg-control px-1.5 py-1 font-mono text-foreground">porthub keyboard enable --registration {selected}</code>. The updated agent is required. A local disable always blocks server control.</>}</div>}
        {target?.kind==='esp32'&&<DeviceSettings key={target.id} target={target} disconnect={disconnect} refresh={refresh} onError={setError}/>}
        {connected&&target?.kind==='esp32'&&<div className="mt-3 flex flex-wrap gap-2"><button type="button" className={button} onClick={()=>clientAction('pairing')}>Pair another Bluetooth device</button><button type="button" className={button} onClick={()=>clientAction('bluetooth')}>Enable Bluetooth</button><button type="button" className={button} onClick={()=>{try{transport.current.device({type:'bluetooth',on:false});}catch(e){setError(e.message);}}}>Disconnect Bluetooth</button></div>}
          </section>
          <div id="keyboard-panel-text" role="tabpanel" aria-labelledby="keyboard-tab-text" hidden={sheet!=='text'}><section aria-label="Text and clipboard" className="rounded-xl border border-border bg-surface p-4 sm:p-5"><div className="mb-3 flex flex-wrap items-center justify-between gap-2"><h2 className="text-sm font-medium">Text & clipboard</h2><span className="text-xs text-muted-foreground">{new TextEncoder().encode(text).length} / 8192 bytes</span></div><label className="sr-only" htmlFor="keyboard-text">Text to send to the selected client</label><textarea id="keyboard-text" value={text} maxLength={8192} onChange={e=>setText(e.target.value)} placeholder="Paste a link, instructions, or a command here…" className="min-h-[120px] w-full resize-y rounded-lg border border-input bg-background p-3 text-sm text-foreground outline-none focus:border-primary" spellCheck={false}/>
        <div className="mt-3 flex flex-wrap gap-2"><button type="button" disabled={!connected||!text||new TextEncoder().encode(text).length>8192} className={`${button} border-primary bg-primary text-primary-foreground hover:opacity-90`} onClick={()=>send({type:'text',text})}>Type text</button><button type="button" disabled={!connected||!text||!connection.clipboard||new TextEncoder().encode(text).length>8192} className={button} onClick={()=>send({type:'clipboard',text,paste:false})}>Update clipboard</button><button type="button" disabled={!connected||!text||!connection.clipboard||new TextEncoder().encode(text).length>8192} className={button} onClick={()=>send({type:'clipboard',text,paste:true})}>Paste text</button><button type="button" disabled={!connected||!connection.clipboard} className={button} onClick={()=>send({type:'paste'})}>Paste remote clipboard</button><button type="button" className={`${button} ml-auto`} disabled={!text} onClick={()=>setText('')}>Clear text</button></div>
        <p className="mt-3 text-xs text-muted-foreground">Paste text updates the client’s clipboard, then pastes into its focused field. It does not press Enter. {target?.kind==='esp32'?'Bluetooth HID cannot write a system clipboard; use Type text.':''}</p>
      </section>

          {failedAudio&&<button type="button" className={button} disabled={processing} onClick={()=>{const audio=failedAudio;setFailedAudio(null);pending.current++;setProcessing(true);queue.current=queue.current.then(()=>transcribe(audio.bytes,{...audio.settings,live:false})).catch(e=>{setFailedAudio(audio);setError(e.response?.data?.detail||e.message);}).finally(()=>{pending.current--;if(alive.current)setProcessing(pending.current>0);});}}>Retry last audio to text field</button>}
          </div>
          <div id="keyboard-panel-models" role="tabpanel" aria-labelledby="keyboard-tab-models" hidden={sheet!=='models'}><Models active={active} status={status} setStatus={setStatus} isAdmin={isAdmin}/></div>
          <div id="keyboard-panel-flash" role="tabpanel" aria-labelledby="keyboard-tab-flash" hidden={sheet!=='flash'}><Flashing active={active&&sheet==='flash'} onRegistered={refresh}/></div>
        </div>
      </div>
    </dialog>
  </div>;
}
