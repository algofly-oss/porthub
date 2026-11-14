import { useEffect, useRef, useState } from "react";
import { IconKeyboard, IconPointer } from "@tabler/icons-react";
const button="min-h-[44px] min-w-[36px] rounded-md border border-border bg-background px-2 text-sm hover:bg-control focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary disabled:opacity-40";
const special={Enter:'enter',Escape:'escape',Backspace:'backspace',Delete:'delete',Tab:'tab',' ':'space',ArrowUp:'up',ArrowDown:'down',ArrowLeft:'left',ArrowRight:'right',Home:'home',End:'end',PageUp:'pageup',PageDown:'pagedown',Control:'ctrl',Alt:'alt',Shift:'shift',Meta:'meta',CapsLock:'capslock','+':'plus'};
export function keyName(event){const key=special[event.key]||event.key.toLowerCase();return /^[!-~]$|^f(?:[1-9]|1[012])$/.test(key)||special[event.key]?key:null;}
export function Keyboard({send,connected}) {
  const [modifiers,setModifiers]=useState([]);const [functionKeys,setFunctionKeys]=useState(false);
  const held=useRef(new Map());
  const release=()=>{held.current.clear();if(connected)send({type:'release_all'});};
  useEffect(()=>{if(!connected){setModifiers([]);held.current.clear();}},[connected]);
  useEffect(()=>{const blur=()=>release();window.addEventListener('blur',blur);return()=>window.removeEventListener('blur',blur);});
  const press=key=>{send({type:'key',key:[...modifiers,key].join('+'),state:'press'});setModifiers([]);};
  return <section aria-label="Remote keyboard" className="rounded-xl border border-border bg-surface p-4 sm:p-5">
    <div className="mb-4 flex flex-wrap items-center justify-between gap-2"><h2 className="flex items-center gap-2 text-sm font-medium"><IconKeyboard size={18}/>Keyboard</h2><label className="flex min-h-11 items-center gap-2 text-xs text-muted-foreground"><input type="checkbox" checked={functionKeys} onChange={e=>setFunctionKeys(e.target.checked)}/>Function keys</label></div>
    <div className="space-y-1.5" role="group" aria-label="Virtual keyboard">
      {functionKeys&&<div className="grid grid-cols-6 gap-1 sm:grid-cols-12">{Array.from({length:12},(_,i)=>`f${i+1}`).map(key=><button type="button" disabled={!connected} key={key} className={button} onClick={()=>press(key)}>{key.toUpperCase()}</button>)}</div>}
      {['1234567890','qwertyuiop','asdfghjkl','zxcvbnm'].map((row,i)=><div key={row} className={`flex justify-center gap-1 ${i===2?'px-2 sm:px-4':i===3?'px-4 sm:px-8':''}`}>
        {[...row].map(key=><button type="button" key={key} aria-label={`Send ${key}`} disabled={!connected} className={`${button} flex-1 !min-w-0 !px-0.5`} onClick={()=>press(key)}>{key.toUpperCase()}</button>)}
      </div>)}
      <div className="grid grid-cols-8 gap-1">{['-','=','/','.',',',':','_','@'].map(char=><button type="button" key={char} disabled={!connected} className={button} onClick={()=>send({type:'text',text:char})}>{char}</button>)}</div>
      <div className="grid grid-cols-4 gap-1">{[['ctrl','Ctrl'],['alt','Alt'],['shift','Shift'],['meta','⌘ / Win']].map(([key,label])=><button type="button" disabled={!connected} key={key} aria-pressed={modifiers.includes(key)} className={`${button} ${modifiers.includes(key)?'border-primary bg-primary/10 text-primary':''}`} onClick={()=>setModifiers(m=>m.includes(key)?m.filter(k=>k!==key):[...m,key])}>{label}</button>)}</div>
      <div className="grid grid-cols-4 gap-1">{[['escape','Esc'],['tab','Tab'],['backspace','⌫'],['delete','Delete']].map(([key,label])=><button type="button" disabled={!connected} key={key} className={button} onClick={()=>press(key)}>{label}</button>)}</div>
      <div className="grid grid-cols-4 gap-1"><button type="button" disabled={!connected} className={`${button} col-span-2`} onClick={()=>press('space')}>Space</button><button type="button" disabled={!connected} className={`${button} col-span-2`} onClick={()=>press('enter')}>Enter</button></div>
      <div className="grid grid-cols-4 gap-1">{[['left','←'],['up','↑'],['down','↓'],['right','→']].map(([key,label])=><button type="button" aria-label={`Arrow ${key}`} disabled={!connected} key={key} className={button} onClick={()=>press(key)}>{label}</button>)}</div>
    </div>
    <div role="textbox" tabIndex={connected?0:-1} aria-label="Capture physical keyboard" aria-disabled={!connected} className="mt-4 rounded-lg border border-dashed border-border p-3 text-center text-xs text-muted-foreground outline-none focus:border-primary focus:bg-primary/5"
      onKeyDown={e=>{if(!connected)return;const key=keyName(e);if(!key)return;e.preventDefault();if(e.repeat)return;held.current.set(e.code,key);send({type:'key',key,state:'down'});}}
      onKeyUp={e=>{const key=held.current.get(e.code);if(!key)return;e.preventDefault();held.current.delete(e.code);send({type:'key',key,state:'up'});}} onBlur={release}>
      Click here to send your physical keyboard. Click outside to stop.
    </div>
  </section>;
}
export function Touchpad({send,connected}) {
  const pointers=useRef(new Map()),motion=useRef({dx:0,dy:0}),frame=useRef(),held=useRef(new Set());const [reverse,setReverse]=useState(false);
  const move=(dx,dy)=>{motion.current.dx+=dx;motion.current.dy+=dy;if(frame.current)return;frame.current=requestAnimationFrame(()=>{frame.current=null;const {dx,dy}=motion.current;motion.current={dx:0,dy:0};if(dx||dy)send({type:'pointer',action:'move',dx:Math.max(-4000,Math.min(4000,Math.round(dx))),dy:Math.max(-4000,Math.min(4000,Math.round(dy)))});});};
  const release=()=>{pointers.current.clear();for(const button of held.current)send({type:'pointer',action:'release',button});held.current.clear();};
  useEffect(()=>()=>{cancelAnimationFrame(frame.current);},[]);
  useEffect(()=>{window.addEventListener('blur',release);return()=>window.removeEventListener('blur',release);});
  return <section aria-label="Remote touchpad" className="flex flex-col rounded-xl border border-border bg-surface p-4 sm:p-5">
    <div className="mb-3 flex flex-wrap items-center justify-between gap-2"><h2 className="flex items-center gap-2 text-sm font-medium"><IconPointer size={18}/>Mouse</h2><label className="flex min-h-11 items-center gap-2 text-xs text-muted-foreground"><input type="checkbox" checked={reverse} onChange={e=>setReverse(e.target.checked)}/>Reverse scroll</label></div>
    <div role="application" aria-label="Touchpad: drag to move, tap to click, two fingers to scroll" tabIndex={connected?0:-1} aria-disabled={!connected}
      className={`relative flex min-h-[200px] grow touch-none select-none items-center justify-center overflow-hidden rounded-lg border border-border bg-background p-5 text-center text-xs text-muted-foreground ${connected?'cursor-crosshair':'opacity-50'}`}
      onContextMenu={e=>e.preventDefault()}
      onPointerDown={e=>{if(!connected)return;e.preventDefault();e.currentTarget.setPointerCapture(e.pointerId);pointers.current.set(e.pointerId,{x:e.clientX,y:e.clientY,startX:e.clientX,startY:e.clientY,t:Date.now(),moved:false,multi:pointers.current.size>0});if(pointers.current.size>1)for(const p of pointers.current.values())p.multi=true;}}
      onPointerMove={e=>{const p=pointers.current.get(e.pointerId);if(!p)return;const dx=e.clientX-p.x,dy=e.clientY-p.y;p.moved||=Math.abs(e.clientX-p.startX)+Math.abs(e.clientY-p.startY)>5;p.x=e.clientX;p.y=e.clientY;if(pointers.current.size>1){if(p.moved)send({type:'pointer',action:'scroll',dx:Math.round(dx/12)*(reverse?-1:1),dy:Math.round(dy/12)*(reverse?-1:1)});}else move(dx,dy);}}
      onPointerUp={e=>{const p=pointers.current.get(e.pointerId);if(p&&!p.moved&&!p.multi&&Date.now()-p.t<350)send({type:'pointer',action:'click',button:e.button===2?'right':e.button===1?'middle':'left'});pointers.current.delete(e.pointerId);}}
      onPointerCancel={e=>{pointers.current.delete(e.pointerId);}}
      onWheel={e=>{if(!connected)return;send({type:'pointer',action:'scroll',dx:Math.max(-100,Math.min(100,Math.round(e.deltaX/40)))*(reverse?-1:1),dy:Math.max(-100,Math.min(100,Math.round(e.deltaY/40)))*(reverse?-1:1)});}}
      >Move one finger to point.<br/>Tap to click. Use two fingers or the wheel to scroll.</div>
    <div className="mt-2 grid grid-cols-3 gap-2">{['left','middle','right'].map(button=><button type="button" key={button} disabled={!connected} className={`${buttonClass()} touch-none capitalize`}
      onContextMenu={e=>e.preventDefault()} onPointerDown={e=>{e.preventDefault();e.currentTarget.setPointerCapture(e.pointerId);held.current.add(button);send({type:'pointer',action:'press',button});}}
      onPointerUp={()=>{if(held.current.delete(button))send({type:'pointer',action:'release',button});}}
      onLostPointerCapture={()=>{if(held.current.delete(button))send({type:'pointer',action:'release',button});}}
      onPointerCancel={()=>{if(held.current.delete(button))send({type:'pointer',action:'release',button});}}
      onKeyDown={e=>{if(['Enter',' '].includes(e.key)){e.preventDefault();if(!e.repeat)send({type:'pointer',action:'click',button});}}}>{button}</button>)}</div>
  </section>;
}
function buttonClass(){return button;}
