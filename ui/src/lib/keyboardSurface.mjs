// VKeyboard's original controls, scoped to one PortHub surface. No network or URL logic.
export function mountKeyboardSurface({root,keyboard,pad,read,command,mic}) {
  let destroyed=false;const emit=command;command=value=>{if(!destroyed)emit(value)};
  const cleanups=[],timers=new Set(),nativeDocument=globalThis.document;
  const listen=(target,name,fn,options)=>{target.addEventListener(name,fn,options);cleanups.push(()=>target.removeEventListener(name,fn,options))};
  const addEventListener=(name,fn,options)=>listen(window,name,fn,options);
  const document={querySelector:s=>nativeDocument.querySelector(s),querySelectorAll:s=>keyboard.querySelectorAll(s.replace('#vkb ','')),createElement:n=>nativeDocument.createElement(n),createTextNode:t=>nativeDocument.createTextNode(t),addEventListener:(...args)=>listen(nativeDocument,...args),get hidden(){return nativeDocument.hidden}};
  const setInterval=(fn,ms)=>{const id=window.setInterval(fn,ms);timers.add(id);return id};
  const clearInterval=id=>{window.clearInterval(id);timers.delete(id)};
  const cfg=new Proxy({}, {get:(_,key)=>read()[key]});
  const isOn=Boolean,touchDevice=matchMedia('(pointer: coarse)').matches;
  // Explicit vectors keep special keys legible across mobile system fonts.
  const icons={
    shift:'<path d="M16 20h-8v-8h-4l8-8 8 8h-4z"/>',
    caps:'<path d="M16 16h-8v-6h-4l8-7 8 7h-4zM8 21h8"/>',
    delete:'<path d="M20 5h-12l-6 7 6 7h12a2 2 0 0 0 2-2v-10a2 2 0 0 0-2-2zM12 9l6 6M18 9l-6 6"/>',
    enter:'<path d="M20 4v10a3 3 0 0 1-3 3h-13M9 12l-5 5 5 5"/>',
    left:'<path d="M20 12h-16M10 6l-6 6 6 6"/>',
    right:'<path d="M4 12h16M14 6l6 6-6 6"/>',
    up:'<path d="M12 20v-16M6 10l6-6 6 6"/>',
    down:'<path d="M12 4v16M6 14l6 6 6-6"/>',
    mic:'<rect x="9" y="2" width="6" height="12" rx="3"/><path d="M5 10v2a7 7 0 0 0 14 0v-2M12 19v3M8 22h8"/>',
  };
  const svg=name=>icons[name]?`<svg aria-hidden="true" viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${icons[name]}</svg>`:name;
  const typeText=text=>{if(read().connected)command({type:'text',text})};
  // Repeating press/up pairs refresh the server deadman timer and work on native and HID clients.
  const sendKey=query=>{if(!read().connected)return;const p=new URLSearchParams(query),state=p.get('s');command({type:'key',key:p.get('k'),state:state==='up'?'up':'press'})};
  let resetPad=()=>{};
const mods={ctrl:{},alt:{},shift:{},meta:{}};  // meta: Command on a Mac, the Windows key, Super
const modActive=m=>!!(mods[m].latched||mods[m].held);
const comboPrefix=()=>['ctrl','alt','shift','meta'].filter(modActive).map(m=>m+'+').join('');
const capitals=()=>modActive('shift')||!!mods.shift.lock;
const keyQuery=name=>'k='+encodeURIComponent(name);
// After a key: a held modifier counts as used, a latched one is released.
function afterKey(){let changed=false;
  for(const m in mods){if(mods[m].held)mods[m].used=true;if(mods[m].latched){mods[m].latched=false;changed=true}}
  if(changed)renderMods()}
function modKey(b,m){
  b.dataset.mod=m;
  b.addEventListener('pointerdown',e=>{e.preventDefault();if(b.disabled)return;try{b.setPointerCapture(e.pointerId)}catch{}const s=mods[m],now=Date.now();
    if(m==='shift'&&s.latched&&now-(s.lastTap||0)<320){s.latched=false;s.lock=true;s.skip=true}
    else if(s.latched||s.lock){s.latched=false;s.lock=false;s.skip=true}
    else{s.held=true;s.used=false}
    s.lastTap=now;renderMods()});
  const up=()=>{const s=mods[m];if(s.skip){s.skip=false;return}if(!s.held)return;s.held=false;if(!s.used)s.latched=true;renderMods()};
  ['pointerup','pointercancel','lostpointercapture'].forEach(n=>b.addEventListener(n,up));
  b.addEventListener('click',e=>{if(e.detail===0&&!b.disabled){mods[m].latched=!modActive(m);renderMods()}});
  b.addEventListener('contextmenu',e=>e.preventDefault());
}
// Modifier names of the computer being typed on: a Mac has ⌃ ⌥ ⌘, Windows
// Ctrl Alt Win, Linux Ctrl Alt Super. An ESP32 cannot know its host: Ctrl Alt ⌘.
function modLabels(){const p=String(read().platform||'');
  const names=/^(?:darwin|macos)/i.test(p)?{ctrl:['⌃','Control'],alt:['⌥','Option'],meta:['⌘','Command']}
    :/^windows/.test(p)?{ctrl:['Ctrl','Ctrl'],alt:['Alt','Alt'],meta:['Win','Windows key']}
    :/^linux/.test(p)?{ctrl:['Ctrl','Ctrl'],alt:['Alt','Alt'],meta:['Super','Super']}
    :{ctrl:['Ctrl','Ctrl'],alt:['Alt','Alt (Option on a Mac)'],meta:['⌘','Command (Windows key on Windows)']};
  document.querySelectorAll('#vkb .vkb-bar [data-mod]').forEach(b=>{const n=names[b.dataset.mod];if(!n)return;
    b.textContent=n[0];b.title=n[1]+' (tap: next key, hold: while held)';b.setAttribute('aria-label',n[1])})}
// Updates the keys in place (no rebuild, so a held key keeps its pointer).
function renderMods(){
  document.querySelectorAll('#vkb [data-mod]').forEach(b=>{const m=b.dataset.mod;
    b.classList.toggle('on',modActive(m));b.classList.toggle('locked',m==='shift'&&!!mods.shift.lock);
    if(m==='shift'){b.innerHTML=svg(mods.shift.lock?'caps':'shift');b.setAttribute('aria-label',mods.shift.lock?'Caps lock on':'Shift')}
    b.setAttribute('aria-pressed',modActive(m)||(m==='shift'&&!!mods.shift.lock))});
  document.querySelectorAll('#vkb [data-base]').forEach(b=>{const base=b.dataset.base;
    b.firstChild.textContent=vkbLayer==='abc'&&capitals()?base.toUpperCase():base});
}

// Named keys (arrows, Backspace, Enter, Esc, Tab): one press per tap and
// auto-repeat while held. With a modifier on, the whole combination repeats.
function holdToRepeat(btn){
  const key=btn.dataset.key;let held=false,renew=0,combo='';
  const down=e=>{if(held||btn.disabled)return;e.preventDefault();held=true;btn.classList.add('pressed');
    try{btn.setPointerCapture(e.pointerId)}catch{}  // keeps "up" coming if the finger slides off
    combo=comboPrefix();
    if(combo){const q=keyQuery(combo+key);sendKey(q);renew=setInterval(()=>sendKey(q),150);afterKey()}
    else{sendKey(keyQuery(key)+'&s=down');renew=setInterval(()=>sendKey(keyQuery(key)+'&s=hold'),150)}};
  const up=()=>{if(!held)return;held=false;clearInterval(renew);btn.classList.remove('pressed');if(!combo)sendKey(keyQuery(key)+'&s=up')};
  btn.addEventListener('pointerdown',down);['pointerup','pointercancel','lostpointercapture'].forEach(n=>btn.addEventListener(n,up));
  btn.addEventListener('keydown',e=>{if((e.key==='Enter'||e.key===' ')&&!e.repeat)down(e)});btn.addEventListener('keyup',up);btn.addEventListener('blur',up);
  btn.addEventListener('contextmenu',e=>e.preventDefault());
}
// A key pressed once (Enter), with the active modifiers.
function pressOnce(b,name,withMods=true){b.addEventListener('pointerdown',e=>{e.preventDefault();if(b.disabled)return;
  sendKey(keyQuery((withMods?comboPrefix():'')+name));afterKey()});b.addEventListener('click',e=>{if(e.detail===0&&!b.disabled){sendKey(keyQuery((withMods?comboPrefix():'')+name));afterKey()}})}

// ---------- System keyboard ----------
// On a computer, keys typed while this page has focus go to the client, as if
// typed on the on-screen keyboard: characters as text, named keys held and
// repeated, and Ctrl, Alt or ⌘ with a letter, digit or named key as one
// combination. Not while typing in a field or with a dialog open. The browser
// keeps a few combinations for itself (⌘W, ⌘T, ⌘Q, Ctrl+W, …).
const SYS_KEYS={Backspace:'backspace',Enter:'enter',Tab:'tab',Escape:'escape',
  ArrowLeft:'left',ArrowRight:'right',ArrowUp:'up',ArrowDown:'down'};
for(let i=1;i<=12;i++)SYS_KEYS['F'+i]='f'+i;
const sysHeld=new Map();  // e.code → named key sent "down", until its keyup
function sysKeyTarget(e){const t=e.target;
  return read().connected&&!touchDevice&&!e.isComposing&&!document.querySelector('dialog[open]')
    &&root.contains(t)&&!(t instanceof HTMLElement&&(t.isContentEditable||t.closest('input,textarea,select,button')))}
document.addEventListener('keydown',e=>{
  if(!sysKeyTarget(e)||['Shift','Control','Alt','Meta','CapsLock','AltGraph','Fn'].includes(e.key))return;
  const named=SYS_KEYS[e.key],chord=e.ctrlKey||e.altKey||e.metaKey;
  const prefix=(e.ctrlKey?'ctrl+':'')+(e.altKey?'alt+':'')+(e.shiftKey?'shift+':'')+(e.metaKey?'meta+':'');
  if(chord){  // by physical key: Option on a Mac changes e.key (⌥A is "å")
    const m=/^(?:Key([A-Z])|Digit(\d))$/.exec(e.code),base=named||(m?(m[1]||m[2]).toLowerCase():e.code==='Space'?'space':'');
    if(!base)return;
    e.preventDefault();sendKey(keyQuery(prefix+base));return}
  if(named&&e.shiftKey){e.preventDefault();sendKey(keyQuery('shift+'+named));return}  // Shift+Tab, Shift+arrows
  if(named){e.preventDefault();
    if(!e.repeat||!sysHeld.has(e.code)){sysHeld.set(e.code,named);sendKey(keyQuery(named)+'&s=down')}
    else sendKey(keyQuery(named)+'&s=hold');
    return}
  if(e.key.length===1||[...e.key].length===1){e.preventDefault();typeText(e.key)}
});
function sysRelease(code){const named=sysHeld.get(code);if(!named)return;sysHeld.delete(code);sendKey(keyQuery(named)+'&s=up')}
document.addEventListener('keyup',e=>sysRelease(e.code));
addEventListener('blur',()=>[...sysHeld.keys()].forEach(sysRelease));  // a key held while switching windows

// ---------- Full keyboard ----------
// Layers as rows of keys: a character, or one of the function keys below.
const VKB_LAYERS={
  abc:[[...'1234567890'],[...'qwertyuiop'],['GAP',...'asdfghjkl','GAP'],['SHIFT',...'zxcvbnm','BKSP'],['SYM',',','SPACE','.','ENTER']],
  sym:[[...'1234567890'],[...'@#$%&-+()/'],['GAP',...'*"\':;!?_','GAP'],['MORE',...'~`|\\^<>','BKSP'],['ABC',',','SPACE','.','ENTER']],
  more:[[...'[]{}€£¥°•§'],[...'=±×÷¶©®™…₹'],['GAP',...'«»¡¿¢','GAP'],['SYM',...'✓','BKSP'],['ABC',',','SPACE','.','ENTER']],
};
let vkbLayer='abc';
function vkbKey(token){
  const b=document.createElement('button');b.type='button';b.className='vk';b.tabIndex=0;
  const fn=(label,cls)=>{b.className='vk fn '+(cls||'');if(label.startsWith('<'))b.innerHTML=label;else b.textContent=label};
  switch(token){
    case 'GAP':b.className='vk gap';b.setAttribute('aria-hidden','true');return b;
    case 'SHIFT':fn(svg('shift'),'wide');modKey(b,'shift');return b;
    case 'BKSP':fn(svg('delete'),'wide');b.dataset.key='backspace';b.setAttribute('aria-label','Backspace');holdToRepeat(b);return b;
    case 'ENTER':fn(svg('enter'),'wide enter');b.setAttribute('aria-label','Enter');pressOnce(b,'enter');return b;
    case 'SYM':case 'ABC':case 'MORE':fn(token==='ABC'?'ABC':token==='SYM'?'?123':'=\\<','wide');
      {const change=()=>{vkbLayer={ABC:'abc',SYM:'sym',MORE:'more'}[token];renderVkb()};b.addEventListener('pointerdown',e=>{e.preventDefault();if(!b.disabled)change()});b.addEventListener('click',e=>{if(e.detail===0&&!b.disabled)change()});}return b;
    case 'SPACE':b.className='vk space';b.setAttribute('aria-label','Space');b.append(document.createTextNode('space'));charKey(b,' ');return b;
  }
  b.dataset.base=token;b.append(document.createTextNode(token));charKey(b,token,true);return b;
}
// A character key: types on press (no waiting for release, so fast two-thumb
// typing keeps every letter), and shows the character above the finger. With
// Ctrl or Alt on, a letter, digit or space goes out as a combination instead.
function charKey(b,base,pop){
  let bubble=null;
  const current=()=>vkbLayer==='abc'&&capitals()?base.toUpperCase():base;
  const emit=()=>{const combo=comboPrefix(),chord=modActive('ctrl')||modActive('alt')||modActive('meta');
    if(chord&&/^[a-z0-9 ]$/i.test(base))sendKey(keyQuery(combo+(base===' '?'space':base.toLowerCase())));
    else typeText(current());
    afterKey()};
  const release=()=>{b.classList.remove('pressed');bubble?.remove();bubble=null};
  b.addEventListener('pointerdown',e=>{e.preventDefault();if(b.disabled)return;b.classList.add('pressed');
    if(pop){bubble=Object.assign(document.createElement('span'),{className:'vk-pop',textContent:current()});b.append(bubble)}
    emit();navigator.vibrate?.(5)});
  ['pointerup','pointercancel','pointerleave'].forEach(n=>b.addEventListener(n,release));
  b.addEventListener('click',e=>{if(e.detail===0&&!b.disabled)emit()});  // keyboard or switch access
  b.addEventListener('contextmenu',e=>e.preventDefault());
}
function updateMicrophone(){
  const button=keyboard.querySelector('.mic-key');if(!button)return;
  const {recording,processing,microphoneDisabled}=read(),busy=!!processing&&!recording;
  const state=recording?'recording':busy?'busy':'idle';
  button.disabled=!!microphoneDisabled;button.setAttribute('aria-pressed',String(!!recording));button.setAttribute('aria-busy',String(busy));
  const label=recording?'Stop recording':busy?'Transcribing…':'Dictate';button.setAttribute('aria-label',label);button.title=label;
  button.classList.toggle('recording',!!recording);button.classList.toggle('busy',busy);
  if(button.dataset.microphoneState!==state){button.dataset.microphoneState=state;button.innerHTML=recording?'<svg aria-hidden="true" viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="2" fill="currentColor"/></svg>':svg('mic');}
}
function renderVkb(){
  const kb=keyboard,bar=document.createElement('div');bar.className='vkb-row vkb-bar';
  const tool=(html,label,cls='')=>{const b=document.createElement('button');b.type='button';b.className='vk fn '+cls;b.tabIndex=0;b.innerHTML=html;b.setAttribute('aria-label',label);b.title=label;bar.append(b);return b};
  const key=(html,label,name)=>{const b=tool(html,label);b.dataset.key=name;holdToRepeat(b)};
  key('Esc','Escape','escape');
  key('Tab','Tab','tab');
  modKey(tool('Ctrl','Ctrl (tap: next key, hold: while held)'),'ctrl');
  modKey(tool('Alt','Alt (tap: next key, hold: while held)'),'alt');
  modKey(tool('⌘','Command (tap: next key, hold: while held)'),'meta');
  for(const [k,label] of [['left','Left'],['up','Up'],['down','Down'],['right','Right']])key(svg(k),label,k);
  // Landscape only: the microphone as the last key of this row.
  const micButton=tool(svg('mic'),'Dictate','mic-key');micButton.dataset.alwaysOn='';
  micButton.addEventListener('pointerdown',e=>e.preventDefault());micButton.addEventListener('click',()=>mic());

  // F1–F12 (Settings → Function keys): hold to repeat, and with Ctrl/Alt/Shift (Alt+F4).
  const fkeys=[];
  if(isOn(cfg.functionKeys)){const row=document.createElement('div');row.className='vkb-row vkb-bar vkb-fn';
    for(let n=1;n<=12;n++){const b=document.createElement('button');b.type='button';b.className='vk fn';b.tabIndex=0;b.textContent='F'+n;
      b.setAttribute('aria-label','F'+n);b.dataset.key='f'+n;holdToRepeat(b);row.append(b)}
    fkeys.push(row)}
  kb.replaceChildren(...fkeys,bar,...VKB_LAYERS[vkbLayer].map(row=>{const r=document.createElement('div');r.className='vkb-row';r.append(...row.map(vkbKey));return r}));
  kb.querySelectorAll('button:not([data-always-on])').forEach(b=>b.disabled=!read().connected);
  renderMods();
  modLabels();
  updateMicrophone();
}
(function touchpad(){
  const fingers=new Map(),move={x:0,y:0},scroll={x:0,y:0};
  const SCROLL_PX=18;  // finger travel per scroll step
  // Tap and drag, as on Windows: a finger that lands within DRAG_WINDOW of a tap
  // holds the left button once it moves, until it lifts.
  const DRAG_WINDOW=450,DRAG_START_PX=6;
  let gesture=null,frame=0,lastTap=-1e9,dragging=false,holdTimer=0,heldRenew=0;
  const send=m=>{if(read().connected)command({type:'pointer',...m})};
  const flush=()=>{frame=0;
    const mx=Math.round(move.x),my=Math.round(move.y);
    if(mx||my){send({action:'move',dx:mx,dy:my});move.x-=mx;move.y-=my}
    const sx=Math.trunc(scroll.x),sy=Math.trunc(scroll.y);if(sx||sy){send({action:'scroll',dx:sx,dy:sy});scroll.x-=sx;scroll.y-=sy}};
  const later=()=>{frame||=requestAnimationFrame(flush)};
  const now=()=>{cancelAnimationFrame(frame);flush()};  // pending motion first, then the button
  const cancelHold=()=>{window.clearTimeout(holdTimer);holdTimer=0};
  const stopRenew=()=>{if(!dragging&&!buttonsDown.size&&heldRenew){clearInterval(heldRenew);heldRenew=0}};
  const renew=()=>{heldRenew||=setInterval(()=>{if(!read().connected){resetPad();return;}if(dragging||buttonsDown.size)send({action:'move',dx:0,dy:0});else stopRenew()},1000)};
  const beginDrag=()=>{cancelHold();if(dragging||!gesture?.drag||fingers.size!==1||!read().connected)return;dragging=true;now();send({action:'press',button:'left'});pad.classList.add('dragging');renew();navigator.vibrate?.(12)};
  const release=()=>{cancelHold();if(!dragging)return;dragging=false;now();send({action:'release',button:'left'});pad.classList.remove('dragging');stopRenew()};
  // A finger (or the mouse) goes down, moves, lifts: the same for touch and pointer events.
  const down=(id,x,y,t)=>{if(!read().connected)return;fingers.set(id,{x,y,t});
    if(fingers.size===1)gesture={start:t,travel:0,most:1,drag:t-lastTap<DRAG_WINDOW};else if(gesture)gesture.most=Math.max(gesture.most,fingers.size);
    if(fingers.size===1&&gesture.drag)holdTimer=window.setTimeout(beginDrag,80);else if(fingers.size>1){cancelHold();gesture.drag=false;}
    pad.classList.add('touching')};
  const moved=(id,x,y,t)=>{const f=fingers.get(id);if(!f||!gesture)return;
    const dx=x-f.x,dy=y-f.y,dt=Math.max(1,t-f.t);Object.assign(f,{x,y,t});
    gesture.travel+=Math.abs(dx)+Math.abs(dy);
    if(gesture.drag&&!dragging&&fingers.size===1&&gesture.travel>DRAG_START_PX){
      beginDrag()}
    if(fingers.size===1){  // faster swipes go further, like a laptop touchpad
      const gain=(1.3+Math.min(2.2,Math.hypot(dx,dy)/dt*1.4))*(buttonsDown.size?DRAG_SPEED:1);move.x+=dx*gain;move.y+=dy*gain}
    else{  // two fingers: scroll, the content following the fingers; each finger adds half
      const dir=isOn(cfg.reverseScroll)?-1:1;  // Settings → Reverse scrolling
      scroll.x-=dir*dx/SCROLL_PX/fingers.size;scroll.y-=dir*dy/SCROLL_PX/fingers.size}
    later()};
  const lifted=(id,t)=>{if(!fingers.delete(id)||fingers.size)return;cancelHold();
    pad.classList.remove('touching');
    if(dragging)release();
    else if(gesture&&gesture.travel<12&&t-gesture.start<320){  // a tap: a click (the second of a double tap too)
      send({action:'click',button:gesture.most>=2?'right':'left'});navigator.vibrate?.(8);
      lastTap=gesture.most>=2?-1e9:t}
    gesture=null};
  // Never leave the button held: leaving the page or losing the socket ends a drag.
  addEventListener('pagehide',release);document.addEventListener('visibilitychange',()=>{if(document.hidden)release()});
  // Touch events, not pointer events: only cancelling them stops iOS Safari from
  // panning and zooming the page with two fingers (it ignores touch-action there).
  const onButton=el=>el?.closest?.('.tp-btn');  // the mouse buttons have their own handlers below
  const each=(e,fn)=>{e.preventDefault();for(const t of e.changedTouches)if(!onButton(t.target))fn(t.identifier,t.clientX,t.clientY,e.timeStamp)};
  listen(pad,'touchstart',e=>each(e,down),{passive:false});
  listen(pad,'touchmove',e=>each(e,moved),{passive:false});
  listen(pad,'touchend',e=>each(e,(id,x,y,t)=>lifted(id,t)),{passive:false});
  listen(pad,'touchcancel',e=>{e.preventDefault();resetPad()},{passive:false});
  ['gesturestart','gesturechange','gestureend'].forEach(n=>listen(pad,n,e=>e.preventDefault()));  // Safari pinch
  // A mouse or a laptop's trackpad, with the computer's cursor left as it is.
  // Holding the button and moving works like a finger (a quick click clicks,
  // click then hold and move drags). After a click, the touchpad is active:
  // moving over it moves the device's pointer until the cursor leaves it.
  // Merely passing over it does nothing.
  const mouse=e=>e.pointerType!=='touch';let active=false,last=null;
  const setActive=on=>{active=on;last=null;pad.classList.toggle('active',on)};
  listen(pad,'pointerdown',e=>{if(!mouse(e)||onButton(e.target))return;e.preventDefault();
    // A mouse's right or middle button clicks that button on the device.
    if(e.button===1||e.button===2){send({action:'click',button:e.button===2?'right':'middle'});return}
    try{pad.setPointerCapture(e.pointerId)}catch{}down('m',e.clientX,e.clientY,e.timeStamp)});
  listen(pad,'pointermove',e=>{if(!mouse(e))return;
    if(fingers.has('m')){moved('m',e.clientX,e.clientY,e.timeStamp);return}
    if(!active)return;
    if(last){const dx=e.clientX-last.x,dy=e.clientY-last.y,dt=Math.max(1,e.timeStamp-last.t);
      const gain=1.3+Math.min(2.2,Math.hypot(dx,dy)/dt*1.4);move.x+=dx*gain;move.y+=dy*gain;later()}
    last={x:e.clientX,y:e.clientY,t:e.timeStamp}});
  ['pointerup','pointercancel'].forEach(n=>listen(pad,n,e=>{if(!mouse(e)||!fingers.has('m'))return;if(n==='pointercancel'){resetPad();return;}lifted('m',e.timeStamp);setActive(true)}));
  listen(pad,'pointerleave',e=>{if(mouse(e)&&!fingers.has('m'))setActive(false)});
  addEventListener('blur',()=>setActive(false));
  // A mouse wheel (or a laptop's two-finger scroll) over the touchpad scrolls the device.
  listen(pad,'wheel',e=>{e.preventDefault();if(!read().connected)return;
    const perStep=e.deltaMode===1?3:e.deltaMode===2?0.1:100;  // lines, pages, or pixels per step
    const dir=read().reverseScroll?-1:1;scroll.x+=dir*e.deltaX/perStep;scroll.y+=dir*e.deltaY/perStep;later()},{passive:false});
  // Mouse buttons (Settings → Mouse buttons): each holds its button on the device
  // while pressed: a tap clicks, holding it still is a long press. The finger on
  // it drags, like a finger on the device's screen: the pointer follows it, also
  // beyond the button, until it lifts (swipe down on an iPad's home screen for
  // search, left and right for pages). Another finger moving on the touchpad
  // drags too.
  const buttonsDown=new Map();  // pointer id -> {b, name, x, y, t}
  const DRAG_SPEED=0.5;  // pointer speed while a button is held: drags are for precision
  const releaseButton=id=>{const p=buttonsDown.get(id);if(!p)return;buttonsDown.delete(id);
    p.b.classList.remove('pressed');pad.classList.toggle('holding',buttonsDown.size>0);now();send({action:'release',button:p.name});stopRenew()};
  pad.querySelectorAll('.tp-btn').forEach(b=>{
    listen(b,'pointerdown',e=>{e.preventDefault();e.stopPropagation();if(!read().connected||buttonsDown.has(e.pointerId))return;
      try{b.setPointerCapture(e.pointerId)}catch{}now();
      buttonsDown.set(e.pointerId,{b,name:b.dataset.button,x:e.clientX,y:e.clientY,t:e.timeStamp});b.classList.add('pressed');pad.classList.add('holding');
      send({action:'press',button:b.dataset.button});renew();navigator.vibrate?.(8)});
    listen(b,'pointermove',e=>{const p=buttonsDown.get(e.pointerId);if(!p)return;
      const dx=e.clientX-p.x,dy=e.clientY-p.y,dt=Math.max(1,e.timeStamp-p.t);Object.assign(p,{x:e.clientX,y:e.clientY,t:e.timeStamp});
      const gain=(1.3+Math.min(2.2,Math.hypot(dx,dy)/dt*1.4))*DRAG_SPEED;  // as on the touchpad, slower
      move.x+=dx*gain;move.y+=dy*gain;later()});
    ['pointerup','pointercancel','lostpointercapture'].forEach(n=>listen(b,n,e=>releaseButton(e.pointerId)));
  });
  const releaseAll=()=>{for(const id of [...buttonsDown.keys()])releaseButton(id)};
  resetPad=()=>{cancelHold();release();releaseAll();if(heldRenew){clearInterval(heldRenew);heldRenew=0}fingers.clear();gesture=null;lastTap=-1e9;setActive(false);cancelAnimationFrame(frame);frame=0;move.x=move.y=scroll.x=scroll.y=0;pad.classList.remove('touching','holding')};  // never leave a button held
  addEventListener('pagehide',()=>resetPad());addEventListener('blur',()=>resetPad());
  document.addEventListener('visibilitychange',()=>{if(document.hidden)resetPad()});
  listen(pad,'contextmenu',e=>e.preventDefault());
})();


  renderVkb();
  const release=()=>{resetPad();for(const id of [...timers])clearInterval(id);sysHeld.clear();for(const m in mods)mods[m]={};renderMods();if(read().connected)command({type:'release_all'});renderVkb()};
  addEventListener('blur',release);
  document.addEventListener('visibilitychange',()=>{if(document.hidden)release()});
  return {microphone:()=>{if(!destroyed)updateMicrophone()},refresh:()=>{if(!destroyed){release();renderVkb()}},release:()=>{if(!destroyed)release()},destroy:()=>{if(destroyed)return;release();destroyed=true;cleanups.splice(0).forEach(fn=>fn());keyboard.replaceChildren()}};
}
