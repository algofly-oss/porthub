import {useEffect,useRef} from 'react';
import {mountKeyboardSurface} from '@/lib/keyboardSurface.mjs';
import styles from './Surface.module.css';
const special={Enter:'enter',Escape:'escape',Backspace:'backspace',Delete:'delete',Tab:'tab',' ':'space',ArrowUp:'up',ArrowDown:'down',ArrowLeft:'left',ArrowRight:'right',Home:'home',End:'end',PageUp:'pageup',PageDown:'pagedown',Control:'ctrl',Alt:'alt',Shift:'shift',Meta:'meta',CapsLock:'capslock','+':'plus'};
export function keyName(event){const key=special[event.key]||event.key.toLowerCase();return /^[!-~]$|^f(?:[1-9]|1[012])$/.test(key)||special[event.key]?key:null;}
export default function Controls({send,connected,preferences,platform,microphone,header,caption,padView}){
  const root=useRef(),keyboard=useRef(),pad=useRef(),controller=useRef(),latest=useRef();
  latest.current={...preferences,connected,platform,send,microphone};
  useEffect(()=>{controller.current=mountKeyboardSurface({root:root.current,keyboard:keyboard.current,pad:pad.current,read:()=>latest.current,command:value=>latest.current.send(value),mic:()=>latest.current.microphone()});return()=>controller.current?.destroy();},[]);
  useEffect(()=>{controller.current?.refresh();if(connected)root.current?.focus({preventScroll:true});},[connected,preferences.functionKeys,platform]);
  return <div ref={root} className={`${styles.surface} ${padView?styles.padView:''}`} onBlurCapture={e=>{if(!e.currentTarget.contains(e.relatedTarget))controller.current?.release();}} role="textbox" aria-label="Capture physical keyboard" tabIndex={connected?0:-1}>
    {header}
    <div className={`${styles.stage} ${!preferences.touchpad?styles.noPad:''}`}>
      <div ref={pad} hidden={!preferences.touchpad} className={styles.pad} role="application" aria-label="Touchpad: drag to move, tap to click, two fingers to scroll" aria-disabled={!connected}>
        <span className={styles.padHint}>Touchpad</span>
        <div hidden={!preferences.mouseButtons} className={styles.mouseButtons}>{['left','right'].map(button=><button type="button" key={button} disabled={!connected} className="tp-btn" data-button={button} aria-label={`${button} mouse button`}>{button==='left'?'Left':'Right'}</button>)}</div>
      </div>
      {caption}
    </div>
    <div ref={keyboard} className={styles.keyboard} role="group" aria-label="Virtual keyboard"/>
  </div>;
}
