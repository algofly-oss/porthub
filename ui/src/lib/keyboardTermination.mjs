// Only fixed server-owned categories are retained. CloseEvent.reason and peer
// error strings can contain arbitrary data and must never be shown or logged.
const phases=new Set(['host','controller']);
const causes=new Set(['closed','transport','frame','json','idle','authorization','replaced','send','host_ended','busy','rate']);
export function terminationCategory(value) {
 return phases.has(value?.phase)&&causes.has(value?.cause)?{phase:value.phase,cause:value.cause}:{};
}
export function socketTermination(event) {
 const match=typeof event?.reason==='string'&&event.reason.length<=64?/^keyboard:(host|controller):([a-z_]+)$/.exec(event.reason):null;
 return {...terminationCategory(match?{phase:match[1],cause:match[2]}:null),
  code:Number.isInteger(event?.code)&&event.code>=1000&&event.code<=4999?event.code:null,
  wasClean:typeof event?.wasClean==='boolean'?event.wasClean:null};
}
export function terminationMessage(value) {
 const {phase,cause}=terminationCategory(value);
 // Preserve only the old server's exact fixed messages, never arbitrary errors.
 if(!phase&&!cause){
  if(value?.error==='Input channel is busy; reconnect')return 'Input channel is busy; reconnect';
  if(value?.error==='Desktop reconnected')return 'The desktop client reconnected. Connect again.';
  if(value?.error==='VKeyboard disconnected')return 'The desktop client connection ended. Reconnect to continue.';
 }
 if(cause==='idle')return 'VKeyboard timed out. Reconnect to continue.';
 if(cause==='authorization')return 'Access to this client changed. Check client permissions before reconnecting.';
 if(cause==='replaced')return 'The desktop client reconnected. Connect again.';
 if(cause==='frame'||cause==='json')return 'VKeyboard received an unsupported message. Reconnect to continue.';
 if(cause==='rate')return 'Input arrived too quickly. Reconnect to continue.';
 if(cause==='busy')return 'The client is busy. Reconnect to continue.';
 if(phase==='host'||cause==='host_ended')return 'The desktop client connection ended. Reconnect to continue.';
 if(cause==='transport'||cause==='send')return 'VKeyboard connection was interrupted. Reconnect to continue.';
 return 'VKeyboard disconnected. Reconnect before sending more input.';
}
