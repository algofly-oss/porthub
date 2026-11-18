import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { KeyboardTransport,KEYBOARD_CHANNEL } from '../src/lib/keyboardTransport.mjs';
import {socketTermination} from '../src/lib/keyboardTermination.mjs';
import { pcm16,VoiceRecorder } from '../src/lib/keyboardRecorder.mjs';
import { firmwareSegments,verifyFirmware } from '../src/lib/keyboardFlash.mjs';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
function fixture(options={}){const sent=[],changes=[];const socket={readyState:1,send:value=>sent.push(JSON.parse(value)),close(){}};const transport=new KeyboardTransport({...options,target:'test',origin:'https://porthub.test',createSocket:()=>socket,changed:v=>changes.push(v)});transport.connect();transport.event({type:'ready',session:'session',clipboard:true,direct:false});return {transport,socket,sent,changes};}
test('clipboard text and paste are explicit remote commands, not browser clipboard operations',async()=>{const f=fixture();const pending=f.transport.send({type:'clipboard',text:'https://example.test/a?b=1',paste:true});const input=f.sent[0].input;assert.equal(input.command.type,'clipboard');assert.equal(input.command.paste,true);f.transport.event({type:'ack',ack:{id:input.id,ok:true}});await pending;f.transport.close();});
test('fallback retains command identity so the desktop can deduplicate delivery',async()=>{const f=fixture();let direct;f.transport.channel={readyState:'open',bufferedAmount:0,send:value=>direct=JSON.parse(value),close(){}};const promise=f.transport.send({type:'key',key:'ctrl+v',state:'press'});assert.equal(f.sent.length,0);f.transport.fallback();assert.equal(f.sent[0].input.id,direct.id);f.transport.event({type:'ack',ack:{id:direct.id,ok:true}});await promise;f.transport.close();});
test('disconnect rejects pending input and never replays it into another session',async()=>{const f=fixture();const pending=f.transport.send({type:'text',text:'command'});f.transport.close();await assert.rejects(pending,/session closed/);assert.equal(f.transport.pending.size,0);await assert.rejects(f.transport.send({type:'paste'}),/Connect/);});
test('failed desktop acknowledgement surfaces the native error',async()=>{const f=fixture();const pending=f.transport.send({type:'paste'});f.transport.event({type:'ack',ack:{id:f.sent[0].input.id,ok:false,error:'Clipboard unavailable'}});await assert.rejects(pending,/Clipboard unavailable/);f.transport.close();});
test('LAN discovery keeps the original public origin and uses no external ICE servers',async()=>{const f=fixture();let config,label;const peer={iceGatheringState:'complete',createDataChannel(name){label=name;return {close(){}};},async createOffer(){return {type:'offer',sdp:'local-offer'};},async setLocalDescription(value){this.localDescription={toJSON:()=>value};},close(){}};f.transport.createPeer=value=>{config=value;return peer;};await f.transport.discover();assert.deepEqual(config,{iceServers:[]});assert.equal(label,KEYBOARD_CHANNEL);assert.equal(f.transport.origin,'https://porthub.test');assert.equal(f.sent[0].type,'direct_offer');f.transport.close();});
test('resampling creates bounded little endian 16 kHz PCM',()=>{const bytes=pcm16([new Float32Array(48000).fill(0.5)],48000);assert.equal(bytes.byteLength,32000);assert.equal(new DataView(bytes).getInt16(0,true),16384);assert.equal(new DataView(pcm16([new Float32Array([-2,2])],16000)).getInt16(0,true),-32768);});
test('silence consumes bounded memory and does not request inference',()=>{let segments=0;const recorder=new VoiceRecorder({segment:()=>segments++});for(let i=0;i<500;i++)recorder.accept(new Float32Array(4000),16000);assert(recorder.frames.length<=3);assert.equal(segments,0);for(let i=0;i<4;i++)recorder.accept(new Float32Array(4000).fill(.1),16000);for(let i=0;i<4;i++)recorder.accept(new Float32Array(4000),16000);assert.equal(segments,1);});
test('firmware updates preserve NVS and pairing; checksum mismatch rejects before flashing',async()=>{const bytes=new Uint8Array(0x20000);const segments=firmwareSegments(bytes,true);assert.deepEqual(segments.map(s=>[s.address,s.data.length]),[[0,0x9000],[0x10000,0x10000]]);assert.equal(firmwareSegments(bytes,false).length,1);await assert.rejects(verifyFirmware(bytes,'bad'),/checksum/);const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');await verifyFirmware(bytes,digest);});
test('pointer batching preserves distance and action barriers',async t=>{
 t.mock.timers.enable({apis:['setTimeout','Date'],now:1000});
 const f=fixture(),a=f.transport.send({type:'pointer',action:'move',dx:1,dy:0});
 const b=f.transport.send({type:'pointer',action:'move',dx:2,dy:3});
 const c=f.transport.send({type:'pointer',action:'move',dx:3,dy:-1});assert.equal(b,c);
 const click=f.transport.send({type:'pointer',action:'click',button:'left'});
 const d=f.transport.send({type:'pointer',action:'move',dx:4,dy:0});
 t.mock.timers.tick(17);t.mock.timers.tick(17);
 assert.deepEqual(f.sent.map(v=>v.input.command),[{type:'pointer',action:'move',dx:1,dy:0},{type:'pointer',action:'move',dx:5,dy:2},{type:'pointer',action:'click',button:'left'},{type:'pointer',action:'move',dx:4,dy:0}]);
 for(const v of f.sent)f.transport.event({type:'ack',ack:{id:v.input.id,ok:true}});
 await Promise.all([a,b,c,click,d]);f.transport.close();
});
test('slow input receivers have a bounded acknowledgement window',async()=>{
 const f=fixture(),promises=Array.from({length:30},()=>f.transport.send({type:'key',key:'left',state:'press'}));
 assert.equal(f.sent.length,4);assert.equal(f.transport.pending.size,4);
 f.transport.event({type:'ack',ack:{id:f.sent[0].input.id,ok:true}});assert.equal(f.sent.length,5);
 f.transport.close();const results=await Promise.allSettled(promises);assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.equal(f.transport.queue.length,0);
});
test('240 Hz pointing remains below the gateway budget without losing movement',async t=>{
 t.mock.timers.enable({apis:['setTimeout','Date'],now:1000});
 const f=fixture(),times=[],promises=[];
 f.socket.send=value=>{const v=JSON.parse(value);f.sent.push(v);times.push(Date.now());f.transport.event({type:'ack',ack:{id:v.input.id,ok:true}});};
 for(let i=0;i<500;i++){promises.push(f.transport.send({type:'pointer',action:'move',dx:1,dy:0}));t.mock.timers.tick(4);}
 t.mock.timers.tick(20);await Promise.all(promises);
 assert.equal(f.sent.reduce((sum,v)=>sum+v.input.command.dx,0),500);
 for(const at of times)assert(times.filter(time=>time>=at&&time<at+1000).length<=60);
 assert.equal(f.transport.closed,false);f.transport.close();
});
test('session failure keeps the original reason for queued and active commands',async()=>{
 const f=fixture(),promises=Array.from({length:6},()=>f.transport.send({type:'key',key:'left',state:'press'}));
 f.transport.event({type:'closed',error:'Input channel is busy; reconnect'});
 const results=await Promise.allSettled(promises);assert(results.every(r=>r.status==='rejected'&&r.reason.message==='Input channel is busy; reconnect'));
});

test('socket close retains only fixed category and numeric metadata, never peer reason',()=>{
 const f=fixture(),messages=[];f.transport.failed=v=>messages.push(v);
 f.socket.onclose({code:1006,wasClean:false,reason:'Bearer SECRET /Users/private input text'});
 assert.equal(f.transport.closed,true);assert.deepEqual(f.changes.find(v=>v.ended).ended,{code:1006,wasClean:false});
 assert(!JSON.stringify({messages,changes:f.changes}).includes('SECRET'));
 assert.match(messages[0],/Reconnect/);
});
test('fixed controller close category rejects pending input and cannot be overwritten',async()=>{
 const f=fixture(),messages=[];f.transport.failed=v=>messages.push(v);
 const pending=f.transport.send({type:'release_all'});
 f.transport.event({type:'closed',phase:'controller',cause:'idle',error:'SECRET input/path/token'});
 await assert.rejects(pending,/timed out/);assert.equal(messages.length,1);assert.deepEqual(f.changes.find(v=>v.ended).ended,{phase:'controller',cause:'idle',code:null,wasClean:null});
 f.transport.event({type:'closed',phase:'host',cause:'closed'});assert.equal(messages.length,1);assert(!JSON.stringify(f.changes).includes('SECRET'));
});
test('close frame allowlist differentiates host failure from controller format failure',()=>{
 for(const [reason,wanted] of [['keyboard:host:closed',/desktop client connection ended/],['keyboard:controller:json',/unsupported message/]]){
  const f=fixture(),messages=[];f.transport.failed=v=>messages.push(v);f.socket.onclose({code:1000,wasClean:true,reason});assert.match(messages[0],wanted);assert.equal(f.changes.find(v=>v.ended).ended.wasClean,true);
 }
});
test('unknown or hostile termination fields are never surfaced',()=>{
 for(const data of [{phase:'host SECRET',cause:'closed'},{phase:'host',cause:'closed SECRET'},{error:'SECRET'}]){
  const f=fixture(),messages=[];f.transport.failed=v=>messages.push(v);f.transport.event({type:'closed',...data});assert(!JSON.stringify({messages,changes:f.changes}).includes('SECRET'));assert.equal(messages[0],'VKeyboard disconnected. Reconnect before sending more input.');
 }
});

test('close details reject forged metadata and category suffixes',()=>{
 for(const reason of ['keyboard:host:closed SECRET','keyboard:host:unknown','keyboard:foreign:closed','x'.repeat(1000)])assert.deepEqual(socketTermination({code:'1006',wasClean:'false',reason}),{code:null,wasClean:null});
 assert.deepEqual(socketTermination({code:1000,wasClean:true,reason:'keyboard:host:transport'}),{phase:'host',cause:'transport',code:1000,wasClean:true});
});


test('ESP32 temporary-off resumes once before text, key and pointer input; only connected status releases the bounded queue',async()=>{
 const f=fixture({bluetoothKeyboard:true});f.transport.event({type:'device_status',bluetooth:'off'});
 const promises=[{type:'text',text:'recognized words'},{type:'key',key:'enter',state:'press'},{type:'pointer',action:'move',dx:5,dy:2}].map(c=>f.transport.send(c));
 assert.deepEqual(f.sent,[{type:'device',command:{type:'bluetooth',on:true}}]);
 assert(!f.changes.some(x=>x.bluetooth==='connected'),'sending enable never fabricates success');
 f.transport.event({type:'device_status',bluetooth:'off'});assert.equal(f.sent.length,1);
 f.transport.event({type:'device_status',bluetooth:'waiting'});assert.equal(f.sent.length,1,'advertising is not a connected keyboard');
 f.transport.event({type:'device_status',bluetooth:'connected'});
 assert.deepEqual(f.sent.slice(1).map(x=>x.input.command.type),['text','key','pointer']);
 for(const x of f.sent.slice(1))f.transport.event({type:'ack',ack:{id:x.input.id,ok:true}});
 await Promise.all(promises);f.transport.close();
});
test('dictation reconnect hint works before the first recognized segment without claiming connected',async()=>{
 const f=fixture({bluetoothKeyboard:true});f.transport.event({type:'device_status',bluetooth:'off'});
 const p=f.transport.keyboardNeeded();assert.equal(f.sent[0].command.on,true);
 assert.equal(f.transport.keyboardNeeded(),p,'concurrent hints share one bounded reconnect operation');
 f.transport.event({type:'device_status',bluetooth:'off'});f.transport.event({type:'device_status',bluetooth:'waiting'});f.transport.event({type:'device_status',bluetooth:'connected'});await p;assert.equal(f.sent.length,1);f.transport.close();
});
test('failed ESP32 reconnect rejects dependent input without sending it or fabricating success',async()=>{
 const f=fixture({bluetoothKeyboard:true});f.transport.event({type:'device_status',bluetooth:'off'});
 const p=f.transport.send({type:'text',text:'must not type'});f.transport.device({type:'bluetooth',on:false});
 await assert.rejects(p,/cancelled/);f.transport.event({type:'device_status',bluetooth:'connected'});assert.equal(f.sent.length,2);assert.equal(f.transport.queue.length,0);assert(!f.changes.some(x=>x.bluetooth==='connected'));f.transport.close();
});
test('ESP32 reconnect timeout and synchronous send failure cannot leak queued input',async t=>{
 t.mock.timers.enable({apis:['setTimeout','Date'],now:1000});
 const f=fixture({bluetoothKeyboard:true});f.transport.event({type:'device_status',bluetooth:'off'});
 const p=f.transport.send({type:'pointer',action:'press',button:'left'});const rejected=assert.rejects(p,/did not reconnect/);f.transport.event({type:'device_status',bluetooth:'waiting'});t.mock.timers.tick(10000);await rejected;
 const next=f.transport.send({type:'text',text:'new intent'});assert.equal(f.sent.length,2,'new intent must reconnect again after advertising timed out');assert(f.sent.every(x=>x.type==='device'));
 f.transport.event({type:'device_status',bluetooth:'connected'});assert.equal(f.sent.length,3,'late confirmation can release only the new intent');assert.equal(f.sent[2].input.command.text,'new intent');f.transport.event({type:'ack',ack:{id:f.sent[2].input.id,ok:true}});await next;f.transport.close();
 const broken=fixture({bluetoothKeyboard:true});broken.transport.event({type:'device_status',bluetooth:'off'});broken.socket.send=()=>{throw Error('socket unavailable')};
 await assert.rejects(broken.transport.send({type:'key',key:'enter'}),/socket unavailable/);assert.equal(broken.transport.queue.length,0);broken.transport.close();
});
test('resume never overrides desktop feature revocation or disconnected sessions, and release_all never enables BLE',async()=>{
 const desktop=fixture();desktop.transport.event({type:'device_status',bluetooth:'off'});const input=desktop.transport.send({type:'text',text:'desktop'});assert.equal(desktop.sent[0].type,'input');desktop.transport.close();await assert.rejects(input);
 const f=fixture({bluetoothKeyboard:true});f.transport.event({type:'device_status',bluetooth:'off'});const release=f.transport.send({type:'release_all'});assert.equal(f.sent[0].type,'input');f.transport.event({type:'ack',ack:{id:f.sent[0].input.id,ok:true}});await release;
 const p=f.transport.send({type:'text',text:'revoked'});f.transport.event({type:'closed',phase:'host',cause:'closed'});await assert.rejects(p);await assert.rejects(f.transport.keyboardNeeded(),/Connect/);assert.equal(f.transport.queue.length,0);
});
test('reconnecting ESP32 keeps the existing64 command bound and original queued expiry',async t=>{
 t.mock.timers.enable({apis:['setTimeout','Date'],now:1000});const f=fixture({bluetoothKeyboard:true});f.transport.event({type:'device_status',bluetooth:'off'});
 const pending=Array.from({length:64},()=>f.transport.send({type:'key',key:'enter'}));const results=Promise.allSettled(pending);await assert.rejects(f.transport.send({type:'key',key:'enter'}),/Wait for pending/);
 t.mock.timers.tick(10000);await results;f.transport.event({type:'device_status',bluetooth:'connected'});assert.equal(f.sent.length,1);f.transport.close();
});

test('release_all cancels unsent dependent input and bypasses a full reconnect queue',async()=>{
 const f=fixture({bluetoothKeyboard:true});f.transport.event({type:'device_status',bluetooth:'off'});
 const queued=Array.from({length:64},()=>f.transport.send({type:'key',key:'enter'}));const all=Promise.allSettled(queued);
 const release=f.transport.send({type:'release_all'});assert.equal(f.sent.length,2);assert.equal(f.sent[1].input.command.type,'release_all');
 f.transport.event({type:'ack',ack:{id:f.sent[1].input.id,ok:true}});await release;assert((await all).every(x=>x.status==='rejected'));
 f.transport.event({type:'device_status',bluetooth:'connected'});assert.equal(f.sent.length,2);f.transport.close();
});

test('manual Bluetooth off cancels throttled unsent motion without resuming old intent on timer or ACK',async t=>{
 t.mock.timers.enable({apis:['setTimeout','Date'],now:1000});const f=fixture({bluetoothKeyboard:true});f.transport.event({type:'device_status',bluetooth:'connected'});
 const first=f.transport.send({type:'pointer',action:'move',dx:1,dy:0});
 let outcome='pending';const queued=f.transport.send({type:'pointer',action:'move',dx:2,dy:0}).then(()=>{outcome='fulfilled'},()=>{outcome='rejected'});
 assert.equal(f.transport.queue.length,1);f.transport.device({type:'bluetooth',on:false});await Promise.resolve();
 assert.equal(outcome,'rejected','latest explicit off cancels prior unsent input even without a resume');
 t.mock.timers.tick(20);f.transport.event({type:'ack',ack:{id:f.sent[0].input.id,ok:true}});await first;await queued;
 assert.deepEqual(f.sent.map(x=>x.type),['input','device']);assert.equal(f.sent[1].command.on,false);assert.equal(f.transport.pending.size,0);f.transport.close();
});
test('manual Bluetooth off cancels window-blocked input while retaining in-flight ACK uncertainty',async()=>{
 const f=fixture({bluetoothKeyboard:true});f.transport.event({type:'device_status',bluetooth:'connected'});
 const pending=Array.from({length:4},()=>f.transport.send({type:'key',key:'enter'}));let rejected=false;const queued=f.transport.send({type:'text',text:'old queued intent'}).catch(()=>{rejected=true});
 f.transport.device({type:'bluetooth',on:false});await Promise.resolve();assert.equal(rejected,true);assert.equal(f.transport.pending.size,4,'already sent inputs remain pending rather than falsely cancelled');
 for(const x of f.sent.filter(x=>x.type==='input'))f.transport.event({type:'ack',ack:{id:x.input.id,ok:true}});await Promise.all([...pending,queued]);assert.equal(f.sent.length,5);assert.equal(f.sent[4].command.on,false);f.transport.close();
});
