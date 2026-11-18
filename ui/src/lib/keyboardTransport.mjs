import {socketTermination,terminationCategory,terminationMessage} from './keyboardTermination.mjs';
// One ordered control session. LAN discovery uses authenticated ICE signaling;
// the public URL and login never change. A command identity survives fallback.
export const KEYBOARD_CHANNEL = "porthub-keyboard/1";
export class KeyboardTransport {
  constructor({target,bluetoothKeyboard=false,changed=()=>{},failed=()=>{},createSocket=url=>new WebSocket(url),createPeer=config=>new RTCPeerConnection(config),origin=globalThis.location?.origin}) {
    Object.assign(this,{target,bluetoothKeyboard,changed,failed,createSocket,createPeer,origin});
    this.pending=new Map();this.queue=[];this.closed=false;this.generation=0;this.motionAfter=0;
  }
  connect() {
    const url=new URL(`/api/keyboard/control/${encodeURIComponent(this.target)}`,this.origin);url.protocol=url.protocol==='https:'?'wss:':'ws:';
    const socket=this.socket=this.createSocket(url.toString());
    socket.onmessage=event=>{try{this.event(JSON.parse(event.data));}catch{this.fail('Invalid VKeyboard response');}};
    socket.onerror=()=>this.fail('Could not connect. Check that VKeyboard is enabled on this client.');
    socket.onclose=event=>{if(!this.closed){const ended=socketTermination(event);this.changed({ended});this.fail(terminationMessage(ended));}};
  }
  event(message) {
    if(this.closed)return;
    if(message.type==='ready') {this.ready=true;this.session=message.session;this.changed({state:'connected',route:'relay',clipboard:message.clipboard});if(message.direct)void this.discover();}
    else if(message.type==='device_status') {
      if(this.manualBluetoothOff&&message.bluetooth!=='off')return;
      this.bluetooth=message.bluetooth;this.changed({bluetooth:message.bluetooth});
      if(this.bluetoothResume&&message.bluetooth==='connected')this.finishBluetooth();
      // A previously queued off report can arrive before advertising/waiting.
      // Only connected confirms resume; repeated off is bounded by the timer.
    }
    else if(message.type==='ping')this.socket.send(JSON.stringify({type:'pong'}));
    else if(message.type==='ack') {const pending=this.pending.get(message.ack?.id);if(!pending)return;clearTimeout(pending.timer);this.pending.delete(message.ack.id);message.ack.ok?pending.resolve():pending.reject(new Error(message.ack.error||'Input failed'));this.pump();}
    else if(message.type==='direct_answer') {if(!this.peer||message.session!==this.session)return;void this.peer.setRemoteDescription(JSON.parse(message.description)).catch(()=>this.fallback());}
    else if(message.type==='direct_unavailable')this.fallback();
    else if(message.type==='closed'){const ended={...terminationCategory(message),code:null,wasClean:null};this.changed({ended});this.fail(terminationMessage(message));}
    else if(message.type==='error')this.fail(message.error||'VKeyboard unavailable');
  }
  send(command) {
    if(!this.ready||this.closed)return Promise.reject(new Error('Connect to a client first'));
    if(command.type==='release_all'&&this.bluetoothResume){
      for(const item of this.queue)item.reject(new Error('Queued input cancelled to release held controls'));this.queue=[];
    }
    const motion=command.type==='pointer'&&command.action==='move';
    const tail=this.queue.at(-1);
    // Only combine adjacent, unsent relative movements. A click, key or scroll
    // remains a barrier, and already-sent identities are never modified.
    if(motion&&tail?.motion){
      const dx=(tail.input.command.dx||0)+(command.dx||0),dy=(tail.input.command.dy||0)+(command.dy||0);
      if(Math.abs(dx)<=4000&&Math.abs(dy)<=4000){Object.assign(tail.input.command,{dx,dy});return tail.promise;}
    }
    if(this.pending.size+this.queue.length>=64)return Promise.reject(new Error('Wait for pending input to finish'));
    const input={id:crypto.randomUUID(),command:{...command}};
    const envelope=JSON.stringify({type:'input',input});
    if(new TextEncoder().encode(envelope).length>32000)return Promise.reject(new Error('Text exceeds the input limit'));
    let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});
    this.queue.push({input,motion,promise,resolve,reject,expires:Date.now()+10000});this.pump();return promise;
  }
  // Only the ESP32's temporary Bluetooth switch is resumed. A desktop's local
  // feature disable still closes/rejects the authenticated control session.
  keyboardNeeded() {
    if(!this.ready||this.closed)return Promise.reject(new Error('Connect to a client first'));
    if(this.bluetoothResume)return this.bluetoothResume.promise;
    if(!this.bluetoothKeyboard||this.bluetooth!=='off')return Promise.resolve();
    let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});
    this.bluetoothResume={promise,resolve,reject};
    this.bluetoothResume.timer=setTimeout(()=>this.finishBluetooth(new Error('Bluetooth keyboard did not reconnect; turn it on in Clients settings')),10000);
    try{this.device({type:'bluetooth',on:true});}catch(error){this.finishBluetooth(error);}
    return promise;
  }
  finishBluetooth(error) {
    const waiting=this.bluetoothResume;if(!waiting)return;
    this.bluetoothResume=null;clearTimeout(waiting.timer);
    if(error){
      // Advertising alone grants no delivery permission, including after timeout.
      this.bluetooth='off';
      for(const item of this.queue)item.reject(error);this.queue=[];waiting.reject(error);
    }
    else{waiting.resolve();this.pump();}
  }
  pump() {
    while(!this.closed&&this.ready&&this.pending.size<4&&this.queue.length){
      if(this.queue[0].input.command.type!=='release_all'&&this.bluetoothKeyboard&&(this.bluetoothResume||this.bluetooth==='off')){
        // Keep the ordinary 64-command queue/expiry bounds while reconnecting;
        // never send dependent input or claim success before board confirmation.
        void this.keyboardNeeded().catch(()=>{});return;
      }
      const next=this.queue[0];
      if(next.expires<=Date.now()){this.queue.shift();next.reject(new Error('Input expired before it could be sent'));continue;}
      // A 120/240 Hz display must not exceed the gateway's input budget. Keep
      // a small acknowledgement window so a slow desktop cannot build a flood.
      const delay=next.motion?this.motionAfter-Date.now():0;
      if(delay>0){if(!this.pumpTimer)this.pumpTimer=setTimeout(()=>{this.pumpTimer=null;this.pump();},delay);return;}
      this.queue.shift();if(next.motion)this.motionAfter=Date.now()+17;
      const {input}=next;const pending=next;pending.timer=setTimeout(()=>{
        // A timeout never repeats a command: the client may have executed it.
        this.pending.delete(input.id);pending.reject(new Error('No acknowledgement. Input may have reached the client; check before retrying.'));this.pump();
      },10000);this.pending.set(input.id,pending);
      try{if(this.channel?.readyState==='open'&&this.channel.bufferedAmount<65536)this.channel.send(JSON.stringify(input));else this.socket.send(JSON.stringify({type:'input',input}));}catch{this.pending.delete(input.id);clearTimeout(pending.timer);pending.reject(new Error('Input was not sent'));}
    }
  }
  device(command) {
    if(!this.ready||this.closed)throw new Error('Connect to a board first');
    if(this.bluetoothKeyboard&&command.type==='bluetooth'){
      this.manualBluetoothOff=command.on===false;
      if(this.manualBluetoothOff){
        this.bluetooth='off';this.changed({bluetooth:'off'});
        const cancelled=new Error('Queued input cancelled by the keyboard toggle');
        for(const item of this.queue)item.reject(cancelled);this.queue=[];
        clearTimeout(this.pumpTimer);this.pumpTimer=null;
        // Already transmitted commands keep their original ACK/uncertainty.
        this.finishBluetooth(cancelled);
      }
    }
    this.socket.send(JSON.stringify({type:'device',command}));
  }
  async discover() {
    const generation=++this.generation;
    try {
      const peer=this.peer=this.createPeer({iceServers:[]});
      const channel=this.channel=peer.createDataChannel(KEYBOARD_CHANNEL,{ordered:true});channel.binaryType='arraybuffer';
      channel.onopen=()=>{if(!this.closed)this.changed({route:'local'});};
      channel.onmessage=event=>{try{const text=typeof event.data==='string'?event.data:new TextDecoder().decode(event.data);this.event(JSON.parse(text));}catch{this.fallback();}};
      channel.onclose=channel.onerror=()=>this.fallback();
      peer.onconnectionstatechange=()=>{if(['failed','disconnected','closed'].includes(peer.connectionState))this.fallback();};
      await peer.setLocalDescription(await peer.createOffer());
      if(peer.iceGatheringState!=='complete')await new Promise(resolve=>{
        const finish=()=>{clearTimeout(this.gather);resolve();};this.finishGather=finish;
        this.gather=setTimeout(finish,2500);peer.onicegatheringstatechange=()=>{if(peer.iceGatheringState==='complete')finish();};
      });
      if(this.closed||generation!==this.generation)return;
      const description=JSON.stringify(peer.localDescription.toJSON());if(description.length>16384)throw Error('Offer too large');
      this.socket.send(JSON.stringify({type:'direct_offer',description}));
      this.localDeadline=setTimeout(()=>{if(channel.readyState!=='open')this.fallback();},7000);
    }catch{this.fallback();}
  }
  fallback() {
    const peer=this.peer,channel=this.channel;this.peer=null;this.channel=null;
    if(channel){channel.onclose=channel.onerror=null;channel.close();}if(peer){peer.onconnectionstatechange=null;peer.close();}
    clearTimeout(this.localDeadline);if(this.closed)return;
    this.changed({route:'relay'});
    // The desktop deduplicates identities across both carriers in this session.
    for(const {input} of this.pending.values()){try{this.socket.send(JSON.stringify({type:'input',input}));}catch{this.fail('Relay connection failed');break;}}
  }
  fail(message) {if(this.closed)return;this.failed(message);this.close(new Error(message));}
  close(reason=new Error('Input session closed')) {
    if(this.closed)return;this.closed=true;this.ready=false;this.finishBluetooth(reason);this.generation++;clearTimeout(this.gather);this.finishGather?.();clearTimeout(this.localDeadline);
    clearTimeout(this.pumpTimer);this.fallback();if(this.socket){this.socket.onclose=this.socket.onerror=this.socket.onmessage=null;this.socket.close();}
    for(const p of this.pending.values()){clearTimeout(p.timer);p.reject(reason);}this.pending.clear();for(const p of this.queue)p.reject(reason);this.queue=[];this.changed({state:'disconnected',route:null});
  }
}
