// One ordered control session. LAN discovery uses authenticated ICE signaling;
// the public URL and login never change. A command identity survives fallback.
export const KEYBOARD_CHANNEL = "porthub-keyboard/1";
export class KeyboardTransport {
  constructor({target,changed=()=>{},failed=()=>{},createSocket=url=>new WebSocket(url),createPeer=config=>new RTCPeerConnection(config),origin=globalThis.location?.origin}) {
    Object.assign(this,{target,changed,failed,createSocket,createPeer,origin});
    this.pending=new Map();this.closed=false;this.generation=0;
  }
  connect() {
    const url=new URL(`/api/keyboard/control/${encodeURIComponent(this.target)}`,this.origin);url.protocol=url.protocol==='https:'?'wss:':'ws:';
    const socket=this.socket=this.createSocket(url.toString());
    socket.onmessage=event=>{try{this.event(JSON.parse(event.data));}catch{this.fail('Invalid VKeyboard response');}};
    socket.onerror=()=>this.fail('Could not connect. Check that VKeyboard is enabled on this client.');
    socket.onclose=()=>{if(!this.closed)this.fail('VKeyboard disconnected. Reconnect before sending more input.');};
  }
  event(message) {
    if(this.closed)return;
    if(message.type==='ready') {this.ready=true;this.session=message.session;this.changed({state:'connected',route:'relay',clipboard:message.clipboard});if(message.direct)void this.discover();}
    else if(message.type==='device_status')this.changed({bluetooth:message.bluetooth});
    else if(message.type==='ping')this.socket.send(JSON.stringify({type:'pong'}));
    else if(message.type==='ack') {const pending=this.pending.get(message.ack?.id);if(!pending)return;clearTimeout(pending.timer);this.pending.delete(message.ack.id);message.ack.ok?pending.resolve():pending.reject(new Error(message.ack.error||'Input failed'));}
    else if(message.type==='direct_answer') {if(!this.peer||message.session!==this.session)return;void this.peer.setRemoteDescription(JSON.parse(message.description)).catch(()=>this.fallback());}
    else if(message.type==='direct_unavailable')this.fallback();
    else if(message.type==='closed'||message.type==='error')this.fail(message.error||'VKeyboard unavailable');
  }
  send(command) {
    if(!this.ready||this.closed)return Promise.reject(new Error('Connect to a client first'));
    if(this.pending.size>=64)return Promise.reject(new Error('Wait for pending input to finish'));
    const input={id:crypto.randomUUID(),command};const bytes=JSON.stringify(input);
    const envelope=JSON.stringify({type:'input',input});
    if(new TextEncoder().encode(envelope).length>32000)return Promise.reject(new Error('Text exceeds the input limit'));
    return new Promise((resolve,reject)=>{
      const pending={input,resolve,reject};pending.timer=setTimeout(()=>{
        // A timeout never repeats a command: the client may have executed it.
        this.pending.delete(input.id);reject(new Error('No acknowledgement. Input may have reached the client; check before retrying.'));
      },10000);this.pending.set(input.id,pending);
      try{if(this.channel?.readyState==='open'&&this.channel.bufferedAmount<65536)this.channel.send(bytes);else this.socket.send(envelope);}catch{this.pending.delete(input.id);clearTimeout(pending.timer);reject(new Error('Input was not sent'));}
    });
  }
  device(command) {if(!this.ready||this.closed)throw new Error('Connect to a board first');this.socket.send(JSON.stringify({type:'device',command}));}
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
  fail(message) {if(this.closed)return;this.failed(message);this.close();}
  close() {
    if(this.closed)return;this.closed=true;this.ready=false;this.generation++;clearTimeout(this.gather);this.finishGather?.();clearTimeout(this.localDeadline);
    this.fallback();if(this.socket){this.socket.onclose=this.socket.onerror=this.socket.onmessage=null;this.socket.close();}
    for(const p of this.pending.values()){clearTimeout(p.timer);p.reject(new Error('Input session closed'));}this.pending.clear();this.changed({state:'disconnected',route:null});
  }
}
