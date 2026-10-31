// Isolated engine interoperability probe; no invitation or production account.
const assert=require('node:assert/strict');const readline=require('node:readline');const {launchBrowser}=require('./browser.cjs');
(async()=>{
  const input=readline.createInterface({input:process.stdin});const lines=input[Symbol.asyncIterator]();
  const browser=await launchBrowser();
  try{
    const page=await browser.newPage();
    const offer=await page.evaluate(async()=>{
      const pc=new RTCPeerConnection({iceServers:[]});
      const channel=pc.createDataChannel('porthub-terminal/1',{ordered:true});channel.binaryType='arraybuffer';
      window.peer=pc;window.channel=channel;
      const gathered=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('candidate gathering timed out')),5000);pc.onicegatheringstatechange=()=>{if(pc.iceGatheringState==='complete'){clearTimeout(timer);resolve();}}});
      await pc.setLocalDescription(await pc.createOffer());await gathered;return pc.localDescription.toJSON();
    });
    process.stdout.write(JSON.stringify(offer)+'\n');const answer=JSON.parse((await lines.next()).value);
    const result=await page.evaluate(async answer=>{
      const channel=window.channel;
      const packet=(kind,epoch,payload=new Uint8Array())=>{const bytes=new Uint8Array(25+payload.length);bytes[0]=kind;bytes.fill(epoch,1,17);new DataView(bytes.buffer).setBigUint64(17,1n);bytes.set(payload,25);return bytes;};
      let acknowledge,received;
      const output=new Promise(resolve=>received=resolve),ack=new Promise(resolve=>acknowledge=resolve);
      channel.onmessage=event=>{
        const bytes=new Uint8Array(event.data);if(bytes.length<25 || new DataView(event.data).getBigUint64(17)!==1n)throw Error('invalid sequence');
        if(bytes[0]===1){if(!bytes.slice(1,17).every(value=>value===0xbb))throw Error('wrong output epoch');channel.send(packet(2,0xbb));received(new TextDecoder().decode(bytes.slice(25)));}
        else if(bytes[0]===2){if(bytes.length!==25 || !bytes.slice(1,17).every(value=>value===0xaa))throw Error('wrong input acknowledgement');acknowledge();}
        else throw Error('invalid terminal frame');
      };
      channel.onopen=()=>{const frame=packet(1,0xaa,new TextEncoder().encode('direct terminal interoperability'));channel.send(frame);channel.send(frame);};
      await window.peer.setRemoteDescription(answer);
      return Promise.race([Promise.all([output,ack]).then(([text])=>text),new Promise((_,reject)=>setTimeout(()=>reject(Error('direct replay exchange timed out')),10000))]);
    },answer);
    assert.equal(result,'direct terminal interoperability');
    // The host releases us after it has observed the output acknowledgement
    // and discarded the duplicated input, rather than relying on a sleep.
    await lines.next();await page.evaluate(()=>window.peer.close());
    console.error('PASS browser WebRTC terminal engine: binary frames, scoped acknowledgements and duplicate-input rejection');
  }finally{input.close();await browser.close();}
})().catch(error=>{console.error(String(error));process.exitCode=1});
