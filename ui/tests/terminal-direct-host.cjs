const assert=require('node:assert/strict');const readline=require('node:readline');const {launchBrowser}=require('./browser.cjs');
(async()=>{
 const browser=await launchBrowser(),input=readline.createInterface({input:process.stdin});let finish;
 const finished=new Promise(resolve=>finish=resolve);
 try{
  const page=await browser.newPage();await page.exposeFunction('relayPacket',packet=>process.stdout.write(JSON.stringify({type:'relay',packet})+'\n'));
  input.on('line',line=>{const event=JSON.parse(line);if(event.type==='finish'){finish();return;}page.evaluate(async event=>{
   if(event.type==='answer'){window.inputEpoch=event.answer.input_epoch;window.outputEpoch=event.answer.output_epoch;await window.pc.setRemoteDescription(JSON.parse(event.answer.description));}
   if(event.type==='relay'){const bytes=Uint8Array.from(atob(event.packet),c=>c.charCodeAt(0));window.accept(bytes,false);}
  },event).catch(error=>{console.error(String(error));process.exitCode=1;finish();});});
  const offer=await page.evaluate(async()=>{
   const pc=window.pc=new RTCPeerConnection({iceServers:[]}),dc=window.dc=pc.createDataChannel('porthub-terminal/1',{ordered:true});dc.binaryType='arraybuffer';
   window.text='';window.sequence=0;window.committed=0;window.pending=new Map();window.frames=new Map();window.directOutputs=0;window.relayOutputs=0;window.duplicates=0;window.relay=false;window.dropDirectAcks=false;
   window.packet=(kind,epoch,sequence,payload=new Uint8Array())=>{const bytes=new Uint8Array(25+payload.length);bytes[0]=kind;for(let i=0;i<16;i++)bytes[i+1]=parseInt(epoch.slice(i*2,i*2+2),16);new DataView(bytes.buffer).setBigUint64(17,BigInt(sequence));bytes.set(payload,25);return bytes;};
   window.sendRelay=bytes=>{let raw='';for(const byte of bytes)raw+=String.fromCharCode(byte);window.relayPacket(btoa(raw));};
   window.keys=text=>{const sequence=++window.sequence;const bytes=window.packet(1,window.inputEpoch,sequence,new TextEncoder().encode(text));window.pending.set(sequence,bytes);if(window.relay)window.sendRelay(bytes);else dc.send(bytes);return bytes;};
   window.accept=(bytes,direct)=>{
    if(bytes.length<25)throw Error('short frame');const sequence=Number(new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength).getBigUint64(17));let epoch='';for(const byte of bytes.slice(1,17))epoch+=byte.toString(16).padStart(2,'0');
    if(bytes[0]===2){if(epoch!==window.inputEpoch)throw Error('input ACK epoch mismatch');for(const key of window.pending.keys())if(key<=sequence)window.pending.delete(key);return;}
    if(bytes[0]!==1 || epoch!==window.outputEpoch)throw Error('output epoch mismatch');
    if(direct)window.directOutputs++;else window.relayOutputs++;
    if(sequence<=window.committed)window.duplicates++;else window.frames.set(sequence,bytes.slice(25));
    while(window.frames.has(window.committed+1)){const data=window.frames.get(++window.committed);window.frames.delete(window.committed);window.text=(window.text+new TextDecoder().decode(data)).slice(-262144);}
    if(!(direct && window.dropDirectAcks)){const ack=window.packet(2,window.outputEpoch,window.committed);if(direct && dc.readyState==='open')dc.send(ack);else window.sendRelay(ack);}
   };
   dc.onmessage=event=>window.accept(new Uint8Array(event.data),true);
   dc.onopen=()=>{window.first=window.keys("DCOUNT=$((DCOUNT+1)); printf 'DIRECT%s:%s\\n' 'VALUE' \"$DCOUNT\"\r");dc.send(window.first);};
   const gathered=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('gather timeout')),5000);pc.onicegatheringstatechange=()=>{if(pc.iceGatheringState==='complete'){clearTimeout(timer);resolve();}}});await pc.setLocalDescription(await pc.createOffer());await gathered;return pc.localDescription.toJSON();
  });
  process.stdout.write(JSON.stringify({type:'offer',description:JSON.stringify(offer)})+'\n');
  await page.waitForFunction(()=>window.text.includes('DIRECTVALUE:1') && window.pending.size===0,{},{timeout:10000});
  await page.evaluate(()=>{window.dropDirectAcks=true;window.keys("printf 'REPLAY%s:%s\\n' 'VALUE' \"$DCOUNT\"\r");});
  await page.waitForFunction(()=>window.text.includes('REPLAYVALUE:1') && window.relayOutputs>0 && window.duplicates>0,{},{timeout:10000});
  await page.evaluate(()=>{window.relay=true;window.sendRelay(window.first);window.keys("printf 'FALLBACK%s:%s\\n' 'VALUE' \"$DCOUNT\"\r");});
  await page.waitForFunction(()=>window.text.includes('FALLBACKVALUE:1') && window.pending.size===0,{},{timeout:10000});
  const result=await page.evaluate(()=>({direct:window.directOutputs,relay:window.relayOutputs,duplicates:window.duplicates,wrong:window.text.includes('DIRECTVALUE:2') || window.text.includes('FALLBACKVALUE:2')}));
  assert(!result.wrong);assert(result.direct>0 && result.relay>0 && result.duplicates>0);
  process.stdout.write(JSON.stringify({type:'result',...result})+'\n');await finished;await page.evaluate(()=>window.pc.close());
  console.error('PASS host actor: real PTY, direct input/output, replayed input applied once and automatic output fallback');
 }finally{input.close();await browser.close();}
})().catch(error=>{console.error(String(error));process.exitCode=1});
