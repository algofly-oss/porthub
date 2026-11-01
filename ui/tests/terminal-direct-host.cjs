const assert=require('node:assert/strict');const readline=require('node:readline');const {launchBrowser}=require('./browser.cjs');
(async()=>{
 const browser=await launchBrowser(),input=readline.createInterface({input:process.stdin});let finish;
 const finished=new Promise(resolve=>finish=resolve);
 try{
  const page=await browser.newPage();
  await page.evaluate(async source=>{const url=URL.createObjectURL(new Blob([source],{type:'text/javascript'}));try{window.delivery=await import(url);}finally{URL.revokeObjectURL(url);}},require('node:fs').readFileSync(require('node:path').join(__dirname,'../src/lib/terminalDelivery.js'),'utf8'));
  await page.exposeFunction('relayPacket',packet=>process.stdout.write(JSON.stringify({type:'relay',packet})+'\n'));
  input.on('line',line=>{const event=JSON.parse(line);if(event.type==='finish'){finish();return;}page.evaluate(async event=>{
   if(event.type==='answer'){window.inputEpoch=event.answer.input_epoch;window.outputEpoch=event.answer.output_epoch;window.inputJournal=new window.delivery.InputJournal(window.inputEpoch);window.outputJournal=new window.delivery.OutputJournal(window.outputEpoch);await window.pc.setRemoteDescription(JSON.parse(event.answer.description));}
   if(event.type==='relay'){const bytes=Uint8Array.from(atob(event.packet),c=>c.charCodeAt(0));window.accept(bytes,false);}
  },event).catch(error=>{console.error(String(error));process.exitCode=1;finish();});});
  const offer=await page.evaluate(async()=>{
   const pc=window.pc=new RTCPeerConnection({iceServers:[]}),dc=window.dc=pc.createDataChannel('porthub-terminal/1',{ordered:true});dc.binaryType='arraybuffer';
   window.text='';window.directOutputs=0;window.relayOutputs=0;window.duplicates=0;window.relay=false;window.dropDirectAcks=false;
   window.sendRelay=bytes=>{let raw='';for(const byte of bytes)raw+=String.fromCharCode(byte);window.relayPacket(btoa(raw));};
   window.keys=text=>{const bytes=window.inputJournal.enqueue(new TextEncoder().encode(text));if(window.relay)window.sendRelay(bytes);else dc.send(bytes);return bytes;};
   const decoder=new TextDecoder();
   window.accept=(bytes,direct)=>{
    const packet=window.delivery.parsePacket(bytes);
    if(packet.kind==='ack'){window.inputJournal.acknowledge(packet);return;}
    if(direct)window.directOutputs++;else window.relayOutputs++;
    if(!window.outputJournal.stage(packet))window.duplicates++;
    let frame;while((frame=window.outputJournal.next())){window.text=(window.text+decoder.decode(frame.payload,{stream:true})).slice(-262144);window.outputJournal.commit(frame.sequence);}
    if(!(direct && window.dropDirectAcks)){const ack=window.outputJournal.acknowledgement();if(direct && dc.readyState==='open')dc.send(ack);else window.sendRelay(ack);}
   };
   dc.onmessage=event=>window.accept(new Uint8Array(event.data),true);
   dc.onopen=()=>{window.first=window.keys("DCOUNT=$((DCOUNT+1)); printf 'DIRECT%s:%s\\n' 'VALUE' \"$DCOUNT\"\r");dc.send(window.first);};
   const gathered=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('gather timeout')),5000);pc.onicegatheringstatechange=()=>{if(pc.iceGatheringState==='complete'){clearTimeout(timer);resolve();}}});await pc.setLocalDescription(await pc.createOffer());await gathered;return pc.localDescription.toJSON();
  });
  process.stdout.write(JSON.stringify({type:'offer',description:JSON.stringify(offer)})+'\n');
  await page.waitForFunction(()=>window.text.includes('DIRECTVALUE:1') && window.inputJournal.pendingFrames===0,{},{timeout:10000});
  await page.evaluate(()=>{window.dropDirectAcks=true;window.keys("printf 'REPLAY%s:%s\\n' 'VALUE' \"$DCOUNT\"\r");});
  await page.waitForFunction(()=>window.text.includes('REPLAYVALUE:1') && window.relayOutputs>0 && window.duplicates>0,{},{timeout:10000});
  await page.evaluate(()=>{window.relay=true;window.sendRelay(window.first);window.keys("printf 'FALLBACK%s:%s\\n' 'VALUE' \"$DCOUNT\"\r");});
  await page.waitForFunction(()=>window.text.includes('FALLBACKVALUE:1') && window.inputJournal.pendingFrames===0,{},{timeout:10000});
  const result=await page.evaluate(()=>({direct:window.directOutputs,relay:window.relayOutputs,duplicates:window.duplicates,wrong:window.text.includes('DIRECTVALUE:2') || window.text.includes('FALLBACKVALUE:2')}));
  assert(!result.wrong);assert(result.direct>0 && result.relay>0 && result.duplicates>0);
  process.stdout.write(JSON.stringify({type:'result',...result})+'\n');await finished;await page.evaluate(()=>window.pc.close());
  console.error('PASS host actor: real PTY, direct input/output, replayed input applied once and automatic output fallback');
 }finally{input.close();await browser.close();}
})().catch(error=>{console.error(String(error));process.exitCode=1});
