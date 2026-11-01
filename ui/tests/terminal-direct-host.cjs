const assert=require('node:assert/strict');const readline=require('node:readline');const {launchBrowser}=require('./browser.cjs');
(async()=>{
 const browser=await launchBrowser(),input=readline.createInterface({input:process.stdin});let finish;
 const finished=new Promise(resolve=>finish=resolve);
 try{
  const page=await browser.newPage();
  const fs=require('node:fs'),path=require('node:path');
  await page.evaluate(async sources=>{
   const journal=URL.createObjectURL(new Blob([sources.journal],{type:'text/javascript'}));
   const transport=URL.createObjectURL(new Blob([sources.transport.replace('"./terminalDelivery"',JSON.stringify(journal))],{type:'text/javascript'}));
   try{window.delivery=await import(journal);window.transportModule=await import(transport);}finally{URL.revokeObjectURL(journal);URL.revokeObjectURL(transport);}
  },{journal:fs.readFileSync(path.join(__dirname,'../src/lib/terminalDelivery.js'),'utf8'),transport:fs.readFileSync(path.join(__dirname,'../src/lib/terminalTransport.js'),'utf8')});
  await page.exposeFunction('relayPacket',packet=>process.stdout.write(JSON.stringify({type:'relay',packet})+'\n'));
  input.on('line',line=>{const event=JSON.parse(line);if(event.type==='finish'){finish();return;}page.evaluate(async event=>{
   if(event.type==='answer')window.hostTransport.event({type:'direct_answer',answer:event.answer});
   if(event.type==='relay')window.hostTransport.event({type:'delivery',packet:event.packet});
  },event).catch(error=>{console.error(String(error));process.exitCode=1;finish();});});
  const offer=await page.evaluate(async()=>{
   window.text='';window.directOutputs=0;window.relayOutputs=0;window.duplicates=0;window.dropDirectAcks=false;
   const decoder=new TextDecoder(),seen=new Set();let offer;
   const transport=window.hostTransport=new window.transportModule.TerminalTransport({
    readOnly:false,
    send:event=>{if(event.type==='direct_offer')offer=JSON.parse(event.description);else if(event.type==='delivery')window.relayPacket(event.packet);else throw Error('unexpected legacy input');},
    write:async bytes=>{window.text=(window.text+decoder.decode(bytes,{stream:true})).slice(-262144);},
    fail:reason=>{window.transportFailure=reason;},
    createPeer:config=>(window.pc=new RTCPeerConnection(config)),
   });
   const accept=transport.accept.bind(transport);
   transport.accept=(bytes,direct)=>{
    const packet=window.delivery.parsePacket(bytes);
    if(packet.kind==='data'){if(direct)window.directOutputs++;else window.relayOutputs++;if(seen.has(packet.sequence))window.duplicates++;seen.add(packet.sequence);}
    accept(bytes,direct);
   };
   window.sendRelay=bytes=>{let raw='';for(const byte of bytes)raw+=String.fromCharCode(byte);window.relayPacket(btoa(raw));};
   window.keys=text=>{transport.input(new TextEncoder().encode(text));return [...transport.inputJournal.replay()].at(-1);};
   await transport.start();
   Object.defineProperty(window,'inputJournal',{get:()=>transport.inputJournal});
   const dc=window.dc=transport.channel,send=dc.send.bind(dc),opened=dc.onopen;
   dc.send=bytes=>{if(!(window.dropDirectAcks && window.delivery.parsePacket(bytes).kind==='ack'))send(bytes);};
   dc.onopen=()=>{opened();window.first=window.keys("DCOUNT=$((DCOUNT+1)); printf 'DIRECT%s:%s\\n' 'VALUE' \"$DCOUNT\"\r");dc.send(window.first);};
   return offer;
  });
  process.stdout.write(JSON.stringify({type:'offer',description:JSON.stringify(offer)})+'\n');
  await page.waitForFunction(()=>window.text.includes('DIRECTVALUE:1') && window.inputJournal.pendingFrames===0,{},{timeout:10000});
  await page.evaluate(()=>{window.dropDirectAcks=true;window.keys("printf 'REPLAY%s:%s\\n' 'VALUE' \"$DCOUNT\"\r");});
  await page.waitForFunction(()=>window.text.includes('REPLAYVALUE:1') && window.relayOutputs>0 && window.duplicates>0,{},{timeout:10000});
  await page.evaluate(()=>{window.hostTransport.fallback();window.sendRelay(window.first);window.keys("printf 'FALLBACK%s:%s\\n' 'VALUE' \"$DCOUNT\"\r");});
  await page.waitForFunction(()=>window.text.includes('FALLBACKVALUE:1') && window.inputJournal.pendingFrames===0,{},{timeout:10000});
  const result=await page.evaluate(()=>({direct:window.directOutputs,relay:window.relayOutputs,duplicates:window.duplicates,wrong:window.text.includes('DIRECTVALUE:2') || window.text.includes('FALLBACKVALUE:2')}));
  assert(!result.wrong);assert(result.direct>0 && result.relay>0 && result.duplicates>0);
  process.stdout.write(JSON.stringify({type:'result',...result})+'\n');await finished;await page.evaluate(()=>{if(window.transportFailure)throw Error(window.transportFailure);window.hostTransport.close();});
  console.error('PASS host actor: real PTY, direct input/output, replayed input applied once and automatic output fallback');
 }finally{input.close();await browser.close();}
})().catch(error=>{console.error(String(error));process.exitCode=1});
