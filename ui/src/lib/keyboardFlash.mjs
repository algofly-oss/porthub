// PortHub's serial setup protocol. Passwords and enrollment credentials are
// written only to the user's chosen board, never browser storage or logs.
export class BoardLink {
  constructor(port,event=()=>{}){this.port=port;this.event=event;this.waiters=new Set();}
  async open(){await this.port.open({baudRate:115200,bufferSize:16384});try{await this.port.setSignals({dataTerminalReady:false,requestToSend:false});}catch{}this.reading=this.read();}
  async read(){const decoder=new TextDecoder();let buffer='';while(this.port.readable&&!this.closed){this.reader=this.port.readable.getReader();try{for(;;){const {done,value}=await this.reader.read();if(done)break;buffer+=decoder.decode(value,{stream:true});let index;while((index=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,index);buffer=buffer.slice(index+1);if(!line.startsWith('@vk '))continue;let value;try{value=JSON.parse(line.slice(4));}catch{continue;}this.event(value);for(const w of [...this.waiters])if(w.match(value)){this.waiters.delete(w);clearTimeout(w.timer);w.resolve(value);}}if(buffer.length>20000)buffer='';}}catch{}finally{this.reader.releaseLock();}}}
  async request(command,event=null,timeout=5000){
    let waiter;const response=new Promise((resolve,reject)=>{waiter={match:v=>event?v.ev===event:(v.ev==='ok'||v.ev==='error')&&v.cmd===command.cmd,resolve,reject};waiter.timer=setTimeout(()=>{this.waiters.delete(waiter);reject(new Error('Board did not respond'));},timeout);this.waiters.add(waiter);});
    const writer=this.port.writable.getWriter();try{await writer.write(new TextEncoder().encode(`${JSON.stringify(command)}\n`));}catch(error){clearTimeout(waiter.timer);this.waiters.delete(waiter);waiter.reject(error);}finally{writer.releaseLock();}
    const reply=await response;if(reply.ev==='error')throw Error(reply.msg||'Board rejected settings');return reply;
  }
  async close(){this.closed=true;for(const w of this.waiters){clearTimeout(w.timer);w.reject(new Error('Board disconnected'));}this.waiters.clear();try{await this.reader?.cancel();await this.reading;}catch{}try{await this.port.close();}catch{}}
}
export async function verifyFirmware(bytes,expected){const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');if(hash!==expected)throw new Error('Firmware checksum verification failed');}
export function firmwareSegments(bytes,keepSettings){
  if(!keepSettings)return [{data:bytes,address:0}];
  // ESP-IDF NVS partition 0x9000..0xffff stores Wi-Fi and Bluetooth bonds.
  return [{data:bytes.slice(0,0x9000),address:0},{data:bytes.slice(0x10000),address:0x10000}].filter(s=>s.data.length);
}
export async function flashBoard(port,image,{keepSettings=true,progress=()=>{}}={}){
  const r=await fetch(image.url,{cache:'no-store'});if(!r.ok)throw Error('Firmware download failed');const bytes=new Uint8Array(await r.arrayBuffer());await verifyFirmware(bytes,image.sha256);
  const {ESPLoader,Transport}=await import(/* webpackIgnore: true */ '/vendor/esptool-js-0.7.0.mjs');
  const transport=new Transport(port,false);const loader=new ESPLoader({transport,baudrate:460800,terminal:{clean(){},write(){},writeLine(){}}});
  try{
    await loader.main();const detected=loader.chip.CHIP_NAME.toLowerCase().replaceAll('-','');if(detected!==image.chip)throw Error(`Selected firmware is for ${image.chip}; connected chip is ${detected}`);
    const files=firmwareSegments(bytes,keepSettings);
    await loader.writeFlash({fileArray:files,flashSize:'keep',flashMode:'keep',flashFreq:'keep',eraseAll:false,compress:true,reportProgress:(_index,written,total)=>progress(written/total)});

  }finally{try{await loader.after('hard_reset');}catch{}try{await transport.disconnect();}catch{}}
}
