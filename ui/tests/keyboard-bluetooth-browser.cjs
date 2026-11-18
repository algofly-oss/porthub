// Real browser execution of the production transport with a controlled board
// protocol peer. No ESP32 hardware, Bluetooth stack or physical keyboard claim.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {launchBrowser}=require('./browser.cjs');
(async()=>{const browser=await launchBrowser();try{
 const page=await browser.newPage();await page.route('https://porthub.test/**',r=>r.fulfill({contentType:'text/html',body:'<!doctype html><title>Owned Bluetooth transport regression</title>'}));await page.goto('https://porthub.test/');
 const termination='data:text/javascript;base64,'+Buffer.from(fs.readFileSync(path.join(__dirname,'../src/lib/keyboardTermination.mjs'))).toString('base64');
 const source=fs.readFileSync(path.join(__dirname,'../src/lib/keyboardTransport.mjs'),'utf8').replace("'./keyboardTermination.mjs'",JSON.stringify(termination));
 await page.evaluate(async source=>{const module=await import('data:text/javascript;base64,'+btoa(source));window.Transport=module.KeyboardTransport;
 window.fixture=()=>{const sent=[],changes=[],socket={send:s=>sent.push(JSON.parse(s)),close(){}};const transport=new Transport({target:'owned-board',bluetoothKeyboard:true,origin:location.origin,createSocket:()=>socket,changed:x=>changes.push(x)});transport.connect();transport.event({type:'ready',session:'owned-session',direct:false});transport.event({type:'device_status',bluetooth:'off'});return{transport,sent,changes,socket}};
 },source);
 const resumed=await page.evaluate(async()=>{const f=fixture();const pending=[{type:'text',text:'recognized segment'},{type:'pointer',action:'move',dx:6,dy:2},{type:'key',key:'enter'}].map(x=>f.transport.send(x));const before=f.sent.slice();if(before.some(x=>x.type==='input')){for(const p of pending)p.catch(()=>{});f.transport.close();throw Error('Dependent input sent before Bluetooth resume confirmation')}f.transport.event({type:'device_status',bluetooth:'off'});f.transport.event({type:'device_status',bluetooth:'waiting'});const waiting=f.sent.length;f.transport.event({type:'device_status',bluetooth:'connected'});const commands=f.sent.slice(1);for(const x of commands)f.transport.event({type:'ack',ack:{id:x.input.id,ok:true}});await Promise.all(pending);f.transport.close();return{before,waiting,types:commands.map(x=>x.input.command.type)}});
 assert.deepEqual(resumed,{before:[{type:'device',command:{type:'bluetooth',on:true}}],waiting:1,types:['text','pointer','key']});console.log('PASS Bluetooth reconnect precedes dependent text/pointer/key; waiting never claims connected');
 const failed=await page.evaluate(async()=>{const f=fixture();const pending=f.transport.send({type:'text',text:'never delivered'}).then(()=>false,()=>true);f.transport.device({type:'bluetooth',on:false});const rejected=await pending;f.transport.event({type:'device_status',bluetooth:'connected'});const result={rejected,inputCount:f.sent.filter(x=>x.type==='input').length,claimedConnected:f.changes.some(x=>x.bluetooth==='connected')};f.transport.close();return result});assert.deepEqual(failed,{rejected:true,inputCount:0,claimedConnected:false});console.log('PASS explicit off cancels pending reconnect; late connected cannot deliver input');
 const revoked=await page.evaluate(async()=>{const f=fixture();const pending=f.transport.keyboardNeeded().then(()=>false,()=>true);f.transport.event({type:'closed',phase:'host',cause:'closed'});return{rejected:await pending,closed:f.transport.closed,inputCount:f.sent.filter(x=>x.type==='input').length}});assert.deepEqual(revoked,{rejected:true,closed:true,inputCount:0});console.log('PASS revoked authenticated session cancels reconnect without input');
 if(process.env.REVIEW_ORIGIN){
  const {createKeyboardFixture}=require('./keyboard-local-fixture.cjs');
  for(const viewport of [{width:402,height:874},{width:1512,height:982}]){
   const f=await createKeyboardFixture(browser,viewport,{targetKind:'esp32'});
   try{
    await f.page.goto(process.env.REVIEW_ORIGIN+'/home?view=keyboard');
    await f.page.getByRole('button',{name:'Keyboard clients',exact:true}).click();await f.page.getByRole('button',{name:'Connect client',exact:true}).click();
    await f.page.getByRole('button',{name:'Disconnect client',exact:true}).waitFor();await f.page.getByRole('button',{name:'Close VKeyboard settings',exact:true}).click();await f.page.getByRole('dialog').waitFor({state:'hidden'});
    await f.page.getByRole('button',{name:'Enable Bluetooth keyboard',exact:true}).waitFor();
    assert.equal(f.deviceRecords.length,0,'opening Clients/release_all does not resume BLE');
    const start=f.page.getByRole('button',{name:'Start dictation',exact:true});if(await start.isVisible())await start.click();else await f.page.getByRole('button',{name:'Dictate',exact:true}).click();
    await f.page.getByRole('button',{name:'Stop recording',exact:true}).waitFor();
    await f.page.waitForFunction(()=>document.querySelector('[title^="Bluetooth: waiting."]'));
    assert.deepEqual(f.deviceRecords,[{type:'bluetooth',on:true}],'compiled dictation start reconnects the actual selected ESP32 target');
    await f.feed(.08);await f.feed(0);f.releaseFirst();await f.page.getByLabel('Recognized text',{exact:true}).getByText('THE NEWEST SPOKEN WORDS ARE VISIBLE',{exact:false}).waitFor();
    assert(!f.records.some(x=>x.command.type==='text'),'recognized segment waits while BLE advertises');
    f.reportBluetooth('connected');await f.page.waitForFunction(()=>document.querySelector('[title^="Bluetooth: connected."]'));
    for(let n=0;n<50&&!f.records.some(x=>x.command.type==='text');n++)await f.page.waitForTimeout(20);
    assert.equal(f.records.filter(x=>x.command.type==='text').length,1);assert.match(f.records.find(x=>x.command.type==='text').command.text,/THE NEWEST SPOKEN WORDS/);
    await f.page.getByRole('button',{name:'Temporarily disable Bluetooth keyboard',exact:true}).click();await f.page.getByRole('button',{name:'Enable Bluetooth keyboard',exact:true}).waitFor();assert.equal(f.deviceRecords.at(-1).on,false);
    await f.page.getByRole('button',{name:'Stop recording',exact:true}).click();assert.deepEqual(f.errors,[]);
    if(process.env.REVIEW_SCREENSHOT_DIR){fs.mkdirSync(process.env.REVIEW_SCREENSHOT_DIR,{recursive:true});await f.page.screenshot({path:path.join(process.env.REVIEW_SCREENSHOT_DIR,`${process.env.REVIEW_BROWSER||'chromium'}-bluetooth-${viewport.width}x${viewport.height}.png`)});}
    console.log(`PASS compiled ESP32 dictation resume/wait/recognized input/explicit off ${viewport.width}x${viewport.height}`);
   }finally{await f.close()}
  }
 }
 }finally{await browser.close()}})().catch(e=>{console.error(e);process.exit(1)});
