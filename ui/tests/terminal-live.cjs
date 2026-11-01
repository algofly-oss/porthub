const assert=require('node:assert/strict');const {launchBrowser}=require('./browser.cjs');const {spawn}=require('node:child_process');
async function output(page,text){await page.bringToFront();try{await page.waitForFunction(text=>document.querySelector('.xterm-rows')?.textContent.includes(text),text,{timeout:15000})}catch(error){await page.screenshot({path:'/tmp/porthub-terminal-live-output-failure.png'});throw new Error('Expected '+text+'; real terminal view: '+(await page.locator('main').innerText()).slice(-5000)+'; transport '+JSON.stringify(page.__transportStats?.()));}}
async function type(page,command){await page.bringToFront();await page.locator('.xterm-helper-textarea').focus();await page.keyboard.type(command);await page.keyboard.press('Enter');}
(async()=>{const browser=await launchBrowser();let ssh,sshReader;try{
const origin=process.env.REVIEW_ORIGIN,write=process.env.PORTHUB_TEST_TERMINAL_WRITE,read=process.env.PORTHUB_TEST_TERMINAL_READ,session=process.env.PORTHUB_TEST_TERMINAL_SESSION;
const owner=await browser.newContext({viewport:{width:1440,height:900}}),guest=await browser.newContext({viewport:{width:1100,height:900}});
if(process.env.PORTHUB_TEST_TERMINAL_DIRECT)for(const context of [owner,guest])await context.addInitScript(blocked=>{
 const Peer=window.RTCPeerConnection;window.__terminalDirect={opened:0,sent:0,received:0};
 window.RTCPeerConnection=function(config){const peer=new Peer(config),create=peer.createDataChannel.bind(peer);if(blocked)peer.setRemoteDescription=async()=>{throw Error('fixture blocks the direct path');};peer.createDataChannel=(...args)=>{
  const channel=create(...args),send=channel.send.bind(channel);channel.addEventListener('open',()=>window.__terminalDirect.opened++);channel.addEventListener('message',()=>window.__terminalDirect.received++);
  channel.send=bytes=>{window.__terminalDirect.sent++;return send(bytes);};return channel;
 };return peer;};
},process.env.PORTHUB_TEST_TERMINAL_DIRECT==='blocked');
const cookie=process.env.PORTHUB_TEST_TERMINAL_COOKIE;const separator=cookie.indexOf('=');await owner.addCookies([{name:cookie.slice(0,separator),value:cookie.slice(separator+1),url:origin,httpOnly:true,sameSite:'Lax'}]);
const host=await owner.newPage(),watcher=await guest.newPage();let phase="join";const hostEvents=[];let hostConnections=0,directRelay=0,relayInputs=0,relayAcks=0;host.on('websocket',socket=>{if(new URL(socket.url()).pathname==='/api/terminal/join'){hostConnections++;hostEvents.push({phase,event:"open"});socket.on("close",()=>hostEvents.push({phase,event:"close"}));socket.on('framesent',({payload})=>{try{const frame=JSON.parse(payload);if(frame.type==='delivery'){directRelay++;if(Buffer.from(frame.packet,'base64')[0]===1)relayInputs++;}}catch{}});socket.on('framereceived',({payload})=>{try{const frame=JSON.parse(payload);if(frame.type==='closed')hostEvents.push({phase,event:'closed',reason:frame.reason});if(frame.type==='delivery'&&Buffer.from(frame.packet,'base64')[0]===2)relayAcks++;}catch{}});}});host.__transportStats=()=>({hostConnections,relayInputs,relayAcks});const errors=[];for(const page of [host,watcher])page.on('pageerror',e=>errors.push(e.message));
await host.goto(`${origin}/terminal#${write}`);await host.getByRole('button',{name:'Connect',exact:true}).click();await host.getByRole('heading',{name:'amberotter',exact:true}).waitFor();
const historyFrames=[];watcher.on('websocket',socket=>socket.on('framesent',({payload})=>{try{const frame=JSON.parse(payload);if(frame.type==='history')historyFrames.push(frame)}catch{}}));
await watcher.goto(`${origin}/terminal#${read}`);await watcher.getByRole('button',{name:'Connect',exact:true}).click();await watcher.getByRole('heading',{name:'amberotter',exact:true}).waitFor();
await output(host,'porthub-test$');await output(watcher,'porthub-test$');
await type(host,"OWNVAR=preserved; printf 'INITIAL%s\\n' 'SHARED'");await output(host,'INITIALSHARED');await output(watcher,'INITIALSHARED');
if(process.env.PORTHUB_TEST_TERMINAL_DIRECT==='blocked'){
 await host.waitForFunction(()=>window.__terminalDirect.opened===0);
 assert(directRelay>0,'blocked direct path must carry sequenced bytes through the actual gateway');
 console.log('PASS blocked browser direct path: real SDK and gateway relay preserve shell input/output without an open data channel');
}else if(process.env.PORTHUB_TEST_TERMINAL_DIRECT){
 // Setup output may finish over relay before either channel opens on a busy
 // runner. Wait for both channels, then generate fresh traffic to prove their
 // bidirectional data path rather than requiring earlier bytes to use it.
 for(const page of [host,watcher])await page.waitForFunction(()=>window.__terminalDirect.opened>0,null,{timeout:15000});
 await type(host,"printf 'DIRECT%s\\n' 'READY'");await output(host,'DIRECTREADY');await output(watcher,'DIRECTREADY');
 for(const page of [host,watcher])try{await page.waitForFunction(()=>window.__terminalDirect.sent>0 && window.__terminalDirect.received>0,null,{timeout:15000});}catch(error){throw Error('Direct channel opened but fresh shared I/O did not traverse it: '+JSON.stringify(await page.evaluate(()=>window.__terminalDirect)));}
 console.log('PASS real browser direct path: native sharing supervisor, authenticated broker, API signalling and bidirectional WebRTC bytes');
}
const sshArguments=['-F','/dev/null','-oStrictHostKeyChecking=no','-oUserKnownHostsFile=/dev/null','-oLogLevel=ERROR','-oBatchMode=yes','-tt','-p',process.env.PORTHUB_TEST_TERMINAL_SSH_PORT,'-l',write,'127.0.0.1'];ssh=spawn('ssh',sshArguments,{stdio:['pipe','pipe','pipe'],env:{...process.env,TERM:'xterm-256color'}});
const readerArguments=[...sshArguments];readerArguments[readerArguments.indexOf('-l')+1]=read;
sshReader=spawn('ssh',readerArguments,{stdio:['pipe','pipe','pipe'],env:{...process.env,TERM:'xterm-256color'}});let readerText='',readerError='';sshReader.stdout.on('data',data=>readerText=(readerText+data.toString()).slice(-262144));sshReader.stderr.on('data',data=>readerError=(readerError+data.toString()).slice(-4096));
async function readerOutput(text){const deadline=Date.now()+10000;while(!readerText.includes(text)){assert(Date.now()<deadline && sshReader.exitCode===null,'read-only SSH did not show '+text+': '+readerError+' '+readerText.slice(-1000));await new Promise(resolve=>setTimeout(resolve,25));}}
await readerOutput('porthub-test$');sshReader.stdin.write('UNAUTHORIZED=bad\r');
let sshText='',sshError='';ssh.stdout.on('data',data=>{sshText=(sshText+data.toString()).slice(-262144)});ssh.stderr.on('data',data=>{sshError=(sshError+data.toString()).slice(-4096)});
async function sshOutput(text){const deadline=Date.now()+10000;while(!sshText.includes(text)){assert(Date.now()<deadline && ssh.exitCode===null,'ordinary SSH did not show shared output: '+sshError);await new Promise(resolve=>setTimeout(resolve,25));}}
await sshOutput('porthub-test$');ssh.stdin.write("printf 'SSHJOINED:%s\\n' \"$OWNVAR\"\r");await output(host,'SSHJOINED:preserved');await output(watcher,'SSHJOINED:preserved');await sshOutput('SSHJOINED:preserved');
// Actual guest WebSockets churn recovery leases while the bundled shell keeps
// emitting output. No production account, broker or network route is touched.
await watcher.evaluate(async token=>{
  const endpoint=new URL('/api/terminal/join',location.origin);endpoint.protocol=location.protocol==='https:'?'wss:':'ws:';
  window.__terminalStress=[];
  window.__terminalStressAttach=(capability,resume,expected)=>new Promise((resolve,reject)=>{
    const socket=new WebSocket(endpoint),state={socket,bytes:0,closed:false,text:'',history:null};let ready=false,admitted=false;
    state.pressureStarted=new Promise(resolve=>state.startPressure=resolve);
    const deadline=setTimeout(()=>{socket.close();reject(new Error('stress guest attach timed out'));},5000);
    // Admission precedes the native PTY's initial screen. Start pressure only
    // after that screen arrives, so a late attachment cannot miss line zero.
    const complete=()=>{if(admitted && !ready && state.bytes>0){clearTimeout(deadline);ready=true;window.__terminalStress.push(state);resolve(state);}};
    socket.onopen=()=>socket.send(JSON.stringify({...(resume?{resume_token:capability}:{token:capability}),cols:80,rows:24}));
    socket.onerror=()=>{if(!ready){clearTimeout(deadline);reject(new Error('stress guest transport failed'));}};
    socket.onclose=()=>{state.closed=true;if(!ready){clearTimeout(deadline);reject(new Error('stress guest closed before welcome'));}};
    socket.onmessage=event=>{const message=JSON.parse(event.data);
      if(message.type==='ping'){socket.send(JSON.stringify({type:'pong'}));return;}
      if(message.type==='recovery'){state.recovery=message.token;state.identity=message.participant;}
      if(message.type==='welcome'){if(!message.read_only || expected && state.identity!==expected){clearTimeout(deadline);socket.close();reject(new Error('stress recovery changed identity or role'));return;}admitted=true;complete();}
      if(message.type==='output'){const bytes=atob(message.data);state.bytes+=bytes.length;state.text=(state.text+bytes).slice(-8192);if(state.text.includes('churn-line-0-')){state.startPressure?.();state.startPressure=null;}complete();}
      if(message.type==='history' && message.page.done && state.history){state.history(message.page);state.history=null;}
      if(message.type==='closed'){socket.close();if(!ready){clearTimeout(deadline);reject(new Error('stress guest admission denied'));}}
    };
  });
  window.__stressStable=await window.__terminalStressAttach(token,false);
  window.__stressMoving=await window.__terminalStressAttach(token,false);
},read);
phase="pressure";const pressure=type(host,"i=0; while [ $i -lt 100 ]; do printf 'churn-line-%s-%080d\\n' \"$i\" 0; i=$((i+1)); sleep 0.005; done; printf 'CHURN%s:%s\\n' 'DONE' \"$OWNVAR\"");
const churn=watcher.evaluate(async()=>{
  await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('shell pressure did not begin')),5000);window.__stressStable.pressureStarted.then(()=>{clearTimeout(timer);resolve();});});
  const identity=window.__stressMoving.identity;let histories=0;
  for(let index=0;index<6;index++){
    const previous=window.__stressMoving;previous.socket.close();
    const current=await window.__terminalStressAttach(previous.recovery,true,identity);window.__stressMoving=current;
    await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('history stalled during recovery churn')),5000);current.history=page=>{clearTimeout(timer);if(page.request!==index+1)reject(new Error('history response crossed guest requests'));else{histories++;resolve();}};current.socket.send(JSON.stringify({type:'history',request:index+1,pane:'',before:0,lines:20}));});
  }
  if(window.__stressStable.closed || window.__stressMoving.closed)throw new Error('independent read-only guest was interrupted during churn');
  return {histories,attachments:window.__terminalStress.length};
});
let stress;
try{[,stress]=await Promise.all([pressure,churn]);}catch(error){
 const diagnostics={hostConnections,relayInputs,relayAcks,host:await host.evaluate(()=>({screen:document.querySelector('.xterm-rows')?.textContent.slice(-2500),alerts:[...document.querySelectorAll('[role="alert"]')].map(node=>node.textContent),direct:window.__terminalDirect})),watcher:await watcher.evaluate(()=>({direct:window.__terminalDirect,stable:window.__stressStable&&{bytes:window.__stressStable.bytes,closed:window.__stressStable.closed,text:window.__stressStable.text.slice(-1200)}}))};
 throw Error(error.message+'; pressure diagnostics '+JSON.stringify(diagnostics));
}
assert.equal(stress.histories,6);assert.equal(stress.attachments,8);
await output(host,'CHURNDONE:preserved');await output(watcher,'CHURNDONE:preserved');
await watcher.evaluate(()=>{if(window.__stressStable.bytes===0)throw new Error('stable guest received no output');for(const state of window.__terminalStress)state.socket.close();delete window.__terminalStressAttach;delete window.__terminalStress;delete window.__stressStable;delete window.__stressMoving;});
phase="history";await host.getByRole('button',{name:'Block new joins',exact:true}).click();await host.getByRole('button',{name:'Block invitation URLs',exact:true}).click();await host.getByText('New invitation joins blocked',{exact:true}).waitFor();
const blocked=await guest.newPage();blocked.on('pageerror',error=>errors.push(error.message));await blocked.goto(`${origin}/terminal#${read}`);await blocked.getByRole('button',{name:'Connect',exact:true}).click();await blocked.getByRole('alert').filter({hasText:'Invitation expired, revoked'}).waitFor();await blocked.close();



const deniedSsh=spawn('ssh',sshArguments,{stdio:['ignore','ignore','pipe'],timeout:5000});let rejection='';deniedSsh.stderr.on('data',data=>rejection+=data.toString());
const rejected=await new Promise(resolve=>deniedSsh.once('exit',(code,signal)=>resolve({code,signal})));assert.equal(rejected.code,255);assert.equal(rejected.signal,null);assert(/Permission denied|Authentication failed/i.test(rejection),'revoked SSH invitation must be denied during authentication');
ssh.stdin.write("printf 'SSHAFTERBLOCK:%s\\n' \"$OWNVAR\"\r");await output(host,'SSHAFTERBLOCK:preserved');await sshOutput('SSHAFTERBLOCK:preserved');
ssh.kill('SIGTERM');await new Promise(resolve=>ssh.once('exit',resolve));ssh=null;
await type(host,"printf 'SSHDISCONNECT:%s\\n' \"$OWNVAR\"");await output(host,'SSHDISCONNECT:preserved');
await watcher.bringToFront();await watcher.locator('.xterm-helper-textarea').focus();await watcher.keyboard.type('UNAUTHORIZED=bad');await watcher.keyboard.press('Enter');
const denied=await watcher.evaluate(async session=>{const result=await fetch(`/api/terminal/${session}/kick`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client:1})});return result.status},session);assert(denied>=400,'anonymous guest cannot manage participants');assert.equal(await watcher.getByRole('button',{name:/^Remove Guest /}).count(),0);
await type(host,"i=0; while [ $i -lt 260 ]; do printf 'history-line-%s\\n' \"$i\"; i=$((i+1)); done; printf 'HISTORY%s\\n' 'READY'");await output(host,'HISTORYREADY');await output(watcher,'HISTORYREADY');
readerText='';sshReader.stdin.write('\x1b[18~');await readerOutput('Scrollback');await readerOutput('F7 or q live');
await type(host,"printf 'LIVESSH%s:%s\\n' 'PAGER' \"$OWNVAR\"");await output(host,'LIVESSHPAGER:preserved');
readerText='';sshReader.stdin.write('\x1b[5~');await readerOutput('21 lines back');
readerText='';sshReader.stdin.write('q');await readerOutput('LIVESSHPAGER:preserved');
sshReader.kill('SIGTERM');await new Promise(resolve=>sshReader.once('exit',resolve));sshReader=null;

await watcher.getByRole('button',{name:'History',exact:true}).click();try{await watcher.getByLabel('Captured history text',{exact:true}).getByText('history-line-100',{exact:true}).waitFor({timeout:5000})}catch(error){await watcher.screenshot({path:'/tmp/porthub-terminal-live-history-failure.png'});throw new Error('Real history failed: '+(await watcher.getByLabel('Terminal history',{exact:true}).innerText()).slice(0,1600));}
assert.equal(await watcher.getByLabel('History pane',{exact:true}).inputValue(),'%0','real history must pin the resolved workspace pane');
const frozenText=await watcher.getByLabel('Captured history text',{exact:true}).innerText();
assert.equal(historyFrames.at(-1).freeze,true,'real browser negotiates frozen history');
assert.equal(historyFrames.at(-1).snapshot,undefined,'first capture has no existing anchor');
await type(host,"i=0; while [ $i -lt 80 ]; do echo subsequent-$i; i=$((i+1)); done; printf 'AFTER%s\\n' 'SNAPSHOT'");await output(host,'AFTERSNAPSHOT');
await watcher.setViewportSize({width:720,height:700});
await watcher.waitForTimeout(550);await watcher.getByRole('button',{name:'Older',exact:true}).click();
await watcher.waitForFunction(()=>!Array.from(document.querySelectorAll('button')).find(b=>b.textContent==='Latest')?.disabled);
const anchor=historyFrames.at(-1).snapshot;assert.match(anchor,/^[a-f0-9]{32}$/);
await watcher.waitForTimeout(550);await watcher.getByRole('button',{name:'Latest',exact:true}).click();
await watcher.waitForFunction(()=>!Array.from(document.querySelectorAll('button')).find(b=>b.textContent==='Refresh history')?.disabled);
assert.equal(await watcher.getByLabel('Captured history text',{exact:true}).innerText(),frozenText,'live output and resize cannot shift retained history');
assert.equal(historyFrames.at(-1).snapshot,anchor,'Latest keeps the same anchor');
await watcher.waitForTimeout(550);await watcher.getByRole('button',{name:'Refresh history',exact:true}).click();
await watcher.getByLabel('Captured history text',{exact:true}).getByText('subsequent-0',{exact:true}).waitFor();
assert.equal(historyFrames.at(-1).snapshot,undefined,'explicit refresh captures new history');

await type(host,"printf 'LIVE%s:%s\\n' 'CONTINUES' \"$OWNVAR\"");await output(host,'LIVECONTINUES:preserved');await watcher.getByRole('button',{name:'Return to live',exact:true}).click();await output(watcher,'LIVECONTINUES:preserved');
const identity=(await watcher.getByText(/Guest .*\(you\)/).innerText()).match(/Guest (\d+)/)[1];
await watcher.reload();await watcher.getByRole('button',{name:'Connect',exact:true}).click();await watcher.getByRole('heading',{name:'amberotter',exact:true}).waitFor();await watcher.getByText(`Guest ${identity} (you)`,{exact:true}).waitFor();
await output(watcher,'LIVECONTINUES:preserved');
phase="management";let nativeRemoval;
if(process.env.PORTHUB_TEST_NATIVE_CLI){
  const driver=spawn('python3',[require('node:path').join(__dirname,'../../scripts/test-terminal-supervisor-sidebar.py'),process.env.PORTHUB_TEST_NATIVE_CLI,session,identity],{stdio:['ignore','pipe','pipe']});
  let diagnostics='';for(const stream of [driver.stdout,driver.stderr])stream.on('data',data=>diagnostics=(diagnostics+data.toString()).slice(-8192));
  nativeRemoval=new Promise((resolve,reject)=>{driver.once('error',reject);driver.once('exit',code=>code===0?resolve():reject(new Error('Native sidebar failed: '+diagnostics)));});
}else{
  const remove=host.getByRole('button',{name:`Remove Guest ${identity}`,exact:true});await remove.click();await host.getByRole('button',{name:'Remove guest',exact:true}).click();
}
await watcher.getByRole('alert').filter({hasText:'removed by the host'}).waitFor();
if(nativeRemoval){await nativeRemoval;await output(host,"SIDEBAROWNER:preserved");console.log("PASS native CLI sidebar -> real owner socket -> broker -> API: selected guest removed; remaining browser and shell preserved");}

await type(host,"printf 'SURVIVED:%s:%s\\n' \"$OWNVAR\" \"${UNAUTHORIZED-unset}\"");await output(host,'SURVIVED:preserved:unset');
await watcher.getByRole('button',{name:'Reconnect',exact:true}).click();await watcher.getByRole('alert').filter({hasText:'Recovery expired, revoked'}).waitFor();
assert.equal(hostConnections,1,'host input must survive pressure without a hidden reconnect: '+JSON.stringify(hostEvents));
await host.locator('.xterm-helper-textarea').focus();await host.keyboard.press('Control+d');await host.getByRole('button',{name:'Reconnect',exact:true}).waitFor();
if(process.env.PORTHUB_TEST_NATIVE_CLI){
  await host.bringToFront();
  await host.goto(`${origin}/home?view=dashboard&terminal_range=10m&terminal_scope=direct`);
  const card=host.getByRole('region',{name:'Terminal traffic',exact:true});
  const chart=card.getByRole('group',{name:/Terminal traffic chart/});
  await chart.waitFor();
  assert.equal(await card.getByLabel('Terminal traffic range',{exact:true}).inputValue(),'10m');
  assert.equal(await card.getByRole('tab',{name:'Direct UDP',exact:true}).getAttribute('aria-selected'),'true');
  await host.evaluate(()=>fetch('/__fixture/terminal-traffic/unavailable',{method:'POST'}));
  await host.getByRole('button',{name:'Refresh dashboard',exact:true}).click();
  await card.getByRole('alert').filter({hasText:'Showing the last successful snapshot'}).waitFor();
  assert(await chart.isVisible(),'reporting errors must preserve the last successful graph');
  await host.evaluate(()=>fetch('/__fixture/terminal-traffic/available',{method:'POST'}));
  await host.getByRole('button',{name:'Refresh dashboard',exact:true}).click();
  await card.getByRole('alert').waitFor({state:'hidden'});
  if(process.env.REVIEW_BROWSER!=='webkit' && process.env.PORTHUB_TEST_TERMINAL_DIRECT==='1'){
    await card.getByRole('button',{name:'Pause terminal measurements',exact:true}).click();
    await card.getByText('Paused',{exact:true}).waitFor();
    await host.waitForTimeout(250);
    const requests=()=>host.evaluate(async()=> (await fetch('/__fixture/terminal-traffic/requests',{method:'POST',cache:'no-store'})).json());
    const before=(await requests()).requests;assert(before>0,'fixture must observe actual graph requests');
    await host.waitForTimeout(16000);
    assert.equal((await requests()).requests,before,'paused terminal graphs must stop HTTP polling');
  }
  console.log('PASS real account dashboard: reported terminal intervals, URL controls, outage recovery and preserved snapshots');
}
assert.deepEqual(errors,[]);console.log('PASS live browser/API/bundled tmux: anonymous browser and ordinary SSH guests, owner administration, shared shell state and SSH-disconnect persistence, safe browser and read-only SSH scrollback, concurrent recovery/history/output pressure, tab recovery despite revoked invitations, durable removal and explicit Ctrl+D teardown');
await owner.close();await guest.close();
}finally{ssh?.kill('SIGTERM');sshReader?.kill('SIGTERM');await browser.close()}})().catch(error=>{console.error(String(error.stack||error).replace(/[a-f0-9]{64}/g,'[capability]'));process.exitCode=1});
