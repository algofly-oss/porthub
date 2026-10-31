const assert=require('node:assert/strict');const {launchBrowser}=require('./browser.cjs');const {spawn}=require('node:child_process');
async function output(page,text){await page.bringToFront();try{await page.waitForFunction(text=>document.querySelector('.xterm-rows')?.textContent.includes(text),text,{timeout:15000})}catch(error){await page.screenshot({path:'/tmp/porthub-terminal-live-output-failure.png'});throw new Error('Expected '+text+'; real terminal view: '+(await page.locator('main').innerText()).slice(-5000));}}
async function type(page,command){await page.bringToFront();await page.locator('.xterm-helper-textarea').focus();await page.keyboard.type(command);await page.keyboard.press('Enter');}
(async()=>{const browser=await launchBrowser();let ssh,sshReader;try{
const origin=process.env.REVIEW_ORIGIN,write=process.env.PORTHUB_TEST_TERMINAL_WRITE,read=process.env.PORTHUB_TEST_TERMINAL_READ,session=process.env.PORTHUB_TEST_TERMINAL_SESSION;
const owner=await browser.newContext({viewport:{width:1440,height:900}}),guest=await browser.newContext({viewport:{width:1100,height:900}});
const cookie=process.env.PORTHUB_TEST_TERMINAL_COOKIE;const separator=cookie.indexOf('=');await owner.addCookies([{name:cookie.slice(0,separator),value:cookie.slice(separator+1),url:origin,httpOnly:true,sameSite:'Lax'}]);
const host=await owner.newPage(),watcher=await guest.newPage();let hostConnections=0;host.on('websocket',socket=>{if(new URL(socket.url()).pathname==='/api/terminal/join')hostConnections++;});const errors=[];for(const page of [host,watcher])page.on('pageerror',e=>errors.push(e.message));
await host.goto(`${origin}/terminal#${write}`);await host.getByRole('button',{name:'Connect',exact:true}).click();await host.getByRole('heading',{name:'amberotter',exact:true}).waitFor();
await watcher.goto(`${origin}/terminal#${read}`);await watcher.getByRole('button',{name:'Connect',exact:true}).click();await watcher.getByRole('heading',{name:'amberotter',exact:true}).waitFor();
await output(host,'porthub-test$');await output(watcher,'porthub-test$');
await type(host,"OWNVAR=preserved; printf 'INITIAL%s\\n' 'SHARED'");await output(host,'INITIALSHARED');await output(watcher,'INITIALSHARED');
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
    const socket=new WebSocket(endpoint),state={socket,bytes:0,closed:false,text:'',history:null};let ready=false;
    state.pressureStarted=new Promise(resolve=>state.startPressure=resolve);
    const deadline=setTimeout(()=>{socket.close();reject(new Error('stress guest attach timed out'));},5000);
    socket.onopen=()=>socket.send(JSON.stringify({...(resume?{resume_token:capability}:{token:capability}),cols:80,rows:24}));
    socket.onerror=()=>{if(!ready){clearTimeout(deadline);reject(new Error('stress guest transport failed'));}};
    socket.onclose=()=>{state.closed=true;if(!ready){clearTimeout(deadline);reject(new Error('stress guest closed before welcome'));}};
    socket.onmessage=event=>{const message=JSON.parse(event.data);
      if(message.type==='ping'){socket.send(JSON.stringify({type:'pong'}));return;}
      if(message.type==='recovery'){state.recovery=message.token;state.identity=message.participant;}
      if(message.type==='welcome'){clearTimeout(deadline);if(!message.read_only || expected && state.identity!==expected){socket.close();reject(new Error('stress recovery changed identity or role'));return;}ready=true;window.__terminalStress.push(state);resolve(state);}
      if(message.type==='output'){const bytes=atob(message.data);state.bytes+=bytes.length;state.text=(state.text+bytes).slice(-8192);if(state.text.includes('churn-line-0-')){state.startPressure?.();state.startPressure=null;}}
      if(message.type==='history' && message.page.done && state.history){state.history(message.page);state.history=null;}
      if(message.type==='closed'){socket.close();if(!ready){clearTimeout(deadline);reject(new Error('stress guest admission denied'));}}
    };
  });
  window.__stressStable=await window.__terminalStressAttach(token,false);
  window.__stressMoving=await window.__terminalStressAttach(token,false);
},read);
const pressure=type(host,"i=0; while [ $i -lt 100 ]; do printf 'churn-line-%s-%080d\\n' \"$i\" 0; i=$((i+1)); sleep 0.005; done; printf 'CHURN%s:%s\\n' 'DONE' \"$OWNVAR\"");
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
const [,stress]=await Promise.all([pressure,churn]);assert.equal(stress.histories,6);assert.equal(stress.attachments,8);
await output(host,'CHURNDONE:preserved');await output(watcher,'CHURNDONE:preserved');
await watcher.evaluate(()=>{if(window.__stressStable.bytes===0)throw new Error('stable guest received no output');for(const state of window.__terminalStress)state.socket.close();delete window.__terminalStressAttach;delete window.__terminalStress;delete window.__stressStable;delete window.__stressMoving;});
await host.getByRole('button',{name:'Block new joins',exact:true}).click();await host.getByRole('button',{name:'Block invitation URLs',exact:true}).click();await host.getByText('New invitation joins blocked',{exact:true}).waitFor();
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
await type(host,"printf 'LIVE%s:%s\\n' 'CONTINUES' \"$OWNVAR\"");await output(host,'LIVECONTINUES:preserved');await watcher.getByRole('button',{name:'Return to live',exact:true}).click();await output(watcher,'LIVECONTINUES:preserved');
const identity=(await watcher.getByText(/Guest .*\(you\)/).innerText()).match(/Guest (\d+)/)[1];
await watcher.reload();await watcher.getByRole('button',{name:'Connect',exact:true}).click();await watcher.getByRole('heading',{name:'amberotter',exact:true}).waitFor();await watcher.getByText(`Guest ${identity} (you)`,{exact:true}).waitFor();
await output(watcher,'LIVECONTINUES:preserved');
const remove=host.getByRole('button',{name:`Remove Guest ${identity}`,exact:true});await remove.click();await host.getByRole('button',{name:'Remove guest',exact:true}).click();await watcher.getByRole('alert').filter({hasText:'removed by the host'}).waitFor();
await type(host,"printf 'SURVIVED:%s:%s\\n' \"$OWNVAR\" \"${UNAUTHORIZED-unset}\"");await output(host,'SURVIVED:preserved:unset');
await watcher.getByRole('button',{name:'Reconnect',exact:true}).click();await watcher.getByRole('alert').filter({hasText:'Recovery expired, revoked'}).waitFor();
assert.equal(hostConnections,1,'host input must survive pressure without a hidden reconnect');
await host.locator('.xterm-helper-textarea').focus();await host.keyboard.press('Control+d');await host.getByRole('button',{name:'Reconnect',exact:true}).waitFor();
assert.deepEqual(errors,[]);console.log('PASS live browser/API/bundled tmux: anonymous browser and ordinary SSH guests, owner administration, shared shell state and SSH-disconnect persistence, safe browser and read-only SSH scrollback, concurrent recovery/history/output pressure, tab recovery despite revoked invitations, durable removal and explicit Ctrl+D teardown');
await owner.close();await guest.close();
}finally{ssh?.kill('SIGTERM');sshReader?.kill('SIGTERM');await browser.close()}})().catch(error=>{console.error(String(error.stack||error).replace(/[a-f0-9]{64}/g,'[capability]'));process.exitCode=1});
