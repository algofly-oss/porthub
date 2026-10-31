const assert=require('node:assert/strict');const {launchBrowser}=require('./browser.cjs');const {spawn}=require('node:child_process');
async function output(page,text){await page.bringToFront();try{await page.waitForFunction(text=>document.querySelector('.xterm-rows')?.textContent.includes(text),text,{timeout:15000})}catch(error){await page.screenshot({path:'/tmp/porthub-terminal-live-output-failure.png'});throw new Error('Expected '+text+'; real terminal view: '+(await page.locator('main').innerText()).slice(-5000));}}
async function type(page,command){await page.bringToFront();await page.locator('.xterm-helper-textarea').focus();await page.keyboard.type(command);await page.keyboard.press('Enter');}
(async()=>{const browser=await launchBrowser();let ssh,sshReader;try{
const origin=process.env.REVIEW_ORIGIN,write=process.env.PORTHUB_TEST_TERMINAL_WRITE,read=process.env.PORTHUB_TEST_TERMINAL_READ,session=process.env.PORTHUB_TEST_TERMINAL_SESSION;
const owner=await browser.newContext({viewport:{width:1440,height:900}}),guest=await browser.newContext({viewport:{width:1100,height:900}});
const cookie=process.env.PORTHUB_TEST_TERMINAL_COOKIE;const separator=cookie.indexOf('=');await owner.addCookies([{name:cookie.slice(0,separator),value:cookie.slice(separator+1),url:origin,httpOnly:true,sameSite:'Lax'}]);
const host=await owner.newPage(),watcher=await guest.newPage();const errors=[];for(const page of [host,watcher])page.on('pageerror',e=>errors.push(e.message));
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
await host.locator('.xterm-helper-textarea').focus();await host.keyboard.press('Control+d');await host.getByRole('button',{name:'Reconnect',exact:true}).waitFor();
assert.deepEqual(errors,[]);console.log('PASS live browser/API/bundled tmux: anonymous browser and ordinary SSH guests, owner administration, shared shell state and SSH-disconnect persistence, safe browser and read-only SSH scrollback, tab recovery despite revoked invitations, durable removal and explicit Ctrl+D teardown');
await owner.close();await guest.close();
}finally{ssh?.kill('SIGTERM');sshReader?.kill('SIGTERM');await browser.close()}})().catch(error=>{console.error(String(error.stack||error).replace(/[a-f0-9]{64}/g,'[capability]'));process.exitCode=1});
