// Explicit live deployment fixture; receives only its own invitations on stdin.
const assert = require('node:assert/strict');
const {spawn,execFileSync} = require('node:child_process');
const {launchBrowser} = require('../ui/tests/browser.cjs');
const fs = require('node:fs');
const input = JSON.parse(fs.readFileSync(0,'utf8'));
const children = [];
const owner = (...args) => execFileSync('ssh',['-oBatchMode=yes',input.host,
  input.ownerPrefix+' '+args.map(value=>{assert(/^[a-z0-9-]+$/.test(String(value)));return String(value)}).join(' ')],
  {encoding:'utf8',timeout:20000});
async function text(page,marker) {
  await page.waitForFunction(value=>document.querySelector('.xterm-rows')?.textContent.includes(value),marker,{timeout:15000});
}
async function main() {
  let browser,page;
  try {
    browser = await launchBrowser();
    const context = await browser.newContext({viewport:{width:1440,height:900}});
    page = await context.newPage();
    const errors=[],historyFrames=[];let welcome;
    page.on('pageerror',error=>errors.push(error.message));
    page.on('websocket',socket=>{
      if(new URL(socket.url()).pathname!=='/api/terminal/join')return;
      socket.on('framereceived',({payload})=>{try{const event=JSON.parse(String(payload));if(event.type==='welcome')welcome=event;}catch{}});
      socket.on('framesent',({payload})=>{try{const event=JSON.parse(String(payload));if(event.type==='history')historyFrames.push(event);}catch{}});
    });
    await page.goto(input.invitation.read_only_url,{waitUntil:'networkidle',timeout:30000});
    await page.getByRole('button',{name:'Connect',exact:true}).click();
    await page.getByRole('heading',{name:input.name,exact:true}).waitFor();
    assert.equal(await page.getByRole('button',{name:/Remove Guest|Remove participant|Block new joins/i}).count(),0);
    const launchSSH=()=>{
      const child=spawn('ssh',[...input.sshOptions,...input.sshArguments],{stdio:['pipe','pipe','pipe'],env:{...process.env,TERM:'xterm-256color'}});
      children.push(child);let output='';child.stdout.on('data',data=>output=(output+data.toString()).slice(-262144));
      child.stderr.resume();child.output=()=>output;
      return child;
    };
    const waitSSH=async(child,marker)=>{
      const deadline=Date.now()+15000;
      while(!child.output().includes(marker)){
        assert(Date.now()<deadline&&child.exitCode===null,'SSH did not reach the shared terminal');
        await new Promise(resolve=>setTimeout(resolve,25));
      }
    };
    let ssh=launchSSH();
    await waitSSH(ssh,'porthub-live$');
    ssh.stdin.write(`LIVEVALUE=${input.marker}; printf 'LIVE%s\\n' 'READY${input.marker}'\r`);
    await waitSSH(ssh,'LIVEREADY'+input.marker);await text(page,'LIVEREADY'+input.marker);
    // Scrollback excludes the currently visible screen. Produce real history
    // before checking a retained marker; a fresh shell has none yet.
    ssh.stdin.write(`i=0; while [ $i -lt 80 ]; do printf 'HISTORYROW%s\\n' \"$i\"; i=$((i+1)); done; printf 'PAGEEND%s\\n' '${input.marker}'\r`);
    await waitSSH(ssh,'PAGEEND'+input.marker);await text(page,'PAGEEND'+input.marker);
    await page.getByRole('button',{name:'History',exact:true}).click();
    await page.getByLabel('Captured history text',{exact:true}).filter({hasText:'LIVEREADY'+input.marker}).waitFor();
    if(input.requireModern){
      assert.equal(welcome?.history_snapshots,true,'live host and gateway must negotiate frozen history');
      assert.equal(historyFrames.at(-1)?.freeze,true,'browser must request a frozen snapshot');
      const pane=await page.getByLabel('History pane',{exact:true}).inputValue();assert.match(pane,/^%[0-9]+$/);
      const captured=await page.getByLabel('Captured history text',{exact:true}).innerText();
      await page.getByRole('button',{name:'Refresh history',exact:true}).waitFor({state:'visible'});
      assert(await page.getByLabel('Terminal history',{exact:true}).innerText().then(text=>text.includes('History stays fixed until you refresh.')));
      ssh.stdin.write(`printf 'SNAPSHOTSTABLE%s\\n' '${input.marker}'\r`);
      await waitSSH(ssh,'SNAPSHOTSTABLE'+input.marker);
      assert.equal(await page.getByLabel('Captured history text',{exact:true}).innerText(),captured,'live output must preserve the captured page');
      console.log('PASS live modern negotiation: frozen history with a resolved pane and stable capture');
    }
    await page.getByRole('button',{name:'Return to live',exact:true}).click();
    // Losing the stock SSH attachment must preserve the shell variable.
    ssh.kill('SIGTERM');await new Promise(resolve=>ssh.once('close',resolve));
    ssh=launchSSH();await waitSSH(ssh,'porthub-live$');
    ssh.stdin.write(`printf 'PERSIST=%s\\n' "$LIVEVALUE"\r`);
    await waitSSH(ssh,'PERSIST='+input.marker);await text(page,'PERSIST='+input.marker);
    owner('invite',input.name,'--revoke','--json');
    ssh.stdin.write(`printf 'AFTERREVOKE%s\\n' '${input.marker}'\r`);
    await text(page,'AFTERREVOKE'+input.marker);
    await page.reload({waitUntil:'networkidle'});
    await page.getByRole('button',{name:'Connect',exact:true}).click();
    await page.getByRole('heading',{name:input.name,exact:true}).waitFor();
    ssh.stdin.write(`printf 'RECOVERED%s\\n' '${input.marker}'\r`);await text(page,'RECOVERED'+input.marker);
    const fresh=await browser.newContext();const denied=await fresh.newPage();
    await denied.goto(input.invitation.read_only_url,{waitUntil:'networkidle'});
    await denied.getByRole('button',{name:'Connect',exact:true}).click();
    await denied.getByRole('alert').filter({hasText:/expired|revoked|unavailable/i}).waitFor();
    await fresh.close();
    const snapshot=JSON.parse(owner('participants',input.name,'--json'));
    assert(snapshot.connected&&snapshot.members.some(member=>!member.read_only));
    const reader=snapshot.members.find(member=>member.read_only);assert(reader,'Expected the anonymous read-only guest');
    owner('kick',input.name,String(reader.id));
    await page.getByRole('alert').filter({hasText:/removed/i}).waitFor();
    ssh.stdin.write(`printf 'WRITERSTILL%s\\n' '${input.marker}'\r`);await waitSSH(ssh,'WRITERSTILL'+input.marker);
    ssh.stdin.write('exit\r');
    await new Promise((resolve,reject)=>{const timeout=setTimeout(()=>reject(Error('Explicit exit did not close SSH')),10000);ssh.once('close',()=>{clearTimeout(timeout);resolve()})});
    assert(!JSON.parse(owner('list','--json')).some(session=>session.name===input.name));
    const sessions=JSON.parse(owner('list','--all','--json'));
    assert(sessions.some(session=>session.name===input.name&&session.state==='ended'));
    assert.deepEqual(errors,[]);
    console.log('PASS live CLI/broker/gateway: account-free browser and stock SSH, shared output/history, disconnect persistence, revoked-invite recovery, owner removal and explicit exit');
  } catch(error) {
    if(page) {
      const view=await page.locator('main').innerText().catch(()=> 'Page unavailable');
      console.error('Owned fixture view: '+view.slice(-3500));
    }
    throw error;
  } finally {
    for(const child of children)if(child.exitCode===null)child.kill('SIGTERM');
    if(browser)await browser.close();
  }
}
main().catch(error=>{console.error(error.message);process.exitCode=1});
