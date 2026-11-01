const assert=require('node:assert/strict');
const {launchBrowser}=require('./browser.cjs');
(async()=>{const browser=await launchBrowser();try{
 for(const theme of ['dark','light'])for(const width of [1440,402,320]){
  const context=await browser.newContext({viewport:{width,height:1000}});
  await context.addInitScript(theme=>{localStorage.setItem('mantine-color-scheme',JSON.stringify(theme));window.__terminalPeers=0;const Peer=window.RTCPeerConnection;if(Peer)window.RTCPeerConnection=function(...args){window.__terminalPeers++;return new Peer(...args);};},theme);
  const page=await context.newPage(),errors=[];let joined=0;
  page.on('pageerror',error=>errors.push(error.message));page.on('websocket',socket=>{if(new URL(socket.url()).pathname==='/api/terminal/join')joined++;});
  await page.goto(`${process.env.REVIEW_ORIGIN||'http://127.0.0.1:32923'}/terminal#${'a'.repeat(64)}`);
  await page.getByText('Connection options',{exact:true}).click();
  const input=page.getByLabel('Optional UDP STUN endpoints',{exact:true}),connect=page.getByRole('button',{name:'Connect',exact:true});
  assert.equal(await input.inputValue(),'');
  await input.fill('turn:user:password@example.com');assert(await connect.isDisabled());
  await page.getByRole('alert').filter({hasText:'credential-free UDP STUN URI'}).waitFor();
  const relay=page.getByRole('checkbox',{name:'Use gateway relay only',exact:true});
  await relay.check();
  await page.waitForFunction(()=>[...document.querySelectorAll('button')].some(button=>button.textContent==='Connect'&&!button.disabled));
  await page.reload();await page.getByText('Connection options',{exact:true}).click();
  assert(await relay.isChecked(),'relay-only choice survives reload in this tab');
  await input.fill('turn:user:password@example.com');
  await relay.uncheck();assert(await connect.isDisabled());
  await input.fill('stun:example.com');
  await page.waitForFunction(()=>[...document.querySelectorAll('button')].some(button=>button.textContent==='Connect'&&!button.disabled));
  await page.reload();await page.getByText('Connection options',{exact:true}).click();
  assert.equal(await input.inputValue(),'stun:example.com:3478');
  assert.equal(await page.evaluate(()=>window.__terminalPeers),0,'editing consent must not create a peer or discovery probe');assert.equal(joined,0);
  await input.fill('');await page.screenshot({path:`/tmp/porthub-terminal-connectivity-${process.env.REVIEW_BROWSER||'chromium'}-${theme}-${width}.png`,fullPage:true});
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));assert.deepEqual(errors,[]);
  console.log('PASS terminal connectivity consent, persistence and layout',theme,width);await context.close();
 }
}finally{await browser.close();}})().catch(error=>{console.error(error);process.exitCode=1;});
