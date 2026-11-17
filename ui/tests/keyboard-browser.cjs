const {chooseDropdown}=require('./search-dropdown.cjs');
const assert=require('node:assert/strict');
const {chromium}=require('playwright');
const {execFile}=require('node:child_process');const {promisify}=require('node:util');const run=promisify(execFile);
const fs=require('node:fs/promises');
const base=process.env.PORTHUB_TEST_UI_URL,cookie=process.env.PORTHUB_TEST_BOARD_COOKIE?.split('=')[1];
async function verifySurfaceDictation(browser){
 const page=await browser.newPage({viewport:{width:1440,height:900}}),errors=[];
 page.on('pageerror',error=>errors.push(error.message));
 try{
  await page.setContent('<div id="surface"><div id="keyboard"></div><div id="pad"></div></div>');
  const source=(await fs.readFile(require('node:path').join(__dirname,'../src/lib/keyboardSurface.mjs'),'utf8')).replace('export function mountKeyboardSurface','window.mountKeyboardSurface = function');
  await page.addScriptTag({content:source});
  await page.evaluate(()=>{
   window.dictationCalls=0;window.preferences={connected:false};
   window.surface=mountKeyboardSurface({root:document.querySelector('#surface'),keyboard:document.querySelector('#keyboard'),pad:document.querySelector('#pad'),read:()=>preferences,command:()=>{},mic:()=>window.dictationCalls++});
  });
  const dictate=()=>page.getByRole('button',{name:'Dictate',exact:true});
  assert(await dictate().isEnabled(),'local dictation stays available without a connected input client');
  await dictate().click();
  await dictate().focus();await page.keyboard.press('Enter');await page.keyboard.press('Space');
  assert.equal(await page.evaluate(()=>dictationCalls),3,'pointer and accessible keyboard activation invoke injected microphone callback');
  await page.setViewportSize({width:844,height:390});
  await page.evaluate(()=>{preferences.connected=true;surface.refresh();});
  await dictate().click();
  assert.equal(await page.evaluate(()=>dictationCalls),4,'landscape control works after surface rerender');
  assert.deepEqual(errors,[],'dictation control never throws a browser exception');
  await page.evaluate(()=>surface.destroy());assert.equal(await dictate().count(),0);
 }finally{await page.close();}
}
(async()=>{
 if(process.env.PORTHUB_TEST_SURFACE_ONLY==='1'){
  const browser=await chromium.launch({headless:true,executablePath:'/usr/bin/google-chrome',args:['--no-sandbox']});
  try{await verifySurfaceDictation(browser);console.log('PASS real browser landscape dictation callback');}finally{await browser.close();}
  return;
 }
 const targetBrowser=await chromium.launch({headless:false,executablePath:'/usr/bin/google-chrome',args:['--no-sandbox','--disable-gpu'],env:{...process.env}});
 const portalBrowser=await chromium.launch({headless:true,executablePath:'/usr/bin/google-chrome',args:['--no-sandbox','--disable-features=WebRtcHideLocalIpsWithMdns']});
 const errors=[];
 try{
  await verifySurfaceDictation(portalBrowser);
  const target=await targetBrowser.newPage();await target.setContent('<title>PortHub isolated native target</title><textarea id="target" autofocus style="width:700px;height:400px"></textarea><script>window.pointer=0;window.nativeButtons=[];window.heldMoves=0;window.nativePosition=null;document.addEventListener("mousedown",e=>nativeButtons.push({type:"down",trusted:e.isTrusted}));document.addEventListener("mouseup",e=>nativeButtons.push({type:"up",trusted:e.isTrusted}));document.addEventListener("mousemove",e=>{window.pointer++;window.nativePosition={x:e.clientX,y:e.clientY};if(e.buttons&1)window.heldMoves++;});document.getElementById("target").focus();</script>');await target.bringToFront();await target.locator('textarea').focus();
  const context=await portalBrowser.newContext({viewport:{width:1440,height:1000},serviceWorkers:'block'});await context.addInitScript(()=>{delete Object.getPrototypeOf(navigator).serviceWorker;});await context.addCookies([{name:'porthub_session',value:cookie,url:base}]);
  const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));await page.goto(base+'/home?view=keyboard');
  await page.getByRole('button',{name:'VKeyboard settings',exact:true}).waitFor();
  await page.getByRole('button',{name:'VKeyboard settings',exact:true}).click();await page.getByRole('tab',{name:'General',exact:true}).click();await chooseDropdown(page.getByLabel('Dictation language',{exact:true}),'English');await page.screenshot({path:'/tmp/porthub-general-settings-polished.png'});await page.getByRole('tab',{name:'Clients',exact:true}).click();
  for(let i=0;i<15;i++){await page.getByRole('button',{name:'Refresh keyboard clients'}).click();if(await page.locator('button[aria-label="Connect"]').isEnabled())break;await page.waitForTimeout(200);}
  await page.getByRole('button',{name:'Close VKeyboard settings',exact:true}).click();await page.getByRole('dialog').waitFor({state:'hidden'});await page.getByRole('button',{name:'Connect',exact:true}).click();await page.getByRole('button',{name:'Disconnect',exact:true}).waitFor();
  await page.getByRole('button',{name:'Text and clipboard',exact:true}).click();await page.getByLabel('Text to send to the selected client').fill('Native PortHub input');await page.getByRole('button',{name:'Type text',exact:true}).click();await target.waitForFunction(()=>document.querySelector('textarea').value==='Native PortHub input');
  await page.getByLabel('Text to send to the selected client').fill(' https://example.invalid/clipboard');await page.getByRole('button',{name:'Paste text',exact:true}).click();await target.waitForFunction(()=>document.querySelector('textarea').value.endsWith('https://example.invalid/clipboard'));
  await page.getByLabel('Text to send to the selected client').fill(' remote clipboard');await page.getByRole('button',{name:'Update clipboard',exact:true}).click();await page.waitForTimeout(150);await page.getByRole('button',{name:'Paste remote clipboard',exact:true}).click();await target.waitForFunction(()=>document.querySelector('textarea').value.endsWith(' remote clipboard'));
  await page.getByRole('button',{name:'Close VKeyboard settings',exact:true}).click();await page.getByRole('dialog').waitFor({state:'hidden'});await page.getByRole('textbox',{name:'Capture physical keyboard'}).focus();await page.keyboard.press('Control+a');await page.keyboard.type('native-replacement');await page.keyboard.press('Tab');
  await target.waitForFunction(()=>document.querySelector('textarea').value==='native-replacement');
  await page.getByRole('button',{name:'VKeyboard settings',exact:true}).click();await page.getByRole('tab',{name:'Clients',exact:true}).click();const status=page.getByRole('status').filter({hasText:'Connected to Isolated desktop'});await status.waitFor();
  let local=false;for(let i=0;i<50;i++){if((await status.textContent()).includes('Local connection')){local=true;break;}await page.waitForTimeout(100);}
  assert(local,'Authenticated LAN data channel connects without changing the public page URL');assert.equal(new URL(page.url()).pathname,'/home');
  await page.getByRole('button',{name:'Close VKeyboard settings',exact:true}).click();await page.getByRole('dialog').waitFor({state:'hidden'});const pad=page.getByRole('application',{name:/Touchpad:/}),box=await pad.boundingBox();const before=await target.evaluate(()=>window.pointer);await page.mouse.move(box.x+60,box.y+60);await page.mouse.down();await page.mouse.move(box.x+100,box.y+90,{steps:5});await page.mouse.up();await target.waitForFunction(before=>window.pointer>before,before);
  // Hold the second tap without motion beyond the native deadman, then drag.
  // Events are injected only into the isolated portal; the separate Xvfb target
  // must observe trusted events emitted by the real Rust desktop worker.
  const nativeBefore=await target.evaluate(()=>({events:nativeButtons.length,moves:heldMoves}));
  const touchPad=async(type,x=box.x+60,y=box.y+60)=>page.evaluate(({type,x,y})=>{const pad=document.querySelector('[aria-label^="Touchpad:"]');const touch=new Touch({identifier:41,target:pad,clientX:x,clientY:y});pad.dispatchEvent(new TouchEvent(type,{bubbles:true,cancelable:true,changedTouches:[touch]}));},{type,x,y});
  await touchPad('touchstart');await touchPad('touchend');await page.waitForTimeout(100);await touchPad('touchstart');
  await target.waitForFunction(start=>nativeButtons.slice(start).filter(e=>e.type==='down').length===2,nativeBefore.events);
  await page.waitForTimeout(6100);
  assert.equal(await target.evaluate(start=>nativeButtons.slice(start).filter(e=>e.type==='up').length,nativeBefore.events),1,'Second-tap hold survives stationary native deadman');
  const heldBeforeMove=await target.evaluate(()=>({moves:heldMoves,position:nativePosition}));
  await touchPad('touchmove',box.x+70,box.y+65);
  await target.waitForFunction(before=>heldMoves>before.moves&&nativePosition&&(nativePosition.x!==before.position?.x||nativePosition.y!==before.position?.y),heldBeforeMove);
  await touchPad('touchend',box.x+70,box.y+65);
  await target.waitForFunction(start=>nativeButtons.slice(start).filter(e=>e.type==='up').length===2,nativeBefore.events);
  assert((await target.evaluate(start=>nativeButtons.slice(start),nativeBefore.events)).every(event=>event.trusted),'Mouse hold and release reached the native desktop');
  await page.getByRole('button',{name:'VKeyboard settings',exact:true}).click();await page.getByRole('tab',{name:'Models',exact:true}).click();await page.getByRole('button',{name:'Model library',exact:true}).click();await page.getByRole('button',{name:'Download',exact:true}).first().waitFor();assert((await page.getByText('Whisper Tiny Q8',{exact:false}).count())>=1);assert(await page.getByRole('button',{name:'GPU',exact:true}).isDisabled());
  await page.getByRole('button',{name:'Close VKeyboard settings',exact:true}).click();await page.getByRole('dialog').waitFor({state:'hidden'});const screenshots='/tmp/porthub-keyboard-browser';await fs.mkdir(screenshots,{recursive:true});
  for(const width of [320,390,768,1024,1440,1920]){await page.setViewportSize({width,height:950});await page.waitForTimeout(100);const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1);assert(!overflow,`No horizontal overflow at ${width}`);
    const tools=page.getByRole('toolbar',{name:'Keyboard controls'});for(const button of await tools.getByRole('button').all()){const bounds=await button.boundingBox();assert(bounds.width>=44&&bounds.height>=44,`Toolbar keeps accessible touch controls at ${width}`);}
    if(width<768){const client=await page.getByLabel('Keyboard client',{exact:true}).boundingBox(),touchpad=await pad.boundingBox(),bar=await tools.boundingBox();assert(Math.abs(client.x-touchpad.x)<=1&&Math.abs(client.x+client.width-touchpad.x-touchpad.width)<=1,'Phone picker matches touchpad edges');assert(Math.abs(bar.x-touchpad.x)<=1&&Math.abs(bar.width-touchpad.width)<=1,'Phone toolbar matches touchpad width');}
    assert.equal(await page.getByRole('img',{name:/Keyboard (?:connected|disconnected)/}).count(),0,'Connection dot removed');
    await page.screenshot({path:`${screenshots}/keyboard-${width}.png`,fullPage:true});}
  for(const width of [320,390]){
    await page.setViewportSize({width,height:740});
    await page.getByRole('button',{name:'VKeyboard settings',exact:true}).click();
    const popup=page.getByRole('dialog');await popup.waitFor();
    await page.waitForTimeout(350);
    const bounds=await popup.boundingBox();assert(bounds.x>=-1&&bounds.x+bounds.width<=width+1,`Settings fit ${width}px`);
    assert(await popup.locator('input[type="checkbox"]').count()>=6,'All reference settings retained');
    await page.screenshot({path:`${screenshots}/settings-${width}.png`});
    await page.getByRole('button',{name:'Close VKeyboard settings',exact:true}).click();await page.getByRole('dialog').waitFor({state:'hidden'});
  }
  await page.setViewportSize({width:1440,height:1000});await page.getByRole('button',{name:'Switch to portrait layout',exact:true}).click();assert(await page.locator('[aria-label="Capture physical keyboard"]').evaluate(el=>getComputedStyle(el).maxWidth==='480px'));await page.getByRole('button',{name:'Switch to landscape layout',exact:true}).click();assert(await page.locator('[aria-label="Capture physical keyboard"]').evaluate(el=>getComputedStyle(el).gridTemplateColumns.split(' ').length===1));
  // High-refresh-rate pointing must stay connected through the real relay and
  // native worker, even when samples arrive faster than input can be applied.
  await page.getByRole('button',{name:'Disconnect',exact:true}).click();
  // Use the real module loader: the transport has an explicit local dependency.
  // Classic-script export stripping silently fails when a new import is added.
  const dependency='data:text/javascript;base64,'+Buffer.from(await fs.readFile(require('node:path').join(__dirname,'../src/lib/keyboardTermination.mjs'),'utf8')).toString('base64');
  const source=await fs.readFile(require('node:path').join(__dirname,'../src/lib/keyboardTransport.mjs'),'utf8');
  assert.equal(source.split("'./keyboardTermination.mjs'").length,2,'Expected one explicit termination dependency');
  const moduleUrl='data:text/javascript;base64,'+Buffer.from(source.replace("'./keyboardTermination.mjs'",JSON.stringify(dependency))).toString('base64');
  await page.evaluate(async url=>{window.MotionTransport=(await import(url)).KeyboardTransport;},moduleUrl);
  const motion=await page.evaluate(async()=>{
    const targets=await fetch('/api/keyboard/targets').then(r=>r.json());
    const target=targets.targets.find(t=>t.name==='Isolated desktop');
    let failure='',acknowledged=0;
    const transport=new window.MotionTransport({target:target.id,createPeer:()=>{throw Error('Exercise relay');},failed:reason=>failure=reason});
    transport.connect();
    for(let i=0;i<100&&!transport.ready&&!transport.closed;i++)await new Promise(r=>setTimeout(r,20));
    if(!transport.ready)throw Error('Stress session did not connect: '+failure);
    const promises=[];
    for(let i=0;i<500;i++){
      promises.push(transport.send({type:'pointer',action:'move',dx:i%2?1:-1,dy:0}).then(()=>acknowledged++,reason=>{failure||=reason.message;}));
      await new Promise(r=>setTimeout(r,4));
    }
    await Promise.all(promises);
    const connected=!transport.closed;
    transport.close();
    return {connected,failure,acknowledged};
  });
  assert(motion.connected,`Sustained pointer session closed: ${JSON.stringify(motion)}`);
  assert.equal(motion.failure,'');assert.equal(motion.acknowledged,500);
  await page.getByRole('button',{name:'Connect',exact:true}).click();await page.getByRole('button',{name:'Disconnect',exact:true}).waitFor();
  const cli=process.env.PORTHUB_TEST_AGENT_EXECUTABLE;const env={...process.env,XDG_CONFIG_HOME:process.env.PORTHUB_TEST_KEYBOARD_CONFIG,XDG_DATA_HOME:process.env.PORTHUB_TEST_KEYBOARD_DATA};
  await run(cli,['keyboard','disable','--user','--registration',process.env.PORTHUB_TEST_KEYBOARD_ID],{env});await page.getByRole('button',{name:'Connect',exact:true}).waitFor();await page.getByRole('button',{name:'Text and clipboard',exact:true}).click();assert(await page.getByRole('button',{name:'Type text',exact:true}).isDisabled(),'Local disable revokes active remote input');
  await page.getByRole('tab',{name:'Flash',exact:true}).click();await page.getByRole('heading',{name:'Bluetooth keyboard board',exact:true}).waitFor();assert.equal(new URL(page.url()).pathname,'/home');
  await page.goto(base+'/home?view=dashboard');
  const ranking=page.getByRole('region',{name:'Machine resource utilization'});await ranking.getByRole('listitem').first().waitFor();
  assert((await ranking.getByRole('listitem').first().textContent()).includes('Busy CPU host'));
  assert.equal(await ranking.getByRole('listitem').count(),3);
  for(const width of [1440,390]){
    await page.setViewportSize({width,height:900});await page.waitForTimeout(150);
    const geometry=await ranking.evaluate(card=>{
      const viewport=card.querySelector('[aria-label="Live machine rankings"]');
      const bounds=viewport.getBoundingClientRect();
      const rows=[...viewport.querySelectorAll('li')].map(row=>row.getBoundingClientRect());
      const visible=rows.filter(row=>row.bottom>bounds.top+1&&row.top<bounds.bottom-1);
      return {height:card.getBoundingClientRect().height,viewport:bounds.height,contents:[...viewport.querySelectorAll('[data-ranking-row-content]')].map(el=>el.getBoundingClientRect().height),visible:visible.length,complete:visible.every(row=>row.top>=bounds.top-1&&row.bottom<=bounds.bottom+1)};
    });
    if(width===1440){
      const web=await page.getByRole('region',{name:'Recent Web Addresses',exact:true}).boundingBox();
      const rankingBox=await ranking.boundingBox();
      assert(Math.abs(web.x-rankingBox.x)<=1&&Math.abs(web.width-rankingBox.width)<=1,'Upper and lower right cards share the same grid column');
    }
    const bars=await ranking.getByRole('listitem').first().getByRole('meter').evaluateAll(items=>items.map(el=>el.getBoundingClientRect().top));
    assert(Math.max(...bars)-Math.min(...bars)<=1,'All hardware progress bars share one baseline');
    if(width===1440)assert.equal(geometry.visible,3,'Compact desktop table shows all three fixture machines');
    if(width===1440){const traffic=await page.getByRole('heading',{name:'Public port traffic',exact:true}).locator('..').locator('..').locator('..').boundingBox();assert(Math.abs(geometry.height-traffic.height)<=1,'Resource and traffic cards share the available row height');}else assert.equal(geometry.height,360,'Phone card stays compact');
    assert(geometry.visible>=1&&geometry.complete,`Only complete resource rows at ${width}px: ${JSON.stringify(geometry)}`);
    await ranking.scrollIntoViewIfNeeded();await page.screenshot({path:`${screenshots}/dashboard-${width}.png`,fullPage:true});
  }
  await page.setViewportSize({width:1440,height:1000});
  await ranking.getByRole('radio',{name:'GPU',exact:true}).check();
  assert((await ranking.getByRole('listitem').first().textContent()).includes('Isolated desktop'));
  assert.equal(await ranking.locator('input[type=radio]:checked').count(),1);
  assert.equal(await ranking.getByRole('radio',{name:'CPU',exact:true}).isChecked(),false);
  await chooseDropdown(ranking.getByLabel('Resource sort order',{exact:true}),'Least utilized first');
  assert((await ranking.getByRole('listitem').first().textContent()).includes('Busy CPU host'));
  assert.equal(await ranking.getByRole('listitem').first().getByRole('meter').count(),4,'CPU, GPU, RAM and disk bars stay visible without a dashboard health column');
  await ranking.getByRole('radio',{name:'Health',exact:true}).check();
  await chooseDropdown(ranking.getByLabel('Resource sort order',{exact:true}),'Most at risk first');
  assert((await ranking.getByRole('listitem').first().textContent()).includes('Busy CPU host'),'One critical physical drive ranks ahead of healthy hosts');
  assert.equal(await ranking.locator('input[type=radio]:checked').count(),1);
  await ranking.getByRole('listitem').filter({hasText:'Isolated desktop'}).getByRole('button').click();
  const health=page.getByRole('region',{name:'Machine health and resource history'});
  await health.getByRole('img',{name:'CPU utilization history from 0 to 100 percent'}).waitFor();await page.waitForFunction(()=>document.querySelector('section[aria-label="Machine health and resource history"] [role="meter"][aria-label="GPU"]')?.getAttribute('aria-valuenow')==='96');assert.equal(await health.getByRole('meter',{name:'GPU',exact:true}).getAttribute('aria-valuenow'),'96');assert.equal(await health.getByRole('meter',{name:'GPU',exact:true}).locator('div').evaluate(el=>getComputedStyle(el).backgroundColor),'rgb(240, 82, 82)');
  await chooseDropdown(health.getByLabel('Resource history period',{exact:true}),'Last hour');
  await health.getByText('Fixture GPU',{exact:false}).first().waitFor();
  await page.waitForFunction(()=>document.querySelector('section[aria-label="Machine health and resource history"]')?.querySelectorAll('svg[role="img"]').length===5);
  assert.equal(await health.getByRole('img').count(),5);
  const integrated=health.getByRole('heading',{name:'GPU · Fixture GPU',exact:true}).locator('..');
  assert((await integrated.getByRole('listitem').filter({hasText:'Dedicated VRAM'}).innerText()).includes('Unavailable'),'An integrated adapter without dedicated-memory data never invents zero VRAM');
  assert((await integrated.getByRole('listitem').filter({hasText:'Shared GPU memory'}).innerText()).includes('256.0 MB / 8.0 GB max'),'Shared usage is measured against its maximum shareable limit');
  assert.equal(await integrated.locator('polyline').count(),2,'Only measured utilization and shared memory generate lines; absent dedicated VRAM, temperature and fan remain gaps');
  await chooseDropdown(health.getByLabel('GPU device',{exact:true}),'Fixture discrete GPU · fixture-discrete');
  const discrete=health.getByRole('heading',{name:'GPU · Fixture discrete GPU',exact:true}).locator('..');
  assert((await discrete.getByRole('listitem').filter({hasText:'Dedicated VRAM'}).innerText()).includes('953.7 MB / 3.7 GB'),'Switching adapters reads only that adapter memory, without summing shared limits');
  assert.equal(await discrete.getByRole('listitem').filter({hasText:'Shared GPU memory'}).count(),0,'Shared memory from the integrated adapter does not leak into a discrete adapter history');
  assert.equal(await discrete.locator('polyline').count(),1,'An adapter with unknown utilization draws only its measured dedicated-memory line');
  await chooseDropdown(health.getByLabel('GPU device',{exact:true}),'Fixture GPU · fixture-integrated');
  const drives=health.getByRole('region',{name:'Physical drive health and history'});
  await drives.getByRole('img',{name:'Drive SMART condition history'}).waitFor();
  assert((await drives.getByLabel('Physical drive',{exact:true}).inputValue()).includes('Fixture physical SSD'));
  await chooseDropdown(drives.getByLabel('Drive health history period',{exact:true}),'Last 90 days');
  await drives.getByRole('img',{name:'Drive SMART condition history'}).waitFor();
  await health.getByRole('img',{name:'CPU utilization history from 0 to 100 percent'}).locator('polyline').first().waitFor();
  await page.waitForFunction(()=>[...document.querySelectorAll('svg[aria-label="CPU utilization history from 0 to 100 percent"] polyline')].some(line=>(line.getAttribute('points')||'').split(' ').length>30));
  for(const width of [390,1440]){await page.setViewportSize({width,height:1000});await page.waitForTimeout(100);assert(!(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1)));await page.screenshot({path:`${screenshots}/resources-${width}.png`,fullPage:true});}
  await page.getByRole('button',{name:'USB',exact:true}).click();
  const usb=page.getByRole('region',{name:'USB forwarding',exact:true});
  await chooseDropdown(usb.getByLabel('USB device',{exact:true}),'Fixture USB microphone · 1-2');
  await chooseDropdown(usb.getByLabel('USB destination machine',{exact:true}),'Busy CPU host');
  const saved=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/usb/forwards'&&response.request().method()==='POST',{timeout:5000});
  await usb.getByRole('button',{name:'Forward device',exact:true}).click();
  const saveResponse=await saved.catch(async error=>{throw Error(error.message+' · '+await usb.innerText()+' · '+JSON.stringify(await usb.locator('input').evaluateAll(items=>items.map(i=>({value:i.value,required:i.required,invalid:!i.validity.valid})))));});assert.equal(saveResponse.status(),200,await saveResponse.text());
  await usb.getByText('Persistent rule',{exact:true}).waitFor();
  await usb.getByRole('button',{name:'Remove',exact:true}).click();await usb.getByText('Persistent rule',{exact:true}).waitFor({state:'hidden'});
  assert.equal(await page.locator('select').count(),0,'All PortHub dropdowns use searchable custom controls');
  assert.deepEqual(errors,[]);console.log(JSON.stringify({native_text:true,remote_clipboard:true,arbitrary_text_paste:true,physical_keys:true,mouse:true,local_transport:true,local_disable:true,embedded_flashing:true,resource_ranking:true,single_resource_sort:true,resource_history_graphs:true,searchable_dropdowns:true,persistent_usb_configuration:true,viewports:[320,390,768,1024,1440,1920]}));
 }finally{await portalBrowser.close();await targetBrowser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
