const {chooseDropdown}=require('./search-dropdown.cjs');
const assert=require('node:assert/strict');
const {chromium}=require('playwright');
const {execFile}=require('node:child_process');const {promisify}=require('node:util');const run=promisify(execFile);
const fs=require('node:fs/promises');
const base=process.env.PORTHUB_TEST_UI_URL,cookie=process.env.PORTHUB_TEST_BOARD_COOKIE.split('=')[1];
(async()=>{
 const targetBrowser=await chromium.launch({headless:false,executablePath:'/usr/bin/google-chrome',args:['--no-sandbox','--disable-gpu'],env:{...process.env}});
 const portalBrowser=await chromium.launch({headless:true,executablePath:'/usr/bin/google-chrome',args:['--no-sandbox','--disable-features=WebRtcHideLocalIpsWithMdns']});
 const errors=[];
 try{
  const target=await targetBrowser.newPage();await target.setContent('<title>PortHub isolated native target</title><textarea id="target" autofocus style="width:700px;height:400px"></textarea><script>window.pointer=0;document.addEventListener("mousemove",()=>window.pointer++);document.getElementById("target").focus();</script>');await target.bringToFront();await target.locator('textarea').focus();
  const context=await portalBrowser.newContext({viewport:{width:1440,height:1000},serviceWorkers:'block'});await context.addInitScript(()=>{delete Object.getPrototypeOf(navigator).serviceWorker;});await context.addCookies([{name:'porthub_session',value:cookie,url:base}]);
  const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));await page.goto(base+'/home?view=keyboard');
  await page.getByRole('button',{name:'VKeyboard settings',exact:true}).waitFor();
  await page.getByRole('button',{name:'VKeyboard settings',exact:true}).click();await page.getByRole('tab',{name:'General',exact:true}).click();await chooseDropdown(page.getByLabel('Dictation language',{exact:true}),'English');await page.getByRole('tab',{name:'Clients',exact:true}).click();
  for(let i=0;i<15;i++){await page.getByRole('button',{name:'Refresh keyboard clients'}).click();if(await page.locator('button[aria-label="Connect"]').isEnabled())break;await page.waitForTimeout(200);}
  await page.getByRole('button',{name:'Close VKeyboard settings',exact:true}).click();await page.getByRole('button',{name:'Connect',exact:true}).click();await page.getByRole('button',{name:'Disconnect',exact:true}).waitFor();
  await page.getByRole('button',{name:'Text and clipboard',exact:true}).click();await page.getByLabel('Text to send to the selected client').fill('Native PortHub input');await page.getByRole('button',{name:'Type text',exact:true}).click();await target.waitForFunction(()=>document.querySelector('textarea').value==='Native PortHub input');
  await page.getByLabel('Text to send to the selected client').fill(' https://example.invalid/clipboard');await page.getByRole('button',{name:'Paste text',exact:true}).click();await target.waitForFunction(()=>document.querySelector('textarea').value.endsWith('https://example.invalid/clipboard'));
  await page.getByLabel('Text to send to the selected client').fill(' remote clipboard');await page.getByRole('button',{name:'Update clipboard',exact:true}).click();await page.waitForTimeout(150);await page.getByRole('button',{name:'Paste remote clipboard',exact:true}).click();await target.waitForFunction(()=>document.querySelector('textarea').value.endsWith(' remote clipboard'));
  await page.getByRole('button',{name:'Close VKeyboard settings',exact:true}).click();await page.getByRole('textbox',{name:'Capture physical keyboard'}).focus();await page.keyboard.press('Control+a');await page.keyboard.type('native-replacement');await page.keyboard.press('Tab');
  await target.waitForFunction(()=>document.querySelector('textarea').value==='native-replacement');
  await page.getByRole('button',{name:'VKeyboard settings',exact:true}).click();await page.getByRole('tab',{name:'Clients',exact:true}).click();const status=page.getByRole('status').filter({hasText:'Connected to Isolated desktop'});await status.waitFor();
  let local=false;for(let i=0;i<50;i++){if((await status.textContent()).includes('Local connection')){local=true;break;}await page.waitForTimeout(100);}
  assert(local,'Authenticated LAN data channel connects without changing the public page URL');assert.equal(new URL(page.url()).pathname,'/home');
  await page.getByRole('button',{name:'Close VKeyboard settings',exact:true}).click();const pad=page.getByRole('application',{name:/Touchpad:/}),box=await pad.boundingBox();const before=await target.evaluate(()=>window.pointer);await page.mouse.move(box.x+60,box.y+60);await page.mouse.down();await page.mouse.move(box.x+100,box.y+90,{steps:5});await page.mouse.up();await target.waitForFunction(before=>window.pointer>before,before);
  await page.getByRole('button',{name:'VKeyboard settings',exact:true}).click();await page.getByRole('tab',{name:'Models',exact:true}).click();await page.getByRole('button',{name:'Model library',exact:true}).click();await page.getByRole('button',{name:'Download',exact:true}).first().waitFor();assert((await page.getByText('Whisper Tiny Q8',{exact:false}).count())>=1);assert(await page.getByRole('button',{name:'GPU',exact:true}).isDisabled());
  await page.getByRole('button',{name:'Close VKeyboard settings',exact:true}).click();const screenshots='/tmp/porthub-keyboard-browser';await fs.mkdir(screenshots,{recursive:true});
  for(const width of [320,390,768,1024,1440,1920]){await page.setViewportSize({width,height:950});await page.waitForTimeout(100);const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1);assert(!overflow,`No horizontal overflow at ${width}`);await page.screenshot({path:`${screenshots}/keyboard-${width}.png`,fullPage:true});}
  await page.setViewportSize({width:1440,height:1000});
  const cli=process.env.PORTHUB_TEST_AGENT_EXECUTABLE;const env={...process.env,XDG_CONFIG_HOME:process.env.PORTHUB_TEST_KEYBOARD_CONFIG,XDG_DATA_HOME:process.env.PORTHUB_TEST_KEYBOARD_DATA};
  await run(cli,['keyboard','disable','--user','--registration',process.env.PORTHUB_TEST_KEYBOARD_ID],{env});await page.getByRole('button',{name:'Connect',exact:true}).waitFor();await page.getByRole('button',{name:'Text and clipboard',exact:true}).click();assert(await page.getByRole('button',{name:'Type text',exact:true}).isDisabled(),'Local disable revokes active remote input');
  await page.getByRole('tab',{name:'Flash',exact:true}).click();await page.getByRole('heading',{name:'Bluetooth keyboard board',exact:true}).waitFor();assert.equal(new URL(page.url()).pathname,'/home');
  await page.goto(base+'/home?view=dashboard');
  const ranking=page.getByRole('region',{name:'Machine resource utilization'});await ranking.getByRole('listitem').first().waitFor();
  assert((await ranking.getByRole('listitem').first().textContent()).includes('Busy CPU host'));
  await ranking.getByRole('checkbox',{name:'GPU',exact:true}).check();
  assert((await ranking.getByRole('listitem').first().textContent()).includes('Isolated desktop'));
  await chooseDropdown(ranking.getByLabel('Resource sort order',{exact:true}),'Least utilized first');
  assert((await ranking.getByRole('listitem').first().textContent()).includes('Busy CPU host'));
  await ranking.getByRole('listitem').filter({hasText:'Isolated desktop'}).getByRole('button').click();
  const health=page.getByRole('region',{name:'Machine health and resource history'});
  await health.getByRole('img',{name:'CPU utilization history from 0 to 100 percent'}).waitFor();
  await chooseDropdown(health.getByLabel('Resource history period',{exact:true}),'Last hour');
  await health.getByText('Fixture GPU',{exact:false}).first().waitFor();
  assert.equal(await health.getByRole('img').count(),4);
  await health.getByRole('img',{name:'CPU utilization history from 0 to 100 percent'}).locator('polyline').first().waitFor();
  await page.waitForFunction(()=>[...document.querySelectorAll('svg[aria-label="CPU utilization history from 0 to 100 percent"] polyline')].some(line=>(line.getAttribute('points')||'').split(' ').length>30));
  for(const width of [390,1440]){await page.setViewportSize({width,height:1000});await page.waitForTimeout(100);assert(!(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1)));await page.screenshot({path:`${screenshots}/resources-${width}.png`,fullPage:true});}
  await page.getByRole('button',{name:'USB',exact:true}).click();
  const usb=page.getByRole('region',{name:'USB forwarding',exact:true});
  await chooseDropdown(usb.getByLabel('USB device',{exact:true}),'Fixture USB microphone · 1-2');
  await chooseDropdown(usb.getByLabel('USB destination machine',{exact:true}),'Busy CPU host');
  const saved=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/usb/forwards'&&response.request().method()==='POST',{timeout:5000});
  await usb.getByRole('button',{name:'Save USB forward',exact:true}).click();
  const saveResponse=await saved.catch(async error=>{throw Error(error.message+' · '+await usb.innerText()+' · '+JSON.stringify(await usb.locator('input').evaluateAll(items=>items.map(i=>({value:i.value,required:i.required,invalid:!i.validity.valid})))));});assert.equal(saveResponse.status(),200,await saveResponse.text());
  await usb.getByText('Persistent rule',{exact:true}).waitFor();
  await usb.getByRole('button',{name:'Remove',exact:true}).click();await usb.getByText('Persistent rule',{exact:true}).waitFor({state:'hidden'});
  assert.equal(await page.locator('select').count(),0,'All PortHub dropdowns use searchable custom controls');
  assert.deepEqual(errors,[]);console.log(JSON.stringify({native_text:true,remote_clipboard:true,arbitrary_text_paste:true,physical_keys:true,mouse:true,local_transport:true,local_disable:true,embedded_flashing:true,resource_ranking:true,combined_sort:true,resource_history_graphs:true,searchable_dropdowns:true,persistent_usb_configuration:true,viewports:[320,390,768,1024,1440,1920]}));
 }finally{await portalBrowser.close();await targetBrowser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
