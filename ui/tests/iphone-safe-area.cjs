const assert=require('node:assert/strict');
const {launchBrowser,navigateWorkspace,waitForWorkspaceLayout}=require('./browser.cjs');
(async()=>{
 const {makeDemoData,handleDemoRequest}=await import('../src/shared/demo/data.mjs');
 const browser=await launchBrowser(),engine=process.env.REVIEW_BROWSER||'chromium';
 try{for(const viewport of [{width:874,height:402,left:48,right:0},{width:874,height:402,left:0,right:48},{width:874,height:402,left:48,right:48}]){
  const context=await browser.newContext({viewport:{width:viewport.width,height:viewport.height},isMobile:true,hasTouch:true,deviceScaleFactor:3,serviceWorkers:'block'});
  // Keep the exported PWA from serving mock API requests outside Playwright routing.
  await context.addInitScript(({left,right})=>{delete Object.getPrototypeOf(navigator).serviceWorker;addEventListener('DOMContentLoaded',()=>{document.documentElement.style.setProperty('--safe-left',left+'px');document.documentElement.style.setProperty('--safe-right',right+'px')},{once:true});},{left:viewport.left,right:viewport.right});
  const state=makeDemoData(),host=state.machines[1],now=Date.now();
  const drive={id:'a'.repeat(64),name:'Phone fixture SSD',capacity:512*1024**3,protocol:'nvme',present:true,status:'healthy',observed_at:now,checked_at:now,reasons:[],self_test:'passed'};
  const sample={cpu:25,cores:8,ram:{used:4*1024**3,total:16*1024**3},disk:{used:50*1024**3,total:512*1024**3},gpus:[],drive_health_enabled:true,drive_tests_enabled:true,drive_health:[drive]};
  const latest=()=>({at:Date.now(),sample});
  await context.route('**/api/**',async route=>{
   const req=route.request(),path=new URL(req.url()).pathname;let data;
   if(path==='/api/keyboard/targets')data={targets:[{id:host._id,name:host.name,online:true,kind:'agent'}]};
   else if(path==='/api/keyboard/speech')data={settings:{enabled:false,model:'whisper-tiny'},models:[],engines:[]};
   else if(path==='/api/usb/inventory')data={machines:state.machines.slice(0,2).map(m=>({id:m._id,name:m.name,owner:true,online:true,report:{enabled:true,supported:true,can_import:true,devices:m._id===host._id?[{busid:'1-1',name:'Fixture external SSD',vendor:'1234',product:'5678'}]:[]}}))};
   else if(path==='/api/usb/forwards')data={forwards:[]};
   else if(path==='/api/machines/metrics')data={machines:[{id:host._id,name:host.name,live:true,reading:latest()}]};
   else if(path.endsWith('/drives'))data={drives:[drive],history:[{at:now-3600000,snapshot:drive},{at:now,snapshot:drive}]};
   else if(path===`/api/machines/metrics/${host._id}`)data={latest:latest(),history:[{at:now-60000,sample},{at:now,sample}],interval_ms:60000};
   else{try{data=handleDemoRequest(state,req.method(),req.url());}catch{data={};}}
   await route.fulfill({json:data});
  });
  const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  const audit=async name=>{
   let settlingError;try{await waitForWorkspaceLayout(page,{dialog:!['keyboard','touchpad','dashboard','settings'].includes(name)});}catch(error){settlingError=error;}
   const info=await page.evaluate(()=>({width:innerWidth,height:innerHeight,scale:visualViewport?.scale,viewport:document.querySelector('meta[name=viewport]')?.content,overflow:document.documentElement.scrollWidth>innerWidth+1,smallFields:[...document.querySelectorAll('input:not([type=checkbox]):not([type=radio]):not([type=hidden]),textarea,select')].filter(e=>e.getBoundingClientRect().width&&e.getBoundingClientRect().height&&parseFloat(getComputedStyle(e).fontSize)<16).map(e=>({name:e.getAttribute('aria-label')||e.placeholder,size:getComputedStyle(e).fontSize})),dialogs:[...document.querySelectorAll('[role=dialog]')].filter(e=>e.getBoundingClientRect().width).map(e=>{const r=e.getBoundingClientRect();return{x:r.x,y:r.y,right:r.right,bottom:r.bottom,transform:getComputedStyle(e).transform,animations:e.getAnimations().map(a=>({state:a.playState,currentTime:a.currentTime,endTime:a.effect?.getComputedTiming().endTime}))}})}));
   if(settlingError)throw settlingError;
   await page.screenshot({path:`/tmp/porthub-iphone-safe-area-${engine}-${viewport.left}-${viewport.right}-${name}.png`});console.log(JSON.stringify({engine,viewport,name,...info}));
   const exposed=await page.evaluate(({left,right})=>[...document.querySelectorAll('button,input,textarea,[role=combobox]')].flatMap(e=>{const r=e.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2;if(!r.width||!r.height||x<0||x>=innerWidth||y<0||y>=innerHeight)return [];const hit=document.elementFromPoint(x,y);if(!hit||!(e===hit||e.contains(hit)))return [];return r.left<left-1||r.right>innerWidth-right+1?[{label:e.getAttribute('aria-label')||e.innerText,left:r.left,right:r.right}]:[];}),{left:viewport.left,right:viewport.right});assert.deepEqual(exposed,[],`${name} exposed controls clear simulated notch`);
   assert(!info.overflow,`${name} horizontal overflow`);assert.equal(info.scale,1,`${name} initial viewport scale`);assert.deepEqual(info.smallFields,[],`${name} form fields avoid iOS auto zoom`);for(const d of info.dialogs)assert(d.x>=-1&&d.right<=info.width+1&&d.y>=-1&&d.bottom<=info.height+1,`${name} dialog fits viewport`);
  };
  await page.goto(`${process.env.REVIEW_ORIGIN||'http://127.0.0.1:3220'}/home?view=keyboard`);
  await page.getByRole('button',{name:'VKeyboard settings',exact:true}).waitFor();await audit('keyboard');
  const keys=await page.getByRole('group',{name:'Virtual keyboard'}).boundingBox();assert(keys.y>=0&&keys.y+keys.height<=viewport.height+1,'virtual keyboard stays inside reduced viewport');
  for(const button of await page.getByRole('toolbar',{name:'Keyboard controls'}).getByRole('button').all()){const r=await button.boundingBox();assert(r.width>=44&&r.height>=44,'keyboard toolbar touch target');}
  if(viewport.width>viewport.height){await page.getByRole('button',{name:'Show the touchpad',exact:true}).click();await page.getByRole('application',{name:/Touchpad:/}).waitFor({state:'visible'});await audit('touchpad');const dictation=await page.getByRole('button',{name:/^(Start dictation|Stop recording)$/}).boundingBox();assert(dictation&&dictation.width>=44&&dictation.height>=44,'landscape dictation touch target');await page.getByRole('button',{name:'Show the keyboard',exact:true}).click();}
  await page.getByRole('button',{name:'VKeyboard settings',exact:true}).click();await audit('keyboard-settings');
  await page.getByRole('tab',{name:'Text',exact:true}).click();const text=page.getByLabel('Text to send to the selected client');await text.fill('Layout test only');await text.focus();await audit('keyboard-text');
  if(viewport.width===402){await page.setViewportSize({width:402,height:460});await text.scrollIntoViewIfNeeded();await audit('keyboard-text-reduced');await page.getByRole('button',{name:'Clear text',exact:true}).scrollIntoViewIfNeeded();await page.setViewportSize(viewport);}
  await page.getByRole('button',{name:'Clear text',exact:true}).scrollIntoViewIfNeeded();await page.getByRole('button',{name:'Clear text',exact:true}).click();assert.equal(await text.inputValue(),'');
  await page.getByRole('button',{name:'Close VKeyboard settings',exact:true}).click();
  await navigateWorkspace(page,'Dashboard');await page.getByRole('region',{name:'Machine resource utilization'}).waitFor();await audit('dashboard');
  await page.getByRole('region',{name:'Machine resource utilization'}).getByRole('button').filter({hasText:host.name}).click();const health=page.getByRole('region',{name:'Physical drive health and history'});await health.getByLabel('Physical drive',{exact:true}).waitFor();await audit('host-health');
  await health.getByRole('list',{name:'Drive health observations'}).scrollIntoViewIfNeeded();await audit('host-history');
  await page.getByRole('button',{name:'USB',exact:true}).click();await page.getByRole('region',{name:'USB forwarding'}).waitFor();await audit('host-usb');
  const usb=page.getByRole('region',{name:'USB forwarding'});await usb.getByLabel('USB device',{exact:true}).scrollIntoViewIfNeeded();await usb.getByLabel('USB device',{exact:true}).click();await page.getByRole('option',{name:/Fixture external SSD/}).click();await usb.getByLabel('USB destination machine',{exact:true}).scrollIntoViewIfNeeded();await usb.getByLabel('USB destination machine',{exact:true}).click();await page.getByRole('option',{name:state.machines[0].name,exact:true}).click();await usb.getByRole('button',{name:'Forward device',exact:true}).scrollIntoViewIfNeeded();assert(await usb.getByRole('button',{name:'Forward device',exact:true}).isEnabled());await audit('host-usb-controls');
  await page.getByRole('button',{name:'Close',exact:true}).click();await navigateWorkspace(page,'Settings');await audit('settings');
  assert.deepEqual(errors,[]);await context.close();console.log(`PASS ${engine} simulated safe-area ${viewport.left}/${viewport.right} at ${viewport.width}×${viewport.height}`);
 }}finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1});
