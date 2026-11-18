const assert=require('node:assert/strict');
const {launchBrowser}=require('./browser.cjs');
const {chooseDropdown}=require('./search-dropdown.cjs');
(async()=>{
 const {makeDemoData,handleDemoRequest}=await import('../src/shared/demo/data.mjs');const browser=await launchBrowser();
 try{for(const viewport of [{width:320,height:1000},{width:390,height:1000},{width:1440,height:1000}]){
  const context=await browser.newContext({viewport,serviceWorkers:'block'}),state=makeDemoData(),source=state.machines[1],receiver=state.machines[2],unconfigured=state.machines[3];let plans=[],saved;
  const sourceId='media:'+'a'.repeat(64),cameraId='media:'+'c'.repeat(64),desktopSession='windows:'+'d'.repeat(64),now=Date.now();
  const machines=[{id:source._id,name:source.name,live:true,report:{protocol:2,microphone_enabled:true,camera_enabled:true,sources:[{uid:0,desktop_session:desktopSession,device:{id:cameraId,name:'Built-in camera',kind:'camera',capture_available:false,capture_state:'permission-unknown'}},{uid:0,desktop_session:desktopSession,device:{id:sourceId,name:'Built-in microphone',kind:'microphone',capture_available:false,capture_state:'permission-unknown'}}]}},{id:receiver._id,name:receiver.name,live:true,report:{protocol:2,receive_enabled:true,camera_receiver_available:true,receiver_available:true,receiver_identity:{vendor:0x1209,product:1}}},{id:unconfigured._id,name:unconfigured.name,live:true,report:{receive_enabled:true,receiver_available:false,receiver_identity:null,receiver_unavailable_reason:'Receiver USB identity required'}}];
  const speakerId='media:'+'e'.repeat(64);
  machines[0].report.speaker_enabled=true;
  machines[0].report.sources.push({uid:0,desktop_session:desktopSession,device:{id:speakerId,name:'Desktop output',kind:'speaker',capture_state:'ready'}});
  machines[1].report.speaker_receiver_available=true;
  await context.route('**/api/**',async route=>{const req=route.request(),path=new URL(req.url()).pathname;let data;
   if(path.endsWith('/discover'))data={requested:true};
   else if(path==='/api/media/inventory')data={protocol:2,modes:['phm1-microphone-v1','phv1-camera-mjpeg-v1','phs1-speaker-v1'],machines};
   else if(path==='/api/media/forwards'&&req.method()==='POST'){saved=req.postDataJSON();plans=[{...saved,id:'b'.repeat(32)}];data={plan:plans[0]};}
   else if(path==='/api/media/forwards')data={plans};
   else if(path.startsWith('/api/media/forwards/')){plans=[];data={ok:true};}
   else if(path==='/api/usb/inventory')data={machines:machines.map(m=>({...m,online:true,report:{enabled:true,supported:true,can_export:true,can_import:true,devices:[],states:[]}}))};
   else if(path==='/api/usb/forwards')data={forwards:[]};
   else if(path==='/api/machines/metrics')data={machines:[{id:source._id,name:source.name,live:true,reading:{at:now,sample:{cpu:10,cores:8,ram:{used:1,total:2},disk:{used:1,total:2},gpus:[]}}}]};
   else if(path.startsWith('/api/machines/metrics/'))data={latest:null,history:[],drives:[]};
   else{try{data=handleDemoRequest(state,req.method(),req.url());}catch{data={};}}await route.fulfill({json:data});
  });
  await context.addInitScript(()=>{delete Object.getPrototypeOf(navigator).serviceWorker;});const width=viewport.width;const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));await page.goto(`${process.env.REVIEW_ORIGIN||'http://127.0.0.1:3019'}/home?view=dashboard`);
  await page.getByRole('region',{name:'Machine resource utilization'}).getByRole('button').filter({hasText:source.name}).click();await page.getByRole('button',{name:'USB',exact:true}).click();
  const panel=page.getByRole('region',{name:'Built-in microphone and camera forwarding'});await panel.waitFor();
  await panel.getByRole('button',{name:'Refresh microphones',exact:true}).click();await panel.getByRole('status').filter({hasText:'Discovery requested'}).waitFor();
  await chooseDropdown(panel.getByLabel('Microphone',{exact:true}),'Built-in microphone');
  const destination=panel.getByLabel('Receiving machine',{exact:true});assert(await panel.getByRole('button',{name:'Share microphone',exact:true}).isDisabled());await destination.click();await destination.fill(unconfigured.name);const unavailable=page.getByRole('option',{name:unconfigured.name+' · Receiver USB identity required',exact:true});await unavailable.waitFor();assert(await unavailable.evaluate(e=>e.getAttribute('aria-disabled')==='true'||e.hasAttribute('data-disabled')),'Unconfigured receivers cannot be chosen');await destination.press('Escape');await chooseDropdown(destination,receiver.name);
  assert.equal(await panel.locator('select').count(),0,'Microphone selectors remain custom and searchable');
  await panel.getByRole('button',{name:'Share microphone',exact:true}).click();await panel.getByText('Persistent configuration · Capture follows application use',{exact:true}).waitFor();
  assert.equal(saved.source_id,sourceId);assert.equal(saved.desktop_uid,0);assert.equal(saved.desktop_session,desktopSession);assert.equal(saved.mode,'phm1-microphone-v1');assert.equal(saved.persistent,true);assert.equal(saved.destination,receiver._id);assert.equal(saved.identity,undefined,'A session uses receiver-local identity without asking for VID/PID again');
  await panel.getByRole('button',{name:'Remove',exact:true}).click();await panel.getByText('Persistent configuration · Capture follows application use',{exact:true}).waitFor({state:'hidden'});
  await panel.getByText('Receiver setup and local permissions',{exact:true}).click();assert((await panel.innerText()).includes('receiving permissions are independent')); await panel.getByRole('radio',{name:'Camera',exact:true}).click();await chooseDropdown(panel.getByLabel('Camera',{exact:true}),'Built-in camera');await chooseDropdown(panel.getByLabel('Receiving machine',{exact:true}),receiver.name);await panel.getByRole('button',{name:'Share camera',exact:true}).scrollIntoViewIfNeeded();assert(await panel.getByRole('button',{name:'Share camera',exact:true}).isEnabled());await panel.getByRole('button',{name:'Share camera',exact:true}).click();await panel.getByText('Persistent configuration · Capture follows application use',{exact:true}).waitFor();assert.equal(saved.mode,'phv1-camera-mjpeg-v1');assert.equal(saved.source_id,cameraId);assert.equal(saved.desktop_uid,0);assert.equal(saved.desktop_session,desktopSession);assert.equal(saved.destination,receiver._id);assert.equal(saved.identity,undefined);await panel.getByRole('button',{name:'Remove',exact:true}).click();await panel.getByText('Persistent configuration · Capture follows application use',{exact:true}).waitFor({state:'hidden'});
  await panel.getByRole('radio',{name:'Speaker',exact:true}).click();
  await chooseDropdown(panel.getByLabel('Speaker',{exact:true}),'Desktop output');
  await chooseDropdown(panel.getByLabel('Play audio on',{exact:true}),receiver.name);
  await panel.getByRole('button',{name:'Forward audio'}).click();
  await panel.getByText(`Audio from ${source.name} → ${receiver.name}`,{exact:true}).waitFor();
  assert.equal(saved.source,source._id);
  assert.equal(saved.destination,receiver._id);
  assert.equal(saved.source_id,speakerId);
  assert.equal(saved.mode,'phs1-speaker-v1');
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));assert.deepEqual(errors,[]);await page.getByRole('button',{name:'Close',exact:true}).scrollIntoViewIfNeeded();await page.screenshot({path:`/tmp/porthub-native-media-ui-${process.env.REVIEW_BROWSER||'chromium'}-${width}.png`});await context.close();console.log(`PASS native microphone/camera flow ${process.env.REVIEW_BROWSER||'chromium'} ${width}`);
 }}finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
