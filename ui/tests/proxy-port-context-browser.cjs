const assert=require('node:assert/strict');
const {launchBrowser}=require('./browser.cjs');
(async()=>{
 const {makeDemoData,handleDemoRequest}=await import('../src/shared/demo/data.mjs');const browser=await launchBrowser();
 try{for(const width of [1440,402]){
  const context=await browser.newContext({viewport:{width,height:950},serviceWorkers:'allow'}),state=makeDemoData();
  const machine={...state.machines[1],name:'Clear target'},other={...state.machines[2],name:'Other machine'},template=state.connections.find(c=>c.machine_id===machine._id);
  const port=(id,host,name,external)=>({...template,_id:id.repeat(24),machine_id:host._id,machine_name:host.name,service_name:name,internal_port:80,external_port:external,enabled:true});
  const wrong=port('a',machine,'First HTTP service',46538),target=port('b',machine,'Exact BMC port',46539),foreign=port('c',other,'Other BMC port',46540);state.machines=[other,machine];state.connections=[wrong,foreign,target];state.proxies=[];
  let release;const gate=new Promise(resolve=>release=resolve),writes=[],detailQueries=[];
  await context.route('**/api/**',async route=>{const request=route.request(),url=new URL(request.url()),path=url.pathname;
   // This telemetry POST is read-only; every other non-GET remains a forbidden write.
   if(request.method()!=='GET'&&!(request.method()==='POST'&&path==='/api/connections/firewall/traffic/snapshot'))writes.push({method:request.method(),path});
   if(path==='/api/inventory/connections'&&url.searchParams.get('ids')===target._id&&url.searchParams.has('options')){detailQueries.push(target._id);await gate;}
   let data;try{data=handleDemoRequest(state,request.method(),request.url(),request.postDataJSON()||{});}catch{data={};}await route.fulfill({json:data});
  });
  const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(`${process.env.REVIEW_ORIGIN||'http://127.0.0.1:33428'}/home?view=machines&machine=${machine._id}&machineTab=ports`);
  await page.getByRole('button',{name:'Edit forwarding rule Exact BMC port',exact:true}).click();await page.getByRole('button',{name:'Web Addresses',exact:true}).click();await page.getByRole('button',{name:'Create proxy',exact:true}).click();
  const dialog=page.getByRole('dialog').filter({has:page.getByText('Create Proxy Route',{exact:true})});await dialog.waitFor();await dialog.getByRole('button',{name:'Bindings',exact:true}).click();
  const machinePicker=dialog.getByLabel('Binding 1 machine',{exact:true}),portPicker=dialog.getByLabel('Binding 1 port',{exact:true});
  await machinePicker.waitFor({state:'visible'});
  if(!await machinePicker.count())await page.screenshot({path:`/tmp/porthub-proxy-context-missing-${width}.png`});
  assert.equal(await machinePicker.count(),1,'Host-port creation must initialize Machine port, not Standalone URL');
  const selectedId=locator=>locator.evaluate(e=>e.closest('.mantine-Select-root').querySelector('input[type=hidden]').value);
  assert.equal(await selectedId(machinePicker),machine._id);assert.equal(await selectedId(portPicker),target._id,'Exact second port ID, never first/same-number/other host');
  await dialog.getByLabel('Binding 1 label',{exact:true}).fill('Operator draft');await dialog.getByLabel('Binding 1 priority',{exact:true}).fill('7');assert(detailQueries.length>0,'Exact selected-port metadata is fetched lazily');
  const response=page.waitForResponse(r=>new URL(r.url()).searchParams.get('ids')===target._id&&new URL(r.url()).searchParams.has('options'));release();await response;
  await page.waitForFunction(()=>document.querySelector('input[aria-label="Binding 1 port"]').value.includes('Exact BMC port'));
  assert.equal(await dialog.getByLabel('Binding 1 label',{exact:true}).inputValue(),'Operator draft');assert.equal(await dialog.getByLabel('Binding 1 priority',{exact:true}).inputValue(),'7');assert.equal(await selectedId(machinePicker),machine._id);assert.equal(await selectedId(portPicker),target._id);
  await portPicker.click();await page.getByRole('option',{name:/First HTTP service/}).click();assert.equal(await selectedId(portPicker),wrong._id,'Prefilled binding remains editable');
  await dialog.getByRole('button',{name:'Standalone URL',exact:true}).click();await dialog.getByLabel('Binding 1 URL',{exact:true}).fill('https://edited.example.invalid/app');await dialog.getByRole('button',{name:'Machine port',exact:true}).click();assert.equal(await selectedId(portPicker),wrong._id);assert.equal(await dialog.getByLabel('Binding 1 label',{exact:true}).inputValue(),'Operator draft');
  await page.screenshot({path:`/tmp/porthub-proxy-context-${process.env.REVIEW_BROWSER||'chromium'}-${width}.png`});await dialog.getByRole('button',{name:'Cancel',exact:true}).click();await dialog.waitFor({state:'hidden'});assert.deepEqual(writes,[],'Cancel creates no proxy/port/policy writes');
  await page.goto(`${process.env.REVIEW_ORIGIN||'http://127.0.0.1:33428'}/home?view=proxies`);await page.getByRole('button',{name:'Create proxy',exact:true}).click();
  const global=page.getByRole('dialog').filter({has:page.getByText('Create Proxy Route',{exact:true})});await global.getByRole('button',{name:'Bindings',exact:true}).click();await global.getByLabel('Binding 1 URL',{exact:true}).waitFor({state:'visible'});assert.equal(await global.getByLabel('Binding 1 URL',{exact:true}).count(),1);assert.equal(await global.getByLabel('Binding 1 machine',{exact:true}).count(),0,'Global create still defaults to standalone');await global.getByRole('button',{name:'Cancel',exact:true}).click();assert.deepEqual(writes,[]);assert.deepEqual(errors,[]);assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));await context.close();console.log(`PASS proxy exact port context/lazy metadata/edit/cancel/global ${width}`);
 }}finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
