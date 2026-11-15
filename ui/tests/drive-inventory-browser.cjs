const assert=require('node:assert/strict');
const {launchBrowser}=require('./browser.cjs');
(async()=>{
 const {makeDemoData,handleDemoRequest}=await import('../src/shared/demo/data.mjs');
 const browser=await launchBrowser();
 try {
  for(const width of (process.env.CATALOG_ONLY?[]:[390,768,1024,1440]))for(const scenario of ['fresh-empty','disabled','missing','stale','rejoined','removed']){
   const context=await browser.newContext({viewport:{width,height:1000},serviceWorkers:'allow'});
   const state=makeDemoData(),machine=state.machines[1],now=Date.now();
   const old={id:'a'.repeat(64),name:'Legacy virtual disk',capacity:32*1024**3,protocol:'ata',present:true,status:'critical',observed_at:now-3600000,checked_at:now-3600000,reasons:['Historical SMART observation'],self_test:'unsupported'};
   const removed={...old,name:'Unplugged external SSD',present:false,status:'removed'};
   const rejoined={...old,name:'Rejoined physical SSD',status:'healthy',observed_at:now,checked_at:now,reasons:[]};
   const historical=scenario==='removed'||scenario==='rejoined'?removed:old;
   await context.route('**/api/**',async route=>{
    const request=route.request(),path=new URL(request.url()).pathname;
    const sample={cpu:10,cores:4,ram:{used:1024**3,total:8*1024**3},disk:{used:1024**3,total:16*1024**3},gpus:[],drive_health_enabled:scenario!=='disabled',drive_tests_enabled:false};
    if(scenario!=='missing')sample.drive_health=scenario==='rejoined'?[rejoined]:scenario==='removed'?[removed]:[];
    const latest={at:Date.now()-(scenario==='stale'?120000:0),sample};let data;
    if(path==='/api/machines/metrics')data={machines:[{id:machine._id,name:machine.name,live:true,reading:latest}]};
    else if(path===`/api/machines/metrics/${machine._id}`)data={latest,history:[{at:now-60000,sample}],interval_ms:60000};
    else if(path.endsWith('/drives'))data={drives:[historical],history:[{at:now-3600000,snapshot:historical}]};
    else{try{data=handleDemoRequest(state,request.method(),request.url());}catch{data={};}}
    await route.fulfill({json:data});
   });
   const page=await context.newPage(),errors=[];page.on('pageerror',error=>errors.push(error.message));
   await page.goto(`${process.env.REVIEW_ORIGIN||'http://127.0.0.1:3219'}/home?view=dashboard`);
   await page.getByRole('region',{name:'Machine resource utilization'}).getByRole('button').filter({hasText:machine.name}).click();
   const panel=page.getByRole('region',{name:'Physical drive health and history'});
   await panel.getByLabel('Physical drive',{exact:true}).waitFor();
   const picker=await panel.getByLabel('Physical drive',{exact:true}).inputValue();
   if(scenario==='fresh-empty'){
    assert(picker.includes('Historical'));await panel.getByText('Historical',{exact:true}).waitFor();
    await panel.getByText('No physical drives in the current report',{exact:true}).waitFor();
    assert((await panel.innerText()).includes('Not in the current report. Last recorded health: Critical.'));assert(!(await panel.innerText()).includes(' · Removed '));
   }else if(['disabled','missing','stale'].includes(scenario)){
    assert(picker.includes('Last recorded'));await panel.getByText('Current status unknown',{exact:true}).waitFor();
    assert((await panel.innerText()).includes('Current presence is unknown.'));assert(!(await panel.innerText()).includes(' · Removed '));
   }else if(scenario==='rejoined'){
    assert(picker.includes('Rejoined physical SSD'));assert(!picker.includes('Historical'));await panel.getByText('Healthy',{exact:true}).first().waitFor();assert(!(await panel.innerText()).includes('Not in the current report.'));
   }else{
    assert(picker.includes('Removed'));await panel.getByText('Removed',{exact:true}).first().waitFor();assert((await panel.innerText()).includes(' · Removed '));
   }
   assert.equal(await panel.getByRole('list',{name:'Drive health observations'}).locator('li').count(),1,'Raw retained history remains visible');
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));assert.deepEqual(errors,[]);
   if(scenario==='fresh-empty')await panel.screenshot({path:`/tmp/porthub-drive-historical-${width}.png`});
   await context.close();console.log(`PASS drive inventory ${scenario} ${width}`);
  }

  const context=await browser.newContext({viewport:{width:1024,height:1000},serviceWorkers:'allow'});
  const state=makeDemoData(),hosts=state.machines.slice(0,2),now=Date.now(),queries=[];
  const snapshot=(id,name)=>({id,name,capacity:32*1024**3,protocol:'ata',present:true,status:'healthy',observed_at:now-3600000,checked_at:now-3600000,reasons:[],self_test:'unsupported'});
  const catalogs=[[snapshot('a'.repeat(64),'Historical A'),snapshot('b'.repeat(64),'Historical B')],[snapshot('c'.repeat(64),'Other host C')]];
  const reading=()=>({at:Date.now(),sample:{cpu:10,cores:4,ram:{used:1024**3,total:8*1024**3},disk:{used:1024**3,total:16*1024**3},gpus:[],drive_health_enabled:true,drive_health:[]}});
  await context.route('**/api/**',async route=>{
   const request=route.request(),url=new URL(request.url()),path=url.pathname;let data;
   const index=hosts.findIndex(host=>path.includes(host._id));
   if(path==='/api/machines/metrics')data={machines:hosts.map(host=>({id:host._id,name:host.name,live:true,reading:reading()}))};
   else if(index>=0&&path.endsWith('/drives')){const id=url.searchParams.get('drive');queries.push({host:index,id});const drives=catalogs[index].filter(d=>!id||d.id===id);data={drives,history:drives.map(snapshot=>({at:now-3600000,snapshot}))};}
   else if(index>=0&&path.includes('/metrics/'))data={latest:reading(),history:[],interval_ms:60000};
   else{try{data=handleDemoRequest(state,request.method(),request.url());}catch{data={};}}
   await route.fulfill({json:data});
  });
  const page=await context.newPage();await page.goto(`${process.env.REVIEW_ORIGIN||'http://127.0.0.1:3219'}/home?view=dashboard`);
  const openHost=async host=>{await page.getByRole('region',{name:'Machine resource utilization'}).getByRole('button').filter({hasText:host.name}).click();await page.getByLabel('Physical drive',{exact:true}).waitFor();};
  await openHost(hosts[0]);
  const choose=async name=>{await page.getByLabel('Physical drive',{exact:true}).click();await page.getByRole('option',{name:new RegExp(name)}).click();};
  await Promise.all([page.waitForResponse(response=>response.url().includes('/drives?')&&response.url().includes('drive='+catalogs[0][0].id)),choose('Historical A')]);
  await Promise.all([page.waitForResponse(response=>response.url().includes('/drives?')&&response.url().includes('drive='+catalogs[0][1].id)),choose('Historical B')]);
  await page.getByRole('button',{name:'Close',exact:true}).click();await page.getByRole('region',{name:'Physical drive health and history'}).waitFor({state:'hidden'});
  await page.getByRole('button',{name:'Dashboard',exact:true}).click();await openHost(hosts[1]);assert((await page.getByLabel('Physical drive',{exact:true}).inputValue()).includes('Other host C'));
  await page.getByLabel('Physical drive',{exact:true}).click();assert.equal(await page.getByRole('option',{name:/Historical [AB]/}).count(),0);await page.keyboard.press('Escape');
  assert(!queries.some(query=>query.host===1&&query.id&&query.id!==catalogs[1][0].id),'Old host selection must never reach another host query');
  await context.close();console.log('PASS historical A→B selection and host isolation');
 }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
