const assert=require('node:assert/strict');
const {launchBrowser}=require('./browser.cjs');
const {chooseDropdown}=require('./search-dropdown.cjs');
(async()=>{
 const {makeDemoData,handleDemoRequest}=await import('../src/shared/demo/data.mjs');
 const browser=await launchBrowser();
 try{
  for(const width of [390,1440]){
   const context=await browser.newContext({viewport:{width,height:1000},serviceWorkers:'block'});
   const state=makeDemoData(),machine=state.machines[1],now=Date.now();
   const integrated={id:'integrated',name:'Integrated fixture',integrated:true,utilization:50,memory:null,shared_memory_capacity:8*1024**3,shared_memory:{used:256*1024**2,total:8*1024**3}};
   const discrete={id:'discrete',name:'Discrete fixture',utilization:null,memory:{used:1024**3,total:4*1024**3}};
   const limitOnly={id:'limit-only',name:'Capacity-only fixture',integrated:true,utilization:null,memory:null,shared_memory_capacity:8*1024**3};
   const sample={cpu:25,cores:8,ram:{used:1024**3,total:8*1024**3},disk:{used:1024**3,total:4*1024**3},gpus:[integrated,discrete,limitOnly]};
   const latest={at:now,sample},history=[{at:now-60000,sample},{at:now,sample}];
   await context.route('**/api/**',async route=>{
    const request=route.request(),path=new URL(request.url()).pathname;
    let data;
    if(path==='/api/machines/metrics')data={machines:[{id:machine._id,name:machine.name,live:true,reading:latest}]};
    else if(path===`/api/machines/metrics/${machine._id}`)data={latest,history,interval_ms:60000};
    else if(path.endsWith('/drives'))data={drives:[],history:[]};
    else{try{data=handleDemoRequest(state,request.method(),request.url());}catch{data={};}}
    await route.fulfill({json:data});
   });
   const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
   await page.goto(`${process.env.REVIEW_ORIGIN||'http://127.0.0.1:3019'}/home?view=dashboard`);
   await page.getByRole('region',{name:'Machine resource utilization'}).getByRole('button').filter({hasText:machine.name}).click();
   const health=page.getByRole('region',{name:'Machine health and resource history'});
   const chart=name=>health.getByRole('heading',{name:`GPU · ${name}`,exact:true}).locator('..');
   const first=chart('Integrated fixture');await first.waitFor();
   assert((await first.getByRole('listitem').filter({hasText:'Dedicated VRAM'}).innerText()).includes('Unavailable'));
   assert((await first.getByRole('listitem').filter({hasText:'Shared GPU memory'}).innerText()).includes('256.0 MB / 8.0 GB max'));
   assert.equal(await first.locator('polyline').count(),2,'Only measured utilization and shared usage generate history lines');
   await chooseDropdown(health.getByLabel('GPU device',{exact:true}),'Discrete fixture · discrete');
   const second=chart('Discrete fixture');
   assert((await second.getByRole('listitem').filter({hasText:'Dedicated VRAM'}).innerText()).includes('1.0 GB / 4.0 GB'));
   assert.equal(await second.getByRole('listitem').filter({hasText:'Shared GPU memory'}).count(),0,'Shared limits do not cross adapters');
   assert.equal(await second.locator('polyline').count(),1,'Unknown utilization is not plotted as zero');
   await chooseDropdown(health.getByLabel('GPU device',{exact:true}),'Capacity-only fixture · limit-only');
   const third=chart('Capacity-only fixture');
   assert((await third.getByRole('listitem').filter({hasText:'Shared GPU memory'}).innerText()).includes('Up to 8.0 GB · usage unavailable'));
   assert.equal(await third.locator('polyline,circle').count(),0,'Capacity alone never becomes measured memory usage');
   assert.equal(await third.getByText('No sensor readings in this period.',{exact:true}).count(),1);
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   assert.deepEqual(errors,[]);await page.screenshot({path:`/tmp/porthub-shared-gpu-${width}.png`,fullPage:true});
   await context.close();console.log(`PASS independent shared GPU semantics and adapter switching ${width}`);
  }
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
