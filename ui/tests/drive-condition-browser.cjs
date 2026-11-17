const assert=require('node:assert/strict');
const {launchBrowser}=require('./browser.cjs');
(async()=>{
 const {makeDemoData,handleDemoRequest}=await import('../src/shared/demo/data.mjs');
 const browser=await launchBrowser();
 try{for(const width of [1440,402])for(const scenario of ['three-drives','empty','removed','disabled']){
  const context=await browser.newContext({viewport:{width,height:950},serviceWorkers:'allow'});
  const state=makeDemoData(),machine=state.machines[1],now=Date.now(),queries=[];
  const drive=(id,name,status)=>({id:id.repeat(64),name,status,present:true,protocol:'ata',capacity:512*1024**3,observed_at:now,checked_at:now,reasons:status==='critical'?['SMART failure assessment']:status==='warning'?['Pending sectors reported']:[],self_test:'unsupported'});
  const a=drive('a','System SSD','warning'),b=drive('b','Archive HDD','critical'),c=drive('c','External USB SSD','unavailable');
  let current=[a,b,c],history=[];
  for(let i=0;i<25;i++)for(const d of current)history.push({at:now-(25-i)*3600000,snapshot:{...d,status:d.id===a.id?(i===15?'unavailable':i<12?'healthy':'warning'):d.id===b.id?(i<10?'healthy':'critical'):'unavailable'}});
  if(scenario==='empty'){current=[];history=[];}
  if(scenario==='removed'){current=[{...a,present:false,status:'removed'}];history=[{at:now-3600000,snapshot:{...a,status:'healthy'}},{at:now,snapshot:current[0]}];}
  const sample={cpu:10,cores:4,ram:{used:1024**3,total:8*1024**3},disk:{used:1024**3,total:16*1024**3},gpus:[],drive_health_enabled:scenario!=='disabled',drive_tests_enabled:false,drive_health:current};
  await context.route('**/api/**',async route=>{
   const request=route.request(),url=new URL(request.url()),path=url.pathname;let data;
   const latest={at:Date.now(),sample};
   if(path==='/api/machines/metrics')data={machines:[{id:machine._id,name:machine.name,live:true,reading:latest}]};
   else if(path===`/api/machines/metrics/${machine._id}`)data={latest,history:[{at:now-60000,sample}],interval_ms:60000};
   else if(path.endsWith('/drives')){const id=url.searchParams.get('drive');queries.push(id);data={drives:current,history:history.filter(p=>!id||p.snapshot.id===id),days:7,retention_days:90,truncated:false};}
   else{try{data=handleDemoRequest(state,request.method(),request.url());}catch{data={};}}
   await route.fulfill({json:data});
  });
  const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(`${process.env.REVIEW_ORIGIN||'http://127.0.0.1:33418'}/home?view=dashboard`);
  await page.getByRole('region',{name:'Machine resource utilization'}).getByRole('button').filter({hasText:machine.name}).click();
  const panel=page.getByRole('region',{name:'Physical drive health and history'});await panel.waitFor();
  if(scenario==='empty'){
   await panel.getByText('No physical drives are reported by this client.',{exact:true}).waitFor();assert.equal(await panel.getByRole('img',{name:'All-drive SMART condition history'}).count(),0);
  }else{
   const legend=panel.getByRole('list',{name:'Drive condition legend'});await legend.waitFor();
   if(scenario==='three-drives'){
    const alert=panel.getByRole('status',{name:'Drives needing attention'});await alert.waitFor();assert((await alert.getAttribute('class')).includes('border-red-500/30'));assert((await alert.innerText()).includes('System SSD'));assert((await alert.innerText()).includes('Archive HDD'));assert(!(await alert.innerText()).includes('External USB SSD'));
    const chart=panel.getByRole('img',{name:'All-drive SMART condition history'});assert(await panel.locator('[data-condition-axis] span,[data-condition-dates] span').evaluateAll(nodes=>nodes.length===5&&nodes.every(e=>parseFloat(getComputedStyle(e).fontSize)>=10)));assert.equal(await chart.locator('g[data-drive-id]').count(),3);assert.equal(await legend.locator('li').count(),3);assert.equal(await chart.locator(`g[data-drive-id="${a.id}"] polyline`).count(),2,'Unknown observation breaks the SSD line');assert.equal(await chart.locator(`g[data-drive-id="${c.id}"] circle`).count(),0,'Unsupported drive is not healthy or zero');
    await Promise.all([page.waitForResponse(r=>r.url().includes('drive='+b.id)),(async()=>{const picker=panel.getByLabel('Physical drive',{exact:true});await picker.click();await picker.fill('Archive HDD');await page.getByRole('option',{name:/Archive HDD/}).click();})()]);
    assert.equal(await chart.locator('g[data-drive-id]').count(),3,'Selected details never filter all-drive chart');assert.equal(await panel.getByRole('list',{name:'Drive health observations'}).locator('li').count(),12);assert(await panel.getByRole('list',{name:'Drive health observations'}).evaluate(e=>e.getBoundingClientRect().height<=209&&getComputedStyle(e).overflowY==='auto'));assert(queries.includes(null)&&queries.includes(b.id));
   }else if(scenario==='removed'){
    assert((await legend.innerText()).includes('Removed'));assert.equal(await panel.getByRole('status',{name:'Drives needing attention'}).count(),0);assert.equal(await panel.getByRole('img').locator('polyline').count(),0,'Removed sample cannot extend a healthy line');
   }else{
    assert((await legend.innerText()).includes('Current status unknown'));assert.equal(await panel.getByRole('status',{name:'Drives needing attention'}).count(),0,'Disabled reports cannot assert current failure');await panel.getByText('Drive-health reporting is disabled on this client.',{exact:false}).waitFor();
   }
  }
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));assert.deepEqual(errors,[]);
  if(scenario==='three-drives'){await panel.getByRole('heading',{name:'Drive health',exact:true}).scrollIntoViewIfNeeded();await page.screenshot({path:`/tmp/porthub-all-drive-${process.env.REVIEW_BROWSER||'chromium'}-${width}.png`});await panel.getByLabel('All physical drives SMART condition',{exact:true}).scrollIntoViewIfNeeded();await page.screenshot({path:`/tmp/porthub-all-drive-${process.env.REVIEW_BROWSER||'chromium'}-${width}-chart.png`});}
  await context.close();console.log(`PASS all-drive SMART ${scenario} ${width}`);
 }}finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
