const assert=require('node:assert/strict');
const artifactTag=process.env.REVIEW_ARTIFACT_TAG?'-'+process.env.REVIEW_ARTIFACT_TAG:'';
const {launchBrowser}=require('./browser.cjs');
(async()=>{const {makeDemoData,handleDemoRequest}=await import('../src/shared/demo/data.mjs');const browser=await launchBrowser();try{
for(const viewport of [{width:1440,height:900},{width:402,height:874}]){
 const context=await browser.newContext({viewport,serviceWorkers:'block'});await context.addInitScript(()=>{delete Object.getPrototypeOf(navigator).serviceWorker;});
 const state=makeDemoData(),[luna,aero,miro]=state.machines;luna.name='Luna';aero.name='Aero';miro.name='Miro';
 const physical={busid:'2-3',vendor:'1377',product:'1100',serial:'headset',name:'Headset'},alias={...physical,busid:'0-12',name:'Headset (forwarded)'},busy={...physical,busid:'3-4',serial:'busy',name:'Busy headset'};
 const forwards=[{id:'one',source:luna._id,destination:aero._id,device:physical,persistent:true},{id:'two',source:aero._id,destination:miro._id,device:busy,persistent:true}];
 let requests=[];
 await context.route('**/api/**',async route=>{const r=route.request(),p=new URL(r.url()).pathname;requests.push([r.method(),p]);let data;
 if(p==='/api/boards')data={boards:[]};
 else if(p==='/api/usb/inventory')data={machines:[luna,aero,miro].map(m=>({id:m._id,name:m.name,online:true,report:{enabled:true,supported:true,can_export:true,can_import:true,devices:m===aero?[alias,busy]:m===luna?[physical]:[],imports:m===aero?[{busid:alias.busid,upstream_id:'one'}]:[],states:[]}}))};
 else if(p==='/api/usb/forwards')data={forwards};
 else if(p==='/api/media/inventory')data={machines:[]};else if(p==='/api/media/forwards')data={plans:[]};
 else{try{data=handleDemoRequest(state,r.method(),r.url())}catch{data={}}}await route.fulfill({json:data});});
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
 const origin=process.env.REVIEW_ORIGIN||'http://127.0.0.1:3057';
 await page.goto(origin+'/home?view=boards');await page.getByRole('heading',{name:'No boards yet',exact:true}).waitFor();
 await page.evaluate(()=>document.fonts.ready);await page.waitForTimeout(200);
 const box=await page.locator('[aria-labelledby="boards-empty-title"]').evaluate(el=>{const r=el.getBoundingClientRect(),p=el.parentElement.getBoundingClientRect();return {top:r.top,bottom:r.bottom,parentBottom:p.bottom,height:r.height,viewport:innerHeight,workspaceBottom:document.querySelector('#workspace-content').getBoundingClientRect().bottom,overflow:document.documentElement.scrollWidth>innerWidth};});
 assert(box.height>viewport.height/2,'Empty Boards uses remaining view height');assert(Math.abs(box.bottom-box.parentBottom)<3,'Empty state fills its card');assert(Math.abs(box.workspaceBottom-box.parentBottom-12)<3,'Card fills workspace above the phone navigation');assert(!box.overflow,'No horizontal overflow');
 await page.screenshot({path:`/tmp/porthub-boards-fill-${process.env.REVIEW_BROWSER||'chromium'}-${viewport.width}${artifactTag}.png`});
 await page.goto(origin+'/home?view=machines&machine='+aero._id+'&machineTab=usb');
 const usb=page.getByRole('region',{name:'USB forwarding'});await usb.waitFor();
 await usb.getByLabel('USB device',{exact:true}).click();
 const choice=page.getByRole('option').filter({hasText:'Forwarded from Luna'});await choice.waitFor();assert.match(await choice.textContent(),/Headset/);
 const inUse=page.getByRole('option').filter({hasText:'In use on Miro'});assert(await inUse.evaluate(el=>el.hasAttribute('data-disabled')||el.getAttribute('aria-disabled')==='true'),'Outgoing option remains disabled');
 await page.screenshot({path:`/tmp/porthub-usb-origin-menu-${process.env.REVIEW_BROWSER||'chromium'}-${viewport.width}${artifactTag}.png`});await choice.click();const closed=usb.getByLabel('USB device',{exact:true});assert.match(await closed.inputValue(),/^Forwarded from Luna · Headset · 0-12$/);assert(await closed.evaluate(el=>{const s=getComputedStyle(el),c=document.createElement('canvas').getContext('2d');c.font=s.font;return c.measureText('Forwarded from Luna').width<el.getBoundingClientRect().width-parseFloat(s.paddingLeft)-parseFloat(s.paddingRight)}),'Original source fits the closed selector');await usb.getByLabel('USB destination machine',{exact:true}).click();await page.getByRole('option',{name:'Miro',exact:true}).click();
 await usb.getByLabel('USB forwarding direction').getByText('Luna → Aero → Miro',{exact:true}).waitFor();
 assert.match(await usb.getByLabel('USB forwarding direction').innerText(),/physically connected to Luna and forwarded through Aero/);
 await page.screenshot({path:`/tmp/porthub-usb-chain-${process.env.REVIEW_BROWSER||'chromium'}-${viewport.width}${artifactTag}.png`});
 assert(!requests.some(([method])=>method!=='GET'),'Lineage and selection cause no mutation requests');assert.deepEqual(errors,[]);
 console.log(JSON.stringify({viewport,boards:box,origin:'Luna',chain:'Luna → Aero → Miro',disabled_destination_explained:true,no_mutations:true}));await context.close();
}
}finally{await browser.close()}})().catch(e=>{console.error(e);process.exit(1)});
