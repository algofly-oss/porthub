const assert=require('node:assert/strict');

const {launchBrowser}=require('./browser.cjs');

(async()=>{const{makeDemoData,handleDemoRequest}=await import('../src/shared/demo/data.mjs');
const browser=await launchBrowser();
try{for(const viewport of [{width:402,height:874},{width:874,height:402}]){const context=await browser.newContext({viewport,isMobile:true,hasTouch:true,serviceWorkers:'block'});
// Exported-app fixture: disable registration as well as blocking workers so
// the PWA wrapper cannot observe a rejected/undefined registration.
await context.addInitScript(()=>{delete Object.getPrototypeOf(navigator).serviceWorker;});
const state=makeDemoData(),host=state.machines[1],target=state.machines[2],long='ExternalUSBStorageDeviceWithAnExtremelyLongUnbrokenIdentifier01234567890123456789';
const now=Date.now(),drive={id:'fixture-drive',name:'NVMe fixture',protocol:'nvme',present:true,status:'healthy',capacity:1024**4,checked_at:now,observed_at:now,temperature:42,percentage_used:3,available_spare:100,power_on_hours:1000,media_errors:0,self_test:'passed',reasons:[]},sample={cpu:25,cores:8,ram:{used:1024**3,total:8*1024**3},disk:{used:1024**3,total:4*1024**3},gpus:[],drive_health:[drive],drive_health_enabled:true};
const device={busid:'1-14',vendor:'0781',product:'55a9',serial:'fixture',name:long};
await context.route('**/api/**',async route=>{const r=route.request(),p=new URL(r.url()).pathname;
let data;
if(p==='/api/machines/metrics')data={machines:[{id:host._id,name:host.name,live:true,reading:{at:Date.now(),sample}}]};
else if(p.endsWith('/drives'))data={drives:[drive],history:[{at:now-60000,snapshot:drive},{at:now,snapshot:drive}]};
else if(p.startsWith('/api/machines/metrics/'))data={latest:{at:now,sample},history:[{at:now-60000,sample},{at:now,sample}],interval_ms:60000};
else if(p==='/api/usb/inventory')data={machines:[host,target].map(m=>({id:m._id,name:m.name,online:true,report:{enabled:true,supported:true,can_export:true,can_import:true,devices:m===host?[device,{...device,busid:"1-15",blocked:"Mounted storage "+long}]:[],states:[]}}))};
else if(p==='/api/usb/forwards')data={forwards:[{id:'a'.repeat(32),source:host._id,destination:target._id,device,persistent:true}]};
else if(p==='/api/media/inventory')data={machines:[]};
else if(p==='/api/media/forwards')data={plans:[]};
else{try{data=handleDemoRequest(state,r.method(),r.url());
}catch{data={};
}}await route.fulfill({json:data});
});
const page=await context.newPage(),errors=[];
page.on('pageerror',e=>errors.push(e.message));
await page.goto(`${process.env.REVIEW_ORIGIN||'http://127.0.0.1:3019'}/home?view=dashboard`);
await page.getByRole('region',{name:'Machine resource utilization'}).getByRole('button').filter({hasText:host.name}).click();
// Reload the actual URL-backed Resources selection: clicking first would let
// browser/Playwright focus scrolling hide a missing StatusTabs mount effect.
await page.waitForURL(url=>url.searchParams.get('machineTab')==='resources');
await page.waitForLoadState('networkidle');
await page.reload();
const sections=page.getByRole('group',{name:'Machine configuration sections',exact:true});
await sections.waitFor();
const selectedGeometry=()=>sections.evaluate(group=>{
 const selected=group.querySelector('[aria-pressed="true"]');
 let parent=group.parentElement;
 while(parent&&!['auto','scroll'].includes(getComputedStyle(parent).overflowX))parent=parent.parentElement;
 const tab=selected.getBoundingClientRect(),clip=parent.getBoundingClientRect();
 return {label:selected.textContent,visible:tab.left>=clip.left+parent.clientLeft-1&&tab.right<=clip.left+parent.clientLeft+parent.clientWidth+1};
});
const vertical=()=>page.evaluate(()=>({page:scrollY,modal:[...document.querySelectorAll('[role="dialog"], [role="dialog"] *')].filter(el=>['auto','scroll'].includes(getComputedStyle(el).overflowY)).reduce((sum,el)=>sum+el.scrollTop,0)}));
await page.waitForFunction(()=>{const g=document.querySelector('[aria-label="Machine configuration sections"]'),b=g?.querySelector('[aria-pressed="true"]');if(!b)return false;const p=g.parentElement,r=p.getBoundingClientRect(),t=b.getBoundingClientRect();return t.left>=r.left-1&&t.right<=r.left+p.clientWidth+1;});
assert.deepEqual(await selectedGeometry(),{label:'Resources',visible:true},'Deep-linked selected Resources is visible after mounting');
const before=await vertical();
// DOM click deliberately avoids Playwright's automatic scrollIntoView.
await sections.getByRole('button',{name:'Details',exact:true}).evaluate(button=>button.click());
await page.waitForURL(url=>url.searchParams.get('machineTab')==='groups');
await page.waitForFunction(()=>document.querySelector('[aria-label="Machine configuration sections"] [aria-pressed="true"]')?.textContent==='Details');
await page.waitForTimeout(50);
assert.deepEqual(await selectedGeometry(),{label:'Details',visible:true},'Value change reveals the selected tab');
assert.deepEqual(await vertical(),before,'Tab reveal does not scroll page or modal vertically');
await sections.getByRole('button',{name:'Resources',exact:true}).evaluate(button=>button.click());
await page.waitForURL(url=>url.searchParams.get('machineTab')==='resources');
await page.waitForFunction(()=>document.querySelector('[aria-label="Machine configuration sections"] [aria-pressed="true"]')?.textContent==='Resources');
await page.setViewportSize({width:320,height:viewport.height});
await page.waitForTimeout(50);
assert.deepEqual(await selectedGeometry(),{label:'Resources',visible:true},'Resize keeps Resources visible');
assert.deepEqual(await vertical(),before,'Resize reveal preserves vertical scroll');
await page.setViewportSize(viewport);

for(const tab of ['Resources','USB']){await page.getByRole('button',{name:tab,exact:true}).click();
const dialog=page.getByRole('dialog');
await page.waitForTimeout(200);
if(tab==='Resources'){const health=page.getByRole('region',{name:'Physical drive health and history'});
await health.getByLabel('Physical drive',{exact:true}).waitFor();
await health.getByLabel('Physical drive',{exact:true}).click();
await page.getByRole('listbox').waitFor();
const menu=await page.getByRole('listbox').boundingBox();
assert(menu.x>=-1&&menu.x+menu.width<=viewport.width+1&&menu.y>=-1&&menu.y+menu.height<=viewport.height+1,'Search results remain inside phone');
await page.keyboard.press('Escape');
await health.getByText('Physical drives are rediscovered every minute.',{exact:false}).scrollIntoViewIfNeeded();
}if(tab==='USB'){await page.getByRole('region',{name:'USB forwarding'}).waitFor();
await page.getByLabel('USB destination machine',{exact:true}).click();
await page.getByRole('listbox').waitFor();
const menu=await page.getByRole('listbox').boundingBox();
assert(menu.x>=-1&&menu.x+menu.width<=viewport.width+1&&menu.y>=-1&&menu.y+menu.height<=viewport.height+1,'Search results remain inside phone');
await page.keyboard.press('Escape');
await page.getByText('CLI and client permissions',{exact:true}).click();
await page.getByText('Block USB sharing and attaching locally:',{exact:false}).scrollIntoViewIfNeeded();
}const geometry=await dialog.evaluate(el=>({client:el.clientWidth,scroll:el.scrollWidth,wide:[...el.querySelectorAll('*')].filter(e=>{const r=e.getBoundingClientRect();
let p=e.parentElement;
while(p&&p!==el){if(/auto|scroll/.test(getComputedStyle(p).overflowX)&&p.scrollWidth>p.clientWidth+1)return false;
p=p.parentElement;
}return r.width&&r.left>=0&&r.right>innerWidth+1;
}).map(e=>({tag:e.tagName,text:e.textContent.slice(0,70),width:e.getBoundingClientRect().width}))}));
console.log(JSON.stringify({viewport,tab,geometry}));
assert(geometry.scroll<=geometry.client+1,`${tab} dialog has no horizontal clipping`);
assert.deepEqual(geometry.wide,[],`${tab} descendants fit phone`);
await page.screenshot({path:`/tmp/porthub-iphone-host-${viewport.width}-${tab}.png`});
}const close=page.getByRole('dialog').getByRole('button',{name:'Close',exact:true});
await close.scrollIntoViewIfNeeded();
const box=await close.boundingBox();
assert(box.y>=0&&box.y+box.height<=viewport.height,'Host close remains reachable');
await close.click();
await page.getByRole('dialog').waitFor({state:'hidden'});
assert.deepEqual(errors,[]);
await context.close();
}}finally{await browser.close();
}})().catch(e=>{console.error(e);
process.exitCode=1;
});

