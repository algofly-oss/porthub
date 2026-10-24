const { launchBrowser } = require("./browser.cjs");
const assert = require('node:assert/strict');
(async () => {
 const {makeDemoData,handleDemoRequest} = await import("../src/shared/demo/data.mjs");
 const state=makeDemoData(); const originalName=state.machines[0].name;
 // A gateway bind address must not appear in public port labels; internal
 // destinations remain explicit IP:port values.
 state.connections.forEach(connection => connection.external_bind_ip = '192.0.2.44');
 const browser=await launchBrowser();
 const page=await browser.newPage({viewport:{width:1512,height:982},serviceWorkers:'block'});
 // These fixtures mock API traffic; disable PWA registration as well as its network interception.
 await page.addInitScript(()=>{delete Navigator.prototype.serviceWorker;});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 let release=null, hold=false, refreshRequested=false;
 await page.route('**/api/**',async route=>{
  const req=route.request(); let body={};try{body=req.postDataJSON()||{}}catch{}
  if(hold && req.url().includes('/machines/list')) {refreshRequested=true; await new Promise(r=>release=r);}
  await route.fulfill({json:handleDemoRequest(state,req.method().toLowerCase(),req.url(),body)}).catch(()=>{});
 });
 try {
  await page.goto(`${process.env.REVIEW_ORIGIN || "http://127.0.0.1:47130"}/home?view=machines`);
  await page.getByText(state.machines[0].name,{exact:true}).first().waitFor();
  await page.getByRole('navigation',{name:'Workspace pages',exact:true}).getByRole('button',{name:'Proxies',exact:true}).click();
  await page.getByRole('heading',{name:'Public Web Proxies',exact:true}).waitFor();
  state.machines[0].name='AAA Refreshed machine name';hold=true;
  await page.getByRole('navigation',{name:'Workspace pages',exact:true}).getByRole('button',{name:'Machines',exact:true}).click();
  await page.getByText(originalName,{exact:true}).first().waitFor({timeout:5000});
  await page.waitForFunction(()=>!document.querySelector('main').innerText.includes('Loading machines'));
  await page.waitForTimeout(150);
  assert(refreshRequested,'tab activation should request fresh data');
  assert(release,'refresh request should remain delayed');
  assert(!(await page.locator('main').innerText()).includes('AAA Refreshed machine name'),'cached data stays visible until fresh response');
  release();hold=false;
  await page.getByText('AAA Refreshed machine name',{exact:true}).first().waitFor();
  await page.getByRole('navigation',{name:'Workspace pages',exact:true}).getByRole('button',{name:'Traffic',exact:true}).click();
  await page.getByText(/\d+ → 127\.0\.0\.1:\d+/).first().waitFor();
  assert(!(await page.locator('main').innerText()).includes('192.0.2.44:'), 'public labels omit the gateway bind IP');
  assert.deepEqual(errors,[]);
  console.log('PASS cached tab content appears while revalidation is delayed; fresh data replaces it; public ports and internal endpoints displayed; no browser errors');
 }finally{release?.();await browser.close()}
})().catch(e=>{console.error(e);process.exit(1)});
