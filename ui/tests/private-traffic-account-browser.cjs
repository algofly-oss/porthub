const assert=require('node:assert/strict');
const {launchBrowser}=require('./browser.cjs');
(async()=>{
 const{makeDemoData,handleDemoRequest}=await import('../src/shared/demo/data.mjs');
 const{demoPrivateTraffic}=await import('../src/shared/demo/private-traffic.mjs');
 const states={};for(const account of ['A','B']){const state=makeDemoData();state.user.username=`local-test-${account}@example.invalid`;state.machines=state.machines.map(machine=>({...machine,name:`Account ${account} ${machine.name}`}));states[account]=state;}
 let account='A',holdOld=false,releaseOld,releaseNew,oldStarted,newStarted;
 const oldSeen=new Promise(resolve=>oldStarted=resolve),newSeen=new Promise(resolve=>newStarted=resolve);
 const oldGate=new Promise(resolve=>releaseOld=resolve),newGate=new Promise(resolve=>releaseNew=resolve);
 const browser=await launchBrowser(),context=await browser.newContext({viewport:{width:402,height:874},serviceWorkers:'block'});
 try{
  await context.addInitScript(()=>{
        // API/demo fixtures own their responses; PWA registration is outside this test.
        // Blocking registration alone yields undefined in Workbox. Model SW unavailable.
        for(const owner of [navigator,Object.getPrototypeOf(navigator)])if(Object.prototype.hasOwnProperty.call(owner,'serviceWorker')&&!Reflect.deleteProperty(owner,'serviceWorker'))throw Error('Fixture cannot isolate service workers');
        if('serviceWorker' in navigator)throw Error('Fixture service worker isolation failed');
      });
  await context.route('**/socket.io/**',route=>route.abort());
  await context.route('**/api/**',async route=>{const req=route.request(),url=new URL(req.url()),selected=account;
   if(url.pathname==='/api/private/traffic'){if(selected==='A'&&holdOld){oldStarted();await oldGate;}if(selected==='B'){newStarted();await newGate;}}
   let response;try{response=handleDemoRequest(states[selected],req.method(),req.url(),req.postData()||{});}catch(error){await route.fulfill({status:400,json:{detail:error.message}}).catch(()=>{});return;}
   await route.fulfill({json:response}).catch(()=>{});
  });
  const page=await context.newPage(),errors=[];page.on('pageerror',error=>errors.push(error.message));await page.goto(`${process.env.REVIEW_ORIGIN||'http://127.0.0.1:8321'}/home?view=dashboard`);
  const panel=page.getByRole('region',{name:'Private network traffic',exact:true});
  await panel.getByText('Account A atlas-prod-01',{exact:true}).first().waitFor();
  await panel.locator('button[aria-pressed]').first().click();
  const history=panel.getByRole('group',{name:/Selected machine pair traffic history/});
  // The group mounts while the selection request is still in flight. A visibility
  // refresh can start once the selected pair's measurements have rendered.
  await history.getByText(/peak per interval/).waitFor();
  holdOld=true;await page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));
  await Promise.race([oldSeen,new Promise((_,reject)=>setTimeout(()=>reject(Error('old account refresh not started')),5000))]);
  account='B';await page.evaluate(()=>window.dispatchEvent(new Event('pageshow')));
  await Promise.race([newSeen,new Promise((_,reject)=>setTimeout(()=>reject(Error('new account traffic request not started')),5000))]);
  await panel.getByText('Loading private traffic…',{exact:true}).waitFor();
  assert.doesNotMatch(await panel.innerText(),/Account A/,'old account pair/header must disappear before new response');
  releaseOld();await page.waitForTimeout(100);
  assert.doesNotMatch(await panel.innerText(),/Account A/,'late old-account response cannot republish cached data');
  releaseNew();await panel.getByText('Account B atlas-prod-01',{exact:true}).first().waitFor();
  assert.equal(await panel.locator('button[aria-pressed="true"]').count(),0,'old account selection must reset');
  assert.doesNotMatch(await panel.innerText(),/Account A/);
  assert.deepEqual(errors,[]);
  console.log(`PASS ${process.env.REVIEW_BROWSER||'chromium'} account change clears private pair/cache and ignores held old response`);
 }finally{releaseOld();releaseNew();await context.close();await browser.close();}
})().catch(error=>{console.error(error);process.exit(1)});
