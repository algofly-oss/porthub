// Exercises the real API and Mongo fixture; demo adapters cannot prove network bounds.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const {launchBrowser,navigateWorkspace}=require('./browser.cjs');
(async()=>{
 const fixture=JSON.parse(fs.readFileSync(process.env.INVENTORY_FIXTURE || '/tmp/porthub-inventory-fixture/fixture.json','utf8'));
 const origin=process.env.REVIEW_ORIGIN || 'http://127.0.0.1:3114';
 const browser=await launchBrowser();
 try{for(const width of (process.env.REVIEW_WIDTHS || '1440,402').split(',').map(Number)){
  const context=await browser.newContext({viewport:{width,height:1000}});
  await context.addCookies([{name:'porthub_session',value:fixture.cookie,url:origin}]);
  const page=await context.newPage(),requests=[],responses=[],errors=[];
  page.on('request',request=>{if(new URL(request.url()).pathname.startsWith('/api/'))requests.push(request.url());});
  page.on('response',response=>{if(new URL(response.url()).pathname.startsWith('/api/'))responses.push(response);});
  page.on('pageerror',error=>errors.push(error.message));
  await page.goto(`${origin}/home?view=machines`);
  await page.getByRole('button',{name:'Configure Reid',exact:true}).waitFor();console.log('Loaded machines');
  const search=page.getByLabel('Search machines',{exact:true});
  const start=requests.length;
  await search.pressSequentially('reod',{delay:45});
  await page.getByRole('button',{name:'Configure Reid',exact:true}).waitFor();
  await page.waitForTimeout(750);
  assert(await search.evaluate(element=>element===document.activeElement),'Search must retain focus while results load');
  console.log('Typed search');
  const searched=requests.slice(start).filter(url=>new URL(url).pathname==='/api/inventory/machines' && new URL(url).searchParams.get('q'));
  assert.equal(searched.length,1,'Rapid typing must issue one debounced search request');
  assert.equal(new URL(searched[0]).searchParams.get('q'),'reod');
  assert.equal(await page.locator('[aria-label^="Configure "]:visible').count(),1,'Typo search must return the matching machine');
  // Deliberately delay an obsolete response and ensure it cannot replace a newer query.
  let release,held;
  const gate=new Promise(resolve=>release=resolve),arrived=new Promise(resolve=>held=resolve);
  await page.route('**/api/inventory/machines?*',async route=>{
   if(new URL(route.request().url()).searchParams.get('q')==='worker-0003'){
    const response=await route.fetch();held();await gate;await route.fulfill({response}).catch(()=>{});
   }else await route.continue();
  });
  await search.fill('worker-0003');await Promise.race([arrived,new Promise((_,reject)=>setTimeout(()=>reject(Error('Delayed request was not intercepted')),15000))]);
  await search.fill('Reid');
  await page.waitForTimeout(650);release();
  await page.waitForTimeout(250);
  assert.equal(await search.inputValue(),'Reid');
  assert.equal(await page.locator('[aria-label^="Configure "]:visible').count(),1);
  assert(await page.getByRole('button',{name:'Configure Reid',exact:true}).isVisible(),'Cancelled response must not overwrite newer results');
  await navigateWorkspace(page,'Public Web Proxies');
  await page.locator('[aria-label="Edit proxy proxy-000.example.invalid"]:visible').waitFor();
  await navigateWorkspace(page,'Access Rules');
  await page.getByRole('heading',{name:'Access Rules',exact:true}).waitFor();
  await page.locator('[aria-label="Edit policy Policy 000"]:visible').waitFor();
  await page.waitForTimeout(400);
  const forbidden=/\/api\/(machines\/list|connections\/list|traffic-routes\/list|groups\/list|admin\/overview|access\/(snapshot|workspaces))(\?|$)/;
  assert.deepEqual(requests.filter(url=>forbidden.test(url)),[],'UI must not download legacy full inventories');
  const measures=[];
  for(const response of responses){try{const body=await response.body();measures.push({path:new URL(response.url()).pathname,query:new URL(response.url()).search,bytes:body.length,status:response.status()});}catch{/* Cancelled requests have no completed body. */}}
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
  assert.deepEqual(errors,[]);
  fs.writeFileSync(`/tmp/porthub-inventory-network-${width}.json`,JSON.stringify({width,requests:requests.length,responses:measures},null,2));
  await page.screenshot({path:`/tmp/porthub-inventory-network-${width}.png`});
  console.log(`PASS real inventory ${width}: bounded reads, one debounced typo query, retained focus, cancelled stale response, no legacy full inventories`);
  await context.close();
 }}finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
