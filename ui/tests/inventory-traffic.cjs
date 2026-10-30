const assert=require('node:assert/strict'),fs=require('node:fs');
const {launchBrowser}=require('./browser.cjs');
(async()=>{
 const f=JSON.parse(fs.readFileSync(process.env.INVENTORY_FIXTURE || '/tmp/porthub-inventory-fixture/fixture.json','utf8'));
 const origin=process.env.REVIEW_ORIGIN || 'http://127.0.0.1:3114',browser=await launchBrowser();
 try{
  const context=await browser.newContext({viewport:{width:402,height:1000}});
  await context.addCookies([{name:'porthub_session',value:f.cookie,url:origin}]);
  const page=await context.newPage(),traffic=[],errors=[];
  page.on('request',request=>{if(new URL(request.url()).pathname==='/api/inventory/traffic')traffic.push(new URL(request.url()));});
  page.on('pageerror',error=>errors.push(error.message));
  await page.goto(`${origin}/home?view=traffic`);
  await page.getByRole('button',{name:'Pause',exact:true}).waitFor();
  await page.getByText('950 ports',{exact:true}).waitFor();
  await page.waitForTimeout(2600);assert(traffic.length>=2,'Live traffic must poll');
  assert(traffic.some(url=>url.searchParams.get('aggregate_token')),'Polls must send aggregate delta tokens');
  assert(traffic.every(url=>Number(url.searchParams.get('page_size'))<=25),'Traffic rows must be bounded');
  await page.getByRole('button',{name:'Pause',exact:true}).click();
  await page.waitForTimeout(200);const paused=traffic.length;
  await page.waitForTimeout(2500);assert.equal(traffic.length,paused,'Pause must stop network polling');
  await Promise.all([page.waitForResponse(response=>new URL(response.url()).pathname==='/api/inventory/traffic'),page.getByRole('button',{name:'Resume',exact:true}).click()]);
  await page.waitForTimeout(100);assert(traffic.length>paused,'Resume must restore polling');
  await page.evaluate(()=>{Object.defineProperty(document,'hidden',{configurable:true,get:()=>true});document.dispatchEvent(new Event('visibilitychange'));});
  await page.waitForTimeout(200);const hidden=traffic.length;
  await page.waitForTimeout(2500);assert.equal(traffic.length,hidden,'Hidden documents must stop traffic requests');
  await Promise.all([page.waitForRequest(request=>new URL(request.url()).pathname==='/api/inventory/traffic'),page.evaluate(()=>{Object.defineProperty(document,'hidden',{configurable:true,get:()=>false});document.dispatchEvent(new Event('visibilitychange'));})]);
  assert(traffic.length>hidden,'Visible documents must resume polling');
  await page.getByLabel('Search traffic',{exact:true}).fill('20151');
  await page.getByText('1 ports',{exact:true}).waitFor();
  assert.deepEqual(errors,[]);assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
  console.log('PASS real traffic: 950-port totals, bounded rows, token deltas, pause/resume, document visibility and server filtering');
 }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
