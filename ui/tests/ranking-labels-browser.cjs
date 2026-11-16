const assert=require('node:assert/strict');
const {launchBrowser}=require('./browser.cjs');
const {chooseDropdown}=require('./search-dropdown.cjs');
(async()=>{
 const browser=await launchBrowser();
 try{for(const size of [{width:402,height:874},{width:874,height:402},{width:320,height:874},{width:1440,height:900}]){
  const context=await browser.newContext({viewport:size,serviceWorkers:'block'});
  await context.addInitScript(()=>{delete Object.getPrototypeOf(navigator).serviceWorker;});
  await context.route('**/api/machines/metrics',route=>route.fulfill({json:{machines:[{id:'fixture',name:'Fixture',live:true,reading:{at:Date.now(),sample:{cpu:25,ram:{used:1024,total:2048},disk:{used:1024,total:2048},gpus:[{name:'GPU',utilization:25}],drive_health:[{id:'drive',name:'Drive',present:true,status:'healthy',checked_at:Date.now()}],drive_health_enabled:true}}}]}}));
  const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(`${process.env.REVIEW_ORIGIN||'http://127.0.0.1:3019'}/home?demo=1&view=dashboard`);
  const ranking=page.getByRole('region',{name:'Machine resource utilization',exact:true});
  const input=ranking.getByLabel('Resource sort order',{exact:true});
  async function closed(short,full){
   await page.waitForFunction(({short})=>document.querySelector('[aria-label="Resource sort order"]')?.value===short,{short});
   assert.equal(await input.getAttribute('title'),full);
   const geometry=await input.evaluate(e=>{const css=getComputedStyle(e),c=document.createElement('canvas').getContext('2d');c.font=css.font;return {text:c.measureText(e.value).width,room:e.clientWidth-parseFloat(css.paddingLeft)-parseFloat(css.paddingRight),width:e.getBoundingClientRect().width};});
   assert(geometry.text<=geometry.room+1,`${short} must fit closed112px control ${JSON.stringify(geometry)}`);
   assert(geometry.width<=112.5,'Header control does not widen');
   assert.equal(await ranking.locator('input[type=radio]:checked').count(),1,'Exactly one resource sort active');
  }
  await closed('High first','Most utilized first');
  await chooseDropdown(input,'Least utilized first');await closed('Low first','Least utilized first');
  await ranking.getByRole('radio',{name:'Health',exact:true}).check();
  await closed('Best first','Healthiest first');
  await chooseDropdown(input,'Most at risk first');await closed('Risk first','Most at risk first');
  await input.click();await input.fill('Healthiest');assert.equal(await page.getByRole('option',{name:'Healthiest first',exact:true}).count(),1);await page.keyboard.press('Escape');
  const row=ranking.locator('[data-ranking-row-content]').first();await row.waitFor();
  assert.equal(await row.getByRole('meter').count(),4,'All four utilization bars retained');
  const aligned=await ranking.evaluate(el=>{const header=el.querySelector('[aria-hidden="true"].grid'),row=el.querySelector('[data-ranking-row-content]');return {header:getComputedStyle(header).gridTemplateColumns,row:getComputedStyle(row).gridTemplateColumns};});
  assert.equal(aligned.header,aligned.row,'Header and four-bar row grid align');
  assert.deepEqual(errors,[]);await page.screenshot({path:`/tmp/porthub-ranking-labels-${process.env.REVIEW_BROWSER||'chromium'}-${size.width}.png`});await context.close();console.log('PASS concise selected labels/full searchable labels/single sort/four bars',size);
 }}finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
