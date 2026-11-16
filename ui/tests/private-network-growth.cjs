const assert=require('node:assert/strict');
const {launchBrowser,waitForWorkspaceLayout}=require('./browser.cjs');
(async()=>{
 const {makeDemoData}=await import('../src/shared/demo/data.mjs');
 const browser=await launchBrowser(),engine=process.env.REVIEW_BROWSER||'chromium';
 try{for(const width of [1512,402,320]){
  const viewport={width,height:width===1512?982:874},context=await browser.newContext({viewport,locale:'en-US',isMobile:width<768,hasTouch:width<768,serviceWorkers:'block'});
  const state=makeDemoData(),pools=['10.203.0.0/16',...Array.from({length:10},(_,i)=>`10.204.${i}.0/24`)];
  state.access={books:[],invitations:[],network:{cidr:pools[0],dns_suffix:'phub',auto_expand:true,cidrs:pools,address_capacity:65534+2540}};
  await context.addInitScript(seed=>{sessionStorage.setItem('porthub-demo-v1',JSON.stringify(seed));delete Object.getPrototypeOf(navigator).serviceWorker;},state);
  const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(`${process.env.REVIEW_ORIGIN||'http://127.0.0.1:3219'}/home?demo=1&view=access&tab=network`);
  const heading=page.getByRole('heading',{name:'Private Network Preferences',exact:true});await heading.waitFor();await waitForWorkspaceLayout(page);
  const panel=heading.locator('..');
  await panel.getByText('Automatic address allocation',{exact:true}).waitFor();
  assert(await panel.getByText('68,074 addresses across the current pools.',{exact:true}).isVisible());
  const list=panel.getByText(pools.join(', '),{exact:true});await list.scrollIntoViewIfNeeded();
  const geometry=await list.evaluate(e=>{const r=e.getBoundingClientRect();return{left:r.left,right:r.right,height:r.height,lineHeight:parseFloat(getComputedStyle(e).lineHeight),scrollWidth:e.scrollWidth,clientWidth:e.clientWidth}});
  assert(geometry.left>=0&&geometry.right<=width+1,'Pool list stays within viewport');assert(geometry.scrollWidth<=geometry.clientWidth+1,'Pool list wraps inside card');assert(geometry.height>geometry.lineHeight,'Long pool list uses multiple lines');
  assert.equal(await panel.locator('select').count(),0,'No native dropdowns introduced');
  assert.equal(await panel.getByLabel('Private IPv4 range',{exact:true}).inputValue(),pools[0]);
  assert.equal(await panel.getByLabel('Private DNS suffix',{exact:true}).inputValue(),'phub');
  await panel.getByRole('button',{name:'Save Preferences',exact:true}).scrollIntoViewIfNeeded();assert(await panel.getByRole('button',{name:'Save Preferences',exact:true}).isVisible());
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'No horizontal page overflow');assert.deepEqual(errors,[]);
  await page.screenshot({path:`/tmp/porthub-private-network-growth-${engine}-${width}.png`});await context.close();console.log(`PASS automatic private network pools ${engine} ${width}`);
 }}finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1});
