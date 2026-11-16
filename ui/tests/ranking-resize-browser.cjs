const assert=require('node:assert/strict');
const {launchBrowser}=require('./browser.cjs');
(async()=>{
 const browser=await launchBrowser(),origin=process.env.REVIEW_ORIGIN||'http://127.0.0.1:32924';
 try{for(const theme of ['dark','light'])for(const width of [1512,402,320]){
  const context=await browser.newContext({viewport:{width,height:1100}});
  await context.addInitScript(theme=>localStorage.setItem('mantine-color-scheme',JSON.stringify(theme)),theme);
  await context.addInitScript(()=>{
   window.__rankingFixtureCount=17;
   const nativeFetch=window.fetch.bind(window);
   window.fetch=(input,init)=>{
    const path=new URL(typeof input==='string'?input:input.url,location.href).pathname;
    if(path!=='/api/machines/metrics')return nativeFetch(input,init);
    const machines=Array.from({length:window.__rankingFixtureCount},(_,i)=>({id:String(i).padStart(24,'0'),name:`fixture-${i}`,live:true,reading:{at:Date.now(),sample:{cpu:i,ram:{used:100,total:200},disk:{used:100,total:200}}}}));
    return Promise.resolve(new Response(JSON.stringify({machines}),{status:200,headers:{'Content-Type':'application/json'}}));
   };
  });
  const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  const setCount=count=>page.evaluate(count=>{window.__rankingFixtureCount=count;},count);
  await page.goto(`${origin}/home?demo=1&view=dashboard`);
  const viewport=page.getByRole('region',{name:'Live machine rankings',exact:true});
  async function settle(expected){
   await viewport.locator('[data-ranking-row-content]').nth(expected-1).waitFor();assert.equal(await viewport.locator('[data-ranking-row-content]').count(),expected);
   const samples=await viewport.evaluate(async e=>{
    const samples=[];for(let i=0;i<4;i++){await new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)));samples.push({height:e.clientHeight,width:e.clientWidth,row:e.style.getPropertyValue('--ranking-row-height'),gutter:e.parentElement.style.getPropertyValue('--ranking-scrollbar')});}return samples;
   });
   assert.deepEqual(samples[2],samples[3],'ranking geometry must settle');assert(samples[3].height>0);assert(parseFloat(samples[3].row)>0);
   return viewport.evaluate(e=>({overflow:e.scrollHeight>e.clientHeight+1,rowHeight:e.firstElementChild.firstElementChild.getBoundingClientRect().height,configured:parseFloat(e.style.getPropertyValue('--ranking-row-height'))}));
  }
  const full=await settle(17);assert(full.overflow);assert(Math.abs(full.rowHeight-full.configured)<1);
  // Exercise header wrapping and row-count boundaries on the real component.
  for(const [cardWidth,height] of [[260,310],[349,470],[310,350]]){
   await viewport.evaluate((e,{cardWidth,height})=>{const wrapper=e.parentElement.parentElement;wrapper.style.width=`${cardWidth}px`;wrapper.style.minHeight='0';wrapper.style.height=`${height}px`;},{cardWidth:Math.min(cardWidth,width-32),height});await settle(17);
  }
  await setCount(1);await page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));await page.waitForFunction(()=>document.querySelectorAll('[data-ranking-row-content]').length===1);const short=await settle(1);assert(!short.overflow,'short list must remove scrolling');
  await setCount(17);await page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));await page.waitForFunction(()=>document.querySelectorAll('[data-ranking-row-content]').length===17);assert((await settle(17)).overflow);
  assert.deepEqual(errors,[]);await context.close();console.log('PASS ranking wrap, scroll transition and settled geometry',theme,width);
 }}finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
