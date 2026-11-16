const assert=require('node:assert/strict');
const {waitForWorkspaceLayout,launchBrowser}=require('./browser.cjs');
exports.verifyLayoutSettling=async browser=>{
 const context=await browser.newContext({viewport:{width:402,height:874}});
 try{
  const page=await context.newPage();
  await page.setContent(`<style>@keyframes pulse{to{opacity:.8}}[role=dialog]{position:fixed;left:12px;bottom:0;width:200px;height:100px;transform:translateY(160px);transition:transform 800ms linear}[role=dialog] i{animation:pulse 1s infinite alternate}</style><div role="dialog"><i>Decoration</i></div>`);
  await page.evaluate(()=>{const dialog=document.querySelector('[role=dialog]');void dialog.offsetHeight;dialog.style.transform='translateY(0)';});
  await page.waitForFunction(()=>document.querySelector('[role=dialog]').getAnimations().some(a=>a.playState==='running'));
  assert(await page.locator('[role=dialog]').evaluate(e=>e.getBoundingClientRect().bottom>innerHeight+1),'Regression begins with a genuine in-flight transition outside viewport');
  await waitForWorkspaceLayout(page);
  const settled=await page.locator('[role=dialog]').evaluate(e=>({bottom:e.getBoundingClientRect().bottom,height:innerHeight,finite:e.getAnimations().filter(a=>Number.isFinite(a.effect.getComputedTiming().endTime)&&a.playState==='running').length,decoration:e.querySelector('i').getAnimations().some(a=>a.playState==='running')}));
  assert(settled.bottom<=settled.height+1);assert.equal(settled.finite,0);assert(settled.decoration,'Infinite decorative animation is preserved without blocking layout');
  // A React update can mount the drawer after click() resolves. Do not treat a
  // temporarily absent dialog as a settled layout.
  await page.locator('[role=dialog]').evaluate(e=>e.remove());
  await page.evaluate(()=>setTimeout(()=>{
    const dialog=document.createElement('div');dialog.setAttribute('role','dialog');dialog.innerHTML='<i>Decoration</i>';document.body.append(dialog);void dialog.offsetHeight;
    requestAnimationFrame(()=>requestAnimationFrame(()=>{dialog.style.transform='translateY(0)';}));
  },100));
  await waitForWorkspaceLayout(page,{dialog:true});
  assert(await page.locator('[role=dialog]').evaluate(e=>e.getBoundingClientRect().bottom<=innerHeight+1),'Delayed dialog mount also reaches its final bounds');
 }finally{await context.close();}
};

if(require.main===module)(async()=>{
 const browser=await launchBrowser();try{await exports.verifyLayoutSettling(browser);console.log(`PASS ${process.env.REVIEW_BROWSER||'chromium'} delayed mount and finite transition settling without disabling decoration`);}finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
