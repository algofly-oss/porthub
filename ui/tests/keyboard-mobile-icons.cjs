const assert=require('node:assert/strict');
const {launchBrowser}=require('./browser.cjs');
(async()=>{
 const {makeDemoData,handleDemoRequest}=await import('../src/shared/demo/data.mjs');
 const browser=await launchBrowser();
 try {
  for(const width of [320,390,402,768,1512,1920]) {
   const context=await browser.newContext({viewport:{width,height:874},serviceWorkers:'block'});
   // Workbox expects a registration when the browser exposes the service worker API.
   await context.addInitScript(()=>{delete Object.getPrototypeOf(navigator).serviceWorker;});
   const state=makeDemoData();
   await context.route('**/api/**',async route=>{
    const request=route.request(),path=new URL(request.url()).pathname;
    let data;
    if(path==='/api/keyboard/targets') data={targets:[{id:'fixture',name:'Aero',online:false,kind:'desktop',platform:'windows'}]};
    else if(path==='/api/keyboard/speech') data={settings:{enabled:false,engine:'cpu',model:''},models:[],loaded:false};
    else {try{data=handleDemoRequest(state,request.method(),request.url());}catch{data={};}}
    await route.fulfill({json:data});
   });
   const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
   await page.goto(`${process.env.REVIEW_ORIGIN || 'http://127.0.0.1:3018'}/home?view=keyboard`);
   console.log('Loaded',width);
   const pad=page.getByRole('application',{name:/Touchpad:/});await pad.waitFor();
   for(const name of ['Shift','Backspace','Enter','Left','Right','Up','Down']) {
    console.log('Checking',width,name);
    const icon=page.getByRole('group',{name:'Virtual keyboard'}).getByRole('button',{name,exact:true}).locator('svg');
    await icon.waitFor();const bounds=await icon.boundingBox();assert(bounds.width>=22&&bounds.height>=22,`${name} has legible vector size`);
   }
   for(const button of await page.getByRole('toolbar',{name:'Keyboard controls'}).getByRole('button').all()) {
    if(!await button.isVisible())continue;
    const rect=await button.boundingBox();assert(rect.width>=44 && rect.height>=44,'Accessible toolbar touch target');
   }
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'No horizontal overflow');
   if(width>=768){
    const padBounds=await pad.boundingBox(),keysBounds=await page.getByRole('group',{name:'Virtual keyboard'}).boundingBox();
    assert(padBounds.y+padBounds.height<=keysBounds.y,'Wide layout keeps touchpad ABOVE keyboard');
    assert(Math.abs(padBounds.x-keysBounds.x)<=1&&Math.abs(padBounds.width-keysBounds.width)<=1,'Wide pad and keys share full width');
    assert(keysBounds.y+keysBounds.height>=850,'Wide keyboard anchors near bottom of usable screen');
   }
   assert.deepEqual(errors,[]);
   await page.getByRole('button',{name:'VKeyboard settings',exact:true}).click();
   const popup=page.getByRole('dialog');await popup.waitFor();await page.waitForTimeout(200);
   const close=page.getByRole('button',{name:'Close VKeyboard settings',exact:true});
   const popupBounds=await popup.boundingBox(),closeBounds=await close.boundingBox();
   assert(popupBounds.x+popupBounds.width-closeBounds.x-closeBounds.width<=25,'Settings close is aligned to the right inset');
   assert(closeBounds.x>popupBounds.x+popupBounds.width/2,'Settings close remains on the right');
   await page.screenshot({path:`/tmp/porthub-keyboard-close-polish-${width}.png`,fullPage:true});
   await close.click();await popup.waitFor({state:'hidden'});
   await page.screenshot({path:`/tmp/porthub-keyboard-mobile-polish-${width}.png`,fullPage:true});
   await context.close();console.log(`PASS keyboard vector icons/touch targets/layout ${width}`);
  }
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
