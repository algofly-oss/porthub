const assert=require('node:assert/strict');
const {launchBrowser}=require('./browser.cjs');
(async()=>{
 const {makeDemoData,handleDemoRequest}=await import('../src/shared/demo/data.mjs');
 const browser=await launchBrowser();
 try {
  for(const width of [320,390,402,768]) {
   const context=await browser.newContext({viewport:{width,height:874},serviceWorkers:'block'});
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
   assert.deepEqual(errors,[]);
   await page.screenshot({path:`/tmp/porthub-keyboard-mobile-polish-${width}.png`,fullPage:true});
   await context.close();console.log(`PASS keyboard vector icons/touch targets/layout ${width}`);
  }
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
