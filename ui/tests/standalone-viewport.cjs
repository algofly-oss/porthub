const assert=require("node:assert/strict");
const {launchBrowser}=require("./browser.cjs");

(async()=>{
 const browser=await launchBrowser();
 try{
  const context=await browser.newContext({viewport:{width:402,height:874},isMobile:true,hasTouch:true});
  await context.addInitScript(()=>{
   Object.defineProperty(navigator,"standalone",{value:true,configurable:true});
   // Some installed iOS launches retain a shortened JS window height even
   // though the fixed-position layout viewport already fills the screen.
   Object.defineProperty(window,"innerHeight",{value:840,configurable:true});
   const viewport=new EventTarget();Object.assign(viewport,{height:840,width:402,offsetTop:0,offsetLeft:0,scale:1});
   Object.defineProperty(window,"visualViewport",{value:viewport,configurable:true});
  });
  const page=await context.newPage();const errors=[];page.on("pageerror",error=>errors.push(error.message));
  await page.goto(`${process.env.REVIEW_ORIGIN||"http://luna.local:8345"}/home?demo=1&view=machines`);
  const nav=page.getByRole("complementary",{name:"Main navigation"});await nav.waitFor();
  assert(Math.abs((await nav.boundingBox()).y+(await nav.boundingBox()).height-874)<1,"Standalone fills the fixed viewport even when innerHeight and visualViewport are both shortened");
  await page.evaluate(()=>{visualViewport.height=820;visualViewport.dispatchEvent(new Event("resize"));});
  await page.waitForTimeout(100);
  assert(Math.abs((await nav.boundingBox()).y+(await nav.boundingBox()).height-874)<1,"A standalone viewport resize cannot introduce a bottom chin");
  await page.getByLabel("Search machines",{exact:true}).focus();
  await page.evaluate(()=>{Object.defineProperty(window,"innerHeight",{value:500,configurable:true});visualViewport.height=500;visualViewport.offsetTop=20;visualViewport.dispatchEvent(new Event("resize"));});
  await page.waitForTimeout(100);
  assert(Math.abs((await nav.boundingBox()).y+(await nav.boundingBox()).height-520)<1,"Keyboard uses visible height and offset");
  await page.getByLabel("Search machines",{exact:true}).blur();
  await page.waitForTimeout(100);
  assert(Math.abs((await nav.boundingBox()).y+(await nav.boundingBox()).height-874)<1,"Blur restores the bottom edge without waiting for an iOS resize event or fresh innerHeight");
  await page.evaluate(()=>{visualViewport.height=874;visualViewport.offsetTop=0;visualViewport.dispatchEvent(new Event("resize"));});
  await page.waitForTimeout(100);
  assert(Math.abs((await nav.boundingBox()).y+(await nav.boundingBox()).height-874)<1,"Full height is restored after keyboard closes");
  for (const view of ["Proxies", "Settings", "Machines"]) {
   await page.getByRole("button",{name:view,exact:true}).click();
   assert(Math.abs((await nav.boundingBox()).y+(await nav.boundingBox()).height-874)<1,`${view}: changing pages cannot lift the installed navigation`);
  }
  assert.equal(await page.evaluate(()=>scrollY),0);
  assert.deepEqual(errors,[]);
  console.log(`PASS ${process.env.REVIEW_BROWSER||"chromium"}: standalone full-height launch, safe-area viewport change, keyboard resize/restore, no document scroll`);
 }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
