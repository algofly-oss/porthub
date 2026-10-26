const assert=require("node:assert/strict");
const {launchBrowser}=require("./browser.cjs");
(async()=>{
 const browser=await launchBrowser();
 try{
  for(const theme of ["dark","light"])for(const width of [320,402]){
   const context=await browser.newContext({viewport:{width,height:874},isMobile:true,hasTouch:true});
   await context.addInitScript(theme=>localStorage.setItem("mantine-color-scheme",JSON.stringify(theme)),theme);
   const page=await context.newPage();const errors=[];page.on("pageerror",error=>errors.push(error.message));
   for(const view of ["dashboard","machines","access","proxies","traffic","settings","platform"]){
    await page.goto(`${process.env.REVIEW_ORIGIN||"http://luna.local:8345"}/home?demo=1&view=${view}`);
    const nav=page.getByRole("complementary",{name:"Main navigation"});await nav.waitFor();
    await page.waitForTimeout(200);
    assert.equal(await page.locator('.workspace-topbar').count(),0);
    assert.equal(await page.getByRole("button",{name:"Toggle color theme",exact:true}).filter({visible:true}).count(),0);
    const geometry=await page.evaluate(()=>{
     const nav=document.querySelector('[aria-label="Main navigation"]'),main=document.querySelector('.workspace-body'),active=nav.querySelector('[aria-current="page"]');
     return {nav:nav.getBoundingClientRect().toJSON(),body:main.getBoundingClientRect().toJSON(),line:getComputedStyle(active,'::before').content,overflow:document.documentElement.scrollWidth>innerWidth+1,pagePadding:getComputedStyle(document.querySelector('.workspace-page')).paddingBottom};
    });
    assert.equal(geometry.overflow,false,view);
    assert(Math.abs(geometry.nav.bottom-874)<1,`${view}: navbar at viewport bottom`);
    assert(Math.abs(geometry.body.bottom-geometry.nav.top)<1,`${view}: no gap between content and navbar`);
    assert.equal(geometry.pagePadding,"8px",`${view}: small intentional inset separates panels from navigation`);
    assert(["none","normal"].includes(geometry.line),`${view}: no blue active line on phone`);
    if(["machines","proxies"].includes(view)){
     const insets=await page.locator('[aria-label$="tools"] [role="group"]:visible').evaluateAll(groups=>groups.map(group=>{
      const box=group.getBoundingClientRect(),buttons=group.querySelectorAll("button"),first=buttons[0].getBoundingClientRect(),last=buttons[buttons.length-1].getBoundingClientRect();
      return [first.top-box.top,box.bottom-first.bottom,first.left-box.left,box.right-last.right];
     }));
     assert(insets.length>0,"Status control is present");
     insets.forEach(inset=>inset.forEach(value=>assert(Math.abs(value-4)<1,`Even status-control padding: ${inset}`)));
     const search=page.getByRole("textbox",{name:view==="machines"?"Search machines":"Search proxies",exact:true});
     const create=page.getByRole("button",{name:view==="machines"?"Create machine":"Create proxy",exact:true});
     assert(Math.abs((await search.boundingBox()).y-(await create.boundingBox()).y)<8,"Search/create share the first row");
     await page.getByRole("button",{name:"Filters",exact:true}).click();
     const sort=page.getByLabel(view==="machines"?"Sort machines":"Sort proxies",{exact:true});
     await sort.click();await page.getByRole("option",{name:"Incoming Traffic · 30s",exact:true}).click();
     await page.waitForFunction(label=>document.querySelector(`input[aria-label="${label}"]`)?.value==="Incoming Traffic · 30s",view==="machines"?"Sort machines":"Sort proxies");
     assert.equal(await sort.inputValue(),"Incoming Traffic · 30s");
     assert(await sort.isVisible(),"Selecting a nested dropdown keeps the filter panel available");
     await page.keyboard.press("Escape");
    }
    await page.screenshot({path:`/tmp/porthub-mobile-${theme}-${width}-${view}.png`});
   }
   assert.deepEqual(errors,[]);await context.close();console.log(`PASS mobile ${theme} ${width}: all pages fill available height, no topbar/active line/gap, compact toolbar and searchable sorting`);
  }
 }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
