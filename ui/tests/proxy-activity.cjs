const assert=require("node:assert/strict");
const {launchBrowser}=require("./browser.cjs");

(async()=>{
 const {makeDemoData}=await import("../src/shared/demo/data.mjs");
 const state=makeDemoData(),chosen=state.proxies.slice(-7).reverse();
 state.proxyActivity={available:true,tracking_since:new Date(Date.now()-86400000).toISOString(),data:chosen.map((proxy,index)=>({route_id:proxy._id,requests:7000000-index,monthly_requests:12500-index,last_requested_at:new Date(Date.now()-index*60000).toISOString(),last_host:proxy.hosts[0]}))};
 const browser=await launchBrowser();
 try{
  for(const width of [1512,402,320]){
   const context=await browser.newContext({viewport:{width,height:982}});
   await context.addInitScript(state=>sessionStorage.setItem("porthub-demo-v1",JSON.stringify(state)),state);
   const page=await context.newPage();const errors=[];page.on("pageerror",error=>errors.push(error.message));
   await page.goto(`${process.env.REVIEW_ORIGIN||"http://luna.local:8345"}/home?demo=1&view=dashboard`);
   const recent=page.getByRole("region",{name:"Recent Web Addresses",exact:true});
   await recent.getByText("7M lifetime",{exact:true}).first().waitFor();
   await recent.locator('[aria-label="12.5K this month"]').first().waitFor();
   const links=recent.getByRole("link");assert.equal(await links.count(),5);
   assert.deepEqual(await links.evaluateAll(links=>links.map(link=>new URL(link.href).hostname)),chosen.slice(0,5).map(proxy=>proxy.hosts[0]));
   assert.equal(await links.first().getAttribute("target"),"_blank");
   const dimensions=await links.first().evaluate(link=>({tile:link.firstElementChild.getBoundingClientRect().height,text:link.firstElementChild.nextElementSibling.getBoundingClientRect().height}));
   assert.equal(dimensions.tile,40,"Web icon has a 40px tile");
   assert.equal(dimensions.text,40,"URL and compact request counts stay on two aligned lines");
   await recent.screenshot({path:`/tmp/porthub-recent-addresses-${width}.png`});
   await page.getByRole("button",{name:"Proxies",exact:true}).click();
   await page.getByLabel("Search proxies",{exact:true}).fill(chosen[0].hosts[0]);
   await page.locator('[aria-label^="Edit proxy "]:visible').getByText("7M lifetime",{exact:true}).waitFor();
   assert.deepEqual(errors,[]);await context.close();
   console.log(`PASS proxy activity ${width}: five actual most-recent requests, counts, direct URL links, shared proxy-list usage`);
  }
 }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
