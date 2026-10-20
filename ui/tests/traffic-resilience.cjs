const assert=require("node:assert/strict");
const {launchBrowser}=require("./browser.cjs");

(async()=>{
  const {makeDemoData,handleDemoRequest}=await import("../src/shared/demo/data.mjs");
  const state=makeDemoData();
  const browser=await launchBrowser();
  let failed=false,snapshots=0,handled=0;
  try{
    const page=await browser.newPage({viewport:{width:402,height:874}});
    const errors=[];page.on("pageerror",error=>errors.push(error.message));
    await page.route("**/api/**",async route=>{
      const request=route.request();handled++;
      let body={};try{body=request.postDataJSON()||{};}catch{}
      if(request.url().includes("/traffic/snapshot")){
        snapshots++;
        if(failed){await route.fulfill({status:503,json:{detail:"Audit firewall is unavailable"}});return;}
      }
      // Every API response comes from this local fixture, not the real API.
      await route.fulfill({json:handleDemoRequest(state,request.method().toLowerCase(),request.url(),body)});
    });
    await page.goto("http://luna.local:8345/home?view=traffic");
    const chart=page.getByRole("img",{name:"Combined traffic chart",exact:true});
    await chart.waitFor();
    assert.equal(await page.locator('button[aria-controls^="traffic-"]').count(),10);
    failed=true;
    await page.getByRole("button",{name:"Refresh traffic",exact:true}).click();
    await page.getByRole("alert").filter({hasText:"Showing the last successful snapshot"}).waitFor();
    assert(await chart.isVisible(),"A temporary outage keeps the last successful chart visible");
    assert.equal(await page.locator('button[aria-controls^="traffic-"]').count(),10);
    await page.getByRole("button",{name:"Pause",exact:true}).click();
    const before=snapshots;
    await page.waitForTimeout(2200);assert.equal(snapshots,before,"Pause stops requests, including retries");
    failed=false;
    await page.getByRole("button",{name:"Resume",exact:true}).click();
    await page.getByRole("alert").filter({hasText:"Audit firewall is unavailable"}).waitFor({state:"hidden"});
    assert(snapshots>before,"Resume reconnects the stream");
    failed=true;
    await page.reload();
    await page.getByRole("heading",{name:"Traffic Unavailable",exact:true}).waitFor();
    assert.equal(await page.getByRole("heading",{name:"No port traffic to explore yet",exact:true}).count(),0,"Outage must not be presented as an empty workspace");
    failed=false;
    await page.getByRole("button",{name:"Try Again",exact:true}).click();
    await chart.waitFor();
    assert(handled>0);assert.deepEqual(errors,[]);
    console.log(`PASS ${process.env.REVIEW_BROWSER||"chromium"}: retained snapshots, explicit outage state, stopped polling when paused, resume/retry recovery, all API traffic mocked`);
  }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
