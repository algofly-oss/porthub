const assert = require("node:assert/strict");
const {launchBrowser} = require("./browser.cjs");

(async () => {
  const {makeDemoData, handleDemoRequest} = await import("../src/shared/demo/data.mjs");
  const state = makeDemoData(); state.user.preferences.nav_collapsed = true;
  const browser = await launchBrowser();
  try {
    const context = await browser.newContext({viewport:{width:1512,height:982}});
    await context.addInitScript(() => {
      if (!localStorage.getItem("porthub-navigation-v1")) localStorage.setItem("porthub-navigation-v1", JSON.stringify({collapsed:true}));
      window.navigationWidths = [];
      const observer = new MutationObserver(() => {
        const nav = document.querySelector('[aria-label="Main navigation"]');
        if (nav) window.navigationWidths.push(nav.getBoundingClientRect().width);
      });
      observer.observe(document, {subtree:true,childList:true,attributes:true,attributeFilter:["class"]});
    });
    const page = await context.newPage(); const errors = []; let failSave = false;
    page.on("pageerror", error => errors.push(error.message));
    await page.route("**/api/**", async route => {
      const request=route.request(); let body={};try{body=request.postDataJSON()||{};}catch{}
      if(request.url().endsWith("/auth/me")) await new Promise(resolve=>setTimeout(resolve,2000));
      if(request.url().endsWith("/auth/preferences") && failSave) return route.fulfill({status:503,json:{detail:"Test failure"}});
      await route.fulfill({json:handleDemoRequest(state,request.method().toLowerCase(),request.url(),body)});
    });
    await page.goto(`${process.env.REVIEW_ORIGIN || "http://luna.local:8345"}/home?view=machines`);
    const expand=page.getByRole("button",{name:"Expand navigation",exact:true});
    await expand.waitFor();
    await page.waitForTimeout(2500);
    assert((await page.evaluate(()=>window.navigationWidths)).every(width=>Math.abs(width-64)<1),"No expanded navigation is ever painted while the server is delayed");
    await expand.click();
    await page.waitForFunction(()=>JSON.parse(localStorage.getItem("porthub-navigation-v1")).collapsed===false);
    await page.reload();
    await page.getByRole("button",{name:"Collapse navigation",exact:true}).waitFor();
    await page.waitForTimeout(2500);
    assert((await page.evaluate(()=>window.navigationWidths)).every(width=>Math.abs(width-224)<1),"Expanded state is also restored before auth finishes");
    failSave=true;
    await page.getByRole("button",{name:"Collapse navigation",exact:true}).click();
    await page.getByText("Could not save navigation preference. Please try again.",{exact:true}).waitFor();
    await page.getByRole("button",{name:"Collapse navigation",exact:true}).waitFor();
    assert.equal(await page.evaluate(()=>JSON.parse(localStorage.getItem("porthub-navigation-v1")).collapsed),false,"Failed save rolls back the local cache too");
    state.user.preferences.nav_collapsed=true; failSave=false;
    await page.reload(); await expand.waitFor();
    assert.equal(await page.evaluate(()=>JSON.parse(localStorage.getItem("porthub-navigation-v1")).collapsed),true,"Server changes reconcile back to the local cache");
    assert.deepEqual(errors,[]);
    console.log("PASS sidebar cached before first paint, collapsed/expanded refresh, server reconciliation, failed-save rollback, no hydration errors");
  } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
