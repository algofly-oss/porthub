const assert = require("node:assert/strict");
const fs = require("node:fs");
const {launchBrowser} = require("./browser.cjs");
const origin=process.env.REVIEW_URL||"http://luna.local:8345";
const engine=process.env.REVIEW_BROWSER||"chromium";
const output=process.env.REVIEW_OUTPUT||`/tmp/porthub-goal-audit/${engine}`;
const views=[["dashboard","Dashboard"],["machines","Machines"],["proxies","Public Web Proxies"],["traffic","Traffic Explorer"],["settings","Settings"],["platform","Platform Overview"]];

(async()=>{
  fs.mkdirSync(output,{recursive:true});
  const browser=await launchBrowser();
  const errors=[],requests=[];
  function observe(context) {
    context.on("page",page=>{page.on("pageerror",error=>errors.push(error.message));page.on("console",message=>{if(message.type()==="error"&&/hydration|server HTML|validateDOMNesting/i.test(message.text()))errors.push(message.text());});});
    context.on("request",request=>{if(new URL(request.url()).pathname.startsWith("/api/"))requests.push(request.url());});
  }
  async function go(page,view) {
    await page.goto(`${origin}/home?demo=1&view=${view}`);
    await page.getByRole("heading",{name:views.find(item=>item[0]===view)[1],exact:true}).waitFor();
    await page.waitForTimeout(200);
  }
  async function choose(page,label,option) {
    await page.getByLabel(label,{exact:true}).click();
    await page.getByRole("option",{name:option,exact:true}).click();
  }
  try {
    for(const theme of ["light","dark"])for(const [device,width,height,scale] of [["iphone16pro",402,874,3],["macbook14",1512,982,2],["4k",3840,2160,1],["wide",5120,2880,1],["small",320,700,1]]) {
      const context=await browser.newContext({viewport:{width,height},deviceScaleFactor:scale,isMobile:width<=402,hasTouch:width<=402});
      observe(context);
      await context.addInitScript(theme=>{if(location.protocol==="http:"||location.protocol==="https:")localStorage.setItem("mantine-color-scheme",JSON.stringify(theme));},theme);
      const page=await context.newPage();
      for(const [view]of views) {
        await go(page,view);
        const geometry=await page.locator(".workspace-page").evaluate(element=>{const area=element.getBoundingClientRect(),main=element.closest("main").getBoundingClientRect();return{left:area.x,width:area.width,center:area.x+area.width/2,mainCenter:main.x+main.width/2,scrollWidth:document.documentElement.scrollWidth,scrollHeight:document.documentElement.scrollHeight};});
        assert(geometry.scrollWidth<=width+1&&geometry.scrollHeight<=height+1,`${theme} ${device} ${view}: no full-page overflow`);
        assert(geometry.width<=1600&&Math.abs(geometry.center-geometry.mainCenter)<2,`${device}: centered content with readable maximum width`);
        const clipping=await page.locator(".workspace-page input:not([type=hidden])").evaluateAll(elements=>elements.filter(element=>element.getClientRects().length).map(element=>({name:element.getAttribute("aria-label"),left:element.getBoundingClientRect().left,right:element.getBoundingClientRect().right})).filter(bounds=>bounds.left<0||bounds.right>innerWidth+1));
        assert.deepEqual(clipping,[],`${device} ${view}: no clipped search/filter controls`);
        const scrollAreas=await page.locator(".workspace-page .data-scroll").evaluateAll(elements=>elements.filter(element=>element.getClientRects().length).map(element=>({width:element.clientWidth,scrollWidth:element.scrollWidth})));
        assert(scrollAreas.every(area=>area.scrollWidth<=area.width+1),`${device} ${view}: no horizontally scrolling functional area`);
        if(view==="traffic") {
          const results=page.getByRole("region",{name:"Traffic results",exact:true});
          const footer=await results.locator("footer").boundingBox(),card=await results.boundingBox();
          assert(Math.abs(footer.y+footer.height-card.y-card.height)<2,"Traffic pagination attached to the shared results surface");
          assert(await page.locator("details").first().evaluate(element=>element.open),"Combined traffic expanded by default");
        }
        await page.screenshot({path:`${output}/${theme}-${device}-${view}.png`});
        if(view==="settings")for(const section of ["Security","Notifications","Appearance"]) {
          await page.getByRole("button",{name:section,exact:true}).click();
          assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1&&document.documentElement.scrollHeight<=innerHeight+1));
          await page.screenshot({path:`${output}/${theme}-${device}-settings-${section}.png`});
        }
      }
      await context.close();
      console.log(`PASS ${engine} ${theme} ${device} ${width}×${height}: all pages, settings categories, safe control bounds, independent scrolling, centered layout`);
    }
    const context=await browser.newContext({viewport:{width:1512,height:982}});
    observe(context);
    const page=await context.newPage();
    await go(page,"proxies");
    await page.getByLabel("Search proxies",{exact:true}).fill("oroin 20003");
    await page.getByRole("button",{name:"Edit proxy orion-dev-02.preview.invalid",exact:true}).waitFor();
    assert.equal(await page.getByRole("button",{name:/^Edit proxy/}).count(),1,"Fuzzy, multi-field search combines machine typo with external port");
    await page.getByLabel("Search proxies",{exact:true}).fill("");
    await choose(page,"Filter proxy group","Development");
    await page.getByRole("group",{name:"Proxy status",exact:true}).getByRole("button",{name:"Disabled",exact:true}).click();
    assert.equal(await page.getByRole("table",{name:"Web proxies",exact:true}).locator("tbody > tr").count(),1,"Group and status filters combine");
    await page.getByRole("group",{name:"Proxy status",exact:true}).getByRole("button",{name:"All",exact:true}).click();
    await choose(page,"Filter proxy group","All groups");
    await page.getByRole("button",{name:"Filters",exact:true}).click();
    await choose(page,"Sort proxies","Recently updated");
    await choose(page,"Group proxies by","Group by project");
    await page.getByRole("button",{name:"Filters",exact:true}).click();
    for(const group of ["Production","Development","Personal"])await page.locator(".proxy-results").getByRole("heading",{name:new RegExp(`^${group}`)}).waitFor();
    await choose(page,"Proxies per page","10 per page");
    await page.getByText("36 proxies · 1/4",{exact:true}).waitFor();
    await page.getByRole("button",{name:"2",exact:true}).click();
    await page.getByText("36 proxies · 2/4",{exact:true}).waitFor();
    console.log(`PASS ${engine}: fuzzy cross-field proxy search, combined filters, sorting, grouping, and pagination`);
    await go(page,"traffic");
    await page.getByLabel("Search traffic",{exact:true}).fill("orion 20003");
    const row=page.locator('button[aria-controls^="traffic-"]');
    await row.waitFor();assert.equal(await row.count(),1);
    await row.click();
    await page.getByRole("heading",{name:"Observed IP addresses",exact:true}).waitFor();
    await page.getByText("192.0.2.25",{exact:true}).waitFor();
    await page.getByText("198.51.100.8",{exact:true}).waitFor();
    const [monitor]=await Promise.all([context.waitForEvent("page"),page.getByRole("link",{name:"Open Dedicated Monitor",exact:true}).click()]);
    await monitor.getByRole("img",{name:/Traffic monitor chart/i}).waitFor();
    assert.equal(new URL(monitor.url()).searchParams.get("demo"),"1");
    await monitor.close();
    await page.getByRole("button",{name:"Pause",exact:true}).click();
    const paused=await page.locator('[role="img"][aria-label="Combined traffic chart"]').getAttribute("data-window-end");
    await page.waitForTimeout(2200);
    assert.equal(await page.locator('[role="img"][aria-label="Combined traffic chart"]').getAttribute("data-window-end"),paused,"Pause freezes the displayed snapshot");
    await page.getByRole("button",{name:"Resume",exact:true}).click();
    await page.waitForFunction(value=>document.querySelector('[aria-label="Combined traffic chart"]')?.getAttribute("data-window-end")!==value,paused);
    await go(page,"machines");
    await page.getByRole("button",{name:"Configure orion-dev-02",exact:true}).click();
    const machine=page.getByRole("dialog",{name:/^Configure orion-dev-02/});
    await machine.getByRole("button",{name:"Edit forwarding rule API",exact:true}).click();
    await machine.getByRole("button",{name:"Traffic",exact:true}).click();
    const [portMonitor]=await Promise.all([context.waitForEvent("page"),machine.getByRole("button",{name:"Open traffic monitor in a separate window",exact:true}).click()]);
    await portMonitor.getByRole("img",{name:/Traffic monitor chart/i}).waitFor();
    assert.equal(new URL(portMonitor.url()).searchParams.get("demo"),"1");
    await portMonitor.close();
    assert.deepEqual(errors,[],"No browser runtime/hydration errors");assert.deepEqual(requests,[],"No demo API request reaches real infrastructure, including monitor windows");
    await context.close();
    console.log(`PASS ${engine}: quick port drilldown, source IPs, pause/resume, dedicated monitor links from Traffic and Machines, isolated demo windows`);
  }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
